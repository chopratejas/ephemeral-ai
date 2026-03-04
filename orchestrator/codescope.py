"""CodeScope - 7-Layer AI Security Audit for GitHub Repositories.

This script runs INSIDE a DigitalOcean Droplet. It is structured as a string
constant that gets embedded in cloud-init, following the same pattern as
worker_daemon.py.

Given a GitHub repo URL, CodeScope:
  1. Clones the repo
  2. Detects the primary language
  3. Runs 7 analysis layers (SAST, SCA, Secrets, Licenses, Tests, Health, AI)
  4. Generates a comprehensive markdown report
  5. Writes everything to /tmp/output/
"""

CODESCOPE_SCRIPT = r'''#!/usr/bin/env python3
"""CodeScope - 7-Layer AI Security Audit for GitHub Repositories.

Runs inside an ephemeral DigitalOcean Droplet with Python 3.11+, Node.js 18+,
git, curl, jq, and network access.
"""

import json
import os
import re
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GRADIENT_KEY = os.environ.get("EPHEMERAL_GRADIENT_KEY", "")
GRADIENT_MODEL = os.environ.get("EPHEMERAL_MODEL", "openai-gpt-oss-120b")
GRADIENT_API_URL = "https://inference.do-ai.run/v1/chat/completions"

OUTPUT_DIR = Path("/tmp/output")
AUDIT_DIR = Path("/opt/audit")
REPO_DIR = AUDIT_DIR / "repo"

# Layer timeouts in seconds
TIMEOUT_SAST = 60
TIMEOUT_SCA = 30
TIMEOUT_SECRETS = 30
TIMEOUT_LICENSES = 30
TIMEOUT_TESTS = 30
TIMEOUT_HEALTH = 15
TIMEOUT_AI = 120

# File/directory exclusion patterns for scanning
EXCLUDED_DIRS = {".git", "node_modules", "__pycache__", ".tox", ".mypy_cache",
                 ".pytest_cache", "dist", "build", ".eggs", "venv", ".venv"}

BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
                     ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4",
                     ".avi", ".mov", ".zip", ".tar", ".gz", ".bz2", ".7z",
                     ".rar", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
                     ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe",
                     ".class", ".jar", ".war"}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    """Print a timestamped log message."""
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _ensure_dirs() -> None:
    """Create required directories."""
    for d in [OUTPUT_DIR, AUDIT_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def _run(cmd, timeout=60, cwd=None, env=None):
    """Run a subprocess with timeout, returning (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=cwd or str(REPO_DIR), env=env,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        log(f"Command timed out ({timeout}s): {cmd[:3] if isinstance(cmd, list) else cmd}")
        return -1, "", f"TimeoutError: exceeded {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd}"
    except Exception as e:
        return -1, "", str(e)


def _is_scannable_file(path: Path) -> bool:
    """Check if a file should be included in scanning."""
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return False
    if path.name.endswith(".min.js") or path.name.endswith(".min.css"):
        return False
    # Skip very large files (>1MB)
    try:
        if path.stat().st_size > 1_048_576:
            return False
    except OSError:
        return False
    return True


def _iter_repo_files(repo_path: Path):
    """Yield all scannable files in the repo, respecting exclusions."""
    for root, dirs, files in os.walk(repo_path):
        # Modify dirs in-place to skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in files:
            fpath = Path(root) / fname
            if _is_scannable_file(fpath):
                yield fpath


def _read_file_safe(path: Path, max_bytes: int = 524288) -> str:
    """Read a file, returning empty string on failure."""
    try:
        raw = path.read_bytes()[:max_bytes]
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _redact_secret(value: str) -> str:
    """Redact a secret value, keeping only the first 4 characters."""
    if len(value) <= 4:
        return "***"
    return value[:4] + "***"


def _rel_path(path: Path, repo_path: Path) -> str:
    """Return a relative path string for display."""
    try:
        return str(path.relative_to(repo_path))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".swift": "swift",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".sh": "bash",
}


def detect_language(repo_path: Path) -> str:
    """Detect the primary language of the repository by file count."""
    counts = {}
    for fpath in _iter_repo_files(repo_path):
        lang = EXTENSION_MAP.get(fpath.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1

    if not counts:
        # Fallback: check for common manifest files
        if (repo_path / "package.json").exists():
            return "javascript"
        if (repo_path / "requirements.txt").exists() or (repo_path / "setup.py").exists():
            return "python"
        return "unknown"

    # Merge TypeScript into JavaScript for analysis purposes
    if "typescript" in counts and "javascript" in counts:
        counts["javascript"] += counts.pop("typescript")
    elif "typescript" in counts:
        counts["javascript"] = counts.pop("typescript")

    return max(counts, key=counts.get)


# ---------------------------------------------------------------------------
# Tool installation
# ---------------------------------------------------------------------------

def install_audit_tools(language: str) -> None:
    """Install language-specific audit tools."""
    pip_cmd = [sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages"]

    if language == "python":
        log("Installing Python audit tools (bandit, pip-audit)...")
        _run(pip_cmd + ["bandit", "pip-audit"], timeout=60, cwd="/tmp")
    elif language in ("javascript", "typescript"):
        log("JavaScript/TypeScript detected; npm audit is built-in.")

    # pip-audit is useful even for JS projects that might have Python components
    if language != "python":
        log("Installing pip-audit as fallback...")
        _run(pip_cmd + ["pip-audit"], timeout=60, cwd="/tmp")


# ---------------------------------------------------------------------------
# Layer 1: SAST (Static Analysis Security Testing)
# ---------------------------------------------------------------------------

# Regex patterns for common vulnerability detection across languages
SAST_PATTERNS = [
    # Dangerous function calls
    (r'\beval\s*\(', "high", "dangerous-eval", "Use of eval() can lead to code injection"),
    (r'\bnew\s+Function\s*\(', "high", "dangerous-function-constructor", "new Function() can lead to code injection"),
    (r'\.innerHTML\s*=', "medium", "innerHTML-xss", "Direct innerHTML assignment may lead to XSS"),
    (r'dangerouslySetInnerHTML', "medium", "react-dangerous-html", "dangerouslySetInnerHTML may lead to XSS"),

    # SQL injection
    (r'(?:"|\')\s*SELECT\s+.*["\']?\s*\+', "high", "sql-injection-concat", "SQL query built via string concatenation"),
    (r'f["\'].*SELECT\s+.*\{', "high", "sql-injection-fstring", "SQL query built via f-string interpolation"),
    (r'f["\'].*INSERT\s+.*\{', "high", "sql-injection-fstring", "SQL query built via f-string interpolation"),
    (r'f["\'].*UPDATE\s+.*\{', "high", "sql-injection-fstring", "SQL query built via f-string interpolation"),
    (r'f["\'].*DELETE\s+.*\{', "high", "sql-injection-fstring", "SQL query built via f-string interpolation"),

    # Command injection
    (r'child_process\.exec\s*\(', "high", "command-injection", "child_process.exec() is vulnerable to command injection"),
    (r'\bos\.system\s*\(', "high", "command-injection", "os.system() is vulnerable to command injection"),
    (r'\bos\.popen\s*\(', "high", "command-injection", "os.popen() is vulnerable to command injection"),
    (r'subprocess\.call\s*\([^,\]]*shell\s*=\s*True', "high", "command-injection-shell", "subprocess with shell=True is vulnerable to injection"),
    (r'subprocess\.run\s*\([^,\]]*shell\s*=\s*True', "medium", "command-injection-shell", "subprocess.run with shell=True may be vulnerable"),

    # Path traversal
    (r'\.\./\.\./\.\./', "medium", "path-traversal", "Potential path traversal with multiple ../"),

    # Prototype pollution (JS)
    (r'__proto__', "high", "prototype-pollution", "Access to __proto__ may lead to prototype pollution"),
    (r'constructor\.prototype', "high", "prototype-pollution", "Direct prototype modification may lead to pollution"),

    # Hardcoded IPs (non-loopback, non-example)
    (r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b', "low", "hardcoded-ip", "Hardcoded IP address detected"),

    # Security-related TODOs
    (r'(?:TODO|FIXME|HACK|XXX)\s*:?\s*.*(?:security|auth|password|secret|token|cred|vuln|csrf|xss|inject)', "low", "security-todo", "Security-related TODO/FIXME comment found"),
]

# IPs to exclude from hardcoded IP findings
SAFE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "192.168.0.1",
            "10.0.0.0", "172.16.0.0", "224.0.0.0"}


def layer_1_sast(repo_path: Path, language: str) -> list:
    """Layer 1: Static Analysis Security Testing."""
    log("[Layer 1/7] Running SAST analysis...")
    findings = []

    # Run bandit for Python projects
    if language == "python":
        log("  Running bandit...")
        rc, stdout, stderr = _run(
            ["bandit", "-r", str(repo_path), "-f", "json", "-ll",
             "--exclude", ".git,node_modules,__pycache__,venv,.venv"],
            timeout=TIMEOUT_SAST,
        )
        if rc == 0 or (rc == 1 and stdout):
            try:
                bandit_data = json.loads(stdout)
                for result in bandit_data.get("results", []):
                    findings.append({
                        "file": _rel_path(Path(result.get("filename", "")), repo_path),
                        "line": result.get("line_number", 0),
                        "severity": result.get("issue_severity", "MEDIUM").lower(),
                        "rule": result.get("test_id", "unknown"),
                        "message": result.get("issue_text", ""),
                    })
            except json.JSONDecodeError:
                log("  bandit output was not valid JSON")
        else:
            log(f"  bandit returned rc={rc}: {stderr[:200]}")

    # Regex-based scanning for all languages
    log("  Running regex-based pattern scanning...")
    compiled_patterns = []
    for pattern_str, severity, rule, message in SAST_PATTERNS:
        try:
            compiled_patterns.append((re.compile(pattern_str, re.IGNORECASE), severity, rule, message))
        except re.error:
            pass

    for fpath in _iter_repo_files(repo_path):
        content = _read_file_safe(fpath)
        if not content:
            continue

        for line_num, line in enumerate(content.split("\n"), start=1):
            for regex, severity, rule, message in compiled_patterns:
                if regex.search(line):
                    # Filter out safe IPs
                    if rule == "hardcoded-ip":
                        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                        if ip_match and ip_match.group() in SAFE_IPS:
                            continue
                        # Skip version-like patterns (e.g., 1.2.3.4 in package versions)
                        if re.search(r'version|ver\b|v\d', line, re.IGNORECASE):
                            continue

                    findings.append({
                        "file": _rel_path(fpath, repo_path),
                        "line": line_num,
                        "severity": severity,
                        "rule": rule,
                        "message": message,
                    })

    log(f"  SAST complete: {len(findings)} findings")
    return findings


# ---------------------------------------------------------------------------
# Layer 2: SCA (Software Composition Analysis)
# ---------------------------------------------------------------------------

def layer_2_sca(repo_path: Path, language: str) -> list:
    """Layer 2: Software Composition Analysis - known vulnerabilities in deps."""
    log("[Layer 2/7] Running SCA analysis...")
    findings = []

    # Python: pip-audit
    if language == "python":
        requirements_files = []
        for name in ["requirements.txt", "requirements-dev.txt", "requirements-test.txt"]:
            rpath = repo_path / name
            if rpath.exists():
                requirements_files.append(rpath)

        for req_file in requirements_files:
            log(f"  Running pip-audit on {req_file.name}...")
            rc, stdout, stderr = _run(
                ["pip-audit", "-r", str(req_file), "-f", "json", "--progress-spinner", "off"],
                timeout=TIMEOUT_SCA,
            )
            if stdout.strip():
                try:
                    audit_data = json.loads(stdout)
                    deps = audit_data if isinstance(audit_data, list) else audit_data.get("dependencies", [])
                    for dep in deps:
                        vulns = dep.get("vulns", [])
                        for vuln in vulns:
                            findings.append({
                                "package": dep.get("name", "unknown"),
                                "version": dep.get("version", "unknown"),
                                "vulnerability": vuln.get("id", "unknown"),
                                "severity": vuln.get("fix_versions", ["unknown"])[0] if vuln.get("fix_versions") else "unknown",
                                "fix_version": ", ".join(vuln.get("fix_versions", [])) or "no fix available",
                            })
                except json.JSONDecodeError:
                    log(f"  pip-audit output was not valid JSON for {req_file.name}")

        # Also check pyproject.toml, setup.py, setup.cfg existence
        for manifest in ["pyproject.toml", "setup.py", "setup.cfg", "Pipfile"]:
            if (repo_path / manifest).exists():
                log(f"  Detected {manifest} (additional dependency source)")

    # JavaScript: npm audit
    if language in ("javascript", "typescript") or (repo_path / "package.json").exists():
        if (repo_path / "package.json").exists():
            log("  Running npm audit...")

            # Install deps first if no node_modules
            if not (repo_path / "node_modules").exists():
                if (repo_path / "package-lock.json").exists():
                    _run(["npm", "ci", "--ignore-scripts"], timeout=TIMEOUT_SCA, cwd=str(repo_path))
                else:
                    _run(["npm", "install", "--ignore-scripts", "--package-lock-only"],
                         timeout=TIMEOUT_SCA, cwd=str(repo_path))

            rc, stdout, stderr = _run(
                ["npm", "audit", "--json"],
                timeout=TIMEOUT_SCA,
                cwd=str(repo_path),
            )
            if stdout.strip():
                try:
                    audit_data = json.loads(stdout)

                    # npm audit v2+ format (npm 7+)
                    vulns = audit_data.get("vulnerabilities", {})
                    for pkg_name, vuln_info in vulns.items():
                        findings.append({
                            "package": pkg_name,
                            "version": vuln_info.get("range", "unknown"),
                            "vulnerability": vuln_info.get("via", [{}])[0].get("title", "unknown")
                                if isinstance(vuln_info.get("via", [{}])[0], dict)
                                else str(vuln_info.get("via", ["unknown"])[0]),
                            "severity": vuln_info.get("severity", "unknown"),
                            "fix_version": vuln_info.get("fixAvailable", {}).get("version", "unknown")
                                if isinstance(vuln_info.get("fixAvailable"), dict) else "unknown",
                        })

                    # npm audit v1 format (fallback)
                    if not vulns and "advisories" in audit_data:
                        for adv_id, advisory in audit_data["advisories"].items():
                            findings.append({
                                "package": advisory.get("module_name", "unknown"),
                                "version": advisory.get("findings", [{}])[0].get("version", "unknown")
                                    if advisory.get("findings") else "unknown",
                                "vulnerability": advisory.get("title", "unknown"),
                                "severity": advisory.get("severity", "unknown"),
                                "fix_version": advisory.get("patched_versions", "unknown"),
                            })
                except json.JSONDecodeError:
                    log("  npm audit output was not valid JSON")

    log(f"  SCA complete: {len(findings)} findings")
    return findings


# ---------------------------------------------------------------------------
# Layer 3: Secret Detection
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    # AWS
    (r'AKIA[0-9A-Z]{16}', "aws-access-key", "AWS Access Key ID"),
    (r'(?:aws_secret|secret_key|AWS_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "aws-secret-key", "AWS Secret Access Key"),

    # Generic API keys / secrets / tokens
    (r"""["\'](?:api[_\-]?key|apikey|token|secret|password|auth)["\'][\s]*[:=][\s]*["\']([^"\']{8,})["\']""", "generic-api-key", "Generic API key or secret"),

    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "private-key", "Private key file"),

    # GitHub tokens
    (r'gh[ps]_[A-Za-z0-9_]{36,}', "github-token", "GitHub personal access token"),

    # Slack tokens
    (r'xox[baprs]-[0-9a-zA-Z\-]+', "slack-token", "Slack API token"),

    # JWT tokens
    (r'eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*', "jwt-token", "JWT token"),

    # Generic high-entropy strings that look like secrets (base64-ish, 32+ chars, assigned to suspicious vars)
    (r'(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{32,})["\']', "generic-secret", "Potential secret in variable assignment"),
]


def layer_3_secrets(repo_path: Path) -> list:
    """Layer 3: Secret detection across all repo files."""
    log("[Layer 3/7] Running secret detection...")
    findings = []

    compiled_patterns = []
    for pattern_str, secret_type, description in SECRET_PATTERNS:
        try:
            compiled_patterns.append((re.compile(pattern_str, re.IGNORECASE), secret_type, description))
        except re.error:
            pass

    for fpath in _iter_repo_files(repo_path):
        content = _read_file_safe(fpath)
        if not content:
            continue

        for line_num, line in enumerate(content.split("\n"), start=1):
            for regex, secret_type, description in compiled_patterns:
                match = regex.search(line)
                if match:
                    # Extract the secret value for redaction
                    secret_value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    redacted = _redact_secret(secret_value)

                    findings.append({
                        "file": _rel_path(fpath, repo_path),
                        "line": line_num,
                        "type": secret_type,
                        "description": description,
                        "snippet": redacted,
                    })

    # Check for committed .env files
    env_file = repo_path / ".env"
    if env_file.exists():
        gitignore = repo_path / ".gitignore"
        env_ignored = False
        if gitignore.exists():
            gi_content = _read_file_safe(gitignore)
            env_ignored = ".env" in gi_content

        if not env_ignored:
            findings.append({
                "file": ".env",
                "line": 0,
                "type": "committed-env-file",
                "description": ".env file is committed and not in .gitignore",
                "snippet": "(entire file)",
            })

    # Also check for other env-like files
    for env_name in [".env.local", ".env.production", ".env.development", ".env.staging"]:
        if (repo_path / env_name).exists():
            findings.append({
                "file": env_name,
                "line": 0,
                "type": "committed-env-file",
                "description": f"{env_name} file found in repository",
                "snippet": "(entire file)",
            })

    log(f"  Secret detection complete: {len(findings)} findings")
    return findings


# ---------------------------------------------------------------------------
# Layer 4: License Compliance
# ---------------------------------------------------------------------------

# Licenses that may cause issues when mixed
COPYLEFT_LICENSES = {"gpl", "agpl", "lgpl", "gpl-2.0", "gpl-3.0",
                     "agpl-3.0", "lgpl-2.1", "lgpl-3.0", "gpl-2.0-only",
                     "gpl-3.0-only", "agpl-3.0-only"}
PERMISSIVE_LICENSES = {"mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause",
                       "isc", "0bsd", "unlicense", "cc0-1.0", "wtfpl"}


def _classify_license(license_str: str) -> str:
    """Classify a license string as permissive, copyleft, or unknown."""
    lower = license_str.lower().strip()
    for cl in COPYLEFT_LICENSES:
        if cl in lower:
            return "copyleft"
    for pl in PERMISSIVE_LICENSES:
        if pl in lower:
            return "permissive"
    if lower in ("unlicensed", "none", ""):
        return "unlicensed"
    return "unknown"


def _get_project_license(repo_path: Path) -> str:
    """Detect the project's own license."""
    # Check LICENSE file
    for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md"]:
        lpath = repo_path / name
        if lpath.exists():
            content = _read_file_safe(lpath, max_bytes=4096).lower()
            if "mit" in content:
                return "MIT"
            if "apache" in content:
                return "Apache-2.0"
            if "bsd" in content:
                return "BSD"
            if "gpl" in content or "gnu general public" in content:
                return "GPL"
            if "agpl" in content:
                return "AGPL"
            return "detected (unknown type)"

    # Check package.json
    pkg_json = repo_path / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(_read_file_safe(pkg_json))
            return data.get("license", "")
        except json.JSONDecodeError:
            pass

    return ""


def layer_4_licenses(repo_path: Path, language: str) -> list:
    """Layer 4: License compliance analysis."""
    log("[Layer 4/7] Running license compliance check...")
    findings = []

    project_license = _get_project_license(repo_path)
    project_class = _classify_license(project_license)
    log(f"  Project license: {project_license or 'not found'} ({project_class})")

    # Python: check pip show for each requirement
    if language == "python":
        req_file = repo_path / "requirements.txt"
        if req_file.exists():
            content = _read_file_safe(req_file)
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Extract package name (before ==, >=, etc.)
                pkg_name = re.split(r'[><=!~\[]', line)[0].strip()
                if not pkg_name:
                    continue

                rc, stdout, stderr = _run(
                    [sys.executable, "-m", "pip", "show", pkg_name],
                    timeout=10, cwd="/tmp",
                )
                pkg_license = ""
                if rc == 0:
                    for show_line in stdout.split("\n"):
                        if show_line.startswith("License:"):
                            pkg_license = show_line.split(":", 1)[1].strip()
                            break

                dep_class = _classify_license(pkg_license)
                status = "ok"
                reason = ""

                if dep_class == "copyleft" and project_class == "permissive":
                    status = "violation"
                    reason = f"Copyleft license ({pkg_license}) in a {project_license} project"
                elif dep_class == "unlicensed":
                    status = "warning"
                    reason = "Package has no license declaration"
                elif dep_class == "unknown" and pkg_license:
                    status = "warning"
                    reason = f"Unknown license type: {pkg_license}"
                elif not pkg_license:
                    status = "warning"
                    reason = "Could not determine package license"

                findings.append({
                    "package": pkg_name,
                    "license": pkg_license or "unknown",
                    "status": status,
                    "reason": reason,
                })

    # JavaScript: parse package.json and node_modules
    if language in ("javascript", "typescript") or (repo_path / "package.json").exists():
        pkg_json = repo_path / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(_read_file_safe(pkg_json))
                all_deps = {}
                all_deps.update(data.get("dependencies", {}))
                all_deps.update(data.get("devDependencies", {}))

                for pkg_name, version in all_deps.items():
                    pkg_license = ""
                    # Try to read from node_modules
                    nm_pkg_json = repo_path / "node_modules" / pkg_name / "package.json"
                    if nm_pkg_json.exists():
                        try:
                            nm_data = json.loads(_read_file_safe(nm_pkg_json))
                            pkg_license = nm_data.get("license", "")
                            if isinstance(pkg_license, dict):
                                pkg_license = pkg_license.get("type", "")
                        except json.JSONDecodeError:
                            pass

                    dep_class = _classify_license(pkg_license)
                    status = "ok"
                    reason = ""

                    if dep_class == "copyleft" and project_class == "permissive":
                        status = "violation"
                        reason = f"Copyleft license ({pkg_license}) in a {project_license} project"
                    elif pkg_license.upper() == "UNLICENSED":
                        status = "warning"
                        reason = "Package is explicitly UNLICENSED"
                    elif dep_class == "unlicensed" or not pkg_license:
                        status = "warning"
                        reason = "No license declaration found"
                    elif dep_class == "unknown":
                        status = "warning"
                        reason = f"Unknown license type: {pkg_license}"

                    findings.append({
                        "package": pkg_name,
                        "license": pkg_license or "unknown",
                        "status": status,
                        "reason": reason,
                    })
            except json.JSONDecodeError:
                log("  Failed to parse package.json")

    log(f"  License check complete: {len(findings)} entries")
    return findings


# ---------------------------------------------------------------------------
# Layer 5: Test Coverage Analysis
# ---------------------------------------------------------------------------

def layer_5_tests(repo_path: Path, language: str) -> dict:
    """Layer 5: Test coverage and testing health analysis."""
    log("[Layer 5/7] Running test coverage analysis...")

    result = {
        "test_framework": "none",
        "test_files": 0,
        "estimated_tests": 0,
        "has_coverage_config": False,
        "has_ci": False,
    }

    test_files = []

    if language == "python":
        # Look for Python test files
        for fpath in _iter_repo_files(repo_path):
            name = fpath.name
            if (name.startswith("test_") or name.endswith("_test.py") or
                    name == "conftest.py"):
                test_files.append(fpath)

        # Detect test framework
        if (repo_path / "pytest.ini").exists() or (repo_path / "pyproject.toml").exists():
            result["test_framework"] = "pytest"
        elif (repo_path / "setup.cfg").exists():
            cfg = _read_file_safe(repo_path / "setup.cfg")
            if "pytest" in cfg or "tool:pytest" in cfg:
                result["test_framework"] = "pytest"
            elif "unittest" in cfg:
                result["test_framework"] = "unittest"
        elif test_files:
            result["test_framework"] = "pytest (assumed)"

        # Count tests using pytest --co (collect only)
        if test_files:
            log("  Counting Python tests...")
            rc, stdout, stderr = _run(
                [sys.executable, "-m", "pytest", "--co", "-q"],
                timeout=TIMEOUT_TESTS,
            )
            if rc == 0 and stdout.strip():
                # Last line is usually "X tests collected" or similar
                lines = [l for l in stdout.strip().split("\n") if l.strip()]
                if lines:
                    last = lines[-1]
                    match = re.search(r'(\d+)\s+test', last)
                    if match:
                        result["estimated_tests"] = int(match.group(1))
                    else:
                        # Count non-empty lines (each is a test)
                        result["estimated_tests"] = len([l for l in lines if "::" in l])

        # Check for coverage config
        for cov_indicator in [".coveragerc", "coverage.cfg"]:
            if (repo_path / cov_indicator).exists():
                result["has_coverage_config"] = True
                break
        if not result["has_coverage_config"]:
            pyproject = repo_path / "pyproject.toml"
            if pyproject.exists():
                content = _read_file_safe(pyproject)
                if "coverage" in content or "pytest-cov" in content:
                    result["has_coverage_config"] = True

    elif language in ("javascript", "typescript"):
        # Look for JS/TS test files
        for fpath in _iter_repo_files(repo_path):
            name = fpath.name
            if (name.endswith(".test.js") or name.endswith(".test.ts") or
                    name.endswith(".test.jsx") or name.endswith(".test.tsx") or
                    name.endswith(".spec.js") or name.endswith(".spec.ts") or
                    name.endswith(".spec.jsx") or name.endswith(".spec.tsx")):
                test_files.append(fpath)

        # Check for test directories
        for test_dir_name in ["__tests__", "tests", "test", "spec"]:
            test_dir = repo_path / test_dir_name
            if test_dir.is_dir():
                for fpath in _iter_repo_files(test_dir):
                    if fpath not in test_files:
                        test_files.append(fpath)

        # Detect test framework
        pkg_json = repo_path / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(_read_file_safe(pkg_json))
                all_deps = {}
                all_deps.update(data.get("dependencies", {}))
                all_deps.update(data.get("devDependencies", {}))

                if "jest" in all_deps:
                    result["test_framework"] = "jest"
                elif "mocha" in all_deps:
                    result["test_framework"] = "mocha"
                elif "vitest" in all_deps:
                    result["test_framework"] = "vitest"
                elif "ava" in all_deps:
                    result["test_framework"] = "ava"
                elif "jasmine" in all_deps:
                    result["test_framework"] = "jasmine"
            except json.JSONDecodeError:
                pass

        # Check for jest/vitest config
        for cfg in ["jest.config.js", "jest.config.ts", "jest.config.mjs",
                     "vitest.config.js", "vitest.config.ts", ".mocharc.yml",
                     ".mocharc.json"]:
            if (repo_path / cfg).exists():
                if not result["test_framework"] or result["test_framework"] == "none":
                    result["test_framework"] = cfg.split(".")[0]
                break

        # Count test cases via grep
        if test_files:
            log("  Counting JavaScript/TypeScript test cases...")
            count = 0
            for tf in test_files:
                content = _read_file_safe(tf)
                # Count describe/it/test blocks
                count += len(re.findall(r'\b(?:it|test)\s*\(', content))
            result["estimated_tests"] = count

        # Check for coverage config
        if pkg_json.exists():
            content = _read_file_safe(pkg_json)
            if "coverage" in content or "c8" in content or "istanbul" in content or "nyc" in content:
                result["has_coverage_config"] = True

    result["test_files"] = len(test_files)

    # Check for CI configuration
    ci_paths = [
        repo_path / ".github" / "workflows",
        repo_path / ".gitlab-ci.yml",
        repo_path / "Jenkinsfile",
        repo_path / ".circleci",
        repo_path / ".travis.yml",
        repo_path / "azure-pipelines.yml",
        repo_path / "bitbucket-pipelines.yml",
    ]
    for ci_path in ci_paths:
        if ci_path.exists():
            result["has_ci"] = True
            # Check if CI runs tests
            if ci_path.is_dir():
                for wf in ci_path.iterdir():
                    content = _read_file_safe(wf)
                    if "test" in content.lower():
                        result["ci_runs_tests"] = True
                        break
            else:
                content = _read_file_safe(ci_path)
                if "test" in content.lower():
                    result["ci_runs_tests"] = True
            break

    log(f"  Test analysis complete: {result['test_files']} test files, "
        f"~{result['estimated_tests']} tests, framework={result['test_framework']}")
    return result


# ---------------------------------------------------------------------------
# Layer 6: Repository Health & Structure
# ---------------------------------------------------------------------------

def layer_6_repo_health(repo_path: Path, language: str) -> dict:
    """Layer 6: Repository health, structure, and best practices."""
    log("[Layer 6/7] Running repository health analysis...")

    # File statistics
    total_files = 0
    total_lines = 0
    languages = {}

    for fpath in _iter_repo_files(repo_path):
        total_files += 1
        ext = fpath.suffix.lower()
        lang = EXTENSION_MAP.get(ext, ext or "unknown")
        languages[lang] = languages.get(lang, 0) + 1

        try:
            content = fpath.read_bytes()
            total_lines += content.count(b"\n")
        except OSError:
            pass

    # Security structure checks
    checks = []

    # README
    readme_exists = any((repo_path / name).exists()
                        for name in ["README.md", "README.rst", "README.txt", "README"])
    checks.append({
        "name": "README",
        "status": "pass" if readme_exists else "fail",
        "details": "README file found" if readme_exists else "No README file found",
    })

    # .gitignore
    gitignore_exists = (repo_path / ".gitignore").exists()
    checks.append({
        "name": ".gitignore",
        "status": "pass" if gitignore_exists else "fail",
        "details": ".gitignore found" if gitignore_exists else "No .gitignore file - risk of committing sensitive files",
    })

    # SECURITY.md
    security_exists = any((repo_path / name).exists()
                          for name in ["SECURITY.md", "security.md", ".github/SECURITY.md"])
    checks.append({
        "name": "Security Policy",
        "status": "pass" if security_exists else "warning",
        "details": "Security policy found" if security_exists else "No SECURITY.md - consider adding a vulnerability disclosure policy",
    })

    # Dependency lockfile
    lockfiles = {
        "package-lock.json": "npm",
        "yarn.lock": "yarn",
        "pnpm-lock.yaml": "pnpm",
        "Pipfile.lock": "pipenv",
        "poetry.lock": "poetry",
        "Gemfile.lock": "bundler",
        "go.sum": "go modules",
        "Cargo.lock": "cargo",
    }
    found_lockfile = None
    for lf_name, lf_tool in lockfiles.items():
        if (repo_path / lf_name).exists():
            found_lockfile = (lf_name, lf_tool)
            break

    checks.append({
        "name": "Dependency Lockfile",
        "status": "pass" if found_lockfile else "warning",
        "details": f"Found {found_lockfile[0]} ({found_lockfile[1]})" if found_lockfile
                   else "No dependency lockfile - builds may be non-deterministic",
    })

    # Dockerfile analysis
    dockerfile = repo_path / "Dockerfile"
    if dockerfile.exists():
        df_content = _read_file_safe(dockerfile)
        has_user = bool(re.search(r'^USER\s+\S+', df_content, re.MULTILINE))
        checks.append({
            "name": "Dockerfile Security",
            "status": "pass" if has_user else "warning",
            "details": "Dockerfile has USER directive (non-root)" if has_user
                       else "Dockerfile exists but no USER directive - container runs as root",
        })
    else:
        checks.append({
            "name": "Dockerfile",
            "status": "info",
            "details": "No Dockerfile found",
        })

    # CI/CD
    ci_found = False
    ci_details = "No CI/CD configuration found"
    ci_configs = {
        ".github/workflows": "GitHub Actions",
        ".gitlab-ci.yml": "GitLab CI",
        "Jenkinsfile": "Jenkins",
        ".circleci": "CircleCI",
        ".travis.yml": "Travis CI",
        "azure-pipelines.yml": "Azure Pipelines",
    }
    for ci_path, ci_name in ci_configs.items():
        if (repo_path / ci_path).exists():
            ci_found = True
            ci_details = f"{ci_name} configuration found"
            break

    checks.append({
        "name": "CI/CD",
        "status": "pass" if ci_found else "warning",
        "details": ci_details,
    })

    # CODEOWNERS
    codeowners_exists = any((repo_path / name).exists()
                            for name in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"])
    checks.append({
        "name": "CODEOWNERS",
        "status": "pass" if codeowners_exists else "info",
        "details": "CODEOWNERS file found" if codeowners_exists else "No CODEOWNERS file",
    })

    # Dependency freshness (lockfile newer than manifest?)
    manifest_lockfile_pairs = [
        ("package.json", "package-lock.json"),
        ("package.json", "yarn.lock"),
        ("Pipfile", "Pipfile.lock"),
        ("pyproject.toml", "poetry.lock"),
    ]
    for manifest, lockfile in manifest_lockfile_pairs:
        m_path = repo_path / manifest
        l_path = repo_path / lockfile
        if m_path.exists() and l_path.exists():
            try:
                m_mtime = m_path.stat().st_mtime
                l_mtime = l_path.stat().st_mtime
                stale = m_mtime > l_mtime
                checks.append({
                    "name": "Dependency Freshness",
                    "status": "warning" if stale else "pass",
                    "details": f"{manifest} is newer than {lockfile} - lockfile may be stale"
                               if stale else f"{lockfile} is up to date with {manifest}",
                })
            except OSError:
                pass
            break

    result = {
        "files": total_files,
        "lines": total_lines,
        "languages": languages,
        "checks": checks,
    }

    log(f"  Health analysis complete: {total_files} files, {total_lines} lines, "
        f"{len(checks)} checks")
    return result


# ---------------------------------------------------------------------------
# Layer 7: AI Synthesis (Gradient AI)
# ---------------------------------------------------------------------------

AI_SYNTHESIS_SYSTEM_PROMPT = """\
You are a senior application security engineer performing a comprehensive code audit.
You have been given findings from 6 automated analysis layers. Your job is to:

1. PRIORITIZE findings by actual exploitability and business risk (not just CVSS scores)
2. GROUP findings by severity: Critical, High, Medium, Low, Informational
3. CROSS-REFERENCE findings across layers:
   - A dependency CVE in code with no test coverage = escalate to Critical
   - A hardcoded secret in a file with no .gitignore protection = Critical
   - A missing lockfile + known vulnerable deps = High
4. For each Critical/High finding, provide:
   - Plain English explanation of the risk
   - Specific remediation steps
   - Code example of the fix if applicable
5. Generate an EXECUTIVE SUMMARY (3-4 sentences) for non-technical stakeholders
6. Generate a RISK SCORE from 0-100 (0=perfect, 100=critical risk)

Output your analysis as a structured markdown report.
"""


def layer_7_ai_synthesis(findings: dict, gradient_key: str, model: str) -> str:
    """Layer 7: AI-powered synthesis and prioritization of all findings."""
    log("[Layer 7/7] Running AI synthesis via Gradient AI...")

    if not gradient_key:
        log("  WARNING: No Gradient API key provided. Generating basic report without AI.")
        return _generate_fallback_report(findings)

    # Prepare the findings summary for the AI
    findings_json = json.dumps(findings, indent=2, default=str)

    # Truncate if too large (reserve room for system prompt + response)
    max_findings_chars = 12000
    if len(findings_json) > max_findings_chars:
        findings_json = findings_json[:max_findings_chars] + "\n... (truncated)"

    user_message = (
        "Here are the findings from all 6 automated analysis layers for a code repository audit. "
        "Please analyze, cross-reference, and produce your comprehensive security report.\n\n"
        f"```json\n{findings_json}\n```"
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": AI_SYNTHESIS_SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        "temperature": 0.2,
        "max_completion_tokens": 4096,
    }

    try:
        req = urllib.request.Request(
            GRADIENT_API_URL,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {gradient_key}",
            },
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=TIMEOUT_AI)
        result = json.loads(resp.read().decode())
        ai_report = result["choices"][0]["message"]["content"]
        log("  AI synthesis complete.")
        return _build_full_report(findings, ai_report)

    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()[:500]
        except Exception:
            pass
        log(f"  Gradient AI HTTP error {e.code}: {body}")
        return _generate_fallback_report(findings)
    except Exception as e:
        log(f"  Gradient AI error: {e}")
        return _generate_fallback_report(findings)


def _build_full_report(findings: dict, ai_report: str) -> str:
    """Combine raw findings with AI analysis into a final markdown report."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    sections = [
        f"# CodeScope 7-Layer Security Audit Report",
        f"",
        f"**Generated:** {timestamp}",
        f"",
        f"---",
        f"",
    ]

    # AI Analysis (the main event)
    sections.append("## AI Security Analysis")
    sections.append("")
    sections.append(ai_report)
    sections.append("")
    sections.append("---")
    sections.append("")

    # Raw findings summary
    sections.append("## Raw Layer Findings Summary")
    sections.append("")

    # Layer 1: SAST
    sast = findings.get("sast", [])
    sections.append(f"### Layer 1: SAST ({len(sast)} findings)")
    if sast:
        by_severity = {}
        for f in sast:
            sev = f.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        sections.append(f"Breakdown: {', '.join(f'{k}: {v}' for k, v in sorted(by_severity.items()))}")
    else:
        sections.append("No SAST findings.")
    sections.append("")

    # Layer 2: SCA
    sca = findings.get("sca", [])
    sections.append(f"### Layer 2: SCA ({len(sca)} findings)")
    if sca:
        for f in sca[:10]:  # Limit display
            sections.append(f"- **{f.get('package')}** {f.get('version')}: "
                          f"{f.get('vulnerability')} (fix: {f.get('fix_version')})")
        if len(sca) > 10:
            sections.append(f"- ... and {len(sca) - 10} more")
    else:
        sections.append("No known vulnerable dependencies found.")
    sections.append("")

    # Layer 3: Secrets
    secrets = findings.get("secrets", [])
    sections.append(f"### Layer 3: Secret Detection ({len(secrets)} findings)")
    if secrets:
        for f in secrets[:10]:
            sections.append(f"- **{f.get('type')}** in `{f.get('file')}` line {f.get('line')}: "
                          f"{f.get('description')} [{f.get('snippet')}]")
        if len(secrets) > 10:
            sections.append(f"- ... and {len(secrets) - 10} more")
    else:
        sections.append("No secrets detected.")
    sections.append("")

    # Layer 4: Licenses
    licenses = findings.get("licenses", [])
    violations = [f for f in licenses if f.get("status") == "violation"]
    warnings = [f for f in licenses if f.get("status") == "warning"]
    sections.append(f"### Layer 4: License Compliance ({len(licenses)} packages checked)")
    if violations:
        sections.append(f"**{len(violations)} violations:**")
        for f in violations:
            sections.append(f"- {f.get('package')}: {f.get('reason')}")
    if warnings:
        sections.append(f"**{len(warnings)} warnings:**")
        for f in warnings[:5]:
            sections.append(f"- {f.get('package')}: {f.get('reason')}")
        if len(warnings) > 5:
            sections.append(f"- ... and {len(warnings) - 5} more")
    if not violations and not warnings:
        sections.append("All licenses OK.")
    sections.append("")

    # Layer 5: Tests
    tests = findings.get("tests", {})
    sections.append(f"### Layer 5: Test Coverage")
    sections.append(f"- Framework: {tests.get('test_framework', 'none')}")
    sections.append(f"- Test files: {tests.get('test_files', 0)}")
    sections.append(f"- Estimated tests: {tests.get('estimated_tests', 0)}")
    sections.append(f"- Coverage config: {'Yes' if tests.get('has_coverage_config') else 'No'}")
    sections.append(f"- CI configured: {'Yes' if tests.get('has_ci') else 'No'}")
    sections.append("")

    # Layer 6: Repo Health
    health = findings.get("repo_health", {})
    sections.append(f"### Layer 6: Repository Health")
    sections.append(f"- Total files: {health.get('files', 0)}")
    sections.append(f"- Total lines: {health.get('lines', 0)}")
    if health.get("languages"):
        lang_str = ", ".join(f"{k}: {v}" for k, v in
                            sorted(health["languages"].items(), key=lambda x: -x[1])[:10])
        sections.append(f"- Languages: {lang_str}")
    sections.append("")
    for check in health.get("checks", []):
        icon = {"pass": "PASS", "fail": "FAIL", "warning": "WARN", "info": "INFO"}.get(
            check.get("status"), "???")
        sections.append(f"- [{icon}] **{check.get('name')}**: {check.get('details')}")
    sections.append("")

    sections.append("---")
    sections.append("")
    sections.append("*Report generated by CodeScope 7-Layer Security Audit*")

    return "\n".join(sections)


def _generate_fallback_report(findings: dict) -> str:
    """Generate a basic report without AI when Gradient AI is unavailable."""
    log("  Generating fallback report (no AI synthesis)...")

    # Calculate a basic risk score
    risk_score = 0

    sast = findings.get("sast", [])
    sca = findings.get("sca", [])
    secrets = findings.get("secrets", [])
    licenses = findings.get("licenses", [])
    tests = findings.get("tests", {})
    health = findings.get("repo_health", {})

    # Score from SAST
    for f in sast:
        sev = f.get("severity", "").lower()
        if sev == "high":
            risk_score += 5
        elif sev == "medium":
            risk_score += 2
        elif sev == "low":
            risk_score += 1

    # Score from SCA
    risk_score += len(sca) * 8

    # Score from secrets (high impact)
    risk_score += len(secrets) * 15

    # Score from license violations
    violations = [f for f in licenses if f.get("status") == "violation"]
    risk_score += len(violations) * 10

    # Score from missing tests
    if tests.get("test_files", 0) == 0:
        risk_score += 10

    # Score from health checks
    for check in health.get("checks", []):
        if check.get("status") == "fail":
            risk_score += 5
        elif check.get("status") == "warning":
            risk_score += 2

    risk_score = min(100, risk_score)

    ai_section = (
        f"## AI Security Analysis\n\n"
        f"*AI synthesis was unavailable. Below is an automated summary.*\n\n"
        f"### Risk Score: {risk_score}/100\n\n"
        f"### Executive Summary\n\n"
        f"This repository has {len(sast)} static analysis findings, "
        f"{len(sca)} known vulnerable dependencies, "
        f"{len(secrets)} potential secret exposures, and "
        f"{len(violations)} license compliance violations. "
        f"{'No test files were detected, increasing overall risk.' if tests.get('test_files', 0) == 0 else str(tests.get('test_files', 0)) + ' test files were found.'}\n\n"
        f"### Critical Findings\n\n"
    )

    if secrets:
        ai_section += "**Exposed Secrets:**\n"
        for s in secrets[:5]:
            ai_section += f"- {s.get('type')} in `{s.get('file')}` (line {s.get('line')})\n"
        ai_section += "\n"

    if sca:
        ai_section += "**Vulnerable Dependencies:**\n"
        for v in sca[:5]:
            ai_section += f"- {v.get('package')} {v.get('version')}: {v.get('vulnerability')}\n"
        ai_section += "\n"

    high_sast = [f for f in sast if f.get("severity") == "high"]
    if high_sast:
        ai_section += "**High-Severity Code Issues:**\n"
        for h in high_sast[:5]:
            ai_section += f"- {h.get('rule')} in `{h.get('file')}` line {h.get('line')}: {h.get('message')}\n"
        ai_section += "\n"

    return _build_full_report(findings, ai_section)


# ---------------------------------------------------------------------------
# Clone and main audit orchestration
# ---------------------------------------------------------------------------

def clone_repo(repo_url: str, branch: str = "main") -> Path:
    """Clone the repository. Falls back to default branch if specified branch fails."""
    log(f"Cloning repository: {repo_url} (branch: {branch})")

    repo_path = REPO_DIR
    if repo_path.exists():
        import shutil
        shutil.rmtree(str(repo_path))

    # Try specified branch first
    rc, stdout, stderr = _run(
        ["git", "clone", "--depth", "1", "--branch", branch, repo_url, str(repo_path)],
        timeout=120, cwd="/tmp",
    )

    if rc != 0:
        log(f"  Branch '{branch}' failed, trying without --branch...")
        if repo_path.exists():
            import shutil
            shutil.rmtree(str(repo_path))

        rc, stdout, stderr = _run(
            ["git", "clone", "--depth", "1", repo_url, str(repo_path)],
            timeout=120, cwd="/tmp",
        )

        if rc != 0:
            raise RuntimeError(f"Failed to clone repository: {stderr[:500]}")

    log(f"  Clone complete.")
    return repo_path


def run_audit(repo_url: str, branch: str = "main",
              gradient_key: str = "", model: str = "openai-gpt-oss-120b") -> None:
    """Execute the full 7-layer CodeScope audit."""
    start_time = time.time()
    _ensure_dirs()

    log("=" * 60)
    log("  CodeScope 7-Layer Security Audit")
    log("=" * 60)
    log(f"Repository:  {repo_url}")
    log(f"Branch:      {branch}")
    log(f"Model:       {model}")
    log(f"Output:      {OUTPUT_DIR}")
    log("")

    # Step 1: Clone
    try:
        repo_path = clone_repo(repo_url, branch)
    except RuntimeError as e:
        log(f"FATAL: {e}")
        error_result = {"status": "error", "error": str(e)}
        with open(OUTPUT_DIR / "findings.json", "w") as f:
            json.dump(error_result, f, indent=2)
        print(json.dumps(error_result))
        return

    # Step 2: Detect language
    language = detect_language(repo_path)
    log(f"Primary language detected: {language}")
    log("")

    # Step 3: Install audit tools
    try:
        install_audit_tools(language)
    except Exception as e:
        log(f"WARNING: Tool installation issue: {e}")

    # Step 4: Run all layers (each with independent error handling)
    findings = {}

    # Layer 1: SAST
    try:
        findings["sast"] = layer_1_sast(repo_path, language)
    except Exception as e:
        log(f"ERROR in Layer 1 (SAST): {e}")
        log(traceback.format_exc())
        findings["sast"] = []

    # Layer 2: SCA
    try:
        findings["sca"] = layer_2_sca(repo_path, language)
    except Exception as e:
        log(f"ERROR in Layer 2 (SCA): {e}")
        log(traceback.format_exc())
        findings["sca"] = []

    # Layer 3: Secrets
    try:
        findings["secrets"] = layer_3_secrets(repo_path)
    except Exception as e:
        log(f"ERROR in Layer 3 (Secrets): {e}")
        log(traceback.format_exc())
        findings["secrets"] = []

    # Layer 4: Licenses
    try:
        findings["licenses"] = layer_4_licenses(repo_path, language)
    except Exception as e:
        log(f"ERROR in Layer 4 (Licenses): {e}")
        log(traceback.format_exc())
        findings["licenses"] = []

    # Layer 5: Tests
    try:
        findings["tests"] = layer_5_tests(repo_path, language)
    except Exception as e:
        log(f"ERROR in Layer 5 (Tests): {e}")
        log(traceback.format_exc())
        findings["tests"] = {}

    # Layer 6: Repo Health
    try:
        findings["repo_health"] = layer_6_repo_health(repo_path, language)
    except Exception as e:
        log(f"ERROR in Layer 6 (Repo Health): {e}")
        log(traceback.format_exc())
        findings["repo_health"] = {}

    # Step 5: AI Synthesis (Layer 7)
    key = gradient_key or GRADIENT_KEY
    mdl = model or GRADIENT_MODEL
    try:
        report = layer_7_ai_synthesis(findings, key, mdl)
    except Exception as e:
        log(f"ERROR in Layer 7 (AI Synthesis): {e}")
        log(traceback.format_exc())
        report = _generate_fallback_report(findings)

    # Step 6: Write outputs
    log("")
    log("Writing output files...")
    try:
        with open(OUTPUT_DIR / "report.md", "w") as f:
            f.write(report)
        log(f"  Written: {OUTPUT_DIR / 'report.md'}")
    except Exception as e:
        log(f"  ERROR writing report.md: {e}")

    try:
        with open(OUTPUT_DIR / "findings.json", "w") as f:
            json.dump(findings, f, indent=2, default=str)
        log(f"  Written: {OUTPUT_DIR / 'findings.json'}")
    except Exception as e:
        log(f"  ERROR writing findings.json: {e}")

    # Step 7: Summary
    elapsed = time.time() - start_time
    total_findings = 0
    for key_name, value in findings.items():
        if isinstance(value, list):
            total_findings += len(value)

    log("")
    log("=" * 60)
    log("  Audit Complete")
    log("=" * 60)
    log(f"Language:       {language}")
    log(f"Total findings: {total_findings}")
    log(f"Elapsed:        {elapsed:.1f}s")
    log("")

    # Machine-readable summary on stdout
    summary = {
        "status": "complete",
        "total_findings": total_findings,
        "language": language,
        "elapsed_seconds": round(elapsed, 1),
        "layers": {
            "sast": len(findings.get("sast", [])),
            "sca": len(findings.get("sca", [])),
            "secrets": len(findings.get("secrets", [])),
            "licenses": len(findings.get("licenses", [])),
            "test_files": findings.get("tests", {}).get("test_files", 0),
            "health_checks": len(findings.get("repo_health", {}).get("checks", [])),
        },
    }
    print(json.dumps(summary))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CodeScope 7-Layer Security Audit")
    parser.add_argument("repo_url", help="GitHub repository URL to audit")
    parser.add_argument("--branch", default="main", help="Branch to audit (default: main)")
    parser.add_argument("--gradient-key", default="",
                        help="Gradient AI API key (default: from EPHEMERAL_GRADIENT_KEY env)")
    parser.add_argument("--model", default="openai-gpt-oss-120b",
                        help="AI model to use (default: openai-gpt-oss-120b)")

    args = parser.parse_args()
    run_audit(args.repo_url, args.branch, args.gradient_key, args.model)
'''


def get_codescope_script() -> str:
    """Return the CodeScope audit script for embedding in cloud-init."""
    return CODESCOPE_SCRIPT
