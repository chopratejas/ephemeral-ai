"""CodeScope - AI-Era Security Audit Engine."""

CODESCOPE_SCRIPT = r'''#!/usr/bin/env python3
"""CodeScope - AI-Era Security Audit Engine.

A 7-layer security audit engine that runs inside a DigitalOcean Droplet.
Scans GitHub repos for security vulnerabilities with special focus on
AI-generated code patterns.

Layers:
  1. SAST - Static Analysis (OWASP Top 10 + AI Code + LLM Security)
  2. SCA - Software Composition Analysis + Hallucinated Dependency Detection
  3. Secret Detection (with redaction)
  4. License Compliance
  5. Test Coverage Analysis
  6. Repository Health
  7. AI Synthesis (Gradient AI)

Runs inside an ephemeral DigitalOcean Droplet with Python 3.11+, Node.js 18+,
git, curl, jq, and network access.
"""

import json
import os
import re
import shutil
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
GRADIENT_MODEL = os.environ.get("EPHEMERAL_MODEL", "llama3.3-70b-instruct")
GRADIENT_API_URL = "https://inference.do-ai.run/v1/chat/completions"

OUTPUT_DIR = Path("/tmp/output")
AUDIT_DIR = Path("/opt/audit")
REPO_DIR = AUDIT_DIR / "repo"

# Layer timeouts in seconds
TIMEOUT_CLONE = 120
TIMEOUT_SAST = 90
TIMEOUT_SCA = 60
TIMEOUT_SECRETS = 30
TIMEOUT_LICENSES = 30
TIMEOUT_TESTS = 30
TIMEOUT_HEALTH = 15
TIMEOUT_AI = 120
TIMEOUT_PKG_CHECK = 10

# File/directory exclusion patterns for scanning
EXCLUDED_DIRS = {
    ".git", "node_modules", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", "dist", "build", ".eggs", "venv", ".venv",
    "vendor", ".next", ".nuxt", "coverage", ".nyc_output",
    "bower_components", ".gradle", "target", "out",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".webm", ".ogg", ".flac", ".wav",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".o", ".a",
    ".class", ".jar", ".war", ".ear",
    ".sqlite", ".db", ".sqlite3",
    ".wasm",
}


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
        log(f"  Command timed out ({timeout}s): {cmd[:3] if isinstance(cmd, list) else cmd}")
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
    try:
        if path.stat().st_size > 1_048_576:  # >1MB
            return False
    except OSError:
        return False
    return True


def _iter_repo_files(repo_path: Path):
    """Yield all scannable files in the repo, respecting exclusions."""
    for root, dirs, files in os.walk(repo_path):
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
# Layer 1: SAST (Static Analysis Security Testing) - MASSIVELY EXPANDED
# ---------------------------------------------------------------------------

# OWASP Top 10 Patterns
OWASP_PATTERNS = [
    # --- A03: Injection ---
    ("sql_injection", r"""(?:execute|query|raw)\s*\(\s*f["\']|(?:execute|query|raw)\s*\(\s*["\'].*?\%s|(?:SELECT|INSERT|UPDATE|DELETE|DROP).*?\+\s*(?:req\.|request\.|params\.|query\.)""", "high", "SQL injection via string concatenation"),
    ("nosql_injection", r"""\$where|\$regex.*(?:req\.|request\.|params\.)""", "high", "NoSQL injection vector"),
    ("command_injection", r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|child_process\.exec|child_process\.spawn)\s*\(.*(?:req\.|request\.|input|argv|params)""", "critical", "OS command injection with user input"),
    ("template_injection", r"""render_template_string\s*\(.*(?:request\.|req\.)|\{\{.*(?:request\.|req\.)""", "high", "Server-side template injection"),
    ("xpath_injection", r"""xpath\s*\(.*\+|evaluate\s*\(.*\+""", "medium", "XPath injection"),
    ("ldap_injection", r"""ldap.*(?:search|bind).*(?:req\.|request\.|input)""", "medium", "LDAP injection"),

    # --- A02: Cryptographic Failures ---
    ("weak_hash_password", r"""(?:md5|sha1|sha256)\s*\(.*(?:password|passwd|pwd|secret)""", "critical", "Weak hash for password storage - use bcrypt/argon2"),
    ("hardcoded_crypto_key", r"""(?:secret_key|encryption_key|aes_key|private_key)\s*=\s*["\'][^"\']{8,}["\']""", "critical", "Hardcoded cryptographic key"),
    ("http_sensitive_url", r"""http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|placeholder).*(?:api|auth|login|token|password|secret)""", "medium", "Sensitive endpoint over plain HTTP"),

    # --- A05: Security Misconfiguration ---
    ("debug_mode", r"""(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True|"debug"\s*:\s*true|NODE_ENV.*development)""", "high", "Debug mode enabled - must be disabled in production"),
    ("verbose_errors", r"""(?:traceback\.print_exc|console\.trace|e\.stack|stackTrace|res\.send\(err\)|res\.json\(.*error.*stack)""", "medium", "Verbose error information exposed to client"),
    ("default_password", r"""(?:password|passwd|pwd)\s*[:=]\s*["\'](?:admin|password|123456|default|changeme|test|root)["\']""", "critical", "Default/weak password"),

    # --- A01: Broken Access Control ---
    ("cors_wildcard", r"""(?:Access-Control-Allow-Origin|cors)\s*[:({]\s*["\']?\*["\']?|allowedOrigins.*\*|origin:\s*true""", "high", "CORS allows all origins - restrict to specific domains"),
    ("no_csrf", r"""(?:csrf|xsrf).*(?:disabled|false|off)|(?:CSRF_ENABLED|WTF_CSRF_ENABLED)\s*=\s*False""", "high", "CSRF protection disabled"),

    # --- A08: Integrity Failures ---
    ("unsafe_deserialize_python", r"""(?:pickle\.loads?|yaml\.(?:load|unsafe_load)|shelve\.open|marshal\.loads)\s*\(""", "critical", "Unsafe deserialization - can lead to RCE"),
    ("unsafe_deserialize_js", r"""(?:unserialize|deserialize)\s*\(.*(?:req\.|request\.|body|params|query)""", "high", "Unsafe deserialization of user input"),
    ("eval_usage", r"""(?:^|\s)eval\s*\(|(?:^|\s)exec\s*\(|new\s+Function\s*\(|setTimeout\s*\(["\']|setInterval\s*\(["\']""", "critical", "eval/exec usage - potential code injection"),

    # --- A10: SSRF ---
    ("ssrf_vector", r"""(?:requests\.get|fetch|axios|http\.get|urllib)\s*\(.*(?:req\.|request\.|params\.|query\.|body\.)""", "high", "User-controlled URL in server request (SSRF)"),

    # --- XSS ---
    ("xss_innerhtml", r"""\.innerHTML\s*=|dangerouslySetInnerHTML|v-html\s*=|\.html\s*\(.*(?:req\.|request\.|params)""", "high", "Direct HTML injection - XSS vector"),

    # --- Path Traversal ---
    ("path_traversal", r"""(?:\.\.\/|\.\.\\|path\.join|path\.resolve).*(?:req\.|request\.|params\.|query\.|body\.)""", "high", "Path traversal with user input"),

    # --- Prototype Pollution (JS) ---
    ("prototype_pollution", r"""__proto__|constructor\s*\[\s*["\']prototype["\']|Object\.assign\s*\(\s*\{\}.*(?:req\.|request\.|body)""", "high", "Prototype pollution vector"),
]

# AI-Generated Code Specific Patterns
AI_CODE_PATTERNS = [
    # --- AI01: Missing Input Validation (THE #1 AI FLAW) ---
    ("no_input_validation_express", r"""app\.(?:get|post|put|delete|patch)\s*\(["\'][^"\']+["\']\s*,\s*(?:async\s+)?\(?(?:req|request)\s*,\s*(?:res|response)\s*\)?\s*(?:=>|{)\s*\n\s*(?!.*(?:validate|sanitize|check|joi|zod|yup|express-validator|celebrate))""", "high", "API route with no input validation (common in AI-generated code)"),
    ("no_input_validation_fastapi", r"""@app\.(?:get|post|put|delete)\s*\(\s*["\'][^"\']+["\']\s*\)\s*\n\s*(?:async\s+)?def\s+\w+\s*\(\s*(?!.*(?:Query|Path|Body|Depends|HTTPBearer|Security))""", "high", "FastAPI route with no parameter validation"),
    ("no_input_validation_flask", r"""@app\.route\s*\(.*\)\s*\n\s*def\s+\w+\s*\(\s*\)\s*:\s*\n\s*.*request\.(?:args|form|json|data)\.get\s*\(.*\)\s*\n\s*(?!.*(?:validate|sanitize|bleach|wtforms))""", "medium", "Flask route uses request data without validation"),

    # --- AI02: Hallucinated Dependencies (Slopsquatting) ---
    ("suspicious_import", r"""(?:from|import)\s+(?:ai_utils|ml_helper|data_processor|smart_api|auto_ml|neural_utils|deep_utils)""", "medium", "Potentially hallucinated package name (verify on PyPI/npm)"),

    # --- AI03: Tutorial/Example Code Left in Production ---
    ("todo_security", r"""(?:#|//|/\*)\s*(?:TODO|FIXME|HACK|XXX|TEMP|TEMPORARY).*(?:security|auth|password|token|secret|encrypt|sanitize|validate|permission)""", "high", "Security-related TODO left unfixed"),
    ("example_url", r"""(?:https?://)?(?:example\.com|test\.com|foo\.bar|placeholder|YOUR_API_KEY|YOUR_SECRET|REPLACE_ME|CHANGEME)""", "medium", "Placeholder/example value in code"),
    ("localhost_in_config", r"""(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+.*(?:production|prod|deploy|config)""", "medium", "Localhost URL in production config"),

    # --- AI04: Missing Error Handling ---
    ("empty_catch_python", r"""except(?:\s+\w+)?:\s*\n\s*(?:pass|\.\.\.)\s*$""", "medium", "Empty except block - errors silently swallowed"),
    ("empty_catch_js", r"""catch\s*\(\s*\w*\s*\)\s*\{\s*\}""", "medium", "Empty catch block - errors silently swallowed"),
    ("unhandled_promise", r"""(?:\.then\s*\((?!.*\.catch)|await\s+(?!(?:.*try)))""", "low", "Potentially unhandled promise (missing .catch or try/await)"),

    # --- AI05: Overly Permissive Defaults ---
    ("file_perm_777", r"""chmod\s+777|0o777|0777|os\.chmod.*0o?777""", "high", "File permissions set to 777 (world-writable)"),
    ("no_rate_limit", r"""app\.(?:listen|use)|createServer""", "info", "Server created - verify rate limiting is configured"),
    ("wildcard_allow", r"""allow_all|permit_all|public\s*=\s*true|no_auth|skip_auth""", "medium", "Permissive access pattern detected"),
]

# Prompt Injection / LLM Security Patterns
LLM_SECURITY_PATTERNS = [
    # --- PS01: Prompt Template Injection ---
    ("prompt_injection_fstring", r"""(?:prompt|message|system_prompt|user_message)\s*=\s*f["\'].*\{(?:user|input|query|request|data|text|content)""", "critical", "User input directly in LLM prompt template (prompt injection vector)"),
    ("prompt_injection_concat", r"""(?:prompt|message|system_prompt)\s*(?:\+|\.format|%\s).*(?:user_input|request\.|query|body\.)""", "critical", "User input concatenated into LLM prompt without sanitization"),
    ("prompt_injection_template", r"""(?:ChatPromptTemplate|PromptTemplate|SystemMessage).*\{(?:user|input|query)""", "high", "LangChain/framework prompt template with user input - verify sanitization"),

    # --- PS02: Insecure LLM Integration ---
    ("llm_output_eval", r"""eval\s*\(.*(?:completion|response|output|result|generated|llm|gpt|claude|ai)""", "critical", "Evaluating LLM output as code - extremely dangerous"),
    ("llm_output_html", r"""(?:innerHTML|dangerouslySetInnerHTML|v-html).*(?:completion|response|output|generated|llm|gpt|claude|ai)""", "critical", "Rendering LLM output as HTML - XSS via AI"),
    ("llm_output_sql", r"""(?:execute|query|raw)\s*\(.*(?:completion|response|output|generated|llm|gpt|claude|ai)""", "critical", "Using LLM output in SQL query - injection via AI"),
    ("llm_shell_access", r"""(?:subprocess|os\.system|exec|spawn).*(?:completion|response|output|generated|llm|gpt|claude|ai)""", "critical", "LLM output used in shell command - RCE via AI"),
    ("system_prompt_client", r"""(?:system_prompt|SYSTEM_PROMPT|systemMessage|system_message).*(?:localStorage|sessionStorage|window\.|document\.|export\s+const|export\s+default)""", "high", "System prompt exposed in client-side code"),
    ("no_output_validation", r"""(?:response|completion|result)\s*(?:\.choices\[0\]|\.message|\.content|\.text)\s*(?:;|\))\s*$""", "medium", "LLM output used without validation or sanitization"),

    # --- PS03: RAG Security ---
    ("untrusted_rag_source", r"""(?:add_documents|ingest|index|embed).*(?:url|http|fetch|request|user|upload)""", "medium", "RAG ingestion from potentially untrusted source"),

    # --- PS04: PII in AI ---
    ("pii_to_llm", r"""(?:openai|anthropic|llm|gpt|claude|gradient|inference).*(?:ssn|social_security|credit_card|passport|medical|health|salary|bank_account)""", "high", "Potential PII sent to LLM API without masking"),
    ("logging_llm_pii", r"""(?:log|print|console\.log|logger).*(?:prompt|completion|response|message).*(?:password|token|key|secret|ssn|credit)""", "high", "Logging LLM interactions that may contain sensitive data"),
]

# IPs to exclude from hardcoded IP findings
SAFE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "192.168.0.1",
            "10.0.0.0", "172.16.0.0", "224.0.0.0"}


def _compile_patterns(pattern_list):
    """Compile a list of (name, regex, severity, message) tuples. Returns compiled list."""
    compiled = []
    for entry in pattern_list:
        name, pattern_str, severity, message = entry
        try:
            compiled.append((name, re.compile(pattern_str, re.IGNORECASE | re.MULTILINE), severity, message))
        except re.error as e:
            log(f"  WARNING: Could not compile pattern '{name}': {e}")
    return compiled


def layer_1_sast(repo_path: Path, language: str) -> list:
    """Layer 1: Static Analysis Security Testing - OWASP + AI Code + LLM Security."""
    total_checks = len(OWASP_PATTERNS) + len(AI_CODE_PATTERNS) + len(LLM_SECURITY_PATTERNS)
    log(f"[Layer 1/7] Running SAST analysis... ({total_checks}+ checks)")
    findings = []

    # ---------------------------------------------------------------
    # 1a. Run bandit for Python projects
    # ---------------------------------------------------------------
    if language == "python":
        log("  Running bandit...")
        rc, stdout, stderr = _run(
            ["bandit", "-r", str(repo_path), "-f", "json", "-ll",
             "--exclude", ".git,node_modules,__pycache__,venv,.venv,dist,build"],
            timeout=TIMEOUT_SAST,
        )
        if rc == 0 or (rc == 1 and stdout):
            try:
                bandit_data = json.loads(stdout)
                for result in bandit_data.get("results", []):
                    findings.append({
                        "layer": "sast",
                        "source": "bandit",
                        "file": _rel_path(Path(result.get("filename", "")), repo_path),
                        "line": result.get("line_number", 0),
                        "severity": result.get("issue_severity", "MEDIUM").lower(),
                        "rule": result.get("test_id", "unknown"),
                        "message": result.get("issue_text", ""),
                        "category": "bandit",
                    })
            except json.JSONDecodeError:
                log("  bandit output was not valid JSON")
        else:
            log(f"  bandit returned rc={rc}: {stderr[:200]}")

    # ---------------------------------------------------------------
    # 1b. Compile all regex pattern sets once
    # ---------------------------------------------------------------
    log("  Compiling pattern sets...")
    compiled_owasp = _compile_patterns(OWASP_PATTERNS)
    compiled_ai = _compile_patterns(AI_CODE_PATTERNS)
    compiled_llm = _compile_patterns(LLM_SECURITY_PATTERNS)

    all_compiled = (
        [(name, regex, sev, msg, "owasp") for name, regex, sev, msg in compiled_owasp]
        + [(name, regex, sev, msg, "ai_code") for name, regex, sev, msg in compiled_ai]
        + [(name, regex, sev, msg, "llm_security") for name, regex, sev, msg in compiled_llm]
    )

    # ---------------------------------------------------------------
    # 1c. Scan all files against all patterns
    # ---------------------------------------------------------------
    log("  Scanning files against all pattern sets...")
    file_count = 0
    for fpath in _iter_repo_files(repo_path):
        content = _read_file_safe(fpath)
        if not content:
            continue

        file_count += 1
        rel = _rel_path(fpath, repo_path)

        # For multiline patterns, scan the whole file content
        for name, regex, severity, message, category in all_compiled:
            try:
                for match in regex.finditer(content):
                    # Calculate line number from match position
                    line_num = content[:match.start()].count("\n") + 1

                    # Filter out safe IPs for hardcoded-ip style rules
                    if "hardcoded_ip" in name:
                        ip_text = match.group(0)
                        if any(safe in ip_text for safe in SAFE_IPS):
                            continue

                    findings.append({
                        "layer": "sast",
                        "source": "pattern",
                        "file": rel,
                        "line": line_num,
                        "severity": severity,
                        "rule": name,
                        "message": message,
                        "category": category,
                    })
            except Exception:
                # Individual pattern failures should not stop the scan
                continue

    log(f"  SAST complete: scanned {file_count} files, {len(findings)} findings")
    return findings


# ---------------------------------------------------------------------------
# Layer 2: SCA (Software Composition Analysis) + Hallucinated Dep Detection
# ---------------------------------------------------------------------------

def _check_package_exists_pypi(pkg_name: str) -> bool:
    """Check if a Python package exists on PyPI / is installed."""
    rc, stdout, stderr = _run(
        [sys.executable, "-m", "pip", "index", "versions", pkg_name],
        timeout=TIMEOUT_PKG_CHECK, cwd="/tmp",
    )
    if rc == 0 and stdout.strip():
        return True
    # Fallback: pip show
    rc2, stdout2, stderr2 = _run(
        [sys.executable, "-m", "pip", "show", pkg_name],
        timeout=TIMEOUT_PKG_CHECK, cwd="/tmp",
    )
    return rc2 == 0 and "Name:" in stdout2


def _check_package_exists_npm(pkg_name: str) -> bool:
    """Check if an npm package exists in the registry."""
    rc, stdout, stderr = _run(
        ["npm", "view", pkg_name, "version"],
        timeout=TIMEOUT_PKG_CHECK, cwd="/tmp",
    )
    return rc == 0 and stdout.strip() != ""


def _extract_python_imports(repo_path: Path) -> list:
    """Extract all imported package names from Python files."""
    imports = set()
    stdlib_modules = {
        "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
        "asyncore", "atexit", "audioop", "base64", "bdb", "binascii",
        "binhex", "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb",
        "chunk", "cmath", "cmd", "code", "codecs", "codeop", "collections",
        "colorsys", "compileall", "concurrent", "configparser", "contextlib",
        "contextvars", "copy", "copyreg", "cProfile", "crypt", "csv",
        "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
        "difflib", "dis", "distutils", "doctest", "email", "encodings",
        "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
        "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
        "getpass", "gettext", "glob", "grp", "gzip", "hashlib", "heapq",
        "hmac", "html", "http", "idlelib", "imaplib", "imghdr", "imp",
        "importlib", "inspect", "io", "ipaddress", "itertools", "json",
        "keyword", "lib2to3", "linecache", "locale", "logging", "lzma",
        "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
        "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
        "numbers", "operator", "optparse", "os", "ossaudiodev",
        "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil",
        "platform", "plistlib", "poplib", "posix", "posixpath", "pprint",
        "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr",
        "pydoc", "queue", "quopri", "random", "re", "readline", "reprlib",
        "resource", "rlcompleter", "runpy", "sched", "secrets", "select",
        "selectors", "shelve", "shlex", "shutil", "signal", "site",
        "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "sqlite3",
        "ssl", "stat", "statistics", "string", "stringprep", "struct",
        "subprocess", "sunau", "symtable", "sys", "sysconfig", "syslog",
        "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "test",
        "textwrap", "threading", "time", "timeit", "tkinter", "token",
        "tokenize", "tomllib", "trace", "traceback", "tracemalloc",
        "tty", "turtle", "turtledemo", "types", "typing", "unicodedata",
        "unittest", "urllib", "uu", "uuid", "venv", "warnings", "wave",
        "weakref", "webbrowser", "winreg", "winsound", "wsgiref",
        "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport",
        "zlib", "_thread",
    }

    import_re = re.compile(r'(?:^|\n)\s*(?:from\s+(\S+)\s+import|import\s+(\S+))')

    for fpath in _iter_repo_files(repo_path):
        if fpath.suffix != ".py":
            continue
        content = _read_file_safe(fpath)
        for match in import_re.finditer(content):
            pkg = match.group(1) or match.group(2)
            if pkg:
                top_level = pkg.split(".")[0]
                if top_level not in stdlib_modules and not top_level.startswith("_"):
                    imports.add(top_level)

    return sorted(imports)


def _extract_js_dependencies(repo_path: Path) -> list:
    """Extract dependencies from package.json."""
    deps = []
    pkg_json = repo_path / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(_read_file_safe(pkg_json))
            for dep_name in data.get("dependencies", {}):
                deps.append(dep_name)
            for dep_name in data.get("devDependencies", {}):
                deps.append(dep_name)
        except json.JSONDecodeError:
            pass
    return deps


def layer_2_sca(repo_path: Path, language: str) -> list:
    """Layer 2: Software Composition Analysis + hallucinated dependency detection."""
    log("[Layer 2/7] Running SCA analysis...")
    findings = []

    # ------------------------------------------------------------------
    # 2a. Python: pip-audit
    # ------------------------------------------------------------------
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
                                "layer": "sca",
                                "source": "pip-audit",
                                "package": dep.get("name", "unknown"),
                                "version": dep.get("version", "unknown"),
                                "vulnerability": vuln.get("id", "unknown"),
                                "severity": "high",
                                "fix_version": ", ".join(vuln.get("fix_versions", [])) or "no fix available",
                            })
                except json.JSONDecodeError:
                    log(f"  pip-audit output was not valid JSON for {req_file.name}")

        # Also note additional dependency sources
        for manifest in ["pyproject.toml", "setup.py", "setup.cfg", "Pipfile"]:
            if (repo_path / manifest).exists():
                log(f"  Detected {manifest} (additional dependency source)")

    # ------------------------------------------------------------------
    # 2b. JavaScript: npm audit
    # ------------------------------------------------------------------
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
                        via = vuln_info.get("via", [{}])
                        first_via = via[0] if via else {}
                        vuln_title = (
                            first_via.get("title", "unknown")
                            if isinstance(first_via, dict)
                            else str(first_via)
                        )
                        fix_avail = vuln_info.get("fixAvailable", {})
                        fix_ver = (
                            fix_avail.get("version", "unknown")
                            if isinstance(fix_avail, dict)
                            else "unknown"
                        )
                        findings.append({
                            "layer": "sca",
                            "source": "npm-audit",
                            "package": pkg_name,
                            "version": vuln_info.get("range", "unknown"),
                            "vulnerability": vuln_title,
                            "severity": vuln_info.get("severity", "unknown"),
                            "fix_version": fix_ver,
                        })

                    # npm audit v1 format (fallback)
                    if not vulns and "advisories" in audit_data:
                        for adv_id, advisory in audit_data["advisories"].items():
                            adv_findings = advisory.get("findings", [{}])
                            adv_ver = adv_findings[0].get("version", "unknown") if adv_findings else "unknown"
                            findings.append({
                                "layer": "sca",
                                "source": "npm-audit",
                                "package": advisory.get("module_name", "unknown"),
                                "version": adv_ver,
                                "vulnerability": advisory.get("title", "unknown"),
                                "severity": advisory.get("severity", "unknown"),
                                "fix_version": advisory.get("patched_versions", "unknown"),
                            })
                except json.JSONDecodeError:
                    log("  npm audit output was not valid JSON")

    # ------------------------------------------------------------------
    # 2c. Hallucinated package detection (slopsquatting)
    # ------------------------------------------------------------------
    log("  Checking for hallucinated dependencies...")
    hallucinated_count = 0

    if language == "python":
        py_imports = _extract_python_imports(repo_path)
        # Only check imports that are NOT in requirements files (likely hallucinated)
        req_packages = set()
        for name in ["requirements.txt", "requirements-dev.txt", "requirements-test.txt"]:
            rpath = repo_path / name
            if rpath.exists():
                content = _read_file_safe(rpath)
                for line in content.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("-"):
                        pkg = re.split(r'[><=!~\[]', line)[0].strip().replace("-", "_").lower()
                        req_packages.add(pkg)

        # Check each import that is NOT a local module
        local_modules = set()
        for fpath in _iter_repo_files(repo_path):
            if fpath.suffix == ".py":
                local_modules.add(fpath.stem)
                for parent in fpath.relative_to(repo_path).parents:
                    if str(parent) != ".":
                        local_modules.add(str(parent).split("/")[0].split("\\")[0])

        for imp in py_imports:
            normalized = imp.replace("-", "_").lower()
            if normalized in local_modules:
                continue
            if normalized in req_packages:
                continue
            # Check if it exists on PyPI
            if not _check_package_exists_pypi(imp):
                hallucinated_count += 1
                findings.append({
                    "layer": "sca",
                    "source": "hallucination-check",
                    "package": imp,
                    "severity": "critical",
                    "vulnerability": f"HALLUCINATED DEPENDENCY: Package '{imp}' not found on PyPI (slopsquatting risk)",
                    "fix_version": "Remove or replace with a real package",
                })

    if language in ("javascript", "typescript"):
        js_deps = _extract_js_dependencies(repo_path)
        for dep in js_deps:
            if not _check_package_exists_npm(dep):
                hallucinated_count += 1
                findings.append({
                    "layer": "sca",
                    "source": "hallucination-check",
                    "package": dep,
                    "severity": "critical",
                    "vulnerability": f"HALLUCINATED DEPENDENCY: Package '{dep}' not found on npm (slopsquatting risk)",
                    "fix_version": "Remove or replace with a real package",
                })

    if hallucinated_count > 0:
        log(f"  WARNING: {hallucinated_count} potentially hallucinated package(s) detected!")

    log(f"  SCA complete: {len(findings)} findings")
    return findings


# ---------------------------------------------------------------------------
# Layer 3: Secret Detection
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    # AWS
    (r'AKIA[0-9A-Z]{16}', "aws-access-key", "AWS Access Key ID"),
    (r'(?:aws_secret|secret_key|AWS_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "aws-secret-key", "AWS Secret Access Key"),

    # GCP
    (r'AIza[0-9A-Za-z\-_]{35}', "gcp-api-key", "Google Cloud API key"),
    (r'"type"\s*:\s*"service_account"', "gcp-service-account", "GCP service account JSON"),

    # Azure
    (r'(?:AccountKey|SharedAccessKey)\s*=\s*([A-Za-z0-9+/=]{44,})', "azure-key", "Azure storage/shared access key"),

    # Generic API keys / secrets / tokens
    (r'["\'](?:api[_\-]?key|apikey|token|secret|password|auth)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', "generic-api-key", "Generic API key or secret"),

    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "private-key", "Private key file"),

    # GitHub tokens
    (r'gh[ps]_[A-Za-z0-9_]{36,}', "github-token", "GitHub personal access token"),
    (r'github_pat_[A-Za-z0-9_]{22,}', "github-fine-grained-token", "GitHub fine-grained PAT"),

    # Slack tokens
    (r'xox[baprs]-[0-9a-zA-Z\-]+', "slack-token", "Slack API token"),

    # Stripe
    (r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}', "stripe-key", "Stripe API key"),

    # JWT tokens
    (r'eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*', "jwt-token", "JWT token"),

    # SendGrid
    (r'SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}', "sendgrid-key", "SendGrid API key"),

    # Twilio
    (r'SK[0-9a-fA-F]{32}', "twilio-key", "Twilio API key"),

    # Database connection strings with credentials
    (r'(?:mongodb|postgres|mysql|redis)://[^:]+:[^@]+@', "db-connection-string", "Database connection string with embedded credentials"),

    # Generic high-entropy strings assigned to suspicious variable names
    (r'(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{32,})["\']', "generic-secret", "Potential secret in variable assignment"),

    # Passwords in URLs
    (r'https?://[^:]+:[^@]+@(?!localhost|127\.0\.0\.1)', "password-in-url", "Password embedded in URL"),
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
        # Skip certain file types that commonly have false positives
        if fpath.suffix in (".lock", ".sum"):
            continue
        content = _read_file_safe(fpath)
        if not content:
            continue

        for line_num, line in enumerate(content.split("\n"), start=1):
            for regex, secret_type, description in compiled_patterns:
                match = regex.search(line)
                if match:
                    # Extract the secret value for redaction - NEVER include actual secret
                    secret_value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    redacted = _redact_secret(secret_value)

                    findings.append({
                        "layer": "secrets",
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
                "layer": "secrets",
                "file": ".env",
                "line": 0,
                "type": "committed-env-file",
                "description": ".env file is committed and not in .gitignore - CRITICAL",
                "snippet": "(entire file - secrets redacted)",
            })

    # Also check for other env-like files
    for env_name in [".env.local", ".env.production", ".env.development", ".env.staging"]:
        if (repo_path / env_name).exists():
            findings.append({
                "layer": "secrets",
                "file": env_name,
                "line": 0,
                "type": "committed-env-file",
                "description": f"{env_name} file found in repository",
                "snippet": "(entire file - secrets redacted)",
            })

    log(f"  Secret detection complete: {len(findings)} findings")
    return findings


# ---------------------------------------------------------------------------
# Layer 4: License Compliance
# ---------------------------------------------------------------------------

COPYLEFT_LICENSES = {"gpl", "agpl", "lgpl", "gpl-2.0", "gpl-3.0",
                     "agpl-3.0", "lgpl-2.1", "lgpl-3.0", "gpl-2.0-only",
                     "gpl-3.0-only", "agpl-3.0-only", "eupl",
                     "osl-3.0", "cecill"}
PERMISSIVE_LICENSES = {"mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause",
                       "isc", "0bsd", "unlicense", "cc0-1.0", "wtfpl",
                       "zlib", "artistic-2.0"}


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
            if "agpl" in content:
                return "AGPL"
            if "gpl" in content or "gnu general public" in content:
                return "GPL"
            return "detected (unknown type)"

    # Check package.json
    pkg_json = repo_path / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(_read_file_safe(pkg_json))
            return data.get("license", "")
        except json.JSONDecodeError:
            pass

    # Check pyproject.toml
    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists():
        content = _read_file_safe(pyproject)
        license_match = re.search(r'license\s*=\s*["\']([^"\']+)["\']', content)
        if license_match:
            return license_match.group(1)

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
                    "layer": "licenses",
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
                        "layer": "licenses",
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
        "ci_runs_tests": False,
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
                lines = [l for l in stdout.strip().split("\n") if l.strip()]
                if lines:
                    last = lines[-1]
                    match = re.search(r'(\d+)\s+test', last)
                    if match:
                        result["estimated_tests"] = int(match.group(1))
                    else:
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

        # Count test cases via regex
        if test_files:
            log("  Counting JavaScript/TypeScript test cases...")
            count = 0
            for tf in test_files:
                content = _read_file_safe(tf)
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
# Layer 6: Repository Health & Structure (EXPANDED)
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

    # .env.example (good practice)
    env_example_exists = any((repo_path / name).exists()
                              for name in [".env.example", ".env.sample", ".env.template"])
    checks.append({
        "name": ".env.example",
        "status": "pass" if env_example_exists else "info",
        "details": ".env.example found (good practice)" if env_example_exists
                   else "No .env.example - consider adding one to document required environment variables",
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

    # Input validation library
    validation_libs = {
        "python": ["pydantic", "marshmallow", "cerberus", "wtforms", "voluptuous"],
        "javascript": ["joi", "zod", "yup", "express-validator", "celebrate", "ajv", "class-validator"],
    }
    has_validation_lib = False
    target_lang = "javascript" if language in ("javascript", "typescript") else language
    if target_lang in validation_libs:
        if target_lang == "python":
            for req_name in ["requirements.txt", "requirements-dev.txt", "pyproject.toml"]:
                req_path = repo_path / req_name
                if req_path.exists():
                    content = _read_file_safe(req_path).lower()
                    for lib in validation_libs["python"]:
                        if lib in content:
                            has_validation_lib = True
                            break
                if has_validation_lib:
                    break
        elif target_lang == "javascript":
            pkg_json_path = repo_path / "package.json"
            if pkg_json_path.exists():
                content = _read_file_safe(pkg_json_path).lower()
                for lib in validation_libs["javascript"]:
                    if lib in content:
                        has_validation_lib = True
                        break

    checks.append({
        "name": "Input Validation Library",
        "status": "pass" if has_validation_lib else "warning",
        "details": "Input validation library detected" if has_validation_lib
                   else "No input validation library found - strongly recommended for API projects",
    })

    # Rate limiting configuration
    has_rate_limiting = False
    rate_limit_indicators = [
        "express-rate-limit", "rate-limit", "ratelimit", "throttle",
        "slowapi", "flask-limiter", "django-ratelimit",
    ]
    for fpath in _iter_repo_files(repo_path):
        if fpath.name in ("package.json", "requirements.txt", "pyproject.toml"):
            content = _read_file_safe(fpath).lower()
            for indicator in rate_limit_indicators:
                if indicator in content:
                    has_rate_limiting = True
                    break
        if has_rate_limiting:
            break

    checks.append({
        "name": "Rate Limiting",
        "status": "pass" if has_rate_limiting else "warning",
        "details": "Rate limiting library detected" if has_rate_limiting
                   else "No rate limiting library found - recommended for public-facing APIs",
    })

    # Authentication middleware
    has_auth = False
    auth_indicators = [
        "passport", "jsonwebtoken", "jwt", "express-jwt", "auth0",
        "flask-login", "flask-jwt", "django-auth", "python-jose",
        "authlib", "oauth", "firebase-admin", "next-auth",
        "clerk", "supabase", "lucia",
    ]
    for fpath in _iter_repo_files(repo_path):
        if fpath.name in ("package.json", "requirements.txt", "pyproject.toml"):
            content = _read_file_safe(fpath).lower()
            for indicator in auth_indicators:
                if indicator in content:
                    has_auth = True
                    break
        if has_auth:
            break

    checks.append({
        "name": "Authentication",
        "status": "pass" if has_auth else "info",
        "details": "Authentication library detected" if has_auth
                   else "No authentication library detected - may not be needed for all projects",
    })

    # HTTPS/TLS configuration
    has_tls = False
    tls_indicators = ["https", "ssl", "tls", "cert", "certificate"]
    for cfg_name in ["docker-compose.yml", "docker-compose.yaml", "nginx.conf",
                     "Caddyfile", "traefik.yml", "traefik.yaml"]:
        cfg_path = repo_path / cfg_name
        if cfg_path.exists():
            content = _read_file_safe(cfg_path).lower()
            for indicator in tls_indicators:
                if indicator in content:
                    has_tls = True
                    break
        if has_tls:
            break

    checks.append({
        "name": "HTTPS/TLS",
        "status": "pass" if has_tls else "info",
        "details": "TLS/HTTPS configuration detected" if has_tls
                   else "No explicit HTTPS/TLS configuration found - may be handled by hosting provider",
    })

    # Dockerfile analysis
    dockerfile = repo_path / "Dockerfile"
    if dockerfile.exists():
        df_content = _read_file_safe(dockerfile)
        has_user = bool(re.search(r'^USER\s+\S+', df_content, re.MULTILINE))
        has_healthcheck = bool(re.search(r'^HEALTHCHECK\s', df_content, re.MULTILINE))
        issues = []
        if not has_user:
            issues.append("no USER directive (runs as root)")
        if not has_healthcheck:
            issues.append("no HEALTHCHECK")
        status = "pass" if not issues else "warning"
        details = "Dockerfile security OK" if not issues else f"Dockerfile issues: {', '.join(issues)}"
        checks.append({
            "name": "Dockerfile Security",
            "status": status,
            "details": details,
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
# Layer 7: AI Synthesis (Gradient AI) - UPDATED PROMPT
# ---------------------------------------------------------------------------

AI_SYNTHESIS_SYSTEM_PROMPT = """\
You are a senior application security engineer specializing in AI-generated code security.
You are reviewing findings from a 7-layer security audit. This audit specifically targets
vulnerabilities common in code written by AI assistants (Claude, Cursor, Copilot).

Your analysis MUST include:

1. EXECUTIVE SUMMARY (3-4 sentences for non-technical stakeholders)
2. RISK SCORE (0-100, where 0=perfect, 100=critical risk)
3. AI CODE SAFETY SECTION - specifically call out:
   - Prompt injection vulnerabilities
   - Hallucinated/suspicious dependencies
   - Missing input validation (the #1 AI code flaw)
   - AI-specific anti-patterns found
4. FINDINGS BY SEVERITY (Critical/High/Medium/Low/Info)
   For each Critical/High finding:
   - Plain English explanation
   - Why AI generates this pattern
   - Specific remediation steps
   - Code example of the fix
5. CROSS-LAYER INSIGHTS
   - A dependency CVE in untested code = escalate to Critical
   - A secret in a file without .gitignore protection = Critical
   - Prompt injection + no output validation = Critical chain
6. SUPPLY CHAIN ASSESSMENT
   - Any hallucinated packages?
   - License risks?
   - Outdated dependencies?

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
    max_findings_chars = 14000
    if len(findings_json) > max_findings_chars:
        findings_json = findings_json[:max_findings_chars] + "\n... (truncated)"

    user_message = (
        "Here are the findings from all 7 automated analysis layers for a code repository audit. "
        "This audit specifically targets AI-generated code patterns. "
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
        f"# CodeScope: AI-Era Security Audit Report",
        f"",
        f"**Generated:** {timestamp}",
        f"**Engine:** CodeScope 7-Layer AI Security Audit",
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
        by_category = {}
        for f in sast:
            sev = f.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cat = f.get("category", "unknown")
            by_category[cat] = by_category.get(cat, 0) + 1
        sections.append(f"**By severity:** {', '.join(f'{k}: {v}' for k, v in sorted(by_severity.items()))}")
        sections.append(f"**By category:** {', '.join(f'{k}: {v}' for k, v in sorted(by_category.items()))}")

        # Show critical and high findings
        critical_high = [f for f in sast if f.get("severity") in ("critical", "high")]
        if critical_high:
            sections.append("")
            sections.append("**Critical/High findings:**")
            for f in critical_high[:15]:
                sections.append(f"- [{f.get('severity').upper()}] `{f.get('file')}` L{f.get('line')}: "
                              f"{f.get('rule')} - {f.get('message')}")
            if len(critical_high) > 15:
                sections.append(f"- ... and {len(critical_high) - 15} more critical/high findings")
    else:
        sections.append("No SAST findings.")
    sections.append("")

    # Layer 2: SCA
    sca = findings.get("sca", [])
    sections.append(f"### Layer 2: SCA ({len(sca)} findings)")
    if sca:
        hallucinated = [f for f in sca if f.get("source") == "hallucination-check"]
        vuln_deps = [f for f in sca if f.get("source") != "hallucination-check"]

        if hallucinated:
            sections.append("")
            sections.append("**HALLUCINATED DEPENDENCIES (Slopsquatting Risk):**")
            for f in hallucinated:
                sections.append(f"- CRITICAL: `{f.get('package')}` - {f.get('vulnerability')}")

        if vuln_deps:
            sections.append("")
            sections.append("**Vulnerable Dependencies:**")
            for f in vuln_deps[:10]:
                sections.append(f"- **{f.get('package')}** {f.get('version')}: "
                              f"{f.get('vulnerability')} (fix: {f.get('fix_version')})")
            if len(vuln_deps) > 10:
                sections.append(f"- ... and {len(vuln_deps) - 10} more")
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
    sections.append(f"- CI runs tests: {'Yes' if tests.get('ci_runs_tests') else 'No'}")
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
    sections.append("*Report generated by CodeScope: AI-Era Security Audit Engine*")

    return "\n".join(sections)


def _calculate_risk_score(findings: dict) -> int:
    """Calculate a heuristic risk score from 0-100."""
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
        cat = f.get("category", "")
        base = {"critical": 8, "high": 5, "medium": 2, "low": 1, "info": 0}.get(sev, 1)
        # AI-specific and LLM findings get a multiplier
        if cat in ("ai_code", "llm_security"):
            base = int(base * 1.5)
        risk_score += base

    # Score from SCA
    for f in sca:
        if f.get("source") == "hallucination-check":
            risk_score += 20  # Hallucinated deps are extremely dangerous
        else:
            risk_score += 8

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

    # Cross-layer escalation: secrets without .gitignore
    has_gitignore = False
    for check in health.get("checks", []):
        if check.get("name") == ".gitignore" and check.get("status") == "pass":
            has_gitignore = True
    if secrets and not has_gitignore:
        risk_score += 15  # Escalate

    # Cross-layer escalation: CVEs in untested code
    if sca and tests.get("test_files", 0) == 0:
        risk_score += 10  # Escalate

    return min(100, risk_score)


def _generate_fallback_report(findings: dict) -> str:
    """Generate a basic report without AI when Gradient AI is unavailable."""
    log("  Generating fallback report (no AI synthesis)...")

    risk_score = _calculate_risk_score(findings)

    sast = findings.get("sast", [])
    sca = findings.get("sca", [])
    secrets = findings.get("secrets", [])
    licenses = findings.get("licenses", [])
    tests = findings.get("tests", {})
    violations = [f for f in licenses if f.get("status") == "violation"]

    # Separate AI-specific findings
    ai_sast = [f for f in sast if f.get("category") in ("ai_code", "llm_security")]
    hallucinated = [f for f in sca if f.get("source") == "hallucination-check"]

    ai_section = (
        f"## AI Security Analysis\n\n"
        f"*AI synthesis was unavailable. Below is an automated summary.*\n\n"
        f"### Risk Score: {risk_score}/100\n\n"
        f"### Executive Summary\n\n"
        f"This repository has {len(sast)} static analysis findings "
        f"({len(ai_sast)} AI-code-specific), "
        f"{len(sca)} dependency findings "
        f"({len(hallucinated)} potentially hallucinated), "
        f"{len(secrets)} potential secret exposures, and "
        f"{len(violations)} license compliance violations. "
    )

    if tests.get("test_files", 0) == 0:
        ai_section += "No test files were detected, increasing overall risk."
    else:
        ai_section += f"{tests.get('test_files', 0)} test files were found."
    ai_section += "\n\n"

    # AI Code Safety Section
    ai_section += "### AI Code Safety\n\n"
    if ai_sast or hallucinated:
        if hallucinated:
            ai_section += "**Hallucinated Dependencies (CRITICAL):**\n"
            for h in hallucinated:
                ai_section += f"- `{h.get('package')}`: {h.get('vulnerability')}\n"
            ai_section += "\n"

        llm_findings = [f for f in sast if f.get("category") == "llm_security"]
        if llm_findings:
            ai_section += "**LLM/Prompt Security Issues:**\n"
            for f in llm_findings[:5]:
                ai_section += f"- [{f.get('severity').upper()}] `{f.get('file')}` L{f.get('line')}: {f.get('message')}\n"
            ai_section += "\n"

        ai_specific = [f for f in sast if f.get("category") == "ai_code"]
        if ai_specific:
            ai_section += "**AI-Generated Code Anti-Patterns:**\n"
            for f in ai_specific[:5]:
                ai_section += f"- [{f.get('severity').upper()}] `{f.get('file')}` L{f.get('line')}: {f.get('message')}\n"
            ai_section += "\n"
    else:
        ai_section += "No AI-specific code issues detected.\n\n"

    # Critical findings
    ai_section += "### Critical Findings\n\n"

    if secrets:
        ai_section += "**Exposed Secrets:**\n"
        for s in secrets[:5]:
            ai_section += f"- {s.get('type')} in `{s.get('file')}` (line {s.get('line')})\n"
        ai_section += "\n"

    if sca:
        vuln_deps = [f for f in sca if f.get("source") != "hallucination-check"]
        if vuln_deps:
            ai_section += "**Vulnerable Dependencies:**\n"
            for v in vuln_deps[:5]:
                ai_section += f"- {v.get('package')} {v.get('version')}: {v.get('vulnerability')}\n"
            ai_section += "\n"

    critical_high_sast = [f for f in sast if f.get("severity") in ("critical", "high")]
    if critical_high_sast:
        ai_section += "**Critical/High-Severity Code Issues:**\n"
        for h in critical_high_sast[:10]:
            ai_section += f"- [{h.get('severity').upper()}] {h.get('rule')} in `{h.get('file')}` line {h.get('line')}: {h.get('message')}\n"
        ai_section += "\n"

    # Cross-layer insights
    ai_section += "### Cross-Layer Insights\n\n"
    cross_insights = []
    if sca and tests.get("test_files", 0) == 0:
        cross_insights.append("- ESCALATED: Dependency vulnerabilities found in code with NO test coverage")
    if secrets:
        has_gitignore = False
        for check in findings.get("repo_health", {}).get("checks", []):
            if check.get("name") == ".gitignore" and check.get("status") == "pass":
                has_gitignore = True
        if not has_gitignore:
            cross_insights.append("- ESCALATED: Secrets found with no .gitignore protection")

    prompt_injection = [f for f in sast if "prompt_injection" in f.get("rule", "")]
    no_output_val = [f for f in sast if f.get("rule") == "no_output_validation"]
    if prompt_injection and no_output_val:
        cross_insights.append("- ESCALATED: Prompt injection + no output validation = critical attack chain")

    if cross_insights:
        for ci in cross_insights:
            ai_section += ci + "\n"
    else:
        ai_section += "No cross-layer escalations identified.\n"

    return _build_full_report(findings, ai_section)


# ---------------------------------------------------------------------------
# Clone and main audit orchestration
# ---------------------------------------------------------------------------

def clone_repo(repo_url: str, branch: str = "main") -> Path:
    """Clone the repository. Falls back to default branch if specified branch fails."""
    log(f"Cloning repository: {repo_url} (branch: {branch})")

    repo_path = REPO_DIR
    if repo_path.exists():
        shutil.rmtree(str(repo_path))

    # Try specified branch first
    rc, stdout, stderr = _run(
        ["git", "clone", "--depth", "1", "--branch", branch, repo_url, str(repo_path)],
        timeout=TIMEOUT_CLONE, cwd="/tmp",
    )

    if rc != 0:
        log(f"  Branch '{branch}' failed, trying without --branch...")
        if repo_path.exists():
            shutil.rmtree(str(repo_path))

        rc, stdout, stderr = _run(
            ["git", "clone", "--depth", "1", repo_url, str(repo_path)],
            timeout=TIMEOUT_CLONE, cwd="/tmp",
        )

        if rc != 0:
            raise RuntimeError(f"Failed to clone repository: {stderr[:500]}")

    log(f"  Clone complete.")
    return repo_path


def run_audit(repo_url: str, branch: str = "main",
              gradient_key: str = "", model: str = "llama3.3-70b-instruct") -> None:
    """Execute the full 7-layer CodeScope audit."""
    start_time = time.time()
    _ensure_dirs()

    log("=" * 60)
    log("  CodeScope: AI-Era Security Audit")
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

    risk_score = _calculate_risk_score(findings)

    log("")
    log("=" * 60)
    log("  Audit Complete")
    log("=" * 60)
    log(f"Language:       {language}")
    log(f"Total findings: {total_findings}")
    log(f"Risk score:     {risk_score}/100")
    log(f"Elapsed:        {elapsed:.1f}s")
    log("")

    # Machine-readable summary on stdout
    summary = {
        "status": "complete",
        "total_findings": total_findings,
        "risk_score": risk_score,
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

    parser = argparse.ArgumentParser(description="CodeScope: AI-Era Security Audit")
    parser.add_argument("repo_url", help="GitHub repository URL to audit")
    parser.add_argument("--branch", default="main", help="Branch to audit (default: main)")
    parser.add_argument("--gradient-key", default="",
                        help="Gradient AI API key (default: from EPHEMERAL_GRADIENT_KEY env)")
    parser.add_argument("--model", default=os.environ.get("EPHEMERAL_MODEL", "llama3.3-70b-instruct"),
                        help="AI model to use (default: llama3.3-70b-instruct)")

    args = parser.parse_args()
    run_audit(args.repo_url, args.branch, args.gradient_key, args.model)
'''


def get_codescope_script() -> str:
    """Return the CodeScope audit script for embedding in cloud-init."""
    return CODESCOPE_SCRIPT
