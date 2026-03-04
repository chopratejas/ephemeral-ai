"""Worker Daemon - Long-lived multi-task executor for ephemeral Droplets.

This script runs INSIDE a DigitalOcean Droplet. Unlike the one-shot workbench
agent, the daemon stays alive for up to 55 minutes (fitting within the 1-hour
billing window) and processes MULTIPLE tasks by polling the Orchestrator API.

Lifecycle:
  1. Register with Orchestrator as idle
  2. Poll for assigned tasks
  3. For each task: generate code via Gradient AI, execute, self-heal, upload
  4. Return to idle and poll again
  5. At 55 minutes, gracefully shut down

The daemon supports multi-language code generation: Python, TypeScript, and Bash.
The Gradient AI LLM chooses the best language for each task.
"""

WORKER_DAEMON_SCRIPT = r'''#!/usr/bin/env python3
"""Ephemeral.ai Worker Daemon - long-lived multi-task executor.

Runs inside a DigitalOcean Droplet. Processes multiple tasks within the
billing hour, communicating with the Orchestrator API for task assignment
and status reporting.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration (injected via cloud-init environment variables)
# ---------------------------------------------------------------------------

WORKER_ID = os.environ["EPHEMERAL_WORKER_ID"]
ORCHESTRATOR_URL = os.environ["EPHEMERAL_ORCHESTRATOR_URL"].rstrip("/")
GRADIENT_KEY = os.environ["EPHEMERAL_GRADIENT_KEY"]
GRADIENT_MODEL = os.environ.get("EPHEMERAL_MODEL", "llama3.3-70b-instruct")
SPACES_REGION = os.environ.get("EPHEMERAL_SPACES_REGION", "sfo3")

GRADIENT_API_URL = "https://inference.do-ai.run/v1/chat/completions"

MAX_HEAL_ATTEMPTS = 3
POLL_INTERVAL_SECONDS = 3
MAX_ALIVE_MINUTES = 55
CODE_EXECUTION_TIMEOUT = 300  # seconds per execution attempt

WORK_DIR = Path("/opt/task")
OUTPUT_DIR = Path("/tmp/output")
LOG_DIR = Path("/var/log/ephemeral")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FILE = LOG_DIR / "worker_daemon.log"


def _ensure_dirs():
    """Create all required directories."""
    for d in [WORK_DIR, OUTPUT_DIR, LOG_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def log(msg: str) -> None:
    """Write a timestamped line to both stdout and the log file."""
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_shutdown_requested = False


def _handle_signal(signum, _frame):
    global _shutdown_requested
    log(f"Received signal {signum}, requesting graceful shutdown...")
    _shutdown_requested = True


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only - no external deps required for the daemon itself)
# ---------------------------------------------------------------------------

def _http_request(url: str, *, method: str = "GET", data: dict | None = None,
                  headers: dict | None = None, timeout: int = 30) -> dict | None:
    """Make an HTTP request and return parsed JSON, or None on failure."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)

    body = json.dumps(data).encode() if data is not None else None

    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)

    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        resp_body = ""
        try:
            resp_body = e.read().decode()[:500]
        except Exception:
            pass
        log(f"HTTP {e.code} from {method} {url}: {resp_body}")
        return None
    except Exception as e:
        log(f"HTTP error for {method} {url}: {e}")
        return None


def _http_put_bytes(url: str, data: bytes, content_type: str = "application/octet-stream",
                    timeout: int = 120) -> bool:
    """PUT raw bytes to a URL (for presigned uploads). Returns True on success."""
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": content_type},
        method="PUT",
    )
    try:
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception as e:
        log(f"PUT upload failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Orchestrator communication
# ---------------------------------------------------------------------------

def post_status(status: str, extra: dict | None = None) -> dict | None:
    """POST worker status to the Orchestrator."""
    url = f"{ORCHESTRATOR_URL}/api/v1/workers/{WORKER_ID}/status"
    payload = {"status": status}
    if extra:
        payload.update(extra)
    return _http_request(url, method="POST", data=payload)


def poll_for_task() -> dict | None:
    """GET the next task assigned to this worker. Returns None if no task."""
    url = f"{ORCHESTRATOR_URL}/api/v1/workers/{WORKER_ID}/task"
    result = _http_request(url, method="GET")
    if not result:
        return None
    # API wraps in {"task": {...}} - unwrap it
    task = result.get("task") or result
    if task and task.get("task_id"):
        return task
    return None


def post_task_status(task_id: str, status: str, phase: str = "",
                     extra: dict | None = None) -> None:
    """Notify the Orchestrator of a task-level status change."""
    url = f"{ORCHESTRATOR_URL}/api/v1/tasks/{task_id}/callback"
    payload = {"status": status, "phase": phase}
    if extra:
        payload.update(extra)
    _http_request(url, method="POST", data=payload, timeout=10)


# ---------------------------------------------------------------------------
# Gradient AI (LLM) communication
# ---------------------------------------------------------------------------

CODE_GEN_SYSTEM_PROMPT = """\
You are a code generation AI running inside an ephemeral Linux VM (Ubuntu 22.04).
The VM has Python 3.11+, Node.js 18+, and standard GNU/Linux utilities installed.

The user will describe a task. Generate COMPLETE, SELF-CONTAINED code that:
1. Accomplishes the task fully
2. Writes ALL output files to /tmp/output/
3. Prints a summary of what was done to stdout
4. Handles errors gracefully
5. Is immediately runnable without modification

LANGUAGE SELECTION - choose the best language for the task:

**Python** (default for most tasks):
- Best for: data processing, ML, scraping, file manipulation, API calls, analysis
- Use standard library + common pip packages (requests, pandas, numpy, etc.)
- Available packages will be auto-installed

**TypeScript** (for type-safe or web-focused work):
- Best for: API integrations with complex schemas, JSON transformations, type-safe data pipelines
- Use strict mode ("strict": true in tsconfig)
- Use built-in fetch() for HTTP (Node 18+)
- Include full type annotations
- Use npm packages when needed (they will be auto-installed)
- Target: ES2022, module: Node16

**Bash** (for system-level tasks):
- Best for: file operations, system administration, piping commands, text processing with awk/sed/grep
- Use set -euo pipefail at the top
- Use standard GNU/Linux utilities

RESPONSE FORMAT:
You MUST wrap your code in a fenced code block with the language identifier:

```python
# your python code here
```

```typescript
// your typescript code here
```

```bash
#!/bin/bash
# your bash code here
```

RULES:
- Output ONLY a single fenced code block. No explanations before or after.
- The code must be complete and runnable as-is.
- Write output files to /tmp/output/ (directory already exists).
- You have full network access for HTTP requests.
- For Python AI tasks, you can call Gradient AI at https://inference.do-ai.run/v1/
  using the API key in environment variable EPHEMERAL_GRADIENT_KEY.
- NEVER include hardcoded secrets, API keys, or passwords.
- NEVER run destructive commands (rm -rf /, mkfs, dd on devices, etc.).
- NEVER attempt to access the cloud metadata endpoint (169.254.169.254).
"""

FIX_CODE_PROMPT = """\
The previous code FAILED. Fix it.

TASK DESCRIPTION:
{task}

LANGUAGE: {language}

CODE THAT FAILED:
```{language}
{code}
```

ERROR OUTPUT:
```
{error}
```

Instructions:
- Fix the SPECIFIC error shown above.
- Keep the same overall approach and language ({language}).
- Output ONLY the corrected code in a fenced ```{language} block.
- Make sure the fix addresses the root cause, not just the symptom.
- If a dependency is missing, add the appropriate import/require.
"""


def call_gradient(messages: list[dict]) -> str:
    """Call Gradient AI and return the assistant's response text."""
    payload = {
        "model": GRADIENT_MODEL,
        "messages": messages,
        "temperature": 0.1,
        "max_completion_tokens": 4096,
    }
    req = urllib.request.Request(
        GRADIENT_API_URL,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GRADIENT_KEY}",
        },
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=180)
    result = json.loads(resp.read().decode())
    return result["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Code extraction and language detection
# ---------------------------------------------------------------------------

SUPPORTED_LANGUAGES = {"python", "typescript", "bash"}

# Map of aliases to canonical language names
LANGUAGE_ALIASES = {
    "python": "python",
    "python3": "python",
    "py": "python",
    "typescript": "typescript",
    "ts": "typescript",
    "bash": "bash",
    "sh": "bash",
    "shell": "bash",
}


def extract_code_and_language(response: str) -> tuple[str, str]:
    """Extract code and detect language from the LLM response.

    Returns (code, language) where language is one of: python, typescript, bash.
    Falls back to python if detection fails.
    """
    text = response.strip()

    # Try to find a fenced code block with a language identifier
    for lang_tag, canonical in LANGUAGE_ALIASES.items():
        fence = f"```{lang_tag}"
        if fence in text.lower():
            # Find the fence (case-insensitive)
            idx = text.lower().find(fence)
            after_fence = text[idx + len(fence):]
            # Skip to the next newline (handles ```python3\n, ```typescript\n, etc.)
            newline_idx = after_fence.find("\n")
            if newline_idx == -1:
                continue
            code_block = after_fence[newline_idx + 1:]
            # Find closing fence
            end_idx = code_block.find("```")
            if end_idx != -1:
                code_block = code_block[:end_idx]
            return code_block.strip(), canonical

    # Fallback: try generic ``` fences
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 3:
            code_block = parts[1]
            # The first line might be a language tag
            first_line = code_block.split("\n", 1)[0].strip().lower()
            if first_line in LANGUAGE_ALIASES:
                code_block = code_block.split("\n", 1)[1] if "\n" in code_block else ""
                return code_block.strip(), LANGUAGE_ALIASES[first_line]
            # No language tag - try to infer from content
            return code_block.strip(), _infer_language(code_block)

    # No fences at all - treat entire response as code
    return text, _infer_language(text)


def _infer_language(code: str) -> str:
    """Heuristically infer the language of a code snippet."""
    # TypeScript indicators
    ts_indicators = [
        "interface ", "type ", ": string", ": number", ": boolean",
        "import {", "export ", "async function", "=> {",
        "const ", "let ", ".ts",
    ]
    # Bash indicators
    bash_indicators = [
        "#!/bin/bash", "#!/bin/sh", "set -e", "set -u",
        "if [", "then", "fi", "done", "esac",
        "echo ", "grep ", "awk ", "sed ",
    ]

    ts_score = sum(1 for ind in ts_indicators if ind in code)
    bash_score = sum(1 for ind in bash_indicators if ind in code)

    if bash_score >= 3:
        return "bash"
    if ts_score >= 3:
        return "typescript"
    return "python"


# ---------------------------------------------------------------------------
# Dependency installation
# ---------------------------------------------------------------------------

# Python packages: import name -> pip package name
PYTHON_INSTALLABLE = {
    "requests": "requests",
    "pandas": "pandas",
    "numpy": "numpy",
    "matplotlib": "matplotlib",
    "bs4": "beautifulsoup4",
    "BeautifulSoup": "beautifulsoup4",
    "PIL": "Pillow",
    "yaml": "pyyaml",
    "scipy": "scipy",
    "sklearn": "scikit-learn",
    "flask": "flask",
    "fastapi": "fastapi",
    "httpx": "httpx",
    "aiohttp": "aiohttp",
    "lxml": "lxml",
    "openpyxl": "openpyxl",
    "tabulate": "tabulate",
    "rich": "rich",
    "jinja2": "jinja2",
    "markdown": "markdown",
    "seaborn": "seaborn",
    "plotly": "plotly",
    "xlsxwriter": "xlsxwriter",
    "cssselect": "cssselect",
    "html5lib": "html5lib",
    "chardet": "chardet",
    "tqdm": "tqdm",
    "pyarrow": "pyarrow",
}


def install_python_deps(code: str) -> None:
    """Detect and pip-install Python dependencies from import statements."""
    to_install = set()
    for line in code.split("\n"):
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            for mod, pkg in PYTHON_INSTALLABLE.items():
                if mod in stripped:
                    to_install.add(pkg)

    if to_install:
        pkgs = sorted(to_install)
        log(f"Installing Python dependencies: {', '.join(pkgs)}")
        # Try with --break-system-packages first, fall back without
        cmd = [sys.executable, "-m", "pip", "install", "--quiet"]
        result = subprocess.run(
            cmd + ["--break-system-packages"] + pkgs,
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0 and "no such option" in result.stderr:
            result = subprocess.run(
                cmd + pkgs,
                capture_output=True, text=True, timeout=120,
            )
        if result.returncode != 0:
            log(f"pip install warning: {result.stderr[:500]}")


def install_typescript_deps(code: str) -> None:
    """Detect and npm-install TypeScript/Node dependencies."""
    # Common npm packages that might be imported
    npm_packages = {
        "axios": "axios",
        "lodash": "lodash",
        "cheerio": "cheerio",
        "csv-parse": "csv-parse",
        "csv-parser": "csv-parser",
        "node-fetch": "node-fetch",
        "zod": "zod",
        "date-fns": "date-fns",
        "uuid": "uuid",
        "chalk": "chalk",
        "glob": "glob",
        "yaml": "yaml",
        "marked": "marked",
        "json5": "json5",
        "papaparse": "papaparse",
        "fast-csv": "fast-csv",
    }
    to_install = set()
    for line in code.split("\n"):
        stripped = line.strip()
        if "require(" in stripped or "from '" in stripped or 'from "' in stripped:
            for mod, pkg in npm_packages.items():
                if mod in stripped:
                    to_install.add(pkg)

    # Always need typescript for compilation
    to_install.add("typescript")
    to_install.add("@types/node")

    pkgs = sorted(to_install)
    log(f"Installing TypeScript/Node dependencies: {', '.join(pkgs)}")

    # Initialize a package.json if needed
    pkg_json = WORK_DIR / "package.json"
    if not pkg_json.exists():
        pkg_json.write_text(json.dumps({
            "name": "ephemeral-task",
            "version": "1.0.0",
            "private": True,
        }))

    result = subprocess.run(
        ["npm", "install", "--save"] + pkgs,
        capture_output=True, text=True, timeout=120,
        cwd=str(WORK_DIR),
    )
    if result.returncode != 0:
        log(f"npm install warning: {result.stderr[:500]}")


# ---------------------------------------------------------------------------
# Code execution (multi-language)
# ---------------------------------------------------------------------------

def write_tsconfig(work_dir: Path) -> None:
    """Write a tsconfig.json for TypeScript compilation."""
    config = {
        "compilerOptions": {
            "target": "ES2022",
            "module": "Node16",
            "moduleResolution": "Node16",
            "strict": True,
            "esModuleInterop": True,
            "skipLibCheck": True,
            "outDir": "./dist",
            "rootDir": ".",
            "resolveJsonModule": True,
            "declaration": False,
            "sourceMap": False,
        },
        "include": ["*.ts"],
    }
    tsconfig_path = work_dir / "tsconfig.json"
    tsconfig_path.write_text(json.dumps(config, indent=2))


def execute_code(code: str, language: str, attempt: int) -> tuple[bool, str, str]:
    """Write code to a file and execute it.

    Handles Python, TypeScript, and Bash.
    Returns (success, stdout, stderr).
    """
    if language == "python":
        return _execute_python(code, attempt)
    elif language == "typescript":
        return _execute_typescript(code, attempt)
    elif language == "bash":
        return _execute_bash(code, attempt)
    else:
        log(f"Unsupported language '{language}', falling back to Python")
        return _execute_python(code, attempt)


def _execute_python(code: str, attempt: int) -> tuple[bool, str, str]:
    """Execute Python code directly."""
    script_path = WORK_DIR / f"task_attempt_{attempt}.py"
    script_path.write_text(code)

    log(f"Executing Python code (attempt {attempt})...")
    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True, text=True,
        timeout=CODE_EXECUTION_TIMEOUT,
        cwd=str(WORK_DIR),
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )

    return result.returncode == 0, result.stdout, result.stderr


def _execute_typescript(code: str, attempt: int) -> tuple[bool, str, str]:
    """Compile and execute TypeScript code."""
    ts_path = WORK_DIR / f"task_attempt_{attempt}.ts"
    ts_path.write_text(code)
    write_tsconfig(WORK_DIR)

    # Step 1: Compile TypeScript to JavaScript
    log(f"Compiling TypeScript (attempt {attempt})...")
    compile_result = subprocess.run(
        ["npx", "tsc", "--project", str(WORK_DIR / "tsconfig.json")],
        capture_output=True, text=True,
        timeout=60,
        cwd=str(WORK_DIR),
    )

    if compile_result.returncode != 0:
        log(f"TypeScript compilation failed:\n{compile_result.stderr[:2000]}")
        combined_err = compile_result.stderr + compile_result.stdout
        return False, compile_result.stdout, f"[TypeScript Compilation Error]\n{combined_err}"

    # Step 2: Run the compiled JavaScript
    js_path = WORK_DIR / "dist" / f"task_attempt_{attempt}.js"
    if not js_path.exists():
        return False, "", f"Compiled JS not found at {js_path}. Check tsconfig outDir."

    log(f"Executing compiled JavaScript (attempt {attempt})...")
    result = subprocess.run(
        ["node", str(js_path)],
        capture_output=True, text=True,
        timeout=CODE_EXECUTION_TIMEOUT,
        cwd=str(WORK_DIR),
    )

    return result.returncode == 0, result.stdout, result.stderr


def _execute_bash(code: str, attempt: int) -> tuple[bool, str, str]:
    """Execute a Bash script."""
    script_path = WORK_DIR / f"task_attempt_{attempt}.sh"
    script_path.write_text(code)
    script_path.chmod(0o755)

    log(f"Executing Bash script (attempt {attempt})...")
    result = subprocess.run(
        ["bash", str(script_path)],
        capture_output=True, text=True,
        timeout=CODE_EXECUTION_TIMEOUT,
        cwd=str(WORK_DIR),
    )

    return result.returncode == 0, result.stdout, result.stderr


# ---------------------------------------------------------------------------
# File upload (presigned PUT URLs)
# ---------------------------------------------------------------------------

def upload_file(filepath: str | Path, presigned_url: str) -> bool:
    """Upload a single file using a presigned PUT URL."""
    filepath = Path(filepath)
    if not presigned_url or not filepath.exists():
        return False
    try:
        data = filepath.read_bytes()
        success = _http_put_bytes(presigned_url, data)
        if success:
            log(f"Uploaded {filepath.name} ({len(data)} bytes)")
        return success
    except Exception as e:
        log(f"Upload failed for {filepath}: {e}")
        return False


def upload_task_results(task: dict) -> None:
    """Tar output files and upload everything for a completed task.

    Uses presigned URLs provided in the task payload by the Orchestrator.
    """
    upload_urls = task.get("upload_urls", {})

    # Upload the daemon log as stdout
    stdout_url = upload_urls.get("stdout.log", "")
    if stdout_url and LOG_FILE.exists():
        upload_file(LOG_FILE, stdout_url)

    # Create and upload output archive
    output_url = upload_urls.get("output.tar.gz", "")
    if output_url and OUTPUT_DIR.exists() and any(OUTPUT_DIR.iterdir()):
        tar_path = Path("/tmp/output.tar.gz")
        try:
            with tarfile.open(str(tar_path), "w:gz") as tar:
                for item in OUTPUT_DIR.iterdir():
                    tar.add(str(item), arcname=item.name)
            upload_file(tar_path, output_url)
        except Exception as e:
            log(f"Failed to create output archive: {e}")

    # Write and upload _done.json completion marker
    done_url = upload_urls.get("_done.json", "")
    if done_url:
        done_data = {
            "status": task.get("_final_status", "completed"),
            "exit_code": task.get("_final_exit_code", 0),
            "attempts": task.get("_attempts", 0),
            "language": task.get("_language", "unknown"),
            "worker_id": WORKER_ID,
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        done_path = Path("/tmp/_done.json")
        done_path.write_text(json.dumps(done_data))
        upload_file(done_path, done_url)


# ---------------------------------------------------------------------------
# Task execution (self-healing loop)
# ---------------------------------------------------------------------------

def clean_workspace() -> None:
    """Reset the workspace between tasks."""
    # Clear output directory contents but keep the directory
    if OUTPUT_DIR.exists():
        for item in OUTPUT_DIR.iterdir():
            try:
                if item.is_dir():
                    shutil.rmtree(str(item))
                else:
                    item.unlink()
            except OSError:
                pass

    # Clear work directory contents
    if WORK_DIR.exists():
        for item in WORK_DIR.iterdir():
            try:
                if item.is_dir():
                    shutil.rmtree(str(item))
                else:
                    item.unlink()
            except OSError:
                pass

    # Re-create directories
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)


def execute_audit(task: dict) -> None:
    """Run a CodeScope 7-layer security audit.

    The audit script is pre-built (not LLM-generated) for reliability.
    It clones a GitHub repo, runs 7 analysis layers, and uses Gradient AI
    for synthesis.
    """
    task_id = task.get("task_id", "unknown")
    repo_url = task.get("repo_url", "")
    branch = task.get("branch", "main")

    log(f"\n{'=' * 60}")
    log(f"CODESCOPE AUDIT: {task_id}")
    log(f"REPO: {repo_url}")
    log(f"BRANCH: {branch}")
    log(f"{'=' * 60}\n")

    post_task_status(task_id, "running", "audit_starting")

    try:
        # Run the CodeScope script
        codescope_path = Path("/opt/workbench/codescope.py")
        if not codescope_path.exists():
            raise FileNotFoundError("CodeScope script not found at /opt/workbench/codescope.py")

        cmd = [
            sys.executable, str(codescope_path),
            repo_url,
            "--branch", branch,
            "--gradient-key", GRADIENT_KEY,
            "--model", GRADIENT_MODEL,
        ]

        log("Starting CodeScope audit...")

        # Stream stdout line-by-line so we can forward progress to the orchestrator
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd="/opt/audit",
        )

        for line in iter(proc.stdout.readline, ''):
            line = line.rstrip()
            if not line:
                continue
            log(line)

            # Forward layer progress as callbacks so the dashboard can show it
            if "[Layer " in line and "/7]" in line:
                post_task_status(task_id, "running", "scanning",
                                 {"log_line": line})
            elif "Audit Complete" in line:
                post_task_status(task_id, "running", "finalizing",
                                 {"log_line": line})
            elif "findings" in line.lower() or "complete" in line.lower():
                post_task_status(task_id, "running", "scanning",
                                 {"log_line": line})

        proc.wait(timeout=480)
        exit_code = proc.returncode

        if exit_code == 0:
            log("CodeScope audit completed successfully!")
            task["_final_status"] = "completed"
            task["_final_exit_code"] = 0
        else:
            log(f"CodeScope audit finished with exit code {exit_code}")
            task["_final_status"] = "completed"
            task["_final_exit_code"] = exit_code

        task["_attempts"] = 1
        task["_language"] = "codescope"

    except subprocess.TimeoutExpired:
        log("CodeScope audit timed out (480s)")
        task["_final_status"] = "failed"
        task["_final_exit_code"] = 124
        task["_attempts"] = 1
        task["_language"] = "codescope"

    except Exception as e:
        log(f"CodeScope audit error: {e}")
        log(traceback.format_exc())
        task["_final_status"] = "failed"
        task["_final_exit_code"] = 1
        task["_attempts"] = 1
        task["_language"] = "codescope"

    # Upload results (same as regular tasks)
    upload_task_results(task)


def execute_task(task: dict) -> None:
    """Run the full self-healing code generation and execution cycle for a task.

    Steps:
      1. Call Gradient AI to generate code (with language selection)
      2. Detect language and extract code
      3. Install dependencies
      4. Execute code
      5. On failure, send (task + code + error) back to Gradient AI for a fix
      6. Retry up to MAX_HEAL_ATTEMPTS times
      7. Upload results
    """
    task_id = task.get("task_id", "unknown")
    description = task.get("prompt", task.get("description", ""))

    log(f"\n{'=' * 60}")
    log(f"TASK: {task_id}")
    log(f"DESCRIPTION: {description[:200]}")
    log(f"{'=' * 60}\n")

    post_task_status(task_id, "running", "code_generation")

    final_status = "failed"
    final_exit_code = 1
    language = "python"
    attempts_made = 0

    try:
        # --- Step 1: Generate initial code ---
        log("Step 1: Generating code via Gradient AI...")
        response = call_gradient([
            {"role": "system", "content": CODE_GEN_SYSTEM_PROMPT},
            {"role": "user", "content": description},
        ])

        code, language = extract_code_and_language(response)
        log(f"Language selected: {language}")
        log(f"Generated {len(code)} characters of code")

        # Save the generated code for inspection
        ext = {"python": ".py", "typescript": ".ts", "bash": ".sh"}[language]
        (OUTPUT_DIR / f"generated_code{ext}").write_text(code)

        # --- Step 2: Install dependencies ---
        log("Step 2: Installing dependencies...")
        if language == "python":
            install_python_deps(code)
        elif language == "typescript":
            install_typescript_deps(code)
        # Bash needs no dependency installation

        # --- Step 3: Self-healing execution loop ---
        for attempt in range(1, MAX_HEAL_ATTEMPTS + 1):
            attempts_made = attempt
            log(f"\n--- Execution attempt {attempt}/{MAX_HEAL_ATTEMPTS} ---")
            post_task_status(task_id, "running", "executing",
                             {"attempt": attempt, "language": language})

            try:
                success, stdout, stderr = execute_code(code, language, attempt)
            except subprocess.TimeoutExpired:
                log(f"Execution timed out ({CODE_EXECUTION_TIMEOUT}s)")
                stderr = (f"TimeoutError: Code execution exceeded "
                          f"{CODE_EXECUTION_TIMEOUT} second limit")
                success = False
                stdout = ""

            # Log output (truncated)
            if stdout:
                log(f"STDOUT:\n{stdout[:3000]}")
            if stderr:
                log(f"STDERR:\n{stderr[:3000]}")

            if success:
                log(f"\nTask completed successfully on attempt {attempt}!")
                final_status = "completed"
                final_exit_code = 0
                break

            log(f"Attempt {attempt} failed (exit code != 0)")

            # --- Self-heal if attempts remain ---
            if attempt < MAX_HEAL_ATTEMPTS:
                log("Self-healing: sending error to Gradient AI for a fix...")
                post_task_status(task_id, "running", "self_healing",
                                 {"attempt": attempt})

                error_output = (stderr if stderr else stdout)[:3000]
                fix_prompt = FIX_CODE_PROMPT.format(
                    task=description,
                    language=language,
                    code=code,
                    error=error_output,
                )

                try:
                    fix_response = call_gradient([
                        {"role": "system", "content": CODE_GEN_SYSTEM_PROMPT},
                        {"role": "user", "content": fix_prompt},
                    ])
                    fixed_code, fixed_lang = extract_code_and_language(fix_response)

                    # Keep the same language unless there's a compelling reason
                    if fixed_lang != language:
                        log(f"Fix changed language from {language} to {fixed_lang}")
                        language = fixed_lang

                    code = fixed_code
                    log(f"Received fixed code ({len(code)} chars)")

                    # Save the fixed version
                    fix_ext = {"python": ".py", "typescript": ".ts", "bash": ".sh"}[language]
                    (OUTPUT_DIR / f"fixed_code_v{attempt + 1}{fix_ext}").write_text(code)

                    # Re-install deps in case the fix added new ones
                    if language == "python":
                        install_python_deps(code)
                    elif language == "typescript":
                        install_typescript_deps(code)

                except Exception as heal_err:
                    log(f"Self-healing failed: {heal_err}")
                    log(traceback.format_exc())
            else:
                log(f"\nAll {MAX_HEAL_ATTEMPTS} attempts exhausted. Task failed.")

    except Exception as e:
        log(f"\nTask execution error: {e}")
        log(traceback.format_exc())

    # --- Step 4: Upload results ---
    log("\nUploading results...")
    post_task_status(task_id, "uploading", "results")

    task["_final_status"] = final_status
    task["_final_exit_code"] = final_exit_code
    task["_attempts"] = attempts_made
    task["_language"] = language

    upload_task_results(task)
    post_task_status(task_id, final_status, "done",
                     {"exit_code": final_exit_code, "attempts": attempts_made})

    log(f"\nTask {task_id} finished: {final_status} "
        f"(attempts={attempts_made}, language={language})")


# ---------------------------------------------------------------------------
# Main daemon loop
# ---------------------------------------------------------------------------

def get_uptime_minutes(start_time: float) -> float:
    """Return how many minutes the daemon has been alive."""
    return (time.time() - start_time) / 60.0


def main() -> None:
    """Main entry point for the Worker Daemon."""
    _ensure_dirs()
    start_time = time.time()
    tasks_completed = 0
    tasks_failed = 0

    log("=" * 60)
    log("  Ephemeral.ai Worker Daemon")
    log("=" * 60)
    log(f"Worker ID:      {WORKER_ID}")
    log(f"Orchestrator:   {ORCHESTRATOR_URL}")
    log(f"Model:          {GRADIENT_MODEL}")
    log(f"Max lifetime:   {MAX_ALIVE_MINUTES} minutes")
    log(f"Max heal attempts: {MAX_HEAL_ATTEMPTS}")
    log(f"Poll interval:  {POLL_INTERVAL_SECONDS}s")
    log("")

    # --- Register with the Orchestrator as idle ---
    log("Registering with Orchestrator...")
    reg_result = post_status("idle", {
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "max_alive_minutes": MAX_ALIVE_MINUTES,
    })
    if reg_result is None:
        log("WARNING: Failed to register with Orchestrator. "
            "Will continue polling anyway.")

    log("Entering main polling loop...\n")

    # --- Main loop ---
    while not _shutdown_requested:
        uptime = get_uptime_minutes(start_time)

        # Check if we've exceeded the lifetime limit
        if uptime >= MAX_ALIVE_MINUTES:
            log(f"\nLifetime limit reached ({uptime:.1f} >= {MAX_ALIVE_MINUTES} min). "
                f"Shutting down gracefully.")
            break

        # Also check: if less than 2 minutes remain, don't start a new task
        remaining = MAX_ALIVE_MINUTES - uptime
        if remaining < 2.0:
            log(f"\nLess than 2 minutes remaining ({remaining:.1f} min). "
                f"Stopping task acceptance.")
            break

        # --- Poll for a task ---
        task = None
        try:
            task = poll_for_task()
        except Exception as e:
            log(f"Polling error: {e}")

        if task:
            task_id = task.get("task_id", "unknown")
            log(f"Received task: {task_id}")

            # Update status to busy
            post_status("busy", {"task_id": task_id})

            # Clean workspace from previous task
            clean_workspace()

            # Execute the task (dispatch by type)
            try:
                if task.get("type") == "audit":
                    # CodeScope security audit
                    execute_audit(task)
                else:
                    # Standard code generation task
                    execute_task(task)

                if task.get("_final_status") == "completed":
                    tasks_completed += 1
                else:
                    tasks_failed += 1
            except Exception as e:
                log(f"Unhandled error executing task {task_id}: {e}")
                log(traceback.format_exc())
                tasks_failed += 1
                post_task_status(task_id, "failed", "unhandled_error",
                                 {"error": str(e)[:500]})

            # Return to idle
            post_status("idle", {
                "tasks_completed": tasks_completed,
                "tasks_failed": tasks_failed,
                "uptime_minutes": round(get_uptime_minutes(start_time), 1),
            })
            log(f"\nReturning to idle. "
                f"(completed={tasks_completed}, failed={tasks_failed}, "
                f"uptime={get_uptime_minutes(start_time):.1f}m)\n")
        else:
            # No task available - sleep before next poll
            time.sleep(POLL_INTERVAL_SECONDS)

    # --- Graceful shutdown ---
    uptime = get_uptime_minutes(start_time)
    log(f"\n{'=' * 60}")
    log(f"  Worker Daemon shutting down")
    log(f"{'=' * 60}")
    log(f"Uptime:          {uptime:.1f} minutes")
    log(f"Tasks completed: {tasks_completed}")
    log(f"Tasks failed:    {tasks_failed}")
    log(f"Shutdown reason: {'signal' if _shutdown_requested else 'lifetime_limit'}")

    # Notify Orchestrator of shutdown
    post_status("shutdown", {
        "uptime_minutes": round(uptime, 1),
        "tasks_completed": tasks_completed,
        "tasks_failed": tasks_failed,
        "reason": "signal" if _shutdown_requested else "lifetime_limit",
    })

    log("Goodbye.")


if __name__ == "__main__":
    main()
'''


def get_worker_daemon_script() -> str:
    """Return the worker daemon script for embedding in cloud-init."""
    return WORKER_DAEMON_SCRIPT
