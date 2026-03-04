"""Scout - Lightweight repo pre-analysis to determine Droplet sizing.

Runs on the Orchestrator (App Platform), NOT inside a Droplet.
Fetches just the README + manifest files via GitHub API, asks an LLM
to determine what size Droplet the repo needs, and what setup commands
to run.
"""

import json
import logging
import urllib.request
import urllib.error

from .config import settings

logger = logging.getLogger("ephemeral.scout")

SCOUT_PROMPT = """\
You are a DevOps engineer sizing infrastructure for a code security audit.

Given a GitHub repository's README and dependency files, determine:
1. What Droplet size is needed to clone, install, and run this project
2. What commands to run to set it up
3. Key characteristics of the project

SIZING RULES:
- s-1vcpu-1gb ($0.009/hr): Small repos (<50 files), simple Python/Node scripts, no heavy deps
- s-1vcpu-2gb ($0.018/hr): Medium repos, basic web apps, moderate dependencies
- s-2vcpu-4gb ($0.036/hr): Large repos (200+ files), ML/AI projects, heavy deps (pandas, torch, etc.)
- s-4vcpu-8gb ($0.071/hr): Very large repos (1000+ files), monorepos, multiple services

Output ONLY valid JSON:
{
    "slug": "s-1vcpu-2gb",
    "language": "python",
    "framework": "fastapi",
    "description": "what this project does in one sentence",
    "estimated_files": 150,
    "estimated_install_time_seconds": 60,
    "setup_commands": [
        "pip install -e .",
        "pip install -r requirements-dev.txt"
    ],
    "start_command": "uvicorn app:main --port 8000",
    "has_ai_integration": true,
    "has_database": true,
    "has_web_server": true
}
"""


def _fetch_github_file(repo_url: str, filepath: str, branch: str = "main") -> str:
    """Fetch a single file from GitHub via the raw content URL."""
    # Extract owner/repo from URL
    parts = repo_url.rstrip("/").replace("https://github.com/", "").replace(".git", "")
    raw_url = f"https://raw.githubusercontent.com/{parts}/{branch}/{filepath}"

    try:
        req = urllib.request.Request(raw_url, headers={"User-Agent": "CodeScope-Scout/1.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        content = resp.read().decode("utf-8", errors="replace")
        return content[:10000]  # Cap at 10KB
    except urllib.error.HTTPError:
        return ""
    except Exception as e:
        logger.debug("Failed to fetch %s: %s", raw_url, e)
        return ""


def _fetch_github_tree(repo_url: str, branch: str = "main") -> str:
    """Fetch the file tree via GitHub API."""
    parts = repo_url.rstrip("/").replace("https://github.com/", "").replace(".git", "")
    api_url = f"https://api.github.com/repos/{parts}/git/trees/{branch}?recursive=1"

    try:
        req = urllib.request.Request(api_url, headers={
            "User-Agent": "CodeScope-Scout/1.0",
            "Accept": "application/vnd.github.v3+json",
        })
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())

        # Build a concise file list (just paths, skip blobs > 200 entries)
        paths = []
        for item in data.get("tree", [])[:500]:
            if item.get("type") == "blob":
                paths.append(item["path"])

        return "\n".join(paths[:300])
    except Exception as e:
        logger.debug("Failed to fetch tree: %s", e)
        return ""


def _call_llm(system: str, user: str) -> str:
    """Quick LLM call for scouting (uses fast model)."""
    from openai import OpenAI

    client = OpenAI(
        base_url=settings.gradient_base_url,
        api_key=settings.gradient_model_access_key,
    )

    response = client.chat.completions.create(
        model=settings.gradient_model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.1,
        max_completion_tokens=1024,
    )

    return response.choices[0].message.content.strip()


def scout_repo(repo_url: str, branch: str = "main") -> dict:
    """Pre-analyze a repo to determine Droplet sizing and setup commands.

    Runs on the Orchestrator. Fetches README + manifests from GitHub
    (no cloning needed), asks LLM to size the Droplet.

    Returns a dict with: slug, language, framework, setup_commands, etc.
    """
    logger.info("Scouting repo: %s (branch: %s)", repo_url, branch)

    # Fetch key files from GitHub (lightweight, no clone needed)
    readme = _fetch_github_file(repo_url, "README.md", branch)
    if not readme:
        readme = _fetch_github_file(repo_url, "readme.md", branch)

    requirements = _fetch_github_file(repo_url, "requirements.txt", branch)
    pyproject = _fetch_github_file(repo_url, "pyproject.toml", branch)
    package_json = _fetch_github_file(repo_url, "package.json", branch)
    setup_py = _fetch_github_file(repo_url, "setup.py", branch)
    dockerfile = _fetch_github_file(repo_url, "Dockerfile", branch)

    file_tree = _fetch_github_tree(repo_url, branch)

    # Build context for the LLM
    context_parts = []
    if file_tree:
        context_parts.append(f"FILE TREE ({file_tree.count(chr(10))+1} files):\n{file_tree[:3000]}")
    if readme:
        context_parts.append(f"README.md:\n{readme[:5000]}")
    if requirements:
        context_parts.append(f"requirements.txt:\n{requirements[:2000]}")
    if pyproject:
        context_parts.append(f"pyproject.toml:\n{pyproject[:2000]}")
    if package_json:
        context_parts.append(f"package.json:\n{package_json[:2000]}")
    if setup_py:
        context_parts.append(f"setup.py:\n{setup_py[:1000]}")
    if dockerfile:
        context_parts.append(f"Dockerfile:\n{dockerfile[:1000]}")

    user_message = "\n\n---\n\n".join(context_parts)

    if not user_message.strip():
        logger.warning("Could not fetch any files from %s", repo_url)
        return {
            "slug": "s-1vcpu-2gb",
            "language": "unknown",
            "framework": "unknown",
            "description": "Could not analyze - using default sizing",
            "setup_commands": [],
            "has_ai_integration": False,
        }

    # Ask LLM to analyze
    try:
        raw = _call_llm(SCOUT_PROMPT, user_message)

        # Parse JSON (strip markdown fences if present)
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1]
            if raw.endswith("```"):
                raw = raw[:raw.rfind("```")]
            raw = raw.strip()

        profile = json.loads(raw)

        # Enforce minimum slug
        from .security import enforce_min_slug
        profile["slug"] = enforce_min_slug(profile.get("slug", "s-1vcpu-2gb"))

        logger.info(
            "Scout result: slug=%s lang=%s framework=%s files~%s",
            profile.get("slug"),
            profile.get("language"),
            profile.get("framework"),
            profile.get("estimated_files"),
        )

        return profile

    except (json.JSONDecodeError, Exception) as e:
        logger.error("Scout LLM analysis failed: %s", e)
        return {
            "slug": "s-1vcpu-2gb",
            "language": "unknown",
            "framework": "unknown",
            "description": "LLM analysis failed - using defaults",
            "setup_commands": [],
            "has_ai_integration": False,
        }
