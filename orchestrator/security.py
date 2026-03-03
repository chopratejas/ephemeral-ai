"""Security module - code scanning, rate limiting, budget enforcement."""

import logging
import re
import time
from collections import defaultdict

from .config import settings

logger = logging.getLogger("ephemeral.security")

# Patterns that should never appear in LLM-generated code
DANGEROUS_PATTERNS = [
    (r"\bos\.system\s*\(", "os.system() call"),
    (r"\bsubprocess\b", "subprocess module usage"),
    (r"\beval\s*\(", "eval() call"),
    (r"\bexec\s*\(", "exec() call"),
    (r"\b__import__\s*\(", "__import__() call"),
    (r"\bshutil\.rmtree\s*\(", "shutil.rmtree() call"),
    (r"rm\s+-rf\s+/", "rm -rf / command"),
    (r"\bfork\s*\(\)", "fork bomb attempt"),
    (r":(){ :\|:& };:", "bash fork bomb"),
    (r"\bcrypto\b.*\bwallet\b", "cryptocurrency reference"),
    (r"\bsocket\.socket\b", "raw socket creation"),
    (r"\bparamiko\b", "SSH library usage"),
    (r"\bfabric\b", "remote execution library"),
]

# Ordered smallest to largest. Snapshot needs 25GB disk, so s-1vcpu-1gb is minimum.
DROPLET_SIZE_ORDER = [
    "s-1vcpu-1gb",       # 25GB disk, $0.009/hr
    "s-1vcpu-2gb",       # 50GB disk, $0.018/hr
    "s-2vcpu-2gb",       # 60GB disk, $0.027/hr
    "s-2vcpu-4gb",       # 80GB disk, $0.036/hr
    "s-4vcpu-8gb",       # 160GB disk, $0.071/hr
]

ALLOWED_DROPLET_SLUGS = set(DROPLET_SIZE_ORDER)

MIN_SLUG = "s-1vcpu-1gb"


def enforce_min_slug(slug: str) -> str:
    """Clamp a slug to at least the minimum size (snapshot disk requirement)."""
    if slug not in ALLOWED_DROPLET_SLUGS:
        return MIN_SLUG
    idx = DROPLET_SIZE_ORDER.index(slug) if slug in DROPLET_SIZE_ORDER else 0
    return DROPLET_SIZE_ORDER[max(0, idx)]


class RateLimiter:
    """Simple in-memory sliding window rate limiter."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: list[float] = []

    def check(self) -> bool:
        now = time.time()
        self.requests = [t for t in self.requests if now - t < self.window_seconds]
        if len(self.requests) >= self.max_requests:
            return False
        self.requests.append(now)
        return True


class BudgetTracker:
    """Track daily spending to enforce budget limits."""

    def __init__(self):
        self.daily_spend: dict[str, float] = defaultdict(float)

    def record_spend(self, amount: float) -> None:
        today = time.strftime("%Y-%m-%d")
        self.daily_spend[today] += amount

    def get_today_spend(self) -> float:
        today = time.strftime("%Y-%m-%d")
        return self.daily_spend.get(today, 0.0)

    def check_budget(self, estimated_cost: float) -> bool:
        return (
            self.get_today_spend() + estimated_cost <= settings.daily_budget_usd
        )


# Global instances
rate_limiter = RateLimiter()
budget_tracker = BudgetTracker()


def scan_code(code: str) -> list[str]:
    """Scan LLM-generated code for dangerous patterns.

    Returns a list of security violations found.
    """
    violations = []
    for pattern, description in DANGEROUS_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            violations.append(description)

    if violations:
        logger.warning("Code scan found %d violations: %s", len(violations), violations)

    return violations


def validate_droplet_slug(slug: str) -> bool:
    """Ensure the requested Droplet size is in the allowed set."""
    if slug not in ALLOWED_DROPLET_SLUGS:
        logger.warning("Rejected Droplet slug: %s", slug)
        return False
    return True
