"""Warm Pool Manager - reuse idle Droplets within their billing hour.

DigitalOcean bills Droplets per hour (minimum 1 hour). A 30-second task
costs the same as a 59-minute task. Instead of create-use-destroy, we keep
Droplets alive for the full billing hour and reuse them for subsequent tasks.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("ephemeral.pool")

# ---------------------------------------------------------------------------
# Size hierarchy: ordered from smallest to largest.
# A worker can handle any task whose required size appears at the same index
# or earlier (i.e., smaller or equal) in this list.
# ---------------------------------------------------------------------------
SIZE_HIERARCHY: list[str] = [
    "s-1vcpu-512mb",
    "s-1vcpu-1gb",
    "s-1vcpu-2gb",
    "s-2vcpu-2gb",
    "s-2vcpu-4gb",
    "s-4vcpu-8gb",
    "s-8vcpu-16gb",
]

_size_rank: dict[str, int] = {slug: idx for idx, slug in enumerate(SIZE_HIERARCHY)}

# How many minutes before the billing-hour boundary we stop reusing a worker.
# 5 minutes gives enough headroom to finish a short task before the next
# billing tick.
_BILLING_BUFFER_MINUTES = 5
_BILLING_WINDOW_MINUTES = 60 - _BILLING_BUFFER_MINUTES  # 55 minutes


def can_handle(worker_size: str, required_size: str) -> bool:
    """Return True if *worker_size* is large enough to run a task that needs
    *required_size*.

    Unknown sizes are only considered a match when they are identical strings.
    """
    worker_rank = _size_rank.get(worker_size)
    required_rank = _size_rank.get(required_size)

    if worker_rank is None or required_rank is None:
        # Fall back to exact match for sizes we don't recognise.
        return worker_size == required_size

    return worker_rank >= required_rank


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WarmWorker:
    """Represents a single warm Droplet in the pool."""

    worker_id: str                       # UUID
    droplet_id: int                      # DO Droplet ID
    droplet_ip: str                      # Public IPv4
    size_slug: str                       # e.g. "s-1vcpu-1gb"
    status: str = "booting"              # booting | idle | busy | shutting_down
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    billing_expires_at: datetime = field(default=None)  # type: ignore[assignment]
    current_task_id: str | None = None
    tasks_completed: int = 0
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.billing_expires_at is None:
            self.billing_expires_at = self.created_at + timedelta(
                minutes=_BILLING_WINDOW_MINUTES
            )

    @property
    def minutes_remaining(self) -> float:
        """Minutes left before the billing window closes."""
        delta = self.billing_expires_at - datetime.now(timezone.utc)
        return max(delta.total_seconds() / 60.0, 0.0)

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.billing_expires_at


# ---------------------------------------------------------------------------
# WarmPool
# ---------------------------------------------------------------------------

class WarmPool:
    """In-memory pool of warm (idle or busy) Droplets.

    Thread-safe via a reentrant lock so the pool can be queried from both
    the async FastAPI event loop (via ``asyncio.to_thread``) and synchronous
    background tasks.
    """

    def __init__(self) -> None:
        self.workers: dict[str, WarmWorker] = {}  # worker_id -> WarmWorker
        self._lock = threading.RLock()

    # -- mutators ----------------------------------------------------------

    def add_worker(
        self,
        worker_id: str,
        droplet_id: int,
        droplet_ip: str,
        size_slug: str,
    ) -> WarmWorker:
        """Register a freshly-created Droplet as a warm worker.

        The worker starts in ``"idle"`` status, ready to accept a task
        immediately.
        """
        now = datetime.now(timezone.utc)
        worker = WarmWorker(
            worker_id=worker_id,
            droplet_id=droplet_id,
            droplet_ip=droplet_ip,
            size_slug=size_slug,
            status="idle",
            created_at=now,
            last_activity=now,
        )

        with self._lock:
            self.workers[worker_id] = worker

        logger.info(
            "Worker added: id=%s droplet=%d ip=%s size=%s expires_in=%.0fm",
            worker_id[:8],
            droplet_id,
            droplet_ip,
            size_slug,
            worker.minutes_remaining,
        )
        return worker

    def mark_busy(self, worker_id: str, task_id: str) -> None:
        """Assign a task to a worker, transitioning it to ``"busy"``."""
        with self._lock:
            worker = self._get_or_raise(worker_id)
            worker.status = "busy"
            worker.current_task_id = task_id
            worker.last_activity = datetime.now(timezone.utc)

        logger.info(
            "Worker %s marked busy (task=%s)",
            worker_id[:8],
            task_id[:8],
        )

    def mark_idle(self, worker_id: str) -> None:
        """Return a worker to the idle pool after its task finishes."""
        with self._lock:
            worker = self._get_or_raise(worker_id)
            was_busy = worker.status == "busy"
            worker.status = "idle"
            if was_busy:
                worker.tasks_completed += 1
            worker.current_task_id = None
            worker.last_activity = datetime.now(timezone.utc)

        logger.info(
            "Worker %s marked idle (tasks_completed=%d, remaining=%.0fm)",
            worker_id[:8],
            worker.tasks_completed,
            worker.minutes_remaining,
        )

    def mark_shutting_down(self, worker_id: str) -> None:
        """Mark a worker as shutting down (pending destruction)."""
        with self._lock:
            worker = self._get_or_raise(worker_id)
            worker.status = "shutting_down"

        logger.info("Worker %s marked shutting_down", worker_id[:8])

    def remove_worker(self, worker_id: str) -> None:
        """Remove a worker from the pool entirely (after Droplet destruction)."""
        with self._lock:
            worker = self.workers.pop(worker_id, None)

        if worker:
            logger.info(
                "Worker removed: id=%s droplet=%d tasks_completed=%d",
                worker_id[:8],
                worker.droplet_id,
                worker.tasks_completed,
            )
        else:
            logger.warning("Attempted to remove unknown worker %s", worker_id[:8])

    # -- queries -----------------------------------------------------------

    def get_idle_worker(self, min_size_slug: str) -> WarmWorker | None:
        """Find the *smallest* idle worker that can handle *min_size_slug*.

        Preferring the smallest eligible worker preserves larger workers for
        tasks that actually need them.

        Returns ``None`` if no suitable idle worker exists.
        """
        with self._lock:
            candidates: list[WarmWorker] = []
            for worker in self.workers.values():
                if (
                    worker.status == "idle"
                    and not worker.is_expired
                    and can_handle(worker.size_slug, min_size_slug)
                ):
                    candidates.append(worker)

        if not candidates:
            return None

        # Sort by size rank ascending (smallest first).
        candidates.sort(key=lambda w: _size_rank.get(w.size_slug, 999))
        chosen = candidates[0]

        logger.info(
            "Idle worker found: id=%s size=%s (requested=%s, remaining=%.0fm)",
            chosen.worker_id[:8],
            chosen.size_slug,
            min_size_slug,
            chosen.minutes_remaining,
        )
        return chosen

    def get_expired_workers(self) -> list[WarmWorker]:
        """Return all workers whose billing window has elapsed."""
        now = datetime.now(timezone.utc)
        with self._lock:
            return [
                w
                for w in self.workers.values()
                if now >= w.billing_expires_at
                and w.status not in ("shutting_down",)
            ]

    def get_worker_by_droplet(self, droplet_id: int) -> WarmWorker | None:
        """Look up a worker by its DigitalOcean Droplet ID."""
        with self._lock:
            for worker in self.workers.values():
                if worker.droplet_id == droplet_id:
                    return worker
        return None

    def get_stats(self) -> dict:
        """Return aggregate statistics about the pool."""
        with self._lock:
            workers = list(self.workers.values())

        total = len(workers)
        idle = sum(1 for w in workers if w.status == "idle")
        busy = sum(1 for w in workers if w.status == "busy")
        shutting_down = sum(1 for w in workers if w.status == "shutting_down")
        tasks_completed = sum(w.tasks_completed for w in workers)

        return {
            "total": total,
            "idle": idle,
            "busy": busy,
            "shutting_down": shutting_down,
            "tasks_completed": tasks_completed,
        }

    # -- internals ---------------------------------------------------------

    def _get_or_raise(self, worker_id: str) -> WarmWorker:
        """Return a worker or raise ``KeyError``."""
        worker = self.workers.get(worker_id)
        if worker is None:
            raise KeyError(f"Unknown worker: {worker_id}")
        return worker

    def __len__(self) -> int:
        return len(self.workers)

    def __repr__(self) -> str:
        stats = self.get_stats()
        return (
            f"<WarmPool total={stats['total']} idle={stats['idle']} "
            f"busy={stats['busy']} tasks_done={stats['tasks_completed']}>"
        )
