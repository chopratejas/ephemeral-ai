"""Task Router - route incoming tasks to warm workers or trigger new Droplets.

The router is the bridge between the API layer and the warm pool.  When a
new task comes in it checks whether an already-running (and idle) Droplet
can handle it.  If so the task is enqueued on that worker, saving the full
Droplet boot time (~30-60 s).  If not, the caller creates a fresh Droplet
as before.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

from .models import Manifest
from .spaces import generate_upload_presigned_urls
from .warm_pool import WarmPool, WarmWorker

logger = logging.getLogger("ephemeral.router")


# ---------------------------------------------------------------------------
# Routing decision
# ---------------------------------------------------------------------------

@dataclass
class RoutingDecision:
    """Result of the routing attempt."""

    warm: bool                       # True  -> reused an existing worker
    worker: WarmWorker | None = None # The worker (when warm=True)
    reason: str = ""                 # Human-readable explanation


# ---------------------------------------------------------------------------
# Task queue (per-worker)
# ---------------------------------------------------------------------------

class TaskQueue:
    """In-memory, thread-safe per-worker task queue.

    Workers poll ``GET /api/v1/workers/{worker_id}/next-task`` to pick up
    work.  Each queue is a simple FIFO list.
    """

    def __init__(self) -> None:
        self.queues: dict[str, list[dict]] = {}  # worker_id -> [task_dicts]
        self._lock = threading.RLock()

    def enqueue(self, worker_id: str, task: dict) -> None:
        """Add a task to the tail of a worker's queue."""
        with self._lock:
            self.queues.setdefault(worker_id, []).append(task)

        logger.info(
            "Task %s enqueued on worker %s (queue_depth=%d)",
            task.get("task_id", "?")[:8],
            worker_id[:8],
            len(self.queues.get(worker_id, [])),
        )

    def dequeue(self, worker_id: str) -> dict | None:
        """Pop the next task from the head of a worker's queue.

        Returns ``None`` when the queue is empty.
        """
        with self._lock:
            queue = self.queues.get(worker_id, [])
            if not queue:
                return None
            task = queue.pop(0)

        logger.info(
            "Task %s dequeued from worker %s",
            task.get("task_id", "?")[:8],
            worker_id[:8],
        )
        return task

    def has_tasks(self, worker_id: str) -> bool:
        """Return ``True`` if the worker has pending tasks."""
        with self._lock:
            return bool(self.queues.get(worker_id))

    def queue_depth(self, worker_id: str) -> int:
        """Return the number of pending tasks for a worker."""
        with self._lock:
            return len(self.queues.get(worker_id, []))

    def remove_worker(self, worker_id: str) -> list[dict]:
        """Remove a worker's queue entirely and return any orphaned tasks."""
        with self._lock:
            return self.queues.pop(worker_id, [])


# ---------------------------------------------------------------------------
# Module-level singletons (imported by main.py / other modules)
# ---------------------------------------------------------------------------

task_queue = TaskQueue()


# ---------------------------------------------------------------------------
# Core routing function
# ---------------------------------------------------------------------------

async def route_task(
    task_id: str,
    manifest: Manifest,
    task_description: str,
    warm_pool: WarmPool,
) -> RoutingDecision:
    """Attempt to route *task_id* to an idle warm worker.

    Strategy
    --------
    1. Look for the *smallest* idle worker whose size can handle the
       manifest's required size (``manifest.infra.slug``).
    2. If found, mark the worker busy, build the task payload (including
       presigned upload URLs), enqueue it, and return a warm routing
       decision.
    3. If no suitable idle worker exists, return a cold routing decision
       so the caller can provision a brand-new Droplet.
    """
    required_size = manifest.infra.slug
    worker = warm_pool.get_idle_worker(required_size)

    if worker is None:
        logger.info(
            "No warm worker for task %s (need %s) - cold start required",
            task_id[:8],
            required_size,
        )
        return RoutingDecision(
            warm=False,
            worker=None,
            reason="no_suitable_worker",
        )

    # --- Warm hit: assign and enqueue ----------------------------------

    warm_pool.mark_busy(worker.worker_id, task_id)

    # Build the task payload that the worker daemon will pick up.
    upload_urls = generate_upload_presigned_urls(task_id)

    task_payload: dict = {
        "task_id": task_id,
        "description": task_description,
        "upload_urls": {
            "stdout.log": upload_urls.get("stdout.log", ""),
            "output.tar.gz": upload_urls.get("output.tar.gz", ""),
            "_done.json": upload_urls.get("_done.json", ""),
        },
        "manifest": {
            "code": manifest.payload.code,
            "entry_command": manifest.payload.entry_command,
            "language": manifest.runtime.language,
            "version": manifest.runtime.version,
            "dependencies": manifest.runtime.dependencies,
            "input_files": [
                f.model_dump() for f in manifest.payload.input_files
            ],
            "timeout_seconds": manifest.lifecycle.timeout_seconds,
        },
    }

    task_queue.enqueue(worker.worker_id, task_payload)

    logger.info(
        "Task %s routed to warm worker %s (droplet=%d, size=%s, "
        "minutes_remaining=%.0f, tasks_done=%d)",
        task_id[:8],
        worker.worker_id[:8],
        worker.droplet_id,
        worker.size_slug,
        worker.minutes_remaining,
        worker.tasks_completed,
    )

    return RoutingDecision(
        warm=True,
        worker=worker,
        reason="warm_pool_hit",
    )
