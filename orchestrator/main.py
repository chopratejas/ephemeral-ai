"""Ephemeral.ai - FastAPI Orchestrator.

Self-healing AI workbench with warm Droplet pools and pipeline execution.
"""

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .cost_tracker import build_cost_report
from .droplet_manager import (
    count_active_droplets,
    create_worker_droplet,
    destroy_droplet,
    wait_for_active,
)
from .models import (
    AuditRequest,
    CallbackPayload,
    DropletInfo,
    PhaseRecord,
    StatsResponse,
    Task,
    TaskPhase,
    TaskRequest,
    TaskResponse,
    TaskResult,
    WorkerStatusUpdate,
    WorkerTaskResponse,
)
from .neural_gateway import generate_manifest
from .pipeline import PipelineManager, decompose_task
from .security import budget_tracker, enforce_min_slug, rate_limiter, validate_droplet_slug
from .spaces import check_task_done, generate_upload_presigned_urls, list_task_results
from .task_router import TaskQueue, RoutingDecision, route_task, task_queue
from .warm_pool import WarmPool
from .websocket import ws_manager

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ephemeral.main")

# --- State ---
tasks: dict[str, Task] = {}
warm_pool = WarmPool()
pipeline_manager = PipelineManager()


# --- Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Ephemeral.ai Orchestrator starting up")
    logger.info("Model: %s", settings.gradient_model)
    logger.info("Max Droplets: %d, Budget: $%.2f/day",
                settings.max_concurrent_droplets, settings.daily_budget_usd)

    # Rediscover existing Droplets (survives orchestrator restarts)
    await _rediscover_warm_pool()

    # Background tasks
    pool_reaper = asyncio.create_task(_pool_reaper_loop())
    yield
    pool_reaper.cancel()
    logger.info("Orchestrator shutting down")


# --- App ---
app = FastAPI(
    title="Ephemeral.ai",
    description="Self-healing AI workbench with warm Droplet pools",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ========================================
# Task Endpoints
# ========================================


@app.get("/health")
async def health():
    stats = warm_pool.get_stats()
    return {
        "status": "ok",
        "service": "ephemeral-ai-orchestrator",
        "pool": stats,
    }


@app.post("/api/v1/tasks", response_model=TaskResponse)
async def submit_task(req: TaskRequest):
    """Submit a task. Routes to warm Droplet if available, else creates one."""
    if not rate_limiter.check():
        raise HTTPException(429, "Rate limit exceeded")

    task_id = str(uuid.uuid4())
    task = Task(task_id=task_id, prompt=req.prompt)
    tasks[task_id] = task

    asyncio.create_task(_run_task(task, req))

    ws_url = f"ws://{settings.orchestrator_url.replace('http://', '').replace('https://', '')}/ws/tasks/{task_id}"
    return TaskResponse(
        task_id=task_id,
        status=TaskPhase.PLANNING,
        websocket_url=ws_url,
    )


@app.get("/api/v1/tasks/{task_id}")
async def get_task(task_id: str):
    """Get task status and results."""
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")

    if task.status == TaskPhase.COMPLETED and not task.results:
        try:
            results = await asyncio.to_thread(list_task_results, task_id)
            task.results = [TaskResult(**r) for r in results]
        except Exception as e:
            logger.error("Failed to fetch results for %s: %s", task_id, e)

    return task


@app.get("/api/v1/tasks/{task_id}/report")
async def get_task_report(task_id: str):
    """Get the parsed audit report with findings from Spaces."""
    import tarfile, io

    task = tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if task.status != TaskPhase.COMPLETED:
        raise HTTPException(400, "Task not completed yet")

    # Download output.tar.gz from Spaces and extract findings + report
    try:
        from .spaces import _create_client as create_s3
        from .config import settings as cfg
        s3 = create_s3()
        key = f"tasks/{task_id}/output.tar.gz"
        obj = await asyncio.to_thread(
            s3.get_object, Bucket=cfg.spaces_bucket, Key=key
        )
        tar_bytes = obj["Body"].read()

        findings = []
        report_md = ""

        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.endswith("findings.json"):
                    f = tar.extractfile(member)
                    if f:
                        import json as _json
                        findings = _json.loads(f.read().decode())
                elif member.isfile() and member.name.endswith("report.md"):
                    f = tar.extractfile(member)
                    if f:
                        report_md = f.read().decode()

        return {
            "task_id": task_id,
            "findings": findings,
            "report_md": report_md,
            "logs": task.logs,
        }
    except Exception as e:
        logger.error("Failed to get report for %s: %s", task_id, e)
        raise HTTPException(500, f"Failed to extract report: {e}")


@app.delete("/api/v1/tasks/{task_id}")
async def cancel_task(task_id: str):
    """Force-kill a task."""
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    _record_phase(task, TaskPhase.FAILED)
    task.error = "Cancelled by user"
    return {"ok": True}


@app.post("/api/v1/findings/fix")
async def generate_finding_fix(body: dict):
    """Generate a code fix for a specific finding.

    Request: { file, line, vulnerability, fix_suggestion, code_context }
    Returns the LLM-generated fix with before/after code.
    """
    from .fix_generator import generate_fix

    file_path = body.get("file", "")
    line = body.get("line", 0)
    vuln = body.get("vulnerability", "")

    if not file_path or not vuln:
        raise HTTPException(400, "file and vulnerability are required")

    code_context = body.get("code_context", f"// File: {file_path}, Line: {line}")

    fix = await asyncio.to_thread(
        generate_fix,
        file_path=file_path,
        line_number=line,
        vulnerability=vuln,
        code_context=code_context,
        fix_suggestion=body.get("fix_suggestion", ""),
    )

    return fix


# ========================================
# CodeScope Audit Endpoint
# ========================================


@app.post("/api/v1/audit", response_model=TaskResponse)
async def submit_audit(req: AuditRequest):
    """Submit a CodeScope security audit for a GitHub repository.

    Clones the repo into an ephemeral Droplet, runs 7-layer analysis,
    uses Gradient AI for synthesis, and destroys the VM after.
    """
    if not rate_limiter.check():
        raise HTTPException(429, "Rate limit exceeded")

    task_id = str(uuid.uuid4())
    task = Task(
        task_id=task_id,
        prompt=f"CodeScope audit: {req.repo_url} (branch: {req.branch})",
    )
    tasks[task_id] = task

    asyncio.create_task(_run_audit(task, req))

    ws_url = f"ws://{settings.orchestrator_url.replace('http://', '').replace('https://', '')}/ws/tasks/{task_id}"
    return TaskResponse(task_id=task_id, status=TaskPhase.PLANNING, websocket_url=ws_url)


async def _run_audit(task: Task, req: AuditRequest) -> None:
    """Execute a CodeScope audit through the warm pool pipeline."""
    task_id = task.task_id

    try:
        # Phase 1: Scout - LLM analyzes the repo to determine Droplet size
        _record_phase(task, TaskPhase.PLANNING)
        task.logs.append(f"Starting audit: {req.repo_url}")
        task.logs.append("Scouting repo via GitHub API...")
        await ws_manager.broadcast(task_id, "planning", {"type": "security_audit", "repo": req.repo_url})

        from .scout import scout_repo
        scout_profile = await asyncio.to_thread(scout_repo, req.repo_url, req.branch)
        slug = scout_profile.get("slug", "s-1vcpu-2gb")

        logger.info(
            "Scout: %s → slug=%s lang=%s framework=%s",
            req.repo_url, slug,
            scout_profile.get("language"),
            scout_profile.get("framework"),
        )
        await ws_manager.broadcast(task_id, "scouted", {
            "slug": slug,
            "language": scout_profile.get("language"),
            "framework": scout_profile.get("framework"),
            "description": scout_profile.get("description", ""),
        })

        cost_report = build_cost_report(slug)
        task.cost = cost_report

        task.logs.append(f"Scouted repo: {scout_profile.get('language', '?')}/{scout_profile.get('framework', '?')} → {slug}")

        if not budget_tracker.check_budget(cost_report.total_cost_usd):
            raise Exception("Daily budget exceeded")

        # Phase 2: Route to warm pool or cold start
        _record_phase(task, TaskPhase.PROVISIONING)

        # Check warm pool for an idle worker
        worker = warm_pool.get_idle_worker(slug)
        if worker:
            warm_pool.mark_busy(worker.worker_id, task_id)
            upload_urls = generate_upload_presigned_urls(task_id)
            task_queue.enqueue(worker.worker_id, {
                "task_id": task_id,
                "type": "audit",
                "repo_url": req.repo_url,
                "branch": req.branch,
                "description": f"CodeScope audit: {req.repo_url}",
                "upload_urls": upload_urls,
            })
            task.droplet.id = worker.droplet_id
            task.droplet.ip = worker.droplet_ip
            task.droplet.slug = worker.size_slug
            task.logs.append(f"Warm pool hit: routed to worker {worker.worker_id[:8]} ({worker.droplet_ip})")
            task.logs.append("Task queued. Waiting for worker to pick it up...")
            await ws_manager.broadcast(task_id, "warm_hit", {"worker_id": worker.worker_id[:8]})
            logger.info("Audit %s routed to warm worker %s", task_id[:8], worker.worker_id[:8])
        else:
            # Cold start
            task.logs.append("No warm worker available. Creating new droplet...")
            await ws_manager.broadcast(task_id, "provisioning", {"reason": "no_warm_worker"})

            active = await count_active_droplets()
            if active >= settings.max_concurrent_droplets:
                raise Exception(f"Max Droplets reached ({settings.max_concurrent_droplets})")

            worker_id = str(uuid.uuid4())
            task.logs.append(f"Creating droplet ({slug}) in sfo3...")
            droplet_info = await create_worker_droplet(slug, worker_id)
            droplet_id = droplet_info["droplet_id"]

            task.logs.append(f"Droplet {droplet_id} created. Waiting for boot...")
            active_info = await wait_for_active(droplet_id)
            task.logs.append(f"Droplet active at {active_info.get('ip', '?')}. Installing runtimes...")

            warm_pool.add_worker(
                worker_id=worker_id,
                droplet_id=droplet_id,
                droplet_ip=active_info.get("ip", ""),
                size_slug=slug,
            )

            upload_urls = generate_upload_presigned_urls(task_id)
            task_queue.enqueue(worker_id, {
                "task_id": task_id,
                "type": "audit",
                "repo_url": req.repo_url,
                "branch": req.branch,
                "description": f"CodeScope audit: {req.repo_url}",
                "upload_urls": upload_urls,
            })
            task.logs.append("Task queued. Worker daemon starting CodeScope...")
            warm_pool.mark_busy(worker_id, task_id)

            task.droplet.id = droplet_id
            task.droplet.ip = active_info.get("ip", "")
            task.droplet.slug = slug

            await ws_manager.broadcast(task_id, "droplet_active", {
                "droplet_id": droplet_id,
                "ip": task.droplet.ip,
            })
            logger.info("Audit %s assigned to new worker %s", task_id[:8], worker_id[:8])

        # Phase 3: Wait for completion
        _record_phase(task, TaskPhase.EXECUTING)
        await ws_manager.broadcast(task_id, "executing", {"type": "audit"})
        budget_tracker.record_spend(cost_report.total_cost_usd)

        timeout = 900  # 15 min max for audits (clone + install tools + 7 layers + AI)
        await _wait_for_completion(task, timeout)

    except Exception as e:
        logger.error("Audit %s failed: %s", task_id[:8], e)
        task.error = str(e)
        _record_phase(task, TaskPhase.FAILED)
        await ws_manager.broadcast(task_id, "error", {"message": str(e)})


@app.post("/api/v1/tasks/{task_id}/callback")
async def task_callback(task_id: str, payload: CallbackPayload):
    """Receive lifecycle callbacks from worker daemons."""
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")

    if payload.log_line:
        task.logs.append(payload.log_line)
        await ws_manager.broadcast(task_id, "log", {"line": payload.log_line})

    phase_map = {
        "running": TaskPhase.EXECUTING,
        "uploading": TaskPhase.UPLOADING,
        "completed": TaskPhase.COMPLETED,
        "failed": TaskPhase.FAILED,
    }
    new_phase = phase_map.get(payload.status)
    if new_phase and new_phase != task.status:
        _record_phase(task, new_phase)
        await ws_manager.broadcast(task_id, new_phase.value, {
            "status": payload.status,
            "exit_code": payload.exit_code,
        })

    return {"ok": True}


# ========================================
# Worker Endpoints (called by Droplet daemons)
# ========================================


@app.post("/api/v1/workers/{worker_id}/status")
async def worker_status(worker_id: str, update: WorkerStatusUpdate):
    """Worker reports its status (idle, busy, shutting_down)."""
    worker = warm_pool.workers.get(worker_id)
    if not worker:
        logger.warning("Unknown worker %s reporting status", worker_id)
        return {"ok": True}

    if update.status.value == "idle":
        warm_pool.mark_idle(worker_id)
    elif update.status.value == "busy":
        warm_pool.mark_busy(worker_id, update.current_task_id or "")
    elif update.status.value == "shutting_down":
        warm_pool.mark_shutting_down(worker_id)

    logger.info("Worker %s status: %s", worker_id[:8], update.status.value)
    return {"ok": True}


@app.get("/api/v1/workers/{worker_id}/task")
async def get_worker_task(worker_id: str):
    """Worker polls for its next task. Returns 204 if no task available."""
    task_data = task_queue.dequeue(worker_id)
    if not task_data:
        return {"task": None}
    return {"task": task_data}


# ========================================
# Stats
# ========================================


@app.get("/api/v1/audits/recent")
async def get_recent_audits(limit: int = 50):
    """Get the most recent audits across all users.

    Data is persisted in DigitalOcean Spaces - survives restarts.
    """
    from .audit_store import get_recent_audits as fetch_recent
    recent = await asyncio.to_thread(fetch_recent, limit)
    return {"audits": recent, "total": len(recent)}


@app.get("/api/v1/stats", response_model=StatsResponse)
async def get_stats():
    completed = [t for t in tasks.values() if t.status == TaskPhase.COMPLETED]
    all_tasks = list(tasks.values())
    pool_stats = warm_pool.get_stats()

    total_cost = sum(t.cost.total_cost_usd for t in all_tasks)
    total_monthly = sum(t.cost.always_on_equivalent_monthly for t in completed)
    total_seconds = sum(t.droplet.lifetime_seconds for t in completed)

    return StatsResponse(
        total_tasks=len(all_tasks),
        total_droplets_created=pool_stats.get("total", 0),
        total_droplets_destroyed=pool_stats.get("shutting_down", 0),
        total_compute_seconds=total_seconds,
        total_cost_usd=round(total_cost, 4),
        equivalent_always_on_cost_usd=round(total_monthly, 2),
        total_savings_usd=round(total_monthly - total_cost, 2),
        average_task_duration_seconds=(
            round(total_seconds / len(completed), 1) if completed else 0
        ),
        warm_pool_size=pool_stats.get("total", 0),
        warm_pool_idle=pool_stats.get("idle", 0),
        warm_pool_busy=pool_stats.get("busy", 0),
    )


# ========================================
# WebSocket
# ========================================


@app.websocket("/ws/tasks/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    await ws_manager.connect(task_id, websocket)
    try:
        task = tasks.get(task_id)
        if task:
            await websocket.send_json(
                {"event": "state", "data": task.model_dump(mode="json")}
            )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(task_id, websocket)


# ========================================
# Task Pipeline
# ========================================


async def _run_task(task: Task, req: TaskRequest) -> None:
    """Execute a task: plan → route to warm/new Droplet → track completion."""
    task_id = task.task_id

    try:
        # Phase 1: Planning
        _record_phase(task, TaskPhase.PLANNING)
        await ws_manager.broadcast(task_id, "planning", {"model": settings.gradient_model})

        input_files = [f.model_dump() for f in req.input_files] if req.input_files else None
        manifest = await asyncio.to_thread(
            generate_manifest, req.prompt, task_id, input_files
        )
        task.manifest = manifest

        # Enforce minimum Droplet size (snapshot needs 25GB disk)
        manifest.infra.slug = enforce_min_slug(manifest.infra.slug)

        cost_report = build_cost_report(manifest.infra.slug)
        task.cost = cost_report

        if not budget_tracker.check_budget(cost_report.total_cost_usd):
            raise Exception("Daily budget exceeded")

        await ws_manager.broadcast(task_id, "manifest_ready", {
            "slug": manifest.infra.slug,
            "reasoning": manifest.intent.reasoning,
        })

        # Phase 2: Route to warm pool or create new Droplet
        _record_phase(task, TaskPhase.PROVISIONING)
        routing = await route_task(task_id, manifest, req.prompt, warm_pool)

        if routing.warm:
            # Warm pool hit - task already queued for the worker
            worker = routing.worker
            task.droplet.id = worker.droplet_id
            task.droplet.ip = worker.droplet_ip
            task.droplet.slug = worker.size_slug
            await ws_manager.broadcast(task_id, "warm_hit", {
                "worker_id": worker.worker_id[:8],
                "droplet_id": worker.droplet_id,
                "reason": routing.reason,
            })
            logger.info("Task %s routed to warm worker %s", task_id[:8], worker.worker_id[:8])
        else:
            # Cold start - create new worker Droplet
            await ws_manager.broadcast(task_id, "provisioning", {"reason": "no_warm_worker"})

            active = await count_active_droplets()
            if active >= settings.max_concurrent_droplets:
                raise Exception(f"Max Droplets reached ({settings.max_concurrent_droplets})")

            worker_id = str(uuid.uuid4())
            droplet_info = await create_worker_droplet(manifest.infra.slug, worker_id)
            droplet_id = droplet_info["droplet_id"]

            # Wait for Droplet to boot
            active_info = await wait_for_active(droplet_id)

            # Register in warm pool
            warm_pool.add_worker(
                worker_id=worker_id,
                droplet_id=droplet_id,
                droplet_ip=active_info.get("ip", ""),
                size_slug=manifest.infra.slug,
            )

            # Assign this task to the new worker
            upload_urls = generate_upload_presigned_urls(task_id)
            task_queue.enqueue(worker_id, {
                "task_id": task_id,
                "description": req.prompt,
                "upload_urls": upload_urls,
            })
            warm_pool.mark_busy(worker_id, task_id)

            task.droplet.id = droplet_id
            task.droplet.ip = active_info.get("ip", "")
            task.droplet.slug = manifest.infra.slug

            await ws_manager.broadcast(task_id, "droplet_active", {
                "droplet_id": droplet_id,
                "ip": task.droplet.ip,
                "worker_id": worker_id[:8],
            })
            logger.info("Task %s assigned to new worker %s", task_id[:8], worker_id[:8])

        # Phase 3: Wait for completion
        _record_phase(task, TaskPhase.EXECUTING)
        await ws_manager.broadcast(task_id, "executing", {})

        budget_tracker.record_spend(cost_report.total_cost_usd)

        timeout = manifest.lifecycle.timeout_seconds + 420  # 7 min buffer for first boot + runtime install
        await _wait_for_completion(task, timeout)

    except Exception as e:
        logger.error("Task %s failed: %s", task_id[:8], e)
        task.error = str(e)
        _record_phase(task, TaskPhase.FAILED)
        await ws_manager.broadcast(task_id, "error", {"message": str(e)})


async def _wait_for_completion(task: Task, timeout: int) -> None:
    """Poll Spaces for _done.json marker."""
    task_id = task.task_id
    start = asyncio.get_event_loop().time()

    while asyncio.get_event_loop().time() - start < timeout:
        if task.status in (TaskPhase.COMPLETED, TaskPhase.FAILED):
            return

        try:
            done_data = await asyncio.to_thread(check_task_done, task_id)
            if done_data:
                logger.info("Task %s done: %s", task_id[:8], done_data)
                _record_phase(task, TaskPhase.COMPLETED)

                # Fetch results
                try:
                    results = await asyncio.to_thread(list_task_results, task_id)
                    task.results = [TaskResult(**r) for r in results]
                except Exception:
                    pass

                await ws_manager.broadcast(task_id, "completed", {
                    "exit_code": done_data.get("exit_code", -1),
                    "attempts": done_data.get("attempts", 0),
                    "language": done_data.get("language", "unknown"),
                    "files": [r.filename for r in task.results],
                })

                # Calculate lifetime
                if task.phases:
                    task.droplet.lifetime_seconds = (
                        datetime.utcnow() - task.phases[0].started_at
                    ).total_seconds()

                # Persist audit result to Spaces (survives restarts)
                try:
                    from .audit_store import save_audit
                    await asyncio.to_thread(
                        save_audit,
                        task_id=task_id,
                        repo_url=task.prompt.replace("CodeScope audit: ", "").split(" (branch")[0],
                        branch="main",
                        risk_score=done_data.get("risk_score", 0),
                        total_findings=done_data.get("total_findings", 0),
                        severity_counts={},
                        language=done_data.get("language", "unknown"),
                        framework=done_data.get("framework", "unknown"),
                        duration_seconds=task.droplet.lifetime_seconds,
                        summary=f"Audit completed with {done_data.get('total_findings', 0)} findings",
                    )
                except Exception as e:
                    logger.error("Failed to persist audit: %s", e)

                return
        except Exception:
            pass

        await asyncio.sleep(5)

    # Timeout
    task.error = f"Task timed out after {timeout}s"
    _record_phase(task, TaskPhase.FAILED)
    await ws_manager.broadcast(task.task_id, "error", {"message": task.error})


# ========================================
# Background: Pool Reaper
# ========================================


async def _rediscover_warm_pool() -> None:
    """On startup, find existing ephemeral-ai Droplets and re-register them.

    This survives orchestrator restarts - Droplets keep running and polling,
    we just need to know about them so we can route tasks to them.
    """
    try:
        from .droplet_manager import list_ephemeral_droplets
        droplets = await list_ephemeral_droplets()
        for d in droplets:
            droplet_id = d["id"]
            name = d.get("name", "")
            ip = ""
            for net in d.get("networks", {}).get("v4", []):
                if net.get("type") == "public":
                    ip = net["ip_address"]
                    break
            size = d.get("size_slug", "s-1vcpu-1gb")
            # Extract worker_id from name (format: worker-{id[:8]})
            worker_id = name.replace("worker-", "") + "-rediscovered"

            # Extract worker_id from tags
            for tag in d.get("tags", []):
                if tag.startswith("worker-"):
                    worker_id = tag.replace("worker-", "")

            warm_pool.add_worker(
                worker_id=worker_id,
                droplet_id=droplet_id,
                droplet_ip=ip,
                size_slug=size,
            )
            logger.info(
                "Rediscovered Droplet %d (%s) ip=%s -> warm pool",
                droplet_id, name, ip,
            )

        if droplets:
            logger.info("Rediscovered %d Droplets into warm pool", len(droplets))
        else:
            logger.info("No existing Droplets found")
    except Exception as e:
        logger.error("Warm pool rediscovery failed: %s", e)


async def _pool_reaper_loop() -> None:
    """Destroy expired workers and orphaned Droplets."""
    await asyncio.sleep(30)  # Let app fully start before first reap
    logger.info("Pool reaper started (interval=60s)")
    while True:
        try:
            # Destroy workers past their billing window
            expired = warm_pool.get_expired_workers()
            for worker in expired:
                logger.warning(
                    "Reaping expired worker %s (Droplet %d)",
                    worker.worker_id[:8],
                    worker.droplet_id,
                )
                try:
                    await destroy_droplet(worker.droplet_id)
                except Exception as e:
                    logger.error("Failed to destroy Droplet %d: %s", worker.droplet_id, e)
                warm_pool.remove_worker(worker.worker_id)

        except Exception as e:
            logger.error("Reaper error: %s", e)

        await asyncio.sleep(60)


# ========================================
# Helpers
# ========================================


def _record_phase(task: Task, phase: TaskPhase) -> None:
    now = datetime.utcnow()
    if task.phases:
        prev = task.phases[-1]
        if prev.duration_ms is None:
            prev.duration_ms = int((now - prev.started_at).total_seconds() * 1000)
    task.phases.append(PhaseRecord(phase=phase, started_at=now))
    task.status = phase


# --- Entry point ---

def run():
    import uvicorn
    uvicorn.run("orchestrator.main:app", host="0.0.0.0", port=8000, reload=True)

if __name__ == "__main__":
    run()
