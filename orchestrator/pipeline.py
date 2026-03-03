"""Pipeline/DAG Engine for Ephemeral.ai.

Handles multi-step task execution with dependency resolution and fan-out/fan-in
batch processing. Complex tasks are decomposed into pipeline steps that run on
separate ephemeral Droplets, passing data between steps via DigitalOcean Spaces.

Inter-step data flow:
    Step A writes results to  tasks/{step_a_task_id}/output.tar.gz
    Step B's prompt includes a presigned URL to download Step A's output
    The build_step_context() method generates these references automatically
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from openai import OpenAI

from .config import settings

logger = logging.getLogger("ephemeral.pipeline")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PipelineStep:
    """A single step within a pipeline DAG."""

    step_id: str  # e.g. "step_1"
    description: str  # Natural language description of this step
    depends_on: list[str]  # step_ids that must complete before this starts
    status: str = "pending"  # pending | running | completed | failed
    task_id: str | None = None  # Ephemeral task ID assigned to run this step
    result_key: str | None = None  # Spaces key prefix where results are stored
    worker_id: str | None = None  # Worker (Droplet) that executed this step
    error: str | None = None  # Error message if the step failed
    started_at: datetime | None = None
    completed_at: datetime | None = None


@dataclass
class Pipeline:
    """A directed acyclic graph of PipelineSteps."""

    pipeline_id: str
    description: str  # Original user task
    steps: list[PipelineStep]
    status: str = "planning"  # planning | running | completed | failed
    created_at: datetime = field(default_factory=datetime.utcnow)

    # ---- DAG helpers ----

    def get_ready_steps(self) -> list[PipelineStep]:
        """Return steps whose dependencies are all completed and that are
        still pending (not yet dispatched)."""
        completed_ids = {
            s.step_id for s in self.steps if s.status == "completed"
        }
        return [
            s
            for s in self.steps
            if s.status == "pending"
            and all(dep in completed_ids for dep in s.depends_on)
        ]

    def is_complete(self) -> bool:
        """True when every step has completed, *or* any step has failed."""
        if any(s.status == "failed" for s in self.steps):
            return True
        return all(s.status == "completed" for s in self.steps)

    def get_step(self, step_id: str) -> PipelineStep | None:
        """Look up a step by its ID."""
        for s in self.steps:
            if s.step_id == step_id:
                return s
        return None


# ---------------------------------------------------------------------------
# Fan-out models
# ---------------------------------------------------------------------------


@dataclass
class FanOutConfig:
    """Configuration for splitting a batch task across multiple workers."""

    task_template: str  # Task description template with {item} placeholder
    items: list[str]  # Items to process
    batch_size: int  # Items per worker
    merge_task: str | None = None  # Optional task to merge results


@dataclass
class FanOutJob:
    """Tracks a fan-out job that distributes work across parallel workers."""

    job_id: str
    config: FanOutConfig
    batches: list[dict] = field(default_factory=list)
    # Each batch: {batch_id: str, items: list[str], task_id: str|None, status: str}
    merge_step: dict | None = None
    # Merge step: {task_id: str|None, status: str}
    status: str = "running"  # running | merging | completed | failed


# ---------------------------------------------------------------------------
# Pipeline Manager
# ---------------------------------------------------------------------------


class PipelineManager:
    """In-memory manager for pipelines and fan-out jobs.

    Used by main.py to orchestrate complex multi-step tasks that span
    multiple ephemeral Droplets.  All state is held in memory (hackathon
    scope -- no persistent backend required).
    """

    def __init__(self) -> None:
        self.pipelines: dict[str, Pipeline] = {}
        self.fan_out_jobs: dict[str, FanOutJob] = {}

    # ---- Pipeline lifecycle ----

    def create_pipeline(
        self,
        pipeline_id: str,
        description: str,
        steps: list[dict],
    ) -> Pipeline:
        """Create a new pipeline from a list of step definitions.

        Args:
            pipeline_id: Unique identifier for this pipeline.
            description: Original user task description.
            steps: List of dicts, each containing:
                - step_id (str)
                - description (str)
                - depends_on (list[str])

        Returns:
            The newly created Pipeline.

        Raises:
            ValueError: If step definitions are invalid or contain cycles.
        """
        # Validate step definitions
        step_ids: set[str] = set()
        for step_def in steps:
            sid = step_def.get("step_id")
            if not sid:
                raise ValueError("Every step must have a step_id")
            if sid in step_ids:
                raise ValueError(f"Duplicate step_id: {sid}")
            step_ids.add(sid)

        # Validate dependencies reference existing steps
        for step_def in steps:
            for dep in step_def.get("depends_on", []):
                if dep not in step_ids:
                    raise ValueError(
                        f"Step '{step_def['step_id']}' depends on unknown "
                        f"step '{dep}'"
                    )

        # Check for cycles using topological sort (Kahn's algorithm)
        _validate_no_cycles(steps)

        pipeline_steps = [
            PipelineStep(
                step_id=s["step_id"],
                description=s["description"],
                depends_on=s.get("depends_on", []),
            )
            for s in steps
        ]

        pipeline = Pipeline(
            pipeline_id=pipeline_id,
            description=description,
            steps=pipeline_steps,
            status="running",
        )
        self.pipelines[pipeline_id] = pipeline

        logger.info(
            "Created pipeline %s with %d steps: %s",
            pipeline_id,
            len(pipeline_steps),
            [s.step_id for s in pipeline_steps],
        )
        return pipeline

    def mark_step_running(
        self,
        pipeline_id: str,
        step_id: str,
        task_id: str,
        worker_id: str,
    ) -> None:
        """Mark a pipeline step as running on a specific worker."""
        step = self._get_step_or_raise(pipeline_id, step_id)
        step.status = "running"
        step.task_id = task_id
        step.worker_id = worker_id
        step.started_at = datetime.utcnow()

        logger.info(
            "Pipeline %s step %s now running (task=%s, worker=%s)",
            pipeline_id,
            step_id,
            task_id,
            worker_id,
        )

    def mark_step_completed(
        self,
        pipeline_id: str,
        step_id: str,
        result_key: str,
    ) -> None:
        """Mark a pipeline step as completed and record where results live."""
        pipeline = self._get_pipeline_or_raise(pipeline_id)
        step = self._get_step_or_raise(pipeline_id, step_id)
        step.status = "completed"
        step.result_key = result_key
        step.completed_at = datetime.utcnow()

        logger.info(
            "Pipeline %s step %s completed (result_key=%s)",
            pipeline_id,
            step_id,
            result_key,
        )

        # Check if the entire pipeline is now complete
        if pipeline.is_complete():
            pipeline.status = "completed"
            logger.info("Pipeline %s fully completed", pipeline_id)

    def mark_step_failed(
        self,
        pipeline_id: str,
        step_id: str,
        error: str,
    ) -> None:
        """Mark a pipeline step (and the whole pipeline) as failed."""
        pipeline = self._get_pipeline_or_raise(pipeline_id)
        step = self._get_step_or_raise(pipeline_id, step_id)
        step.status = "failed"
        step.error = error
        step.completed_at = datetime.utcnow()

        # A single failed step fails the pipeline
        pipeline.status = "failed"
        logger.error(
            "Pipeline %s step %s failed: %s", pipeline_id, step_id, error
        )

    def get_ready_steps(self, pipeline_id: str) -> list[PipelineStep]:
        """Get steps that are ready to execute (all dependencies met)."""
        pipeline = self._get_pipeline_or_raise(pipeline_id)
        return pipeline.get_ready_steps()

    def get_pipeline_status(self, pipeline_id: str) -> dict:
        """Build a full pipeline status dict suitable for the dashboard.

        Returns a JSON-serializable dict with pipeline metadata and per-step
        status information.
        """
        pipeline = self._get_pipeline_or_raise(pipeline_id)

        steps_status = []
        for step in pipeline.steps:
            step_info: dict[str, Any] = {
                "step_id": step.step_id,
                "description": step.description,
                "depends_on": step.depends_on,
                "status": step.status,
                "task_id": step.task_id,
                "result_key": step.result_key,
                "worker_id": step.worker_id,
                "error": step.error,
            }
            if step.started_at:
                step_info["started_at"] = step.started_at.isoformat() + "Z"
            if step.completed_at:
                step_info["completed_at"] = step.completed_at.isoformat() + "Z"
                if step.started_at:
                    duration = (
                        step.completed_at - step.started_at
                    ).total_seconds()
                    step_info["duration_seconds"] = round(duration, 2)
            steps_status.append(step_info)

        completed = sum(1 for s in pipeline.steps if s.status == "completed")
        failed = sum(1 for s in pipeline.steps if s.status == "failed")
        running = sum(1 for s in pipeline.steps if s.status == "running")
        pending = sum(1 for s in pipeline.steps if s.status == "pending")

        return {
            "pipeline_id": pipeline.pipeline_id,
            "description": pipeline.description,
            "status": pipeline.status,
            "created_at": pipeline.created_at.isoformat() + "Z",
            "total_steps": len(pipeline.steps),
            "completed": completed,
            "failed": failed,
            "running": running,
            "pending": pending,
            "progress_pct": round(
                completed / len(pipeline.steps) * 100, 1
            )
            if pipeline.steps
            else 0,
            "steps": steps_status,
        }

    def build_step_context(self, pipeline_id: str, step_id: str) -> str:
        """Build context for a step, including references to predecessor outputs.

        When a step depends on earlier steps that have completed, this method
        generates human-readable instructions telling the workbench agent where
        to find predecessor outputs in Spaces.  The presigned download URLs are
        constructed using the standard Spaces URL pattern.

        Returns:
            A string to prepend to the step's task description, giving the
            workbench agent full context about upstream results.
        """
        pipeline = self._get_pipeline_or_raise(pipeline_id)
        step = self._get_step_or_raise(pipeline_id, step_id)

        context_parts: list[str] = []

        # Add pipeline-level context
        context_parts.append(
            f"You are executing step '{step.step_id}' of a multi-step pipeline."
        )
        context_parts.append(f"Pipeline goal: {pipeline.description}")
        context_parts.append("")

        # Add predecessor output references
        predecessor_refs: list[str] = []
        for dep_id in step.depends_on:
            dep_step = pipeline.get_step(dep_id)
            if dep_step is None:
                continue

            if dep_step.status == "completed" and dep_step.task_id:
                spaces_url = (
                    f"https://{settings.spaces_bucket}"
                    f".{settings.spaces_region}.digitaloceanspaces.com"
                    f"/tasks/{dep_step.task_id}/output.tar.gz"
                )
                predecessor_refs.append(
                    f"- Previous step '{dep_step.step_id}' "
                    f"({dep_step.description}): results stored at "
                    f"s3://{settings.spaces_bucket}/tasks/"
                    f"{dep_step.task_id}/output.tar.gz  "
                    f"Download URL: {spaces_url}"
                )

        if predecessor_refs:
            context_parts.append("=== Upstream Results ===")
            context_parts.append(
                "Download and use the outputs from these completed steps:"
            )
            context_parts.extend(predecessor_refs)
            context_parts.append("")

        # Add the step's own description
        context_parts.append("=== Your Task ===")
        context_parts.append(step.description)

        return "\n".join(context_parts)

    # ---- Fan-out operations ----

    def create_fan_out(self, job_id: str, config: FanOutConfig) -> FanOutJob:
        """Create a fan-out job that splits work across multiple workers.

        Items are divided into batches of ``config.batch_size``. Each batch
        gets its own ephemeral task, with the task description generated from
        ``config.task_template`` by substituting ``{item}`` with the
        comma-separated list of items for that batch.

        Args:
            job_id: Unique identifier for this fan-out job.
            config: Fan-out configuration with template, items, and batch size.

        Returns:
            The newly created FanOutJob with batch definitions.
        """
        if config.batch_size <= 0:
            raise ValueError("batch_size must be > 0")
        if not config.items:
            raise ValueError("items list must not be empty")

        batches: list[dict] = []
        num_batches = math.ceil(len(config.items) / config.batch_size)

        for i in range(num_batches):
            start = i * config.batch_size
            end = start + config.batch_size
            batch_items = config.items[start:end]
            batch_id = f"{job_id}_batch_{i}"

            batches.append(
                {
                    "batch_id": batch_id,
                    "items": batch_items,
                    "task_id": None,
                    "status": "pending",
                }
            )

        merge_step = None
        if config.merge_task:
            merge_step = {"task_id": None, "status": "pending"}

        job = FanOutJob(
            job_id=job_id,
            config=config,
            batches=batches,
            merge_step=merge_step,
            status="running",
        )
        self.fan_out_jobs[job_id] = job

        logger.info(
            "Created fan-out job %s: %d items -> %d batches (batch_size=%d)",
            job_id,
            len(config.items),
            len(batches),
            config.batch_size,
        )
        return job

    def get_fan_out_batch_description(
        self, job_id: str, batch_id: str
    ) -> str:
        """Generate the task description for a specific fan-out batch.

        Substitutes ``{item}`` in the task template with the batch's items.
        """
        job = self._get_fan_out_or_raise(job_id)

        batch = None
        for b in job.batches:
            if b["batch_id"] == batch_id:
                batch = b
                break
        if batch is None:
            raise ValueError(
                f"Batch '{batch_id}' not found in fan-out job '{job_id}'"
            )

        items_str = ", ".join(batch["items"])
        return job.config.task_template.replace("{item}", items_str)

    def mark_fan_out_batch_running(
        self, job_id: str, batch_id: str, task_id: str
    ) -> None:
        """Mark a fan-out batch as running with the given task ID."""
        job = self._get_fan_out_or_raise(job_id)
        for batch in job.batches:
            if batch["batch_id"] == batch_id:
                batch["status"] = "running"
                batch["task_id"] = task_id
                logger.info(
                    "Fan-out %s batch %s running (task=%s)",
                    job_id,
                    batch_id,
                    task_id,
                )
                return
        raise ValueError(
            f"Batch '{batch_id}' not found in fan-out job '{job_id}'"
        )

    def mark_fan_out_batch_completed(
        self, job_id: str, batch_id: str
    ) -> None:
        """Mark a fan-out batch as completed. Transitions job to 'merging'
        or 'completed' when all batches are done."""
        job = self._get_fan_out_or_raise(job_id)
        for batch in job.batches:
            if batch["batch_id"] == batch_id:
                batch["status"] = "completed"
                logger.info(
                    "Fan-out %s batch %s completed", job_id, batch_id
                )
                break
        else:
            raise ValueError(
                f"Batch '{batch_id}' not found in fan-out job '{job_id}'"
            )

        # Check if all batches are done
        if all(b["status"] == "completed" for b in job.batches):
            if job.merge_step is not None:
                job.status = "merging"
                logger.info(
                    "Fan-out %s all batches complete, moving to merge",
                    job_id,
                )
            else:
                job.status = "completed"
                logger.info("Fan-out %s completed (no merge step)", job_id)

    def mark_fan_out_batch_failed(
        self, job_id: str, batch_id: str, error: str
    ) -> None:
        """Mark a fan-out batch as failed, which fails the whole job."""
        job = self._get_fan_out_or_raise(job_id)
        for batch in job.batches:
            if batch["batch_id"] == batch_id:
                batch["status"] = "failed"
                break
        job.status = "failed"
        logger.error(
            "Fan-out %s batch %s failed: %s", job_id, batch_id, error
        )

    def mark_fan_out_merge_running(
        self, job_id: str, task_id: str
    ) -> None:
        """Mark the merge step of a fan-out job as running."""
        job = self._get_fan_out_or_raise(job_id)
        if job.merge_step is None:
            raise ValueError(f"Fan-out job '{job_id}' has no merge step")
        job.merge_step["status"] = "running"
        job.merge_step["task_id"] = task_id
        logger.info(
            "Fan-out %s merge step running (task=%s)", job_id, task_id
        )

    def mark_fan_out_merge_completed(self, job_id: str) -> None:
        """Mark the merge step as completed, completing the job."""
        job = self._get_fan_out_or_raise(job_id)
        if job.merge_step is None:
            raise ValueError(f"Fan-out job '{job_id}' has no merge step")
        job.merge_step["status"] = "completed"
        job.status = "completed"
        logger.info("Fan-out %s merge completed, job done", job_id)

    def mark_fan_out_merge_failed(self, job_id: str, error: str) -> None:
        """Mark the merge step as failed, failing the job."""
        job = self._get_fan_out_or_raise(job_id)
        if job.merge_step is None:
            raise ValueError(f"Fan-out job '{job_id}' has no merge step")
        job.merge_step["status"] = "failed"
        job.status = "failed"
        logger.error("Fan-out %s merge failed: %s", job_id, error)

    def build_fan_out_merge_context(self, job_id: str) -> str:
        """Build the merge task description with references to all batch outputs.

        After all fan-out batches complete, this generates a task description
        for the merge step that includes download URLs for every batch's
        output.
        """
        job = self._get_fan_out_or_raise(job_id)
        if not job.config.merge_task:
            raise ValueError(f"Fan-out job '{job_id}' has no merge_task")

        parts: list[str] = []
        parts.append(
            "You are the merge step of a fan-out batch processing job."
        )
        parts.append(f"Merge task: {job.config.merge_task}")
        parts.append("")
        parts.append("=== Batch Outputs ===")
        parts.append(
            "Download and combine the results from these completed batches:"
        )

        for batch in job.batches:
            task_id = batch.get("task_id")
            if task_id and batch["status"] == "completed":
                spaces_url = (
                    f"https://{settings.spaces_bucket}"
                    f".{settings.spaces_region}.digitaloceanspaces.com"
                    f"/tasks/{task_id}/output.tar.gz"
                )
                items_preview = ", ".join(batch["items"][:3])
                if len(batch["items"]) > 3:
                    items_preview += f" ... (+{len(batch['items']) - 3} more)"
                parts.append(
                    f"- Batch '{batch['batch_id']}' "
                    f"(items: {items_preview}): {spaces_url}"
                )

        parts.append("")
        parts.append("=== Your Task ===")
        parts.append(job.config.merge_task)

        return "\n".join(parts)

    def get_fan_out_status(self, job_id: str) -> dict:
        """Build a status dict for a fan-out job."""
        job = self._get_fan_out_or_raise(job_id)

        completed = sum(1 for b in job.batches if b["status"] == "completed")
        failed = sum(1 for b in job.batches if b["status"] == "failed")
        running = sum(1 for b in job.batches if b["status"] == "running")
        pending = sum(1 for b in job.batches if b["status"] == "pending")

        return {
            "job_id": job.job_id,
            "status": job.status,
            "total_items": len(job.config.items),
            "batch_size": job.config.batch_size,
            "total_batches": len(job.batches),
            "batches_completed": completed,
            "batches_failed": failed,
            "batches_running": running,
            "batches_pending": pending,
            "progress_pct": round(
                completed / len(job.batches) * 100, 1
            )
            if job.batches
            else 0,
            "has_merge_step": job.merge_step is not None,
            "merge_status": (
                job.merge_step["status"] if job.merge_step else None
            ),
            "batches": [
                {
                    "batch_id": b["batch_id"],
                    "item_count": len(b["items"]),
                    "task_id": b["task_id"],
                    "status": b["status"],
                }
                for b in job.batches
            ],
        }

    # ---- Private helpers ----

    def _get_pipeline_or_raise(self, pipeline_id: str) -> Pipeline:
        pipeline = self.pipelines.get(pipeline_id)
        if pipeline is None:
            raise ValueError(f"Pipeline '{pipeline_id}' not found")
        return pipeline

    def _get_step_or_raise(
        self, pipeline_id: str, step_id: str
    ) -> PipelineStep:
        pipeline = self._get_pipeline_or_raise(pipeline_id)
        step = pipeline.get_step(step_id)
        if step is None:
            raise ValueError(
                f"Step '{step_id}' not found in pipeline '{pipeline_id}'"
            )
        return step

    def _get_fan_out_or_raise(self, job_id: str) -> FanOutJob:
        job = self.fan_out_jobs.get(job_id)
        if job is None:
            raise ValueError(f"Fan-out job '{job_id}' not found")
        return job


# ---------------------------------------------------------------------------
# DAG validation
# ---------------------------------------------------------------------------


def _validate_no_cycles(steps: list[dict]) -> None:
    """Validate that a list of step definitions forms a valid DAG (no cycles).

    Uses Kahn's algorithm for topological sorting.

    Raises:
        ValueError: If the dependency graph contains a cycle.
    """
    # Build adjacency list and in-degree map
    in_degree: dict[str, int] = {}
    dependents: dict[str, list[str]] = {}  # parent -> [children]

    for step in steps:
        sid = step["step_id"]
        if sid not in in_degree:
            in_degree[sid] = 0
        if sid not in dependents:
            dependents[sid] = []

        for dep in step.get("depends_on", []):
            in_degree[sid] = in_degree.get(sid, 0) + 1
            if dep not in dependents:
                dependents[dep] = []
            dependents[dep].append(sid)

    # Start with nodes that have no dependencies
    queue = [sid for sid, deg in in_degree.items() if deg == 0]
    visited_count = 0

    while queue:
        node = queue.pop(0)
        visited_count += 1
        for child in dependents.get(node, []):
            in_degree[child] -= 1
            if in_degree[child] == 0:
                queue.append(child)

    if visited_count != len(in_degree):
        raise ValueError(
            "Pipeline step dependencies contain a cycle. "
            "Steps must form a directed acyclic graph (DAG)."
        )


# ---------------------------------------------------------------------------
# Task decomposition via Gradient AI
# ---------------------------------------------------------------------------


DECOMPOSITION_SYSTEM_PROMPT = """\
You are the Ephemeral.ai task planner. Given a user's task description, decide \
whether it should run as a single task, a multi-step pipeline, or a fan-out \
batch job.

MODES:
- "single": The task is simple enough to run on one Droplet in one shot.
- "pipeline": The task requires multiple sequential/parallel steps with data \
dependencies. Each step runs on its own ephemeral Droplet. Steps can depend on \
other steps (DAG structure). Data passes between steps via cloud storage.
- "fan_out": The task involves processing many items in parallel with the same \
operation. Items are batched across workers, with an optional merge step.

RULES:
1. Prefer "single" unless the task genuinely needs multiple stages or batch \
parallelism.
2. For "pipeline", define clear step boundaries. Each step should be a self-contained \
unit of work that produces output the next step can consume.
3. For "fan_out", identify the repeating unit of work and the item list.
4. Steps should have meaningful, descriptive IDs (e.g., "scrape_data", "analyze", \
"generate_report").
5. Keep pipelines short - usually 2-4 steps. Only add steps when there is a real \
data dependency or resource boundary.

Output ONLY valid JSON. No markdown, no explanation, no code fences.

SCHEMA:
{
    "mode": "single" | "pipeline" | "fan_out",
    "reasoning": "<brief explanation of why you chose this mode>",
    "steps": [
        {
            "step_id": "step_1",
            "description": "<what this step does, detailed enough for an AI agent>",
            "depends_on": []
        },
        {
            "step_id": "step_2",
            "description": "<what this step does>",
            "depends_on": ["step_1"]
        }
    ],
    "fan_out": {
        "task_template": "Process {item} and save results",
        "items": ["item1", "item2", "item3"],
        "batch_size": 25,
        "merge_task": "Combine all batch results into a final report"
    }
}

NOTES:
- "steps" is always present. For "single" mode, return exactly one step.
- "fan_out" is only present when mode == "fan_out".
- For "fan_out", also include a single step in "steps" as a placeholder.
- Step descriptions should be detailed - the executing agent has no other context.
"""


def build_decomposition_prompt(task_description: str) -> str:
    """Build a prompt for Gradient AI to decompose a task into pipeline steps.

    This is used by the orchestrator to decide whether a user's task should
    run as a single task, a multi-step pipeline, or a fan-out batch job.

    Args:
        task_description: The user's original task description.

    Returns:
        The user-role prompt string to send alongside DECOMPOSITION_SYSTEM_PROMPT.
    """
    return (
        f"Analyze this task and decide how to execute it:\n\n"
        f"{task_description}\n\n"
        f"Respond with the execution plan JSON."
    )


def decompose_task(task_description: str) -> dict:
    """Call Gradient AI to decompose a task into an execution plan.

    Uses the task decomposition prompt to ask the LLM whether the task should
    be a single execution, a pipeline, or a fan-out job.

    Args:
        task_description: The user's original task prompt.

    Returns:
        Parsed JSON dict with keys: mode, reasoning, steps, and optionally
        fan_out.

    Raises:
        RuntimeError: If the LLM fails to produce valid JSON after retries.
    """
    client = OpenAI(
        base_url=settings.gradient_base_url,
        api_key=settings.gradient_model_access_key,
    )

    user_prompt = build_decomposition_prompt(task_description)
    last_error = None

    for attempt in range(3):
        try:
            logger.info(
                "Decomposing task (attempt %d/3): %.80s...",
                attempt + 1,
                task_description,
            )
            response = client.chat.completions.create(
                model=settings.gradient_model,
                messages=[
                    {"role": "system", "content": DECOMPOSITION_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_completion_tokens=2048,
            )

            raw = response.choices[0].message.content.strip()

            # Strip markdown code fences if present
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1]
                if raw.endswith("```"):
                    raw = raw[: raw.rfind("```")]
                raw = raw.strip()

            plan = json.loads(raw)

            # Validate required fields
            if "mode" not in plan:
                raise ValueError("Missing 'mode' in decomposition output")
            if plan["mode"] not in ("single", "pipeline", "fan_out"):
                raise ValueError(f"Invalid mode: {plan['mode']}")
            if "steps" not in plan or not plan["steps"]:
                raise ValueError("Missing or empty 'steps' in output")
            if plan["mode"] == "fan_out" and "fan_out" not in plan:
                raise ValueError(
                    "Mode is 'fan_out' but 'fan_out' config is missing"
                )

            logger.info(
                "Task decomposed: mode=%s, %d steps",
                plan["mode"],
                len(plan["steps"]),
            )
            return plan

        except (json.JSONDecodeError, ValueError, Exception) as e:
            last_error = e
            logger.warning(
                "Task decomposition attempt %d failed: %s", attempt + 1, e
            )

    raise RuntimeError(
        f"Failed to decompose task after 3 attempts: {last_error}"
    )
