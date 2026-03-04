"""Pydantic models for the Ephemeral.ai API."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# --- Enums ---


class TaskPhase(str, Enum):
    PLANNING = "planning"
    PROVISIONING = "provisioning"
    EXECUTING = "executing"
    UPLOADING = "uploading"
    COMPLETED = "completed"
    FAILED = "failed"
    DESTROYED = "destroyed"


class TaskCategory(str, Enum):
    DATA_PROCESSING = "data_processing"
    WEB_SCRAPING = "web_scraping"
    CODE_EXECUTION = "code_execution"
    FILE_CONVERSION = "file_conversion"
    API_INTEGRATION = "api_integration"
    ANALYSIS = "analysis"
    BATCH_PROCESSING = "batch_processing"
    SECURITY_AUDIT = "security_audit"


class TerminationPolicy(str, Enum):
    IMMEDIATE_AFTER_OUTPUT = "immediate_after_output"
    WAIT_FOR_UPLOAD = "wait_for_upload"
    MANUAL = "manual"


class OutputFormat(str, Enum):
    STDOUT = "stdout"
    FILE = "file"
    JSON = "json"
    PRESIGNED_URL = "presigned_url"


# --- Manifest (LLM output) ---


class TaskComplexity(str, Enum):
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"


class ManifestIntent(BaseModel):
    summary: str
    category: TaskCategory
    complexity: TaskComplexity = TaskComplexity.SIMPLE
    reasoning: str


class ManifestInfra(BaseModel):
    slug: str = "s-1vcpu-1gb"
    region: str = "nyc3"
    snapshot_id: str | None = None


class ManifestRuntime(BaseModel):
    language: str = "python"
    version: str = "3.11"
    dependencies: list[str] = Field(default_factory=list)


class ManifestInputFile(BaseModel):
    url: str
    path: str = "/tmp/input/data"


class ManifestPayload(BaseModel):
    code: str
    entry_command: str = "python3 /opt/task/main.py"
    input_files: list[ManifestInputFile] = Field(default_factory=list)


class ManifestLifecycle(BaseModel):
    timeout_seconds: int = Field(default=120, ge=30, le=3600)
    estimated_attempts: int = Field(default=1, ge=1, le=5)
    termination: TerminationPolicy = TerminationPolicy.WAIT_FOR_UPLOAD
    output_format: OutputFormat = OutputFormat.PRESIGNED_URL


class ManifestCostEstimate(BaseModel):
    droplet_hourly_rate: float = 0.0
    estimated_duration_seconds: int = 60
    estimated_cost_usd: float = 0.0
    always_on_monthly_cost: float = 0.0
    savings_percentage: float = 0.0


class Manifest(BaseModel):
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    intent: ManifestIntent
    infra: ManifestInfra
    runtime: ManifestRuntime
    payload: ManifestPayload
    lifecycle: ManifestLifecycle
    cost_estimate: ManifestCostEstimate = Field(
        default_factory=ManifestCostEstimate
    )


# --- API request/response ---


class InputFileRef(BaseModel):
    url: str
    filename: str | None = None


class TaskPreferences(BaseModel):
    region: str = "nyc3"
    max_cost_usd: float = 0.10


class TaskRequest(BaseModel):
    prompt: str
    input_files: list[InputFileRef] = Field(default_factory=list)
    preferences: TaskPreferences = Field(default_factory=TaskPreferences)


class PhaseRecord(BaseModel):
    phase: TaskPhase
    started_at: datetime
    duration_ms: int | None = None


class TaskResult(BaseModel):
    filename: str
    size_bytes: int = 0
    download_url: str = ""


class CostReport(BaseModel):
    inference_cost_usd: float = 0.0
    droplet_cost_usd: float = 0.0
    total_cost_usd: float = 0.0
    always_on_equivalent_monthly: float = 0.0
    savings_pct: float = 0.0


class DropletInfo(BaseModel):
    id: int = 0
    slug: str = ""
    ip: str = ""
    lifetime_seconds: float = 0.0


class Task(BaseModel):
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: TaskPhase = TaskPhase.PLANNING
    prompt: str = ""
    manifest: Manifest | None = None
    phases: list[PhaseRecord] = Field(default_factory=list)
    results: list[TaskResult] = Field(default_factory=list)
    cost: CostReport = Field(default_factory=CostReport)
    droplet: DropletInfo = Field(default_factory=DropletInfo)
    logs: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None


class TaskResponse(BaseModel):
    task_id: str
    status: TaskPhase
    manifest: Manifest | None = None
    websocket_url: str = ""
    estimated_cost_usd: float = 0.0
    estimated_duration_seconds: int = 0


class CallbackPayload(BaseModel):
    status: str
    phase: str = ""
    exit_code: int | None = None
    log_line: str | None = None
    error: str | None = None


# --- Worker / Warm Pool ---


class WorkerStatus(str, Enum):
    BOOTING = "booting"
    IDLE = "idle"
    BUSY = "busy"
    SHUTTING_DOWN = "shutting_down"


class WorkerStatusUpdate(BaseModel):
    status: WorkerStatus
    current_task_id: str | None = None
    tasks_completed: int | None = None
    error: str | None = None


class WorkerTaskResponse(BaseModel):
    """Task assignment sent to a polling worker."""
    task_id: str
    description: str
    upload_urls: dict[str, str]  # filename -> presigned PUT URL


class StatsResponse(BaseModel):
    total_tasks: int = 0
    total_droplets_created: int = 0
    total_droplets_destroyed: int = 0
    total_compute_seconds: float = 0.0
    total_cost_usd: float = 0.0
    equivalent_always_on_cost_usd: float = 0.0
    total_savings_usd: float = 0.0
    average_task_duration_seconds: float = 0.0
    warm_pool_size: int = 0
    warm_pool_idle: int = 0
    warm_pool_busy: int = 0


# --- CodeScope Audit ---


class AuditRequest(BaseModel):
    repo_url: str
    branch: str = "main"
