# Ephemeral.ai - Comprehensive Technical Specification

**Version:** 2.0
**Status:** Hackathon Submission / Open Source
**Hackathon:** [DigitalOcean Gradient AI Hackathon](https://digitalocean.devpost.com/) (Deadline: March 18, 2026)
**Infrastructure:** DigitalOcean Gradient AI Platform, App Platform, Droplets, Spaces
**License:** MIT

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement & Market Context](#2-problem-statement--market-context)
3. [Evolved Architecture](#3-evolved-architecture)
4. [The Manifest Protocol v2](#4-the-manifest-protocol-v2)
5. [Component Deep-Dives](#5-component-deep-dives)
6. [API Design](#6-api-design)
7. [Security Model](#7-security-model)
8. [Cost Optimization Engine](#8-cost-optimization-engine)
9. [Dashboard & UX](#9-dashboard--ux)
10. [Implementation Plan](#10-implementation-plan)
11. [Prize Strategy](#11-prize-strategy)
12. [Tech Stack Summary](#12-tech-stack-summary)
13. [Risk Mitigation](#13-risk-mitigation)
14. [Future Vision](#14-future-vision)

---

## 1. Executive Summary

**Ephemeral.ai** is a Just-In-Time (JIT) agentic infrastructure orchestrator built on DigitalOcean's Gradient AI Platform. It transforms natural language task descriptions into precisely-sized, short-lived compute environments that exist only for the "lifetime of a thought."

**Core Philosophy:** Infrastructure should materialize on demand, execute with precision, and vanish without a trace.

### What Makes This Different

| Existing Solutions | Ephemeral.ai |
|---|---|
| Lambda/Cloud Run: fixed runtimes, language-locked | LLM predicts optimal runtime, language, and size |
| Modal.com: Python-only, proprietary | Any language, open-source, DO-native |
| E2B: sandboxes for code only | Full VM orchestration with data pipeline support |
| Manual DevOps: human decides server size | AI-driven resource prediction with cost reasoning |

### The Innovation

The LLM doesn't just run code - it **reasons about infrastructure**. Given "Process this 500MB CSV and generate charts," it determines:
- Python + pandas + matplotlib (not Node.js)
- `s-2vcpu-4gb` (pandas needs ~3x data size in RAM)
- 3-minute timeout (not 30 seconds)
- Output: PNG files to Spaces, summary to user

This "Zero-Shot Infrastructure" capability is the core differentiator.

---

## 2. Problem Statement & Market Context

### The Idle Compute Problem

Cloud servers sit idle 76% of the time (Flexera State of the Cloud Report 2024). A developer running a $24/month Droplet for occasional data processing tasks pays the same whether they use it 24/7 or 5 minutes/week.

**Cost comparison for a weekly 5-minute CSV processing task:**

| Approach | Monthly Cost | Utilization |
|---|---|---|
| Always-on Droplet (s-2vcpu-4gb) | $24.00 | 0.12% |
| Ephemeral.ai | ~$0.15 (4x $0.036/hr) | 100% |
| **Savings** | **$23.85/month (99.4%)** | |

### Competitive Landscape

- **AWS Lambda**: 15-min max, cold starts, no GPU, complex IAM
- **Google Cloud Run**: Container-only, no VM isolation for untrusted code
- **Modal.com**: Python-exclusive, closed source, $$$
- **E2B.dev**: Code sandboxes only, no full VM or data pipeline support
- **Fly.io Machines**: Manual sizing, no AI-driven resource prediction

**Ephemeral.ai's gap:** No existing solution combines LLM-driven resource prediction + full VM provisioning + open source + DigitalOcean native.

---

## 3. Evolved Architecture

```
                    User Prompt
                        |
                        v
        +-------------------------------+
        |     Neural Gateway (Brain)     |
        |   DO Gradient Serverless AI    |
        |   - Task analysis              |
        |   - Resource prediction        |
        |   - Code generation            |
        |   - Manifest output            |
        +-------------------------------+
                        |
                   Manifest JSON
                        |
                        v
        +-------------------------------+
        |   Orchestrator (Nerve Center)  |
        |   DO App Platform (FastAPI)    |
        |   - Manifest validation        |
        |   - Droplet lifecycle mgmt     |
        |   - WebSocket log streaming    |
        |   - Cost tracking              |
        |   - Reaper (orphan cleanup)    |
        +-------------------------------+
                  /           \
                 /             \
                v               v
  +-------------------+   +-----------------+
  | Thought-Node      |   | State-Vault     |
  | DO Droplet        |   | DO Spaces       |
  | - Boot via        |   | - Task outputs  |
  |   cloud-init      |   | - Logs          |
  | - Execute payload |   | - Artifacts     |
  | - Stream logs     |   | - Cost reports  |
  | - Upload results  |   |                 |
  | - Signal death    |   |                 |
  +-------------------+   +-----------------+
                \               ^
                 \             /
                  `-- upload --'
```

### Layer Breakdown

#### A. Neural Gateway (The Brain)

- **Host:** DigitalOcean Gradient Serverless Inference
- **Endpoint:** `https://inference.do-ai.run/v1/chat/completions`
- **Model Options (available on Gradient):**
  - **Primary:** Claude Sonnet 4.6 via Gradient ($3.00/$15.00 per M tokens) - best reasoning for infrastructure decisions
  - **Fallback:** Qwen3-32B via Gradient (open-source, lower cost) - good for code generation
  - **Budget:** Claude Haiku 4.5 ($0.80/$4.00 per M tokens) - fast, cheap for simple tasks
- **Function:** Receives natural language task, outputs a structured Manifest JSON containing resource specs, runtime environment, executable code, and termination policy
- **Key Capability:** Uses Gradient's OpenAI-compatible API, meaning we use the standard `openai` Python SDK with a custom `base_url`

#### B. Orchestrator (The Nerve Center)

- **Host:** DigitalOcean App Platform (Professional tier, ~$12/mo)
- **Tech Stack:** Python 3.12 + FastAPI + WebSockets
- **Database:** SQLite (embedded, sufficient for hackathon) or DO Managed PostgreSQL
- **Function:** Validates Manifests, manages Droplet lifecycle via DO API v2, streams logs to dashboard, tracks costs, runs orphan Droplet reaper

#### C. Thought-Node (The Muscle)

- **Host:** DigitalOcean Droplet (ephemeral, 30s - 10min lifetime)
- **Provisioning:** `POST /v2/droplets` with `user_data` (cloud-init)
- **Boot Time:** ~55 seconds to `active` status, ~90 seconds to SSH-ready
- **Optimization:** Pre-built Snapshots for common runtimes (Python, Node.js, Go) reduce cloud-init overhead to ~10 seconds
- **Lifecycle:** Boot -> Pull payload -> Execute -> Upload results to Spaces -> Signal Orchestrator -> Get destroyed

#### D. State-Vault (The Memory)

- **Host:** DigitalOcean Spaces (S3-compatible)
- **Endpoint:** `https://{space}.{region}.digitaloceanspaces.com`
- **Function:** Stores task outputs, logs, artifacts. Provides presigned URLs for user download
- **Client:** `boto3` with DO Spaces endpoint configuration
- **Cost:** $5/mo for 250GB included

---

## 4. The Manifest Protocol v2

The Manifest is the structured contract between the Neural Gateway and the Orchestrator. It is the core innovation of Ephemeral.ai.

### Schema (JSON Schema)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["task_id", "intent", "infra", "runtime", "payload", "lifecycle"],
  "properties": {
    "task_id": {
      "type": "string",
      "format": "uuid"
    },
    "intent": {
      "type": "object",
      "properties": {
        "summary": { "type": "string" },
        "category": {
          "type": "string",
          "enum": ["data_processing", "web_scraping", "code_execution",
                   "file_conversion", "api_integration", "analysis"]
        },
        "reasoning": { "type": "string" }
      }
    },
    "infra": {
      "type": "object",
      "properties": {
        "slug": {
          "type": "string",
          "enum": ["s-1vcpu-512mb-10gb", "s-1vcpu-1gb", "s-1vcpu-2gb",
                   "s-2vcpu-2gb", "s-2vcpu-4gb", "s-4vcpu-8gb"]
        },
        "region": {
          "type": "string",
          "enum": ["nyc3", "sfo3", "ams3", "sgp1", "fra1"]
        },
        "snapshot_id": {
          "type": ["string", "null"],
          "description": "Pre-built snapshot ID for fast boot, or null for base image"
        }
      }
    },
    "runtime": {
      "type": "object",
      "properties": {
        "language": {
          "type": "string",
          "enum": ["python", "node", "bash", "go"]
        },
        "version": { "type": "string" },
        "dependencies": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "payload": {
      "type": "object",
      "properties": {
        "code": { "type": "string" },
        "entry_command": { "type": "string" },
        "input_files": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "url": { "type": "string" },
              "path": { "type": "string" }
            }
          }
        }
      }
    },
    "lifecycle": {
      "type": "object",
      "properties": {
        "timeout_seconds": {
          "type": "integer",
          "minimum": 30,
          "maximum": 600
        },
        "termination": {
          "type": "string",
          "enum": ["immediate_after_output", "wait_for_upload", "manual"]
        },
        "output_format": {
          "type": "string",
          "enum": ["stdout", "file", "json", "presigned_url"]
        }
      }
    },
    "cost_estimate": {
      "type": "object",
      "properties": {
        "droplet_hourly_rate": { "type": "number" },
        "estimated_duration_seconds": { "type": "integer" },
        "estimated_cost_usd": { "type": "number" },
        "always_on_monthly_cost": { "type": "number" },
        "savings_percentage": { "type": "number" }
      }
    }
  }
}
```

### Example Manifest

```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "intent": {
    "summary": "Process 500MB CSV: clean nulls, compute statistics, generate bar chart",
    "category": "data_processing",
    "reasoning": "CSV is 500MB. Pandas loads data into memory (~1.5GB with overhead). Matplotlib for charting adds ~200MB. Need s-2vcpu-4gb for headroom. Python is optimal for pandas/matplotlib. Estimated runtime: 2 minutes for read + process + chart generation."
  },
  "infra": {
    "slug": "s-2vcpu-4gb",
    "region": "nyc3",
    "snapshot_id": "python-datascience-v3"
  },
  "runtime": {
    "language": "python",
    "version": "3.11",
    "dependencies": ["pandas", "matplotlib", "numpy"]
  },
  "payload": {
    "code": "import pandas as pd\nimport matplotlib\nmatplotlib.use('Agg')\nimport matplotlib.pyplot as plt\nimport json\nimport sys\n\ndf = pd.read_csv('/tmp/input/data.csv')\ndf = df.dropna()\nstats = df.describe().to_dict()\n\nplt.figure(figsize=(12, 6))\ndf.select_dtypes(include='number').iloc[:, :5].plot(kind='bar')\nplt.tight_layout()\nplt.savefig('/tmp/output/chart.png', dpi=150)\n\nwith open('/tmp/output/summary.json', 'w') as f:\n    json.dump(stats, f, indent=2, default=str)\n\nprint(json.dumps({'status': 'complete', 'files': ['chart.png', 'summary.json']}))",
    "entry_command": "python3 /opt/task/main.py",
    "input_files": [
      {
        "url": "https://my-space.nyc3.digitaloceanspaces.com/uploads/data.csv",
        "path": "/tmp/input/data.csv"
      }
    ]
  },
  "lifecycle": {
    "timeout_seconds": 180,
    "termination": "wait_for_upload",
    "output_format": "presigned_url"
  },
  "cost_estimate": {
    "droplet_hourly_rate": 0.03571,
    "estimated_duration_seconds": 120,
    "estimated_cost_usd": 0.036,
    "always_on_monthly_cost": 24.00,
    "savings_percentage": 99.85
  }
}
```

---

## 5. Component Deep-Dives

### 5.1 Neural Gateway - LLM System Prompt

The system prompt is the most critical piece. It must produce valid, executable Manifests in one shot.

```
You are Ephemeral, an infrastructure-aware AI. Given a user's task description,
you produce a Manifest JSON that specifies the exact compute resources, runtime
environment, and executable code needed to accomplish the task.

RULES:
1. Always output valid JSON matching the Manifest schema. Nothing else.
2. Choose the SMALLEST Droplet size that can handle the task:
   - Text processing, small scripts: s-1vcpu-512mb-10gb ($0.006/hr)
   - Medium data work (<100MB): s-1vcpu-1gb ($0.009/hr)
   - Data processing (100MB-500MB): s-1vcpu-2gb ($0.018/hr)
   - Heavy data/ML inference: s-2vcpu-4gb ($0.036/hr)
   - Large datasets (>1GB), concurrent work: s-4vcpu-8gb ($0.071/hr)
3. ALWAYS include error handling in generated code (try/except, exit codes).
4. ALWAYS write output to /tmp/output/ directory.
5. NEVER include credentials, API keys, or secrets in the payload.
6. NEVER generate code that makes network requests unless explicitly asked.
7. NEVER generate destructive commands (rm -rf /, fork bombs, etc.).
8. Include your reasoning in the intent.reasoning field.
9. Set realistic timeout_seconds based on task complexity.
10. Prefer pre-built snapshots when the language matches:
    - Python tasks: snapshot_id "python-datascience-v3"
    - Node.js tasks: snapshot_id "node18-v2"
    - Bash/system tasks: snapshot_id null (use ubuntu-22-04-x64)

Available Droplet slugs and their specs:
- s-1vcpu-512mb-10gb: 1 vCPU, 512MB RAM, 10GB disk
- s-1vcpu-1gb: 1 vCPU, 1GB RAM, 25GB disk
- s-1vcpu-2gb: 1 vCPU, 2GB RAM, 50GB disk
- s-2vcpu-2gb: 2 vCPU, 2GB RAM, 60GB disk
- s-2vcpu-4gb: 2 vCPU, 4GB RAM, 80GB disk
- s-4vcpu-8gb: 4 vCPU, 8GB RAM, 160GB disk
```

### 5.2 Neural Gateway - Gradient Integration Code

```python
from openai import OpenAI

# Gradient Serverless Inference uses OpenAI-compatible API
client = OpenAI(
    base_url="https://inference.do-ai.run/v1/",
    api_key=os.environ["GRADIENT_MODEL_ACCESS_KEY"]
)

def generate_manifest(user_prompt: str) -> dict:
    response = client.chat.completions.create(
        model="anthropic/claude-sonnet-4-6",  # or "qwen/qwen3-32b"
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.1,  # Low temp for deterministic infra decisions
        max_completion_tokens=4096,
        response_format={"type": "json_object"}
    )
    manifest = json.loads(response.choices[0].message.content)
    validate_manifest(manifest)  # JSON Schema validation
    return manifest
```

### 5.3 Orchestrator - Droplet Lifecycle Manager

```python
import httpx
import asyncio
from pydo import Client as DOClient

DO_API_TOKEN = os.environ["DIGITALOCEAN_API_TOKEN"]
do_client = DOClient(token=DO_API_TOKEN)

SNAPSHOT_MAP = {
    "python-datascience-v3": "123456789",  # Actual snapshot ID
    "node18-v2": "987654321",
}

async def provision_thought_node(manifest: dict, task_id: str) -> dict:
    """Create an ephemeral Droplet from a Manifest."""

    # Build cloud-init script
    cloud_init = build_cloud_init(manifest, task_id)

    # Determine image
    snapshot_id = manifest["infra"].get("snapshot_id")
    if snapshot_id and snapshot_id in SNAPSHOT_MAP:
        image = int(SNAPSHOT_MAP[snapshot_id])
    else:
        image = "ubuntu-22-04-x64"

    # Create Droplet via DO API
    body = {
        "name": f"ephemeral-{task_id[:8]}",
        "region": manifest["infra"]["region"],
        "size": manifest["infra"]["slug"],
        "image": image,
        "user_data": cloud_init,
        "tags": ["ephemeral-ai", f"task-{task_id}"],
        "monitoring": True,
    }
    response = do_client.droplets.create(body=body)
    droplet_id = response["droplet"]["id"]

    # Poll until active (typically ~55 seconds)
    droplet = await wait_for_active(droplet_id, timeout=120)

    return {
        "droplet_id": droplet_id,
        "ip": droplet["networks"]["v4"][0]["ip_address"],
        "status": "active",
        "created_at": droplet["created_at"]
    }


async def wait_for_active(droplet_id: int, timeout: int = 120) -> dict:
    """Poll DO API until Droplet status is 'active'."""
    start = asyncio.get_event_loop().time()
    while asyncio.get_event_loop().time() - start < timeout:
        resp = do_client.droplets.get(droplet_id=droplet_id)
        if resp["droplet"]["status"] == "active":
            return resp["droplet"]
        await asyncio.sleep(5)
    raise TimeoutError(f"Droplet {droplet_id} did not become active in {timeout}s")


async def destroy_thought_node(droplet_id: int):
    """Destroy a Droplet after task completion."""
    do_client.droplets.destroy(droplet_id=droplet_id)
```

### 5.4 Cloud-Init Builder

```python
def build_cloud_init(manifest: dict, task_id: str) -> str:
    """Generate cloud-init user_data script for the Thought-Node."""

    deps = manifest["runtime"].get("dependencies", [])
    dep_install = ""
    if manifest["runtime"]["language"] == "python" and deps:
        dep_install = f"pip install --quiet {' '.join(deps)}"
    elif manifest["runtime"]["language"] == "node" and deps:
        dep_install = f"npm install --silent {' '.join(deps)}"

    # Download input files
    download_cmds = ""
    for f in manifest["payload"].get("input_files", []):
        download_cmds += f'curl -sS -o "{f["path"]}" "{f["url"]}"\n'

    code_escaped = manifest["payload"]["code"].replace("'", "'\\''")

    return f"""#!/bin/bash
set -euo pipefail

# === Ephemeral.ai Thought-Node Bootstrap ===
TASK_ID="{task_id}"
CALLBACK_URL="{os.environ['ORCHESTRATOR_URL']}/api/v1/tasks/$TASK_ID/callback"
SPACES_BUCKET="{os.environ['SPACES_BUCKET']}"
SPACES_REGION="{os.environ['SPACES_REGION']}"

# Signal: booting
curl -sS -X POST "$CALLBACK_URL" -H "Content-Type: application/json" \
  -d '{{"status":"booting","phase":"init"}}'

# Create working directories
mkdir -p /tmp/input /tmp/output /opt/task

# Install dependencies
{dep_install}

# Download input files
{download_cmds}

# Write payload
cat > /opt/task/main.py << 'PAYLOAD_EOF'
{manifest["payload"]["code"]}
PAYLOAD_EOF

# Signal: running
curl -sS -X POST "$CALLBACK_URL" -H "Content-Type: application/json" \
  -d '{{"status":"running","phase":"execute"}}'

# Execute with timeout
timeout {manifest["lifecycle"]["timeout_seconds"]} \
  {manifest["payload"]["entry_command"]} > /tmp/output/stdout.log 2>&1
EXIT_CODE=$?

# Signal: uploading
curl -sS -X POST "$CALLBACK_URL" -H "Content-Type: application/json" \
  -d "{{\\"status\\":\\"uploading\\",\\"phase\\":\\"sync\\",\\"exit_code\\":$EXIT_CODE}}"

# Upload results to Spaces using s3cmd (pre-installed in snapshot)
s3cmd put --recursive /tmp/output/ \
  s3://$SPACES_BUCKET/tasks/$TASK_ID/ \
  --host=$SPACES_REGION.digitaloceanspaces.com \
  --host-bucket="%(bucket)s.$SPACES_REGION.digitaloceanspaces.com" 2>/dev/null

# Signal: done (Orchestrator will destroy this Droplet)
curl -sS -X POST "$CALLBACK_URL" -H "Content-Type: application/json" \
  -d "{{\\"status\\":\\"completed\\",\\"phase\\":\\"done\\",\\"exit_code\\":$EXIT_CODE}}"
"""
```

### 5.5 Spaces Integration (State-Vault)

```python
import boto3

spaces_client = boto3.client(
    "s3",
    region_name=os.environ["SPACES_REGION"],
    endpoint_url=f"https://{os.environ['SPACES_REGION']}.digitaloceanspaces.com",
    aws_access_key_id=os.environ["SPACES_KEY"],
    aws_secret_access_key=os.environ["SPACES_SECRET"],
)

def get_task_results(task_id: str) -> list[dict]:
    """List and generate presigned URLs for task output files."""
    prefix = f"tasks/{task_id}/"
    response = spaces_client.list_objects_v2(
        Bucket=os.environ["SPACES_BUCKET"],
        Prefix=prefix
    )
    results = []
    for obj in response.get("Contents", []):
        url = spaces_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": os.environ["SPACES_BUCKET"], "Key": obj["Key"]},
            ExpiresIn=3600  # 1 hour
        )
        results.append({
            "filename": obj["Key"].replace(prefix, ""),
            "size_bytes": obj["Size"],
            "download_url": url
        })
    return results
```

### 5.6 Orphan Reaper (Safety Net)

```python
import asyncio

async def reaper_loop():
    """Periodically destroy orphaned ephemeral Droplets."""
    while True:
        try:
            # List all Droplets tagged "ephemeral-ai"
            droplets = do_client.droplets.list(tag_name="ephemeral-ai")
            now = datetime.utcnow()

            for droplet in droplets.get("droplets", []):
                created = datetime.fromisoformat(
                    droplet["created_at"].replace("Z", "+00:00")
                )
                age_minutes = (now - created.replace(tzinfo=None)).total_seconds() / 60

                # Kill anything older than 15 minutes
                if age_minutes > 15:
                    logger.warning(
                        f"Reaping orphan Droplet {droplet['id']} "
                        f"(age: {age_minutes:.0f}m)"
                    )
                    do_client.droplets.destroy(droplet_id=droplet["id"])

        except Exception as e:
            logger.error(f"Reaper error: {e}")

        await asyncio.sleep(300)  # Run every 5 minutes
```

---

## 6. API Design

### Base URL: `https://ephemeral-ai.ondigitalocean.app/api/v1`

### Endpoints

#### `POST /tasks`
Submit a new task for ephemeral execution.

**Request:**
```json
{
  "prompt": "Process this CSV and give me summary statistics",
  "input_files": [
    { "url": "https://example.com/data.csv" }
  ],
  "preferences": {
    "region": "nyc3",
    "max_cost_usd": 0.10
  }
}
```

**Response (202 Accepted):**
```json
{
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "planning",
  "manifest": { ... },
  "websocket_url": "wss://ephemeral-ai.ondigitalocean.app/ws/tasks/a1b2c3d4",
  "estimated_cost_usd": 0.036,
  "estimated_duration_seconds": 120
}
```

#### `GET /tasks/{task_id}`
Get task status, manifest, and results.

**Response:**
```json
{
  "task_id": "a1b2c3d4",
  "status": "completed",
  "phases": [
    { "phase": "planning", "started_at": "...", "duration_ms": 2300 },
    { "phase": "provisioning", "started_at": "...", "duration_ms": 55000 },
    { "phase": "executing", "started_at": "...", "duration_ms": 45000 },
    { "phase": "uploading", "started_at": "...", "duration_ms": 3000 },
    { "phase": "destroyed", "started_at": "...", "duration_ms": 2000 }
  ],
  "results": [
    { "filename": "chart.png", "download_url": "https://..." },
    { "filename": "summary.json", "download_url": "https://..." }
  ],
  "cost": {
    "actual_usd": 0.036,
    "always_on_equivalent_monthly": 24.00,
    "savings_pct": 99.85
  },
  "droplet": {
    "id": 12345678,
    "slug": "s-2vcpu-4gb",
    "lifetime_seconds": 107
  }
}
```

#### `GET /tasks/{task_id}/logs`
Stream execution logs (also available via WebSocket).

#### `DELETE /tasks/{task_id}`
Force-kill a running task and destroy its Droplet.

#### `GET /stats`
Dashboard statistics.

**Response:**
```json
{
  "total_tasks": 142,
  "total_droplets_created": 142,
  "total_droplets_destroyed": 142,
  "total_compute_seconds": 8520,
  "total_cost_usd": 2.34,
  "equivalent_always_on_cost_usd": 336.00,
  "total_savings_usd": 333.66,
  "average_task_duration_seconds": 60
}
```

#### `POST /tasks/{task_id}/callback`
Internal endpoint called by Thought-Nodes to report lifecycle events.

### WebSocket: `wss://.../ws/tasks/{task_id}`

Real-time event stream for the dashboard:

```json
{"event": "planning", "data": {"model": "claude-sonnet-4-6", "tokens": 1200}}
{"event": "manifest_ready", "data": {"slug": "s-2vcpu-4gb", "reasoning": "..."}}
{"event": "provisioning", "data": {"droplet_id": 12345678}}
{"event": "droplet_active", "data": {"ip": "167.71.x.x", "boot_time_ms": 55000}}
{"event": "executing", "data": {"phase": "running"}}
{"event": "log", "data": {"line": "Processing 500MB CSV...", "timestamp": "..."}}
{"event": "log", "data": {"line": "Generated chart.png", "timestamp": "..."}}
{"event": "uploading", "data": {"files": 2}}
{"event": "completed", "data": {"duration_s": 107, "cost_usd": 0.036}}
{"event": "destroyed", "data": {"droplet_id": 12345678}}
```

---

## 7. Security Model

### Threat Model

| Threat | Mitigation |
|---|---|
| LLM generates malicious code | VM isolation (Droplets), code scanning, allowlisted packages |
| Credential leakage | API keys only in Orchestrator env vars; Thought-Nodes get callback tokens only |
| Runaway costs | Concurrent Droplet cap (5), per-task cost limit, 15-min reaper |
| DDoS via task spam | Rate limiting (10 tasks/min), task queue with backpressure |
| Metadata service abuse | iptables rule in cloud-init blocks 169.254.169.254 |
| Network exfiltration | Outbound firewall: allow only Orchestrator callback + Spaces |

### Defense-in-Depth Layers

```
Layer 1: LLM Guardrails
  - System prompt forbids dangerous patterns
  - Gradient guardrails (Jailbreak Detection, Content Moderation)
  - Manifest schema validation rejects unexpected fields

Layer 2: Orchestrator Validation
  - Allowlist of permitted Droplet sizes (no GPU Droplets in hackathon)
  - Allowlist of permitted packages (pandas, numpy, requests, etc.)
  - Static analysis of generated code (block os.system, subprocess, eval)
  - Cost ceiling per task ($0.10 default)

Layer 3: Network Isolation
  - Cloud Firewall on Thought-Nodes:
    - ALLOW outbound HTTPS to Orchestrator callback URL
    - ALLOW outbound HTTPS to Spaces endpoint
    - DENY all other outbound
    - DENY all inbound
  - Block metadata endpoint (169.254.169.254)

Layer 4: VM Isolation
  - Each task runs in a separate Droplet (hardware-level isolation)
  - Droplet is destroyed after task completion
  - No SSH keys installed (no human access needed)
  - No sensitive data on the VM beyond the task payload

Layer 5: Lifecycle Safety
  - Hard timeout per task (max 600 seconds)
  - Reaper process kills orphaned Droplets every 5 minutes
  - Concurrent Droplet cap (configurable, default 5)
  - Daily budget cap ($5/day for hackathon)
```

### Cloud-Init Security Hardening

```bash
# Block metadata endpoint
iptables -A OUTPUT -d 169.254.169.254 -j DROP

# Block all outbound except allowed endpoints
iptables -A OUTPUT -p tcp --dport 443 -d $ORCHESTRATOR_IP -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -d $SPACES_IP -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT  # DNS
iptables -A OUTPUT -p tcp --dport 443 -j DROP  # Block everything else
```

---

## 8. Cost Optimization Engine

### The Hourly Billing Problem

DigitalOcean bills Droplets per hour (rounded up). A 30-second task on a `s-1vcpu-1gb` Droplet costs $0.009 (one full hour).

### Optimization Strategies

#### Strategy 1: Intelligent Sizing
The LLM picks the smallest viable Droplet. The `intent.reasoning` field must justify the size choice.

| Task Type | Recommended Slug | Hourly Cost |
|---|---|---|
| Print "hello world" | s-1vcpu-512mb-10gb | $0.006 |
| Parse 10MB JSON | s-1vcpu-1gb | $0.009 |
| Process 500MB CSV | s-2vcpu-4gb | $0.036 |
| ML inference (small model) | s-4vcpu-8gb | $0.071 |

#### Strategy 2: Pre-Built Snapshots
Instead of `apt-get install` at boot (adds 60-120s), use snapshots:

| Snapshot | Contents | Boot Overhead |
|---|---|---|
| `python-datascience-v3` | Python 3.11, pandas, numpy, matplotlib, scipy, s3cmd | ~10s |
| `node18-v2` | Node.js 18 LTS, npm, common packages, s3cmd | ~10s |
| `base-tools-v1` | curl, jq, s3cmd, basic utils | ~5s |

**Snapshot creation (one-time setup):**
```bash
# Create a Droplet, install everything, then snapshot it
doctl compute droplet create snapshot-builder \
  --region nyc3 --size s-1vcpu-1gb --image ubuntu-22-04-x64 --wait

# SSH in and install packages, then:
doctl compute droplet-action snapshot snapshot-builder-id --snapshot-name python-datascience-v3
```

#### Strategy 3: Task Batching (Future)
For tasks under 60 seconds, batch multiple onto one Droplet within its billing hour.

#### Strategy 4: Result Caching
Hash the task prompt. If an identical task was run recently, return cached results from Spaces.

### Cost Tracking

Every task logs:
- `inference_cost`: Gradient API token usage cost
- `droplet_cost`: Hourly rate of the Droplet (billed 1 hour minimum)
- `spaces_cost`: Negligible (included in $5/mo base)
- `total_cost`: Sum of above
- `equivalent_always_on`: What a 24/7 Droplet of that size costs monthly
- `savings_pct`: `1 - (total_cost / equivalent_always_on) * 100`

---

## 9. Dashboard & UX

### Shadow Dashboard (React + Tailwind)

The dashboard is the **visual storytelling** element. It makes the invisible infrastructure lifecycle visible.

#### Key Views

**1. Task Submission (Hero)**
- Large text input: "What do you need computed?"
- File upload zone (drag & drop, uploads to Spaces)
- "Estimate" button (calls LLM without provisioning)
- "Execute" button (full pipeline)

**2. Live Pipeline View (The Star)**
A horizontal timeline showing the task's journey:

```
[Planning]  ->  [Provisioning]  ->  [Executing]  ->  [Uploading]  ->  [Destroyed]
  2.3s            55.0s              45.0s            3.0s             2.0s
   LLM            Droplet            Code             Spaces          Cleanup
 reasoning       booting           running           syncing         deleted
```

Each phase animates in real-time with:
- Duration counter
- Phase-specific icon (brain, server, terminal, cloud, skull)
- Color transition (blue -> yellow -> green -> green -> red)

**3. Terminal Stream**
Real-time log output from the Thought-Node, styled as a terminal:
```
$ Processing 500MB CSV...
$ Cleaning null values: 12,847 rows removed
$ Computing statistics...
$ Generating chart.png (1920x1080)
$ Upload complete: 2 files -> Spaces
$ Task completed in 45.2 seconds
```

**4. Cost Savings Counter**
A prominent real-time counter showing:
- **This task:** $0.036
- **Always-on equivalent:** $24.00/month
- **You saved:** 99.85%
- **Lifetime savings:** $333.66 across 142 tasks

**5. Graveyard (Task History)**
Table of past tasks showing:
- Task summary, status, duration, cost, Droplet size
- Downloadable results (presigned URLs from Spaces)
- Manifest JSON viewer (expandable)

### Tech Stack

- **Framework:** React 18 + Vite
- **Styling:** Tailwind CSS
- **Real-time:** Native WebSocket API
- **Charts:** Recharts (lightweight)
- **Hosting:** DigitalOcean App Platform (static site, free tier)

---

## 10. Implementation Plan

### Timeline: 16 days remaining (March 2 - March 18, 2026)

### Phase 1: Foundation (Days 1-3)

**Goals:** Working Gradient integration, basic Orchestrator, first Droplet lifecycle

- [ ] Set up DO account, generate API tokens, Spaces keys, Gradient model access key
- [ ] Create pre-built Droplet snapshots (Python, Node.js)
- [ ] Build Neural Gateway: system prompt + Gradient API integration
- [ ] Test Manifest generation with 10 diverse prompts
- [ ] Build Orchestrator skeleton (FastAPI): `/tasks` POST endpoint
- [ ] Implement Droplet create/poll/destroy lifecycle
- [ ] Build cloud-init template generator
- [ ] **Milestone:** Submit a prompt -> get a Manifest -> Droplet boots -> code runs -> Droplet dies

### Phase 2: Pipeline (Days 4-7)

**Goals:** End-to-end working pipeline with Spaces integration

- [ ] Implement Spaces upload from Thought-Node (s3cmd in cloud-init)
- [ ] Build callback system (Thought-Node -> Orchestrator status updates)
- [ ] Implement presigned URL generation for result downloads
- [ ] Add WebSocket endpoint for real-time event streaming
- [ ] Implement orphan Reaper background task
- [ ] Add Manifest validation (JSON Schema)
- [ ] Add basic code scanning (block dangerous patterns)
- [ ] **Milestone:** Full pipeline works: prompt -> plan -> provision -> execute -> upload -> results -> destroy

### Phase 3: Dashboard (Days 8-12)

**Goals:** Polished, demo-ready frontend

- [ ] Scaffold React + Vite + Tailwind project
- [ ] Build task submission form with file upload
- [ ] Build live pipeline visualization (animated timeline)
- [ ] Build terminal log stream (WebSocket consumer)
- [ ] Build cost savings counter (real-time + historical)
- [ ] Build task history / graveyard view
- [ ] Build Manifest JSON viewer
- [ ] Deploy frontend to App Platform (static site)
- [ ] **Milestone:** Beautiful, working dashboard that tells the story

### Phase 4: Polish & Submission (Days 13-16)

**Goals:** Demo video, documentation, submission

- [ ] Prepare 3-4 demo scenarios (CSV processing, web scraping, code analysis, file conversion)
- [ ] Test each scenario end-to-end 5+ times
- [ ] Record 3-minute demo video (screen recording + voiceover)
- [ ] Write comprehensive README with architecture diagram
- [ ] Add MIT license to repository
- [ ] Clean up git history (judges review commits)
- [ ] Deploy final version to App Platform
- [ ] Submit to Devpost by March 18, 5:00 PM EDT

### Commit Strategy

Judges explicitly review repositories. Commit frequently with meaningful messages:
```
feat: add Neural Gateway with Gradient serverless inference
feat: implement Droplet lifecycle manager with cloud-init
feat: add Spaces integration for result persistence
feat: add WebSocket real-time event streaming
feat: build live pipeline visualization dashboard
fix: handle Droplet provisioning timeout gracefully
docs: add architecture diagram and setup instructions
```

---

## 11. Prize Strategy

### Primary Target: 1st Place ($8,000 + $600 credits)

**Judging Criteria Alignment:**

| Criterion | How Ephemeral.ai Scores |
|---|---|
| **Technological Implementation** | Deep use of Gradient (serverless inference, OpenAI-compatible API), Droplets API (full lifecycle), Spaces (S3 API), App Platform (hosting). Not a single API call - a multi-service orchestration. |
| **Design** | The Shadow Dashboard makes invisible infrastructure visible. The pipeline animation is the "wow" moment. |
| **Potential Impact** | Solves real cloud waste problem (76% idle compute). Open source. Applicable to any developer running occasional compute tasks. |
| **Idea Quality** | "Infrastructure for the lifetime of a thought" is a novel concept. LLM-driven resource prediction doesn't exist in open source. |

### Secondary Target: The Great Whale Prize ($2,000)

This prize rewards ambitious, large-scale use of DigitalOcean infrastructure. Ephemeral.ai uses **four DO services simultaneously** (Gradient, Droplets, Spaces, App Platform) with an orchestration layer that exercises the full API.

### Secondary Target: Best Program for the People ($2,000)

Frame as democratizing compute: "A student shouldn't need a $24/month server to process a dataset once. Ephemeral.ai gives them $0.006 compute on demand."

---

## 12. Tech Stack Summary

| Component | Technology | DO Service |
|---|---|---|
| AI Inference | OpenAI Python SDK -> Gradient Serverless | Gradient AI Platform |
| API Server | Python 3.12 + FastAPI + Uvicorn | App Platform (Professional) |
| Ephemeral VMs | cloud-init + DO API v2 | Droplets |
| Object Storage | boto3 + S3 API | Spaces |
| Frontend | React 18 + Vite + Tailwind | App Platform (Static) |
| Real-time | WebSockets (native) | App Platform |
| Monitoring | DO Monitoring Agent | Droplet Metrics API |

### Python Dependencies (Orchestrator)

```
fastapi>=0.115.0
uvicorn>=0.32.0
openai>=1.50.0        # Gradient serverless inference
pydo>=0.6.0           # DigitalOcean API
boto3>=1.35.0         # Spaces (S3-compatible)
jsonschema>=4.23.0    # Manifest validation
websockets>=13.0
pydantic>=2.9.0
```

### Repository Structure

```
ephemeral-ai/
├── README.md
├── LICENSE                  # MIT
├── docker-compose.yml       # Local development
├── .github/
│   └── workflows/
│       └── deploy.yml       # Auto-deploy to App Platform
├── orchestrator/
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Environment config
│   ├── models.py            # Pydantic models
│   ├── manifest_schema.json # JSON Schema for Manifest
│   ├── neural_gateway.py    # Gradient LLM integration
│   ├── droplet_manager.py   # Droplet lifecycle (create/poll/destroy)
│   ├── cloud_init.py        # Cloud-init script builder
│   ├── spaces.py            # Spaces upload/download/presigned URLs
│   ├── reaper.py            # Orphan Droplet cleanup
│   ├── websocket.py         # Real-time event streaming
│   ├── security.py          # Code scanning, rate limiting
│   └── cost_tracker.py      # Cost calculation and logging
├── dashboard/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── TaskForm.tsx
│   │   │   ├── PipelineView.tsx
│   │   │   ├── TerminalStream.tsx
│   │   │   ├── CostCounter.tsx
│   │   │   └── TaskHistory.tsx
│   │   └── hooks/
│   │       └── useWebSocket.ts
│   └── index.html
├── snapshots/
│   ├── python-datascience.sh  # Snapshot build script
│   └── node18.sh
└── docs/
    └── architecture.png
```

---

## 13. Risk Mitigation

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Droplet boot time too slow for demo | Medium | High | Pre-create snapshot, start demo with pre-warmed Droplet, explain architecture during boot |
| LLM generates invalid Manifest | Medium | Medium | JSON Schema validation + retry with error feedback to LLM |
| Runaway Droplet costs | Low | High | Reaper process, concurrent cap (5), daily budget ($5), tag-based bulk delete |
| Gradient API rate limits | Low | Medium | Cache Manifests for repeated prompts, use Haiku for simple tasks |
| DO API rate limit (5000/hr) | Very Low | Low | Efficient polling (5s intervals), batch operations |
| Demo fails live | Medium | High | Pre-recorded backup video, 3-4 tested scenarios, use `nyc3` region (closest to most infra) |
| Cloud-init script too large | Low | Low | 64KB limit is generous; use gzip for large payloads |

### Budget Planning (Hackathon)

Participants receive $200 in DO credits. Expected costs:

| Item | Estimated Cost |
|---|---|
| App Platform (Orchestrator, 16 days) | ~$6.00 |
| App Platform (Dashboard, static) | Free |
| Gradient inference (~500 API calls) | ~$5.00 |
| Droplets (~200 ephemeral, 1hr each) | ~$10.00 |
| Spaces (250GB included) | $5.00 |
| Snapshots (~3, small) | ~$1.00 |
| **Total estimated** | **~$27.00** |
| **Available credits** | **$200.00** |
| **Headroom** | **$173.00** |

---

## 14. Future Vision

### Post-Hackathon Roadmap

**v2.0 - Smart Routing**
- Route short tasks (<60s) to App Platform Functions (per-invocation billing) instead of Droplets
- Route GPU tasks to GPU Droplets
- Intelligent routing reduces cost by 10-50x for micro-tasks

**v2.1 - Agent Memory**
- Persistent task context using Gradient Knowledge Bases
- "Last time you processed this CSV, you wanted bar charts. Want the same?"
- Learning from past Manifests to improve future predictions

**v2.2 - Multi-Agent Pipeline**
- Chain multiple Thought-Nodes: "Download data -> Clean it -> Analyze it -> Generate report"
- Use Gradient Agent Routing for multi-step workflows
- Each step gets its own optimally-sized Droplet

**v2.3 - Collaborative Ephemerality**
- Team workspaces with shared Spaces buckets
- Concurrent task execution with dependency graphs
- Cost allocation per team member

**v3.0 - Cross-Provider Arbitrage**
- Same Orchestrator, multiple cloud backends (DO, AWS, GCP)
- LLM picks cheapest provider for each task type
- Managed by the DO-hosted "Brain" (Gradient stays as the control plane)

**v3.1 - Gradient ADK Integration**
- Deploy the Neural Gateway as a Gradient ADK agent
- Built-in tracing, evaluation, and knowledge base support
- One-command deployment: `gradient agent deploy`

---

## Appendix A: DigitalOcean Service Reference

| Service | Purpose in Ephemeral.ai | Pricing |
|---|---|---|
| [Gradient Serverless Inference](https://docs.digitalocean.com/products/gradient-ai-platform/how-to/use-serverless-inference/) | Neural Gateway LLM calls | Per-token (varies by model) |
| [Droplets API](https://docs.digitalocean.com/reference/api/api-reference/) | Thought-Node VMs | Per-hour ($0.006-$0.071/hr) |
| [Spaces](https://docs.digitalocean.com/products/spaces/) | Result storage | $5/mo for 250GB |
| [App Platform](https://docs.digitalocean.com/products/app-platform/) | Orchestrator + Dashboard hosting | $12/mo (Pro) + Free (Static) |
| [Cloud Firewalls](https://docs.digitalocean.com/products/networking/firewalls/) | Thought-Node network isolation | Free |
| [Monitoring](https://docs.digitalocean.com/products/monitoring/) | Droplet resource metrics | Free |

## Appendix B: Key API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `https://inference.do-ai.run/v1/chat/completions` | POST | Gradient serverless inference |
| `https://inference.do-ai.run/v1/models` | GET | List available models |
| `https://api.digitalocean.com/v2/droplets` | POST | Create Droplet |
| `https://api.digitalocean.com/v2/droplets/{id}` | GET | Get Droplet status |
| `https://api.digitalocean.com/v2/droplets/{id}` | DELETE | Destroy Droplet |
| `https://api.digitalocean.com/v2/droplets?tag_name=X` | DELETE | Bulk destroy by tag |
| `https://{region}.digitaloceanspaces.com` | S3 API | Object storage operations |
