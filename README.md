# CodeScope by Ephemeral.ai

**AI-Era Security Auditing -- 7 layers, 40+ checks, $0.01 per audit**

> Built for the 45% -- because AI writes fast but doesn't write safe.

[Live Demo](https://ephemeral-ai-dgdbw.ondigitalocean.app) | [API Docs](https://ephemeral-ai-dgdbw.ondigitalocean.app/docs) | [Hackathon: DigitalOcean Gradient AI](https://dograduation.devpost.com/)

---

## The Problem

45% of AI-generated code contains security vulnerabilities (Veracode, 2025). Existing scanners like Snyk, CodeQL, and Semgrep were designed for human-written code patterns and miss AI-specific failure modes: hallucinated dependencies, missing input validation, prompt injection vectors, and tutorial-quality code shipped to production. Teams adopting AI coding assistants have no tool purpose-built to catch what those assistants get wrong.

## The Solution

CodeScope clones any GitHub repository into an ephemeral DigitalOcean Droplet, runs a 7-layer security audit (OWASP Top 10, AI-specific patterns, supply chain, secrets, licensing, tests, repo health), then uses Gradient AI (Llama 3.3 70B) to synthesize findings into a prioritized, actionable report. The Droplet is destroyed after -- your code never persists.

---

## Architecture

```
User --> POST /api/v1/audit --> Orchestrator (App Platform)
                                       |
                                 Warm Pool Router
                                 /              \
                          Warm Droplet      New Droplet
                              |                 |
                         Worker Daemon     Worker Daemon
                              |                 |
                         CodeScope 7-Layer Audit
                         |-- SAST (40+ patterns)
                         |-- SCA (dependency CVEs)
                         |-- Secrets (regex scan)
                         |-- Licenses (compliance)
                         |-- Tests (coverage analysis)
                         |-- Repo Health (structure)
                         +-- AI Synthesis (Gradient AI)
                              |
                         Results --> Spaces (S3)
                              |
                         Droplet stays warm 55 min
                         (reused for next audit, same cost)
```

---

## The 7 Layers

| Layer | What It Scans | Unique to CodeScope |
|-------|--------------|---------------------|
| **SAST** | SQL injection, XSS, eval(), command injection, SSRF, path traversal | AI-specific: missing input validation, hallucinated imports, tutorial code in production |
| **SCA** | Dependency CVEs via npm audit / pip-audit / cargo audit | Hallucinated package detection (slopsquatting) |
| **Secrets** | AWS keys, API tokens, private keys, .env files, high-entropy strings | Scans git history, not just HEAD |
| **Licenses** | GPL in MIT projects, unknown or missing licenses | Flags copyleft contamination risk |
| **Tests** | Test framework detection, coverage analysis, test-to-code ratio | Flags zero-test repos shipping to production |
| **Repo Health** | README, .gitignore, CI/CD, lockfile, Dockerfile, linting config | Rate limiting, validation libraries, auth middleware checks |
| **AI Synthesis** | Gradient AI reads ALL findings, prioritizes, explains in plain English | Cross-layer correlation, dedicated AI Code Safety section |

---

## AI Code Safety -- A New Scanning Category

CodeScope introduces four scanning categories that do not exist in traditional SAST tools:

**Prompt Injection Detection** -- Finds user input concatenated directly into LLM prompt templates. Patterns like `f"Summarize: {user_input}"` passed to an LLM API are flagged as high-severity.

**Hallucinated Dependencies** -- Checks whether imported packages actually exist on npm and PyPI. AI models frequently generate imports for packages that sound plausible but do not exist, creating supply chain attack vectors (slopsquatting).

**AI Anti-Patterns** -- Catches missing input validation, empty catch blocks, overly permissive CORS/defaults, and tutorial-quality code (hardcoded credentials, TODO-as-implementation, placeholder error handling).

**LLM Output Misuse** -- Detects LLM output fed directly into dangerous sinks: `eval()`, `innerHTML`, SQL queries, shell commands, and `dangerouslySetInnerHTML`. AI-generated code rarely sanitizes LLM responses before use.

---

## Why Ephemeral Droplets?

| Concern | How Ephemeral Addresses It |
|---------|---------------------------|
| **Isolation** | Full VM -- git clone, install any tool, run any scanner. No shared container risk. |
| **Privacy** | Code destroyed after audit. Nothing persists on disk or in memory. |
| **Speed** | Warm pool reuses Droplets within their billing hour. First audit: ~30s boot. Subsequent: 0s (instant). |
| **Cost** | $0.009 per audit. DigitalOcean bills hourly; warm pool maximizes each hour. |

The warm pool architecture is key: DigitalOcean charges a minimum of 1 hour per Droplet. A 30-second audit costs the same as a 55-minute audit. Instead of create-use-destroy, CodeScope keeps Droplets alive for 55 minutes and routes subsequent audits to idle workers. One Droplet can serve dozens of audits before being reaped.

---

## DigitalOcean Services Used

| Service | Purpose |
|---------|---------|
| **Gradient AI** (Serverless Inference) | AI synthesis of findings via Llama 3.3 70B (OpenAI-compatible API) |
| **Droplets** | Ephemeral audit VMs with warm pool architecture |
| **Spaces** | S3-compatible result storage (reports, findings, logs) |
| **App Platform** | Orchestrator hosting (FastAPI + React dashboard via Docker) |
| **Container Registry** (DOCR) | Docker image deployment for the orchestrator |
| **Cloud Firewalls** | Network isolation for audit Droplets |
| **Monitoring** | Droplet resource metrics and health checks |
| **Snapshots** | Pre-built worker images (`ephemeral-lean-v3`) with Python 3.11, Node.js 18, and audit tooling for fast boot |

---

## Quick Start

```bash
# Clone
git clone https://github.com/chopratejas/ephemeral-ai
cd ephemeral-ai

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your DigitalOcean API token, Spaces credentials,
# and Gradient AI key

# Run the orchestrator
uvicorn orchestrator.main:app --port 8000

# Submit a security audit
curl -X POST http://localhost:8000/api/v1/audit \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/expressjs/cors"}'
```

The dashboard is available at `http://localhost:8000` after starting the orchestrator. To develop the dashboard separately:

```bash
cd dashboard
npm install
npm run dev
```

---

## API Reference

```
POST /api/v1/audit         Submit a CodeScope security audit for a GitHub repo
GET  /api/v1/tasks/{id}    Get audit status, phases, and results
POST /api/v1/tasks         Submit a general code execution task
GET  /api/v1/stats         Platform statistics (costs, pool state, task counts)
GET  /health               Health check with warm pool status
WS   /ws/tasks/{id}        Real-time WebSocket stream of audit progress
```

**Example: Submit an audit**
```bash
curl -X POST https://ephemeral-ai-dgdbw.ondigitalocean.app/api/v1/audit \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/juice-shop/juice-shop", "branch": "main"}'
```

**Example: Check results**
```bash
curl https://ephemeral-ai-dgdbw.ondigitalocean.app/api/v1/tasks/{task_id}
```

---

## Cost Analysis

```
Traditional penetration test:    $5,000 - $50,000
Commercial SAST tool:            $100 - $500/month
CodeScope per audit:             $0.009
                                 (DigitalOcean Droplet: $0.00893/hr,
                                  amortized across warm pool reuse)
```

At 100 audits/month, CodeScope costs under $1. The warm pool ensures each Droplet is reused for its full billing hour, driving per-audit cost toward zero as usage increases.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| **Backend** | Python 3.11, FastAPI 0.115, Pydantic v2, uvicorn |
| **AI** | DigitalOcean Gradient AI (Llama 3.3 70B) via OpenAI-compatible SDK |
| **Compute** | DigitalOcean Droplets (pre-built snapshots, warm pool, cloud-init) |
| **Storage** | DigitalOcean Spaces (S3-compatible, presigned URL uploads) |
| **Hosting** | DigitalOcean App Platform (Docker via DOCR) |
| **Frontend** | React 18, TypeScript, Tailwind CSS, Vite |
| **IaC** | DigitalOcean API via pydo SDK, cloud-init for Droplet provisioning |

---

## Project Structure

```
ephemeral-ai/
  orchestrator/
    main.py             # FastAPI app, endpoints, task lifecycle
    codescope.py        # 7-layer audit engine (runs inside Droplet)
    warm_pool.py        # Warm pool manager with billing-aware reuse
    worker_daemon.py    # Long-lived multi-task executor for Droplets
    neural_gateway.py   # Gradient AI integration for manifest generation
    droplet_manager.py  # DigitalOcean Droplet CRUD via pydo
    spaces.py           # Spaces upload/download with presigned URLs
    task_router.py      # Warm pool routing decisions
    config.py           # Environment-based configuration
    models.py           # Pydantic models for API and internal state
    security.py         # Rate limiting, budget tracking, input validation
    cost_tracker.py     # Per-task cost calculation
  dashboard/
    src/                # React + TypeScript frontend
    vite.config.ts      # Vite build configuration
  Dockerfile            # Orchestrator container image
  requirements.txt      # Python dependencies
```

---

## License

MIT -- see [LICENSE](LICENSE).
