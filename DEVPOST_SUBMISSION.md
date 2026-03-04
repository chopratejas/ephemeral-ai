# Project Story

## Inspiration

45% of AI-generated code contains security vulnerabilities. Tools like Snyk and CodeQL catch less than 20% of them in real-world tests — because they use regex pattern matching designed for human-written code. AI code fails differently: missing input validation, hallucinated dependencies, prompt injection vectors, unsafe LLM output handling. These are patterns existing tools were never built to detect.

We asked: what if a security scanner could actually **read and understand** code the way a developer does? Not pattern match — but reason about it. And what if it could **run the code**, follow the README, install dependencies, and try to break it — like a human pen tester?

That requires a full computer. Not a Lambda function. Not a container. A real VM with git, pip, npm, a network stack, and the ability to install anything. But VMs are expensive to keep running. So we made them **ephemeral** — they exist only for the duration of the audit, then they're recycled.

## What it does

**CodeScope** is an LLM-first security audit platform. You paste a GitHub repo URL. We:

1. **Scout** the repo via GitHub API — an LLM reads the README and dependency files to determine what size VM is needed
2. **Spin up an ephemeral DigitalOcean Droplet** from a pre-built snapshot (30s boot)
3. **Clone the repo, install dependencies, and try to run the app** — following the actual README instructions
4. **Run 6 parallel security analyses** using DigitalOcean Gradient AI — each reviewer gets the relevant source files and a focused security prompt (auth, injection, AI security, secrets, dependencies, error handling)
5. **Dynamic test** the running app if it started successfully — check headers, probe endpoints, send crafted payloads
6. **Synthesize findings** using a multi-model consensus (openai-gpt-oss-120b for prioritization, llama3.3-70b-instruct for code fixes, deepseek-r1-distill-llama-70b for false positive detection)
7. **Generate a fix** for each finding on the same Droplet (branch, apply fix, build, test, commit)
8. The Droplet goes back to the **warm pool** — reused for the next audit within the billing hour (0s provisioning on subsequent audits)

Real example: auditing [chopratejas/headroom](https://github.com/chopratejas/headroom) found 18 real vulnerabilities including a critical prompt injection in the LLM gateway, SQL injection in SQLite adapters, and missing authentication on all API routes — with exploit scenarios and code fixes for each.

## How we built it

**Backend (Python/FastAPI)** — deployed on DigitalOcean App Platform via Container Registry. Handles task routing, warm pool management, and the audit lifecycle.

**Worker Daemon** — a long-lived Python script that runs inside each Droplet for up to 55 minutes (fitting within the 1-hour billing window). It polls the orchestrator for tasks, executes CodeScope audits, applies fixes, and uploads results to Spaces.

**CodeScope v3** — the audit engine (1,729 lines). No regex patterns. Every finding comes from an LLM reading actual code. 5 phases: Understand → Setup → Analyze (6 parallel) → Dynamic Test → Synthesize.

**Scout** — runs on the orchestrator before provisioning. Fetches README + manifests via GitHub API, asks the LLM to size the Droplet. A Python data science project gets `s-2vcpu-4gb`; a simple Node script gets `s-1vcpu-1gb`.

**Warm Pool** — Droplets are billed per hour. Instead of create-use-destroy, we create-use-**reuse**. First audit: 30s cold start. Second audit: 0.024s. Same cost.

**Dashboard (React/TypeScript)** — deployed as a static site on DigitalOcean Spaces. Inter + JetBrains Mono fonts. Teal accent. Live log streaming during scans.

## DigitalOcean Services Used

| Service | How we use it |
|---------|--------------|
| **Gradient AI (Serverless Inference)** | All security analysis — 3 models in parallel for multi-model consensus |
| **Droplets** | Ephemeral audit VMs — clone repos, install deps, run code, execute attacks |
| **Spaces** | Result storage, dashboard hosting, CodeScope script distribution, audit history persistence |
| **App Platform** | Orchestrator API hosting (Docker via DOCR) |
| **Container Registry (DOCR)** | Docker image storage for the orchestrator |
| **Snapshots** | Pre-built Droplet images with Python + Node.js + TypeScript for fast boot |
| **Cloud Firewalls** | Network isolation for audit Droplets |
| **Monitoring API** | Droplet health checks |

## Challenges we faced

**Droplet boot time vs. billing**: Droplets take 30s to boot but are billed per hour. Destroying after each 3-minute audit wastes 57 minutes of paid time. Solution: the warm pool architecture — Droplets stay alive and accept multiple tasks within their billing hour.

**Cloud-init size limit**: The CodeScope script (69KB) + worker daemon (44KB) exceeded the 64KB user_data limit. Solution: embed the daemon in cloud-init, download CodeScope from Spaces at boot.

**Regex scanning was a dead end**: Our v2 scanner had 48 regex patterns that produced 1,603 findings on a real repo — 83% were false positives. Solution: v3 has zero regex. Every finding comes from an LLM reading actual code with context.

**Zombie Droplets**: When the orchestrator restarts (new deployment), in-memory state is lost. Orphaned Droplets keep running but their daemon has expired. Solution: rediscovery on startup — query DO API for tagged Droplets, destroy any older than 50 minutes, re-register fresh ones.

**Dynamic analysis reliability**: Starting arbitrary repos is unreliable — different frameworks, different ports, different entry points. Solution: the Scout LLM reads the README and generates setup commands, but we gracefully degrade if the app doesn't start (static analysis still runs).

## What we learned

- LLMs are dramatically better at finding security issues than regex — because they understand context. `await` in Python test code is not an "unhandled promise."
- The warm pool pattern makes ephemeral VMs economically viable for short tasks. Same hourly cost, 1500x faster after the first request.
- Multi-model consensus reduces false positives. When 3 models agree something is critical, it probably is.
- DigitalOcean's Gradient AI serverless inference is genuinely easy to use — OpenAI-compatible API, no model management, works from inside Droplets.

## What's next

- **GitHub OAuth + PR creation**: The fix is already built and tested on the Droplet. One click to push the branch and open a PR.
- **CI/CD integration**: Run CodeScope on every PR as a GitHub Action.
- **Private repo support**: Currently public repos only. With GitHub OAuth, we can scan private repos.
- **Diff-mode scanning**: Instead of scanning the whole repo, scan just the changed files in a PR. Faster, cheaper, more focused.
