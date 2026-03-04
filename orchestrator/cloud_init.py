"""Cloud-init script builder for Worker Droplets.

Uses a pre-built snapshot with Python, Node.js, TypeScript installed.
Cloud-init writes the worker daemon and downloads CodeScope from Spaces.
"""

from .config import settings
from .worker_daemon import get_worker_daemon_script


def build_cloud_init(worker_id: str, size_slug: str) -> str:
    """Generate a cloud-init script that starts the worker daemon.

    The daemon script is embedded directly (fits in 64KB).
    The CodeScope script is downloaded from Spaces at boot (too large to embed).
    """
    daemon_script = get_worker_daemon_script()

    # Public URL for CodeScope script in Spaces
    codescope_url = (
        f"https://{settings.spaces_bucket}.{settings.spaces_region}"
        f".digitaloceanspaces.com/scripts/codescope.py"
    )

    return f"""#!/bin/bash
set -euo pipefail

# === Ephemeral.ai Worker Droplet (snapshot boot) ===
# Worker: {worker_id}
# Size: {size_slug}

# --- Security ---
iptables -A OUTPUT -d 169.254.169.254 -j DROP 2>/dev/null || true

# --- Directories ---
mkdir -p /tmp/input /tmp/output /opt/task /opt/workbench /opt/audit

# --- Environment ---
export EPHEMERAL_WORKER_ID="{worker_id}"
export EPHEMERAL_ORCHESTRATOR_URL="{settings.orchestrator_url}"
export EPHEMERAL_GRADIENT_KEY="{settings.gradient_model_access_key}"
export EPHEMERAL_MODEL="{settings.gradient_model}"
export EPHEMERAL_SPACES_REGION="{settings.spaces_region}"
export NODE_PATH="/opt/node_modules"

# --- Write worker daemon ---
cat > /opt/workbench/daemon.py << 'WORKER_DAEMON_EOF'
{daemon_script}
WORKER_DAEMON_EOF

# --- Download CodeScope from Spaces (non-fatal) ---
curl -sS -o /opt/workbench/codescope.py "{codescope_url}" || echo "WARN: CodeScope download failed"

# --- Start daemon ---
python3 /opt/workbench/daemon.py 2>&1 | tee /var/log/ephemeral-daemon.log
"""
