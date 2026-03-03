"""Cloud-init script builder for Worker Droplets.

Uses a pre-built snapshot (ephemeral-worker-v1) with Python, Node.js,
TypeScript, and common packages already installed. Cloud-init only needs
to write the worker daemon and start it - no runtime installation.
"""

from .config import settings
from .worker_daemon import get_worker_daemon_script


def build_cloud_init(worker_id: str, size_slug: str) -> str:
    """Generate a cloud-init script that starts the worker daemon.

    The snapshot already has all runtimes installed, so this just:
    1. Sets environment variables
    2. Writes the worker daemon script
    3. Starts it
    """
    daemon_script = get_worker_daemon_script()

    return f"""#!/bin/bash
set -euo pipefail

# === Ephemeral.ai Worker Droplet (snapshot boot) ===
# Worker: {worker_id}
# Size: {size_slug}

# --- Security ---
iptables -A OUTPUT -d 169.254.169.254 -j DROP 2>/dev/null || true

# --- Directories ---
mkdir -p /tmp/input /tmp/output /opt/task /opt/workbench

# --- Environment ---
export EPHEMERAL_WORKER_ID="{worker_id}"
export EPHEMERAL_ORCHESTRATOR_URL="{settings.orchestrator_url}"
export EPHEMERAL_GRADIENT_KEY="{settings.gradient_model_access_key}"
export EPHEMERAL_MODEL="{settings.gradient_model}"
export EPHEMERAL_SPACES_REGION="{settings.spaces_region}"
export NODE_PATH="/opt/node_modules"

# --- Write daemon ---
cat > /opt/workbench/daemon.py << 'WORKER_DAEMON_EOF'
{daemon_script}
WORKER_DAEMON_EOF

# --- Start daemon ---
python3 /opt/workbench/daemon.py 2>&1 | tee /var/log/ephemeral-daemon.log
"""
