"""Droplet lifecycle manager - create, monitor, and destroy worker Droplets.

In the warm pool architecture, Droplets are generic workers that run for up to
55 minutes. They poll the Orchestrator for tasks rather than receiving a single
task via cloud-init.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from pydo import Client as DOClient

from .cloud_init import build_cloud_init
from .config import settings

logger = logging.getLogger("ephemeral.droplets")


def _create_client() -> DOClient:
    return DOClient(token=settings.digitalocean_api_token)


async def create_worker_droplet(
    size_slug: str = "s-1vcpu-1gb",
    worker_id: str | None = None,
) -> dict:
    """Create a new worker Droplet that runs the worker daemon.

    The worker daemon is a long-lived process that:
    - Polls the Orchestrator for tasks
    - Generates and executes code via Gradient AI
    - Self-heals on failure
    - Shuts down at 55 minutes

    Returns dict with worker_id, droplet_id, status.
    """
    client = _create_client()
    wid = worker_id or str(uuid.uuid4())
    user_data = build_cloud_init(wid, size_slug)

    body = {
        "name": f"worker-{wid[:8]}",
        "region": settings.default_region,
        "size": size_slug,
        "image": int(settings.default_image),  # Snapshot ID (integer)
        "user_data": user_data,
        "tags": [settings.droplet_tag, f"worker-{wid}"],
        "monitoring": True,
    }

    logger.info(
        "Creating worker Droplet: worker=%s size=%s region=%s",
        wid,
        size_slug,
        settings.default_region,
    )

    response = await asyncio.to_thread(client.droplets.create, body=body)
    droplet = response["droplet"]

    logger.info(
        "Worker Droplet created: id=%d worker=%s",
        droplet["id"],
        wid,
    )

    return {
        "worker_id": wid,
        "droplet_id": droplet["id"],
        "name": droplet["name"],
        "status": droplet["status"],
        "created_at": droplet["created_at"],
    }


async def wait_for_active(droplet_id: int, timeout: int = 120) -> dict:
    """Poll the DO API until the Droplet status is 'active'."""
    client = _create_client()
    start = asyncio.get_event_loop().time()

    while asyncio.get_event_loop().time() - start < timeout:
        response = await asyncio.to_thread(
            client.droplets.get, droplet_id=droplet_id
        )
        droplet = response["droplet"]

        if droplet["status"] == "active":
            ip = ""
            for net in droplet.get("networks", {}).get("v4", []):
                if net.get("type") == "public":
                    ip = net["ip_address"]
                    break

            logger.info(
                "Droplet %d active (ip=%s, %.1fs)",
                droplet_id,
                ip,
                asyncio.get_event_loop().time() - start,
            )
            return {
                "droplet_id": droplet["id"],
                "ip": ip,
                "status": "active",
                "created_at": droplet["created_at"],
            }

        await asyncio.sleep(5)

    raise TimeoutError(
        f"Droplet {droplet_id} did not become active within {timeout}s"
    )


async def destroy_droplet(droplet_id: int) -> None:
    """Destroy a Droplet by ID."""
    client = _create_client()
    logger.info("Destroying Droplet %d", droplet_id)
    await asyncio.to_thread(client.droplets.destroy, droplet_id=droplet_id)
    logger.info("Droplet %d destroyed", droplet_id)


async def list_ephemeral_droplets() -> list[dict]:
    """List all Droplets tagged with the ephemeral tag."""
    client = _create_client()
    response = await asyncio.to_thread(
        client.droplets.list, tag_name=settings.droplet_tag
    )
    return response.get("droplets", [])


async def count_active_droplets() -> int:
    """Count currently active ephemeral Droplets."""
    droplets = await list_ephemeral_droplets()
    return len(droplets)
