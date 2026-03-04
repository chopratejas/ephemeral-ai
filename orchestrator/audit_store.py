"""Audit Store - Persists audit results to DigitalOcean Spaces.

Uses Spaces as a simple document store:
- Each audit: audits/{task_id}.json (full summary)
- Global index: audits/recent.json (last 100 audits, sorted by date)

All files are public-read so the dashboard can fetch them directly.
"""

import json
import logging
import time
from datetime import datetime, timezone

from .config import settings

logger = logging.getLogger("ephemeral.audit_store")


def _create_client():
    import boto3
    return boto3.client(
        "s3",
        region_name=settings.spaces_region,
        endpoint_url=f"https://{settings.spaces_region}.digitaloceanspaces.com",
        aws_access_key_id=settings.spaces_key,
        aws_secret_access_key=settings.spaces_secret,
    )


def save_audit(
    task_id: str,
    repo_url: str,
    branch: str,
    risk_score: int,
    total_findings: int,
    severity_counts: dict,
    language: str,
    framework: str,
    duration_seconds: float,
    summary: str,
) -> None:
    """Save an audit result to Spaces and update the global index."""
    client = _create_client()

    repo_name = repo_url.replace("https://github.com/", "").rstrip("/")

    audit_record = {
        "task_id": task_id,
        "repo_url": repo_url,
        "repo_name": repo_name,
        "branch": branch,
        "risk_score": risk_score,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "language": language,
        "framework": framework,
        "duration_seconds": round(duration_seconds, 1),
        "summary": summary[:300],
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }

    # 1. Save individual audit record
    try:
        client.put_object(
            Bucket=settings.spaces_bucket,
            Key=f"audits/{task_id}.json",
            Body=json.dumps(audit_record, indent=2).encode(),
            ContentType="application/json",
            ACL="public-read",
        )
        logger.info("Saved audit %s to Spaces", task_id[:8])
    except Exception as e:
        logger.error("Failed to save audit %s: %s", task_id[:8], e)
        return

    # 2. Update the global recent index
    try:
        # Fetch existing index
        try:
            resp = client.get_object(
                Bucket=settings.spaces_bucket,
                Key="audits/recent.json",
            )
            recent = json.loads(resp["Body"].read().decode())
        except Exception:
            recent = []

        # Prepend new audit
        recent.insert(0, audit_record)

        # Keep only last 100
        recent = recent[:100]

        # Write back
        client.put_object(
            Bucket=settings.spaces_bucket,
            Key="audits/recent.json",
            Body=json.dumps(recent, indent=2).encode(),
            ContentType="application/json",
            ACL="public-read",
        )
        logger.info("Updated recent audits index (%d entries)", len(recent))

    except Exception as e:
        logger.error("Failed to update recent index: %s", e)


def get_recent_audits(limit: int = 50) -> list[dict]:
    """Fetch the most recent audits from Spaces."""
    client = _create_client()

    try:
        resp = client.get_object(
            Bucket=settings.spaces_bucket,
            Key="audits/recent.json",
        )
        recent = json.loads(resp["Body"].read().decode())
        return recent[:limit]
    except Exception:
        return []
