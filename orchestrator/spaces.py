"""State-Vault - DigitalOcean Spaces integration for task result storage."""

import logging

import boto3

from .config import settings

logger = logging.getLogger("ephemeral.spaces")


def _create_client():
    return boto3.client(
        "s3",
        region_name=settings.spaces_region,
        endpoint_url=f"https://{settings.spaces_region}.digitaloceanspaces.com",
        aws_access_key_id=settings.spaces_key,
        aws_secret_access_key=settings.spaces_secret,
    )


def list_task_results(task_id: str) -> list[dict]:
    """List output files for a completed task and generate presigned download URLs."""
    client = _create_client()
    prefix = f"tasks/{task_id}/"

    response = client.list_objects_v2(
        Bucket=settings.spaces_bucket,
        Prefix=prefix,
    )

    results = []
    for obj in response.get("Contents", []):
        key = obj["Key"]
        filename = key.replace(prefix, "")
        if not filename or filename == "_done.json":
            continue

        url = client.generate_presigned_url(
            "get_object",
            Params={"Bucket": settings.spaces_bucket, "Key": key},
            ExpiresIn=3600,
        )

        results.append(
            {
                "filename": filename,
                "size_bytes": obj.get("Size", 0),
                "download_url": url,
            }
        )

    logger.info("Found %d result files for task %s", len(results), task_id)
    return results


def check_task_done(task_id: str) -> dict | None:
    """Check if the _done.json marker exists for a task.

    Returns the parsed JSON content if found, None otherwise.
    """
    client = _create_client()
    key = f"tasks/{task_id}/_done.json"

    try:
        response = client.get_object(
            Bucket=settings.spaces_bucket,
            Key=key,
        )
        import json

        return json.loads(response["Body"].read().decode("utf-8"))
    except client.exceptions.NoSuchKey:
        return None
    except Exception:
        return None


def upload_file(task_id: str, filename: str, data: bytes) -> str:
    """Upload a file to Spaces under the task prefix."""
    client = _create_client()
    key = f"tasks/{task_id}/{filename}"

    client.put_object(
        Bucket=settings.spaces_bucket,
        Key=key,
        Body=data,
    )

    logger.info("Uploaded %s (%d bytes) for task %s", filename, len(data), task_id)
    return key


def generate_upload_presigned_urls(task_id: str) -> dict[str, str]:
    """Generate presigned PUT URLs for uploading task output files.

    Returns a dict mapping filenames to presigned PUT URLs.
    Also includes a '__prefix__' key with the base URL for dynamic filenames.
    """
    client = _create_client()
    urls = {}

    # Known files the Thought-Node will upload
    for filename in ["stdout.log", "output.tar.gz", "_done.json"]:
        key = f"tasks/{task_id}/{filename}"
        urls[filename] = client.generate_presigned_url(
            "put_object",
            Params={"Bucket": settings.spaces_bucket, "Key": key},
            ExpiresIn=3600,
        )

    logger.info("Generated %d presigned upload URLs for task %s", len(urls), task_id)
    return urls
