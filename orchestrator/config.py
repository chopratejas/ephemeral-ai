"""Configuration loaded from environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # DigitalOcean API
    digitalocean_api_token: str

    # DigitalOcean Spaces
    spaces_key: str
    spaces_secret: str
    spaces_bucket: str = "ephemeral-ai"
    spaces_region: str = "sfo3"

    # Gradient AI
    gradient_model_access_key: str
    gradient_model: str = "llama3.3-70b-instruct"
    gradient_base_url: str = "https://inference.do-ai.run/v1/"

    # Orchestrator
    orchestrator_url: str = "http://localhost:8000"
    max_concurrent_droplets: int = 5
    max_droplet_age_minutes: int = 15
    daily_budget_usd: float = 5.0
    default_region: str = "sfo3"

    # Droplet defaults
    droplet_tag: str = "ephemeral-ai"
    default_image: str = "219195233"  # ephemeral-lean-v3 (25GB disk, Python+Node+TS)
    min_droplet_slug: str = "s-1vcpu-1gb"  # Minimum size (snapshot needs 25GB disk)

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
