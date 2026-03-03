"""Cost tracking for inference and compute spend."""

import logging

from .models import CostReport

logger = logging.getLogger("ephemeral.cost")

# Droplet hourly rates (from DigitalOcean pricing)
DROPLET_HOURLY_RATES = {
    "s-1vcpu-512mb-10gb": 0.00595,
    "s-1vcpu-1gb": 0.00893,
    "s-1vcpu-2gb": 0.01786,
    "s-2vcpu-2gb": 0.02679,
    "s-2vcpu-4gb": 0.03571,
    "s-4vcpu-8gb": 0.07143,
}

# Gradient model pricing (per million tokens) - DO-native billing
MODEL_PRICING = {
    "llama3.3-70b-instruct": {"input": 0.65, "output": 0.65},
    "alibaba-qwen3-32b": {"input": 0.25, "output": 0.55},
    "deepseek-r1-distill-llama-70b": {"input": 0.99, "output": 0.99},
    "llama3-8b-instruct": {"input": 0.198, "output": 0.198},
    "mistral-nemo-instruct-2407": {"input": 0.30, "output": 0.30},
    "openai-gpt-oss-20b": {"input": 0.05, "output": 0.45},
    "openai-gpt-oss-120b": {"input": 0.10, "output": 0.70},
}


def calculate_inference_cost(
    model: str, input_tokens: int, output_tokens: int
) -> float:
    """Calculate the cost of a Gradient inference call."""
    pricing = MODEL_PRICING.get(model, {"input": 3.0, "output": 15.0})
    cost = (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000
    return round(cost, 6)


def calculate_droplet_cost(slug: str) -> float:
    """Calculate Droplet cost (always 1 hour minimum billing)."""
    return DROPLET_HOURLY_RATES.get(slug, 0.00893)


def calculate_always_on_monthly(slug: str) -> float:
    """What it would cost to keep this Droplet running 24/7 for a month."""
    hourly = DROPLET_HOURLY_RATES.get(slug, 0.00893)
    return round(hourly * 730, 2)  # ~730 hours in a month


def build_cost_report(
    slug: str,
    inference_cost: float = 0.0,
) -> CostReport:
    """Build a complete cost report for a task."""
    droplet_cost = calculate_droplet_cost(slug)
    total = inference_cost + droplet_cost
    monthly = calculate_always_on_monthly(slug)
    savings = ((monthly - total) / monthly * 100) if monthly > 0 else 0.0

    report = CostReport(
        inference_cost_usd=round(inference_cost, 6),
        droplet_cost_usd=round(droplet_cost, 5),
        total_cost_usd=round(total, 5),
        always_on_equivalent_monthly=monthly,
        savings_pct=round(savings, 2),
    )

    logger.info(
        "Cost report: total=$%.5f, equivalent_monthly=$%.2f, savings=%.1f%%",
        report.total_cost_usd,
        report.always_on_equivalent_monthly,
        report.savings_pct,
    )

    return report
