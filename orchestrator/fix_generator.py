"""Fix Generator - Uses LLM to generate code fixes for security findings.

Given a finding (file, line, description), reads the surrounding code context
and generates a precise fix. Can optionally create a GitHub PR.
"""

import json
import logging

from openai import OpenAI

from .config import settings

logger = logging.getLogger("ephemeral.fix_generator")

FIX_PROMPT = """\
You are a senior security engineer writing a code fix.

You will receive:
1. The vulnerable file path and line number
2. The code surrounding the vulnerability (with line numbers)
3. A description of the vulnerability

Generate a MINIMAL fix. Only change what's necessary. Do not refactor,
do not add comments, do not change style. Just fix the security issue.

Output ONLY valid JSON:
{
    "fixed_code": "the complete fixed version of the shown code block",
    "explanation": "one sentence explaining what was changed and why",
    "diff_summary": "- removed: description of what was removed\\n+ added: description of what was added"
}
"""


def generate_fix(
    file_path: str,
    line_number: int,
    vulnerability: str,
    code_context: str,
    fix_suggestion: str = "",
) -> dict:
    """Generate a code fix for a security finding using LLM.

    Args:
        file_path: Path to the vulnerable file
        line_number: Line number of the vulnerability
        vulnerability: Description of the vulnerability
        code_context: The code surrounding the vulnerability (50 lines)
        fix_suggestion: Optional hint about how to fix it

    Returns:
        dict with fixed_code, explanation, diff_summary
    """
    client = OpenAI(
        base_url=settings.gradient_base_url,
        api_key=settings.gradient_model_access_key,
    )

    user_message = f"""File: {file_path}
Line: {line_number}
Vulnerability: {vulnerability}

Code context (with line numbers):
```
{code_context}
```
"""
    if fix_suggestion:
        user_message += f"\nSuggested approach: {fix_suggestion}"

    try:
        response = client.chat.completions.create(
            model=settings.gradient_model,
            messages=[
                {"role": "system", "content": FIX_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.1,
            max_completion_tokens=2048,
        )

        raw = response.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1]
            if raw.endswith("```"):
                raw = raw[:raw.rfind("```")]
            raw = raw.strip()

        fix = json.loads(raw)
        logger.info("Generated fix for %s:%d", file_path, line_number)
        return fix

    except Exception as e:
        logger.error("Fix generation failed: %s", e)
        return {
            "fixed_code": "",
            "explanation": f"Fix generation failed: {e}",
            "diff_summary": "",
        }
