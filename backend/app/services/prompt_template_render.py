"""Canonical prompt-registry variable rendering (Mustache-like `{{identifier}}`).

Single shared strategy for Playground render, `/v1/prompts/{id}/render`, and
gateway/orchestration prompt-registry fill. Intentionally separate from Flow
Studio step/input templates (`resolve_safe_template`).
"""

from __future__ import annotations

import re

from fastapi import HTTPException

# Strict identifier tokens only — no spaces inside the name, optional whitespace
# around the braces: {{name}}, {{ user.id }}, {{foo-bar}}.
PROMPT_TEMPLATE_VAR_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_\-\.]*)\s*\}\}")

MAX_PROMPT_TEMPLATE_VARIABLES = 64
MAX_PROMPT_TEMPLATE_KEY_LEN = 64
MAX_PROMPT_TEMPLATE_VALUE_LEN = 4000


def extract_prompt_template_variables(prompt_text: str) -> list[str]:
    return sorted(
        {match.group(1).strip() for match in PROMPT_TEMPLATE_VAR_PATTERN.finditer(prompt_text or "")}
    )


def sanitize_prompt_template_variables(variables: dict[str, str] | None) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    if not isinstance(variables, dict):
        return sanitized
    for raw_key, raw_value in list(variables.items())[:MAX_PROMPT_TEMPLATE_VARIABLES]:
        key = str(raw_key or "").strip()[:MAX_PROMPT_TEMPLATE_KEY_LEN]
        if not key:
            continue
        sanitized[key] = str(raw_value)[:MAX_PROMPT_TEMPLATE_VALUE_LEN]
    return sanitized


def render_prompt_template_variables(
    prompt_text: str,
    variables: dict[str, str] | None = None,
    *,
    require_matched_braces: bool = True,
) -> str:
    """Replace `{{identifier}}` tokens. Missing keys become empty strings."""
    text = str(prompt_text or "")
    if require_matched_braces:
        if "{{" in text and "}}" not in text:
            raise HTTPException(status_code=422, detail="Prompt template has unmatched opening braces.")
        if "}}" in text and "{{" not in text:
            raise HTTPException(status_code=422, detail="Prompt template has unmatched closing braces.")

    sanitized = sanitize_prompt_template_variables(variables)

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        return str(sanitized.get(key, ""))

    return PROMPT_TEMPLATE_VAR_PATTERN.sub(_replace, text)
