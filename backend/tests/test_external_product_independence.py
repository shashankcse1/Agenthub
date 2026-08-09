"""Guardrail: core gateway must not hard-depend on competitor / external AI products."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
FORBIDDEN_PACKAGES = {
    "portkey",
    "portkey_ai",
    "portkey-ai",
    "helicone",
    "n8n",
    "n8n_client",
    "litellm",
    "langsmith",
    "langchain",
    "langchain_core",
    "openai",  # use httpx; do not require OpenAI SDK
    "anthropic",
}
FORBIDDEN_IMPORT_ROOTS = FORBIDDEN_PACKAGES | {"helicone_client", "portkey_ai"}


def _requirement_names(text: str) -> set[str]:
    names: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[<>=!~;\[]", line, maxsplit=1)[0].strip().lower().replace("_", "-")
        if name:
            names.add(name)
    return names


def test_backend_requirements_exclude_competitor_and_vendor_sdks():
    req = (BACKEND / "requirements.txt").read_text(encoding="utf-8")
    names = _requirement_names(req)
    banned = {p.replace("_", "-") for p in FORBIDDEN_PACKAGES}
    present = sorted(names & banned)
    assert present == [], f"Forbidden packages in requirements.txt: {present}"


def test_sdk_pyproject_has_no_runtime_dependencies():
    text = (ROOT / "sdk" / "python" / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in text


def test_sdk_js_package_has_no_runtime_dependencies():
    text = (ROOT / "sdk" / "js" / "package.json").read_text(encoding="utf-8")
    assert '"dependencies"' not in text


def test_backend_app_has_no_forbidden_imports():
    app_root = BACKEND / "app"
    offenders: list[str] = []
    for path in app_root.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0].lower()
                    if root in FORBIDDEN_IMPORT_ROOTS:
                        offenders.append(f"{path.relative_to(ROOT)}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0].lower()
                if root in FORBIDDEN_IMPORT_ROOTS:
                    offenders.append(f"{path.relative_to(ROOT)}: from {node.module}")
    assert offenders == [], "Forbidden external-product imports:\n" + "\n".join(offenders[:40])


def test_gateway_inference_supports_offline_simulation_path():
    text = (BACKEND / "app" / "services" / "gateway_inference.py").read_text(encoding="utf-8")
    assert "GATEWAY_INFERENCE_SIMULATION" in text
    assert "api.openai.com" in text  # overridable default only
    # Must not import vendor SDKs
    assert "import openai" not in text
    assert "from openai" not in text


def test_external_product_independence_doc_exists():
    path = BACKEND / "docs" / "governance" / "external-product-independence.md"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    assert "does not depend on Portkey" in body
    assert "competitive benchmarks only" in body
