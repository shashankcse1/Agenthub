"""Live discovery of hyperscaler foundation / deployment models.

Discovers currently published IDs from AWS Bedrock, Azure OpenAI, and Google
Gemini/Vertex when credentials/env are available, then maps them into
CloudModelSpec rows for catalog preview or sync.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from app.services.cloud_model_catalog import CloudModelSpec


def _ctx_tokens_from_summary(raw: Any, default: int = 128000) -> int:
    try:
        value = int(raw)
        if value > 0:
            return min(value, 10_000_000)
    except (TypeError, ValueError):
        pass
    return default


def _bedrock_region() -> str:
    return (
        str(os.getenv("AWS_BEDROCK_REGION") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1")
        .strip()
        or "us-east-1"
    )


def discover_bedrock_models(*, region: Optional[str] = None) -> tuple[list[CloudModelSpec], dict[str, Any]]:
    """List Bedrock foundation models (+ inference profiles when available)."""
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("boto3 is required for Bedrock model discovery") from exc

    resolved_region = str(region or _bedrock_region()).strip() or "us-east-1"
    client = boto3.client("bedrock", region_name=resolved_region)
    specs: list[CloudModelSpec] = []
    seen: set[str] = set()

    foundation = client.list_foundation_models()
    for summary in foundation.get("modelSummaries") or []:
        if not isinstance(summary, dict):
            continue
        model_id = str(summary.get("modelId") or "").strip()
        if not model_id or model_id in seen:
            continue
        # Prefer TEXT / EMBEDDING modalities for the chat/embeddings catalog.
        modalities = {str(item).upper() for item in (summary.get("inputModalities") or [])}
        output_modalities = {str(item).upper() for item in (summary.get("outputModalities") or [])}
        if modalities and not (modalities & {"TEXT", "IMAGE"} or output_modalities & {"TEXT", "EMBEDDING", "IMAGE"}):
            continue
        seen.add(model_id)
        name = str(summary.get("modelName") or model_id).strip() or model_id
        provider_name = str(summary.get("providerName") or "AWS").strip() or "AWS"
        specs.append(
            CloudModelSpec(
                provider_type="aws",
                model_name=model_id,
                display_name=f"{name} (Bedrock)",
                context_window_tokens=128000,
                description=f"Live Bedrock foundation model from {provider_name} ({resolved_region})",
                recommendation_rationale="Discovered via list_foundation_models",
                status="active",
            )
        )

    profile_count = 0
    try:
        profiles = client.list_inference_profiles(maxResults=1000, typeEquals="SYSTEM_DEFINED")
        for profile in profiles.get("inferenceProfileSummaries") or []:
            if not isinstance(profile, dict):
                continue
            profile_id = str(profile.get("inferenceProfileId") or profile.get("inferenceProfileArn") or "").strip()
            if not profile_id or profile_id in seen:
                continue
            # Prefer short inference profile IDs (us.anthropic....) over ARNs.
            if profile_id.startswith("arn:"):
                continue
            seen.add(profile_id)
            profile_count += 1
            name = str(profile.get("inferenceProfileName") or profile_id).strip() or profile_id
            specs.append(
                CloudModelSpec(
                    provider_type="aws",
                    model_name=profile_id,
                    display_name=f"{name} (Bedrock profile)",
                    context_window_tokens=200000,
                    description=f"Live Bedrock inference profile ({resolved_region})",
                    recommendation_rationale="Discovered via list_inference_profiles",
                    status="active",
                )
            )
    except Exception:
        # Older regions / IAM policies may not allow inference-profile listing.
        profile_count = 0

    meta = {
        "provider": "aws",
        "region": resolved_region,
        "foundation_models": len(specs) - profile_count,
        "inference_profiles": profile_count,
        "total": len(specs),
        "source": "live",
    }
    return specs, meta


def discover_azure_openai_models(
    *,
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
    api_version: Optional[str] = None,
) -> tuple[list[CloudModelSpec], dict[str, Any]]:
    """List Azure OpenAI deployments from the resource endpoint."""
    base = str(
        endpoint
        or os.getenv("AZURE_OPENAI_API_BASE")
        or os.getenv("AZURE_OPENAI_ENDPOINT")
        or os.getenv("AZURE_OPENAI_BASE_URL")
        or ""
    ).strip().rstrip("/")
    key = str(api_key or os.getenv("AZURE_OPENAI_API_KEY") or "").strip()
    version = str(api_version or os.getenv("AZURE_OPENAI_API_VERSION") or "2024-10-21").strip() or "2024-10-21"
    if not base or not key:
        raise RuntimeError(
            "Azure discovery requires AZURE_OPENAI_API_BASE (or ENDPOINT) and AZURE_OPENAI_API_KEY"
        )

    root = base[:-len("/openai")] if base.endswith("/openai") else base
    if root.endswith("/v1") or "/openai/v1" in root:
        # v1-compatible resources still expose classic deployments listing under /openai/deployments.
        root = root.split("/openai")[0].rstrip("/")
    url = f"{root}/openai/deployments?api-version={version}"
    response = httpx.get(
        url,
        headers={"api-key": key, "Authorization": f"Bearer {key}"},
        timeout=30.0,
    )
    if response.status_code >= 400:
        raise RuntimeError(f"Azure deployments list failed ({response.status_code}): {response.text[:300]}")

    payload = response.json()
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        rows = payload if isinstance(payload, list) else []

    specs: list[CloudModelSpec] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        deployment_id = str(row.get("id") or row.get("deployment_id") or "").strip()
        if not deployment_id:
            continue
        model_name = str(row.get("model") or row.get("model_name") or deployment_id).strip()
        specs.append(
            CloudModelSpec(
                provider_type="azure-openai",
                model_name=deployment_id,
                display_name=f"Azure {deployment_id}",
                context_window_tokens=128000,
                description=f"Live Azure OpenAI deployment (model={model_name})",
                recommendation_rationale="Discovered via Azure deployments API",
                status="active",
            )
        )
    meta = {
        "provider": "azure-openai",
        "endpoint": root,
        "api_version": version,
        "total": len(specs),
        "source": "live",
    }
    return specs, meta


def discover_google_gemini_models(*, api_key: Optional[str] = None) -> tuple[list[CloudModelSpec], dict[str, Any]]:
    """List Google AI Studio / Gemini API models."""
    key = str(api_key or os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY") or "").strip()
    if not key:
        raise RuntimeError("Google Gemini discovery requires GOOGLE_API_KEY (or GEMINI_API_KEY)")

    url = "https://generativelanguage.googleapis.com/v1beta/models"
    response = httpx.get(url, params={"key": key, "pageSize": 200}, timeout=30.0)
    if response.status_code >= 400:
        raise RuntimeError(f"Gemini models list failed ({response.status_code}): {response.text[:300]}")
    payload = response.json()
    rows = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        rows = []

    specs: list[CloudModelSpec] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw_name = str(row.get("name") or "").strip()
        model_id = raw_name.split("/")[-1] if raw_name else ""
        if not model_id:
            continue
        methods = {str(item) for item in (row.get("supportedGenerationMethods") or [])}
        # Keep generative + embedding models; skip obscure utility-only entries when methods exist.
        if methods and not (methods & {"generateContent", "embedContent", "countTokens", "predict"}):
            continue
        display = str(row.get("displayName") or model_id).strip() or model_id
        specs.append(
            CloudModelSpec(
                provider_type="google",
                model_name=model_id,
                display_name=display,
                context_window_tokens=_ctx_tokens_from_summary(row.get("inputTokenLimit"), 1000000),
                description=str(row.get("description") or "Live Gemini API model")[:500],
                recommendation_rationale="Discovered via Gemini models.list",
                status="active",
            )
        )
    meta = {"provider": "google", "total": len(specs), "source": "live"}
    return specs, meta


def discover_vertex_models(
    *,
    project: Optional[str] = None,
    location: Optional[str] = None,
    access_token: Optional[str] = None,
) -> tuple[list[CloudModelSpec], dict[str, Any]]:
    """List Google publisher Gemini models via Vertex OpenAPI publisher catalog."""
    resolved_project = str(
        project or os.getenv("VERTEX_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT") or ""
    ).strip()
    resolved_location = str(
        location or os.getenv("VERTEX_LOCATION") or os.getenv("GOOGLE_CLOUD_LOCATION") or "us-central1"
    ).strip() or "us-central1"
    token = str(
        access_token
        or os.getenv("VERTEX_ACCESS_TOKEN")
        or os.getenv("VERTEX_API_KEY")
        or os.getenv("GOOGLE_OAUTH_ACCESS_TOKEN")
        or os.getenv("GOOGLE_API_KEY")
        or ""
    ).strip()
    if not resolved_project:
        raise RuntimeError("Vertex discovery requires VERTEX_PROJECT (or GOOGLE_CLOUD_PROJECT)")
    if not token:
        raise RuntimeError("Vertex discovery requires VERTEX_ACCESS_TOKEN / VERTEX_API_KEY / GOOGLE_API_KEY")

    # Publisher model collection (Google Gemini family).
    url = (
        f"https://{resolved_location}-aiplatform.googleapis.com/v1/"
        f"publishers/google/models"
    )
    response = httpx.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        params={"pageSize": 200},
        timeout=45.0,
    )
    if response.status_code >= 400:
        # Fall back to short Gemini IDs when publisher listing is unauthorized.
        raise RuntimeError(f"Vertex publisher models list failed ({response.status_code}): {response.text[:300]}")

    payload = response.json()
    rows = payload.get("publisherModels") or payload.get("models") or []
    if not isinstance(rows, list):
        rows = []

    specs: list[CloudModelSpec] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        full_name = str(row.get("name") or "").strip()
        short = full_name.split("/")[-1] if full_name else str(row.get("versionId") or "").strip()
        if not short or short in seen:
            continue
        seen.add(short)
        display = str(row.get("displayName") or short).strip() or short
        specs.append(
            CloudModelSpec(
                provider_type="vertex",
                model_name=short,
                display_name=f"Vertex {display}",
                context_window_tokens=1000000,
                description=f"Live Vertex publisher model ({resolved_location})",
                recommendation_rationale="Discovered via Vertex publishers/google/models",
                status="active",
            )
        )
        # Also register the full publisher path when present.
        if full_name.startswith("publishers/") and full_name not in seen:
            seen.add(full_name)
            specs.append(
                CloudModelSpec(
                    provider_type="vertex",
                    model_name=full_name,
                    display_name=f"Vertex {display} (publisher path)",
                    context_window_tokens=1000000,
                    description=f"Live Vertex publisher path ({resolved_location})",
                    recommendation_rationale="Discovered via Vertex publishers/google/models",
                    status="active",
                )
            )

    meta = {
        "provider": "vertex",
        "project": resolved_project,
        "location": resolved_location,
        "total": len(specs),
        "source": "live",
    }
    return specs, meta


SUPPORTED_DISCOVER_TARGETS = frozenset({"bedrock", "aws", "azure", "azure-openai", "gcp", "google", "vertex", "all"})


def discover_cloud_models(
    targets: list[str],
    *,
    region: Optional[str] = None,
) -> dict[str, Any]:
    requested = [str(item).strip().lower() for item in targets if str(item).strip()]
    if not requested or "all" in requested:
        requested = ["bedrock", "azure", "google", "vertex"]

    normalized: list[str] = []
    for item in requested:
        if item in {"aws", "bedrock"}:
            key = "bedrock"
        elif item in {"azure", "azure-openai"}:
            key = "azure"
        elif item in {"gcp", "google"}:
            key = "google"
        elif item == "vertex":
            key = "vertex"
        else:
            raise ValueError(f"Unknown discover target: {item}")
        if key not in normalized:
            normalized.append(key)

    specs: list[CloudModelSpec] = []
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for target in normalized:
        try:
            if target == "bedrock":
                found, meta = discover_bedrock_models(region=region)
            elif target == "azure":
                found, meta = discover_azure_openai_models()
            elif target == "google":
                found, meta = discover_google_gemini_models()
            else:
                found, meta = discover_vertex_models()
            specs.extend(found)
            results.append(meta)
        except Exception as exc:  # noqa: BLE001 - collect per-target errors for operator UI
            errors.append({"target": target, "error": str(exc)[:500]})
            results.append({"provider": target, "total": 0, "source": "error", "error": str(exc)[:500]})

    # Deduplicate by provider+model while preserving order.
    deduped: list[CloudModelSpec] = []
    seen_keys: set[tuple[str, str]] = set()
    for spec in specs:
        key = (spec.provider_type, spec.model_name)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(spec)

    return {
        "targets": normalized,
        "models": [
            {
                "provider_type": spec.provider_type,
                "model_name": spec.model_name,
                "display_name": spec.display_name,
                "context_window_tokens": spec.context_window_tokens,
                "description": spec.description,
                "recommendation_rationale": spec.recommendation_rationale,
                "status": spec.status,
            }
            for spec in deduped
        ],
        "specs": deduped,
        "results": results,
        "errors": errors,
        "total": len(deduped),
    }
