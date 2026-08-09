"""Control-plane / data-plane isolation mode (APP_PLANE).

Architecture §12 / §13 / §21.6 call for CP/DP isolation. Until services are
fully split, one codebase can run as:

- ``all`` (default): monolith — admin + inference (current behavior)
- ``control``: control-plane only — admin, policy, evidence; reject inference
- ``data``: data-plane only — OpenAI-compatible inference + RAG; reject admin

Path classification is prefix-based so mixed routers (e.g. gateway.py) stay
intact while process-level isolation becomes deployable.
"""

from __future__ import annotations

import os
from typing import Literal, Optional

AppPlane = Literal["all", "control", "data"]
PathPlane = Literal["shared", "control", "data"]

PLANE_ENV_VAR = "APP_PLANE"
VALID_PLANES: frozenset[str] = frozenset({"all", "control", "data"})

# Always reachable regardless of APP_PLANE (readiness, docs, CORS preflight).
_SHARED_EXACT: frozenset[str] = frozenset(
    {
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/favicon.ico",
        "/platform/control-plane/live",
    }
)
_SHARED_PREFIXES: tuple[str, ...] = (
    "/docs/",
    "/redoc/",
)

# Data-plane inference and RAG (must not run on APP_PLANE=control).
# Checked before control-plane /v1/* SDK admin aliases.
_DATA_PREFIXES: tuple[str, ...] = (
    "/v1/chat/",
    "/v1/embeddings",
    "/v1/responses",
    "/v1/files",
    "/v1/audio/",
    "/v1/images",
    "/v1/rerank",
    "/v1/realtime",
    "/v1/messages",
    "/v1/assistants",
    "/v1/threads",
    "/v1/fine_tuning",
    "/v1/passthrough",
    "/rag/",
)

# Control-plane SDK aliases under /v1 (admin read/list — not inference).
_CONTROL_V1_PREFIXES: tuple[str, ...] = (
    "/v1/virtual-keys",
    "/v1/configs",
    "/v1/analytics",
    "/v1/guardrails",
    "/v1/models",
    "/v1/vector_stores",
)


def resolve_app_plane(raw: Optional[str] = None) -> AppPlane:
    value = (raw if raw is not None else os.getenv(PLANE_ENV_VAR) or "all").strip().lower()
    if value in {"cp", "control-plane", "control_plane"}:
        return "control"
    if value in {"dp", "data-plane", "data_plane", "gateway"}:
        return "data"
    if value in VALID_PLANES:
        return value  # type: ignore[return-value]
    return "all"


def classify_path(path: str) -> PathPlane:
    normalized = (path or "/").strip() or "/"
    if normalized != "/" and normalized.endswith("/"):
        normalized = normalized.rstrip("/") or "/"

    if normalized in _SHARED_EXACT:
        return "shared"
    for prefix in _SHARED_PREFIXES:
        if normalized.startswith(prefix):
            return "shared"

    # Auth sessions and login helpers are needed on both planes.
    if normalized == "/auth" or normalized.startswith("/auth/"):
        return "shared"

    for prefix in _DATA_PREFIXES:
        if normalized == prefix.rstrip("/") or normalized.startswith(prefix):
            return "data"

    for prefix in _CONTROL_V1_PREFIXES:
        if normalized == prefix.rstrip("/") or normalized.startswith(prefix):
            return "control"

    # Remaining /v1/* treated as data (fail closed for unknown inference families).
    if normalized == "/v1" or normalized.startswith("/v1/"):
        return "data"

    # Everything else is control-plane admin.
    return "control"


def path_allowed_on_plane(path: str, plane: AppPlane) -> bool:
    if plane == "all":
        return True
    path_plane = classify_path(path)
    if path_plane == "shared":
        return True
    return path_plane == plane


def should_run_control_schedulers(plane: Optional[AppPlane] = None) -> bool:
    """Discovery / orchestration poll loops belong on control (or combined) plane."""
    resolved = plane if plane is not None else resolve_app_plane()
    return resolved in {"all", "control"}


def plane_rejection_payload(*, path: str, plane: AppPlane, path_plane: PathPlane) -> dict:
    return {
        "detail": {
            "error_code": "PLANE_ROUTE_REJECTED",
            "message": (
                f"Path '{path}' is classified as {path_plane}-plane and is not served "
                f"when APP_PLANE={plane}."
            ),
            "app_plane": plane,
            "path_plane": path_plane,
            "hint": (
                "Deploy separate processes with APP_PLANE=control and APP_PLANE=data, "
                "or set APP_PLANE=all for combined monolith mode."
            ),
        }
    }


def build_plane_posture(
    *,
    plane: Optional[AppPlane] = None,
    on_plane_coverage: Optional[dict] = None,
    schedulers_enabled: Optional[bool] = None,
    policy_generation: Optional[dict] = None,
    peer: Optional[dict] = None,
    drift_status: Optional[str] = None,
    rejection_stats: Optional[dict] = None,
    gate: Optional[dict] = None,
    last_reconcile: Optional[dict] = None,
    drift_events_recent: Optional[list] = None,
    published_policy_generation: Optional[dict] = None,
    slos: Optional[dict] = None,
) -> dict:
    resolved = plane if plane is not None else resolve_app_plane()
    schedulers = (
        should_run_control_schedulers(resolved)
        if schedulers_enabled is None
        else bool(schedulers_enabled)
    )
    isolation = "combined" if resolved == "all" else "process_isolated"
    coverage = on_plane_coverage or {}
    return {
        "app_plane": resolved,
        "isolation_mode": isolation,
        "control_schedulers_enabled": schedulers,
        "env_var": PLANE_ENV_VAR,
        "architecture_targets": {
            "control_plane_data_plane_isolation": resolved != "all",
            "stateless_gateway_workers": resolved == "data",
            "admin_off_inference_path": resolved == "control",
            "policy_generation_reconcile": True,
            "active_drift_watcher": True,
            "hot_policy_publish": True,
            "durable_drift_events": True,
            "last_known_good_policy": True,
            "desired_observed_split": True,
            "control_readonly_freeze": True,
            "lkg_rollback": True,
            "peer_ack": True,
            "liveness_probe": True,
        },
        "policy_generation": policy_generation,
        "published_policy_generation": published_policy_generation,
        "peer": peer,
        "drift_status": drift_status,
        "rejection_stats": rejection_stats,
        "gate": gate,
        "last_reconcile": last_reconcile,
        "drift_events_recent": drift_events_recent,
        "slos": slos,
        "on_plane_coverage": {
            "on_plane_events": int(coverage.get("on_plane_events") or 0),
            "off_plane_detected": int(coverage.get("off_plane_detected") or 0),
            "on_plane_coverage_percent": coverage.get("on_plane_coverage_percent"),
            "formula": coverage.get("formula"),
        }
        if coverage
        else None,
        "notes": (
            "APP_PLANE=all preserves monolith behavior. "
            "Set APP_PLANE=control|data for deploy-time isolation per architecture §12. "
            "Set DATA_PLANE_PEER_URL / CONTROL_PLANE_PEER_URL for peer health and generation drift. "
            "PLANE_FAIL_CLOSED_MODE=off|peer_unreachable|drift gates data-plane inference. "
            "PLANE_DRIFT_WATCHER_ENABLED controls background reconcile. "
            "PLANE_CONTROL_READONLY freezes control-plane mutations during incidents. "
            "Policy generation is hot-published to Redis (optional) and plane.policy_generation_json; "
            "last-known-good fingerprint supports DP continue-on-CP-degradation."
        ),
    }
