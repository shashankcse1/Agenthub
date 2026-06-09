import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.database import Base, SessionLocal, engine
from app.logging_utils import configure_logging, get_logger, sanitize_fields
from app.models import RuntimeConfig
from app.routers import (
    agentic,
    agent_configs,
    agents,
    audit,
    auth,
    benchmark_scan,
    compliance,
    cost,
    discovery,
    gateway,
    modules,
    observability,
    playground,
    providers,
    runtime_config,
    route_drafts,
)
from app.runtime_constants import RUNTIME_CONFIG_SECURITY_CORS_ALLOW_ORIGINS_CSV
from app.services.rate_limit import SlidingWindowRateLimiter
from app.services.provider_crypto import provider_encryption_warnings, validate_provider_encryption_configuration
from app.security import (
    insecure_configuration_warnings,
    resolve_session_id_from_bearer_token,
    validate_session_secret_configuration,
)

configure_logging()
logger = get_logger(__name__)
_SECURITY_ALERT_WEBHOOK_URL = (os.getenv("SECURITY_ALERT_WEBHOOK_URL") or "").strip()


def _security_alert_webhook_timeout_seconds() -> float:
    raw = (os.getenv("SECURITY_ALERT_WEBHOOK_TIMEOUT_SECONDS") or "2.0").strip()
    try:
        parsed = float(raw)
    except ValueError:
        logger.warning(
            "invalid_security_alert_webhook_timeout_seconds %s",
            sanitize_fields({"value": raw, "fallback_seconds": 2.0}),
        )
        return 2.0
    if parsed <= 0:
        logger.warning(
            "non_positive_security_alert_webhook_timeout_seconds %s",
            sanitize_fields({"value": raw, "fallback_seconds": 2.0}),
        )
        return 2.0
    return parsed


_SECURITY_ALERT_WEBHOOK_TIMEOUT_SECONDS = _security_alert_webhook_timeout_seconds()


def _runtime_environment() -> str:
    return (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "dev").strip().lower()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _should_auto_create_schema_on_startup() -> bool:
    env = _runtime_environment()
    if env not in {"dev", "test", "local"}:
        if _env_bool("STARTUP_AUTO_CREATE_SCHEMA", False):
            logger.warning(
                "startup_schema_auto_create_ignored_non_local %s",
                sanitize_fields({"environment": env}),
            )
        return False

    return _env_bool("STARTUP_AUTO_CREATE_SCHEMA", True)


def _cors_allow_origins() -> list[str]:
    db = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_SECURITY_CORS_ALLOW_ORIGINS_CSV).first()
        if row and row.config_value.strip():
            origins = [item.strip() for item in row.config_value.split(",") if item.strip()]
            if _runtime_environment() not in {"dev", "test", "local"} and "*" in origins:
                raise RuntimeError("security.cors_allow_origins_csv cannot include '*' outside dev/test/local.")
            return origins
    except Exception:
        logger.info(
            "runtime_config_cors_lookup_skipped %s",
            sanitize_fields({"environment": _runtime_environment()}),
        )
    finally:
        db.close()

    raw = (os.getenv("CORS_ALLOW_ORIGINS") or "").strip()
    if not raw:
        if _runtime_environment() in {"dev", "test", "local"}:
            ui_port = (os.getenv("UI_PORT") or "4173").strip() or "4173"
            # Local defaults keep browser-based operator workflows working without extra env setup.
            return [
                f"http://127.0.0.1:{ui_port}",
                f"http://localhost:{ui_port}",
            ]
        return []
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    if _runtime_environment() not in {"dev", "test", "local"} and "*" in origins:
        raise RuntimeError("CORS_ALLOW_ORIGINS cannot include '*' outside dev/test/local.")
    return origins


def _emit_security_alert(warning: str) -> None:
    if not _SECURITY_ALERT_WEBHOOK_URL:
        return
    payload = {
        "event_type": "insecure_configuration_detected",
        "environment": _runtime_environment(),
        "warning": warning,
    }
    try:
        with httpx.Client(timeout=_SECURITY_ALERT_WEBHOOK_TIMEOUT_SECONDS) as client:
            client.post(_SECURITY_ALERT_WEBHOOK_URL, json=payload)
    except Exception:
        logger.error(
            "security_alert_webhook_failed %s",
            sanitize_fields({"warning": warning, "environment": _runtime_environment()}),
        )


def _upgrade_agent_table_schema() -> None:
    statements = [
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_type VARCHAR(64) NOT NULL DEFAULT 'other'",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_provider_table_schema() -> None:
    statements = [
        "ALTER TABLE workload_identity_federation_profiles ADD COLUMN IF NOT EXISTS role_arn_or_equivalent_encrypted TEXT",
        "ALTER TABLE workload_identity_federation_profiles ADD COLUMN IF NOT EXISTS bootstrap_token_encrypted TEXT",
        "ALTER TABLE secret_provider_configs ADD COLUMN IF NOT EXISTS provider_address_encrypted TEXT",
        "ALTER TABLE secret_provider_configs ADD COLUMN IF NOT EXISTS auth_method_encrypted TEXT",
        "ALTER TABLE secret_provider_configs ADD COLUMN IF NOT EXISTS role_or_mount_encrypted TEXT",
        "ALTER TABLE secret_provider_configs ADD COLUMN IF NOT EXISTS bootstrap_token_encrypted TEXT",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_directory_identity_schema() -> None:
    statements = [
        "ALTER TABLE directory_users ADD COLUMN IF NOT EXISTS password_hash TEXT",
        "ALTER TABLE directory_users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE directory_users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP",
        "ALTER TABLE directory_users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_auth_policy_schema() -> None:
    statements = [
        "ALTER TABLE auth_policy_configs ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE auth_policy_config_revisions ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_cost_event_schema() -> None:
    statements = [
        "ALTER TABLE cost_events ADD COLUMN IF NOT EXISTS request_tag VARCHAR(64)",
        "CREATE INDEX IF NOT EXISTS ix_cost_events_request_tag ON cost_events (request_tag)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


@asynccontextmanager
async def lifespan(_: FastAPI):
    validate_session_secret_configuration()
    validate_provider_encryption_configuration()
    for warning in [*insecure_configuration_warnings(), *provider_encryption_warnings()]:
        logger.warning("insecure_configuration_detected %s", sanitize_fields({"warning": warning}))
        _emit_security_alert(warning)
    if _should_auto_create_schema_on_startup():
        Base.metadata.create_all(bind=engine)
        _upgrade_agent_table_schema()
        _upgrade_provider_table_schema()
        _upgrade_directory_identity_schema()
        _upgrade_auth_policy_schema()
        _upgrade_cost_event_schema()
    else:
        logger.info(
            "startup_schema_auto_create_skipped %s",
            sanitize_fields({"environment": _runtime_environment()}),
        )
    yield


app = FastAPI(
    title="Enterprise Multi-Agent Platform API",
    description=(
        "Security-first multi-agent platform API with audited control-plane workflows, "
        "role-based authorization, dual-approval guardrails for sensitive production actions, "
        "and OpenAI-compatible gateway operations."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "Health", "description": "Service readiness and runtime status endpoints."},
        {"name": "Benchmark and Scan", "description": "Benchmark and security scan execution/history workflows."},
        {"name": "Agents", "description": "Agent registration and ownership workflows."},
        {"name": "Agent Config", "description": "Persisted runtime agent configuration controls."},
        {"name": "Auth and Security", "description": "AuthN/AuthZ, session, and governance controls."},
        {"name": "Audit", "description": "Audit evidence querying and traceability endpoints."},
        {"name": "Discovery", "description": "Source sync and discovered-agent governance workflows."},
        {"name": "Modules", "description": "Module lifecycle, validation, upgrade, and deprecation workflows."},
        {"name": "Gateway and Keys", "description": "Routing, key lifecycle, OpenAI-compatible APIs, and gateway governance."},
        {"name": "Providers", "description": "Tenant, identity federation, and secret provider management workflows."},
        {"name": "Runtime Config", "description": "Runtime configuration read/validate/write governance endpoints."},
        {"name": "Cost", "description": "Cost telemetry, budgets, anomaly, and policy evaluation workflows."},
        {"name": "Route Drafts", "description": "Route draft approval, promote, and rollback workflows."},
        {"name": "Observability", "description": "Trace and log observability endpoints with schema diagnostics."},
        {"name": "Compliance", "description": "Control coverage, mappings, evidence, and retention workflows."},
        {"name": "Playground", "description": "Interactive prompt execution and governed run workflows."},
        {"name": "Agentic", "description": "Readiness, certification, checkpoint, and policy automation workflows."},
    ],
    lifespan=lifespan,
)


def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )

    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "Signed session bearer token issued by /auth/sessions.",
    }
    security_schemes["ActorIdHeader"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-Actor-Id",
        "description": "Header-based actor identity for local/dev/test compatibility only.",
    }
    security_schemes["ActorRoleHeader"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-Actor-Role",
        "description": "Header-based actor role for local/dev/test compatibility only.",
    }
    security_schemes["MfaVerifiedHeader"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-MFA-Verified",
        "description": "Optional header required by privileged endpoints that enforce MFA.",
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = _custom_openapi

cors_allow_origins = _cors_allow_origins()
if cors_allow_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_allow_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Actor-Id", "X-Actor-Role", "X-MFA-Verified"],
    )

rate_limiter = SlidingWindowRateLimiter()


def _rate_limit_actor_identity(request: Request) -> str:
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header:
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            try:
                session_id = resolve_session_id_from_bearer_token(token.strip())
                return f"session:{session_id}"
            except Exception:
                logger.trace("rate_limiter_invalid_bearer_fallback_to_ip")

    # Keep test/local compatibility while blocking header identity trust in production.
    if _runtime_environment() in {"dev", "test", "local"}:
        header_actor = (request.headers.get("X-Actor-Id") or "").strip()
        if header_actor:
            return header_actor

    client_ip = request.client.host if request.client and request.client.host else "unknown"
    return f"ip:{client_ip}"


@app.middleware("http")
async def ui_polling_rate_limit_middleware(request: Request, call_next):
    actor_id = _rate_limit_actor_identity(request)
    logger.trace(
        "request_received %s",
        sanitize_fields(
            {
                "method": request.method,
                "path": request.url.path,
                "actor_id": actor_id,
            }
        ),
    )
    allowed, retry_after = rate_limiter.allow(
        actor_id=actor_id,
        method=request.method,
        path=request.url.path,
    )
    if not allowed:
        logger.error(
            "rate_limit_exceeded %s",
            sanitize_fields(
                {
                    "actor_id": actor_id,
                    "path": request.url.path,
                    "retry_after_seconds": retry_after,
                }
            ),
        )
        return JSONResponse(
            status_code=429,
            content={
                "detail": {
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests for this endpoint. Reduce UI polling frequency.",
                    "actor_id": actor_id,
                    "path": request.url.path,
                    "retry_after_seconds": retry_after,
                }
            },
            headers={"Retry-After": str(retry_after)},
        )
    try:
        response = await call_next(request)
    except Exception:
        logger.error(
            "request_failed %s",
            sanitize_fields(
                {
                    "method": request.method,
                    "path": request.url.path,
                    "actor_id": actor_id,
                }
            ),
        )
        raise
    logger.info(
        "request_completed %s",
        sanitize_fields(
            {
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "actor_id": actor_id,
            }
        ),
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    return response


app.include_router(benchmark_scan.router, tags=["Benchmark and Scan"])
app.include_router(agents.router, tags=["Agents"])
app.include_router(agent_configs.router, tags=["Agent Config"])
app.include_router(auth.router, tags=["Auth and Security"])
app.include_router(audit.router, tags=["Audit"])
app.include_router(discovery.router, tags=["Discovery"])
app.include_router(modules.router, tags=["Modules"])
app.include_router(gateway.router, tags=["Gateway and Keys"])
app.include_router(providers.router, tags=["Providers"])
app.include_router(runtime_config.router, tags=["Runtime Config"])
app.include_router(cost.router, tags=["Cost"])
app.include_router(route_drafts.router, tags=["Route Drafts"])
app.include_router(observability.router, tags=["Observability"])
app.include_router(compliance.router, tags=["Compliance"])
app.include_router(playground.router, tags=["Playground"])
app.include_router(agentic.router, tags=["Agentic"])


@app.get("/health", tags=["Health"], summary="Service health", description="Returns API health status and rate-limiter runtime status.")
def health():
    return {
        "status": "ok",
        "rate_limit": rate_limiter.runtime_status(),
    }
