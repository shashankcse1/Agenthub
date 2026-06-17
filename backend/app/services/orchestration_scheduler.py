from __future__ import annotations

import os
import threading
from typing import Optional

from app.database import SessionLocal
from app.logging_utils import get_logger, sanitize_fields
from app.runtime_constants import (
    RUNTIME_CONFIG_ORCHESTRATION_SCHEDULER_ENABLED,
    RUNTIME_CONFIG_ORCHESTRATION_SCHEDULER_INTERVAL_SECONDS,
)
from app.security import ActorContext
from app.services.orchestration_triggers import poll_due_scheduled_flows
from app.services.runtime_config import get_runtime_config, get_runtime_config_int

logger = get_logger(__name__)

_scheduler_thread: Optional[threading.Thread] = None
_scheduler_stop = threading.Event()


def _env_flag(name: str, default: str = "false") -> bool:
    return str(os.getenv(name, default)).strip().lower() in {"1", "true", "yes", "on"}


def orchestration_scheduler_enabled(db=None) -> bool:
    if not _env_flag("ORCHESTRATION_SCHEDULER_ENABLED", "true"):
        return False
    session = db
    owns_session = False
    if session is None:
        session = SessionLocal()
        owns_session = True
    try:
        value = get_runtime_config(session, RUNTIME_CONFIG_ORCHESTRATION_SCHEDULER_ENABLED, "true").strip().lower()
        return value in {"1", "true", "yes", "on"}
    finally:
        if owns_session:
            session.close()


def orchestration_scheduler_interval_seconds(db=None) -> int:
    if db is None:
        session = SessionLocal()
        try:
            value = get_runtime_config_int(session, RUNTIME_CONFIG_ORCHESTRATION_SCHEDULER_INTERVAL_SECONDS, 60)
        finally:
            session.close()
    else:
        value = get_runtime_config_int(db, RUNTIME_CONFIG_ORCHESTRATION_SCHEDULER_INTERVAL_SECONDS, 60)
    return max(15, min(3600, int(value)))


def _scheduler_loop() -> None:
    logger.info(
        "orchestration_scheduler_started %s",
        sanitize_fields({"env_override": _env_flag("ORCHESTRATION_SCHEDULER_ENABLED", "true")}),
    )
    while not _scheduler_stop.is_set():
        db = SessionLocal()
        try:
            if orchestration_scheduler_enabled(db):
                ctx = ActorContext(
                    actor_id="orchestration-scheduler",
                    actor_role="Platform Admin",
                    user_login=None,
                    approver_id=None,
                    approver_role=None,
                    mfa_verified=True,
                )
                triggered = poll_due_scheduled_flows(db, ctx, dry_run=False)
                if triggered:
                    logger.info(
                        "orchestration_scheduler_tick %s",
                        sanitize_fields({"triggered_count": len(triggered)}),
                    )
            interval = orchestration_scheduler_interval_seconds(db)
        except Exception as exc:  # noqa: BLE001 — scheduler must survive tick failures
            db.rollback()
            logger.error(
                "orchestration_scheduler_tick_failed %s",
                sanitize_fields({"error": str(exc)}),
            )
            interval = 60
        finally:
            db.close()
        _scheduler_stop.wait(interval)


def start_orchestration_scheduler() -> None:
    global _scheduler_thread
    if not _env_flag("ORCHESTRATION_SCHEDULER_ENABLED", "true"):
        logger.info("orchestration_scheduler_disabled_by_env")
        return
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _scheduler_stop.clear()
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop,
        name="orchestration-flow-scheduler",
        daemon=True,
    )
    _scheduler_thread.start()


def stop_orchestration_scheduler() -> None:
    _scheduler_stop.set()
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        _scheduler_thread.join(timeout=5)
    _scheduler_thread = None
