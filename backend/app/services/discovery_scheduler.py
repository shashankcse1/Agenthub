from __future__ import annotations

import os
import threading
import time
from typing import Optional

from app.database import SessionLocal
from app.logging_utils import get_logger, sanitize_fields
from app.services.discovery_live_sync import run_due_discovery_syncs

logger = get_logger(__name__)

_scheduler_thread: Optional[threading.Thread] = None
_scheduler_stop = threading.Event()


def _poll_interval_seconds() -> int:
    raw = (os.getenv("DISCOVERY_SYNC_POLL_INTERVAL_SECONDS") or "60").strip()
    try:
        value = int(raw)
    except ValueError:
        return 60
    return max(15, value)


def discovery_scheduler_enabled() -> bool:
    raw = (os.getenv("DISCOVERY_SYNC_SCHEDULER_ENABLED") or "true").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _scheduler_loop() -> None:
    interval = _poll_interval_seconds()
    logger.info(
        "discovery_scheduler_started %s",
        sanitize_fields({"poll_interval_seconds": interval}),
    )
    while not _scheduler_stop.is_set():
        db = SessionLocal()
        try:
            stats = run_due_discovery_syncs(db, actor_id="discovery-scheduler")
            if stats.get("processed"):
                logger.info("discovery_scheduler_tick %s", sanitize_fields(stats))
        except Exception as exc:
            logger.error(
                "discovery_scheduler_tick_failed %s",
                sanitize_fields({"error": str(exc)}),
            )
            db.rollback()
        finally:
            db.close()
        _scheduler_stop.wait(interval)


def start_discovery_scheduler() -> None:
    global _scheduler_thread
    if not discovery_scheduler_enabled():
        logger.info("discovery_scheduler_disabled")
        return
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _scheduler_stop.clear()
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop,
        name="discovery-sync-scheduler",
        daemon=True,
    )
    _scheduler_thread.start()


def stop_discovery_scheduler() -> None:
    _scheduler_stop.set()
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        _scheduler_thread.join(timeout=5)
    _scheduler_thread = None
