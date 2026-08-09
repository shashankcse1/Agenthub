"""Background control/data plane drift watcher.

Periodically runs peer probe + policy-generation reconcile and updates the
fail-closed gate used by data-plane inference middleware.
"""

from __future__ import annotations

import os
import threading
from typing import Optional

from app.database import SessionLocal
from app.logging_utils import get_logger, sanitize_fields
from app.plane_mode import resolve_app_plane
from app.services.plane_reconcile import (
    WATCHER_ENABLED_ENV,
    WATCHER_INTERVAL_ENV,
    mark_watcher_status,
    run_reconcile_and_record,
)

logger = get_logger(__name__)

_scheduler_thread: Optional[threading.Thread] = None
_scheduler_stop = threading.Event()


def _poll_interval_seconds() -> int:
    raw = (os.getenv(WATCHER_INTERVAL_ENV) or "30").strip()
    try:
        value = int(raw)
    except ValueError:
        return 30
    return max(10, min(value, 600))


def plane_drift_watcher_enabled() -> bool:
    raw = (os.getenv(WATCHER_ENABLED_ENV) or "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    # Default on for process-isolated planes; off for combined monolith.
    return resolve_app_plane() in {"control", "data"}


def _scheduler_loop() -> None:
    interval = _poll_interval_seconds()
    plane = resolve_app_plane()
    mark_watcher_status(enabled=True)
    logger.info(
        "plane_drift_watcher_started %s",
        sanitize_fields({"poll_interval_seconds": interval, "app_plane": plane}),
    )
    while not _scheduler_stop.is_set():
        db = SessionLocal()
        try:
            snapshot = run_reconcile_and_record(
                db,
                plane=plane,
                probe_peer=True,
                source="watcher",
            )
            mark_watcher_status(enabled=True, tick=True)
            logger.info(
                "plane_drift_watcher_tick %s",
                sanitize_fields(
                    {
                        "drift_status": snapshot.get("drift_status"),
                        "fingerprint": (snapshot.get("policy_generation") or {}).get("fingerprint"),
                        "inference_allowed": (snapshot.get("gate") or {}).get("inference_allowed"),
                    }
                ),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "plane_drift_watcher_tick_failed %s",
                sanitize_fields({"error": str(exc)}),
            )
            try:
                db.rollback()
            except Exception:
                pass
        finally:
            db.close()
        _scheduler_stop.wait(interval)
    mark_watcher_status(enabled=False)


def start_plane_drift_watcher() -> None:
    global _scheduler_thread
    if not plane_drift_watcher_enabled():
        mark_watcher_status(enabled=False)
        logger.info(
            "plane_drift_watcher_disabled %s",
            sanitize_fields({"app_plane": resolve_app_plane()}),
        )
        return
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _scheduler_stop.clear()
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop,
        name="plane-drift-watcher",
        daemon=True,
    )
    _scheduler_thread.start()


def stop_plane_drift_watcher() -> None:
    _scheduler_stop.set()
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        _scheduler_thread.join(timeout=5)
    _scheduler_thread = None
    mark_watcher_status(enabled=False)
