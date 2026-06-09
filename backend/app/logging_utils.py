from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

TRACE_LEVEL_NUM = 5
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")

_ORIGINAL_LOG_RECORD_FACTORY = logging.getLogRecordFactory()


def _description_log_record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
    record = _ORIGINAL_LOG_RECORD_FACTORY(*args, **kwargs)
    msg_text = str(record.msg or "")
    if "description" in msg_text.lower():
        return record

    record_args = record.args
    if isinstance(record_args, dict):
        if "description" in {str(k).lower() for k in record_args.keys()}:
            return record
    elif isinstance(record_args, tuple):
        for item in record_args:
            if isinstance(item, dict) and "description" in {str(k).lower() for k in item.keys()}:
                return record

    record.msg = f"{msg_text} | description=auto"
    return record


def _trace(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kwargs)


if not hasattr(logging.Logger, "trace"):
    logging.Logger.trace = _trace  # type: ignore[attr-defined]


SENSITIVE_KEYWORDS = {
    "authorization",
    "token",
    "access_token",
    "secret",
    "password",
    "api_key",
    "approval_token",
    "session_id",
}

SENSITIVE_EXACT_KEYS = {
    "redis_url",
    "database_url",
    "token_url",
    "uri",
    "dsn",
}

PII_KEYS = {
    "actor_id",
    "approver_id",
    "resource_id",
    "email",
    "phone",
    "ssn",
    "subject",
    "secret_ref",
}


def _stable_fingerprint(value: Any) -> str:
    raw = str(value)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"fp:{digest}"


def sanitize_for_log(key: str, value: Any) -> Any:
    lowered = key.lower()
    if lowered in SENSITIVE_EXACT_KEYS:
        return "[REDACTED]"
    if any(keyword in lowered for keyword in SENSITIVE_KEYWORDS):
        return "[REDACTED]"
    if lowered in PII_KEYS:
        return _stable_fingerprint(value)
    return value


def sanitize_fields(fields: dict[str, Any]) -> dict[str, Any]:
    sanitized = {k: sanitize_for_log(k, v) for k, v in fields.items()}
    if "description" not in {str(k).lower() for k in sanitized.keys()}:
        sanitized["description"] = "auto"
    return sanitized


def configure_logging() -> None:
    configured_level = (os.getenv("LOG_LEVEL") or "INFO").strip().upper()
    if configured_level == "TRACE":
        level = TRACE_LEVEL_NUM
    else:
        level = getattr(logging, configured_level, logging.INFO)

    root_logger = logging.getLogger()
    if not root_logger.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
    else:
        root_logger.setLevel(level)

    if logging.getLogRecordFactory() is not _description_log_record_factory:
        logging.setLogRecordFactory(_description_log_record_factory)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
