import os
from getpass import getuser

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.db_constants import (
    DB_POOL_MAX_OVERFLOW_DEFAULT_ENV,
    DB_POOL_MAX_OVERFLOW_ENV,
    DB_POOL_MAX_OVERFLOW_MIN_ENV,
    DB_POOL_PRE_PING_DEFAULT_ENV,
    DB_POOL_PRE_PING_ENV,
    DB_POOL_RECYCLE_SECONDS_DEFAULT_ENV,
    DB_POOL_RECYCLE_SECONDS_ENV,
    DB_POOL_RECYCLE_SECONDS_MIN_ENV,
    DB_POOL_SIZE_DEFAULT_ENV,
    DB_POOL_SIZE_ENV,
    DB_POOL_SIZE_MIN_ENV,
    DB_POOL_TIMEOUT_SECONDS_DEFAULT_ENV,
    DB_POOL_TIMEOUT_SECONDS_ENV,
    DB_POOL_TIMEOUT_SECONDS_MIN_ENV,
)
from app.logging_utils import get_logger

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"postgresql+psycopg://{getuser()}@localhost:5432/agenthub",
)


def _int_env(name: str, default: int, min_value: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(min_value, value)


def _bool_env(name: str, default: bool) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=_bool_env(
        DB_POOL_PRE_PING_ENV,
        _bool_env(DB_POOL_PRE_PING_DEFAULT_ENV, True),
    ),
    pool_recycle=_int_env(
        DB_POOL_RECYCLE_SECONDS_ENV,
        _int_env(DB_POOL_RECYCLE_SECONDS_DEFAULT_ENV, 1800, 1),
        _int_env(DB_POOL_RECYCLE_SECONDS_MIN_ENV, 60, 1),
    ),
    pool_size=_int_env(
        DB_POOL_SIZE_ENV,
        _int_env(DB_POOL_SIZE_DEFAULT_ENV, 10, 1),
        _int_env(DB_POOL_SIZE_MIN_ENV, 1, 0),
    ),
    max_overflow=_int_env(
        DB_POOL_MAX_OVERFLOW_ENV,
        _int_env(DB_POOL_MAX_OVERFLOW_DEFAULT_ENV, 20, 0),
        _int_env(DB_POOL_MAX_OVERFLOW_MIN_ENV, 0, 0),
    ),
    pool_timeout=_int_env(
        DB_POOL_TIMEOUT_SECONDS_ENV,
        _int_env(DB_POOL_TIMEOUT_SECONDS_DEFAULT_ENV, 30, 1),
        _int_env(DB_POOL_TIMEOUT_SECONDS_MIN_ENV, 1, 1),
    ),
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
logger = get_logger(__name__)


class Base(DeclarativeBase):
    pass


def get_db():
    logger.trace("db_session_open")
    db = SessionLocal()
    try:
        yield db
    except Exception:
        try:
            db.rollback()
            logger.trace("db_session_rollback")
        except Exception:
            logger.error("db_session_rollback_failed")
        raise
    finally:
        try:
            db.close()
            logger.trace("db_session_close")
        except Exception:
            logger.error("db_session_close_failed")
            raise
