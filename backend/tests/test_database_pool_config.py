from app.database import _bool_env, _int_env


def test_int_env_invalid_returns_default(monkeypatch):
    monkeypatch.setenv("DB_POOL_RECYCLE_SECONDS", "invalid")
    assert _int_env("DB_POOL_RECYCLE_SECONDS", 1800, 60) == 1800


def test_int_env_enforces_minimum(monkeypatch):
    monkeypatch.setenv("DB_POOL_RECYCLE_SECONDS", "10")
    assert _int_env("DB_POOL_RECYCLE_SECONDS", 1800, 60) == 60


def test_bool_env_parses_truthy_and_falsy(monkeypatch):
    monkeypatch.setenv("DB_POOL_PRE_PING", "yes")
    assert _bool_env("DB_POOL_PRE_PING", False) is True

    monkeypatch.setenv("DB_POOL_PRE_PING", "no")
    assert _bool_env("DB_POOL_PRE_PING", True) is False
