from app.main import _should_auto_create_schema_on_startup


def test_startup_schema_auto_create_denied_in_production_even_when_requested(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("STARTUP_AUTO_CREATE_SCHEMA", "true")
    assert _should_auto_create_schema_on_startup() is False


def test_startup_schema_auto_create_allowed_by_default_in_local(monkeypatch):
    monkeypatch.setenv("APP_ENV", "local")
    monkeypatch.delenv("STARTUP_AUTO_CREATE_SCHEMA", raising=False)
    assert _should_auto_create_schema_on_startup() is True
