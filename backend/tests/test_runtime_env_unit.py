"""Unit coverage for runtime_env helpers — target 100% of module."""

from __future__ import annotations

from app.services import runtime_env as re


def test_runtime_environment_precedence(monkeypatch):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("RUNTIME_ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert re.runtime_environment() == "dev"

    monkeypatch.setenv("ENVIRONMENT", "Stage")
    assert re.runtime_environment() == "stage"

    monkeypatch.setenv("RUNTIME_ENVIRONMENT", "Test")
    assert re.runtime_environment() == "test"

    monkeypatch.setenv("APP_ENV", "Production")
    assert re.runtime_environment() == "production"


def test_is_production_runtime(monkeypatch):
    monkeypatch.setenv("APP_ENV", "prod")
    assert re.is_production_runtime() is True
    monkeypatch.setenv("APP_ENV", "production")
    assert re.is_production_runtime() is True
    monkeypatch.setenv("APP_ENV", "dev")
    assert re.is_production_runtime() is False


def test_is_prod_target_environment():
    assert re.is_prod_target_environment("prod") is True
    assert re.is_prod_target_environment("PRODUCTION") is True
    assert re.is_prod_target_environment("dev") is False
    assert re.is_prod_target_environment(None) is False
    assert re.is_prod_target_environment("") is False
