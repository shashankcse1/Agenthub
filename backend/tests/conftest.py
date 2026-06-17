import os
import time
from typing import Optional

import pytest


def response_error_message(response) -> str:
    detail = response.json().get("detail")
    if isinstance(detail, dict):
        return str(detail.get("message", detail))
    return str(detail)


def response_error_code(response) -> Optional[str]:
    detail = response.json().get("detail")
    if isinstance(detail, dict):
        return detail.get("error_code")
    return None


def wait_for_benchmark_run(client, run_id: str, headers: dict, *, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = client.get(f"/benchmarks/runs/{run_id}", headers=headers)
        assert response.status_code == 200, response.text
        payload = response.json()
        if payload.get("status") in {"completed", "cancelled", "failed"}:
            return payload
        time.sleep(0.15)
    raise AssertionError(f"benchmark run {run_id} did not finish within {timeout}s")


def wait_for_scan_run(client, run_id: str, headers: dict, *, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = client.get(f"/scans/runs/{run_id}", headers=headers)
        assert response.status_code == 200, response.text
        payload = response.json()
        if payload.get("status") in {"completed", "cancelled", "failed"}:
            return payload
        time.sleep(0.15)
    raise AssertionError(f"scan run {run_id} did not finish within {timeout}s")


def post_benchmark_run_and_wait(client, payload: dict, headers: dict, *, timeout: float = 30.0) -> dict:
    response = client.post("/benchmarks/run", json=payload, headers=headers)
    assert response.status_code == 200, response.text
    started = response.json()
    assert started.get("status") == "running"
    return wait_for_benchmark_run(client, started["benchmark_run_id"], headers, timeout=timeout)


def post_scan_run_and_wait(client, payload: dict, headers: dict, *, timeout: float = 30.0) -> dict:
    response = client.post("/scans/run", json=payload, headers=headers)
    assert response.status_code == 200, response.text
    started = response.json()
    assert started.get("status") == "running"
    return wait_for_scan_run(client, started["scan_run_id"], headers, timeout=timeout)


@pytest.fixture(autouse=True)
def _gateway_inference_test_isolation(monkeypatch):
    for env_key in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "COHERE_API_KEY",
        "MISTRAL_API_KEY",
        "GROQ_API_KEY",
        "CURSOR_API_KEY",
        "AZURE_OPENAI_API_KEY",
    ):
        monkeypatch.delenv(env_key, raising=False)
    monkeypatch.setenv("GATEWAY_INFERENCE_SIMULATION", "true")


@pytest.fixture(autouse=True)
def _reset_gateway_cache_short_circuit():
    from app.database import SessionLocal
    from app.models import RuntimeConfig
    from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED
    from app.services.runtime_config import invalidate_runtime_config_cache

    db = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(
            config_key=RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED
        ).first()
        if row is None:
            db.add(
                RuntimeConfig(
                    config_key=RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED,
                    config_value="false",
                )
            )
        else:
            row.config_value = "false"
        db.commit()
        invalidate_runtime_config_cache(RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED)
    finally:
        db.close()
    yield
