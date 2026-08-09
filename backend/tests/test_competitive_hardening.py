"""Regression coverage for n8n/Helicone/Portkey competitive hardening slices."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.services import gateway_notification_delivery as notify
from app.services import provider_crypto
from app.services.orchestration_executor import _execute_live_node


def test_notification_channel_rate_limit_raises_429():
    db = MagicMock()
    channel_id = "channel-rate-limit-test"
    notify._RATE_WINDOWS.pop(channel_id, None)

    with patch.object(notify, "get_runtime_config_int", return_value=2):
        notify._enforce_channel_rate_limit(db, channel_id)
        notify._enforce_channel_rate_limit(db, channel_id)
        with pytest.raises(HTTPException) as exc:
            notify._enforce_channel_rate_limit(db, channel_id)
    assert exc.value.status_code == 429
    assert "sends/minute" in str(exc.value.detail)
    notify._RATE_WINDOWS.pop(channel_id, None)


def test_live_executor_control_and_trigger_nodes_are_live():
    db = MagicMock()
    ctx = SimpleNamespace(actor_id="actor-competitive")

    for node_type, config in (
        ("parallel_fork", {"group_id": "g1", "branch_count": 2}),
        ("parallel_join", {"group_id": "g1", "fork_node_id": "fork-1"}),
        ("schedule_trigger", {"cron_expression": "0 * * * *"}),
        ("webhook_trigger", {"webhook_path_ref": "support-triage"}),
    ):
        result = _execute_live_node(
            db,
            ctx,
            {"id": f"node-{node_type}", "type": node_type, "config": config},
            environment="dev",
            trace_id="trace-competitive",
            step_outputs={},
            run_input="hello",
            flow_id="flow-competitive",
            run_id="run-competitive",
        )
        assert result["status"] == "completed"
        assert result["output"]["live"] is True
        assert result["output"]["simulated"] is False


def test_live_executor_unknown_node_fails_closed():
    db = MagicMock()
    ctx = SimpleNamespace(actor_id="actor-competitive")
    result = _execute_live_node(
        db,
        ctx,
        {"id": "node-unknown", "type": "legacy_mystery_node", "config": {}},
        environment="dev",
        trace_id="trace-competitive",
        step_outputs={},
        run_input="hello",
        flow_id="flow-competitive",
        run_id="run-competitive",
    )
    assert result["status"] == "failed"
    assert "does not support" in str(result["output"].get("error") or "")


def test_provider_crypto_fail_closed_outside_local(monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("PROVIDER_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode("utf-8"))
    monkeypatch.setattr(provider_crypto, "_runtime_environment", lambda: "staging")
    with pytest.raises(RuntimeError, match="Encrypted provider secret required"):
        provider_crypto.decrypt_value("plaintext-not-fernet")


def test_provider_crypto_fail_open_in_test(monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("PROVIDER_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode("utf-8"))
    monkeypatch.setattr(provider_crypto, "_runtime_environment", lambda: "test")
    assert provider_crypto.decrypt_value("plaintext-not-fernet") == "plaintext-not-fernet"


def test_legacy_cursor_token_retired_outside_local(monkeypatch):
    from app.routers import gateway as gateway_router

    monkeypatch.setenv("APP_ENV", "staging")
    assert gateway_router._requires_gateway_secret_dual_approval() is True
    monkeypatch.setenv("APP_ENV", "local")
    assert gateway_router._requires_gateway_secret_dual_approval() is False


def test_live_github_api_operation_preset_uses_httpx():
    """Wave 1 connector depth: named operation + live httpx path (mocked)."""
    from app.services.orchestration_flows import resolve_connector_operation_preset

    method, path = resolve_connector_operation_preset(
        "github_api",
        {"operation": "list_issues"},
        owner="acme",
        repo="gateway",
    )
    assert method == "GET"
    assert path == "/repos/acme/gateway/issues"

    db = MagicMock()
    ctx = SimpleNamespace(actor_id="actor-github-live")

    class _Resp:
        status_code = 200
        text = '{"ok":true,"items":[]}'

        def json(self):
            return {"ok": True, "items": []}

    with (
        patch("app.services.orchestration_executor._validate_http_url", return_value=None),
        patch("app.services.orchestration_executor.apply_http_auth_headers", return_value={"Authorization": "Bearer t"}),
        patch("app.services.orchestration_executor.httpx.request", return_value=_Resp()) as request_mock,
    ):
        result = _execute_live_node(
            db,
            ctx,
            {
                "id": "gh-1",
                "type": "github_api",
                "config": {
                    "operation": "get_user",
                    "auth_binding_id": "binding-gh",
                    "auth_type": "bearer",
                },
            },
            environment="dev",
            trace_id="trace-gh-live",
            step_outputs={},
            run_input="",
            flow_id="flow-gh",
            run_id="run-gh",
        )
    assert result["status"] == "completed"
    assert result["output"]["live"] is True
    assert result["output"]["simulated"] is False
    assert result["output"]["provider"] == "github"
    request_mock.assert_called_once()
    called_url = request_mock.call_args.kwargs.get("url")
    if called_url is None and request_mock.call_args.args:
        # httpx.request(method=..., url=...) or positional
        called_url = request_mock.call_args.kwargs.get("url") or (
            request_mock.call_args.args[1] if len(request_mock.call_args.args) > 1 else ""
        )
    assert "api.github.com/user" in str(called_url)


def test_files_create_rejects_multipart_file_object():
    from app.schemas import GatewayOpenAIFileCreateRequest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        GatewayOpenAIFileCreateRequest(
            filename="notes.txt",
            purpose="assistants",
            bytes=12,
            file={"raw": True},
        )


def test_files_create_rejects_content_when_store_disabled():
    from app.routers import gateway as gateway_router
    from app.schemas import GatewayOpenAIFileCreateRequest

    db = MagicMock()
    ctx = SimpleNamespace(actor_id="actor-files", actor_role="Platform Admin")
    payload = GatewayOpenAIFileCreateRequest(
        filename="notes.txt",
        purpose="assistants",
        bytes=5,
        content="hello",
        environment="dev",
    )
    with (
        patch.object(gateway_router, "require_role"),
        patch.object(gateway_router, "_files_content_store_enabled", return_value=False),
    ):
        with pytest.raises(HTTPException) as exc:
            gateway_router.gateway_openai_files_create(payload=payload, db=db, ctx=ctx)
    assert exc.value.status_code == 422
    assert "content_store_enabled" in str(exc.value.detail)


def test_files_create_stores_encrypted_content_when_enabled():
    from app.routers import gateway as gateway_router
    from app.schemas import GatewayOpenAIFileCreateRequest

    db = MagicMock()
    ctx = SimpleNamespace(actor_id="actor-files", actor_role="Platform Admin")
    payload = GatewayOpenAIFileCreateRequest(
        filename="notes.txt",
        purpose="assistants",
        bytes=5,
        content="hello",
        environment="dev",
    )
    with (
        patch.object(gateway_router, "require_role"),
        patch.object(gateway_router, "_files_content_store_enabled", return_value=True),
        patch.object(gateway_router, "_files_content_max_bytes", return_value=262144),
        patch.object(gateway_router, "create_audit_event"),
        patch("app.services.provider_crypto.encrypt_value", side_effect=lambda v: f"enc:{v}"),
    ):
        result = gateway_router.gateway_openai_files_create(payload=payload, db=db, ctx=ctx)
    assert result["content_stored"] is True
    assert db.add.called
    record = db.add.call_args[0][0]
    assert str(record.content_encrypted).startswith("enc:")
    assert record.content_sha256


def test_live_slack_and_stripe_operation_presets_use_httpx():
    from app.services.orchestration_flows import resolve_connector_operation_preset

    slack_method, slack_path = resolve_connector_operation_preset(
        "slack_api", {"operation": "chat_post_message"}
    )
    assert slack_method == "POST"
    assert slack_path == "/chat.postMessage"
    stripe_method, stripe_path = resolve_connector_operation_preset(
        "stripe_api", {"operation": "list_charges"}
    )
    assert stripe_method == "GET"
    assert stripe_path == "/v1/charges"

    db = MagicMock()
    ctx = SimpleNamespace(actor_id="actor-connectors")

    class _Resp:
        status_code = 200
        text = '{"ok":true}'

        def json(self):
            return {"ok": True}

    for node_type, operation, provider in (
        ("slack_api", "auth_test", "slack"),
        ("stripe_api", "get_balance", "stripe"),
    ):
        with (
            patch("app.services.orchestration_executor._validate_http_url", return_value=None),
            patch(
                "app.services.orchestration_executor.apply_http_auth_headers",
                return_value={"Authorization": "Bearer t"},
            ),
            patch("app.services.orchestration_executor.httpx.request", return_value=_Resp()) as request_mock,
        ):
            result = _execute_live_node(
                db,
                ctx,
                {
                    "id": f"{node_type}-1",
                    "type": node_type,
                    "config": {"operation": operation, "auth_binding_id": "b1", "auth_type": "bearer"},
                },
                environment="dev",
                trace_id="trace-conn",
                step_outputs={},
                run_input="",
                flow_id="flow-conn",
                run_id="run-conn",
            )
        assert result["status"] == "completed"
        assert result["output"]["live"] is True
        assert result["output"]["provider"] == provider
        request_mock.assert_called_once()


def test_live_readiness_helpers_seed_hosts():
    from app.services.orchestration_flows import (
        LEADERSHIP_CONNECTOR_HOSTS,
        leadership_connector_host_coverage,
        merge_http_allowed_hosts,
    )

    db = MagicMock()
    with (
        patch("app.services.orchestration_flows._load_http_allowlist", return_value=[]),
        patch("app.services.runtime_config.upsert_runtime_config_value") as upsert_rc,
    ):
        merged = merge_http_allowed_hosts(db, ["api.github.com", "slack.com"])
        assert "api.github.com" in merged
        assert "slack.com" in merged
        assert upsert_rc.called

    with patch(
        "app.services.orchestration_flows._load_http_allowlist",
        return_value=list(LEADERSHIP_CONNECTOR_HOSTS),
    ):
        coverage = leadership_connector_host_coverage(db)
    assert coverage["ready"] is True
    assert coverage["missing_hosts"] == []


def test_live_readiness_snapshot_recommendations():
    from app.services.orchestration_flows import live_readiness_snapshot

    db = MagicMock()
    with (
        patch(
            "app.services.orchestration_flows.leadership_connector_host_coverage",
            return_value={
                "required_hosts": ["api.github.com"],
                "allowed_hosts": [],
                "missing_hosts": ["api.github.com"],
                "ready": False,
            },
        ),
        patch(
            "app.services.orchestration_executor.live_executor_policy_snapshot",
            return_value={
                "live_executor_enabled": "false",
                "live_executor_prod_enabled": "false",
                "live_executor_max_wait_seconds": "30",
            },
        ),
    ):
        snap = live_readiness_snapshot(db)
    assert snap["non_prod_live_ready"] is False
    assert snap["recommendations"]


def test_tick_due_key_rotation_schedules_rotates_due_dev():
    from datetime import datetime, timedelta

    from app.routers import gateway as gateway_router

    now = datetime.utcnow()
    due_at = (now - timedelta(hours=1)).isoformat() + "Z"
    key = SimpleNamespace(key_id="vk-tick-1", key_hash="old-hash")
    schedule = {
        "schedule_id": "sch-due",
        "environment": "dev",
        "interval_hours": 24,
        "enabled": True,
        "next_run_at": due_at,
    }
    db = MagicMock()
    db.query.return_value.all.return_value = [key]
    ctx = SimpleNamespace(actor_id="actor-tick", actor_role="Platform Admin")

    with (
        patch.object(gateway_router, "require_role"),
        patch.object(gateway_router, "_load_key_policy_state", return_value={"rotation_schedules": [schedule]}),
        patch.object(gateway_router, "_get_rotation_schedules", return_value=[schedule]),
        patch.object(gateway_router, "_save_key_policy_state"),
        patch.object(gateway_router, "create_audit_event"),
    ):
        result = gateway_router.tick_due_key_rotation_schedules(include_prod=False, db=db, ctx=ctx)

    assert result["scanned_keys"] == 1
    assert result["due_schedules"] == 1
    assert len(result["executed"]) == 1
    assert result["executed"][0]["schedule_id"] == "sch-due"
    assert key.key_hash != "old-hash"
    db.commit.assert_called_once()
