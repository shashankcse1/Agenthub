import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _admin_headers(actor_id: str, with_approver: bool = False) -> dict[str, str]:
    headers = {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": actor_id,
    }
    if with_approver:
        headers["X-Approver-Id"] = f"{actor_id}-approver"
        headers["X-Approver-Role"] = "Security Approver"
    return headers


def _upsert_mcp_servers(config_value: str, actor_id: str = "mcp-config-admin") -> None:
    response = client.put(
        "/runtime-config/gateway.mcp.servers_json",
        headers=_admin_headers(actor_id, with_approver=True),
        json={
            "config_value": config_value,
            "description": "test mcp server registry",
        },
    )
    assert response.status_code == 200, response.text


def test_runtime_config_validate_rejects_invalid_mcp_servers_json():
    response = client.post(
        "/runtime-config/validate",
        headers=_admin_headers("mcp-validate-admin"),
        json={
            "config_key": "gateway.mcp.servers_json",
            "config_value": '{"not":"a-list"}',
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"] is False
    assert "JSON array" in payload["error"]


def test_gateway_mcp_servers_and_tools_flow(monkeypatch):
    _upsert_mcp_servers(
        json.dumps(
            [
                {
                    "server_id": "docs-mcp",
                    "base_url": "http://127.0.0.1:9100/mcp",
                    "transport": "streamable_http",
                    "enabled": True,
                    "allowed_tools": ["docs.search"],
                    "auth_token": "secret-token",
                    "headers": {"X-Tenant": "tenant-platform"},
                }
            ]
        ),
        actor_id="mcp-registry-admin",
    )

    servers_resp = client.get(
        "/gateway/mcp/servers",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-mcp-read"},
    )
    assert servers_resp.status_code == 200, servers_resp.text
    servers = servers_resp.json()
    assert len(servers) == 1
    assert servers[0]["server_id"] == "docs-mcp"
    assert "auth_token" not in servers[0]

    class _FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "jsonrpc": "2.0",
                "id": "rpc-1",
                "result": {
                    "tools": [
                        {"name": "docs.search", "description": "Search docs"},
                        {"name": "docs.fetch", "description": "Fetch page"},
                    ]
                },
            }

    def _fake_post(url, json, headers, timeout):
        assert url == "http://127.0.0.1:9100/mcp"
        assert json["method"] == "tools/list"
        assert headers["X-Tenant"] == "tenant-platform"
        return _FakeResponse()

    monkeypatch.setattr("app.services.mcp_gateway.httpx.post", _fake_post)

    tools_resp = client.post(
        "/gateway/mcp/servers/docs-mcp/tools/list",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-mcp-tools"},
        json={"environment": "dev"},
    )
    assert tools_resp.status_code == 200, tools_resp.text
    payload = tools_resp.json()
    assert payload["server_id"] == "docs-mcp"
    assert len(payload["tools"]) == 2


def test_mcp_server_config_persisted_in_runtime_config_db():
    registry_json = json.dumps(
        [
            {
                "server_id": "db-backed-mcp",
                "base_url": "http://127.0.0.1:9200/mcp",
                "transport": "streamable_http",
                "enabled": True,
                "allowed_tools": ["db.read"],
            }
        ]
    )
    _upsert_mcp_servers(registry_json, actor_id="mcp-db-config-admin")

    runtime_configs_resp = client.get(
        "/runtime-config",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "mcp-db-config-admin"},
    )
    assert runtime_configs_resp.status_code == 200, runtime_configs_resp.text
    rows = runtime_configs_resp.json()
    target = next((row for row in rows if row.get("config_key") == "gateway.mcp.servers_json"), None)
    assert target is not None
    assert target["config_value"] == registry_json

    servers_resp = client.get(
        "/gateway/mcp/servers",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-mcp-db-read"},
    )
    assert servers_resp.status_code == 200, servers_resp.text
    servers = servers_resp.json()
    assert any(row.get("server_id") == "db-backed-mcp" for row in servers)


def test_gateway_mcp_call_enforces_prod_approval_and_allowlist(monkeypatch):
    _upsert_mcp_servers(
        json.dumps(
            [
                {
                    "server_id": "ops-mcp",
                    "base_url": "http://127.0.0.1:9101/mcp",
                    "transport": "streamable_http",
                    "enabled": True,
                    "allowed_tools": ["ops.health"],
                }
            ]
        ),
        actor_id="mcp-prod-config-admin",
    )

    no_approval_resp = client.post(
        "/gateway/mcp/servers/ops-mcp/tools/call",
        headers=_admin_headers("mcp-prod-admin", with_approver=False),
        json={
            "environment": "prod",
            "tool_name": "ops.health",
            "arguments": {"service": "gateway"},
        },
    )
    assert no_approval_resp.status_code == 403

    disallowed_tool_resp = client.post(
        "/gateway/mcp/servers/ops-mcp/tools/call",
        headers=_admin_headers("mcp-prod-admin", with_approver=True),
        json={
            "environment": "prod",
            "tool_name": "ops.restart",
            "arguments": {"service": "gateway"},
        },
    )
    assert disallowed_tool_resp.status_code == 403

    class _FakeCallResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "jsonrpc": "2.0",
                "id": "rpc-2",
                "result": {"content": [{"type": "text", "text": "ok"}]},
            }

    def _fake_post(url, json, headers, timeout):
        assert url == "http://127.0.0.1:9101/mcp"
        assert json["method"] == "tools/call"
        assert json["params"]["name"] == "ops.health"
        return _FakeCallResponse()

    monkeypatch.setattr("app.services.mcp_gateway.httpx.post", _fake_post)

    allowed_resp = client.post(
        "/gateway/mcp/servers/ops-mcp/tools/call",
        headers=_admin_headers("mcp-prod-admin", with_approver=True),
        json={
            "environment": "prod",
            "tool_name": "ops.health",
            "arguments": {"service": "gateway"},
        },
    )
    assert allowed_resp.status_code == 200, allowed_resp.text
    payload = allowed_resp.json()
    assert payload["server_id"] == "ops-mcp"
    assert payload["tool_name"] == "ops.health"
    assert payload["result"]["content"][0]["text"] == "ok"
