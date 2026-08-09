import os
from unittest.mock import MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app
from app.services.gateway_passthrough import _sanitize_client_headers

client = TestClient(app)


def _admin_headers():
    return {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": f"assistants-admin-{uuid4().hex[:8]}",
    }


def _dual_approval_headers(actor_id: str, approver_id: str) -> dict:
    return {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": actor_id,
        "X-Approver-Role": "Security Approver",
        "X-Approver-Id": approver_id,
    }


def test_gateway_assistants_thread_run_flow_simulation():
    with patch.dict(os.environ, {"GATEWAY_INFERENCE_SIMULATION": "true"}, clear=False):
        assistant_resp = client.post(
            "/v1/assistants",
            json={
                "name": "Ops Assistant",
                "model": "gpt-4o-mini",
                "instructions": "Answer concisely.",
                "environment": "dev",
            },
            headers=_admin_headers(),
        )
        assert assistant_resp.status_code == 200
        assistant_id = assistant_resp.json()["id"]

        thread_resp = client.post(
            "/v1/threads",
            json={"metadata": {"source": "test"}, "environment": "dev"},
            headers=_admin_headers(),
        )
        assert thread_resp.status_code == 200
        thread_id = thread_resp.json()["id"]

        message_resp = client.post(
            f"/v1/threads/{thread_id}/messages",
            json={"role": "user", "content": "what is capital of russia"},
            headers=_admin_headers(),
        )
        assert message_resp.status_code == 200

        run_resp = client.post(
            f"/v1/threads/{thread_id}/runs",
            json={"assistant_id": assistant_id, "environment": "dev"},
            headers=_admin_headers(),
        )
        assert run_resp.status_code == 200
        run_body = run_resp.json()
        assert run_body["status"] == "completed"
        assert run_body["response_text"]

        list_resp = client.get("/v1/assistants", headers=_admin_headers())
        assert list_resp.status_code == 200
        assert any(row["id"] == assistant_id for row in list_resp.json()["data"])

        get_run_resp = client.get(
            f"/v1/threads/{thread_id}/runs/{run_body['id']}",
            headers=_admin_headers(),
        )
        assert get_run_resp.status_code == 200

        delete_resp = client.delete(f"/v1/assistants/{assistant_id}", headers=_admin_headers())
        assert delete_resp.status_code == 200
        assert delete_resp.json()["deleted"] is True


def test_gateway_assistants_denies_auditor_role():
    response = client.post(
        "/v1/assistants",
        json={"name": "Denied", "model": "gpt-4o-mini", "instructions": "x", "environment": "dev"},
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"assistants-auditor-{uuid4().hex[:8]}"},
    )
    assert response.status_code == 403


def test_gateway_assistants_owner_cannot_access_other_owners_assistant():
    owner_b = client.post(
        "/v1/assistants",
        json={
            "name": "Owner B Assistant",
            "model": "gpt-4o-mini",
            "instructions": "scoped",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-asst-b"},
    )
    assert owner_b.status_code == 200
    assistant_id = owner_b.json()["id"]

    cross_read = client.get(
        f"/v1/assistants/{assistant_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-asst-a"},
    )
    assert cross_read.status_code == 403
    assert cross_read.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_gateway_assistants_prod_delete_requires_dual_approval():
    actor_id = f"admin-asst-del-{uuid4().hex[:8]}"
    created = client.post(
        "/v1/assistants",
        json={
            "name": "Prod Delete Target",
            "model": "gpt-4o-mini",
            "instructions": "prod guard",
            "environment": "prod",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert created.status_code == 200
    assistant_id = created.json()["id"]

    denied = client.delete(
        f"/v1/assistants/{assistant_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed = client.delete(
        f"/v1/assistants/{assistant_id}",
        headers=_dual_approval_headers(actor_id, f"sec-asst-del-{uuid4().hex[:8]}"),
    )
    assert allowed.status_code == 200
    assert allowed.json()["deleted"] is True


def test_gateway_assistants_thread_run_without_user_message_returns_422():
    thread_resp = client.post(
        "/v1/threads",
        json={"metadata": {"source": "empty-run-test"}, "environment": "dev"},
        headers=_admin_headers(),
    )
    assert thread_resp.status_code == 200
    thread_id = thread_resp.json()["id"]

    assistant_resp = client.post(
        "/v1/assistants",
        json={
            "name": "Empty Thread Run",
            "model": "gpt-4o-mini",
            "instructions": "Answer briefly.",
            "environment": "dev",
        },
        headers=_admin_headers(),
    )
    assert assistant_resp.status_code == 200
    assistant_id = assistant_resp.json()["id"]

    run_resp = client.post(
        f"/v1/threads/{thread_id}/runs",
        json={"assistant_id": assistant_id, "environment": "dev"},
        headers=_admin_headers(),
    )
    assert run_resp.status_code == 422


def test_gateway_assistants_list_thread_messages_returns_posted_messages():
    thread_resp = client.post(
        "/v1/threads",
        json={"metadata": {"source": "list-messages-test"}, "environment": "dev"},
        headers=_admin_headers(),
    )
    assert thread_resp.status_code == 200
    thread_id = thread_resp.json()["id"]

    message_content = "list messages parity check"
    post_resp = client.post(
        f"/v1/threads/{thread_id}/messages",
        json={"role": "user", "content": message_content},
        headers=_admin_headers(),
    )
    assert post_resp.status_code == 200
    posted_id = post_resp.json()["id"]

    list_resp = client.get(
        f"/v1/threads/{thread_id}/messages",
        headers=_admin_headers(),
    )
    assert list_resp.status_code == 200
    rows = list_resp.json()["data"]
    assert any(
        row["id"] == posted_id
        and (
            row["content"] == message_content
            or (isinstance(row["content"], list) and any(
                part.get("text") == message_content for part in row["content"] if isinstance(part, dict)
            ))
        )
        for row in rows
    )


def test_gateway_authz_explain_assistant_delete_prod_requires_dual_approval():
    denied = client.post(
        "/gateway/authz/explain",
        json={
            "actor_role": "Platform Admin",
            "actor_id": "admin-authz-asst",
            "action": "gateway.assistants.delete",
            "environment": "prod",
            "resource_type": "gateway_assistant",
            "resource_id": "asst_example",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-authz-asst-{uuid4().hex[:8]}"},
    )
    assert denied.status_code == 200
    body = denied.json()
    assert body["requires_dual_approval"] is True
    assert body["decision"] == "deny"
    assert "dual_approval_missing" in body["reasons"]

    allowed = client.post(
        "/gateway/authz/explain",
        json={
            "actor_role": "Platform Admin",
            "actor_id": "admin-authz-asst",
            "action": "gateway.assistants.delete",
            "environment": "prod",
            "resource_type": "gateway_assistant",
            "resource_id": "asst_example",
            "approver_role": "Security Approver",
            "approver_id": "sec-authz-asst",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-authz-asst-2-{uuid4().hex[:8]}"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["decision"] == "allow"


def test_gateway_assistants_owner_cannot_delete_other_owners_assistant():
    owner_b = client.post(
        "/v1/assistants",
        json={
            "name": "Owner B Delete Target",
            "model": "gpt-4o-mini",
            "instructions": "scoped",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-del-b"},
    )
    assert owner_b.status_code == 200
    assistant_id = owner_b.json()["id"]

    denied = client.delete(
        f"/v1/assistants/{assistant_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-del-a"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_gateway_assistants_response_includes_environment():
    created = client.post(
        "/v1/assistants",
        json={
            "name": "Env Check",
            "model": "gpt-4o-mini",
            "instructions": "x",
            "environment": "prod",
        },
        headers=_admin_headers(),
    )
    assert created.status_code == 200
    assert created.json()["environment"] == "prod"


def test_gateway_assistants_thread_run_stream_simulation():
    with patch.dict(os.environ, {"GATEWAY_INFERENCE_SIMULATION": "true"}, clear=False):
        assistant_resp = client.post(
            "/v1/assistants",
            json={
                "name": "Stream Assistant",
                "model": "gpt-4o-mini",
                "instructions": "Answer concisely.",
                "environment": "dev",
            },
            headers=_admin_headers(),
        )
        assert assistant_resp.status_code == 200
        assistant_id = assistant_resp.json()["id"]

        thread_resp = client.post(
            "/v1/threads",
            json={"metadata": {"source": "stream-test"}, "environment": "dev"},
            headers=_admin_headers(),
        )
        assert thread_resp.status_code == 200
        thread_id = thread_resp.json()["id"]

        message_resp = client.post(
            f"/v1/threads/{thread_id}/messages",
            json={"role": "user", "content": "stream this reply"},
            headers=_admin_headers(),
        )
        assert message_resp.status_code == 200

        run_resp = client.post(
            f"/v1/threads/{thread_id}/runs",
            json={"assistant_id": assistant_id, "environment": "dev", "stream": True},
            headers=_admin_headers(),
        )
        assert run_resp.status_code == 200
        assert run_resp.headers.get("content-type", "").startswith("text/event-stream")
        body = run_resp.text
        assert "thread.run" in body
        assert "data: [DONE]" in body


def test_gateway_assistants_thread_retrieve_endpoint():
    thread_resp = client.post(
        "/v1/threads",
        json={"metadata": {"source": "retrieve-test"}, "environment": "dev"},
        headers=_admin_headers(),
    )
    assert thread_resp.status_code == 200
    thread_id = thread_resp.json()["id"]

    retrieve_resp = client.get(f"/v1/threads/{thread_id}", headers=_admin_headers())
    assert retrieve_resp.status_code == 200
    assert retrieve_resp.json()["id"] == thread_id
