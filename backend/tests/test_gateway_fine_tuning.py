from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _admin_headers():
    return {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": f"fine-tuning-admin-{uuid4().hex[:8]}",
    }


def _dual_approval_headers(actor_id: str, approver_id: str) -> dict:
    return {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": actor_id,
        "X-Approver-Role": "Security Approver",
        "X-Approver-Id": approver_id,
    }


def test_gateway_fine_tuning_job_simulated_completion():
    file_resp = client.post(
        "/v1/files",
        json={
            "filename": "training.jsonl",
            "purpose": "fine-tune",
            "bytes": 128,
            "environment": "dev",
        },
        headers=_admin_headers(),
    )
    assert file_resp.status_code == 200
    training_file_id = file_resp.json()["id"]

    create_resp = client.post(
        "/v1/fine_tuning/jobs",
        json={
            "model": "gpt-4o-mini",
            "training_file_id": training_file_id,
            "environment": "dev",
        },
        headers=_admin_headers(),
    )
    assert create_resp.status_code == 200
    body = create_resp.json()
    assert body["status"] == "succeeded"
    assert body["fine_tuned_model"]
    assert body["live_mode"] is False

    job_id = body["id"]
    get_resp = client.get(f"/v1/fine_tuning/jobs/{job_id}", headers=_admin_headers())
    assert get_resp.status_code == 200
    assert get_resp.json()["status"] == "succeeded"

    list_resp = client.get("/v1/fine_tuning/jobs", headers=_admin_headers())
    assert list_resp.status_code == 200
    assert any(row["id"] == job_id for row in list_resp.json()["data"])


def test_gateway_fine_tuning_cancel_queued_job():
    file_resp = client.post(
        "/v1/files",
        json={
            "filename": "cancel-training.jsonl",
            "purpose": "fine-tune",
            "bytes": 64,
            "environment": "dev",
        },
        headers=_admin_headers(),
    )
    training_file_id = file_resp.json()["id"]

    with patch("app.services.gateway_fine_tuning._live_enabled", return_value=True):
        with patch("app.services.gateway_fine_tuning._submit_upstream_job"):
            create_resp = client.post(
                "/v1/fine_tuning/jobs",
                json={
                    "model": "gpt-4o-mini",
                    "training_file_id": training_file_id,
                    "environment": "dev",
                },
                headers=_admin_headers(),
            )
            assert create_resp.status_code == 200
            job_id = create_resp.json()["id"]
            assert create_resp.json()["status"] == "queued"
            assert create_resp.json()["live_mode"] is True

        cancel_resp = client.post(
            f"/v1/fine_tuning/jobs/{job_id}/cancel",
            headers=_admin_headers(),
        )
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["status"] == "cancelled"
        assert cancel_resp.json()["live_mode"] is True


def test_gateway_fine_tuning_live_upstream_submission():
    file_resp = client.post(
        "/v1/files",
        json={
            "filename": "live-upstream-training.jsonl",
            "purpose": "fine-tune",
            "bytes": 64,
            "environment": "dev",
        },
        headers=_admin_headers(),
    )
    assert file_resp.status_code == 200
    training_file_id = file_resp.json()["id"]

    credential = type(
        "Credential",
        (),
        {
            "provider_type": "openai",
            "api_key": "sk-test",
            "base_url": "https://api.openai.com/v1",
            "upstream_model": "gpt-4o-mini",
            "credential_source": "test",
        },
    )()

    file_upload_response = type("Resp", (), {"status_code": 200, "json": lambda self: {"id": "file-upstream-1"}})()
    job_create_response = type(
        "Resp",
        (),
        {
            "status_code": 200,
            "json": lambda self: {"id": "ft-upstream-1", "status": "queued", "fine_tuned_model": None},
        },
    )()

    with patch("app.services.gateway_fine_tuning._live_enabled", return_value=True):
        with patch(
            "app.services.gateway_fine_tuning.resolve_fine_tuning_credential",
            return_value=credential,
        ):
            with patch(
                "app.services.gateway_fine_tuning_upstream.httpx.post",
                side_effect=[file_upload_response, job_create_response],
            ):
                create_resp = client.post(
                    "/v1/fine_tuning/jobs",
                    json={
                        "model": "gpt-4o-mini",
                        "training_file_id": training_file_id,
                        "environment": "dev",
                    },
                    headers=_admin_headers(),
                )
    assert create_resp.status_code == 200
    body = create_resp.json()
    assert body["live_mode"] is True
    assert body["status"] == "queued"
    assert body["upstream_job_id"] == "ft-upstream-1"


def test_gateway_fine_tuning_prod_cancel_requires_dual_approval():
    actor_id = f"admin-ft-cancel-{uuid4().hex[:8]}"
    file_resp = client.post(
        "/v1/files",
        json={
            "filename": "prod-cancel-training.jsonl",
            "purpose": "fine-tune",
            "bytes": 64,
            "environment": "prod",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert file_resp.status_code == 200
    training_file_id = file_resp.json()["id"]

    with patch("app.services.gateway_fine_tuning._live_enabled", return_value=True):
        with patch("app.services.gateway_fine_tuning._submit_upstream_job"):
            create_resp = client.post(
                "/v1/fine_tuning/jobs",
                json={
                    "model": "gpt-4o-mini",
                    "training_file_id": training_file_id,
                    "environment": "prod",
                },
                headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
            )
            assert create_resp.status_code == 200
            job_id = create_resp.json()["id"]

        denied = client.post(
            f"/v1/fine_tuning/jobs/{job_id}/cancel",
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
        )
        assert denied.status_code == 403
        assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

        allowed = client.post(
            f"/v1/fine_tuning/jobs/{job_id}/cancel",
            headers=_dual_approval_headers(actor_id, f"sec-ft-cancel-{uuid4().hex[:8]}"),
        )
        assert allowed.status_code == 200
        assert allowed.json()["status"] == "cancelled"


def test_gateway_fine_tuning_owner_cannot_read_other_owners_job():
    owner_b = client.post(
        "/v1/files",
        json={
            "filename": "owner-scope-training.jsonl",
            "purpose": "fine-tune",
            "bytes": 64,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-ft-b"},
    )
    assert owner_b.status_code == 200
    training_file_id = owner_b.json()["id"]

    create_resp = client.post(
        "/v1/fine_tuning/jobs",
        json={
            "model": "gpt-4o-mini",
            "training_file_id": training_file_id,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-ft-b"},
    )
    assert create_resp.status_code == 200
    job_id = create_resp.json()["id"]

    cross_read = client.get(
        f"/v1/fine_tuning/jobs/{job_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-ft-a"},
    )
    assert cross_read.status_code == 403
    assert cross_read.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_gateway_fine_tuning_cancel_terminal_job_returns_409():
    file_resp = client.post(
        "/v1/files",
        json={"filename": "terminal-cancel.jsonl", "purpose": "fine-tune", "bytes": 64, "environment": "dev"},
        headers=_admin_headers(),
    )
    training_file_id = file_resp.json()["id"]
    create_resp = client.post(
        "/v1/fine_tuning/jobs",
        json={"model": "gpt-4o-mini", "training_file_id": training_file_id, "environment": "dev"},
        headers=_admin_headers(),
    )
    assert create_resp.status_code == 200
    job_id = create_resp.json()["id"]
    assert create_resp.json()["status"] == "succeeded"

    cancel_resp = client.post(f"/v1/fine_tuning/jobs/{job_id}/cancel", headers=_admin_headers())
    assert cancel_resp.status_code == 409


def test_gateway_fine_tuning_response_includes_environment():
    file_resp = client.post(
        "/v1/files",
        json={"filename": "env-check.jsonl", "purpose": "fine-tune", "bytes": 64, "environment": "prod"},
        headers=_admin_headers(),
    )
    training_file_id = file_resp.json()["id"]
    create_resp = client.post(
        "/v1/fine_tuning/jobs",
        json={"model": "gpt-4o-mini", "training_file_id": training_file_id, "environment": "prod"},
        headers=_admin_headers(),
    )
    assert create_resp.status_code == 200
    assert create_resp.json()["environment"] == "prod"


def test_gateway_authz_explain_fine_tuning_cancel_prod_requires_dual_approval():
    denied = client.post(
        "/gateway/authz/explain",
        json={
            "actor_role": "Platform Admin",
            "actor_id": "admin-ft-explain",
            "action": "gateway.fine_tuning.cancel",
            "environment": "prod",
            "resource_type": "gateway_fine_tuning_job",
            "resource_id": "ftjob_example",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-ft-explain-{uuid4().hex[:8]}"},
    )
    assert denied.status_code == 200
    assert denied.json()["requires_dual_approval"] is True
    assert denied.json()["decision"] == "deny"
