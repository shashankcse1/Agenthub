import json
from typing import Optional
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.main import app
from app.models import AuditEvent, OrchestrationFlowDefinition, RuntimeConfig
from app.services.runtime_config import invalidate_runtime_config_cache
from tests.conftest import response_error_code

client = TestClient(app)

ADMIN_HEADERS = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "orch-admin-test"}
RELEASE_HEADERS = {"X-Actor-Role": "Release Manager", "X-Actor-Id": "orch-release-test"}
SECURITY_HEADERS = {"X-Actor-Role": "Security Approver", "X-Actor-Id": "orch-security-test"}
OPS_HEADERS = {"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "orch-ops-test"}
AUDITOR_HEADERS = {"X-Actor-Role": "Auditor", "X-Actor-Id": "orch-auditor-test"}


def _sample_graph(*, include_http: bool = False) -> str:
    nodes = [
        {
            "id": "node-1",
            "type": "llm_chat",
            "config": {
                "model_id": "gpt-4o-mini",
                "prompt_template": "Summarize {{input}}",
                "binding_id": "binding-test-001",
            },
            "position": {"x": 0, "y": 0},
        },
        {
            "id": "node-2",
            "type": "human_approval",
            "config": {"approval_title": "Review output"},
            "position": {"x": 0, "y": 120},
        },
    ]
    if include_http:
        nodes.append(
            {
                "id": "node-3",
                "type": "http_request",
                "config": {"url": "https://api.example.com/hook", "method": "POST"},
                "position": {"x": 0, "y": 240},
            }
        )
    graph = {
        "nodes": nodes,
        "edges": [{"source": "node-1", "target": "node-2"}],
    }
    return json.dumps(graph)


def _create_flow(*, environment: str = "dev", graph_json: Optional[str] = None, headers: Optional[dict] = None) -> dict:
    payload = {
        "flow_name": f"test-flow-{uuid4().hex[:8]}",
        "description": "Orchestration test flow",
        "environment": environment,
        "trigger_type": "manual",
        "trigger_config_json": "{}",
        "graph_json": graph_json or _sample_graph(),
    }
    response = client.post("/orchestration/flows", json=payload, headers=headers or RELEASE_HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


def test_orchestration_node_types_catalog():
    response = client.get("/orchestration/node-types", headers=AUDITOR_HEADERS)
    assert response.status_code == 200
    payload = response.json()
    types = {item["type"] for item in payload["node_types"]}
    assert "llm_chat" in types
    assert "human_approval" in types
    assert "http_request" in types
    assert "vector_query" in types
    assert "vector_ingest" in types
    assert payload["policy"]["max_nodes_per_flow"] >= 1


def test_orchestration_flow_crud_and_audit():
    created = _create_flow()
    flow_id = created["flow_id"]
    assert created["approval_status"] == "pending"

    fetched = client.get(f"/orchestration/flows/{flow_id}", headers=ADMIN_HEADERS)
    assert fetched.status_code == 200
    assert fetched.json()["flow_name"] == created["flow_name"]

    updated = client.put(
        f"/orchestration/flows/{flow_id}",
        json={"description": "Updated description"},
        headers=RELEASE_HEADERS,
    )
    assert updated.status_code == 200
    assert updated.json()["description"] == "Updated description"
    assert updated.json()["metadata_version"] >= 2

    listed = client.get("/orchestration/flows", headers=AUDITOR_HEADERS)
    assert listed.status_code == 200
    assert listed.json()["total"] >= 1

    deleted = client.delete(f"/orchestration/flows/{flow_id}", headers=RELEASE_HEADERS)
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deprecated"

    db: Session = SessionLocal()
    try:
        audit = (
            db.query(AuditEvent)
            .filter_by(action_type="orchestration.flow.create", resource_id=flow_id)
            .first()
        )
        assert audit is not None
        assert audit.decision_outcome == "allow"
    finally:
        db.close()


def test_orchestration_validate_rejects_bad_graph():
    bad_graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "bad-1",
                    "type": "llm_chat",
                    "config": {"api_key": "sk-test-secret", "model_id": "gpt-4o-mini"},
                }
            ],
            "edges": [],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "bad-flow",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": bad_graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "VALIDATION_ERROR"

    flow = _create_flow()
    validate = client.post(f"/orchestration/flows/{flow['flow_id']}/validate", headers=ADMIN_HEADERS)
    assert validate.status_code == 200
    assert validate.json()["valid"] is True


def test_orchestration_prod_run_blocked_without_approval():
    flow = _create_flow(environment="prod")
    flow_id = flow["flow_id"]
    assert flow["approval_status"] == "pending"

    denied = client.post(
        f"/orchestration/flows/{flow_id}/run",
        json={"dry_run": False},
        headers=ADMIN_HEADERS,
    )
    assert denied.status_code == 403
    assert response_error_code(denied) == "VALIDATION_ERROR"

    db: Session = SessionLocal()
    try:
        audit = (
            db.query(AuditEvent)
            .filter_by(action_type="orchestration.flow.run", resource_id=flow_id, decision_outcome="deny")
            .first()
        )
        assert audit is not None
    finally:
        db.close()


def test_orchestration_prod_run_allowed_after_approval():
    flow = _create_flow(environment="prod")
    flow_id = flow["flow_id"]

    approve = client.post(
        f"/orchestration/flows/{flow_id}/approve",
        json={"decision": "approved", "approval_ticket_ref": "TICKET-ORCH-001"},
        headers={
            **SECURITY_HEADERS,
            "X-Approver-Role": "Platform Admin",
            "X-Approver-Id": "platform-approver-orch",
        },
    )
    assert approve.status_code == 200
    assert approve.json()["approval_status"] == "approved"

    run = client.post(
        f"/orchestration/flows/{flow_id}/run",
        json={"dry_run": True},
        headers=ADMIN_HEADERS,
    )
    assert run.status_code == 200
    body = run.json()
    assert body["status"] == "dry_run_completed"
    assert body["trace_id"].startswith("orch-run-")

    runs = client.get(f"/orchestration/flows/{flow_id}/runs", headers=AUDITOR_HEADERS)
    assert runs.status_code == 200
    assert runs.json()["total"] >= 1


def test_orchestration_dry_run_dev_flow():
    flow = _create_flow(environment="dev")
    flow_id = flow["flow_id"]
    run = client.post(
        f"/orchestration/flows/{flow_id}/run",
        json={"dry_run": True},
        headers=ADMIN_HEADERS,
    )
    assert run.status_code == 200
    run_id = run.json()["run_id"]

    detail = client.get(f"/orchestration/flows/{flow_id}/runs/{run_id}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    steps = json.loads(detail.json()["step_results_json"])
    assert len(steps) >= 2


def test_orchestration_condition_json_path_config_validates():
    db: Session = SessionLocal()
    try:
        db.merge(
            RuntimeConfig(
                config_key="orchestration.http_allowed_hosts_json",
                config_value='["api.example.com"]',
                updated_by="orch-test",
            )
        )
        db.commit()
    finally:
        db.close()

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "node-1",
                    "type": "http_request",
                    "config": {"url": "https://api.example.com/data", "method": "GET"},
                },
                {
                    "id": "node-2",
                    "type": "condition",
                    "config": {
                        "source_node_id": "node-1",
                        "json_path": "$.status",
                        "operator": "==",
                        "compare_value": "ok",
                        "expression": "jsonPath(steps['node-1'].output, '$.status') == 'ok'",
                        "true_branch": "node-3",
                        "false_branch": "node-4",
                    },
                },
            ],
            "edges": [{"source": "node-1", "target": "node-2"}],
        }
    )
    created = _create_flow(graph_json=graph)
    validate = client.post(f"/orchestration/flows/{created['flow_id']}/validate", headers=ADMIN_HEADERS)
    assert validate.status_code == 200
    assert validate.json()["valid"] is True


def test_orchestration_human_approval_json_path_config_validates():
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "node-1",
                    "type": "llm_chat",
                    "config": {"model_id": "gpt-4o-mini", "prompt_template": "Suggest reviewer"},
                },
                {
                    "id": "node-2",
                    "type": "human_approval",
                    "config": {
                        "approval_title": "Review LLM output",
                        "approver_source": "json_path",
                        "source_node_id": "node-1",
                        "approver_role_json_path": "$.reviewer.role",
                        "approver_id_json_path": "$.reviewer.user_id",
                    },
                },
            ],
            "edges": [{"source": "node-1", "target": "node-2"}],
        }
    )
    created = _create_flow(graph_json=graph)
    validate = client.post(f"/orchestration/flows/{created['flow_id']}/validate", headers=ADMIN_HEADERS)
    assert validate.status_code == 200
    assert validate.json()["valid"] is True


def test_orchestration_http_node_requires_allowlist():
    db: Session = SessionLocal()
    try:
        db.merge(
            RuntimeConfig(
                config_key="orchestration.http_allowed_hosts_json",
                config_value='["api.example.com"]',
                updated_by="orch-test",
            )
        )
        db.commit()
    finally:
        db.close()

    graph = _sample_graph(include_http=True)
    created = _create_flow(graph_json=graph)
    assert created["flow_id"]

    db = SessionLocal()
    try:
        row = db.query(OrchestrationFlowDefinition).filter_by(flow_id=created["flow_id"]).first()
        assert row is not None
    finally:
        db.close()

    denied_graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "http-bad",
                    "type": "http_request",
                    "config": {"url": "https://evil.example.net/hook", "method": "GET"},
                }
            ],
            "edges": [],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "http-denied",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": denied_graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400


def test_orchestration_http_auth_requires_binding():
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="orchestration.http_allowed_hosts_json").first()
        if row is None:
            db.add(
                RuntimeConfig(
                    config_key="orchestration.http_allowed_hosts_json",
                    config_value='["api.example.com"]',
                )
            )
        else:
            row.config_value = '["api.example.com"]'
        db.commit()
    finally:
        db.close()

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "http-auth",
                    "type": "http_request",
                    "config": {
                        "url": "https://api.example.com/hook",
                        "method": "POST",
                        "auth_type": "bearer",
                    },
                }
            ],
            "edges": [],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "http-auth-missing-binding",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "VALIDATION_ERROR"


def _parallel_graph() -> str:
    graph = {
        "nodes": [
            {
                "id": "node-1",
                "type": "llm_chat",
                "config": {"model_id": "gpt-4o-mini", "prompt_template": "Prepare"},
            },
            {
                "id": "fork-1",
                "type": "parallel_fork",
                "config": {"group_id": "pg-test-1", "branch_count": 2},
            },
            {
                "id": "branch-a",
                "type": "http_request",
                "config": {"url": "https://api.example.com/a", "method": "GET"},
            },
            {
                "id": "branch-b",
                "type": "mcp_tool",
                "config": {"server_id": "srv-1", "tool_name": "lookup"},
            },
            {
                "id": "join-1",
                "type": "parallel_join",
                "config": {"group_id": "pg-test-1", "fork_node_id": "fork-1"},
            },
            {
                "id": "node-2",
                "type": "human_approval",
                "config": {"approval_title": "Review parallel output"},
            },
        ],
        "edges": [
            {"source": "node-1", "target": "fork-1"},
            {"source": "fork-1", "target": "branch-a", "branch": 0},
            {"source": "fork-1", "target": "branch-b", "branch": 1},
            {"source": "branch-a", "target": "join-1"},
            {"source": "branch-b", "target": "join-1"},
            {"source": "join-1", "target": "node-2"},
        ],
    }
    return json.dumps(graph)


def test_orchestration_parallel_graph_validates():
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="orchestration.http_allowed_hosts_json").first()
        if row is None:
            db.add(
                RuntimeConfig(
                    config_key="orchestration.http_allowed_hosts_json",
                    config_value='["api.example.com"]',
                )
            )
        else:
            row.config_value = '["api.example.com"]'
        db.commit()
    finally:
        db.close()

    created = _create_flow(graph_json=_parallel_graph())
    validate = client.post(f"/orchestration/flows/{created['flow_id']}/validate", headers=ADMIN_HEADERS)
    assert validate.status_code == 200
    body = validate.json()
    assert body["valid"] is True
    assert body["node_count"] == 6


def test_orchestration_parallel_fork_requires_join():
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "fork-only",
                    "type": "parallel_fork",
                    "config": {"group_id": "pg-orphan"},
                },
                {
                    "id": "branch-a",
                    "type": "llm_chat",
                    "config": {"model_id": "gpt-4o-mini", "prompt_template": "A"},
                },
            ],
            "edges": [{"source": "fork-only", "target": "branch-a"}],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "parallel-missing-join",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "VALIDATION_ERROR"


def test_orchestration_parallel_dry_run_executes_branches():
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="orchestration.http_allowed_hosts_json").first()
        if row is None:
            db.add(
                RuntimeConfig(
                    config_key="orchestration.http_allowed_hosts_json",
                    config_value='["api.example.com"]',
                )
            )
        else:
            row.config_value = '["api.example.com"]'
        db.commit()
    finally:
        db.close()

    flow = _create_flow(graph_json=_parallel_graph())
    flow_id = flow["flow_id"]
    run = client.post(
        f"/orchestration/flows/{flow_id}/run",
        json={"dry_run": True},
        headers=ADMIN_HEADERS,
    )
    assert run.status_code == 200
    run_id = run.json()["run_id"]

    detail = client.get(f"/orchestration/flows/{flow_id}/runs/{run_id}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    steps = json.loads(detail.json()["step_results_json"])
    fork_step = next((step for step in steps if step.get("node_type") == "parallel_fork"), None)
    assert fork_step is not None
    assert fork_step["output"]["execution_mode"] == "parallel"
    assert fork_step["output"]["branch_count"] == 2
    assert len(fork_step["output"]["branches"]) == 2
    branch_types = {step["node_type"] for branch in fork_step["output"]["branches"] for step in branch}
    assert "http_request" in branch_types
    assert "mcp_tool" in branch_types
    join_step = next((step for step in steps if step.get("node_type") == "parallel_join"), None)
    assert join_step is not None
    assert join_step["output"]["merged"] is True


def test_orchestration_http_auth_binding_ref_validates():
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="orchestration.http_allowed_hosts_json").first()
        if row is None:
            db.add(
                RuntimeConfig(
                    config_key="orchestration.http_allowed_hosts_json",
                    config_value='["api.example.com"]',
                )
            )
        else:
            row.config_value = '["api.example.com"]'
        db.commit()
    finally:
        db.close()

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "http-auth",
                    "type": "http_request",
                    "config": {
                        "url": "https://api.example.com/hook",
                        "method": "POST",
                        "auth_type": "bearer",
                        "auth_binding_id": "binding-http-outbound-001",
                    },
                }
            ],
            "edges": [],
        }
    )
    flow = _create_flow(graph_json=graph)
    validate = client.post(f"/orchestration/flows/{flow['flow_id']}/validate", headers=ADMIN_HEADERS)
    assert validate.status_code == 200
    assert validate.json()["valid"] is True


def _seed_vector_stores() -> None:
    stores_json = (
        '[{"store_id":"orch-qdrant","provider_type":"qdrant","connection_url":"https://qdrant.local:6333",'
        '"collection_name":"docs","embedding_dimensions":1536,"similarity_metric":"cosine","enabled":true,'
        '"secret_provider_id":"sp-orch-vector","api_key_secret_ref":"providers/vector/qdrant/orch-qdrant/api-key"}]'
    )
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="gateway.vector_stores_json").first()
        if row is None:
            db.add(RuntimeConfig(config_key="gateway.vector_stores_json", config_value=stores_json))
        else:
            row.config_value = stores_json
        db.commit()
        invalidate_runtime_config_cache("gateway.vector_stores_json")
    finally:
        db.close()


def test_orchestration_vector_query_validates_with_registry_store():
    _seed_vector_stores()
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "vec-search",
                    "type": "vector_query",
                    "config": {"store_id": "orch-qdrant", "query": "What is our refund policy?", "top_k": 5},
                }
            ],
            "edges": [],
        }
    )
    flow = _create_flow(graph_json=graph)
    validate = client.post(f"/orchestration/flows/{flow['flow_id']}/validate", headers=ADMIN_HEADERS)
    assert validate.status_code == 200
    assert validate.json()["valid"] is True


def test_orchestration_vector_query_rejects_unknown_store():
    _seed_vector_stores()
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "vec-bad",
                    "type": "vector_query",
                    "config": {"store_id": "missing-store", "query": "test"},
                }
            ],
            "edges": [],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "vector-unknown-store",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "VALIDATION_ERROR"


def test_orchestration_vector_ingest_stub_run():
    _seed_vector_stores()
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "vec-ingest",
                    "type": "vector_ingest",
                    "config": {
                        "store_id": "orch-qdrant",
                        "content_template": "Policy update for Q2",
                        "document_id": "policy-q2",
                    },
                }
            ],
            "edges": [],
        }
    )
    flow = _create_flow(graph_json=graph)
    run = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers=ADMIN_HEADERS,
    )
    assert run.status_code == 200
    run_id = run.json()["run_id"]
    detail = client.get(f"/orchestration/flows/{flow['flow_id']}/runs/{run_id}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    steps = json.loads(detail.json()["step_results_json"])
    ingest_step = next((step for step in steps if step.get("node_type") == "vector_ingest"), None)
    assert ingest_step is not None
    assert ingest_step["output"]["store_id"] == "orch-qdrant"
    assert ingest_step["output"]["document_id"] == "policy-q2"


def test_orchestration_parallel_branch_count_mismatch():
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="orchestration.http_allowed_hosts_json").first()
        if row is None:
            db.add(
                RuntimeConfig(
                    config_key="orchestration.http_allowed_hosts_json",
                    config_value='["api.example.com"]',
                )
            )
        else:
            row.config_value = '["api.example.com"]'
        db.commit()
    finally:
        db.close()

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "fork-1",
                    "type": "parallel_fork",
                    "config": {"group_id": "pg-mismatch", "branch_count": 3},
                },
                {"id": "branch-a", "type": "llm_chat", "config": {"model_id": "gpt-4o-mini", "prompt_template": "A"}},
                {"id": "branch-b", "type": "llm_chat", "config": {"model_id": "gpt-4o-mini", "prompt_template": "B"}},
                {
                    "id": "join-1",
                    "type": "parallel_join",
                    "config": {"group_id": "pg-mismatch", "fork_node_id": "fork-1"},
                },
            ],
            "edges": [
                {"source": "fork-1", "target": "branch-a"},
                {"source": "fork-1", "target": "branch-b"},
                {"source": "branch-a", "target": "join-1"},
                {"source": "branch-b", "target": "join-1"},
            ],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "branch-count-mismatch",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "VALIDATION_ERROR"


def test_orchestration_graph_cycle_rejected():
    graph = json.dumps(
        {
            "nodes": [
                {"id": "node-a", "type": "llm_chat", "config": {"model_id": "gpt-4o-mini", "prompt_template": "A"}},
                {"id": "node-b", "type": "llm_chat", "config": {"model_id": "gpt-4o-mini", "prompt_template": "B"}},
            ],
            "edges": [
                {"source": "node-a", "target": "node-b"},
                {"source": "node-b", "target": "node-a"},
            ],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "cycle-flow",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "VALIDATION_ERROR"


def test_orchestration_condition_invalid_json_path():
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "node-1",
                    "type": "llm_chat",
                    "config": {"model_id": "gpt-4o-mini", "prompt_template": "Prepare"},
                },
                {
                    "id": "node-2",
                    "type": "condition",
                    "config": {
                        "source_node_id": "node-1",
                        "json_path": "status",
                        "operator": "==",
                        "compare_value": "ok",
                        "expression": "legacy",
                    },
                },
            ],
            "edges": [{"source": "node-1", "target": "node-2"}],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "bad-json-path",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "VALIDATION_ERROR"


def _seed_notification_channels() -> None:
    channels_json = json.dumps(
        [
            {
                "channel_id": "orch-email",
                "provider_type": "sendgrid",
                "enabled": True,
                "environment": "dev",
                "from_address": "alerts@example.com",
                "default_recipient_domain_allowlist": ["example.com"],
                "credential_binding_id": "bind-orch-email",
                "api_base_url": "https://api.sendgrid.com",
                "metadata": {},
            },
            {
                "channel_id": "orch-sms",
                "provider_type": "twilio",
                "enabled": True,
                "environment": "dev",
                "from_address": "+15551234567",
                "default_recipient_domain_allowlist": [],
                "credential_binding_id": "bind-orch-sms",
                "api_base_url": "https://api.twilio.com",
                "metadata": {},
            },
        ]
    )
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="gateway.notification_channels_json").first()
        if row is None:
            db.add(RuntimeConfig(config_key="gateway.notification_channels_json", config_value=channels_json))
        else:
            row.config_value = channels_json
        db.commit()
        invalidate_runtime_config_cache("gateway.notification_channels_json")
    finally:
        db.close()


def test_orchestration_node_types_include_email_and_sms():
    response = client.get("/orchestration/node-types", headers=AUDITOR_HEADERS)
    assert response.status_code == 200
    types = {item["type"] for item in response.json()["node_types"]}
    assert "email_send" in types
    assert "sms_send" in types


def test_orchestration_email_send_validates_with_registry_channel():
    _seed_notification_channels()
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "email-1",
                    "type": "email_send",
                    "config": {
                        "channel_id": "orch-email",
                        "to_template": "{{steps['prior'].output.email}}",
                        "subject_template": "Alert: workflow complete",
                        "body_template": "Run finished successfully.",
                    },
                }
            ],
            "edges": [],
        }
    )
    flow = _create_flow(graph_json=graph)
    validate = client.post(f"/orchestration/flows/{flow['flow_id']}/validate", headers=ADMIN_HEADERS)
    assert validate.status_code == 200
    assert validate.json()["valid"] is True


def test_orchestration_email_send_rejects_unknown_channel():
    _seed_notification_channels()
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "email-bad",
                    "type": "email_send",
                    "config": {
                        "channel_id": "missing-channel",
                        "to_template": "ops@example.com",
                        "subject_template": "Test",
                        "body_template": "Body",
                    },
                }
            ],
            "edges": [],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "email-unknown-channel",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "VALIDATION_ERROR"


def test_orchestration_email_send_rejects_inline_secret_in_to_template():
    _seed_notification_channels()
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "email-secret",
                    "type": "email_send",
                    "config": {
                        "channel_id": "orch-email",
                        "to_template": "sk-live1234567890abcdef",
                        "subject_template": "Test",
                        "body_template": "Body",
                    },
                }
            ],
            "edges": [],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "email-secret-to",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "VALIDATION_ERROR"


def test_orchestration_sms_send_stub_run():
    _seed_notification_channels()
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "sms-1",
                    "type": "sms_send",
                    "config": {
                        "channel_id": "orch-sms",
                        "to_template": "+15559876543",
                        "body_template": "Workflow alert: {{input.summary}}",
                    },
                }
            ],
            "edges": [],
        }
    )
    flow = _create_flow(graph_json=graph)
    run = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers=ADMIN_HEADERS,
    )
    assert run.status_code == 200
    run_id = run.json()["run_id"]
    detail = client.get(f"/orchestration/flows/{flow['flow_id']}/runs/{run_id}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    steps = json.loads(detail.json()["step_results_json"])
    sms_step = next((step for step in steps if step.get("node_type") == "sms_send"), None)
    assert sms_step is not None
    assert sms_step["output"]["channel_id"] == "orch-sms"
    assert sms_step["output"]["simulated"] is True
    assert sms_step["output"]["delivery_status"] == "simulated"


def test_orchestration_llm_chat_extended_config_validates():
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "llm-ext",
                    "type": "llm_chat",
                    "config": {
                        "model_id": "gpt-4o-mini",
                        "prompt_template": "Answer using context",
                        "route_id": "route-support-v1",
                        "prompt_registry_id": "prompt-support-answer",
                        "max_tokens": 512,
                        "response_format": "json_object",
                        "cache_mode": "bypass",
                    },
                }
            ],
            "edges": [],
        }
    )
    flow = _create_flow(graph_json=graph)
    validate = client.post(f"/orchestration/flows/{flow['flow_id']}/validate", headers=ADMIN_HEADERS)
    assert validate.status_code == 200
    assert validate.json()["valid"] is True


def test_orchestration_new_litellm_node_types_validate():
    _seed_vector_stores()
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "embed-1",
                    "type": "embedding_create",
                    "config": {"model_id": "text-embedding-3-small", "input_template": "{{input.text}}"},
                },
                {
                    "id": "rag-1",
                    "type": "rag_query",
                    "config": {
                        "store_id": "orch-qdrant",
                        "query_template": "What is our refund policy?",
                        "top_k": 5,
                    },
                },
                {
                    "id": "wait-1",
                    "type": "wait_delay",
                    "config": {"delay_seconds": 30},
                },
                {
                    "id": "guard-1",
                    "type": "guardrail_evaluate",
                    "config": {
                        "key_id": "key-ops-001",
                        "input_template": "{{steps['rag-1'].output}}",
                        "guardrail_policy_id": "policy-output-safety",
                    },
                },
            ],
            "edges": [
                {"source": "embed-1", "target": "rag-1"},
                {"source": "rag-1", "target": "wait-1"},
                {"source": "wait-1", "target": "guard-1"},
            ],
        }
    )
    flow = _create_flow(graph_json=graph)
    validate = client.post(f"/orchestration/flows/{flow['flow_id']}/validate", headers=ADMIN_HEADERS)
    assert validate.status_code == 200
    assert validate.json()["valid"] is True


def test_orchestration_rag_query_rejects_unknown_store():
    _seed_vector_stores()
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "rag-bad",
                    "type": "rag_query",
                    "config": {"store_id": "missing-store", "query_template": "test"},
                }
            ],
            "edges": [],
        }
    )
    denied = client.post(
        "/orchestration/flows",
        json={
            "flow_name": "rag-unknown-store",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": graph,
        },
        headers=RELEASE_HEADERS,
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "VALIDATION_ERROR"


def test_orchestration_wait_delay_rejects_out_of_range():
    for delay_seconds in [0, 3601]:
        graph = json.dumps(
            {
                "nodes": [
                    {
                        "id": "wait-bad",
                        "type": "wait_delay",
                        "config": {"delay_seconds": delay_seconds},
                    }
                ],
                "edges": [],
            }
        )
        denied = client.post(
            "/orchestration/flows",
            json={
                "flow_name": f"wait-delay-{delay_seconds}",
                "environment": "dev",
                "trigger_type": "manual",
                "trigger_config_json": "{}",
                "graph_json": graph,
            },
            headers=RELEASE_HEADERS,
        )
        assert denied.status_code == 400
        assert response_error_code(denied) == "VALIDATION_ERROR"


def test_orchestration_new_node_types_stub_run():
    _seed_vector_stores()
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "embed-1",
                    "type": "embedding_create",
                    "config": {"model_id": "text-embedding-3-small", "input_template": "hello"},
                },
                {
                    "id": "rag-1",
                    "type": "rag_query",
                    "config": {"store_id": "orch-qdrant", "query_template": "policy question"},
                },
                {
                    "id": "wait-1",
                    "type": "wait_delay",
                    "config": {"delay_seconds": 5},
                },
                {
                    "id": "guard-1",
                    "type": "guardrail_evaluate",
                    "config": {"key_id": "key-ops-001", "input_template": "output text"},
                },
                {
                    "id": "llm-1",
                    "type": "llm_chat",
                    "config": {
                        "model_id": "gpt-4o-mini",
                        "prompt_template": "Summarize",
                        "route_id": "route-v1",
                        "cache_mode": "inherit",
                    },
                },
            ],
            "edges": [
                {"source": "embed-1", "target": "rag-1"},
                {"source": "rag-1", "target": "wait-1"},
                {"source": "wait-1", "target": "guard-1"},
                {"source": "guard-1", "target": "llm-1"},
            ],
        }
    )
    flow = _create_flow(
        graph_json=graph,
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": f"orch-stub-run-{uuid4().hex[:8]}"},
    )
    run = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers=ADMIN_HEADERS,
    )
    assert run.status_code == 200
    run_id = run.json()["run_id"]
    detail = client.get(f"/orchestration/flows/{flow['flow_id']}/runs/{run_id}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    steps = json.loads(detail.json()["step_results_json"])
    step_types = {step["node_type"] for step in steps}
    assert "embedding_create" in step_types
    assert "rag_query" in step_types
    assert "wait_delay" in step_types
    assert "guardrail_evaluate" in step_types

    embed_step = next(step for step in steps if step["node_type"] == "embedding_create")
    assert embed_step["output"]["embedding_dims"] == 1536
    assert embed_step["output"]["model_id"] == "text-embedding-3-small"

    rag_step = next(step for step in steps if step["node_type"] == "rag_query")
    assert rag_step["output"]["source"] == "rag_query"
    assert rag_step["output"]["store_id"] == "orch-qdrant"

    wait_step = next(step for step in steps if step["node_type"] == "wait_delay")
    assert wait_step["output"]["delay_seconds"] == 5
    assert wait_step["output"]["waited"] is True

    guard_step = next(step for step in steps if step["node_type"] == "guardrail_evaluate")
    assert guard_step["output"]["passed"] is True
    assert guard_step["output"]["violations"] == []

    llm_step = next(step for step in steps if step["node_type"] == "llm_chat")
    assert llm_step["output"]["route_id"] == "route-v1"
    assert llm_step["output"]["cache_mode"] == "inherit"


def test_orchestration_global_runs_list_includes_flow_name():
    actor_headers = {**RELEASE_HEADERS, "X-Actor-Id": f"orch-global-runs-{uuid4().hex[:8]}"}
    flow = _create_flow(headers=actor_headers)
    flow_id = flow["flow_id"]
    run = client.post(
        f"/orchestration/flows/{flow_id}/run",
        json={"dry_run": True},
        headers={**ADMIN_HEADERS, "X-Actor-Id": f"orch-global-run-{uuid4().hex[:8]}"},
    )
    assert run.status_code == 200

    listed = client.get("/orchestration/runs?limit=20", headers=AUDITOR_HEADERS)
    assert listed.status_code == 200
    payload = listed.json()
    assert payload["total"] >= 1
    match = next((row for row in payload["data"] if row["run_id"] == run.json()["run_id"]), None)
    assert match is not None
    assert match["flow_id"] == flow_id
    assert match["flow_name"] == flow["flow_name"]


def test_orchestration_run_audit_uses_run_trace_id():
    actor_headers = {**RELEASE_HEADERS, "X-Actor-Id": f"orch-audit-trace-{uuid4().hex[:8]}"}
    flow = _create_flow(headers=actor_headers)
    flow_id = flow["flow_id"]
    run = client.post(
        f"/orchestration/flows/{flow_id}/run",
        json={"dry_run": True},
        headers={**ADMIN_HEADERS, "X-Actor-Id": f"orch-audit-run-{uuid4().hex[:8]}"},
    )
    assert run.status_code == 200
    run_payload = run.json()
    trace_id = run_payload["trace_id"]

    db: Session = SessionLocal()
    try:
        audit = (
            db.query(AuditEvent)
            .filter_by(action_type="orchestration.flow.run", resource_id=flow_id, decision_outcome="allow")
            .order_by(AuditEvent.timestamp.desc())
            .first()
        )
        assert audit is not None
        assert audit.trace_id == trace_id
        context = json.loads(audit.action_context_json or "{}")
        assert context.get("run_id") == run_payload["run_id"]
        assert context.get("trace_id") == trace_id
    finally:
        db.close()


def test_orchestration_live_executor_disabled_by_default():
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="orchestration.live_executor_enabled").first()
        if row is not None:
            row.config_value = "false"
            db.commit()
            invalidate_runtime_config_cache("orchestration.live_executor_enabled")
    finally:
        db.close()

    actor_headers = {**RELEASE_HEADERS, "X-Actor-Id": f"orch-live-off-{uuid4().hex[:8]}"}
    flow = _create_flow(headers=actor_headers)
    run = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": False},
        headers={**ADMIN_HEADERS, "X-Actor-Id": f"orch-live-run-off-{uuid4().hex[:8]}"},
    )
    assert run.status_code == 200
    steps = json.loads(run.json()["step_results_json"])
    llm_step = next(step for step in steps if step["node_type"] == "llm_chat")
    assert llm_step["output"].get("simulated") is True


def test_orchestration_live_condition_evaluation():
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="orchestration.live_executor_enabled").first()
        if row is None:
            db.add(
                RuntimeConfig(
                    config_key="orchestration.live_executor_enabled",
                    config_value="true",
                    description="test enable live executor",
                )
            )
        else:
            row.config_value = "true"
        db.commit()
        invalidate_runtime_config_cache("orchestration.live_executor_enabled")
    finally:
        db.close()

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "node-set",
                    "type": "llm_chat",
                    "config": {
                        "model_id": "gpt-4o-mini",
                        "prompt_template": "hello",
                        "binding_id": "binding-test-001",
                    },
                },
                {
                    "id": "node-cond",
                    "type": "condition",
                    "config": {
                        "source_node_id": "node-set",
                        "json_path": "$.message",
                        "operator": "contains",
                        "compare_value": "Simulated",
                        "expression": "legacy",
                    },
                },
            ],
            "edges": [{"source": "node-set", "target": "node-cond"}],
        }
    )
    actor_headers = {**RELEASE_HEADERS, "X-Actor-Id": f"orch-live-cond-{uuid4().hex[:8]}"}
    created = client.post(
        "/orchestration/flows",
        json={
            "flow_name": f"live-cond-{uuid4().hex[:6]}",
            "environment": "dev",
            "trigger_type": "manual",
            "trigger_config_json": "{}",
            "graph_json": graph,
        },
        headers=actor_headers,
    )
    assert created.status_code == 200
    flow_id = created.json()["flow_id"]
    run = client.post(
        f"/orchestration/flows/{flow_id}/run",
        json={"dry_run": False},
        headers={**ADMIN_HEADERS, "X-Actor-Id": f"orch-live-cond-run-{uuid4().hex[:8]}"},
    )
    assert run.status_code == 200
    steps = json.loads(run.json()["step_results_json"])
    cond = next(step for step in steps if step["node_type"] == "condition")
    assert cond["output"].get("live") is True
    assert cond["output"].get("matched") is True

    db = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key="orchestration.live_executor_enabled").first()
        if row is not None:
            row.config_value = "false"
            db.commit()
            invalidate_runtime_config_cache("orchestration.live_executor_enabled")
    finally:
        db.close()


def test_orchestration_flow_access_policy_runners_enforced():
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": f"orch-owner-{uuid4().hex[:8]}"}
    runner_id = f"orch-runner-{uuid4().hex[:8]}"
    flow = _create_flow(headers=owner_headers, graph_json=_sample_graph(include_http=False))
    policy = {
        "version": 1,
        "owners": {"users": [owner_headers["X-Actor-Id"]], "groups": [], "teams": [], "match": "any"},
        "runners": {"users": [runner_id], "groups": [], "teams": [], "match": "any"},
        "schedulers": {"users": [], "groups": [], "teams": [], "match": "any"},
        "approvers": {"match": "any", "clauses": []},
    }
    updated = client.put(
        f"/orchestration/flows/{flow['flow_id']}",
        json={"access_policy_json": json.dumps(policy)},
        headers=owner_headers,
    )
    assert updated.status_code == 200

    denied = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers={**OPS_HEADERS, "X-Actor-Id": "orch-not-runner"},
    )
    assert denied.status_code == 403
    assert response_error_code(denied) == "AUTHZ_FLOW_SCOPE_FORBIDDEN"

    allowed = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers={**OPS_HEADERS, "X-Actor-Id": runner_id},
    )
    assert allowed.status_code == 200


def test_orchestration_flow_access_policy_approver_all_clauses():
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": f"orch-appr-owner-{uuid4().hex[:8]}"}
    approver_id = f"orch-appr-{uuid4().hex[:8]}"
    flow = _create_flow(headers=owner_headers)
    policy = {
        "version": 1,
        "owners": {"users": [owner_headers["X-Actor-Id"]], "groups": [], "teams": [], "match": "any"},
        "runners": {"users": [], "groups": [], "teams": [], "match": "any"},
        "schedulers": {"users": [], "groups": [], "teams": [], "match": "any"},
        "approvers": {
            "match": "all",
            "clauses": [
                {"users": [approver_id], "groups": [], "teams": []},
                {"users": [approver_id], "groups": [], "teams": []},
            ],
        },
    }
    client.put(
        f"/orchestration/flows/{flow['flow_id']}",
        json={"access_policy_json": json.dumps(policy)},
        headers=owner_headers,
    )

    denied = client.post(
        f"/orchestration/flows/{flow['flow_id']}/approve",
        json={"decision": "approved"},
        headers={**SECURITY_HEADERS, "X-Actor-Id": "orch-not-approver"},
    )
    assert denied.status_code == 403

    allowed = client.post(
        f"/orchestration/flows/{flow['flow_id']}/approve",
        json={"decision": "approved"},
        headers={**SECURITY_HEADERS, "X-Actor-Id": approver_id},
    )
    assert allowed.status_code == 200


def _set_runtime_config(key: str, value: str) -> None:
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key=key).first()
        if row is None:
            db.add(RuntimeConfig(config_key=key, config_value=value, description="test"))
        else:
            row.config_value = value
        db.commit()
        invalidate_runtime_config_cache(key)
    finally:
        db.close()


def _enable_live_executor(enabled: bool = True) -> None:
    _set_runtime_config("orchestration.live_executor_enabled", "true" if enabled else "false")


def test_orchestration_live_email_send_with_mocked_delivery():
    from app.models import ProviderCredentialBinding
    from unittest.mock import patch

    _seed_notification_channels()
    _enable_live_executor(True)
    binding_id = "bind-orch-email"
    db: Session = SessionLocal()
    try:
        if db.query(ProviderCredentialBinding).filter_by(binding_id=binding_id).first() is None:
            db.add(
                ProviderCredentialBinding(
                    binding_id=binding_id,
                    tenant_id="tenant-orch-email",
                    binding_name="Orch email binding",
                    consumer_type="platform",
                    consumer_key="gateway",
                    provider_type="sendgrid",
                    credential_plane="secret_ref",
                    secret_provider_id="sp-test",
                    secret_ref="providers/sendgrid/api-key",
                    environment="dev",
                    status="active",
                )
            )
            db.commit()
    finally:
        db.close()

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "email-live",
                    "type": "email_send",
                    "config": {
                        "channel_id": "orch-email",
                        "to_template": "ops@example.com",
                        "subject_template": "Live test",
                        "body_template": "Hello from live executor",
                    },
                }
            ],
            "edges": [],
        }
    )
    actor_headers = {**RELEASE_HEADERS, "X-Actor-Id": f"orch-email-live-{uuid4().hex[:8]}"}
    flow = _create_flow(graph_json=graph, headers=actor_headers)
    with patch(
        "app.services.orchestration_executor.deliver_email",
        return_value={
            "live": True,
            "simulated": False,
            "delivery_status": "sent",
            "provider_type": "sendgrid",
            "channel_id": "orch-email",
            "receipt_id": "mock-receipt-1",
        },
    ):
        run = client.post(
            f"/orchestration/flows/{flow['flow_id']}/run",
            json={"dry_run": False},
            headers={**ADMIN_HEADERS, "X-Actor-Id": f"orch-email-run-{uuid4().hex[:8]}"},
        )
    assert run.status_code == 200
    steps = json.loads(run.json()["step_results_json"])
    email_step = next(step for step in steps if step["node_type"] == "email_send")
    assert email_step["output"]["live"] is True
    assert email_step["output"]["delivery_status"] == "sent"
    _enable_live_executor(False)


def test_orchestration_live_http_request_injects_auth_header():
    from app.models import ProviderCredentialBinding
    from unittest.mock import Mock, patch
    import httpx

    _enable_live_executor(True)
    _set_runtime_config("orchestration.http_allowed_hosts_json", '["api.example.com"]')
    binding_id = f"bind-http-{uuid4().hex[:8]}"
    db: Session = SessionLocal()
    try:
        db.add(
            ProviderCredentialBinding(
                binding_id=binding_id,
                tenant_id=f"tenant-{uuid4().hex[:6]}",
                binding_name="HTTP auth binding",
                consumer_type="platform",
                consumer_key="gateway",
                provider_type="generic",
                credential_plane="secret_ref",
                secret_provider_id="sp-test",
                secret_ref="providers/http/token",
                environment="dev",
                status="active",
            )
        )
        db.commit()
    finally:
        db.close()

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "http-auth",
                    "type": "http_request",
                    "config": {
                        "url": "https://api.example.com/hook",
                        "method": "GET",
                        "auth_type": "bearer",
                        "auth_binding_id": binding_id,
                    },
                }
            ],
            "edges": [],
        }
    )
    actor_headers = {**RELEASE_HEADERS, "X-Actor-Id": f"orch-http-auth-{uuid4().hex[:8]}"}
    flow = _create_flow(graph_json=graph, headers=actor_headers)
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = '{"ok":true}'

    with patch(
        "app.services.orchestration_http_auth.resolve_binding_for_runtime",
        return_value=Mock(secret_value="secret-bearer-token"),
    ):
        with patch("app.services.orchestration_executor.httpx.request", return_value=mock_response) as mock_request:
            run = client.post(
                f"/orchestration/flows/{flow['flow_id']}/run",
                json={"dry_run": False},
                headers={**ADMIN_HEADERS, "X-Actor-Id": f"orch-http-run-{uuid4().hex[:8]}"},
            )
    assert run.status_code == 200
    headers = mock_request.call_args.kwargs.get("headers") or mock_request.call_args[1].get("headers")
    assert headers["Authorization"] == "Bearer secret-bearer-token"
    _enable_live_executor(False)


def test_orchestration_human_approval_gate_pauses_and_resumes():
    from unittest.mock import patch

    _enable_live_executor(True)
    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "approve-node",
                    "type": "human_approval",
                    "config": {
                        "approval_title": "Review workflow",
                        "required_role": "Security Approver",
                    },
                },
                {
                    "id": "after-approve",
                    "type": "wait_delay",
                    "config": {"delay_seconds": 1},
                },
            ],
            "edges": [{"source": "approve-node", "target": "after-approve"}],
        }
    )
    actor_headers = {**RELEASE_HEADERS, "X-Actor-Id": f"orch-gate-{uuid4().hex[:8]}"}
    flow = _create_flow(graph_json=graph, headers=actor_headers)
    run = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": False},
        headers={**ADMIN_HEADERS, "X-Actor-Id": f"orch-gate-run-{uuid4().hex[:8]}"},
    )
    assert run.status_code == 200
    run_payload = run.json()
    assert run_payload["status"] == "awaiting_approval"
    assert run_payload["finished_at"] is None

    gates = client.get(
        f"/orchestration/flows/{flow['flow_id']}/runs/{run_payload['run_id']}/approval-gates",
        headers=ADMIN_HEADERS,
    )
    assert gates.status_code == 200
    assert gates.json()["total"] == 1
    gate_id = gates.json()["data"][0]["gate_id"]
    assert gates.json()["data"][0]["status"] == "pending"

    with patch("app.services.orchestration_executor.time.sleep", return_value=None):
        decided = client.post(
            f"/orchestration/flows/{flow['flow_id']}/runs/{run_payload['run_id']}/approval-gates/{gate_id}/decide",
            json={"decision": "approved", "comment": "Looks good"},
            headers={**SECURITY_HEADERS, "X-Actor-Id": f"orch-gate-decide-{uuid4().hex[:8]}"},
        )
    assert decided.status_code == 200
    assert decided.json()["status"] == "completed"
    steps = json.loads(decided.json()["step_results_json"])
    assert any(step["node_type"] == "wait_delay" for step in steps)
    _enable_live_executor(False)


def test_orchestration_data_connections_list_includes_platform():
    actor_id = f"orch-conn-{uuid4().hex[:8]}"
    response = client.get(
        "/orchestration/data-connections",
        headers={**ADMIN_HEADERS, "X-Actor-Id": actor_id},
    )
    assert response.status_code == 200
    payload = response.json()
    connection_ids = [row["connection_id"] for row in payload["data"]]
    assert "platform" in connection_ids
    platform = next(row for row in payload["data"] if row["connection_id"] == "platform")
    assert platform["driver"] == "platform"


def test_orchestration_data_connection_test_query_platform():
    actor_id = f"orch-conn-test-{uuid4().hex[:8]}"
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": actor_id}
    flow = _create_flow(headers=owner_headers, graph_json=_sample_graph(include_http=False))
    response = client.post(
        "/orchestration/data-connections/platform/test-query",
        json={
            "sql": "SELECT flow_id, flow_name FROM orchestration_flow_definitions WHERE flow_id = :flow_id",
            "parameters": {"flow_id": flow["flow_id"]},
            "preview_limit": 5,
        },
        headers={**ADMIN_HEADERS, "X-Actor-Id": actor_id},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["row_count"] >= 1
    assert payload["rows"][0]["flow_id"] == flow["flow_id"]


def test_orchestration_access_policy_resolve_dynamic_approvers():
    owner_id = f"orch-resolve-owner-{uuid4().hex[:8]}"
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": owner_id}
    flow = _create_flow(headers=owner_headers, graph_json=_sample_graph(include_http=False))
    policy = {
        "version": 1,
        "owners": {"users": [owner_id], "groups": [], "teams": [], "match": "any"},
        "runners": {"users": [], "groups": [], "teams": [], "match": "any"},
        "schedulers": {"users": [], "groups": [], "teams": [], "match": "any"},
        "approvers": {
            "match": "any",
            "clauses": [
                {
                    "users": [],
                    "groups": [],
                    "teams": [],
                    "match": "any",
                    "resolve_from": {
                        "type": "database_query",
                        "connection_id": "platform",
                        "sql": (
                            "SELECT created_by AS user_id FROM orchestration_flow_definitions "
                            "WHERE flow_id = :flow_id"
                        ),
                        "parameters": {"flow_id": "{{flow.flow_id}}"},
                        "mapping": {"user_field": "user_id"},
                    },
                }
            ],
        },
    }
    response = client.post(
        f"/orchestration/flows/{flow['flow_id']}/access-policy/resolve",
        json={"access_policy_json": json.dumps(policy)},
        headers={**ADMIN_HEADERS, "X-Actor-Id": owner_id},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["flow_id"] == flow["flow_id"]
    assert not body["resolve_errors"]
    resolved_users = body["resolved_policy"]["approvers"]["clauses"][0]["users"]
    assert owner_id in resolved_users
    assert body["template_context"]["flow.flow_id"] == flow["flow_id"]


def test_orchestration_summary_endpoint():
    actor_id = f"orch-summary-{uuid4().hex[:8]}"
    response = client.get(
        "/orchestration/summary",
        headers={**ADMIN_HEADERS, "X-Actor-Id": actor_id},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "flow_count" in payload
    assert "flows_by_environment" in payload
    assert "pending_prod_approvals" in payload


def test_orchestration_template_resolves_scope_id_from_prior_step():
    from app.services.orchestration_executor import resolve_orchestration_template

    resolved = resolve_orchestration_template(
        "{{steps['node-1'].output.data.session_id}}",
        step_outputs={"node-1": {"data": {"session_id": "sess-42"}}},
        run_input="ignored",
    )
    assert resolved == "sess-42"

    run_input_scope = resolve_orchestration_template("{{input}}", step_outputs={}, run_input="run-scope-key")
    assert run_input_scope == "run-scope-key"


def test_orchestration_template_resolves_http_header_values():
    from app.services.orchestration_executor import resolve_orchestration_template

    headers = '{"X-Session":"{{steps[\'hook\'].output.data.session_id}}"}'
    resolved = resolve_orchestration_template(
        headers,
        step_outputs={"hook": {"data": {"session_id": "sess-99"}}},
        run_input="",
    )
    assert "sess-99" in resolved


def test_orchestration_template_resolves_array_paths_and_full_output():
    from app.services.orchestration_executor import resolve_orchestration_template

    step_outputs = {
        "llm-1": {
            "choices": [{"message": {"content": "hello world"}}],
            "message": "hello world",
        }
    }
    nested = resolve_orchestration_template(
        "{{steps['llm-1'].output.choices[0].message.content}}",
        step_outputs=step_outputs,
        run_input="",
    )
    assert nested == "hello world"

    full = resolve_orchestration_template(
        "{{steps['llm-1'].output}}",
        step_outputs=step_outputs,
        run_input="",
    )
    assert "hello world" in full


def _condition_branch_graph(*, compare_value: str) -> str:
    return json.dumps(
        {
            "nodes": [
                {
                    "id": "node-c",
                    "type": "condition",
                    "config": {
                        "expression": "yes",
                        "operator": "==",
                        "compare_value": compare_value,
                        "true_branch": "node-t",
                        "false_branch": "node-f",
                    },
                },
                {"id": "node-t", "type": "wait_delay", "config": {"delay_seconds": 1}},
                {"id": "node-f", "type": "wait_delay", "config": {"delay_seconds": 1}},
                {
                    "id": "node-m",
                    "type": "llm_chat",
                    "config": {"model_id": "gpt-4o-mini", "prompt_template": "done"},
                },
            ],
            "edges": [
                {"source": "node-c", "target": "node-t"},
                {"source": "node-c", "target": "node-f"},
                {"source": "node-t", "target": "node-m"},
                {"source": "node-f", "target": "node-m"},
            ],
        }
    )


def _run_step_node_ids(flow_id: str, *, headers: Optional[dict] = None) -> set[str]:
    run_headers = headers or OPS_HEADERS
    run = client.post(
        f"/orchestration/flows/{flow_id}/run",
        json={"dry_run": True},
        headers=run_headers,
    )
    assert run.status_code == 200, run.text
    run_id = run.json()["run_id"]
    detail = client.get(f"/orchestration/flows/{flow_id}/runs/{run_id}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    steps = json.loads(detail.json()["step_results_json"])
    return {step["node_id"] for step in steps}


def test_orchestration_condition_branch_true_skips_false():
    headers = {**ADMIN_HEADERS, "X-Actor-Id": f"orch-cond-true-{uuid4().hex[:8]}"}
    created = _create_flow(graph_json=_condition_branch_graph(compare_value="yes"), headers=headers)
    node_ids = _run_step_node_ids(created["flow_id"], headers=headers)
    assert "node-t" in node_ids
    assert "node-f" not in node_ids
    assert "node-m" in node_ids


def test_orchestration_condition_branch_false_skips_true():
    headers = {**ADMIN_HEADERS, "X-Actor-Id": f"orch-cond-false-{uuid4().hex[:8]}"}
    created = _create_flow(graph_json=_condition_branch_graph(compare_value="no"), headers=headers)
    node_ids = _run_step_node_ids(created["flow_id"], headers=headers)
    assert "node-f" in node_ids
    assert "node-t" not in node_ids
    assert "node-m" in node_ids


def test_orchestration_webhook_trigger_starts_run():
    graph = _sample_graph()
    token = f"hook-token-{uuid4().hex[:8]}"
    headers = {**ADMIN_HEADERS, "X-Actor-Id": f"orch-webhook-{uuid4().hex[:8]}"}
    payload = {
        "flow_name": f"webhook-flow-{uuid4().hex[:8]}",
        "description": "Webhook trigger test",
        "environment": "dev",
        "trigger_type": "webhook",
        "trigger_config_json": json.dumps({"webhook_path_ref": token}),
        "graph_json": graph,
    }
    create_response = client.post("/orchestration/flows", json=payload, headers=headers)
    assert create_response.status_code == 200, create_response.text
    created = create_response.json()
    response = client.post(
        f"/orchestration/webhooks/{token}/trigger",
        json={"dry_run": True, "run_input": "webhook payload"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["flow_id"] == created["flow_id"]


def test_orchestration_scheduler_tick_requires_admin():
    response = client.get("/orchestration/scheduler/tick", headers=AUDITOR_HEADERS)
    assert response.status_code == 403

