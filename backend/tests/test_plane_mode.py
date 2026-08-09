"""Control / data plane isolation (APP_PLANE) unit and API tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import main as main_mod
from app.database import SessionLocal
from app.main import app
from app.plane_mode import (
    build_plane_posture,
    classify_path,
    path_allowed_on_plane,
    plane_rejection_payload,
    resolve_app_plane,
    should_run_control_schedulers,
)
from app.services.control_plane_contract import RUNTIME_CONFIG_PLANE_CONTROL_READONLY
from app.services.plane_reconcile import (
    compute_policy_generation,
    probe_peer_health,
    record_plane_rejection,
    rejection_stats_snapshot,
    resolve_peer_url,
)
from app.services.runtime_config import invalidate_runtime_config_cache, upsert_runtime_config_value

client = TestClient(app)
ADMIN = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "plane-admin"}


@pytest.fixture(autouse=True)
def _clear_control_plane_freeze(monkeypatch):
    """Keep plane mutation tests isolated from leftover freeze state."""
    monkeypatch.delenv("PLANE_CONTROL_READONLY", raising=False)
    db = SessionLocal()
    try:
        upsert_runtime_config_value(db, RUNTIME_CONFIG_PLANE_CONTROL_READONLY, "false")
        db.commit()
        invalidate_runtime_config_cache(RUNTIME_CONFIG_PLANE_CONTROL_READONLY)
    finally:
        db.close()
    yield


def test_resolve_and_classify_paths():
    assert resolve_app_plane("all") == "all"
    assert resolve_app_plane("control") == "control"
    assert resolve_app_plane("cp") == "control"
    assert resolve_app_plane("data") == "data"
    assert resolve_app_plane("gateway") == "data"
    assert resolve_app_plane("bogus") == "all"

    assert classify_path("/health") == "shared"
    assert classify_path("/platform/control-plane/live") == "shared"
    assert classify_path("/auth/sessions") == "shared"
    assert classify_path("/v1/chat/completions") == "data"
    assert classify_path("/v1/embeddings") == "data"
    assert classify_path("/rag/query") == "data"
    assert classify_path("/v1/virtual-keys") == "control"
    assert classify_path("/v1/configs") == "control"
    assert classify_path("/v1/models") == "control"
    assert classify_path("/gateway/routes") == "control"
    assert classify_path("/keys") == "control"
    assert classify_path("/platform/control-plane") == "control"

    assert path_allowed_on_plane("/v1/chat/completions", "all") is True
    assert path_allowed_on_plane("/v1/chat/completions", "control") is False
    assert path_allowed_on_plane("/v1/chat/completions", "data") is True
    assert path_allowed_on_plane("/gateway/routes", "data") is False
    assert path_allowed_on_plane("/gateway/routes", "control") is True
    assert path_allowed_on_plane("/health", "data") is True

    assert should_run_control_schedulers("all") is True
    assert should_run_control_schedulers("control") is True
    assert should_run_control_schedulers("data") is False


def test_build_plane_posture_includes_targets():
    combined = build_plane_posture(
        plane="all",
        on_plane_coverage={
            "on_plane_events": 3,
            "off_plane_detected": 1,
            "on_plane_coverage_percent": 75.0,
            "formula": "on_plane / (on_plane + off_plane_detected)",
        },
        policy_generation={"fingerprint": "abc123", "route_count": 1},
        drift_status="none_combined",
    )
    assert combined["app_plane"] == "all"
    assert combined["isolation_mode"] == "combined"
    assert combined["architecture_targets"]["control_plane_data_plane_isolation"] is False
    assert combined["architecture_targets"]["policy_generation_reconcile"] is True
    assert combined["on_plane_coverage"]["on_plane_coverage_percent"] == 75.0
    assert combined["policy_generation"]["fingerprint"] == "abc123"
    assert combined["drift_status"] == "none_combined"

    isolated = build_plane_posture(plane="control")
    assert isolated["isolation_mode"] == "process_isolated"
    assert isolated["architecture_targets"]["admin_off_inference_path"] is True


def test_plane_rejection_payload_shape():
    body = plane_rejection_payload(path="/v1/chat/completions", plane="control", path_plane="data")
    assert body["detail"]["error_code"] == "PLANE_ROUTE_REJECTED"
    assert body["detail"]["app_plane"] == "control"
    assert body["detail"]["path_plane"] == "data"


def test_rejection_stats_accumulate():
    before = rejection_stats_snapshot()["total"]
    record_plane_rejection(path="/v1/chat/completions", app_plane="control", path_plane="data")
    after = rejection_stats_snapshot()
    assert after["total"] >= before + 1
    assert any("chat" in item["key"] for item in after["top_paths"])


def test_resolve_peer_url(monkeypatch):
    monkeypatch.setenv("DATA_PLANE_PEER_URL", "http://gateway:8000")
    monkeypatch.setenv("CONTROL_PLANE_PEER_URL", "http://control:8000")
    assert resolve_peer_url("control") == "http://gateway:8000"
    assert resolve_peer_url("data") == "http://control:8000"
    assert resolve_peer_url("all") is None


def test_probe_peer_health_unreachable():
    result = probe_peer_health(
        peer_url="http://127.0.0.1:1",
        local_generation={"fingerprint": "localfp"},
        timeout_seconds=0.3,
    )
    assert result["configured"] is True
    assert result["reachable"] is False
    assert result["error"]


def test_health_includes_plane_posture():
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert "plane" in payload
    assert payload["plane"]["app_plane"] in {"all", "control", "data"}
    assert payload["plane"]["env_var"] == "APP_PLANE"
    generation = payload["plane"].get("policy_generation")
    if generation is not None:
        assert "fingerprint" in generation


def test_platform_control_plane_endpoint():
    response = client.get(
        "/platform/control-plane?window_hours=24&probe_peer=false",
        headers=ADMIN,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["app_plane"] in {"all", "control", "data"}
    assert payload["isolation_mode"] in {"combined", "process_isolated"}
    assert "on_plane_coverage" in payload
    assert "architecture_targets" in payload
    assert "policy_generation" in payload
    assert payload["policy_generation"] is None or "fingerprint" in payload["policy_generation"]
    assert "drift_status" in payload
    assert "rejection_stats" in payload


def test_platform_control_plane_requires_role():
    response = client.get(
        "/platform/control-plane",
        headers={"X-Actor-Id": "viewer", "X-Actor-Role": "Viewer"},
    )
    assert response.status_code == 403


def test_control_plane_rejects_inference(monkeypatch):
    monkeypatch.setattr(main_mod, "APP_PLANE", "control")
    response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]},
        headers=ADMIN,
    )
    assert response.status_code == 404
    detail = response.json().get("detail") or {}
    assert detail.get("error_code") == "PLANE_ROUTE_REJECTED"
    assert detail.get("path_plane") == "data"
    assert client.get("/health").status_code == 200


def test_data_plane_rejects_admin(monkeypatch):
    monkeypatch.setattr(main_mod, "APP_PLANE", "data")
    response = client.get("/gateway/routes", headers=ADMIN)
    assert response.status_code == 404
    detail = response.json().get("detail") or {}
    assert detail.get("error_code") == "PLANE_ROUTE_REJECTED"
    assert detail.get("path_plane") == "control"
    assert client.get("/health").status_code == 200


def test_compute_policy_generation_stable():
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        first = compute_policy_generation(db)
        second = compute_policy_generation(db)
        assert first["fingerprint"] == second["fingerprint"]
        assert "route_count" in first
        assert "key_count" in first
        assert "cache_policy_count" in first
    finally:
        db.close()


def test_fail_closed_gate_blocks_when_armed(monkeypatch):
    from app.services import plane_reconcile as reconcile

    monkeypatch.setenv("PLANE_FAIL_CLOSED_MODE", "drift")
    reconcile._update_gate_state(drift_status="peer_unreachable")
    allowed, reason = reconcile.inference_allowed_by_gate()
    assert allowed is False
    assert reason

    monkeypatch.setenv("PLANE_FAIL_CLOSED_MODE", "off")
    allowed_off, _ = reconcile.inference_allowed_by_gate()
    assert allowed_off is True


def test_run_reconcile_records_event():
    from app.database import SessionLocal
    from app.services.plane_reconcile import list_drift_events, run_reconcile_and_record

    db = SessionLocal()
    try:
        before = len(list_drift_events(50))
        snapshot = run_reconcile_and_record(db, plane="all", probe_peer=False, source="api.test")
        assert snapshot["drift_status"] == "none_combined"
        assert snapshot["gate"]["inference_allowed"] is True
        after = list_drift_events(50)
        assert len(after) >= before + 1
        assert after[0]["source"] == "api.test"
    finally:
        db.close()


def test_platform_reconcile_and_drift_events():
    reconcile = client.post("/platform/control-plane/reconcile?window_hours=24", headers=ADMIN)
    assert reconcile.status_code == 200, reconcile.text
    payload = reconcile.json()
    assert "drift_status" in payload
    assert "gate" in payload
    assert "policy_generation" in payload
    assert "published_policy_generation" in payload
    assert "slos" in payload
    assert payload["published_policy_generation"] is None or "fingerprint" in (
        payload["published_policy_generation"] or {}
    )

    events = client.get("/platform/control-plane/drift-events?limit=10", headers=ADMIN)
    assert events.status_code == 200, events.text
    body = events.json()
    assert "events" in body
    assert body["count"] >= 1


def test_policy_generation_publish_and_read():
    from app.database import SessionLocal
    from app.services.plane_policy_publish import publish_policy_generation, read_published_policy_generation
    from app.services.plane_reconcile import compute_policy_generation

    db = SessionLocal()
    try:
        generation = compute_policy_generation(db)
        published = publish_policy_generation(db, generation, app_plane="all")
        db.commit()
        assert published["fingerprint"] == generation["fingerprint"]
        assert "runtime_config" in published["publish_backends"]
        read_back = read_published_policy_generation(db)
        assert read_back is not None
        assert read_back["fingerprint"] == generation["fingerprint"]
    finally:
        db.close()


def test_plane_split_profile_available_and_raises_isolation_credit():
    from app.services.control_plane_leadership import plane_split_profile_available

    assert plane_split_profile_available() is True


def test_control_plane_leadership_and_attest(monkeypatch):
    monkeypatch.setenv("SESSION_TOKEN_SIGNING_KEYS", "cpli-test:super-secret-cpli-key")
    client.post("/platform/control-plane/reconcile?window_hours=24", headers=ADMIN)

    leadership = client.get(
        "/platform/control-plane/leadership?window_hours=24&probe_peer=false",
        headers=ADMIN,
    )
    assert leadership.status_code == 200, leadership.text
    scorecard = leadership.json()
    assert scorecard["index_name"] == "control_plane_leadership_index"
    assert scorecard["max_score"] == 20
    assert scorecard["marketing_claim_allowed"] is False
    assert scorecard.get("plane_split_ready") is True
    isolation = next(d for d in scorecard["dimensions"] if d["id"] == "isolation")
    assert isolation["score"] >= 2  # split-ready monolith earns 2/3
    assert isinstance(scorecard["dimensions"], list)
    assert len(scorecard["dimensions"]) >= 7
    assert "blockers" in scorecard
    assert "next_actions" in scorecard
    assert "points_to_leader_band" in scorecard
    assert scorecard["score"] + scorecard["points_to_leader_band"] >= scorecard["leader_band_threshold"] or scorecard[
        "engineering_leader_ready"
    ]
    # After publish + split-ready isolation, combined plane should reach eng leader band.
    assert scorecard["score"] >= 16
    assert scorecard["engineering_leader_ready"] is True
    assert scorecard["band"] == "leader_ready_engineering"

    forbidden = client.get("/platform/control-plane/leadership", headers={"X-Actor-Id": "v", "X-Actor-Role": "Viewer"})
    assert forbidden.status_code == 403

    attest = client.post(
        "/platform/control-plane/attest?window_hours=24&probe_peer=false",
        headers=ADMIN,
    )
    assert attest.status_code == 200, attest.text
    bundle = attest.json()
    assert bundle["attestation_id"].startswith("cpla-")
    assert bundle["marketing_claim_allowed"] is False
    assert bundle["signature"]["signed"] is True
    assert bundle["signature"]["algorithm"] == "HMAC-SHA256"
    assert bundle["verification"]["valid"] is True
    assert isinstance(bundle.get("attestation_history"), list)
    assert any(h.get("attestation_id") == bundle["attestation_id"] for h in bundle["attestation_history"])

    verify = client.get("/platform/control-plane/attest/verify", headers=ADMIN)
    assert verify.status_code == 200, verify.text
    verified = verify.json()
    assert verified["verification"]["valid"] is True
    assert verified["attestation_id"] == bundle["attestation_id"]
    assert verified["marketing_claim_allowed"] is False

    leadership2 = client.get(
        "/platform/control-plane/leadership?window_hours=24&probe_peer=false",
        headers=ADMIN,
    )
    assert leadership2.status_code == 200, leadership2.text
    card2 = leadership2.json()
    assert "release_gate" in card2
    assert "score_trend" in card2
    assert "attestation_freshness" in card2
    assert card2["attestation_freshness"]["fresh"] is True
    assert isinstance(card2["release_gate"]["checks"], list)
    assert card2["release_gate"]["marketing_claim_allowed"] is False
    assert "promotion_readiness" in card2
    assert "streak" in card2["promotion_readiness"]
    assert card2["promotion_readiness"]["marketing_claim_allowed"] is False

    posture = client.get("/platform/control-plane?window_hours=24&probe_peer=false", headers=ADMIN)
    assert posture.status_code == 200, posture.text
    assert "leadership_summary" in posture.json()

    promo = client.get("/platform/control-plane/promotion-readiness?window_hours=24", headers=ADMIN)
    assert promo.status_code == 200, promo.text
    promo_body = promo.json()
    assert "promotion_readiness" in promo_body
    assert promo_body["marketing_claim_allowed"] is False

    ops = client.get("/platform/operational-status", headers=ADMIN)
    assert ops.status_code == 200, ops.text
    assert "control_plane" in ops.json()
    assert ops.json()["control_plane"]["marketing_claim_allowed"] is False

    gate = client.get("/platform/control-plane/release-gate?window_hours=24", headers=ADMIN)
    assert gate.status_code == 200, gate.text
    gate_body = gate.json()
    assert gate_body["gate_name"] == "control_plane_engineering_release_gate"
    assert "passed" in gate_body
    assert gate_body["marketing_claim_allowed"] is False
    # After attest + reconcile, core checks should pass even if CPLI band unmet.
    check_ids = {c["id"] for c in gate_body["checks"]}
    assert "attestation_present" in check_ids
    assert "attestation_valid" in check_ids

    pack = client.get("/platform/control-plane/evidence-pack?window_hours=24&probe_peer=false", headers=ADMIN)
    assert pack.status_code == 200, pack.text
    pack_body = pack.json()
    assert pack_body["pack_id"].startswith("cpep-")
    assert pack_body["purpose"] == "control_plane_engineering_evidence"
    assert pack_body["marketing_claim_allowed"] is False
    assert "release_gate" in pack_body
    assert "scorecard" in pack_body
    assert "drift_events_recent" in pack_body
    assert pack_body["signature"]["signed"] is True
    assert pack_body["verification"]["valid"] is True
    assert "promotion_readiness" in pack_body

    minted = client.post(
        "/platform/control-plane/evidence-pack?window_hours=24&probe_peer=false",
        headers=ADMIN,
    )
    assert minted.status_code == 200, minted.text
    minted_body = minted.json()
    assert minted_body["pack_id"].startswith("cpep-")
    assert minted_body["verification"]["valid"] is True
    assert minted_body["marketing_claim_allowed"] is False

    evaluated = client.post(
        "/platform/control-plane/release-gate/evaluate?window_hours=24",
        headers=ADMIN,
    )
    assert evaluated.status_code == 200, evaluated.text
    eval_body = evaluated.json()
    assert eval_body["evaluation_id"].startswith("cprg-")
    assert "ci" in eval_body
    assert eval_body["ci"]["exit_code_hint"] in (0, 1)
    assert eval_body["marketing_claim_allowed"] is False
    assert any(h.get("evaluation_id") == eval_body["evaluation_id"] for h in eval_body["release_gate_history"])

    ceremony = client.post(
        "/platform/control-plane/reconcile?window_hours=24&attest=true&evaluate_gate=true",
        headers=ADMIN,
    )
    assert ceremony.status_code == 200, ceremony.text
    ceremony_body = ceremony.json()
    assert ceremony_body.get("leadership_attestation", {}).get("attestation_id", "").startswith("cpla-")
    assert "release_gate" in ceremony_body
    assert ceremony_body["release_gate"]["marketing_claim_allowed"] is False

    qbr = client.get("/gateway/governance/qbr-snapshot?hours=24", headers=ADMIN)
    assert qbr.status_code == 200, qbr.text
    cpli = qbr.json().get("control_plane_leadership") or {}
    assert cpli.get("score") is not None
    assert cpli.get("marketing_claim_allowed") is False
    assert "release_gate_passed" in cpli
    assert cpli.get("release_gate_evaluations", 0) >= 1
    assert cpli.get("contract_version") == "plane-contract-v2"
    assert "control_ready" in cpli
    assert "control_readonly" in cpli


def test_control_plane_contract_ready_snapshot_and_readonly(monkeypatch):
    from app.services.control_plane_contract import PLANE_CONTRACT_VERSION

    assert PLANE_CONTRACT_VERSION == "plane-contract-v2"
    monkeypatch.delenv("PLANE_CONTROL_READONLY", raising=False)
    # Clear any leftover runtime freeze from prior runs.
    client.post(
        "/platform/control-plane/freeze?enabled=false&reason=test-reset",
        headers=ADMIN,
    )

    reconcile = client.post("/platform/control-plane/reconcile?window_hours=24", headers=ADMIN)
    assert reconcile.status_code == 200, reconcile.text
    body = reconcile.json()
    assert body.get("drift_status") in {
        "none_combined",
        "in_sync",
        "peer_unconfigured",
        "drift_detected",
        "peer_unreachable",
        "published_mismatch",
    }
    if body.get("drift_status") in {"none_combined", "in_sync", "peer_unconfigured"}:
        assert body.get("last_known_good", {}).get("fingerprint")
        assert body["last_known_good"]["contract_version"] == PLANE_CONTRACT_VERSION

    posture = client.get("/platform/control-plane?window_hours=24&probe_peer=false", headers=ADMIN)
    assert posture.status_code == 200, posture.text
    posture_body = posture.json()
    assert posture_body.get("contract", {}).get("contract_version") == PLANE_CONTRACT_VERSION
    assert "desired_observed" in posture_body
    assert "control_readonly" in posture_body
    assert posture_body["desired_observed"]["contract_version"] == PLANE_CONTRACT_VERSION

    live = client.get("/platform/control-plane/live")
    assert live.status_code == 200, live.text
    assert live.json()["alive"] is True
    assert live.json()["contract_version"] == PLANE_CONTRACT_VERSION

    contract = client.get("/platform/control-plane/contract", headers=ADMIN)
    assert contract.status_code == 200, contract.text
    assert contract.json()["contract_version"] == PLANE_CONTRACT_VERSION
    assert contract.json()["capabilities"]["lkg_rollback"] is True
    assert contract.json()["capabilities"]["peer_ack"] is True
    assert contract.json()["marketing_claim_allowed"] is False

    ready = client.get("/platform/control-plane/ready", headers=ADMIN)
    assert ready.status_code in {200, 503}, ready.text
    ready_body = ready.json() if ready.status_code == 200 else ready.json().get("detail")
    assert isinstance(ready_body, dict)
    assert "ready" in ready_body
    assert ready_body.get("alive") is True
    assert ready_body.get("contract_version") == PLANE_CONTRACT_VERSION

    snap = client.get("/platform/control-plane/snapshot", headers=ADMIN)
    assert snap.status_code == 200, snap.text
    snap_body = snap.json()
    assert snap_body["snapshot_id"].startswith("cpsnap-")
    assert snap_body["canonical_sha256"]
    assert snap_body["marketing_claim_allowed"] is False
    assert "desired_observed" in snap_body

    mint = client.post("/platform/control-plane/snapshot", headers=ADMIN)
    assert mint.status_code == 200, mint.text
    assert mint.json()["snapshot_id"].startswith("cpsnap-")
    minted = mint.json()
    assert minted.get("canonical_sha256")
    apply = client.post(
        f"/platform/control-plane/snapshot/apply"
        f"?snapshot_id={minted['snapshot_id']}"
        f"&canonical_sha256={minted['canonical_sha256']}"
        f"&reason=test-apply",
        headers=ADMIN,
    )
    assert apply.status_code == 200, apply.text
    assert apply.json()["ok"] is True
    assert apply.json()["to_fingerprint"]
    assert apply.json()["apply_id"].startswith("cpsap-")
    # Hash required by default
    missing_hash = client.post(
        f"/platform/control-plane/snapshot/apply?snapshot_id={minted['snapshot_id']}&reason=no-hash",
        headers=ADMIN,
    )
    assert missing_hash.status_code == 409, missing_hash.text

    # Runtime freeze (audited) blocks mutations; API can clear it.
    freeze = client.post(
        "/platform/control-plane/freeze?enabled=true&reason=test-freeze",
        headers=ADMIN,
    )
    assert freeze.status_code == 200, freeze.text
    assert freeze.json()["control_readonly"] is True
    blocked = client.post("/platform/control-plane/reconcile?window_hours=24", headers=ADMIN)
    assert blocked.status_code == 403, blocked.text
    assert (blocked.json().get("detail") or {}).get("error_code") == "PLANE_CONTROL_READONLY"
    unfreeze = client.post(
        "/platform/control-plane/freeze?enabled=false&reason=test-unfreeze",
        headers=ADMIN,
    )
    assert unfreeze.status_code == 200, unfreeze.text
    assert unfreeze.json()["control_readonly"] is False

    # Env hard-freeze still works and blocks API unfreeze.
    monkeypatch.setenv("PLANE_CONTROL_READONLY", "true")
    blocked_env = client.post("/platform/control-plane/reconcile?window_hours=24", headers=ADMIN)
    assert blocked_env.status_code == 403, blocked_env.text
    env_unfreeze = client.post(
        "/platform/control-plane/freeze?enabled=false&reason=should-fail",
        headers=ADMIN,
    )
    assert env_unfreeze.status_code == 409, env_unfreeze.text
    monkeypatch.delenv("PLANE_CONTROL_READONLY", raising=False)

    # Ensure LKG exists then rollback + peer ack.
    client.post("/platform/control-plane/reconcile?window_hours=24", headers=ADMIN)
    posture2 = client.get("/platform/control-plane?window_hours=24&probe_peer=false", headers=ADMIN).json()
    published_fp = (posture2.get("published_policy_generation") or {}).get("fingerprint") or (
        posture2.get("last_known_good") or {}
    ).get("fingerprint")
    if published_fp:
        rollback = client.post(
            "/platform/control-plane/rollback-lkg?reason=test-rollback",
            headers=ADMIN,
        )
        assert rollback.status_code == 200, rollback.text
        assert rollback.json()["ok"] is True
        assert rollback.json()["to_fingerprint"]
        ack = client.post(
            f"/platform/control-plane/peer-ack?fingerprint={published_fp}&note=test",
            headers=ADMIN,
        )
        assert ack.status_code == 200, ack.text
        assert ack.json()["ok"] is True
        ack_get = client.get("/platform/control-plane/peer-ack", headers=ADMIN)
        assert ack_get.status_code == 200
        assert "peer_ack" in ack_get.json()

    ops = client.get("/platform/operational-status")
    assert ops.status_code == 200
    cp = ops.json().get("control_plane") or {}
    assert cp.get("contract_version") == PLANE_CONTRACT_VERSION
    assert "ready" in cp
    assert cp.get("alive") is True
    assert cp.get("marketing_claim_allowed") is False


def test_plane_slos_scorecard():
    from app.services.plane_reconcile import build_plane_slos

    slos = build_plane_slos(
        peer={"latency_ms": 50},
        published={"published_at_unix": __import__("time").time()},
        on_plane_coverage={"on_plane_coverage_percent": 95.0},
        drift_status="in_sync",
    )
    assert slos["peer_probe_within_slo"] is True
    assert slos["generation_within_slo"] is True
    assert slos["on_plane_within_slo"] is True
    assert slos["overall_within_slo"] is True


def test_data_plane_fail_closed_middleware(monkeypatch):
    from app.services import plane_reconcile as reconcile

    monkeypatch.setattr(main_mod, "APP_PLANE", "data")
    monkeypatch.setenv("PLANE_FAIL_CLOSED_MODE", "drift")
    reconcile._update_gate_state(drift_status="drift_detected")
    response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]},
        headers=ADMIN,
    )
    assert response.status_code == 503
    detail = response.json().get("detail") or {}
    assert detail.get("error_code") == "PLANE_FAIL_CLOSED"
    monkeypatch.setenv("PLANE_FAIL_CLOSED_MODE", "off")
