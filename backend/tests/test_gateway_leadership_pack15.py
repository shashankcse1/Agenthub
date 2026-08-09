from unittest.mock import MagicMock, patch

from app.services.gateway_leadership_pack15 import (
    apply_preferred_model_bias,
    auto_route_audit_summary,
    bulk_close_open_incidents,
    clear_preferred_model_override,
    composite_go_no_go,
    pack15_manifest,
    purge_auto_route_audit,
    unmute_score_trend,
    upsert_preferred_model_override,
)


def test_pack15_manifest_and_preferred_bias():
    assert pack15_manifest()["pack"] == 15
    assert pack15_manifest()["gov"] == "GOV-AI-MARKET-015"
    decision = {
        "complexity": {"tier": "simple"},
        "tier_candidates": {
            "simple": [
                {"model_name": "other", "provider_type": "openai"},
                {"model_name": "gpt-4o-mini", "provider_type": "openai"},
            ]
        },
        "selected_model": "other",
        "rationale": "base",
    }
    biased = apply_preferred_model_bias(
        decision,
        {"enabled": True, "model_name": "gpt-4o-mini", "provider_type": "openai"},
    )
    assert biased["selected_model"] == "gpt-4o-mini"
    assert biased["preferred_model_bias"]["applied"] is True


def test_pack15_composite_and_audit_hygiene():
    db = MagicMock()
    with patch(
        "app.services.gateway_leadership_pack15.leadership_floor_gate",
        return_value={"passed": True, "decision": "go", "score": 80},
    ), patch(
        "app.services.gateway_leadership_pack15.checklist_completion_gate",
        return_value={"passed": True, "completion_percent": 66},
    ), patch(
        "app.services.gateway_leadership_pack15.build_traffic_light",
        return_value={"light": "green", "score": 80},
    ):
        composite = composite_go_no_go(db)
    assert composite["passed"] is True
    assert composite["decision"] == "go"

    stored = {"gateway.leadership.auto_route_audit_json": [
        {"strategy": "balanced", "tier": "simple", "cache_hit": True},
        {"strategy": "cost", "tier": "complex", "cache_hit": False},
        {"strategy": "balanced", "tier": "simple", "cache_hit": True},
    ]}

    def fake_get(_db, key, default="{}"):
        if key in stored:
            return stored[key]
        return [] if default == "[]" else {}

    def fake_set(_db, key, value, description=""):
        stored[key] = value

    with patch("app.services.gateway_leadership_pack15._rt_get", side_effect=fake_get), patch(
        "app.services.gateway_leadership_pack15._rt_set",
        side_effect=fake_set,
    ), patch(
        "app.services.gateway_leadership_pack15.record_ops_activity",
    ), patch(
        "app.services.gateway_leadership_pack15.list_auto_route_audit",
        return_value={"count": 3, "audits": stored["gateway.leadership.auto_route_audit_json"]},
    ):
        summary = auto_route_audit_summary(db)
        purged = purge_auto_route_audit(db, keep=1)
        unmute = unmute_score_trend(db)
    assert summary["cache_hits"] == 2
    assert purged["kept"] == 1
    assert unmute["unmuted"] is True


def test_pack15_preferred_and_bulk_close():
    db = MagicMock()
    stored = {}

    def fake_get(_db, key, default="{}"):
        return stored.get(key, [] if default == "[]" else {})

    def fake_set(_db, key, value, description=""):
        stored[key] = value

    with patch("app.services.gateway_leadership_pack15._rt_get", side_effect=fake_get), patch(
        "app.services.gateway_leadership_pack15._rt_set",
        side_effect=fake_set,
    ), patch(
        "app.services.gateway_leadership_pack15.record_ops_activity",
    ):
        pref = upsert_preferred_model_override(db, model_name="gpt-4o-mini", enabled=True)
        cleared = clear_preferred_model_override(db)
        stored["gateway.leadership.incidents_json"] = [
            {"incident_id": "inc-1", "status": "open"},
            {"incident_id": "inc-2", "status": "open"},
            {"incident_id": "inc-3", "status": "closed"},
        ]
        closed = bulk_close_open_incidents(db, limit=10)
    assert pref["model_name"] == "gpt-4o-mini"
    assert cleared["cleared"] is True
    assert closed["closed_count"] == 2
