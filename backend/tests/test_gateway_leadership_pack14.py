from unittest.mock import MagicMock, patch

from app.services.gateway_leadership_pack14 import (
    checklist_completion_gate,
    close_leadership_incident,
    explain_snippet_from_decision,
    leadership_floor_gate,
    list_auto_route_audit,
    mute_score_trend,
    open_leadership_incident,
    pack14_manifest,
    provider_diversity_score,
    record_auto_route_audit,
    score_trend_with_mute,
)


def test_pack14_manifest_and_explain_snippet():
    assert pack14_manifest()["pack"] == 14
    assert pack14_manifest()["gov"] == "GOV-AI-MARKET-014"
    snippet = explain_snippet_from_decision(
        {
            "selected_model": "gpt-4o-mini",
            "strategy": "balanced",
            "cache_hit": True,
            "complexity": {"tier": "simple"},
        }
    )
    assert "gpt-4o-mini" in snippet
    assert "cache=hit" in snippet


def test_pack14_audit_incidents_and_diversity():
    db = MagicMock()
    stored = {}

    def fake_get(_db, key, default="{}"):
        return stored.get(key, [] if default == "[]" else {})

    def fake_set(_db, key, value, description=""):
        stored[key] = value

    with patch("app.services.gateway_leadership_pack14._rt_get", side_effect=fake_get), patch(
        "app.services.gateway_leadership_pack14._rt_set",
        side_effect=fake_set,
    ), patch(
        "app.services.gateway_leadership_pack14.record_ops_activity",
    ):
        entry = record_auto_route_audit(
            db,
            decision={"selected_model": "m1", "strategy": "cost", "complexity": {"tier": "simple", "score": 9}},
            source="live",
        )
        listed = list_auto_route_audit(db, limit=5)
        incident = open_leadership_incident(db, title="t1", severity="warning")
        closed = close_leadership_incident(db, incident_id=incident["incident_id"])
    assert entry["selected_model"] == "m1"
    assert listed["count"] == 1
    assert closed["closed"] is True

    diversity = provider_diversity_score(
        {
            "tier_candidates": {
                "simple": [
                    {"provider_type": "openai", "model_name": "a"},
                    {"provider_type": "groq", "model_name": "b"},
                ]
            }
        }
    )
    assert diversity["provider_count"] == 2


def test_pack14_floor_gate_mute_checklist():
    db = MagicMock()
    with patch(
        "app.services.gateway_leadership.build_gateway_leadership_index",
        return_value={"score": 82, "band": "market_leader"},
    ):
        gate = leadership_floor_gate(db, floor_score=70)
    assert gate["passed"] is True
    assert gate["decision"] == "go"

    stored = {}

    def fake_get(_db, key, default="{}"):
        return stored.get(key, {})

    def fake_set(_db, key, value, description=""):
        stored[key] = value

    with patch("app.services.gateway_leadership_pack14._rt_get", side_effect=fake_get), patch(
        "app.services.gateway_leadership_pack14._rt_set",
        side_effect=fake_set,
    ), patch(
        "app.services.gateway_leadership_pack14.record_ops_activity",
    ), patch(
        "app.services.gateway_leadership_pack14.detect_score_trend",
        return_value={"alert": True, "scores": [90, 80, 70], "declining_streak": 3, "message": "declining"},
    ):
        mute_score_trend(db, minutes=60, reason="test")
        muted = score_trend_with_mute(db)
    assert muted["muted"] is True
    assert muted["effective_alert"] is False

    with patch(
        "app.services.gateway_leadership_pack14.get_operator_checklist",
        return_value={"completed_count": 3, "total": 6},
    ):
        checklist = checklist_completion_gate(db, min_percent=50)
    assert checklist["passed"] is True
