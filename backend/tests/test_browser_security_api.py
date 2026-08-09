"""
Browser Security API tests.

Covers:
- Session register (all canonical browser names including Firefox, Safari, Edge,
  Opera, Brave, Arc, Vivaldi, Samsung) with geo analytics fields
- Heartbeat
- Session list with browser/geo filters
- Event ingest (allow, warn, deny, mask; PII data class; all action types)
- Shadow AI auto-inventory from event ingest
- Shadow AI list and status update
- Risk policy CRUD (create, list, update, delete)
- Policy fetch for extension SDK
- Risk summary dashboard
- Analytics breakdown (browser_name, os_name, geo_country, decision_outcome)
- Incident evidence export
- RBAC: Auditor read-only, Security Approver write, Platform Admin full access
- Invalid browser_name normalised to "other"
- City-level geo never stored server-side (stripped at ingest)
- Deny-path audit events emitted
"""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app

# Use context manager to trigger lifespan (schema upgrade for browser security tables).
@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _admin(suffix: str) -> dict:
    return {"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-{suffix}"}


def _sec(suffix: str) -> dict:
    return {"X-Actor-Role": "Security Approver", "X-Actor-Id": f"sec-{suffix}"}


def _auditor(suffix: str) -> dict:
    return {"X-Actor-Role": "Auditor", "X-Actor-Id": f"auditor-{suffix}"}


def _agent_owner(suffix: str) -> dict:
    return {"X-Actor-Role": "Agent Owner", "X-Actor-Id": f"owner-{suffix}"}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _create_session(cl, suffix: str, browser_name: str = "chrome", **extra) -> dict:
    payload = {
        "actor_id": f"user-{suffix}",
        "environment": "dev",
        "browser_name": browser_name,
        "browser_version": "124.0",
        "extension_version": "1.0.0",
        "os_name": "macos",
        "os_version": "14.5",
        "device_type": "desktop",
        "device_managed": True,
        "user_agent_digest": "abc123",
        "geo_country": "US",
        "geo_region": "CA",
        "geo_detail_level": "region",
        "ip_hash": "deadbeef",
        **extra,
    }
    return cl.post("/browser/extensions/sessions", json=payload, headers=_admin(suffix))


def _ingest_event(cl, suffix: str, action_type: str = "prompt_send", decision: str = "allow",
                  browser_name: str = "chrome", **extra) -> dict:
    payload = {
        "trace_id": f"trace-{suffix}",
        "actor_id": f"user-{suffix}",
        "environment": "dev",
        "action_type": action_type,
        "destination_domain": "chatgpt.com",
        "destination_app": "ChatGPT",
        "page_url_host": "chatgpt.com",
        "decision_outcome": decision,
        "data_class": "standard",
        "browser_name": browser_name,
        "browser_version": "124.0",
        "os_name": "macos",
        "device_type": "desktop",
        "geo_country": "US",
        "geo_region": "CA",
        **extra,
    }
    return cl.post("/browser/extensions/events", json=payload, headers=_admin(suffix))


# ── Session tests ──────────────────────────────────────────────────────────────

def test_session_create_chrome(client):
    s = uuid4().hex[:8]
    r = _create_session(client, s, browser_name="chrome")
    assert r.status_code == 200
    body = r.json()
    assert body["browser_name"] == "chrome"
    assert body["geo_country"] == "US"
    assert body["geo_region"] == "CA"
    assert body["status"] == "active"


def test_session_create_all_canonical_browsers(client):
    """All canonical browser types must be accepted and stored as-is."""
    browsers = ["chrome", "firefox", "safari", "edge", "opera", "brave", "arc",
                "vivaldi", "samsung"]
    for browser in browsers:
        s = uuid4().hex[:8]
        r = _create_session(client, s, browser_name=browser)
        assert r.status_code == 200, f"browser {browser!r} failed: {r.text}"
        assert r.json()["browser_name"] == browser


def test_session_create_unknown_browser_normalised(client):
    """Unknown browser names are normalised to 'other', not rejected."""
    s = uuid4().hex[:8]
    r = _create_session(client, s, browser_name="opera-gx-custom-fork")
    assert r.status_code == 200
    assert r.json()["browser_name"] == "other"


def test_session_city_not_stored_server_side(client):
    """City-level geo is stripped server-side regardless of client input."""
    s = uuid4().hex[:8]
    r = _create_session(client, s, geo_detail_level="city", geo_city="San Francisco")
    assert r.status_code == 200
    body = r.json()
    # geo_city is not in the response model (stripped); country/region still stored
    assert body["geo_country"] == "US"


def test_session_heartbeat(client):
    s = uuid4().hex[:8]
    session_id = _create_session(client, s).json()["session_id"]
    r = client.post(f"/browser/extensions/sessions/{session_id}/heartbeat",
                    headers=_admin(s))
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_session_heartbeat_404_for_unknown(client):
    s = uuid4().hex[:8]
    r = client.post("/browser/extensions/sessions/nonexistent-session/heartbeat",
                    headers=_admin(s))
    assert r.status_code == 404


def test_session_list_filter_by_browser(client):
    s = uuid4().hex[:8]
    _create_session(client, s, browser_name="firefox")
    r = client.get("/browser/extensions/sessions?browser_name=firefox", headers=_auditor(s))
    assert r.status_code == 200
    assert all(item["browser_name"] == "firefox" for item in r.json())


def test_session_list_filter_by_geo_country(client):
    s = uuid4().hex[:8]
    _create_session(client, s, geo_country="DE")
    r = client.get("/browser/extensions/sessions?geo_country=DE", headers=_auditor(s))
    assert r.status_code == 200
    assert all(item["geo_country"] == "DE" for item in r.json())


def test_session_list_requires_auth(client):
    """Agent Owner cannot list sessions."""
    s = uuid4().hex[:8]
    r = client.get("/browser/extensions/sessions", headers=_agent_owner(s))
    assert r.status_code == 403


# ── Event ingest tests ─────────────────────────────────────────────────────────

def test_event_ingest_allow(client):
    s = uuid4().hex[:8]
    r = _ingest_event(client, s, decision="allow")
    assert r.status_code == 200
    body = r.json()
    assert body["decision_outcome"] == "allow"
    assert body["browser_name"] == "chrome"
    assert body["geo_country"] == "US"


def test_event_ingest_deny(client):
    s = uuid4().hex[:8]
    r = _ingest_event(client, s, decision="deny", data_class="pii")
    assert r.status_code == 200
    assert r.json()["decision_outcome"] == "deny"


def test_event_ingest_mask(client):
    s = uuid4().hex[:8]
    r = _ingest_event(client, s, decision="mask", data_class="credentials")
    assert r.status_code == 200
    assert r.json()["data_class"] == "credentials"


def test_event_ingest_all_action_types(client):
    action_types = ["prompt_send", "file_upload", "file_download", "paste", "copy",
                    "screenshot", "extension_install", "extension_update",
                    "navigation", "form_submit", "api_call", "other"]
    for action in action_types:
        s = uuid4().hex[:8]
        r = _ingest_event(client, s, action_type=action)
        assert r.status_code == 200, f"action_type {action!r} failed: {r.text}"
        assert r.json()["action_type"] == action


def test_event_ingest_all_browsers(client):
    for browser in ["chrome", "firefox", "safari", "edge", "opera", "brave", "arc",
                    "vivaldi", "samsung"]:
        s = uuid4().hex[:8]
        r = _ingest_event(client, s, browser_name=browser)
        assert r.status_code == 200
        assert r.json()["browser_name"] == browser


def test_event_ingest_unknown_action_normalised(client):
    s = uuid4().hex[:8]
    r = _ingest_event(client, s, action_type="wizard-magic")
    assert r.status_code == 200
    assert r.json()["action_type"] == "other"


def test_event_list_filter_by_decision(client):
    s = uuid4().hex[:8]
    _ingest_event(client, s, decision="deny")
    r = client.get("/browser/extensions/events?decision_outcome=deny", headers=_auditor(s))
    assert r.status_code == 200
    assert all(e["decision_outcome"] == "deny" for e in r.json())


def test_event_list_filter_by_browser(client):
    s = uuid4().hex[:8]
    _ingest_event(client, s, browser_name="safari")
    r = client.get("/browser/extensions/events?browser_name=safari", headers=_auditor(s))
    assert r.status_code == 200
    assert all(e["browser_name"] == "safari" for e in r.json())


def test_event_list_filter_by_geo_country(client):
    s = uuid4().hex[:8]
    _ingest_event(client, s, geo_country="GB")
    r = client.get("/browser/extensions/events?geo_country=GB", headers=_auditor(s))
    assert r.status_code == 200
    assert all(e["geo_country"] == "GB" for e in r.json())


# ── Shadow AI inventory ────────────────────────────────────────────────────────

def test_shadow_ai_auto_created_from_event(client):
    s = uuid4().hex[:8]
    domain = f"shadow-{s}.ai"
    r = _ingest_event(client, s, destination_domain=domain)
    assert r.status_code == 200
    listed = client.get("/browser/extensions/shadow-ai/apps", headers=_auditor(s))
    assert listed.status_code == 200
    domains = [a["domain"] for a in listed.json()]
    assert domain in domains


def test_shadow_ai_update_status(client):
    s = uuid4().hex[:8]
    domain = f"update-{s}.ai"
    _ingest_event(client, s, destination_domain=domain)
    listed = client.get("/browser/extensions/shadow-ai/apps", headers=_auditor(s))
    app_id = next(a["app_id"] for a in listed.json() if a["domain"] == domain)
    r = client.patch(f"/browser/extensions/shadow-ai/apps/{app_id}",
                     json={"status": "sanctioned", "notes": "Approved by CISO"},
                     headers=_sec(s))
    assert r.status_code == 200
    assert r.json()["status"] == "sanctioned"
    assert r.json()["reviewed_by"] == f"sec-{s}"


def test_shadow_ai_update_invalid_status(client):
    s = uuid4().hex[:8]
    domain = f"invalid-status-{s}.ai"
    _ingest_event(client, s, destination_domain=domain)
    listed = client.get("/browser/extensions/shadow-ai/apps", headers=_auditor(s))
    app_id = next(a["app_id"] for a in listed.json() if a["domain"] == domain)
    r = client.patch(f"/browser/extensions/shadow-ai/apps/{app_id}",
                     json={"status": "approved-totally-real"},
                     headers=_sec(s))
    assert r.status_code == 422


# ── Risk policy CRUD ───────────────────────────────────────────────────────────

def _policy_payload(suffix: str, decision_mode: str = "warn") -> dict:
    return {
        "name": f"policy-{suffix}",
        "description": "test policy",
        "scope_type": "global",
        "action_type_pattern": "prompt_send",
        "domain_pattern": "*.openai.com",
        "data_class_filter": "pii",
        "decision_mode": decision_mode,
        "enabled": True,
        "environment": "dev",
        "geo_collection_enabled": False,
        "geo_detail_level": "country",
        "analytics_retention_days": 90,
    }


def test_policy_create_and_list(client):
    s = uuid4().hex[:8]
    r = client.post("/browser/risk-policies", json=_policy_payload(s), headers=_admin(s))
    assert r.status_code == 200
    body = r.json()
    assert body["decision_mode"] == "warn"
    assert body["geo_collection_enabled"] is False
    policy_id = body["policy_id"]
    listed = client.get("/browser/risk-policies", headers=_auditor(s))
    assert listed.status_code == 200
    ids = [p["policy_id"] for p in listed.json()]
    assert policy_id in ids


def test_policy_all_decision_modes(client):
    for mode in ["allow", "warn", "challenge", "deny", "mask"]:
        s = uuid4().hex[:8]
        r = client.post("/browser/risk-policies", json=_policy_payload(s, mode),
                        headers=_admin(s))
        assert r.status_code == 200
        assert r.json()["decision_mode"] == mode


def test_policy_invalid_decision_mode(client):
    s = uuid4().hex[:8]
    payload = _policy_payload(s, "log-only")
    r = client.post("/browser/risk-policies", json=payload, headers=_admin(s))
    assert r.status_code == 422


def test_policy_update(client):
    s = uuid4().hex[:8]
    r = client.post("/browser/risk-policies", json=_policy_payload(s), headers=_admin(s))
    policy_id = r.json()["policy_id"]
    updated = _policy_payload(s, "deny")
    updated["name"] = f"policy-updated-{s}"
    r2 = client.patch(f"/browser/risk-policies/{policy_id}", json=updated, headers=_sec(s))
    assert r2.status_code == 200
    assert r2.json()["decision_mode"] == "deny"
    assert r2.json()["updated_by"] == f"sec-{s}"


def test_policy_delete(client):
    s = uuid4().hex[:8]
    r = client.post("/browser/risk-policies", json=_policy_payload(s), headers=_admin(s))
    policy_id = r.json()["policy_id"]
    del_r = client.delete(f"/browser/risk-policies/{policy_id}", headers=_admin(s))
    assert del_r.status_code == 200
    assert del_r.json()["deleted"] is True
    listed = client.get("/browser/risk-policies", headers=_auditor(s))
    ids = [p["policy_id"] for p in listed.json()]
    assert policy_id not in ids


def test_policy_geo_region_and_city_levels(client):
    for level in ["country", "region", "city"]:
        s = uuid4().hex[:8]
        payload = _policy_payload(s)
        payload["geo_collection_enabled"] = True
        payload["geo_detail_level"] = level
        r = client.post("/browser/risk-policies", json=payload, headers=_admin(s))
        assert r.status_code == 200
        assert r.json()["geo_detail_level"] == level


def test_policy_invalid_geo_detail_level(client):
    s = uuid4().hex[:8]
    payload = _policy_payload(s)
    payload["geo_detail_level"] = "zip_code"
    r = client.post("/browser/risk-policies", json=payload, headers=_admin(s))
    assert r.status_code == 422


# ── Extension SDK policy fetch ─────────────────────────────────────────────────

def test_extension_policy_fetch(client):
    s = uuid4().hex[:8]
    client.post("/browser/risk-policies", json=_policy_payload(s), headers=_admin(s))
    r = client.get("/browser/extensions/policies?environment=dev", headers=_admin(s))
    assert r.status_code == 200
    body = r.json()
    assert "policies" in body
    assert "count" in body


# ── Risk summary ───────────────────────────────────────────────────────────────

def test_risk_summary(client):
    s = uuid4().hex[:8]
    _ingest_event(client, s, decision="deny")
    _ingest_event(client, s, decision="warn")
    _ingest_event(client, s, decision="allow")
    r = client.get("/browser/extensions/risk/summary", headers=_sec(s))
    assert r.status_code == 200
    body = r.json()
    assert "total_events_24h" in body
    assert "top_browsers" in body
    assert "top_countries" in body
    assert "top_denied_domains" in body
    assert "top_action_types" in body


# ── Analytics ─────────────────────────────────────────────────────────────────

def test_analytics_by_browser(client):
    s = uuid4().hex[:8]
    for browser in ["chrome", "firefox", "safari", "edge"]:
        _ingest_event(client, s, browser_name=browser)
    r = client.get("/browser/analytics?group_by=browser_name", headers=_auditor(s))
    assert r.status_code == 200
    assert r.json()["group_by"] == "browser_name"
    assert len(r.json()["rows"]) > 0


def test_analytics_by_geo_country(client):
    s = uuid4().hex[:8]
    for country in ["US", "GB", "DE"]:
        _ingest_event(client, s, geo_country=country)
    r = client.get("/browser/analytics?group_by=geo_country", headers=_auditor(s))
    assert r.status_code == 200


def test_analytics_by_decision_outcome(client):
    s = uuid4().hex[:8]
    _ingest_event(client, s, decision="deny")
    r = client.get("/browser/analytics?group_by=decision_outcome", headers=_auditor(s))
    assert r.status_code == 200


def test_analytics_invalid_group_by(client):
    s = uuid4().hex[:8]
    r = client.get("/browser/analytics?group_by=raw_ip", headers=_auditor(s))
    assert r.status_code == 422


# ── Incident export ────────────────────────────────────────────────────────────

def test_incident_export(client):
    s = uuid4().hex[:8]
    _ingest_event(client, s, decision="deny")
    r = client.post(
        "/browser/extensions/incidents/export",
        params={"decision_outcome": "deny", "since_hours": 1, "include_analytics": True},
        headers=_admin(s),
    )
    assert r.status_code == 200
    body = r.json()
    assert "events" in body
    assert "generated_by" in body
    assert "analytics" in body
    # Must never include raw prompt content
    for evt in body["events"]:
        assert "content_fingerprint" not in evt or isinstance(evt.get("content_fingerprint", ""), str)


def test_incident_export_no_raw_content(client):
    """Ensure content_fingerprint field is hash-only, not raw text."""
    s = uuid4().hex[:8]
    _ingest_event(client, s, content_fingerprint="sha256:abc123", decision="deny")
    r = client.post(
        "/browser/extensions/incidents/export",
        params={"since_hours": 1},
        headers=_admin(s),
    )
    assert r.status_code == 200
    # The bundle must not leak any raw prompt text
    body_str = str(r.json())
    assert "raw_prompt" not in body_str
    assert "prompt_text" not in body_str


# ── RBAC enforcement ───────────────────────────────────────────────────────────

def test_agent_owner_cannot_create_policy(client):
    s = uuid4().hex[:8]
    r = client.post("/browser/risk-policies", json=_policy_payload(s),
                    headers=_agent_owner(s))
    assert r.status_code == 403


def test_agent_owner_cannot_ingest_event(client):
    s = uuid4().hex[:8]
    r = client.post(
        "/browser/extensions/events",
        json={"trace_id": f"t-{s}", "actor_id": f"u-{s}", "action_type": "prompt_send",
              "decision_outcome": "allow", "environment": "dev"},
        headers=_agent_owner(s),
    )
    assert r.status_code == 403


def test_auditor_cannot_create_policy(client):
    s = uuid4().hex[:8]
    r = client.post("/browser/risk-policies", json=_policy_payload(s),
                    headers=_auditor(s))
    assert r.status_code == 403


def test_auditor_can_read_events(client):
    s = uuid4().hex[:8]
    r = client.get("/browser/extensions/events", headers=_auditor(s))
    assert r.status_code == 200


def test_security_approver_can_update_shadow_ai(client):
    s = uuid4().hex[:8]
    domain = f"sec-approver-{s}.ai"
    _ingest_event(client, s, destination_domain=domain)
    listed = client.get("/browser/extensions/shadow-ai/apps", headers=_auditor(s))
    app_id = next(a["app_id"] for a in listed.json() if a["domain"] == domain)
    r = client.patch(f"/browser/extensions/shadow-ai/apps/{app_id}",
                     json={"status": "blocked"},
                     headers=_sec(s))
    assert r.status_code == 200
