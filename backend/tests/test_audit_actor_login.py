from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import AuditEvent, DirectoryUser
from app.request_context import clear_request_actor, set_request_actor
from app.services.audit import create_audit_event, serialize_audit_event
from app.services.audit_action_catalog import resolve_action_description

client = TestClient(app)


def _admin_headers(actor_id: str) -> dict[str, str]:
    return {
        "X-Actor-Role": "Master Admin",
        "X-Actor-Id": actor_id,
        "X-MFA-Verified": "true",
    }


def test_create_audit_event_persists_actor_login_from_directory_user():
    suffix = uuid4().hex[:8]
    actor_id = f"audit-login-{suffix}"
    email = f"{actor_id}@example.com"
    trace_id = f"trace-audit-login-{suffix}"

    created = client.post(
        "/auth/directory/users",
        json={
            "user_id": actor_id,
            "display_name": "Audit Login User",
            "email": email,
            "role_name": "Platform Admin",
            "status": "active",
            "password": "StrongPass!234",
        },
        headers=_admin_headers(f"master-{suffix}"),
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        event = create_audit_event(
            db,
            actor_id=actor_id,
            action_type="test.audit.actor_login",
            resource_type="directory_user",
            resource_id=actor_id,
            trace_id=trace_id,
        )
        db.commit()
        assert event.actor_login == email

        stored = db.query(AuditEvent).filter_by(trace_id=trace_id).one()
        assert stored.actor_login == email
    finally:
        db.close()


def test_create_audit_event_uses_request_context_user_login():
    suffix = uuid4().hex[:8]
    actor_id = f"ctx-login-{suffix}"
    user_login = f"{actor_id}@example.com"
    trace_id = f"trace-ctx-login-{suffix}"

    set_request_actor(actor_id, user_login)
    db = SessionLocal()
    try:
        event = create_audit_event(
            db,
            actor_id=actor_id,
            action_type="test.audit.context_login",
            resource_type="directory_user",
            resource_id=actor_id,
            trace_id=trace_id,
        )
        db.commit()
        assert event.actor_login == user_login
    finally:
        clear_request_actor()
        db.close()


def test_audit_events_api_returns_actor_login():
    suffix = uuid4().hex[:8]
    actor_id = f"api-login-{suffix}"
    email = f"{actor_id}@example.com"
    trace_id = f"trace-api-login-{suffix}"

    created = client.post(
        "/auth/directory/users",
        json={
            "user_id": actor_id,
            "display_name": "Audit API User",
            "email": email,
            "role_name": "Platform Admin",
            "status": "active",
            "password": "StrongPass!234",
        },
        headers=_admin_headers(f"master-api-{suffix}"),
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type="test.audit.api_login",
            resource_type="directory_user",
            resource_id=actor_id,
            trace_id=trace_id,
        )
        db.commit()
    finally:
        db.close()

    response = client.get(
        f"/audit/events?action_type=test.audit.api_login&resource_id={actor_id}",
        headers=_admin_headers(f"auditor-{suffix}"),
    )
    assert response.status_code == 200
    rows = [row for row in response.json() if row["trace_id"] == trace_id]
    assert rows
    assert rows[0]["actor_login"] == email


def test_password_login_audit_event_includes_actor_login():
    suffix = uuid4().hex[:8]
    user_id = f"login-user-{suffix}"
    email = f"{user_id}@example.com"

    created = client.post(
        "/auth/directory/users",
        json={
            "user_id": user_id,
            "display_name": "Login Audit User",
            "email": email,
            "role_name": "Platform Admin",
            "status": "active",
            "password": "StrongPass!234",
        },
        headers=_admin_headers(f"master-login-{suffix}"),
    )
    assert created.status_code == 200

    login = client.post(
        "/auth/login",
        json={"username": user_id, "password": "StrongPass!234"},
    )
    assert login.status_code == 200

    db = SessionLocal()
    try:
        events = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.action_type == "auth.login.password",
                AuditEvent.resource_id == user_id,
                AuditEvent.decision_outcome == "allow",
            )
            .order_by(AuditEvent.timestamp.desc())
            .all()
        )
        assert events
        assert events[0].actor_login == email
    finally:
        db.close()


def test_create_audit_event_persists_user_prompt_in_action_context():
    suffix = uuid4().hex[:8]
    actor_id = f"prompt-audit-{suffix}"
    trace_id = f"trace-prompt-audit-{suffix}"
    prompt_text = "Summarize the customer escalation for ticket 12345"

    db = SessionLocal()
    try:
        event = create_audit_event(
            db,
            actor_id=actor_id,
            action_type="test.audit.user_prompt",
            resource_type="playground_run",
            resource_id=f"run-{suffix}",
            trace_id=trace_id,
            user_login=f"{actor_id}@example.com",
            action_context={"user_prompt": prompt_text, "selected_model": "gpt-4o-mini"},
        )
        db.commit()
        assert event.action_context_json
        assert prompt_text in event.action_context_json

        response = client.get(
            f"/audit/events?action_type=test.audit.user_prompt&resource_id=run-{suffix}",
            headers=_admin_headers(f"auditor-prompt-{suffix}"),
        )
        assert response.status_code == 200
        rows = [row for row in response.json() if row["trace_id"] == trace_id]
        assert rows
        assert rows[0]["user_prompt"] == prompt_text
        assert rows[0]["action_context"]["selected_model"] == "gpt-4o-mini"
    finally:
        db.close()


def test_sanitize_fields_fingerprints_user_login():
    from app.logging_utils import sanitize_fields

    sanitized = sanitize_fields({"user_login": "operator@example.com"})
    assert sanitized["user_login"].startswith("fp:")
    assert "operator@example.com" not in str(sanitized["user_login"])


def test_create_audit_event_persists_actor_role_and_action_description():
    suffix = uuid4().hex[:8]
    actor_id = f"audit-role-{suffix}"
    email = f"{actor_id}@example.com"
    trace_id = f"trace-audit-role-{suffix}"
    action_type = "test.audit.actor_role"

    created = client.post(
        "/auth/directory/users",
        json={
            "user_id": actor_id,
            "display_name": "Audit Role User",
            "email": email,
            "role_name": "Platform Admin",
            "status": "active",
            "password": "StrongPass!234",
        },
        headers=_admin_headers(f"master-role-{suffix}"),
    )
    assert created.status_code == 200

    set_request_actor(actor_id, email, "Platform Admin")
    db = SessionLocal()
    try:
        event = create_audit_event(
            db,
            actor_id=actor_id,
            action_type=action_type,
            resource_type="directory_user",
            resource_id=actor_id,
            trace_id=trace_id,
        )
        db.commit()
        assert event.actor_login == email
        assert event.actor_role == "Platform Admin"
        assert event.action_description == resolve_action_description(action_type)

        stored = db.query(AuditEvent).filter_by(trace_id=trace_id).one()
        assert stored.actor_role == "Platform Admin"
        assert stored.action_description == resolve_action_description(action_type)
    finally:
        clear_request_actor()
        db.close()


def test_audit_events_api_returns_all_three_fields():
    suffix = uuid4().hex[:8]
    actor_id = f"api-fields-{suffix}"
    email = f"{actor_id}@example.com"
    trace_id = f"trace-api-fields-{suffix}"
    action_type = "test.audit.api_fields"

    created = client.post(
        "/auth/directory/users",
        json={
            "user_id": actor_id,
            "display_name": "Audit Fields User",
            "email": email,
            "role_name": "Platform Admin",
            "status": "active",
            "password": "StrongPass!234",
        },
        headers=_admin_headers(f"master-fields-{suffix}"),
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type=action_type,
            resource_type="directory_user",
            resource_id=actor_id,
            trace_id=trace_id,
            actor_role="Platform Admin",
        )
        db.commit()
    finally:
        db.close()

    response = client.get(
        f"/audit/events?action_type={action_type}&resource_id={actor_id}",
        headers=_admin_headers(f"auditor-fields-{suffix}"),
    )
    assert response.status_code == 200
    rows = [row for row in response.json() if row["trace_id"] == trace_id]
    assert rows
    assert rows[0]["actor_login"] == email
    assert rows[0]["actor_role"] == "Platform Admin"
    assert rows[0]["action_description"] == resolve_action_description(action_type)


def test_legacy_events_backfill_on_read_via_serialize():
    suffix = uuid4().hex[:8]
    actor_id = f"legacy-{suffix}"
    email = f"{actor_id}@example.com"
    trace_id = f"trace-legacy-{suffix}"
    action_type = "test.audit.legacy_backfill"

    created = client.post(
        "/auth/directory/users",
        json={
            "user_id": actor_id,
            "display_name": "Legacy Audit User",
            "email": email,
            "role_name": "Platform Admin",
            "status": "active",
            "password": "StrongPass!234",
        },
        headers=_admin_headers(f"master-legacy-{suffix}"),
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        legacy = AuditEvent(
            audit_event_id=f"legacy-{suffix}",
            actor_type="user",
            actor_id=actor_id,
            actor_login=None,
            actor_role=None,
            action_description=None,
            action_type=action_type,
            resource_type="directory_user",
            resource_id=actor_id,
            trace_id=trace_id,
            decision_outcome="allow",
            policy_version="v1",
        )
        db.add(legacy)
        db.commit()

        serialized = serialize_audit_event(legacy, db)
        assert serialized["actor_login"] == email
        assert serialized["actor_role"] == "Platform Admin"
        assert serialized["action_description"] == resolve_action_description(action_type)
    finally:
        db.close()
