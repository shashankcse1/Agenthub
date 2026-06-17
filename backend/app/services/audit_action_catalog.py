from __future__ import annotations

ACTION_DESCRIPTIONS: dict[str, str] = {
    "auth.login.password": "User authenticated with password",
    "auth.session.issue": "Session token issued",
    "auth.session.reauth": "Session re-authenticated",
    "auth.directory.user.create": "Directory user created",
    "auth.directory.user.update": "Directory user updated",
    "auth.directory.user.delete": "Directory user deleted",
    "gateway.assistants.create": "Gateway assistant created",
    "gateway.assistants.update": "Gateway assistant updated",
    "gateway.assistants.delete": "Gateway assistant deleted",
    "gateway.threads.create": "Gateway thread created",
    "gateway.threads.update": "Gateway thread updated",
    "gateway.threads.delete": "Gateway thread deleted",
    "gateway.fine_tuning.create": "Fine-tuning job created",
    "gateway.fine_tuning.cancel": "Fine-tuning job cancelled",
    "gateway.passthrough.execute": "Gateway passthrough request executed",
    "compliance.evidence.export": "Compliance evidence bundle exported",
    "compliance.evidence.generate": "Compliance evidence generated",
    "compliance.evidence.bundle.retrieve": "Compliance evidence bundle retrieved",
    "compliance.controls.mapping.upsert": "Compliance control mapping updated",
    "compliance.retention_policy.upsert": "Compliance retention policy updated",
    "compliance.legal_hold.place": "Compliance legal hold placed",
    "compliance.legal_hold.release": "Compliance legal hold released",
    "orchestration.flow.create": "Orchestration flow created",
    "orchestration.flow.update": "Orchestration flow updated",
    "orchestration.flow.run": "Orchestration flow executed",
    "orchestration.flow.delete": "Orchestration flow deleted",
    "gateway.governance.evidence.export": "Gateway governance evidence exported",
    "gateway.key.create": "Gateway API key created",
    "gateway.key.rotate": "Gateway API key rotated",
    "gateway.route.create": "Gateway route created",
    "playground.run.create": "Playground prompt run executed",
    "playground.compare": "Playground model comparison executed",
    "platform.feedback.create": "Operator feedback submitted",
    "platform.feedback.triage": "Operator feedback triaged",
    "observability.siem_rules.list": "SIEM alert rules catalog listed",
    "observability.siem.alert.dispatch": "SIEM alert dispatched for audit event",
    "observability.siem.alert.unrouted": "SIEM alert could not be routed",
}

PREFIX_ACTION_DESCRIPTIONS: list[tuple[str, str]] = sorted(
    [
        ("gateway.assistants.", "Gateway assistant lifecycle action"),
        ("gateway.threads.", "Gateway thread lifecycle action"),
        ("gateway.fine_tuning.", "Gateway fine-tuning lifecycle action"),
        ("gateway.passthrough.", "Gateway passthrough execution action"),
        ("compliance.", "Compliance governance action"),
        ("orchestration.", "Orchestration workflow action"),
        ("gateway.", "Gateway governance or routing action"),
        ("auth.", "Authentication or directory governance action"),
        ("playground.", "Playground evaluation action"),
        ("platform.", "Platform operator action"),
        ("observability.siem.", "Observability SIEM action"),
    ],
    key=lambda item: len(item[0]),
    reverse=True,
)


def _humanize_action_type(action_type: str) -> str:
    parts = [part.replace("_", " ").strip() for part in action_type.split(".") if part.strip()]
    if not parts:
        return "Unknown action"
    return " ".join(part.title() for part in parts)


def resolve_action_description(action_type: str) -> str:
    normalized = (action_type or "").strip()
    if not normalized:
        return "Unknown action"

    explicit = ACTION_DESCRIPTIONS.get(normalized)
    if explicit:
        return explicit

    for prefix, description in PREFIX_ACTION_DESCRIPTIONS:
        if normalized.startswith(prefix):
            return description

    return _humanize_action_type(normalized)
