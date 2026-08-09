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
    "gateway.nhi.export": "Gateway NHI inventory exported for IGA correlation",
    "gateway.nhi.iga_export.config.update": "Gateway NHI IGA export webhook config updated",
    "gateway.nhi.iga_export.test": "Gateway NHI IGA export test delivery executed",
    "gateway.nhi.iga_export.deliver": "Gateway NHI IGA export delivered to webhook",
    "gateway.nhi.iga_deny.config.update": "Gateway NHI IGA deny-signal config updated",
    "gateway.nhi.iga_deny.ingest": "Gateway NHI IGA deny signal ingested",
    "gateway.nhi.iga_deny.revoke": "Gateway NHI IGA deny signal revoked",
    "gateway.nhi.iga_deny.enforce": "Gateway NHI IGA deny signal enforced on inference",
    "gateway.nhi.iga_deny.evaluate": "Gateway NHI IGA deny signal evaluated",
    "gateway.nhi.iga_deny.events.read": "Gateway NHI IGA deny event history read",
    "gateway.nhi.insights.read": "Gateway NHI insights risk ranking read",
    "gateway.nhi.access_map.read": "Gateway NHI access map read",
    "gateway.nhi.timeline.read": "Gateway NHI activity timeline read",
    "gateway.nhi.owner.update": "Gateway NHI owner assigned",
    "gateway.nhi.lifecycle.update": "Gateway NHI lifecycle transition applied",
    "gateway.nhi.intents.update": "Gateway NHI approved intents updated",
    "gateway.nhi.intent_check": "Gateway NHI intent-check evaluated",
    "gateway.nhi.governance.config.update": "Gateway NHI intent governance config updated",
    "gateway.nhi.correlation.update": "Gateway NHI IGA correlation identifiers updated",
    "gateway.nhi.correlation.ingest": "Gateway NHI IGA correlation identifiers ingested",
    "gateway.nhi.evidence.export": "Gateway NHI coexistence evidence pack exported",
    "gateway.nhi.orphans.read": "Gateway NHI orphan remediation queue read",
    "gateway.nhi.orphans.assign": "Gateway NHI orphan bulk owner assign applied",
    "gateway.nhi.agents.read": "Gateway NHI unified agent inventory read",
    "gateway.nhi.access.config.update": "Gateway NHI IARA-lite access policies updated",
    "gateway.nhi.access.authorize": "Gateway NHI IARA-lite access authorize evaluated",
    "gateway.nhi.shadow.action": "Gateway NHI shadow AI sanction/block/review applied",
    "gateway.nhi.gate_events.read": "Gateway NHI native intent/access gate events read",
    "gateway.key.create": "Gateway API key created",
    "gateway.key.rotate": "Gateway API key rotated",
    "gateway.jit.request.create": "Gateway JIT access request created",
    "gateway.jit.request.approve": "Gateway JIT access request approved",
    "gateway.jit.request.deny": "Gateway JIT access request denied",
    "gateway.jit.request.revoke": "Gateway JIT access grant revoked",
    "gateway.jit.request.expire": "Gateway JIT access grant expired",
    "gateway.jit.request.read": "Gateway JIT access request read",
    "gateway.jit.decision_notify.config.update": "Gateway JIT email/external REST decision notify config updated",
    "gateway.jit.decision_notify.send": "Gateway JIT decision notification sent",
    "gateway.jit.decision_notify.action": "Gateway JIT approve/deny applied via email action token",
    "gateway.jit.decision_notify.test": "Gateway JIT decision notify test delivery executed",
    "gateway.jit.decision_notify.key_email": "Gateway JIT minted virtual key emailed to decision recipients",
    "gateway.jit.decision_notify.preview": "Gateway JIT email action links previewed",
    "gateway.jit.decision_notify.retry": "Gateway JIT failed webhook deliveries retried",
    "gateway.jit.decision_notify.history": "Gateway JIT notify delivery history read",
    "gateway.jit.decision_notify.tick": "Gateway JIT notify SLA reminder/escalation tick executed",
    "gateway.jit.decision_notify.pending_summary": "Gateway JIT pending notify summary read",
    "gateway.jit.virtual_key.mint": "Short-lived virtual key minted for approved JIT grant",
    "gateway.jit.virtual_key.revoke": "JIT-linked virtual key revoked after grant expiry",
    "gateway.jit.request.revoke": "Gateway JIT access grant revoked",
    "gateway.jit.request.expire": "Gateway JIT access grant expired by tick",
    "gateway.jit.request.read": "Gateway JIT access request read",
    "gateway.route.create": "Gateway route created",
    "gateway.best_practices.leadership_bootstrap": "Best-practices leadership posture bootstrap applied",
    "playground.run.create": "Playground prompt run executed",
    "playground.compare": "Playground model comparison executed",
    "platform.feedback.create": "Operator feedback submitted",
    "platform.feedback.triage": "Operator feedback triaged",
    "platform.plane.route_rejected": "Cross-plane route rejected by APP_PLANE isolation",
    "platform.plane.reconcile": "Control/data plane reconcile forced by operator",
    "platform.plane.attest": "Control plane leadership posture attested",
    "platform.plane.release_gate_evaluate": "Control plane engineering release gate evaluated",
    "platform.plane.evidence_pack": "Control plane engineering evidence pack minted",
    "platform.plane.snapshot": "Control plane desired/observed snapshot minted",
    "platform.plane.snapshot_apply": "Control plane snapshot fence applied",
    "platform.plane.freeze": "Control plane change freeze toggled",
    "platform.plane.rollback_lkg": "Control plane published fence rolled back to last-known-good",
    "platform.plane.peer_ack": "Control plane peer ack of published fingerprint recorded",
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
