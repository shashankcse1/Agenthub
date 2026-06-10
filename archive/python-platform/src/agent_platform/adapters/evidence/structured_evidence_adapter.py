import hmac
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from glob import glob
from hashlib import sha256
from threading import Lock
from typing import List
from urllib.parse import urlparse

from agent_platform.application.ports.evidence_port import EvidencePort
from agent_platform.domain.model.audit_event import AuditEvent
from agent_platform.domain.model.evidence_bundle import EvidenceBundle
from agent_platform.domain.model.policy_decision import PolicyDecision

LOGGER = logging.getLogger("platform.evidence")
SUPPORTED_EVIDENCE_STORAGE_MODES = {"append_jsonl", "worm_json"}


class StructuredEvidenceAdapter(EvidencePort):
    def __init__(self) -> None:
        self._lock = Lock()
        self._storage_mode = os.getenv("EVIDENCE_STORAGE_MODE", "append_jsonl")
        if self._storage_mode not in SUPPORTED_EVIDENCE_STORAGE_MODES:
            raise ValueError(
                f"Unsupported EVIDENCE_STORAGE_MODE '{self._storage_mode}'. "
                f"Supported values: {sorted(SUPPORTED_EVIDENCE_STORAGE_MODES)}"
            )

        default_jsonl_path = f"/tmp/agent_platform_evidence_{os.getpid()}.jsonl"
        configured_path = os.getenv("EVIDENCE_STORE_PATH", default_jsonl_path)

        if self._storage_mode == "worm_json":
            # WORM mode stores each event as a dedicated immutable file.
            self._worm_dir = configured_path
            self._store_path = ""
            os.makedirs(self._worm_dir, exist_ok=True)
        else:
            self._store_path = configured_path
            self._worm_dir = ""
            os.makedirs(os.path.dirname(self._store_path), exist_ok=True)
            if not os.path.exists(self._store_path):
                with open(self._store_path, "a", encoding="utf-8"):
                    pass

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _parse_iso(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _retention_days() -> int:
        raw = os.getenv("EVIDENCE_RETENTION_DAYS", "30")
        try:
            parsed = int(raw)
            return parsed if parsed >= 0 else 30
        except ValueError:
            return 30

    @staticmethod
    def _legal_hold_enabled() -> bool:
        return os.getenv("EVIDENCE_LEGAL_HOLD_ENABLED", "false").lower() == "true"

    @staticmethod
    def _fingerprint(value: str) -> str:
        return sha256(value.encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _target_scope(target: str) -> str:
        parsed = urlparse(target)
        if parsed.scheme and parsed.netloc:
            return parsed.netloc
        return "non-url-target"

    @staticmethod
    def _decision_description(action: str, decision: PolicyDecision, target_scope: str) -> str:
        return (
            f"Policy preview {decision.outcome.value.lower()} decision for action "
            f"'{action}' against scope '{target_scope}'."
        )

    @staticmethod
    def _signature_secret() -> str:
        return os.getenv("AUDIT_SIGNING_SECRET") or os.getenv("JWT_SIGNING_SECRET", "dev-audit-secret")

    @staticmethod
    def _signature_algorithm() -> str:
        return "HMAC-SHA256"

    @classmethod
    def _sign_bundle_payload(cls, payload: str) -> str:
        return hmac.new(
            cls._signature_secret().encode("utf-8"),
            payload.encode("utf-8"),
            digestmod="sha256",
        ).hexdigest()

    @staticmethod
    def _event_payload_for_hash(event_payload: dict) -> dict:
        payload = dict(event_payload)
        payload.pop("event_hash", None)
        payload.pop("prev_event_hash", None)
        return payload

    @classmethod
    def _compute_event_hash(cls, prev_event_hash: str, event_payload: dict) -> str:
        canonical_payload = json.dumps(
            {
                "prev_event_hash": prev_event_hash,
                "event": cls._event_payload_for_hash(event_payload),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(canonical_payload.encode("utf-8")).hexdigest()

    def _append_event(self, event: AuditEvent) -> None:
        payload = json.dumps(event.__dict__, sort_keys=True)
        if self._storage_mode == "worm_json":
            # Use O_EXCL to guarantee write-once semantics for each event artifact.
            filename = f"{event.created_at.replace(':', '-')}_{event.event_hash}.json"
            file_path = os.path.join(self._worm_dir, filename)
            fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload + "\n")
            return

        with open(self._store_path, "a", encoding="utf-8") as fh:
            fh.write(payload + "\n")

    def _load_events(self) -> List[AuditEvent]:
        events: List[AuditEvent] = []
        prev_hash = "GENESIS"

        if self._storage_mode == "worm_json":
            files = sorted(glob(os.path.join(self._worm_dir, "*.json")))
            for file_path in files:
                try:
                    raw = open(file_path, "r", encoding="utf-8").read().strip()
                except OSError:
                    LOGGER.warning("Skipping unreadable WORM event file: %s", file_path)
                    continue
                if not raw:
                    continue
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    LOGGER.warning("Skipping malformed WORM audit event file: %s", file_path)
                    continue
                payload.setdefault("created_at", self._now_iso())
                payload.setdefault("prev_event_hash", prev_hash)
                payload.setdefault("event_hash", self._compute_event_hash(payload["prev_event_hash"], payload))
                try:
                    event = AuditEvent(**payload)
                    events.append(event)
                    prev_hash = event.event_hash
                except TypeError:
                    LOGGER.warning("Skipping incompatible WORM audit event payload: %s", file_path)
            return events

        with open(self._store_path, "r", encoding="utf-8") as fh:
            for line in fh:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    LOGGER.warning("Skipping malformed audit event line in evidence store")
                    continue
                payload.setdefault("created_at", self._now_iso())
                payload.setdefault("prev_event_hash", prev_hash)
                payload.setdefault("event_hash", self._compute_event_hash(payload["prev_event_hash"], payload))
                try:
                    event = AuditEvent(**payload)
                    events.append(event)
                    prev_hash = event.event_hash
                except TypeError:
                    LOGGER.warning("Skipping incompatible audit event payload in evidence store")
        return events

    def _apply_retention(self, events: List[AuditEvent]) -> List[AuditEvent]:
        if self._legal_hold_enabled():
            return events
        retention_days = self._retention_days()
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        return [event for event in events if self._parse_iso(event.created_at) >= cutoff]

    def write_decision_evidence(
        self,
        trace_id: str,
        actor_id: str,
        tenant_id: str,
        action: str,
        target: str,
        decision: PolicyDecision,
    ) -> None:
        actor_fingerprint = self._fingerprint(actor_id)
        target_fingerprint = self._fingerprint(target)
        target_scope = self._target_scope(target)
        decision_description = self._decision_description(action, decision, target_scope)

        with self._lock:
            last_events = self._load_events()
            prev_hash = last_events[-1].event_hash if last_events else "GENESIS"
            event_payload = {
                "created_at": self._now_iso(),
                "prev_event_hash": prev_hash,
                "event_hash": "",
                "event_type": "policy.preview",
                "decision_description": decision_description,
                "trace_id": trace_id,
                "actor_fingerprint": actor_fingerprint,
                "tenant_id": tenant_id,
                "action": action,
                "target_scope": target_scope,
                "target_fingerprint": target_fingerprint,
                "outcome": decision.outcome.value,
                "reason": decision.reason,
                "policy_trace_id": decision.policy_trace_id,
                "policy_version": decision.policy_version,
                "pii_redaction": "enabled",
            }
            event_payload["event_hash"] = self._compute_event_hash(prev_hash, event_payload)
            event = AuditEvent(**event_payload)
            self._append_event(event)

        LOGGER.info(
            "audit_event=policy.preview decision_description=%s trace_id=%s actor_fingerprint=%s tenant_id=%s action=%s target_scope=%s target_fingerprint=%s outcome=%s reason=%s policy_trace_id=%s policy_version=%s pii_redaction=enabled",
            decision_description,
            trace_id,
            actor_fingerprint,
            tenant_id,
            action,
            target_scope,
            target_fingerprint,
            decision.outcome.value,
            decision.reason,
            decision.policy_trace_id,
            decision.policy_version,
        )

    def list_audit_events(self, limit: int = 100) -> List[AuditEvent]:
        with self._lock:
            events = self._apply_retention(self._load_events())
            return list(events[-limit:])

    def export_evidence_bundle(
        self,
        exported_by: str,
        exporter_role: str,
        limit: int = 100,
    ) -> EvidenceBundle:
        events = self.list_audit_events(limit=limit)
        chain_head = events[-1].event_hash if events else "GENESIS"
        payload = json.dumps(
            {
                "exported_by": exported_by,
                "exporter_role": exporter_role,
                "event_count": len(events),
                "signature_algorithm": self._signature_algorithm(),
                "chain_head": chain_head,
                "events": [event.__dict__ for event in events],
            },
            sort_keys=True,
        )
        signature = self._sign_bundle_payload(payload)
        return EvidenceBundle(
            exported_by=exported_by,
            exporter_role=exporter_role,
            event_count=len(events),
            signature_algorithm=self._signature_algorithm(),
            chain_head=chain_head,
            signature=signature,
            events=events,
        )

    def verify_evidence_bundle(self, bundle: EvidenceBundle) -> bool:
        if bundle.event_count != len(bundle.events):
            return False

        prev_hash = "GENESIS"
        for event in bundle.events:
            if event.prev_event_hash != prev_hash:
                return False
            expected_event_hash = self._compute_event_hash(event.prev_event_hash, event.__dict__)
            if event.event_hash != expected_event_hash:
                return False
            prev_hash = event.event_hash

        expected_chain_head = bundle.events[-1].event_hash if bundle.events else "GENESIS"
        if bundle.chain_head != expected_chain_head:
            return False

        payload = json.dumps(
            {
                "exported_by": bundle.exported_by,
                "exporter_role": bundle.exporter_role,
                "event_count": bundle.event_count,
                "signature_algorithm": bundle.signature_algorithm,
                "chain_head": bundle.chain_head,
                "events": [event.__dict__ for event in bundle.events],
            },
            sort_keys=True,
        )
        expected_signature = self._sign_bundle_payload(payload)
        return hmac.compare_digest(bundle.signature, expected_signature)
