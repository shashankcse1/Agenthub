"""First-party turnkey client for AgentHub AI Gateway (no external product SDKs)."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Optional
from urllib import error, request


def _rid(prefix: str = "req") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _estimate_tokens(text: str) -> int:
    value = str(text or "")
    if not value:
        return 0
    return max(1, (len(value) + 3) // 4)


class AgentHubGateway:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str = "",
        actor_role: str = "AI Ops Approver",
        actor_id: str = "sdk-client",
        environment: str = "dev",
        agent_id: str = "sdk-agent",
        scope_type: str = "agent",
        scope_id: Optional[str] = None,
        track_cost: bool = True,
        timeout_seconds: float = 60.0,
        virtual_key_id: str = "",
        session_id: str = "",
        user: str = "",
        properties: Optional[dict[str, Any]] = None,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = str(base_url).rstrip("/")
        self.api_key = api_key
        self.actor_role = actor_role
        self.actor_id = actor_id
        self.environment = environment
        self.agent_id = agent_id
        self.scope_type = scope_type
        self.scope_id = scope_id or agent_id
        self.track_cost = track_cost
        self.timeout_seconds = timeout_seconds
        self.virtual_key_id = str(virtual_key_id or "").strip()
        self.session_id = str(session_id or "").strip()
        self.user = str(user or "").strip()
        self.properties = properties if isinstance(properties, dict) else {}
        self._stamp_headers = create_gateway_request_instrumenter(
            session_id=self.session_id,
            user=self.user,
            properties=self.properties,
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-Actor-Role": self.actor_role,
            "X-Actor-Id": self.actor_id,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return self._stamp_headers(headers)

    def _post(self, path: str, payload: dict[str, Any], extra_headers: Optional[dict[str, str]] = None) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        headers = self._headers()
        if extra_headers:
            headers.update(extra_headers)
        req = request.Request(f"{self.base_url}{path}", data=body, headers=headers, method="POST")
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gateway request failed ({exc.code}): {detail}") from exc

    def _put(self, path: str, payload: dict[str, Any], extra_headers: Optional[dict[str, str]] = None) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        headers = self._headers()
        if extra_headers:
            headers.update(extra_headers)
        req = request.Request(f"{self.base_url}{path}", data=body, headers=headers, method="PUT")
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gateway request failed ({exc.code}): {detail}") from exc

    def _patch(self, path: str, payload: dict[str, Any], extra_headers: Optional[dict[str, str]] = None) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        headers = self._headers()
        if extra_headers:
            headers.update(extra_headers)
        req = request.Request(f"{self.base_url}{path}", data=body, headers=headers, method="PATCH")
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gateway request failed ({exc.code}): {detail}") from exc

    def _get(self, path: str, extra_headers: Optional[dict[str, str]] = None) -> Any:
        headers = self._headers()
        if extra_headers:
            headers.update(extra_headers)
        req = request.Request(f"{self.base_url}{path}", headers=headers, method="GET")
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gateway request failed ({exc.code}): {detail}") from exc

    def _get_text(self, path: str, extra_headers: Optional[dict[str, str]] = None) -> str:
        headers = self._headers()
        if extra_headers:
            headers.update(extra_headers)
        req = request.Request(f"{self.base_url}{path}", headers=headers, method="GET")
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gateway request failed ({exc.code}): {detail}") from exc

    def _delete(self, path: str, extra_headers: Optional[dict[str, str]] = None) -> Any:
        headers = self._headers()
        if extra_headers:
            headers.update(extra_headers)
        req = request.Request(f"{self.base_url}{path}", headers=headers, method="DELETE")
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gateway request failed ({exc.code}): {detail}") from exc

    def auto_route_classify(
        self,
        prompt_text: str,
        *,
        strategy: str = "balanced",
        prefer_live_only: bool = True,
        refine_with_judge: bool = True,
        use_telemetry_ranking: bool = True,
    ) -> dict[str, Any]:
        """Classify prompt complexity and select a catalog model (Pack 7 SDK helper)."""
        return self._post(
            "/gateway/best-practices/auto-route",
            {
                "prompt_text": str(prompt_text or ""),
                "strategy": strategy,
                "prefer_live_only": prefer_live_only,
                "refine_with_judge": refine_with_judge,
                "use_telemetry_ranking": use_telemetry_ranking,
            },
        )

    def chat_completions(
        self,
        body: dict[str, Any],
        *,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_tag: str = "gateway-sdk",
        user_properties: Optional[dict[str, Any]] = None,
        user: Optional[str] = None,
        properties: Optional[dict[str, Any]] = None,
        virtual_key_id: Optional[str] = None,
        guardrail_id: Optional[str] = None,
        prompt_id: Optional[str] = None,
        prompt_registry_id: Optional[str] = None,
        config_id: Optional[str] = None,
        route_policy_id: Optional[str] = None,
        variables: Optional[dict[str, str]] = None,
        session_path: Optional[str] = None,
        session_name: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        cache_mode: Optional[str] = None,
        auto_route: bool = False,
        auto_route_strategy: str = "balanced",
    ) -> dict[str, Any]:
        request_id = _rid("sdk")
        trace = trace_id or _rid("trace")
        session = session_id or _rid("session")
        model = str(body.get("model") or "gpt-4o-mini")
        request_body = dict(body or {})
        if auto_route or str(request_body.get("auto_route") or "").lower() in {"1", "true", "yes"}:
            request_body["auto_route"] = True
            request_body["auto_route_strategy"] = str(
                auto_route_strategy or request_body.get("auto_route_strategy") or "balanced"
            )
            if str(request_body.get("model") or "").strip().lower() in {"", "auto", "gateway/auto"}:
                request_body["model"] = "auto"
        merged_props: dict[str, Any] = {}
        if isinstance(properties, dict):
            merged_props.update(properties)
        if isinstance(body.get("properties"), dict):
            merged_props.update(body["properties"])  # type: ignore[arg-type]
        if isinstance(user_properties, dict):
            merged_props.update(user_properties)
        if isinstance(body.get("user_properties"), dict):
            merged_props.update(body["user_properties"])  # type: ignore[arg-type]
        if merged_props:
            request_body["user_properties"] = merged_props
            request_body["properties"] = merged_props
        end_user = str(user or body.get("user") or "").strip()
        if end_user:
            request_body["user"] = end_user
        vk = str(
            virtual_key_id
            or guardrail_id
            or body.get("virtual_key_id")
            or body.get("guardrail_id")
            or getattr(self, "virtual_key_id", "")
            or ""
        ).strip()
        if vk:
            request_body["virtual_key_id"] = vk
            request_body["guardrail_id"] = vk
        registry_id = str(
            prompt_id or prompt_registry_id or body.get("prompt_id") or body.get("prompt_registry_id") or ""
        ).strip()
        if registry_id:
            request_body["prompt_id"] = registry_id
            request_body["prompt_registry_id"] = registry_id
        resolved_config = str(
            config_id or route_policy_id or body.get("config_id") or body.get("route_policy_id") or ""
        ).strip()
        if resolved_config:
            request_body["config_id"] = resolved_config
            request_body["route_policy_id"] = resolved_config
        vars_payload = variables if isinstance(variables, dict) else body.get("variables")
        if isinstance(vars_payload, dict) and vars_payload:
            request_body["variables"] = {
                str(k)[:64]: str(v)[:4000] for k, v in list(vars_payload.items())[:64] if str(k or "").strip()
            }
        if not request_body.get("session_id"):
            request_body["session_id"] = session
        path = str(session_path or body.get("session_path") or "").strip()
        if path:
            request_body["session_path"] = path[:256]
        name = str(session_name or body.get("session_name") or "").strip()
        if name:
            request_body["session_name"] = name[:128]
        meta = metadata if isinstance(metadata, dict) else body.get("metadata")
        if isinstance(meta, dict) and meta:
            request_body["metadata"] = {
                str(k)[:64]: (v if isinstance(v, (str, int, float, bool)) or v is None else str(v)[:256])
                for k, v in list(meta.items())[:32]
                if str(k or "").strip()
            }
        mode = str(cache_mode or body.get("cache_mode") or "").strip().lower()
        if mode in {"inherit", "bypass", "force"}:
            request_body["cache_mode"] = mode
        extra_headers = {"X-Request-Id": request_id, "X-Trace-Id": trace}
        if vk:
            extra_headers["X-Virtual-Key-Id"] = vk
        payload = self._post(
            "/v1/chat/completions",
            request_body,
            extra_headers=extra_headers,
        )
        usage = payload.get("usage") or {}
        messages = body.get("messages") or []
        input_tokens = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0) or _estimate_tokens(
            "\n".join(str(m.get("content") or "") for m in messages if isinstance(m, dict))
        )
        content = ""
        choices = payload.get("choices") or []
        if choices and isinstance(choices[0], dict):
            content = str((choices[0].get("message") or {}).get("content") or "")
        output_tokens = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0) or _estimate_tokens(
            content
        )
        cost_event = None
        if self.track_cost:
            try:
                cost_event = self.track_spend(
                    request_id=request_id,
                    trace_id=trace,
                    session_id=session,
                    request_tag=request_tag,
                    model_name=model,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    user_properties=merged_props or None,
                    cache_hit=bool(payload.get("cache_short_circuit")),
                )
            except Exception as exc:  # noqa: BLE001 — instrumentation must not break inference
                cost_event = {"error": str(exc), "ts": time.time()}
        payload["agenthub"] = {
            "request_id": request_id,
            "trace_id": trace,
            "session_id": session,
            "cost_event": cost_event,
            "observability_url": f"{self.base_url}/observability/traces/{trace}",
        }
        return payload

    def responses(
        self,
        body: dict[str, Any],
        *,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_tag: str = "gateway-sdk",
        user_properties: Optional[dict[str, Any]] = None,
        user: Optional[str] = None,
        properties: Optional[dict[str, Any]] = None,
        virtual_key_id: Optional[str] = None,
        guardrail_id: Optional[str] = None,
        prompt_id: Optional[str] = None,
        prompt_registry_id: Optional[str] = None,
        config_id: Optional[str] = None,
        route_policy_id: Optional[str] = None,
        variables: Optional[dict[str, str]] = None,
        session_path: Optional[str] = None,
        session_name: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        cache_mode: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create an OpenAI-compatible Responses API call via the gateway."""
        request_id = _rid("sdk")
        trace = trace_id or _rid("trace")
        session = session_id or _rid("session")
        model = str(body.get("model") or "gpt-4o-mini")
        request_body = dict(body or {})
        merged_props: dict[str, Any] = {}
        if isinstance(properties, dict):
            merged_props.update(properties)
        if isinstance(body.get("properties"), dict):
            merged_props.update(body["properties"])  # type: ignore[arg-type]
        if isinstance(user_properties, dict):
            merged_props.update(user_properties)
        if isinstance(body.get("user_properties"), dict):
            merged_props.update(body["user_properties"])  # type: ignore[arg-type]
        if merged_props:
            request_body["user_properties"] = merged_props
            request_body["properties"] = merged_props
        end_user = str(user or body.get("user") or "").strip()
        if end_user:
            request_body["user"] = end_user
        vk = str(
            virtual_key_id
            or guardrail_id
            or body.get("virtual_key_id")
            or body.get("guardrail_id")
            or getattr(self, "virtual_key_id", "")
            or ""
        ).strip()
        if vk:
            request_body["virtual_key_id"] = vk
            request_body["guardrail_id"] = vk
        registry_id = str(
            prompt_id or prompt_registry_id or body.get("prompt_id") or body.get("prompt_registry_id") or ""
        ).strip()
        if registry_id:
            request_body["prompt_id"] = registry_id
            request_body["prompt_registry_id"] = registry_id
        resolved_config = str(
            config_id or route_policy_id or body.get("config_id") or body.get("route_policy_id") or ""
        ).strip()
        if resolved_config:
            request_body["config_id"] = resolved_config
            request_body["route_policy_id"] = resolved_config
        vars_payload = variables if isinstance(variables, dict) else body.get("variables")
        if isinstance(vars_payload, dict) and vars_payload:
            request_body["variables"] = {
                str(k)[:64]: str(v)[:4000] for k, v in list(vars_payload.items())[:64] if str(k or "").strip()
            }
        if not request_body.get("session_id"):
            request_body["session_id"] = session
        path = str(session_path or body.get("session_path") or "").strip()
        if path:
            request_body["session_path"] = path[:256]
        name = str(session_name or body.get("session_name") or "").strip()
        if name:
            request_body["session_name"] = name[:128]
        # OpenAI Responses metadata is upstream-only; do not treat as Helicone props.
        meta = metadata if isinstance(metadata, dict) else body.get("metadata")
        if isinstance(meta, dict) and meta:
            request_body["metadata"] = {
                str(k)[:64]: (v if isinstance(v, (str, int, float, bool)) or v is None else str(v)[:256])
                for k, v in list(meta.items())[:32]
                if str(k or "").strip()
            }
        mode = str(cache_mode or body.get("cache_mode") or "").strip().lower()
        if mode in {"inherit", "bypass", "force"}:
            request_body["cache_mode"] = mode
        extra_headers = {"X-Request-Id": request_id, "X-Trace-Id": trace}
        if vk:
            extra_headers["X-Virtual-Key-Id"] = vk
        payload = self._post(
            "/v1/responses",
            request_body,
            extra_headers=extra_headers,
        )
        usage = payload.get("usage") or {}
        input_tokens = int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0) or _estimate_tokens(
            str(body.get("input") or "")
        )
        output_tokens = int(usage.get("output_tokens") or usage.get("completion_tokens") or 0) or _estimate_tokens(
            str(payload.get("output_text") or "")
        )
        cost_event = None
        if self.track_cost:
            try:
                cost_props = dict(merged_props)
                if path:
                    cost_props["session_path"] = path[:256]
                if name:
                    cost_props["session_name"] = name[:128]
                cost_event = self.track_spend(
                    request_id=request_id,
                    trace_id=trace,
                    session_id=session,
                    request_tag=request_tag,
                    model_name=model,
                    endpoint_family="responses",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    user_properties=cost_props or None,
                    cache_hit=bool(payload.get("cache_short_circuit")),
                )
            except Exception as exc:  # noqa: BLE001 — instrumentation must not break inference
                cost_event = {"error": str(exc), "ts": time.time()}
        payload["agenthub"] = {
            "request_id": request_id,
            "trace_id": trace,
            "session_id": session,
            "cost_event": cost_event,
            "observability_url": f"{self.base_url}/observability/traces/{trace}",
        }
        return payload

    def list_responses(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        model_contains: Optional[str] = None,
        output_contains: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """OpenAI/Portkey-style responses list (`GET /v1/responses`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 20), 200)),
            "offset": max(0, int(offset or 0)),
        }
        model = str(model_contains or "").strip()
        if model:
            query["model_contains"] = model
        output = str(output_contains or "").strip()
        if output:
            query["output_contains"] = output
        data = self._get(f"/v1/responses?{urlencode(query)}")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def get_response(self, response_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style response get (`GET /v1/responses/{id}`)."""
        rid = str(response_id or "").strip()
        if not rid:
            raise ValueError("response_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/responses/{quote(rid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def delete_response(self, response_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style response delete (`DELETE /v1/responses/{id}`)."""
        rid = str(response_id or "").strip()
        if not rid:
            raise ValueError("response_id is required")
        from urllib.parse import quote

        payload = self._delete(f"/v1/responses/{quote(rid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def track_spend(
        self,
        *,
        request_id: str,
        trace_id: str,
        session_id: str,
        model_name: str,
        request_tag: str = "gateway-sdk",
        endpoint_family: str = "chat.completions",
        input_tokens: int = 0,
        output_tokens: int = 0,
        estimated_cost_cents: int = 0,
        user_properties: Optional[dict[str, Any]] = None,
        cache_hit: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "request_id": request_id,
            "trace_id": trace_id,
            "request_tag": request_tag,
            "session_id": session_id,
            "agent_id": self.agent_id,
            "scope_type": self.scope_type,
            "scope_id": self.scope_id,
            "environment": self.environment,
            "model_name": model_name,
            "endpoint_family": endpoint_family,
            "input_tokens": max(0, int(input_tokens or 0)),
            "output_tokens": max(0, int(output_tokens or 0)),
            "estimated_cost_cents": max(0, int(estimated_cost_cents or 0)),
            "currency": "USD",
            "cache_hit": bool(cache_hit),
        }
        if isinstance(user_properties, dict) and user_properties:
            body["user_properties"] = user_properties
        return self._post("/cost/events", body)

    def submit_feedback(
        self,
        *,
        request_id: str,
        rating: Optional[int] = None,
        scores: Optional[dict[str, float]] = None,
        comment: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Helicone-style feedback attached to cost events by request_id."""
        body: dict[str, Any] = {"request_id": str(request_id or "").strip()}
        if rating is not None:
            body["rating"] = int(rating)
        if isinstance(scores, dict) and scores:
            body["scores"] = scores
        if comment is not None and str(comment).strip():
            body["comment"] = str(comment).strip()[:2048]
        if trace_id:
            body["trace_id"] = str(trace_id).strip()
        return self._post("/v1/feedback", body)

    def get_feedback(
        self,
        *,
        request_id: str,
        trace_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Read Helicone-style feedback previously attached to cost events."""
        from urllib.parse import urlencode

        query = {"request_id": str(request_id or "").strip()}
        if trace_id:
            query["trace_id"] = str(trace_id).strip()
        payload = self._get(f"/v1/feedback?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def list_virtual_keys(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Portkey-style virtual key inventory (`GET /v1/virtual-keys`)."""
        from urllib.parse import urlencode

        query = {
            "limit": max(1, min(int(limit or 50), 500)),
            "offset": max(0, int(offset or 0)),
        }
        data = self._get(f"/v1/virtual-keys?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("items") or data.get("data") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def get_virtual_key(self, key_id: str) -> dict[str, Any]:
        """Portkey-style virtual key get (`GET /v1/virtual-keys/{id}`)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/virtual-keys/{quote(key, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def get_virtual_key_usage(self, key_id: str) -> dict[str, Any]:
        """Portkey-style virtual key usage (`GET /v1/virtual-keys/{id}/usage`)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/virtual-keys/{quote(key, safe='')}/usage")
        return payload if isinstance(payload, dict) else {}

    def create_virtual_key(
        self,
        *,
        owner_scope_type: str,
        owner_scope_id: str,
        allowed_endpoint_families: str = "[]",
        allowed_models: str = "[]",
        guardrail_policy: str = "{}",
        budget_policy_id: str = "default",
        rate_limit_policy_id: str = "default",
        expires_at: Optional[str] = None,
        authn_method: str = "token",
    ) -> dict[str, Any]:
        """Portkey-style virtual key create (`POST /keys`; never returns secret material)."""
        body: dict[str, Any] = {
            "owner_scope_type": str(owner_scope_type or "").strip(),
            "owner_scope_id": str(owner_scope_id or "").strip(),
            "allowed_endpoint_families": str(allowed_endpoint_families or "[]"),
            "allowed_models": str(allowed_models or "[]"),
            "guardrail_policy": str(guardrail_policy or "{}"),
            "budget_policy_id": str(budget_policy_id or "default").strip() or "default",
            "rate_limit_policy_id": str(rate_limit_policy_id or "default").strip() or "default",
            "authn_method": str(authn_method or "token").strip() or "token",
        }
        if expires_at is not None:
            body["expires_at"] = str(expires_at).strip() or None
        payload = self._post("/keys", body)
        return payload if isinstance(payload, dict) else {}

    def update_virtual_key(
        self,
        key_id: str,
        *,
        allowed_endpoint_families: Optional[str] = None,
        allowed_models: Optional[str] = None,
        guardrail_policy: Optional[str] = None,
        status: Optional[str] = None,
        budget_policy_id: Optional[str] = None,
        rate_limit_policy_id: Optional[str] = None,
        expires_at: Optional[str] = None,
        authn_method: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style virtual key update (`PATCH /keys/{id}`; never returns secret material)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {}
        if allowed_endpoint_families is not None:
            body["allowed_endpoint_families"] = str(allowed_endpoint_families)
        if allowed_models is not None:
            body["allowed_models"] = str(allowed_models)
        if guardrail_policy is not None:
            body["guardrail_policy"] = str(guardrail_policy)
        if status is not None:
            body["status"] = str(status).strip()
        if budget_policy_id is not None:
            body["budget_policy_id"] = str(budget_policy_id).strip() or "default"
        if rate_limit_policy_id is not None:
            body["rate_limit_policy_id"] = str(rate_limit_policy_id).strip() or "default"
        if expires_at is not None:
            body["expires_at"] = str(expires_at).strip() or None
        if authn_method is not None:
            body["authn_method"] = str(authn_method).strip() or "token"
        payload = self._patch(f"/keys/{quote(key, safe='')}", body)
        return payload if isinstance(payload, dict) else {}

    def evaluate_key_guardrails(
        self,
        key_id: str,
        *,
        environment: str = "dev",
        stage: str = "input",
        policy_mode: str = "block",
        requests_last_minute: int = 0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        owner_scope_id: Optional[str] = None,
        mfa_verified: bool = False,
    ) -> dict[str, Any]:
        """Portkey-style virtual key guardrail evaluate (`POST /keys/{id}/guardrails/evaluate`)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "environment": str(environment or "dev").strip() or "dev",
            "stage": str(stage or "input").strip() or "input",
            "policy_mode": str(policy_mode or "block").strip() or "block",
            "requests_last_minute": max(0, int(requests_last_minute or 0)),
            "input_tokens": max(0, int(input_tokens or 0)),
            "output_tokens": max(0, int(output_tokens or 0)),
            "mfa_verified": bool(mfa_verified),
        }
        if owner_scope_id is not None:
            body["owner_scope_id"] = str(owner_scope_id).strip() or None
        payload = self._post(f"/keys/{quote(key, safe='')}/guardrails/evaluate", body)
        return payload if isinstance(payload, dict) else {}

    def create_key_rotation_schedule(
        self,
        key_id: str,
        *,
        environment: str = "dev",
        interval_hours: int = 24,
        enabled: bool = True,
        reason: str = "scheduled-rotation",
    ) -> dict[str, Any]:
        """Portkey-style virtual key rotation schedule create (`POST /keys/{id}/rotation-schedules`)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote

        body = {
            "environment": str(environment or "dev").strip() or "dev",
            "interval_hours": max(1, min(int(interval_hours or 24), 720)),
            "enabled": bool(enabled),
            "reason": str(reason or "scheduled-rotation").strip() or "scheduled-rotation",
        }
        payload = self._post(f"/keys/{quote(key, safe='')}/rotation-schedules", body)
        return payload if isinstance(payload, dict) else {}

    def list_key_rotation_schedules(self, key_id: str) -> list[dict[str, Any]]:
        """Portkey-style virtual key rotation schedule list (`GET /keys/{id}/rotation-schedules`)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote

        data = self._get(f"/keys/{quote(key, safe='')}/rotation-schedules")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def update_key_rotation_schedule(
        self,
        key_id: str,
        schedule_id: str,
        *,
        interval_hours: Optional[int] = None,
        enabled: Optional[bool] = None,
        reason: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style virtual key rotation schedule update (`PATCH /keys/{id}/rotation-schedules/{schedule_id}`)."""
        key = str(key_id or "").strip()
        sid = str(schedule_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        if not sid:
            raise ValueError("schedule_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {}
        if interval_hours is not None:
            body["interval_hours"] = max(1, min(int(interval_hours), 720))
        if enabled is not None:
            body["enabled"] = bool(enabled)
        if reason is not None:
            body["reason"] = str(reason).strip() or "scheduled-rotation"
        payload = self._patch(
            f"/keys/{quote(key, safe='')}/rotation-schedules/{quote(sid, safe='')}",
            body,
        )
        return payload if isinstance(payload, dict) else {}

    def execute_key_rotation_schedule_now(self, key_id: str, schedule_id: str) -> dict[str, Any]:
        """Portkey-style virtual key rotation execute-now (`POST .../execute-now`)."""
        key = str(key_id or "").strip()
        sid = str(schedule_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        if not sid:
            raise ValueError("schedule_id is required")
        from urllib.parse import quote

        payload = self._post(
            f"/keys/{quote(key, safe='')}/rotation-schedules/{quote(sid, safe='')}/execute-now",
            {},
        )
        return payload if isinstance(payload, dict) else {}

    def tick_key_rotation_schedules(self, *, include_prod: bool = False) -> dict[str, Any]:
        """Advance due virtual-key rotation schedules (`POST /keys/rotation-schedules/tick`)."""
        from urllib.parse import urlencode

        query = urlencode({"include_prod": "true" if include_prod else "false"})
        payload = self._post(f"/keys/rotation-schedules/tick?{query}", {})
        return payload if isinstance(payload, dict) else {}

    def block_virtual_key(self, key_id: str) -> dict[str, Any]:
        """Portkey-style virtual key block (`POST /keys/{id}/block`)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote

        payload = self._post(f"/keys/{quote(key, safe='')}/block", {})
        return payload if isinstance(payload, dict) else {}

    def unblock_virtual_key(self, key_id: str) -> dict[str, Any]:
        """Portkey-style virtual key unblock (`POST /keys/{id}/unblock`)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote

        payload = self._post(f"/keys/{quote(key, safe='')}/unblock", {})
        return payload if isinstance(payload, dict) else {}

    def rotate_virtual_key(self, key_id: str, *, environment: str = "dev") -> dict[str, Any]:
        """Portkey-style virtual key rotate (`POST /keys/{id}/rotate`)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote, urlencode

        query = urlencode({"environment": str(environment or "dev").strip() or "dev"})
        payload = self._post(f"/keys/{quote(key, safe='')}/rotate?{query}", {})
        return payload if isinstance(payload, dict) else {}

    def increase_key_budget_temporary(
        self,
        key_id: str,
        *,
        increase_cents: int,
        environment: str = "dev",
        duration_minutes: int = 60,
        reason: str = "operator-request",
    ) -> dict[str, Any]:
        """Portkey-style temporary key budget increase (`POST /keys/{id}/budget/increase-temporary`)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote

        body = {
            "environment": str(environment or "dev").strip() or "dev",
            "increase_cents": max(1, int(increase_cents or 0)),
            "duration_minutes": max(1, min(int(duration_minutes or 60), 10080)),
            "reason": str(reason or "operator-request").strip() or "operator-request",
        }
        payload = self._post(f"/keys/{quote(key, safe='')}/budget/increase-temporary", body)
        return payload if isinstance(payload, dict) else {}

    def get_key_budget_increase_temporary(self, key_id: str) -> dict[str, Any]:
        """Portkey-style temporary key budget increase get (`GET /keys/{id}/budget/increase-temporary`)."""
        key = str(key_id or "").strip()
        if not key:
            raise ValueError("key_id is required")
        from urllib.parse import quote

        payload = self._get(f"/keys/{quote(key, safe='')}/budget/increase-temporary")
        return payload if isinstance(payload, dict) else {}

    def get_analytics(
        self,
        *,
        hours: int = 24,
        environment: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style analytics summary (`GET /v1/analytics`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {"hours": max(1, min(int(hours or 24), 168))}
        if environment:
            query["environment"] = str(environment).strip()
        payload = self._get(f"/v1/analytics?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def list_guardrails(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        has_policy: Optional[bool] = None,
    ) -> list[dict[str, Any]]:
        """Portkey-style guardrail inventory (`GET /v1/guardrails`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "limit": max(1, min(int(limit or 50), 500)),
            "offset": max(0, int(offset or 0)),
        }
        if has_policy is True:
            query["has_policy"] = "true"
        elif has_policy is False:
            query["has_policy"] = "false"
        data = self._get(f"/v1/guardrails?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("items") or data.get("data") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def get_guardrail(self, guardrail_id: str) -> dict[str, Any]:
        """Portkey-style guardrail get (`GET /v1/guardrails/{id}`)."""
        guardrail = str(guardrail_id or "").strip()
        if not guardrail:
            raise ValueError("guardrail_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/guardrails/{quote(guardrail, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def list_configs(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Portkey-style route/config inventory (`GET /v1/configs`)."""
        from urllib.parse import urlencode

        query = {
            "limit": max(1, min(int(limit or 50), 500)),
            "offset": max(0, int(offset or 0)),
        }
        data = self._get(f"/v1/configs?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("items") or data.get("data") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def get_config(self, config_id: str) -> dict[str, Any]:
        """Portkey-style route/config get (`GET /v1/configs/{id}`)."""
        config = str(config_id or "").strip()
        if not config:
            raise ValueError("config_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/configs/{quote(config, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def list_models(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Portkey/OpenAI-style model catalog (`GET /v1/models`)."""
        from urllib.parse import urlencode

        query = {
            "limit": max(1, min(int(limit or 50), 500)),
            "offset": max(0, int(offset or 0)),
        }
        data = self._get(f"/v1/models?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def get_model(self, model_id: str) -> dict[str, Any]:
        """Portkey/OpenAI-style model get (`GET /v1/models/{id}`)."""
        model = str(model_id or "").strip()
        if not model:
            raise ValueError("model_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/models/{quote(model, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def list_prompts(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        q: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Portkey-style prompt registry list (`GET /v1/prompts`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 50), 200)),
            "offset": max(0, int(offset or 0)),
        }
        search = str(q or "").strip()
        if search:
            query["q"] = search[:128]
        data = self._get(f"/v1/prompts?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("items") or data.get("data") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def get_prompt(self, prompt_id: str) -> dict[str, Any]:
        """Portkey-style prompt registry get (`GET /v1/prompts/{id}`)."""
        prompt_key = str(prompt_id or "").strip()
        if not prompt_key:
            raise ValueError("prompt_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/prompts/{quote(prompt_key, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def list_prompt_versions(self, prompt_id: str) -> list[dict[str, Any]]:
        """Portkey-style prompt version history (`GET /v1/prompts/{id}/versions`)."""
        prompt_key = str(prompt_id or "").strip()
        if not prompt_key:
            raise ValueError("prompt_id is required")
        from urllib.parse import quote

        data = self._get(f"/v1/prompts/{quote(prompt_key, safe='')}/versions")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("items") or data.get("data") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def get_prompt_version(self, prompt_id: str, version: int) -> dict[str, Any]:
        """Portkey-style prompt version get (`GET /v1/prompts/{id}/versions/{version}`)."""
        prompt_key = str(prompt_id or "").strip()
        if not prompt_key:
            raise ValueError("prompt_id is required")
        version_number = int(version)
        if version_number < 1:
            raise ValueError("version must be >= 1")
        from urllib.parse import quote

        payload = self._get(f"/v1/prompts/{quote(prompt_key, safe='')}/versions/{version_number}")
        return payload if isinstance(payload, dict) else {}

    def render_prompt(
        self,
        prompt_id: str,
        *,
        variables: Optional[dict[str, str]] = None,
        version: Optional[int] = None,
        require_all_variables: bool = True,
    ) -> dict[str, Any]:
        """Portkey-style prompt render/preview (`POST /v1/prompts/{id}/render`)."""
        prompt_key = str(prompt_id or "").strip()
        if not prompt_key:
            raise ValueError("prompt_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "variables": dict(variables or {}),
            "require_all_variables": bool(require_all_variables),
        }
        if version is not None:
            body["version"] = int(version)
        payload = self._post(f"/v1/prompts/{quote(prompt_key, safe='')}/render", body)
        return payload if isinstance(payload, dict) else {}

    def promote_prompt(
        self,
        prompt_id: str,
        *,
        target_environment: str = "dev",
        reason: str = "promote",
        approval_ticket: Optional[str] = None,
        require_render_validation: bool = True,
        render_variables: Optional[dict[str, str]] = None,
        preview_only: bool = False,
    ) -> dict[str, Any]:
        """Portkey-style prompt promote (`POST /v1/prompts/{id}/promote`)."""
        prompt_key = str(prompt_id or "").strip()
        if not prompt_key:
            raise ValueError("prompt_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "target_environment": str(target_environment or "dev").strip() or "dev",
            "reason": str(reason or "promote").strip() or "promote",
            "require_render_validation": bool(require_render_validation),
            "render_variables": dict(render_variables or {}),
            "preview_only": bool(preview_only),
        }
        ticket = str(approval_ticket or "").strip()
        if ticket:
            body["approval_ticket"] = ticket
        payload = self._post(f"/v1/prompts/{quote(prompt_key, safe='')}/promote", body)
        return payload if isinstance(payload, dict) else {}

    def list_logs(
        self,
        *,
        window_hours: int = 24,
        user_id: Optional[str] = None,
        model: Optional[str] = None,
        property_key: Optional[str] = None,
        property_value: Optional[str] = None,
        cache_hit: Optional[bool] = None,
        has_feedback: Optional[bool] = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Portkey-style request logs (`GET /v1/logs`; metadata-only)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "limit": max(1, min(int(limit or 50), 200)),
        }
        if user_id:
            query["user_id"] = str(user_id).strip()
        if model:
            query["model"] = str(model).strip()
        if property_key:
            query["property_key"] = str(property_key).strip()
        if property_value:
            query["property_value"] = str(property_value).strip()
        if cache_hit is not None:
            query["cache_hit"] = "true" if cache_hit else "false"
        if has_feedback is not None:
            query["has_feedback"] = "true" if has_feedback else "false"
        payload = self._get(f"/v1/logs?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def get_log(self, request_id: str) -> dict[str, Any]:
        """Portkey-style single request log (`GET /v1/logs/{request_id}`)."""
        rid = str(request_id or "").strip()
        if not rid:
            raise ValueError("request_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/logs/{quote(rid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def create_log_export(
        self,
        *,
        filters: Optional[dict[str, Any]] = None,
        requested_data: Optional[list[str]] = None,
        description: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style log export job create (`POST /v1/logs/exports`)."""
        body: dict[str, Any] = {
            "filters": dict(filters or {}),
            "requested_data": list(requested_data or []),
        }
        if description is not None:
            body["description"] = str(description)
        if workspace_id is not None:
            body["workspace_id"] = str(workspace_id)
        payload = self._post("/v1/logs/exports", body)
        return payload if isinstance(payload, dict) else {}

    def list_log_exports(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Portkey-style log export job list (`GET /v1/logs/exports`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "limit": max(1, min(int(limit or 20), 200)),
            "offset": max(0, int(offset or 0)),
        }
        if status:
            query["status"] = str(status).strip()
        data = self._get(f"/v1/logs/exports?{urlencode(query)}")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def get_log_export(self, export_id: str) -> dict[str, Any]:
        """Portkey-style log export job get (`GET /v1/logs/exports/{id}`)."""
        eid = str(export_id or "").strip()
        if not eid:
            raise ValueError("export_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/logs/exports/{quote(eid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def start_log_export(self, export_id: str) -> dict[str, Any]:
        """Portkey-style log export start (`POST /v1/logs/exports/{id}/start`)."""
        eid = str(export_id or "").strip()
        if not eid:
            raise ValueError("export_id is required")
        from urllib.parse import quote

        payload = self._post(f"/v1/logs/exports/{quote(eid, safe='')}/start", {})
        return payload if isinstance(payload, dict) else {}

    def download_log_export(self, export_id: str) -> dict[str, Any]:
        """Portkey-style log export download (`GET /v1/logs/exports/{id}/download`)."""
        eid = str(export_id or "").strip()
        if not eid:
            raise ValueError("export_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/logs/exports/{quote(eid, safe='')}/download")
        return payload if isinstance(payload, dict) else {}

    def cancel_log_export(self, export_id: str) -> dict[str, Any]:
        """Portkey-style log export cancel (`POST /v1/logs/exports/{id}/cancel`)."""
        eid = str(export_id or "").strip()
        if not eid:
            raise ValueError("export_id is required")
        from urllib.parse import quote

        payload = self._post(f"/v1/logs/exports/{quote(eid, safe='')}/cancel", {})
        return payload if isinstance(payload, dict) else {}

    def delete_log_export(self, export_id: str) -> dict[str, Any]:
        """Portkey-style log export delete (`DELETE /v1/logs/exports/{id}`)."""
        eid = str(export_id or "").strip()
        if not eid:
            raise ValueError("export_id is required")
        from urllib.parse import quote

        payload = self._delete(f"/v1/logs/exports/{quote(eid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def create_file(
        self,
        *,
        filename: str,
        purpose: str = "assistants",
        bytes: int,
        content_type: str = "application/octet-stream",
        metadata: Optional[dict[str, Any]] = None,
        environment: str = "dev",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style file create (`POST /v1/files`; registry metadata only)."""
        body: dict[str, Any] = {
            "filename": str(filename or "").strip(),
            "purpose": str(purpose or "assistants").strip() or "assistants",
            "bytes": int(bytes),
            "content_type": str(content_type or "application/octet-stream").strip() or "application/octet-stream",
            "environment": str(environment or "dev").strip() or "dev",
        }
        if metadata is not None:
            body["metadata"] = dict(metadata)
        payload = self._post("/v1/files", body)
        return payload if isinstance(payload, dict) else {}

    def list_files(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        purpose: Optional[str] = None,
        status: Optional[str] = None,
        filename_contains: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """OpenAI/Portkey-style file list (`GET /v1/files`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "limit": max(1, min(int(limit or 20), 200)),
            "offset": max(0, int(offset or 0)),
        }
        if purpose:
            query["purpose"] = str(purpose).strip()
        if status:
            query["status"] = str(status).strip()
        if filename_contains:
            query["filename_contains"] = str(filename_contains).strip()
        data = self._get(f"/v1/files?{urlencode(query)}")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def get_file(self, file_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style file get (`GET /v1/files/{id}`)."""
        fid = str(file_id or "").strip()
        if not fid:
            raise ValueError("file_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/files/{quote(fid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def get_file_content(self, file_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style file content (`GET /v1/files/{id}/content`; metadata-only)."""
        fid = str(file_id or "").strip()
        if not fid:
            raise ValueError("file_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/files/{quote(fid, safe='')}/content")
        return payload if isinstance(payload, dict) else {}

    def delete_file(self, file_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style file delete (`DELETE /v1/files/{id}`)."""
        fid = str(file_id or "").strip()
        if not fid:
            raise ValueError("file_id is required")
        from urllib.parse import quote

        payload = self._delete(f"/v1/files/{quote(fid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def create_assistant(
        self,
        *,
        name: str,
        model: str,
        instructions: str = "",
        metadata: Optional[dict[str, Any]] = None,
        environment: str = "dev",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style assistant create (`POST /v1/assistants`)."""
        body: dict[str, Any] = {
            "name": str(name or "").strip(),
            "model": str(model or "").strip(),
            "instructions": str(instructions or ""),
            "environment": str(environment or "dev").strip() or "dev",
        }
        if metadata is not None:
            body["metadata"] = dict(metadata)
        payload = self._post("/v1/assistants", body)
        return payload if isinstance(payload, dict) else {}

    def list_assistants(self, *, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        """OpenAI/Portkey-style assistant list (`GET /v1/assistants`)."""
        from urllib.parse import urlencode

        query = {
            "limit": max(1, min(int(limit or 20), 200)),
            "offset": max(0, int(offset or 0)),
        }
        data = self._get(f"/v1/assistants?{urlencode(query)}")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def get_assistant(self, assistant_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style assistant get (`GET /v1/assistants/{id}`)."""
        aid = str(assistant_id or "").strip()
        if not aid:
            raise ValueError("assistant_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/assistants/{quote(aid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def delete_assistant(self, assistant_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style assistant delete (`DELETE /v1/assistants/{id}`)."""
        aid = str(assistant_id or "").strip()
        if not aid:
            raise ValueError("assistant_id is required")
        from urllib.parse import quote

        payload = self._delete(f"/v1/assistants/{quote(aid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def create_thread(
        self,
        *,
        metadata: Optional[dict[str, Any]] = None,
        environment: str = "dev",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style thread create (`POST /v1/threads`)."""
        body: dict[str, Any] = {"environment": str(environment or "dev").strip() or "dev"}
        if metadata is not None:
            body["metadata"] = dict(metadata)
        payload = self._post("/v1/threads", body)
        return payload if isinstance(payload, dict) else {}

    def get_thread(self, thread_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style thread get (`GET /v1/threads/{id}`)."""
        tid = str(thread_id or "").strip()
        if not tid:
            raise ValueError("thread_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/threads/{quote(tid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def create_thread_message(
        self,
        thread_id: str,
        *,
        content: str,
        role: str = "user",
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style thread message create (`POST /v1/threads/{id}/messages`)."""
        tid = str(thread_id or "").strip()
        if not tid:
            raise ValueError("thread_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "role": str(role or "user").strip() or "user",
            "content": str(content or ""),
        }
        if metadata is not None:
            body["metadata"] = dict(metadata)
        payload = self._post(f"/v1/threads/{quote(tid, safe='')}/messages", body)
        return payload if isinstance(payload, dict) else {}

    def list_thread_messages(
        self,
        thread_id: str,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """OpenAI/Portkey-style thread message list (`GET /v1/threads/{id}/messages`)."""
        tid = str(thread_id or "").strip()
        if not tid:
            raise ValueError("thread_id is required")
        from urllib.parse import quote, urlencode

        query = {
            "limit": max(1, min(int(limit or 20), 200)),
            "offset": max(0, int(offset or 0)),
        }
        data = self._get(f"/v1/threads/{quote(tid, safe='')}/messages?{urlencode(query)}")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def create_thread_run(
        self,
        thread_id: str,
        *,
        assistant_id: str,
        model: Optional[str] = None,
        additional_instructions: str = "",
        environment: str = "dev",
        stream: bool = False,
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style thread run create (`POST /v1/threads/{id}/runs`)."""
        tid = str(thread_id or "").strip()
        aid = str(assistant_id or "").strip()
        if not tid:
            raise ValueError("thread_id is required")
        if not aid:
            raise ValueError("assistant_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "assistant_id": aid,
            "additional_instructions": str(additional_instructions or ""),
            "environment": str(environment or "dev").strip() or "dev",
            "stream": bool(stream),
        }
        if model is not None:
            body["model"] = str(model)
        payload = self._post(f"/v1/threads/{quote(tid, safe='')}/runs", body)
        return payload if isinstance(payload, dict) else {}

    def get_thread_run(self, thread_id: str, run_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style thread run get (`GET /v1/threads/{id}/runs/{run_id}`)."""
        tid = str(thread_id or "").strip()
        rid = str(run_id or "").strip()
        if not tid:
            raise ValueError("thread_id is required")
        if not rid:
            raise ValueError("run_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/threads/{quote(tid, safe='')}/runs/{quote(rid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def create_fine_tuning_job(
        self,
        *,
        model: str,
        training_file_id: str,
        metadata: Optional[dict[str, Any]] = None,
        environment: str = "dev",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style fine-tuning job create (`POST /v1/fine_tuning/jobs`)."""
        body: dict[str, Any] = {
            "model": str(model or "").strip(),
            "training_file_id": str(training_file_id or "").strip(),
            "environment": str(environment or "dev").strip() or "dev",
        }
        if metadata is not None:
            body["metadata"] = dict(metadata)
        payload = self._post("/v1/fine_tuning/jobs", body)
        return payload if isinstance(payload, dict) else {}

    def list_fine_tuning_jobs(self, *, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        """OpenAI/Portkey-style fine-tuning job list (`GET /v1/fine_tuning/jobs`)."""
        from urllib.parse import urlencode

        query = {
            "limit": max(1, min(int(limit or 20), 200)),
            "offset": max(0, int(offset or 0)),
        }
        data = self._get(f"/v1/fine_tuning/jobs?{urlencode(query)}")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def get_fine_tuning_job(self, job_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style fine-tuning job get (`GET /v1/fine_tuning/jobs/{id}`)."""
        jid = str(job_id or "").strip()
        if not jid:
            raise ValueError("job_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/fine_tuning/jobs/{quote(jid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def cancel_fine_tuning_job(self, job_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style fine-tuning job cancel (`POST /v1/fine_tuning/jobs/{id}/cancel`)."""
        jid = str(job_id or "").strip()
        if not jid:
            raise ValueError("job_id is required")
        from urllib.parse import quote

        payload = self._post(f"/v1/fine_tuning/jobs/{quote(jid, safe='')}/cancel", {})
        return payload if isinstance(payload, dict) else {}

    def create_batch(
        self,
        *,
        requests: list[dict[str, Any]],
        endpoint_family: str = "responses",
        metadata: Optional[dict[str, Any]] = None,
        environment: str = "dev",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style batch create (`POST /v1/batches`)."""
        body: dict[str, Any] = {
            "endpoint_family": str(endpoint_family or "responses").strip() or "responses",
            "requests": list(requests or []),
            "environment": str(environment or "dev").strip() or "dev",
        }
        if metadata is not None:
            body["metadata"] = dict(metadata)
        payload = self._post("/v1/batches", body)
        return payload if isinstance(payload, dict) else {}

    def list_batches(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """OpenAI/Portkey-style batch list (`GET /v1/batches`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "limit": max(1, min(int(limit or 20), 200)),
            "offset": max(0, int(offset or 0)),
        }
        if status:
            query["status"] = str(status).strip()
        data = self._get(f"/v1/batches?{urlencode(query)}")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style batch get (`GET /v1/batches/{id}`)."""
        bid = str(batch_id or "").strip()
        if not bid:
            raise ValueError("batch_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/batches/{quote(bid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def get_batch_results(self, batch_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style batch results (`GET /v1/batches/{id}/results`; metadata-only)."""
        bid = str(batch_id or "").strip()
        if not bid:
            raise ValueError("batch_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/batches/{quote(bid, safe='')}/results")
        return payload if isinstance(payload, dict) else {}

    def cancel_batch(self, batch_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style batch cancel (`POST /v1/batches/{id}/cancel`)."""
        bid = str(batch_id or "").strip()
        if not bid:
            raise ValueError("batch_id is required")
        from urllib.parse import quote

        payload = self._post(f"/v1/batches/{quote(bid, safe='')}/cancel", {})
        return payload if isinstance(payload, dict) else {}

    def complete_batch(
        self,
        batch_id: str,
        *,
        completed_count: Optional[int] = None,
        failed_count: Optional[int] = None,
        status: str = "completed",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style batch complete (`POST /v1/batches/{id}/complete`)."""
        bid = str(batch_id or "").strip()
        if not bid:
            raise ValueError("batch_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {"status": str(status or "completed").strip() or "completed"}
        if completed_count is not None:
            body["completed_count"] = int(completed_count)
        if failed_count is not None:
            body["failed_count"] = int(failed_count)
        payload = self._post(f"/v1/batches/{quote(bid, safe='')}/complete", body)
        return payload if isinstance(payload, dict) else {}

    def expire_batch(self, batch_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style batch expire (`POST /v1/batches/{id}/expire`)."""
        bid = str(batch_id or "").strip()
        if not bid:
            raise ValueError("batch_id is required")
        from urllib.parse import quote

        payload = self._post(f"/v1/batches/{quote(bid, safe='')}/expire", {})
        return payload if isinstance(payload, dict) else {}

    def delete_batch(self, batch_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style batch delete (`DELETE /v1/batches/{id}`)."""
        bid = str(batch_id or "").strip()
        if not bid:
            raise ValueError("batch_id is required")
        from urllib.parse import quote

        payload = self._delete(f"/v1/batches/{quote(bid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def export_logs(
        self,
        *,
        window_hours: int = 24,
        user_id: Optional[str] = None,
        model: Optional[str] = None,
        property_key: Optional[str] = None,
        property_value: Optional[str] = None,
        cache_hit: Optional[bool] = None,
        has_feedback: Optional[bool] = None,
        limit: int = 1000,
    ) -> str:
        """Portkey-style logs CSV export (`GET /v1/logs/export`; metadata-only)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "limit": max(1, min(int(limit or 1000), 5000)),
        }
        if user_id:
            query["user_id"] = str(user_id).strip()
        if model:
            query["model"] = str(model).strip()
        if property_key:
            query["property_key"] = str(property_key).strip()
        if property_value:
            query["property_value"] = str(property_value).strip()
        if cache_hit is not None:
            query["cache_hit"] = "true" if cache_hit else "false"
        if has_feedback is not None:
            query["has_feedback"] = "true" if has_feedback else "false"
        path = f"/v1/logs/export?{urlencode(query)}"
        headers = self._headers()
        req = request.Request(f"{self.base_url}{path}", headers=headers, method="GET")
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return resp.read().decode("utf-8")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gateway request failed ({exc.code}): {detail}") from exc

    def estimate_cost_cents(
        self,
        *,
        model_name: str,
        endpoint_family: str = "chat.completions",
        input_tokens: int = 0,
        output_tokens: int = 0,
        provider_type: str = "openai",
    ) -> int:
        try:
            payload = self._post(
                "/cost/pricing/calculate",
                {
                    "model_name": model_name,
                    "provider_type": provider_type,
                    "endpoint_family": endpoint_family,
                    "input_tokens": max(0, int(input_tokens or 0)),
                    "output_tokens": max(0, int(output_tokens or 0)),
                },
            )
            return max(0, int(payload.get("estimated_cost_cents") or 0))
        except Exception:  # noqa: BLE001
            return 0

    def embeddings(
        self,
        body: dict[str, Any],
        *,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_tag: str = "gateway-sdk",
    ) -> dict[str, Any]:
        request_id = _rid("sdk")
        trace = trace_id or _rid("trace")
        session = session_id or _rid("session")
        model = str(body.get("model") or "text-embedding-3-small")
        payload = self._post(
            "/v1/embeddings",
            body,
            extra_headers={"X-Request-Id": request_id, "X-Trace-Id": trace},
        )
        usage = payload.get("usage") or {}
        raw_input = body.get("input")
        if isinstance(raw_input, list):
            text = "\n".join(str(item) for item in raw_input)
        else:
            text = str(raw_input or "")
        input_tokens = int(usage.get("prompt_tokens") or usage.get("total_tokens") or 0) or _estimate_tokens(text)
        cost_event = None
        if self.track_cost:
            try:
                estimated = self.estimate_cost_cents(
                    model_name=model,
                    endpoint_family="embeddings",
                    input_tokens=input_tokens,
                    output_tokens=0,
                )
                cost_event = self.track_spend(
                    request_id=request_id,
                    trace_id=trace,
                    session_id=session,
                    request_tag=request_tag,
                    model_name=model,
                    endpoint_family="embeddings",
                    input_tokens=input_tokens,
                    output_tokens=0,
                    estimated_cost_cents=estimated,
                )
            except Exception as exc:  # noqa: BLE001
                cost_event = {"error": str(exc)}
        payload["agenthub"] = {
            "request_id": request_id,
            "trace_id": trace,
            "session_id": session,
            "cost_event": cost_event,
        }
        return payload

    def images(
        self,
        body: dict[str, Any],
        *,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_tag: str = "gateway-sdk",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style image generation (`POST /v1/images`)."""
        request_id = _rid("sdk")
        trace = trace_id or _rid("trace")
        session = session_id or _rid("session")
        model = str(body.get("model") or "gpt-image-1")
        payload = self._post(
            "/v1/images",
            body,
            extra_headers={"X-Request-Id": request_id, "X-Trace-Id": trace},
        )
        prompt_text = str(body.get("prompt") or "")
        input_tokens = _estimate_tokens(prompt_text)
        cost_event = None
        if self.track_cost:
            try:
                estimated = self.estimate_cost_cents(
                    model_name=model,
                    endpoint_family="images",
                    input_tokens=input_tokens,
                    output_tokens=0,
                )
                cost_event = self.track_spend(
                    request_id=request_id,
                    trace_id=trace,
                    session_id=session,
                    request_tag=request_tag,
                    model_name=model,
                    endpoint_family="images",
                    input_tokens=input_tokens,
                    output_tokens=0,
                    estimated_cost_cents=estimated,
                )
            except Exception as exc:  # noqa: BLE001
                cost_event = {"error": str(exc)}
        payload["agenthub"] = {
            "request_id": request_id,
            "trace_id": trace,
            "session_id": session,
            "cost_event": cost_event,
        }
        return payload

    def audio_transcriptions(
        self,
        body: dict[str, Any],
        *,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_tag: str = "gateway-sdk",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style audio transcription (`POST /v1/audio/transcriptions`)."""
        request_id = _rid("sdk")
        trace = trace_id or _rid("trace")
        session = session_id or _rid("session")
        model = str(body.get("model") or "whisper-1")
        payload = self._post(
            "/v1/audio/transcriptions",
            body,
            extra_headers={"X-Request-Id": request_id, "X-Trace-Id": trace},
        )
        audio_text = str(body.get("input_text") or body.get("prompt") or "")
        input_tokens = _estimate_tokens(audio_text)
        cost_event = None
        if self.track_cost:
            try:
                estimated = self.estimate_cost_cents(
                    model_name=model,
                    endpoint_family="audio.transcriptions",
                    input_tokens=input_tokens,
                    output_tokens=0,
                )
                cost_event = self.track_spend(
                    request_id=request_id,
                    trace_id=trace,
                    session_id=session,
                    request_tag=request_tag,
                    model_name=model,
                    endpoint_family="audio.transcriptions",
                    input_tokens=input_tokens,
                    output_tokens=0,
                    estimated_cost_cents=estimated,
                )
            except Exception as exc:  # noqa: BLE001
                cost_event = {"error": str(exc)}
        payload["agenthub"] = {
            "request_id": request_id,
            "trace_id": trace,
            "session_id": session,
            "cost_event": cost_event,
        }
        return payload

    def audio_translations(
        self,
        body: dict[str, Any],
        *,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_tag: str = "gateway-sdk",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style audio translation (`POST /v1/audio/translations`)."""
        request_id = _rid("sdk")
        trace = trace_id or _rid("trace")
        session = session_id or _rid("session")
        model = str(body.get("model") or "whisper-1")
        payload = self._post(
            "/v1/audio/translations",
            body,
            extra_headers={"X-Request-Id": request_id, "X-Trace-Id": trace},
        )
        audio_text = str(body.get("input_text") or body.get("prompt") or "")
        input_tokens = _estimate_tokens(audio_text)
        cost_event = None
        if self.track_cost:
            try:
                estimated = self.estimate_cost_cents(
                    model_name=model,
                    endpoint_family="audio.translations",
                    input_tokens=input_tokens,
                    output_tokens=0,
                )
                cost_event = self.track_spend(
                    request_id=request_id,
                    trace_id=trace,
                    session_id=session,
                    request_tag=request_tag,
                    model_name=model,
                    endpoint_family="audio.translations",
                    input_tokens=input_tokens,
                    output_tokens=0,
                    estimated_cost_cents=estimated,
                )
            except Exception as exc:  # noqa: BLE001
                cost_event = {"error": str(exc)}
        payload["agenthub"] = {
            "request_id": request_id,
            "trace_id": trace,
            "session_id": session,
            "cost_event": cost_event,
        }
        return payload

    def rerank(
        self,
        body: dict[str, Any],
        *,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_tag: str = "gateway-sdk",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style rerank (`POST /v1/rerank`)."""
        request_id = _rid("sdk")
        trace = trace_id or _rid("trace")
        session = session_id or _rid("session")
        model = str(body.get("model") or "rerank-english-v3.0")
        payload = self._post(
            "/v1/rerank",
            body,
            extra_headers={"X-Request-Id": request_id, "X-Trace-Id": trace},
        )
        usage = payload.get("usage") or {}
        query_text = str(body.get("query") or "")
        docs = body.get("documents") or []
        doc_text = "\n".join(str(item) for item in docs) if isinstance(docs, list) else str(docs or "")
        input_tokens = int(usage.get("prompt_tokens") or usage.get("total_tokens") or 0) or _estimate_tokens(
            f"{query_text}\n{doc_text}"
        )
        cost_event = None
        if self.track_cost:
            try:
                estimated = self.estimate_cost_cents(
                    model_name=model,
                    endpoint_family="rerank",
                    input_tokens=input_tokens,
                    output_tokens=0,
                )
                cost_event = self.track_spend(
                    request_id=request_id,
                    trace_id=trace,
                    session_id=session,
                    request_tag=request_tag,
                    model_name=model,
                    endpoint_family="rerank",
                    input_tokens=input_tokens,
                    output_tokens=0,
                    estimated_cost_cents=estimated,
                )
            except Exception as exc:  # noqa: BLE001
                cost_event = {"error": str(exc)}
        payload["agenthub"] = {
            "request_id": request_id,
            "trace_id": trace,
            "session_id": session,
            "cost_event": cost_event,
        }
        return payload

    def messages(
        self,
        body: dict[str, Any],
        *,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_tag: str = "gateway-sdk",
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style messages (`POST /v1/messages`)."""
        request_id = _rid("sdk")
        trace = trace_id or _rid("trace")
        session = session_id or _rid("session")
        model = str(body.get("model") or "gpt-4o-mini")
        payload = self._post(
            "/v1/messages",
            body,
            extra_headers={"X-Request-Id": request_id, "X-Trace-Id": trace},
        )
        input_text = str(body.get("input") or "")
        content = str(payload.get("content") or "")
        input_tokens = _estimate_tokens(input_text)
        output_tokens = _estimate_tokens(content)
        cost_event = None
        if self.track_cost:
            try:
                estimated = self.estimate_cost_cents(
                    model_name=model,
                    endpoint_family="messages",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                )
                cost_event = self.track_spend(
                    request_id=request_id,
                    trace_id=trace,
                    session_id=session,
                    request_tag=request_tag,
                    model_name=model,
                    endpoint_family="messages",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    estimated_cost_cents=estimated,
                )
            except Exception as exc:  # noqa: BLE001
                cost_event = {"error": str(exc)}
        payload["agenthub"] = {
            "request_id": request_id,
            "trace_id": trace,
            "session_id": session,
            "cost_event": cost_event,
        }
        return payload

    def a2a_messages(
        self,
        body: dict[str, Any],
        *,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_tag: str = "gateway-sdk",
    ) -> dict[str, Any]:
        """Agent-to-agent messages (`POST /v1/a2a/messages`)."""
        request_id = _rid("sdk")
        trace = trace_id or _rid("trace")
        session = session_id or str(body.get("session_id") or "").strip() or _rid("session")
        model = str(body.get("model") or "gpt-4o-mini")
        payload = self._post(
            "/v1/a2a/messages",
            body,
            extra_headers={"X-Request-Id": request_id, "X-Trace-Id": trace},
        )
        message_text = str(body.get("message") or "")
        content = str(payload.get("content") or payload.get("message") or "")
        input_tokens = _estimate_tokens(message_text)
        output_tokens = _estimate_tokens(content)
        cost_event = None
        if self.track_cost:
            try:
                estimated = self.estimate_cost_cents(
                    model_name=model,
                    endpoint_family="a2a",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                )
                cost_event = self.track_spend(
                    request_id=request_id,
                    trace_id=trace,
                    session_id=session,
                    request_tag=request_tag,
                    model_name=model,
                    endpoint_family="a2a",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    estimated_cost_cents=estimated,
                )
            except Exception as exc:  # noqa: BLE001
                cost_event = {"error": str(exc)}
        if isinstance(payload, dict):
            payload["agenthub"] = {
                "request_id": request_id,
                "trace_id": trace,
                "session_id": session,
                "cost_event": cost_event,
            }
            return payload
        return {
            "agenthub": {
                "request_id": request_id,
                "trace_id": trace,
                "session_id": session,
                "cost_event": cost_event,
            }
        }

    def passthrough(
        self,
        *,
        provider_id: str,
        path: str,
        method: str = "POST",
        headers: Optional[dict[str, Any]] = None,
        body: Optional[dict[str, Any]] = None,
        environment: str = "dev",
    ) -> dict[str, Any]:
        """Portkey-style provider passthrough (`POST /v1/passthrough`)."""
        pid = str(provider_id or "").strip()
        pth = str(path or "").strip()
        if not pid:
            raise ValueError("provider_id is required")
        if not pth:
            raise ValueError("path is required")
        payload_body: dict[str, Any] = {
            "provider_id": pid,
            "path": pth,
            "method": str(method or "POST").strip().upper() or "POST",
            "environment": str(environment or "dev").strip() or "dev",
        }
        if headers is not None:
            payload_body["headers"] = dict(headers)
        if body is not None:
            payload_body["body"] = dict(body)
        payload = self._post("/v1/passthrough", payload_body)
        return payload if isinstance(payload, dict) else {}

    def create_realtime_session(
        self,
        body: dict[str, Any],
        *,
        trace_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style realtime session create (`POST /v1/realtime`)."""
        request_id = _rid("sdk")
        trace = trace_id or _rid("trace")
        payload = self._post(
            "/v1/realtime",
            body,
            extra_headers={"X-Request-Id": request_id, "X-Trace-Id": trace},
        )
        if isinstance(payload, dict):
            payload.setdefault("agenthub", {})
            if isinstance(payload["agenthub"], dict):
                payload["agenthub"].update({"request_id": request_id, "trace_id": trace})
            return payload
        return {}

    def list_realtime_sessions(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """OpenAI/Portkey-style realtime session list (`GET /v1/realtime/sessions`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 20), 200)),
            "offset": max(0, int(offset or 0)),
        }
        if status:
            query["status"] = str(status).strip()
        data = self._get(f"/v1/realtime/sessions?{urlencode(query)}")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def get_realtime_session(self, session_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style realtime session get (`GET /v1/realtime/sessions/{id}`)."""
        sid = str(session_id or "").strip()
        if not sid:
            raise ValueError("session_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/realtime/sessions/{quote(sid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def create_realtime_session_event(
        self,
        session_id: str,
        *,
        event_type: str,
        payload: Optional[dict[str, Any]] = None,
        binary_mode: str = "metadata_only",
        event_bytes: int = 0,
    ) -> dict[str, Any]:
        """OpenAI/Portkey-style realtime event create (`POST /v1/realtime/sessions/{id}/events`)."""
        sid = str(session_id or "").strip()
        if not sid:
            raise ValueError("session_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "event_type": str(event_type or "").strip(),
            "binary_mode": str(binary_mode or "metadata_only").strip() or "metadata_only",
            "event_bytes": max(0, int(event_bytes or 0)),
        }
        if payload is not None:
            body["payload"] = dict(payload)
        result = self._post(f"/v1/realtime/sessions/{quote(sid, safe='')}/events", body)
        return result if isinstance(result, dict) else {}

    def list_realtime_session_events(self, session_id: str) -> list[dict[str, Any]]:
        """OpenAI/Portkey-style realtime event list (`GET /v1/realtime/sessions/{id}/events`)."""
        sid = str(session_id or "").strip()
        if not sid:
            raise ValueError("session_id is required")
        from urllib.parse import quote

        data = self._get(f"/v1/realtime/sessions/{quote(sid, safe='')}/events")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def close_realtime_session(self, session_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style realtime session close (`POST /v1/realtime/sessions/{id}/close`)."""
        sid = str(session_id or "").strip()
        if not sid:
            raise ValueError("session_id is required")
        from urllib.parse import quote

        payload = self._post(f"/v1/realtime/sessions/{quote(sid, safe='')}/close", {})
        return payload if isinstance(payload, dict) else {}

    def list_vector_stores(self) -> list[dict[str, Any]]:
        """OpenAI/Portkey-style vector store list (`GET /v1/vector_stores`)."""
        data = self._get("/v1/vector_stores")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def get_vector_store(self, store_id: str) -> dict[str, Any]:
        """OpenAI/Portkey-style vector store get (`GET /v1/vector_stores/{id}`)."""
        sid = str(store_id or "").strip()
        if not sid:
            raise ValueError("store_id is required")
        from urllib.parse import quote

        payload = self._get(f"/v1/vector_stores/{quote(sid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def rag_ingest(
        self,
        *,
        store_id: str,
        documents: list[dict[str, Any]],
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Portkey-style RAG ingest (`POST /rag/ingest`)."""
        sid = str(store_id or "").strip()
        if not sid:
            raise ValueError("store_id is required")
        if not isinstance(documents, list) or not documents:
            raise ValueError("documents is required")
        body: dict[str, Any] = {
            "store_id": sid,
            "documents": [dict(doc) for doc in documents if isinstance(doc, dict)],
        }
        if not body["documents"]:
            raise ValueError("documents must contain at least one object")
        if isinstance(metadata, dict) and metadata:
            body["metadata"] = dict(metadata)
        payload = self._post("/rag/ingest", body)
        return payload if isinstance(payload, dict) else {}

    def rag_query(
        self,
        *,
        store_id: str,
        query: str,
        top_k: Optional[int] = None,
    ) -> dict[str, Any]:
        """Portkey-style RAG query (`POST /rag/query`)."""
        sid = str(store_id or "").strip()
        q = str(query or "").strip()
        if not sid:
            raise ValueError("store_id is required")
        if not q:
            raise ValueError("query is required")
        body: dict[str, Any] = {"store_id": sid, "query": q}
        if top_k is not None:
            body["top_k"] = max(1, min(int(top_k), 100))
        payload = self._post("/rag/query", body)
        return payload if isinstance(payload, dict) else {}

    def create_memory_record(
        self,
        *,
        memory_tier: str,
        scope_type: str,
        scope_id: str,
        content: str,
        label: str = "",
        metadata_json: Optional[str] = None,
        environment: str = "dev",
    ) -> dict[str, Any]:
        """Portkey-style memory create (`POST /gateway/memory/records`)."""
        body: dict[str, Any] = {
            "memory_tier": str(memory_tier or "").strip(),
            "scope_type": str(scope_type or "").strip(),
            "scope_id": str(scope_id or "").strip(),
            "content": str(content or ""),
            "label": str(label or "")[:256],
            "environment": str(environment or "dev").strip() or "dev",
        }
        if metadata_json is not None:
            body["metadata_json"] = str(metadata_json)
        payload = self._post("/gateway/memory/records", body)
        return payload if isinstance(payload, dict) else {}

    def list_memory_records(
        self,
        *,
        memory_tier: Optional[str] = None,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Portkey-style memory list (`GET /gateway/memory/records`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 50), 500)),
            "offset": max(0, int(offset or 0)),
        }
        if memory_tier:
            query["memory_tier"] = str(memory_tier).strip()
        if scope_type:
            query["scope_type"] = str(scope_type).strip()
        if scope_id:
            query["scope_id"] = str(scope_id).strip()
        data = self._get(f"/gateway/memory/records?{urlencode(query)}")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def get_memory_record(self, memory_id: str) -> dict[str, Any]:
        """Portkey-style memory get (`GET /gateway/memory/records/{id}`)."""
        mid = str(memory_id or "").strip()
        if not mid:
            raise ValueError("memory_id is required")
        from urllib.parse import quote

        payload = self._get(f"/gateway/memory/records/{quote(mid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def delete_memory_record(self, memory_id: str) -> dict[str, Any]:
        """Portkey-style memory delete (`DELETE /gateway/memory/records/{id}`)."""
        mid = str(memory_id or "").strip()
        if not mid:
            raise ValueError("memory_id is required")
        from urllib.parse import quote

        payload = self._delete(f"/gateway/memory/records/{quote(mid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def get_memory_overview(self) -> dict[str, Any]:
        """Portkey-style memory overview (`GET /gateway/memory/overview`)."""
        payload = self._get("/gateway/memory/overview")
        return payload if isinstance(payload, dict) else {}

    def get_memory_config(self) -> dict[str, Any]:
        """Portkey-style memory platform config (`GET /gateway/memory/config`)."""
        payload = self._get("/gateway/memory/config")
        return payload if isinstance(payload, dict) else {}

    def list_mcp_servers(self) -> list[dict[str, Any]]:
        """Portkey-style MCP server registry (`GET /gateway/mcp/servers`)."""
        data = self._get("/gateway/mcp/servers")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def get_endpoints_compatibility(self) -> dict[str, Any]:
        """Portkey-style endpoint family compatibility (`GET /gateway/endpoints/compatibility`)."""
        payload = self._get("/gateway/endpoints/compatibility")
        return payload if isinstance(payload, dict) else {}

    def list_notification_channels(self) -> list[dict[str, Any]]:
        """Portkey-style notification channel registry (`GET /gateway/notification-channels`)."""
        data = self._get("/gateway/notification-channels")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def list_gateway_vector_stores(self) -> list[dict[str, Any]]:
        """Portkey-style gateway vector store registry (`GET /gateway/vector-stores`)."""
        data = self._get("/gateway/vector-stores")
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def list_entitlements(
        self,
        *,
        entitlement_id: Optional[str] = None,
        action: Optional[str] = None,
        tenant_id: Optional[str] = None,
        environment: Optional[str] = None,
        enabled: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Portkey-style entitlement list (`GET /gateway/entitlements`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 100), 500)),
            "offset": max(0, int(offset or 0)),
        }
        if entitlement_id:
            query["entitlement_id"] = str(entitlement_id).strip()
        if action:
            query["action"] = str(action).strip()
        if tenant_id:
            query["tenant_id"] = str(tenant_id).strip()
        if environment:
            query["environment"] = str(environment).strip()
        if enabled is not None:
            query["enabled"] = "true" if enabled else "false"
        data = self._get(f"/gateway/entitlements?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def upsert_entitlement(
        self,
        entitlement_id: str,
        *,
        action: str,
        tenant_id: Optional[str] = None,
        environment: str = "dev",
        route_policy_id: Optional[str] = None,
        request_tag: Optional[str] = None,
        model_name: Optional[str] = None,
        tool_name: Optional[str] = None,
        allowed_roles: Optional[str] = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Portkey-style entitlement upsert (`PUT /gateway/entitlements/{entitlement_id}`)."""
        eid = str(entitlement_id or "").strip()
        if not eid:
            raise ValueError("entitlement_id is required")
        payload: dict[str, Any] = {
            "action": str(action or "").strip(),
            "environment": str(environment or "dev").strip() or "dev",
            "allowed_roles": str(allowed_roles if allowed_roles is not None else "[]"),
            "enabled": bool(enabled),
        }
        if tenant_id is not None:
            payload["tenant_id"] = str(tenant_id).strip() or None
        if route_policy_id is not None:
            payload["route_policy_id"] = str(route_policy_id).strip() or None
        if request_tag is not None:
            payload["request_tag"] = str(request_tag).strip() or None
        if model_name is not None:
            payload["model_name"] = str(model_name).strip() or None
        if tool_name is not None:
            payload["tool_name"] = str(tool_name).strip() or None
        result = self._put(f"/gateway/entitlements/{eid}", payload)
        return result if isinstance(result, dict) else {}

    def get_nhi_hygiene(
        self,
        *,
        max_credential_age_days: int = 90,
        tenant_id: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style NHI hygiene summary (`GET /gateway/nhi/hygiene`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "max_credential_age_days": max(1, min(int(max_credential_age_days or 90), 3650)),
        }
        if tenant_id:
            query["tenant_id"] = str(tenant_id).strip()
        if environment:
            query["environment"] = str(environment).strip()
        payload = self._get(f"/gateway/nhi/hygiene?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def list_nhi_inventory(
        self,
        *,
        tenant_id: Optional[str] = None,
        environment: Optional[str] = None,
        source_type: Optional[str] = None,
        status: Optional[str] = None,
        stale_only: bool = False,
        max_credential_age_days: int = 90,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Portkey-style NHI inventory (`GET /gateway/nhi/inventory`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 100), 500)),
            "offset": max(0, int(offset or 0)),
            "max_credential_age_days": max(1, min(int(max_credential_age_days or 90), 3650)),
            "stale_only": "true" if stale_only else "false",
        }
        if tenant_id:
            query["tenant_id"] = str(tenant_id).strip()
        if environment:
            query["environment"] = str(environment).strip()
        if source_type:
            query["source_type"] = str(source_type).strip()
        if status:
            query["status"] = str(status).strip()
        data = self._get(f"/gateway/nhi/inventory?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def export_nhi_inventory(
        self,
        *,
        tenant_id: Optional[str] = None,
        environment: Optional[str] = None,
        profile: str = "iga_correlation",
        target_system: str = "generic",
        stale_only: bool = False,
        missing_owner_only: bool = False,
        max_credential_age_days: int = 90,
        limit: int = 100,
        include_hygiene_summary: bool = True,
        deliver_webhook: bool = False,
        dry_run_delivery: bool = True,
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Export gateway NHI inventory for IGA correlation (`POST /gateway/nhi/export`)."""
        body: dict[str, Any] = {
            "profile": str(profile or "iga_correlation").strip(),
            "target_system": str(target_system or "generic").strip(),
            "stale_only": bool(stale_only),
            "missing_owner_only": bool(missing_owner_only),
            "max_credential_age_days": max(1, min(int(max_credential_age_days or 90), 3650)),
            "limit": max(1, min(int(limit or 100), 500)),
            "include_hygiene_summary": bool(include_hygiene_summary),
            "deliver_webhook": bool(deliver_webhook),
            "dry_run_delivery": bool(dry_run_delivery),
        }
        if tenant_id:
            body["tenant_id"] = str(tenant_id).strip()
        if environment:
            body["environment"] = str(environment).strip()
        payload = self._post("/gateway/nhi/export", body, extra_headers=headers or None)
        return payload if isinstance(payload, dict) else {}

    def get_nhi_insights(
        self,
        *,
        tenant_id: Optional[str] = None,
        environment: Optional[str] = None,
        max_credential_age_days: int = 90,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Gateway NHI Insights risk ranking (`GET /gateway/nhi/insights`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "max_credential_age_days": max(1, min(int(max_credential_age_days or 90), 3650)),
            "limit": max(1, min(int(limit or 50), 100)),
        }
        if tenant_id:
            query["tenant_id"] = str(tenant_id).strip()
        if environment:
            query["environment"] = str(environment).strip()
        payload = self._get(f"/gateway/nhi/insights?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def get_nhi_access_map(self, nhi_record_id: str) -> dict[str, Any]:
        """Gateway-plane NHI access map (`GET /gateway/nhi/{id}/access-map`)."""
        rid = str(nhi_record_id or "").strip()
        if not rid:
            raise ValueError("nhi_record_id is required")
        payload = self._get(f"/gateway/nhi/{rid}/access-map")
        return payload if isinstance(payload, dict) else {}

    def get_nhi_timeline(self, nhi_record_id: str, *, limit: int = 50) -> dict[str, Any]:
        """NHI activity timeline (`GET /gateway/nhi/{id}/timeline`)."""
        from urllib.parse import urlencode

        rid = str(nhi_record_id or "").strip()
        if not rid:
            raise ValueError("nhi_record_id is required")
        query = {"limit": max(1, min(int(limit or 50), 200))}
        payload = self._get(f"/gateway/nhi/{rid}/timeline?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def update_nhi_owner(
        self,
        nhi_record_id: str,
        *,
        owner_scope_type: str,
        owner_scope_id: str,
        purpose: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Assign NHI owner (`PUT /gateway/nhi/{id}/owner`; dual-approval)."""
        rid = str(nhi_record_id or "").strip()
        if not rid:
            raise ValueError("nhi_record_id is required")
        body: dict[str, Any] = {
            "owner_scope_type": str(owner_scope_type or "").strip(),
            "owner_scope_id": str(owner_scope_id or "").strip(),
        }
        if purpose is not None:
            body["purpose"] = str(purpose).strip() or None
        payload = self._put(f"/gateway/nhi/{rid}/owner", body, extra_headers=headers or None)
        return payload if isinstance(payload, dict) else {}

    def update_nhi_lifecycle(
        self,
        nhi_record_id: str,
        *,
        action: str,
        reason: str = "",
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """NHI lifecycle suspend/reactivate/retire (`POST /gateway/nhi/{id}/lifecycle`).

        For virtual keys this mirrors Key Lifecycle block/unblock (same VK status plane).
        """
        rid = str(nhi_record_id or "").strip()
        if not rid:
            raise ValueError("nhi_record_id is required")
        body = {
            "action": str(action or "").strip(),
            "reason": str(reason or "").strip(),
        }
        payload = self._post(f"/gateway/nhi/{rid}/lifecycle", body, extra_headers=headers or None)
        return payload if isinstance(payload, dict) else {}

    def update_nhi_intents(
        self,
        nhi_record_id: str,
        *,
        approved_intents: Optional[list[str]] = None,
        purpose: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Set approved intents for an NHI (`PUT /gateway/nhi/{id}/intents`)."""
        rid = str(nhi_record_id or "").strip()
        if not rid:
            raise ValueError("nhi_record_id is required")
        body: dict[str, Any] = {"approved_intents": list(approved_intents or [])}
        if purpose is not None:
            body["purpose"] = str(purpose).strip() or None
        payload = self._put(f"/gateway/nhi/{rid}/intents", body, extra_headers=headers or None)
        return payload if isinstance(payload, dict) else {}

    def get_nhi_governance_config(self) -> dict[str, Any]:
        """Read NHI intent_mode config (`GET /gateway/nhi/governance/config`)."""
        payload = self._get("/gateway/nhi/governance/config")
        return payload if isinstance(payload, dict) else {}

    def update_nhi_governance_config(
        self,
        *,
        intent_mode: str = "off",
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Save NHI intent_mode (`PUT /gateway/nhi/governance/config`; dual-approval)."""
        body = {"intent_mode": str(intent_mode or "off").strip() or "off"}
        payload = self._put("/gateway/nhi/governance/config", body, extra_headers=headers or None)
        return payload if isinstance(payload, dict) else {}

    def check_nhi_intent(
        self,
        *,
        declared_intent: str,
        nhi_record_id: Optional[str] = None,
        virtual_key_id: Optional[str] = None,
        action: Optional[str] = None,
    ) -> dict[str, Any]:
        """Evaluate declared intent vs approved intents (`POST /gateway/nhi/intent-check`)."""
        body: dict[str, Any] = {"declared_intent": str(declared_intent or "").strip()}
        if nhi_record_id:
            body["nhi_record_id"] = str(nhi_record_id).strip()
        if virtual_key_id:
            body["virtual_key_id"] = str(virtual_key_id).strip()
        if action:
            body["action"] = str(action).strip()
        payload = self._post("/gateway/nhi/intent-check", body)
        return payload if isinstance(payload, dict) else {}

    def get_nhi_iga_export_config(self) -> dict[str, Any]:
        """Read NHI IGA export webhook config (`GET /gateway/nhi/iga-export/config`)."""
        payload = self._get("/gateway/nhi/iga-export/config")
        return payload if isinstance(payload, dict) else {}

    def get_nhi_iga_deny_config(self) -> dict[str, Any]:
        """Read NHI IGA deny-signal config (`GET /gateway/nhi/iga-deny/config`)."""
        payload = self._get("/gateway/nhi/iga-deny/config")
        return payload if isinstance(payload, dict) else {}

    def list_nhi_iga_deny_events(self, *, limit: int = 50) -> dict[str, Any]:
        """IGA deny event history (`GET /gateway/nhi/iga-deny/events`)."""
        from urllib.parse import urlencode

        query = {"limit": max(1, min(int(limit or 50), 200))}
        payload = self._get(f"/gateway/nhi/iga-deny/events?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def list_nhi_orphans(
        self,
        *,
        tenant_id: Optional[str] = None,
        environment: Optional[str] = None,
        max_credential_age_days: int = 90,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Missing-owner orphan queue (`GET /gateway/nhi/orphans`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "max_credential_age_days": max(1, min(int(max_credential_age_days or 90), 3650)),
            "limit": max(1, min(int(limit or 100), 200)),
        }
        if tenant_id:
            query["tenant_id"] = str(tenant_id).strip()
        if environment:
            query["environment"] = str(environment).strip()
        payload = self._get(f"/gateway/nhi/orphans?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def assign_nhi_orphans(
        self,
        *,
        nhi_record_ids: list[str],
        owner_scope_type: str,
        owner_scope_id: str,
        purpose: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Bulk orphan owner assign (`POST /gateway/nhi/orphans/assign`; dual-approval)."""
        body: dict[str, Any] = {
            "nhi_record_ids": list(nhi_record_ids or []),
            "owner_scope_type": str(owner_scope_type or "").strip(),
            "owner_scope_id": str(owner_scope_id or "").strip(),
        }
        if purpose is not None:
            body["purpose"] = str(purpose).strip() or None
        payload = self._post("/gateway/nhi/orphans/assign", body, extra_headers=headers or None)
        return payload if isinstance(payload, dict) else {}

    def update_nhi_correlation(
        self,
        nhi_record_id: str,
        *,
        external_ref: Optional[str] = None,
        iga_agent_id: Optional[str] = None,
        source_system: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Set IGA correlation ids (`PUT /gateway/nhi/{id}/correlation`)."""
        rid = str(nhi_record_id or "").strip()
        if not rid:
            raise ValueError("nhi_record_id is required")
        body: dict[str, Any] = {}
        if external_ref is not None:
            body["external_ref"] = str(external_ref).strip() or None
        if iga_agent_id is not None:
            body["iga_agent_id"] = str(iga_agent_id).strip() or None
        if source_system is not None:
            body["source_system"] = str(source_system).strip() or None
        payload = self._put(f"/gateway/nhi/{rid}/correlation", body, extra_headers=headers or None)
        return payload if isinstance(payload, dict) else {}

    def export_nhi_evidence(
        self,
        *,
        tenant_id: Optional[str] = None,
        environment: Optional[str] = None,
        max_credential_age_days: int = 90,
    ) -> dict[str, Any]:
        """NHI coexistence evidence pack (`POST /gateway/nhi/evidence/export`)."""
        body: dict[str, Any] = {
            "max_credential_age_days": max(1, min(int(max_credential_age_days or 90), 3650)),
        }
        if tenant_id:
            body["tenant_id"] = str(tenant_id).strip()
        if environment:
            body["environment"] = str(environment).strip()
        payload = self._post("/gateway/nhi/evidence/export", body)
        return payload if isinstance(payload, dict) else {}

    def evaluate_nhi_iga_deny(self, **kwargs: Any) -> dict[str, Any]:
        """Evaluate whether an IGA deny matches (`POST /gateway/nhi/iga-deny/evaluate`)."""
        payload = self._post("/gateway/nhi/iga-deny/evaluate", dict(kwargs or {}))
        return payload if isinstance(payload, dict) else {}

    def get_tunnel_config(self) -> dict[str, Any]:
        """Portkey-style OpenAI-compatible tunnel config (`GET /gateway/tunnel/config`)."""
        payload = self._get("/gateway/tunnel/config")
        return payload if isinstance(payload, dict) else {}

    def get_system_instructions(self) -> dict[str, Any]:
        """Portkey-style gateway system instructions (`GET /gateway/system-instructions`)."""
        payload = self._get("/gateway/system-instructions")
        return payload if isinstance(payload, dict) else {}

    def update_system_instructions(self, *, instructions: str = "") -> dict[str, Any]:
        """Portkey-style gateway system instructions update (`PUT /gateway/system-instructions`)."""
        payload = self._put(
            "/gateway/system-instructions",
            {"instructions": str(instructions or "")},
        )
        return payload if isinstance(payload, dict) else {}

    def get_system_rules(self) -> dict[str, Any]:
        """Portkey-style gateway system rules (`GET /gateway/system-rules`)."""
        payload = self._get("/gateway/system-rules")
        return payload if isinstance(payload, dict) else {}

    def update_system_rules(self, *, rules: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
        """Portkey-style gateway system rules update (`PUT /gateway/system-rules`)."""
        payload = self._put(
            "/gateway/system-rules",
            {"rules": list(rules or [])},
        )
        return payload if isinstance(payload, dict) else {}

    def list_external_callbacks(self) -> list[dict[str, Any]]:
        """Portkey-style external callback registry (`GET /gateway/external-callbacks`)."""
        data = self._get("/gateway/external-callbacks")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def create_external_callback(
        self,
        *,
        callback_url: str,
        event_types: Optional[list[str]] = None,
        environment: str = "dev",
        sink_type: str = "generic_webhook",
        sink_route_key: Optional[str] = None,
        correlation_preset: str = "trace_resource",
        redact_sensitive: bool = True,
        enabled: bool = True,
        description: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style external callback create (`POST /gateway/external-callbacks`)."""
        body: dict[str, Any] = {
            "callback_url": str(callback_url or "").strip(),
            "event_types": list(event_types or ["gateway.route.execute_fallback"]),
            "environment": str(environment or "dev").strip() or "dev",
            "sink_type": str(sink_type or "generic_webhook").strip() or "generic_webhook",
            "correlation_preset": str(correlation_preset or "trace_resource").strip() or "trace_resource",
            "redact_sensitive": bool(redact_sensitive),
            "enabled": bool(enabled),
        }
        if sink_route_key is not None:
            body["sink_route_key"] = str(sink_route_key).strip() or None
        if description is not None:
            body["description"] = str(description).strip() or None
        payload = self._post("/gateway/external-callbacks", body)
        return payload if isinstance(payload, dict) else {}

    def update_external_callback(
        self,
        callback_id: str,
        *,
        callback_url: Optional[str] = None,
        event_types: Optional[list[str]] = None,
        environment: Optional[str] = None,
        sink_type: Optional[str] = None,
        sink_route_key: Optional[str] = None,
        correlation_preset: Optional[str] = None,
        redact_sensitive: Optional[bool] = None,
        enabled: Optional[bool] = None,
        description: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style external callback update (`PATCH /gateway/external-callbacks/{id}`)."""
        cid = str(callback_id or "").strip()
        if not cid:
            raise ValueError("callback_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {}
        if callback_url is not None:
            body["callback_url"] = str(callback_url).strip()
        if event_types is not None:
            body["event_types"] = list(event_types)
        if environment is not None:
            body["environment"] = str(environment).strip()
        if sink_type is not None:
            body["sink_type"] = str(sink_type).strip()
        if sink_route_key is not None:
            body["sink_route_key"] = str(sink_route_key).strip() or None
        if correlation_preset is not None:
            body["correlation_preset"] = str(correlation_preset).strip()
        if redact_sensitive is not None:
            body["redact_sensitive"] = bool(redact_sensitive)
        if enabled is not None:
            body["enabled"] = bool(enabled)
        if description is not None:
            body["description"] = str(description).strip() or None
        payload = self._patch(f"/gateway/external-callbacks/{quote(cid, safe='')}", body)
        return payload if isinstance(payload, dict) else {}

    def test_external_callback_delivery(
        self,
        callback_id: str,
        *,
        environment: str = "dev",
        sample_payload: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Portkey-style external callback test delivery (`POST .../test-delivery`)."""
        cid = str(callback_id or "").strip()
        if not cid:
            raise ValueError("callback_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "environment": str(environment or "dev").strip() or "dev",
            "sample_payload": dict(sample_payload or {}),
        }
        payload = self._post(f"/gateway/external-callbacks/{quote(cid, safe='')}/test-delivery", body)
        return payload if isinstance(payload, dict) else {}

    def export_external_callbacks(
        self,
        *,
        environment: Optional[str] = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Portkey-style external callback evidence export (`POST /gateway/external-callbacks/export`)."""
        body: dict[str, Any] = {
            "limit": max(1, min(int(limit or 50), 500)),
        }
        if environment is not None:
            body["environment"] = str(environment).strip() or None
        payload = self._post("/gateway/external-callbacks/export", body)
        return payload if isinstance(payload, dict) else {}

    def export_gateway_governance_evidence(
        self,
        *,
        decision_outcome: Optional[str] = None,
        limit_per_action: int = 100,
        bundle_label: str = "gateway-governance-evidence",
        data_classification: str = "confidential",
        retention_days: int = 90,
        approved_sharing_channels: Optional[list[str]] = None,
        redact_actor_login: bool = False,
    ) -> dict[str, Any]:
        """Portkey-style gateway governance evidence export (`POST /gateway/governance/evidence/export`)."""
        body: dict[str, Any] = {
            "limit_per_action": max(10, min(int(limit_per_action or 100), 500)),
            "bundle_label": str(bundle_label or "gateway-governance-evidence").strip()
            or "gateway-governance-evidence",
            "data_classification": str(data_classification or "confidential").strip() or "confidential",
            "retention_days": max(7, min(int(retention_days or 90), 2555)),
            "approved_sharing_channels": list(
                approved_sharing_channels or ["security-ops", "compliance-review"]
            ),
            "redact_actor_login": bool(redact_actor_login),
        }
        if decision_outcome is not None:
            body["decision_outcome"] = str(decision_outcome).strip() or None
        payload = self._post("/gateway/governance/evidence/export", body)
        return payload if isinstance(payload, dict) else {}

    def get_cursor_secret_binding(self) -> dict[str, Any]:
        """Portkey-style Cursor secret binding posture (`GET /gateway/cursor-secret-binding`; no raw secrets)."""
        payload = self._get("/gateway/cursor-secret-binding")
        return payload if isinstance(payload, dict) else {}

    def update_cursor_secret_binding(
        self,
        *,
        secret_provider_id: str,
        secret_ref: str,
    ) -> dict[str, Any]:
        """Portkey-style Cursor secret binding update (`PUT /gateway/cursor-secret-binding`; no raw secrets returned)."""
        payload = self._put(
            "/gateway/cursor-secret-binding",
            {
                "secret_provider_id": str(secret_provider_id or "").strip(),
                "secret_ref": str(secret_ref or "").strip(),
            },
        )
        return payload if isinstance(payload, dict) else {}

    def clear_cursor_secret_binding(self) -> dict[str, Any]:
        """Portkey-style Cursor secret binding clear (`DELETE /gateway/cursor-secret-binding`)."""
        payload = self._delete("/gateway/cursor-secret-binding")
        return payload if isinstance(payload, dict) else {}

    def list_least_privilege_recommendations(
        self,
        *,
        tenant_id: Optional[str] = None,
        environment: Optional[str] = None,
        entitlement_id: Optional[str] = None,
        recommendation_type: Optional[str] = None,
        status: Optional[str] = "pending",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Portkey-style least-privilege recommendations (`GET /gateway/least-privilege/recommendations`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 100), 500)),
            "offset": max(0, int(offset or 0)),
        }
        if tenant_id:
            query["tenant_id"] = str(tenant_id).strip()
        if environment:
            query["environment"] = str(environment).strip()
        if entitlement_id:
            query["entitlement_id"] = str(entitlement_id).strip()
        if recommendation_type:
            query["recommendation_type"] = str(recommendation_type).strip()
        if status:
            query["status"] = str(status).strip()
        data = self._get(f"/gateway/least-privilege/recommendations?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def get_decision_trace(self, trace_id: str, *, limit: int = 200) -> dict[str, Any]:
        """Portkey-style decision trace (`GET /gateway/decision-traces/{trace_id}`)."""
        tid = str(trace_id or "").strip()
        if not tid:
            raise ValueError("trace_id is required")
        from urllib.parse import quote, urlencode

        query = {"limit": max(1, min(int(limit or 200), 1000))}
        payload = self._get(
            f"/gateway/decision-traces/{quote(tid, safe='')}?{urlencode(query)}"
        )
        return payload if isinstance(payload, dict) else {}

    def get_access_review_campaign(self, campaign_id: str) -> dict[str, Any]:
        """Portkey-style access review campaign (`GET /gateway/access-reviews/campaigns/{id}`)."""
        cid = str(campaign_id or "").strip()
        if not cid:
            raise ValueError("campaign_id is required")
        from urllib.parse import quote

        payload = self._get(f"/gateway/access-reviews/campaigns/{quote(cid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def create_access_review_campaign(
        self,
        *,
        campaign_name: str,
        tenant_id: Optional[str] = None,
        environment: str = "dev",
        include_disabled: bool = False,
        reviewer_role: str = "Security Approver",
    ) -> dict[str, Any]:
        """Portkey-style access review create (`POST /gateway/access-reviews/campaigns`)."""
        name = str(campaign_name or "").strip()
        if not name:
            raise ValueError("campaign_name is required")
        body: dict[str, Any] = {
            "campaign_name": name,
            "environment": str(environment or "dev").strip() or "dev",
            "include_disabled": bool(include_disabled),
            "reviewer_role": str(reviewer_role or "Security Approver").strip() or "Security Approver",
        }
        if tenant_id:
            body["tenant_id"] = str(tenant_id).strip()
        payload = self._post("/gateway/access-reviews/campaigns", body)
        return payload if isinstance(payload, dict) else {}

    def create_jit_access_request(
        self,
        *,
        entitlement_id: str,
        justification: str,
        environment: str = "dev",
        requested_duration_minutes: int = 60,
        owner_scope_type: Optional[str] = None,
        owner_scope_id: Optional[str] = None,
        mint_virtual_key: Optional[bool] = None,
    ) -> dict[str, Any]:
        """Portkey-style JIT access request (`POST /gateway/jit-requests`)."""
        eid = str(entitlement_id or "").strip()
        if not eid:
            raise ValueError("entitlement_id is required")
        reason = str(justification or "").strip()
        if len(reason) < 8:
            raise ValueError("justification must be at least 8 characters")
        body: dict[str, Any] = {
            "entitlement_id": eid,
            "justification": reason,
            "environment": str(environment or "dev").strip() or "dev",
            "requested_duration_minutes": max(5, min(int(requested_duration_minutes or 60), 1440)),
        }
        if owner_scope_type is not None and str(owner_scope_type).strip():
            body["owner_scope_type"] = str(owner_scope_type).strip().lower()
        if owner_scope_id is not None and str(owner_scope_id).strip():
            body["owner_scope_id"] = str(owner_scope_id).strip()
        if mint_virtual_key is not None:
            body["mint_virtual_key"] = bool(mint_virtual_key)
        payload = self._post("/gateway/jit-requests", body)
        return payload if isinstance(payload, dict) else {}

    def approve_jit_access_request(
        self,
        request_id: str,
        *,
        decision: str = "approve",
        decision_reason: Optional[str] = None,
        mint_virtual_key: Optional[bool] = None,
    ) -> dict[str, Any]:
        """Portkey-style JIT approve/deny (`POST /gateway/jit-requests/{id}/approve`)."""
        rid = str(request_id or "").strip()
        if not rid:
            raise ValueError("request_id is required")
        choice = str(decision or "approve").strip().lower() or "approve"
        if choice not in {"approve", "deny"}:
            raise ValueError("decision must be one of: approve, deny")
        from urllib.parse import quote

        body: dict[str, Any] = {"decision": choice}
        if decision_reason is not None:
            body["decision_reason"] = str(decision_reason)
        if mint_virtual_key is not None:
            body["mint_virtual_key"] = bool(mint_virtual_key)
        payload = self._post(f"/gateway/jit-requests/{quote(rid, safe='')}/approve", body)
        return payload if isinstance(payload, dict) else {}

    def list_jit_access_requests(
        self,
        *,
        status: Optional[str] = None,
        environment: Optional[str] = None,
        entitlement_id: Optional[str] = None,
        requester_id: Optional[str] = None,
        active_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List gateway JIT requests (`GET /gateway/jit-requests`)."""
        from urllib.parse import urlencode

        params: dict[str, Any] = {
            "limit": max(1, min(int(limit or 50), 200)),
            "offset": max(0, int(offset or 0)),
        }
        if status:
            params["status"] = str(status).strip().lower()
        if environment:
            params["environment"] = str(environment).strip().lower()
        if entitlement_id:
            params["entitlement_id"] = str(entitlement_id).strip()
        if requester_id:
            params["requester_id"] = str(requester_id).strip()
        if active_only:
            params["active_only"] = "true"
        payload = self._get(f"/gateway/jit-requests?{urlencode(params)}")
        return payload if isinstance(payload, dict) else {"total": 0, "data": []}

    def get_jit_access_request(self, request_id: str) -> dict[str, Any]:
        """Get one gateway JIT request (`GET /gateway/jit-requests/{id}`)."""
        from urllib.parse import quote

        rid = str(request_id or "").strip()
        if not rid:
            raise ValueError("request_id is required")
        payload = self._get(f"/gateway/jit-requests/{quote(rid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def revoke_jit_access_request(
        self,
        request_id: str,
        *,
        reason: Optional[str] = None,
    ) -> dict[str, Any]:
        """Revoke a gateway JIT grant (`POST /gateway/jit-requests/{id}/revoke`)."""
        from urllib.parse import quote

        rid = str(request_id or "").strip()
        if not rid:
            raise ValueError("request_id is required")
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = str(reason)
        payload = self._post(f"/gateway/jit-requests/{quote(rid, safe='')}/revoke", body)
        return payload if isinstance(payload, dict) else {}

    def expire_jit_access_grants(self, *, limit: int = 200) -> dict[str, Any]:
        """Expire stale approved JIT grants (`POST /gateway/jit-requests/expire-tick`)."""
        from urllib.parse import urlencode

        params = urlencode({"limit": max(1, min(int(limit or 200), 1000))})
        payload = self._post(f"/gateway/jit-requests/expire-tick?{params}", {})
        return payload if isinstance(payload, dict) else {}

    def get_jit_decision_notify_config(self) -> dict[str, Any]:
        """Get JIT email/external REST decision notify config."""
        payload = self._get("/gateway/jit-decision-notify/config")
        return payload if isinstance(payload, dict) else {}

    def update_jit_decision_notify_config(
        self,
        config: dict[str, Any],
        *,
        approver_role: Optional[str] = None,
        approver_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Update JIT decision notify config (dual-approval headers recommended)."""
        headers: dict[str, str] = {}
        if approver_role:
            headers["X-Approver-Role"] = str(approver_role)
        if approver_id:
            headers["X-Approver-Id"] = str(approver_id)
        payload = self._put(
            "/gateway/jit-decision-notify/config",
            config or {},
            extra_headers=headers or None,
        )
        return payload if isinstance(payload, dict) else {}

    def test_jit_decision_notify_delivery(self) -> dict[str, Any]:
        """Probe email/webhook delivery for JIT decision notify config."""
        payload = self._post("/gateway/jit-decision-notify/test-delivery", {})
        return payload if isinstance(payload, dict) else {}

    def notify_jit_access_request(
        self,
        request_id: str,
        *,
        reminder: bool = False,
        force: bool = False,
        escalate: bool = False,
    ) -> dict[str, Any]:
        """Send JIT review emails / external REST events for a request."""
        rid = str(request_id or "").strip()
        if not rid:
            raise ValueError("request_id is required")
        from urllib.parse import quote, urlencode

        params: dict[str, str] = {}
        if reminder:
            params["reminder"] = "true"
        if escalate:
            params["escalate"] = "true"
        if force:
            params["force"] = "true"
        qs = f"?{urlencode(params)}" if params else ""
        payload = self._post(f"/gateway/jit-requests/{quote(rid, safe='')}/notify{qs}", {})
        return payload if isinstance(payload, dict) else {}

    def run_jit_notify_tick(self, *, limit: int = 100) -> dict[str, Any]:
        """Run SLA reminder/escalation/retry tick for pending JIT requests."""
        from urllib.parse import urlencode

        params = urlencode({"limit": str(max(1, min(int(limit or 100), 500)))})
        payload = self._post(f"/gateway/jit-requests/notify-tick?{params}", {})
        return payload if isinstance(payload, dict) else {}

    def get_jit_pending_notify_summary(self) -> dict[str, Any]:
        """Read pending JIT notify SLA summary."""
        payload = self._get("/gateway/jit-decision-notify/pending-summary")
        return payload if isinstance(payload, dict) else {}

    def retry_jit_notify_webhooks(self, request_id: str) -> dict[str, Any]:
        """Retry failed webhook deliveries for a JIT request."""
        rid = str(request_id or "").strip()
        if not rid:
            raise ValueError("request_id is required")
        from urllib.parse import quote

        payload = self._post(f"/gateway/jit-requests/{quote(rid, safe='')}/notify-retry", {})
        return payload if isinstance(payload, dict) else {}

    def get_jit_notify_history(self, request_id: str) -> dict[str, Any]:
        """Read notify delivery history for a JIT request."""
        rid = str(request_id or "").strip()
        if not rid:
            raise ValueError("request_id is required")
        from urllib.parse import quote

        payload = self._get(f"/gateway/jit-requests/{quote(rid, safe='')}/notify-history")
        return payload if isinstance(payload, dict) else {}

    def preview_jit_action_links(
        self,
        request_id: str,
        *,
        reviewer_email: str = "preview@example.com",
    ) -> dict[str, Any]:
        """Preview signed email approve/deny links for a JIT request."""
        rid = str(request_id or "").strip()
        if not rid:
            raise ValueError("request_id is required")
        from urllib.parse import quote, urlencode

        params = urlencode({"reviewer_email": str(reviewer_email or "preview@example.com").strip()})
        payload = self._post(
            f"/gateway/jit-requests/{quote(rid, safe='')}/preview-action-links?{params}",
            {},
        )
        return payload if isinstance(payload, dict) else {}

    def apply_least_privilege_recommendation(
        self,
        recommendation_id: str,
        *,
        decision_reason: Optional[str] = None,
        change_ticket_id: Optional[str] = None,
        review_evidence_uri: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style LPR apply (`POST /gateway/least-privilege/recommendations/{id}/apply`)."""
        rid = str(recommendation_id or "").strip()
        if not rid:
            raise ValueError("recommendation_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {}
        if decision_reason is not None:
            body["decision_reason"] = str(decision_reason)
        if change_ticket_id is not None:
            body["change_ticket_id"] = str(change_ticket_id).strip()
        if review_evidence_uri is not None:
            body["review_evidence_uri"] = str(review_evidence_uri).strip()
        payload = self._post(
            f"/gateway/least-privilege/recommendations/{quote(rid, safe='')}/apply",
            body,
        )
        return payload if isinstance(payload, dict) else {}

    def list_mcp_tools(self, server_id: str, *, environment: str = "dev") -> dict[str, Any]:
        """Portkey-style MCP tool list (`POST /gateway/mcp/servers/{id}/tools/list`)."""
        sid = str(server_id or "").strip()
        if not sid:
            raise ValueError("server_id is required")
        from urllib.parse import quote

        payload = self._post(
            f"/gateway/mcp/servers/{quote(sid, safe='')}/tools/list",
            {"environment": str(environment or "dev").strip() or "dev"},
        )
        return payload if isinstance(payload, dict) else {}

    def call_mcp_tool(
        self,
        server_id: str,
        tool_name: str,
        *,
        arguments: Optional[dict[str, Any]] = None,
        environment: str = "dev",
    ) -> dict[str, Any]:
        """Portkey-style MCP tool call (`POST /gateway/mcp/servers/{id}/tools/call`)."""
        sid = str(server_id or "").strip()
        name = str(tool_name or "").strip()
        if not sid:
            raise ValueError("server_id is required")
        if not name:
            raise ValueError("tool_name is required")
        from urllib.parse import quote

        payload = self._post(
            f"/gateway/mcp/servers/{quote(sid, safe='')}/tools/call",
            {
                "environment": str(environment or "dev").strip() or "dev",
                "tool_name": name,
                "arguments": arguments if isinstance(arguments, dict) else {},
            },
        )
        return payload if isinstance(payload, dict) else {}

    def list_routes(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Portkey-style route policy inventory (`GET /gateway/routes`)."""
        from urllib.parse import urlencode

        query = {
            "limit": max(1, min(int(limit or 50), 500)),
            "offset": max(0, int(offset or 0)),
        }
        data = self._get(f"/gateway/routes?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("items") or data.get("data") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def get_route(self, route_policy_id: str) -> dict[str, Any]:
        """Portkey-style route policy get (`GET /gateway/routes/{id}`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote

        payload = self._get(f"/gateway/routes/{quote(rid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def create_route(
        self,
        *,
        route_name: str,
        candidate_deployments: str = "[]",
        load_balancing_strategy: str = "weighted",
        retry_policy: str = "{}",
        fallback_policy: str = "{}",
        timeout_policy: str = "{}",
    ) -> dict[str, Any]:
        """Portkey-style route policy create (`POST /gateway/routes`)."""
        body = {
            "route_name": str(route_name or "").strip(),
            "candidate_deployments": str(candidate_deployments or "[]"),
            "load_balancing_strategy": str(load_balancing_strategy or "weighted").strip() or "weighted",
            "retry_policy": str(retry_policy or "{}"),
            "fallback_policy": str(fallback_policy or "{}"),
            "timeout_policy": str(timeout_policy or "{}"),
        }
        payload = self._post("/gateway/routes", body)
        return payload if isinstance(payload, dict) else {}


    def list_cost_anomalies(self) -> list[dict[str, Any]]:
        """Portkey/Helicone-style cost anomaly list (`GET /cost/anomalies`)."""
        payload = self._get("/cost/anomalies")
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            items = payload.get("items") or payload.get("data") or payload.get("anomalies") or []
            return [item for item in items if isinstance(item, dict)]
        return []

    def evaluate_cost_limits(
        self,
        *,
        actor_id: Optional[str] = None,
        team_ids: Optional[list[str]] = None,
        group_ids: Optional[list[str]] = None,
        agent_ids: Optional[list[str]] = None,
        window_type: str = "daily",
        projected_additional_cost_cents: int = 0,
    ) -> dict[str, Any]:
        """Portkey-style preflight cost limit evaluation (`POST /cost/limits/evaluate`)."""
        body: dict[str, Any] = {
            "window_type": str(window_type or "daily").strip() or "daily",
            "projected_additional_cost_cents": max(0, int(projected_additional_cost_cents or 0)),
            "team_ids": [str(x).strip() for x in (team_ids or []) if str(x).strip()],
            "group_ids": [str(x).strip() for x in (group_ids or []) if str(x).strip()],
            "agent_ids": [str(x).strip() for x in (agent_ids or []) if str(x).strip()],
        }
        if actor_id:
            body["actor_id"] = str(actor_id).strip()
        payload = self._post("/cost/limits/evaluate", body)
        return payload if isinstance(payload, dict) else {}



    def list_cost_requests(
        self,
        *,
        window_hours: int = 24,
        user_id: Optional[str] = None,
        model: Optional[str] = None,
        property_key: Optional[str] = None,
        property_value: Optional[str] = None,
        cache_hit: Optional[bool] = None,
        has_feedback: Optional[bool] = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Helicone-style request search (`GET /cost/requests`; metadata + spend only)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "limit": max(1, min(int(limit or 50), 200)),
        }
        if user_id:
            query["user_id"] = str(user_id).strip()
        if model:
            query["model"] = str(model).strip()
        if property_key:
            query["property_key"] = str(property_key).strip()
        if property_value:
            query["property_value"] = str(property_value).strip()
        if cache_hit is not None:
            query["cache_hit"] = "true" if cache_hit else "false"
        if has_feedback is not None:
            query["has_feedback"] = "true" if has_feedback else "false"
        payload = self._get(f"/cost/requests?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def get_cost_session_tree(
        self,
        *,
        window_hours: int = 24,
        path_prefix: Optional[str] = None,
        max_depth: int = 4,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Helicone-style session path tree (`GET /cost/sessions/tree`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "max_depth": max(1, min(int(max_depth or 4), 16)),
            "limit": max(1, min(int(limit or 50), 200)),
        }
        if path_prefix:
            query["path_prefix"] = str(path_prefix).strip()
        payload = self._get(f"/cost/sessions/tree?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_rollout_timeseries(
        self,
        *,
        window_hours: int = 24,
        rollout_filter: Optional[str] = None,
        top_rollouts: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style rollout burn timeseries (`GET /cost/rollouts/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_rollouts": max(1, min(int(top_rollouts or 8), 20)),
        }
        if rollout_filter:
            query["rollout_filter"] = str(rollout_filter).strip()
        payload = self._get(f"/cost/rollouts/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def get_cost_route_timeseries(
        self,
        *,
        window_hours: int = 24,
        route_filter: Optional[str] = None,
        top_routes: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style route burn timeseries (`GET /cost/routes/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_routes": max(1, min(int(top_routes or 8), 20)),
        }
        if route_filter:
            query["route_filter"] = str(route_filter).strip()
        payload = self._get(f"/cost/routes/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_batch_timeseries(
        self,
        *,
        window_hours: int = 24,
        batch_filter: Optional[str] = None,
        top_batches: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style batch burn timeseries (`GET /cost/batches/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_batches": max(1, min(int(top_batches or 8), 20)),
        }
        if batch_filter:
            query["batch_filter"] = str(batch_filter).strip()
        payload = self._get(f"/cost/batches/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def get_cost_job_timeseries(
        self,
        *,
        window_hours: int = 24,
        job_filter: Optional[str] = None,
        top_jobs: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style job burn timeseries (`GET /cost/jobs/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_jobs": max(1, min(int(top_jobs or 8), 20)),
        }
        if job_filter:
            query["job_filter"] = str(job_filter).strip()
        payload = self._get(f"/cost/jobs/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_queue_timeseries(
        self,
        *,
        window_hours: int = 24,
        queue_filter: Optional[str] = None,
        top_queues: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style queue burn timeseries (`GET /cost/queues/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_queues": max(1, min(int(top_queues or 8), 20)),
        }
        if queue_filter:
            query["queue_filter"] = str(queue_filter).strip()
        payload = self._get(f"/cost/queues/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def get_cost_topic_timeseries(
        self,
        *,
        window_hours: int = 24,
        topic_filter: Optional[str] = None,
        top_topics: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style topic burn timeseries (`GET /cost/topics/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_topics": max(1, min(int(top_topics or 8), 20)),
        }
        if topic_filter:
            query["topic_filter"] = str(topic_filter).strip()
        payload = self._get(f"/cost/topics/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_pipeline_timeseries(
        self,
        *,
        window_hours: int = 24,
        pipeline_filter: Optional[str] = None,
        top_pipelines: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style pipeline burn timeseries (`GET /cost/pipelines/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_pipelines": max(1, min(int(top_pipelines or 8), 20)),
        }
        if pipeline_filter:
            query["pipeline_filter"] = str(pipeline_filter).strip()
        payload = self._get(f"/cost/pipelines/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_run_timeseries(
        self,
        *,
        window_hours: int = 24,
        run_filter: Optional[str] = None,
        top_runs: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style run burn timeseries (`GET /cost/runs/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_runs": max(1, min(int(top_runs or 8), 20)),
        }
        if run_filter:
            query["run_filter"] = str(run_filter).strip()
        payload = self._get(f"/cost/runs/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_worker_timeseries(
        self,
        *,
        window_hours: int = 24,
        worker_filter: Optional[str] = None,
        top_workers: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style worker burn timeseries (`GET /cost/workers/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_workers": max(1, min(int(top_workers or 8), 20)),
        }
        if worker_filter:
            query["worker_filter"] = str(worker_filter).strip()
        payload = self._get(f"/cost/workers/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def get_cost_slot_timeseries(
        self,
        *,
        window_hours: int = 24,
        slot_filter: Optional[str] = None,
        top_slots: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style slot burn timeseries (`GET /cost/slots/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_slots": max(1, min(int(top_slots or 8), 20)),
        }
        if slot_filter:
            query["slot_filter"] = str(slot_filter).strip()
        payload = self._get(f"/cost/slots/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_task_timeseries(
        self,
        *,
        window_hours: int = 24,
        task_filter: Optional[str] = None,
        top_tasks: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style task burn timeseries (`GET /cost/tasks/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_tasks": max(1, min(int(top_tasks or 8), 20)),
        }
        if task_filter:
            query["task_filter"] = str(task_filter).strip()
        payload = self._get(f"/cost/tasks/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_step_timeseries(
        self,
        *,
        window_hours: int = 24,
        step_filter: Optional[str] = None,
        top_steps: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style step burn timeseries (`GET /cost/steps/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_steps": max(1, min(int(top_steps or 8), 20)),
        }
        if step_filter:
            query["step_filter"] = str(step_filter).strip()
        payload = self._get(f"/cost/steps/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_replica_timeseries(
        self,
        *,
        window_hours: int = 24,
        replica_filter: Optional[str] = None,
        top_replicas: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style replica burn timeseries (`GET /cost/replicas/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_replicas": max(1, min(int(top_replicas or 8), 20)),
        }
        if replica_filter:
            query["replica_filter"] = str(replica_filter).strip()
        payload = self._get(f"/cost/replicas/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_shard_timeseries(
        self,
        *,
        window_hours: int = 24,
        shard_filter: Optional[str] = None,
        top_shards: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style shard burn timeseries (`GET /cost/shards/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_shards": max(1, min(int(top_shards or 8), 20)),
        }
        if shard_filter:
            query["shard_filter"] = str(shard_filter).strip()
        payload = self._get(f"/cost/shards/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_partition_timeseries(
        self,
        *,
        window_hours: int = 24,
        partition_filter: Optional[str] = None,
        top_partitions: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style partition burn timeseries (`GET /cost/partitions/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_partitions": max(1, min(int(top_partitions or 8), 20)),
        }
        if partition_filter:
            query["partition_filter"] = str(partition_filter).strip()
        payload = self._get(f"/cost/partitions/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_consumer_timeseries(
        self,
        *,
        window_hours: int = 24,
        consumer_filter: Optional[str] = None,
        top_consumers: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style consumer burn timeseries (`GET /cost/consumers/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_consumers": max(1, min(int(top_consumers or 8), 20)),
        }
        if consumer_filter:
            query["consumer_filter"] = str(consumer_filter).strip()
        payload = self._get(f"/cost/consumers/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_producer_timeseries(
        self,
        *,
        window_hours: int = 24,
        producer_filter: Optional[str] = None,
        top_producers: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style producer burn timeseries (`GET /cost/producers/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_producers": max(1, min(int(top_producers or 8), 20)),
        }
        if producer_filter:
            query["producer_filter"] = str(producer_filter).strip()
        payload = self._get(f"/cost/producers/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_gpu_timeseries(
        self,
        *,
        window_hours: int = 24,
        gpu_filter: Optional[str] = None,
        top_gpus: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style gpu burn timeseries (`GET /cost/gpus/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_gpus": max(1, min(int(top_gpus or 8), 20)),
        }
        if gpu_filter:
            query["gpu_filter"] = str(gpu_filter).strip()
        payload = self._get(f"/cost/gpus/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_accelerator_timeseries(
        self,
        *,
        window_hours: int = 24,
        accelerator_filter: Optional[str] = None,
        top_accelerators: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style accelerator burn timeseries (`GET /cost/accelerators/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_accelerators": max(1, min(int(top_accelerators or 8), 20)),
        }
        if accelerator_filter:
            query["accelerator_filter"] = str(accelerator_filter).strip()
        payload = self._get(f"/cost/accelerators/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_cell_timeseries(
        self,
        *,
        window_hours: int = 24,
        cell_filter: Optional[str] = None,
        top_cells: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style cell burn timeseries (`GET /cost/cells/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_cells": max(1, min(int(top_cells or 8), 20)),
        }
        if cell_filter:
            query["cell_filter"] = str(cell_filter).strip()
        payload = self._get(f"/cost/cells/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_zone_timeseries(
        self,
        *,
        window_hours: int = 24,
        zone_filter: Optional[str] = None,
        top_zones: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style zone burn timeseries (`GET /cost/zones/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_zones": max(1, min(int(top_zones or 8), 20)),
        }
        if zone_filter:
            query["zone_filter"] = str(zone_filter).strip()
        payload = self._get(f"/cost/zones/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_rack_timeseries(
        self,
        *,
        window_hours: int = 24,
        rack_filter: Optional[str] = None,
        top_racks: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style rack burn timeseries (`GET /cost/racks/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_racks": max(1, min(int(top_racks or 8), 20)),
        }
        if rack_filter:
            query["rack_filter"] = str(rack_filter).strip()
        payload = self._get(f"/cost/racks/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_pool_timeseries(
        self,
        *,
        window_hours: int = 24,
        pool_filter: Optional[str] = None,
        top_pools: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style pool burn timeseries (`GET /cost/pools/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_pools": max(1, min(int(top_pools or 8), 20)),
        }
        if pool_filter:
            query["pool_filter"] = str(pool_filter).strip()
        payload = self._get(f"/cost/pools/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_fleet_timeseries(
        self,
        *,
        window_hours: int = 24,
        fleet_filter: Optional[str] = None,
        top_fleets: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style fleet burn timeseries (`GET /cost/fleets/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_fleets": max(1, min(int(top_fleets or 8), 20)),
        }
        if fleet_filter:
            query["fleet_filter"] = str(fleet_filter).strip()
        payload = self._get(f"/cost/fleets/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_lease_timeseries(
        self,
        *,
        window_hours: int = 24,
        lease_filter: Optional[str] = None,
        top_leases: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style lease burn timeseries (`GET /cost/leases/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_leases": max(1, min(int(top_leases or 8), 20)),
        }
        if lease_filter:
            query["lease_filter"] = str(lease_filter).strip()
        payload = self._get(f"/cost/leases/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}


    def get_cost_quota_timeseries(
        self,
        *,
        window_hours: int = 24,
        quota_filter: Optional[str] = None,
        top_quotas: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style quota burn timeseries (`GET /cost/quotas/timeseries`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "top_quotas": max(1, min(int(top_quotas or 8), 20)),
        }
        if quota_filter:
            query["quota_filter"] = str(quota_filter).strip()
        payload = self._get(f"/cost/quotas/timeseries?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def get_cost_live(self) -> dict[str, Any]:
        """Helicone-style live burn snapshot (`GET /cost/live`)."""
        payload = self._get("/cost/live")
        return payload if isinstance(payload, dict) else {}

    def get_cost_breakdown(
        self,
        *,
        dimension: str = "all",
        window_hours: int = 24,
        limit: int = 8,
    ) -> dict[str, Any]:
        """Helicone-style cost breakdown (`GET /cost/breakdown`)."""
        from urllib.parse import urlencode

        query = {
            "dimension": str(dimension or "all").strip() or "all",
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "limit": max(1, min(int(limit or 8), 50)),
        }
        payload = self._get(f"/cost/breakdown?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def export_cost(
        self,
        *,
        window_hours: int = 24,
        dimension: str = "all",
        scope_filter: Optional[str] = None,
        property_key: Optional[str] = None,
        property_value: Optional[str] = None,
        limit: int = 1000,
    ) -> str:
        """Helicone-style cost events CSV export (`GET /cost/export`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "window_hours": max(1, min(int(window_hours or 24), 24 * 30)),
            "dimension": str(dimension or "all").strip() or "all",
            "limit": max(1, min(int(limit or 1000), 5000)),
        }
        if scope_filter:
            query["scope_filter"] = str(scope_filter).strip()
        if property_key:
            query["property_key"] = str(property_key).strip()
        if property_value:
            query["property_value"] = str(property_value).strip()
        return self._get_text(f"/cost/export?{urlencode(query)}")

    def get_gateway_analytics_summary(
        self,
        *,
        hours: int = 24,
        environment: Optional[str] = None,
    ) -> dict[str, Any]:
        """Analytics summary (`GET /gateway/analytics/summary`).

        Includes Leader Readiness on-plane fields: ``on_plane_coverage_percent``,
        ``on_plane_events``, ``off_plane_detected``, nested ``on_plane_coverage``.
        """
        from urllib.parse import urlencode

        query: dict[str, object] = {"hours": max(1, min(int(hours or 24), 168))}
        if environment:
            query["environment"] = str(environment).strip()
        payload = self._get(f"/gateway/analytics/summary?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def get_leadership_qbr_snapshot(
        self,
        *,
        hours: int = 2160,
        environment: Optional[str] = None,
    ) -> dict[str, Any]:
        """Numbers-first QBR pack (`GET /gateway/governance/qbr-snapshot`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {"hours": max(1, min(int(hours or 2160), 4320))}
        if environment:
            query["environment"] = str(environment).strip()
        payload = self._get(f"/gateway/governance/qbr-snapshot?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def list_leadership_drill_runs(
        self,
        *,
        drill_id: Optional[str] = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List dated Clock/RT drill attestations."""
        from urllib.parse import urlencode

        query: dict[str, object] = {"limit": max(1, min(int(limit or 50), 200))}
        if drill_id:
            query["drill_id"] = str(drill_id).strip()
        payload = self._get(f"/gateway/governance/drill-runs?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def record_leadership_drill_run(self, body: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Record a dated drill after a real exercise."""
        payload = self._post("/gateway/governance/drill-runs", body or {})
        return payload if isinstance(payload, dict) else {}

    def get_route_provider_health(
        self,
        route_policy_id: str,
        *,
        request_tag: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style route provider health (`GET /gateway/routes/{id}/providers/health`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        path = f"/gateway/routes/{quote(rid, safe='')}/providers/health"
        if request_tag:
            path = f"{path}?{urlencode({'request_tag': str(request_tag).strip()})}"
        payload = self._get(path)
        return payload if isinstance(payload, dict) else {}

    def get_route_provider_priority(
        self,
        route_policy_id: str,
        *,
        request_tag: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style route provider priority (`GET /gateway/routes/{id}/providers/priority`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        path = f"/gateway/routes/{quote(rid, safe='')}/providers/priority"
        if request_tag:
            path = f"{path}?{urlencode({'request_tag': str(request_tag).strip()})}"
        payload = self._get(path)
        return payload if isinstance(payload, dict) else {}

    def upsert_route_provider_priority(
        self,
        route_policy_id: str,
        *,
        tenant_id: str,
        environment: str = "prod",
        request_tag: Optional[str] = None,
        priority_order: str = "[]",
        global_timeout_ms: int = 4500,
        max_fallback_hops: int = 2,
        health_check_enabled: bool = False,
        budget_limit_cents: Optional[int] = None,
    ) -> dict[str, Any]:
        """Portkey-style provider priority upsert (`POST /gateway/routes/{id}/providers/priority`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "tenant_id": str(tenant_id or "").strip(),
            "environment": str(environment or "prod").strip() or "prod",
            "priority_order": str(priority_order if priority_order is not None else "[]"),
            "global_timeout_ms": max(100, min(int(global_timeout_ms or 4500), 120000)),
            "max_fallback_hops": max(0, min(int(max_fallback_hops or 0), 10)),
            "health_check_enabled": bool(health_check_enabled),
        }
        if request_tag is not None:
            body["request_tag"] = str(request_tag).strip() or None
        if budget_limit_cents is not None:
            body["budget_limit_cents"] = int(budget_limit_cents)
        payload = self._post(f"/gateway/routes/{quote(rid, safe='')}/providers/priority", body)
        return payload if isinstance(payload, dict) else {}

    def upsert_route_provider_health(
        self,
        route_policy_id: str,
        *,
        entries: Optional[list[dict[str, Any]]] = None,
        request_tag: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style provider health upsert (`PUT /gateway/routes/{id}/providers/health`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {"entries": list(entries or [])}
        if request_tag is not None:
            body["request_tag"] = str(request_tag).strip() or None
        payload = self._put(f"/gateway/routes/{quote(rid, safe='')}/providers/health", body)
        return payload if isinstance(payload, dict) else {}

    def get_route_provider_priority_timeline(
        self,
        route_policy_id: str,
        *,
        limit: int = 25,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Portkey-style provider priority timeline (`GET /gateway/routes/{id}/providers/priority/timeline`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        query = {
            "limit": max(1, min(int(limit or 25), 200)),
            "offset": max(0, int(offset or 0)),
        }
        payload = self._get(
            f"/gateway/routes/{quote(rid, safe='')}/providers/priority/timeline?{urlencode(query)}"
        )
        return payload if isinstance(payload, dict) else {}

    def get_route_traffic_mirroring_analytics_summary(
        self,
        route_policy_id: str,
        *,
        hours: int = 24,
        request_tag: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style traffic mirroring analytics (`GET /gateway/routes/{id}/traffic-mirroring/analytics-summary`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        query: dict[str, object] = {"hours": max(1, min(int(hours or 24), 168))}
        if request_tag:
            query["request_tag"] = str(request_tag).strip()
        if environment:
            query["environment"] = str(environment).strip()
        payload = self._get(
            f"/gateway/routes/{quote(rid, safe='')}/traffic-mirroring/analytics-summary?{urlencode(query)}"
        )
        return payload if isinstance(payload, dict) else {}

    def get_route_traffic_mirroring_experiment_report(
        self,
        route_policy_id: str,
        *,
        hours: int = 24,
        request_tag: Optional[str] = None,
        environment: Optional[str] = None,
        limit: int = 25,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Portkey-style traffic mirroring experiment report (`GET /gateway/routes/{id}/traffic-mirroring/experiment-report`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        query: dict[str, object] = {
            "hours": max(1, min(int(hours or 24), 168)),
            "limit": max(1, min(int(limit or 25), 200)),
            "offset": max(0, int(offset or 0)),
        }
        if request_tag:
            query["request_tag"] = str(request_tag).strip()
        if environment:
            query["environment"] = str(environment).strip()
        payload = self._get(
            f"/gateway/routes/{quote(rid, safe='')}/traffic-mirroring/experiment-report?{urlencode(query)}"
        )
        return payload if isinstance(payload, dict) else {}

    def simulate_route_fallback(
        self,
        route_policy_id: str,
        *,
        tenant_id: str,
        environment: str = "prod",
        request_tag: Optional[str] = None,
        requested_region: Optional[str] = None,
        simulate_fail_provider_ids: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style dry-run fallback simulation (`POST /gateway/routes/{id}/simulate-fallback`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        tid = str(tenant_id or "").strip()
        if not tid:
            raise ValueError("tenant_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "tenant_id": tid,
            "environment": str(environment or "prod").strip() or "prod",
            "simulate_fail_provider_ids": str(simulate_fail_provider_ids or "[]"),
        }
        if request_tag:
            body["request_tag"] = str(request_tag).strip()
        if requested_region:
            body["requested_region"] = str(requested_region).strip()
        payload = self._post(f"/gateway/routes/{quote(rid, safe='')}/simulate-fallback", body)
        return payload if isinstance(payload, dict) else {}

    def get_route_traffic_mirroring(
        self,
        route_policy_id: str,
        *,
        request_tag: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style traffic mirroring policy (`GET /gateway/routes/{id}/traffic-mirroring`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        path = f"/gateway/routes/{quote(rid, safe='')}/traffic-mirroring"
        if request_tag:
            path = f"{path}?{urlencode({'request_tag': str(request_tag).strip()})}"
        payload = self._get(path)
        return payload if isinstance(payload, dict) else {}

    def upsert_route_traffic_mirroring(
        self,
        route_policy_id: str,
        *,
        tenant_id: str,
        environment: str = "prod",
        request_tag: Optional[str] = None,
        mirror_targets: str = "[]",
        enabled: bool = True,
        max_live_attempts: int = 1,
    ) -> dict[str, Any]:
        """Portkey-style traffic mirroring upsert (`PUT /gateway/routes/{id}/traffic-mirroring`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "tenant_id": str(tenant_id or "").strip(),
            "environment": str(environment or "prod").strip() or "prod",
            "mirror_targets": str(mirror_targets if mirror_targets is not None else "[]"),
            "enabled": bool(enabled),
            "max_live_attempts": max(0, min(int(max_live_attempts or 0), 3)),
        }
        if request_tag is not None:
            body["request_tag"] = str(request_tag).strip() or None
        payload = self._put(f"/gateway/routes/{quote(rid, safe='')}/traffic-mirroring", body)
        return payload if isinstance(payload, dict) else {}

    def get_route_canary_rollout(
        self,
        route_policy_id: str,
        *,
        request_tag: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style canary rollout policy (`GET /gateway/routes/{id}/canary-rollout`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        path = f"/gateway/routes/{quote(rid, safe='')}/canary-rollout"
        if request_tag:
            path = f"{path}?{urlencode({'request_tag': str(request_tag).strip()})}"
        payload = self._get(path)
        return payload if isinstance(payload, dict) else {}

    def upsert_route_canary_rollout(
        self,
        route_policy_id: str,
        *,
        tenant_id: str,
        baseline_provider_id: str,
        environment: str = "prod",
        request_tag: Optional[str] = None,
        canary_targets: str = "[]",
        cohort_request_tags: str = "[]",
        cohort_owner_scopes: str = "[]",
        gate_min_requests: Optional[int] = None,
        gate_max_failure_rate: Optional[float] = None,
        gate_min_success_rate: Optional[float] = None,
        enabled: bool = True,
        notes: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style canary rollout upsert (`PUT /gateway/routes/{id}/canary-rollout`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "tenant_id": str(tenant_id or "").strip(),
            "environment": str(environment or "prod").strip() or "prod",
            "baseline_provider_id": str(baseline_provider_id or "").strip(),
            "canary_targets": str(canary_targets if canary_targets is not None else "[]"),
            "cohort_request_tags": str(cohort_request_tags if cohort_request_tags is not None else "[]"),
            "cohort_owner_scopes": str(cohort_owner_scopes if cohort_owner_scopes is not None else "[]"),
            "enabled": bool(enabled),
        }
        if request_tag is not None:
            body["request_tag"] = str(request_tag).strip() or None
        if gate_min_requests is not None:
            body["gate_min_requests"] = int(gate_min_requests)
        if gate_max_failure_rate is not None:
            body["gate_max_failure_rate"] = float(gate_max_failure_rate)
        if gate_min_success_rate is not None:
            body["gate_min_success_rate"] = float(gate_min_success_rate)
        if notes is not None:
            body["notes"] = str(notes)
        payload = self._put(f"/gateway/routes/{quote(rid, safe='')}/canary-rollout", body)
        return payload if isinstance(payload, dict) else {}

    def stop_route_canary_rollout(
        self,
        route_policy_id: str,
        *,
        request_tag: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style canary stop (`POST /gateway/routes/{id}/canary-rollout/stop`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        path = f"/gateway/routes/{quote(rid, safe='')}/canary-rollout/stop"
        if request_tag:
            path = f"{path}?{urlencode({'request_tag': str(request_tag).strip()})}"
        body: dict[str, Any] = {}
        if notes is not None:
            body["notes"] = str(notes)
        payload = self._post(path, body)
        return payload if isinstance(payload, dict) else {}

    def promote_route_canary_rollout(
        self,
        route_policy_id: str,
        *,
        request_tag: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style canary promote (`POST /gateway/routes/{id}/canary-rollout/promote`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        path = f"/gateway/routes/{quote(rid, safe='')}/canary-rollout/promote"
        if request_tag:
            path = f"{path}?{urlencode({'request_tag': str(request_tag).strip()})}"
        body: dict[str, Any] = {}
        if notes is not None:
            body["notes"] = str(notes)
        payload = self._post(path, body)
        return payload if isinstance(payload, dict) else {}

    def optimize_route(
        self,
        route_policy_id: str,
        *,
        optimize_for: str = "balanced",
        environment: str = "prod",
    ) -> dict[str, Any]:
        """Portkey-style route optimize (`POST /gateway/routes/{id}/optimize`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote

        goal = str(optimize_for or "balanced").strip().lower() or "balanced"
        if goal not in {"balanced", "cost", "latency"}:
            raise ValueError("optimize_for must be one of: balanced, cost, latency")
        body: dict[str, Any] = {
            "optimize_for": goal,
            "environment": str(environment or "prod").strip() or "prod",
        }
        payload = self._post(f"/gateway/routes/{quote(rid, safe='')}/optimize", body)
        return payload if isinstance(payload, dict) else {}

    def execute_route_fallback(
        self,
        route_policy_id: str,
        *,
        tenant_id: str,
        agent_id: str,
        environment: str = "prod",
        request_tag: Optional[str] = None,
        requested_region: Optional[str] = None,
        request_priority: str = "normal",
        model_name: Optional[str] = None,
        session_id: str = "gateway-session",
        owner_scope: Optional[str] = None,
        owner_scope_type: Optional[str] = None,
        owner_scope_id: Optional[str] = None,
        endpoint_family: str = "responses",
        input_tokens: int = 100,
        output_tokens: int = 50,
        simulated_input_text: Optional[str] = None,
        simulated_output_text: Optional[str] = None,
        currency: str = "USD",
        simulate_fail_provider_ids: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style governed fallback execute (`POST /gateway/routes/{id}/execute-fallback`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        tid = str(tenant_id or "").strip()
        if not tid:
            raise ValueError("tenant_id is required")
        aid = str(agent_id or "").strip()
        if not aid:
            raise ValueError("agent_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "tenant_id": tid,
            "agent_id": aid,
            "environment": str(environment or "prod").strip() or "prod",
            "request_priority": str(request_priority or "normal").strip() or "normal",
            "session_id": str(session_id or "gateway-session").strip() or "gateway-session",
            "endpoint_family": str(endpoint_family or "responses").strip() or "responses",
            "input_tokens": max(0, int(input_tokens or 0)),
            "output_tokens": max(0, int(output_tokens or 0)),
            "currency": str(currency or "USD").strip() or "USD",
            "simulate_fail_provider_ids": str(simulate_fail_provider_ids or "[]"),
        }
        if request_tag:
            body["request_tag"] = str(request_tag).strip()
        if requested_region:
            body["requested_region"] = str(requested_region).strip()
        if model_name:
            body["model_name"] = str(model_name).strip()
        if owner_scope:
            body["owner_scope"] = str(owner_scope).strip()
        if owner_scope_type:
            body["owner_scope_type"] = str(owner_scope_type).strip()
        if owner_scope_id:
            body["owner_scope_id"] = str(owner_scope_id).strip()
        if simulated_input_text is not None:
            body["simulated_input_text"] = str(simulated_input_text)
        if simulated_output_text is not None:
            body["simulated_output_text"] = str(simulated_output_text)
        payload = self._post(f"/gateway/routes/{quote(rid, safe='')}/execute-fallback", body)
        return payload if isinstance(payload, dict) else {}

    def get_route_fallbacks(
        self,
        route_policy_id: str,
        *,
        request_tag: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style route fallbacks (`GET /gateway/routes/{id}/fallbacks`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        path = f"/gateway/routes/{quote(rid, safe='')}/fallbacks"
        if request_tag:
            path = f"{path}?{urlencode({'request_tag': str(request_tag).strip()})}"
        payload = self._get(path)
        return payload if isinstance(payload, dict) else {}

    def upsert_route_fallbacks(
        self,
        route_policy_id: str,
        *,
        tenant_id: str,
        environment: str = "prod",
        request_tag: Optional[str] = None,
        priority_order: str = "[]",
        global_timeout_ms: int = 4500,
        max_fallback_hops: int = 2,
        health_check_enabled: bool = False,
        budget_limit_cents: Optional[int] = None,
    ) -> dict[str, Any]:
        """Portkey-style route fallbacks upsert (`PUT /gateway/routes/{id}/fallbacks`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "tenant_id": str(tenant_id or "").strip(),
            "environment": str(environment or "prod").strip() or "prod",
            "priority_order": str(priority_order if priority_order is not None else "[]"),
            "global_timeout_ms": max(100, min(int(global_timeout_ms or 4500), 120000)),
            "max_fallback_hops": max(0, min(int(max_fallback_hops or 0), 10)),
            "health_check_enabled": bool(health_check_enabled),
        }
        if request_tag is not None:
            body["request_tag"] = str(request_tag).strip() or None
        if budget_limit_cents is not None:
            body["budget_limit_cents"] = int(budget_limit_cents)
        payload = self._put(f"/gateway/routes/{quote(rid, safe='')}/fallbacks", body)
        return payload if isinstance(payload, dict) else {}

    def get_route_pre_call_filters(
        self,
        route_policy_id: str,
        *,
        request_tag: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style pre-call filters (`GET /gateway/routes/{id}/pre-call-filters`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        path = f"/gateway/routes/{quote(rid, safe='')}/pre-call-filters"
        if request_tag:
            path = f"{path}?{urlencode({'request_tag': str(request_tag).strip()})}"
        payload = self._get(path)
        return payload if isinstance(payload, dict) else {}

    def upsert_route_pre_call_filters(
        self,
        route_policy_id: str,
        *,
        tenant_id: str,
        environment: str = "prod",
        request_tag: Optional[str] = None,
        allowed_regions: str = "[]",
        min_context_window_tokens: Optional[int] = None,
        max_context_window_tokens: Optional[int] = None,
        enforce: bool = True,
    ) -> dict[str, Any]:
        """Portkey-style pre-call filters upsert (`PUT /gateway/routes/{id}/pre-call-filters`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "tenant_id": str(tenant_id or "").strip(),
            "environment": str(environment or "prod").strip() or "prod",
            "allowed_regions": str(allowed_regions if allowed_regions is not None else "[]"),
            "enforce": bool(enforce),
        }
        if request_tag is not None:
            body["request_tag"] = str(request_tag).strip() or None
        if min_context_window_tokens is not None:
            body["min_context_window_tokens"] = int(min_context_window_tokens)
        if max_context_window_tokens is not None:
            body["max_context_window_tokens"] = int(max_context_window_tokens)
        payload = self._put(f"/gateway/routes/{quote(rid, safe='')}/pre-call-filters", body)
        return payload if isinstance(payload, dict) else {}

    def get_route_input_data_policy(
        self,
        route_policy_id: str,
        *,
        request_tag: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style input data policy (`GET /gateway/routes/{id}/input-data-policy`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        path = f"/gateway/routes/{quote(rid, safe='')}/input-data-policy"
        if request_tag:
            path = f"{path}?{urlencode({'request_tag': str(request_tag).strip()})}"
        payload = self._get(path)
        return payload if isinstance(payload, dict) else {}

    def upsert_route_input_data_policy(
        self,
        route_policy_id: str,
        *,
        tenant_id: str,
        environment: str = "prod",
        request_tag: Optional[str] = None,
        policy_mode: str = "warn",
        data_classes: str = "[]",
        block_patterns: str = "[]",
        mask_token: str = "[REDACTED]",
        enforce: bool = True,
    ) -> dict[str, Any]:
        """Portkey-style input data policy upsert (`PUT /gateway/routes/{id}/input-data-policy`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "tenant_id": str(tenant_id or "").strip(),
            "environment": str(environment or "prod").strip() or "prod",
            "policy_mode": str(policy_mode or "warn").strip() or "warn",
            "data_classes": str(data_classes if data_classes is not None else "[]"),
            "block_patterns": str(block_patterns if block_patterns is not None else "[]"),
            "mask_token": str(mask_token or "[REDACTED]"),
            "enforce": bool(enforce),
        }
        if request_tag is not None:
            body["request_tag"] = str(request_tag).strip() or None
        payload = self._put(f"/gateway/routes/{quote(rid, safe='')}/input-data-policy", body)
        return payload if isinstance(payload, dict) else {}

    def get_route_output_guardrails(
        self,
        route_policy_id: str,
        *,
        request_tag: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style output guardrails (`GET /gateway/routes/{id}/output-guardrails`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote, urlencode

        path = f"/gateway/routes/{quote(rid, safe='')}/output-guardrails"
        if request_tag:
            path = f"{path}?{urlencode({'request_tag': str(request_tag).strip()})}"
        payload = self._get(path)
        return payload if isinstance(payload, dict) else {}

    def upsert_route_output_guardrails(
        self,
        route_policy_id: str,
        *,
        tenant_id: str,
        environment: str = "prod",
        request_tag: Optional[str] = None,
        policy_mode: str = "warn",
        blocked_phrases: str = "[]",
        redact_phrases: str = "[]",
        max_output_tokens: Optional[int] = None,
        enforce: bool = True,
    ) -> dict[str, Any]:
        """Portkey-style output guardrails upsert (`PUT /gateway/routes/{id}/output-guardrails`)."""
        rid = str(route_policy_id or "").strip()
        if not rid:
            raise ValueError("route_policy_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "tenant_id": str(tenant_id or "").strip(),
            "environment": str(environment or "prod").strip() or "prod",
            "policy_mode": str(policy_mode or "warn").strip() or "warn",
            "blocked_phrases": str(blocked_phrases if blocked_phrases is not None else "[]"),
            "redact_phrases": str(redact_phrases if redact_phrases is not None else "[]"),
            "enforce": bool(enforce),
        }
        if request_tag is not None:
            body["request_tag"] = str(request_tag).strip() or None
        if max_output_tokens is not None:
            body["max_output_tokens"] = int(max_output_tokens)
        payload = self._put(f"/gateway/routes/{quote(rid, safe='')}/output-guardrails", body)
        return payload if isinstance(payload, dict) else {}

    def list_cache_policies(
        self,
        *,
        scope: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Portkey/Helicone-style cache policy list (`GET /gateway/cache/policies`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 100), 500)),
            "offset": max(0, int(offset or 0)),
        }
        if scope:
            query["scope"] = str(scope).strip()
        if status:
            query["status"] = str(status).strip()
        data = self._get(f"/gateway/cache/policies?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def create_cache_policy(
        self,
        *,
        scope: str,
        ttl_seconds: int = 60,
        key_strategy: str = "default",
        invalidation_strategy: str = "ttl",
        privacy_mode: str = "standard",
        privacy_scope: str = "tenant",
        non_cache_data_classes: str = "[]",
        cache_mode: str = "exact",
        similarity_threshold: float = 0.9,
    ) -> dict[str, Any]:
        """Portkey/Helicone-style cache policy create (`POST /gateway/cache/policies`)."""
        body: dict[str, Any] = {
            "scope": str(scope or "").strip(),
            "ttl_seconds": max(1, min(int(ttl_seconds or 60), 86400)),
            "key_strategy": str(key_strategy or "default").strip() or "default",
            "invalidation_strategy": str(invalidation_strategy or "ttl").strip() or "ttl",
            "privacy_mode": str(privacy_mode or "standard").strip() or "standard",
            "privacy_scope": str(privacy_scope or "tenant").strip() or "tenant",
            "non_cache_data_classes": str(
                non_cache_data_classes if non_cache_data_classes is not None else "[]"
            ),
            "cache_mode": str(cache_mode or "exact").strip() or "exact",
            "similarity_threshold": max(0.0, min(float(similarity_threshold or 0.0), 1.0)),
        }
        payload = self._post("/gateway/cache/policies", body)
        return payload if isinstance(payload, dict) else {}

    def invalidate_cache(
        self,
        *,
        scope: Optional[str] = None,
        cache_keys: Optional[list[str]] = None,
        reason: Optional[str] = None,
        active_only: bool = True,
    ) -> dict[str, Any]:
        """Portkey/Helicone-style cache invalidate (`POST /gateway/cache/delete`)."""
        body: dict[str, Any] = {
            "cache_keys": [str(item).strip() for item in (cache_keys or []) if str(item).strip()],
            "active_only": bool(active_only),
        }
        if scope is not None:
            body["scope"] = str(scope).strip() or None
        if reason is not None:
            body["reason"] = str(reason)
        payload = self._post("/gateway/cache/delete", body)
        return payload if isinstance(payload, dict) else {}

    def list_budget_policies(
        self,
        *,
        status: Optional[str] = "active",
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Helicone-style budget policy list (`GET /cost/budgets`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 100), 500)),
            "offset": max(0, int(offset or 0)),
        }
        if status is not None:
            query["status"] = str(status).strip()
        if scope_type:
            query["scope_type"] = str(scope_type).strip()
        if scope_id:
            query["scope_id"] = str(scope_id).strip()
        data = self._get(f"/cost/budgets?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def create_budget_policy(
        self,
        *,
        scope_type: str,
        scope_id: str,
        budget_amount_cents: int,
        window_type: str = "daily",
        soft_limit_percent: int = 80,
        hard_limit_percent: int = 100,
        action_on_soft_limit: str = "warn",
        action_on_hard_limit: str = "block",
        reset_timezone: str = "UTC",
        reset_hour_local: int = 0,
        temporary_increase_cents: int = 0,
        soft_alert_enabled: bool = True,
        rate_limit_tpm: Optional[int] = None,
        rate_limit_rpm: Optional[int] = None,
        session_iteration_cap: Optional[int] = None,
        session_budget_cents: Optional[int] = None,
    ) -> dict[str, Any]:
        """Helicone-style budget policy create (`POST /cost/budgets`)."""
        body: dict[str, Any] = {
            "scope_type": str(scope_type or "").strip(),
            "scope_id": str(scope_id or "").strip(),
            "budget_amount_cents": max(0, int(budget_amount_cents or 0)),
            "window_type": str(window_type or "daily").strip() or "daily",
            "soft_limit_percent": max(1, min(int(soft_limit_percent or 80), 100)),
            "hard_limit_percent": max(1, min(int(hard_limit_percent or 100), 100)),
            "action_on_soft_limit": str(action_on_soft_limit or "warn").strip() or "warn",
            "action_on_hard_limit": str(action_on_hard_limit or "block").strip() or "block",
            "reset_timezone": str(reset_timezone or "UTC").strip() or "UTC",
            "reset_hour_local": max(0, min(int(reset_hour_local or 0), 23)),
            "temporary_increase_cents": max(0, int(temporary_increase_cents or 0)),
            "soft_alert_enabled": bool(soft_alert_enabled),
        }
        if rate_limit_tpm is not None:
            body["rate_limit_tpm"] = int(rate_limit_tpm)
        if rate_limit_rpm is not None:
            body["rate_limit_rpm"] = int(rate_limit_rpm)
        if session_iteration_cap is not None:
            body["session_iteration_cap"] = int(session_iteration_cap)
        if session_budget_cents is not None:
            body["session_budget_cents"] = int(session_budget_cents)
        payload = self._post("/cost/budgets", body)
        return payload if isinstance(payload, dict) else {}

    def update_budget_policy(
        self,
        budget_policy_id: str,
        *,
        scope_type: str,
        scope_id: str,
        budget_amount_cents: int,
        window_type: str = "daily",
        soft_limit_percent: int = 80,
        hard_limit_percent: int = 100,
        action_on_soft_limit: str = "warn",
        action_on_hard_limit: str = "block",
        reset_timezone: str = "UTC",
        reset_hour_local: int = 0,
        temporary_increase_cents: int = 0,
        soft_alert_enabled: bool = True,
        rate_limit_tpm: Optional[int] = None,
        rate_limit_rpm: Optional[int] = None,
        session_iteration_cap: Optional[int] = None,
        session_budget_cents: Optional[int] = None,
    ) -> dict[str, Any]:
        """Helicone-style budget policy update (`PUT /cost/budgets/{id}`)."""
        bid = str(budget_policy_id or "").strip()
        if not bid:
            raise ValueError("budget_policy_id is required")
        from urllib.parse import quote

        body: dict[str, Any] = {
            "scope_type": str(scope_type or "").strip(),
            "scope_id": str(scope_id or "").strip(),
            "budget_amount_cents": max(0, int(budget_amount_cents or 0)),
            "window_type": str(window_type or "daily").strip() or "daily",
            "soft_limit_percent": max(1, min(int(soft_limit_percent or 80), 100)),
            "hard_limit_percent": max(1, min(int(hard_limit_percent or 100), 100)),
            "action_on_soft_limit": str(action_on_soft_limit or "warn").strip() or "warn",
            "action_on_hard_limit": str(action_on_hard_limit or "block").strip() or "block",
            "reset_timezone": str(reset_timezone or "UTC").strip() or "UTC",
            "reset_hour_local": max(0, min(int(reset_hour_local or 0), 23)),
            "temporary_increase_cents": max(0, int(temporary_increase_cents or 0)),
            "soft_alert_enabled": bool(soft_alert_enabled),
        }
        if rate_limit_tpm is not None:
            body["rate_limit_tpm"] = int(rate_limit_tpm)
        if rate_limit_rpm is not None:
            body["rate_limit_rpm"] = int(rate_limit_rpm)
        if session_iteration_cap is not None:
            body["session_iteration_cap"] = int(session_iteration_cap)
        if session_budget_cents is not None:
            body["session_budget_cents"] = int(session_budget_cents)
        payload = self._put(f"/cost/budgets/{quote(bid, safe='')}", body)
        return payload if isinstance(payload, dict) else {}

    def delete_budget_policy(self, budget_policy_id: str) -> dict[str, Any]:
        """Helicone-style budget policy delete (`DELETE /cost/budgets/{id}`)."""
        bid = str(budget_policy_id or "").strip()
        if not bid:
            raise ValueError("budget_policy_id is required")
        from urllib.parse import quote

        payload = self._delete(f"/cost/budgets/{quote(bid, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def evaluate_budget_policy(
        self,
        *,
        scope_type: str,
        scope_id: str,
        window_type: str = "daily",
    ) -> dict[str, Any]:
        """Helicone-style budget policy evaluate (`POST /cost/policies/evaluate`)."""
        body = {
            "scope_type": str(scope_type or "").strip(),
            "scope_id": str(scope_id or "").strip(),
            "window_type": str(window_type or "daily").strip() or "daily",
        }
        payload = self._post("/cost/policies/evaluate", body)
        return payload if isinstance(payload, dict) else {}

    def get_cache_stats(self) -> dict[str, Any]:
        """Portkey/Helicone-style cache stats (`GET /gateway/cache/stats`)."""
        payload = self._get("/gateway/cache/stats")
        return payload if isinstance(payload, dict) else {}

    def get_cache_health(self) -> dict[str, Any]:
        """Portkey/Helicone-style cache health (`GET /gateway/cache/health`)."""
        payload = self._get("/gateway/cache/health")
        return payload if isinstance(payload, dict) else {}

    def list_cache_entries(
        self,
        *,
        tenant_id: Optional[str] = None,
        cache_policy_id: Optional[str] = None,
        status: Optional[str] = "active",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Portkey/Helicone-style cache entry metadata (`GET /gateway/cache/entries`; no bodies)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 100), 500)),
            "offset": max(0, int(offset or 0)),
        }
        if tenant_id:
            query["tenant_id"] = str(tenant_id).strip()
        if cache_policy_id:
            query["cache_policy_id"] = str(cache_policy_id).strip()
        if status:
            query["status"] = str(status).strip()
        data = self._get(f"/gateway/cache/entries?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    def list_cache_decisions(
        self,
        *,
        decision: Optional[str] = None,
        tenant_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        cache_policy_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Portkey/Helicone-style cache decisions (`GET /gateway/cache/decisions`)."""
        from urllib.parse import urlencode

        query: dict[str, Any] = {
            "limit": max(1, min(int(limit or 100), 500)),
            "offset": max(0, int(offset or 0)),
        }
        if decision:
            query["decision"] = str(decision).strip()
        if tenant_id:
            query["tenant_id"] = str(tenant_id).strip()
        if trace_id:
            query["trace_id"] = str(trace_id).strip()
        if cache_policy_id:
            query["cache_policy_id"] = str(cache_policy_id).strip()
        data = self._get(f"/gateway/cache/decisions?{urlencode(query)}")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("data") or data.get("items") or []
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []





    def get_observability_log_schema_status(self, *, sample_size: Optional[int] = None) -> dict[str, Any]:
        """Portkey-style observability log schema status (`GET /observability/logs/schema-status`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {}
        if sample_size is not None:
            query["sample_size"] = max(1, min(int(sample_size), 1000))
        path = "/observability/logs/schema-status"
        if query:
            path = f"{path}?{urlencode(query)}"
        payload = self._get(path)
        return payload if isinstance(payload, dict) else {}

    def list_siem_rules(self) -> dict[str, Any]:
        """Portkey-style SIEM alert rule catalog (`GET /observability/siem-rules`)."""
        payload = self._get("/observability/siem-rules")
        return payload if isinstance(payload, dict) else {}

    def export_siem_rules(self) -> dict[str, Any]:
        """Portkey-style SIEM alert rule export (`POST /observability/siem-rules/export`)."""
        payload = self._post("/observability/siem-rules/export", {})
        return payload if isinstance(payload, dict) else {}

    def evaluate_siem_rules(
        self,
        *,
        limit: int = 100,
        since_hours: int = 24,
        action_type_prefix: Optional[str] = None,
        decision_outcome: Optional[str] = None,
    ) -> dict[str, Any]:
        """Portkey-style SIEM rule evaluation (`GET /observability/siem-rules/evaluate`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "limit": max(1, min(int(limit or 100), 500)),
            "since_hours": max(1, min(int(since_hours or 24), 720)),
        }
        if action_type_prefix:
            query["action_type_prefix"] = str(action_type_prefix).strip()
        if decision_outcome:
            query["decision_outcome"] = str(decision_outcome).strip()
        payload = self._get(f"/observability/siem-rules/evaluate?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def list_observability_logs(
        self,
        *,
        since_hours: int = 24,
        limit: int = 50,
        offset: int = 0,
        trace_id: Optional[str] = None,
        action_type: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        decision_outcome: Optional[str] = None,
        search: Optional[str] = None,
        redact_sensitive: bool = False,
    ) -> list[dict[str, Any]]:
        """Portkey-style observability log list (`GET /observability/logs`)."""
        from urllib.parse import urlencode

        query: dict[str, object] = {
            "since_hours": max(1, min(int(since_hours or 24), 720)),
            "limit": max(1, min(int(limit or 50), 500)),
            "offset": max(0, int(offset or 0)),
            "redact_sensitive": "true" if redact_sensitive else "false",
        }
        if trace_id:
            query["trace_id"] = str(trace_id).strip()
        if action_type:
            query["action_type"] = str(action_type).strip()
        if resource_type:
            query["resource_type"] = str(resource_type).strip()
        if resource_id:
            query["resource_id"] = str(resource_id).strip()
        if actor_id:
            query["actor_id"] = str(actor_id).strip()
        if decision_outcome:
            query["decision_outcome"] = str(decision_outcome).strip()
        if search:
            query["search"] = str(search).strip()
        payload = self._get(f"/observability/logs?{urlencode(query)}")
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            items = payload.get("items") or payload.get("data") or payload.get("logs") or []
            return [item for item in items if isinstance(item, dict)]
        return []

    def export_observability_logs(
        self,
        *,
        format: str = "csv",
        since_hours: int = 24,
        limit: int = 500,
        offset: int = 0,
        trace_id: Optional[str] = None,
        action_type: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        decision_outcome: Optional[str] = None,
        search: Optional[str] = None,
        redact_sensitive: bool = False,
    ) -> str:
        """Portkey-style observability log export (`GET /observability/logs/export`)."""
        from urllib.parse import urlencode

        normalized_format = str(format or "csv").strip().lower() or "csv"
        if normalized_format not in {"csv", "json"}:
            raise ValueError("format must be csv or json")
        query: dict[str, object] = {
            "format": normalized_format,
            "since_hours": max(1, min(int(since_hours or 24), 720)),
            "limit": max(1, min(int(limit or 500), 2000)),
            "offset": max(0, int(offset or 0)),
            "redact_sensitive": "true" if redact_sensitive else "false",
        }
        if trace_id:
            query["trace_id"] = str(trace_id).strip()
        if action_type:
            query["action_type"] = str(action_type).strip()
        if resource_type:
            query["resource_type"] = str(resource_type).strip()
        if resource_id:
            query["resource_id"] = str(resource_id).strip()
        if actor_id:
            query["actor_id"] = str(actor_id).strip()
        if decision_outcome:
            query["decision_outcome"] = str(decision_outcome).strip()
        if search:
            query["search"] = str(search).strip()
        return self._get_text(f"/observability/logs/export?{urlencode(query)}")

    def get_observability_summary(self, *, since_hours: int = 24) -> dict[str, Any]:
        """Portkey/Helicone-style observability summary (`GET /observability/summary`)."""
        from urllib.parse import urlencode

        query = {"since_hours": max(1, min(int(since_hours or 24), 168))}
        payload = self._get(f"/observability/summary?{urlencode(query)}")
        return payload if isinstance(payload, dict) else {}

    def get_trace_events(self, trace_id: str) -> dict[str, Any]:
        """Portkey/Helicone-style trace event timeline (`GET /observability/traces/{id}/events`)."""
        tid = str(trace_id or "").strip()
        if not tid:
            raise ValueError("trace_id is required")
        from urllib.parse import quote

        payload = self._get(f"/observability/traces/{quote(tid, safe='')}/events")
        return payload if isinstance(payload, dict) else {}

    def get_trace(self, trace_id: str) -> dict[str, Any]:
        req = request.Request(
            f"{self.base_url}/observability/traces/{trace_id}",
            headers=self._headers(),
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Trace lookup failed ({exc.code}): {detail}") from exc


def create_gateway_request_instrumenter(
    *,
    session_id: str = "",
    user: str = "",
    properties: Optional[dict[str, Any]] = None,
):
    """Gateway-native header stamp helper for urllib/request-style clients."""

    props = properties if isinstance(properties, dict) else {}

    def _stamp(headers: Optional[dict[str, str]] = None) -> dict[str, str]:
        out = dict(headers or {})
        if session_id:
            out["x-session-id"] = str(session_id)
        if user:
            out["x-user"] = str(user)
        for key, value in list(props.items())[:32]:
            k = str(key or "").strip()[:64]
            if not k:
                continue
            out[f"x-property-{k}"] = str(value)[:256]
        return out

    return _stamp
