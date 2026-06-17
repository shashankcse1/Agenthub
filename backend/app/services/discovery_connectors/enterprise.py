import hashlib
from typing import Any
from urllib.parse import quote

from app.services.discovery_connectors.http_utils import bearer_headers, http_get_json
from app.services.discovery_connectors.types import ConnectionRuntime, DiscoveryCandidate

ENTERPRISE_SPECS: dict[str, dict[str, str]] = {
    "huggingface": {"default_base": "https://huggingface.co/api", "path": "/models"},
    "langsmith": {"default_base": "https://api.smith.langchain.com", "path": "/sessions"},
    "slack": {"default_base": "https://slack.com/api", "path": "/users.list"},
    "okta": {"default_base": "", "path": "/api/v1/users"},
    "servicenow": {"default_base": "", "path": "/api/now/table/sys_user"},
    "salesforce": {"default_base": "", "path": "/services/data/v59.0/sobjects"},
    "snowflake": {"default_base": "", "path": "/api/v2/statements"},
    "databricks": {"default_base": "", "path": "/api/2.0/clusters/list"},
    "kubernetes": {"default_base": "", "path": "/api/v1/namespaces/default/pods"},
    "mongodb_atlas": {"default_base": "https://cloud.mongodb.com/api/atlas/v1.0", "path": "/groups"},
}


def _fingerprint(*parts: str) -> str:
    payload = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _items_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("data", "items", "values", "members", "result", "models", "records"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def fetch_enterprise_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    token = str(runtime.credentials.secret_value or "").strip()
    if not token:
        raise ValueError(f"{runtime.source_id} connection requires API token")

    source_id = runtime.source_id
    spec = ENTERPRISE_SPECS.get(source_id, {})
    base = (runtime.base_url or runtime.config.get("instance_url") or spec.get("default_base") or "").rstrip("/")
    if not base:
        raise ValueError(f"{source_id} connection requires base_url or instance_url in connection_config")

    path = spec.get("path") or "/"
    headers = bearer_headers(token)
    params = None

    if source_id == "huggingface":
        author = str(runtime.config.get("author") or runtime.config.get("org") or "").strip()
        params = {"author": author} if author else {"limit": "50"}
        headers = {"Authorization": f"Bearer {token}"}
    elif source_id == "slack":
        headers = {"Authorization": f"Bearer {token}"}
    elif source_id == "okta":
        domain = str(runtime.config.get("domain") or "").strip()
        if domain:
            base = f"https://{domain}"
        headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
    elif source_id == "servicenow":
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    elif source_id == "kubernetes":
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    elif source_id == "mongodb_atlas":
        headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
        group_id = str(runtime.config.get("group_id") or "").strip()
        if group_id:
            path = f"/groups/{quote(group_id)}/clusters"

    url = f"{base}{path}"
    payload = http_get_json(
        url,
        headers=headers,
        params=params,
    )
    items = _items_from_payload(payload)
    records: list[DiscoveryCandidate] = []
    for item in items:
        key = str(
            item.get("id")
            or item.get("name")
            or item.get("email")
            or item.get("modelId")
            or item.get("login")
            or item.get("cluster_id")
            or ""
        ).strip()
        if not key:
            continue
        records.append(
            DiscoveryCandidate(
                canonical_agent_key=f"{source_id}:{key}",
                source_fingerprint=_fingerprint(runtime.connection_id, source_id, key),
                confidence=85,
                metadata={"live": True, "provider": source_id},
            )
        )

    if not records and source_id == "kubernetes":
        namespace = str(runtime.config.get("namespace") or "default").strip()
        url = f"{base}/api/v1/namespaces/{quote(namespace)}/pods"
        payload = http_get_json(
            url,
            headers=headers,
        )
        items = _items_from_payload(payload.get("items") if isinstance(payload, dict) else payload)
        for item in items:
            name = str(item.get("metadata", {}).get("name") if isinstance(item.get("metadata"), dict) else item.get("name") or "").strip()
            if name:
                records.append(
                    DiscoveryCandidate(
                        canonical_agent_key=f"k8s:{namespace}:{name}",
                        source_fingerprint=_fingerprint(runtime.connection_id, namespace, name),
                        confidence=86,
                        metadata={"live": True, "namespace": namespace},
                    )
                )

    if not records:
        raise ValueError(f"{source_id} API returned no discoverable resources")
    return records
