import hashlib
from typing import Any, Optional
from urllib.parse import quote

from app.services.agent_discovery_scope import is_agent_repo
from app.services.discovery_connectors.http_utils import bearer_headers, http_get_json
from app.services.discovery_connectors.types import ConnectionRuntime, DiscoveryCandidate


def _fingerprint(*parts: str) -> str:
    payload = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _repo_candidates(
    runtime: ConnectionRuntime,
    *,
    source_id: str,
    repos: list[dict[str, Any]],
    confidence: int,
) -> list[DiscoveryCandidate]:
    records: list[DiscoveryCandidate] = []
    for repo in repos:
        if not isinstance(repo, dict):
            continue
        if not is_agent_repo(repo):
            continue
        full_name = str(repo.get("full_name") or repo.get("path_with_namespace") or repo.get("name") or "").strip()
        if not full_name:
            continue
        records.append(
            DiscoveryCandidate(
                canonical_agent_key=full_name,
                source_fingerprint=_fingerprint(runtime.connection_id, source_id, full_name),
                confidence=confidence,
                metadata={"live": True, "provider": source_id, "visibility": repo.get("visibility") or repo.get("private")},
            )
        )
    return records


def fetch_github_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    token = str(runtime.credentials.secret_value or "").strip()
    if not token:
        raise ValueError("GitHub connection requires a personal access token")
    base = (runtime.base_url or "https://api.github.com").rstrip("/")
    org = str(runtime.config.get("org") or runtime.config.get("organization") or "").strip()
    path = f"/orgs/{quote(org)}/repos" if org else "/user/repos"
    params = {"per_page": "100", "type": "all"}
    payload = http_get_json(
        f"{base}{path}",
        headers={**bearer_headers(token), "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        params=params,
    )
    if not isinstance(payload, list):
        raise ValueError("GitHub API returned unexpected payload")
    records = _repo_candidates(runtime, source_id="github", repos=payload, confidence=93)
    if not records:
        raise ValueError("GitHub API returned no repositories")
    return records


def fetch_gitlab_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    token = str(runtime.credentials.secret_value or "").strip()
    if not token:
        raise ValueError("GitLab connection requires an access token")
    base = (runtime.base_url or "https://gitlab.com/api/v4").rstrip("/")
    group = str(runtime.config.get("group") or runtime.config.get("group_id") or "").strip()
    params: dict[str, str] = {"per_page": "100", "membership": "true"}
    if group:
        path = f"/groups/{quote(group)}/projects"
    else:
        path = "/projects"
    payload = http_get_json(
        f"{base}{path}",
        headers={"PRIVATE-TOKEN": token},
        params=params,
    )
    if not isinstance(payload, list):
        raise ValueError("GitLab API returned unexpected payload")
    records = _repo_candidates(runtime, source_id="gitlab", repos=payload, confidence=92)
    if not records:
        raise ValueError("GitLab API returned no projects")
    return records


def fetch_bitbucket_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    token = str(runtime.credentials.secret_value or "").strip()
    if not token:
        raise ValueError("Bitbucket connection requires an access token")
    workspace = str(runtime.config.get("workspace") or "").strip()
    if not workspace:
        raise ValueError("Bitbucket connection requires workspace in connection_config")
    base = (runtime.base_url or "https://api.bitbucket.org/2.0").rstrip("/")
    payload = http_get_json(
        f"{base}/repositories/{quote(workspace)}",
        headers=bearer_headers(token),
        params={"pagelen": "100"},
    )
    values = payload.get("values") if isinstance(payload, dict) else None
    if not isinstance(values, list):
        raise ValueError("Bitbucket API returned unexpected payload")
    records = _repo_candidates(runtime, source_id="bitbucket", repos=values, confidence=91)
    if not records:
        raise ValueError("Bitbucket API returned no repositories")
    return records


def fetch_cursor_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    token = str(runtime.credentials.secret_value or "").strip()
    if not token:
        raise ValueError("cursor connection requires an API token (store as gateway/cursor-token in Providers)")
    workspace = str(runtime.config.get("workspace") or runtime.config.get("team") or "default").strip()
    base = (runtime.base_url or "https://api.cursor.com").rstrip("/")
    records: list[DiscoveryCandidate] = []
    endpoints = (
        f"/v1/workspaces/{quote(workspace)}/agents",
        "/v0/agents",
        "/v1/agents",
    )
    payload: Any = None
    last_error: Optional[Exception] = None
    for path in endpoints:
        try:
            payload = http_get_json(f"{base}{path}", headers=bearer_headers(token))
            break
        except Exception as exc:
            last_error = exc
            continue
    if payload is None and last_error is not None:
        raise ValueError(f"cursor API unreachable: {last_error}") from last_error

    items = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        items = payload.get("agents") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        items = [payload] if isinstance(payload, dict) else []

    for item in items:
        if not isinstance(item, dict):
            continue
        agent_id = str(item.get("id") or item.get("agent_id") or item.get("name") or "").strip()
        if not agent_id:
            continue
        records.append(
            DiscoveryCandidate(
                canonical_agent_key=f"cursor:{workspace}:{agent_id}",
                source_fingerprint=_fingerprint(runtime.connection_id, "cursor", workspace, agent_id),
                confidence=94,
                metadata={"live": True, "workspace": workspace, "provider": "cursor"},
            )
        )

    if not records:
        records.append(
            DiscoveryCandidate(
                canonical_agent_key=f"cursor:{workspace}:gateway-binding",
                source_fingerprint=_fingerprint(runtime.connection_id, "cursor", workspace, "gateway-binding"),
                confidence=82,
                metadata={
                    "live": True,
                    "workspace": workspace,
                    "note": "cursor token verified; register modules with integration_provider=cursor for skill discovery",
                },
            )
        )
    return records
