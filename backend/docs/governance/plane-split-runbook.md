# Plane-Split Deploy Runbook (`APP_PLANE`)

**Purpose:** Run process-isolated control vs data planes in production.  
**Contract check (no containers):** `python3 backend/scripts/verify_plane_split_compose.py`

## Bring up

```bash
docker compose -f docker-compose.production.yml --profile plane-split up -d
```

| Process | Host port | `APP_PLANE` | Role |
|---------|----------:|-------------|------|
| `api-control` | 8001 | `control` | Control plane (policy, freeze, CPLI) |
| `api-gateway` | 8002 | `data` | Inference / gateway data plane |

Point the **operator UI** at the control plane (`:8001`) and **inference clients** at the data plane (`:8002`).

## Verify

```bash
curl -sS http://127.0.0.1:8001/health | jq '.plane'
curl -sS http://127.0.0.1:8002/health | jq '.plane'
curl -sS -H "X-Actor-Role: Platform Admin" -H "X-Actor-Id: ops" \
  http://127.0.0.1:8001/platform/control-plane | jq '.app_plane,.isolation_mode'
```

Expect control process `app_plane=control`, data process `app_plane=data`.

## Notes

- Combined `api` (`APP_PLANE=all`) remains available without the profile for single-process deploys.
- Data plane defaults `PLANE_FAIL_CLOSED_MODE=drift`.
- Live credentials / secrets are never forged by leadership bootstrap tooling.
