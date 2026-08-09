#!/usr/bin/env python3
"""Verify docker-compose.production.yml plane-split contract (APP_PLANE isolation).

Does not start containers — validates the compose definition CPLI already credits.
Exit 0 when api-control / api-gateway expose control|data planes with peer URLs.

Usage (repo root or backend/):
  python3 backend/scripts/verify_plane_split_compose.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.production.yml"


def _service_block(text: str, service: str) -> str:
    pattern = rf"(?m)^  {re.escape(service)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)"
    match = re.search(pattern, text, flags=re.DOTALL)
    if not match:
        raise SystemExit(f"missing service '{service}' in {COMPOSE}")
    return match.group(1)


def _env_value(block: str, key: str) -> str | None:
    match = re.search(rf"(?m)^\s+{re.escape(key)}:\s*(.+)$", block)
    if not match:
        return None
    return match.group(1).strip().strip('"').strip("'")


def main() -> int:
    if not COMPOSE.is_file():
        print(f"FAIL: {COMPOSE} not found", file=sys.stderr)
        return 1
    text = COMPOSE.read_text(encoding="utf-8")
    errors: list[str] = []

    control = _service_block(text, "api-control")
    gateway = _service_block(text, "api-gateway")

    if "profiles:" not in control or "plane-split" not in control:
        errors.append("api-control must use profiles: [plane-split]")
    if "profiles:" not in gateway or "plane-split" not in gateway:
        errors.append("api-gateway must use profiles: [plane-split]")

    if _env_value(control, "APP_PLANE") != "control":
        errors.append("api-control APP_PLANE must be control")
    if _env_value(gateway, "APP_PLANE") != "data":
        errors.append("api-gateway APP_PLANE must be data")

    data_peer = _env_value(control, "DATA_PLANE_PEER_URL") or ""
    control_peer = _env_value(gateway, "CONTROL_PLANE_PEER_URL") or ""
    if "api-gateway" not in data_peer:
        errors.append("api-control DATA_PLANE_PEER_URL must reference api-gateway")
    if "api-control" not in control_peer:
        errors.append("api-gateway CONTROL_PLANE_PEER_URL must reference api-control")

    fail_closed = _env_value(gateway, "PLANE_FAIL_CLOSED_MODE") or ""
    if "drift" not in fail_closed:
        errors.append("api-gateway PLANE_FAIL_CLOSED_MODE should default to drift")

    if "8001:8000" not in control:
        errors.append("api-control should publish host port 8001")
    if "8002:8000" not in gateway:
        errors.append("api-gateway should publish host port 8002")

    if errors:
        print("FAIL: plane-split compose contract", file=sys.stderr)
        for item in errors:
            print(f"  - {item}", file=sys.stderr)
        return 1

    print(
        "OK: plane-split compose contract "
        "(api-control:control:8001 · api-gateway:data:8002 · peer URLs · fail-closed=drift)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
