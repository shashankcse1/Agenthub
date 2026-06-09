#!/usr/bin/env python3
"""Fail CI when API routes are missing control-ID coverage mappings."""

from __future__ import annotations

import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.dirname(CURRENT_DIR)
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

from app.main import app
from app.services.control_coverage import build_route_coverage, unknown_referenced_control_ids


def main() -> int:
    unknown_control_ids = unknown_referenced_control_ids()
    if unknown_control_ids:
        print("Unknown control IDs referenced in route map:")
        for control_id in unknown_control_ids:
            print(f"- {control_id}")
        return 1

    report = build_route_coverage(app.routes)
    if report["uncovered_paths"]:
        print("Missing control mappings for the following API paths:")
        for path in report["uncovered_paths"]:
            print(f"- {path}")
        return 1

    print(f"Control coverage check passed. Covered routes: {report['covered_routes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
