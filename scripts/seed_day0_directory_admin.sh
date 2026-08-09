#!/usr/bin/env bash
# Ensure Day-0 admin exists as a DirectoryUser so /auth/login works after fresh DB.
# Password stays in macOS Keychain; never printed.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.runtime"
META_FILE="${DAY0_ADMIN_META_FILE:-${RUNTIME_DIR}/day0_admin_credentials_meta.env}"
BACKEND_DIR="${ROOT_DIR}/backend"

if [[ ! -f "$META_FILE" ]]; then
  bash "$ROOT_DIR/scripts/bootstrap_day0_admin_credentials.sh" >/dev/null
fi

# shellcheck disable=SC1090
source "$META_FILE"

if [[ -z "${DAY0_ADMIN_USERNAME:-}" || -z "${DAY0_ADMIN_KEYCHAIN_SERVICE:-}" ]]; then
  echo "Invalid Day-0 metadata: $META_FILE" >&2
  exit 1
fi

if ! command -v security >/dev/null 2>&1; then
  echo "macOS 'security' is required to read Day-0 admin password." >&2
  exit 1
fi

DAY0_ADMIN_PASSWORD="$(security find-generic-password -s "$DAY0_ADMIN_KEYCHAIN_SERVICE" -a "$DAY0_ADMIN_USERNAME" -w)"
export DAY0_ADMIN_USERNAME
export DAY0_ADMIN_PASSWORD

# Prefer repo env for DATABASE_URL without echoing contents
if [[ -f "${RUNTIME_DIR}/local-dev.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${RUNTIME_DIR}/local-dev.env"
  set +a
fi

cd "$BACKEND_DIR"
python3 - <<'PY'
import os
import sys

from app.database import SessionLocal
from app.models import DirectoryUser
from app.policy_constants import ROLE_MASTER_ADMIN
from app.security import hash_user_password

username = (os.environ.get("DAY0_ADMIN_USERNAME") or "").strip()
password = os.environ.get("DAY0_ADMIN_PASSWORD") or ""
if not username or not password:
    print("Day-0 username/password unavailable.", file=sys.stderr)
    sys.exit(1)

db = SessionLocal()
try:
    row = db.query(DirectoryUser).filter_by(user_id=username).first()
    if row is None:
        db.add(
            DirectoryUser(
                user_id=username,
                display_name="Day 0 Admin",
                email=f"{username}@localhost",
                role_name=ROLE_MASTER_ADMIN,
                password_hash=hash_user_password(password),
                status="active",
                updated_by="day0-seed",
            )
        )
        db.commit()
        print(f"Seeded Day-0 directory user '{username}' (Master Admin).")
    else:
        # Keep role/status usable; refresh password hash to match Keychain (local sync).
        row.password_hash = hash_user_password(password)
        row.status = "active"
        row.locked_until = None
        row.failed_login_attempts = 0
        if not str(row.role_name or "").strip():
            row.role_name = ROLE_MASTER_ADMIN
        row.updated_by = "day0-seed"
        db.commit()
        print(f"Synced Day-0 directory user '{username}' password from Keychain.")
finally:
    db.close()
PY
