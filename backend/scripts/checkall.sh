#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DEFAULT_DB_URL="postgresql+psycopg://${USER}@localhost:5432/agenthub"
export DATABASE_URL="${DATABASE_URL:-$DEFAULT_DB_URL}"
PSQL_DATABASE_URL="${DATABASE_URL/postgresql+psycopg/postgresql}"

echo "[1/6] Starting infra"
make startinfra

echo "[2/6] Waiting for database readiness"
if command -v pg_isready >/dev/null 2>&1; then
	pg_isready -h localhost -p 5432 -U "$USER" -t 60 >/dev/null
else
	for _ in $(seq 1 60); do
		if psql "$PSQL_DATABASE_URL" -c 'select 1;' >/dev/null 2>&1; then
			break
		fi
		sleep 1
	done
fi

echo "[3/6] Applying migrations"
MIGRATION_MAX_ATTEMPTS=5
for attempt in $(seq 1 "$MIGRATION_MAX_ATTEMPTS"); do
	if make migrate; then
		break
	fi

	if [[ "$attempt" -eq "$MIGRATION_MAX_ATTEMPTS" ]]; then
		echo "Migration failed after ${MIGRATION_MAX_ATTEMPTS} attempts."
		exit 1
	fi

	echo "Migration attempt ${attempt}/${MIGRATION_MAX_ATTEMPTS} failed; retrying..."
	sleep 2
done

echo "[4/6] Checking control coverage"
python3 scripts/check_control_coverage.py

echo "[5/6] Running frontend security smoke checks"
bash ../frontend/scripts/security_smoke.sh

echo "[6/6] Running tests"
python3 -m pytest -q

echo "[post] Printing runtime status"
make statusall

echo "Check completed successfully."
