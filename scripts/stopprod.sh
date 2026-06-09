#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
	echo "Usage: ./scripts/stopprod.sh"
	echo "Stops production compose stack using scripts/stack.sh stop prod"
	echo "Env vars: PROD_ENV_FILE, PROD_COMPOSE_FILE"
	exit 0
fi

"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stack.sh" stop prod "$@"
