#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
	echo "Usage: ./scripts/shutdownall.sh"
	echo "Stops local infra + backend + UI using scripts/stack.sh stop all"
	exit 0
fi

"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stack.sh" stop all "$@"