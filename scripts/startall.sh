#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
	echo "Usage: ./scripts/startall.sh"
	echo "Starts local infra + backend + UI using scripts/stack.sh start all"
	exit 0
fi

"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stack.sh" start all "$@"