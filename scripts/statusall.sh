#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
	echo "Usage: ./scripts/statusall.sh"
	echo "Shows local infra + backend + UI status using scripts/stack.sh status all"
	exit 0
fi

"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/stack.sh" status all "$@"
