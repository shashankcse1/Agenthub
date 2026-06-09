#!/usr/bin/env bash
set -euo pipefail

POSTGRES_CONTAINER_NAME="${POSTGRES_CONTAINER_NAME:-agenthub-postgres}"

docker_is_reachable() {
  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi
  if [[ ! -S /var/run/docker.sock && ! -S "${HOME}/.docker/run/docker.sock" ]]; then
    return 1
  fi
  DOCKER_CLIENT_TIMEOUT=3 COMPOSE_HTTP_TIMEOUT=3 docker info >/dev/null 2>&1
}

if ! command -v brew >/dev/null 2>&1 && [[ -x /opt/homebrew/bin/brew ]]; then
  brew() { /opt/homebrew/bin/brew "$@"; }
fi

stopped_any="false"

if command -v brew >/dev/null 2>&1; then
  brew services stop postgresql@16 >/dev/null 2>&1 || true
  stopped_any="true"
  echo "Infra stopped: postgresql@16 (Homebrew)"
fi

if docker_is_reachable; then
  if docker ps --format '{{.Names}}' | grep -Fx "$POSTGRES_CONTAINER_NAME" >/dev/null 2>&1; then
    docker stop "$POSTGRES_CONTAINER_NAME" >/dev/null || true
    stopped_any="true"
    echo "Infra stopped: ${POSTGRES_CONTAINER_NAME} (Docker)"
  fi
fi

if [[ "$stopped_any" != "true" ]]; then
  echo "No managed infra process found to stop."
fi
