#!/usr/bin/env bash
set -euo pipefail

POSTGRES_CONTAINER_NAME="${POSTGRES_CONTAINER_NAME:-agenthub-postgres}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
POSTGRES_DB="${POSTGRES_DB:-agenthub}"
ALLOW_INSECURE_LOCAL_POSTGRES_PASSWORD="${ALLOW_INSECURE_LOCAL_POSTGRES_PASSWORD:-false}"

if ! command -v brew >/dev/null 2>&1 && [[ -x /opt/homebrew/bin/brew ]]; then
  brew() { /opt/homebrew/bin/brew "$@"; }
fi

start_with_brew() {
  if ! command -v brew >/dev/null 2>&1; then
    return 1
  fi

  if brew services start postgresql@16 >/dev/null 2>&1; then
    echo "Infra started: postgresql@16 (Homebrew)"
    return 0
  fi

  return 1
}

start_with_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi

  if [[ ! -S /var/run/docker.sock && ! -S "${HOME}/.docker/run/docker.sock" ]]; then
    return 1
  fi

  if ! DOCKER_CLIENT_TIMEOUT=3 COMPOSE_HTTP_TIMEOUT=3 docker info >/dev/null 2>&1; then
    return 1
  fi

  if docker ps --format '{{.Names}}' | grep -Fx "$POSTGRES_CONTAINER_NAME" >/dev/null 2>&1; then
    echo "Infra started: ${POSTGRES_CONTAINER_NAME} (Docker, already running)"
    return 0
  fi

  if docker ps -a --format '{{.Names}}' | grep -Fx "$POSTGRES_CONTAINER_NAME" >/dev/null 2>&1; then
    docker start "$POSTGRES_CONTAINER_NAME" >/dev/null
    echo "Infra started: ${POSTGRES_CONTAINER_NAME} (Docker, started existing container)"
    return 0
  fi

  if [[ -z "$POSTGRES_PASSWORD" ]]; then
    echo "POSTGRES_PASSWORD is required to create a new Docker PostgreSQL container."
    echo "Example: export POSTGRES_PASSWORD=\"<strong-random-password>\""
    return 1
  fi

  if [[ "$POSTGRES_PASSWORD" == "postgres" && "$ALLOW_INSECURE_LOCAL_POSTGRES_PASSWORD" != "true" ]]; then
    echo "Refusing insecure default POSTGRES_PASSWORD=postgres for new Docker PostgreSQL container."
    echo "Set a strong password or explicitly override for local throwaway use:"
    echo "  export POSTGRES_PASSWORD=\"<strong-random-password>\""
    echo "  # or (not recommended) export ALLOW_INSECURE_LOCAL_POSTGRES_PASSWORD=true"
    return 1
  fi

  docker run --name "$POSTGRES_CONTAINER_NAME" \
    -e "POSTGRES_USER=${POSTGRES_USER}" \
    -e "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}" \
    -e "POSTGRES_DB=${POSTGRES_DB}" \
    -p "${POSTGRES_PORT}:5432" \
    -d "$POSTGRES_IMAGE" >/dev/null
  echo "Infra started: ${POSTGRES_CONTAINER_NAME} (Docker, new container)"
  return 0
}

if start_with_brew; then
  exit 0
fi

if start_with_docker; then
  exit 0
fi

echo "Unable to start PostgreSQL infra via Homebrew or Docker."
echo "Install one of:"
echo "  - Homebrew with postgresql@16"
echo "  - Docker Desktop (running)"
exit 1
