#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-slipsweb}"
NETWORK_NAME="${SLIPSWEB_NETWORK:-${PROJECT_NAME}_slipsnet}"

if [[ -f "$ENV_FILE" ]]; then
  (cd "$ROOT_DIR" && COMPOSE_PROJECT_NAME="$PROJECT_NAME" docker compose --env-file "$ENV_FILE" down --remove-orphans) || true
else
  (cd "$ROOT_DIR" && COMPOSE_PROJECT_NAME="$PROJECT_NAME" docker compose down --remove-orphans) || true
fi

containers=$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT_NAME")
if [[ -n "$containers" ]]; then
  docker rm -f $containers >/dev/null 2>&1 || true
fi

containers=$(docker ps -aq --filter "network=$NETWORK_NAME")
if [[ -n "$containers" ]]; then
  docker rm -f $containers >/dev/null 2>&1 || true
fi

if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
  for _ in {1..10}; do
    if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done
fi
