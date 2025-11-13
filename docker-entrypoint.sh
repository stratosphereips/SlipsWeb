#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[slipsweb] $*"
}

if [[ $# -gt 0 ]]; then
  exec "$@"
fi

CONFIG_PATH="${MEDALLION_CONFIG:-config/medallion_config.json}"
MEDALLION_HOST="${MEDALLION_HOST:-0.0.0.0}"
MEDALLION_PORT="${MEDALLION_PORT:-1234}"
MEDALLION_LOG_LEVEL="${MEDALLION_LOG_LEVEL:-INFO}"

log "Starting Medallion on ${MEDALLION_HOST}:${MEDALLION_PORT} using ${CONFIG_PATH}"
medallion "${CONFIG_PATH}" \
  --host "${MEDALLION_HOST}" \
  --port "${MEDALLION_PORT}" \
  --log-level "${MEDALLION_LOG_LEVEL}" &
MEDALLION_PID=$!

cleanup() {
  log "Shutting down Medallion (${MEDALLION_PID})"
  kill "${MEDALLION_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "Starting SlipsWeb dashboard on ${FLASK_RUN_HOST:-0.0.0.0}:${FLASK_RUN_PORT:-5000}"
exec flask run --no-debugger --no-reload
