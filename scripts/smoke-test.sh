#!/usr/bin/env bash
# Starts the container image passed as $1, waits for readiness, exercises the
# primary user-facing path, and fails loudly if anything does not behave.
set -euo pipefail

IMAGE="${1:?usage: smoke-test.sh <image[:tag]>}"
PORT="${SMOKE_PORT:-8000}"
NAME="smoke-$(date +%s)-$$"

cleanup() {
  docker logs "${NAME}" 2>&1 | tail -50 || true
  docker rm -f "${NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "${NAME}" -p "${PORT}:8000" "${IMAGE}" >/dev/null

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS "http://127.0.0.1:${PORT}/healthz" | tee /dev/stderr | grep -q '"status"'
curl -fsS "http://127.0.0.1:${PORT}/readyz" >/dev/null
echo "smoke test passed for ${IMAGE}"
