#!/usr/bin/env bash
set -euo pipefail
# Pull + run api-sentinel-sensor on Linux.
# Private registry: docker login registry.gitlab.com  (PAT read_registry)

IMAGE="${IMAGE:-registry.gitlab.com/saasproduct2026/argus-inc/api-sentinel-sensor:v1.0.0}"
INGEST_URL="${INGEST_URL:-http://127.0.0.1:8000/v1/events}"
ACCOUNT_ID="${ACCOUNT_ID:-1000000}"
API_KEY="${API_KEY:?Set API_KEY to your Sensor sensor_key}"
RUST_LOG="${RUST_LOG:-info}"
SAMPLE_RATE="${SAMPLE_RATE:-1.0}"
NAME="${NAME:-api-sentinel-sensor-run}"

if [[ "${SKIP_PULL:-0}" != "1" ]]; then
  if ! docker pull "$IMAGE"; then
    echo "Pull failed. If you see 'denied' or 'forbidden', login first:" >&2
    echo "  docker login registry.gitlab.com -u YOUR_USERNAME -p YOUR_TOKEN" >&2
    echo "Use a GitLab PAT with scope: read_registry" >&2
    exit 1
  fi
fi

docker rm -f "$NAME" 2>/dev/null || true

exec docker run --name "$NAME" --rm \
  --privileged --pid=host --net=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -e API_KEY="$API_KEY" \
  -e RUST_LOG="$RUST_LOG" \
  "$IMAGE" \
  --bpf /app/bpf/http_trace.bpf.o \
  --ingest "$INGEST_URL" \
  --account-id "$ACCOUNT_ID" \
  --sample-rate "$SAMPLE_RATE" \
  --discover-libs
