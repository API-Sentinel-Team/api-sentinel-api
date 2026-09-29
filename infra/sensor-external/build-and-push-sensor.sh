#!/usr/bin/env bash
# Build API-Sensor from GitHub (session-4-production-fixes by default) and push to a registry.
#
# Prerequisites: docker, git, make, clang/llvm/bpftool/rust — best run on Linux or WSL2.
#
# Usage:
#   export REGISTRY_IMAGE="docker.io/myuser/api-sentinel-sensor:v1.4.0"
#   ./infra/sensor-external/build-and-push-sensor.sh
#
# Optional env:
#   SENSOR_REPO_URL   (default: https://github.com/vediyappanm/API-Sensor.git)
#   SENSOR_BRANCH     (default: session-4-production-fixes)
#   SENSOR_DIR        (default: temporary clone under /tmp)
#   SKIP_CLONE=1      use existing SENSOR_DIR without cloning
#   SKIP_PUSH=1       build and tag only

set -euo pipefail

SENSOR_REPO_URL="${SENSOR_REPO_URL:-https://github.com/vediyappanm/API-Sensor.git}"
SENSOR_BRANCH="${SENSOR_BRANCH:-session-4-production-fixes}"

if [[ -z "${REGISTRY_IMAGE:-}" ]]; then
  echo "Set REGISTRY_IMAGE to the full tag to push, e.g." >&2
  echo "  export REGISTRY_IMAGE=registry.gitlab.com/group/proj/api-sentinel-sensor:v1.4.0" >&2
  exit 1
fi

if [[ "${SKIP_CLONE:-0}" == "1" ]]; then
  WORKDIR="${SENSOR_DIR:?Set SENSOR_DIR to your local API-Sensor clone when SKIP_CLONE=1}"
  echo "==> Using existing SENSOR_DIR=$WORKDIR"
else
  WORKDIR=$(mktemp -d)
  trap 'rm -rf "$WORKDIR"' EXIT
  echo "==> Cloning $SENSOR_REPO_URL (branch $SENSOR_BRANCH) -> $WORKDIR"
  git clone --depth 1 --branch "$SENSOR_BRANCH" "$SENSOR_REPO_URL" "$WORKDIR"
fi

cd "$WORKDIR"

if [[ ! -f Dockerfile ]]; then
  echo "No Dockerfile in $WORKDIR" >&2
  exit 1
fi

echo "==> make BPF object (userspace/ dir shadows the Makefile target)"
make bpf/http_trace.bpf.o
( cd userspace && cargo build --release )

echo "==> Stage binary for Dockerfile"
cp -f userspace/target/release/api-sec-sensor ./api-sec-sensor

echo "==> docker build -> $REGISTRY_IMAGE"
docker build -t "$REGISTRY_IMAGE" .

if [[ "${SKIP_PUSH:-0}" == "1" ]]; then
  echo "==> SKIP_PUSH=1 — not pushing"
  exit 0
fi

echo "==> docker push $REGISTRY_IMAGE"
docker push "$REGISTRY_IMAGE"

echo "Done. Image: $REGISTRY_IMAGE"
