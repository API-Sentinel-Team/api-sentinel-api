#!/usr/bin/env bash
# Build + push API Sentinel images to Harbor (wecrew).
# Each service now lives in its own repo; check them out as siblings of this one:
#   ../api-sentinel-frontend  ../api-sentinel-scan-worker  ../api-sentinel-scheduler  ../api-sentinel-archiver
# sentinel-core is a private repo, so export GH_TOKEN (read access to it) before building.
# Usage:
#   ./k8s/build-and-push.sh              # backend + frontend + scheduler + archiver
#   ./k8s/build-and-push.sh backend|frontend|scheduler|archiver
#   ./k8s/build-and-push.sh worker        # heavy (Nuclei+ZAP)
#   ./k8s/build-and-push.sh sensor        # eBPF API-Sensor (needs clang + rustc)
#   TAG=20260809 ./k8s/build-and-push.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIBLINGS="$(cd "$ROOT/.." && pwd)"
REGISTRY="${REGISTRY:-harbor.wecrew.in/finspot}"
TAG="${TAG:-latest}"
TARGET="${1:-all}"

build_push() {
  local name="$1" context="$2" dockerfile="$3" needs_core="${4:-yes}"
  local image="${REGISTRY}/${name}:${TAG}"
  [ -d "${context}" ] || { echo "missing ${context} - clone that repo next to this one" >&2; exit 1; }
  echo "==> building ${image}"
  if [ "${needs_core}" = "yes" ]; then
    : "${GH_TOKEN:?export GH_TOKEN with read access to api-sentinel-core}"
    DOCKER_BUILDKIT=1 docker build --secret id=gh_token,env=GH_TOKEN -f "${dockerfile}" -t "${image}" "${context}"
  else
    docker build -f "${dockerfile}" -t "${image}" "${context}"
  fi
  echo "==> pushing ${image}"
  docker push "${image}"
  echo "==> done ${image}"
}

case "$TARGET" in
  all)
    build_push api-sentinel-backend "$ROOT" "$ROOT/Dockerfile"
    build_push api-sentinel-frontend "$SIBLINGS/api-sentinel-frontend" "$SIBLINGS/api-sentinel-frontend/Dockerfile" no
    build_push api-sentinel-scheduler "$SIBLINGS/api-sentinel-scheduler" "$SIBLINGS/api-sentinel-scheduler/Dockerfile"
    build_push api-sentinel-archiver "$SIBLINGS/api-sentinel-archiver" "$SIBLINGS/api-sentinel-archiver/Dockerfile"
    ;;
  backend)
    build_push api-sentinel-backend "$ROOT" "$ROOT/Dockerfile"
    ;;
  frontend)
    build_push api-sentinel-frontend "$SIBLINGS/api-sentinel-frontend" "$SIBLINGS/api-sentinel-frontend/Dockerfile" no
    ;;
  scheduler)
    build_push api-sentinel-scheduler "$SIBLINGS/api-sentinel-scheduler" "$SIBLINGS/api-sentinel-scheduler/Dockerfile"
    ;;
  archiver)
    build_push api-sentinel-archiver "$SIBLINGS/api-sentinel-archiver" "$SIBLINGS/api-sentinel-archiver/Dockerfile"
    ;;
  worker)
    build_push api-sentinel-scan-worker "$SIBLINGS/api-sentinel-scan-worker" "$SIBLINGS/api-sentinel-scan-worker/Dockerfile"
    ;;
  sensor)
    # Prefer the in-tree checkout (API-Sensor/). Makefile `userspace` is now
    # .PHONY so `make` works; cargo is still invoked explicitly as a fallback.
    SENSOR_REPO_URL="${SENSOR_REPO_URL:-https://github.com/vediyappanm/API-Sensor.git}"
    SENSOR_BRANCH="${SENSOR_BRANCH:-session-4-production-fixes}"
    LOCAL_SENSOR="${ROOT}/API-Sensor"
    if [[ "${SKIP_CLONE:-0}" == "1" ]]; then
      WORKDIR="${SENSOR_DIR:?Set SENSOR_DIR when SKIP_CLONE=1}"
    elif [[ -z "${SENSOR_DIR:-}" && -f "${LOCAL_SENSOR}/Dockerfile" ]]; then
      WORKDIR="$LOCAL_SENSOR"
      echo "==> using local sensor ${WORKDIR}"
    else
      WORKDIR="${SENSOR_DIR:-$(mktemp -d)}"
      echo "==> cloning ${SENSOR_REPO_URL} (${SENSOR_BRANCH})"
      git clone --depth 1 --branch "$SENSOR_BRANCH" "$SENSOR_REPO_URL" "$WORKDIR"
    fi
    (
      cd "$WORKDIR"
      make bpf/http_trace.bpf.o
      ( cd userspace && cargo build --release )
      cp -f userspace/target/release/api-sec-sensor ./api-sec-sensor
    )
    build_push api-sentinel-sensor "$WORKDIR" "$WORKDIR/Dockerfile"
    ;;
  *)
    echo "Usage: $0 [all|backend|frontend|worker|sensor]" >&2
    exit 1
    ;;
esac
