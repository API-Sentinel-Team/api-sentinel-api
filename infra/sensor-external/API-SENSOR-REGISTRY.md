# Push [API-Sensor](https://github.com/vediyappanm/API-Sensor) to a container registry

Your sensor image is built from the repo’s root **`Dockerfile`**, which expects:

- **`api-sec-sensor`** — the Rust release binary (at repo root)
- **`bpf/http_trace.bpf.o`** — compiled eBPF object (produced by `make`)

I cannot log in to your registry or push from Cursor; run the steps below on your machine or in CI.

---

## 1. One-time: create registry access

| Registry | Login |
|----------|--------|
| **Docker Hub** | `docker login` (or `docker login -u USER docker.io`) |
| **GitLab** | `docker login registry.gitlab.com -u USER -p TOKEN` (PAT: `read_registry` + `write_registry`) |
| **GitHub Container Registry (GHCR)** | `echo TOKEN \| docker login ghcr.io -u USER --password-stdin` (PAT: `write:packages`) |

Create the **repository/image name** in the registry UI first if required (e.g. GitLab project → Deploy → Container Registry).

---

## 2. Build (Linux or WSL2 — needs kernel headers / `bpftool` for BPF)

```bash
git clone https://github.com/vediyappanm/API-Sensor.git
cd API-Sensor
git checkout session-4-production-fixes

# Optional: verify environment
make verify-env   # or: bash scripts/verify_env.sh

# Build BPF + Rust
make

# Dockerfile COPY expects binary named api-sec-sensor at repo root
cp userspace/target/release/api-sec-sensor ./api-sec-sensor

docker build -t YOUR_REGISTRY/YOUR_IMAGE:YOUR_TAG .
```

**Examples of `YOUR_REGISTRY/YOUR_IMAGE:YOUR_TAG`:**

- Docker Hub: `vediyappanm/api-sentinel-sensor:v1.4.0-session4`
- GitLab: `registry.gitlab.com/saasproduct2026/argus-inc/api-sentinel-sensor:v1.4.0-session4`
- GHCR: `ghcr.io/vediyappanm/api-sentinel-sensor:session-4-production-fixes`

---

## 3. Push

```bash
docker push YOUR_REGISTRY/YOUR_IMAGE:YOUR_TAG
```

---

## 4. Use with API Sentinel

Point **`infra/scripts/run-sensor.ps1`**, **`run-sensor.sh`**, or your DaemonSet to:

```text
YOUR_REGISTRY/YOUR_IMAGE:YOUR_TAG
```

Keep **`API_KEY`**, **`INGEST_URL`** (`…/v1/events`), and **`account-id`** aligned with your backend sensor registration ([SENSOR-RUNBOOK](../SENSOR-RUNBOOK.md)).

---

## 5. Scripted build + push

From this repo root:

```bash
chmod +x infra/sensor-external/build-and-push-sensor.sh
export REGISTRY_IMAGE="registry.gitlab.com/group/project/api-sentinel-sensor:v1.4.0"
./infra/sensor-external/build-and-push-sensor.sh
```

Set **`SENSOR_DIR`** if you already cloned API-Sensor elsewhere. See script header for env vars.

---

## 6. GitHub Actions (optional)

Copy **`sensor-publish.example.yml`** into **API-Sensor** as `.github/workflows/sensor-publish.yml`, set **`REGISTRY`** / secrets, and push to trigger build + push to GHCR or Docker Hub.

Building BPF in GitHub-hosted runners is supported on **`ubuntu-latest`** if `linux-tools-common`, `clang`, `llvm`, `libbpf-dev`, etc. are installed in the workflow (the example workflow installs them).
