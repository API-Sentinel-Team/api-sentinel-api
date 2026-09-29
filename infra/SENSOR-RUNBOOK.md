# Sensor: pull, auth, run

To **build and push** your own image from GitHub (`vediyappanm/API-Sensor`, branch `session-4-production-fixes`), see **[sensor-external/API-SENSOR-REGISTRY.md](sensor-external/API-SENSOR-REGISTRY.md)**.

---

## 1. Registry login (required — image is private)

```bash
docker login registry.gitlab.com -u YOUR_GITLAB_USERNAME -p YOUR_TOKEN
```

Use a [Personal Access Token](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html) with **`read_registry`**, or a **Deploy Token** with `read_registry` for project `saasproduct2026/argus-inc`.

### 1.1 Pull errors (`denied`, `access forbidden`, `403`)

| Symptom | Fix |
|--------|-----|
| `Error response from daemon: denied` / `access forbidden` | Run **`docker login registry.gitlab.com`** with a token that has **`read_registry`**. Username is your GitLab username (or literal token user for deploy tokens per GitLab docs). |
| Wrong project path | Image must be **`registry.gitlab.com/saasproduct2026/argus-inc/api-sentinel-sensor:v1.0.0`** — confirm your account can read that registry. |
| Expired login | Re-run **`docker login`**; credentials are stored in Docker’s config, not the repo. |

## 2. Backend must accept ingest

- API Sentinel listening on **port 8000** (or HTTPS behind nginx).
- **Register a sensor** in the UI/API so a row exists in `sensors` with a **`sensor_key`**.
- **`API_KEY`** in the container = that **`sensor_key`** (sent as `Authorization: Bearer ...`).
- **`--account-id`** must match the **`account_id`** of that sensor row.

## 3. Pull image

```bash
docker pull registry.gitlab.com/saasproduct2026/argus-inc/api-sentinel-sensor:v1.0.0
```

## 4. Run (Linux / WSL2 recommended)

From repo root:

```bash
chmod +x infra/scripts/run-sensor.sh
export API_KEY='your-sensor-key-from-db'
export INGEST_URL='http://127.0.0.1:8000/v1/events'
export ACCOUNT_ID=1000000
./infra/scripts/run-sensor.sh
```

**Docker Desktop (Windows):** use PowerShell:

```powershell
.\infra\scripts\run-sensor.ps1 -ApiKey "your-sensor-key" -IngestUrl "http://host.docker.internal:8000/v1/events" -AccountId 1000000 -DiscoverLibs
```

`-DiscoverLibs` is optional (auto-find OpenSSL).

## 5. Limitations

| Environment | Notes |
|-------------|--------|
| **Docker Desktop (Windows/macOS)** | eBPF runs inside the Linux VM; `--net=host` is not the same as on bare metal. BPF programs may fail to load — test on a **real Linux** server for production. |
| **Kernel** | Needs **≥ 5.8** and BPF privileges. |
| **HTTPS ingest** | Use your nginx URL: `https://api.example.com/v1/events` |

## 6. One-liner (after login)

```bash
docker run --rm --privileged --pid=host --net=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -e API_KEY='YOUR_SENSOR_KEY' \
  -e RUST_LOG=info \
  registry.gitlab.com/saasproduct2026/argus-inc/api-sentinel-sensor:v1.0.0 \
  --bpf /app/bpf/http_trace.bpf.o \
  --ingest https://YOUR_DOMAIN/v1/events \
  --account-id YOUR_ACCOUNT_ID \
  --discover-libs
```
