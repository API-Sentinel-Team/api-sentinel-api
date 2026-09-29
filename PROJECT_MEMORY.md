# API Sentinel / API Security Engine — Project Memory

Last reviewed: 2026-08-15  
Purpose: persistent context for humans and agents working in this repository.  
Full E2E guide: [`docs/PROJECT_END_TO_END.md`](docs/PROJECT_END_TO_END.md)

---

## What this project is

**API-Sentinel-Team** is a full-stack **API security platform** (branded in code as **“API Security Engine”** / AppSentinel-style). It provides:

- **API inventory** and endpoint lifecycle management  
- **Vulnerability and security testing** driven by a large **tests library** (YAML templates, remediation docs; lineage from **Akto**-style patterns)  
- **Runtime monitoring**: traffic/stream ingestion, sensors, alerts, evidence, playbooks  
- **Detection pipeline** (unified “engine” with shadow/active modes)  
- **LLM/agent-adjacent controls**: agent guard, MCP shield, agentic sessions  
- **ML-assisted detection** (scikit-learn, PyOD, anomaly-oriented workflows)  
- **Enforcement** (blocks, adaptive rate limiting, policies)  
- **Compliance / PII / governance / audit** surfaces  
- **Pentest orchestration** (profiles, Nuclei integration, safe/balanced/aggressive modes)  
- **Recon** scheduling and external findings  

North star: evidence-grade continuous API red team — see `docs/API_PENTESTING_NORTH_STAR.md`.

---

## Active working state (agents: read this first)

| Field | Value |
|-------|--------|
| **Branch** | `main` |
| **Primary docs** | `docs/PROJECT_END_TO_END.md`, this file, `AGENTS.md`, `k8s/README.md` |
| **WIP focus** | Live traffic → inventory → tests on `https://sentinel.wecrew.in/` |
| **Cluster** | kind `wecrew`, ns `api-sentinel`, Harbor `harbor.wecrew.in/finspot/api-sentinel-{backend,frontend,sensor}` |

**Live status (2026-08-16):** backend/frontend/postgres/redis Running; eBPF sensor DaemonSet `api-sentinel-sensor` Ready; LE cert Ready; `/healthz` + `/api/health/ready` OK. Sensor `wecrew-ebpf` (account_id=1) ingesting via in-cluster `POST /v1/events`. Console self-traffic (`/api/*` with blank host, `sentinel.wecrew.in`) is dropped from Live Feed.

**Shipped on this branch:**

1. Production Dockerfiles (multi-stage backend + non-root nginx frontend on `:8080`)  
2. `k8s/` manifests + secrets/build scripts + **sensor DaemonSet** (`k8s/35-sensor.yaml`)  
3. Fix: Alembic greenfield stamp uses `version_num` varchar(128) (long revision ids)  
4. Fix: `CICD_GATE_SIGNING_SECRET` required in prod secrets  
5. eBPF ingest unwraps session-4 `{MsgHeader, Batch}` envelopes on `/v1/events` and **upserts `APIEndpoint` inventory**. `request_logs.host` is persisted. OCI blob digests collapse to `{digest}`.  
6. Request-guard lookup is host-aware so duplicate catalogue rows cannot 500 every API.  
7. Ingest skips this product's own console polls so Live Feed shows cluster apps, not `/api/stream/recent`.  

**Recent commits:** OpenAPI drift processor + Schema Validation UI + fan-out caps; Evidence UI polish on main.

**In review — `feat/queued-external-engine-worker` (2026-09-14):** queued external-engine execution bound to a target + hashed OpenAPI spec (`external_engine_scope` on `POST /api/tests/run`, queued mode only), scanner subprocess kill on cancellation, preflight labelled `configuration_preflight` / `production_verified=false`, opt-in Helm leased scan-worker Deployment, k8s config moved to `background` execution. Backlog: `NORTH_STAR_IMPLEMENTATION_STATUS.md`. No live staging canary has run yet.

---

## Repository layout (high level)

| Path | Role |
|------|------|
| `server/` | Python backend (FastAPI app, routers, business logic, modules) |
| `api-sentinel-view-main/` | Frontend: **Vite + React 18 + TypeScript**, Radix/shadcn-style UI, TanStack Query, Playwright/Vitest |
| `tests-library/` | Massive catalog of security **test templates** and **remediation** markdown |
| `migrations/` | Alembic migration scripts (`versions/`, `env.py`) |
| `tests/` | `unit/`, `integration/`, `e2e/`, `security/`, `load/` (Locust), `benchmark/` |
| `docs/` | Architecture + north-star + detection engine + plans |
| `infra/` | Helm, Terraform AWS, nginx, Flink, sensor-external, K8s examples |
| `docker-compose.yml` | **Postgres 16**, **Redis 7**, **Kafka**, FastAPI |
| `Dockerfile` | Python 3.11; uvicorn; copies `server/`, `migrations/`, `tests-library/` |
| `Makefile` | Test targets: unit, integration, e2e, load, security |
| `requirements.txt` | Python dependencies |
| `api_security.db` | Local SQLite DB artifact (dev; also via `DATABASE_URL`) |

---

## Backend stack

- **Framework:** FastAPI (`server.api.main:app`)  
- **ASGI:** Uvicorn  
- **DB:** SQLAlchemy 2.x async; SQLite default locally; Postgres + `asyncpg` in compose/prod  
- **Migrations:** Alembic (`migrations/`); keep `alembic.ini` for Docker builds  
- **Cache / queue:** Redis (optional)  
- **Streaming:** Kafka + `aiokafka`; optional Flink when `STREAM_ENGINE=FLINK`  
- **Auth:** JWT, bcrypt, API keys, sensor keys (HMAC), optional tenant RLS  
- **Rate limiting:** `slowapi` + AdaptiveRequestGuard  
- **Scheduling:** APScheduler components  
- **Logging:** `structlog`  

**Config:** `server/config.py` — key flags:

- `UNIFIED_PIPELINE_MODE`: `off` | `shadow` | `active` (compose default: **shadow**)  
- `STREAM_ENGINE`: `IN_PROCESS` | `FLINK`  
- `TESTS_LIBRARY_PATH` → `./tests-library`  
- Startup toggles: demo bootstrap, template refresh, playbooks, analytics, archiver, ingestion queue, stream pipeline  

**API prefix:** REST under **`/api`**. Sensor ingest also at `POST /v1/events` and `POST /`.

**Models:** almost everything lives in `server/models/core.py` with `account_id` tenancy.

---

## Main Python packages (`server/`)

- **`server/api/`** — `main.py`, `routers/` (~50+), websocket live feed, rate limiter  
- **`server/models/`** — ORM entities (accounts, endpoints, tests, vulns, sensors, evidence, agentic, ML, …)  
- **`server/modules/`** — Feature implementations:  
  - `ingestion/`, `streaming/`, `threat_engine/`, `detection/`, `enforcement/`  
  - `test_executor/`, `pentest/`, `nuclei/`, `schemathesis/`, `zap/`  
  - `analytics/`, `recon/`, `ml/`, `api_inventory/`, `identity/`  
  - `response/`, `storage/`, `scheduler/`, `agentic/`, `sensors/`, `auth/`, `rls/`, `tenancy/`  

---

## Detection engine (conceptual)

`docs/detection-engine/README.md`:

`source adapters → NormalizationAgent → DetectionEnvelope → RuleDetectionAgent → DetectionSignal[] → CorrelationAgent → IncidentDecision → EnforcementAgent`

**Modes:** `off` (legacy), `shadow` (observe only), `active` (unified owns alerts/evidence/enforcement).

---

## Frontend (`api-sentinel-view-main/`)

- **Vite 5**, **React 18**, **TypeScript**, Tailwind, Radix/shadcn  
- **Data:** TanStack React Query (zustand listed but unused)  
- **Workspaces:** `/app` (customer), `/admin` (org admin), `/platform` (PLATFORM_ADMIN)  
- **Auth:** cookie session + optional in-memory Bearer; `GET /api/auth/me` bootstrap  
- **Pattern:** pages → hooks → services → `lib/api-client.ts`  
- **Realtime:** `lib/realtime.ts` → `/api/stream/live` invalidates query namespaces  
- **UI:** GlassCard (legacy) + Evidence\* system under `.evd-root`  
- Dev commonly via Vite proxy to backend (check `vite.config.ts` port)

---

## Tests library (`tests-library/`)

- Large YAML/YML corpus + remediation markdown (OWASP API / LLM Top 10 style)  
- Loaded via WordlistManager when `STARTUP_REFRESH_TEMPLATE_LIBRARY` is true  
- Not pytest — runtime scanner input  

---

## How to run (typical)

1. **Backend:** `pip install -r requirements.txt`, `.env` from `.env.example`, `alembic upgrade head` (Postgres), `uvicorn server.api.main:app --reload --host 127.0.0.1 --port 8000`  
2. **Frontend:** `cd api-sentinel-view-main && npm install && npm run dev`  
3. **Health:** `/api/health/ready`  
4. **Compose:** FastAPI **8000**, Redis **6380**, Kafka **9092**

### eBPF sensor

- Ingest: `POST /v1/events` (`Authorization: Bearer <sensor_key>`)  
- Register Sensor in app; account_id must match  
- Ops: `infra/SENSOR-RUNBOOK.md`, `infra/sensor-external/build-and-push-sensor.sh`

---

## Testing commands (`Makefile`)

- `make test-unit` / `test-integration` / `test-e2e` / `test-security` / `test-load` / `test-all`  
- Frontend: `npm run lint`, `npm test`, `npm run test:e2e`

---

## Security / ops notes

- Production secrets: `JWT_SECRET`, `API_KEY`, `ENCRYPTION_KEY`, `SENSOR_KEY_HASH_PEPPER`, CI gate signing  
- Demo users only with DEBUG + bootstrap flags  
- Multi-tenant: `account_id` + optional RLS  
- Pentest: allowlist, target_guard, auth profile scopes, worker isolation  
- Do not commit `.env`, cookies, or generated DBs  

---

## Quick “what file do I touch?”

| Task | Likely location |
|------|------------------|
| New REST endpoint | `server/api/routers/<feature>.py`, register in `routers/__init__.py` |
| DB schema change | `server/models/core.py`, `migrations/versions/` |
| Detection / pipeline | `server/modules/detection/`, `threat_engine/`, `streaming/` |
| Security test template | `tests-library/` |
| Customer UI | `api-sentinel-view-main/src/customer/` |
| Admin UI | `api-sentinel-view-main/src/admin/` |
| Evidence / realtime UI | `src/components/ui/Evidence*.tsx`, `src/lib/realtime.ts`, `index.css` |
| Nuclei | `server/modules/nuclei/`, `server/api/routers/nuclei.py` |
| Env / defaults | `server/config.py`, `.env.example` |
| Sensor / deploy | `infra/` |

---

## Agent working agreements for this repo

1. Keep routers thin; put logic in `server/modules/`.  
2. Always respect `account_id` tenancy and RBAC.  
3. UI: use existing workspace routes; prefer services/hooks over raw fetch in pages.  
4. Do not invent purple/glow redesigns that fight Evidence or GlassCard systems — extend the active language.  
5. Update this file + `docs/PROJECT_END_TO_END.md` when topology or major contracts change.  
6. Prefer `/context-restore` after long gaps; checkpoints live under gstack project `api-sentinel-team`.  

---

*Working snapshot of architecture and conventions. Refreshed 2026-08-09 after full E2E analysis.*
