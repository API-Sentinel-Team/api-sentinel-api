# API Sentinel — End-to-End Project Guide

Last updated: 2026-08-09  
Branch at review: `codex/north-star-api-red-team-platform`  
Companion memory file: [`PROJECT_MEMORY.md`](../PROJECT_MEMORY.md)

This document is the durable map of how the platform works from sensor to UI. Use it (and `PROJECT_MEMORY.md`) to resume work in a new agent session.

---

## 1. What the product is

**API-Sentinel-Team** is a multi-tenant API security platform (UI brand often “API Security Engine” / AppSentinel-style). It:

1. **Discovers** APIs (sensors, HAR/Postman/OpenAPI, traffic ingest)
2. **Monitors** runtime traffic (stream pipeline, alerts, evidence)
3. **Tests** APIs (YAML template library, Nuclei, Schemathesis, ZAP, identity/BOLA)
4. **Detects** threats via a unified detection pipeline (`off` / `shadow` / `active`)
5. **Enforces** (blocklist, rate limits, playbooks, MCP shield, agent guard)
6. **Governs** findings with evidence, retests, SLA, CI gates, and compliance reports

North-star product mandate: [`docs/API_PENTESTING_NORTH_STAR.md`](./API_PENTESTING_NORTH_STAR.md) — evidence-grade continuous API red team with hard production safety gates.

---

## 2. Repository map

| Path | Role |
|------|------|
| `server/` | FastAPI backend: routers (thin), modules (thick), models, config |
| `api-sentinel-view-main/` | Vite + React 18 + TypeScript UI |
| `tests-library/` | Runtime YAML security templates + remediation markdown (~Akto lineage) |
| `migrations/` | Alembic schema + RLS migrations |
| `tests/` | `unit/`, `integration/`, `security/`, `e2e/`, `load/`, `benchmark/` |
| `infra/` | Helm, Terraform (AWS), nginx edge, Flink, sensor build/run, K8s examples |
| `docs/` | Architecture, north-star, detection engine, sensor docs, plans |
| `docker-compose.yml` | FastAPI + Postgres 16 + Redis 7 + Kafka |
| `AGENTS.md` | Repo conventions for agents |

---

## 3. Runtime topology

```text
[eBPF Sensor / DaemonSet] --Bearer sensor_key--> POST /v1/events
[UI :8080 Vite] ----------cookie/JWT----------> /api/*
[CI / scanners] ----------API tokens----------> /api/tests|/pentest|/cicd
                |
                v
         [nginx edge optional]
                |
                v
         [FastAPI :8000]
         /  |  |  \
   Postgres Redis Kafka  (optional Flink / ClickHouse / S3)
```

**Compose defaults:** FastAPI on `8000`, Redis host `6380→6379`, Kafka `9092`, `UNIFIED_PIPELINE_MODE=shadow`.

**Frontend dev:** Vite often on **8080**; proxy `/api` → backend (see `vite.config.ts`; align port with running uvicorn). Prefer same-origin `/api` via proxy over a stale `VITE_API_BASE_URL`.

---

## 4. Backend architecture

### Entry points

- App: `server.api.main:app` (`server/api/main.py`)
- REST: mounted under **`/api`**
- Sensor aliases (same eBPF handler): `POST /v1/events`, `POST /` (also `/api/stream/ingest/ebpf`)
- Config: `server/config.py` (pydantic-settings, `.env`)
- Models: `server/models/core.py` (single source of truth)
- Domain logic: `server/modules/*`

### Auth & tenancy

| Concern | Mechanism |
|---------|-----------|
| Users | JWT (HS256) + optional `access_token` cookie; roles VIEWER→ADMIN + PLATFORM_ADMIN |
| Sensors | `Authorization: Bearer <sensor_key>` / `X-Sensor-Key`; keys hashed at rest (`SENSOR_KEY_HASH_PEPPER`) |
| Tenant key | `account_id` on almost every row |
| Isolation | App filters + ContextVar + optional Postgres RLS (`TENANT_RLS_ENABLED`) |
| RBAC | `server/modules/auth/rbac.py` permission matrix |

Demo bootstrap only when `DEBUG` + `STARTUP_ENABLE_DEMO_BOOTSTRAP` — never enable in production.

### Core data flows

#### A. Sensor → detection → alerts

```text
Sensor → /v1/events → resolve_sensor_by_key
  → upsert APIEndpoint inventory (Default Inventory; host + path_pattern)
  → UNIFIED_PIPELINE_MODE:
       active  → unified detection pipeline (normalize/rules/correlate/enforce)
       shadow  → pipeline side-by-side; legacy path may still write alerts
       off     → legacy detectors only
  → DB commit + WebSocket broadcast (tenant-scoped)
```

Key files: `server/api/routers/stream.py`, `server/modules/detection/pipeline.py`, `server/modules/sensors/keys.py`.

#### B. Log/traffic ingest → event bus → stream pipeline

```text
/api/stream/ingest or ingestion jobs
  → IngestionJob queue → processors (endpoints, samples, PII, governance)
  → EnrichedEvent → Kafka topic events.enriched.{account_id}
       (or InMemoryEventBus if Kafka off)
  → StreamPipeline (IN_PROCESS) or Flink + KafkaAlertConsumer
```

#### C. Active scanning

```text
/api/tests | /api/pentest | /api/nuclei
  → RBAC + target_guard + auth_profile rules
  → engines: YAML (tests-library), Nuclei, Schemathesis, ZAP, identity modules
  → Vulnerability fingerprint merge + Evidence
  → optional CI gate + integrations
```

External engines (Schemathesis, Nuclei, ZAP) run in the queued worker only when
`POST /api/tests/run` carries `external_engine_scope: {target_url, openapi_spec_id}`
and `PENTEST_SCAN_EXECUTION_MODE=queued`. The API validates the target and
auth-profile scope, records the spec's sha256 in the plan, and the worker rejects
changed specs, mismatched targets, missing endpoints, and remote spec references.
Without the binding, external engines are `blocked` in the plan while the YAML
template path still runs. Worker acceptance requires a hash-verified execution
artifact from the same run for every required engine.

#### D. Dashboard reads

JWT/cookie → set `account_id` → `/api/dashboard`, `/endpoints`, `/alerts`, `/vulnerabilities`, … (Redis cache when configured).

### Important routers (under `/api`)

| Area | Routers |
|------|---------|
| Auth/org | `auth`, `oauth`, `organization`, `audit_logs`, `billing` |
| Inventory | `endpoints`, `collections`, `openapi`, `lineage`, `governance`, `traffic` |
| Runtime | `sensors`, `stream`, `ingestion`, `alerts`, `threat_actors`, `blocklist`, `enforcement`, `waf` |
| Testing | `tests`, `suites`, `schedules`, `bola`, `pentest`, `nuclei`, `cicd` |
| Findings | `vulnerabilities`, `pii`, `evidence`, `compliance`, `playbooks` |
| Advanced | `detection_meta`, `ml_*`, `recon*`, `agentic`, `agent_guard`, `mcp_shield`, `business_logic` |
| Ops | `dashboard`, `analytics`, `health`, `storage`, `retention`, `akto_admin` shims |

### Detection modes

Documented in `docs/detection-engine/README.md`:

`source adapters → Normalization → Rules → Signals → Correlation → IncidentDecision → Enforcement`

- **`off`**: legacy detectors own writes  
- **`shadow`**: unified pipeline observes; no canonical ownership (compose default)  
- **`active`**: unified pipeline owns alerts/evidence/enforcement  

---

## 5. Frontend architecture (`api-sentinel-view-main/`)

### Stack

Vite 5, React 18, TypeScript, Tailwind + Radix/shadcn, TanStack Query, react-router-dom, recharts, Vitest + Playwright.

### Three workspaces

| Prefix | Audience | Roles |
|--------|----------|-------|
| `/app/*` | Customer SOC / engineers | ADMIN … VIEWER |
| `/admin/*` | Org admin / onboarding / sensors | ADMIN, SECURITY_ENGINEER |
| `/platform/*` | Platform ops | PLATFORM_ADMIN only |

Shell: `WorkspaceLayout` + `workspaces.ts`. Public: `/login`, `/access-restricted`. Legacy paths redirect into `/app` or `/admin`.

### Data access pattern

```text
Page → hooks (React Query) → services → lib/api-client.ts
```

- Base URL: `(VITE_API_BASE_URL || window.location.origin) + '/api'`
- Always `credentials: 'include'`; optional in-memory Bearer (not localStorage)
- WebSocket live feed: `/api/stream/live` (query `?token=` when memory token present)

Key hooks: `use-dashboard`, `use-discovery`, `use-testing`, `use-protection`, `use-security-ops`, `use-admin`, `use-openapi-docs`, `use-compliance`.

### UI systems

- **GlassCard** — older purple-accent card language (still used on admin)
- **Evidence\*** — newer case-file aesthetic under `.evd-root` (customer workspace): `EvidencePanel`, `EvidenceStamp`, `EvidenceLedger`, `EvidenceStatLine`, `EvidenceTrace`, `EvidenceSectionHead`
- **RealtimeProvider** (`src/lib/realtime.ts`) — app-level WS invalidates React Query namespaces; hooks often poll at ~60s as fallback

---

## 6. Sensor (eBPF / Argus)

| Item | Detail |
|------|--------|
| External source | Separate API-Sensor repo (see `infra/sensor-external/`) |
| Build/push | `infra/sensor-external/build-and-push-sensor.sh` |
| Runbooks | `infra/SENSOR-RUNBOOK.md`, `docs/eBPF_Sensor_Architecture.md` |
| Ingest | `POST /v1/events` with `events[]`, Bearer = sensor key; upserts catalogue + `request_logs` |
| Fleet | `infra/k8s/sensor-daemonset.example.yaml` |
| Local helpers | `infra/scripts/run-sensor.sh` / `.ps1` |

Captures HTTP metadata via kernel TLS uprobes; not full bodies; needs real Linux BPF (not typical Docker Desktop).

---

## 7. Infra & deploy

| Layer | Location |
|-------|----------|
| Local | `docker compose up --build` (+ `--profile scan-worker` for engines) |
| Production deploy | [`docs/DEPLOY_PRODUCTION.md`](./DEPLOY_PRODUCTION.md) |
| Edge TLS | `infra/nginx/` + compose overlay |
| K8s app | `infra/helm/api-sentinel/` (migrate Job, HPA, optional Bitnami deps) |
| AWS | `infra/terraform/aws/` (EKS, RDS, MSK, ElastiCache, S3) |
| Stream job | `infra/flink/` |
| Isolated scans | `Dockerfile.scan-worker` + `infra/scripts/build-and-push-scan-worker.sh` + `infra/k8s/scan-worker-job.example.yaml` |
| Leased scan worker (Helm, opt-in) | `infra/helm/api-sentinel/templates/scan-worker.yaml` — `scanWorker.enabled=true` + digest-pinned `scanWorker.image`; non-root, read-only FS, no SA token, forces `queued` mode. Leased worker, not per-run Job isolation. |

---

## 8. Tests & quality

| Command | Scope |
|---------|-------|
| `make test-unit` | `tests/unit/` + coverage on `server` |
| `make test-integration` | API/tenancy/ingestion/pentest/nuclei |
| `make test-security` | Auth, sensor creds, tenant isolation |
| `make test-e2e` | Broader e2e |
| `make test-load` | Locust |
| `make test-all` | unit + integration + e2e + security |
| Frontend | `npm run lint|test|test:e2e|build` in `api-sentinel-view-main/` |

`tests-library/` is **not** pytest — it is the scanner corpus loaded via `TESTS_LIBRARY_PATH` / WordlistManager.

---

## 9. How to run locally

**Backend**

```bash
pip install -r requirements.txt
# copy .env.example → .env
alembic upgrade head   # if using Postgres
uvicorn server.api.main:app --reload --host 127.0.0.1 --port 8000
```

Or: `docker compose up --build`

**Frontend**

```bash
cd api-sentinel-view-main
npm install
npm run dev
```

Health: `GET /api/health/ready`

---

## 10. “What file do I touch?”

| Task | Location |
|------|----------|
| New REST API | `server/api/routers/<feature>.py` + register in `routers/__init__.py` |
| Business logic | `server/modules/<domain>/` |
| Schema | `server/models/core.py` + `migrations/versions/` |
| Detection | `server/modules/detection/`, `streaming/`, `threat_engine/` |
| Active scan engine | `server/modules/pentest/`, `nuclei/`, `test_executor/` |
| Security template | `tests-library/` |
| Customer UI page | `api-sentinel-view-main/src/customer/pages/` |
| Admin UI | `api-sentinel-view-main/src/admin/pages/` |
| API client / WS | `src/lib/api-client.ts`, `src/lib/realtime.ts` |
| Config / env | `server/config.py`, `.env.example` |
| Sensor ops | `infra/sensor-external/`, `infra/SENSOR-RUNBOOK.md` |

---

## 11. Production gotchas

1. Set `JWT_SECRET`, `API_KEY`, `ENCRYPTION_KEY`, `SENSOR_KEY_HASH_PEPPER`, CI gate signing secret before `DEBUG=False`.
2. Pentest target allowlist + target_guard are mandatory in production; private targets blocked.
3. Auth profiles with credentials need concrete `scope_domains` (no `*` wildcards for credentialed profiles).
4. Kafka off ⇒ in-memory bus (not multi-replica safe).
5. Nuclei needs binary on `PATH` or scans return `RUNTIME_UNAVAILABLE`.
6. Prefer Alembic; disable `STARTUP_BOOTSTRAP_SCHEMA` / demo bootstrap in prod.
7. Frontend port/env mismatches are a common local footgun — match Vite proxy to uvicorn.
8. LiveFeed may open a second WS beside app-level `RealtimeProvider`.
9. Onboarding completion is partly `localStorage` (`appsentinel-onboarding-v1`).
10. Never commit `.env`, sensor keys, or local DB artifacts.

---

## 12. Current WIP snapshot (2026-08-09)

Uncommitted work on branch `codex/north-star-api-red-team-platform` (also ahead of origin):

- **Evidence UI** — new Evidence\* components, Dashboard rewrite, CSS tokens, chart/layout tweaks
- **Realtime** — `src/lib/realtime.ts` + slower poll intervals on dashboard/protection/testing hooks
- **Nuclei finding promotion** — `server/modules/nuclei/runner.py`, `server/api/routers/nuclei.py`, unit + integration tests

Recent committed theme: OpenAPI drift processor, Schema Validation UI, fan-out caps, Release Governance surfaces.

---

## 13. Session restore checklist

When starting a new chat on this repo:

1. Read this file + `PROJECT_MEMORY.md`
2. Read `docs/API_PENTESTING_NORTH_STAR.md` if touching pentest/evidence/CI
3. Check `git status` / branch (`codex/north-star-api-red-team-platform`)
4. Prefer thin routers + modules; keep tenant `account_id` filters
5. For UI: preserve workspace RBAC and existing service/hook patterns
6. Restore gstack checkpoint via `/context-restore` if present under `~/.gstack/projects/api-sentinel-team/checkpoints/`

---

*Update this document when topology, ingest contracts, or workspace routing change.*
