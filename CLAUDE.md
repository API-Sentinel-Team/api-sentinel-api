# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**API Sentinel** (branded in code as *API Security Engine*) — a full-stack API security platform:
discovery/inventory, vulnerability testing from a YAML template corpus, runtime traffic ingestion via
eBPF sensors, a detection→correlation→enforcement pipeline, pentest orchestration (Nuclei /
Schemathesis / ZAP), and compliance/evidence surfaces.

- `server/` — FastAPI backend (Python 3.11, SQLAlchemy 2.x async, Alembic)
- `api-sentinel-view-main/` — Vite 5 + React 18 + TypeScript SPA (Tailwind, Radix/shadcn, TanStack Query)
- `tests-library/` — YAML security-test templates + remediation markdown. **Runtime scanner input, not pytest.** Never point pytest at it.
- `k8s/` — deploy to kind cluster `wecrew`, namespace `api-sentinel`, `https://sentinel.wecrew.in/`
- `infra/` — Helm, Terraform (AWS), nginx, Flink, eBPF sensor packaging

Companion docs: `PROJECT_MEMORY.md` (living architecture snapshot), `docs/PROJECT_END_TO_END.md`,
`AGENTS.md` (style conventions), `k8s/README.md`, `docs/CI_REQUIRED_CHECKS.md`.

## Commands

### Backend

```bash
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head                       # required for Postgres; see migrations note below
uvicorn server.api.main:app --reload --host 127.0.0.1 --port 8000
```

`pytest.ini` sets `pythonpath = .` and `asyncio_mode = auto`, so no `PYTHONPATH` export and no
`@pytest.mark.asyncio` decorators are needed locally.

```bash
make test-unit          # pytest tests/unit/ with coverage
make test-integration   # needs Postgres + Redis (DATABASE_URL, REDIS_URL)
make test-security
make test-e2e           # pytest tests/e2e/ — backend API E2E, not the browser suite
make test-load          # locust, 50 users / 30s against localhost:8000
make test-all

pytest tests/unit/test_cicd_quality_gate.py -v                    # one file
pytest tests/unit/test_cicd_quality_gate.py::test_name -v         # one test
pytest tests/ -k "tenancy" -v                                     # by keyword
```

Most backend tests need `DEBUG=true` (production validation in `server/config.py` otherwise refuses
to construct `Settings`). CI sets it explicitly on every backend job.

### Frontend (from `api-sentinel-view-main/`)

```bash
npm install
npm run dev            # Vite on :8080, proxies /api and WS to 127.0.0.1:8000
npm run lint           # ESLint — a CI gate, run before any UI change lands
npm test               # vitest run
npm test -- src/services/discovery.service.test.ts   # single vitest file
npm run test:e2e       # Playwright; boots its own backend + frontend
npm run build
```

Playwright's `webServer` starts a **throwaway backend** on `:18000` with a SQLite DB
(`e2e_api_security.db`), `STARTUP_BOOTSTRAP_SCHEMA=true` and every background processor disabled —
override ports with `E2E_BACKEND_PORT` / `E2E_FRONTEND_PORT`, or reuse running servers with
`E2E_REUSE_EXISTING_SERVER=true`.

### Docker / Kubernetes

```bash
docker compose up --build                          # FastAPI :8000, Postgres, Redis :6380, Kafka :9092
docker compose --profile scan-worker up --build    # adds the isolated Schemathesis/Nuclei/ZAP worker

./k8s/build-and-push.sh          # harbor.wecrew.in/finspot/api-sentinel-{backend,frontend}:latest
./k8s/build-and-push.sh worker   # optional heavy scan-worker image
```

Apply `k8s/` manifests in number order (`00-` → `50-`) after `./k8s/create-secrets.sh`; see
`k8s/README.md` for the Traefik SNI passthrough step required to expose the host publicly.

## Architecture

### Request path and router registration

`server/api/main.py` builds the app: CORS → `AdaptiveRequestGuard` middleware → a single aggregate
`router` from `server/api/routers/__init__.py` mounted at **`/api`**.

Adding an endpoint is a **two-step edit**: create `server/api/routers/<feature>.py` exposing
`router`, then both import it and `include_router` it in `routers/__init__.py`. Missing the second
step silently yields a 404. Note `akto_admin` is mounted with no prefix (paths like
`/api/fetchModuleInfo`), and `ml_models` + `ml_training` share the `/ml` prefix.

Two routes live **outside** `/api`, defined directly on the app: `POST /v1/events` and `POST /`
(legacy) both delegate to `handle_ebpf_ingest_request` for eBPF sensor ingest, authenticated with a
sensor API key as a bearer token rather than a user JWT.

WebSocket live feed is at `/api/stream/live`.

### Auth, RBAC, and tenancy — the core invariant

`server/modules/auth/rbac.py` provides the dependencies every router uses:

```python
user: dict = Depends(RBAC.require_permission(Permission.ENDPOINTS_READ))
account_id = user["account_id"]
filters = [APIEndpoint.account_id == account_id]     # every query, no exceptions
```

`RBAC.require_auth` accepts a bearer header *or* the `access_token` cookie, and calls
`set_current_account_id()` so optional Postgres RLS (`TENANT_RLS_ENABLED`) sees the tenant.

Subtlety worth knowing: **`require_role` grants `ADMIN` an unconditional bypass;
`require_permission` does not** — `ADMIN` passes only because `ROLE_PERMISSIONS["ADMIN"]` lists the
permission. Prefer `require_permission` for new endpoints.

Every multi-tenant table carries `account_id`. Omitting the filter is a cross-tenant data leak, which
the `tests/security/` suite exists to catch.

### Models and migrations

Essentially the whole ORM lives in one file: `server/models/core.py` (~1200 lines). Schema changes
mean editing it *and* adding an Alembic revision under `migrations/versions/`.

`migrations/env.py` has a greenfield path: on an empty database it creates all tables from metadata
and stamps head directly, with `alembic_version.version_num` as **`String(128)`** (the default 32
chars truncates this project's long revision ids). Preserve that width if you touch `env.py`.

### Configuration and startup

`server/config.py` is a pydantic-settings `Settings` singleton (~180 flags) read from env/`.env`.
Two things drive most surprises:

1. **`_validate_production_secrets` fails startup hard when `DEBUG=False`.** It requires non-default
   `JWT_SECRET` and `API_KEY`, plus `ENCRYPTION_KEY` (a valid Fernet key), `SENSOR_KEY_HASH_PEPPER`
   and `CICD_GATE_SIGNING_SECRET`; forbids `STARTUP_BOOTSTRAP_SCHEMA` / demo bootstrap; forbids
   localhost in CORS origins; and demands a non-wildcard `PENTEST_TARGET_ALLOWLIST` with
   `PENTEST_RESOLVE_TARGET_HOSTS=true` and the target guard enabled. A prod config that "just won't
   boot" is almost always one of these.
2. **Background work is feature-flagged via `STARTUP_ENABLE_*`.** `_build_runtime_components()` in
   `main.py` assembles the scheduler, ingestion queue, analytics, archiver, warm exporter, endpoint
   lifecycle, recon, continuous testing, OpenAPI drift, stream pipeline, and Kafka consumer. A
   component that raises during start **aborts startup**. Add new background workers there, gated by
   their own flag.

Key mode flags: `UNIFIED_PIPELINE_MODE` (`off` | `shadow` | `active` — compose runs `shadow`),
`STREAM_ENGINE` (`IN_PROCESS` | `FLINK`), `PENTEST_SCAN_WORKER_ISOLATION_MODE`
(`background` | `kubernetes_job`).

Default `DATABASE_URL` is SQLite (`sqlite+aiosqlite:///./api_security.db`); compose/prod use
Postgres via `asyncpg`.

### Detection pipeline

`source adapters → NormalizationAgent → DetectionEnvelope → RuleDetectionAgent → DetectionSignal[]
→ CorrelationAgent → IncidentDecision → EnforcementAgent` (`docs/detection-engine/README.md`).
In `shadow` the unified pipeline observes only; in `active` it owns alerts, evidence, and
enforcement. Scoring weights (`DETECTION_*_WEIGHT`) are config, not code.

### Pentest safety model

Active scanning is guarded by `TargetGuard` (allowlist + private-IP and DNS-rebinding checks),
required auth profiles, per-mode concurrency caps (safe/balanced/aggressive), and worker isolation.
`DEBUG=true` alone does **not** fail open on private targets — tests and Playwright explicitly set
`PENTEST_ALLOW_PRIVATE_TARGETS=true` plus `PENTEST_TARGET_ALLOWLIST=127.0.0.1,localhost`. Keep that
explicit when adding scan tests.

### Frontend

Three workspaces behind `ProtectedRoute` in `src/App.tsx`, all lazy-loaded: `/app` (customer),
`/admin` (org admin), `/platform` (PLATFORM_ADMIN).

Data flow is strictly **pages → hooks (`src/hooks/use-*.ts`) → services (`src/services/*.service.ts`)
→ `src/lib/api-client.ts`**. Don't call `fetch` from a page.

`api-client.ts` sends `credentials: 'include'` (httpOnly cookie is the real session) with an
in-memory bearer token as fallback — nothing touches `localStorage`. Any 401 clears the token and
redirects to `/login`.

**Cross-file invariant:** `src/lib/realtime.ts` maps backend WS event types to React Query key
*namespaces* (`['dashboard']`, `['testing']`, `['protection']`, …). Its `WSEventType` union must stay
in sync with `server/api/websocket/event_types.py`, and new query keys must start with one of those
namespaces or the view will never refresh on live events. Global polling is deliberately off
(`refetchInterval: false`) — realtime invalidation replaces it.

UI has two layers: legacy `GlassCard` and the newer Evidence system (`src/components/ui/Evidence*.tsx`
scoped under `.evd-root` in `index.css`). Extend whichever the surrounding page already uses; don't
introduce a third visual language.

`vite.config.ts` `manualChunks` deliberately **does not split** recharts / d3 / react-simple-maps —
their circular imports become TDZ errors ("Cannot access 'S' before initialization") across chunk
boundaries. Leave that comment and behavior intact.

## CI gates

`.github/workflows/ci.yml` runs seven required jobs, aggregated by `ci-required`: backend unit,
integration (Postgres 16 + Redis 7 services), security (uploads SARIF to code scanning), CI/CD gate
accountability, backend E2E/API, frontend lint+test+build, and frontend Playwright E2E. Every job
asserts its junit/coverage artifact is non-empty — a passing test run that writes no evidence still
fails. The gate job additionally asserts the `strict` and `llm-strict` policy packs in
`server/modules/cicd/policy_packs.py` keep their required controls and `fail_on: CRITICAL,HIGH`.

## Conventions

- Keep routers thin; behavior belongs in `server/modules/<feature>/`. 4-space indent, type hints on
  new public functions, `snake_case` modules, `PascalCase` classes.
- React: TypeScript functional components, `PascalCase` component files, `camelCase` helpers.
- Backend tests are `test_*.py` under the matching `tests/` layer; UI unit tests under `src/test/`
  or beside the service; browser flows in `tests/e2e/`.
- Demo users (`admin@demo.sentinel` etc., seeded in `main.py`) exist only under
  `DEBUG=true` + `STARTUP_ENABLE_DEMO_BOOTSTRAP`. Never enable that flag outside local dev.
- Update `PROJECT_MEMORY.md` and `docs/PROJECT_END_TO_END.md` when topology or major contracts change.
