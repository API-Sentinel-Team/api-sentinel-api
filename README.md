# api-sentinel-api

The FastAPI service: authentication/RBAC, discovery, ingestion and detection, and the scan control plane. It **validates and queues** scans (target guard, auth scope, kill switch, budgets) but never executes one.

Part of API Sentinel. This repo contains **only this service's code**; everything shared
(database models, migrations, config, tenancy, audit, redaction, pentest policy, scan planning,
the security-test template library) lives in
[`api-sentinel-core`](https://github.com/API-Sentinel-Team/api-sentinel-core), installed as the
`sentinel-core` dependency and pinned to a released tag in `pyproject.toml`.

## Boundaries

- Never import another service's package. Services cooperate only through the database run
  queue and Redis pub/sub. `tests/unit/test_service_boundaries.py` enforces this in the
  api repo; the same rule holds here.
- Schema changes are made in `api-sentinel-core` (the single owner of migrations), never here.

## Run

```bash
uvicorn server.api.main:app --host 0.0.0.0 --port 8000
```

## Develop

```bash
pip install -e ../api-sentinel-core           # or the pinned tag from pyproject.toml
pip install --no-deps -e ".[test]"
DEBUG=true pytest -q
```

`DEBUG=true` is required by tests: without it `sentinel_core.config` refuses to build settings
(production validation).

## Cross-service tests

`tests/cross_service/` drive the API and then the scan-worker end to end, so they need the worker
installed too (`pip install --no-deps -e ../api-sentinel-scan-worker`). They are excluded from the
default CI run and run in the integration workflow.
