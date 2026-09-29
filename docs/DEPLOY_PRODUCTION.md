# Production Deploy Guide

Ship API Sentinel with fail-closed scan safety and an isolated scan-worker image that includes Schemathesis, Nuclei, and OWASP ZAP.

## 1. Prerequisites

- Docker 24+ (Compose v2) **or** Kubernetes + Helm 3
- Postgres 16, Redis 7, Kafka (Compose bundle includes these)
- Registry access to push API + scan-worker images
- Real secrets (never commit them): `JWT_SECRET`, `API_KEY`, `ENCRYPTION_KEY`, DB password

## 2. Configure production env

Copy [`.env.example`](../.env.example) → `.env` on the server and set at least:

| Variable | Production value |
|----------|------------------|
| `DEBUG` | `False` |
| `PENTEST_ALLOW_PRIVATE_TARGETS` | `False` |
| `PENTEST_TARGET_ALLOWLIST` | your owned API hosts |
| `PENTEST_SCAN_EXECUTION_MODE` | `queued` |
| `PENTEST_SCAN_WORKER_IMAGE` | your registry scan-worker tag |
| `CORS_ORIGINS_OVERRIDE` | your UI origin |
| `UNIFIED_PIPELINE_MODE` | `shadow` until enforcement is validated |

## 3. Build and push images

```bash
# API image
docker build -t registry.example.com/api-sentinel/api:v1 .
docker push registry.example.com/api-sentinel/api:v1

# Scan worker (Schemathesis + Nuclei + ZAP)
export REGISTRY_IMAGE=registry.example.com/api-sentinel/scan-worker:v1
./infra/scripts/build-and-push-scan-worker.sh
# Smoke engines without pushing:
# SKIP_PUSH=1 ./infra/scripts/build-and-push-scan-worker.sh
```

Prefer `linux/amd64` for the scan-worker (ZAP Linux package).

## 4A. Deploy with Docker Compose

```bash
# API + Postgres + Redis + Kafka
docker compose up --build -d

# Optional dedicated worker process
docker compose --profile scan-worker up --build -d

# Migrations run on API container start (alembic upgrade head)
curl -fsS http://localhost:8000/api/health/ready
```

Edge TLS: see [`infra/nginx/`](../infra/nginx/).

## 4B. Deploy with Helm (Kubernetes)

```bash
# Edit infra/helm/api-sentinel/values.yaml:
#   image.repository / image.tag
#   env.PENTEST_TARGET_ALLOWLIST
#   env.PENTEST_SCAN_WORKER_IMAGE
#   secrets.*  (use sealed-secrets / external-secrets in real prod)

helm upgrade --install api-sentinel ./infra/helm/api-sentinel \
  --namespace api-sentinel --create-namespace

# Apply example Job contract (replace image + secret refs first)
kubectl apply -f infra/k8s/scan-worker-job.example.yaml
```

Helm defaults already set `DEBUG=false` and fail-closed pentest flags.

## 5. Post-deploy checks

1. `GET /api/health/ready` returns healthy.
2. `GET /api/pentest/meta` shows worker queue health.
3. `docker run --rm $REGISTRY_IMAGE engines` → Schemathesis/Nuclei/ZAP READY.
4. Run a scoped allowlisted scan; confirm artifacts + audit events (`SCAN_RUN_CLAIMED`, `SCAN_RUN_COMPLETED`).
5. Confirm private/loopback targets are rejected unless explicitly allowlisted **and** `PENTEST_ALLOW_PRIVATE_TARGETS=true` (keep false in prod).

## 6. GitHub release gate

Require the checks listed in [`CI_REQUIRED_CHECKS.md`](./CI_REQUIRED_CHECKS.md) on `main` before merging further releases.

## 7. Rollback

- Compose: `docker compose pull && docker compose up -d` previous tags, or redeploy prior image digests.
- Helm: `helm rollback api-sentinel`.
- Keep DB migrations forward-only; restore from Postgres backup if a migration must be undone.
