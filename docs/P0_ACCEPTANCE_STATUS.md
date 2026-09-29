# P0 Acceptance Status (2026-08-09)

Implementation against [`P0_RELEASE_BLOCKERS_TASK_LIST.md`](./P0_RELEASE_BLOCKERS_TASK_LIST.md).

## Checklist

| Gate | Status | Evidence |
|------|--------|----------|
| Production Safety Enforcement | Done | `DEBUG` no longer fails open private targets; auth/target/state errors redacted; allowlist + destructive-arming tests added |
| Isolated Scan Workers | Done | reclaim `SCAN_RUN_WORKER_LOST` audit; run timeout `SCAN_RUN_TIMED_OUT`; uncaught exception → `FAILED` + redacted context; kill-switch cooperative checks; audit filter by `resource_id`; CLI entrypoint for dedicated worker process |
| Real Multi-Engine Runtime | Done | Ready-engine missing-artifact quality gate covered in unit tests; scan-worker image packages Schemathesis/Nuclei/ZAP CLIs (`Dockerfile.scan-worker`) |
| Frontend lint/test/build/e2e | Done | lint 0 errors; Vitest 34 passed; Vite build ok; Playwright 2/2 passed after e2e private-target env fix |
| CI hardening | Done | CI triggers expanded; [`CI_REQUIRED_CHECKS.md`](./CI_REQUIRED_CHECKS.md) documents required GitHub checks; `ci-required` aggregator already present |

## Verification commands run

```text
pytest tests/unit/: 851 passed (+ scan_worker CLI tests added after packaging work)
pytest tests/integration/ + tests/security/: 333 passed
npm run lint: 0 errors (warnings only)
npm test: 34 passed
npm run build: success
npm run test:e2e: 2 passed
ci.yml: YAML parse ok
```

## Working branch

- Active implementation branch: `p0/production-ready` (cut from `codex/north-star-api-red-team-platform`)
- Commits on branch:
  - `7e59197` — Clear P0 release blockers for scan safety, workers, and CI gates
  - `c629380` — Add Evidence UI primitives and realtime query invalidation
  - (pending) scan-worker image packaging + worker CLI entrypoint
- Evidence UI components remain in the tree because committed Schema Validation imports them; full Evidence redesign is not a P0 deliverable but cannot be deleted without breaking that page.

## Scan-worker image

| Item | Location |
|------|----------|
| Dockerfile | [`Dockerfile.scan-worker`](../Dockerfile.scan-worker) |
| Python deps | [`requirements-scan-worker.txt`](../requirements-scan-worker.txt) |
| Build/push | [`infra/scripts/build-and-push-scan-worker.sh`](../infra/scripts/build-and-push-scan-worker.sh) |
| K8s example | [`infra/k8s/scan-worker-job.example.yaml`](../infra/k8s/scan-worker-job.example.yaml) |

```bash
export REGISTRY_IMAGE=registry.example.com/api-sentinel/scan-worker:v1
SKIP_PUSH=1 ./infra/scripts/build-and-push-scan-worker.sh
docker run --rm "$REGISTRY_IMAGE" engines
```

Pinned defaults: Nuclei `3.11.1`, ZAP `2.16.1`, Schemathesis `4.24.3`. Prefer `linux/amd64`.

Local image smoke (2026-08-09): `api-sentinel/scan-worker:local` → Schemathesis READY, Nuclei READY, ZAP READY (Java 21).

## Operator follow-up (cannot be done in-repo alone)

1. In GitHub branch protection, require the checks listed in `docs/CI_REQUIRED_CHECKS.md`.
2. Production deploy: set `DEBUG=False`, real secrets, `PENTEST_TARGET_ALLOWLIST`, keep `PENTEST_ALLOW_PRIVATE_TARGETS=False`.
3. Build/push `Dockerfile.scan-worker` to your registry and point `PENTEST_SCAN_WORKER_IMAGE` / Job specs at that tag.
4. Follow [`DEPLOY_PRODUCTION.md`](./DEPLOY_PRODUCTION.md) for server image build, env, Compose/Helm, and post-deploy checks.
