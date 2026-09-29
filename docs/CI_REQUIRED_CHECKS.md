# CI Required Checks

This is the release traceability map for the `CI enforces` sections in
[`SHARED_CONTRACTS.md`](SHARED_CONTRACTS.md). A check is complete only when the
named test or validator runs in `.github/workflows/ci.yml`; staging-only claims
remain separate from CI proof.

| Contract | Required check | Authoritative verification | CI job |
|---|---|---|---|
| §1 Scan status | Seven-state vocabulary, terminal stickiness, cross-worker finalize, lease reclaim, dead-letter limits | `tests/unit/test_scan_worker.py`, `tests/unit/test_worker_validation.py`, `tests/integration/test_pentest_queued_dispatch.py` | `backend-unit`, `backend-integration`, `backend-ci-gates` |
| §2 Engine outcome | Plan vocabulary, scope rewrite, runner status derivation, `FAILED_WITH_FINDINGS` success, `SKIPPED` rejection | `tests/unit/test_pentest_builders.py`, `tests/unit/test_external_engine_runtime_readiness.py`, `tests/unit/test_scan_worker.py`, `tests/unit/test_worker_validation.py`, `tests/integration/test_cicd_gate.py` | `backend-ci-gates`, `backend-integration` |
| §3 Finding confirmation | Derived confirmation, 2xx-only remains unconfirmed, deduplication, false-positive coupling, clean retest closure gate | `tests/unit/test_vulnerability_lifecycle.py`, `tests/unit/test_vulnerability_ticketing.py`, `tests/integration/test_vulnerability_lifecycle_api.py` | `backend-unit`, `backend-integration`, `backend-ci-gates` |
| §4 Evidence | Completeness, hash integrity, redaction, LLM/business-logic minimization, single promotion path | `tests/unit/test_active_scan_evidence.py`, `tests/unit/test_llm_active_judge.py`, `tests/unit/test_cicd_quality_gate.py`, `tests/integration/test_cicd_gate.py` | `backend-unit`, `backend-ci-gates` |
| §5 Artifact ownership | Same-run artifact requirement, verified hashes, prepare-time exclusion, no secret persistence, worker isolation metadata | `tests/unit/test_pentest_execution_artifacts.py`, `tests/unit/test_worker_validation.py`, `tests/unit/test_scan_worker.py`, `tests/integration/test_cicd_gate.py` | `backend-unit`, `backend-ci-gates`, `backend-security` |
| §6 Cancellation | Terminal cancel no-op, kill switch, lease-loss abort, subprocess cancellation, canceled-run acceptance failure | `tests/unit/test_scan_worker.py`, `tests/unit/test_worker_validation.py`, `tests/integration/test_pentest_queued_dispatch.py` | `backend-unit`, `backend-integration`, `backend-ci-gates` |
| CI-1 | JUnit/SARIF presence, SARIF 2.1.0 structure, deployment manifests retained with evidence | Workflow `Validate SARIF structure`, `Verify * evidence` steps, artifact uploads | `backend-security`, all test jobs |
| CI-2 | Action SHA pins and scan-worker/gitleaks checksums | Pinned `uses:` references, checksum verification steps, `Dockerfile.scan-worker` checksum verification | `dependency-secret-scan`, `backend-security` |
| CI-3 | Dependency and secret scanning | `pip-audit --strict`, checksum-pinned Gitleaks scan | `dependency-secret-scan` |

## Evidence policy

CI proves code, schema, provenance, and artifact invariants. It does not prove a
live worker, registry image, Kubernetes CNI, external scanner binary, tenant RLS
deployment, or owned staging API. Those remain explicit staging/deployment
gates in `docs/NORTH_STAR_PENDING.md` and must not be marked complete from CI
alone.
