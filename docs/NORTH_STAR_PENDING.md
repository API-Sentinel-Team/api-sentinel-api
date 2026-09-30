# North Star Pending Tracker

**Purpose:** single live checklist of everything still required before the North Star
("evidence-grade continuous API red team") can be declared complete. Derived from
[`NORTH_STAR_GAP_ANALYSIS.md`](../NORTH_STAR_GAP_ANALYSIS.md),
[`NORTH_STAR_IMPLEMENTATION_STATUS.md`](../NORTH_STAR_IMPLEMENTATION_STATUS.md) (Still
Required 1–9), [`SHARED_CONTRACTS.md`](./SHARED_CONTRACTS.md) (open decisions A–F),
[`SPRINT_1_PLAN.md`](./SPRINT_1_PLAN.md), and the P0 task list.

**Status legend:** `TODO` · `IN PROGRESS` · `DONE` (code + tests) · `BLOCKED` (needs
cluster / registry / credentials / staging).

**Baseline:** branch `docs/shared-contracts`, HEAD `40fa4db`. Backend test suite:
1270 tests collect, `tests/unit/test_scan_worker.py` + CLI pass.

---

## Service split (2026-09-30) - what changed for the North Star

The backend is now six repos: `api-sentinel-core` (shared models, the only migrations, policy, scan
planning, template library), `api-sentinel-api` (queues scans, never executes), `api-sentinel-scan-worker`
(the only component that sends attack traffic), `api-sentinel-scheduler`, `api-sentinel-archiver`, and the
frontend. Many file paths in the tables below predate the split: shared code is now under
`sentinel_core/`, worker code under `sentinel_worker/`, scheduler under `sentinel_scheduler/`,
archiver under `sentinel_archiver/`; `server/` is the API only.

What the split does for the tracker:

- **P0-1 (queued mode)**: the API now *rejects* any mode other than `queued` and it is the default, so
  in-process scan execution can no longer happen by misconfiguration. Cluster activation and evidence
  are still required, so this stays BLOCKED.
- **P0-2 (deploy the worker)**: manifests now exist for the worker, scheduler and archiver
  (`k8s/32`, `34`, `36`; Helm `scan-worker`, `scheduler`, `archiver`), and `k8s/build-and-push.sh`
  builds each from its own repo. Images have not been built or deployed, so this stays BLOCKED.
- **HARD-2**: the scheduler/archiver/recon/continuous/drift loops moved out of the API into their own
  services. Before this change the k8s API pod ran the scheduler in-process; without the new
  `34-scheduler.yaml` Deployment, scheduled scans would silently stop. The archiver Deployment ships at
  `replicas: 0` because it deletes data past retention and archiving is intentionally staged.
- **Boundary enforcement** (new, tested in `tests/unit/test_service_boundaries.py`): core imports no
  service, services never import each other, only the API touches `server.api`.
- **Legacy `POST /api/nuclei/scan` retired**: the API no longer runs Nuclei itself; use the queued,
  profile-bound route. Its execution tests moved to `tests/unit/test_nuclei_engine.py`.

Not verified by the split work: Docker image builds, hosted CI runs (each repo needs a
`CORE_REPO_TOKEN` secret to read the private core repo), Helm rendering, and the cross-service tests in
`tests/cross_service/`.

---

## P0 — blocks the release milestone

| # | Item | Where | Owner | Sprint | Status |
|---|------|-------|-------|--------|--------|
| P0-1 | Activate `queued` execution mode in the real cluster (currently `background`) | `k8s/25-config.yaml` | Eng 4 | E4.4 | **BLOCKED (config queued; cluster activation/evidence required)** |
| P0-2 | Deploy the scan worker (no `k8s/` manifest; Helm `scanWorker.enabled=false`, empty image) | `k8s/`, `infra/helm` | Eng 4 | E4.4 | **BLOCKED (manifest/prep complete; image/cluster deployment required)** |
| P0-3 | Route direct Schemathesis/Nuclei/ZAP routes through the queue in `queued` mode; return a `run_id` | `server/api/routers/pentest.py` (`_enqueue_engine_run`) | Eng 1 | E1.3 | **DONE** |
| P0-4 | Honor `CANCEL_REQUESTED` in the queued external phase (**decision C**) | `scan_worker.py` | Eng 1 | E1.2 | **DONE** |
| P0-5 | `FAILED_WITH_FINDINGS` = success in phase rule + acceptance (**decision A**) | `engine_plan.py`, `scan_worker.py`, `worker_validation.py` | Eng 1 + 3 | E1.1 | **DONE** |
| P0-6 | First real staging CLI canary (auth expiry, cancel, failure recovery, artifact verification) | `P0_ACCEPTANCE_STATUS.md` | Eng 1 + 4 | E1.5 | BLOCKED |
| P0-7 | Truthful readiness from runtime probes + persisted facts (drop function/config-presence checks) | `orchestrator.py`, `worker_validation.py` | Eng 1 + 3 | E3.4 | **DONE (code; live evidence still required by gate)** |

## P0/P1 — worker isolation

| # | Item | Where | Owner | Sprint | Status |
|---|------|-------|-------|--------|--------|
| ISO-1 | Worker capability advertisement; `runtime_available` evaluated on API host is advisory only | claim/heartbeat, artifact `worker_isolation` | Eng 1 | E1.4 | **DONE (code/tests; live worker advertisement still required)** |
| ISO-2 | Per-run Kubernetes Job dispatch, network isolation, TTL, RBAC | `infra/k8s/scan-worker-job.example.yaml` | Eng 4 | E4.5 | **BLOCKED (manifest/prep exists; controller/cluster activation required)** |
| ISO-3 | Reconcile `values.yaml` (`kubernetes_job`) vs `scan-worker.yaml` (`leased_external_worker`) | `infra/helm` | Eng 4 | E4.5 | **DONE** (`values.yaml` now says `leased_external_worker` with a pointer to ISO-2) |

## P1 — coverage and lifecycle

| # | Item | Where | Owner | Sprint | Status |
|---|------|-------|-------|--------|--------|
| COV-1 | Identity selection excludes expired/disabled/credential-less accounts | `orchestrator.py`, `identity/` | Eng 2 | E2.1 | **DONE (code/tests)** |
| COV-2 | Automatic identity replay across ordinary scan paths; tenant + privilege matrices | `engine_plan.py`, `identity/multi_identity_replay.py` | Eng 2 | E2.2 | **DONE (code/tests; live two-identity evidence still required)** |
| COV-3 | Durable stateful business-flow execution (setup → mutation → cleanup, invariants) | `business_logic/` | Eng 2 | E2.3 | **IN PROGRESS (bounded lifecycle executor wired; concrete staging flows still required)** |
| COV-4 | Live LLM fixtures + deterministic judges (no 2xx-only confirmation) | `llm/`, `agentic/` | Eng 2 | E2.4 / Sprint 2 | **IN PROGRESS (deterministic templates/judges tested; live fixtures still required)** |
| LIFE-1 | Aggregate external-engine results into counters, reports, retest selection, ticket transitions (**SR #7**) | new `promote_external_findings`, `scan_worker.py` counters | Eng 3 | E3.2 | **DONE (code/tests; end-to-end provider proof still required)** |
| LIFE-2 | One ticket provider end to end (create → sync → resolved → retest queued) | `ticketing.py` | Eng 3 | E3.3 | **DONE (code/tests; live provider credentials still required)** |
| LIFE-3 | Finding lifecycle end to end; reopen on `STILL_VULNERABLE` | lifecycle + UI | Eng 3 | E3.5 | **DONE (code/tests; live provider/UI evidence still required)** |
| LIFE-4 | Retest outcome vocabulary (**decision B**) | `vulnerabilities.py`, `tests.py`, `lifecycle.py` | Eng 3 | E3.1 | **DONE** |
| LIFE-5 | Pin closure-gate `ready_for_closure` predicate (**decision D**) | `ticketing.py`, tests | Eng 3 | E3.1 | **DONE** |
| LIFE-6 | Per-engine `normalized_evidence` → `finalize_finding_evidence` mapping table | `docs/SHARED_CONTRACTS.md` §4 | Eng 1 + 3 | D4 | **DONE** |
| LIFE-7 | Tie identity readiness into `prepare` (`test_accounts_count`, role context) | `orchestrator.py:105-113, 423-448` | Eng 2 | E2.1 | **DONE (code/tests)** |

## P1 — reporting / CI / provenance

| # | Item | Where | Owner | Sprint | Status |
|---|------|-------|-------|--------|--------|
| CI-1 | Required schema-valid SARIF; retain JUnit + SARIF + manifests + artifacts together (**SR #8**) | `.github/workflows/ci.yml` | Eng 4 | E4.3 | **DONE (workflow; hosted-run evidence still required)** |
| CI-2 | Pin actions by SHA; verify scan-worker binary checksums (**SR #8**) | CI, `Dockerfile.scan-worker` | Eng 4 | E4.3 | **DONE (workflow; hosted-run evidence still required)** |
| CI-3 | Dependency + secret scanning gates | CI | Eng 4 | E4.6 | **DONE (workflow; hosted-run evidence still required)** |
| CI-4 | Map every "CI enforces" bullet in contracts §1–§6 to a required test | `docs/CI_REQUIRED_CHECKS.md` | Eng 4 | E4.2 | **DONE** |

## P1 — production hardening

| # | Item | Where | Owner | Sprint | Status |
|---|------|-------|-------|--------|--------|
| HARD-1 | Enable + validate tenant RLS; cross-tenant negative tests | `k8s/25-config.yaml` (`TENANT_RLS_ENABLED=true`) | Eng 4 | E4.4 | **BLOCKED (enabled in config; live DB/RLS negative evidence required)** |
| HARD-2 | Enable continuous testing, discovery, analytics, archiving, OpenAPI drift | `k8s/25-config.yaml:28-36` | Eng 4 | E4.4 | **BLOCKED (deployment flags remain intentionally staged; activation/evidence required)** |
| HARD-3 | NetworkPolicy restricting worker egress to allowlisted targets | `infra/k8s/` | Eng 4 | E4.4 | **DONE (manifest; CNI enforcement still requires staging proof)** |
| HARD-4 | Workload identity (IRSA), secret rotation, dashboards, retention, SLA, governance acceptance | infra + docs | Eng 4 | E4.6 | **BLOCKED (cloud/staging configuration and operational evidence required)** |
| HARD-5 | `PentestArtifact` retention/deletion policy (**decision E**) | contracts §5 | Eng 4 | E4.6 | **DONE (code/tests; live retention sweep still requires deployment proof)** |
| HARD-6 | `timed_out` vs `TIMEOUT` spelling; stale `TestRun.status` comment; legacy SLA statuses (**decision F**) | `scan_worker.py`, `core.py`, `lifecycle.py` | Eng 1 + 3 | Sprint 1 | **DONE** |

## Completion gate

| # | Item | Status |
|---|------|--------|
| GATE-1 | Staging canary proving: authenticated queued execution across all enabled engines; two-identity BOLA/BFLA; bounded business-flow + LLM probes; redacted reproducible evidence; deterministic judge + confirmatory retest; dedup/SLA/ticket transitions; valid SARIF/JUnit/report artifacts; tenant isolation; auditable kill-switch test | BLOCKED |

---

## Change log

- **2026-09-24** — Tracker created. Decisions **A** and **C** implemented with tests;
  recorded in `SHARED_CONTRACTS.md`.
- **2026-09-24** — **P0-3 done**: direct engine routes dispatch to the queue in
  `queued` mode (`_enqueue_engine_run`), never executing in-request. Decisions
  **B**, **D**, **F** implemented and pinned with tests; ISO-3 helm isolation-mode
  inconsistency reconciled. Decision **E** documented as pending Eng 4 sign-off.
- **2026-09-27** — Persisted runtime facts and worker capability advertisements are implemented and tested; COV-1/COV-2 identity eligibility/replay paths are complete in code; LIFE-1 external finding summaries/retest linkage and LIFE-6 evidence mappings are complete; CI-1/2/3 workflow gates and CI-4 traceability map are present; artifact retention now protects open-finding references and audits deletions. COV-3 has a bounded lifecycle executor wired into template execution but still needs concrete staging flow fixtures. Live worker, hosted-CI, and staging canary gates remain blocked until observed.
- **2026-09-27** — **LIFE-1 retest closure**: external-engine findings (`endpoint_id=None`) are now fully retestable through the queued worker. Retest prep resolves the endpoint from the evidence URL (unambiguous match required), queues an engine-only plan under the `EXTERNAL_ENGINE_RETEST` sentinel, and the worker finalizes the hashed remediation-retest outcome from verified engine artifacts — feeding the decision-B vocabulary and decision-D closure gate. `vulnerability_retest_support` no longer reports external findings as un-retestable. Retest contract documented in `SHARED_CONTRACTS.md` §4. Pinned by 3 new tests (worker executor, API queuing, endpoint-resolution rejection).
- **2026-09-27** — Regression verification: the four previously failing lifecycle/readiness cases pass; the integration suite reached 204 passing tests, with six Windows temp-directory ACL setup errors and one temp-file ACL failure isolated to the test host. Custom Nuclei template materialization now prefers the configured application-owned scan work directory, with a read-only deployment fallback. Remaining North Star blockers are explicitly deployment/provider/staging evidence gates, not unimplemented local test contracts.
