# Sprint 1 Plan — Reliable authenticated scanning, worker isolation, evidence contracts

**Date:** 2026-09-14. **Inputs:** the four-engineer plan, `NORTH_STAR_IMPLEMENTATION_STATUS.md` ("Still Required" 1–9), `docs/SHARED_CONTRACTS.md` (open decisions A–F).
**Release milestone (unchanged):** discovery → authenticated scan → evidence → ticket → fix → retest, running successfully in staging.

**Rules that apply to every item:** one owner per module; small tested PRs daily; done means a demonstration + regression tests + documented limitations; no readiness percentage anywhere; no new engines, no new ticket providers, no unrelated UI redesign.

## Days 1–2 (everyone)

| # | Item | Owner | Exit |
|---|---|---|---|
| D1 | Land `feat/queued-external-engine-worker` (blocked today on repo write permission for `vediyappanm05`) and stack `docs/shared-contracts` on top | Eng 4 | Both merged; `main` is the baseline |
| D2 | Resolve contract decisions **A** (`FAILED_WITH_FINDINGS` = success?) and **B** (retest outcome vocabulary) | Eng 1 + Eng 3 | Decision recorded in `SHARED_CONTRACTS.md`, tests updated |
| D3 | Staging fixtures: an owned target API (the benchmark target under `tests/benchmark/targets/` is the candidate), `TestAccount` rows for two regular users, one admin, and one account in a second tenant; `PENTEST_TARGET_ALLOWLIST` set | Eng 4 (env) + Eng 2 (identities) | Fixtures reachable from the staging worker |
| D4 | Agree the per-engine `normalized_evidence` → `finalize_finding_evidence` mapping (contracts §4/§5 boundary) | Eng 1 + Eng 3 | Mapping table added to `SHARED_CONTRACTS.md` §4 |

## Engineer 1 — Scanning Engine & Workers

Owns `server/modules/test_executor/`, scanner adapters, execution routes. Owns contracts §1, §2, §6.

| # | Deliverable | Where | Acceptance |
|---|---|---|---|
| E1.1 | Implement decision A in the phase rule and acceptance | `scan_worker.py:_execute_planned_external_engines`, `worker_validation.py` | Schemathesis run with failures completes the run and satisfies its required artifact; `SKIPPED` never does |
| E1.2 | Honor `CANCEL_REQUESTED` in the queued external phase (decision C); unify `timed_out`/`TIMEOUT` | `scan_worker.py:_run_external_with_lease` | Cancel during an in-flight Nuclei run terminates the subprocess within the wait window; test pins it |
| E1.3 | Route direct engine routes through the queue when `PENTEST_SCAN_EXECUTION_MODE=queued` | `server/api/routers/pentest.py` (direct Schemathesis/Nuclei/ZAP calls) | In queued mode no engine executes inside a request; direct routes return a `run_id` |
| E1.4 | Worker capability advertisement (Still Required #2, part) | claim/heartbeat path + execution artifact `worker_isolation` | Artifact records which engine binaries the executing worker actually had; API-host `runtime_available` marked advisory |
| E1.5 | First real scanner canary in staging | with Eng 4's staging | One authenticated queued run executes templates + ≥1 external engine end to end, producing same-run hash-verified artifacts; results logged in `docs/P0_ACCEPTANCE_STATUS.md` with limitations |
| E1.6 | Cancellation, lease expiry, retry, crash recovery, duplicate prevention verified | `tests/unit/test_scan_worker.py`, staging | Each §6 mechanism demonstrated once in staging; no duplicate findings across a re-claim |

## Engineer 2 — Authorization, Business Logic & LLM Testing

Owns `server/modules/identity/`, `business_logic/`, `llm/`, `agentic/`. Consumes §3, §4.

| # | Deliverable | Where | Acceptance |
|---|---|---|---|
| E2.1 | Identity selection excludes expired, disabled, or credential-less accounts | `orchestrator.py` (currently `status == "ACTIVE"` only), `identity/` | Expired/disabled fixtures are never selected; count reported in preflight matches |
| E2.2 | Authorization replay runs on ordinary scan paths (Still Required #4) | `engine_plan.py`, `scan_worker.py` dispatch, `identity/multi_identity_replay.py` | Against the deliberately vulnerable fixture: BOLA/BFLA confirmed with two regular users, admin, and cross-tenant; against the corrected fixture: no finding |
| E2.3 | Stateful business-flow executor skeleton (Still Required #5): setup → prerequisite → bounded mutation → cleanup | `business_logic/` | Coupon reuse and OTP throttling scenarios run end to end with cleanup verified; findings only via `finalize_finding_evidence` |
| E2.4 | LLM fixture harness interface + deterministic judge contract (execution in Sprint 2) | `llm/`, `agentic/` | Interface documented; a successful HTTP response alone can never produce `CONFIRMED` (§3) — test pins it |

## Engineer 3 — Evidence, Lifecycle & Product Experience

Owns vulnerability lifecycle, reporting, ticket integration, related frontend. Owns contracts §3, §4; co-owns decision A.

| # | Deliverable | Where | Acceptance |
|---|---|---|---|
| E3.1 | Decisions B and D: retest outcome vocabulary; closure-gate predicate pinned | `vulnerabilities.py`, `ticketing.py`, `lifecycle.py` | `SHARED_CONTRACTS.md` §3 states the predicate as a formula; tests enforce it |
| E3.2 | Promote external-engine results into findings, counters, and reports (Still Required #7) | new `promote_external_findings`, `scan_worker.py` counters, run report | A queued run with a Nuclei finding yields a `Vulnerability` with complete evidence (§4) and correct `total_tests`/`vulnerable_count` |
| E3.3 | One ticket provider end to end (create → sync → resolved → retest queued) | `ticketing.py`, `/ticket*` endpoints | Provider chosen on Day 1 (the one with the most complete adapter today); demonstrated in staging |
| E3.4 | Readiness UI shows measured facts only (Still Required #3) | `TestDashboard.tsx`, `ReleaseGovernance.tsx` | `assessment_scope=configuration_preflight` and `production_verified=false` rendered explicitly; no "ready" label without a staging-verified fact behind it |
| E3.5 | Finding lifecycle end to end: detect → ticket → remediation event → clean retest → closure; reopen on `STILL_VULNERABLE` | lifecycle + UI | Status consistent across list, detail, report, and ticket |

## Engineer 4 — DevSecOps, Isolation & Release Lead

Owns `infra/`, `k8s/`, CI workflows, deployment verification. Enforces all contracts; owns decision E.

| # | Deliverable | Where | Acceptance |
|---|---|---|---|
| E4.1 | Land the patch PR; branch protection requires `ci-required` | GitHub | `main` protected; team starts from the merged baseline |
| E4.2 | Contract enforcement tests: every "CI enforces" bullet in §1–§6 exists as a required test (many already do — inventory, then add the missing ones) | `tests/unit`, `tests/integration`, `tests/security` | Checklist in `docs/CI_REQUIRED_CHECKS.md` maps each bullet to a test id |
| E4.3 | SARIF/JUnit required, not optional (Still Required #8); actions pinned by SHA; scan-worker binaries checksum-verified (`Dockerfile.scan-worker`) | `.github/workflows/ci.yml`, `Dockerfile.scan-worker` | Missing SARIF fails the job; tampered binary checksum fails the build |
| E4.4 | Staging: Helm with `scanWorker.enabled=true` (digest-pinned image), `PENTEST_SCAN_EXECUTION_MODE=queued`, `TENANT_RLS_ENABLED=true`, owned target allowlisted, NetworkPolicy restricting worker egress to allowlisted targets | `infra/helm`, `k8s/` | E1.5 can run; cross-tenant negative tests pass with RLS on |
| E4.5 | Per-run Kubernetes Job isolation: design + `isolation_model` truthfulness (implementation Sprint 2) | `infra/k8s/scan-worker-job.example.yaml`, contracts §5 | Design reviewed; artifacts never claim `kubernetes_job` while running as the leased Deployment |
| E4.6 | Dependency and secret scanning gates; artifact retention decision (E) | CI, `SHARED_CONTRACTS.md` §5 | Gates required in `ci-required`; retention documented |

## Sprint 1 exit criterion

One authenticated, **queued** scan against the owned staging API executes templates plus at least one external engine end to end, produces same-run hash-verified artifacts, promotes at least one external finding into a `Vulnerability` with complete evidence, and cancel, kill-switch, and lease-expiry each behave as §6 specifies — demonstrated in staging, not in mocks. Limitations written down next to the demonstration.

## Parking lot (explicitly not Sprint 1)

- The frontend glass restyle held in the working tree (Outfit font, blue/teal theme, default dark). Eng 3 decides its fate after Sprint 1; the `tailwind.config.ts` move from hard-coded hex to CSS variables is worth landing on its own regardless.
- LLM live fixtures (Sprint 2), per-run Job isolation implementation (Sprint 2), additional ticket providers (never in this push).
