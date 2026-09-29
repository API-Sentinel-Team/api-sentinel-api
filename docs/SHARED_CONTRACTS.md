# Shared Contracts — Scan, Engine, Finding, Evidence, Artifact, Cancellation

**Status:** Draft for team agreement (Days 1–2). **Date:** 2026-09-14.
**Basis:** branch `feat/queued-external-engine-worker` (the landed North Star patch). Every statement below was read from code; file references are given so it can be checked. Where the code disagrees with itself, the item is marked **OPEN** and assigned — nothing here was decided by omission.

**Who agrees what:** Engineer 1 (scanning/workers) and Engineer 3 (evidence/lifecycle/UX) own the definitions. Engineer 2 (identity/business-logic/LLM) consumes 3–4. Engineer 4 (DevSecOps/release) turns the "CI enforces" bullets into required checks.

**Change control:** a contract change is a PR that touches (a) this file, (b) the code, and (c) the test that pins it. No silent drift.

## 0. Conventions that hold across all six

- Every persisted row is tenant-scoped by `account_id`; every query filters on it (`server/modules/auth/rbac.py`).
- Everything persisted passes `Redactor` (`server/modules/utils/redactor.py`). Raw request/response bodies, matched text, and secret values are never stored.
- Integrity is sha256 over canonical JSON (`sort_keys=True`, compact separators, `default=str`), with the hash fields themselves excluded from the digest.
- Casing is inconsistent today and is **kept as-is** to avoid churn: run and finding statuses are `UPPER_SNAKE`; engine-plan statuses, worker phase results, and reason codes are `lower_snake`. Do not add a third style.

---

## 1. Scan status (`TestRun.status`)

**Source:** `server/models/core.py:178` (`TestRun`), `server/modules/test_executor/scan_worker.py` (claim / heartbeat / fail / dead-letter), `server/api/routers/tests.py` (create / execute / cancel / finalize).

### States

| State | Meaning | Written by |
|---|---|---|
| `PENDING` | Created, not yet claimed | API (`run_scan`) |
| `DISPATCHED` | Claimed by a worker; lease + `started_at` set | Worker claim (`claim_next_pending_run`) |
| `RUNNING` | Worker began execution; `worker_heartbeat_at` set | Worker |
| `CANCEL_REQUESTED` | Operator asked to stop; not terminal | API `POST /api/tests/runs/{id}/cancel` |
| `COMPLETED` | Finished; counters final | Executor / worker |
| `FAILED` | Errored, timed out, dead-lettered, or claim budget exhausted | Executor / worker / dead-letter sweep |
| `CANCELED` | Stop honored | Executor / worker |

Terminal set: `{"COMPLETED", "FAILED", "CANCELED"}` (`tests.py:74`, `scan_worker.py:723`). Terminal is sticky — `_mark_claimed_run_failed` returns without writing if the run is already terminal.

> **OPEN (Engineer 1, trivial):** the model comment on `TestRun.status` still says `PENDING/RUNNING/COMPLETED/FAILED`. Update it to the seven states above.

### Fields that travel with the state

`worker_id`, `dispatch_lease_expires_at`, `worker_heartbeat_at`, `claim_count`, `started_at`, `completed_at`, `total_tests`, `vulnerable_count`, `error_count`. Terminal transitions set `completed_at` and clear `dispatch_lease_expires_at`; `FAILED` sets `error_count = max(1, error_count)`.

### Claim, lease, and re-claim (`_claimable_filter`, `scan_worker.py:561`)

A run is claimable when **any** of:
- `status == PENDING`; or
- `status == DISPATCHED` and (lease expired, **or** no lease and `started_at` is null or older than the lease window); or
- `status == RUNNING` and `worker_id` is set and lease expired.

Claiming sets `DISPATCHED`, `worker_id`, `started_at`, the lease, and increments `claim_count`. Config: `PENTEST_SCAN_DISPATCH_LEASE_SECONDS = 900`, `PENTEST_SCAN_MAX_CLAIMS = 3`, `PENTEST_SCAN_WORKER_TIMEOUT_SECONDS = 0` (= use the lease as the run budget; the lease is always the upper bound).

Heartbeat (`heartbeat_claimed_run`) renews the lease **only** if the same `worker_id` holds it, status ∈ {`DISPATCHED`, `RUNNING`}, and the lease has not already expired. A failed heartbeat means `worker_claim_lost`: the worker aborts **without** writing a terminal state (another worker may now own the run).

Dead-letter (`_dead_letter_exhausted_claims`): claimable runs with `claim_count >= PENTEST_SCAN_MAX_CLAIMS` → `FAILED`, reason `worker_claim_limit_exceeded`, audit `SCAN_RUN_DEAD_LETTERED`; retest-triggered runs also get a retest outcome recorded (§3).

### Invariants

1. Only the claiming worker (`worker_id` match) may move a run to a terminal state.
2. A terminal state is never overwritten.
3. `CANCEL_REQUESTED` is only reachable from a non-terminal state; cancelling a terminal run returns `not_cancelled` and changes nothing.
4. Every status change is audited (`SCAN_RUN_FAILED`, `SCAN_RUN_DEAD_LETTERED`, `SCAN_CANCEL_REQUESTED`, …).

### CI enforces (Engineer 4)

- The seven-state vocabulary and terminal set (pin `_TERMINAL_RUN_STATUSES`).
- Re-claim rule: expired-lease `RUNNING` run is claimable by a different worker; same-worker heartbeat after expiry fails.
- Dead-letter at `PENTEST_SCAN_MAX_CLAIMS`.
- No terminal overwrite; no cross-worker finalize.

---

## 2. Engine outcome

Two layers: **plan-time** (can this engine run?) and **run-time** (what happened when it ran?).

### 2a. Plan-time — engine plan entry (`server/modules/pentest/engine_plan.py`)

Order: `ENGINE_EXECUTION_ORDER = ("templates", "authorization_replay", "schemathesis", "nuclei", "zap", "passive")`.

Entry shape:

```json
{
  "engine": "schemathesis",
  "display_name": "Schemathesis OpenAPI Fuzzing",
  "enabled": true,
  "status": "ready | blocked | disabled | available",
  "reason": "<reason code>",
  "requires_auth_profile": true,
  "requires_openapi_spec": true,
  "artifact_type": "schemathesis",
  "runtime_available": true
}
```

Status rule (`_engine_entry`): `disabled` if the profile disables it (`disabled_by_profile`) → `blocked` if a requirement is missing (`missing_openapi_spec`, `auth_profile_missing_or_inactive`, `auth_profile_missing_runtime_credentials`, `auth_profile_required`, `requires_two_test_accounts`) → `blocked` if the runtime is absent (`engine_runtime_unavailable`) → else `ready` (`requirements_satisfied`, `template_engine_available`, `identity_matrix_ready`). `passive` is always `available` (`continuous_ingestion_pipeline`).

Added by the API when a queued run has no external binding: `schemathesis|nuclei|zap` entries that were `ready` become `blocked` with reason `external_engine_scope_required` (`tests.py:_build_scan_plan_for_run`).

`runtime_available` is currently evaluated **on the API host** (`_scan_engine_runtime_availability`). Worker capability advertisement is Still Required #2 — until then this field can be wrong for the worker that actually runs the engine.

### 2b. Run-time — runner result (`nuclei/runner.py`, `zap/runner.py`, `pentest/schemathesis_runner.py`)

```json
{
  "status": "COMPLETED | FAILED_WITH_FINDINGS | FAILED | TIMEOUT | SKIPPED | RUNTIME_UNAVAILABLE",
  "exit_code": 0,
  "command": "<redacted argv or string>",
  "stdout": "<redacted>", "stderr": "<redacted>",
  "env_var_names": ["..."],
  "state_change_policy": {"...": "..."},
  "worker_isolation_enforcement": {"...": "..."},
  "findings": [...]            // nuclei
  "report": {...}, "alerts": 0 // zap
  "junit_xml": "...", "failures": 0 // schemathesis
}
```

Status rule (identical in all three): exit 0 → `COMPLETED`; exit ≠ 0 with findings/alerts/failures → `FAILED_WITH_FINDINGS`; exit ≠ 0 without → `FAILED`; `TIMEOUT` on wall-clock; `SKIPPED` when a prerequisite (spec, config, credentials) is absent; `RUNTIME_UNAVAILABLE` when the binary is missing (nuclei). The worker wraps its own budget expiry as `{"status": "timed_out"}` (lower-case, `scan_worker.py:2118`).

### 2c. Run-time — worker external phase result (`_execute_planned_external_engines`)

```json
{
  "status": "completed | failed",
  "engines": [{"engine": "nuclei", "status": "COMPLETED", "artifact_id": "...", "artifact_type": "nuclei_execution", "artifact_hash": "..."}],
  "engine_count": 1,
  "reason": "<only when short-circuited>"
}
```

Rule as implemented: engines run in `ENGINE_EXECUTION_ORDER`; after each, if the runner status is **not** in `SUCCESSFUL_ENGINE_EXECUTION_STATUSES = {COMPLETED, FAILED_WITH_FINDINGS}` (`engine_plan.py`) the loop **breaks**, the phase is `failed`, and the primary (template) phase is **not run** (decision A below). Pre-flight rejections raise with these reason codes: `worker_openapi_spec_invalid`, `worker_endpoint_outside_target`, `worker_endpoint_outside_base_path`, `worker_spec_has_no_selected_operations`, `worker_external_spec_reference_blocked`, `worker_scan_plan_integrity_failed`, `worker_endpoints_missing`, `worker_external_target_binding_missing`, `worker_external_target_scope_mismatch`, `worker_pentest_profile_missing`, `worker_external_auth_profile_required`, `worker_openapi_spec_changed`, `worker_openapi_spec_missing`, `worker_nuclei_requires_explicit_method_arming`, `worker_claim_lost`, `invalid_engine_result`, `no_external_engines_ready`.

> **RESOLVED — decision A (Engineers 1 + 3).** Success = `{COMPLETED, FAILED_WITH_FINDINGS}` for the phase rule **and** artifact acceptance (§5). `FAILED | TIMEOUT | RUNTIME_UNAVAILABLE | timed_out` fail the phase; `SKIPPED` neither fails the phase nor satisfies a required artifact. Pinned by `SUCCESSFUL_ENGINE_EXECUTION_STATUSES` / `engine_execution_succeeded` in `server/modules/pentest/engine_plan.py`, consumed by `scan_worker._execute_planned_external_engines` and `worker_validation.validate_worker_staging_scan_acceptance`. Tests: `test_external_findings_status_completes_phase` (worker) and the `FAILED_WITH_FINDINGS`/`TIMEOUT`/`SKIPPED` cases in `test_worker_validation.py`.

> **RESOLVED (decision F, Eng 1):** the worker's budget expiry now emits `TIMEOUT` (upper-snake), matching the runner vocabulary; previously lower-snake `timed_out`. The worker *envelope* status keeps its own lower-snake flow outcomes (`executed`/`failed`/`aborted`/`canceled`) per §0; only the engine-level spelling was unified. Test: `test_run_pending_scan_once_times_out_and_audits`.

### CI enforces (Engineer 4)

- Engine plan status vocabulary and the `external_engine_scope_required` rewrite.
- Runner status derivation from exit code + findings (fixture per engine).
- Phase rule per the decision above, including "`SKIPPED` never satisfies a required engine".

---

## 3. Finding confirmation

**Source:** `server/models/core.py:152` (`Vulnerability`), `server/modules/vulnerability_detector/lifecycle.py`, `store.py`, `ticketing.py`, `server/api/routers/vulnerabilities.py`.

### Finding status (`Vulnerability.status`)

Allowed: `OPEN | TRIAGED | IN_REMEDIATION | ACCEPTED_RISK | CLOSED` (`_ALLOWED_VULNERABILITY_STATUSES`). `false_positive=true` forces `CLOSED`; clearing it on a `CLOSED` finding reopens to `OPEN`.

> **RESOLVED (decision F, partial):** `SLA_STOPPED_STATUSES` keeps `RESOLVED`, `FALSE_POSITIVE`, `FALSE-POSITIVE` as documented legacy data values tolerated for existing rows; a comment in `lifecycle.py` states this. The stale `TestRun.status` model comment now lists the seven-state vocabulary.

### Confirmation status — **derived, never set**

`CONFIRMED | DISPROVEN | UNCONFIRMED`, computed by `confirmation_status_from_evidence` in this precedence:
1. `evidence.confirmation.confirmed` (bool) — set only by a confirmatory retest / authorization replay.
2. `evidence.finding_status == "CONFIRMED" | "DISPROVEN"`.
3. Latest `occurrences[i].confirmation_status` / `confirmed`.
4. Nested `evidence.value`.
5. Legacy text markers `confirmatory_retest=passed|failed`.

No endpoint writes confirmation. `/status`, `/false-positive`, `/bulk-status` change `status` only; `confirmation_status` is filter-only. **This is the rule from the plan: a 2xx response alone is never a vulnerability; only reproduced evidence confirms.**

### Confidence (`vulnerability_confidence_from_evidence`)

`DISPROVEN → LOW`; evidence hash not verified → `LOW`; `CONFIRMED → HIGH`; otherwise `MEDIUM`.

### Deduplication (`store.create_or_merge_vulnerability`)

Candidates are matched within the account on `template_id`, `endpoint_id`, `method`, `type`, `url`, then compared by `fingerprint` (`vulnerability_fingerprint`, transient keys stripped). A match merges: `occurrence_count += 1`, an occurrence is appended (last 10 kept), `lifecycle.last_seen_at` updates, evidence hash re-computed. A confirmed, non-false-positive finding raises its endpoint's risk score (`endpoint_risk.py`).

### Retest

- Trigger sources: `vulnerability_retest`, `vulnerability_auto_retest`, `vulnerability_fix_event`, `vulnerability_ticket_sync` (`VULNERABILITY_RETEST_TRIGGER_SOURCES`). A run with such a `trigger_source` and `source_vulnerability_id` reports its outcome into the finding.
- Active retest run statuses: `PENDING | DISPATCHED | RUNNING | CANCEL_REQUESTED`.
- Outcome vocabulary via `POST /api/vulnerabilities/{id}/retest/outcome`: normalized to **`CLEAN`** (accepts clean/fixed/passed) or **`STILL_VULNERABLE`** (accepts still_vulnerable/vulnerable/failed); anything else is 400. Counts: `executed`, `vulnerable`, `errors`, `skipped`; optional `run_id`, `reason`.
- Each retest entry is hashed: `retest_hash = sha256(entry − {retest_hash, hash_algorithm})` and verified per entry (`_verify_retest_evidence`: `VERIFIED | MISMATCH | MISSING_HASH | UNSUPPORTED_HASH | NOT_STRUCTURED`).

> **RESOLVED — decision B (Engineer 3).** The stored vocabulary is the five-value set `REMEDIATION_RETEST_OUTCOMES = {CLEAN, STILL_VULNERABLE, FAILED, CANCELED, NO_EXECUTION}` in `lifecycle.py`. The retest outcome endpoint accepts synonyms (clean/fixed/passed → CLEAN; still_vulnerable/vulnerable → STILL_VULNERABLE) and now also admits the non-executed outcomes FAILED / CANCELED / NO_EXECUTION. A non-executed outcome never changes the finding status (previously the endpoint's else-branch **closed** the finding on any non-STILL_VULNERABLE outcome — a FAILED retest could close a vulnerability) and never passes the closure gate, which treats only CLEAN as passing (`latest_retest_clean = outcome == "CLEAN"`).

### Remediation events

`POST /{id}/remediation-event` with `event_type ∈ {FIX_DEPLOYED, TICKET_RESOLVED, PULL_REQUEST_MERGED, CI_DEPLOYED, MANUAL_FIX}` records the event, moves the finding to `IN_REMEDIATION`, and queues a scoped retest. Ticket sync maps provider states: resolved ∈ `{DONE, RESOLVED, CLOSED, COMPLETE, COMPLETED}`, in-progress ∈ `{IN_PROGRESS, IN PROGRESS, REMEDIATING, REMEDIATION}`.

### Closure gate (`ticketing.py:evidence_closure_gate` / `vulnerability_closure_gate`)

Closing (status → `CLOSED`, and ticket-sync closure) runs `_enforce_closure_gate`; if `ready_for_closure` is not `true` the API returns 400 `closure_gate_blocked` with `blockers`. The gate's inputs are: `confirmation_status`, evidence-integrity verification, the latest remediation retest's `outcome`, and that retest's hash verification. The message contract is: *"Vulnerability closure requires verified evidence and a clean confirmatory retest."*

> **RESOLVED — decision D (Engineer 3).** The closure-gate predicate is pinned in `tests/unit/test_vulnerability_ticketing.py::test_closure_gate_predicate_is_ready_only_when_every_input_holds` and `::test_closure_gate_requires_clean_retest_and_verified_hash`. As a formula: `ready_for_closure = confirmed AND evidence_integrity_verified AND evidence_complete AND evidence_reproducible AND scope_validated AND latest_retest_clean AND latest_retest_integrity_verified`, where `confirmed = (confirmation_status_from_evidence == CONFIRMED)` (precedence per §3: explicit `confirmation.confirmed` beats `finding_status`), `latest_retest_clean = (latest retest outcome == "CLEAN")`, and `latest_retest_integrity_verified` = the matching retest entry's hash verifies.

### CI enforces (Engineer 4)

- Status allowlist; false-positive ↔ `CLOSED` coupling.
- Confirmation is derived only (no request can set it).
- A finding with only a 2xx observation and no `confirmation` stays `UNCONFIRMED` / `MEDIUM` at best.
- Closure blocked without a verified `CLEAN` retest; retest hash mismatch blocks.
- Dedupe: same fingerprint merges, different fingerprint creates.

---

## 4. Evidence format

**Source:** `server/modules/test_executor/evidence.py` (`build_active_scan_evidence` for templates; `finalize_finding_evidence` — the shared contract every other engine must go through), `lifecycle.py` (`evidence_with_lifecycle`, `verify_vulnerability_evidence`).

### Required shape (what `evidence_completeness` checks)

`_EVIDENCE_COMPLETENESS_FIELDS = [status, matched_rule, sent_request, received_response, similarity, reproduction, remediation]`; `evidence_completeness = {complete, required, present, missing}`.

```json
{
  "engine": "template | authorization_replay | schemathesis | nuclei | zap | passive | ...",
  "template_id": "...",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "finding_status": "UNCONFIRMED | CONFIRMED | DISPROVEN",
  "endpoint": {"id": "...", "method": "GET", "url": "<redacted>"},
  "sent_request": {"method": "GET", "url": "<redacted>", "headers": {"<sorted>": "<redacted>"}, "body": "<absent for LLM/business-logic>"},
  "received_response": {"status_code": 200, "headers": {}, "body": "<redacted or absent>"},
  "matched_rule": {...}, "similarity": {...},
  "reproduction": {"curl": "<redacted curl>"},
  "remediation": "...",
  "retest_support": {...},
  "safety_policies": {...}, "scope_validation": {"validated": true},
  "confirmation": {"confirmed": true, "...": "..."},
  "observation": "<redacted>", "results": [], "context": [],
  "security_category": "...", "business_logic_scenario": {...},
  "llm_judge_validation": {...},
  "content_minimization": {...},
  "evidence_reproducibility": {...},
  "hash_algorithm": "sha256",
  "evidence_hash": "<sha256>"
}
```

`received_response` counts as present when `status_code > 0`, else when `body` is non-empty, else (non-HTTP shapes such as passive PII or business-logic transitions) when any value is non-empty (`_has_received_response`).

### Integrity

`evidence_hash = sha256(evidence − _ACTIVE_EVIDENCE_DIGEST_IGNORED_KEYS)`; the ignored set includes `evidence_hash, hash_algorithm, lifecycle, occurrences, remediation_retests, latest_remediation_retest` (see the constant for the full list — mutable lifecycle metadata is deliberately outside the hash). `verify_vulnerability_evidence` → `{verified, checked_count, failed_count, missing_count, finding_evidence, remediation_retests[]}`; `verified` iff at least one hash checked, none mismatched, none missing.

### Minimization and reproducibility (stored alongside)

`content_minimization = {raw_request_body_persisted: false, raw_response_body_persisted: false, matched_text_persisted: false, secret_values_persisted: false, body_content_persisted: <bool>, business_logic_scenario_content_persisted, details_content_persisted: true, persisted_material: [...]}`.
`evidence_reproducibility = {redaction_policy: "api_sentinel_redactor", raw_payload_persisted: false, deterministic_hash: true, hash_algorithm, reproduction_available, scope_validated, evidence_complete}`.

Rules: LLM-judge and business-logic findings drop both request and response bodies before persisting. Everything else passes `Redactor.redact_http_message` / `redact_url` / `redact_text`.

### Lifecycle additions (on persist / merge)

`lifecycle = {fingerprint, first_seen_at, last_seen_at, occurrence_count, sla_due_at}`; `occurrences[≤10] = {seen_at, engine, template_id, evidence_hash, source_fingerprint, result_count, confirmed, confirmation_status, safety_policies?}`; `remediation_retests[] = {run_id, outcome, retest_hash, hash_algorithm, …}`. SLA days: CRITICAL 1, HIGH 7, MEDIUM 30, LOW 90, INFO 180.

### Boundary with external engines

Engineer 1 produces the execution artifact (§5) whose `normalized_evidence` is engine-specific. Engineer 3 promotes findings to `Vulnerability` **only** through `finalize_finding_evidence`, so every promoted finding satisfies this contract. Still Required #7 (aggregate external results into findings/counters/reports) lives on this boundary — agree the `normalized_evidence` → `finalize_finding_evidence(...)` mapping per engine in Sprint 1.

#### Per-engine evidence mapping (LIFE-6)

| Engine | `normalized_evidence` source | `finalize_finding_evidence` mapping | Promotion / retest identity |
|---|---|---|---|
| `templates` | `build_active_scan_evidence` from the redacted template result | Template evidence is already complete; the shared finalizer remains the contract for any non-template promotion | `template_id` + endpoint + vulnerability fingerprint |
| `schemathesis` | `server/modules/schemathesis/findings.py` parses JUnit failure/error records into `failure`, `testcase`, and extracted HTTP request/response data | `method`/`url` from the failure record; `matched_rule={check, kind, type}`; response status/body from the failure block; similarity source `schemathesis_check`; remediation from the OpenAPI failure class | `schemathesis-{check_name}` + source fingerprint; remediation retests use the resulting vulnerability id |
| `nuclei` | `server/modules/nuclei/findings.py` normalizes each finding, matcher metadata, request/curl data, response status/body, and scope validation | `method`/`url` from the finding; `matched_rule={template_id, name, severity}`; response from status/response fields; similarity source `nuclei_matcher`; remediation from template info/reference | `NUCLEI:{template_id}` + Nuclei source fingerprint; remediation retests use the resulting vulnerability id |
| `zap` | `server/modules/zap/findings.py` normalizes alert and alert-instance data, including plugin, URL, method, confidence, and response evidence | `method`/`url` from the alert instance; `matched_rule={plugin_id, name, risk}`; response from status/header/evidence fields; similarity source `zap_confidence`; remediation from solution/reference | `ZAP:{plugin_id}` + ZAP source fingerprint; remediation retests use the resulting vulnerability id |

All external-engine rows must remain redacted, scope-validated, hashable, and `UNCONFIRMED` until a deterministic confirmation or authorization replay changes the finding state. The worker reports the promoted vulnerability ids and created/merged/normalized counts in `execution.finding_summary` so reports and retest selection can trace results back to the originating engine.

#### External-engine retest contract (LIFE-1, implemented)

Remediation retests for external-engine findings run through the queued worker, mirroring the authorization-replay pattern:

1. **Queuing.** `POST /api/vulnerabilities/{id}/retest` detects an external-engine finding (`evidence.engine` ∈ {schemathesis, nuclei, zap} or the engine-specific `template_id` prefixes). The finding's `endpoint_id` is resolved by matching the evidence URL (scheme+host+path) against inventory — zero or multiple matches is a 400 (`retest_external_engine_endpoint_not_found` / `..._ambiguous`), never a guess. The run carries the sentinel `template_id` `EXTERNAL_ENGINE_RETEST` and an engine-only scan plan (`selection_mode: external_engine_retest`) whose ready entry uses reason `retest_external_engine` and binds `external_engine_scope` (target URL + spec hash).
2. **Execution.** The worker's external phase runs the producing engine with the same auth preflight, scope guard, and lease/cancel checks as any queued run. The templates phase never executes (`_claimed_run_requests_external_engine_retest` short-circuits it).
3. **Lifecycle.** The retest executor (`_execute_external_engine_retest_claimed_run`) derives counters from hash-verified engine artifacts (verified artifact = executed check; promoted findings = still-vulnerable observations) and records the hashed remediation-retest outcome via the shared finalizer — so decision B's outcome vocabulary and decision D's closure gate apply unchanged. Failure/timeout/cancel record `FAILED`/`TIMEOUT`/`CANCELED` through the generic terminal handlers.

### CI enforces (Engineer 4)

- Completeness fields; hash excludes lifecycle keys; hash verifies after merge.
- No raw bodies for LLM/business-logic findings; `secret_values_persisted` always false.
- `finalize_finding_evidence` is the only promotion path (grep-guard or test).

---

## 5. Artifact ownership

**Source:** `server/models/core.py:137` (`PentestArtifact`), `server/modules/pentest/execution_artifacts.py`, `scan_worker.py:_worker_engine_accountability`, `worker_validation.py:validate_worker_staging_scan_acceptance`, consumers in `server/api/routers/cicd.py`.

`PentestArtifact = {id, account_id, run_id, pentest_profile_id, artifact_type, filename, content_text | content_json, created_at}`.

### Two families

| Family | Produced by | `artifact_type` | Notes |
|---|---|---|---|
| **Prepare-time** | Orchestrator (`PentestOrchestrator.prepare`, `persist=True`) | from the engine plan: `schemathesis`, `nuclei_secret_file`, `zap_plan`, plus run summaries | Stored via `storage_safe_artifact_payload` — secret files never persist raw secrets. Labelled `configuration_preflight`, `production_verified=false`. |
| **Execution** | The worker holding the claim (`worker_id`) | `templates_execution`, `schemathesis_execution`, `nuclei_execution`, `zap_execution`, `passive_findings` (`_ENGINE_EXECUTION_ARTIFACT_TYPES`); filename `{engine}-execution.json` | One per engine per run. Hash-verified. |

### Execution artifact payload (`build_execution_artifact_payload`)

```json
{
  "engine": "nuclei", "target_url": "<redacted>", "target_scope_validation": {...},
  "auth_context": {"<safe subset>": "..."}, "pentest_profile_id": "...", "openapi_spec_id": "...",
  "run_id": "...", "execution_id": "...",
  "status": "<runner status>", "execution": {"<redacted runner result>": "..."}, "findings": {...},
  "normalized_evidence": {...}, "scan_plan_provenance": {...}, "context_aware_selection": {...},
  "engine_plan": [...], "multi_engine_orchestration": {...},
  "worker_isolation": {"isolation_model": "leased_external_worker | kubernetes_job | background", "...": "..."},
  "content_redacted": true, "secret_values_persisted": false,
  "hash_algorithm": "sha256", "artifact_hash": "<sha256>",
  "artifact_verification": {"verified": true, "status": "VERIFIED | MISMATCH | MISSING", "expected_hash": "...", "actual_hash": "...", "covered_fields": [...]}
}
```

`artifact_hash = sha256(payload − {artifact_hash, hash_algorithm, artifact_verification})`.

### Ownership and accountability rules

1. **Producer:** only the worker whose `worker_id` holds the claim writes `{engine}_execution` for that `run_id`. Prepare-time artifacts belong to the API/orchestrator and never satisfy execution requirements.
2. **Required set:** `required_artifacts = [{engine, artifact_type, hash_required: true, verification_required: true}]` for every engine that is `ready` in the run's scan plan (`_worker_engine_accountability`). Engines the worker did not execute itself appear in `planned_external_artifacts` with `produced_by_this_worker: false`.
3. **Acceptance** (`validate_worker_staging_scan_acceptance`): for every required `artifact_type` there must be an artifact with the **same `run_id`**, `status` in `SUCCESSFUL_ENGINE_EXECUTION_STATUSES` (`{COMPLETED, FAILED_WITH_FINDINGS}` — decision A), and `artifact_verification.verified == true`. Missing, `SKIPPED`, failed, or cross-run artifacts do not count → blocker `required_engine_artifact_missing`.
4. **Consumers:** the CI gate (`cicd.py:_engine_accountability_required_artifacts`) and reports read `required_artifacts` and verify hashes; they never recompute outcomes from stdout.
5. **Truthfulness of `worker_isolation`:** Engineer 4 owns that `isolation_model` reflects the actual deployment (`leased_external_worker` for the Helm Deployment; `kubernetes_job` only once per-run Jobs exist — Still Required #2).

> **RESOLVED (decision E):** execution and prepare-time artifacts inherit the tenant retention policy of the account that produced them. The retention sweep deletes only expired, unreferenced artifacts; artifacts referenced by a non-terminal vulnerability's evidence are retained until the finding reaches a terminal state. Every deletion emits `ARTIFACT_DELETED` with a redacted artifact id/type and retention reason. Implementation: `server/modules/pentest/artifact_retention.py`, invoked by the archive processor. Manual deletion remains permission-gated by the artifact API; the sweep is the only automated deletion path.

### CI enforces (Engineer 4)

- Hash round-trip; tamper → `MISMATCH`; missing → `MISSING`.
- Same-run requirement; a `SKIPPED`/failed/cross-run artifact never satisfies `required_artifacts`.
- Prepare-time artifacts cannot satisfy execution requirements.
- No secret material in any persisted artifact (fixture with a known token; assert absent).

---

## 6. Cancellation behavior

**Source:** `tests.py` (`cancel_run`, `_scan_should_stop`, `_scan_cancel_requested`), `scan_worker.py` (`run_pending_scan_once`, `_run_external_with_lease`, `heartbeat_claimed_run`, `_claimable_filter`), `kill_switch.py`, the three runners.

### Mechanisms

| Mechanism | Trigger | Effect |
|---|---|---|
| **Operator cancel** | `POST /api/tests/runs/{id}/cancel` | Non-terminal run → `CANCEL_REQUESTED` (audited). Terminal → `not_cancelled`, no change. |
| **Kill switch** | `PENTEST_KILL_SWITCH_ENABLED=true` | Worker refuses to claim (`{"status": "paused", "reason": "pentest_kill_switch_enabled"}`); in-flight loops call `ensure_pentest_not_killed()` and raise `PentestKillSwitchError`. |
| **Lease loss** | Heartbeat fails (lease expired or another worker claimed) | `worker_claim_lost`: abort locally, **no terminal write**; the run is claimable again (§1). |
| **Timeout** | Runner wall-clock (`TIMEOUT`) or worker budget (`timed_out`) | Subprocess killed; engine result recorded as failed. |
| **Task cancellation** | asyncio cancellation of the engine task | Runners catch `CancelledError`, kill the subprocess, drain, re-raise. |

### Where a stop is honored

- **Router / background execution:** `_scan_should_stop` (kill switch **or** `CANCEL_REQUESTED`) is checked between units of work; on stop the run becomes `CANCELED`, `completed_at` set, lease cleared, and — for retest-triggered runs — a retest outcome `CANCELED` with `{reason, processed, executed, …}` is recorded (§3).
- **Queued worker, external phase:** `_run_external_with_lease` wakes every `min(5, lease/3)` seconds to (a) `ensure_pentest_not_killed()` and (b) heartbeat; either failure cancels the engine task (`finally: task.cancel()`), which kills the subprocess.

> **RESOLVED — decision C (Engineer 1).** The queued external phase now polls for an operator cancel on every wake (`_claimed_run_cancel_requested` in `scan_worker.py`). Cancel is checked **before** the heartbeat in both `_run_external_with_lease` and `_assert_claim_live`, because an operator cancel sets the run to `CANCEL_REQUESTED`, which the heartbeat's status filter rejects. On cancel the engine task is cancelled (killing the subprocess), the worker raises `ScanCancelRequestedError`, and `run_pending_scan_once` finalizes the run as `CANCELED` (audit `SCAN_RUN_CANCELED`, lease cleared, retest outcome `CANCELED` via `_record_terminal_retest_outcome`). Tests: `test_queued_external_phase_honors_cancel_requested`, `test_run_pending_scan_once_finalizes_canceled_run`.

### Guarantees (to be enforced)

1. Cancellation never deletes persisted evidence, findings, or artifacts.
2. A canceled or failed run never satisfies artifact acceptance (§5).
3. Terminal states are sticky; only the claiming worker finalizes; `worker_claim_lost` never writes a terminal state.
4. Subprocesses do not outlive their task (cancel, timeout, or kill switch).
5. Kill switch is global and immediate for new claims; cooperative (≤ lease/3 seconds) for in-flight work.

> **To confirm (Engineer 1):** partial `TestResult` rows written before a cancel are retained (expected) — pin with a test.

### CI enforces (Engineer 4)

- Cancel on terminal run is a no-op; cancel on non-terminal sets `CANCEL_REQUESTED`.
- Kill switch: no claim; in-flight external engine terminated within the wait window; subprocess gone.
- Lease-loss abort leaves the run claimable and writes no terminal state.
- Canceled run fails acceptance.

---

## Open decisions summary (owner → needed by)

| # | Decision | Owner | Needed by |
|---|---|---|---|
| A | `FAILED_WITH_FINDINGS` counts as success for phase rule and acceptance (§2, §5) | Eng 1 + Eng 3 | **RESOLVED** |
| B | Retest outcome stored vocabulary: five-value set, non-executed outcomes never close or pass the gate (§3) | Eng 3 | **RESOLVED** |
| C | Does the queued external phase honor `CANCEL_REQUESTED` (§6) | Eng 1 | **RESOLVED** |
| D | Closure-gate predicate pinned in a test (§3) | Eng 3 | **RESOLVED** |
| E | Artifact retention / deletion policy (§5) | Eng 4 | Sprint 2 |
| F | `timed_out` vs `TIMEOUT` spelling; stale `TestRun.status` comment; legacy SLA statuses (§1–3) | Eng 1 / Eng 3 | **RESOLVED** |
