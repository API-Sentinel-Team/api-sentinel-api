# P0 Release Blockers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clear the release-blocking gates for frontend quality, CI enforcement, real scanner execution artifacts, isolated workers, and production scan safety.

**Architecture:** Keep the platform split into disjoint release-gate slices: frontend quality lives under `api-sentinel-view-main/`, CI under `.github/workflows/`, scanner runtime under `server/modules/pentest|nuclei|schemathesis|zap`, worker governance under `server/modules/test_executor/scan_worker.py`, and safety controls under `server/modules/test_executor` plus `server/modules/pentest`. All active scan paths must produce redacted, verifiable, account-scoped evidence.

**Tech Stack:** FastAPI, async SQLAlchemy, pytest, Vite React TypeScript, Vitest, Playwright, GitHub Actions, Schemathesis, Nuclei, OWASP ZAP.

---

## File Structure

- Modify: `api-sentinel-view-main/src/**` only for frontend lint/test/build/E2E failures.
- Modify: `.github/workflows/ci.yml` for release-blocking CI jobs and artifact uploads.
- Modify: `server/modules/pentest/execution_artifacts.py` for external-engine artifact verification behavior.
- Modify: `server/modules/pentest/schemathesis_runner.py`, `server/modules/nuclei/runner.py`, `server/modules/zap/runner.py` for runtime readiness and execution metadata.
- Modify: `server/modules/cicd/quality_gate.py` for ready-engine artifact gate summaries.
- Modify: `server/modules/test_executor/scan_worker.py` and `server/modules/pentest/worker_isolation.py` for worker lease/isolation/recovery metadata.
- Modify: `server/modules/test_executor/target_guard.py`, `server/modules/test_executor/state_change_guard.py`, `server/modules/test_executor/evidence.py`, `server/modules/pentest/target_policy.py`, `server/modules/pentest/auth_scope.py`, and `server/modules/pentest/artifact_sanitizer.py` for fail-closed safety and redaction behavior.
- Test: `tests/unit/test_*` and `tests/integration/test_*` files nearest each changed backend behavior.
- Test: `api-sentinel-view-main/src/**/*.test.tsx` and `api-sentinel-view-main/tests/e2e/*.spec.ts` for frontend behavior.

## Task 1: Frontend Lint Cleanup

**Files:**
- Modify: `api-sentinel-view-main/src/**/*.tsx`
- Modify: `api-sentinel-view-main/src/**/*.ts`
- Test: existing Vitest and Playwright tests under `api-sentinel-view-main/src` and `api-sentinel-view-main/tests/e2e`

- [ ] **Step 1: Capture lint baseline**

Run:

```powershell
cd api-sentinel-view-main
npm run lint
```

Expected: current lint failures identify exact files and rules.

- [ ] **Step 2: Fix lint failures without weakening rules**

Use code-level fixes: remove unused imports, replace `any` with existing types, add exhaustive hook dependencies where semantically correct, and keep components aligned to the current shadcn/Radix patterns.

- [ ] **Step 3: Verify frontend gates**

Run:

```powershell
cd api-sentinel-view-main
npm run lint
npm test
npm run build
npm run test:e2e
```

Expected: all commands pass, or E2E reports a concrete environment blocker such as a missing browser/server prerequisite.

## Task 2: CI Pipeline Hardening

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Inspect existing jobs**

Run:

```powershell
Get-Content .github\workflows\ci.yml
```

Expected: identify backend unit/security/integration jobs and frontend build/E2E jobs already present.

- [ ] **Step 2: Add missing release gates**

Ensure the workflow includes backend unit, integration, security, E2E/API tests, frontend lint, frontend tests, frontend build, frontend E2E, and artifact uploads for JUnit/SARIF/Playwright output.

- [ ] **Step 3: Validate workflow syntax**

Run:

```powershell
python - << "PY"
import yaml
yaml.safe_load(open(".github/workflows/ci.yml", encoding="utf-8"))
print("ci yaml ok")
PY
```

Expected: YAML parses successfully.

## Task 3: Real Multi-Engine Runtime Execution

**Files:**
- Modify: `server/modules/pentest/execution_artifacts.py`
- Modify: `server/modules/pentest/schemathesis_runner.py`
- Modify: `server/modules/nuclei/runner.py`
- Modify: `server/modules/zap/runner.py`
- Modify: `server/modules/cicd/quality_gate.py`
- Test: `tests/unit/test_pentest_execution_artifacts.py`
- Test: `tests/unit/test_schemathesis_runner.py`
- Test: `tests/unit/test_nuclei_runner.py`
- Test: `tests/unit/test_zap_runner.py`
- Test: `tests/unit/test_cicd_quality_gate.py`

- [ ] **Step 1: Add failing artifact verification test**

Add or extend a test that creates a ready engine summary without a verified artifact and asserts the quality gate reports a blocking artifact failure.

- [ ] **Step 2: Run the focused test**

Run:

```powershell
pytest tests/unit/test_cicd_quality_gate.py -q
```

Expected: fails because ready-engine missing-artifact behavior is not enforced or not fully reported.

- [ ] **Step 3: Implement minimal artifact gate**

Update quality-gate logic to treat ready external engines as requiring verified execution artifacts. Keep disabled/unavailable engines non-blocking when their status and redacted reason are explicit.

- [ ] **Step 4: Verify scanner runner tests**

Run:

```powershell
pytest tests/unit/test_pentest_execution_artifacts.py tests/unit/test_schemathesis_runner.py tests/unit/test_nuclei_runner.py tests/unit/test_zap_runner.py tests/unit/test_cicd_quality_gate.py -q
```

Expected: all pass.

## Task 4: Isolated Scan Workers

**Files:**
- Modify: `server/modules/test_executor/scan_worker.py`
- Modify: `server/modules/test_executor/kill_switch.py`
- Modify: `server/modules/pentest/worker_isolation.py`
- Test: `tests/unit/test_scan_worker.py`

- [ ] **Step 1: Add failing worker recovery/audit test**

Add a focused test that verifies lost, failed, or timed-out workers produce recoverable queue state and redacted audit metadata tied to `run_id`.

- [ ] **Step 2: Run focused test**

Run:

```powershell
pytest tests/unit/test_scan_worker.py -q
```

Expected: fails on the missing recovery/audit behavior.

- [ ] **Step 3: Implement worker governance metadata**

Ensure worker leases, heartbeat, claim count, timeout/failure status, kill switch policy, isolation mode, resource limits, and audit context are returned or persisted consistently.

- [ ] **Step 4: Verify worker tests**

Run:

```powershell
pytest tests/unit/test_scan_worker.py tests/unit/test_north_star_readiness.py -q
```

Expected: all pass.

## Task 5: Production Safety Enforcement

**Files:**
- Modify: `server/modules/test_executor/target_guard.py`
- Modify: `server/modules/test_executor/state_change_guard.py`
- Modify: `server/modules/test_executor/evidence.py`
- Modify: `server/modules/pentest/target_policy.py`
- Modify: `server/modules/pentest/auth_scope.py`
- Modify: `server/modules/pentest/artifact_sanitizer.py`
- Test: `tests/unit/test_target_guard.py`
- Test: `tests/unit/test_auth_scope.py`
- Test: `tests/unit/test_execution_engine_state_guard.py`
- Test: `tests/unit/test_active_scan_evidence.py`
- Test: `tests/unit/test_openapi_state_policy.py`
- Test: `tests/integration/test_workflow_auth_safety.py`

- [ ] **Step 1: Add failing unsafe-scan tests**

Add or extend tests for allowlist denial, SSRF/private/metadata host denial, auth scope mismatch, destructive method denial, and secret redaction in failed-closed evidence.

- [ ] **Step 2: Run focused safety tests**

Run:

```powershell
pytest tests/unit/test_target_guard.py tests/unit/test_auth_scope.py tests/unit/test_execution_engine_state_guard.py tests/unit/test_active_scan_evidence.py tests/unit/test_openapi_state_policy.py tests/integration/test_workflow_auth_safety.py -q
```

Expected: tests fail only where behavior is missing.

- [ ] **Step 3: Implement fail-closed behavior**

Apply minimal changes so unsafe scans fail before credential attachment or external execution, and so returned evidence/loggable context is redacted and structured.

- [ ] **Step 4: Verify safety tests**

Run the same focused safety command. Expected: all pass.

## Final Verification

- [ ] Run backend unit tests:

```powershell
pytest tests/unit -q
```

- [ ] Run backend integration tests:

```powershell
pytest tests/integration -q
```

- [ ] Run backend security tests:

```powershell
pytest tests/security -q
```

- [ ] Run frontend gates:

```powershell
cd api-sentinel-view-main
npm run lint
npm test
npm run build
npm run test:e2e
```

- [ ] Confirm CI workflow has blocking jobs and artifact uploads.

## Self-Review

- Spec coverage: The plan maps each P0 blocker to one implementation task plus final release gates.
- Placeholder scan: No `TBD`, `TODO`, or undefined implementation target remains in this plan.
- Type consistency: The plan uses existing repo terms: `TestRun`, execution artifacts, target guard, auth scope, state-change guard, CI quality gate, and Playwright artifacts.
