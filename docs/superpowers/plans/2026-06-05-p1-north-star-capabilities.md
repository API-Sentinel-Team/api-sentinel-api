# P1 North Star Capabilities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the next P1 production slice for identity-boundary evidence, active business abuse tests, deterministic LLM security evidence, and governance reporting.

**Architecture:** Keep each workstream isolated: AuthZ evidence stays in identity modules, active business tests stay in business-logic modules, LLM judge/template work stays in LLM modules and YAML templates, and UI/reporting stays in Release Governance service/component files. Each workstream starts with a failing test that proves the missing acceptance behavior.

**Tech Stack:** Python 3.12, pytest, FastAPI domain modules, React 18, TypeScript, Vitest, Vite.

---

### Task 1: Multi-Identity BOLA/BFLA Evidence

**Files:**
- Modify: `server/modules/identity/authorization_replay.py`
- Modify if needed: `server/modules/identity/roles_context.py`
- Test: `tests/unit/test_authorization_replay.py`

- [ ] **Step 1: Write the failing test**

Add a test showing a replay finding includes deterministic response diff evidence for status, headers, body schema, object ownership, sensitive fields, and identity boundary labels without raw tenant/user/token values.

- [ ] **Step 2: Run the test to verify RED**

Run: `$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; .\.venv\Scripts\python.exe -m pytest tests/unit/test_authorization_replay.py -q`

Expected: FAIL because the new response diff or ownership/sensitive-field evidence is missing.

- [ ] **Step 3: Implement minimal AuthZ evidence support**

Extend the evidence builder to emit redacted, deterministic response-diff metadata and boundary proof from the identity matrix. Do not persist raw response bodies, tenant IDs, user IDs, API keys, or auth headers.

- [ ] **Step 4: Verify GREEN**

Run the same command. Expected: all authorization replay unit tests pass.

### Task 2: Business Logic Active Abuse Tests

**Files:**
- Modify: `server/modules/business_logic/active_tests.py`
- Modify if needed: `server/modules/business_logic/active_testing.py`
- Test: `tests/unit/test_business_logic_active_tests.py`
- Test if needed: `tests/unit/test_business_logic_active_testing.py`

- [ ] **Step 1: Write the failing test**

Add a test requiring generated active templates to cover coupon replay, OTP throttle probing, workflow bypass, resource exhaustion, and flow graph/sensitive-flow mapping with deterministic evidence metadata.

- [ ] **Step 2: Run the test to verify RED**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_business_logic_active_tests.py tests/unit/test_business_logic_active_testing.py -q`

Expected: FAIL on missing workflow-bypass active template or missing flow mapping.

- [ ] **Step 3: Implement minimal active template coverage**

Generate safe, bounded workflow-bypass probes from sensitive flow signals. Ensure every active abuse template declares scenario type, family, throttling/safety limits, flow graph mapping, deterministic evidence fields, and content minimization.

- [ ] **Step 4: Verify GREEN**

Run the same command. Expected: all business-logic active tests pass.

### Task 3: LLM API Security Evidence Gate

**Files:**
- Modify: `server/modules/llm/active_judge.py`
- Modify if needed: `server/modules/llm/findings.py`
- Modify if needed: `tests-library/LLM-Security/*.yaml`
- Test: `tests/unit/test_llm_active_judge.py`
- Test: `tests/unit/test_llm_active_templates.py`
- Test if needed: `tests/unit/test_llm_findings.py`

- [ ] **Step 1: Write the failing test**

Add a test requiring prompt injection, system prompt leakage, RAG exfiltration, and unsafe tool-call findings to hold promotion unless deterministic judge material includes redacted request/response hashes and required evidence fields.

- [ ] **Step 2: Run the test to verify RED**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_llm_active_judge.py tests/unit/test_llm_active_templates.py -q`

Expected: FAIL on missing deterministic evidence requirement or missing active template metadata.

- [ ] **Step 3: Implement minimal LLM gate/template support**

Extend the deterministic judge and active template metadata so no LLM finding can promote without the required hash/minimized evidence contract.

- [ ] **Step 4: Verify GREEN**

Run the same command. Expected: all LLM active tests pass.

### Task 4: Governance UI And Reports

**Files:**
- Modify: `api-sentinel-view-main/src/customer/pages/testing/ReleaseGovernance.tsx`
- Modify: `api-sentinel-view-main/src/customer/pages/testing/ReleaseGovernance.test.tsx`
- Modify: `api-sentinel-view-main/src/services/security-ops.service.ts`
- Modify: `api-sentinel-view-main/src/services/security-ops.service.test.ts`

- [ ] **Step 1: Write the failing test**

Add UI/service tests requiring North Star readiness blockers, owners, evidence status, SLA health, endpoint risk, executive summary, and technical report data to render from normalized dashboard payloads.

- [ ] **Step 2: Run the test to verify RED**

Run: `npm test -- src/customer/pages/testing/ReleaseGovernance.test.tsx src/services/security-ops.service.test.ts`

Expected: FAIL on missing report/readiness fields or UI labels.

- [ ] **Step 3: Implement minimal reporting UI**

Normalize report/readiness fields and render dense enterprise dashboard sections without raw secrets. Keep the UI consistent with existing Tailwind/shadcn patterns.

- [ ] **Step 4: Verify GREEN**

Run the same command plus `npm run build`. Expected: tests and production build pass.

### Task 5: Local Integration Verification

**Files:**
- Modify only if a focused integration gap is found: `server/modules/pentest/north_star_readiness.py`
- Modify only if a focused integration gap is found: `server/api/routers/dashboard.py`
- Test: `tests/unit/test_north_star_readiness.py`
- Test: `tests/integration/test_dashboard_governance_api.py`

- [ ] **Step 1: Write a failing integration test if readiness/reporting lacks the new P1 signals**

Run: `.venv\Scripts\python.exe -m pytest tests/unit/test_north_star_readiness.py tests/integration/test_dashboard_governance_api.py -q`

Expected: If existing coverage already passes and exposes the new fields, no production edit is needed. If a field is missing, add a failing assertion first.

- [ ] **Step 2: Implement only the missing integration glue**

Add non-secret readiness/reporting fields for the four P1 lanes.

- [ ] **Step 3: Verify GREEN**

Run the focused backend and frontend commands from Tasks 1-4 and the integration command above.
