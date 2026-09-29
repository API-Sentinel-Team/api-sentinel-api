# Lifecycle CI/CD Governance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make API Sentinel lifecycle and CI gates more enterprise-ready with configurable SLA policy, reopen-on-rediscovery dedupe, policy-pack gates, gate exports, signed decisions, audit events, and tenant quota enforcement.

**Architecture:** Keep lifecycle decisions in `server/modules/vulnerability_detector`, deterministic gate policy in `server/modules/cicd`, and HTTP exposure in `server/api/routers/cicd.py`. Preserve existing redaction, tenant scoping, and tamper-evident hash behavior.

**Tech Stack:** FastAPI, SQLAlchemy async ORM, pytest, existing `TestRun`/`TestResult`/`Vulnerability`/`AuditLog` models, SARIF/JUnit builders in `server/modules/test_executor/reporting.py`.

---

### Task 1: Configurable SLA Policy

**Files:**
- Modify: `server/modules/vulnerability_detector/lifecycle.py`
- Test: `tests/unit/test_vulnerability_lifecycle.py`

- [ ] **Step 1: Write the failing test**
  Add a test that calls `parse_sla_policy("critical=2,high=5,medium=20")` and asserts uppercase severity keys, integer days, ignored whitespace, and a clear `ValueError` for invalid severities or non-positive days.

- [ ] **Step 2: Run test to verify it fails**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_vulnerability_lifecycle.py::test_parse_sla_policy_accepts_configured_days -q`
  Expected: FAIL because `parse_sla_policy` is not defined.

- [ ] **Step 3: Implement minimal code**
  Add `parse_sla_policy`, `configured_sla_policy`, and use the configured policy in `vulnerability_sla_status` when a caller does not pass an explicit policy.

- [ ] **Step 4: Run test to verify it passes**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_vulnerability_lifecycle.py -q`
  Expected: PASS.

### Task 2: Reopen Rediscovered Findings

**Files:**
- Modify: `server/modules/vulnerability_detector/store.py`
- Test: `tests/unit/test_vulnerability_lifecycle.py`

- [ ] **Step 1: Write the failing test**
  Add a test that creates a closed vulnerability, calls `create_or_merge_vulnerability` with equivalent fingerprint data, and asserts the existing record is reopened to `OPEN`, occurrence count increments, SLA is recalculated, and evidence lifecycle gets the new occurrence.

- [ ] **Step 2: Run test to verify it fails**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_vulnerability_lifecycle.py::test_closed_equivalent_vulnerability_is_reopened_on_rediscovery -q`
  Expected: FAIL because the current query excludes closed findings.

- [ ] **Step 3: Implement minimal code**
  Search active findings first; if none match, search closed/resolved equivalent findings and reopen the matching record.

- [ ] **Step 4: Run test to verify it passes**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_vulnerability_lifecycle.py -q`
  Expected: PASS.

### Task 3: CI Policy Packs and Signed Decisions

**Files:**
- Create: `server/modules/cicd/policy_packs.py`
- Modify: `server/modules/cicd/quality_gate.py`
- Modify: `server/api/routers/cicd.py`
- Test: `tests/unit/test_cicd_quality_gate.py`
- Test: `tests/integration/test_cicd_gate.py`

- [ ] **Step 1: Write failing tests**
  Add unit coverage for `resolve_policy_pack("strict")`, `resolve_policy_pack("advisory")`, and `resolve_policy_pack("evidence-only")`. Add an integration test that calls `/api/cicd/gate/{run_id}?policy_pack=evidence-only&allow_policy_overrides=true` and asserts the decision includes `policy_pack`, `decision_integrity.signature_algorithm`, and a redacted audit row.

- [ ] **Step 2: Run tests to verify they fail**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_cicd_quality_gate.py::test_quality_gate_policy_packs_resolve_named_controls tests/integration/test_cicd_gate.py::test_cicd_run_gate_applies_policy_pack_signs_and_audits -q`
  Expected: FAIL because policy packs and signed decision fields are not implemented.

- [ ] **Step 3: Implement minimal code**
  Add named policy pack definitions, use pack defaults in gate routes, add HMAC-SHA256 signing when a configured secret exists and deterministic SHA256 fallback otherwise, and write `CICD_GATE_EVALUATED` audit entries.

- [ ] **Step 4: Run tests to verify they pass**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_cicd_quality_gate.py tests/integration/test_cicd_gate.py -q`
  Expected: PASS.

### Task 4: Gate SARIF/JUnit Export and Tenant Quota

**Files:**
- Modify: `server/api/routers/cicd.py`
- Test: `tests/integration/test_cicd_gate.py`

- [ ] **Step 1: Write failing tests**
  Add integration tests for `/api/cicd/gate/{run_id}/sarif`, `/api/cicd/gate/{run_id}/junit`, and quota blocking by monkeypatching the quota checker to return `allowed=False`.

- [ ] **Step 2: Run tests to verify they fail**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/integration/test_cicd_gate.py::test_cicd_gate_exports_sarif_and_junit tests/integration/test_cicd_gate.py::test_cicd_gate_enforces_tenant_quota_before_evaluation -q`
  Expected: FAIL because export routes and gate quota checks are not implemented.

- [ ] **Step 3: Implement minimal code**
  Add SARIF/JUnit routes using existing reporting builders, add a gate quota helper backed by the existing quota module, and include quota metadata in responses.

- [ ] **Step 4: Run tests to verify they pass**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/integration/test_cicd_gate.py -q`
  Expected: PASS.

---

**Verification:** Finish with unit, integration, security, and e2e pytest layers before claiming completion.
