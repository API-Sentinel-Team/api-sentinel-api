# Red Team Workstreams Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the next production gaps toward a continuous, authenticated, evidence-grade API red-team platform for owned APIs.

**Architecture:** Keep scanner safety centralized in `server/modules/test_executor` and `server/modules/pentest`, keep authenticated execution policy in pentest profiles and CI/schedule preflight, and move discovery feed normalization into reusable inventory modules. The first implementation slice focuses on gaps not already covered by existing tests: multi-source discovery normalization and inventory metadata.

**Tech Stack:** FastAPI, SQLAlchemy async ORM, pytest, existing API Sentinel modules.

---

### Task 1: Unified Discovery Normalization

**Files:**
- Modify: `server/modules/api_inventory/endpoint_discovery.py`
- Test: `tests/unit/test_endpoint_discovery.py`

- [ ] **Step 1: Write failing tests**

Add tests that call `EndpointDiscovery.discover()` with HAR/gateway/cloud/ingress-style records and assert one normalized endpoint is created for `/users/123` and `/users/456` as `/users/{id}`, with `account_id`, `owner`, `auth_required`, `sensitivity`, `version`, `deprecated`, `shadow`, and source tags preserved.

- [ ] **Step 2: Verify red**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\unit\test_endpoint_discovery.py -q
```

Expected before implementation: at least one failure because `EndpointDiscovery.discover()` does not accept account-aware generic records or populate the metadata tags.

- [ ] **Step 3: Implement minimal code**

Update `EndpointDiscovery.discover()` so it accepts records with `account_id`, `source`, `method`, `url`, `host`, `scheme`/`protocol`, `owner`, `auth_required`, `sensitivity`, `version`, `deprecated`, `shadow`, and `status`. Persist extended inventory metadata in `APIEndpoint.tags` without adding a migration in this slice.

- [ ] **Step 4: Verify green**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\unit\test_endpoint_discovery.py -q
```

Expected after implementation: all tests pass.

### Task 2: Safety/Auth Regression Sweep

**Files:**
- Inspect: `server/modules/test_executor/target_guard.py`
- Inspect: `server/modules/test_executor/state_change_guard.py`
- Inspect: `server/modules/pentest/auth_scope.py`
- Inspect: `server/modules/pentest/auth_preflight.py`
- Inspect: `server/api/routers/cicd.py`
- Inspect: `server/api/routers/schedules.py`

- [ ] **Step 1: Compare existing tests to workstream requirements**

Use `rg` and targeted pytest runs to confirm current coverage for target guard, private-IP/DNS resolution, state-changing/destructive methods, auth-required CI gates, auth-profile scope enforcement, and schedule preflight.

- [ ] **Step 2: Add missing regression tests only where gaps are confirmed**

Add tests near the touched behavior. Do not duplicate existing assertions.

- [ ] **Step 3: Implement minimal code for confirmed gaps**

Keep safety/auth fixes scoped to the module that owns the behavior. Do not loosen redaction or target-guard rules.

### Task 3: Final Verification

**Files:**
- Modify docs only if operator behavior changes: `docs/API_PENTESTING_NORTH_STAR.md`

- [ ] **Step 1: Run targeted suites**

Run the tests for every changed module.

- [ ] **Step 2: Run aggregate backend verification**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\unit tests\integration tests\security tests\e2e -q
```

Expected: all tests pass. Report warnings separately.
