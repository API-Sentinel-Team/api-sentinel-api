# P0 Worker Platform Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate that queued API Sentinel scans can run through isolated external/Kubernetes workers, clean their sandboxes, honor leases and kill switches, enforce CPU/memory limits, and emit verified hashed artifacts.

**Architecture:** Keep queue execution in `scan_worker.py`, keep sandbox details in `worker_isolation.py`, and add a small validation module that turns existing runtime facts into a production-readiness report. Worker run results should include a post-run acceptance summary proving sandbox cleanup and artifact verification.

**Tech Stack:** Python 3.12, pytest, FastAPI domain modules, SQLAlchemy async test database.

---

### Task 1: Worker Runtime Readiness Contract

**Files:**
- Create: `server/modules/test_executor/worker_validation.py`
- Test: `tests/unit/test_worker_validation.py`

- [x] **Step 1: Write the failing test**

Add tests for queued execution mode, external worker isolation, Kubernetes job metadata, lease policy, kill switch status, and resource limits.

- [x] **Step 2: Run the test to verify RED**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_worker_validation.py -q`

Expected: FAIL because `worker_validation.py` does not exist yet.

- [x] **Step 3: Implement minimal readiness code**

Build deterministic readiness checks with `ready`, `status`, `evidence`, and `blockers` fields.

- [x] **Step 4: Verify GREEN**

Run the same command. Expected: worker validation tests pass.

### Task 2: Concrete Staging Scan Acceptance Evidence

**Files:**
- Modify: `server/modules/test_executor/scan_worker.py`
- Test: `tests/unit/test_scan_worker.py`

- [x] **Step 1: Write the failing test**

Extend the real queued-worker unit path to require a `worker_artifact` summary and `worker_acceptance` report after `run_pending_scan_once`.

- [x] **Step 2: Run the test to verify RED**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_scan_worker.py::test_run_pending_scan_once_records_worker_isolation_session_and_cleans_sandbox -q`

Expected: FAIL because the run result does not yet expose artifact verification or acceptance status.

- [x] **Step 3: Implement artifact summary wiring**

After execution and cleanup, fetch the run artifact, verify its hash, and attach acceptance evidence to the worker result.

- [x] **Step 4: Verify GREEN**

Run the same command. Expected: external worker and Kubernetes job variants both pass.

### Task 3: Operator Queue Health Wiring

**Files:**
- Modify: `server/modules/test_executor/scan_worker.py`
- Test: `tests/unit/test_scan_worker.py`

- [x] **Step 1: Write the failing test**

Add a queue-health assertion requiring a `runtime_validation` report for queued Kubernetes worker settings.

- [x] **Step 2: Run the test to verify RED**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_scan_worker.py::test_worker_queue_health_exposes_runtime_validation_for_kubernetes_queue -q`

Expected: FAIL because `runtime_validation` is not present.

- [x] **Step 3: Wire readiness into queue health**

Attach `build_worker_runtime_validation` to `worker_queue_health`.

- [x] **Step 4: Verify GREEN**

Run focused worker tests and then the broader backend unit suite.
