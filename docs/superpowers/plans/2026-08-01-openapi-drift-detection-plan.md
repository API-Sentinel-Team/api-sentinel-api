# OpenAPI Auto-Doc + Drift Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automate the platform's existing (but manually-triggered) OpenAPI spec generation and diffing into a scheduled background job that keeps the inferred API spec current and raises findings when it drifts meaningfully — plus a frontend view to see it.

**Architecture:** A new `OpenAPIDriftProcessor` (mirrors the existing `ContinuousTestingProcessor` background-loop pattern exactly) periodically regenerates the spec via the existing `OpenAPIGenerator`, diffs it against the last stored version via the existing `OpenAPIDiffAnalyzer`, and on drift persists a new `OpenAPISpec` row plus one `PolicyViolation` + `Alert` + `EvidenceRecord` per changed item. No new database tables. The frontend gets a new typed service/hook layer and an enhanced Discovery page showing the current spec, version history, and a diff viewer.

**Tech Stack:** FastAPI, SQLAlchemy async (SQLite in dev/test), pytest + pytest-asyncio, React + TypeScript, TanStack Query, Vite.

## Global Constraints

- Feature is off by default: `OPENAPI_DRIFT_ENABLED: bool = False`, `STARTUP_ENABLE_OPENAPI_DRIFT: bool = False` (exact names, matching the `CONTINUOUS_TESTING_ENABLED` / `STARTUP_ENABLE_CONTINUOUS_TESTING` pattern in `server/config.py`).
- No new database tables — reuse `OpenAPISpec`, `PolicyViolation` (new `rule_type="DRIFT"`), `Alert`, `EvidenceRecord`.
- Trigger is scheduled only (fixed interval sweep), not event-driven. This is an explicit decision from the design spec — do not add endpoint-change-triggered rebuilds.
- No new `WSEventType` / realtime push for v1 — the frontend page refetches on mount/focus like other non-realtime pages.
- Follow the exact class shape of `server/modules/scheduler/continuous_testing.py::ContinuousTestingProcessor` for the new processor (`start`/`stop`/`_loop`/`sweep`, per-account error isolation, `interval_sec` constructor param defaulting to a settings value).
- Design spec: `docs/superpowers/specs/2026-08-01-openapi-drift-detection-design.md` — read it if anything here is ambiguous, it is the source of truth for intent.

---

### Task 1: Config + processor scaffold (disabled by default)

**Files:**
- Modify: `server/config.py` (add settings after the `CONTINUOUS_TESTING_*` block, currently ending around line 317)
- Create: `server/modules/scheduler/openapi_drift.py`
- Test: `tests/unit/test_openapi_drift.py`

**Interfaces:**
- Produces: `OpenAPIDriftProcessor` class with `__init__(self, interval_sec: int | None = None)`, `async def start(self) -> None`, `async def stop(self) -> None`, `async def sweep(self) -> dict` returning `{"status": "disabled"}` or `{"status": "ok", "accounts_checked": int, "accounts_drifted": int}`.

- [ ] **Step 1: Add the three settings to `server/config.py`**

Insert immediately after the existing `STARTUP_ENABLE_CONTINUOUS_TESTING: bool = False` line (currently line 317, right before the `@field_validator("DEBUG", ...)` block):

```python
    # ── OpenAPI Auto-Doc + Drift Detection ────────────────────────────────
    # Periodically regenerates the OpenAPI spec from discovered endpoints and
    # diffs it against the last stored version, raising a finding when the
    # API surface changes in a way that matters (endpoint removed, auth
    # requirement dropped, etc). Off by default.
    OPENAPI_DRIFT_ENABLED: bool = False
    OPENAPI_DRIFT_SWEEP_INTERVAL_SECONDS: int = 3600
    STARTUP_ENABLE_OPENAPI_DRIFT: bool = False
```

- [ ] **Step 2: Write the failing test for the disabled no-op**

Create `tests/unit/test_openapi_drift.py`:

```python
"""Tests for the OpenAPI drift processor (auto-doc + drift detection)."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_sweep_is_noop_when_disabled(monkeypatch):
    from server.config import settings
    from server.modules.scheduler.openapi_drift import OpenAPIDriftProcessor

    monkeypatch.setattr(settings, "OPENAPI_DRIFT_ENABLED", False)
    proc = OpenAPIDriftProcessor()
    result = await proc.sweep()
    assert result == {"status": "disabled"}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_openapi_drift.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'server.modules.scheduler.openapi_drift'`

- [ ] **Step 4: Write the processor scaffold**

Create `server/modules/scheduler/openapi_drift.py`:

```python
"""OpenAPI drift processor — auto-generates and diffs the API spec.

Periodically regenerates the OpenAPI spec from discovered endpoints
(``OpenAPIGenerator``) and diffs it against the last stored version
(``OpenAPIDiffAnalyzer``). On drift, persists a new ``OpenAPISpec`` version
and raises a ``PolicyViolation`` + ``Alert`` + ``EvidenceRecord`` per changed
item, using the analyzer's own severity/message/recommendation output.

Gated by ``OPENAPI_DRIFT_ENABLED`` (default off). Mirrors the shape of
``server.modules.scheduler.continuous_testing.ContinuousTestingProcessor``.
"""
from __future__ import annotations

import asyncio

import structlog
from sqlalchemy import select

from server.config import settings
from server.models.core import APIEndpoint
from server.modules.api_inventory.openapi_diff import OpenAPIDiffAnalyzer
from server.modules.api_inventory.openapi_generator import OpenAPIGenerator
from server.modules.persistence.database import AsyncSessionLocal

logger = structlog.get_logger(__name__)


class OpenAPIDriftProcessor:
    def __init__(self, interval_sec: int | None = None) -> None:
        self.interval = interval_sec or settings.OPENAPI_DRIFT_SWEEP_INTERVAL_SECONDS
        self._running = False
        self._task: asyncio.Task | None = None
        self._gen = OpenAPIGenerator()
        self._diff = OpenAPIDiffAnalyzer()

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        task = self._task
        self._task = None
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        try:
            while self._running:
                try:
                    await self.sweep()
                except Exception as exc:  # never let the loop die
                    logger.error("openapi_drift_sweep_error", error=str(exc))
                await asyncio.sleep(self.interval)
        except asyncio.CancelledError:
            logger.info("openapi_drift_loop_cancelled")

    async def sweep(self) -> dict:
        """Check every account with discovered endpoints for spec drift."""
        if not settings.OPENAPI_DRIFT_ENABLED:
            return {"status": "disabled"}

        account_ids = await self._accounts_with_endpoints()
        checked = 0
        drifted = 0
        for account_id in account_ids:
            checked += 1
            try:
                result = await self._check_account(account_id)
            except Exception as exc:  # one bad account must not stop the sweep
                logger.error(
                    "openapi_drift_check_error", account_id=account_id, error=str(exc)
                )
                continue
            if result.get("status") == "drifted":
                drifted += 1

        logger.info(
            "openapi_drift_sweep", accounts_checked=checked, accounts_drifted=drifted
        )
        return {"status": "ok", "accounts_checked": checked, "accounts_drifted": drifted}

    async def _check_account(self, account_id: int) -> dict:
        raise NotImplementedError  # implemented in Task 2

    @staticmethod
    async def _accounts_with_endpoints() -> list[int]:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(APIEndpoint.account_id).distinct())
            return [row for row in result.scalars().all() if row is not None]
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_openapi_drift.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add server/config.py server/modules/scheduler/openapi_drift.py tests/unit/test_openapi_drift.py
git commit -m "feat: scaffold OpenAPIDriftProcessor, disabled by default"
```

---

### Task 2: `_check_account` — baseline and no-drift cases

**Files:**
- Modify: `server/modules/scheduler/openapi_drift.py`
- Test: `tests/unit/test_openapi_drift.py`

**Interfaces:**
- Consumes: `OpenAPIGenerator.generate_spec(collection_name: str, account_id: int | None) -> dict` (returns an OpenAPI dict with a `"paths"` key), `OpenAPIDiffAnalyzer.compare(base_spec: dict | None, revision_spec: dict) -> dict` (returns `{"summary": ..., "breaking_changes": list[dict], "recommendations": ...}`, each change dict has keys `id, severity, path, method, component, message, why_it_matters, recommended_action, details, fingerprint`).
- Produces: `_get_previous_spec(self, db, account_id: int) -> OpenAPISpec | None`, `_persist_spec_version(self, db, account_id: int, spec_json: dict) -> OpenAPISpec`. `_check_account` returns `{"status": "baseline"}` on first run, `{"status": "unchanged"}` when no drift, `{"status": "drifted", "change_count": int}` when drift is found (drift-handling itself is Task 3 — for this task, treat a non-empty diff as `"drifted"` but don't persist findings yet, just the new spec version).

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_openapi_drift.py`:

```python
@pytest.mark.asyncio
async def test_check_account_persists_baseline_when_no_prior_spec(db, monkeypatch):
    from server.config import settings
    from server.modules.scheduler.openapi_drift import OpenAPIDriftProcessor
    from server.models.core import OpenAPISpec
    from sqlalchemy import select

    monkeypatch.setattr(settings, "OPENAPI_DRIFT_ENABLED", True)
    proc = OpenAPIDriftProcessor()

    async def fake_generate_spec(collection_name="Discovered API", account_id=None):
        return {"openapi": "3.0.0", "paths": {"/users": {"get": {}}}}

    monkeypatch.setattr(proc._gen, "generate_spec", fake_generate_spec)

    result = await proc._check_account_with_session(db, account_id=1000000)
    assert result == {"status": "baseline"}

    stored = (await db.execute(
        select(OpenAPISpec).where(OpenAPISpec.account_id == 1000000)
    )).scalars().all()
    assert len(stored) == 1
    assert stored[0].spec_json["paths"] == {"/users": {"get": {}}}


@pytest.mark.asyncio
async def test_check_account_skips_identical_spec(db, monkeypatch):
    from server.config import settings
    from server.modules.scheduler.openapi_drift import OpenAPIDriftProcessor
    from server.models.core import OpenAPISpec
    from sqlalchemy import select

    monkeypatch.setattr(settings, "OPENAPI_DRIFT_ENABLED", True)
    proc = OpenAPIDriftProcessor()

    spec = {"openapi": "3.0.0", "paths": {"/users": {"get": {}}}}
    db.add(OpenAPISpec(account_id=1000000, spec_json=spec))
    await db.commit()

    async def fake_generate_spec(collection_name="Discovered API", account_id=None):
        return dict(spec)

    monkeypatch.setattr(proc._gen, "generate_spec", fake_generate_spec)

    result = await proc._check_account_with_session(db, account_id=1000000)
    assert result == {"status": "unchanged"}

    stored = (await db.execute(
        select(OpenAPISpec).where(OpenAPISpec.account_id == 1000000)
    )).scalars().all()
    assert len(stored) == 1  # no new row was added


@pytest.mark.asyncio
async def test_check_account_detects_drift(db, monkeypatch):
    from server.config import settings
    from server.modules.scheduler.openapi_drift import OpenAPIDriftProcessor
    from server.models.core import OpenAPISpec
    from sqlalchemy import select

    monkeypatch.setattr(settings, "OPENAPI_DRIFT_ENABLED", True)
    proc = OpenAPIDriftProcessor()

    old_spec = {"openapi": "3.0.0", "paths": {"/users": {"get": {}}}}
    db.add(OpenAPISpec(account_id=1000000, spec_json=old_spec))
    await db.commit()

    async def fake_generate_spec(collection_name="Discovered API", account_id=None):
        return {"openapi": "3.0.0", "paths": {}}  # /users removed

    monkeypatch.setattr(proc._gen, "generate_spec", fake_generate_spec)

    result = await proc._check_account_with_session(db, account_id=1000000)
    assert result["status"] == "drifted"
    assert result["change_count"] == 1

    stored = (await db.execute(
        select(OpenAPISpec)
        .where(OpenAPISpec.account_id == 1000000)
        .order_by(OpenAPISpec.created_at.desc())
    )).scalars().all()
    assert len(stored) == 2  # baseline + new drifted version
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_openapi_drift.py -v`
Expected: FAIL — `AttributeError: 'OpenAPIDriftProcessor' object has no attribute '_check_account_with_session'`

- [ ] **Step 3: Implement `_check_account_with_session`, `_get_previous_spec`, `_persist_spec_version`, and wire `_check_account`**

Replace the `_check_account` stub in `server/modules/scheduler/openapi_drift.py` with:

```python
    async def _check_account(self, account_id: int) -> dict:
        async with AsyncSessionLocal() as db:
            result = await self._check_account_with_session(db, account_id)
            await db.commit()
            return result

    async def _check_account_with_session(self, db, account_id: int) -> dict:
        new_spec = await self._gen.generate_spec(
            collection_name="Discovered API", account_id=account_id
        )
        previous = await self._get_previous_spec(db, account_id)

        if previous is None:
            await self._persist_spec_version(db, account_id, new_spec)
            return {"status": "baseline"}

        if previous.spec_json == new_spec:
            return {"status": "unchanged"}

        diff = self._diff.compare(previous.spec_json, new_spec)
        changes = diff["breaking_changes"]
        if not changes:
            return {"status": "unchanged"}

        await self._persist_spec_version(db, account_id, new_spec)
        return {"status": "drifted", "change_count": len(changes), "changes": changes}

    @staticmethod
    async def _get_previous_spec(db, account_id: int):
        from server.models.core import OpenAPISpec

        result = await db.execute(
            select(OpenAPISpec)
            .where(OpenAPISpec.account_id == account_id)
            .order_by(OpenAPISpec.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def _persist_spec_version(db, account_id: int, spec_json: dict):
        from server.models.core import OpenAPISpec

        record = OpenAPISpec(account_id=account_id, spec_json=spec_json)
        db.add(record)
        await db.flush()
        return record
```

Add the `OpenAPISpec` import isn't needed at module level since it's imported locally in each method (avoids a circular-import risk with `server.models.core` at module load time — follow this local-import style consistently in this file).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_openapi_drift.py -v`
Expected: All 4 tests PASS (the Task 1 disabled-noop test plus these 3)

- [ ] **Step 5: Commit**

```bash
git add server/modules/scheduler/openapi_drift.py tests/unit/test_openapi_drift.py
git commit -m "feat: OpenAPIDriftProcessor detects baseline/unchanged/drifted states"
```

---

### Task 3: Raise findings on drift (PolicyViolation + Alert + EvidenceRecord)

**Files:**
- Modify: `server/modules/scheduler/openapi_drift.py`
- Test: `tests/unit/test_openapi_drift.py`

**Interfaces:**
- Consumes: `PolicyViolation(id, account_id, rule_id, endpoint_id, rule_type, severity, status, message, violation_metadata, created_at)`, `Alert(id, account_id, title, message, severity, category, source_ip, endpoint, status, created_at)`, `EvidenceRecord(id, account_id, evidence_type, ref_id, endpoint_id, severity, summary, details, created_at)` — all from `server.models.core`. `APIEndpoint(id, account_id, method, path, ...)`.
- Produces: `_raise_drift_findings(self, db, account_id: int, changes: list[dict]) -> None`, called from `_check_account_with_session` right after persisting the new spec version when `status == "drifted"`.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_openapi_drift.py`:

```python
@pytest.mark.asyncio
async def test_drift_creates_violation_alert_and_evidence(db, monkeypatch):
    from server.config import settings
    from server.modules.scheduler.openapi_drift import OpenAPIDriftProcessor
    from server.models.core import OpenAPISpec, APIEndpoint, PolicyViolation, Alert, EvidenceRecord
    from sqlalchemy import select

    monkeypatch.setattr(settings, "OPENAPI_DRIFT_ENABLED", True)
    proc = OpenAPIDriftProcessor()

    db.add(APIEndpoint(id="ep-1", account_id=1000000, method="GET", path="/users"))
    old_spec = {"openapi": "3.0.0", "paths": {"/users": {"get": {}}}}
    db.add(OpenAPISpec(account_id=1000000, spec_json=old_spec))
    await db.commit()

    async def fake_generate_spec(collection_name="Discovered API", account_id=None):
        return {"openapi": "3.0.0", "paths": {}}  # /users removed -> path_removed, HIGH

    monkeypatch.setattr(proc._gen, "generate_spec", fake_generate_spec)

    result = await proc._check_account_with_session(db, account_id=1000000)
    await db.commit()
    assert result["status"] == "drifted"

    violations = (await db.execute(
        select(PolicyViolation).where(PolicyViolation.account_id == 1000000)
    )).scalars().all()
    assert len(violations) == 1
    assert violations[0].rule_type == "DRIFT"
    assert violations[0].severity == "HIGH"
    assert violations[0].endpoint_id == "ep-1"

    alerts = (await db.execute(
        select(Alert).where(Alert.account_id == 1000000)
    )).scalars().all()
    assert len(alerts) == 1
    assert alerts[0].category == "API_DRIFT"
    assert alerts[0].severity == "HIGH"

    evidence = (await db.execute(
        select(EvidenceRecord).where(EvidenceRecord.account_id == 1000000)
    )).scalars().all()
    assert len(evidence) == 1
    assert evidence[0].evidence_type == "drift"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_openapi_drift.py::test_drift_creates_violation_alert_and_evidence -v`
Expected: FAIL — no `PolicyViolation`/`Alert`/`EvidenceRecord` rows created (assertion `len(violations) == 1` fails with `0 == 1`)

- [ ] **Step 3: Implement `_raise_drift_findings` and `_resolve_endpoint_id`, wire into `_check_account_with_session`**

In `server/modules/scheduler/openapi_drift.py`, update `_check_account_with_session`'s drift branch:

```python
        await self._persist_spec_version(db, account_id, new_spec)
        await self._raise_drift_findings(db, account_id, changes)
        return {"status": "drifted", "change_count": len(changes), "changes": changes}
```

Add these methods to the class:

```python
    async def _raise_drift_findings(self, db, account_id: int, changes: list[dict]) -> None:
        from server.models.core import PolicyViolation, Alert, EvidenceRecord

        for change in changes:
            endpoint_id = await self._resolve_endpoint_id(
                db, account_id, change["path"], change["method"]
            )

            violation = PolicyViolation(
                account_id=account_id,
                endpoint_id=endpoint_id,
                rule_type="DRIFT",
                severity=change["severity"],
                status="OPEN",
                message=change["message"],
                violation_metadata={
                    "change_id": change["id"],
                    "component": change["component"],
                    "path": change["path"],
                    "method": change["method"],
                    "why_it_matters": change["why_it_matters"],
                    "recommended_action": change["recommended_action"],
                    "fingerprint": change["fingerprint"],
                },
            )
            db.add(violation)

            alert = Alert(
                account_id=account_id,
                title=f"API spec drift: {change['id']} on {change['path']}",
                message=change["message"],
                severity=change["severity"],
                category="API_DRIFT",
                endpoint=change["path"],
                status="OPEN",
            )
            db.add(alert)
            await db.flush()

            db.add(EvidenceRecord(
                account_id=account_id,
                evidence_type="drift",
                ref_id=alert.id,
                endpoint_id=endpoint_id,
                severity=change["severity"],
                summary=change["message"],
                details={
                    "change_id": change["id"],
                    "component": change["component"],
                    "path": change["path"],
                    "method": change["method"],
                    "why_it_matters": change["why_it_matters"],
                    "recommended_action": change["recommended_action"],
                },
            ))

    @staticmethod
    async def _resolve_endpoint_id(db, account_id: int, path: str, method: str | None) -> str | None:
        from server.models.core import APIEndpoint

        result = await db.execute(
            select(APIEndpoint).where(
                APIEndpoint.account_id == account_id,
                APIEndpoint.path == path,
            )
        )
        candidates = result.scalars().all()
        if not candidates:
            return None
        if method is None:
            return candidates[0].id
        for endpoint in candidates:
            if (endpoint.method or "").upper() == method.upper():
                return endpoint.id
        return candidates[0].id
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_openapi_drift.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add server/modules/scheduler/openapi_drift.py tests/unit/test_openapi_drift.py
git commit -m "feat: raise PolicyViolation+Alert+EvidenceRecord findings on API drift"
```

---

### Task 4: Wire into app startup + error isolation

**Files:**
- Modify: `server/api/main.py` (the startup-components block, around lines 150-186 — same block that wires `ContinuousTestingProcessor`)
- Test: `tests/unit/test_openapi_drift.py`

**Interfaces:**
- Consumes: the `components.append(("name", start_fn, stop_fn))` pattern already used for every other background processor in this file.

- [ ] **Step 1: Write the failing test for per-account error isolation**

Add to `tests/unit/test_openapi_drift.py`:

```python
@pytest.mark.asyncio
async def test_sweep_continues_when_one_account_errors(monkeypatch):
    from server.config import settings
    from server.modules.scheduler.openapi_drift import OpenAPIDriftProcessor

    monkeypatch.setattr(settings, "OPENAPI_DRIFT_ENABLED", True)
    proc = OpenAPIDriftProcessor()

    async def fake_accounts():
        return [1, 2]

    async def flaky_check(account_id):
        if account_id == 1:
            raise RuntimeError("boom")
        return {"status": "unchanged"}

    monkeypatch.setattr(proc, "_accounts_with_endpoints", fake_accounts)
    monkeypatch.setattr(proc, "_check_account", flaky_check)

    result = await proc.sweep()
    assert result["status"] == "ok"
    assert result["accounts_checked"] == 2
    assert result["accounts_drifted"] == 0
```

Note: `_accounts_with_endpoints` is a `@staticmethod` in Task 1 — `monkeypatch.setattr(proc, "_accounts_with_endpoints", fake_accounts)` still works because it patches the instance attribute, shadowing the staticmethod for this `proc` instance.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_openapi_drift.py::test_sweep_continues_when_one_account_errors -v`
Expected: this should actually already PASS if Task 1's `sweep()` was written correctly with the try/except per account — if it fails, the bug is in `sweep()`'s error handling from Task 1; fix it to match the try/except-per-account shape shown in Task 1 Step 4 before continuing.

- [ ] **Step 3: Wire the processor into app startup**

In `server/api/main.py`, add the import near the existing `from server.modules.scheduler.continuous_testing import ContinuousTestingProcessor` line (around line 29):

```python
from server.modules.scheduler.openapi_drift import OpenAPIDriftProcessor
```

Add this block immediately after the existing continuous-testing block (around line 176, right after its `components.append(...)` call):

```python
    if settings.STARTUP_ENABLE_OPENAPI_DRIFT and settings.OPENAPI_DRIFT_ENABLED:
        openapi_drift = OpenAPIDriftProcessor(
            interval_sec=settings.OPENAPI_DRIFT_SWEEP_INTERVAL_SECONDS
        )
        components.append(
            ("openapi_drift", openapi_drift.start, openapi_drift.stop)
        )
```

- [ ] **Step 4: Run the full test file to verify nothing broke**

Run: `python -m pytest tests/unit/test_openapi_drift.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Run the full backend unit suite to verify no regressions**

Run: `python -m pytest tests/unit/ -q`
Expected: all tests pass (837 passed before this change; should be 843 after — 6 new tests, 0 removed)

- [ ] **Step 6: Commit**

```bash
git add server/api/main.py tests/unit/test_openapi_drift.py
git commit -m "feat: wire OpenAPIDriftProcessor into app startup (gated, off by default)"
```

---

### Task 5: Frontend service + hook layer

**Files:**
- Create: `api-sentinel-view-main/src/services/openapi.service.ts`
- Create: `api-sentinel-view-main/src/hooks/use-openapi-docs.ts`
- Test: `api-sentinel-view-main/src/services/openapi.service.test.ts`

**Interfaces:**
- Consumes: `get<T>(path: string, signal?: AbortSignal): Promise<T>` and `post<T>(path: string, body?: object, signal?: AbortSignal): Promise<T>` from `@/lib/api-client`.
- Produces: `fetchLatestSpec(signal?)`, `fetchSpecHistory(limit?, signal?)`, `diffSpecs(baseSpecId, revisionSpecId, signal?)`, `fetchSchemaViolations(limit?, signal?)` — all exported from `openapi.service.ts`. `useLatestSpec()`, `useSpecHistory(limit?)`, `useSpecDiff(baseSpecId, revisionSpecId)`, `useSchemaViolations(limit?)` — all exported from `use-openapi-docs.ts`, each a thin `useQuery` wrapper with `queryKey: ['openapi', ...]`.

- [ ] **Step 1: Write the failing test**

Create `api-sentinel-view-main/src/services/openapi.service.test.ts`:

```typescript
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fetchLatestSpec, fetchSpecHistory, diffSpecs, fetchSchemaViolations } from './openapi.service';

const jsonResponse = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

describe('openapi.service', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockResolvedValue(jsonResponse({ status: 'ok' }));
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    fetchMock.mockReset();
  });

  it('fetches the latest spec', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: 'spec-1', spec: { paths: {} } }));
    const result = await fetchLatestSpec();
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:3000/api/openapi/latest',
      expect.objectContaining({ method: 'GET', credentials: 'include' }),
    );
    expect(result.id).toBe('spec-1');
  });

  it('fetches spec history with a limit', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, specs: [] }));
    await fetchSpecHistory(10);
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:3000/api/openapi/history?limit=10',
      expect.objectContaining({ method: 'GET', credentials: 'include' }),
    );
  });

  it('diffs two spec versions', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ summary: {}, breaking_changes: [], recommendations: [] }));
    await diffSpecs('base-1', 'rev-1');
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:3000/api/openapi/diff',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify({ base_spec_id: 'base-1', revision_spec_id: 'rev-1' }),
      }),
    );
  });

  it('fetches schema violations', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, violations: [] }));
    await fetchSchemaViolations();
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:3000/api/openapi/violations',
      expect.objectContaining({ method: 'GET', credentials: 'include' }),
    );
  });
});
```

(URLs use `localhost:3000` because that's the jsdom test-environment default origin — the same convention already established in `src/services/discovery.service.test.ts` and `src/services/security-ops.service.test.ts`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd api-sentinel-view-main && npx vitest run src/services/openapi.service.test.ts`
Expected: FAIL — `Failed to resolve import "./openapi.service"`

- [ ] **Step 3: Write the service**

Create `api-sentinel-view-main/src/services/openapi.service.ts`:

```typescript
import { get, post } from '@/lib/api-client';

export interface OpenAPISpecSummary {
  id: string;
  spec: { paths?: Record<string, unknown>; [key: string]: unknown };
}

export interface OpenAPISpecHistoryEntry {
  id: string;
  version: string;
  path_count: number;
  created_at: string | null;
}

export interface OpenAPISpecHistoryResponse {
  total: number;
  specs: OpenAPISpecHistoryEntry[];
}

export interface OpenAPIDiffChange {
  id: string;
  severity: string;
  path: string;
  method: string | null;
  component: string;
  message: string;
  why_it_matters: string;
  recommended_action: string;
  details: Record<string, unknown>;
  fingerprint: string;
}

export interface OpenAPIDiffResponse {
  base_spec_id?: string;
  revision_spec_id?: string;
  summary: Record<string, number>;
  breaking_changes: OpenAPIDiffChange[];
  recommendations: unknown[];
}

export interface SchemaViolation {
  id: string;
  endpoint: string;
  method: string;
  violation_type: string;
  field: string;
  expected: string;
  actual: string;
  severity: 'high' | 'medium' | 'low';
  count: number;
  last_seen: string | null;
}

export interface SchemaViolationsResponse {
  total: number;
  violations: SchemaViolation[];
}

export function fetchLatestSpec(signal?: AbortSignal): Promise<OpenAPISpecSummary> {
  return get<OpenAPISpecSummary>('/openapi/latest', signal);
}

export function fetchSpecHistory(limit = 10, signal?: AbortSignal): Promise<OpenAPISpecHistoryResponse> {
  return get<OpenAPISpecHistoryResponse>(`/openapi/history?limit=${limit}`, signal);
}

export function diffSpecs(
  baseSpecId: string,
  revisionSpecId: string,
  signal?: AbortSignal,
): Promise<OpenAPIDiffResponse> {
  return post<OpenAPIDiffResponse>(
    '/openapi/diff',
    { base_spec_id: baseSpecId, revision_spec_id: revisionSpecId },
    signal,
  );
}

export function fetchSchemaViolations(limit = 50, signal?: AbortSignal): Promise<SchemaViolationsResponse> {
  return get<SchemaViolationsResponse>(`/openapi/violations?limit=${limit}`, signal);
}
```

Note: `post<T>()`'s third parameter in `@/lib/api-client` is `signal?: AbortSignal` (positional, matching the existing `post<T>(path, body?, signal?)` signature) — do not pass an options object.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd api-sentinel-view-main && npx vitest run src/services/openapi.service.test.ts`
Expected: All 4 tests PASS

- [ ] **Step 5: Write the hook file (no test needed — thin wrapper, covered by the page test in Task 6)**

Create `api-sentinel-view-main/src/hooks/use-openapi-docs.ts`:

```typescript
import { useQuery } from '@tanstack/react-query';
import {
  fetchLatestSpec,
  fetchSpecHistory,
  diffSpecs,
  fetchSchemaViolations,
} from '@/services/openapi.service';

export function useLatestSpec() {
  return useQuery({
    queryKey: ['openapi', 'latest'],
    queryFn: ({ signal }) => fetchLatestSpec(signal).catch(() => null),
    retry: false,
  });
}

export function useSpecHistory(limit = 10) {
  return useQuery({
    queryKey: ['openapi', 'history', limit],
    queryFn: ({ signal }) => fetchSpecHistory(limit, signal),
    retry: false,
  });
}

export function useSpecDiff(baseSpecId: string | null, revisionSpecId: string | null) {
  return useQuery({
    queryKey: ['openapi', 'diff', baseSpecId, revisionSpecId],
    queryFn: ({ signal }) => diffSpecs(baseSpecId!, revisionSpecId!, signal),
    enabled: Boolean(baseSpecId && revisionSpecId),
    retry: false,
  });
}

export function useSchemaViolations(limit = 50) {
  return useQuery({
    queryKey: ['openapi', 'violations', limit],
    queryFn: ({ signal }) => fetchSchemaViolations(limit, signal).catch(() => null),
    retry: false,
  });
}
```

- [ ] **Step 6: Run tsc to verify no type errors**

Run: `cd api-sentinel-view-main && node_modules/.bin/tsc --noEmit -p tsconfig.app.json`
Expected: no output, exit code 0

- [ ] **Step 7: Commit**

```bash
git add api-sentinel-view-main/src/services/openapi.service.ts api-sentinel-view-main/src/services/openapi.service.test.ts api-sentinel-view-main/src/hooks/use-openapi-docs.ts
git commit -m "feat: add openapi.service + use-openapi-docs hooks for spec/history/diff/violations"
```

---

### Task 6: Enhance the Schema Validation page with spec summary, history, and diff viewer

**Files:**
- Modify: `api-sentinel-view-main/src/customer/pages/discovery/SchemaValidation.tsx`

**Interfaces:**
- Consumes: `useLatestSpec()`, `useSpecHistory()`, `useSpecDiff()`, `useSchemaViolations()` from `@/hooks/use-openapi-docs` (Task 5). `EvidencePanel` (`{exhibit?, className?, style?, children}`), `EvidenceSectionHead` (`{code, title, desc?, action?}`), `EvidenceStatLine` (`{label, value, dot?}`), `EvidenceBadge` (`{children, color}`) from `@/components/ui/EvidencePanel`, `@/components/ui/EvidenceSectionHead`, `@/components/ui/EvidenceStatLine`.

- [ ] **Step 1: Replace the inline `/openapi/violations` fetch with the new hook**

In `SchemaValidation.tsx`, replace:

```tsx
import { useQuery } from '@tanstack/react-query';
import { get, post } from '@/lib/api-client';
```

with:

```tsx
import { useState } from 'react';
import { useLatestSpec, useSpecHistory, useSpecDiff, useSchemaViolations } from '@/hooks/use-openapi-docs';
import EvidencePanel from '@/components/ui/EvidencePanel';
import EvidenceSectionHead from '@/components/ui/EvidenceSectionHead';
import { EvidenceStatLine } from '@/components/ui/EvidenceStatLine';
import { EvidenceBadge } from '@/components/ui/EvidenceStatLine';
```

Remove the old `interface SchemaViolation { ... }` block (it now lives in `openapi.service.ts` and is imported implicitly through the hook's return type) — keep everything else in the file (`VIOLATION_TYPE_LABELS`, `methodColor`, `sevBadge`, `ViolationRow`) unchanged.

Replace the `const { data } = useQuery({...})` block and the two lines after it with:

```tsx
  const { data } = useSchemaViolations();
  const violations = data?.violations || [];
```

- [ ] **Step 2: Add spec summary + version history + diff viewer sections**

Add this new component above `export default function SchemaValidation()`:

```tsx
function SpecAndDriftSection() {
  const { data: latest } = useLatestSpec();
  const { data: history } = useSpecHistory();
  const [baseId, setBaseId] = useState<string | null>(null);
  const [revisionId, setRevisionId] = useState<string | null>(null);
  const { data: diff } = useSpecDiff(baseId, revisionId);

  const pathCount = latest?.spec?.paths ? Object.keys(latest.spec.paths).length : 0;

  return (
    <EvidencePanel exhibit="EXH-DOC">
      <EvidenceSectionHead code="§DOC" title="API Documentation & Drift" desc="AUTO-GENERATED FROM OBSERVED TRAFFIC" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
        <div>
          <EvidenceStatLine label="Current Spec Paths" value={pathCount} />
          <EvidenceStatLine label="Versions Stored" value={history?.total ?? 0} />
        </div>
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-text-muted mb-2">Version History</p>
          <div className="space-y-1 max-h-32 overflow-auto">
            {(history?.specs ?? []).map((spec) => (
              <button
                key={spec.id}
                className="w-full flex items-center justify-between text-xs px-2 py-1 rounded hover:bg-bg-elevated"
                onClick={() => {
                  if (!baseId) setBaseId(spec.id);
                  else setRevisionId(spec.id);
                }}
              >
                <span className="font-mono">{spec.id.slice(0, 8)}</span>
                <span className="text-text-muted">{spec.path_count} paths</span>
              </button>
            ))}
          </div>
          {baseId && revisionId && (
            <button
              className="text-[10px] text-brand mt-1"
              onClick={() => { setBaseId(null); setRevisionId(null); }}
            >
              Clear selection
            </button>
          )}
        </div>
      </div>

      {diff && (
        <div className="mt-4 space-y-2">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-text-muted">
            Diff: {diff.breaking_changes.length} change(s)
          </p>
          {diff.breaking_changes.map((change) => (
            <div key={change.fingerprint} className="flex items-start gap-2 text-xs border-t border-border-subtle pt-2">
              <EvidenceBadge color={change.severity === 'CRITICAL' || change.severity === 'HIGH' ? '#D63D2F' : '#D4A017'}>
                {change.severity}
              </EvidenceBadge>
              <div>
                <p className="font-mono">{change.method ? `${change.method.toUpperCase()} ` : ''}{change.path}</p>
                <p className="text-text-muted">{change.message}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </EvidencePanel>
  );
}
```

- [ ] **Step 3: Render it in the page**

In `SchemaValidation`'s return statement, add `<SpecAndDriftSection />` right after the header block (after the closing `</div>` of the `flex items-center justify-between` header, before the `{/* KPI row */}` comment):

```tsx
      <SpecAndDriftSection />

      {/* KPI row */}
```

- [ ] **Step 4: Run tsc to verify no type errors**

Run: `cd api-sentinel-view-main && node_modules/.bin/tsc --noEmit -p tsconfig.app.json`
Expected: no output, exit code 0

- [ ] **Step 5: Run the frontend test suite to verify no regressions**

Run: `cd api-sentinel-view-main && npx vitest run`
Expected: all tests pass (29 passed before this task, 33 after — 4 new from Task 5's `openapi.service.test.ts`)

- [ ] **Step 6: Live browser check**

Start the dev server (`preview_start` with the `frontend` launch config), navigate to `/app/discovery/schema`, confirm:
- Page loads with no console errors
- "API Documentation & Drift" panel renders with a path count and version history list (will show 0/empty on a fresh dev DB — that's correct, not a bug)

- [ ] **Step 7: Commit**

```bash
git add api-sentinel-view-main/src/customer/pages/discovery/SchemaValidation.tsx
git commit -m "feat: surface spec summary, version history, and drift diff on Schema Validation page"
```

---

## Self-Review

**Spec coverage:**
- Automated scheduled regeneration → Task 1, 4
- Drift diffing against last version → Task 2
- Findings persisted on drift (PolicyViolation+Alert+EvidenceRecord, no new tables) → Task 3
- Config additions → Task 1
- Startup wiring → Task 4
- Frontend spec summary/history/diff viewer → Task 5, 6
- Explicit non-goals (event-driven trigger, new WSEventType) → not built, correctly absent from every task

**Placeholder scan:** No TBD/TODO; every step has real, complete code matching the actual model fields and function signatures read from the codebase (not assumed).

**Type consistency:** `_check_account` (Task 2) is called by `sweep()` (Task 1) with a single `account_id: int` arg — matches. `_check_account_with_session` (Task 2) takes `(db, account_id)` and is reused directly by Task 3's `_raise_drift_findings` wiring — matches. Frontend hook return shapes (Task 5) match what Task 6's component destructures (`data?.paths`, `history?.specs`, `diff?.breaking_changes`) — matches the `OpenAPISpecSummary`/`OpenAPISpecHistoryResponse`/`OpenAPIDiffResponse` interfaces defined in the same task.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-01-openapi-drift-detection-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
