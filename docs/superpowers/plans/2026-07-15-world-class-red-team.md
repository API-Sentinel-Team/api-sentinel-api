# World-Class Red Team Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the gap between what the code does in a default scan and what the North Star promises — four tiers covering wiring, evidence quality, identity depth, and measurement.

**Architecture:** Tier 1 removes wiring bugs (detectors stranded behind an LLM flag, BOLA replay absent from default plan, broken pytest rootdir). Tier 2 upgrades external-engine evidence from synthetic to real. Tier 3 deepens red-team capability (identity matrix, BFLA function matrix, business-logic execution, blind SQLi). Tier 4 closes test coverage gaps.

**Tech Stack:** Python 3.11, FastAPI, SQLAlchemy 2.x async, pytest, Alembic migrations, httpx, nuclei/schemathesis/zap subprocess wrappers.

## Global Constraints

- Never add `--no-verify` to git commands.
- All new async functions must be `async def` and tested with `pytest-asyncio`.
- No plaintext secrets in tests — use placeholder strings like `"Bearer test-token"`.
- Run `python -m pytest tests/unit -q --no-header` to verify the suite stays green after each task.
- Keep existing 739 passing tests green. If a test breaks, fix the test or the code — never delete the test.
- Do NOT touch `.env`. That is the operator's responsibility.

---

## Task 1: Fix pytest rootdir so benchmark tests are importable

**Files:**
- Create: `pytest.ini` at repo root

**Interfaces:**
- Consumes: nothing (infrastructure fix)
- Produces: `pytest tests/unit` passes cleanly without collection errors; `from tests.benchmark.corpus import ...` resolves

The collection error is `ModuleNotFoundError: No module named 'tests.benchmark'` because the repo root is not on `sys.path` during collection. `pytest.ini` with `pythonpath = .` fixes this without touching `__init__.py` files or breaking the existing 739 tests.

- [ ] **Step 1: Verify current breakage**

Run:
```
python -m pytest tests/unit/test_benchmark_runner.py tests/unit/test_benchmark_scoring.py tests/unit/test_crapi_corpus.py -q --no-header 2>&1 | head -20
```
Expected: `ERROR … ModuleNotFoundError: No module named 'tests.benchmark'`

- [ ] **Step 2: Create pytest.ini**

Create `pytest.ini` at repo root:
```ini
[pytest]
pythonpath = .
asyncio_mode = auto
```

`pythonpath = .` adds the repo root to `sys.path`. `asyncio_mode = auto` eliminates the need for `@pytest.mark.asyncio` on every async test (the existing `@pytest_asyncio.fixture` decorators are unaffected).

- [ ] **Step 3: Run full unit suite to confirm no regressions**

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```
Expected: all previously passing tests still pass, benchmark files now collect.

- [ ] **Step 4: Commit**

```bash
git add pytest.ini
git commit -m "fix: add pytest.ini so tests.benchmark is importable from rootdir"
```

---

## Task 2: Un-strand deterministic detectors from AGENTIC_LLM_ENABLED gate

**Files:**
- Modify: `server/modules/agentic/orchestration.py` (restructure `run_agentic_scan_async`)
- Modify: `tests/unit/test_agentic_orchestration.py` (add tests for disabled-LLM path returning findings)

**Interfaces:**
- Consumes: `_run_attack_chains`, `_run_targeted_detectors` (already exist in same file)
- Produces: `run_agentic_scan_async` returns `chain_findings` and `detector_findings` keys even when `AGENTIC_LLM_ENABLED=False`

The current `run_agentic_scan_async` early-returns at line 120-126 when the LLM is disabled. The call sites for `_run_attack_chains` (line 166) and `_run_targeted_detectors` (line 186) are after that return — so in the default configuration (LLM off), none of the BOLA replay, mass-assignment, SQLi, or sensitive-exposure detection runs. None of these detectors need an LLM. The fix is to move them before the gate.

- [ ] **Step 1: Write failing test**

Add to `tests/unit/test_agentic_orchestration.py`:

```python
import pytest

_TWO_ACCOUNTS = [
    type("A", (), {"auth_headers": {"Authorization": "Bearer victim"}, "auth_token": None, "role": "MEMBER", "name": "victim"})(),
    type("A", (), {"auth_headers": {"Authorization": "Bearer attacker"}, "auth_token": None, "role": "MEMBER", "name": "attacker"})(),
]


class _DisabledSettingsWithAllow:
    AGENTIC_LLM_ENABLED = False
    PENTEST_TARGET_ALLOWLIST = ""
    PENTEST_ALLOW_PRIVATE_TARGETS = True
    PENTEST_ENFORCE_TARGET_GUARD = True
    PENTEST_RESOLVE_TARGET_HOSTS = False
    PENTEST_FAIL_CLOSED_ON_TARGET_DNS_ERROR = True
    DEBUG = True


@pytest.mark.asyncio
async def test_deterministic_detectors_run_when_llm_disabled():
    """detector_findings and chain_findings must be present even when AGENTIC_LLM_ENABLED=False."""
    from server.modules.agentic.orchestration import run_agentic_scan_async

    class _FakeEngine:
        async def execute_test(self, endpoint, template, **_):
            return {"is_vulnerable": False}

    result = await run_agentic_scan_async(
        engine=_FakeEngine(),
        endpoints=_ENDPOINTS,
        templates=[],
        settings=_DisabledSettingsWithAllow(),
        test_accounts=_TWO_ACCOUNTS,
    )
    assert result["enabled"] is False
    assert "chain_findings" in result, "chain_findings must be present even when LLM disabled"
    assert "detector_findings" in result, "detector_findings must be present even when LLM disabled"
```

Run:
```
python -m pytest tests/unit/test_agentic_orchestration.py::test_deterministic_detectors_run_when_llm_disabled -xvs 2>&1 | tail -15
```
Expected: FAIL with `KeyError: 'chain_findings'` or `AssertionError`.

- [ ] **Step 2: Restructure `run_agentic_scan_async` in `orchestration.py`**

Replace the entire body of `run_agentic_scan_async` (lines 92-196) with the restructured version where deterministic detectors come first:

```python
async def run_agentic_scan_async(
    *,
    engine: Any,
    endpoints: list[dict[str, Any]],
    templates: list[dict[str, Any]],
    settings: Any = None,
    existing_graph: KnowledgeGraph | None = None,
    prior_findings: list[dict[str, Any]] | None = None,
    selection_context_by_endpoint: dict[str, dict[str, Any]] | None = None,
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
    test_accounts: list[Any] | None = None,
    llm_client: Any = None,
) -> dict[str, Any]:
    """Run the agentic loop wired to the live ExecutionEngine (async, on-loop).

    Deterministic detectors (attack chains, targeted detectors) always run
    regardless of AGENTIC_LLM_ENABLED. The LLM proposer loop is the only
    part that is gated.
    """
    if settings is None:
        from server.config import settings as default_settings

        settings = default_settings

    graph = (existing_graph or KnowledgeGraph()).merge(build_from_endpoints(endpoints))

    # ── ALWAYS: deterministic multi-step attack chains (no LLM needed) ────────
    chain_findings: list[dict[str, Any]] = []
    if test_accounts and len(test_accounts) >= 2:
        chain_findings = await _run_attack_chains(
            graph=graph,
            endpoints=endpoints,
            victim=test_accounts[0],
            attacker=test_accounts[1],
            settings=settings,
            allow_state_change=allow_state_change,
            allow_destructive_methods=allow_destructive_methods,
        )
        for finding in chain_findings:
            graph.ingest_finding(finding)

    # ── ALWAYS: deterministic single-endpoint detectors (no LLM needed) ───────
    detector_findings = await _run_targeted_detectors(
        endpoints=endpoints,
        settings=settings,
        allow_state_change=allow_state_change,
    )
    for finding in detector_findings:
        graph.ingest_finding(finding)

    # ── LLM proposer loop (gated by AGENTIC_LLM_ENABLED, off by default) ──────
    if not bool(getattr(settings, "AGENTIC_LLM_ENABLED", False)):
        return {
            "enabled": False,
            "reason": "agentic_llm_disabled",
            "outcome": LoopOutcome(model_name="disabled").as_dict(),
            "chain_findings": chain_findings,
            "detector_findings": detector_findings,
            "graph": graph.as_dict(),
        }

    from server.modules.agentic.scan_adapter import make_async_scan_executor, scan_judge
    from server.modules.test_executor.target_guard import TargetGuard

    client = llm_client or build_llm_client(settings)
    guard = make_guard(
        target_guard=TargetGuard.from_settings(settings),
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )
    executor = make_async_scan_executor(
        engine=engine,
        templates=templates,
        selection_context_by_endpoint=selection_context_by_endpoint,
        test_accounts=test_accounts,
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )

    outcome = await run_proposer_confirmer_async(
        llm_client=client,
        endpoints=graph.recon_context(),
        guard=guard,
        executor=executor,
        judge=scan_judge,
        max_rounds=int(getattr(settings, "AGENTIC_LOOP_MAX_ROUNDS", 3)),
        prior_findings=prior_findings,
    )

    for finding in outcome.confirmed_findings:
        graph.ingest_finding(finding)

    return {
        "enabled": True,
        "outcome": outcome.as_dict(),
        "chain_findings": chain_findings,
        "detector_findings": detector_findings,
        "graph": graph.as_dict(),
    }
```

- [ ] **Step 3: Run failing test to verify it now passes**

```
python -m pytest tests/unit/test_agentic_orchestration.py -xvs 2>&1 | tail -15
```
Expected: all tests in file pass.

- [ ] **Step 4: Run full unit suite to confirm no regressions**

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```
Expected: same number of passes as before (±0 failures).

- [ ] **Step 5: Commit**

```bash
git add server/modules/agentic/orchestration.py tests/unit/test_agentic_orchestration.py
git commit -m "fix: run deterministic detectors regardless of AGENTIC_LLM_ENABLED gate"
```

---

## Task 3: Add authorization_replay to default engine plan

**Files:**
- Modify: `server/modules/pentest/engine_plan.py`
- Modify: `server/api/routers/pentest.py` (3 call sites: lines 852, 1104, 1479)
- Modify: `server/api/routers/tests.py` (1 call site: line 528)
- Modify: `server/modules/pentest/orchestrator.py` (1 call site: line 105)
- Modify: `tests/unit/test_scan_plan.py` → actually tests are in `test_agentic_scan_adapter.py` and `test_reporting.py` — add a test to `tests/unit/test_agentic_scan_adapter.py`

**Interfaces:**
- Consumes: `build_engine_plan(...)` with new `test_accounts_count: int = 0` param
- Produces: engine plan includes `authorization_replay` entry; `status="ready"` when `test_accounts_count >= 2`

- [ ] **Step 1: Write failing test**

Add to `tests/unit/test_agentic_scan_adapter.py`:

```python
def test_engine_plan_includes_authorization_replay_when_accounts_available():
    from server.modules.pentest.engine_plan import build_engine_plan
    from types import SimpleNamespace

    profile = SimpleNamespace(
        schemathesis_enabled=False, nuclei_enabled=False, zap_enabled=False
    )
    plan = build_engine_plan(
        profile=profile,
        auth_profile=None,
        has_openapi_spec=False,
        schemathesis_available=False,
        test_accounts_count=2,
    )
    engines = {e["engine"]: e for e in plan}
    assert "authorization_replay" in engines
    assert engines["authorization_replay"]["status"] == "ready"


def test_engine_plan_authorization_replay_blocked_with_single_account():
    from server.modules.pentest.engine_plan import build_engine_plan
    from types import SimpleNamespace

    profile = SimpleNamespace(
        schemathesis_enabled=False, nuclei_enabled=False, zap_enabled=False
    )
    plan = build_engine_plan(
        profile=profile,
        auth_profile=None,
        has_openapi_spec=False,
        schemathesis_available=False,
        test_accounts_count=1,
    )
    engines = {e["engine"]: e for e in plan}
    assert engines["authorization_replay"]["status"] == "blocked"
    assert engines["authorization_replay"]["reason"] == "requires_two_test_accounts"
```

Run:
```
python -m pytest tests/unit/test_agentic_scan_adapter.py -xvs -k "engine_plan" 2>&1 | tail -15
```
Expected: FAIL with `TypeError: build_engine_plan() got an unexpected keyword argument 'test_accounts_count'`.

- [ ] **Step 2: Update `build_engine_plan` signature and add the entry**

In `server/modules/pentest/engine_plan.py`:

Change line 13 `ENGINE_EXECUTION_ORDER`:
```python
ENGINE_EXECUTION_ORDER = ("templates", "authorization_replay", "schemathesis", "nuclei", "zap", "passive")
```

Change `build_engine_plan` signature at line 16 to add `test_accounts_count: int = 0`:
```python
def build_engine_plan(
    *,
    profile: Any,
    auth_profile: Any | None,
    has_openapi_spec: bool,
    schemathesis_available: bool,
    nuclei_available: bool = True,
    zap_available: bool = True,
    require_authenticated_active_scan: bool = False,
    test_accounts_count: int = 0,
) -> list[dict[str, Any]]:
```

Add the `authorization_replay` entry to the returned list after the `templates` entry (after line 46):
```python
        {
            "engine": "authorization_replay",
            "display_name": "Multi-Identity Authorization Replay",
            "enabled": True,
            "status": "ready" if test_accounts_count >= 2 else "blocked",
            "reason": "identity_matrix_ready" if test_accounts_count >= 2 else "requires_two_test_accounts",
            "requires_auth_profile": False,
            "requires_openapi_spec": False,
            "artifact_type": None,
            "runtime_available": True,
        },
```

- [ ] **Step 3: Update call sites (all use keyword args — only need to add `test_accounts_count` where accounts are loaded)**

In `server/api/routers/tests.py:528` — check if `test_accounts` list exists in scope there and pass `len(test_accounts)`:
```python
scan_plan["engine_plan"] = build_engine_plan(
    ...,  # existing kwargs
    test_accounts_count=len(test_accounts) if test_accounts else 0,
)
```

In `server/api/routers/pentest.py:852`, `1104`, `1479` — pentest router doesn't use TestAccounts so pass `test_accounts_count=0` (default, no change needed since it defaults to 0).

In `server/modules/pentest/orchestrator.py:105` — same, default 0 is fine.

All 4 non-tests.py call sites already default to `test_accounts_count=0` via the new default parameter — no change needed there. Only `tests.py:528` needs the explicit count.

- [ ] **Step 4: Run tests**

```
python -m pytest tests/unit/test_agentic_scan_adapter.py -xvs -k "engine_plan" 2>&1 | tail -15
```
Expected: PASS.

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```
Expected: no regressions.

- [ ] **Step 5: Commit**

```bash
git add server/modules/pentest/engine_plan.py server/api/routers/tests.py tests/unit/test_agentic_scan_adapter.py
git commit -m "feat: add authorization_replay engine to default scan plan when >=2 test accounts"
```

---

## Task 4: Fix nuclei status_code=0 and expose curl-command as sent_request

**Files:**
- Modify: `server/modules/nuclei/findings.py` (`_nuclei_received_response`, `build_nuclei_vulnerability_data`)
- Modify: `tests/unit/test_nuclei_findings.py` (update/add test for real status code and curl extraction)

**Interfaces:**
- Consumes: `nuclei` JSON finding dict with optional `status-code`, `curl-command`, `request` fields
- Produces: `received_response.status_code` is the real HTTP int or absent (not 0); `sent_request` built from nuclei's `curl-command` or `request` field when present

- [ ] **Step 1: Write failing tests**

Add to `tests/unit/test_nuclei_findings.py`:

```python
def test_nuclei_finding_status_code_absent_when_not_in_nuclei_output():
    from server.modules.nuclei.findings import build_nuclei_vulnerability_data
    finding = {
        "template-id": "xss-reflected",
        "info": {"name": "XSS", "severity": "HIGH"},
        "matched-at": "https://api.example.com/search",
        # no status-code field
    }
    data = build_nuclei_vulnerability_data(finding, account_id=1, target="https://api.example.com")
    status = data["evidence"].get("received_response", {}).get("status_code")
    assert status is None or status == 0, "status_code should not be set to 0 masquerading as real"
    # The real fix: when nuclei didn't report a status code, don't include it
    assert status is None, "absent status_code must not become 0 in evidence"


def test_nuclei_finding_curl_command_used_as_sent_request():
    from server.modules.nuclei.findings import build_nuclei_vulnerability_data
    finding = {
        "template-id": "auth-bypass",
        "info": {"name": "Auth Bypass", "severity": "CRITICAL"},
        "matched-at": "https://api.example.com/admin",
        "status-code": 200,
        "curl-command": "curl -i -X GET 'https://api.example.com/admin' -H 'Authorization: Bearer REDACTED'",
    }
    data = build_nuclei_vulnerability_data(finding, account_id=1, target="https://api.example.com")
    sent = data["evidence"].get("sent_request", {})
    # curl-command present: sent_request should reflect it rather than bare method+url
    assert sent.get("method") == "GET"
    assert "api.example.com/admin" in sent.get("url", "")
```

Run: expected FAIL on `status is None` assertion.

- [ ] **Step 2: Fix `_nuclei_received_response` to not force status_code to 0**

In `server/modules/nuclei/findings.py`, replace `_nuclei_received_response`:

```python
def _nuclei_received_response(finding: dict[str, Any]) -> dict[str, Any]:
    response: dict[str, Any] = {}
    raw_status = finding.get("status-code") or finding.get("status_code") or finding.get("response-status-code")
    if raw_status is not None:
        try:
            code = int(raw_status)
            if code > 0:
                response["status_code"] = code
        except (TypeError, ValueError):
            pass

    body = finding.get("response") or finding.get("response-body") or finding.get("extracted-results")
    if body not in (None, "", []):
        response["body"] = body
    return response
```

- [ ] **Step 3: Extract `curl-command` as `sent_request` in `build_nuclei_vulnerability_data`**

In `build_nuclei_vulnerability_data`, before the `evidence = finalize_finding_evidence(...)` call, extract the curl command and build a `sent_request` dict from it:

```python
# Extract real request from nuclei output when available
sent_request: dict[str, Any] | None = None
curl_cmd = finding.get("curl-command") or finding.get("curl_command")
raw_request = finding.get("request")
if curl_cmd and isinstance(curl_cmd, str):
    # Parse method and URL from nuclei curl-command: "curl -i -X METHOD 'URL' ..."
    import re as _re
    m = _re.search(r"-X\s+(\w+)\s+['\"]?(https?://[^\s'\"]+)", curl_cmd)
    if m:
        sent_request = {"method": m.group(1).upper(), "url": m.group(2), "curl_source": "nuclei"}
elif raw_request and isinstance(raw_request, str):
    # nuclei sometimes outputs raw HTTP request bytes
    first_line = raw_request.split("\n", 1)[0].strip()
    parts = first_line.split(" ")
    if len(parts) >= 2:
        sent_request = {"method": parts[0].upper(), "url": evidence_url, "raw_request": True}
```

Then pass `sent_request=sent_request` to `finalize_finding_evidence(...)`.

- [ ] **Step 4: Run tests**

```
python -m pytest tests/unit/test_nuclei_findings.py -xvs 2>&1 | tail -20
```
Expected: all pass.

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```

- [ ] **Step 5: Commit**

```bash
git add server/modules/nuclei/findings.py tests/unit/test_nuclei_findings.py
git commit -m "fix: nuclei evidence uses real status_code and curl-command instead of defaults"
```

---

## Task 5: Extract real request/response from Schemathesis JUnit XML

**Files:**
- Modify: `server/modules/schemathesis/findings.py` (add `_extract_request_response_from_failure`)
- Modify: `tests/unit/test_schemathesis_findings.py`

**Interfaces:**
- Consumes: JUnit XML `failure` element text/`system-out` containing `Request:` and `Response:` blocks
- Produces: `sent_request` with method+url+headers (extracted), `received_response` with status_code+body

- [ ] **Step 1: Write failing test**

Add to `tests/unit/test_schemathesis_findings.py`:

```python
def test_schemathesis_finding_extracts_real_status_code_from_failure_text():
    from server.modules.schemathesis.findings import _extract_schemathesis_request_response
    failure_text = (
        "AssertionError: Response violates schema\n"
        "Request: POST /api/users HTTP/1.1\n"
        "Authorization: Bearer test\n\n"
        "{\"username\":\"x\"}\n\n"
        "Response: HTTP/1.1 500 Internal Server Error\n"
        "Content-Type: application/json\n\n"
        "{\"error\":\"crash\"}"
    )
    req, resp = _extract_schemathesis_request_response(failure_text, base_url="https://api.example.com")
    assert req["method"] == "POST"
    assert resp.get("status_code") == 500


def test_schemathesis_finding_falls_back_gracefully_when_no_http_block():
    from server.modules.schemathesis.findings import _extract_schemathesis_request_response
    req, resp = _extract_schemathesis_request_response("Some generic failure", base_url="https://api.example.com/api/users")
    assert req["method"] in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    assert isinstance(resp, dict)
```

Run: expected FAIL with `ImportError: cannot import name '_extract_schemathesis_request_response'`.

- [ ] **Step 2: Add `_extract_schemathesis_request_response` to `schemathesis/findings.py`**

Add after the existing helper functions (after `_check_name`):

```python
_HTTP_REQUEST_RE = re.compile(
    r"(?:Request|request):\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)\s+HTTP",
    re.IGNORECASE,
)
_HTTP_RESPONSE_RE = re.compile(r"HTTP/[\d.]+ (\d{3})", re.IGNORECASE)


def _extract_schemathesis_request_response(
    text: str, *, base_url: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse method, URL, and response status from a Schemathesis failure/system-out block."""
    req: dict[str, Any] = {}
    resp: dict[str, Any] = {}

    req_match = _HTTP_REQUEST_RE.search(text)
    if req_match:
        req["method"] = req_match.group(1).upper()
        raw_path = req_match.group(2)
        req["url"] = raw_path if raw_path.startswith("http") else (base_url.rstrip("/") + raw_path)
    else:
        req["method"] = _extract_method(text)
        req["url"] = _extract_url(text, base_url)

    resp_match = _HTTP_RESPONSE_RE.search(text)
    if resp_match:
        resp["status_code"] = int(resp_match.group(1))

    return req, resp
```

Then in the function that calls `finalize_finding_evidence` for schemathesis (look for `finalize_finding_evidence` calls in schemathesis/findings.py and pass `sent_request` and updated `received_response`):

Find the call and add `sent_request=req, received_response={**existing_received_response, **resp}` where `req, resp = _extract_schemathesis_request_response(failure_text, base_url=target_url)`.

- [ ] **Step 3: Run tests**

```
python -m pytest tests/unit/test_schemathesis_findings.py -xvs 2>&1 | tail -20
```
Expected: all pass.

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```

- [ ] **Step 4: Commit**

```bash
git add server/modules/schemathesis/findings.py tests/unit/test_schemathesis_findings.py
git commit -m "fix: schemathesis evidence extracts real HTTP status and request from JUnit failure text"
```

---

## Task 6: Evidence completeness validates real status_code presence

**Files:**
- Modify: `server/modules/test_executor/evidence.py` (`_has_received_response`, `_evidence_completeness`)
- Modify: `tests/unit/test_active_scan_evidence.py` (add completeness content test)

**Interfaces:**
- Consumes: `received_response` dict from evidence payload
- Produces: `evidence_completeness.complete=False` when `status_code` is absent or 0

- [ ] **Step 1: Write failing test**

Add to `tests/unit/test_active_scan_evidence.py`:

```python
def test_evidence_completeness_false_when_status_code_zero():
    from server.modules.test_executor.evidence import finalize_finding_evidence
    evidence = finalize_finding_evidence(
        {"engine": "nuclei"},
        method="GET",
        url="https://api.example.com/test",
        matched_rule={"template_id": "t1", "name": "Test", "severity": "HIGH"},
        received_response={"status_code": 0, "body": "something"},
        similarity={"source": "nuclei_matcher", "confidence": "external_report"},
        remediation="Fix it",
    )
    assert evidence["evidence_completeness"]["complete"] is False
    assert "received_response" in evidence["evidence_completeness"]["missing"]


def test_evidence_completeness_false_when_status_code_absent():
    from server.modules.test_executor.evidence import finalize_finding_evidence
    evidence = finalize_finding_evidence(
        {"engine": "nuclei"},
        method="GET",
        url="https://api.example.com/test",
        matched_rule={"template_id": "t1", "name": "Test", "severity": "HIGH"},
        received_response={"body": "something"},  # no status_code
        similarity={"source": "nuclei_matcher"},
        remediation="Fix it",
    )
    assert evidence["evidence_completeness"]["complete"] is False
```

Run: expected FAIL because current `_has_received_response` passes on any truthy dict.

- [ ] **Step 2: Tighten `_has_received_response` in `evidence.py`**

Replace:
```python
def _has_received_response(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    return any(item not in (None, "", {}, []) for item in value.values())
```

With:
```python
def _has_received_response(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    status = value.get("status_code")
    if status is None or (isinstance(status, int) and status == 0):
        return False
    return True
```

- [ ] **Step 3: Run tests**

```
python -m pytest tests/unit/test_active_scan_evidence.py -xvs 2>&1 | tail -20
```
Expected: new tests pass.

Check that existing evidence tests still pass (they use template engine paths which have real status codes):
```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```

- [ ] **Step 4: Commit**

```bash
git add server/modules/test_executor/evidence.py tests/unit/test_active_scan_evidence.py
git commit -m "fix: evidence_completeness requires real status_code, not just any truthy response"
```

---

## Task 7: Identity matrix schema — add status, expiry, tenant to TestAccount

**Files:**
- Modify: `server/models/core.py` (add 4 columns to `TestAccount`)
- Create: `migrations/versions/<timestamp>_test_account_identity_matrix.py`
- Modify: `tests/unit/test_multi_identity_replay.py` (add test for expired/disabled filtering)
- Modify: `server/modules/identity/multi_identity_replay.py` (`pick_identity_pair` filters out expired/disabled)

**Interfaces:**
- Consumes: `TestAccount` ORM model
- Produces: `TestAccount` has `status: str` ("ACTIVE"|"EXPIRED"|"DISABLED"), `expired_at: DateTime`, `tenant_id: str`; `pick_identity_pair` skips non-ACTIVE accounts

- [ ] **Step 1: Write failing test**

Add to `tests/unit/test_multi_identity_replay.py`:

```python
def test_pick_identity_pair_skips_expired_and_disabled_accounts():
    from server.modules.identity.multi_identity_replay import pick_identity_pair

    def _account(name, role, status="ACTIVE"):
        a = type("A", (), {
            "auth_headers": {"Authorization": f"Bearer {name}-token"},
            "auth_token": None,
            "role": role,
            "name": name,
        })()
        a.status = status
        return a

    accounts = [
        _account("alice", "MEMBER", "ACTIVE"),
        _account("bob", "MEMBER", "EXPIRED"),   # should be skipped
        _account("charlie", "MEMBER", "DISABLED"),  # should be skipped
        _account("dave", "MEMBER", "ACTIVE"),
    ]
    pair = pick_identity_pair(accounts, issue="BOLA")
    assert pair is not None
    names = {pair[0].name, pair[1].name}
    assert "bob" not in names
    assert "charlie" not in names
```

Run: expected FAIL because `pick_identity_pair` doesn't filter by `status`.

- [ ] **Step 2: Add columns to `TestAccount` in `core.py`**

In `server/models/core.py`, after the existing `role` column (line 65):

```python
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")      # ACTIVE|EXPIRED|DISABLED
    expired_at = mapped_column(DateTime(timezone=True), nullable=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
```

- [ ] **Step 3: Create Alembic migration**

```bash
cd "C:\Users\VediyappanMFinspot\Desktop\API-Sentinel-Team"
python -m alembic revision --autogenerate -m "test_account_identity_matrix"
```

Review the generated file in `migrations/versions/` to confirm it adds `status`, `expired_at`, `tenant_id` columns to `test_accounts`. If autogenerate doesn't pick them up (SQLite quirk), write the migration manually:

```python
def upgrade() -> None:
    op.add_column("test_accounts", sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"))
    op.add_column("test_accounts", sa.Column("expired_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("test_accounts", sa.Column("tenant_id", sa.String(36), nullable=True))
    op.create_index("ix_test_accounts_tenant_id", "test_accounts", ["tenant_id"])

def downgrade() -> None:
    op.drop_index("ix_test_accounts_tenant_id", table_name="test_accounts")
    op.drop_column("test_accounts", "tenant_id")
    op.drop_column("test_accounts", "expired_at")
    op.drop_column("test_accounts", "status")
```

- [ ] **Step 4: Filter non-ACTIVE accounts in `pick_identity_pair`**

In `server/modules/identity/multi_identity_replay.py`, in `pick_identity_pair` (line 247), add a filter before selecting pairs:

```python
def pick_identity_pair(
    accounts: list[Any], *, issue: str = "BOLA"
) -> tuple[Any, Any] | None:
    usable = [a for a in accounts if str(getattr(a, "status", "ACTIVE") or "ACTIVE").upper() == "ACTIVE"]
    if len(usable) < 2:
        return None
    # ... rest of existing logic using `usable` instead of `accounts`
```

- [ ] **Step 5: Run tests**

```
python -m pytest tests/unit/test_multi_identity_replay.py -xvs 2>&1 | tail -20
```
Expected: all pass.

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```

- [ ] **Step 6: Commit**

```bash
git add server/models/core.py server/modules/identity/multi_identity_replay.py migrations/versions/*identity_matrix* tests/unit/test_multi_identity_replay.py
git commit -m "feat: add status/expired_at/tenant_id to TestAccount; filter expired/disabled from identity pairs"
```

---

## Task 8: BFLA — real role×function matrix (one endpoint, N roles)

**Files:**
- Create: `server/modules/identity/bfla_matrix.py`
- Modify: `server/modules/agentic/scan_adapter.py` (`_run_replay` uses `bfla_matrix.run_bfla_function_matrix` for BFLA proposals)
- Create: `tests/unit/test_bfla_matrix.py`

**Interfaces:**
- Consumes: `endpoint`, `accounts`, `allow_state_change`, `allow_destructive_methods`
- Produces: `{"is_vulnerable": bool, "type": "BFLA", "severity": str, "evidence": dict}` with finding per (role, function) pair that was accessible but shouldn't be

BFLA is different from BOLA: it's about accessing a *privileged function* (endpoint) with a *lower-privilege identity*, not about accessing another user's *object*. The current implementation reuses BOLA's object-replay primitive. This task adds a real function-access matrix.

- [ ] **Step 1: Write failing tests**

Create `tests/unit/test_bfla_matrix.py`:

```python
import pytest


def _account(name, role, status="ACTIVE"):
    a = type("A", (), {
        "auth_headers": {"Authorization": f"Bearer {name}-token"},
        "auth_token": None,
        "role": role,
        "name": name,
        "status": status,
    })()
    return a


@pytest.mark.asyncio
async def test_bfla_matrix_detects_unprivileged_access():
    from server.modules.identity.bfla_matrix import run_bfla_function_matrix

    endpoint = {
        "id": "ep-delete",
        "method": "DELETE",
        "path": "/admin/users/{id}",
        "host": "api.example.com",
        "protocol": "https",
        "url": "https://api.example.com/admin/users/123",
    }
    accounts = [
        _account("admin", "ADMIN"),
        _account("member", "MEMBER"),
    ]

    _PRIVILEGED_ROLES = {"ADMIN", "SUPERUSER", "ROOT"}

    async def _mock_send(request):
        # admin gets 200, member gets 200 (BFLA — member shouldn't delete)
        return {"status_code": 200, "body": ""}

    result = await run_bfla_function_matrix(
        endpoint=endpoint,
        accounts=accounts,
        privileged_roles=_PRIVILEGED_ROLES,
        send_fn=_mock_send,
        allow_state_change=True,
        allow_destructive_methods=True,
    )
    assert result["is_vulnerable"] is True
    assert result["type"] == "BFLA"


@pytest.mark.asyncio
async def test_bfla_matrix_not_vulnerable_when_unprivileged_denied():
    from server.modules.identity.bfla_matrix import run_bfla_function_matrix

    endpoint = {
        "id": "ep-admin",
        "method": "GET",
        "path": "/admin/dashboard",
        "host": "api.example.com",
        "protocol": "https",
        "url": "https://api.example.com/admin/dashboard",
    }
    accounts = [_account("admin", "ADMIN"), _account("member", "MEMBER")]

    call_count = {}

    async def _mock_send(request):
        auth = (request.get("headers") or {}).get("Authorization", "")
        if "admin" in auth:
            return {"status_code": 200, "body": "admin content"}
        return {"status_code": 403, "body": "Forbidden"}

    result = await run_bfla_function_matrix(
        endpoint=endpoint,
        accounts=accounts,
        privileged_roles={"ADMIN"},
        send_fn=_mock_send,
        allow_state_change=False,
        allow_destructive_methods=False,
    )
    assert result["is_vulnerable"] is False
```

Run: expected FAIL with `ImportError`.

- [ ] **Step 2: Create `server/modules/identity/bfla_matrix.py`**

```python
"""Role-x-function BFLA matrix: test if unprivileged roles can invoke privileged endpoints."""
from __future__ import annotations

from typing import Any, Callable, Awaitable

from server.modules.identity.authorization_replay import auth_headers_for_account
from server.modules.utils.redactor import Redactor

_DEFAULT_PRIVILEGED_ROLES = {"ADMIN", "SUPERUSER", "ROOT", "OWNER", "PLATFORM"}


async def run_bfla_function_matrix(
    *,
    endpoint: dict[str, Any],
    accounts: list[Any],
    privileged_roles: set[str] | None = None,
    send_fn: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]] | None = None,
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
    target_guard: Any = None,
) -> dict[str, Any]:
    """Test whether low-privilege roles can invoke an endpoint reserved for privileged roles.

    Returns a finding dict with is_vulnerable=True if a non-privileged account receives
    a 2xx response on an endpoint where a privileged account also gets 2xx.
    """
    from server.modules.test_executor.state_change_guard import StateChangeGuard
    import httpx

    privileged = privileged_roles or _DEFAULT_PRIVILEGED_ROLES
    method = str(endpoint.get("method") or "GET").upper()
    url = str(endpoint.get("url") or "")
    if not url:
        return {"is_vulnerable": False, "skip_reason": "missing_url"}

    state_guard = StateChangeGuard(
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )
    try:
        state_guard.validate_request(method, url)
    except Exception:
        return {"is_vulnerable": False, "skip_reason": "state_change_blocked"}

    if target_guard:
        try:
            target_guard.validate_url(url)
        except Exception:
            return {"is_vulnerable": False, "skip_reason": "target_guard_blocked"}

    usable = [a for a in accounts if str(getattr(a, "status", "ACTIVE") or "ACTIVE").upper() == "ACTIVE"]
    privileged_accounts = [a for a in usable if str(getattr(a, "role", "") or "").upper() in privileged]
    low_priv_accounts = [a for a in usable if str(getattr(a, "role", "") or "").upper() not in privileged]

    if not privileged_accounts or not low_priv_accounts:
        return {"is_vulnerable": False, "skip_reason": "no_privilege_boundary_pair"}

    async def _send(account: Any) -> dict[str, Any]:
        headers = auth_headers_for_account(account)
        request = {"method": method, "url": url, "headers": headers}
        if send_fn:
            return await send_fn(request)
        async with httpx.AsyncClient(timeout=10.0, verify=True, follow_redirects=False) as client:
            resp = await client.request(method=method, url=url, headers=headers)
            return {"status_code": resp.status_code, "body": resp.text[:2000]}

    # Test privileged access first (establish baseline)
    priv_result = await _send(privileged_accounts[0])
    if priv_result.get("status_code", 0) not in range(200, 300):
        return {"is_vulnerable": False, "skip_reason": "privileged_account_denied_baseline"}

    # Test each low-privilege account
    for low_account in low_priv_accounts:
        low_result = await _send(low_account)
        low_status = low_result.get("status_code", 0)
        if low_status in range(200, 300):
            return {
                "is_vulnerable": True,
                "type": "BFLA",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": {
                    "privileged_role": str(getattr(privileged_accounts[0], "role", "ADMIN")),
                    "low_privilege_role": str(getattr(low_account, "role", "MEMBER")),
                    "endpoint": Redactor.redact_url(url),
                    "method": method,
                    "privileged_status": priv_result.get("status_code"),
                    "low_privilege_status": low_status,
                    "finding": "low_privilege_role_can_invoke_privileged_function",
                },
            }

    return {"is_vulnerable": False}
```

- [ ] **Step 3: Wire BFLA matrix into `scan_adapter._run_replay` for BFLA proposals**

In `server/modules/agentic/scan_adapter.py`, update `_run_replay` to use `bfla_matrix` for BFLA:

```python
async def _run_replay(
    *,
    proposal: TestProposal,
    endpoint: dict[str, Any],
    accounts: list[Any],
    allow_state_change: bool,
    allow_destructive_methods: bool,
) -> dict[str, Any] | None:
    if proposal.category == "BFLA":
        from server.modules.identity.bfla_matrix import run_bfla_function_matrix
        return await run_bfla_function_matrix(
            endpoint=endpoint,
            accounts=accounts,
            allow_state_change=allow_state_change,
            allow_destructive_methods=allow_destructive_methods,
        )
    # BOLA: existing multi-identity replay
    from server.modules.identity.multi_identity_replay import (
        pick_identity_pair,
        run_multi_identity_replay,
    )
    pair = pick_identity_pair(accounts, issue=proposal.category)
    if pair is None:
        return None
    victim, attacker = pair
    return await run_multi_identity_replay(
        endpoint=endpoint,
        victim=victim,
        attacker=attacker,
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )
```

- [ ] **Step 4: Run tests**

```
python -m pytest tests/unit/test_bfla_matrix.py -xvs 2>&1 | tail -20
```
Expected: all pass.

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```

- [ ] **Step 5: Commit**

```bash
git add server/modules/identity/bfla_matrix.py server/modules/agentic/scan_adapter.py tests/unit/test_bfla_matrix.py
git commit -m "feat: real BFLA role-x-function matrix replacing object-replay for BFLA proposals"
```

---

## Task 9: Business-logic abuse — execute OTP spam and coupon abuse probes

**Files:**
- Create: `server/modules/identity/business_abuse.py`
- Modify: `server/modules/agentic/orchestration.py` (`_run_targeted_detectors` calls abuse probes on POST endpoints)
- Create: `tests/unit/test_business_abuse.py`

**Interfaces:**
- Consumes: `endpoint` dict, `target_guard`, `allow_state_change`
- Produces: `{"is_vulnerable": bool, "type": "BUSINESS_LOGIC_ABUSE", "subtype": "otp_spam"|"coupon_abuse"|"resource_exhaustion", "evidence": dict}`

P5 is currently reporting-only. This adds execution for the two most common and detectable abuse patterns: OTP/SMS amplification (repeated POST to verify/otp endpoint returns 200 multiple times) and resource exhaustion (endpoint rate-limits after N requests).

- [ ] **Step 1: Write failing test**

Create `tests/unit/test_business_abuse.py`:

```python
import pytest


@pytest.mark.asyncio
async def test_otp_spam_detected_when_endpoint_accepts_repeated_requests():
    from server.modules.identity.business_abuse import probe_otp_spam

    endpoint = {
        "id": "ep1",
        "method": "POST",
        "path": "/api/auth/otp/send",
        "host": "api.example.com",
        "protocol": "https",
        "url": "https://api.example.com/api/auth/otp/send",
    }
    call_count = [0]

    async def _mock_send(url, method, payload):
        call_count[0] += 1
        return {"status_code": 200, "body": '{"sent": true}'}

    result = await probe_otp_spam(endpoint=endpoint, send_fn=_mock_send, repeat=5)
    assert result["is_vulnerable"] is True
    assert result["subtype"] == "otp_spam"
    assert call_count[0] >= 5


@pytest.mark.asyncio
async def test_otp_spam_not_detected_when_rate_limited():
    from server.modules.identity.business_abuse import probe_otp_spam

    endpoint = {
        "id": "ep1",
        "method": "POST",
        "path": "/api/auth/otp/send",
        "url": "https://api.example.com/api/auth/otp/send",
    }
    responses = [200, 200, 429, 429, 429]
    idx = [0]

    async def _mock_send(url, method, payload):
        code = responses[min(idx[0], len(responses) - 1)]
        idx[0] += 1
        return {"status_code": code, "body": ""}

    result = await probe_otp_spam(endpoint=endpoint, send_fn=_mock_send, repeat=5)
    assert result["is_vulnerable"] is False
```

Run: expected `ImportError`.

- [ ] **Step 2: Create `server/modules/identity/business_abuse.py`**

```python
"""Active business-logic abuse probes: OTP spam, coupon abuse, resource exhaustion."""
from __future__ import annotations

import re
from typing import Any, Callable, Awaitable

_OTP_PATH_RE = re.compile(r"/(otp|pin|verify|resend|sms|email.?send|token.?send)", re.IGNORECASE)
_COUPON_PATH_RE = re.compile(r"/(coupon|promo|discount|voucher|code)", re.IGNORECASE)


async def probe_otp_spam(
    *,
    endpoint: dict[str, Any],
    send_fn: Callable[..., Awaitable[dict[str, Any]]] | None = None,
    repeat: int = 5,
    target_guard: Any = None,
) -> dict[str, Any]:
    """Send `repeat` identical OTP-trigger requests. Vulnerable if all return 2xx."""
    url = str(endpoint.get("url") or "")
    method = str(endpoint.get("method") or "POST").upper()
    if target_guard:
        try:
            target_guard.validate_url(url)
        except Exception:
            return {"is_vulnerable": False, "skip_reason": "target_guard_blocked"}

    success_count = 0
    rate_limited = False
    for _ in range(repeat):
        if send_fn:
            resp = await send_fn(url, method, {"phone": "+10000000000", "email": "probe@sentinel.test"})
        else:
            import httpx
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                r = await client.request(method, url, json={"phone": "+10000000000"})
                resp = {"status_code": r.status_code, "body": r.text}
        code = resp.get("status_code", 0)
        if code == 429:
            rate_limited = True
            break
        if code in range(200, 300):
            success_count += 1

    vulnerable = (not rate_limited) and (success_count >= repeat)
    return {
        "is_vulnerable": vulnerable,
        "type": "BUSINESS_LOGIC_ABUSE",
        "subtype": "otp_spam",
        "severity": "HIGH" if vulnerable else "INFO",
        "evidence": {
            "repeat": repeat,
            "success_count": success_count,
            "rate_limited": rate_limited,
            "endpoint": url,
        },
    }


async def probe_coupon_abuse(
    *,
    endpoint: dict[str, Any],
    send_fn: Callable[..., Awaitable[dict[str, Any]]] | None = None,
    repeat: int = 3,
    target_guard: Any = None,
) -> dict[str, Any]:
    """Apply the same coupon code `repeat` times. Vulnerable if accepted more than once."""
    url = str(endpoint.get("url") or "")
    method = str(endpoint.get("method") or "POST").upper()
    if target_guard:
        try:
            target_guard.validate_url(url)
        except Exception:
            return {"is_vulnerable": False, "skip_reason": "target_guard_blocked"}

    accept_count = 0
    for _ in range(repeat):
        if send_fn:
            resp = await send_fn(url, method, {"code": "SENTINEL_TEST_COUPON", "amount": 100})
        else:
            import httpx
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                r = await client.request(method, url, json={"code": "SENTINEL_TEST_COUPON", "amount": 100})
                resp = {"status_code": r.status_code}
        if resp.get("status_code", 0) in range(200, 300):
            accept_count += 1

    vulnerable = accept_count > 1
    return {
        "is_vulnerable": vulnerable,
        "type": "BUSINESS_LOGIC_ABUSE",
        "subtype": "coupon_abuse",
        "severity": "HIGH" if vulnerable else "INFO",
        "evidence": {"repeat": repeat, "accept_count": accept_count, "endpoint": url},
    }


def endpoint_looks_like_otp(endpoint: dict[str, Any]) -> bool:
    path = str(endpoint.get("path") or endpoint.get("url") or "")
    return bool(_OTP_PATH_RE.search(path)) and str(endpoint.get("method") or "GET").upper() == "POST"


def endpoint_looks_like_coupon(endpoint: dict[str, Any]) -> bool:
    path = str(endpoint.get("path") or endpoint.get("url") or "")
    return bool(_COUPON_PATH_RE.search(path)) and str(endpoint.get("method") or "GET").upper() == "POST"
```

- [ ] **Step 3: Wire into `_run_targeted_detectors` in `orchestration.py`**

Add to the `_run_targeted_detectors` function body, after the existing `POST/PUT/PATCH` mass-assignment block:

```python
            # Business-logic abuse probes (path-heuristic gated)
            from server.modules.identity.business_abuse import (
                endpoint_looks_like_otp,
                endpoint_looks_like_coupon,
                probe_otp_spam,
                probe_coupon_abuse,
            )
            if endpoint_looks_like_otp(endpoint):
                _record(
                    await probe_otp_spam(endpoint=endpoint, target_guard=guard),
                    endpoint,
                )
            elif endpoint_looks_like_coupon(endpoint):
                _record(
                    await probe_coupon_abuse(endpoint=endpoint, target_guard=guard),
                    endpoint,
                )
```

- [ ] **Step 4: Run tests**

```
python -m pytest tests/unit/test_business_abuse.py -xvs 2>&1 | tail -20
```
Expected: all pass.

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```

- [ ] **Step 5: Commit**

```bash
git add server/modules/identity/business_abuse.py server/modules/agentic/orchestration.py tests/unit/test_business_abuse.py
git commit -m "feat: execute OTP-spam and coupon-abuse P5 probes in targeted detector sweep"
```

---

## Task 10: Blind/boolean SQLi probes

**Files:**
- Modify: `server/modules/identity/sqli_probe.py` (add boolean-based and time-based detection)
- Modify: `tests/unit/test_sqli_probe.py`

**Interfaces:**
- Consumes: `endpoint`, `target_guard`
- Produces: existing `{"is_vulnerable": bool, "type": "INJECTION", ...}` extended with `subtype: "error_based"|"boolean_based"|"time_based"`

Current `detect_error_based_sqli` only catches error signatures. Boolean-based SQLi compares response bodies between a neutral payload and an always-true/always-false payload. Time-based checks elapsed time with a `SLEEP(3)` variant.

- [ ] **Step 1: Write failing tests**

Add to `tests/unit/test_sqli_probe.py`:

```python
import pytest


@pytest.mark.asyncio
async def test_boolean_based_sqli_detected_when_responses_differ():
    from server.modules.identity.sqli_probe import detect_boolean_based_sqli

    responses = {
        "neutral": {"status_code": 200, "body": '{"users": [{"id": 1}]}'},
        "true":    {"status_code": 200, "body": '{"users": [{"id": 1}]}'},   # same as neutral
        "false":   {"status_code": 200, "body": '{"users": []}'},             # different!
    }

    async def _mock_send(url, method, params):
        payload = str(params)
        if "1=0" in payload or "2=1" in payload:
            return responses["false"]
        if "1=1" in payload:
            return responses["true"]
        return responses["neutral"]

    endpoint = {
        "method": "GET",
        "path": "/api/users",
        "host": "api.example.com",
        "protocol": "https",
        "url": "https://api.example.com/api/users",
        "last_query_string": "id=1",
    }
    result = await detect_boolean_based_sqli(endpoint=endpoint, send_fn=_mock_send)
    assert result["is_vulnerable"] is True
    assert result.get("subtype") == "boolean_based"


@pytest.mark.asyncio
async def test_boolean_based_sqli_not_detected_when_responses_identical():
    from server.modules.identity.sqli_probe import detect_boolean_based_sqli

    async def _mock_send(url, method, params):
        return {"status_code": 200, "body": '{"users": [{"id": 1}]}'}

    endpoint = {
        "method": "GET",
        "url": "https://api.example.com/api/users",
        "last_query_string": "id=1",
    }
    result = await detect_boolean_based_sqli(endpoint=endpoint, send_fn=_mock_send)
    assert result["is_vulnerable"] is False
```

Run: expected `ImportError: cannot import name 'detect_boolean_based_sqli'`.

- [ ] **Step 2: Add `detect_boolean_based_sqli` to `sqli_probe.py`**

In `server/modules/identity/sqli_probe.py`, add after the existing `detect_error_based_sqli` function:

```python
_BOOLEAN_TRUE_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1"]
_BOOLEAN_FALSE_PAYLOADS = ["' AND '1'='0", "' AND 1=2--", "\" AND \"1\"=\"2"]


async def detect_boolean_based_sqli(
    *,
    endpoint: dict[str, Any],
    target_guard: Any = None,
    send_fn: Any = None,
) -> dict[str, Any]:
    """Boolean-based SQLi: compare neutral vs true/false payload responses."""
    url = str(endpoint.get("url") or "")
    method = str(endpoint.get("method") or "GET").upper()
    qs = str(endpoint.get("last_query_string") or "")
    if not url or not qs:
        return {"is_vulnerable": False, "skip_reason": "no_query_string_to_inject"}
    if target_guard:
        try:
            target_guard.validate_url(url)
        except Exception:
            return {"is_vulnerable": False, "skip_reason": "target_guard_blocked"}

    # Parse first param name
    param = qs.split("&")[0].split("=")[0]
    if not param:
        return {"is_vulnerable": False, "skip_reason": "no_injectable_param"}

    async def _request(value: str) -> dict[str, Any]:
        params = {param: value}
        if send_fn:
            return await send_fn(url, method, params)
        import httpx
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            r = await client.request(method, url, params=params)
            return {"status_code": r.status_code, "body": r.text}

    neutral = await _request("1")
    neutral_body = str(neutral.get("body", ""))

    for true_p, false_p in zip(_BOOLEAN_TRUE_PAYLOADS, _BOOLEAN_FALSE_PAYLOADS):
        true_resp = await _request(true_p)
        false_resp = await _request(false_p)
        true_body = str(true_resp.get("body", ""))
        false_body = str(false_resp.get("body", ""))
        # Vulnerable: true-payload matches neutral but false-payload differs
        if true_body == neutral_body and false_body != neutral_body:
            return {
                "is_vulnerable": True,
                "type": "INJECTION",
                "subtype": "boolean_based",
                "severity": "HIGH",
                "evidence": {
                    "param": param,
                    "true_payload": "[REDACTED]",
                    "false_payload": "[REDACTED]",
                    "body_differs": True,
                },
            }

    return {"is_vulnerable": False, "subtype": "boolean_based"}
```

- [ ] **Step 3: Wire into `_run_targeted_detectors` in `orchestration.py`**

In `_run_targeted_detectors`, after the `detect_error_based_sqli` call, add:

```python
                from server.modules.identity.sqli_probe import detect_boolean_based_sqli
                _record(await detect_boolean_based_sqli(endpoint=endpoint, target_guard=guard), endpoint)
```

- [ ] **Step 4: Run tests**

```
python -m pytest tests/unit/test_sqli_probe.py -xvs 2>&1 | tail -20
```

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```

- [ ] **Step 5: Commit**

```bash
git add server/modules/identity/sqli_probe.py server/modules/agentic/orchestration.py tests/unit/test_sqli_probe.py
git commit -m "feat: add boolean-based SQLi detection alongside existing error-based probe"
```

---

## Task 11: LLM path test coverage with mocked HTTP

**Files:**
- Modify: `tests/unit/test_agentic_orchestration.py` (add mock-HTTP LLM round-trip test)

**Interfaces:**
- Consumes: `OpenAICompatLLMClient` from `llm_client.py`
- Produces: test that drives a successful HTTP response through `OpenAICompatLLMClient.get_proposals` and asserts it parses a real model JSON response into proposals

The audit found that `OpenAICompatLLMClient` is only tested for *error paths*. This task adds a happy-path test using `unittest.mock.patch` on `httpx.AsyncClient.post`.

- [ ] **Step 1: Write failing test**

Add to `tests/unit/test_agentic_orchestration.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch, MagicMock


@pytest.mark.asyncio
async def test_openai_compat_client_parses_valid_model_response():
    from server.modules.agentic.llm_client import OpenAICompatLLMClient

    fake_response_body = {
        "choices": [{
            "message": {
                "content": '{"proposals": [{"category": "BOLA", "endpoint_id": "ep1", "rationale": "private id in path", "priority": 0.9}]}'
            }
        }]
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = fake_response_body
    mock_response.raise_for_status = MagicMock()

    client = OpenAICompatLLMClient(
        api_base="https://fake.api/v1",
        api_key="test-key",
        model="test-model",
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
        proposals = await client.get_proposals(
            system_prompt="You are a security researcher.",
            user_prompt="Analyze these endpoints and propose tests.",
        )

    assert isinstance(proposals, dict)
    prop_list = proposals.get("proposals", [])
    assert len(prop_list) == 1
    assert prop_list[0]["category"] == "BOLA"
```

Run: expected FAIL (import issue or method signature mismatch).

- [ ] **Step 2: Check `OpenAICompatLLMClient.get_proposals` signature in `llm_client.py` and align test**

Read `server/modules/agentic/llm_client.py` around the `get_proposals` method and adjust the mock target (`httpx.AsyncClient.post` vs the actual method called). Update the test to use the correct method name and response shape.

- [ ] **Step 3: Run tests**

```
python -m pytest tests/unit/test_agentic_orchestration.py::test_openai_compat_client_parses_valid_model_response -xvs 2>&1 | tail -20
```
Expected: PASS.

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -5
```

- [ ] **Step 4: Commit**

```bash
git add tests/unit/test_agentic_orchestration.py
git commit -m "test: add happy-path mock-HTTP test for OpenAICompatLLMClient proposal parsing"
```

---

## Final verification

- [ ] **Run complete unit suite**

```
python -m pytest tests/unit -q --no-header 2>&1 | tail -10
```
Expected: all previous tests green + new tests added.

- [ ] **Verify all new modules import cleanly**

```
python -c "
import server.modules.agentic.orchestration
import server.modules.identity.bfla_matrix
import server.modules.identity.business_abuse
import server.modules.identity.sqli_probe
print('All imports OK')
"
```

- [ ] **Verify benchmark tests now collect**

```
python -m pytest tests/unit/test_benchmark_runner.py tests/unit/test_benchmark_scoring.py --collect-only 2>&1 | tail -5
```
Expected: collected N items, 0 errors.
