# Auto-Generated API Docs + Drift Detection — Design

## Context

This is sub-project 1 of 3 identified while scoping capability gaps against the
commercial competitor AppSentinels (appsentinels.ai). The other two —
bot/scraping+fraud detection, and real AI red-teaming of MCP/agents — are
separate, independent efforts with their own specs.

Initial assumption was that "auto-generated API docs + drift detection" needed
to be built from scratch. Investigation of `server/api/routers/openapi_specs.py`
found this is false: spec generation, versioning, diffing, and conformance
violation detection already exist and work:

- `OpenAPIGenerator.generate_spec()` — builds an OpenAPI spec from discovered
  endpoints (`server/modules/api_inventory/openapi_generator.py`)
- `OpenAPISpec` model — versioned spec storage, already supports history
- `OpenAPIDiffAnalyzer.compare()` — structural diff between two specs, already
  classifies each change with an `id`, `severity`, `message`,
  `why_it_matters`, `recommended_action` (`server/modules/api_inventory/openapi_diff.py`)
- `POST /openapi/rebuild`, `GET /openapi/latest`, `GET /openapi/history`,
  `POST /openapi/diff`, `GET /openapi/violations`, `POST /openapi/validate` —
  all exist as API endpoints

**The actual gaps** are narrower than "build detection logic":

1. **No automatic trigger.** `/rebuild` only fires on a manual API call —
   nothing regenerates the spec on its own.
2. **No drift alerting.** `/diff` is pull-based; nothing runs it automatically
   after a rebuild or raises a finding/alert when the drift is meaningful.
3. **No coherent UI.** `/violations` has a partial frontend page (Schema
   Validation); spec generation, version history, and diffs aren't surfaced
   anywhere.

This design closes those three gaps by wiring existing logic into an automated
loop, not by building new detection engineering.

## Goal

The platform keeps its inferred API spec current on its own, and raises a
finding when something meaningful changes — without anyone needing to click
"rebuild" or "diff."

## Architecture

New `OpenAPIDriftProcessor` in `server/modules/scheduler/openapi_drift.py`,
following the exact structure of the existing
`server/modules/scheduler/continuous_testing.py::ContinuousTestingProcessor`
(config-gated background loop, per-account sweep, errors isolated per account
so one bad account never stops the sweep):

```
class OpenAPIDriftProcessor:
    def __init__(self, interval_sec: int | None = None):
        self.interval = interval_sec or settings.OPENAPI_DRIFT_SWEEP_INTERVAL_SECONDS
        ...
    async def start(self) / stop(self) / _loop(self)   # same shape as ContinuousTestingProcessor
    async def sweep(self) -> dict:
        if not settings.OPENAPI_DRIFT_ENABLED:
            return {"status": "disabled"}
        for account_id in <accounts with endpoints>:
            await self._check_account(account_id)

    async def _check_account(self, account_id: int) -> None:
        new_spec = await self._gen.generate_spec(collection_name="Discovered API", account_id=account_id)
        previous = <most recent OpenAPISpec for account_id>
        if previous is None:
            <persist new_spec as baseline version, no diff, no alert>
            return
        diff = self._diff.compare(previous.spec_json, new_spec)
        if not diff["breaking_changes"]:
            return  # identical - no new version, no alert, no spam
        <persist new_spec as a new OpenAPISpec version>
        for change in diff["breaking_changes"]:
            <create PolicyViolation + Alert + EvidenceRecord for this change>
```

Trigger mechanism: **scheduled**, matching `ContinuousTestingProcessor`'s
pattern exactly — a fixed-interval sweep, not event-driven. Simplest to
reason about, predictable load, no debouncing logic needed. Event-driven
(rebuild-on-endpoint-change) is an explicit non-goal for v1 (see below).

Wired into `server/api/main.py` lifespan exactly like `ContinuousTestingProcessor`
is today (double-gated by a `STARTUP_ENABLE_*` flag and the feature flag itself).

## Data model

No new tables. Reuses:
- `OpenAPISpec` — already versioned, just needs to be written to on a schedule
  instead of only on manual `/rebuild`
- `PolicyViolation` — new `rule_type="DRIFT"` value (existing values include
  `"SCHEMA"`); `severity` taken directly from the diff analyzer's per-change
  severity; `endpoint_id` resolved from the change's `path`/`method` where a
  matching `APIEndpoint` exists, else left null
- `Alert` — one per significant change, same shape as
  `server/modules/agentic/mcp_security.py`'s alert-creation pattern
- `EvidenceRecord` — one per alert, same pattern

## Config additions (`server/config.py`)

```python
OPENAPI_DRIFT_ENABLED: bool = False
STARTUP_ENABLE_OPENAPI_DRIFT: bool = False
OPENAPI_DRIFT_SWEEP_INTERVAL_SECONDS: int = 3600  # hourly
```

Off by default, matching every other continuous-background-processor in this
codebase (`CONTINUOUS_TESTING_ENABLED` follows the identical pattern).

## Frontend

Enhance `src/customer/pages/discovery/SchemaValidation.tsx` (currently only
renders `/openapi/violations`) into a fuller "API Documentation & Drift" view
rather than building a new page:

- Keep the existing violations list.
- Add a current-spec summary card: path count, version, last generated
  timestamp — from `GET /openapi/latest`.
- Add a version history list — from `GET /openapi/history`.
- Add a "View Diff" action between any two selected versions — calls
  `POST /openapi/diff` with `base_spec_id`/`revision_spec_id`, renders
  `breaking_changes` grouped by severity using the evidence design-system
  components already built this session (`EvidencePanel`, `EvidenceStatLine`,
  `EvidenceBadge`).
- New hook file `src/hooks/use-openapi-docs.ts` wrapping `/openapi/latest`,
  `/openapi/history`, `/openapi/diff`, `/openapi/violations`.

Realtime: no new `WSEventType` for v1. The drift sweep is hourly, not
sub-second, so push-invalidation adds complexity without much user-facing
value; the page just refetches on mount/focus like other non-realtime pages.
Explicitly a non-goal for v1 (see below) — can be added later by broadcasting
on `Alert` creation if drift alerts should show up in the live feed too.

## Testing

Mirror the existing `server/modules/scheduler/test_scheduler.py` /
continuous-testing test style. New `tests/unit/test_openapi_drift.py`:

1. No prior spec for an account → baseline persisted, zero violations/alerts created.
2. Regenerated spec identical to previous → no new `OpenAPISpec` row, zero violations/alerts.
3. Regenerated spec has changes → new `OpenAPISpec` version persisted; one
   `PolicyViolation` + `Alert` + `EvidenceRecord` per change, with severity
   matching the diff analyzer's output.
4. `OPENAPI_DRIFT_ENABLED=False` → sweep is a no-op.
5. One account's sweep raising an exception doesn't stop other accounts' sweeps.

Frontend: extend `SchemaValidation`'s existing test coverage (or add one if
none exists) for the new history/diff/summary sections.

## Out of scope for v1 (explicit)

- Event-driven rebuild trigger (endpoint-change-triggered) — scheduled only.
- New `WSEventType` for realtime push of drift alerts.
- Bot/scraping+fraud detection and AI red-teaming of MCP/agents — separate
  sub-projects, tracked independently.
