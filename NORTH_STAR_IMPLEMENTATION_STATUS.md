# North Star Implementation Status

Updated: 2026-09-14. This tracks changes made after `NORTH_STAR_GAP_ANALYSIS.md`.

## Implemented In This Patch

- Preparation loads active identities with credentials, supplies their count to the engine plan, and passes role context into selection.
- Preparation labels its result as configuration preflight, with `production_verified: false`. Background execution no longer counts as queued execution; disabled RLS no longer counts as enabled tenant isolation.
- Queued runs can carry an explicit external-engine target and OpenAPI specification binding. The plan includes the specification hash; the worker rejects changed specifications, invalid plan hashes, missing endpoints, mismatched targets, and remote specification references.
- The worker runs ready Schemathesis, Nuclei, and ZAP adapters before primary execution releases its lease. It renews the lease, checks the kill switch, persists redacted findings and execution artifacts, and stops on an unsuccessful external result.
- Specification-driven runs are limited to selected method/path pairs. Nuclei requires explicit state-changing and destructive-method arming in this worker path.
- Worker acceptance requires successful, hash-verified artifacts from the same run for every required engine. Missing, skipped, failed, and cross-run artifacts cannot satisfy this check.
- Scanner subprocesses are terminated when their task is cancelled.
- An opt-in Helm worker Deployment requires a digest-pinned image and sets resource limits, non-root execution, a read-only filesystem, and no mounted Kubernetes API token. This is a leased worker, not per-run Kubernetes Job isolation.
- The checked-in Kubernetes configuration now uses the supported `background` execution mode. The unused Nuclei simulation option was removed.

## Queued External Execution

Use the existing `POST /api/tests/run` request with `template_ids`, `endpoint_ids`, and `pentest_profile_id`, plus:

```json
{
  "external_engine_scope": {
    "target_url": "https://owned-api.example",
    "openapi_spec_id": "stored-tenant-spec-id"
  }
}
```

The API must use `PENTEST_SCAN_EXECUTION_MODE=queued`. The target and credentials must pass existing scope checks. Omitting this binding blocks external engines in the queued plan while allowing the existing template path. Engine runtime availability is still checked on the API host; worker capability advertisement remains pending.

For Helm, set `scanWorker.enabled=true` and `scanWorker.image` to a built registry image ending in `@sha256:<digest>`. Configure existing secrets and target policies before deployment. The patch does not activate workers or continuous scanning in a live cluster.

## Still Required

1. Real CLI canaries against an owned staging API, including authentication expiry, cancellation, failure recovery, and artifact verification.
2. Per-run Kubernetes Job dispatch, network isolation, worker capability advertisement, and direct-engine route migration to the queue.
3. Complete readiness based on measured deployment and evidence facts; some older capability checks remain implementation/configuration checks.
4. Automatic identity replay across ordinary scan paths, including full tenant and privilege matrices.
5. Durable business-flow execution with prerequisite setup, cleanup, and verified business invariants.
6. Live LLM fixtures for leakage, injection, retrieval exfiltration, and tool misuse, with deterministic confirmation.
7. Aggregate external-engine results into run counters, unified reports, retest selection, and ticket lifecycle transitions.
8. Required schema-valid SARIF/JUnit generation, action and binary provenance, and dependency/secret scanning gates.
9. Production RLS validation, continuous/discovery activation, dashboards, retention, SLA/ticket-provider validation, and governance acceptance.

The North Star is not complete. Passing adapter and contract tests does not establish production readiness.

## Verification

- Backend worker, route selection, scanner adapters, and pentest integration suite: 141 passed.
- Additional focused scope, dispatch, and same-run artifact acceptance checks: 9 passed.
- Helm worker template rendered successfully after resolving chart dependencies. No live deployment or live scanner canary was performed.

## Contracts

Shared definitions the four tracks build against: `docs/SHARED_CONTRACTS.md` (scan status, engine outcome, finding confirmation, evidence format, artifact ownership, cancellation). Open decisions A-F are listed there with owners and due dates.
