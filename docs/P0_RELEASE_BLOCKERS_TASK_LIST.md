# P0 Release Blockers Task List

## Objective

Clear the production release blockers for API Sentinel so the platform can safely ship as an authenticated, evidence-grade API security validation system.

These tasks are release gates. A merge should not be considered production-ready until every acceptance check below passes.

## P0 Tasks

### 1. Frontend Lint Cleanup

**Owner:** Frontend Engineer

**Goal:** Fix all lint failures in `api-sentinel-view-main/` without weakening lint rules or hiding real defects.

**Scope:**
- Resolve all `npm run lint` failures.
- Keep fixes aligned with the existing React, TypeScript, Tailwind, and shadcn patterns.
- Avoid broad rewrites unless a lint issue exposes a real structural problem.
- Keep test coverage intact for changed behavior.

**Acceptance:**
- `cd api-sentinel-view-main && npm run lint` passes.
- `cd api-sentinel-view-main && npm test` passes.
- `cd api-sentinel-view-main && npm run build` passes.
- `cd api-sentinel-view-main && npm run test:e2e` passes.

### 2. CI Pipeline Hardening

**Owner:** DevSecOps Engineer

**Goal:** Make CI enforce the same release gates expected locally across backend, frontend, and browser flows.

**Scope:**
- Add backend jobs for unit, integration, security, and E2E/API-level tests.
- Add frontend jobs for lint, unit tests, production build, and Playwright E2E.
- Upload SARIF, JUnit, and Playwright artifacts.
- Ensure failed gates block merge.
- Keep CI output clear enough for engineers to identify the failing layer quickly.

**Acceptance:**
- CI blocks merge if any backend or frontend gate fails.
- CI uploads SARIF artifacts where security scan/gate output exists.
- CI uploads JUnit artifacts for test result inspection.
- CI uploads Playwright traces/screenshots/videos where configured.
- Required checks are configured for protected release branches.

### 3. Real Multi-Engine Runtime Execution

**Owner:** Backend Security Engineer

**Goal:** Wire real Schemathesis, Nuclei, and OWASP ZAP execution into the worker runtime and prove each engine creates verified artifacts.

**Scope:**
- Install or package Schemathesis, Nuclei, and ZAP in the worker runtime.
- Ensure engine readiness checks reflect actual runtime availability.
- Execute each ready engine from isolated scan execution paths.
- Normalize results into existing vulnerability/evidence models.
- Persist execution artifacts for each engine.
- Redact secrets from commands, stdout, stderr, reports, metadata, and API responses.

**Acceptance:**
- A ready Schemathesis engine produces a verified execution artifact.
- A ready Nuclei engine produces a verified execution artifact.
- A ready ZAP engine produces a verified execution artifact.
- CI gate fails if a ready engine lacks a verified artifact.
- Disabled or unavailable engines are reported as blocked/disabled with redacted reason metadata.

### 4. Isolated Scan Workers

**Owner:** Platform Engineer

**Goal:** Run active scans outside the main API request path with isolation, bounded execution, recovery, and auditability.

**Scope:**
- Execute scans in isolated worker directories and/or isolated worker processes.
- Enforce timeout, kill switch, bounded concurrency, and scoped filesystem access.
- Add scoped network access controls appropriate for the deployment environment.
- Persist worker lifecycle audit logs.
- Recover lost, failed, timed-out, or abandoned workers.
- Ensure worker leases and heartbeats accurately represent execution state.

**Acceptance:**
- Lost workers become recoverable through queue/lease handling.
- Failed workers persist failure reason and redacted execution context.
- Timed-out workers are terminated and audited.
- Kill switch stops active execution safely.
- Worker audit logs are queryable and tied to scan run IDs.

### 5. Production Safety Enforcement

**Owner:** Security Engineer

**Goal:** Verify every active scan path fails closed unless target scope, auth scope, destructive-method policy, and evidence redaction are satisfied.

**Scope:**
- Verify target allowlists across template execution, Schemathesis, Nuclei, ZAP, workflows, and evidence URL handling.
- Verify SSRF guard behavior for private IPs, loopback, metadata services, DNS resolution, and host obfuscation.
- Verify auth scope guard prevents credential attachment outside declared domains.
- Verify state-changing and destructive methods require explicit arming.
- Verify secret and PII redaction across evidence, logs, artifacts, stdout, stderr, and API responses.
- Add regression tests for unsafe scan attempts.

**Acceptance:**
- Unsafe scans fail closed.
- Failed-closed decisions produce redacted safety evidence.
- Credentials are never attached to out-of-scope targets.
- Destructive methods cannot run without explicit arming.
- No plaintext secrets appear in persisted evidence, artifacts, logs, or API responses.

## Execution Order

1. Start with **Production Safety Enforcement** and **Isolated Scan Workers** because they define the safe runtime boundary for every active engine.
2. Run **Real Multi-Engine Runtime Execution** after worker isolation is in place.
3. Run **CI Pipeline Hardening** in parallel, but wire final gates after the engine/artifact expectations are stable.
4. Complete **Frontend Lint Cleanup** in parallel so the UI does not block the final release gate.

## Final Release Gate

Production release is blocked until:

- All frontend lint/test/build/E2E checks pass.
- Backend unit/integration/security/E2E checks pass.
- CI required checks block merge on failure.
- Ready scan engines produce verified artifacts.
- Isolated workers recover from lost/failed/timed-out execution.
- Unsafe scans fail closed with redacted evidence.
- No scan path leaks credentials or secrets into stored or returned artifacts.
