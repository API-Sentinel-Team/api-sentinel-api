# API Sentinel North Star Gap Analysis

**Review date:** 2026-09-13  
**Scope:** API penetration testing, authenticated API testing, evidence, safety, continuous operation, and production deployment.

## Verdict

API Sentinel has a substantial production-oriented foundation, but the North Star is **not complete**. The codebase contains guards, auth profiles, evidence hashing/redaction, replay utilities, engine adapters, business-logic and LLM detectors, lifecycle helpers, and CI accountability tests. The remaining risk is integration: the operator-facing readiness result can report capabilities from function/config presence even when the deployed execution path cannot run them end to end.

Focused verification passed **138 tests**: 85 North Star/engine/worker/business-logic/LLM unit tests and 53 CI-gate/router integration tests. These tests validate contracts and mocked adapters; they do not prove a real isolated worker has executed Schemathesis, Nuclei, or ZAP against an allowlisted API.

## Current Status By Capability

| Capability | Status | Evidence and gap |
|---|---|---|
| Authenticated-by-default | Partial / strong foundation | Auth preflight and encrypted profile material exist. Every active route still needs a live end-to-end test proving auth reaches every engine and fails closed when credentials expire. |
| Target, SSRF, and destructive safety | Implemented in code; deployment proof pending | Target and state-change guards are present. Production needs canary tests for DNS rebinding, redirects, private targets, destructive verbs, kill switch, and concurrency limits. |
| Multi-engine execution | **P0 incomplete** | `engine_plan.py:13-105` lists all engines, but `scan_worker.py:1783-1803` dispatches queued work to templates or authorization replay only. Schemathesis, Nuclei, and ZAP are called directly by API routes (`pentest.py:907`, `1222`, `1534`), so they are request-local rather than isolated-worker executions. |
| Continuous authenticated testing | Partial | Scheduler and preflight code exist, but the active cluster disables continuous testing (`k8s/25-config.yaml:34`) and uses `PENTEST_SCAN_EXECUTION_MODE: inline` (`:44`) even though settings define `background` or `queued` (`server/config.py:144`). |
| Multi-identity BOLA/BFLA | Partial | Replay and BFLA matrix modules exist. The prepare path does not pass `test_accounts_count` to `build_engine_plan` (`orchestrator.py:105-113`), and selection does not pass role context to `_selection_coverage_targets` (`orchestrator.py:423-448`). Readiness therefore cannot prove identity coverage for the selected run. |
| Evidence and confirmatory retests | Partial | Hashing, redaction, artifact manifests, retest support, and policy checks exist. `orchestrator.py:258-294` reports lifecycle/governance controls from helpers and policy values, not from a persisted finding-to-retest-to-resolution workflow. |
| Business logic | Partial | Coupon, OTP, workflow, monetary, and resource scenarios are generated (`business_logic/active_tests.py:15-32`). Graph analysis detects missing/forbidden/too-fast transitions (`graph_builder.py:129-176`), but there is no durable, stateful flow executor that performs and verifies complete business journeys with reset/rollback semantics. |
| LLM API security | Partial / opt-in | Signal detection and deterministic evidence validation exist. Agentic LLM execution is disabled by default (`config.py:308-315`), and coverage is primarily endpoint/body heuristics. Prompt injection, system-prompt leakage, RAG exfiltration, and unsafe tool-call tests need live fixtures, deterministic judges, and a blocking policy that never promotes an unconfirmed signal. |
| Reporting, ticketing, SLA, governance | Partial | Policy packs, RBAC, tenant filters, audit helpers, and artifact generation exist. The active Kubernetes deployment has RLS disabled (`k8s/25-config.yaml:13`), analytics/archiving/OpenAPI drift disabled (`:31-36`), no deployed scan-worker workload, and no visible NetworkPolicy. |
| CI/CD gates | Partial / good foundation | JUnit and coverage artifacts are required. SARIF is collected/uploaded only when present (`.github/workflows/ci.yml:155-180`), so missing SARIF can pass. GitHub actions are tag-pinned, and scan-worker binaries are downloaded without checksum/signature verification (`Dockerfile.scan-worker:45-64`). |

## Highest-Priority Pending Work

### P0: Make queued isolated execution real

1. Add a worker dispatcher contract carrying the selected engine plan, auth profile reference, target scope, policy pack, and run identifier.
2. Implement worker handlers for Schemathesis, Nuclei, ZAP, passive analysis, business-logic flows, and LLM probes. Each handler must persist an engine-specific artifact and signed evidence record.
3. Add the scan-worker Deployment/Job/RBAC/service-account flow to the actual Helm chart and `k8s/` deployment. Pin images by digest, not `latest`.
4. Change the production configuration from `inline` to an accepted queued mode only after a worker smoke test succeeds.
5. Add an integration test that queues one run and asserts every enabled engine executes in isolation, produces an artifact, and is reflected in the final run summary.

### P0: Make readiness truthful

Replace hardcoded values in `orchestrator.py:165-178` and callable-presence checks in `:258-294` with runtime probes and persisted run facts. Readiness must be false when an engine worker is absent, test accounts are missing, the target is not allowlisted, an artifact is absent, or a retest cannot be scheduled.

### P1: Close coverage and lifecycle gaps

- Wire real test-account and role-matrix context into selection, plan construction, execution, and coverage reporting.
- Build stateful business-flow execution with graph versioning, prerequisite replay, bounded mutations, test-data isolation, cleanup, and deterministic impact verification.
- Add live LLM API fixtures for injection, leakage, RAG, and tool-call scenarios. Require judge evidence plus confirmatory retest before creating a blocking finding.
- Make “unconfirmed,” “confirmed,” “retested,” “fixed,” and “reopened” explicit lifecycle states with deduplication, SLA timers, and real ticket-provider synchronization.
- Require non-empty, schema-valid SARIF where the selected policy pack requests it; retain JUnit, SARIF, evidence manifests, and engine artifacts together.

### P1: Production hardening

Enable and verify tenant RLS, analytics, archiving, OpenAPI drift detection, and a continuous-testing profile in the deployment environment. Add NetworkPolicies, workload identity, secret rotation, image and binary provenance checks, dependency auditing, and secret scanning configuration. Remove the unused `PENTEST_ALLOW_NUCLEI_SIMULATION` setting or document and test a safe explicit simulation mode.

## Completion Gate

The North Star should be declared complete only when a staging canary demonstrates: authenticated queued execution across all enabled engines; two-identity BOLA/BFLA replay; bounded business-flow and LLM probes; redacted reproducible evidence; deterministic judge plus confirmatory retest; dedup/SLA/ticket transitions; valid SARIF/JUnit/report artifacts; tenant isolation; and an auditable kill-switch test. Until then, the repository is a capable foundation, not a world-class production API red-team platform.

## Audit Note

This is a repository and deployment-configuration audit, not authorization to probe any third-party system. Active testing must remain restricted to explicitly owned and allowlisted targets with approved test accounts and change windows.
