# Advanced Backend Plan - Phase 1-4 Checklist

**Scope:** Phased delivery of the next-gen API security backend
**Last Updated:** 2026-03-13

## Status Legend
- `[ ]` Not started
- `[~]` In progress
- `[x]` Completed

## Phase 1 Checklist

### Workstream A - Data Plane + Ingestion v2
- [x] Canonical event schema (versioned) for traffic/logs/test results
- [x] Job-based ingestion v2 endpoint with validation, quotas, and queueing
- [x] DLQ + retry semantics for ingestion failures
- [x] Redaction/tokenization by default before storage
- [x] Ingestion job status + backpressure reporting API
- [x] Audit trail hook for ingestion actions

### Workstream B - Inventory + Drift
- [x] Endpoint normalization with path templates
- [x] Endpoint revision history storage for drift detection
- [x] Endpoint revisions API (`/api/endpoints/{id}/revisions`)

### Workstream C - OpenAPI Posture
- [x] OpenAPI reconstruction (account-aware)
- [x] OpenAPI spec storage + validation endpoint
- [x] Policy evaluation persists violations
- [x] Evidence artifacts stored for posture violations
- [x] Evidence listing API (`/api/evidence`)
- [x] Audit trail hook for policy actions

### Workstream D - Sensitive Data Engine
- [x] Persist PII findings as inventory artifacts
- [x] PII list API reads from stored findings (fast path)

### Workstream E - Control Plane Hardening
- [x] RBAC enforced on new endpoints
- [x] Tenant scoping on new endpoints
- [x] Audit trail hooks for policy + ingestion

### Workstream F - Tests
- [x] Unit tests for schema validation, redaction, policy evaluation
- [x] Integration tests for ingestion v2 + job status
- [x] Inventory tests for drift tracking and OpenAPI validation
- [x] Security tests for RBAC boundaries on new endpoints

## Phase 2 Checklist

### Workstream G - Behavioral Detection
- [x] Actor profiling storage model
- [x] Ingestion hook updates actor profiles
- [x] Baseline detection (burst + latency anomalies)

### Workstream H - Evidence + Alerts
- [x] Evidence records for detections
- [x] Alert creation from detection engine

### Workstream I - Phase 2 Tests
- [x] Unit tests for actor profiling and detection

## Phase 3 Checklist

### Workstream J - Business Logic Graph
- [x] BLG build/rebuild pipeline
- [x] BLG violations + evidence artifacts
- [x] BLG APIs (`/api/business-logic/*`)

### Workstream K - Automated Security Testing
- [x] Safety controls (test header, destructive method gating)
- [x] CI/CD feedback artifacts (SARIF/JUnit)

## Phase 4 Checklist

### Workstream L - MCP/Agentic Security
- [x] MCP tool invocation telemetry
- [x] Agent identity + trust-chain enforcement
- [x] Prompt injection detection on tool outputs
- [x] Agentic violations + evidence artifacts

## Completed
- Phase 1 foundation (ingestion v2, posture, drift, PII, RBAC, tests).
- Phase 2 behavioral detection with alerts + evidence.
- Phase 3 BLG foundations with rebuild and violation detection.
- Phase 4 MCP/agentic telemetry and guardrails.

## Next Up (Top 3)
1. Expand agentic analytics dashboards (top tools, risky agents).
2. Add compliance export coverage for PCI/GDPR/SOC2/AI Act mappings.
3. Run full integration and security test suite.
