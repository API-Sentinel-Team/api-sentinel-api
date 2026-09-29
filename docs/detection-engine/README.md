# Detection Engine

Version: `2026-03-29`

## Flow

The unified runtime path is:

`source adapters -> NormalizationAgent -> DetectionEnvelope -> RuleDetectionAgent -> DetectionSignal[] -> CorrelationAgent -> IncidentDecision -> EnforcementAgent`

## Current Source Adapters

- `ingestion/v2/events`
- queued stream-line ingestion
- queued HTTP traffic ingestion
- eBPF stream ingestion
- enriched stream aggregate detection
- detection meta control plane

## Runtime Modes

- `off`: legacy detectors remain authoritative
- `shadow`: new detectors run without canonical writes
- `active`: unified pipeline owns alerts, evidence, and enforcement

## Ownership Rules

- `RuleDetectionAgent` emits signals only
- `CorrelationAgent` is the sole canonical alert creator
- `EnforcementAgent` owns blocks, rate limits, endpoint circuit breakers, and token revocation

## Official References

- FastAPI middleware
- Starlette middleware
- SQLAlchemy asyncio
- Redis `INCR`
- Redis `EXPIRE`
- PyOD
- OWASP API Security Top 10 2023
