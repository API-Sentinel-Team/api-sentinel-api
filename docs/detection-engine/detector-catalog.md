# Detector Catalog

## Detectors

- `InjectionDetector`
- `SSRFDetector`
- `BOLADetector`
- `BFLADetector`
- `ResourceAbuseDetector`
- `BotDetector`
- `AuthAnomalyDetector`
- `ExfiltrationDetector`
- `BurstDetector`
- `BehavioralBaselineDetector`

## Signal Model

Each detector receives a normalized `DetectionEnvelope` plus derived state and returns zero or more `DetectionSignal` records.

## Scoring

Composite scoring uses these weighted inputs when present:

- rule
- behavioral
- ML
- sequence
- reputation

Missing inputs are treated as absent and the final score is renormalized across available weights.
