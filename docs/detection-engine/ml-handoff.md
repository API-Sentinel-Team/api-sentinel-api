# ML Handoff

## Current Boundary

The unified detection engine is production-safe without ML.

## Recommended ML Integration Point

Feed ML scores into the envelope metadata as `ml_score` and let `CorrelationAgent` blend them into composite scoring.

## Requirements Before Cutover

- versioned model registry
- shadow-vs-active comparison metrics
- confidence calibration
- rollback switch independent from pipeline mode
