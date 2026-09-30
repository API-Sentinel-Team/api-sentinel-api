# API Sentinel Detection Benchmark

Turns the North Star SLOs (<5% High/Critical false positives, authorization
coverage, evidence completeness) from **claims** into **measured numbers**.

It scans a deliberately-vulnerable target whose vulnerabilities are known ahead
of time (the *corpus*), compares what the platform found against that ground
truth, and reports per-OWASP-category precision/recall and the High/Critical
false-positive rate.

## Layout

| File | Role |
| --- | --- |
| `corpus.py` | Ground-truth model + path normalization. Pure. |
| `scoring.py` | Findings vs corpus → precision/recall/FP-rate. Pure, fully unit-tested. |
| `report.py` | Renders a text scorecard, one-line summary, and JSON. |
| `runner.py` | Drives the **real** `ExecutionEngine` against a live target, then scores. |
| `corpus/vampi.yaml` | Ground truth for VAmPI. |
| `targets/docker-compose.yml` | Spins up the vulnerable targets. |

The scoring/corpus/report layer has **no network or DB dependency** and is
covered by `tests/unit/test_benchmark_scoring.py`, so it runs in the normal
suite. The live runner is opt-in.

## Run it

```bash
# 1. Start the vulnerable target (isolated/owned env only — these are insecure apps)
docker compose -f tests/benchmark/targets/docker-compose.yml up -d vampi

# 2. Allow private targets so TargetGuard permits localhost (dev/benchmark only)
export PENTEST_ALLOW_PRIVATE_TARGETS=true   # or set DEBUG=true

# 3. Run the benchmark
python -m tests.benchmark.runner tests/benchmark/corpus/vampi.yaml

# JSON for a dashboard / CI artifact:
python -m tests.benchmark.runner tests/benchmark/corpus/vampi.yaml --json
```

Exit code is `0` when the High/Critical FP-rate SLO is met, `1` when it is
breached, `2` when the target is unreachable (skipped, not failed).

## Adding a target

1. Add a corpus YAML under `corpus/` listing each known vulnerability with its
   `method`, `path`, and `owasp_category` (see `corpus.py:OWASP_API_CATEGORIES`).
   Use `{templated}` path segments — they match any concrete value in a finding.
2. Add the target to `targets/docker-compose.yml`.
3. Run the runner against the new corpus.

## Why this matters

You cannot claim "<5% false positives" without measuring it. This harness is the
scoreboard: every change to selection, judging, or a new engine should be run
against the corpus to confirm precision did not regress and recall improved.
Track the numbers over time — that trend line is the credible, world-class signal.
