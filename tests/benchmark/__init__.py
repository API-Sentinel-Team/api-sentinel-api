"""API Sentinel benchmark harness.

Measures the platform's detection quality (precision, recall, false-positive
rate) against deliberately-vulnerable target corpora so the North Star SLOs
(<5% High/Critical false positives, evidence completeness, authorization
coverage) become measured numbers rather than asserted claims.

Two layers:

- ``scoring`` / ``corpus`` / ``report``: pure, deterministic, no network. Given
  a set of findings and a ground-truth corpus, compute per-OWASP-category
  precision/recall/F1 and the High/Critical FP rate. Fully unit-tested.
- ``runner``: drives the real ``ExecutionEngine`` against a live vulnerable
  target (VAmPI / crAPI) and feeds its findings into the scoring layer. Run
  manually with a target up; skipped automatically when no target is reachable.
"""
