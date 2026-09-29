"""Render a benchmark result as a human-readable scorecard and JSON."""
from __future__ import annotations

import json
from typing import Any

from tests.benchmark.scoring import BenchmarkResult


def to_json(result: BenchmarkResult, *, indent: int = 2) -> str:
    return json.dumps(result.as_dict(), indent=indent, sort_keys=True)


def scorecard(result: BenchmarkResult, *, slo_fp_rate: float = 0.05) -> str:
    """Render a compact text scorecard suitable for CI logs / a dashboard panel."""
    data = result.as_dict()
    totals = data["totals"]
    lines: list[str] = []
    lines.append(f"API Sentinel Benchmark — {result.target_name}")
    lines.append("=" * 60)
    lines.append("")
    header = f"{'OWASP Category':<28}{'TP':>4}{'FP':>4}{'FN':>4}{'Prec':>8}{'Recall':>8}"
    lines.append(header)
    lines.append("-" * len(header))
    for cat, score in sorted(result.per_category.items()):
        lines.append(
            f"{cat:<28}{score.true_positives:>4}{score.false_positives:>4}"
            f"{score.false_negatives:>4}{score.precision:>8.2%}{score.recall:>8.2%}"
        )
    lines.append("-" * len(header))
    agg = result.totals
    lines.append(
        f"{'ALL':<28}{agg.true_positives:>4}{agg.false_positives:>4}"
        f"{agg.false_negatives:>4}{agg.precision:>8.2%}{agg.recall:>8.2%}"
    )
    lines.append("")

    fp_rate = result.high_critical_fp_rate
    slo_ok = result.meets_slo(slo_fp_rate)
    status = "PASS" if slo_ok else "FAIL"
    lines.append(
        f"High/Critical FP rate: {fp_rate:.2%} "
        f"({result.high_critical_false_positives}/{result.high_critical_total}) "
        f"— SLO <= {slo_fp_rate:.0%}: [{status}]"
    )
    if result.uncategorized_findings:
        lines.append(
            f"Uncategorized vulnerability findings: {result.uncategorized_findings} "
            f"(map their type in scoring._TYPE_TO_CATEGORY)"
        )
    lines.append("")
    return "\n".join(lines)


def summary_line(result: BenchmarkResult) -> str:
    """One-line summary for quick logs, e.g. for /loop or CI step output."""
    agg = result.totals
    return (
        f"{result.target_name}: precision={agg.precision:.0%} recall={agg.recall:.0%} "
        f"hc_fp_rate={result.high_critical_fp_rate:.1%} "
        f"(TP={agg.true_positives} FP={agg.false_positives} FN={agg.false_negatives})"
    )
