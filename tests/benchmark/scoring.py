"""Scoring engine: compare platform findings to a ground-truth corpus.

Pure and deterministic — no network, no DB. Given a list of normalized findings
and a :class:`~tests.benchmark.corpus.Corpus`, compute per-category and overall
precision, recall, F1, and the High/Critical false-positive rate that the North
Star SLO is stated against (<5%).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from tests.benchmark.corpus import (
    HIGH_CRITICAL,
    OWASP_API_CATEGORIES,
    Corpus,
    GroundTruth,
    normalize_path,
)

# Map the platform's finding ``type`` (and template-id prefixes) to OWASP
# categories. Kept explicit rather than inferred so a miscategorized finding is
# a visible config change, not silent drift.
_TYPE_TO_CATEGORY: dict[str, str] = {
    "BOLA": "API1_BOLA",
    "BFLA": "API5_BFLA",
    "BROKEN_AUTH": "API2_BROKEN_AUTH",
}

# Injection findings (SQLi/NoSQLi/command) map to API8 misconfiguration/injection
# surface in the OWASP API category model used here. ZAP/Nuclei misconfig and
# header findings also land in API8.
_PREFIX_TO_CATEGORY: tuple[tuple[str, str], ...] = (
    ("LLM_", "LLM_API"),
    ("SQLI", "API8_MISCONFIGURATION"),
    ("NOSQLI", "API8_MISCONFIGURATION"),
    ("INJECTION", "API8_MISCONFIGURATION"),
    ("SSRF", "API7_SSRF"),
    ("MASS_ASSIGNMENT", "API3_BOPLA"),
    ("EXCESSIVE_DATA", "API3_BOPLA"),
    ("SENSITIVE_DATA_EXPOSURE", "API3_BOPLA"),
)


def category_for_finding(finding: dict[str, Any]) -> str | None:
    """Resolve a finding's OWASP category from its type/template metadata.

    Order: explicit ``owasp_category`` field > exact ``type`` map > type prefix.
    Returns ``None`` when the finding cannot be mapped (counted as uncategorized).
    """
    explicit = str(finding.get("owasp_category") or "").strip().upper()
    if explicit in OWASP_API_CATEGORIES:
        return explicit

    finding_type = str(finding.get("type") or "").strip().upper()
    if finding_type in _TYPE_TO_CATEGORY:
        return _TYPE_TO_CATEGORY[finding_type]
    for prefix, category in _PREFIX_TO_CATEGORY:
        if finding_type.startswith(prefix):
            return category
    return None


@dataclass(frozen=True)
class NormalizedFinding:
    """A platform finding reduced to its scoring identity."""

    method: str
    path: str
    owasp_category: str | None
    severity: str
    is_vulnerable: bool

    @property
    def identity(self) -> tuple[str, str, str | None]:
        return (self.method.upper(), normalize_path(self.path), self.owasp_category)


def normalize_finding(finding: dict[str, Any]) -> NormalizedFinding:
    return NormalizedFinding(
        method=str(finding.get("method") or "GET"),
        path=str(finding.get("path") or finding.get("url") or "/"),
        owasp_category=category_for_finding(finding),
        severity=str(finding.get("severity") or "INFO").upper(),
        is_vulnerable=bool(finding.get("is_vulnerable", True)),
    )


@dataclass
class CategoryScore:
    category: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class BenchmarkResult:
    target_name: str
    per_category: dict[str, CategoryScore] = field(default_factory=dict)
    high_critical_total: int = 0
    high_critical_false_positives: int = 0
    uncategorized_findings: int = 0

    @property
    def totals(self) -> CategoryScore:
        agg = CategoryScore(category="ALL")
        for score in self.per_category.values():
            agg.true_positives += score.true_positives
            agg.false_positives += score.false_positives
            agg.false_negatives += score.false_negatives
        return agg

    @property
    def high_critical_fp_rate(self) -> float:
        return (
            self.high_critical_false_positives / self.high_critical_total
            if self.high_critical_total
            else 0.0
        )

    def meets_slo(self, max_high_critical_fp_rate: float = 0.05) -> bool:
        return self.high_critical_fp_rate <= max_high_critical_fp_rate

    def as_dict(self) -> dict[str, Any]:
        totals = self.totals
        return {
            "target_name": self.target_name,
            "totals": {
                **totals.as_dict(),
                "category": "ALL",
            },
            "high_critical_fp_rate": round(self.high_critical_fp_rate, 4),
            "high_critical_total": self.high_critical_total,
            "high_critical_false_positives": self.high_critical_false_positives,
            "uncategorized_findings": self.uncategorized_findings,
            "per_category": {
                cat: score.as_dict() for cat, score in sorted(self.per_category.items())
            },
        }


def score(corpus: Corpus, findings: Iterable[dict[str, Any]]) -> BenchmarkResult:
    """Score raw platform findings against a corpus.

    A finding is a TRUE POSITIVE if its (method, path, category) identity matches
    a ground-truth entry. Findings claiming a vulnerability whose identity is not
    in the corpus are FALSE POSITIVES. Ground-truth entries never matched are
    FALSE NEGATIVES (misses). Non-vulnerable findings are ignored.
    """
    result = BenchmarkResult(target_name=corpus.target_name)

    # Seed a score bucket for every category that appears in ground truth so
    # totally-missed categories still surface (recall 0), not silently absent.
    for category in corpus.categories():
        result.per_category.setdefault(category, CategoryScore(category=category))

    matched_gt: set[int] = set()

    for raw in findings:
        nf = normalize_finding(raw)
        if not nf.is_vulnerable:
            continue

        if nf.owasp_category is None:
            result.uncategorized_findings += 1
            # Uncategorized vuln claims still count toward the FP-rate denominator
            # when they are High/Critical, because they are surfaced to a user.
            if nf.severity in HIGH_CRITICAL:
                result.high_critical_total += 1
                result.high_critical_false_positives += 1
            continue

        bucket = result.per_category.setdefault(
            nf.owasp_category, CategoryScore(category=nf.owasp_category)
        )
        is_high_critical = nf.severity in HIGH_CRITICAL
        if is_high_critical:
            result.high_critical_total += 1

        gt_index = _match_ground_truth(corpus.ground_truth, nf)
        if gt_index is not None:
            if gt_index not in matched_gt:
                bucket.true_positives += 1
                matched_gt.add(gt_index)
            # A duplicate match for an already-counted ground-truth entry is
            # neither a new TP nor an FP — dedup is the platform's job, scored
            # elsewhere.
        else:
            bucket.false_positives += 1
            if is_high_critical:
                result.high_critical_false_positives += 1

    # Anything in ground truth we never matched is a miss.
    for index, gt in enumerate(corpus.ground_truth):
        if index not in matched_gt:
            result.per_category[gt.owasp_category].false_negatives += 1

    return result


def _match_ground_truth(
    ground_truth: list[GroundTruth], finding: NormalizedFinding
) -> int | None:
    """Return the index of the first ground-truth entry a finding matches, else None.

    Matching is method + category exact, and path matched segment-by-segment
    where a corpus ``{id}`` (templated) segment is a wildcard for any concrete
    finding segment. This is what lets corpus ``/users/v1/{username}/email`` match
    a finding on ``/users/v1/bob/email`` even though "bob" isn't a numeric id.
    """
    for index, gt in enumerate(ground_truth):
        if gt.owasp_category != finding.owasp_category:
            continue
        if gt.method.upper() != finding.method.upper():
            continue
        if _paths_match(gt.path, finding.path):
            return index
    return None


def _paths_match(corpus_path: str, finding_path: str) -> bool:
    corpus_norm = normalize_path(corpus_path)
    finding_norm = normalize_path(finding_path)
    corpus_segs = corpus_norm.split("/")
    finding_segs = finding_norm.split("/")
    if len(corpus_segs) != len(finding_segs):
        return False
    for c_seg, f_seg in zip(corpus_segs, finding_segs):
        if c_seg == "{id}":
            continue  # wildcard: any concrete segment matches a templated one
        if c_seg != f_seg:
            return False
    return True
