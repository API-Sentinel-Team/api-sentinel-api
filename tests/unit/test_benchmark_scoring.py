"""Tests for the benchmark scoring engine and corpus model.

These verify the *measurement tool* is correct: path normalization, finding->
category mapping, and the precision/recall/FP-rate math. Pure, no network.
"""
from __future__ import annotations

import pytest

from tests.benchmark.corpus import Corpus, GroundTruth, normalize_path
from tests.benchmark.report import scorecard, summary_line, to_json
from tests.benchmark.scoring import category_for_finding, normalize_finding, score


# ── path normalization ───────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/users/42", "/users/{id}"),
        ("/users/42/email", "/users/{id}/email"),
        ("/users/{username}", "/users/{id}"),
        ("/users/550e8400-e29b-41d4-a716-446655440000", "/users/{id}"),
        ("/Users/V1/Login", "/users/v1/login"),
        ("/books/v1/the%20great", "/books/v1/the%20great"),
        ("/users/42?session=abc", "/users/{id}"),
        ("", "/"),
        ("users/7", "/users/{id}"),
    ],
)
def test_normalize_path(raw, expected):
    assert normalize_path(raw) == expected


# ── category mapping ─────────────────────────────────────────────────────────

def test_category_for_finding_explicit_wins():
    assert category_for_finding({"owasp_category": "API1_BOLA", "type": "ZAP:1"}) == "API1_BOLA"


def test_category_for_finding_type_map():
    assert category_for_finding({"type": "BOLA"}) == "API1_BOLA"
    assert category_for_finding({"type": "BFLA"}) == "API5_BFLA"


def test_category_for_finding_llm_prefix():
    assert category_for_finding({"type": "LLM_RAG_EXFILTRATION"}) == "LLM_API"


def test_category_for_finding_unmappable_returns_none():
    assert category_for_finding({"type": "SCHEMATHESIS:response_schema_conformance"}) is None


# ── corpus model ─────────────────────────────────────────────────────────────

def test_corpus_rejects_unknown_category():
    with pytest.raises(ValueError):
        GroundTruth(method="GET", path="/x", owasp_category="NOPE")


def test_corpus_loads_from_yaml(tmp_path):
    yaml_text = """
target_name: T
base_url: http://localhost:1
ground_truth:
  - method: GET
    path: "/users/v1/{username}"
    owasp_category: API3_BOPLA
    severity: HIGH
  - method: PUT
    path: "/users/v1/{username}/email"
    owasp_category: API1_BOLA
    severity: HIGH
"""
    p = tmp_path / "c.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    corpus = Corpus.load(p)
    assert corpus.target_name == "T"
    assert len(corpus.ground_truth) == 2
    assert corpus.categories() == {"API3_BOPLA", "API1_BOLA"}


# ── scoring math ─────────────────────────────────────────────────────────────

def _corpus() -> Corpus:
    return Corpus(
        target_name="T",
        base_url="http://localhost",
        ground_truth=[
            GroundTruth("PUT", "/users/v1/{username}/email", "API1_BOLA", "HIGH"),
            GroundTruth("DELETE", "/users/v1/{username}", "API5_BFLA", "CRITICAL"),
            GroundTruth("GET", "/users/v1/_debug", "API3_BOPLA", "HIGH"),
        ],
    )


def test_perfect_detection():
    findings = [
        {"method": "PUT", "path": "/users/v1/bob/email", "type": "BOLA", "severity": "HIGH", "is_vulnerable": True},
        {"method": "DELETE", "path": "/users/v1/bob", "type": "BFLA", "severity": "CRITICAL", "is_vulnerable": True},
        {"method": "GET", "path": "/users/v1/_debug", "owasp_category": "API3_BOPLA", "severity": "HIGH", "is_vulnerable": True},
    ]
    result = score(_corpus(), findings)
    totals = result.totals
    assert totals.true_positives == 3
    assert totals.false_positives == 0
    assert totals.false_negatives == 0
    assert totals.recall == 1.0
    assert totals.precision == 1.0
    assert result.high_critical_fp_rate == 0.0
    assert result.meets_slo()


def test_false_positive_counts_against_high_critical_rate():
    findings = [
        {"method": "PUT", "path": "/users/v1/bob/email", "type": "BOLA", "severity": "HIGH", "is_vulnerable": True},
        # A High BOLA claim on an endpoint with no ground-truth BOLA == false positive.
        {"method": "GET", "path": "/health", "type": "BOLA", "severity": "HIGH", "is_vulnerable": True},
    ]
    result = score(_corpus(), findings)
    assert result.per_category["API1_BOLA"].true_positives == 1
    assert result.per_category["API1_BOLA"].false_positives == 1
    assert result.high_critical_total == 2
    assert result.high_critical_false_positives == 1
    assert result.high_critical_fp_rate == 0.5
    assert not result.meets_slo()


def test_misses_become_false_negatives():
    findings = [
        {"method": "PUT", "path": "/users/v1/bob/email", "type": "BOLA", "severity": "HIGH", "is_vulnerable": True},
    ]
    result = score(_corpus(), findings)
    assert result.per_category["API5_BFLA"].false_negatives == 1
    assert result.per_category["API3_BOPLA"].false_negatives == 1
    assert result.totals.recall == pytest.approx(1 / 3)


def test_non_vulnerable_findings_ignored():
    findings = [
        {"method": "GET", "path": "/health", "type": "BOLA", "severity": "HIGH", "is_vulnerable": False},
    ]
    result = score(_corpus(), findings)
    assert result.totals.false_positives == 0
    assert result.high_critical_total == 0


def test_duplicate_match_not_double_counted():
    findings = [
        {"method": "PUT", "path": "/users/v1/alice/email", "type": "BOLA", "severity": "HIGH", "is_vulnerable": True},
        {"method": "PUT", "path": "/users/v1/bob/email", "type": "BOLA", "severity": "HIGH", "is_vulnerable": True},
    ]
    result = score(_corpus(), findings)
    # Same normalized identity twice -> one TP, no FP (dedup scored elsewhere).
    assert result.per_category["API1_BOLA"].true_positives == 1
    assert result.per_category["API1_BOLA"].false_positives == 0


def test_uncategorized_high_finding_hits_fp_rate():
    findings = [
        {"method": "GET", "path": "/x", "type": "SCHEMATHESIS:foo", "severity": "HIGH", "is_vulnerable": True},
    ]
    result = score(_corpus(), findings)
    assert result.uncategorized_findings == 1
    assert result.high_critical_false_positives == 1


# ── reporting ────────────────────────────────────────────────────────────────

def test_report_renders_without_error():
    result = score(_corpus(), [
        {"method": "PUT", "path": "/users/v1/bob/email", "type": "BOLA", "severity": "HIGH", "is_vulnerable": True},
    ])
    card = scorecard(result)
    assert "API Sentinel Benchmark" in card
    assert "High/Critical FP rate" in card
    assert "API1_BOLA" in card
    assert "precision=" in summary_line(result)
    parsed = to_json(result)
    assert '"target_name"' in parsed


def test_shipped_vampi_corpus_loads():
    from pathlib import Path

    corpus_path = Path(__file__).resolve().parents[1] / "benchmark" / "corpus" / "vampi.yaml"
    corpus = Corpus.load(corpus_path)
    assert corpus.target_name == "VAmPI"
    assert len(corpus.ground_truth) >= 5
    # Every category in the shipped corpus is valid (constructor would have raised).
    assert corpus.categories().issubset(
        {gt.owasp_category for gt in corpus.ground_truth}
    )
