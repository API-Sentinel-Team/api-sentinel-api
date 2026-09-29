"""Tests for the crAPI benchmark corpus + provisioner (no live crAPI needed)."""
from __future__ import annotations

from pathlib import Path

from tests.benchmark.corpus import OWASP_API_CATEGORIES, Corpus, normalize_path
from tests.benchmark.scoring import score
from tests.benchmark.targets.crapi_auth import provision_crapi_identities


_CORPUS = Path(__file__).resolve().parents[1] / "benchmark" / "corpus" / "crapi.yaml"


def test_crapi_corpus_loads_with_valid_categories():
    corpus = Corpus.load(_CORPUS)
    assert corpus.target_name == "crAPI"
    assert len(corpus.ground_truth) >= 10
    # Every category in the corpus is a valid OWASP category.
    assert corpus.categories().issubset(OWASP_API_CATEGORIES)


def test_crapi_corpus_covers_phase2_phase3_categories():
    # The whole point of crAPI is exercising what VAmPI cannot: BFLA (role),
    # business-logic flows, and SSRF.
    cats = Corpus.load(_CORPUS).categories()
    assert "API5_BFLA" in cats
    assert "API6_SENSITIVE_BUSINESS_FLOW" in cats
    assert "API7_SSRF" in cats


def test_crapi_paths_normalize_consistently():
    # GUID/templated vehicle + order paths collapse so findings match ground truth.
    assert normalize_path("/identity/api/v2/vehicle/{vehicleId}/location") == "/identity/api/v2/vehicle/{id}/location"
    assert normalize_path("/workshop/api/shop/orders/550e8400-e29b-41d4-a716-446655440000") == "/workshop/api/shop/orders/{id}"


def test_scoring_credits_a_matching_crapi_bola_finding():
    corpus = Corpus.load(_CORPUS)
    findings = [
        {"method": "GET", "path": "/identity/api/v2/vehicle/abc-123/location",
         "type": "BOLA", "severity": "HIGH", "is_vulnerable": True},
    ]
    result = score(corpus, findings)
    assert result.per_category["API1_BOLA"].true_positives == 1
    assert result.per_category["API1_BOLA"].false_positives == 0


def test_crapi_provisioner_returns_empty_when_unreachable():
    # Port 1 is unused -> signup/login fail, no env tokens -> [] (clean skip).
    assert provision_crapi_identities("http://127.0.0.1:1", timeout=0.5) == []
