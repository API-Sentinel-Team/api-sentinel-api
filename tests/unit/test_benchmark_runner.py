"""Tests for the benchmark runner's pure helpers (no Docker / live target)."""
from __future__ import annotations

from tests.benchmark.corpus import Corpus, GroundTruth
from tests.benchmark.runner import (
    _endpoint_for,
    _finding_from_engine_result,
    run,
    target_reachable,
)


def test_endpoint_for_substitutes_templated_segments():
    ep = _endpoint_for("http://localhost:5000", "PUT", "/users/v1/{username}/email")
    assert ep["method"] == "PUT"
    assert ep["url"] == "http://localhost:5000/users/v1/1/email"
    assert ep["path"] == "/users/v1/{username}/email"  # corpus form preserved
    assert ep["host"] == "localhost:5000"
    assert ep["protocol"] == "http"


def test_endpoint_for_plain_path():
    ep = _endpoint_for("http://localhost:5000", "GET", "/users/v1/_debug")
    assert ep["url"] == "http://localhost:5000/users/v1/_debug"


def test_finding_adapter_pulls_severity_from_info_block():
    raw = {"template_id": "t1", "is_vulnerable": True, "info": {"severity": "HIGH"}}
    finding = _finding_from_engine_result(method="GET", path="/x", engine_result=raw)
    assert finding["severity"] == "HIGH"
    assert finding["type"] == "t1"
    assert finding["is_vulnerable"] is True
    assert finding["method"] == "GET"
    assert finding["path"] == "/x"


def test_finding_adapter_prefers_explicit_type_and_severity():
    raw = {"template_id": "t1", "type": "BOLA", "severity": "CRITICAL", "is_vulnerable": True}
    finding = _finding_from_engine_result(method="DELETE", path="/u/1", engine_result=raw)
    assert finding["type"] == "BOLA"
    assert finding["severity"] == "CRITICAL"


def test_run_agentic_returns_none_when_target_unreachable():
    # The agentic path also skips cleanly when the target is down.
    corpus = Corpus(
        target_name="Down",
        base_url="http://127.0.0.1:1",
        ground_truth=[GroundTruth("GET", "/x", "API1_BOLA")],
    )
    assert run(corpus, agentic=True) is None


def test_run_returns_none_when_target_unreachable():
    # Port 1 is reserved/unused — guaranteed unreachable, so run() must skip.
    corpus = Corpus(
        target_name="Down",
        base_url="http://127.0.0.1:1",
        ground_truth=[GroundTruth("GET", "/x", "API1_BOLA")],
    )
    assert target_reachable("http://127.0.0.1:1", timeout=0.5) is False
    assert run(corpus) is None
