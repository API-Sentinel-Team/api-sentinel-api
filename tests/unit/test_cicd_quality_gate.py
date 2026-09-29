import hashlib
import json

from server.models import core as models
from server.modules.cicd.policy_packs import resolve_policy_pack
from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
from server.modules.test_executor.evidence import evidence_digest
from server.modules.cicd.quality_gate import (
    attach_decision_integrity,
    evaluate_quality_gate,
    parse_fail_on,
    verify_quality_gate_decision_integrity,
)


def _hashed_evidence(**overrides):
    evidence = {
        "engine": "template",
        "template_id": overrides.pop("template_id", "auth-bypass"),
        "results": [{"vulnerable": True}],
        "evidence_completeness": {
            "complete": True,
            "required": [
                "status",
                "matched_rule",
                "sent_request",
                "received_response",
                "similarity",
                "reproduction",
                "remediation",
            ],
            "present": [
                "status",
                "matched_rule",
                "sent_request",
                "received_response",
                "similarity",
                "reproduction",
                "remediation",
            ],
            "missing": [],
        },
        "retest_support": {
            "supported": True,
            "queued_scan_supported": True,
            "manual_outcome_supported": True,
            "reason": "queued_scan_available",
            "missing_fields": [],
        },
    }
    evidence.update(overrides)
    evidence["hash_algorithm"] = "sha256"
    evidence["evidence_hash"] = evidence_digest(evidence)
    return json.dumps(evidence, sort_keys=True)


def _engine_execution_artifact(engine: str, *, engine_plan: list[dict], status: str = "COMPLETED") -> dict:
    payload = build_execution_artifact_payload(
        engine=engine,
        target_url="https://api.example.com/health",
        profile_id="profile-1",
        execution={
            "status": status,
            "command": f"{engine} runtime",
            "summary": {"requests_sent": 1},
        },
        engine_plan=engine_plan,
        findings={"created_count": 0},
        auth_context={
            "authenticated": True,
            "status": "ready",
            "reason": "auth_profile_ready",
            "has_runtime_credentials": True,
        },
    )
    payload["artifact_type"] = "passive_findings" if engine == "passive" else f"{engine}_execution"
    return payload


def _refresh_artifact_hash(payload: dict) -> None:
    from server.modules.pentest.execution_artifacts import (
        _artifact_digest,
        verify_execution_artifact_payload,
    )

    payload["artifact_hash"] = _artifact_digest(payload)
    payload["artifact_verification"] = verify_execution_artifact_payload(payload)


def _expected_decision_hash(decision: dict) -> str:
    covered = {
        key: value
        for key, value in decision.items()
        if key != "decision_integrity"
    }
    canonical = json.dumps(covered, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_quality_gate_fails_on_blocking_severity():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED", pentest_profile_id="profile-1")
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-bypass",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(template_id="auth-bypass"),
        ),
        models.TestResult(
            id="result-2",
            run_id="run-1",
            endpoint_id="endpoint-2",
            template_id="info-leak",
            is_vulnerable=True,
            severity="LOW",
            evidence=_hashed_evidence(template_id="info-leak"),
        ),
    ]

    decision = evaluate_quality_gate(run, results)

    assert decision["status"] == "FAILED"
    assert decision["passed"] is False
    assert decision["reason"] == "blocking_findings_present"
    assert decision["exit_code"] == 1
    assert decision["counts"]["by_severity"]["HIGH"] == 1
    assert decision["counts"]["by_severity"]["LOW"] == 1
    assert decision["failing_results"][0]["template_id"] == "auth-bypass"


def test_quality_gate_allows_custom_fail_on_thresholds():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED", pentest_profile_id="profile-1")
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-bypass",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(template_id="auth-bypass"),
        ),
    ]

    decision = evaluate_quality_gate(run, results, fail_on="CRITICAL")

    assert decision["status"] == "PASSED"
    assert decision["passed"] is True
    assert decision["counts"]["failing_results"] == 0


def test_quality_gate_fails_on_scan_errors_by_default():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED", pentest_profile_id="profile-1")
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="ssrf",
            is_vulnerable=False,
            severity="MEDIUM",
            error="target timeout",
        ),
    ]

    decision = evaluate_quality_gate(run, results)

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "scan_errors_present"
    assert decision["counts"]["errored_results"] == 1
    assert decision["errored_results"][0]["error"] == "target timeout"


def test_quality_gate_redacts_error_text_at_output_boundary():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED", pentest_profile_id="profile-1")
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="engine-crash",
            is_vulnerable=False,
            severity="MEDIUM",
            error="runner failed with Authorization: Bearer raw-token api_key=raw-key",
        ),
    ]

    decision = evaluate_quality_gate(run, results)
    blob = str(decision)

    assert decision["status"] == "FAILED"
    assert decision["errored_results"][0]["error"] == "runner failed with Authorization: Bearer **** api_key=****"
    assert "raw-token" not in blob
    assert "raw-key" not in blob


def test_quality_gate_fails_when_completed_run_has_no_executed_tests():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=0,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="destructive-delete",
            is_vulnerable=False,
            severity="LOW",
            skip_reason="state_change_guard",
            evidence="state_change_guard=blocked",
        ),
        models.TestResult(
            id="result-2",
            run_id="run-1",
            endpoint_id="endpoint-2",
            template_id="ssrf",
            is_vulnerable=False,
            severity="MEDIUM",
            skip_reason="target_guard",
            evidence="target_guard=blocked",
        ),
    ]

    decision = evaluate_quality_gate(run, results)

    assert decision["status"] == "FAILED"
    assert decision["passed"] is False
    assert decision["reason"] == "no_executed_tests"
    assert decision["exit_code"] == 1
    assert decision["counts"]["executed_results"] == 0
    assert decision["counts"]["skipped_results"] == 2
    assert decision["skipped_results"][0]["skip_reason"] == "state_change_guard"


def test_quality_gate_includes_redacted_safety_policy_for_skipped_results():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=0,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="ssrf",
            is_vulnerable=False,
            severity="MEDIUM",
            skip_reason="target_guard",
            evidence=_hashed_evidence(
                template_id="ssrf",
                safety_policies={
                    "target_guard_policy": {
                        "policy": "target_guard",
                        "blocked": True,
                        "url": "https://api.example.com/search?token=raw-token",
                        "base_url": "https://api.example.com/search?token=raw-token",
                        "reason": "Authorization: Bearer raw-token token=raw-token",
                    }
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(run, results)

    skipped = decision["skipped_results"][0]
    assert skipped["skip_reason"] == "target_guard"
    assert skipped["safety_policies"]["target_guard_policy"]["url"] == "https://api.example.com/search?token=****"
    assert skipped["safety_policies"]["target_guard_policy"]["reason"] == "Authorization: Bearer **** token=****"
    assert "raw-token" not in str(skipped)


def test_quality_gate_can_require_safety_policy_coverage():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=2,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="ssrf",
            is_vulnerable=False,
            severity="MEDIUM",
            evidence=_hashed_evidence(
                template_id="ssrf",
                safety_policies={
                    "target_guard_policy": {
                        "policy": "target_guard",
                        "blocked": False,
                        "url": "https://api.example.com/search",
                    }
                },
            ),
        ),
        models.TestResult(
            id="result-2",
            run_id="run-1",
            endpoint_id="endpoint-2",
            template_id="legacy-state-change",
            is_vulnerable=False,
            severity="LOW",
            evidence=_hashed_evidence(template_id="legacy-state-change"),
        ),
    ]

    decision = evaluate_quality_gate(run, results, require_safety_policies=True)

    assert decision["status"] == "FAILED"
    assert decision["passed"] is False
    assert decision["reason"] == "missing_safety_policy_evidence"
    assert decision["policy"]["require_safety_policies"] is True
    assert decision["counts"]["missing_safety_policy_results"] == 2
    assert decision["counts"]["missing_target_guard_policy_results"] == 1
    assert decision["counts"]["missing_state_change_policy_results"] == 2
    assert decision["missing_safety_policy_results"][0]["template_id"] == "ssrf"
    assert decision["missing_safety_policy_results"][0]["missing_safety_policies"] == [
        "state_change_policy"
    ]
    assert decision["missing_safety_policy_results"][1]["missing_safety_policies"] == [
        "target_guard_policy",
        "state_change_policy",
    ]


def test_quality_gate_requires_auth_scope_policy_for_auth_scope_guard_skips():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=0,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-scope-blocked",
            is_vulnerable=False,
            severity="INFO",
            skip_reason="auth_profile_scope_guard",
            evidence=_hashed_evidence(
                template_id="auth-scope-blocked",
                safety_policies={
                    "target_guard_policy": {
                        "policy": "target_guard",
                        "blocked": False,
                        "url": "https://api.example.com/users",
                    },
                    "state_change_policy": {
                        "policy": "state_change_guard",
                        "method": "GET",
                        "destructive_method": False,
                        "allow_state_change": False,
                        "allow_destructive_methods": False,
                    },
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        fail_on_no_execution=False,
        require_safety_policies=True,
    )

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "missing_safety_policy_evidence"
    assert decision["counts"]["missing_auth_profile_scope_policy_results"] == 1
    assert decision["missing_safety_policy_results"][0]["missing_safety_policies"] == [
        "auth_profile_scope_policy"
    ]


def test_quality_gate_accepts_redacted_auth_scope_policy_for_auth_scope_guard_skips():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=0,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-scope-blocked",
            is_vulnerable=False,
            severity="INFO",
            skip_reason="auth_profile_scope_guard",
            evidence=_hashed_evidence(
                template_id="auth-scope-blocked",
                safety_policies={
                    "auth_profile_scope_policy": {
                        "policy": "auth_profile_scope_guard",
                        "blocked": True,
                        "url": "https://evil.example.net/users?token=raw-token",
                        "base_url": "https://api.example.com/users?token=raw-token",
                        "reason": "Authorization: Bearer raw-token token=raw-token",
                        "auth_profile_id": "auth-profile-1",
                        "scope_domains_configured": True,
                        "scope_domain_count": 1,
                    },
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        fail_on_no_execution=False,
        require_safety_policies=True,
    )

    assert decision["status"] == "PASSED"
    assert decision["counts"]["missing_safety_policy_results"] == 0
    policy = decision["safety_policy_results"][0]["safety_policies"]["auth_profile_scope_policy"]
    assert policy["url"] == "https://evil.example.net/users?token=****"
    assert policy["base_url"] == "https://api.example.com/users?token=****"
    assert policy["reason"] == "Authorization: Bearer **** token=****"
    assert "raw-token" not in str(decision)


def test_quality_gate_passes_when_required_safety_policies_are_present_and_redacted():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="destructive-delete",
            is_vulnerable=False,
            severity="LOW",
            evidence=_hashed_evidence(
                template_id="destructive-delete",
                safety_policies={
                    "target_guard_policy": {
                        "policy": "target_guard",
                        "blocked": False,
                        "url": "https://api.example.com/users?token=raw-token",
                    },
                    "state_change_policy": {
                        "policy": "state_change_guard",
                        "method": "DELETE",
                        "destructive_method": True,
                        "allow_state_change": True,
                        "allow_destructive_methods": False,
                        "reason": "Authorization: Bearer raw-token",
                    },
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(run, results, require_safety_policies=True)

    assert decision["status"] == "PASSED"
    assert decision["passed"] is True
    assert decision["counts"]["missing_safety_policy_results"] == 0
    assert decision["policy"]["require_safety_policies"] is True
    assert decision["safety_policy_results"][0]["safety_policies"]["target_guard_policy"]["url"] == (
        "https://api.example.com/users?token=****"
    )
    assert decision["safety_policy_results"][0]["safety_policies"]["state_change_policy"]["reason"] == (
        "Authorization: Bearer ****"
    )
    assert "raw-token" not in str(decision)


def test_quality_gate_can_opt_out_of_no_execution_failure():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=0,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="destructive-delete",
            is_vulnerable=False,
            severity="LOW",
            skip_reason="state_change_guard",
        )
    ]

    decision = evaluate_quality_gate(run, results, fail_on_no_execution=False)

    assert decision["status"] == "PASSED"
    assert decision["passed"] is True
    assert decision["policy"]["fail_on_no_execution"] is False


def test_quality_gate_reports_pending_for_incomplete_scan():
    run = models.TestRun(id="run-1", account_id=1000000, status="RUNNING")

    decision = evaluate_quality_gate(run, [])

    assert decision["status"] == "PENDING"
    assert decision["reason"] == "scan_not_complete"
    assert decision["exit_code"] == 2


def test_parse_fail_on_defaults_when_empty():
    assert parse_fail_on("") == {"CRITICAL", "HIGH"}


def test_parse_fail_on_accepts_none_to_disable_severity_blocking():
    assert parse_fail_on("none") == set()
    assert parse_fail_on(["NONE"]) == set()


def test_policy_pack_resolves_strict_and_evidence_only_profiles():
    strict = resolve_policy_pack("strict")
    evidence_only = resolve_policy_pack("evidence-only")

    assert strict["name"] == "strict"
    assert strict["fail_on"] == "CRITICAL,HIGH"
    assert strict["require_confirmatory_retests"] is True
    assert strict["require_ticketed_blocking_vulnerabilities"] is True
    assert evidence_only["name"] == "evidence-only"
    assert evidence_only["fail_on"] == "none"
    assert evidence_only["require_evidence_integrity"] is True
    assert evidence_only["require_evidence_completeness"] is True
    assert resolve_policy_pack("strict") is not strict


def test_quality_gate_decision_integrity_includes_hmac_signature(monkeypatch):
    monkeypatch.setattr(
        "server.modules.cicd.quality_gate.settings.CICD_GATE_SIGNING_SECRET",
        "unit-test-signing-secret",
    )
    decision = attach_decision_integrity(
        {
            "status": "PASSED",
            "passed": True,
            "reason": "no_blocking_findings",
            "run_id": "run-1",
        }
    )

    integrity = decision["decision_integrity"]
    verification = verify_quality_gate_decision_integrity(decision)

    assert integrity["signature_algorithm"] == "hmac-sha256"
    assert isinstance(integrity["decision_signature"], str)
    assert len(integrity["decision_signature"]) == 64
    assert verification["verified"] is True
    assert verification["signature_verified"] is True


def test_quality_gate_fails_unauthenticated_completed_runs_by_default():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED", total_tests=1)
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="low-risk",
            is_vulnerable=True,
            severity="LOW",
            evidence=_hashed_evidence(template_id="low-risk"),
        )
    ]

    decision = evaluate_quality_gate(run, results)

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "unauthenticated_scan"
    assert decision["policy"]["fail_on_unauthenticated"] is True
    assert decision["scan_context"]["authenticated"] is False


def test_quality_gate_can_opt_out_of_unauthenticated_failure():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED", total_tests=1)
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="low-risk",
            is_vulnerable=True,
            severity="LOW",
            evidence=_hashed_evidence(template_id="low-risk"),
        )
    ]

    decision = evaluate_quality_gate(run, results, fail_on_unauthenticated=False)

    assert decision["status"] == "PASSED"
    assert decision["passed"] is True
    assert decision["policy"]["fail_on_unauthenticated"] is False


def test_quality_gate_fails_unverified_vulnerable_evidence_by_default():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="legacy-low",
            is_vulnerable=True,
            severity="LOW",
            evidence="legacy unstructured evidence",
        )
    ]

    decision = evaluate_quality_gate(run, results, fail_on="CRITICAL")

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "unverified_evidence_present"
    assert decision["policy"]["require_evidence_integrity"] is True
    assert decision["counts"]["unverified_evidence_results"] == 1
    assert decision["unverified_evidence_results"][0]["evidence_integrity"]["finding_status"] == "NOT_STRUCTURED"


def test_quality_gate_fails_unverified_clean_executed_evidence_by_default():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="clean-auth-check",
            is_vulnerable=False,
            severity="INFO",
            evidence="legacy clean evidence",
        )
    ]

    decision = evaluate_quality_gate(run, results, fail_on="CRITICAL")

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "unverified_evidence_present"
    assert decision["policy"]["require_evidence_integrity"] is True
    assert decision["counts"]["unverified_evidence_results"] == 1
    assert decision["unverified_evidence_results"][0]["template_id"] == "clean-auth-check"
    assert decision["unverified_evidence_results"][0]["is_vulnerable"] is False
    assert decision["unverified_evidence_results"][0]["evidence_integrity"]["finding_status"] == "NOT_STRUCTURED"


def test_quality_gate_detects_tampered_evidence_hash():
    evidence = {
        "engine": "template",
        "template_id": "tampered-auth",
        "results": [{"vulnerable": True}],
    }
    evidence["hash_algorithm"] = "sha256"
    evidence["evidence_hash"] = evidence_digest(evidence)
    evidence["results"].append({"vulnerable": False, "tampered": True})
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="tampered-auth",
            is_vulnerable=True,
            severity="LOW",
            evidence=json.dumps(evidence, sort_keys=True),
        )
    ]

    decision = evaluate_quality_gate(run, results, fail_on="CRITICAL")

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "unverified_evidence_present"
    assert decision["counts"]["unverified_evidence_results"] == 1
    assert decision["unverified_evidence_results"][0]["evidence_integrity"]["finding_status"] == "MISMATCH"


def test_quality_gate_fails_incomplete_evidence_even_when_severity_is_not_blocking():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="low-risk",
            is_vulnerable=True,
            severity="LOW",
            evidence=_hashed_evidence(
                template_id="low-risk",
                evidence_completeness={
                    "complete": False,
                    "required": ["matched_rule", "similarity"],
                    "present": ["status", "reproduction"],
                    "missing": ["matched_rule", "similarity"],
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(run, results, fail_on="CRITICAL")

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "incomplete_evidence_present"
    assert decision["policy"]["require_evidence_completeness"] is True
    assert decision["counts"]["incomplete_evidence_results"] == 1
    assert decision["incomplete_evidence_results"][0]["evidence_completeness"]["missing"] == [
        "matched_rule",
        "similarity",
    ]


def test_quality_gate_fails_vulnerable_result_disproven_by_evidence():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-bypass",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(
                template_id="auth-bypass",
                finding_status="DISPROVEN",
                confirmation={"confirmed": False},
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        require_confirmed_findings=True,
    )

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "inconsistent_evidence_present"
    assert decision["counts"]["inconsistent_evidence_results"] == 1
    assert decision["counts"]["failing_results"] == 0
    assert decision["inconsistent_evidence_results"][0]["confirmed"] is False
    assert (
        decision["inconsistent_evidence_results"][0]["evidence_consistency"]["reason"]
        == "vulnerable_result_disproven_by_evidence"
    )


def test_quality_gate_fails_non_vulnerable_result_confirmed_by_evidence():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-bypass",
            is_vulnerable=False,
            severity="HIGH",
            evidence=_hashed_evidence(
                template_id="auth-bypass",
                finding_status="CONFIRMED",
                confirmation={"confirmed": True},
            ),
        )
    ]

    decision = evaluate_quality_gate(run, results)

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "inconsistent_evidence_present"
    assert decision["counts"]["inconsistent_evidence_results"] == 1
    assert (
        decision["inconsistent_evidence_results"][0]["evidence_consistency"]["reason"]
        == "non_vulnerable_result_confirmed_by_evidence"
    )


def test_quality_gate_can_opt_out_of_evidence_integrity_policy():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="legacy-low",
            is_vulnerable=True,
            severity="LOW",
            evidence="legacy unstructured evidence",
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        fail_on="CRITICAL",
        require_evidence_integrity=False,
        require_evidence_completeness=False,
    )

    assert decision["status"] == "PASSED"
    assert decision["passed"] is True
    assert decision["policy"]["require_evidence_integrity"] is False
    assert decision["policy"]["require_evidence_completeness"] is False


def test_quality_gate_fails_profile_without_auth_ready_context():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-without-auth",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="low-risk",
            is_vulnerable=True,
            severity="LOW",
        )
    ]

    decision = evaluate_quality_gate(run, results, authenticated_context=False)

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "unauthenticated_scan"
    assert decision["scan_context"]["pentest_profile_id"] == "profile-without-auth"
    assert decision["scan_context"]["authenticated"] is False


def test_quality_gate_reports_run_lineage_in_scan_context():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
        trigger_source="schedule",
        source_schedule_id="schedule-nightly",
        source_vulnerability_id="vuln-retest",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="low-risk",
            is_vulnerable=True,
            severity="LOW",
            evidence=_hashed_evidence(template_id="low-risk"),
        )
    ]

    decision = evaluate_quality_gate(run, results)

    assert decision["scan_context"]["trigger_source"] == "schedule"
    assert decision["scan_context"]["source_schedule_id"] == "schedule-nightly"
    assert decision["scan_context"]["source_vulnerability_id"] == "vuln-retest"


def test_quality_gate_filters_authorization_boundary_metadata_to_field_names():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="authz-replay",
            is_vulnerable=True,
            severity="LOW",
            evidence=_hashed_evidence(template_id="authz-replay"),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        authenticated_context=True,
        auth_context_reason="authorization_replay_test_accounts",
        auth_context_metadata={
            "authorization_replay": {
                "identity_pair_count": 1,
                "vulnerable_identity_pair_count": 1,
                "results_with_identity_boundary": 1,
                "compared_boundary_field_count": 3,
                "changed_boundary_field_count": 2,
                "unchanged_boundary_field_count": 1,
                "boundary_kinds": ["cross_tenant", "tenant-a", "Authorization: Bearer raw-token"],
                "compared_boundary_fields": [
                    "X-Tenant-ID",
                    "tenant-a",
                    "Authorization: Bearer raw-token",
                    "X-User-Role",
                ],
                "changed_boundary_fields": ["X-Tenant-ID", "tenant-b"],
                "unchanged_boundary_fields": ["X-Scopes", "orders:refund"],
                "issue_types": ["BFLA"],
            },
        },
    )

    authz_context = decision["scan_context"]["authorization_replay"]
    assert authz_context["boundary_kinds"] == ["cross_tenant"]
    assert authz_context["compared_boundary_field_count"] == 2
    assert authz_context["changed_boundary_field_count"] == 1
    assert authz_context["unchanged_boundary_field_count"] == 1
    assert authz_context["compared_boundary_fields"] == ["x-tenant-id", "x-user-role"]
    assert authz_context["changed_boundary_fields"] == ["x-tenant-id"]
    assert authz_context["unchanged_boundary_fields"] == ["x-scopes"]
    decision_blob = str(decision)
    assert "tenant-a" not in decision_blob
    assert "tenant-b" not in decision_blob
    assert "raw-token" not in decision_blob
    assert "orders:refund" not in decision_blob


def test_quality_gate_can_require_authorization_boundary_coverage_for_replay_results():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="bfla-authz-replay",
            is_vulnerable=False,
            severity="INFO",
            evidence=_hashed_evidence(
                template_id="bfla-authz-replay",
                engine="authorization_replay",
                issue_type="BFLA",
                identity_pair={
                    "victim": {"role": "ADMIN", "id": "admin-user"},
                    "attacker": {"role": "MEMBER", "id": "member-user"},
                },
                replay_request={
                    "method": "GET",
                    "url": "https://api.example.com/admin/users/123",
                    "headers": {"Authorization": "Bearer raw-token"},
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        fail_on="CRITICAL",
        require_authorization_boundary_coverage=True,
    )

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "missing_authorization_boundary_coverage"
    assert decision["policy"]["require_authorization_boundary_coverage"] is True
    assert decision["counts"]["missing_authorization_boundary_results"] == 1
    assert decision["missing_authorization_boundary_results"][0]["template_id"] == "bfla-authz-replay"
    assert decision["missing_authorization_boundary_results"][0]["authorization_boundary_coverage"] == {
        "present": False,
        "complete": False,
        "reason": "missing_authorization_boundary_coverage",
        "boundary_kinds": [],
        "compared_boundary_field_count": 0,
        "changed_boundary_field_count": 0,
        "unchanged_boundary_field_count": 0,
        "missing_fields": ["authorization_boundary_coverage"],
    }
    assert "raw-token" not in str(decision)


def test_quality_gate_accepts_authorization_replay_boundary_coverage():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="bfla-authz-replay",
            is_vulnerable=False,
            severity="INFO",
            evidence=_hashed_evidence(
                template_id="bfla-authz-replay",
                engine="authorization_replay",
                issue_type="BFLA",
                identity_pair={
                    "victim": {"role": "ADMIN", "id": "admin-user"},
                    "attacker": {"role": "MEMBER", "id": "member-user"},
                },
                replay_request={
                    "method": "GET",
                    "url": "https://api.example.com/admin/users/123",
                    "headers": {"Authorization": "Bearer raw-token"},
                },
                authorization_boundary_coverage={
                    "primary_boundary_kind": "cross_role",
                    "boundary_kinds": ["cross_role", "tenant-a"],
                    "compared_fields": ["X-User-Role", "Authorization: Bearer raw-token"],
                    "changed_fields": ["X-User-Role"],
                    "unchanged_fields": ["X-Tenant-ID", "tenant-a"],
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        fail_on="CRITICAL",
        require_authorization_boundary_coverage=True,
    )

    assert decision["status"] == "PASSED"
    result_summaries = decision["safety_policy_results"] + decision["missing_safety_policy_results"]
    coverage = result_summaries[0]["authorization_boundary_coverage"]
    assert coverage["present"] is True
    assert coverage["complete"] is True
    assert coverage["boundary_kinds"] == ["cross_role"]
    assert coverage["compared_boundary_field_count"] == 1
    assert coverage["changed_boundary_field_count"] == 1
    assert coverage["unchanged_boundary_field_count"] == 1
    assert "raw-token" not in str(decision)
    assert "tenant-a" not in str(decision)


def test_quality_gate_requires_authorization_boundary_kind_to_match_claimed_issue_type():
    run = models.TestRun(
        id="run-authz-issue-kind",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-authz-issue-kind",
            run_id=run.id,
            endpoint_id="endpoint-1",
            template_id="bfla-authz-replay",
            is_vulnerable=False,
            severity="INFO",
            evidence=_hashed_evidence(
                template_id="bfla-authz-replay",
                engine="authorization_replay",
                issue_type="BFLA",
                identity_pair={
                    "victim": {"role": "ADMIN", "id": "admin-user"},
                    "attacker": {"role": "MEMBER", "id": "member-user"},
                },
                replay_request={
                    "method": "GET",
                    "url": "https://api.example.com/admin/users/123",
                    "headers": {"Authorization": "Bearer raw-token"},
                },
                authorization_boundary_coverage={
                    "primary_boundary_kind": "cross_tenant",
                    "boundary_kinds": ["cross_tenant"],
                    "compared_fields": ["X-Tenant-ID"],
                    "changed_fields": ["X-Tenant-ID"],
                    "unchanged_fields": ["X-Request-ID"],
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        fail_on="CRITICAL",
        require_authorization_boundary_coverage=True,
    )

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "missing_authorization_boundary_coverage"
    assert decision["counts"]["missing_authorization_boundary_results"] == 1
    coverage = decision["missing_authorization_boundary_results"][0]["authorization_boundary_coverage"]
    assert coverage == {
        "present": True,
        "complete": False,
        "reason": "incomplete_authorization_boundary_coverage",
        "boundary_kinds": ["cross_tenant"],
        "compared_boundary_field_count": 1,
        "changed_boundary_field_count": 1,
        "unchanged_boundary_field_count": 1,
        "missing_fields": ["bfla_boundary_kind"],
    }
    assert "raw-token" not in str(decision)


def test_quality_gate_includes_tamper_evident_decision_integrity():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="low-risk",
            is_vulnerable=True,
            severity="LOW",
            evidence=_hashed_evidence(template_id="low-risk"),
        )
    ]

    decision = evaluate_quality_gate(run, results)
    integrity = decision["decision_integrity"]

    assert integrity["hash_algorithm"] == "sha256"
    assert integrity["decision_hash"] == _expected_decision_hash(decision)
    assert integrity["covered_fields"] == sorted(
        key for key in decision.keys() if key != "decision_integrity"
    )


def test_quality_gate_decision_integrity_verifier_detects_tampering():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="low-risk",
            is_vulnerable=True,
            severity="LOW",
            evidence=_hashed_evidence(template_id="low-risk"),
        )
    ]

    decision = evaluate_quality_gate(run, results)
    verified = verify_quality_gate_decision_integrity(decision)

    tampered = dict(decision)
    tampered["reason"] = "tampered_reason"
    tampered_verification = verify_quality_gate_decision_integrity(tampered)

    assert verified["verified"] is True
    assert verified["status"] == "VERIFIED"
    assert verified["expected_hash"] == decision["decision_integrity"]["decision_hash"]
    assert verified["actual_hash"] == decision["decision_integrity"]["decision_hash"]
    assert tampered_verification["verified"] is False
    assert tampered_verification["status"] == "MISMATCH"
    assert tampered_verification["expected_hash"] == decision["decision_integrity"]["decision_hash"]
    assert tampered_verification["actual_hash"] != decision["decision_integrity"]["decision_hash"]


def test_quality_gate_can_require_confirmed_findings_before_failing():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-bypass",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(template_id="auth-bypass"),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        require_confirmed_findings=True,
    )

    assert decision["status"] == "PASSED"
    assert decision["reason"] == "no_confirmed_blocking_findings"
    assert decision["counts"]["failing_results"] == 0
    assert decision["counts"]["unconfirmed_blocking_results"] == 1
    assert decision["unconfirmed_results"][0]["confirmed"] is None
    assert decision["policy"]["require_confirmed_findings"] is True


def test_quality_gate_can_require_confirmatory_retests_for_blocking_findings():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-bypass",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(template_id="auth-bypass"),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        require_confirmatory_retests=True,
    )

    assert decision["status"] == "FAILED"
    assert decision["passed"] is False
    assert decision["reason"] == "unconfirmed_blocking_findings"
    assert decision["exit_code"] == 1
    assert decision["counts"]["failing_results"] == 0
    assert decision["counts"]["unconfirmed_blocking_results"] == 1
    assert decision["unconfirmed_results"][0]["template_id"] == "auth-bypass"
    assert decision["unconfirmed_results"][0]["confirmed"] is None
    assert decision["policy"]["require_confirmatory_retests"] is True


def test_quality_gate_can_require_retest_support_metadata():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-bypass",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(
                template_id="auth-bypass",
                retest_support=None,
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        fail_on="CRITICAL",
        require_retest_support=True,
    )

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "missing_retest_support"
    assert decision["policy"]["require_retest_support"] is True
    assert decision["counts"]["missing_retest_support_results"] == 1
    assert decision["missing_retest_support_results"][0]["template_id"] == "auth-bypass"
    assert decision["missing_retest_support_results"][0]["retest_support"]["present"] is False


def test_quality_gate_can_require_llm_judge_validation_for_llm_results():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(
                template_id="LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE",
                security_category="llm",
                llm_judge_validation=None,
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        fail_on="CRITICAL",
        require_llm_judge_validation=True,
    )

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "missing_llm_judge_validation"
    assert decision["policy"]["require_llm_judge_validation"] is True
    assert decision["counts"]["missing_llm_judge_validation_results"] == 1
    assert decision["missing_llm_judge_validation_results"][0]["template_id"] == (
        "LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE"
    )


def test_quality_gate_rejects_llm_judge_validation_with_mismatched_signal_family():
    run = models.TestRun(
        id="run-llm-signal-family",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-llm-signal-family",
            run_id=run.id,
            endpoint_id="endpoint-1",
            template_id="LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(
                template_id="LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE",
                security_category="llm",
                llm_judge_validation={
                    "validator": "deterministic_active_llm_signal_judge",
                    "surface": "active_llm_api",
                    "request_body_sha256": "a" * 64,
                    "response_body_sha256": "b" * 64,
                    "signal_count": 1,
                    "signal_types": ["LLM_DANGEROUS_TOOL_INVOCATION"],
                    "deterministic_evidence": True,
                    "body_content_persisted": False,
                    "matched_text_persisted": False,
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        fail_on="CRITICAL",
        require_llm_judge_validation=True,
    )

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "missing_llm_judge_validation"
    assert decision["counts"]["missing_llm_judge_validation_results"] == 1
    judge = decision["missing_llm_judge_validation_results"][0]["llm_judge_validation"]
    assert judge["present"] is True
    assert judge["complete"] is False
    assert judge["signal_types"] == ["LLM_DANGEROUS_TOOL_INVOCATION"]
    assert judge["required_signal_families"] == ["prompt_injection"]
    assert judge["missing_fields"] == ["signal_types.prompt_injection"]


def test_llm_strict_policy_pack_requires_llm_judge_validation():
    pack = resolve_policy_pack("llm-strict")

    assert pack["name"] == "llm-strict"
    assert pack["require_llm_judge_validation"] is True
    assert pack["require_retest_support"] is True
    assert pack["require_safety_policies"] is True


def test_quality_gate_fails_confirmed_blocking_findings_when_confirmation_required():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-bypass",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(
                template_id="auth-bypass",
                confirmation={"confirmed": True},
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        require_confirmed_findings=True,
    )

    assert decision["status"] == "FAILED"
    assert decision["reason"] == "blocking_findings_present"
    assert decision["counts"]["failing_results"] == 1
    assert decision["counts"]["unconfirmed_blocking_results"] == 0
    assert decision["failing_results"][0]["confirmed"] is True


def test_quality_gate_reads_confirmation_from_json_evidence():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
    )
    results = [
        models.TestResult(
            id="result-1",
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="auth-bypass",
            is_vulnerable=True,
            severity="CRITICAL",
            evidence=_hashed_evidence(
                template_id="auth-bypass",
                confirmation={"confirmed": True},
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        require_confirmed_findings=True,
    )

    assert decision["status"] == "FAILED"
    assert decision["failing_results"][0]["confirmed"] is True


def test_quality_gate_fails_when_ready_external_engine_lacks_verified_artifact():
    engine_plan = [
        {"engine": "templates", "status": "ready", "runtime_available": True},
        {"engine": "schemathesis", "status": "ready", "runtime_available": True},
        {"engine": "nuclei", "status": "disabled", "reason": "disabled_by_profile", "runtime_available": True},
        {"engine": "zap", "status": "blocked", "reason": "missing_binary", "runtime_available": False},
        {"engine": "passive", "status": "available", "runtime_available": True},
    ]
    run = models.TestRun(
        id="run-engine-artifacts",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
        scan_plan={"engine_plan": engine_plan},
    )
    results = [
        models.TestResult(
            id="result-clean",
            run_id=run.id,
            endpoint_id="endpoint-1",
            template_id="clean-auth-check",
            is_vulnerable=False,
            severity="LOW",
            evidence=_hashed_evidence(
                template_id="clean-auth-check",
                safety_policies={
                    "target_guard_policy": {
                        "policy": "target_guard",
                        "blocked": False,
                        "url": "https://api.example.com/health",
                    },
                    "state_change_policy": {
                        "allow_state_change": False,
                        "allow_destructive_methods": False,
                        "destructive_method": False,
                    },
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        require_safety_policies=True,
        execution_artifacts=[
            _engine_execution_artifact("templates", engine_plan=engine_plan)
        ],
    )

    assert decision["status"] == "FAILED"
    assert decision["passed"] is False
    assert decision["reason"] == "missing_engine_execution_artifacts"
    assert decision["policy"]["require_engine_artifacts"] is True
    assert decision["counts"]["missing_engine_artifact_results"] == 2
    assert decision["engine_artifact_requirements"] == [
        {
            "engine": "templates",
            "artifact_type": "templates_execution",
            "status": "verified",
            "verification_status": "VERIFIED",
            "normalized_evidence_status": "present",
        },
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "status": "missing",
            "verification_status": "MISSING",
            "normalized_evidence_status": "missing",
        },
        {
            "engine": "passive",
            "artifact_type": "passive_findings",
            "status": "missing",
            "verification_status": "MISSING",
            "normalized_evidence_status": "missing",
        },
    ]
    assert decision["missing_engine_artifact_results"] == [
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "status": "missing",
            "verification_status": "MISSING",
            "normalized_evidence_status": "missing",
        },
        {
            "engine": "passive",
            "artifact_type": "passive_findings",
            "status": "missing",
            "verification_status": "MISSING",
            "normalized_evidence_status": "missing",
        },
    ]


def test_quality_gate_requires_verified_continuous_passive_artifact():
    engine_plan = [
        {"engine": "templates", "status": "ready", "runtime_available": True},
        {"engine": "schemathesis", "status": "blocked", "reason": "missing_openapi_spec", "runtime_available": True},
        {"engine": "nuclei", "status": "disabled", "reason": "disabled_by_profile", "runtime_available": True},
        {"engine": "zap", "status": "disabled", "reason": "disabled_by_profile", "runtime_available": True},
        {"engine": "passive", "status": "available", "runtime_available": True},
    ]
    run = models.TestRun(
        id="run-passive-artifacts",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
        scan_plan={"engine_plan": engine_plan},
    )
    results = [
        models.TestResult(
            id="result-clean-passive",
            run_id=run.id,
            endpoint_id="endpoint-1",
            template_id="clean-auth-check",
            is_vulnerable=False,
            severity="LOW",
            evidence=_hashed_evidence(
                template_id="clean-auth-check",
                safety_policies={
                    "target_guard_policy": {
                        "policy": "target_guard",
                        "blocked": False,
                        "url": "https://api.example.com/health",
                    },
                    "state_change_policy": {
                        "allow_state_change": False,
                        "allow_destructive_methods": False,
                        "destructive_method": False,
                    },
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        require_safety_policies=True,
        execution_artifacts=[
            _engine_execution_artifact("templates", engine_plan=engine_plan)
        ],
    )

    assert decision["status"] == "FAILED"
    assert decision["passed"] is False
    assert decision["reason"] == "missing_engine_execution_artifacts"
    assert decision["counts"]["missing_engine_artifact_results"] == 1
    assert decision["engine_artifact_requirements"] == [
        {
            "engine": "templates",
            "artifact_type": "templates_execution",
            "status": "verified",
            "verification_status": "VERIFIED",
            "normalized_evidence_status": "present",
        },
        {
            "engine": "passive",
            "artifact_type": "passive_findings",
            "status": "missing",
            "verification_status": "MISSING",
            "normalized_evidence_status": "missing",
        },
    ]
    assert decision["missing_engine_artifact_results"] == [
        {
            "engine": "passive",
            "artifact_type": "passive_findings",
            "status": "missing",
            "verification_status": "MISSING",
            "normalized_evidence_status": "missing",
        }
    ]


def test_quality_gate_rejects_hash_valid_engine_artifact_from_wrong_run():
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "runtime_available": True},
    ]
    run = models.TestRun(
        id="run-current",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
        scan_plan={"engine_plan": engine_plan},
    )
    results = [
        models.TestResult(
            id="result-clean-run-binding",
            run_id=run.id,
            endpoint_id="endpoint-1",
            template_id="clean-auth-check",
            is_vulnerable=False,
            severity="LOW",
            evidence=_hashed_evidence(template_id="clean-auth-check"),
        )
    ]
    payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/health?token=raw-token",
        profile_id="profile-1",
        execution={
            "status": "COMPLETED",
            "command": "schemathesis runtime token=raw-token",
            "summary": {"requests_sent": 1},
        },
        engine_plan=engine_plan,
        findings={"created_count": 0},
        run_id="run-other",
    )
    payload["artifact_type"] = "schemathesis_execution"

    decision = evaluate_quality_gate(
        run,
        results,
        execution_artifacts=[payload],
    )

    assert decision["status"] == "FAILED"
    assert decision["passed"] is False
    assert decision["reason"] == "missing_engine_execution_artifacts"
    assert decision["counts"]["missing_engine_artifact_results"] == 1
    assert decision["engine_artifact_requirements"] == [
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "status": "run_mismatch",
            "verification_status": "VERIFIED",
            "normalized_evidence_status": "present",
            "expected_run_id": "run-current",
            "artifact_run_id": "run-other",
            "mismatch_fields": ["run_id"],
        }
    ]
    assert decision["missing_engine_artifact_results"] == decision["engine_artifact_requirements"]
    assert "raw-token" not in str(decision)


def test_quality_gate_rejects_hash_valid_engine_artifact_with_failed_content_governance():
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "runtime_available": True},
    ]
    run = models.TestRun(
        id="run-content-governance",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
        scan_plan={"engine_plan": engine_plan},
    )
    results = [
        models.TestResult(
            id="result-clean-content-governance",
            run_id=run.id,
            endpoint_id="endpoint-1",
            template_id="clean-auth-check",
            is_vulnerable=False,
            severity="LOW",
            evidence=_hashed_evidence(template_id="clean-auth-check"),
        )
    ]
    payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/health?token=raw-token",
        profile_id="profile-1",
        execution={
            "status": "COMPLETED",
            "command": "schemathesis runtime token=raw-token",
            "summary": {"requests_sent": 1},
        },
        engine_plan=engine_plan,
        findings={"created_count": 0},
        run_id=run.id,
    )
    payload["artifact_type"] = "schemathesis_execution"
    payload["content_redacted"] = False
    payload["secret_values_persisted"] = True
    payload["normalized_evidence"]["secret_values_persisted"] = True
    payload["execution"]["stdout"] = "Authorization: Bearer raw-token token=raw-token"
    _refresh_artifact_hash(payload)

    decision = evaluate_quality_gate(
        run,
        results,
        execution_artifacts=[payload],
    )

    assert decision["status"] == "FAILED"
    assert decision["passed"] is False
    assert decision["reason"] == "artifact_content_governance_failed"
    assert decision["counts"]["missing_engine_artifact_results"] == 1
    assert decision["engine_artifact_requirements"] == [
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "status": "artifact_content_governance_failed",
            "verification_status": "VERIFIED",
            "normalized_evidence_status": "present",
            "artifact_content_governance": {
                "required": True,
                "complete": False,
                "status": "failed",
                "redaction_policy": "api_sentinel_redactor",
                "normalized_evidence_status": "present",
                "failed_fields": [
                    "content_redacted",
                    "secret_values_persisted",
                    "normalized_evidence.secret_values_persisted",
                ],
                "missing_fields": [],
            },
        }
    ]
    assert decision["missing_engine_artifact_results"] == decision["engine_artifact_requirements"]
    assert "raw-token" not in str(decision)


def test_quality_gate_recomputes_engine_artifact_hash_instead_of_trusting_embedded_verification():
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "runtime_available": True},
    ]
    run = models.TestRun(
        id="run-tampered-artifact",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
        scan_plan={"engine_plan": engine_plan},
    )
    results = [
        models.TestResult(
            id="result-clean-tampered-artifact",
            run_id=run.id,
            endpoint_id="endpoint-1",
            template_id="clean-auth-check",
            is_vulnerable=False,
            severity="LOW",
            evidence=_hashed_evidence(template_id="clean-auth-check"),
        )
    ]
    payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/health?token=raw-token",
        profile_id="profile-1",
        execution={
            "status": "COMPLETED",
            "command": "schemathesis runtime token=raw-token",
            "summary": {"requests_sent": 1},
        },
        engine_plan=engine_plan,
        findings={"created_count": 0},
        run_id=run.id,
    )
    payload["artifact_type"] = "schemathesis_execution"
    payload["execution"]["status"] = "TAMPERED"

    decision = evaluate_quality_gate(
        run,
        results,
        execution_artifacts=[payload],
    )

    assert decision["status"] == "FAILED"
    assert decision["passed"] is False
    assert decision["reason"] == "missing_engine_execution_artifacts"
    assert decision["counts"]["missing_engine_artifact_results"] == 1
    assert decision["engine_artifact_requirements"] == [
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "status": "unverified",
            "verification_status": "MISMATCH",
            "normalized_evidence_status": "present",
        }
    ]
    assert decision["missing_engine_artifact_results"] == decision["engine_artifact_requirements"]
    assert "raw-token" not in str(decision)


def test_quality_gate_rejects_hash_valid_engine_artifact_for_wrong_engine_slot():
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "runtime_available": True},
    ]
    run = models.TestRun(
        id="run-engine-slot",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
        scan_plan={"engine_plan": engine_plan},
    )
    results = [
        models.TestResult(
            id="result-clean-engine-slot",
            run_id=run.id,
            endpoint_id="endpoint-1",
            template_id="clean-auth-check",
            is_vulnerable=False,
            severity="LOW",
            evidence=_hashed_evidence(template_id="clean-auth-check"),
        )
    ]
    payload = build_execution_artifact_payload(
        engine="nuclei",
        target_url="https://api.example.com/health?token=raw-token",
        profile_id="profile-1",
        execution={
            "status": "COMPLETED",
            "command": "nuclei runtime token=raw-token",
            "summary": {"requests_sent": 1},
        },
        engine_plan=engine_plan,
        findings={"created_count": 0},
        run_id=run.id,
    )
    payload["artifact_type"] = "schemathesis_execution"

    decision = evaluate_quality_gate(
        run,
        results,
        execution_artifacts=[payload],
    )

    assert decision["status"] == "FAILED"
    assert decision["passed"] is False
    assert decision["reason"] == "missing_engine_execution_artifacts"
    assert decision["counts"]["missing_engine_artifact_results"] == 1
    assert decision["engine_artifact_requirements"] == [
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "status": "engine_mismatch",
            "verification_status": "VERIFIED",
            "normalized_evidence_status": "missing",
            "expected_engine": "schemathesis",
            "artifact_engine": "nuclei",
            "mismatch_fields": ["engine"],
        }
    ]
    assert decision["missing_engine_artifact_results"] == decision["engine_artifact_requirements"]
    assert "raw-token" not in str(decision)


def test_quality_gate_accepts_verified_ready_external_engine_artifacts():
    engine_plan = [
        {"engine": "templates", "status": "ready", "runtime_available": True},
        {"engine": "schemathesis", "status": "ready", "runtime_available": True},
        {"engine": "nuclei", "status": "blocked", "reason": "missing_auth_profile token=raw-token", "runtime_available": True},
        {"engine": "zap", "status": "disabled", "reason": "disabled_by_profile", "runtime_available": True},
        {"engine": "passive", "status": "available", "runtime_available": True},
    ]
    run = models.TestRun(
        id="run-engine-artifacts",
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        pentest_profile_id="profile-1",
        scan_plan={"engine_plan": engine_plan},
    )
    results = [
        models.TestResult(
            id="result-clean",
            run_id=run.id,
            endpoint_id="endpoint-1",
            template_id="clean-auth-check",
            is_vulnerable=False,
            severity="LOW",
            evidence=_hashed_evidence(
                template_id="clean-auth-check",
                safety_policies={
                    "target_guard_policy": {
                        "policy": "target_guard",
                        "blocked": False,
                        "url": "https://api.example.com/health",
                    },
                    "state_change_policy": {
                        "allow_state_change": False,
                        "allow_destructive_methods": False,
                        "destructive_method": False,
                    },
                },
            ),
        )
    ]

    decision = evaluate_quality_gate(
        run,
        results,
        require_safety_policies=True,
        execution_artifacts=[
            _engine_execution_artifact("templates", engine_plan=engine_plan),
            _engine_execution_artifact("schemathesis", engine_plan=engine_plan),
            _engine_execution_artifact("passive", engine_plan=engine_plan, status="AVAILABLE"),
        ],
    )

    assert decision["status"] == "PASSED"
    assert decision["passed"] is True
    assert decision["counts"]["missing_engine_artifact_results"] == 0
    assert decision["engine_artifact_requirements"][1]["status"] == "verified"
    assert decision["engine_artifact_requirements"][1]["normalized_evidence_status"] == "present"
    assert decision["engine_artifact_requirements"][2] == {
        "engine": "passive",
        "artifact_type": "passive_findings",
        "status": "verified",
        "verification_status": "VERIFIED",
        "normalized_evidence_status": "present",
    }
    assert "raw-token" not in str(decision)
