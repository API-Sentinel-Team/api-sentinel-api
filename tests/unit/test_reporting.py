import pytest
import hashlib
import json
from copy import deepcopy
from types import SimpleNamespace
from xml.etree import ElementTree as ET

from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
from server.modules.test_executor.reporting import (
    build_junit,
    build_report_artifact_manifest,
    build_sarif,
)
from server.modules.test_executor.evidence import evidence_digest
from server.models import core as models


def _hashed_evidence(**overrides):
    evidence = {
        "engine": "template",
        "template_id": overrides.pop("template_id", "auth-bypass"),
        "results": [{"vulnerable": True}],
    }
    evidence.update(overrides)
    evidence["hash_algorithm"] = "sha256"
    evidence["evidence_hash"] = evidence_digest(evidence)
    return json.dumps(evidence, sort_keys=True)


def _canonical_sarif_payload(payload: dict) -> dict:
    canonical = json.loads(json.dumps(payload, sort_keys=True))
    for run in canonical.get("runs", []):
        if not isinstance(run, dict):
            continue
        for invocation in run.get("invocations", []):
            if isinstance(invocation, dict):
                invocation.pop("endTimeUtc", None)
    return canonical


def _refresh_artifact_hash(payload: dict) -> None:
    from server.modules.pentest.execution_artifacts import (
        _artifact_digest,
        verify_execution_artifact_payload,
    )

    payload["artifact_hash"] = _artifact_digest(payload)
    payload["artifact_verification"] = verify_execution_artifact_payload(payload)


def _json_sha256(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@pytest.mark.asyncio
async def test_sarif_and_junit_generation():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED")
    results = [
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="TEMPLATE-1",
            is_vulnerable=True,
            severity="HIGH",
            evidence="evidence",
        )
    ]
    sarif = build_sarif(run, results)
    assert sarif["version"] == "2.1.0"
    junit = build_junit(run, results)
    assert "<testsuite" in junit


def test_reporting_redacts_evidence_and_includes_execution_counts():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED")
    results = [
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="AUTH-BYPASS",
            is_vulnerable=True,
            severity="HIGH",
            evidence="Authorization: Bearer raw-token token=raw-token",
        ),
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-2",
            template_id="DESTRUCTIVE-GUARD",
            is_vulnerable=False,
            severity="LOW",
            evidence="cookie=session-secret",
            skip_reason="state_change_guard",
        ),
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-3",
            template_id="TIMEOUT",
            is_vulnerable=False,
            severity="MEDIUM",
            error="upstream failed with api_key=raw-key",
        ),
    ]

    sarif = build_sarif(run, results)
    sarif_blob = str(sarif)
    invocation_props = sarif["runs"][0]["invocations"][0]["properties"]

    assert invocation_props["total_results"] == 3
    assert invocation_props["executed_results"] == 2
    assert invocation_props["skipped_results"] == 1
    assert invocation_props["errored_results"] == 1
    assert "raw-token" not in sarif_blob
    assert "Bearer ****" in sarif_blob

    junit = build_junit(run, results)
    root = ET.fromstring(junit)
    junit_blob = ET.tostring(root, encoding="unicode")

    assert root.attrib["tests"] == "3"
    assert root.attrib["failures"] == "1"
    assert root.attrib["errors"] == "1"
    assert root.attrib["skipped"] == "1"
    assert root.findall(".//skipped")
    assert root.findall(".//error")
    assert "raw-token" not in junit_blob
    assert "raw-key" not in junit_blob
    assert "session-secret" not in junit_blob


def test_reporting_exports_evidence_integrity_and_confirmation_metadata():
    evidence = _hashed_evidence(
        template_id="AUTH-BYPASS",
        confirmation={"confirmed": True},
        sent_request={"headers": {"Authorization": "Bearer raw-token"}},
    )
    parsed_evidence = json.loads(evidence)
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED")
    results = [
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="AUTH-BYPASS",
            is_vulnerable=True,
            severity="HIGH",
            evidence=evidence,
        )
    ]

    sarif = build_sarif(run, results)
    properties = sarif["runs"][0]["results"][0]["properties"]
    sarif_blob = str(sarif)

    assert properties["evidence_hash"] == parsed_evidence["evidence_hash"]
    assert properties["evidence_integrity"]["verified"] is True
    assert properties["evidence_integrity"]["finding_status"] == "VERIFIED"
    assert properties["confirmation_status"] == "CONFIRMED"
    assert "raw-token" not in sarif_blob

    junit = build_junit(run, results)
    root = ET.fromstring(junit)
    failure_payload = json.loads(root.find(".//failure").text)

    assert failure_payload["evidence_hash"] == parsed_evidence["evidence_hash"]
    assert failure_payload["evidence_integrity"]["verified"] is True
    assert failure_payload["confirmation_status"] == "CONFIRMED"
    assert "raw-token" not in ET.tostring(root, encoding="unicode")


def test_reporting_exports_redacted_safety_policy_metadata_for_skips():
    evidence = _hashed_evidence(
        template_id="TARGET-GUARD",
        safety_policies={
            "target_guard_policy": {
                "policy": "target_guard",
                "blocked": True,
                "url": "https://api.example.com/search?token=raw-token",
                "base_url": "https://api.example.com/search?token=raw-token",
                "reason": "Authorization: Bearer raw-token token=raw-token",
            }
        },
    )
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED")
    results = [
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="TARGET-GUARD",
            is_vulnerable=False,
            severity="LOW",
            evidence=evidence,
            skip_reason="target_guard",
        )
    ]

    sarif = build_sarif(run, results)
    skipped_detail = sarif["runs"][0]["invocations"][0]["properties"]["skipped_result_details"][0]
    assert skipped_detail["skip_reason"] == "target_guard"
    assert skipped_detail["safety_policies"]["target_guard_policy"]["url"] == (
        "https://api.example.com/search?token=****"
    )
    assert skipped_detail["safety_policies"]["target_guard_policy"]["reason"] == (
        "Authorization: Bearer **** token=****"
    )
    assert "raw-token" not in str(sarif)

    junit = build_junit(run, results)
    root = ET.fromstring(junit)
    skipped_payload = json.loads(root.find(".//skipped").text)
    assert skipped_payload["safety_policies"]["target_guard_policy"]["url"] == (
        "https://api.example.com/search?token=****"
    )
    assert skipped_payload["safety_policies"]["target_guard_policy"]["reason"] == (
        "Authorization: Bearer **** token=****"
    )
    assert "raw-token" not in ET.tostring(root, encoding="unicode")


def test_reporting_exports_redacted_safety_policy_metadata_for_sarif_findings():
    evidence = _hashed_evidence(
        template_id="AUTH-SCOPE-FINDING",
        safety_policies={
            "auth_profile_scope_policy": {
                "policy": "auth_profile_scope_guard",
                "blocked": False,
                "url": "https://api.example.com/orders?token=raw-token",
                "base_url": "https://api.example.com/orders?token=raw-token",
                "reason": "Authorization: Bearer raw-token token=raw-token",
                "auth_profile_id": "auth-profile-1",
                "scope_domains_configured": True,
                "scope_domain_count": 1,
            }
        },
    )
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED")
    results = [
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="AUTH-SCOPE-FINDING",
            is_vulnerable=True,
            severity="HIGH",
            evidence=evidence,
        )
    ]

    sarif = build_sarif(run, results)
    properties = sarif["runs"][0]["results"][0]["properties"]

    policy = properties["safety_policies"]["auth_profile_scope_policy"]
    assert policy["url"] == "https://api.example.com/orders?token=****"
    assert policy["base_url"] == "https://api.example.com/orders?token=****"
    assert policy["reason"] == "Authorization: Bearer **** token=****"
    assert policy["auth_profile_id"] == "auth-profile-1"
    assert "raw-token" not in str(sarif)


def test_sarif_invocation_summarizes_safety_policy_coverage():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED")
    results = [
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="AUTH-SCOPE",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(
                template_id="AUTH-SCOPE",
                safety_policies={
                    "auth_profile_scope_policy": {
                        "policy": "auth_profile_scope_guard",
                        "blocked": False,
                        "url": "https://api.example.com/orders?token=raw-token",
                        "base_url": "https://api.example.com/orders?token=raw-token",
                        "reason": "Authorization: Bearer raw-token token=raw-token",
                    }
                },
            ),
        ),
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-2",
            template_id="STATE-GUARD",
            is_vulnerable=False,
            severity="LOW",
            skip_reason="state_change_guard",
            evidence=_hashed_evidence(
                template_id="STATE-GUARD",
                safety_policies={
                    "target_guard_policy": {
                        "policy": "target_guard",
                        "blocked": False,
                        "url": "https://api.example.com/users?token=raw-token",
                    },
                    "state_change_policy": {
                        "policy": "state_change_guard",
                        "method": "DELETE",
                        "allow_state_change": False,
                        "allow_destructive_methods": False,
                        "destructive_method": True,
                        "reason": "Authorization: Bearer raw-token",
                    },
                },
            ),
        ),
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-3",
            template_id="LEGACY",
            is_vulnerable=False,
            severity="INFO",
            evidence="legacy evidence",
        ),
    ]

    sarif = build_sarif(run, results)
    summary = sarif["runs"][0]["invocations"][0]["properties"]["safety_policy_summary"]

    assert summary == {
        "results_with_safety_policies": 2,
        "policy_keys": [
            "auth_profile_scope_policy",
            "state_change_policy",
            "target_guard_policy",
        ],
        "policy_counts": {
            "auth_profile_scope_policy": 1,
            "state_change_policy": 1,
            "target_guard_policy": 1,
        },
    }
    assert "raw-token" not in str(summary)


def test_junit_suite_properties_summarize_safety_policy_coverage():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED")
    results = [
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="AUTH-SCOPE",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(
                template_id="AUTH-SCOPE",
                safety_policies={
                    "auth_profile_scope_policy": {
                        "policy": "auth_profile_scope_guard",
                        "blocked": False,
                        "url": "https://api.example.com/orders?token=raw-token",
                        "base_url": "https://api.example.com/orders?token=raw-token",
                        "reason": "Authorization: Bearer raw-token token=raw-token",
                    }
                },
            ),
        ),
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-2",
            template_id="STATE-GUARD",
            is_vulnerable=False,
            severity="LOW",
            skip_reason="state_change_guard",
            evidence=_hashed_evidence(
                template_id="STATE-GUARD",
                safety_policies={
                    "target_guard_policy": {
                        "policy": "target_guard",
                        "blocked": False,
                        "url": "https://api.example.com/users?token=raw-token",
                    },
                    "state_change_policy": {
                        "policy": "state_change_guard",
                        "method": "DELETE",
                        "allow_state_change": False,
                        "allow_destructive_methods": False,
                        "destructive_method": True,
                        "reason": "Authorization: Bearer raw-token",
                    },
                },
            ),
        ),
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-3",
            template_id="LEGACY",
            is_vulnerable=False,
            severity="INFO",
            evidence="legacy evidence",
        ),
    ]

    junit = build_junit(run, results)
    root = ET.fromstring(junit)
    prop = root.find(".//properties/property[@name='api_sentinel.safety_policy_summary']")

    assert prop is not None
    summary = json.loads(prop.attrib["value"])
    assert summary == {
        "results_with_safety_policies": 2,
        "policy_keys": [
            "auth_profile_scope_policy",
            "state_change_policy",
            "target_guard_policy",
        ],
        "policy_counts": {
            "auth_profile_scope_policy": 1,
            "state_change_policy": 1,
            "target_guard_policy": 1,
        },
    }
    assert "raw-token" not in prop.attrib["value"]


def test_report_artifact_manifest_tracks_sarif_and_junit_hashes():
    run = models.TestRun(id="run-1", account_id=1000000, status="COMPLETED")
    results = [
        models.TestResult(
            run_id="run-1",
            endpoint_id="endpoint-1",
            template_id="AUTH-SCOPE",
            is_vulnerable=True,
            severity="HIGH",
            evidence=_hashed_evidence(
                template_id="AUTH-SCOPE",
                safety_policies={
                    "target_guard_policy": {
                        "policy": "target_guard",
                        "blocked": False,
                        "url": "https://api.example.com/orders?token=raw-token",
                    },
                    "state_change_policy": {
                        "policy": "state_change_guard",
                        "method": "GET",
                        "allow_state_change": False,
                        "allow_destructive_methods": False,
                        "destructive_method": False,
                    },
                },
            ),
        )
    ]

    manifest = build_report_artifact_manifest(run, results)
    artifacts = {artifact["format"]: artifact for artifact in manifest["artifacts"]}

    assert manifest["required"] is True
    assert artifacts["sarif"]["url"] == "/api/cicd/gate/run-1/sarif"
    assert artifacts["sarif"]["media_type"] == "application/json"
    assert artifacts["sarif"]["hash_algorithm"] == "sha256"
    assert artifacts["sarif"]["canonicalization"] == "sarif-drop-invocation-endTimeUtc"
    assert artifacts["sarif"]["canonical_hash"] == _json_sha256(
        _canonical_sarif_payload(build_sarif(run, results))
    )
    assert artifacts["junit"]["url"] == "/api/cicd/gate/run-1/junit"
    assert artifacts["junit"]["media_type"] == "application/xml"
    assert artifacts["junit"]["hash_algorithm"] == "sha256"
    assert artifacts["junit"]["canonicalization"] == "raw-xml"
    assert artifacts["junit"]["canonical_hash"] == hashlib.sha256(
        build_junit(run, results).encode("utf-8")
    ).hexdigest()
    assert "raw-token" not in str(manifest)


def test_report_artifact_manifest_accounts_for_required_engine_execution_artifacts():
    run = models.TestRun(
        id="run-1",
        account_id=1000000,
        status="COMPLETED",
        scan_plan={
            "engine_plan": [
                {"engine": "templates", "status": "ready", "reason": "template_engine_available"},
                {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
                {"engine": "nuclei", "status": "ready", "reason": "requirements_satisfied"},
                {"engine": "zap", "status": "blocked", "reason": "missing_openapi_spec"},
                {"engine": "passive", "status": "available", "reason": "continuous_ingestion_pipeline"},
            ]
        },
    )
    payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/users?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED"},
        engine_plan=run.scan_plan["engine_plan"],
        run_id=run.id,
    )
    tampered_payload = deepcopy(payload)
    tampered_payload["engine"] = "nuclei"
    tampered_payload["execution"]["status"] = "TAMPERED"
    artifacts = [
        SimpleNamespace(artifact_type="schemathesis_execution", content_json=payload),
        SimpleNamespace(artifact_type="nuclei_execution", content_json=tampered_payload),
    ]

    manifest = build_report_artifact_manifest(run, [], execution_artifacts=artifacts)
    accountability = manifest["engine_accountability"]

    assert accountability["required"] is True
    assert accountability["complete"] is False
    assert accountability["scan_plan_engine_plan_present"] is True
    assert accountability["ready_active_engines"] == ["templates", "schemathesis", "nuclei"]
    assert accountability["continuous_engines"] == ["passive"]
    assert accountability["blocked_engines"] == ["zap"]
    assert accountability["missing_artifact_count"] == 1
    assert accountability["unverified_artifact_count"] == 1
    required = {item["engine"]: item for item in accountability["required_artifacts"]}
    assert required["templates"] == {
        "engine": "templates",
        "artifact_type": "templates_execution",
        "present": False,
        "verified": False,
        "status": "missing",
        "hash_algorithm": "sha256",
    }
    assert required["schemathesis"]["present"] is True
    assert required["schemathesis"]["verified"] is True
    assert required["schemathesis"]["status"] == "verified"
    assert required["nuclei"]["present"] is True
    assert required["nuclei"]["verified"] is False
    assert required["nuclei"]["status"] == "unverified"
    assert "raw-token" not in str(manifest)


def test_report_artifact_manifest_rejects_hash_valid_payload_for_wrong_engine_slot():
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
    ]
    run = models.TestRun(
        id="run-engine-mismatch",
        account_id=1000000,
        status="COMPLETED",
        scan_plan={"engine_plan": engine_plan},
    )
    payload = build_execution_artifact_payload(
        engine="nuclei",
        target_url="https://api.example.com/users?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED", "stdout": "token=raw-token"},
        engine_plan=engine_plan,
        run_id=run.id,
    )
    artifacts = [
        SimpleNamespace(artifact_type="schemathesis_execution", content_json=payload),
    ]

    manifest = build_report_artifact_manifest(run, [], execution_artifacts=artifacts)
    accountability = manifest["engine_accountability"]
    required = {item["engine"]: item for item in accountability["required_artifacts"]}

    assert accountability["complete"] is False
    assert accountability["missing_artifact_count"] == 0
    assert accountability["unverified_artifact_count"] == 1
    assert required["schemathesis"]["present"] is True
    assert required["schemathesis"]["verified"] is False
    assert required["schemathesis"]["status"] == "engine_mismatch"
    assert required["schemathesis"]["expected_engine"] == "schemathesis"
    assert required["schemathesis"]["artifact_engine"] == "nuclei"
    assert required["schemathesis"]["mismatch_fields"] == ["engine"]
    assert "raw-token" not in str(manifest)


def test_report_artifact_manifest_rejects_hash_valid_payload_for_wrong_run():
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
    ]
    run = models.TestRun(
        id="run-current",
        account_id=1000000,
        status="COMPLETED",
        scan_plan={"engine_plan": engine_plan},
    )
    payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/users?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED", "stdout": "token=raw-token"},
        engine_plan=engine_plan,
        run_id="run-other",
    )
    artifacts = [
        SimpleNamespace(artifact_type="schemathesis_execution", content_json=payload),
    ]

    manifest = build_report_artifact_manifest(run, [], execution_artifacts=artifacts)
    accountability = manifest["engine_accountability"]
    required = {item["engine"]: item for item in accountability["required_artifacts"]}

    assert accountability["complete"] is False
    assert accountability["missing_artifact_count"] == 0
    assert accountability["unverified_artifact_count"] == 1
    assert required["schemathesis"]["present"] is True
    assert required["schemathesis"]["verified"] is False
    assert required["schemathesis"]["status"] == "run_mismatch"
    assert required["schemathesis"]["expected_run_id"] == "run-current"
    assert required["schemathesis"]["artifact_run_id"] == "run-other"
    assert required["schemathesis"]["mismatch_fields"] == ["run_id"]
    assert "raw-token" not in str(manifest)


def test_report_artifact_manifest_rejects_hash_valid_artifact_with_failed_content_governance():
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
    ]
    run = models.TestRun(
        id="run-content-governance",
        account_id=1000000,
        status="COMPLETED",
        scan_plan={"engine_plan": engine_plan},
    )
    payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/users?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED", "stdout": "token=raw-token"},
        engine_plan=engine_plan,
        run_id=run.id,
    )
    payload["content_redacted"] = False
    payload["secret_values_persisted"] = True
    payload["normalized_evidence"]["secret_values_persisted"] = True
    payload["execution"]["stdout"] = "Authorization: Bearer raw-token token=raw-token"
    _refresh_artifact_hash(payload)
    artifacts = [
        SimpleNamespace(artifact_type="schemathesis_execution", content_json=payload),
    ]

    manifest = build_report_artifact_manifest(run, [], execution_artifacts=artifacts)
    accountability = manifest["engine_accountability"]
    required = {item["engine"]: item for item in accountability["required_artifacts"]}

    assert accountability["complete"] is False
    assert accountability["unverified_artifact_count"] == 1
    assert accountability["content_governance_failed_artifact_count"] == 1
    assert required["schemathesis"]["present"] is True
    assert required["schemathesis"]["verified"] is False
    assert required["schemathesis"]["status"] == "artifact_content_governance_failed"
    assert required["schemathesis"]["artifact_content_governance"] == {
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
    }
    assert "raw-token" not in str(manifest)


def test_report_artifact_manifest_rejects_duplicate_required_engine_execution_artifacts():
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
    ]
    run = models.TestRun(
        id="run-duplicate-artifacts",
        account_id=1000000,
        status="COMPLETED",
        scan_plan={"engine_plan": engine_plan},
    )
    first_payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/users?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED", "summary": {"source": "first"}},
        engine_plan=engine_plan,
        run_id=run.id,
    )
    second_payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/users?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED", "summary": {"source": "second"}},
        engine_plan=engine_plan,
        run_id=run.id,
    )
    artifacts = [
        SimpleNamespace(artifact_type="schemathesis_execution", content_json=first_payload),
        SimpleNamespace(artifact_type="schemathesis_execution", content_json=second_payload),
    ]

    manifest = build_report_artifact_manifest(run, [], execution_artifacts=artifacts)
    accountability = manifest["engine_accountability"]
    required = {item["engine"]: item for item in accountability["required_artifacts"]}

    assert accountability["complete"] is False
    assert accountability["duplicate_artifact_count"] == 1
    assert accountability["unverified_artifact_count"] == 1
    assert required["schemathesis"]["present"] is True
    assert required["schemathesis"]["verified"] is False
    assert required["schemathesis"]["status"] == "duplicate_artifact"
    assert required["schemathesis"]["duplicate_count"] == 2
    assert required["schemathesis"]["duplicate_artifact_hashes"] == [
        first_payload["artifact_hash"],
        second_payload["artifact_hash"],
    ]
    assert "raw-token" not in str(manifest)


def test_report_artifact_manifest_rejects_external_worker_artifact_with_incomplete_isolation_contract():
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
    ]
    run = models.TestRun(
        id="run-worker-isolation-incomplete",
        account_id=1000000,
        status="COMPLETED",
        scan_plan={"engine_plan": engine_plan},
    )
    payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/users?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED", "stdout": "token=raw-token"},
        engine_plan=engine_plan,
        run_id=run.id,
        worker_isolation={
            "configured_worker_isolation_mode": "kubernetes_job",
            "resource_limits": {
                "cpu": "750m",
                "memory": "768Mi",
                "ephemeral_storage": "1536Mi",
            },
            "kubernetes_job": {"enabled": True},
            "secret_values_persisted": False,
        },
    )
    artifacts = [
        SimpleNamespace(artifact_type="schemathesis_execution", content_json=payload),
    ]

    manifest = build_report_artifact_manifest(run, [], execution_artifacts=artifacts)
    accountability = manifest["engine_accountability"]
    required = {item["engine"]: item for item in accountability["required_artifacts"]}

    assert accountability["complete"] is False
    assert accountability["unverified_artifact_count"] == 1
    assert accountability["incomplete_worker_isolation_artifact_count"] == 1
    assert required["schemathesis"]["present"] is True
    assert required["schemathesis"]["verified"] is False
    assert required["schemathesis"]["status"] == "worker_isolation_incomplete"
    assert required["schemathesis"]["worker_isolation"] == {
        "required": True,
        "complete": False,
        "status": "incomplete",
        "mode": "kubernetes_job",
        "missing_fields": [
            "session",
            "sandbox.created",
            "sandbox.path_confined_to_work_dir",
            "manifest.sha256",
            "enforcement.runtime_context_created",
            "enforcement.filesystem_workdir_enforced",
            "enforcement.subprocess_cwd_confined",
        ],
    }
    assert "raw-token" not in str(manifest)


def test_report_artifact_manifest_accounts_for_continuous_passive_findings_artifact():
    engine_plan = [
        {"engine": "templates", "status": "ready", "reason": "template_engine_available"},
        {"engine": "passive", "status": "available", "reason": "continuous_ingestion_pipeline"},
    ]
    run = models.TestRun(
        id="run-passive",
        account_id=1000000,
        status="COMPLETED",
        scan_plan={"engine_plan": engine_plan},
    )
    passive_payload = build_execution_artifact_payload(
        engine="passive",
        target_url="https://api.example.com/orders?token=raw-token",
        profile_id="profile-1",
        execution={
            "status": "AVAILABLE",
            "summary": {"events_processed": 7, "debug": "Authorization: Bearer raw-token"},
        },
        engine_plan=engine_plan,
        findings={"created_count": 1, "sample": "token=raw-token"},
        run_id=run.id,
    )
    artifacts = [
        SimpleNamespace(artifact_type="passive_findings", content_json=passive_payload),
    ]

    manifest = build_report_artifact_manifest(run, [], execution_artifacts=artifacts)
    accountability = manifest["engine_accountability"]

    assert accountability["continuous_engines"] == ["passive"]
    assert accountability["continuous_artifact_count"] == 1
    assert accountability["missing_continuous_artifact_count"] == 0
    assert accountability["unverified_continuous_artifact_count"] == 0
    assert accountability["continuous_artifact_accountability_complete"] is True
    passive = accountability["continuous_artifacts"][0]
    assert passive["engine"] == "passive"
    assert passive["artifact_type"] == "passive_findings"
    assert passive["present"] is True
    assert passive["verified"] is True
    assert passive["status"] == "verified"
    assert passive["artifact_hash"] == passive_payload["artifact_hash"]
    assert "raw-token" not in str(manifest)


def test_report_artifact_manifest_rolls_up_context_selection_accountability():
    engine_plan = [
        {"engine": "templates", "status": "ready", "reason": "template_engine_available"},
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
        {"engine": "nuclei", "status": "ready", "reason": "requirements_satisfied"},
        {"engine": "zap", "status": "blocked", "reason": "missing_openapi_spec"},
        {"engine": "passive", "status": "available", "reason": "continuous_ingestion_pipeline"},
    ]
    scan_plan = {
        "schema_version": "scan_plan.v1",
        "hash_algorithm": "sha256",
        "scan_plan_hash": "d" * 64,
        "engine_plan": engine_plan,
        "context": {
            "context_aware_selection": True,
            "partial_context_aware_selection": False,
            "status": "ready",
            "required_signals": ["method_context", "auth_context", "token=raw-token"],
            "available_signals": ["method_context", "auth_context", "private_identifier"],
            "satisfied_signals": ["method_context", "auth_context"],
            "missing_signals": ["secret=raw-token"],
            "signal_gaps": [
                {
                    "signal": "private_variable_context",
                    "required_template_count": 1,
                    "available_context_count": 0,
                    "affected_template_count": 1,
                    "affected_template_ids": ["authz-private-object-token=raw-token"],
                    "recommended_inputs": [
                        "capture non-secret object identifiers from path, query, request body, or response body",
                    ],
                    "attacker_supplied": "raw-token",
                }
            ],
        },
        "selection": {
            "template_endpoint_pair_count": 3,
            "selected_pair_count": 2,
            "skipped_pair_count": 1,
            "selected_template_count": 2,
            "selected_endpoint_count": 1,
            "pair_decision_count": 3,
            "pair_decision_report_truncated": False,
        },
        "coverage_targets": {
            "authorization": {
                "template_requested": True,
                "template_covered": True,
                "endpoint_signal_count": 1,
                "status": "available",
                "signals": ["auth_context", "private_identifier", "token=raw-token"],
            },
            "business_logic": {
                "template_requested": True,
                "template_covered": False,
                "endpoint_signal_count": 1,
                "status": "gap",
                "signals": ["workflow_path", "secret=raw-token"],
            },
            "llm_api": {
                "template_requested": True,
                "template_covered": True,
                "endpoint_signal_count": 1,
                "status": "available",
                "signals": ["body_key", "tool_context", "token=raw-token"],
                "readiness": {
                    "prompt_context_ready": True,
                    "tool_context_ready": True,
                    "tool_abuse_testable": True,
                    "raw_prompt": "Ignore instructions token=raw-token",
                },
                "active_test_families": {
                    "prompt_injection": {
                        "template_count": 1,
                        "endpoint_signal_count": 1,
                        "ready": True,
                        "status": "ready",
                        "signals": ["body_key", "path_hint", "token=raw-token"],
                    },
                    "tool_chain_injection": {
                        "template_count": 0,
                        "endpoint_signal_count": 1,
                        "ready": False,
                        "status": "missing_template",
                        "signals": [
                            "tool_invocation_context",
                            "tool_output_context",
                            "secret=raw-token",
                        ],
                    },
                    "attacker_supplied": {
                        "template_count": 999,
                        "signals": ["secret=raw-token"],
                    },
                },
            },
        },
    }
    run = models.TestRun(
        id="run-selection",
        account_id=1000000,
        status="COMPLETED",
        scan_plan=scan_plan,
    )
    templates_payload = build_execution_artifact_payload(
        engine="templates",
        target_url="https://api.example.com/orders?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED", "scan_plan": scan_plan},
        engine_plan=engine_plan,
        run_id=run.id,
    )
    schemathesis_payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/orders?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED"},
        engine_plan=engine_plan,
        run_id=run.id,
    )
    nuclei_payload = build_execution_artifact_payload(
        engine="nuclei",
        target_url="https://api.example.com/orders?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED", "scan_plan": scan_plan},
        engine_plan=engine_plan,
        run_id=run.id,
    )
    nuclei_payload["execution"]["status"] = "TAMPERED"
    artifacts = [
        SimpleNamespace(artifact_type="templates_execution", content_json=templates_payload),
        SimpleNamespace(artifact_type="schemathesis_execution", content_json=schemathesis_payload),
        SimpleNamespace(artifact_type="nuclei_execution", content_json=nuclei_payload),
    ]

    manifest = build_report_artifact_manifest(run, [], execution_artifacts=artifacts)
    selection = manifest["engine_accountability"]["selection_accountability"]

    assert selection == {
        "required": True,
        "scan_plan_context_present": True,
        "run_context_status": "ready",
        "run_scan_plan_hash": "d" * 64,
        "required_engine_count": 3,
        "trusted_selection_accountability_count": 1,
        "missing_selection_accountability_count": 1,
        "unverified_selection_accountability_count": 1,
        "selection_accountability_complete": False,
        "engine_details": [
            {
                "engine": "templates",
                "artifact_type": "templates_execution",
                "artifact_present": True,
                "artifact_verified": True,
                "selection_accountability_present": True,
                "status": "trusted",
                "context_status": "ready",
                "scan_plan_hash": "d" * 64,
                "selected_pair_count": 2,
                "skipped_pair_count": 1,
                "pair_decision_count": 3,
                "pair_decision_report_truncated": False,
                "missing_signals": ["secret=****"],
                "context_signal_gap_count": 1,
                "context_signal_gaps": [
                    {
                        "signal": "private_variable_context",
                        "required_template_count": 1,
                        "available_context_count": 0,
                        "affected_template_count": 1,
                        "affected_template_ids": ["authz-private-object-token=****"],
                        "recommended_inputs": [
                            "capture non-secret object identifiers from path, query, request body, or response body",
                        ],
                    }
                ],
                "coverage_targets": ["authorization", "business_logic", "llm_api"],
                "coverage_target_details": {
                    "authorization": {
                        "template_requested": True,
                        "template_covered": True,
                        "endpoint_signal_count": 1,
                        "status": "available",
                        "signals": ["auth_context", "private_identifier", "token=****"],
                    },
                    "business_logic": {
                        "template_requested": True,
                        "template_covered": False,
                        "endpoint_signal_count": 1,
                        "status": "gap",
                        "signals": ["workflow_path", "secret=****"],
                    },
                    "llm_api": {
                        "template_requested": True,
                        "template_covered": True,
                        "endpoint_signal_count": 1,
                        "status": "available",
                        "signals": ["body_key", "tool_context", "token=****"],
                        "readiness": {
                            "prompt_context_ready": True,
                            "tool_context_ready": True,
                            "tool_abuse_testable": True,
                        },
                        "active_test_families": {
                            "prompt_injection": {
                                "template_count": 1,
                                "endpoint_signal_count": 1,
                                "ready": True,
                                "status": "ready",
                                "signals": ["body_key", "path_hint", "token=****"],
                            },
                            "tool_chain_injection": {
                                "template_count": 0,
                                "endpoint_signal_count": 1,
                                "ready": False,
                                "status": "missing_template",
                                "signals": [
                                    "tool_invocation_context",
                                    "tool_output_context",
                                    "secret=****",
                                ],
                            },
                        },
                    },
                },
            },
            {
                "engine": "schemathesis",
                "artifact_type": "schemathesis_execution",
                "artifact_present": True,
                "artifact_verified": True,
                "selection_accountability_present": False,
                "status": "missing_selection_accountability",
            },
            {
                "engine": "nuclei",
                "artifact_type": "nuclei_execution",
                "artifact_present": True,
                "artifact_verified": False,
                "selection_accountability_present": True,
                "status": "unverified_artifact",
            },
        ],
    }
    assert "raw-token" not in str(selection)
    assert "token=****" not in str(selection["engine_details"][0]["coverage_targets"])
