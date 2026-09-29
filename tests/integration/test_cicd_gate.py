"""
Integration tests for the CI/CD gate endpoints.

Covers:
- Gate pass when no vulnerable findings exist
- Gate blocked when critical/high findings exist
- SARIF export structure
- JUnit XML export structure
- Artifact manifest hashes
- Regression check for reopened findings
"""
import json
import pytest
import pytest_asyncio
from httpx import AsyncClient


pytestmark = pytest.mark.asyncio


def _complete_clean_evidence(template_id: str = "engine-clean-check") -> str:
    from server.modules.test_executor.evidence import evidence_digest

    evidence = {
        "engine": "template",
        "template_id": template_id,
        "results": [{"vulnerable": False}],
        "evidence_completeness": {
            "complete": True,
            "required": ["evidence_completeness", "safety_policies"],
            "present": ["evidence_completeness", "safety_policies"],
            "missing": [],
        },
        "safety_policies": {
            "target_guard_policy": {
                "policy": "target_guard",
                "blocked": False,
                "url": "https://api.example.com/openapi.json",
            },
            "state_change_policy": {
                "policy": "state_change_guard",
                "method": "GET",
                "allow_state_change": False,
                "allow_destructive_methods": False,
                "destructive_method": False,
            },
        },
        "retest_support": {
            "supported": True,
            "queued_scan_supported": True,
            "manual_outcome_supported": True,
            "reason": "queued_scan_available",
            "missing_fields": [],
        },
    }
    evidence["hash_algorithm"] = "sha256"
    evidence["evidence_hash"] = evidence_digest(evidence)
    return json.dumps(evidence, sort_keys=True)


def _complete_confirmed_vulnerability_evidence(template_id: str = "historic-bola") -> dict:
    from server.modules.test_executor.evidence import evidence_digest

    evidence = {
        "engine": "template",
        "template_id": template_id,
        "finding_status": "CONFIRMED",
        "confirmation": {"confirmed": True, "source": "confirmatory_retest"},
        "sent_request": {
            "method": "GET",
            "url": "https://api.example.com/orders/123?token=raw-ticket-token",
            "headers": {"Authorization": "Bearer raw-ticket-token"},
        },
        "received_response": {"status_code": 200},
        "results": [{"vulnerable": True}],
        "evidence_completeness": {
            "complete": True,
            "required": ["evidence_completeness", "safety_policies", "retest_support"],
            "present": ["evidence_completeness", "safety_policies", "retest_support"],
            "missing": [],
        },
        "safety_policies": {
            "target_guard_policy": {
                "policy": "target_guard",
                "blocked": False,
                "url": "https://api.example.com/orders/123?token=raw-ticket-token",
            },
            "state_change_policy": {
                "policy": "state_change_guard",
                "method": "GET",
                "allow_state_change": False,
                "allow_destructive_methods": False,
                "destructive_method": False,
            },
        },
        "retest_support": {
            "supported": True,
            "queued_scan_supported": True,
            "manual_outcome_supported": True,
            "reason": "queued_scan_available",
            "missing_fields": [],
        },
        "evidence_reproducibility": {
            "raw_payload_persisted": False,
            "deterministic_hash": True,
            "reproduction_available": True,
            "scope_validated": True,
            "evidence_complete": True,
        },
        "scope_validation": {"validated": True, "policy": "target_guard"},
    }
    evidence["hash_algorithm"] = "sha256"
    evidence["evidence_hash"] = evidence_digest(evidence)
    return evidence


def _refresh_artifact_hash(payload: dict) -> None:
    from server.modules.pentest.execution_artifacts import (
        _artifact_digest,
        verify_execution_artifact_payload,
    )

    payload["artifact_hash"] = _artifact_digest(payload)
    payload["artifact_verification"] = verify_execution_artifact_payload(payload)


@pytest_asyncio.fixture
async def admin_token():
    """Return a test admin cookie for the default tenant used by these fixtures."""
    from server.modules.auth.jwt_issuer import JWTIssuer

    token = JWTIssuer.create_access_token(
        {
            "sub": "test-user",
            "email": "cicdgate@test.io",
            "account_id": 1000000,
            "role": "ADMIN",
        }
    )
    return {"access_token": token}


@pytest_asyncio.fixture
async def run_id(client: AsyncClient, admin_token, db_session):
    """Create a completed test run with one vulnerable result."""
    from server.models.core import TestRun, TestResult
    import uuid

    run_id = str(uuid.uuid4())
    result_id = str(uuid.uuid4())

    run = TestRun(
        id=run_id,
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        vulnerable_count=1,
        error_count=0,
        template_ids=["bola_user_id"],
        endpoint_ids=["ep-001"],
    )
    db_session.add(run)
    result = TestResult(
        id=result_id,
        run_id=run_id,
        endpoint_id="ep-001",
        template_id="bola_user_id",
        is_vulnerable=True,
        severity="HIGH",
        evidence=json.dumps({"result": "access granted to another user's resource"}),
    )
    db_session.add(result)
    await db_session.commit()

    return run_id


@pytest_asyncio.fixture
async def clean_run_id(client: AsyncClient, admin_token, db_session):
    """Create a completed test run with no vulnerable results."""
    from server.models.core import TestRun, TestResult
    import uuid

    run_id = str(uuid.uuid4())
    result_id = str(uuid.uuid4())

    run = TestRun(
        id=run_id,
        account_id=1000000,
        status="COMPLETED",
        total_tests=1,
        vulnerable_count=0,
        error_count=0,
        template_ids=["bola_user_id"],
        endpoint_ids=["ep-001"],
    )
    db_session.add(run)
    result = TestResult(
        id=result_id,
        run_id=run_id,
        endpoint_id="ep-001",
        template_id="bola_user_id",
        is_vulnerable=False,
        severity="HIGH",
    )
    db_session.add(result)
    await db_session.commit()

    return run_id


async def test_gate_blocked_on_vulnerable_finding(client: AsyncClient, run_id, admin_token):
    r = await client.get(f"/api/cicd/{run_id}/gate", cookies=admin_token)
    assert r.status_code == 200
    data = r.json()
    assert data["gate_passed"] is False
    assert data["blocked"] is True
    assert len(data["blocked_reasons"]) >= 1
    assert any("vulnerable_finding" in reason for reason in data["blocked_reasons"])
    assert data["vulnerable_count"] >= 1


async def test_gate_passes_on_clean_run(client: AsyncClient, clean_run_id, admin_token):
    r = await client.get(f"/api/cicd/{clean_run_id}/gate", cookies=admin_token)
    assert r.status_code == 200
    data = r.json()
    assert data["gate_passed"] is True
    assert data["blocked"] is False
    assert data["blocked_reasons"] == []


async def test_gate_blocks_authorization_replay_without_boundary_coverage(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import TestRun, TestResult
    import uuid

    run_id = str(uuid.uuid4())
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["bfla-authz-replay"],
            endpoint_ids=["ep-authz"],
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-authz",
            template_id="bfla-authz-replay",
            is_vulnerable=False,
            severity="INFO",
            evidence=json.dumps(
                {
                    "engine": "authorization_replay",
                    "issue_type": "BFLA",
                    "identity_pair": {
                        "victim": {"role": "ADMIN", "id": "victim-admin"},
                        "attacker": {"role": "MEMBER", "id": "attacker-member"},
                    },
                    "replay_request": {
                        "method": "GET",
                        "url": "https://api.example.com/admin/users/123",
                        "headers": {
                            "Authorization": "Bearer raw-attacker-token",
                            "X-Tenant-ID": "tenant-a",
                        },
                    },
                },
                sort_keys=True,
            ),
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/{run_id}/gate", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["gate_passed"] is False
    assert data["blocked"] is True
    assert data["blocked_reasons"] == [
        "missing_authorization_boundary_coverage: template=bfla-authz-replay"
    ]
    coverage = data["authorization_boundary_coverage"]
    assert coverage["required"] is True
    assert coverage["missing_result_count"] == 1
    assert coverage["missing_results"][0]["authorization_boundary_coverage"]["present"] is False
    assert "raw-attacker-token" not in str(data)
    assert "tenant-a" not in str(data)


async def test_strict_gate_blocks_authorization_replay_without_boundary_coverage(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import TestRun, TestResult
    from server.modules.test_executor.evidence import evidence_digest
    import uuid

    run_id = str(uuid.uuid4())
    evidence = {
        "engine": "authorization_replay",
        "template_id": "bfla-authz-replay",
        "issue_type": "BFLA",
        "identity_pair": {
            "victim": {"role": "ADMIN", "id": "victim-admin"},
            "attacker": {"role": "MEMBER", "id": "attacker-member"},
        },
        "replay_request": {
            "method": "GET",
            "url": "https://api.example.com/admin/users/123",
            "headers": {
                "Authorization": "Bearer raw-attacker-token",
                "X-Tenant-ID": "tenant-a",
            },
        },
        "evidence_completeness": {
            "complete": True,
            "required": ["evidence_completeness"],
            "present": ["evidence_completeness"],
            "missing": [],
        },
        "safety_policies": {
            "target_guard_policy": {
                "policy": "target_guard",
                "blocked": False,
                "url": "https://api.example.com/admin/users/123",
            },
            "state_change_policy": {
                "policy": "state_change_guard",
                "method": "GET",
                "allow_state_change": False,
                "allow_destructive_methods": False,
                "destructive_method": False,
            },
        },
        "retest_support": {
            "supported": True,
            "queued_scan_supported": True,
            "manual_outcome_supported": True,
            "reason": "queued_scan_available",
            "missing_fields": [],
        },
    }
    evidence["hash_algorithm"] = "sha256"
    evidence["evidence_hash"] = evidence_digest(evidence)
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["bfla-authz-replay"],
            endpoint_ids=["ep-authz"],
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-authz",
            template_id="bfla-authz-replay",
            is_vulnerable=False,
            severity="INFO",
            evidence=json.dumps(evidence, sort_keys=True),
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["reason"] == "missing_authorization_boundary_coverage"
    assert data["policy"]["require_authorization_boundary_coverage"] is True
    assert data["scan_context"]["authenticated"] is True
    assert data["scan_context"]["auth_context_reason"] == "authorization_replay_test_accounts"
    assert data["counts"]["missing_authorization_boundary_results"] == 1
    assert data["missing_authorization_boundary_results"][0]["template_id"] == "bfla-authz-replay"
    assert "raw-attacker-token" not in str(data)
    assert "tenant-a" not in str(data)


async def test_strict_gate_blocks_authorization_replay_boundary_that_does_not_match_issue_type(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import TestRun, TestResult
    from server.modules.test_executor.evidence import evidence_digest
    import uuid

    run_id = str(uuid.uuid4())
    evidence = {
        "engine": "authorization_replay",
        "template_id": "bfla-authz-replay",
        "issue_type": "BFLA",
        "identity_pair": {
            "victim": {"role": "ADMIN", "id": "victim-admin"},
            "attacker": {"role": "MEMBER", "id": "attacker-member"},
        },
        "replay_request": {
            "method": "GET",
            "url": "https://api.example.com/admin/users/123",
            "headers": {
                "Authorization": "Bearer raw-attacker-token",
                "X-Tenant-ID": "tenant-a",
            },
        },
        "authorization_boundary_coverage": {
            "primary_boundary_kind": "cross_tenant",
            "boundary_kinds": ["cross_tenant"],
            "compared_fields": ["X-Tenant-ID"],
            "changed_fields": ["X-Tenant-ID"],
            "unchanged_fields": ["X-Request-ID"],
        },
        "evidence_completeness": {
            "complete": True,
            "required": ["evidence_completeness"],
            "present": ["evidence_completeness"],
            "missing": [],
        },
        "safety_policies": {
            "target_guard_policy": {
                "policy": "target_guard",
                "blocked": False,
                "url": "https://api.example.com/admin/users/123",
            },
            "state_change_policy": {
                "policy": "state_change_guard",
                "method": "GET",
                "allow_state_change": False,
                "allow_destructive_methods": False,
                "destructive_method": False,
            },
        },
        "retest_support": {
            "supported": True,
            "queued_scan_supported": True,
            "manual_outcome_supported": True,
            "reason": "queued_scan_available",
            "missing_fields": [],
        },
    }
    evidence["hash_algorithm"] = "sha256"
    evidence["evidence_hash"] = evidence_digest(evidence)
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["bfla-authz-replay"],
            endpoint_ids=["ep-authz"],
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-authz",
            template_id="bfla-authz-replay",
            is_vulnerable=False,
            severity="INFO",
            evidence=json.dumps(evidence, sort_keys=True),
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["reason"] == "missing_authorization_boundary_coverage"
    assert data["counts"]["missing_authorization_boundary_results"] == 1
    coverage = data["missing_authorization_boundary_results"][0]["authorization_boundary_coverage"]
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
    assert "raw-attacker-token" not in str(data)
    assert "tenant-a" not in str(data)


async def test_sarif_export_structure(client: AsyncClient, run_id, admin_token):
    r = await client.get(f"/api/cicd/{run_id}/sarif", cookies=admin_token)
    assert r.status_code == 200
    sarif = r.json()
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run_data = sarif["runs"][0]
    assert "tool" in run_data
    assert run_data["tool"]["driver"]["name"] == "API-Sentinel"
    # Should have at least one result for the vulnerable finding
    assert len(run_data["results"]) >= 1
    result = run_data["results"][0]
    assert result["level"] in {"error", "warning", "note"}
    assert "ruleId" in result


async def test_junit_export_structure(client: AsyncClient, run_id, admin_token):
    r = await client.get(f"/api/cicd/{run_id}/junit", cookies=admin_token)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/xml")
    xml = r.text
    assert "<testsuite" in xml
    assert "bola_user_id" in xml
    assert "<failure" in xml  # vulnerable finding generates a failure element


async def test_artifact_manifest_hashes(client: AsyncClient, run_id, admin_token):
    r = await client.get(f"/api/cicd/{run_id}/artifacts", cookies=admin_token)
    assert r.status_code == 200
    manifest = r.json()
    assert manifest["required"] is True
    assert manifest["run_id"] == run_id
    artifacts = manifest["artifacts"]
    assert len(artifacts) == 2
    formats = {a["format"] for a in artifacts}
    assert formats == {"sarif", "junit"}
    for artifact in artifacts:
        assert "canonical_hash" in artifact
        assert len(artifact["canonical_hash"]) == 64  # sha256 hex
        assert artifact["hash_algorithm"] == "sha256"


async def test_artifact_manifest_accounts_for_stored_engine_execution_artifacts(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import PentestArtifact, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
        {"engine": "passive", "status": "available", "reason": "continuous_ingestion_pipeline"},
    ]
    payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/openapi.json?token=raw-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED"},
        engine_plan=engine_plan,
        run_id=run_id,
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=0,
            vulnerable_count=0,
            error_count=0,
            scan_plan={"engine_plan": engine_plan},
        )
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id="profile-1",
            artifact_type="schemathesis_execution",
            filename="schemathesis-execution.json",
            content_json=payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/{run_id}/artifacts", headers=auth_headers)

    assert r.status_code == 200
    manifest = r.json()
    accountability = manifest["engine_accountability"]
    assert accountability["required"] is True
    assert accountability["complete"] is True
    assert accountability["ready_active_engines"] == ["schemathesis"]
    assert accountability["continuous_engines"] == ["passive"]
    assert accountability["missing_artifact_count"] == 0
    required = accountability["required_artifacts"][0]
    assert required["engine"] == "schemathesis"
    assert required["artifact_type"] == "schemathesis_execution"
    assert required["present"] is True
    assert required["verified"] is True
    assert required["status"] == "verified"
    assert "raw-token" not in str(manifest)


async def test_strict_gate_fails_when_ready_engine_execution_artifacts_are_missing(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestProfile, TestResult, TestRun
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
        {"engine": "passive", "status": "available", "reason": "continuous_ingestion_pipeline"},
    ]
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["engine-clean-check"],
            endpoint_ids=["ep-engine"],
            pentest_profile_id=profile_id,
            scan_plan={"engine_plan": engine_plan},
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-engine",
            template_id="engine-clean-check",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence(),
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "missing_engine_execution_artifacts"
    assert data["policy"]["require_engine_artifact_accountability"] is True
    assert data["policy"]["require_engine_artifacts"] is True
    assert data["counts"]["missing_engine_artifact_results"] == 2
    assert data["counts"]["missing_engine_execution_artifacts"] == 1
    assert data["counts"]["missing_continuous_engine_artifacts"] == 1
    assert data["counts"]["unverified_engine_execution_artifacts"] == 0
    assert [item["engine"] for item in data["missing_engine_artifact_results"]] == [
        "schemathesis",
        "passive",
    ]
    assert [item["engine"] for item in data["missing_engine_execution_artifacts"]] == ["schemathesis"]
    assert [item["engine"] for item in data["missing_continuous_engine_artifacts"]] == ["passive"]
    accountability = data["report_artifacts"]["engine_accountability"]
    assert accountability["required"] is True
    assert accountability["complete"] is False
    assert accountability["missing_artifact_count"] == 1
    assert accountability["missing_continuous_artifact_count"] == 1
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_engine_execution_artifact_payload_is_for_wrong_engine(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
    ]
    payload = build_execution_artifact_payload(
        engine="nuclei",
        target_url="https://api.example.com/openapi.json?token=raw-runtime-token",
        profile_id="profile-1",
        execution={"status": "COMPLETED", "stdout": "token=raw-runtime-token"},
        engine_plan=engine_plan,
        run_id=run_id,
    )
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"engine-mismatch-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"engine-mismatch-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["engine-clean-check"],
            endpoint_ids=["ep-engine-mismatch"],
            pentest_profile_id=profile_id,
            scan_plan={"engine_plan": engine_plan},
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-engine-mismatch",
            template_id="engine-clean-check",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence(),
        )
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="schemathesis_execution",
            filename="schemathesis-execution.json",
            content_json=payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "missing_engine_execution_artifacts"
    assert data["counts"]["missing_engine_artifact_results"] == 1
    assert data["counts"]["missing_engine_execution_artifacts"] == 0
    assert data["counts"]["unverified_engine_execution_artifacts"] == 1
    assert data["missing_engine_artifact_results"] == [
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
    assert data["unverified_engine_execution_artifacts"] == [
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "present": True,
            "verified": False,
            "status": "engine_mismatch",
            "hash_algorithm": "sha256",
            "artifact_hash": payload["artifact_hash"],
            "expected_hash": payload["artifact_hash"],
            "actual_hash": payload["artifact_hash"],
            "expected_engine": "schemathesis",
            "artifact_engine": "nuclei",
            "mismatch_fields": ["engine"],
        }
    ]
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_engine_artifact_content_governance_is_not_proven(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
    ]
    payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/openapi.json?token=raw-runtime-token",
        profile_id=profile_id,
        execution={"status": "COMPLETED", "stdout": "token=raw-runtime-token"},
        engine_plan=engine_plan,
        run_id=run_id,
    )
    payload["content_redacted"] = False
    payload["secret_values_persisted"] = True
    payload["normalized_evidence"]["secret_values_persisted"] = True
    payload["execution"]["stdout"] = "Authorization: Bearer raw-runtime-token token=raw-runtime-token"
    _refresh_artifact_hash(payload)
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"content-governance-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"content-governance-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["engine-clean-check"],
            endpoint_ids=["ep-engine-content-governance"],
            pentest_profile_id=profile_id,
            scan_plan={"engine_plan": engine_plan},
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-engine-content-governance",
            template_id="engine-clean-check",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence(),
        )
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="schemathesis_execution",
            filename="schemathesis-execution.json",
            content_json=payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "artifact_content_governance_failed"
    assert data["counts"]["missing_engine_artifact_results"] == 1
    assert data["counts"]["content_governance_failed_engine_artifacts"] == 1
    expected_governance = {
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
    assert data["missing_engine_artifact_results"] == [
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "status": "artifact_content_governance_failed",
            "verification_status": "VERIFIED",
            "normalized_evidence_status": "present",
            "artifact_content_governance": expected_governance,
        }
    ]
    assert data["content_governance_failed_engine_artifacts"] == [
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "present": True,
            "verified": False,
            "status": "artifact_content_governance_failed",
            "hash_algorithm": "sha256",
            "artifact_hash": payload["artifact_hash"],
            "expected_hash": payload["artifact_hash"],
            "actual_hash": payload["artifact_hash"],
            "artifact_content_governance": expected_governance,
        }
    ]
    accountability = data["report_artifacts"]["engine_accountability"]
    assert accountability["complete"] is False
    assert accountability["content_governance_failed_artifact_count"] == 1
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_engine_execution_artifacts_are_duplicated(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
    ]
    first_payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/openapi.json?token=raw-runtime-token",
        profile_id=profile_id,
        execution={"status": "COMPLETED", "summary": {"source": "first"}},
        engine_plan=engine_plan,
        run_id=run_id,
    )
    second_payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/openapi.json?token=raw-runtime-token",
        profile_id=profile_id,
        execution={"status": "COMPLETED", "summary": {"source": "second"}},
        engine_plan=engine_plan,
        run_id=run_id,
    )
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"duplicate-artifact-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"duplicate-artifact-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["engine-clean-check"],
            endpoint_ids=["ep-engine"],
            pentest_profile_id=profile_id,
            scan_plan={"engine_plan": engine_plan},
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-engine",
            template_id="engine-clean-check",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence(),
        )
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="schemathesis_execution",
            filename="schemathesis-execution-first.json",
            content_json=first_payload,
        )
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="schemathesis_execution",
            filename="schemathesis-execution-second.json",
            content_json=second_payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "duplicate_engine_execution_artifacts"
    assert data["counts"]["missing_engine_artifact_results"] == 0
    assert data["counts"]["duplicate_engine_execution_artifacts"] == 1
    assert data["duplicate_engine_execution_artifacts"] == [
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "present": True,
            "verified": False,
            "status": "duplicate_artifact",
            "hash_algorithm": "sha256",
            "artifact_hash": first_payload["artifact_hash"],
            "expected_hash": first_payload["artifact_hash"],
            "actual_hash": first_payload["artifact_hash"],
            "duplicate_count": 2,
            "duplicate_artifact_hashes": [
                first_payload["artifact_hash"],
                second_payload["artifact_hash"],
            ],
        }
    ]
    accountability = data["report_artifacts"]["engine_accountability"]
    assert accountability["complete"] is False
    assert accountability["duplicate_artifact_count"] == 1
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_engine_artifact_lacks_external_worker_isolation_contract(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
    ]
    payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/openapi.json?token=raw-runtime-token",
        profile_id=profile_id,
        execution={"status": "COMPLETED", "stdout": "token=raw-runtime-token"},
        engine_plan=engine_plan,
        run_id=run_id,
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
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"worker-isolation-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"worker-isolation-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["engine-clean-check"],
            endpoint_ids=["ep-engine"],
            pentest_profile_id=profile_id,
            scan_plan={"engine_plan": engine_plan},
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-engine",
            template_id="engine-clean-check",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence(),
        )
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="schemathesis_execution",
            filename="schemathesis-execution.json",
            content_json=payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "incomplete_worker_isolation_artifacts"
    assert data["counts"]["missing_engine_artifact_results"] == 0
    assert data["counts"]["incomplete_worker_isolation_engine_artifacts"] == 1
    assert data["incomplete_worker_isolation_engine_artifacts"] == [
        {
            "engine": "schemathesis",
            "artifact_type": "schemathesis_execution",
            "present": True,
            "verified": False,
            "status": "worker_isolation_incomplete",
            "hash_algorithm": "sha256",
            "artifact_hash": payload["artifact_hash"],
            "expected_hash": payload["artifact_hash"],
            "actual_hash": payload["artifact_hash"],
            "worker_isolation": {
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
            },
        }
    ]
    accountability = data["report_artifacts"]["engine_accountability"]
    assert accountability["complete"] is False
    assert accountability["incomplete_worker_isolation_artifact_count"] == 1
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_context_selection_accountability_is_missing(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
        {"engine": "passive", "status": "available", "reason": "continuous_ingestion_pipeline"},
    ]
    scan_plan = {
        "schema_version": "scan_plan.v1",
        "hash_algorithm": "sha256",
        "scan_plan_hash": "e" * 64,
        "engine_plan": engine_plan,
        "context": {
            "context_aware_selection": True,
            "partial_context_aware_selection": False,
            "status": "ready",
            "required_signals": ["method_context", "token=raw-runtime-token"],
            "available_signals": ["method_context"],
            "satisfied_signals": ["method_context"],
            "missing_signals": [],
        },
        "selection": {
            "template_endpoint_pair_count": 1,
            "selected_pair_count": 1,
            "skipped_pair_count": 0,
            "pair_decision_count": 1,
            "pair_decision_report_truncated": False,
        },
    }
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"selection-gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"selection-gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["engine-clean-check"],
            endpoint_ids=["ep-selection"],
            pentest_profile_id=profile_id,
            scan_plan=scan_plan,
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-selection",
            template_id="engine-clean-check",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence(),
        )
    )
    artifact_payload = build_execution_artifact_payload(
        engine="schemathesis",
        target_url="https://api.example.com/openapi.json?token=raw-runtime-token",
        profile_id=profile_id,
        execution={
            "status": "COMPLETED",
            "command": "schemathesis run openapi.json --config schemathesis.toml",
            "summary": {"requests_sent": 1},
        },
        engine_plan=engine_plan,
        run_id=run_id,
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="schemathesis_execution",
            filename="schemathesis-execution.json",
            content_json=artifact_payload,
        )
    )
    passive_payload = build_execution_artifact_payload(
        engine="passive",
        target_url="https://api.example.com/openapi.json?token=raw-runtime-token",
        profile_id=profile_id,
        execution={
            "status": "AVAILABLE",
            "summary": {"events_processed": 1},
        },
        engine_plan=engine_plan,
        findings={"created_count": 0},
        run_id=run_id,
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="passive_findings",
            filename="passive-findings.json",
            content_json=passive_payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "incomplete_selection_accountability"
    assert data["policy"]["require_engine_artifact_accountability"] is True
    assert data["counts"]["missing_engine_execution_artifacts"] == 0
    assert data["counts"]["unverified_engine_execution_artifacts"] == 0
    assert data["counts"]["missing_selection_accountability"] == 1
    assert data["counts"]["unverified_selection_accountability"] == 0
    assert data["missing_selection_accountability"][0] == {
        "engine": "schemathesis",
        "artifact_type": "schemathesis_execution",
        "artifact_present": True,
        "artifact_verified": True,
        "selection_accountability_present": False,
        "status": "missing_selection_accountability",
    }
    selection = data["report_artifacts"]["engine_accountability"]["selection_accountability"]
    assert selection["scan_plan_context_present"] is True
    assert selection["selection_accountability_complete"] is False
    assert selection["missing_selection_accountability_count"] == 1
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_llm_selection_coverage_family_details_are_missing(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "templates", "status": "ready", "reason": "template_engine_available"},
    ]
    scan_plan = {
        "schema_version": "scan_plan.v1",
        "hash_algorithm": "sha256",
        "scan_plan_hash": "f" * 64,
        "engine_plan": engine_plan,
        "context": {
            "context_aware_selection": True,
            "partial_context_aware_selection": False,
            "status": "ready",
            "required_signals": ["method_context", "url_context"],
            "available_signals": ["method_context", "url_context"],
            "satisfied_signals": ["method_context", "url_context"],
            "missing_signals": [],
        },
        "selection": {
            "template_endpoint_pair_count": 1,
            "selected_pair_count": 1,
            "skipped_pair_count": 0,
            "pair_decision_count": 1,
            "pair_decision_report_truncated": False,
        },
        "coverage_targets": {
            "llm_api": {
                "template_requested": True,
                "template_covered": True,
                "endpoint_signal_count": 1,
                "status": "available",
                "signals": ["body_key", "tool_context", "token=raw-runtime-token"],
            },
        },
    }
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"llm-coverage-gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"llm-coverage-gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE"],
            endpoint_ids=["ep-llm-coverage"],
            pentest_profile_id=profile_id,
            scan_plan=scan_plan,
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-llm-coverage",
            template_id="LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence("LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE"),
        )
    )
    artifact_payload = build_execution_artifact_payload(
        engine="templates",
        target_url="https://api.example.com/v1/responses?token=raw-runtime-token",
        profile_id=profile_id,
        execution={
            "status": "COMPLETED",
            "scan_plan": scan_plan,
        },
        engine_plan=engine_plan,
        run_id=run_id,
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="templates_execution",
            filename="templates-execution.json",
            content_json=artifact_payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "incomplete_selection_coverage_accountability"
    assert data["counts"]["selection_coverage_accountability_gaps"] == 1
    assert data["selection_coverage_accountability_gaps"] == [
        {
            "engine": "templates",
            "artifact_type": "templates_execution",
            "target": "llm_api",
            "reason": "missing_coverage_target_fields",
            "missing_fields": ["active_test_families"],
        }
    ]
    assert data["report_artifacts"]["engine_accountability"]["selection_accountability"][
        "selection_accountability_complete"
    ] is True
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_business_logic_selection_coverage_family_details_are_missing(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "templates", "status": "ready", "reason": "template_engine_available"},
    ]
    scan_plan = {
        "schema_version": "scan_plan.v1",
        "hash_algorithm": "sha256",
        "scan_plan_hash": "a" * 64,
        "engine_plan": engine_plan,
        "context": {
            "context_aware_selection": True,
            "partial_context_aware_selection": False,
            "status": "ready",
            "required_signals": ["method_context", "traffic_context"],
            "available_signals": ["method_context", "traffic_context"],
            "satisfied_signals": ["method_context", "traffic_context"],
            "missing_signals": [],
        },
        "selection": {
            "template_endpoint_pair_count": 1,
            "selected_pair_count": 1,
            "skipped_pair_count": 0,
            "pair_decision_count": 1,
            "pair_decision_report_truncated": False,
        },
        "coverage_targets": {
            "business_logic": {
                "template_requested": True,
                "template_covered": True,
                "endpoint_signal_count": 1,
                "status": "available",
                "signals": ["workflow_path", "state_changing_method", "token=raw-runtime-token"],
            },
        },
    }
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"business-coverage-gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"business-coverage-gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["ACTIVE_BUSINESS_LOGIC_WORKFLOW_BYPASS"],
            endpoint_ids=["ep-business-coverage"],
            pentest_profile_id=profile_id,
            scan_plan=scan_plan,
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-business-coverage",
            template_id="ACTIVE_BUSINESS_LOGIC_WORKFLOW_BYPASS",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence("ACTIVE_BUSINESS_LOGIC_WORKFLOW_BYPASS"),
        )
    )
    artifact_payload = build_execution_artifact_payload(
        engine="templates",
        target_url="https://api.example.com/checkout/apply-coupon?token=raw-runtime-token",
        profile_id=profile_id,
        execution={
            "status": "COMPLETED",
            "scan_plan": scan_plan,
        },
        engine_plan=engine_plan,
        run_id=run_id,
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="templates_execution",
            filename="templates-execution.json",
            content_json=artifact_payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "incomplete_selection_coverage_accountability"
    assert data["counts"]["selection_coverage_accountability_gaps"] == 1
    assert data["selection_coverage_accountability_gaps"] == [
        {
            "engine": "templates",
            "artifact_type": "templates_execution",
            "target": "business_logic",
            "reason": "missing_coverage_target_fields",
            "missing_fields": ["active_test_families"],
        }
    ]
    assert data["report_artifacts"]["engine_accountability"]["selection_accountability"][
        "selection_accountability_complete"
    ] is True
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_active_family_coverage_claims_available_but_none_ready(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "templates", "status": "ready", "reason": "template_engine_available"},
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
            "required_signals": ["method_context", "traffic_context", "url_context"],
            "available_signals": ["method_context", "traffic_context", "url_context"],
            "satisfied_signals": ["method_context", "traffic_context", "url_context"],
            "missing_signals": [],
        },
        "selection": {
            "template_endpoint_pair_count": 2,
            "selected_pair_count": 2,
            "skipped_pair_count": 0,
            "pair_decision_count": 2,
            "pair_decision_report_truncated": False,
        },
        "coverage_targets": {
            "business_logic": {
                "template_requested": True,
                "template_covered": True,
                "endpoint_signal_count": 1,
                "status": "available",
                "signals": ["workflow_path", "state_changing_method", "token=raw-runtime-token"],
                "active_test_families": {
                    "workflow_bypass": {
                        "template_count": 1,
                        "endpoint_signal_count": 0,
                        "ready": False,
                        "status": "missing_endpoint_context",
                        "signals": [],
                    }
                },
            },
            "llm_api": {
                "template_requested": True,
                "template_covered": True,
                "endpoint_signal_count": 1,
                "status": "available",
                "signals": ["body_key", "tool_context", "token=raw-runtime-token"],
                "active_test_families": {
                    "prompt_injection": {
                        "template_count": 1,
                        "endpoint_signal_count": 0,
                        "ready": False,
                        "status": "missing_endpoint_context",
                        "signals": [],
                    }
                },
            },
        },
    }
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"active-family-consistency-gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"active-family-consistency-gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=[
                "ACTIVE_BUSINESS_LOGIC_WORKFLOW_BYPASS",
                "LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE",
            ],
            endpoint_ids=["ep-active-family-consistency"],
            pentest_profile_id=profile_id,
            scan_plan=scan_plan,
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-active-family-consistency",
            template_id="ACTIVE_BUSINESS_LOGIC_WORKFLOW_BYPASS",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence("ACTIVE_BUSINESS_LOGIC_WORKFLOW_BYPASS"),
        )
    )
    artifact_payload = build_execution_artifact_payload(
        engine="templates",
        target_url="https://api.example.com/v1/responses?token=raw-runtime-token",
        profile_id=profile_id,
        execution={
            "status": "COMPLETED",
            "scan_plan": scan_plan,
        },
        engine_plan=engine_plan,
        run_id=run_id,
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="templates_execution",
            filename="templates-execution.json",
            content_json=artifact_payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "incomplete_selection_coverage_accountability"
    assert data["counts"]["selection_coverage_accountability_gaps"] == 2
    assert data["selection_coverage_accountability_gaps"] == [
        {
            "engine": "templates",
            "artifact_type": "templates_execution",
            "target": "business_logic",
            "reason": "coverage_target_not_ready",
            "missing_fields": ["active_test_families.ready"],
        },
        {
            "engine": "templates",
            "artifact_type": "templates_execution",
            "target": "llm_api",
            "reason": "coverage_target_not_ready",
            "missing_fields": ["active_test_families.ready"],
        },
    ]
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_authorization_selection_coverage_identity_details_are_missing(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "templates", "status": "ready", "reason": "template_engine_available"},
    ]
    scan_plan = {
        "schema_version": "scan_plan.v1",
        "hash_algorithm": "sha256",
        "scan_plan_hash": "b" * 64,
        "engine_plan": engine_plan,
        "context": {
            "context_aware_selection": True,
            "partial_context_aware_selection": False,
            "status": "ready",
            "required_signals": ["auth_context", "private_variable_context"],
            "available_signals": ["auth_context", "private_variable_context"],
            "satisfied_signals": ["auth_context", "private_variable_context"],
            "missing_signals": [],
        },
        "selection": {
            "template_endpoint_pair_count": 1,
            "selected_pair_count": 1,
            "skipped_pair_count": 0,
            "pair_decision_count": 1,
            "pair_decision_report_truncated": False,
        },
        "coverage_targets": {
            "authorization": {
                "template_requested": True,
                "template_covered": True,
                "endpoint_signal_count": 1,
                "status": "available",
                "signals": ["auth_context", "private_identifier", "token=raw-runtime-token"],
            },
        },
    }
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"authorization-coverage-gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"authorization-coverage-gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["BOLA_AUTHORIZATION_REPLAY"],
            endpoint_ids=["ep-authorization-coverage"],
            pentest_profile_id=profile_id,
            scan_plan=scan_plan,
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-authorization-coverage",
            template_id="BOLA_AUTHORIZATION_REPLAY",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence("BOLA_AUTHORIZATION_REPLAY"),
        )
    )
    artifact_payload = build_execution_artifact_payload(
        engine="templates",
        target_url="https://api.example.com/accounts/123?token=raw-runtime-token",
        profile_id=profile_id,
        execution={
            "status": "COMPLETED",
            "scan_plan": scan_plan,
        },
        engine_plan=engine_plan,
        run_id=run_id,
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="templates_execution",
            filename="templates-execution.json",
            content_json=artifact_payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "incomplete_selection_coverage_accountability"
    assert data["counts"]["selection_coverage_accountability_gaps"] == 1
    assert data["selection_coverage_accountability_gaps"] == [
        {
            "engine": "templates",
            "artifact_type": "templates_execution",
            "target": "authorization",
            "reason": "missing_coverage_target_fields",
            "missing_fields": ["identity_context", "readiness"],
        }
    ]
    assert data["report_artifacts"]["engine_accountability"]["selection_accountability"][
        "selection_accountability_complete"
    ] is True
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_authorization_selection_coverage_identity_details_are_incomplete(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "templates", "status": "ready", "reason": "template_engine_available"},
    ]
    scan_plan = {
        "schema_version": "scan_plan.v1",
        "hash_algorithm": "sha256",
        "scan_plan_hash": "c" * 64,
        "engine_plan": engine_plan,
        "context": {
            "context_aware_selection": True,
            "partial_context_aware_selection": False,
            "status": "ready",
            "required_signals": ["auth_context", "private_variable_context"],
            "available_signals": ["auth_context", "private_variable_context"],
            "satisfied_signals": ["auth_context", "private_variable_context"],
            "missing_signals": [],
        },
        "selection": {
            "template_endpoint_pair_count": 1,
            "selected_pair_count": 1,
            "skipped_pair_count": 0,
            "pair_decision_count": 1,
            "pair_decision_report_truncated": False,
        },
        "coverage_targets": {
            "authorization": {
                "template_requested": True,
                "template_covered": True,
                "endpoint_signal_count": 1,
                "status": "available",
                "signals": ["auth_context", "private_identifier", "token=raw-runtime-token"],
                "identity_context": {
                    "role_count": 2,
                    "multi_identity_ready": True,
                },
                "readiness": {
                    "auth_context_ready": True,
                    "role_context_ready": True,
                },
            },
        },
    }
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"authorization-incomplete-coverage-gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"authorization-incomplete-coverage-gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["BFLA_AUTHORIZATION_REPLAY"],
            endpoint_ids=["ep-authorization-incomplete-coverage"],
            pentest_profile_id=profile_id,
            scan_plan=scan_plan,
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-authorization-incomplete-coverage",
            template_id="BFLA_AUTHORIZATION_REPLAY",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence("BFLA_AUTHORIZATION_REPLAY"),
        )
    )
    artifact_payload = build_execution_artifact_payload(
        engine="templates",
        target_url="https://api.example.com/accounts/123?token=raw-runtime-token",
        profile_id=profile_id,
        execution={
            "status": "COMPLETED",
            "scan_plan": scan_plan,
        },
        engine_plan=engine_plan,
        run_id=run_id,
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="templates_execution",
            filename="templates-execution.json",
            content_json=artifact_payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "incomplete_selection_coverage_accountability"
    assert data["counts"]["selection_coverage_accountability_gaps"] == 1
    assert data["selection_coverage_accountability_gaps"] == [
        {
            "engine": "templates",
            "artifact_type": "templates_execution",
            "target": "authorization",
            "reason": "missing_coverage_target_fields",
            "missing_fields": [
                "identity_context.low_privilege_role_present",
                "identity_context.privilege_boundary_pair_count",
                "identity_context.privileged_role_present",
                "readiness.bfla_replay_testable",
                "readiness.bola_replay_testable",
                "readiness.private_identifier_context_ready",
            ],
        }
    ]
    assert data["report_artifacts"]["engine_accountability"]["selection_accountability"][
        "selection_accountability_complete"
    ] is True
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_when_authorization_coverage_claims_available_but_no_replay_ready(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import AuthProfile, PentestArtifact, PentestProfile, TestResult, TestRun
    from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "templates", "status": "ready", "reason": "template_engine_available"},
    ]
    scan_plan = {
        "schema_version": "scan_plan.v1",
        "hash_algorithm": "sha256",
        "scan_plan_hash": "9" * 64,
        "engine_plan": engine_plan,
        "context": {
            "context_aware_selection": True,
            "partial_context_aware_selection": False,
            "status": "ready",
            "required_signals": ["auth_context", "private_variable_context"],
            "available_signals": ["auth_context", "private_variable_context"],
            "satisfied_signals": ["auth_context", "private_variable_context"],
            "missing_signals": [],
        },
        "selection": {
            "template_endpoint_pair_count": 1,
            "selected_pair_count": 1,
            "skipped_pair_count": 0,
            "pair_decision_count": 1,
            "pair_decision_report_truncated": False,
        },
        "coverage_targets": {
            "authorization": {
                "template_requested": True,
                "template_covered": True,
                "endpoint_signal_count": 1,
                "status": "available",
                "signals": ["auth_context", "private_identifier", "token=raw-runtime-token"],
                "identity_context": {
                    "role_count": 1,
                    "multi_identity_ready": False,
                    "privileged_role_present": True,
                    "low_privilege_role_present": False,
                    "privilege_boundary_pair_count": 0,
                },
                "readiness": {
                    "auth_context_ready": True,
                    "private_identifier_context_ready": False,
                    "role_context_ready": False,
                    "bola_replay_testable": False,
                    "bfla_replay_testable": False,
                },
            },
        },
    }
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"authorization-not-ready-coverage-gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-runtime-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"authorization-not-ready-coverage-gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["BFLA_AUTHORIZATION_REPLAY"],
            endpoint_ids=["ep-authorization-not-ready-coverage"],
            pentest_profile_id=profile_id,
            scan_plan=scan_plan,
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-authorization-not-ready-coverage",
            template_id="BFLA_AUTHORIZATION_REPLAY",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence("BFLA_AUTHORIZATION_REPLAY"),
        )
    )
    artifact_payload = build_execution_artifact_payload(
        engine="templates",
        target_url="https://api.example.com/accounts/123?token=raw-runtime-token",
        profile_id=profile_id,
        execution={
            "status": "COMPLETED",
            "scan_plan": scan_plan,
        },
        engine_plan=engine_plan,
        run_id=run_id,
    )
    db_session.add(
        PentestArtifact(
            account_id=1000000,
            run_id=run_id,
            pentest_profile_id=profile_id,
            artifact_type="templates_execution",
            filename="templates-execution.json",
            content_json=artifact_payload,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "incomplete_selection_coverage_accountability"
    assert data["counts"]["selection_coverage_accountability_gaps"] == 1
    assert data["selection_coverage_accountability_gaps"] == [
        {
            "engine": "templates",
            "artifact_type": "templates_execution",
            "target": "authorization",
            "reason": "coverage_target_not_ready",
            "missing_fields": [
                "readiness.bfla_replay_testable",
                "readiness.bola_replay_testable",
            ],
        }
    ]
    assert data["report_artifacts"]["engine_accountability"]["selection_accountability"][
        "selection_accountability_complete"
    ] is True
    assert "raw-runtime-token" not in str(data)


async def test_strict_gate_fails_clean_run_with_unticketed_blocking_vulnerability(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from datetime import datetime, timezone
    from server.models.core import AuthProfile, PentestProfile, TestResult, TestRun, Vulnerability
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"ticket-gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-ticket-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"ticket-gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["historic-bola"],
            endpoint_ids=["ep-ticketed-release"],
            pentest_profile_id=profile_id,
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-ticketed-release",
            template_id="historic-bola",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence("historic-bola"),
        )
    )
    db_session.add(
        Vulnerability(
            id=str(uuid.uuid4()),
            account_id=1000000,
            endpoint_id="ep-ticketed-release",
            template_id="historic-bola",
            url="https://api.example.com/orders/123?token=raw-ticket-token",
            method="GET",
            severity="HIGH",
            type="BOLA",
            status="OPEN",
            confidence="HIGH",
            evidence=_complete_confirmed_vulnerability_evidence("historic-bola"),
            first_seen_at=datetime(2026, 5, 20, 12, 0, tzinfo=timezone.utc),
            sla_due_at=datetime(2026, 5, 27, 12, 0, tzinfo=timezone.utc),
            ticket_url=None,
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "unticketed_blocking_vulnerabilities"
    assert data["policy"]["require_ticketed_blocking_vulnerabilities"] is True
    assert data["counts"]["scoped_blocking_vulnerabilities"] == 1
    assert data["counts"]["unticketed_blocking_vulnerabilities"] == 1
    assert data["counts"]["overdue_blocking_vulnerabilities"] == 1
    ticketing = data["lifecycle_ticketing"]
    assert ticketing["required"] is True
    assert ticketing["ticketing_complete"] is False
    assert ticketing["scoped_blocking_vulnerability_count"] == 1
    assert ticketing["unticketed_blocking_vulnerability_count"] == 1
    blocker = data["unticketed_blocking_vulnerabilities"][0]
    assert blocker["endpoint_id"] == "ep-ticketed-release"
    assert blocker["template_id"] == "historic-bola"
    assert blocker["severity"] == "HIGH"
    assert blocker["ticket_url_present"] is False
    assert blocker["sla_status"] == "OVERDUE"
    assert blocker["url"] == "https://api.example.com/orders/123?token=****"
    assert "raw-ticket-token" not in str(data)


async def test_strict_gate_fails_clean_run_with_unhealthy_ticket_sync(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from datetime import datetime, timezone
    from server.models.core import AuthProfile, PentestProfile, TestResult, TestRun, Vulnerability
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    evidence = _complete_confirmed_vulnerability_evidence("historic-bola")
    evidence["latest_ticket_sync"] = {
        "synced_at": "2026-06-05T09:00:00Z",
        "source": "jira",
        "external_key": "API-456",
        "external_status": "Reopened",
        "ticket_url": "https://jira.example.com/browse/API-456?selectedIssue=API-456",
        "reason": "ticket_open",
        "notes": "Authorization: Bearer raw-ticket-token",
    }
    evidence["ticket_syncs"] = [evidence["latest_ticket_sync"]]
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"ticket-sync-gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-ticket-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"ticket-sync-gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["historic-bola"],
            endpoint_ids=["ep-ticket-sync-release"],
            pentest_profile_id=profile_id,
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-ticket-sync-release",
            template_id="historic-bola",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence("historic-bola"),
        )
    )
    db_session.add(
        Vulnerability(
            id=str(uuid.uuid4()),
            account_id=1000000,
            endpoint_id="ep-ticket-sync-release",
            template_id="historic-bola",
            url="https://api.example.com/orders/123?token=raw-ticket-token",
            method="GET",
            severity="HIGH",
            type="BOLA",
            status="OPEN",
            confidence="HIGH",
            evidence=evidence,
            first_seen_at=datetime(2026, 5, 20, 12, 0, tzinfo=timezone.utc),
            sla_due_at=datetime(2026, 5, 27, 12, 0, tzinfo=timezone.utc),
            ticket_url="https://jira.example.com/browse/API-456?selectedIssue=API-456",
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "unhealthy_ticket_sync_blocking_vulnerabilities"
    assert data["counts"]["ticketed_blocking_vulnerabilities"] == 1
    assert data["counts"]["unticketed_blocking_vulnerabilities"] == 0
    assert data["counts"]["unhealthy_ticket_sync_blocking_vulnerabilities"] == 1
    ticketing = data["lifecycle_ticketing"]
    assert ticketing["ticketing_complete"] is False
    assert ticketing["unhealthy_ticket_sync_blocking_vulnerability_count"] == 1
    blocker = data["unhealthy_ticket_sync_blocking_vulnerabilities"][0]
    assert blocker["ticket_url_present"] is True
    assert blocker["ticket_url"] == "https://jira.example.com/browse/API-456?selectedIssue=****"
    assert blocker["ticket_sync_present"] is True
    assert blocker["ticket_sync_external_status"] == "Reopened"
    assert blocker["ticket_sync_reason"] == "ticket_open"
    assert blocker["ticket_sync_health"] == "unhealthy"
    assert blocker["ticket_sync_health_reason"] == "ticket_not_in_remediation"
    assert blocker["latest_ticket_sync"]["notes"] == "Authorization: Bearer ****"
    assert "raw-ticket-token" not in str(data)
    assert "selectedIssue=API-456" not in str(data)


async def test_strict_gate_fails_clean_run_with_stale_ticket_sync(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from datetime import datetime, timezone
    from server.models.core import AuthProfile, PentestProfile, TestResult, TestRun, Vulnerability
    import uuid

    run_id = str(uuid.uuid4())
    auth_profile_id = str(uuid.uuid4())
    profile_id = str(uuid.uuid4())
    evidence = _complete_confirmed_vulnerability_evidence("historic-bola")
    evidence["latest_ticket_sync"] = {
        "synced_at": "2020-01-01T00:00:00Z",
        "source": "jira",
        "external_key": "API-789",
        "external_status": "In Progress",
        "ticket_url": "https://jira.example.com/browse/API-789?selectedIssue=API-789",
        "reason": "ticket_in_remediation",
        "notes": "Authorization: Bearer raw-ticket-token",
    }
    evidence["ticket_syncs"] = [evidence["latest_ticket_sync"]]
    db_session.add(
        AuthProfile(
            id=auth_profile_id,
            account_id=1000000,
            name=f"ticket-stale-gate-auth-{auth_profile_id}",
            auth_mode="header",
            header_name="Authorization",
            header_value="Bearer raw-ticket-token",
            is_active=True,
        )
    )
    db_session.add(
        PentestProfile(
            id=profile_id,
            account_id=1000000,
            name=f"ticket-stale-gate-profile-{profile_id}",
            auth_profile_id=auth_profile_id,
        )
    )
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["historic-bola"],
            endpoint_ids=["ep-ticket-stale-release"],
            pentest_profile_id=profile_id,
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-ticket-stale-release",
            template_id="historic-bola",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence("historic-bola"),
        )
    )
    db_session.add(
        Vulnerability(
            id=str(uuid.uuid4()),
            account_id=1000000,
            endpoint_id="ep-ticket-stale-release",
            template_id="historic-bola",
            url="https://api.example.com/orders/123?token=raw-ticket-token",
            method="GET",
            severity="HIGH",
            type="BOLA",
            status="IN_REMEDIATION",
            confidence="HIGH",
            evidence=evidence,
            first_seen_at=datetime(2026, 5, 20, 12, 0, tzinfo=timezone.utc),
            sla_due_at=datetime(2026, 5, 27, 12, 0, tzinfo=timezone.utc),
            ticket_url="https://jira.example.com/browse/API-789?selectedIssue=API-789",
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/gate/{run_id}", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "FAILED"
    assert data["passed"] is False
    assert data["reason"] == "unhealthy_ticket_sync_blocking_vulnerabilities"
    assert data["counts"]["ticketed_blocking_vulnerabilities"] == 1
    assert data["counts"]["unticketed_blocking_vulnerabilities"] == 0
    assert data["counts"]["unhealthy_ticket_sync_blocking_vulnerabilities"] == 1
    ticketing = data["lifecycle_ticketing"]
    assert ticketing["ticketing_complete"] is False
    assert ticketing["unhealthy_ticket_sync_blocking_vulnerability_count"] == 1
    blocker = data["unhealthy_ticket_sync_blocking_vulnerabilities"][0]
    assert blocker["ticket_url_present"] is True
    assert blocker["ticket_sync_present"] is True
    assert blocker["ticket_sync_external_status"] == "In Progress"
    assert blocker["ticket_sync_health"] == "unhealthy"
    assert blocker["ticket_sync_health_reason"] == "stale_ticket_sync"
    assert blocker["ticket_sync_max_age_seconds"] == 86400
    assert blocker["ticket_sync_age_seconds"] > blocker["ticket_sync_max_age_seconds"]
    assert blocker["latest_ticket_sync"]["notes"] == "Authorization: Bearer ****"
    assert "raw-ticket-token" not in str(data)
    assert "selectedIssue=API-789" not in str(data)


async def test_legacy_gate_blocks_missing_ready_engine_execution_artifacts(
    client: AsyncClient,
    db_session,
    auth_headers,
):
    from server.models.core import TestResult, TestRun
    import uuid

    run_id = str(uuid.uuid4())
    engine_plan = [
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
    ]
    db_session.add(
        TestRun(
            id=run_id,
            account_id=1000000,
            status="COMPLETED",
            total_tests=1,
            vulnerable_count=0,
            error_count=0,
            template_ids=["engine-clean-check"],
            endpoint_ids=["ep-engine"],
            scan_plan={"engine_plan": engine_plan},
        )
    )
    db_session.add(
        TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            endpoint_id="ep-engine",
            template_id="engine-clean-check",
            is_vulnerable=False,
            severity="INFO",
            evidence=_complete_clean_evidence(),
        )
    )
    await db_session.commit()

    r = await client.get(f"/api/cicd/{run_id}/gate", headers=auth_headers)

    assert r.status_code == 200
    data = r.json()
    assert data["gate_passed"] is False
    assert data["blocked"] is True
    assert data["blocked_reasons"] == [
        "missing_engine_execution_artifact: engine=schemathesis artifact_type=schemathesis_execution"
    ]
    assert data["engine_accountability"]["required"] is True
    assert data["engine_accountability"]["complete"] is False
    assert data["engine_accountability"]["missing_artifact_count"] == 1


async def test_gate_not_found_for_unknown_run(client: AsyncClient, admin_token):
    r = await client.get("/api/cicd/nonexistent-run-id/gate", cookies=admin_token)
    assert r.status_code == 404


async def test_regression_check_no_regressions(client: AsyncClient, clean_run_id, admin_token):
    r = await client.get(f"/api/cicd/{clean_run_id}/regressions", cookies=admin_token)
    assert r.status_code == 200
    data = r.json()
    assert data["reopened_count"] == 0
    assert data["has_regressions"] is False
    assert data["reopened_findings"] == []


async def test_vulnerability_summary_endpoint(client: AsyncClient, admin_token):
    """The /summary endpoint returns aggregated counts, not raw records."""
    r = await client.get("/api/vulnerabilities/summary", cookies=admin_token)
    assert r.status_code == 200
    data = r.json()
    assert "totalIssues" in data
    assert "openIssues" in data
    assert "fixedIssues" in data
    assert "severityBreakdown" in data
    sev = data["severityBreakdown"]
    for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert key in sev
        assert isinstance(sev[key], int)


async def test_vulnerability_trend_severity_filter(client: AsyncClient, admin_token):
    """The trend endpoint accepts a severity filter without error."""
    r = await client.get(
        "/api/vulnerabilities/trend?severity=CRITICAL",
        cookies=admin_token,
    )
    assert r.status_code == 200
    data = r.json()
    assert "issuesTrend" in data
    assert isinstance(data["issuesTrend"], list)


async def test_vulnerability_trend_invalid_severity(client: AsyncClient, admin_token):
    r = await client.get(
        "/api/vulnerabilities/trend?severity=BOGUS",
        cookies=admin_token,
    )
    assert r.status_code == 400
