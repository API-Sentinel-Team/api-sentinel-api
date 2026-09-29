import pytest
from sqlalchemy import select

from server.models import core as models
from server.api.routers import pentest as pentest_router
from server.models.core import OpenAPISpec, PentestArtifact


def _junit_report(*, failure_type: str = "ignored_auth") -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="schemathesis" tests="1" failures="1">
  <testcase classname="schemathesis" name="POST /admin/users?session=raw-session">
    <failure type="{failure_type}" message="{failure_type}: unauthorized request was accepted">Authorization: Bearer raw-token</failure>
  </testcase>
</testsuite>
"""


@pytest.mark.asyncio
async def test_schemathesis_report_import_promotes_failures_to_vulnerabilities(client, db_session, auth_headers):
    response = await client.post(
        "/api/pentest/schemathesis-report/import",
        headers=auth_headers,
        json={
            "target_url": "https://api.example.com",
            "junit_xml": _junit_report(),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "imported"
    assert payload["testcases_imported"] == 1
    assert payload["failures_imported"] == 1
    assert payload["vulnerabilities_created"] == 1
    assert payload["vulnerabilities_merged"] == 0
    assert payload["vulnerabilities"][0]["template_id"] == "schemathesis-ignored_auth"

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.template_id == "schemathesis-ignored_auth")
        )
    ).scalar_one()
    assert vulnerability.severity == "HIGH"
    assert vulnerability.confidence == "MEDIUM"
    assert vulnerability.type == "SCHEMATHESIS:ignored_auth"
    assert vulnerability.url == "https://api.example.com/admin/users?session=****"
    assert vulnerability.occurrence_count == 1
    assert vulnerability.evidence["engine"] == "schemathesis"
    assert "raw-token" not in str(vulnerability.evidence)
    assert "raw-session" not in str(vulnerability.evidence)


@pytest.mark.asyncio
async def test_schemathesis_report_import_merges_repeated_failures(client, db_session, auth_headers):
    body = {
        "target_url": "https://api.example.com",
        "junit_xml": _junit_report(failure_type="contract_repeat_case"),
    }

    first = await client.post("/api/pentest/schemathesis-report/import", headers=auth_headers, json=body)
    second = await client.post("/api/pentest/schemathesis-report/import", headers=auth_headers, json=body)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["vulnerabilities_created"] == 1
    assert second.json()["vulnerabilities_created"] == 0
    assert second.json()["vulnerabilities_merged"] == 1
    assert second.json()["vulnerabilities"][0]["occurrence_count"] == 2

    rows = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.template_id == "schemathesis-contract-repeat-case"
            )
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].occurrence_count == 2


@pytest.mark.asyncio
async def test_schemathesis_report_import_rejects_invalid_xml(client, auth_headers):
    response = await client.post(
        "/api/pentest/schemathesis-report/import",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "junit_xml": "<testsuite><broken>"},
    )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_schemathesis_report_import_blocks_out_of_scope_failure_url(
    client,
    db_session,
    auth_headers,
):
    junit_xml = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="schemathesis" tests="1" failures="1">
  <testcase classname="schemathesis" name="GET http://169.254.169.254/latest/meta-data">
    <failure type="metadata_report" message="metadata endpoint was reached">Authorization: Bearer raw-token</failure>
  </testcase>
</testsuite>
"""

    response = await client.post(
        "/api/pentest/schemathesis-report/import",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "junit_xml": junit_xml},
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "target_guard_blocked"
    assert "metadata" in message["message"]
    assert message["target_guard_policy"]["policy"] == "target_guard"
    assert message["target_guard_policy"]["blocked"] is True
    assert message["target_guard_policy"]["url"] == "http://169.254.169.254/latest/meta-data"
    assert "metadata" in message["target_guard_policy"]["reason"]

    vulnerabilities = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.template_id == "schemathesis-metadata-report"
            )
        )
    ).scalars().all()
    assert vulnerabilities == []


@pytest.mark.asyncio
async def test_schemathesis_profile_run_executes_and_imports_redacted_findings(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    db_session.add(
        OpenAPISpec(
            account_id=1000000,
            spec_json={
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.0.0"},
                "paths": {"/admin/users": {"post": {"responses": {"200": {"description": "ok"}}}}},
            },
        )
    )
    await db_session.commit()

    auth_profile_resp = await client.post(
        "/api/pentest/auth-profiles",
        headers=auth_headers,
        json={
            "name": "Schemathesis direct bearer",
            "auth_mode": "bearer",
            "token": "direct-token-123",
            "header_name": "Authorization",
            "openapi_security_scheme": "BearerAuth",
            "scope_domains": ["api.example.com"],
        },
    )
    assert auth_profile_resp.status_code == 200
    auth_profile_id = auth_profile_resp.json()["profile"]["id"]

    pentest_profile_resp = await client.post(
        "/api/pentest/profiles",
        headers=auth_headers,
        json={
            "name": "Schemathesis direct profile",
            "mode": "SAFE",
            "auth_profile_id": auth_profile_id,
            "request_timeout_seconds": 17,
            "schemathesis_enabled": True,
            "nuclei_enabled": False,
            "zap_enabled": False,
        },
    )
    assert pentest_profile_resp.status_code == 200
    pentest_profile_id = pentest_profile_resp.json()["profile"]["id"]
    state_change_policy = {
        "allow_state_change": False,
        "safe_methods": ["GET", "HEAD", "OPTIONS"],
        "input_operation_count": 2,
        "retained_operation_count": 1,
        "blocked_operation_count": 1,
        "blocked_operations": [{"method": "POST", "path": "/admin/users", "operation_id": "createAdminUser"}],
        "filtered": True,
    }

    async def fake_run_scan(**kwargs):
        assert kwargs["auth_profile"].token == "direct-token-123"
        assert kwargs["openapi_spec"]["paths"]
        assert kwargs["timeout_seconds"] == 17
        return {
            "status": "FAILED_WITH_FINDINGS",
            "exit_code": 1,
            "env_var_names": ["SCHEMATHESIS_TOKEN"],
            "stdout": "Authorization: Bearer direct-token-123",
            "stderr": "token=direct-token-123",
            "junit_xml": _junit_report(failure_type="direct_contract_case"),
            "failures": 1,
            "state_change_policy": state_change_policy,
            }

    monkeypatch.setattr(pentest_router._orchestrator.schemathesis, "is_available", lambda: True)
    monkeypatch.setattr(pentest_router._orchestrator.schemathesis, "run_scan", fake_run_scan)

    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/schemathesis/run",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "persist_findings": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "executed"
    assert payload["execution_id"]
    assert payload["execution"]["status"] == "FAILED_WITH_FINDINGS"
    assert payload["execution"]["failures"] == 1
    assert payload["execution"]["state_change_policy"] == state_change_policy
    assert payload["findings"]["created_count"] == 1
    assert payload["findings"]["failures_imported"] == 1
    assert "direct-token-123" not in str(payload)
    assert "raw-token" not in str(payload)
    assert "raw-session" not in str(payload)

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.template_id == "schemathesis-direct-contract-case"
            )
        )
    ).scalar_one()
    assert vulnerability.url == "https://api.example.com/admin/users?session=****"
    assert "raw-token" not in str(vulnerability.evidence)
    assert "raw-session" not in str(vulnerability.evidence)

    artifact = (
        await db_session.execute(
            select(PentestArtifact).where(
                PentestArtifact.pentest_profile_id == pentest_profile_id,
                PentestArtifact.artifact_type == "schemathesis_execution",
            )
        )
    ).scalar_one()
    assert artifact.filename == "schemathesis-execution.json"
    assert artifact.content_json["engine"] == "schemathesis"
    assert artifact.content_json["status"] == "FAILED_WITH_FINDINGS"
    assert artifact.content_json["openapi_spec_id"]
    assert artifact.content_json["findings"]["created_count"] == 1
    assert artifact.content_json["execution"]["state_change_policy"] == state_change_policy
    assert artifact.content_json["target_scope_validation"] == {
        "validated": True,
        "policy": "target_guard",
        "scope": "same_origin_or_allowlisted",
        "target": "https://api.example.com",
        "evidence_url": "https://api.example.com",
    }
    assert artifact.content_json["auth_context"]["authenticated"] is True
    assert artifact.content_json["auth_context"]["status"] == "ready"
    assert artifact.content_json["auth_context"]["reason"] == "auth_profile_ready"
    assert artifact.content_json["auth_context"]["auth_profile_id"] == auth_profile_id
    assert artifact.content_json["auth_context"]["has_runtime_credentials"] is True
    assert len(artifact.content_json["artifact_hash"]) == 64
    assert "direct-token-123" not in str(artifact.content_json)
    assert "raw-token" not in str(artifact.content_json)
    assert "raw-session" not in str(artifact.content_json)
    assert payload["artifact"]["id"] == artifact.id
    assert payload["artifact"]["artifact_type"] == "schemathesis_execution"
    assert payload["artifact"]["filename"] == "schemathesis-execution.json"
    assert payload["artifact"]["artifact_hash"] == artifact.content_json["artifact_hash"]
    assert payload["artifact"]["hash_algorithm"] == "sha256"
    assert payload["artifact"]["target_scope_validation"] == artifact.content_json["target_scope_validation"]
    assert payload["artifact"]["auth_context"] == artifact.content_json["auth_context"]
    assert payload["artifact"]["state_change_policy"] == state_change_policy
    assert payload["artifact"]["content_safety"]["content_redacted"] is True
    assert payload["artifact"]["content_safety"]["secret_values_persisted"] is False
    assert payload["artifact"]["integrity"]["verified"] is True
    assert payload["artifact"]["integrity"]["expected_hash"] == artifact.content_json["artifact_hash"]
    assert payload["artifact"]["integrity"]["actual_hash"] == artifact.content_json["artifact_hash"]

    audit_rows = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.resource_id == payload["execution_id"],
                models.AuditLog.action.in_(["PENTEST_ENGINE_RUN_STARTED", "PENTEST_ENGINE_RUN_COMPLETED"]),
            )
        )
    ).scalars().all()
    audit_by_action = {audit.action: audit for audit in audit_rows}
    assert audit_by_action["PENTEST_ENGINE_RUN_STARTED"].details["engine"] == "schemathesis"
    assert audit_by_action["PENTEST_ENGINE_RUN_STARTED"].details["timeout_seconds"] == 17
    started_auth_context = audit_by_action["PENTEST_ENGINE_RUN_STARTED"].details["auth_context"]
    assert started_auth_context["authenticated"] is True
    assert started_auth_context["status"] == "ready"
    assert started_auth_context["auth_profile_id"] == auth_profile_id
    completed_audit = audit_by_action["PENTEST_ENGINE_RUN_COMPLETED"]
    assert completed_audit.user_id == "test-user"
    assert completed_audit.details["artifact_id"] == artifact.id
    assert completed_audit.details["artifact_type"] == "schemathesis_execution"
    assert completed_audit.details["artifact_filename"] == "schemathesis-execution.json"
    assert completed_audit.details["artifact_hash"] == artifact.content_json["artifact_hash"]
    assert completed_audit.details["artifact_hash_algorithm"] == "sha256"
    assert completed_audit.details["artifact_target_scope_validation"] == artifact.content_json["target_scope_validation"]
    assert completed_audit.details["artifact_auth_context"] == artifact.content_json["auth_context"]
    assert completed_audit.details["artifact_state_change_policy"] == state_change_policy
    assert completed_audit.details["artifact_integrity"]["verified"] is True
    assert completed_audit.details["artifact_integrity"]["status"] == "VERIFIED"
    assert completed_audit.details["artifact_integrity"]["expected_hash"] == artifact.content_json["artifact_hash"]
    assert completed_audit.details["artifact_integrity"]["actual_hash"] == artifact.content_json["artifact_hash"]
    assert completed_audit.details["artifact_content_safety"]["content_redacted"] is True
    assert completed_audit.details["artifact_content_safety"]["sensitive_values_persisted"] is False
    assert completed_audit.details["timeout_seconds"] == 17
    assert completed_audit.details["findings_created"] == 1
    assert completed_audit.details["failures_imported"] == 1
    assert "direct-token-123" not in str([audit.details for audit in audit_rows])


@pytest.mark.asyncio
async def test_schemathesis_profile_run_rejects_when_kill_switch_enabled(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    async def unexpected_run_scan(**_kwargs):
        pytest.fail("Schemathesis runner must not be called when the pentest kill switch is enabled")

    db_session.add(
        OpenAPISpec(
            account_id=1000000,
            spec_json={
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.0.0"},
                "paths": {"/users": {"get": {"responses": {"200": {"description": "ok"}}}}},
            },
        )
    )
    await db_session.commit()

    auth_profile_resp = await client.post(
        "/api/pentest/auth-profiles",
        headers=auth_headers,
        json={
            "name": "Schemathesis kill switch bearer",
            "auth_mode": "bearer",
            "token": "direct-token-123",
            "header_name": "Authorization",
            "scope_domains": ["api.example.com"],
        },
    )
    assert auth_profile_resp.status_code == 200
    auth_profile_id = auth_profile_resp.json()["profile"]["id"]

    pentest_profile_resp = await client.post(
        "/api/pentest/profiles",
        headers=auth_headers,
        json={
            "name": "Schemathesis kill switch profile",
            "mode": "SAFE",
            "auth_profile_id": auth_profile_id,
            "schemathesis_enabled": True,
            "nuclei_enabled": False,
            "zap_enabled": False,
        },
    )
    assert pentest_profile_resp.status_code == 200
    pentest_profile_id = pentest_profile_resp.json()["profile"]["id"]

    monkeypatch.setattr("server.modules.test_executor.kill_switch.settings.PENTEST_KILL_SWITCH_ENABLED", True)
    monkeypatch.setattr(pentest_router._orchestrator.schemathesis, "run_scan", unexpected_run_scan)

    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/schemathesis/run",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "persist_findings": True},
    )

    assert response.status_code == 503
    assert response.json()["message"] == "pentest_kill_switch_enabled"
    audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.action == "PENTEST_ENGINE_RUN_BLOCKED",
                models.AuditLog.resource_id == pentest_profile_id,
            )
        )
    ).scalar_one()
    assert audit.details["engine"] == "schemathesis"
    assert audit.details["reason"] == "pentest_kill_switch_enabled"
    assert audit.details["auth_context"]["authenticated"] is True
    assert audit.details["auth_context"]["auth_profile_id"] == auth_profile_id
    assert "direct-token-123" not in str(audit.details)
    artifacts = (
        await db_session.execute(
            select(PentestArtifact).where(
                PentestArtifact.pentest_profile_id == pentest_profile_id,
                PentestArtifact.artifact_type == "schemathesis_execution",
            )
        )
    ).scalars().all()
    assert artifacts == []


@pytest.mark.asyncio
async def test_schemathesis_profile_run_audits_runtime_unavailable_plan(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    async def unexpected_run_scan(**_kwargs):
        pytest.fail("Schemathesis runner must not be called when runtime is unavailable")

    db_session.add(
        OpenAPISpec(
            account_id=1000000,
            spec_json={
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.0.0"},
                "paths": {"/users": {"get": {"responses": {"200": {"description": "ok"}}}}},
            },
        )
    )
    await db_session.commit()

    auth_profile_resp = await client.post(
        "/api/pentest/auth-profiles",
        headers=auth_headers,
        json={
            "name": "Schemathesis runtime bearer",
            "auth_mode": "bearer",
            "token": "direct-token-123",
            "header_name": "Authorization",
            "scope_domains": ["api.example.com"],
        },
    )
    assert auth_profile_resp.status_code == 200
    auth_profile_id = auth_profile_resp.json()["profile"]["id"]

    pentest_profile_resp = await client.post(
        "/api/pentest/profiles",
        headers=auth_headers,
        json={
            "name": "Schemathesis runtime profile",
            "mode": "SAFE",
            "auth_profile_id": auth_profile_id,
            "schemathesis_enabled": True,
            "nuclei_enabled": False,
            "zap_enabled": False,
        },
    )
    assert pentest_profile_resp.status_code == 200
    pentest_profile_id = pentest_profile_resp.json()["profile"]["id"]

    monkeypatch.setattr(pentest_router._orchestrator.schemathesis, "is_available", lambda: False)
    monkeypatch.setattr(pentest_router._orchestrator.schemathesis, "run_scan", unexpected_run_scan)

    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/schemathesis/run",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "persist_findings": True},
    )

    assert response.status_code == 400
    assert response.json()["message"]["reason"] == "engine_runtime_unavailable"
    audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.action == "PENTEST_ENGINE_RUN_BLOCKED",
                models.AuditLog.resource_id == pentest_profile_id,
            )
        )
    ).scalar_one()
    assert audit.details["engine"] == "schemathesis"
    assert audit.details["reason"] == "engine_runtime_unavailable"
    assert audit.details["auth_context"]["authenticated"] is True
    assert audit.details["auth_context"]["auth_profile_id"] == auth_profile_id
    assert audit.details["engine_plan_entry"]["engine"] == "schemathesis"
    assert audit.details["engine_plan_entry"]["status"] == "blocked"
    assert audit.details["engine_plan_entry"]["reason"] == "engine_runtime_unavailable"
    assert audit.details["engine_plan_entry"]["runtime_available"] is False
    assert audit.details["engine_plan_entry"]["artifact_type"] is None
    assert "direct-token-123" not in str(audit.details)
    artifacts = (
        await db_session.execute(
            select(PentestArtifact).where(
                PentestArtifact.pentest_profile_id == pentest_profile_id,
                PentestArtifact.artifact_type == "schemathesis_execution",
            )
        )
    ).scalars().all()
    assert artifacts == []


@pytest.mark.asyncio
async def test_schemathesis_profile_run_blocks_target_before_start_audit(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    async def unexpected_run_scan(**_kwargs):
        pytest.fail("Schemathesis runner must not be called for a target-guard-blocked URL")

    db_session.add(
        OpenAPISpec(
            account_id=1000000,
            spec_json={
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.0.0"},
                "paths": {"/users": {"get": {"responses": {"200": {"description": "ok"}}}}},
            },
        )
    )
    await db_session.commit()

    auth_profile_resp = await client.post(
        "/api/pentest/auth-profiles",
        headers=auth_headers,
        json={
            "name": "Schemathesis target guard bearer",
            "auth_mode": "bearer",
            "token": "direct-token-123",
            "header_name": "Authorization",
            "scope_domains": ["api.example.com"],
        },
    )
    assert auth_profile_resp.status_code == 200
    auth_profile_id = auth_profile_resp.json()["profile"]["id"]

    pentest_profile_resp = await client.post(
        "/api/pentest/profiles",
        headers=auth_headers,
        json={
            "name": "Schemathesis target guard profile",
            "mode": "SAFE",
            "auth_profile_id": auth_profile_id,
            "schemathesis_enabled": True,
            "nuclei_enabled": False,
            "zap_enabled": False,
        },
    )
    assert pentest_profile_resp.status_code == 200
    pentest_profile_id = pentest_profile_resp.json()["profile"]["id"]

    monkeypatch.setattr(pentest_router._orchestrator.schemathesis, "run_scan", unexpected_run_scan)
    monkeypatch.setattr(pentest_router._orchestrator.schemathesis, "is_available", lambda: False)

    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/schemathesis/run",
        headers=auth_headers,
        json={"target_url": "http://169.254.169.254/latest/meta-data", "persist_findings": True},
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "target_guard_blocked"
    assert "metadata" in message["message"]

    audit_rows = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.resource_type == "pentest_engine_run",
                models.AuditLog.action.in_(["PENTEST_ENGINE_RUN_BLOCKED", "PENTEST_ENGINE_RUN_STARTED"]),
            )
        )
    ).scalars().all()
    matching = [
        audit for audit in audit_rows
        if (audit.details or {}).get("pentest_profile_id") == pentest_profile_id
    ]
    assert [audit.action for audit in matching] == ["PENTEST_ENGINE_RUN_BLOCKED"]
    assert matching[0].details["engine"] == "schemathesis"
    assert matching[0].details["reason"] == "target_guard_blocked"
    assert matching[0].details["target_guard_policy"]["policy"] == "target_guard"
    assert matching[0].details["target_guard_policy"]["blocked"] is True
    assert matching[0].details["target_guard_policy"]["url"] == "http://169.254.169.254/latest/meta-data"
    assert matching[0].details["auth_context"]["authenticated"] is True
    assert matching[0].details["auth_context"]["auth_profile_id"] == auth_profile_id
    assert "direct-token-123" not in str(matching[0].details)

    artifacts = (
        await db_session.execute(
            select(PentestArtifact).where(
                PentestArtifact.pentest_profile_id == pentest_profile_id,
                PentestArtifact.artifact_type == "schemathesis_execution",
            )
        )
    ).scalars().all()
    assert artifacts == []


@pytest.mark.asyncio
async def test_schemathesis_profile_run_records_redacted_failure_when_runner_crashes(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    db_session.add(
        OpenAPISpec(
            account_id=1000000,
            spec_json={
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.0.0"},
                "paths": {"/users": {"get": {"responses": {"200": {"description": "ok"}}}}},
            },
        )
    )
    await db_session.commit()

    auth_profile_resp = await client.post(
        "/api/pentest/auth-profiles",
        headers=auth_headers,
        json={
            "name": "Schemathesis failure bearer",
            "auth_mode": "bearer",
            "token": "direct-token-123",
            "header_name": "Authorization",
            "scope_domains": ["api.example.com"],
        },
    )
    assert auth_profile_resp.status_code == 200
    auth_profile_id = auth_profile_resp.json()["profile"]["id"]

    pentest_profile_resp = await client.post(
        "/api/pentest/profiles",
        headers=auth_headers,
        json={
            "name": "Schemathesis failure profile",
            "mode": "SAFE",
            "auth_profile_id": auth_profile_id,
            "schemathesis_enabled": True,
            "nuclei_enabled": False,
            "zap_enabled": False,
        },
    )
    assert pentest_profile_resp.status_code == 200
    pentest_profile_id = pentest_profile_resp.json()["profile"]["id"]

    async def failing_run_scan(**_kwargs):
        raise RuntimeError("schemathesis crashed with Authorization: Bearer direct-token-123")

    monkeypatch.setattr(pentest_router._orchestrator.schemathesis, "is_available", lambda: True)
    monkeypatch.setattr(pentest_router._orchestrator.schemathesis, "run_scan", failing_run_scan)

    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/schemathesis/run",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "persist_findings": True},
    )

    assert response.status_code == 502
    assert response.json()["message"]["reason"] == "external_engine_execution_failed"
    assert "direct-token-123" not in response.text

    audit_rows = (
        await db_session.execute(
            select(models.AuditLog).where(models.AuditLog.action == "PENTEST_ENGINE_RUN_FAILED")
        )
    ).scalars().all()
    failed_audit = next(
        audit for audit in audit_rows
        if audit.details["engine"] == "schemathesis"
        and audit.details["pentest_profile_id"] == pentest_profile_id
    )
    assert failed_audit.details["reason"] == "external_engine_execution_failed"
    assert failed_audit.details["error_type"] == "RuntimeError"
    assert failed_audit.details["auth_context"]["authenticated"] is True
    assert failed_audit.details["auth_context"]["auth_profile_id"] == auth_profile_id
    assert "direct-token-123" not in str(failed_audit.details)

    artifacts = (
        await db_session.execute(
            select(PentestArtifact).where(
                PentestArtifact.pentest_profile_id == pentest_profile_id,
                PentestArtifact.artifact_type == "schemathesis_execution",
            )
        )
    ).scalars().all()
    assert artifacts == []
