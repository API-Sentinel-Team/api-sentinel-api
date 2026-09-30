import pytest
from sqlalchemy import select

from sentinel_core.config import settings
from sentinel_core.models import core as models
from sentinel_core.models.core import OpenAPISpec, PentestArtifact
from sentinel_worker.modules.test_executor import scan_worker as worker
from sentinel_core.modules.test_executor.scan_plan import finalize_scan_plan_hash


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



async def _create_schemathesis_auth_and_profile(
    client,
    auth_headers,
    *,
    auth_name: str,
    profile_name: str,
    request_timeout_seconds: int | None = None,
):
    auth_body = {
        "name": auth_name,
        "auth_mode": "bearer",
        "token": "direct-token-123",
        "header_name": "Authorization",
        "openapi_security_scheme": "BearerAuth",
        "scope_domains": ["api.example.com"],
    }
    auth_profile_resp = await client.post(
        "/api/pentest/auth-profiles", headers=auth_headers, json=auth_body
    )
    assert auth_profile_resp.status_code == 200
    auth_profile_id = auth_profile_resp.json()["profile"]["id"]

    profile_body = {
        "name": profile_name,
        "mode": "SAFE",
        "auth_profile_id": auth_profile_id,
        "schemathesis_enabled": True,
        "nuclei_enabled": False,
        "zap_enabled": False,
    }
    if request_timeout_seconds is not None:
        profile_body["request_timeout_seconds"] = request_timeout_seconds
    pentest_profile_resp = await client.post(
        "/api/pentest/profiles", headers=auth_headers, json=profile_body
    )
    assert pentest_profile_resp.status_code == 200
    pentest_profile_id = pentest_profile_resp.json()["profile"]["id"]
    return auth_profile_id, pentest_profile_id


@pytest.mark.asyncio
async def test_schemathesis_profile_run_executes_and_imports_redacted_findings(
    client,
    db_session,
    test_engine,
    auth_headers,
    monkeypatch,
):
    # The API now only validates and QUEUES; the scan-worker executes. This test drives
    # the two-phase flow: POST queues a PENDING run, then the worker external-engine
    # phase runs the (faked) engine, imports findings, and writes the redacted artifact.
    db_session.add(
        OpenAPISpec(
            account_id=1000000,
            spec_json={
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.0.0"},
                "paths": {
                    "/": {"get": {"responses": {"200": {"description": "ok"}}}},
                    "/admin/users": {"post": {"responses": {"200": {"description": "ok"}}}},
                },
            },
        )
    )
    # The queued worker resolves endpoint_ids from inventory; the target must be present.
    db_session.add(
        models.APIEndpoint(
            account_id=1000000,
            protocol="https",
            host="api.example.com",
            path="/",
            method="GET",
        )
    )
    await db_session.commit()

    auth_profile_id, pentest_profile_id = await _create_schemathesis_auth_and_profile(
        client,
        auth_headers,
        auth_name="Schemathesis direct bearer",
        profile_name="Schemathesis direct profile",
        request_timeout_seconds=17,
    )
    state_change_policy = {
        "allow_state_change": False,
        "safe_methods": ["GET", "HEAD", "OPTIONS"],
        "input_operation_count": 2,
        "retained_operation_count": 1,
        "blocked_operation_count": 1,
        "blocked_operations": [{"method": "POST", "path": "/admin/users", "operation_id": "createAdminUser"}],
        "filtered": True,
    }

    async def fake_run_scan(*_args, **kwargs):
        # The worker invokes SchemathesisRunner().run_scan with the resolved auth profile,
        # the scoped OpenAPI spec, and the engine timeout owned by the worker.
        assert kwargs["auth_profile"].token == "direct-token-123"
        assert kwargs["openapi_spec"]["paths"]
        assert kwargs["timeout_seconds"] == settings.PENTEST_SCHEMATHESIS_TIMEOUT_SECONDS
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

    # Patch the runner ON THE WORKER MODULE (the API no longer executes the engine).
    monkeypatch.setattr(worker.SchemathesisRunner, "run_scan", fake_run_scan)

    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/schemathesis/run",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "persist_findings": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "scan_queued"
    assert payload["engine"] == "schemathesis"
    assert payload["execution_mode"] == "queued"
    assert payload["run_id"]
    assert payload["pentest_profile_id"] == pentest_profile_id
    run_id = payload["run_id"]
    assert "direct-token-123" not in str(payload)

    # Persist the queued run + audit so the worker (separate sessions) can claim it,
    # and assert the API queued a PENDING TestRun without executing anything.
    await db_session.commit()
    queued_run = (
        await db_session.execute(select(models.TestRun).where(models.TestRun.id == run_id))
    ).scalar_one()
    assert queued_run.status == "PENDING"
    assert queued_run.pentest_profile_id == pentest_profile_id

    no_artifact_yet = (
        await db_session.execute(
            select(PentestArtifact).where(
                PentestArtifact.pentest_profile_id == pentest_profile_id,
                PentestArtifact.artifact_type == "schemathesis_execution",
            )
        )
    ).scalars().all()
    assert no_artifact_yet == []

    # Phase 2: the worker claims and executes the queued external-engine run.
    claimed = await worker.claim_next_pending_run(
        db_bind=test_engine, account_id=1000000, worker_id="test-worker"
    )
    assert claimed is not None
    assert claimed.run_id == run_id
    result = await worker._execute_planned_external_engines(
        claimed, db_bind=test_engine, worker_isolation_context=None
    )
    assert result["status"] == "completed"
    assert result["engine_count"] == 1
    assert result["engines"][0]["status"] == "FAILED_WITH_FINDINGS"
    assert "direct-token-123" not in str(result)
    assert "raw-token" not in str(result)
    assert "raw-session" not in str(result)

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.template_id == "schemathesis-direct-contract-case"
            )
        )
    ).scalar_one()
    assert vulnerability.url == "https://api.example.com/admin/users?session=****"
    assert vulnerability.evidence["engine"] == "schemathesis"
    assert "direct-token-123" not in str(vulnerability.evidence)
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
    assert artifact.run_id == run_id
    content = artifact.content_json
    assert content["engine"] == "schemathesis"
    assert content["status"] == "FAILED_WITH_FINDINGS"
    assert content["openapi_spec_id"]
    assert content["findings"]["created_count"] == 1
    assert content["findings"]["failures_imported"] == 1
    assert content["execution"]["state_change_policy"] == state_change_policy
    assert content["target_scope_validation"]["validated"] is True
    assert content["target_scope_validation"]["policy"] == "target_guard"
    assert content["target_scope_validation"]["target"] == "https://api.example.com"
    assert content["auth_context"]["authenticated"] is True
    assert content["auth_context"]["status"] == "ready"
    assert content["auth_context"]["reason"] == "auth_profile_ready"
    assert content["auth_context"]["auth_profile_id"] == auth_profile_id
    assert content["auth_context"]["has_runtime_credentials"] is True
    assert len(content["artifact_hash"]) == 64
    assert content["content_redacted"] is True
    assert content["secret_values_persisted"] is False
    assert content["artifact_verification"]["verified"] is True
    assert "direct-token-123" not in str(content)
    assert "raw-token" not in str(content)
    assert "raw-session" not in str(content)

    # The API-side audit that now occurs is PENTEST_ENGINE_RUN_QUEUED (no STARTED/COMPLETED,
    # since the API no longer executes the engine).
    queued_audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.action == "PENTEST_ENGINE_RUN_QUEUED",
                models.AuditLog.resource_id == run_id,
            )
        )
    ).scalar_one()
    assert queued_audit.details["engine"] == "schemathesis"
    assert queued_audit.details["execution_mode"] == "queued"
    assert "direct-token-123" not in str(queued_audit.details)


@pytest.mark.asyncio
async def test_schemathesis_profile_run_rejects_when_kill_switch_enabled(
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

    auth_profile_id, pentest_profile_id = await _create_schemathesis_auth_and_profile(
        client,
        auth_headers,
        auth_name="Schemathesis kill switch bearer",
        profile_name="Schemathesis kill switch profile",
    )

    # The kill-switch guard rejects and audits BEFORE any run is queued or executed.
    monkeypatch.setattr("sentinel_core.modules.test_executor.kill_switch.settings.PENTEST_KILL_SWITCH_ENABLED", True)

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

    # No run queued and no execution artifact written.
    runs = (
        await db_session.execute(
            select(models.TestRun).where(models.TestRun.pentest_profile_id == pentest_profile_id)
        )
    ).scalars().all()
    assert runs == []
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
async def test_schemathesis_profile_run_worker_finalizes_failed_when_engine_cannot_run(
    client,
    db_session,
    test_engine,
    auth_headers,
    monkeypatch,
):
    # OBSOLETE premise: the API no longer checks its own engine runtime. Rewritten as a
    # worker test: a queued run whose worker cannot run the engine (its bound endpoints
    # are gone) is finalized FAILED with a redacted reason and NO execution artifact.
    db_session.add(
        OpenAPISpec(
            account_id=1000000,
            spec_json={
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.0.0"},
                "paths": {"/": {"get": {"responses": {"200": {"description": "ok"}}}}},
            },
        )
    )
    await db_session.commit()

    auth_profile_id, pentest_profile_id = await _create_schemathesis_auth_and_profile(
        client,
        auth_headers,
        auth_name="Schemathesis runtime bearer",
        profile_name="Schemathesis runtime profile",
    )

    # The runner must never be reached: the worker fails before executing any engine.
    async def unexpected_run_scan(*_args, **_kwargs):
        pytest.fail("Schemathesis runner must not run when the worker cannot bind its targets")

    monkeypatch.setattr(worker.SchemathesisRunner, "run_scan", unexpected_run_scan)

    profile = (
        await db_session.execute(
            select(models.PentestProfile).where(models.PentestProfile.id == pentest_profile_id)
        )
    ).scalar_one()
    spec = (
        await db_session.execute(
            select(OpenAPISpec).where(OpenAPISpec.account_id == 1000000)
        )
    ).scalars().first()
    # Mirror the queued external-engine plan shape, but bind endpoint ids that do not
    # exist in inventory so the worker cannot resolve/verify its targets.
    scan_plan = finalize_scan_plan_hash(
        {
            "engine_plan": [{"engine": "schemathesis", "status": "ready"}],
            "external_engine_scope": {
                "target_url": "https://api.example.com",
                "openapi_spec_id": spec.id,
                "openapi_spec_sha256": worker.worker_spec_digest(spec.spec_json),
            },
        }
    )
    run = models.TestRun(
        account_id=1000000,
        status="PENDING",
        template_ids=[],
        endpoint_ids=["missing-endpoint-id"],
        pentest_profile_id=profile.id,
        trigger_source="manual",
        scan_plan=scan_plan,
    )
    db_session.add(run)
    await db_session.commit()
    run_id = run.id

    result = await worker.run_pending_scan_once(
        db_bind=test_engine, account_id=1000000, worker_id="test-worker"
    )
    assert result["claimed"] is True
    assert result["status"] == "failed"
    assert "direct-token-123" not in str(result)

    # The worker finalized the run in its own session/transaction; drop db_session's
    # cached copy so the assertions read the committed state.
    db_session.expire_all()
    finalized_run = (
        await db_session.execute(select(models.TestRun).where(models.TestRun.id == run_id))
    ).scalar_one()
    assert finalized_run.status == "FAILED"

    failed_audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.action == "SCAN_RUN_FAILED",
                models.AuditLog.resource_id == run_id,
            )
        )
    ).scalar_one()
    assert failed_audit.details["reason"]
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


@pytest.mark.asyncio
async def test_schemathesis_profile_run_blocks_target_before_start_audit(
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

    auth_profile_id, pentest_profile_id = await _create_schemathesis_auth_and_profile(
        client,
        auth_headers,
        auth_name="Schemathesis target guard bearer",
        profile_name="Schemathesis target guard profile",
    )

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
                models.AuditLog.action.in_(["PENTEST_ENGINE_RUN_BLOCKED", "PENTEST_ENGINE_RUN_QUEUED"]),
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

    # No run queued and no execution artifact written for a blocked target.
    runs = (
        await db_session.execute(
            select(models.TestRun).where(models.TestRun.pentest_profile_id == pentest_profile_id)
        )
    ).scalars().all()
    assert runs == []
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
    test_engine,
    auth_headers,
    monkeypatch,
):
    # The engine executes in the worker now: when its runner raises (with a secret in the
    # message), the worker finalizes the run FAILED with a REDACTED reason and never
    # persists the secret in the artifact/audit.
    db_session.add(
        OpenAPISpec(
            account_id=1000000,
            spec_json={
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.0.0"},
                "paths": {"/": {"get": {"responses": {"200": {"description": "ok"}}}}},
            },
        )
    )
    db_session.add(
        models.APIEndpoint(
            account_id=1000000,
            protocol="https",
            host="api.example.com",
            path="/",
            method="GET",
        )
    )
    await db_session.commit()

    auth_profile_id, pentest_profile_id = await _create_schemathesis_auth_and_profile(
        client,
        auth_headers,
        auth_name="Schemathesis failure bearer",
        profile_name="Schemathesis failure profile",
    )

    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/schemathesis/run",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "persist_findings": True},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "scan_queued"
    run_id = payload["run_id"]
    await db_session.commit()

    async def failing_run_scan(*_args, **_kwargs):
        raise RuntimeError("schemathesis crashed with Authorization: Bearer direct-token-123")

    monkeypatch.setattr(worker.SchemathesisRunner, "run_scan", failing_run_scan)

    result = await worker.run_pending_scan_once(
        db_bind=test_engine, account_id=1000000, worker_id="test-worker"
    )
    assert result["claimed"] is True
    assert result["status"] == "failed"
    assert "direct-token-123" not in str(result)

    # The worker finalized the run in its own session/transaction; drop db_session's
    # cached copy so the assertions read the committed state.
    db_session.expire_all()
    finalized_run = (
        await db_session.execute(select(models.TestRun).where(models.TestRun.id == run_id))
    ).scalar_one()
    assert finalized_run.status == "FAILED"

    failed_audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.action == "SCAN_RUN_FAILED",
                models.AuditLog.resource_id == run_id,
            )
        )
    ).scalar_one()
    assert failed_audit.details["reason"]
    assert "direct-token-123" not in str(failed_audit.details)

    # The runner crash must never leak the secret into any persisted artifact.
    artifacts = (
        await db_session.execute(
            select(PentestArtifact).where(PentestArtifact.run_id == run_id)
        )
    ).scalars().all()
    for artifact in artifacts:
        assert "direct-token-123" not in str(artifact.content_json)
