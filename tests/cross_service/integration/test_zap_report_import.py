import pytest
from unittest.mock import AsyncMock
from sqlalchemy import select

from server.api.routers import pentest as pentest_router
from sentinel_core.models import core as models
from sentinel_core.models.core import APIEndpoint, OpenAPISpec, PentestArtifact
from sentinel_worker.modules.test_executor import scan_worker as worker


def _zap_report(template_id: str = "40012") -> dict:
    return {
        "site": [
            {
                "@name": "https://api.example.com",
                "alerts": [
                    {
                        "pluginid": template_id,
                        "alert": "Cross Site Scripting",
                        "riskdesc": "High (Medium)",
                        "confidence": "High",
                        "desc": "Reflected input was observed in the response",
                        "solution": "Encode output and validate input",
                        "instances": [
                            {
                                "uri": "https://api.example.com/search?q=<script>&session=raw-session",
                                "method": "GET",
                                "param": "q",
                                "attack": "<script>alert(1)</script>",
                                "evidence": "Bearer raw-token",
                            }
                        ],
                    }
                ],
            }
        ]
    }


@pytest.mark.asyncio
async def test_zap_report_import_promotes_alert_to_vulnerability(client, db_session, auth_headers):
    response = await client.post(
        "/api/openapi/zap-report/import",
        headers=auth_headers,
        json={
            "target_url": "https://api.example.com",
            "report": _zap_report(),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "imported"
    assert payload["alerts_imported"] == 1
    assert payload["vulnerabilities_created"] == 1
    assert payload["vulnerabilities_merged"] == 0
    assert payload["vulnerabilities"][0]["template_id"] == "zap-40012"

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.template_id == "zap-40012")
        )
    ).scalar_one()
    assert vulnerability.severity == "HIGH"
    assert vulnerability.confidence == "HIGH"
    assert vulnerability.type == "ZAP:40012"
    assert vulnerability.occurrence_count == 1
    assert vulnerability.evidence["engine"] == "zap"
    assert "raw-token" not in str(vulnerability.evidence)
    assert "raw-session" not in str(vulnerability.evidence)


@pytest.mark.asyncio
async def test_zap_report_import_merges_repeated_alert(client, db_session, auth_headers):
    body = {
        "target_url": "https://api.example.com",
        "report": _zap_report(template_id="90001"),
    }

    first = await client.post("/api/openapi/zap-report/import", headers=auth_headers, json=body)
    second = await client.post("/api/openapi/zap-report/import", headers=auth_headers, json=body)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["vulnerabilities_created"] == 1
    assert second.json()["vulnerabilities_created"] == 0
    assert second.json()["vulnerabilities_merged"] == 1
    assert second.json()["vulnerabilities"][0]["occurrence_count"] == 2

    rows = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.template_id == "zap-90001")
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].occurrence_count == 2


@pytest.mark.asyncio
async def test_zap_report_import_rejects_empty_report(client, auth_headers):
    response = await client.post(
        "/api/openapi/zap-report/import",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "report": {}},
    )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_zap_report_import_blocks_out_of_scope_evidence(client, db_session, auth_headers):
    report = _zap_report(template_id="metadata-report")
    report["site"][0]["alerts"][0]["instances"][0]["uri"] = "http://169.254.169.254/latest/meta-data"

    response = await client.post(
        "/api/openapi/zap-report/import",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "report": report},
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "target_guard_blocked"
    assert "metadata" in message["message"]

    vulnerabilities = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.template_id == "zap-metadata-report")
        )
    ).scalars().all()
    assert vulnerabilities == []



# ---------------------------------------------------------------------------
# Engine-run tests under the API-queues / worker-executes contract.
#
# The API route POST /api/pentest/profiles/{id}/zap/run now only validates,
# runs guards, and QUEUES a PENDING TestRun (audit PENTEST_ENGINE_RUN_QUEUED /
# PENTEST_ENGINE_RUN_BLOCKED). It no longer runs ZAP, imports findings, or
# writes a zap_execution artifact inside the request. The scan-worker executes
# the queued run; ZapRunner is patched ON THE WORKER MODULE, and the same
# Vulnerability rows / zap_execution PentestArtifact appear after the worker
# runs. All secret-redaction assertions are made against the worker-produced
# artifact/vuln (and the queued API response/audit).
# ---------------------------------------------------------------------------

_WORKER_SCOPED_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Demo API", "version": "1.0.0"},
    # Path "/" so the worker's scoped spec (target has no path, inventory
    # endpoint path "/") retains a selected operation for ZAP.
    "paths": {"/": {"get": {"responses": {"200": {"description": "ok"}}}}},
}


async def _seed_zap_target(db_session):
    """Persist the OpenAPI spec + inventory endpoint the queued route binds to."""
    db_session.add(OpenAPISpec(account_id=1000000, spec_json=dict(_WORKER_SCOPED_SPEC)))
    db_session.add(
        APIEndpoint(
            account_id=1000000,
            protocol="https",
            host="api.example.com",
            path="/",
            method="GET",
        )
    )
    await db_session.commit()


async def _create_zap_profile(client, auth_headers, *, auth_name, profile_name, extra_profile=None):
    auth_profile_resp = await client.post(
        "/api/pentest/auth-profiles",
        headers=auth_headers,
        json={
            "name": auth_name,
            "auth_mode": "bearer",
            "token": "direct-token-123",
            "header_name": "Authorization",
            "scope_domains": ["api.example.com"],
        },
    )
    assert auth_profile_resp.status_code == 200
    auth_profile_id = auth_profile_resp.json()["profile"]["id"]

    profile_body = {
        "name": profile_name,
        "mode": "SAFE",
        "auth_profile_id": auth_profile_id,
        "schemathesis_enabled": False,
        "nuclei_enabled": False,
        "zap_enabled": True,
    }
    if extra_profile:
        profile_body.update(extra_profile)
    pentest_profile_resp = await client.post(
        "/api/pentest/profiles",
        headers=auth_headers,
        json=profile_body,
    )
    assert pentest_profile_resp.status_code == 200
    pentest_profile_id = pentest_profile_resp.json()["profile"]["id"]
    return auth_profile_id, pentest_profile_id


@pytest.mark.asyncio
async def test_zap_profile_run_executes_and_imports_redacted_findings(
    client,
    db_session,
    auth_headers,
    test_engine,
    monkeypatch,
):
    await _seed_zap_target(db_session)
    auth_profile_id, pentest_profile_id = await _create_zap_profile(
        client,
        auth_headers,
        auth_name="ZAP direct bearer",
        profile_name="ZAP direct profile",
        extra_profile={"request_timeout_seconds": 19},
    )

    state_change_policy = {
        "allow_state_change": False,
        "safe_methods": ["GET", "HEAD", "OPTIONS"],
        "input_operation_count": 2,
        "retained_operation_count": 1,
        "blocked_operation_count": 1,
        "blocked_operations": [{"method": "DELETE", "path": "/search/{id}", "operation_id": "deleteSearch"}],
        "filtered": True,
    }

    async def fake_run_scan(**kwargs):
        # The worker resolves and passes the profile's decrypted auth + the
        # scoped OpenAPI spec down to the runner.
        assert kwargs["auth_profile"].token == "direct-token-123"
        assert kwargs["openapi_spec"]["paths"]
        report = _zap_report(template_id="direct-zap-case")
        report["site"][0]["alerts"][0]["instances"][0]["evidence"] = "Authorization: Bearer direct-token-123"
        report["site"][0]["alerts"][0]["instances"][0]["uri"] = (
            "https://api.example.com/search?q=x&session=raw-session-123"
        )
        return {
            "status": "FAILED_WITH_FINDINGS",
            "exit_code": 1,
            "env_var_names": ["ZAP_AUTH_HEADER_VALUE"],
            "stdout": "Authorization: Bearer direct-token-123",
            "stderr": "token=direct-token-123",
            "report": report,
            "alerts": 1,
            "state_change_policy": state_change_policy,
        }

    # Patch the runner ON THE WORKER MODULE (the worker owns execution now).
    monkeypatch.setattr(worker.ZapRunner, "run_scan", AsyncMock(side_effect=fake_run_scan))

    # Phase 1: the API only validates and QUEUES the run.
    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/zap/run",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "persist_findings": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "scan_queued"
    run_id = payload["run_id"]
    assert run_id
    assert payload["engine"] == "zap"
    assert payload["execution_mode"] == "queued"
    assert payload["pentest_profile_id"] == pentest_profile_id
    assert payload["scan_plan_hash"]
    assert "direct-token-123" not in str(payload)
    assert "raw-session-123" not in str(payload)

    # Commit the queued run so the worker (its own session on this engine) sees it.
    await db_session.commit()

    queued_run = (
        await db_session.execute(select(models.TestRun).where(models.TestRun.id == run_id))
    ).scalar_one()
    assert queued_run.status == "PENDING"
    assert queued_run.pentest_profile_id == pentest_profile_id

    # The API wrote no zap_execution artifact and imported no findings in-request.
    pre_worker_artifacts = (
        await db_session.execute(
            select(PentestArtifact).where(
                PentestArtifact.pentest_profile_id == pentest_profile_id,
                PentestArtifact.artifact_type == "zap_execution",
            )
        )
    ).scalars().all()
    assert pre_worker_artifacts == []

    # Phase 2: the worker claims and executes the queued run.
    claimed = await worker.claim_next_pending_run(
        db_bind=test_engine, account_id=1000000, worker_id="w"
    )
    assert claimed is not None
    assert claimed.run_id == run_id
    result = await worker._execute_planned_external_engines(
        claimed, db_bind=test_engine, worker_isolation_context=None
    )
    assert result["status"] == "completed"
    assert result["engine_count"] == 1
    assert result["engines"][0]["engine"] == "zap"
    assert result["engines"][0]["status"] == "FAILED_WITH_FINDINGS"
    assert result["finding_summary"]["created_count"] == 1
    assert "direct-token-123" not in str(result)
    assert "raw-session-123" not in str(result)

    # The worker imported the redacted finding as a Vulnerability.
    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.template_id == "zap-direct-zap-case")
        )
    ).scalar_one()
    assert vulnerability.severity == "HIGH"
    assert vulnerability.confidence == "HIGH"
    assert vulnerability.type == "ZAP:direct-zap-case"
    assert vulnerability.occurrence_count == 1
    assert vulnerability.evidence["engine"] == "zap"
    assert vulnerability.url == "https://api.example.com/search?q=****&session=****"
    assert "direct-token-123" not in str(vulnerability.evidence)
    assert "raw-session-123" not in str(vulnerability.evidence)

    # The worker wrote the redacted zap_execution artifact.
    artifact = (
        await db_session.execute(
            select(PentestArtifact).where(
                PentestArtifact.pentest_profile_id == pentest_profile_id,
                PentestArtifact.artifact_type == "zap_execution",
            )
        )
    ).scalar_one()
    assert artifact.filename == "zap-execution.json"
    assert artifact.run_id == run_id
    content = artifact.content_json
    assert content["engine"] == "zap"
    assert content["status"] == "FAILED_WITH_FINDINGS"
    assert content["openapi_spec_id"]
    assert content["findings"]["created_count"] == 1
    assert content["findings"]["imported_alert_instances"] == 1
    assert content["execution"]["state_change_policy"] == state_change_policy
    assert content["target_scope_validation"] == {
        "validated": True,
        "policy": "target_guard",
        "scope": "same_origin_or_allowlisted",
        "target": "https://api.example.com",
        "evidence_url": "https://api.example.com",
    }
    assert content["auth_context"]["authenticated"] is True
    assert content["auth_context"]["status"] == "ready"
    assert content["auth_context"]["reason"] == "auth_profile_ready"
    assert content["auth_context"]["auth_profile_id"] == auth_profile_id
    assert content["auth_context"]["has_runtime_credentials"] is True
    assert len(content["artifact_hash"]) == 64
    # Redacted, hash-verified evidence with no secret values persisted.
    assert content["content_redacted"] is True
    assert content["secret_values_persisted"] is False
    assert content["artifact_verification"]["verified"] is True
    assert content["artifact_verification"]["status"] == "VERIFIED"
    assert content["artifact_verification"]["expected_hash"] == content["artifact_hash"]
    assert content["artifact_verification"]["actual_hash"] == content["artifact_hash"]
    assert "direct-token-123" not in str(content)
    assert "raw-session-123" not in str(content)

    # The API recorded the queued event (not STARTED/COMPLETED, which no longer occur).
    queued_audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.action == "PENTEST_ENGINE_RUN_QUEUED",
                models.AuditLog.resource_id == run_id,
            )
        )
    ).scalar_one()
    assert queued_audit.details["engine"] == "zap"
    assert queued_audit.details["execution_mode"] == "queued"
    assert queued_audit.details["scan_plan_hash"] == payload["scan_plan_hash"]
    assert queued_audit.details["auth_context"]["authenticated"] is True
    assert queued_audit.details["auth_context"]["status"] == "ready"
    assert queued_audit.details["auth_context"]["auth_profile_id"] == auth_profile_id
    assert "direct-token-123" not in str(queued_audit.details)
    assert "raw-session-123" not in str(queued_audit.details)


@pytest.mark.asyncio
async def test_zap_profile_run_rejects_when_kill_switch_enabled(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    async def unexpected_run_scan(*_args, **_kwargs):
        pytest.fail("ZAP runner must not be called when the pentest kill switch is enabled")

    await _seed_zap_target(db_session)
    auth_profile_id, pentest_profile_id = await _create_zap_profile(
        client,
        auth_headers,
        auth_name="ZAP kill switch bearer",
        profile_name="ZAP kill switch profile",
    )

    monkeypatch.setattr("sentinel_core.modules.test_executor.kill_switch.settings.PENTEST_KILL_SWITCH_ENABLED", True)
    monkeypatch.setattr(worker.ZapRunner, "run_scan", unexpected_run_scan)

    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/zap/run",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "persist_findings": True},
    )

    # The kill switch rejects BEFORE queuing (audit PENTEST_ENGINE_RUN_BLOCKED, no run).
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
    assert audit.details["engine"] == "zap"
    assert audit.details["reason"] == "pentest_kill_switch_enabled"
    assert audit.details["auth_context"]["authenticated"] is True
    assert audit.details["auth_context"]["auth_profile_id"] == auth_profile_id
    assert "direct-token-123" not in str(audit.details)

    # No queued run and no execution artifact.
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
                PentestArtifact.artifact_type == "zap_execution",
            )
        )
    ).scalars().all()
    assert artifacts == []


@pytest.mark.asyncio
async def test_zap_profile_run_records_redacted_failure_when_runtime_unavailable(
    client,
    db_session,
    auth_headers,
    test_engine,
    monkeypatch,
):
    # OBSOLETE premise rewrite: the API no longer checks its own engine runtime
    # (the worker owns the engine). "Runtime unavailable" is now a worker-side
    # condition: the worker advertises the engine as unavailable and records a
    # redacted failure when the runner refuses to execute.
    async def runtime_unavailable_run_scan(**_kwargs):
        raise RuntimeError("zap runtime not available: binary missing token=direct-token-123")

    monkeypatch.setattr(worker.ZapRunner, "is_available", staticmethod(lambda: False))
    monkeypatch.setattr(worker.ZapRunner, "run_scan", AsyncMock(side_effect=runtime_unavailable_run_scan))

    await _seed_zap_target(db_session)
    _auth_profile_id, pentest_profile_id = await _create_zap_profile(
        client,
        auth_headers,
        auth_name="ZAP runtime bearer",
        profile_name="ZAP runtime profile",
    )

    # The API still queues the run (it does not gate on engine runtime).
    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/zap/run",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "persist_findings": True},
    )
    assert response.status_code == 200
    run_id = response.json()["run_id"]
    await db_session.commit()

    # The executing worker's own capability probe reports ZAP unavailable.
    assert worker._worker_engine_capabilities()["engines"]["zap"]["available"] is False

    claimed = await worker.claim_next_pending_run(
        db_bind=test_engine, account_id=1000000, worker_id="w"
    )
    assert claimed is not None
    assert claimed.run_id == run_id
    result = await worker._execute_planned_external_engines(
        claimed, db_bind=test_engine, worker_isolation_context=None
    )

    # The worker records the engine as FAILED with a redacted reason.
    assert result["status"] == "failed"
    assert result["engines"][0]["engine"] == "zap"
    assert result["engines"][0]["status"] == "FAILED"
    assert "direct-token-123" not in str(result)

    artifact = (
        await db_session.execute(
            select(PentestArtifact).where(
                PentestArtifact.pentest_profile_id == pentest_profile_id,
                PentestArtifact.artifact_type == "zap_execution",
            )
        )
    ).scalar_one()
    content = artifact.content_json
    assert content["status"] == "FAILED"
    assert content["execution"]["reason"] == "worker_external_engine_failed"
    assert content["execution"]["error_type"] == "RuntimeError"
    assert content["content_redacted"] is True
    assert content["secret_values_persisted"] is False
    # The runtime-failure detail (which carried the token) is never persisted.
    assert "direct-token-123" not in str(content)

    # No finding was promoted for an engine that never produced a report.
    vulnerabilities = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.account_id == 1000000)
        )
    ).scalars().all()
    assert vulnerabilities == []


@pytest.mark.asyncio
async def test_zap_profile_run_blocks_target_before_queuing(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    async def unexpected_run_scan(*_args, **_kwargs):
        pytest.fail("ZAP runner must not be called for a target-guard-blocked URL")

    await _seed_zap_target(db_session)
    auth_profile_id, pentest_profile_id = await _create_zap_profile(
        client,
        auth_headers,
        auth_name="ZAP target guard bearer",
        profile_name="ZAP target guard profile",
    )

    monkeypatch.setattr(worker.ZapRunner, "run_scan", unexpected_run_scan)

    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/zap/run",
        headers=auth_headers,
        json={"target_url": "http://169.254.169.254/latest/meta-data", "persist_findings": True},
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "target_guard_blocked"
    assert "metadata" in message["message"]

    # The target guard rejects BEFORE queuing: only a BLOCKED audit, never QUEUED.
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
    assert matching[0].details["engine"] == "zap"
    assert matching[0].details["reason"] == "target_guard_blocked"
    assert matching[0].details["auth_context"]["authenticated"] is True
    assert matching[0].details["auth_context"]["auth_profile_id"] == auth_profile_id
    assert "direct-token-123" not in str(matching[0].details)

    # No run was queued and no execution artifact was written.
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
                PentestArtifact.artifact_type == "zap_execution",
            )
        )
    ).scalars().all()
    assert artifacts == []


@pytest.mark.asyncio
async def test_zap_profile_run_records_redacted_failure_when_runner_crashes(
    client,
    db_session,
    auth_headers,
    test_engine,
    monkeypatch,
):
    await _seed_zap_target(db_session)
    _auth_profile_id, pentest_profile_id = await _create_zap_profile(
        client,
        auth_headers,
        auth_name="ZAP failure bearer",
        profile_name="ZAP failure profile",
    )

    async def failing_run_scan(**_kwargs):
        raise RuntimeError("zap crashed with Authorization: Bearer direct-token-123")

    monkeypatch.setattr(worker.ZapRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(worker.ZapRunner, "run_scan", AsyncMock(side_effect=failing_run_scan))

    # The API queues the run; the crash happens later in the worker.
    response = await client.post(
        f"/api/pentest/profiles/{pentest_profile_id}/zap/run",
        headers=auth_headers,
        json={"target_url": "https://api.example.com", "persist_findings": True},
    )
    assert response.status_code == 200
    run_id = response.json()["run_id"]
    await db_session.commit()

    # Full claim+execute+finalize: the runner raises, the worker marks the run FAILED.
    result = await worker.run_pending_scan_once(
        db_bind=test_engine, account_id=1000000, worker_id="w"
    )
    assert result["status"] == "failed"
    assert result["execution"]["reason"] == "external_engine_execution_failed"
    assert "direct-token-123" not in str(result)

    run = (
        await db_session.execute(select(models.TestRun).where(models.TestRun.id == run_id))
    ).scalar_one()
    assert run.status == "FAILED"

    # The failure is audited with a REDACTED reason (no raw crash message / token).
    failed_audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.action == "SCAN_RUN_FAILED",
                models.AuditLog.resource_id == run_id,
            )
        )
    ).scalar_one()
    assert failed_audit.details["reason"] == "external_engine_execution_failed"
    assert "direct-token-123" not in str(failed_audit.details)

    # The worker's redacted FAILED artifact never persists the crash secret.
    artifact = (
        await db_session.execute(
            select(PentestArtifact).where(
                PentestArtifact.pentest_profile_id == pentest_profile_id,
                PentestArtifact.artifact_type == "zap_execution",
            )
        )
    ).scalar_one()
    content = artifact.content_json
    assert content["status"] == "FAILED"
    assert content["content_redacted"] is True
    assert content["secret_values_persisted"] is False
    assert "direct-token-123" not in str(content)
