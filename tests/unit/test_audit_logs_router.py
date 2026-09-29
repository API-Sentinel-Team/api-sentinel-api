import pytest
from sqlalchemy import select

from server.models.core import AuditLog
from server.modules.auth.audit import log_action
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers_for_role(role: str, account_id: int):
    token = JWTIssuer.create_access_token(
        {
            "sub": f"{role.lower()}-{account_id}",
            "email": f"{role.lower()}-{account_id}@example.com",
            "account_id": account_id,
            "role": role,
        }
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_log_action_keeps_auth_posture_queryable_but_encrypts_secret_material(db_session):
    await log_action(
        db=db_session,
        account_id=9201000,
        action="SCAN_RUN_QUEUED",
        resource_type="test_run",
        resource_id="run-auth-context",
        details={
            "auth_required": True,
            "auth_profile_id": "auth-1",
            "auth_profile_present": True,
            "auth_mode": "bearer",
        },
    )
    await log_action(
        db=db_session,
        account_id=9201000,
        action="SECRET_TEST",
        resource_type="test_run",
        resource_id="run-secret",
        details={"headers": {"Authorization": "Bearer raw-token"}},
    )
    await db_session.commit()

    queryable = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.resource_id == "run-auth-context")
        )
    ).scalar_one()
    encrypted = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.resource_id == "run-secret")
        )
    ).scalar_one()

    assert queryable.details["auth_profile_id"] == "auth-1"
    assert queryable.details["auth_mode"] == "bearer"
    assert queryable.details_encrypted is None
    assert encrypted.details is None
    assert encrypted.details_encrypted


@pytest.mark.asyncio
async def test_log_action_keeps_engine_artifact_labels_queryable(db_session):
    await log_action(
        db=db_session,
        account_id=9201013,
        action="SCAN_RUN_QUEUED",
        resource_type="test_run",
        resource_id="run-engine-plan",
        details={
            "scan_plan": {
                "required_artifacts": [
                    {"engine": "schemathesis", "artifact_type": "schemathesis"},
                    {"engine": "nuclei", "artifact_type": "nuclei_secret_file"},
                    {"engine": "zap", "artifact_type": "zap_plan"},
                ]
            }
        },
    )
    await log_action(
        db=db_session,
        account_id=9201013,
        action="SECRET_TEST",
        resource_type="test_run",
        resource_id="run-engine-secret",
        details={"artifact": {"content": "Authorization: Bearer raw-token"}},
    )
    await db_session.commit()

    queryable = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.resource_id == "run-engine-plan")
        )
    ).scalar_one()
    encrypted = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.resource_id == "run-engine-secret")
        )
    ).scalar_one()

    assert queryable.details["scan_plan"]["required_artifacts"][1]["artifact_type"] == "nuclei_secret_file"
    assert queryable.details_encrypted is None
    assert encrypted.details is None
    assert encrypted.details_encrypted


@pytest.mark.asyncio
async def test_audit_logs_require_audit_read_and_redact_legacy_plaintext(client, db_session):
    account_id = 9201001
    other_account_id = 9201002
    db_session.add_all(
        [
            AuditLog(
                account_id=account_id,
                user_id="admin-user",
                action="PENTEST_ENGINE_RUN_STARTED",
                resource_type="pentest_engine_run",
                resource_id="run-1",
                details={
                    "message": "Authorization: Bearer raw-token-123",
                    "headers": {"Authorization": "Bearer raw-token-123"},
                    "target_url": "https://api.example.com/orders?token=raw-token-123",
                },
                ip_address="203.0.113.10",
            ),
            AuditLog(
                account_id=other_account_id,
                user_id="other-user",
                action="PENTEST_ENGINE_RUN_STARTED",
                resource_type="pentest_engine_run",
                resource_id="other-run",
                details={"message": "other tenant"},
            ),
        ]
    )
    await db_session.commit()

    denied = await client.get(
        "/api/audit-logs/",
        headers=_headers_for_role("MEMBER", account_id),
    )
    assert denied.status_code == 403

    response = await client.get(
        "/api/audit-logs/",
        headers=_headers_for_role("AUDITOR", account_id),
        params={
            "action": "PENTEST_ENGINE_RUN_STARTED",
            "resource_type": "pentest_engine_run",
            "limit": 10,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["logs"][0]["resource_id"] == "run-1"
    assert body["logs"][0]["details"]["headers"]["Authorization"] == "****"
    assert "Bearer ****" in body["logs"][0]["details"]["message"]
    assert "raw-token-123" not in str(body)
    assert "other-run" not in str(body)


@pytest.mark.asyncio
async def test_audit_logs_preserve_redacted_safety_policy_details(client, db_session):
    account_id = 9201004
    db_session.add(
        AuditLog(
            account_id=account_id,
            user_id="admin-user",
            action="PENTEST_ENGINE_RUN_COMPLETED",
            resource_type="pentest_engine_run",
            resource_id="run-policy",
            details={
                "artifact_safety_policies": {
                    "auth_profile_scope_policy": {
                        "policy": "auth_profile_scope_guard",
                        "blocked": True,
                        "url": "https://evil.example.test/search?token=raw-audit-token",
                        "base_url": "https://api.example.com/search?token=raw-audit-token",
                        "reason": "Authorization: Bearer raw-audit-token token=raw-audit-token",
                        "auth_profile_id": "auth-profile-1",
                    }
                },
                "headers": {"Authorization": "Bearer raw-audit-token"},
            },
        )
    )
    await db_session.commit()

    response = await client.get(
        "/api/audit-logs/",
        headers=_headers_for_role("AUDITOR", account_id),
        params={
            "action": "PENTEST_ENGINE_RUN_COMPLETED",
            "resource_type": "pentest_engine_run",
            "limit": 10,
        },
    )

    assert response.status_code == 200
    body = response.json()
    details = body["logs"][0]["details"]
    policy = details["artifact_safety_policies"]["auth_profile_scope_policy"]
    assert details["headers"]["Authorization"] == "****"
    assert policy["policy"] == "auth_profile_scope_guard"
    assert policy["url"] == "https://evil.example.test/search?token=****"
    assert policy["base_url"] == "https://api.example.com/search?token=****"
    assert policy["reason"] == "Authorization: Bearer **** token=****"
    assert policy["auth_profile_id"] == "auth-profile-1"
    assert "raw-audit-token" not in str(body)


@pytest.mark.asyncio
async def test_legacy_fetch_audit_data_redacts_legacy_plaintext(client, db_session):
    account_id = 9201003
    db_session.add(
        AuditLog(
            account_id=account_id,
            user_id="admin-user",
            action="PENTEST_ENGINE_RUN_COMPLETED",
            resource_type="pentest_engine_run",
            resource_id="run-legacy",
            details={
                "stdout": "Authorization: Bearer raw-legacy-token",
                "artifact_url": "https://api.example.com/evidence?api_key=raw-legacy-token",
            },
        )
    )
    await db_session.commit()

    response = await client.post(
        "/api/fetchAuditData",
        headers=_headers_for_role("AUDITOR", account_id),
        json={"skip": 0, "limit": 10},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    assert body["auditLogs"][0]["action"] == "PENTEST_ENGINE_RUN_COMPLETED"
    assert "raw-legacy-token" not in str(body)
    assert "Bearer ****" in str(body)
