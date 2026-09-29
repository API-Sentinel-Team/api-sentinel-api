import os

import pytest
from sqlalchemy import select

from server.api.routers import storage as storage_router
from server.config import settings
from server.models.core import AuditLog, TenantRetentionPolicy
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers_for_role(role: str, account_id: int) -> dict[str, str]:
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
async def test_retention_policy_requires_manage_permission_and_redacts_read_response(client, db_session):
    account_id = 9409001
    raw_token = "retention-raw-token"
    member_headers = _headers_for_role("MEMBER", account_id)
    security_headers = _headers_for_role("SECURITY_ENGINEER", account_id)

    read_response = await client.get("/api/retention/", headers=member_headers)
    assert read_response.status_code == 200
    assert read_response.json()["full_payload_retention"] is False

    denied_response = await client.put(
        "/api/retention/",
        headers=member_headers,
        json={
            "full_payload_retention": True,
            "retain_request_headers": True,
            "retain_response_bodies": True,
            "retention_period_days": 365,
        },
    )
    assert denied_response.status_code == 403

    update_response = await client.put(
        "/api/retention/",
        headers=security_headers,
        json={
            "full_payload_retention": True,
            "retain_request_headers": True,
            "retain_response_bodies": True,
            "retention_encryption_key_id": f"kms://tenant/key?token={raw_token}",
            "retention_period_days": 365,
            "pii_categories_to_retain": ["EMAIL", "AUTH_TOKEN"],
            "pii_vault_enabled": True,
        },
    )
    assert update_response.status_code == 200

    policy = (
        await db_session.execute(
            select(TenantRetentionPolicy).where(TenantRetentionPolicy.account_id == account_id)
        )
    ).scalar_one()
    assert policy.full_payload_retention is True
    assert policy.retention_period_days == 365

    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.account_id == account_id,
                AuditLog.action == "RETENTION_POLICY_UPDATED",
            )
        )
    ).scalar_one()
    assert audit.resource_type == "retention_policy"

    refreshed_response = await client.get("/api/retention/", headers=member_headers)
    assert refreshed_response.status_code == 200
    assert raw_token not in str(refreshed_response.json())
    assert "token=****" in str(refreshed_response.json())

    invalid_response = await client.put(
        "/api/retention/",
        headers=security_headers,
        json={"retention_period_days": 0},
    )
    assert invalid_response.status_code == 400


@pytest.mark.asyncio
async def test_storage_archive_routes_require_privilege_and_hide_absolute_paths(
    client,
    tmp_path,
    monkeypatch,
):
    account_id = 9409002
    archive_root = tmp_path / "archives"
    archive_file = archive_root / f"account_{account_id}" / "request_logs" / "2026" / "06" / "02.jsonl.gz"
    archive_file.parent.mkdir(parents=True)
    archive_file.write_bytes(b"compressed-placeholder")
    monkeypatch.setattr(settings, "ARCHIVE_DIR", str(archive_root))

    async def fake_archive_once(archived_account_id: int):
        return {"status": "ok", "account_id": archived_account_id, "archived": {"request_logs": 0}}

    monkeypatch.setattr(storage_router, "archive_once", fake_archive_once)

    member_headers = _headers_for_role("MEMBER", account_id)
    auditor_headers = _headers_for_role("AUDITOR", account_id)
    security_headers = _headers_for_role("SECURITY_ENGINEER", account_id)

    denied_list = await client.get("/api/storage/archives", headers=member_headers)
    denied_archive = await client.post("/api/storage/archive", headers=member_headers)
    assert denied_list.status_code == 403
    assert denied_archive.status_code == 403

    list_response = await client.get("/api/storage/archives", headers=auditor_headers)
    assert list_response.status_code == 200
    archive = list_response.json()["archives"][0]
    assert archive["path"] == f"account_{account_id}/request_logs/2026/06/02.jsonl.gz"
    assert not os.path.isabs(archive["path"])
    assert str(archive_root) not in str(list_response.json())

    run_response = await client.post("/api/storage/archive", headers=security_headers)
    assert run_response.status_code == 200
    assert run_response.json()["status"] == "ok"
    assert run_response.json()["account_id"] == account_id
