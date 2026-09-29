import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.identity.authorization_replay import auth_headers_for_account
from server.modules.identity.test_account_secrets import TestAccountSecretCodec


@pytest.mark.asyncio
async def test_accounts_api_encrypts_test_account_secrets(client, db_session, auth_headers):
    response = await client.post(
        "/api/accounts/",
        headers=auth_headers,
        json={
            "name": "Member Replay",
            "role": "MEMBER",
            "auth_token": "raw-member-token",
        },
    )

    assert response.status_code == 200
    account_id = response.json()["id"]
    row = (
        await db_session.execute(
            select(models.TestAccount).where(models.TestAccount.id == account_id)
        )
    ).scalar_one()

    assert row.auth_token.startswith(TestAccountSecretCodec.PREFIX)
    assert row.auth_headers["Authorization"].startswith(TestAccountSecretCodec.PREFIX)
    assert "raw-member-token" not in str(row.auth_headers)
    assert auth_headers_for_account(row) == {"Authorization": "Bearer raw-member-token"}

    listed = await client.get("/api/accounts/", headers=auth_headers)
    assert listed.status_code == 200
    assert "raw-member-token" not in str(listed.json())
    assert any(item["id"] == account_id and item["has_token"] for item in listed.json()["accounts"])


@pytest.mark.asyncio
async def test_auth_roles_api_encrypts_test_account_header_values(client, db_session, auth_headers):
    response = await client.post(
        "/api/auth-roles/",
        headers=auth_headers,
        json={
            "name": "Admin Replay",
            "role": "ADMIN",
            "auth_headers": {"Authorization": "Bearer raw-admin-token"},
        },
    )

    assert response.status_code == 200
    role_id = response.json()["id"]
    row = (
        await db_session.execute(
            select(models.TestAccount).where(models.TestAccount.id == role_id)
        )
    ).scalar_one()

    assert row.auth_token is None
    assert row.auth_headers["Authorization"].startswith(TestAccountSecretCodec.PREFIX)
    assert auth_headers_for_account(row) == {"Authorization": "Bearer raw-admin-token"}

    listed = await client.get("/api/auth-roles/", headers=auth_headers)
    assert listed.status_code == 200
    assert "raw-admin-token" not in str(listed.json())
