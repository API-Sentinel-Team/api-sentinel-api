import pytest
from sqlalchemy import select

from server.models.core import AuthMechanism
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers_for_role(role: str = "ADMIN", account_id: int = 9101000):
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
async def test_auth_mechanism_create_validates_and_lists(client):
    account_id = 9101001

    response = await client.post(
        "/api/auth-mechanisms/",
        headers=_headers_for_role(account_id=account_id),
        json={
            "name": "Partner API key",
            "header_key": "X-API-Key",
            "prefix": "",
            "token_type": "api_key",
        },
    )

    assert response.status_code == 200
    created = response.json()
    assert created["status"] == "created"

    list_response = await client.get(
        "/api/auth-mechanisms/",
        headers=_headers_for_role("VIEWER", account_id=account_id),
    )

    assert list_response.status_code == 200
    body = list_response.json()
    assert body["total"] == 1
    assert body["mechanisms"][0]["id"] == created["id"]
    assert body["mechanisms"][0]["header_key"] == "X-API-Key"
    assert body["mechanisms"][0]["prefix"] == ""
    assert body["mechanisms"][0]["token_type"] == "API_KEY"


@pytest.mark.asyncio
async def test_auth_mechanism_rejects_header_injection_and_bad_token_type(client, db_session):
    account_id = 9101002
    headers = _headers_for_role(account_id=account_id)

    injection_response = await client.post(
        "/api/auth-mechanisms/",
        headers=headers,
        json={
            "name": "Injected header",
            "header_key": "X-API-Key\r\nX-Injected",
            "prefix": "",
            "token_type": "API_KEY",
        },
    )
    assert injection_response.status_code == 400

    unknown_type_response = await client.post(
        "/api/auth-mechanisms/",
        headers=headers,
        json={
            "name": "Ambiguous mechanism",
            "header_key": "Authorization",
            "prefix": "Bearer ",
            "token_type": "UNKNOWN",
        },
    )
    assert unknown_type_response.status_code == 400

    result = await db_session.execute(
        select(AuthMechanism).where(AuthMechanism.account_id == account_id)
    )
    assert result.scalars().all() == []


@pytest.mark.asyncio
async def test_auth_mechanism_update_delete_are_tenant_scoped(client, db_session):
    owner_account_id = 9101003
    other_account_id = 9101004
    mechanism = AuthMechanism(
        account_id=owner_account_id,
        name="Owner bearer",
        header_key="Authorization",
        prefix="Bearer ",
        token_type="BEARER",
    )
    db_session.add(mechanism)
    await db_session.commit()

    cross_tenant_patch = await client.patch(
        f"/api/auth-mechanisms/{mechanism.id}",
        headers=_headers_for_role(account_id=other_account_id),
        json={"token_type": "JWT"},
    )
    assert cross_tenant_patch.status_code == 404

    cross_tenant_delete = await client.delete(
        f"/api/auth-mechanisms/{mechanism.id}",
        headers=_headers_for_role(account_id=other_account_id),
    )
    assert cross_tenant_delete.status_code == 404

    owner_patch = await client.patch(
        f"/api/auth-mechanisms/{mechanism.id}",
        headers=_headers_for_role(account_id=owner_account_id),
        json={"token_type": "JWT"},
    )
    assert owner_patch.status_code == 200

    owner_delete = await client.delete(
        f"/api/auth-mechanisms/{mechanism.id}",
        headers=_headers_for_role(account_id=owner_account_id),
    )
    assert owner_delete.status_code == 200

    remaining = await db_session.scalar(
        select(AuthMechanism.id).where(AuthMechanism.id == mechanism.id)
    )
    assert remaining is None
