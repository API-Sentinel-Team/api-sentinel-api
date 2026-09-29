import pytest

from server.models.core import APICollection, APIEndpoint
from server.modules.auth.jwt_issuer import JWTIssuer


@pytest.mark.asyncio
async def test_account_settings_persist_and_compute_license_usage(client, db_session):
    account_id = 2200001
    token = JWTIssuer.create_access_token(
        {"user_id": "admin-settings-user", "account_id": account_id, "role": "ADMIN"}
    )
    auth_headers = {
        "Authorization": f"Bearer {token}"
    }
    collection = APICollection(
        account_id=account_id,
        name="Customer API",
        host="api.example.com",
        type="MIRRORING",
    )
    db_session.add(collection)
    await db_session.flush()

    endpoint = APIEndpoint(
        account_id=account_id,
        collection_id=collection.id,
        method="GET",
        path="/users",
        path_pattern="/users",
        host="api.example.com",
        protocol="https",
    )
    db_session.add(endpoint)
    await db_session.commit()

    initial = await client.post("/api/getAccountSettingsForAdvancedFilters", headers=auth_headers)
    assert initial.status_code == 200
    initial_payload = initial.json()["accountSettings"]
    assert initial_payload["identity"]["userIdKey"] == "x-user-id"
    assert initial_payload["license"]["applicationsUsed"] == 1
    assert initial_payload["license"]["endpointUsage"] == 1

    update = await client.post(
        "/api/modifyAccountSettings",
        headers=auth_headers,
        json={
            "identity": {
                "authHeader": "x-api-key",
                "userIdKey": "user_id",
                "tenantKey": "tenant_id",
            },
            "license": {
                "applicationsPurchased": 25,
                "endpointAllowance": 10000,
                "sensorAllowance": 4,
                "expiresOn": "2026-12-31",
            },
        },
    )
    assert update.status_code == 200
    assert update.json()["success"] is True

    fetched = await client.post("/api/getAccountSettingsForAdvancedFilters", headers=auth_headers)
    assert fetched.status_code == 200
    payload = fetched.json()["accountSettings"]
    assert payload["identity"]["authHeader"] == "x-api-key"
    assert payload["identity"]["userIdKey"] == "user_id"
    assert payload["identity"]["tenantKey"] == "tenant_id"
    assert payload["license"]["applicationsPurchased"] == 25
    assert payload["license"]["endpointAllowance"] == 10000
    assert payload["license"]["sensorAllowance"] == 4
    assert payload["license"]["expiresOn"] == "2026-12-31"
    assert payload["license"]["applicationsUsed"] == 1
    assert payload["license"]["endpointUsage"] == 1


@pytest.mark.asyncio
async def test_api_keys_lifecycle(client):
    token = JWTIssuer.create_access_token(
        {"user_id": "api-key-user", "account_id": 2200002, "role": "ADMIN"}
    )
    auth_headers = {
        "Authorization": f"Bearer {token}"
    }
    created = await client.post(
        "/api/createApiKey",
        headers=auth_headers,
        json={
            "name": "CI bootstrap",
            "scopes": ["discovery:read", "reports:read"],
            "expiresInDays": 30,
        },
    )
    assert created.status_code == 200
    created_payload = created.json()
    assert created_payload["token"].startswith("ask_")
    assert created_payload["apiKey"]["name"] == "CI bootstrap"
    api_key_id = created_payload["apiKey"]["id"]

    listed = await client.post("/api/getApiKeys", headers=auth_headers)
    assert listed.status_code == 200
    list_payload = listed.json()["apiKeys"]
    assert len(list_payload) == 1
    assert list_payload[0]["id"] == api_key_id
    assert list_payload[0]["status"] == "ACTIVE"

    revoked = await client.post(
        "/api/revokeApiKey",
        headers=auth_headers,
        json={"apiKeyId": api_key_id},
    )
    assert revoked.status_code == 200
    assert revoked.json()["success"] is True

    listed_again = await client.post("/api/getApiKeys", headers=auth_headers)
    assert listed_again.status_code == 200
    assert listed_again.json()["apiKeys"] == []
