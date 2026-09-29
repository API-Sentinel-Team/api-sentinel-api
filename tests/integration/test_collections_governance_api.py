import uuid

import pytest
from sqlalchemy import select

from server.models.core import APICollection, APIEndpoint
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
async def test_collection_routes_require_auth_and_enforce_tenant_scope(client, db_session):
    owner_account_id = 9412001
    other_account_id = 9412002
    raw_token = "collection-raw-token"
    owner_collection = APICollection(
        id=str(uuid.uuid4()),
        account_id=owner_account_id,
        name=f"Authorization: Bearer {raw_token}",
        host="api.example.com",
        type="MIRRORING",
    )
    other_collection = APICollection(
        id=str(uuid.uuid4()),
        account_id=other_account_id,
        name="Other tenant collection",
        host="other.example.com",
        type="MIRRORING",
    )
    owner_endpoint = APIEndpoint(
        id=str(uuid.uuid4()),
        account_id=owner_account_id,
        method="GET",
        host="api.example.com",
        path=f"/orders?token={raw_token}",
        last_response_code=200,
    )
    other_endpoint = APIEndpoint(
        id=str(uuid.uuid4()),
        account_id=other_account_id,
        method="GET",
        host="api.example.com",
        path="/other",
        last_response_code=200,
    )
    db_session.add_all([owner_collection, other_collection, owner_endpoint, other_endpoint])
    await db_session.commit()

    unauthenticated_read = await client.get(f"/api/collections/{owner_collection.id}/endpoints")
    unauthenticated_add = await client.post(
        f"/api/collections/{owner_collection.id}/add-endpoint/{owner_endpoint.id}"
    )
    unauthenticated_delete = await client.delete(f"/api/collections/{owner_collection.id}")
    assert unauthenticated_read.status_code == 401
    assert unauthenticated_add.status_code == 401
    assert unauthenticated_delete.status_code == 401

    owner_viewer_headers = _headers_for_role("VIEWER", owner_account_id)
    owner_member_headers = _headers_for_role("MEMBER", owner_account_id)
    other_admin_headers = _headers_for_role("ADMIN", other_account_id)

    denied_create = await client.post(
        "/api/collections/",
        headers=owner_viewer_headers,
        json={"name": "viewer denied"},
    )
    denied_add = await client.post(
        f"/api/collections/{owner_collection.id}/add-endpoint/{owner_endpoint.id}",
        headers=owner_viewer_headers,
    )
    denied_delete = await client.delete(f"/api/collections/{owner_collection.id}", headers=owner_member_headers)
    assert denied_create.status_code == 403
    assert denied_add.status_code == 403
    assert denied_delete.status_code == 403

    cross_tenant_read = await client.get(
        f"/api/collections/{owner_collection.id}/endpoints",
        headers=other_admin_headers,
    )
    cross_tenant_add = await client.post(
        f"/api/collections/{owner_collection.id}/add-endpoint/{other_endpoint.id}",
        headers=owner_member_headers,
    )
    cross_tenant_delete = await client.delete(
        f"/api/collections/{owner_collection.id}",
        headers=other_admin_headers,
    )
    assert cross_tenant_read.status_code == 404
    assert cross_tenant_add.status_code == 404
    assert cross_tenant_delete.status_code == 404

    add_response = await client.post(
        f"/api/collections/{owner_collection.id}/add-endpoint/{owner_endpoint.id}",
        headers=owner_member_headers,
    )
    assert add_response.status_code == 200
    await db_session.refresh(owner_endpoint)
    assert owner_endpoint.collection_id == owner_collection.id

    list_response = await client.get("/api/collections/", headers=owner_member_headers)
    endpoints_response = await client.get(
        f"/api/collections/{owner_collection.id}/endpoints",
        headers=owner_member_headers,
    )
    assert list_response.status_code == 200
    assert endpoints_response.status_code == 200
    assert raw_token not in str(list_response.json())
    assert raw_token not in str(endpoints_response.json())
    assert "Bearer ****" in str(list_response.json())
    assert "token=****" in str(endpoints_response.json())
    owner_item = next(item for item in list_response.json()["collections"] if item["id"] == owner_collection.id)
    assert owner_item["endpoint_count"] == 1
    assert all(item["id"] != other_collection.id for item in list_response.json()["collections"])


@pytest.mark.asyncio
async def test_collection_delete_is_scoped_and_unassigns_only_owner_endpoints(client, db_session):
    owner_account_id = 9412003
    other_account_id = 9412004
    collection_id = str(uuid.uuid4())
    collection = APICollection(
        id=collection_id,
        account_id=owner_account_id,
        name="Deletion target",
        host="api.example.com",
        type="MIRRORING",
    )
    owner_endpoint = APIEndpoint(
        id=str(uuid.uuid4()),
        account_id=owner_account_id,
        method="GET",
        host="api.example.com",
        path="/owner",
        collection_id=collection_id,
    )
    other_endpoint = APIEndpoint(
        id=str(uuid.uuid4()),
        account_id=other_account_id,
        method="GET",
        host="api.example.com",
        path="/other",
        collection_id=collection_id,
    )
    db_session.add_all([collection, owner_endpoint, other_endpoint])
    await db_session.commit()

    response = await client.delete(
        f"/api/collections/{collection.id}",
        headers=_headers_for_role("SECURITY_ENGINEER", owner_account_id),
    )

    assert response.status_code == 200
    assert (
        await db_session.execute(select(APICollection).where(APICollection.id == collection_id))
    ).scalar_one_or_none() is None
    await db_session.refresh(owner_endpoint)
    await db_session.refresh(other_endpoint)
    assert owner_endpoint.collection_id is None
    assert other_endpoint.collection_id == collection_id
