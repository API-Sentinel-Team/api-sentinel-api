import pytest
from sqlalchemy import select

from server.models.core import APIEndpoint
from server.modules.api_inventory.endpoint_discovery import EndpointDiscovery


@pytest.mark.asyncio
async def test_discovery_normalizes_multi_source_records_and_merges_metadata(db_session):
    discovery = EndpointDiscovery(db_session)

    await discovery.discover(
        {
            "account_id": 2001001,
            "source": "har",
            "request": {
                "method": "GET",
                "url": "https://api.example.com/users/123?debug=true",
            },
            "response": {"status": 200},
            "owner": "identity-team",
            "auth_required": True,
            "sensitivity": "high",
            "version": "v1",
        }
    )
    await discovery.discover(
        {
            "account_id": 2001001,
            "source": "aws_api_gateway",
            "method": "GET",
            "url": "https://api.example.com/users/456",
            "status": 404,
            "deprecated": True,
        }
    )

    result = await db_session.execute(
        select(APIEndpoint).where(
            APIEndpoint.account_id == 2001001,
            APIEndpoint.method == "GET",
            APIEndpoint.host == "api.example.com",
            APIEndpoint.path_pattern == "/users/{id}",
        )
    )
    endpoints = result.scalars().all()

    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.path == "/users/123"
    assert endpoint.last_query_string == "debug=true"
    assert endpoint.last_response_code == 404
    assert endpoint.is_sensitive is True
    assert endpoint.status == "DEPRECATED"
    assert endpoint.tags["owner"] == "identity-team"
    assert endpoint.tags["auth_required"] is True
    assert endpoint.tags["sensitivity"] == "high"
    assert endpoint.tags["version"] == "v1"
    assert endpoint.tags["deprecated"] is True
    assert endpoint.tags["sources"] == ["aws_api_gateway", "har"]


@pytest.mark.asyncio
async def test_discovery_accepts_ingress_records_without_full_url(db_session):
    discovery = EndpointDiscovery(db_session)

    endpoint = await discovery.discover(
        {
            "account_id": 2001002,
            "source": "kubernetes_ingress",
            "method": "POST",
            "host": "orders.example.com",
            "path": "/orders/789",
            "scheme": "https",
            "owner": "orders-team",
            "auth_required": False,
            "sensitivity": "medium",
            "version": "2026-06-04",
            "shadow": True,
        }
    )

    assert endpoint.account_id == 2001002
    assert endpoint.protocol == "https"
    assert endpoint.host == "orders.example.com"
    assert endpoint.path == "/orders/789"
    assert endpoint.path_pattern == "/orders/{id}"
    assert endpoint.status == "SHADOW"
    assert endpoint.is_sensitive is True
    assert endpoint.tags == {
        "source": "kubernetes_ingress",
        "sources": ["kubernetes_ingress"],
        "owner": "orders-team",
        "auth_required": False,
        "sensitivity": "medium",
        "version": "2026-06-04",
        "deprecated": False,
        "shadow": True,
    }
