import base64

import pytest
from sqlalchemy import func, select

from server.models.core import APIEndpoint, SampleData
from server.modules.auth.jwt_issuer import JWTIssuer


def _auth_headers_for(account_id: int, role: str = "ADMIN") -> dict[str, str]:
    token = JWTIssuer.create_access_token(
        {
            "sub": f"user-{account_id}",
            "email": f"user-{account_id}@example.com",
            "account_id": account_id,
            "role": role,
        }
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_burp_import_scopes_sample_data_to_callers_account(client, db_session):
    account_id = 2002
    default_account_count_before = await db_session.scalar(
        select(func.count()).select_from(SampleData).where(SampleData.account_id == 1000000)
    )
    request_blob = base64.b64encode(
        b"GET /orders HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
    ).decode("utf-8")
    response_blob = base64.b64encode(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"
    ).decode("utf-8")
    xml_content = (
        "<items>"
        "<item>"
        "<url>https://api.example.com/orders</url>"
        "<method>GET</method>"
        f"<request>{request_blob}</request>"
        f"<response>{response_blob}</response>"
        "</item>"
        "</items>"
    )

    response = await client.post(
        "/api/integrations/import/burp",
        headers=_auth_headers_for(account_id),
        files={"burp_file": ("burp.xml", xml_content, "application/xml")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["endpoints_imported"] == 1
    assert payload["samples_imported"] == 1

    endpoint_result = await db_session.execute(
        select(APIEndpoint).where(APIEndpoint.account_id == account_id, APIEndpoint.path == "/orders")
    )
    sample_result = await db_session.execute(
        select(SampleData).where(SampleData.account_id == account_id)
    )
    default_account_count_after = await db_session.scalar(
        select(func.count()).select_from(SampleData).where(SampleData.account_id == 1000000)
    )

    endpoint = endpoint_result.scalar_one_or_none()
    sample = sample_result.scalar_one_or_none()

    assert endpoint is not None
    assert sample is not None
    assert sample.request["method"] == "GET"
    assert default_account_count_after == default_account_count_before
