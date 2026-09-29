import pytest
from sqlalchemy import select

from server.models.core import APIEndpoint, SampleData


def _burp_xml() -> str:
    return """<items>
  <item>
    <url>https://api.example.com/orders</url>
    <method>GET</method>
    <request>R0VUIC9vcmRlcnMgSFRUUC8xLjENCkhvc3Q6IGFwaS5leGFtcGxlLmNvbQ0KDQo=</request>
    <response>SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCg0KeyJvayI6dHJ1ZX0=</response>
  </item>
</items>"""


@pytest.mark.asyncio
async def test_burp_import_scopes_sample_data_to_authenticated_account(client, auth_headers, db_session):
    response = await client.post(
        "/api/integrations/import/burp",
        headers=auth_headers,
        files={"burp_file": ("burp.xml", _burp_xml(), "application/xml")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["endpoints_imported"] == 1
    assert payload["samples_imported"] == 1

    endpoints = (
        await db_session.execute(
            select(APIEndpoint).where(
                APIEndpoint.account_id == 1000000,
                APIEndpoint.path == "/orders",
                APIEndpoint.host == "api.example.com",
            )
        )
    ).scalars().all()
    assert len(endpoints) >= 1

    samples = (
        await db_session.execute(
            select(SampleData).where(SampleData.account_id == 1000000)
        )
    ).scalars().all()
    assert len(samples) >= 1
