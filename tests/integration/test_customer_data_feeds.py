import pytest

from server.models.core import APIEndpoint, MCPEndpoint, PolicyViolation, SensitiveDataFinding
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers_for_role(role: str, account_id: int = 1000000):
    token = JWTIssuer.create_access_token({
        "sub": f"{role.lower()}-user",
        "email": f"{role.lower()}@example.com",
        "account_id": account_id,
        "role": role,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_openapi_violations_feed_returns_schema_records(client, db_session, auth_headers):
    endpoint = APIEndpoint(
        id="ep-schema-feed",
        account_id=1000000,
        method="POST",
        path="/api/users",
        host="api.example.com",
    )
    violation = PolicyViolation(
        id="viol-schema-feed",
        account_id=1000000,
        endpoint_id=endpoint.id,
        rule_type="SCHEMA",
        severity="HIGH",
        status="OPEN",
        message="Request body did not match OpenAPI schema",
        violation_metadata={
            "violation_type": "MISSING_REQUIRED_FIELD",
            "field": "email",
            "expected": "string (required)",
            "actual": "absent",
            "count": 3,
        },
    )
    db_session.add_all([endpoint, violation])
    await db_session.commit()

    resp = await client.get("/api/openapi/violations", headers=auth_headers)

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] >= 1
    first = next(item for item in payload["violations"] if item["id"] == violation.id)
    assert first["endpoint"] == "/api/users"
    assert first["method"] == "POST"
    assert first["violation_type"] == "MISSING_REQUIRED_FIELD"
    assert first["field"] == "email"
    assert first["severity"] == "high"


@pytest.mark.asyncio
async def test_pii_findings_feed_returns_enriched_findings(client, db_session, auth_headers):
    endpoint = APIEndpoint(
        id="ep-pii-feed",
        account_id=1000000,
        method="GET",
        path="/api/profile",
        host="api.example.com",
    )
    finding = SensitiveDataFinding(
        id="pii-feed-1",
        account_id=1000000,
        endpoint_id=endpoint.id,
        entity_type="EMAIL",
        source="response",
        sample_value="a***@example.com",
    )
    db_session.add_all([endpoint, finding])
    await db_session.commit()

    resp = await client.get("/api/pii/findings", headers=auth_headers)

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] >= 1
    first = next(item for item in payload["findings"] if item["id"] == finding.id)
    assert first["endpoint"] == "/api/profile"
    assert first["method"] == "GET"
    assert first["location"] == "response"
    assert first["data_type"] == "EMAIL"
    assert first["severity"] == "medium"
    assert "GDPR" in first["regulations"]


@pytest.mark.asyncio
async def test_member_can_read_mcp_servers_feed(client, db_session):
    endpoint = MCPEndpoint(
        id="mcp-feed-1",
        account_id=1000000,
        name="GitHub MCP",
        url="sse://mcp.internal/runtime",
        shield_enabled=True,
        allowed_tools=["issues.list", "repos.list"],
        blocked_patterns=["ignore previous instructions"],
    )
    db_session.add(endpoint)
    await db_session.commit()

    resp = await client.get("/api/mcp-shield/servers", headers=_headers_for_role("MEMBER"))

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] >= 1
    first = next(item for item in payload["servers"] if item["server_id"] == endpoint.id)
    assert first["name"] == "GitHub MCP"
    assert first["transport"] == "sse"
    assert first["tool_count"] == 2
    assert first["status"] == "trusted"
