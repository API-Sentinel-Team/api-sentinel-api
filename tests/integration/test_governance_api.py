import pytest
from sqlalchemy import select

from server.models.core import APIEndpoint, PolicyViolation
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
async def test_governance_rules_require_manage_permission_and_redact_outputs(client, db_session):
    account_id = 9408001
    raw_token = "governance-raw-token"
    raw_password = "governance-raw-password"
    member_headers = _headers_for_role("MEMBER", account_id)
    security_headers = _headers_for_role("SECURITY_ENGINEER", account_id)

    denied_create = await client.post(
        "/api/governance/rules",
        headers=member_headers,
        json={
            "name": "Member denied",
            "rule_type": "SECURITY",
            "condition": {"field": "method", "op": "eq", "value": "DELETE"},
            "action": "ALERT",
        },
    )
    assert denied_create.status_code == 403

    create_response = await client.post(
        "/api/governance/rules",
        headers=security_headers,
        json={
            "name": f"Authorization: Bearer {raw_token}",
            "description": f"token={raw_token} password={raw_password}",
            "rule_type": "SECURITY",
            "condition": {"field": "path", "op": "contains", "value": f"token={raw_token}"},
            "action": "ALERT",
        },
    )
    assert create_response.status_code == 200
    rule_id = create_response.json()["id"]

    list_response = await client.get("/api/governance/rules", headers=member_headers)
    assert list_response.status_code == 200
    assert raw_token not in str(list_response.json())
    assert raw_password not in str(list_response.json())
    assert "Bearer ****" in str(list_response.json())
    assert "token=****" in str(list_response.json())

    denied_toggle = await client.patch(
        f"/api/governance/rules/{rule_id}/toggle?enabled=false",
        headers=member_headers,
    )
    denied_scan = await client.post("/api/governance/scan", headers=member_headers)
    denied_delete = await client.delete(f"/api/governance/rules/{rule_id}", headers=member_headers)
    assert denied_toggle.status_code == 403
    assert denied_scan.status_code == 403
    assert denied_delete.status_code == 403

    endpoint = APIEndpoint(
        account_id=account_id,
        method="GET",
        host="api.example.com",
        path=f"/admin?token={raw_token}",
        protocol="https",
    )
    db_session.add(endpoint)
    await db_session.commit()

    scan_response = await client.post("/api/governance/scan", headers=security_headers)
    assert scan_response.status_code == 200
    scan_body = scan_response.json()
    assert scan_body["violations_found"] == 1
    assert raw_token not in str(scan_body)
    assert "token=****" in str(scan_body)

    violation = (
        await db_session.execute(
            select(PolicyViolation).where(PolicyViolation.account_id == account_id)
        )
    ).scalar_one()
    stored_blob = str({"message": violation.message, "metadata": violation.violation_metadata})
    assert raw_token not in stored_blob
    assert "token=****" in stored_blob

    violations_response = await client.get("/api/governance/violations", headers=member_headers)
    assert violations_response.status_code == 200
    assert raw_token not in str(violations_response.json())


@pytest.mark.asyncio
async def test_violations_are_enriched_paginated_and_filterable_by_status(client, db_session):
    account_id = 9408002
    security_headers = _headers_for_role("SECURITY_ENGINEER", account_id)

    endpoint = APIEndpoint(
        account_id=account_id,
        method="DELETE",
        host="api.example.com",
        path="/users/123",
        protocol="https",
    )
    db_session.add(endpoint)
    await db_session.commit()

    open_violation = PolicyViolation(
        account_id=account_id,
        endpoint_id=endpoint.id,
        rule_type="SECURITY",
        severity="HIGH",
        status="OPEN",
        message="No DELETE on sensitive paths violated",
    )
    resolved_violation = PolicyViolation(
        account_id=account_id,
        endpoint_id=endpoint.id,
        rule_type="NAMING",
        severity="LOW",
        status="RESOLVED",
        message="API paths should be lowercase violated",
    )
    db_session.add_all([open_violation, resolved_violation])
    await db_session.commit()

    all_response = await client.get("/api/governance/violations", headers=security_headers)
    assert all_response.status_code == 200
    all_body = all_response.json()
    assert all_body["total"] == 2
    assert len(all_body["violations"]) == 2

    open_only = await client.get(
        "/api/governance/violations?status=OPEN", headers=security_headers
    )
    assert open_only.status_code == 200
    open_body = open_only.json()
    assert open_body["total"] == 1
    row = open_body["violations"][0]
    assert row["status"] == "OPEN"
    assert row["method"] == "DELETE"
    assert row["url"].endswith("/users/123")
    assert row["subCategory"] == "SECURITY"
    assert isinstance(row["timestamp"], int) and row["timestamp"] > 0
    assert row["eventId"] == open_violation.id[:8]

    paginated = await client.get(
        "/api/governance/violations?skip=0&limit=1", headers=security_headers
    )
    assert paginated.status_code == 200
    paginated_body = paginated.json()
    assert paginated_body["total"] == 2
    assert len(paginated_body["violations"]) == 1
