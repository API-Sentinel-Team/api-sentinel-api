import pytest

from server.models.core import APIEndpoint, WAFEvent
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers_for_role(role: str, account_id: int):
    token = JWTIssuer.create_access_token({
        "sub": f"{role.lower()}-waf-user",
        "email": f"{role.lower()}-waf@example.com",
        "account_id": account_id,
        "role": role,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_waf_routes_require_auth_permissions_scope_and_redact(client, db_session):
    owner_account = 52525201
    other_account = 52525202
    raw_token = "raw-waf-token"

    owner_endpoint = APIEndpoint(
        account_id=owner_account,
        method="GET",
        protocol="https",
        host="api.example.com",
        path="/orders",
    )
    other_endpoint = APIEndpoint(
        account_id=other_account,
        method="GET",
        protocol="https",
        host="other.example.com",
        path="/other",
    )
    db_session.add_all([owner_endpoint, other_endpoint])
    await db_session.flush()
    db_session.add_all([
        WAFEvent(
            account_id=owner_account,
            source_ip="203.0.113.10",
            rule_id="token-rule",
            action="BLOCKED",
            method="GET",
            path=f"/admin?token={raw_token}",
            payload_snippet=f"Authorization: Bearer {raw_token}",
            severity="HIGH",
            endpoint_id=owner_endpoint.id,
        ),
        WAFEvent(
            account_id=other_account,
            source_ip="203.0.113.99",
            rule_id="other-rule",
            action="BLOCKED",
            method="GET",
            path="/other-account-only",
            payload_snippet="other account event",
            severity="HIGH",
            endpoint_id=other_endpoint.id,
        ),
    ])
    await db_session.commit()

    assert (await client.get("/api/waf/")).status_code == 401
    assert (await client.post("/api/waf/events", json={"source_ip": "203.0.113.20", "rule_id": "r"})).status_code == 401
    assert (await client.post("/api/waf/rules/reload")).status_code == 401

    member_headers = _headers_for_role("MEMBER", owner_account)
    denied_event = await client.post(
        "/api/waf/events",
        headers=member_headers,
        json={"source_ip": "203.0.113.20", "rule_id": "member-denied"},
    )
    assert denied_event.status_code == 403
    denied_reload = await client.post("/api/waf/rules/reload", headers=member_headers)
    assert denied_reload.status_code == 403

    viewer_headers = _headers_for_role("VIEWER", owner_account)
    listing = await client.get("/api/waf/", headers=viewer_headers)
    assert listing.status_code == 200
    body = listing.json()
    blob = str(body)
    assert body["total"] == 1
    assert raw_token not in blob
    assert "token=****" in blob
    assert "Bearer ****" in blob
    assert "other-account-only" not in blob

    security_headers = _headers_for_role("SECURITY_ENGINEER", owner_account)
    cross_tenant = await client.post(
        "/api/waf/events",
        headers=security_headers,
        json={
            "source_ip": "203.0.113.30",
            "rule_id": "cross-tenant-denied",
            "endpoint_id": other_endpoint.id,
        },
    )
    assert cross_tenant.status_code == 404

    created = await client.post(
        "/api/waf/events",
        headers=security_headers,
        json={
            "source_ip": "203.0.113.30",
            "rule_id": "new-rule",
            "action": "logged",
            "method": "post",
            "path": f"/login?api_key={raw_token}",
            "payload_snippet": f"password={raw_token}",
            "severity": "critical",
            "endpoint_id": owner_endpoint.id,
        },
    )
    assert created.status_code == 200

    stored = await db_session.get(WAFEvent, created.json()["id"])
    assert stored.account_id == owner_account
    assert stored.action == "LOGGED"
    assert stored.method == "POST"
    assert stored.severity == "CRITICAL"
    assert raw_token not in str(stored.path)
    assert raw_token not in str(stored.payload_snippet)

    reload_response = await client.post("/api/waf/rules/reload", headers=security_headers)
    assert reload_response.status_code == 200
    assert reload_response.json() == {"status": "rules_reloaded", "account_id": owner_account}
