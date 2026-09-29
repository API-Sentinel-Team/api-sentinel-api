import pytest

from server.models.core import BusinessLogicGraph, BusinessLogicViolation
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers_for_role(role: str, account_id: int):
    token = JWTIssuer.create_access_token({
        "sub": f"{role.lower()}-bizlogic-user",
        "email": f"{role.lower()}-bizlogic@example.com",
        "account_id": account_id,
        "role": role,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_business_logic_routes_require_permissions_scope_tenant_and_redact(client, db_session):
    owner_account = 42424201
    other_account = 42424202
    raw_token = "raw-business-token"

    db_session.add_all([
        BusinessLogicGraph(
            account_id=owner_account,
            version=7,
            nodes_json=[{"path": f"/orders?token={raw_token}", "count": 4}],
            edges_json=[{
                "from": f"/orders?token={raw_token}",
                "to": f"/admin?api_key={raw_token}",
                "count": 4,
            }],
        ),
        BusinessLogicGraph(
            account_id=other_account,
            version=99,
            nodes_json=[{"path": "/other-account-only", "count": 1}],
            edges_json=[],
        ),
        BusinessLogicViolation(
            account_id=owner_account,
            actor_id=f"user token={raw_token}",
            from_path=f"/orders?token={raw_token}",
            to_path=f"/admin?api_key={raw_token}",
            violation_type="FORBIDDEN_TRANSITION",
            confidence=0.91,
        ),
        BusinessLogicViolation(
            account_id=other_account,
            actor_id="other-actor",
            from_path="/other-from",
            to_path="/other-to",
            violation_type="FORBIDDEN_TRANSITION",
            confidence=0.5,
        ),
    ])
    await db_session.commit()

    assert (await client.get("/api/business-logic/graph/latest")).status_code == 401
    assert (await client.get("/api/business-logic/violations")).status_code == 401
    assert (await client.post("/api/business-logic/rebuild")).status_code == 401

    member_headers = _headers_for_role("MEMBER", owner_account)
    rebuild = await client.post("/api/business-logic/rebuild", headers=member_headers)
    assert rebuild.status_code == 403

    viewer_headers = _headers_for_role("VIEWER", owner_account)
    graph = await client.get("/api/business-logic/graph/latest", headers=viewer_headers)
    assert graph.status_code == 200
    graph_body = graph.json()
    graph_blob = str(graph_body)
    assert graph_body["version"] == 7
    assert raw_token not in graph_blob
    assert "token=****" in graph_blob
    assert "api_key=****" in graph_blob
    assert "other-account-only" not in graph_blob

    violations = await client.get("/api/business-logic/violations", headers=viewer_headers)
    assert violations.status_code == 200
    violation_blob = str(violations.json())
    assert raw_token not in violation_blob
    assert "token=****" in violation_blob
    assert "api_key=****" in violation_blob
    assert "other-actor" not in violation_blob
