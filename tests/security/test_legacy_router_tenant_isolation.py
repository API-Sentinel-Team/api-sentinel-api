import uuid

import pytest

from server.models.core import APIWorkflow, Alert, ThreatActor, Vulnerability
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers_for_account(account_id: int, role: str = "ADMIN") -> dict[str, str]:
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
async def test_alert_routes_are_tenant_scoped(client, db_session):
    alert = Alert(
        id=str(uuid.uuid4()),
        account_id=1000000,
        title="Tenant A alert",
        severity="HIGH",
        status="OPEN",
    )
    db_session.add(alert)
    await db_session.commit()

    own_resp = await client.get("/api/alerts/", headers=_headers_for_account(1000000))
    assert own_resp.status_code == 200
    assert any(row["id"] == alert.id for row in own_resp.json())

    other_resp = await client.get("/api/alerts/", headers=_headers_for_account(2000000))
    assert other_resp.status_code == 200
    assert all(row["id"] != alert.id for row in other_resp.json())

    resolve_resp = await client.patch(
        f"/api/alerts/{alert.id}/resolve",
        headers=_headers_for_account(2000000),
    )
    assert resolve_resp.status_code == 404


@pytest.mark.asyncio
async def test_workflow_routes_are_tenant_scoped(client, db_session):
    workflow = APIWorkflow(
        id=str(uuid.uuid4()),
        account_id=1000000,
        name="Tenant A workflow",
        description="test workflow",
        steps=[],
        enabled=True,
    )
    db_session.add(workflow)
    await db_session.commit()

    own_resp = await client.get(
        f"/api/workflows/{workflow.id}",
        headers=_headers_for_account(1000000),
    )
    assert own_resp.status_code == 200
    assert own_resp.json()["id"] == workflow.id

    other_get = await client.get(
        f"/api/workflows/{workflow.id}",
        headers=_headers_for_account(2000000),
    )
    assert other_get.status_code == 404

    other_execute = await client.post(
        f"/api/workflows/{workflow.id}/execute",
        headers=_headers_for_account(2000000),
        json={},
    )
    assert other_execute.status_code == 404

    other_delete = await client.delete(
        f"/api/workflows/{workflow.id}",
        headers=_headers_for_account(2000000),
    )
    assert other_delete.status_code == 404


@pytest.mark.asyncio
async def test_threat_actor_status_is_tenant_scoped(client, db_session):
    actor = ThreatActor(
        id=str(uuid.uuid4()),
        account_id=1000000,
        source_ip="198.51.100.23",
        status="MONITORING",
        event_count=1,
        risk_score=0.5,
    )
    db_session.add(actor)
    await db_session.commit()

    other_resp = await client.post(
        "/api/threat-detection/actors/status",
        headers=_headers_for_account(2000000),
        json={"ip": actor.source_ip, "status": "BLOCKED", "updated_ts": 1},
    )
    assert other_resp.status_code == 404


@pytest.mark.asyncio
async def test_agentic_sessions_are_tenant_scoped(client):
    update_resp = await client.post(
        "/api/threat-detection/sessions/bulk-update",
        headers=_headers_for_account(1000000),
        json={
            "session_documents": [
                {
                    "session_identifier": "tenant-a-session",
                    "session_summary": "tenant a",
                    "conversation_info": [],
                    "is_malicious": True,
                    "blocked_reason": "test",
                    "created_at": 1,
                    "updated_at": 2,
                }
            ]
        },
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["updated_count"] == 1

    own_list = await client.get(
        "/api/threat-detection/sessions",
        headers=_headers_for_account(1000000),
    )
    assert own_list.status_code == 200
    assert any(item["session_identifier"] == "tenant-a-session" for item in own_list.json()["sessions"])

    other_list = await client.get(
        "/api/threat-detection/sessions",
        headers=_headers_for_account(2000000),
    )
    assert other_list.status_code == 200
    assert all(item["session_identifier"] != "tenant-a-session" for item in other_list.json()["sessions"])


@pytest.mark.asyncio
async def test_bola_vulnerabilities_are_tenant_scoped(client, db_session):
    vulnerability = Vulnerability(
        id=str(uuid.uuid4()),
        account_id=1000000,
        endpoint_id="tenant-a-endpoint",
        url="/api/orders/123",
        method="GET",
        severity="HIGH",
        type="BOLA",
        description="Tenant A BOLA finding",
        status="OPEN",
        confidence="HIGH",
    )
    db_session.add(vulnerability)
    await db_session.commit()

    own_resp = await client.get(
        "/api/bola/vulnerabilities",
        headers=_headers_for_account(1000000),
    )
    assert own_resp.status_code == 200
    assert any(item["id"] == vulnerability.id for item in own_resp.json())

    other_resp = await client.get(
        "/api/bola/vulnerabilities",
        headers=_headers_for_account(2000000),
    )
    assert other_resp.status_code == 200
    assert all(item["id"] != vulnerability.id for item in other_resp.json())
