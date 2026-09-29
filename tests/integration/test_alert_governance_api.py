import uuid

import pytest
from sqlalchemy import select

from server.api.routers import alerts as alerts_router
from server.models.core import Alert
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
async def test_alert_create_requires_manage_permission_and_redacts_storage_and_fanout(
    client,
    db_session,
    monkeypatch,
):
    account_id = 9406001
    raw_token = "alert-create-token"
    raw_password = "alert-create-password"
    captured = {}

    async def fake_dispatch_event(event_type, event_payload, dispatched_account_id, db):
        captured["dispatch"] = {
            "event_type": event_type,
            "payload": event_payload,
            "account_id": dispatched_account_id,
        }

    async def fake_execute_playbooks(db, alert, evidence):
        captured["playbook"] = {
            "title": alert.title,
            "message": alert.message,
            "endpoint": alert.endpoint,
            "evidence": evidence,
        }
        return []

    monkeypatch.setattr(alerts_router, "dispatch_event", fake_dispatch_event)
    monkeypatch.setattr(alerts_router, "execute_playbooks", fake_execute_playbooks)

    body = {
        "title": f"Authorization: Bearer {raw_token}",
        "message": f"token={raw_token} password={raw_password}",
        "severity": "HIGH",
        "category": "AUTH",
        "source_ip": "198.51.100.10",
        "endpoint": f"https://api.example.com/admin?token={raw_token}",
    }

    member_response = await client.post(
        "/api/alerts/",
        headers=_headers_for_role("MEMBER", account_id),
        json=body,
    )
    assert member_response.status_code == 403

    security_response = await client.post(
        "/api/alerts/",
        headers=_headers_for_role("SECURITY_ENGINEER", account_id),
        json=body,
    )
    assert security_response.status_code == 200
    response_body = security_response.json()
    assert raw_token not in str(response_body)
    assert raw_password not in str(response_body)
    assert "Bearer ****" in str(response_body)

    row = (
        await db_session.execute(
            select(Alert).where(
                Alert.account_id == account_id,
                Alert.id == response_body["id"],
            )
        )
    ).scalar_one()
    stored_blob = str(
        {
            "title": row.title,
            "message": row.message,
            "endpoint": row.endpoint,
            "dispatch": captured["dispatch"],
            "playbook": captured["playbook"],
        }
    )
    assert raw_token not in stored_blob
    assert raw_password not in stored_blob
    assert "Bearer ****" in stored_blob
    assert "token=****" in stored_blob


@pytest.mark.asyncio
async def test_alert_list_redacts_legacy_plaintext_rows(client, db_session):
    account_id = 9406002
    raw_token = "alert-legacy-token"
    raw_password = "alert-legacy-password"
    alert = Alert(
        id=str(uuid.uuid4()),
        account_id=account_id,
        title=f"Authorization: Bearer {raw_token}",
        message=f"token={raw_token} password={raw_password}",
        severity="HIGH",
        category="AUTH",
        source_ip="198.51.100.22",
        endpoint=f"https://api.example.com/orders?token={raw_token}",
        status="ACKNOWLEDGED",
        acknowledged_by=f"analyst-token={raw_token}",
    )
    db_session.add(alert)
    await db_session.commit()

    response = await client.get(
        "/api/alerts/",
        headers=_headers_for_role("MEMBER", account_id),
    )
    assert response.status_code == 200
    body = response.json()
    assert any(row["id"] == alert.id for row in body)
    assert raw_token not in str(body)
    assert raw_password not in str(body)
    assert "Bearer ****" in str(body)
    assert "token=****" in str(body)

    summary_response = await client.get(
        "/api/alerts/summary",
        headers=_headers_for_role("MEMBER", account_id),
    )
    assert summary_response.status_code == 200
    assert summary_response.json()["acknowledged"] >= 1


@pytest.mark.asyncio
async def test_alert_acknowledge_redacts_actor_identity(client, db_session):
    account_id = 9406003
    raw_token = "alert-ack-token"
    alert = Alert(
        id=str(uuid.uuid4()),
        account_id=account_id,
        title="Ack target",
        severity="MEDIUM",
        status="OPEN",
    )
    db_session.add(alert)
    await db_session.commit()

    member_response = await client.patch(
        f"/api/alerts/{alert.id}/acknowledge?by=Authorization:%20Bearer%20{raw_token}",
        headers=_headers_for_role("MEMBER", account_id),
    )
    assert member_response.status_code == 403

    response = await client.patch(
        f"/api/alerts/{alert.id}/acknowledge?by=Authorization:%20Bearer%20{raw_token}",
        headers=_headers_for_role("SECURITY_ENGINEER", account_id),
    )
    assert response.status_code == 200

    await db_session.refresh(alert)
    assert raw_token not in (alert.acknowledged_by or "")
    assert alert.acknowledged_by == "Authorization: Bearer ****"

    list_response = await client.get(
        "/api/alerts/",
        headers=_headers_for_role("MEMBER", account_id),
    )
    assert list_response.status_code == 200
    assert raw_token not in str(list_response.json())
