import uuid

import pytest
from sqlalchemy import select

from server.models.core import MaliciousEventRecord, ThreatActor
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
async def test_member_can_read_legacy_threat_events_without_plaintext_url_secrets(client, db_session):
    account_id = 9305001
    raw_token = "legacy-threat-actor-token"
    actor = ThreatActor(
        account_id=account_id,
        source_ip="198.51.100.41",
        status="MONITORING",
        event_count=1,
        risk_score=0.4,
    )
    record = MaliciousEventRecord(
        account_id=account_id,
        actor=actor.source_ip,
        ip=actor.source_ip,
        url=f"https://api.example.com/admin?token={raw_token}",
        method="GET",
        event_type="AUTH_BYPASS",
        category="AUTH",
        severity="HIGH",
        detected_at=1710000000000,
        status="OPEN",
    )
    db_session.add_all([actor, record])
    await db_session.commit()

    response = await client.get(
        "/api/threat-actors/events",
        headers=_headers_for_role("MEMBER", account_id),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    assert raw_token not in str(body)
    assert "token=****" in str(body)


@pytest.mark.asyncio
async def test_legacy_threat_event_ingest_requires_manage_and_redacts_storage(client, db_session):
    account_id = 9305002
    raw_token = "legacy-ingest-token"
    source_ip = f"203.0.113.{uuid.uuid4().int % 200 + 1}"
    payload = {
        "source_ip": source_ip,
        "event_type": "AUTH_BYPASS",
        "severity": "HIGH",
        "url": f"https://api.example.com/orders?token={raw_token}",
        "method": "POST",
    }

    member_response = await client.post(
        "/api/threat-actors/events",
        headers=_headers_for_role("MEMBER", account_id),
        json=payload,
    )
    assert member_response.status_code == 403

    developer_response = await client.post(
        "/api/threat-actors/events",
        headers=_headers_for_role("DEVELOPER", account_id),
        json=payload,
    )
    assert developer_response.status_code == 200
    record_id = developer_response.json()["record_id"]

    record = (
        await db_session.execute(
            select(MaliciousEventRecord).where(
                MaliciousEventRecord.account_id == account_id,
                MaliciousEventRecord.id == record_id,
            )
        )
    ).scalar_one()
    assert raw_token not in (record.url or "")
    assert record.url == "https://api.example.com/orders?token=****"

    list_response = await client.get(
        "/api/threat-actors/events",
        headers=_headers_for_role("MEMBER", account_id),
    )
    assert list_response.status_code == 200
    assert raw_token not in str(list_response.json())


@pytest.mark.asyncio
async def test_legacy_threat_actor_status_changes_require_vulnerability_management(client, db_session):
    account_id = 9305003
    actor = ThreatActor(
        account_id=account_id,
        source_ip="198.51.100.88",
        status="MONITORING",
        event_count=1,
        risk_score=0.7,
    )
    db_session.add(actor)
    await db_session.commit()

    member_response = await client.post(
        f"/api/threat-actors/{actor.source_ip}/block",
        headers=_headers_for_role("MEMBER", account_id),
    )
    assert member_response.status_code == 403

    security_response = await client.post(
        f"/api/threat-actors/{actor.source_ip}/block",
        headers=_headers_for_role("SECURITY_ENGINEER", account_id),
    )
    assert security_response.status_code == 200

    await db_session.refresh(actor)
    assert actor.status == "BLOCKED"
