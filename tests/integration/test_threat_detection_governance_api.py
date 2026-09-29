import json
import uuid

import pytest
from sqlalchemy import select

from server.models.core import AgenticSession, MaliciousEventRecord
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


def _secret_blob(rows) -> str:
    return json.dumps(
        [
            {
                "url": row.url,
                "payload": row.payload,
                "jira_ticket_url": getattr(row, "jira_ticket_url", None),
                "event_metadata": row.event_metadata,
            }
            for row in rows
        ],
        default=str,
    )


@pytest.mark.asyncio
async def test_record_malicious_event_requires_manage_permission_and_redacts_storage(client, db_session):
    account_id = 9103001
    filter_id = f"secret-filter-{uuid.uuid4()}"
    raw_token = "record-raw-token"
    raw_password = "record-raw-password"
    payload = {
        "malicious_event": {
            "actor": "198.51.100.55",
            "filter_id": filter_id,
            "detected_at": 1710000000000,
            "latest_api_ip": "198.51.100.55",
            "latest_api_endpoint": f"https://api.example.com/admin?token={raw_token}",
            "latest_api_method": "POST",
            "latest_api_payload": f"Authorization: Bearer {raw_token} password={raw_password}",
            "event_type": "EVENT_TYPE_SINGLE",
            "category": "AUTH",
            "sub_category": "BROKEN_AUTH",
            "severity": "HIGH",
            "type": "API_ATTACK",
            "metadata": {"reason": f"token={raw_token}"},
        },
        "sample_requests": [
            {
                "ip": "198.51.100.55",
                "timestamp": 1710000000001,
                "url": f"/admin?token={raw_token}",
                "method": "POST",
                "payload": f"api_key={raw_token}",
                "filter_id": filter_id,
                "metadata": {"reason": f"secret={raw_password}"},
            }
        ],
    }

    member_resp = await client.post(
        "/api/threat-detection/record",
        headers=_headers_for_role("MEMBER", account_id),
        json=payload,
    )
    assert member_resp.status_code == 403

    security_resp = await client.post(
        "/api/threat-detection/record",
        headers=_headers_for_role("SECURITY_ENGINEER", account_id),
        json=payload,
    )
    assert security_resp.status_code == 200

    result = await db_session.execute(
        select(MaliciousEventRecord).where(
            MaliciousEventRecord.account_id == account_id,
            MaliciousEventRecord.filter_id == filter_id,
        )
    )
    records = result.scalars().all()
    assert len(records) == 2
    blob = _secret_blob(records)
    assert raw_token not in blob
    assert raw_password not in blob
    assert "****" in blob


@pytest.mark.asyncio
async def test_threat_event_reads_redact_legacy_plaintext_evidence(client, db_session):
    account_id = 9103002
    actor = "203.0.113.77"
    filter_id = f"legacy-filter-{uuid.uuid4()}"
    raw_token = "legacy-threat-token"
    record = MaliciousEventRecord(
        account_id=account_id,
        actor=actor,
        filter_id=filter_id,
        detected_at=1710000000000,
        ip=actor,
        url=f"https://api.example.com/orders?token={raw_token}",
        method="GET",
        payload=f"Authorization: Bearer {raw_token}",
        event_type="EVENT_TYPE_SINGLE",
        category="AUTH",
        sub_category="BOLA",
        severity="HIGH",
        type="API_ATTACK",
        status="OPEN",
        jira_ticket_url=f"https://jira.example.com/browse/API-1?token={raw_token}",
        event_metadata={"reason": f"secret={raw_token}"},
    )
    db_session.add(record)
    await db_session.commit()

    headers = _headers_for_role("MEMBER", account_id)
    list_resp = await client.post(
        "/api/threat-detection/events",
        headers=headers,
        json={"filter": {"actors": [actor]}, "limit": 10},
    )
    assert list_resp.status_code == 200
    list_body = list_resp.json()
    assert list_body["total"] >= 1
    assert raw_token not in str(list_body)
    assert "Bearer ****" in str(list_body)
    assert "token=****" in str(list_body)

    fetch_resp = await client.post(
        "/api/threat-detection/events/fetch",
        headers=headers,
        json={"actor": actor, "filter_id": filter_id},
    )
    assert fetch_resp.status_code == 200
    fetch_body = fetch_resp.json()
    assert raw_token not in str(fetch_body)
    assert "Bearer ****" in str(fetch_body)

    actor_resp = await client.post(
        "/api/threat-detection/actors/threats",
        headers=headers,
        json={"actor": actor, "limit": 5},
    )
    assert actor_resp.status_code == 200
    assert raw_token not in str(actor_resp.json())


@pytest.mark.asyncio
async def test_agentic_session_updates_redact_prompt_response_and_reason(client, db_session):
    account_id = 9103003
    session_id = f"agentic-session-{uuid.uuid4()}"
    raw_token = "agentic-session-token"
    raw_secret = "agentic-block-secret"
    payload = {
        "session_documents": [
            {
                "session_identifier": session_id,
                "session_summary": f"Authorization: Bearer {raw_token}",
                "conversation_info": [
                    {
                        "request_id": "req-1",
                        "request_payload": f"Authorization: Bearer {raw_token}",
                        "response_payload": json.dumps({"access_token": raw_token}),
                        "timestamp": 1710000000000,
                    }
                ],
                "is_malicious": True,
                "blocked_reason": f"secret={raw_secret}",
                "created_at": 1710000000000,
                "updated_at": 1710000000001,
            }
        ]
    }

    denied_resp = await client.post(
        "/api/threat-detection/sessions/bulk-update",
        headers=_headers_for_role("MEMBER", account_id),
        json=payload,
    )
    assert denied_resp.status_code == 403

    update_resp = await client.post(
        "/api/threat-detection/sessions/bulk-update",
        headers=_headers_for_role("DEVELOPER", account_id),
        json=payload,
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["updated_count"] == 1

    result = await db_session.execute(
        select(AgenticSession).where(
            AgenticSession.account_id == account_id,
            AgenticSession.session_identifier == session_id,
        )
    )
    row = result.scalar_one()
    stored_blob = json.dumps(
        {
            "session_summary": row.session_summary,
            "conversation_info": row.conversation_info,
            "blocked_reason": row.blocked_reason,
        },
        default=str,
    )
    assert raw_token not in stored_blob
    assert raw_secret not in stored_blob
    assert "****" in stored_blob

    list_resp = await client.get(
        "/api/threat-detection/sessions",
        headers=_headers_for_role("MEMBER", account_id),
    )
    assert list_resp.status_code == 200
    body = list_resp.json()
    assert raw_token not in str(body)
    assert raw_secret not in str(body)
    assert "****" in str(body)
