import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.auth.jwt_issuer import JWTIssuer
from server.modules.integrations.secrets import IntegrationSecretCodec
from server.modules.response.playbook_secrets import PlaybookActionSecretCodec


def _headers_for_role(role: str, account_id: int = 1000000):
    token = JWTIssuer.create_access_token({
        "sub": f"{role.lower()}-user",
        "email": f"{role.lower()}@example.com",
        "account_id": account_id,
        "role": role,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_create_playbook_encrypts_and_redacts_action_secrets(client, db_session, auth_headers):
    response = await client.post(
        "/api/playbooks/",
        headers=auth_headers,
        json={
            "name": "Webhook response",
            "trigger": "alert.created",
            "severity_threshold": "HIGH",
            "actions": [
                {
                    "type": "WEBHOOK",
                    "url": "https://hooks.example.com/raw-webhook-secret",
                    "secret": "signing-secret",
                }
            ],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert "raw-webhook-secret" not in str(body)
    assert "signing-secret" not in str(body)
    action = body["playbook"]["actions"][0]
    assert action["url"] == "****"
    assert action["secret"] == "****"

    row = (
        await db_session.execute(
            select(models.ResponsePlaybook).where(models.ResponsePlaybook.id == body["id"])
        )
    ).scalar_one()
    assert row.actions[0]["url"].startswith(IntegrationSecretCodec.PREFIX)
    assert row.actions[0]["secret"].startswith(IntegrationSecretCodec.PREFIX)
    assert "raw-webhook-secret" not in str(row.actions)
    assert "signing-secret" not in str(row.actions)
    assert PlaybookActionSecretCodec.decrypt_actions(row.actions)[0]["secret"] == "signing-secret"

    member_read = await client.get(f"/api/playbooks/{row.id}", headers=_headers_for_role("MEMBER"))
    assert member_read.status_code == 200
    assert "raw-webhook-secret" not in str(member_read.json())
    assert "signing-secret" not in str(member_read.json())


@pytest.mark.asyncio
async def test_member_cannot_create_playbook(client):
    response = await client.post(
        "/api/playbooks/",
        headers=_headers_for_role("MEMBER"),
        json={
            "name": "Denied",
            "trigger": "alert.created",
            "actions": [{"type": "NOTIFY"}],
        },
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_playbook_action_logs_route_redacts_legacy_details(client, db_session, auth_headers):
    log = models.ResponseActionLog(
        account_id=1000000,
        playbook_id="11111111-1111-1111-1111-111111111111",
        alert_id="22222222-2222-2222-2222-222222222222",
        action_type="WEBHOOK",
        status="FAILED",
        details={
            "secret": "legacy-secret",
            "error": "delivery failed token=raw-token",
            "url": "https://hooks.example.com/path?token=raw-token",
        },
    )
    db_session.add(log)
    await db_session.commit()

    response = await client.get("/api/playbooks/actions/logs", headers=auth_headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] >= 1
    assert "legacy-secret" not in str(payload)
    assert "raw-token" not in str(payload)
    redacted = next(item for item in payload["logs"] if item["id"] == log.id)
    assert redacted["details"]["secret"] == "****"
    assert redacted["details"]["url"] == "https://hooks.example.com/path?token=****"


@pytest.mark.asyncio
async def test_create_playbook_blocks_unsafe_webhook_destination(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        "server.modules.integrations.destination_guard.settings.DEBUG",
        False,
    )
    monkeypatch.setattr(
        "server.modules.integrations.destination_guard.settings.INTEGRATIONS_ALLOW_PRIVATE_DESTINATIONS",
        False,
    )

    response = await client.post(
        "/api/playbooks/",
        headers=auth_headers,
        json={
            "name": "Unsafe Webhook",
            "trigger": "alert.created",
            "actions": [
                {
                    "type": "WEBHOOK",
                    "url": "http://169.254.169.254/latest/meta-data",
                    "secret": "signing-secret",
                }
            ],
        },
    )

    assert response.status_code == 400
    assert response.json()["message"]["message"] == "Playbook action destination blocked"
