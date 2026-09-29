import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.auth.jwt_issuer import JWTIssuer
from server.modules.integrations.dispatcher import dispatch_event
from server.modules.integrations.secrets import IntegrationSecretCodec


def _headers_for_role(role: str, account_id: int = 1000000):
    token = JWTIssuer.create_access_token({
        "sub": f"{role.lower()}-user",
        "email": f"{role.lower()}@example.com",
        "account_id": account_id,
        "role": role,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_create_integration_encrypts_config_at_rest(client, db_session, auth_headers):
    response = await client.post(
        "/api/integrations/",
        headers=auth_headers,
        json={
            "type": "jira",
            "name": "Jira Security",
            "config": {
                "base_url": "https://jira.example.com",
                "email": "sec@example.com",
                "api_token": "jira-token",
                "project_key": "API",
            },
            "events": ["vulnerability_found"],
        },
    )

    assert response.status_code == 200
    row = (
        await db_session.execute(
            select(models.Integration).where(models.Integration.id == response.json()["id"])
        )
    ).scalar_one()

    assert row.config["api_token"].startswith(IntegrationSecretCodec.PREFIX)
    assert row.config["base_url"].startswith(IntegrationSecretCodec.PREFIX)
    assert "jira-token" not in str(row.config)
    assert IntegrationSecretCodec.runtime_config(row)["api_token"] == "jira-token"

    listed = await client.get("/api/integrations/", headers=auth_headers)
    assert listed.status_code == 200
    assert "jira-token" not in str(listed.json())

    detail = await client.get(f"/api/integrations/{row.id}", headers=auth_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["config_redacted"] is True
    assert body["configured_fields"] == ["api_token", "base_url", "email", "project_key"]
    assert body["config"]["api_token"] == "****"
    assert body["config"]["base_url"] == "****"
    assert "jira-token" not in str(body)
    assert "jira.example.com" not in str(body)


@pytest.mark.asyncio
async def test_member_can_read_but_cannot_write_integration_configs(client, auth_headers):
    create = await client.post(
        "/api/integrations/",
        headers=auth_headers,
        json={
            "type": "webhook",
            "name": "Security Webhook",
            "config": {"url": "https://hooks.example.com/security", "secret": "raw-secret"},
            "events": ["alert.created"],
        },
    )
    assert create.status_code == 200
    integration_id = create.json()["id"]

    member_headers = _headers_for_role("MEMBER")
    readable = await client.get(f"/api/integrations/{integration_id}", headers=member_headers)
    assert readable.status_code == 200
    assert "raw-secret" not in str(readable.json())

    denied = await client.patch(
        f"/api/integrations/{integration_id}",
        headers=member_headers,
        json={"enabled": False},
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_create_integration_blocks_unsafe_destination(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        "server.modules.integrations.destination_guard.settings.DEBUG",
        False,
    )
    monkeypatch.setattr(
        "server.modules.integrations.destination_guard.settings.INTEGRATIONS_ALLOW_PRIVATE_DESTINATIONS",
        False,
    )

    response = await client.post(
        "/api/integrations/",
        headers=auth_headers,
        json={
            "type": "webhook",
            "name": "Unsafe Webhook",
            "config": {"url": "http://169.254.169.254/latest/meta-data", "secret": "raw-secret"},
            "events": ["alert.created"],
        },
    )

    assert response.status_code == 400
    assert response.json()["message"]["message"] == "Integration destination blocked"


@pytest.mark.asyncio
async def test_test_integration_blocks_legacy_unsafe_destination(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    monkeypatch.setattr(
        "server.modules.integrations.destination_guard.settings.DEBUG",
        False,
    )
    monkeypatch.setattr(
        "server.modules.integrations.destination_guard.settings.INTEGRATIONS_ALLOW_PRIVATE_DESTINATIONS",
        False,
    )
    called = {}

    class FakeWebhookClient:
        def __init__(self, *args, **kwargs):
            called["constructed"] = True

        async def send(self, *args, **kwargs):
            called["sent"] = True
            return True

    monkeypatch.setattr("server.api.routers.integrations.WebhookClient", FakeWebhookClient)

    integration = models.Integration(
        account_id=1000000,
        type="webhook",
        name="Legacy Unsafe",
        enabled=True,
        config={"url": "http://127.0.0.1/admin", "secret": "legacy-secret"},
        events=["alert.created"],
    )
    db_session.add(integration)
    await db_session.commit()

    response = await client.post(f"/api/integrations/{integration.id}/test", headers=auth_headers)

    assert response.status_code == 400
    assert response.json()["message"]["message"] == "Integration destination blocked"
    assert called == {}


@pytest.mark.asyncio
async def test_dispatcher_skips_legacy_unsafe_destination(db_session, monkeypatch):
    monkeypatch.setattr(
        "server.modules.integrations.destination_guard.settings.DEBUG",
        False,
    )
    monkeypatch.setattr(
        "server.modules.integrations.destination_guard.settings.INTEGRATIONS_ALLOW_PRIVATE_DESTINATIONS",
        False,
    )
    called = {}

    class FakeWebhookClient:
        def __init__(self, *args, **kwargs):
            called["constructed"] = True

        async def send(self, *args, **kwargs):
            called["sent"] = True
            return True

    monkeypatch.setattr("server.modules.integrations.dispatcher.WebhookClient", FakeWebhookClient)
    integration = models.Integration(
        account_id=1000999,
        type="webhook",
        name="Legacy Unsafe Dispatch",
        enabled=True,
        config={"url": "http://169.254.169.254/latest/meta-data", "secret": "legacy-secret"},
        events=["alert.created"],
    )
    db_session.add(integration)
    await db_session.commit()

    await dispatch_event("alert.created", {"title": "blocked"}, 1000999, db_session)

    assert called == {}


@pytest.mark.asyncio
async def test_integration_test_endpoint_uses_decrypted_runtime_config(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    captured = {}

    class FakeJiraClient:
        def __init__(self, base_url, email, api_token):
            captured["base_url"] = base_url
            captured["email"] = email
            captured["api_token"] = api_token

        async def create_issue(self, project_key, summary, description, issue_type="Bug"):
            captured["project_key"] = project_key
            return "API-123"

    monkeypatch.setattr("server.api.routers.integrations.JiraClient", FakeJiraClient)

    integration = models.Integration(
        account_id=1000000,
        type="jira",
        name="Jira Security",
        enabled=True,
        config=IntegrationSecretCodec.encrypt_config(
            {
                "base_url": "https://jira.example.com",
                "email": "sec@example.com",
                "api_token": "jira-token",
                "project_key": "API",
            }
        ),
        events=["vulnerability_found"],
    )
    db_session.add(integration)
    await db_session.commit()

    response = await client.post(f"/api/integrations/{integration.id}/test", headers=auth_headers)

    assert response.status_code == 200
    assert captured == {
        "base_url": "https://jira.example.com",
        "email": "sec@example.com",
        "api_token": "jira-token",
        "project_key": "API",
    }


@pytest.mark.asyncio
async def test_integration_dispatcher_uses_decrypted_config(db_session, monkeypatch):
    captured = {}

    class FakeSlackClient:
        def __init__(self, webhook_url):
            captured["webhook_url"] = webhook_url

        async def send_alert(self, title, description, severity):
            captured["title"] = title
            captured["severity"] = severity
            return True

    monkeypatch.setattr("server.modules.integrations.dispatcher.SlackClient", FakeSlackClient)
    integration = models.Integration(
        account_id=1000000,
        type="slack",
        name="Slack Security",
        enabled=True,
        config=IntegrationSecretCodec.encrypt_config(
            {"webhook_url": "https://hooks.example.com/raw-webhook-secret"}
        ),
        events=["vulnerability_found"],
    )
    db_session.add(integration)
    await db_session.commit()

    await dispatch_event(
        "vulnerability_found",
        {"type": "BOLA", "description": "confirmed", "severity": "HIGH"},
        1000000,
        db_session,
    )

    assert captured == {
        "webhook_url": "https://hooks.example.com/raw-webhook-secret",
        "title": "BOLA",
        "severity": "HIGH",
    }
