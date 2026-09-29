import pytest
from sqlalchemy import select

from server.models.core import Alert, Integration, ResponseActionLog, ResponsePlaybook
from server.modules.integrations.secrets import IntegrationSecretCodec
from server.modules.response.playbook_executor import execute_playbooks
from server.modules.response.playbook_secrets import PlaybookActionSecretCodec


@pytest.mark.asyncio
async def test_execute_playbooks_logs_actions(db_session):
    account_id = 1000703
    playbook = ResponsePlaybook(
        id="pb-1",
        account_id=account_id,
        name="Test Playbook",
        trigger="alert.created",
        severity_threshold="LOW",
        enabled=True,
        actions=[{"type": "RATE_LIMIT_OVERRIDE"}],
    )
    alert = Alert(
        id="alert-1",
        account_id=account_id,
        title="Test Alert",
        message="Test",
        severity="HIGH",
        category="TEST",
        source_ip="1.2.3.4",
        endpoint="/test",
    )
    db_session.add(playbook)
    db_session.add(alert)
    await db_session.commit()

    logs = await execute_playbooks(db_session, alert, evidence={"source_ips": ["1.2.3.4"]})
    await db_session.commit()

    assert logs
    result = await db_session.execute(select(ResponseActionLog).where(ResponseActionLog.alert_id == "alert-1"))
    rows = result.scalars().all()
    assert rows
    assert rows[0].status in {"SKIPPED", "SUCCESS"}


@pytest.mark.asyncio
async def test_execute_playbooks_decrypts_stored_integration_config(db_session, monkeypatch):
    captured = {}
    account_id = 1000601

    class FakeJiraClient:
        def __init__(self, base_url, email, api_token):
            captured["base_url"] = base_url
            captured["email"] = email
            captured["api_token"] = api_token

        async def create_issue(self, project_key, summary, description, issue_type="Bug"):
            captured["project_key"] = project_key
            captured["issue_type"] = issue_type
            return "API-456"

    monkeypatch.setattr("server.modules.response.playbook_executor.JiraClient", FakeJiraClient)

    integration = Integration(
        account_id=account_id,
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
    )
    playbook = ResponsePlaybook(
        id="pb-ticket",
        account_id=account_id,
        name="Ticket Playbook",
        trigger="alert.created",
        severity_threshold="LOW",
        enabled=True,
        actions=[{"type": "CREATE_TICKET", "system": "jira"}],
    )
    alert = Alert(
        id="alert-ticket",
        account_id=account_id,
        title="Confirmed API Finding",
        message="Confirmed authorization issue",
        severity="HIGH",
        category="TEST",
        endpoint="/admin",
    )
    db_session.add_all([integration, playbook, alert])
    await db_session.commit()

    logs = await execute_playbooks(db_session, alert)

    assert logs[0].status == "SUCCESS"
    assert logs[0].details["ticket"] == "API-456"
    assert captured == {
        "base_url": "https://jira.example.com",
        "email": "sec@example.com",
        "api_token": "jira-token",
        "project_key": "API",
        "issue_type": "Task",
    }


@pytest.mark.asyncio
async def test_execute_playbooks_decrypts_stored_webhook_action_secrets(db_session, monkeypatch):
    captured = {}
    account_id = 1000602

    class FakeWebhookClient:
        def __init__(self, url, secret=None, method="POST"):
            captured["url"] = url
            captured["secret"] = secret

        async def send(self, payload, event_type=None):
            captured["payload"] = payload
            captured["event_type"] = event_type
            return True

    monkeypatch.setattr("server.modules.response.playbook_executor.WebhookClient", FakeWebhookClient)

    playbook = ResponsePlaybook(
        id="pb-webhook",
        account_id=account_id,
        name="Webhook Playbook",
        trigger="alert.created",
        severity_threshold="LOW",
        enabled=True,
        actions=PlaybookActionSecretCodec.encrypt_actions(
            [
                {
                    "type": "WEBHOOK",
                    "url": "https://hooks.example.com/raw-webhook-secret",
                    "secret": "signing-secret",
                }
            ]
        ),
    )
    alert = Alert(
        id="alert-webhook",
        account_id=account_id,
        title="Confirmed API Finding",
        message="Confirmed authorization issue",
        severity="HIGH",
        category="TEST",
        endpoint="/admin",
    )
    db_session.add_all([playbook, alert])
    await db_session.commit()

    logs = await execute_playbooks(db_session, alert, evidence={"safe": True})

    assert logs[0].status == "SUCCESS"
    assert captured["url"] == "https://hooks.example.com/raw-webhook-secret"
    assert captured["secret"] == "signing-secret"
    assert captured["event_type"] == "alert.playbook"
