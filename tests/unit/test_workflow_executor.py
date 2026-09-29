import uuid

import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.test_executor.target_guard import TargetGuard
import server.modules.workflows.executor as workflow_executor_module
from server.modules.workflows.executor import WorkflowExecutor


class _WorkflowResponse:
    def __init__(self, *, status_code=200, body=None, text=None):
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}
        self._body = body if body is not None else {"ok": True}
        self.text = text if text is not None else '{"ok":true}'

    @property
    def is_success(self):
        return 200 <= self.status_code < 300

    def json(self):
        return self._body


class _WorkflowClient:
    calls = []
    init_kwargs = []

    def __init__(self, *args, **kwargs):
        self.init_kwargs.append(kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, method, url, headers=None, json=None, content=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "json": json,
                "content": content,
            }
        )
        if url.endswith("/login"):
            return _WorkflowResponse(
                body={"access_token": "raw-workflow-token", "next": "/me"},
                text='{"access_token":"raw-workflow-token","next":"/me"}',
            )
        return _WorkflowResponse(
            body={"ok": True, "echo_token": "raw-workflow-token"},
            text='{"ok":true,"echo_token":"raw-workflow-token"}',
        )


@pytest.mark.asyncio
async def test_workflow_executor_blocks_metadata_target_before_request(monkeypatch):
    _WorkflowClient.calls = []
    monkeypatch.setattr(workflow_executor_module.httpx, "AsyncClient", _WorkflowClient)

    result = await WorkflowExecutor(
        target_guard=TargetGuard(allow_private_targets=False)
    ).run([
        {
            "name": "metadata",
            "method": "GET",
            "url": "http://169.254.169.254/latest/meta-data?token=raw-token",
        }
    ])

    assert _WorkflowClient.calls == []
    assert result["status"] == "FAILED"
    assert result["step_results"][0]["skip_reason"] == "target_guard"
    assert result["step_results"][0]["url"].endswith("token=****")
    assert result["step_results"][0]["target_guard_policy"]["policy"] == "target_guard"
    assert result["step_results"][0]["target_guard_policy"]["blocked"] is True
    assert result["step_results"][0]["target_guard_policy"]["url"] == (
        "http://169.254.169.254/latest/meta-data?token=****"
    )
    assert "metadata" in result["step_results"][0]["target_guard_policy"]["reason"]
    assert result["error"].startswith("Step 1 failed: target_guard_blocked:")
    assert "raw-token" not in str(result)


@pytest.mark.asyncio
async def test_workflow_executor_blocks_state_change_by_default(monkeypatch):
    _WorkflowClient.calls = []
    monkeypatch.setattr(workflow_executor_module.httpx, "AsyncClient", _WorkflowClient)

    result = await WorkflowExecutor(
        target_guard=TargetGuard(allowlist=["api.example.com"], allow_private_targets=False)
    ).run([
        {
            "name": "create order",
            "method": "POST",
            "url": "https://api.example.com/orders",
        }
    ])

    assert _WorkflowClient.calls == []
    assert result["status"] == "FAILED"
    assert result["step_results"][0]["skip_reason"] == "state_change_guard"
    assert result["step_results"][0]["error"].startswith("state_change_blocked:")
    assert result["step_results"][0]["state_change_policy"] == {
        "policy": "state_change_guard",
        "blocked": True,
        "method": "POST",
        "effective_method": "POST",
        "safe_method": False,
        "destructive_method": True,
        "allow_state_change": False,
        "allow_destructive_methods": False,
        "reason": "state_change_blocked: POST requires pentest profile allow_state_change=true",
    }


@pytest.mark.asyncio
async def test_workflow_executor_requires_profile_level_destructive_opt_in(monkeypatch):
    _WorkflowClient.calls = []
    monkeypatch.setattr(workflow_executor_module.httpx, "AsyncClient", _WorkflowClient)

    result = await WorkflowExecutor(
        target_guard=TargetGuard(allowlist=["api.example.com"], allow_private_targets=False),
        allow_state_change=True,
        allow_destructive_methods=False,
    ).run([
        {
            "name": "delete order",
            "method": "DELETE",
            "url": "https://api.example.com/orders/1?token=raw-token",
            "allow_state_change": True,
            "allow_destructive_methods": True,
        }
    ])

    assert _WorkflowClient.calls == []
    assert result["status"] == "FAILED"
    assert result["step_results"][0]["skip_reason"] == "state_change_guard"
    assert result["step_results"][0]["error"].startswith("destructive_method_blocked:")
    assert result["step_results"][0]["url"].endswith("token=****")
    assert result["step_results"][0]["state_change_policy"]["allow_state_change"] is True
    assert result["step_results"][0]["state_change_policy"]["allow_destructive_methods"] is False
    assert "raw-token" not in str(result)


@pytest.mark.asyncio
async def test_workflow_executor_allows_destructive_step_when_fully_armed(monkeypatch):
    _WorkflowClient.calls = []
    monkeypatch.setattr(workflow_executor_module.httpx, "AsyncClient", _WorkflowClient)

    result = await WorkflowExecutor(
        target_guard=TargetGuard(allowlist=["api.example.com"], allow_private_targets=False),
        allow_state_change=True,
        allow_destructive_methods=True,
    ).run([
        {
            "name": "delete order",
            "method": "DELETE",
            "url": "https://api.example.com/orders/1?token=raw-token",
            "allow_state_change": True,
            "allow_destructive_methods": True,
        }
    ])

    assert result["status"] == "COMPLETED"
    assert _WorkflowClient.calls[0]["method"] == "DELETE"
    assert _WorkflowClient.calls[0]["url"].endswith("token=raw-token")
    assert result["step_results"][0]["url"].endswith("token=****")
    assert "raw-token" not in str(result)


@pytest.mark.asyncio
async def test_workflow_executor_redacts_response_variables_and_urls(monkeypatch):
    _WorkflowClient.calls = []
    _WorkflowClient.init_kwargs = []
    monkeypatch.setattr(workflow_executor_module.httpx, "AsyncClient", _WorkflowClient)

    result = await WorkflowExecutor(
        target_guard=TargetGuard(allowlist=["api.example.com"], allow_private_targets=False)
    ).run([
        {
            "name": "login",
            "method": "GET",
            "url": "https://api.example.com/login",
            "extract": {"access_token": "access_token"},
            "stop_on_failure": True,
        },
        {
            "name": "profile",
            "method": "GET",
            "url": "https://api.example.com/me?session={{access_token}}",
        },
    ], auth_headers={"Authorization": "Bearer runtime-profile-token"})

    assert result["status"] == "COMPLETED"
    assert _WorkflowClient.init_kwargs[0]["verify"] is True
    assert _WorkflowClient.init_kwargs[0]["follow_redirects"] is False
    assert _WorkflowClient.calls[1]["headers"]["Authorization"] == "Bearer runtime-profile-token"
    assert _WorkflowClient.calls[1]["url"].endswith("session=raw-workflow-token")
    assert result["variables"] == {"access_token": "****"}
    assert result["step_results"][0]["response_body"]["access_token"] == "****"
    assert result["step_results"][1]["url"].endswith("session=****")
    assert result["step_results"][1]["response_body"]["echo_token"] == "****"
    assert "raw-workflow-token" not in str(result)


@pytest.mark.asyncio
async def test_workflow_execute_honors_kill_switch_before_run_creation(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    workflow = models.APIWorkflow(
        id=str(uuid.uuid4()),
        account_id=1000000,
        name="Kill switch workflow",
        description="should not execute",
        steps=[{"method": "GET", "url": "https://api.example.com/health"}],
        enabled=True,
    )
    db_session.add(workflow)
    await db_session.commit()

    monkeypatch.setattr("server.modules.test_executor.kill_switch.settings.PENTEST_KILL_SWITCH_ENABLED", True)

    response = await client.post(
        f"/api/workflows/{workflow.id}/execute",
        headers=auth_headers,
        json={},
    )

    assert response.status_code == 503
    assert response.json()["message"] == "pentest_kill_switch_enabled"
    runs = (
        await db_session.execute(
            select(models.APIWorkflowRun).where(models.APIWorkflowRun.workflow_id == workflow.id)
        )
    ).scalars().all()
    assert runs == []
