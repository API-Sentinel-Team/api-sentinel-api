import uuid

import pytest
from sqlalchemy import select

import server.modules.workflows.executor as workflow_executor
from server.models.core import APIWorkflowRun


class _FakeResponse:
    status_code = 200
    text = '{"ok": true}'
    headers = {}
    is_success = True

    def json(self):
        return {"ok": True}


class _FakeAsyncClient:
    calls = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def request(self, method, url, headers=None, json=None, content=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers or {}),
                "json": json,
                "content": content,
            }
        )
        return _FakeResponse()


async def _create_workflow(client, auth_headers, *, url="https://workflow-safe.example.com/me"):
    response = await client.post(
        "/api/workflows/",
        headers=auth_headers,
        json={
            "name": "Workflow auth safety",
            "description": "auth scoped workflow",
            "steps": [
                {
                    "name": "profile request",
                    "method": "GET",
                    "url": url,
                    "assert": {"status_code": 200},
                }
            ],
        },
    )
    assert response.status_code == 200
    return response.json()["id"]


async def _create_auth_profile(client, auth_headers, *, scope_domain="workflow-safe.example.com"):
    response = await client.post(
        "/api/pentest/auth-profiles",
        headers=auth_headers,
        json={
            "name": f"Workflow bearer {scope_domain} {uuid.uuid4()}",
            "auth_mode": "bearer",
            "token": "raw-workflow-token",
            "header_name": "Authorization",
            "scope_domains": [scope_domain],
        },
    )
    assert response.status_code == 200
    return response.json()["profile"]["id"]


@pytest.mark.asyncio
async def test_workflow_execute_rejects_inline_plaintext_auth_headers(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(workflow_executor.httpx, "AsyncClient", _FakeAsyncClient)
    workflow_id = await _create_workflow(client, auth_headers)

    response = await client.post(
        f"/api/workflows/{workflow_id}/execute",
        headers=auth_headers,
        json={"auth_headers": {"Authorization": "Bearer raw-workflow-token"}},
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "plaintext_auth_headers_not_allowed"
    assert "raw-workflow-token" not in str(message)
    assert _FakeAsyncClient.calls == []
    runs = (
        await db_session.execute(select(APIWorkflowRun).where(APIWorkflowRun.workflow_id == workflow_id))
    ).scalars().all()
    assert runs == []


@pytest.mark.asyncio
async def test_workflow_execute_uses_stored_auth_profile_without_persisting_secret(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(workflow_executor.httpx, "AsyncClient", _FakeAsyncClient)
    workflow_id = await _create_workflow(client, auth_headers)
    auth_profile_id = await _create_auth_profile(client, auth_headers)

    response = await client.post(
        f"/api/workflows/{workflow_id}/execute",
        headers=auth_headers,
        json={"auth_profile_id": auth_profile_id},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "COMPLETED"
    assert _FakeAsyncClient.calls[0]["headers"]["Authorization"] == "Bearer raw-workflow-token"
    assert "raw-workflow-token" not in str(payload)
    run = (
        await db_session.execute(select(APIWorkflowRun).where(APIWorkflowRun.workflow_id == workflow_id))
    ).scalar_one()
    assert "raw-workflow-token" not in str(run.step_results)
    assert "raw-workflow-token" not in str(run.variables)


@pytest.mark.asyncio
async def test_workflow_execute_blocks_auth_profile_scope_mismatch_before_request(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(workflow_executor.httpx, "AsyncClient", _FakeAsyncClient)
    workflow_id = await _create_workflow(
        client,
        auth_headers,
        url="https://outside-workflow.example.com/me",
    )
    auth_profile_id = await _create_auth_profile(
        client,
        auth_headers,
        scope_domain="workflow-safe.example.com",
    )

    response = await client.post(
        f"/api/workflows/{workflow_id}/execute",
        headers=auth_headers,
        json={"auth_profile_id": auth_profile_id},
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "auth_profile_scope_blocked"
    assert message["auth_profile_scope_policy"]["policy"] == "auth_profile_scope_guard"
    assert _FakeAsyncClient.calls == []
    runs = (
        await db_session.execute(select(APIWorkflowRun).where(APIWorkflowRun.workflow_id == workflow_id))
    ).scalars().all()
    assert runs == []
