import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import select

import server.api.routers.suites as suites_router
import server.api.routers.tests as tests_router
from server.models import core as models


class _FakeRequest:
    def __init__(self, body):
        self._body = body
        self.client = type("Client", (), {"host": "127.0.0.1"})()

    async def json(self):
        return self._body


class _FakeSuiteManager:
    def __init__(self, templates):
        self.templates = templates

    def get_suite_templates(self, suite_name):
        return self.templates if suite_name == "safe-api" else []

    def list_suites(self):
        return [{"name": "safe-api", "template_count": len(self.templates)}]


@pytest.mark.asyncio
async def test_run_suite_queues_guarded_scan_with_profile(db_session, monkeypatch):
    account_id = 1002100
    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/suite-users",
    )
    auth_profile = models.AuthProfile(
        account_id=account_id,
        name="suite bearer",
        auth_mode="bearer",
        token="Bearer suite-token",
        scope_domains=["api.example.test"],
        is_active=True,
    )
    db_session.add_all([endpoint, auth_profile])
    await db_session.flush()
    pentest_profile = models.PentestProfile(
        account_id=account_id,
        name="suite authenticated profile",
        auth_profile_id=auth_profile.id,
    )
    db_session.add(pentest_profile)
    await db_session.commit()

    monkeypatch.setattr(suites_router, "_suite_manager", _FakeSuiteManager([
        {"id": "suite-auth-check", "info": {"severity": "LOW"}},
        {"id": "suite-bola-check", "info": {"severity": "HIGH"}},
    ]))
    monkeypatch.setattr(tests_router.settings, "PENTEST_SCAN_EXECUTION_MODE", "queued")

    background_tasks = BackgroundTasks()
    response = await suites_router.run_suite(
        suite_name="safe-api",
        request=_FakeRequest({
            "endpoint_ids": [endpoint.id],
            "pentest_profile_id": pentest_profile.id,
        }),
        background_tasks=background_tasks,
        db=db_session,
        payload={"account_id": account_id, "user_id": "suite-user"},
    )

    assert response["status"] == "scan_queued"
    assert response["suite"] == "safe-api"
    assert response["trigger_source"] == "suite"
    assert response["pentest_profile_id"] == pentest_profile.id
    assert len(background_tasks.tasks) == 0

    stored = await db_session.get(models.TestRun, response["run_id"])
    assert stored.trigger_source == "suite"
    assert stored.template_ids == ["suite-auth-check", "suite-bola-check"]
    assert stored.endpoint_ids == [endpoint.id]
    assert stored.pentest_profile_id == pentest_profile.id

    audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.resource_id == response["run_id"],
                models.AuditLog.action == "SCAN_RUN_QUEUED",
            )
        )
    ).scalar_one()
    assert audit.details["source"] == "suite"
    assert audit.details["suite_name"] == "safe-api"
    assert audit.details["planned_tests"] == 2
    assert audit.details["auth_required"] is True
    assert audit.details["auth_profile_id"] == auth_profile.id
    assert audit.details["auth_profile_present"] is True
    assert audit.details["auth_mode"] == "bearer"
    assert "suite-token" not in str(audit.details)


@pytest.mark.asyncio
async def test_run_suite_honors_kill_switch_before_queue(db_session, monkeypatch):
    monkeypatch.setattr(suites_router, "_suite_manager", _FakeSuiteManager([
        {"id": "suite-auth-check", "info": {"severity": "LOW"}},
    ]))
    monkeypatch.setattr(tests_router.settings, "PENTEST_KILL_SWITCH_ENABLED", True)

    background_tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as exc:
        await suites_router.run_suite(
            suite_name="safe-api",
            request=_FakeRequest({"endpoint_ids": []}),
            background_tasks=background_tasks,
            db=db_session,
            payload={"account_id": 1002110, "user_id": "suite-user"},
        )

    assert exc.value.status_code == 503
    assert exc.value.detail == "pentest_kill_switch_enabled"
    assert len(background_tasks.tasks) == 0
    runs = (
        await db_session.execute(
            select(models.TestRun).where(models.TestRun.account_id == 1002110)
        )
    ).scalars().all()
    assert runs == []


@pytest.mark.asyncio
async def test_run_suite_rejects_target_guard_blocked_endpoint_before_queue(db_session, monkeypatch):
    account_id = 1002120
    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/suite-blocked",
    )
    db_session.add(endpoint)
    await db_session.commit()

    monkeypatch.setattr(suites_router, "_suite_manager", _FakeSuiteManager([
        {"id": "suite-auth-check", "info": {"severity": "LOW"}},
    ]))
    guard = tests_router.TargetGuard(
        allow_private_targets=False,
        resolve_hosts=True,
        resolver=lambda _host, _port: ["127.0.0.1"],
    )
    monkeypatch.setattr(tests_router.TargetGuard, "from_settings", staticmethod(lambda: guard))

    background_tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as exc:
        await suites_router.run_suite(
            suite_name="safe-api",
            request=_FakeRequest({"endpoint_ids": [endpoint.id]}),
            background_tasks=background_tasks,
            db=db_session,
            payload={"account_id": account_id, "user_id": "suite-user"},
        )

    assert exc.value.status_code == 400
    assert exc.value.detail["message"] == "Pentest target guard blocked one or more selected endpoints"
    blocked_endpoint = exc.value.detail["blocked_endpoints"][0]
    assert blocked_endpoint["endpoint_id"] == endpoint.id
    assert blocked_endpoint["target_guard_policy"]["policy"] == "target_guard"
    assert blocked_endpoint["target_guard_policy"]["blocked"] is True
    assert blocked_endpoint["target_guard_policy"]["url"] == "https://api.example.test/suite-blocked"
    assert len(background_tasks.tasks) == 0
    runs = (
        await db_session.execute(
            select(models.TestRun).where(models.TestRun.account_id == account_id)
        )
    ).scalars().all()
    assert runs == []
