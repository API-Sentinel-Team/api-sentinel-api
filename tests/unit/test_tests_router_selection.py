import json

import pytest
from fastapi import HTTPException
from fastapi import BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

import server.api.routers.tests as tests_router
from server.models import core as models
from server.modules.test_executor.scan_plan import verify_scan_plan_integrity
from server.modules.vulnerability_detector.lifecycle import (
    confirmation_status_from_evidence,
    retest_outcome_digest,
    verify_vulnerability_evidence,
)


@pytest.fixture(autouse=True)
def _allow_unauthenticated_active_scans_for_router_unit_tests(monkeypatch):
    monkeypatch.setattr(tests_router.settings, "PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS", False)


class _FakeWordlistManager:
    def __init__(self, templates):
        self.templates = templates


def test_scan_plan_coverage_targets_summary_preserves_llm_active_families_without_secrets():
    summary = tests_router._scan_plan_coverage_targets_summary(
        {
            "llm_api": {
                "template_requested": True,
                "template_covered": True,
                "endpoint_signal_count": 1,
                "status": "available",
                "signals": ["body_key", "tool_context", "token=raw-plan-token"],
                "readiness": {
                    "prompt_context_ready": True,
                    "tool_context_ready": True,
                    "tool_abuse_testable": True,
                    "raw_prompt": "Ignore instructions token=raw-plan-token",
                },
                "active_test_families": {
                    "prompt_injection": {
                        "template_count": 1,
                        "endpoint_signal_count": 1,
                        "ready": True,
                        "status": "ready",
                        "signals": ["body_key", "path_hint", "token=raw-plan-token"],
                    },
                    "tool_chain_injection": {
                        "template_count": 0,
                        "endpoint_signal_count": 1,
                        "ready": False,
                        "status": "missing_template",
                        "signals": [
                            "tool_invocation_context",
                            "tool_output_context",
                            "secret=raw-plan-token",
                        ],
                    },
                    "attacker_supplied": {
                        "template_count": 999,
                        "signals": ["secret=raw-plan-token"],
                    },
                },
            },
            "attacker_supplied": {"signals": ["secret=raw-plan-token"]},
        }
    )

    assert summary == {
        "llm_api": {
            "template_requested": True,
            "template_covered": True,
            "endpoint_signal_count": 1,
            "status": "available",
            "signals": ["body_key", "tool_context"],
            "readiness": {
                "prompt_context_ready": True,
                "tool_context_ready": True,
                "tool_abuse_testable": True,
            },
            "active_test_families": {
                "prompt_injection": {
                    "template_count": 1,
                    "endpoint_signal_count": 1,
                    "ready": True,
                    "status": "ready",
                    "signals": ["body_key", "path_hint"],
                },
                "tool_chain_injection": {
                    "template_count": 0,
                    "endpoint_signal_count": 1,
                    "ready": False,
                    "status": "missing_template",
                    "signals": [
                        "tool_invocation_context",
                        "tool_output_context",
                    ],
                },
            },
        }
    }
    assert "attacker_supplied" not in summary
    assert "raw-plan-token" not in str(summary)


class _FakeExecutionEngine:
    calls = []
    init_kwargs = []

    def __init__(self, *args, **kwargs):
        from server.modules.identity.roles_context import RolesContextBuilder

        self.init_kwargs.append(kwargs)
        self.roles_context_builder = RolesContextBuilder()

    async def execute_test(self, endpoint, template, selection_context=None):
        self.calls.append(
            {
                "endpoint_id": endpoint["id"],
                "template_id": template["id"],
                "selection_context": selection_context or {},
            }
        )
        return {
            "template_id": template["id"],
            "severity": template.get("info", {}).get("severity"),
            "is_vulnerable": False,
            "sent_request": {
                "url": f"{endpoint['url']}?token=raw-token",
                "headers": {
                    "Authorization": "Bearer raw-token",
                    "Cookie": "session=raw-session",
                },
                "body": '{"password":"raw-password","ok":"value"}',
            },
            "received_response": {
                "status_code": 200,
                "headers": {"Set-Cookie": "session=raw-response-session"},
                "body": '{"api_key":"raw-key","ok":"value"}',
            },
            "evidence": "Authorization: Bearer raw-token token=raw-token",
        }


class _QueuedExecutionEngine:
    responses = []
    calls = []

    def __init__(self, *args, **kwargs):
        from server.modules.identity.roles_context import RolesContextBuilder

        self.roles_context_builder = RolesContextBuilder()

    async def execute_test(self, endpoint, template, selection_context=None):
        self.calls.append({"endpoint_id": endpoint["id"], "template_id": template["id"]})
        response = dict(self.responses.pop(0))
        response.setdefault("template_id", template["id"])
        response.setdefault("severity", template.get("info", {}).get("severity"))
        response.setdefault("results", [{"vulnerable": response.get("is_vulnerable", False)}])
        response.setdefault("sent_request", {"url": endpoint["url"]})
        response.setdefault("received_response", {"status_code": 200, "body": "{}"})
        return response


def test_scan_budget_rejects_excessive_template_endpoint_plan(monkeypatch):
    monkeypatch.setattr(tests_router.settings, "PENTEST_MAX_TESTS_PER_RUN", 2)

    with pytest.raises(HTTPException) as exc:
        tests_router._validate_scan_budget(["template-1", "template-2"], ["endpoint-1", "endpoint-2"])

    assert exc.value.status_code == 400
    assert "maximum budget is 2" in exc.value.detail


def test_scan_execution_mode_validates_config(monkeypatch):
    monkeypatch.setattr(tests_router.settings, "PENTEST_SCAN_EXECUTION_MODE", "queued")
    assert tests_router._scan_execution_mode() == "queued"

    monkeypatch.setattr(tests_router.settings, "PENTEST_SCAN_EXECUTION_MODE", "invalid")
    with pytest.raises(HTTPException):
        tests_router._scan_execution_mode()


@pytest.mark.asyncio
async def test_run_scan_rejects_when_kill_switch_enabled(db_session, monkeypatch):
    endpoint = models.APIEndpoint(
        account_id=1000000,
        method="GET",
        protocol="http",
        host="api.example.test",
        path="/kill-switch",
    )
    db_session.add(endpoint)
    await db_session.commit()

    monkeypatch.setattr(tests_router.settings, "PENTEST_KILL_SWITCH_ENABLED", True)

    background_tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as exc:
        await tests_router.run_scan.__wrapped__(
            request=None,
            template_ids=["template-1"],
            endpoint_ids=[endpoint.id],
            background_tasks=background_tasks,
            pentest_profile_id=None,
            db=db_session,
            payload={"account_id": 1000000},
        )

    assert exc.value.status_code == 503
    assert exc.value.detail == "pentest_kill_switch_enabled"
    assert len(background_tasks.tasks) == 0


@pytest.mark.asyncio
async def test_run_scan_rejects_target_guard_blocked_endpoint_before_queue(db_session, monkeypatch):
    account_id = 1000900
    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/blocked",
    )
    db_session.add(endpoint)
    await db_session.commit()

    guard = tests_router.TargetGuard(
        allow_private_targets=False,
        resolve_hosts=True,
        resolver=lambda _host, _port: ["127.0.0.1"],
    )
    monkeypatch.setattr(tests_router.TargetGuard, "from_settings", staticmethod(lambda: guard))

    background_tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as exc:
        await tests_router.run_scan.__wrapped__(
            request=None,
            template_ids=["template-1"],
            endpoint_ids=[endpoint.id],
            background_tasks=background_tasks,
            pentest_profile_id=None,
            db=db_session,
            payload={"account_id": account_id},
        )

    assert exc.value.status_code == 400
    assert exc.value.detail["message"] == "Pentest target guard blocked one or more selected endpoints"
    blocked_endpoint = exc.value.detail["blocked_endpoints"][0]
    assert blocked_endpoint["endpoint_id"] == endpoint.id
    assert "private" in blocked_endpoint["reason"]
    assert blocked_endpoint["target_guard_policy"]["policy"] == "target_guard"
    assert blocked_endpoint["target_guard_policy"]["blocked"] is True
    assert blocked_endpoint["target_guard_policy"]["url"] == "https://api.example.test/blocked"
    assert "private" in blocked_endpoint["target_guard_policy"]["reason"]
    assert len(background_tasks.tasks) == 0

    runs = (
        await db_session.execute(select(models.TestRun).where(models.TestRun.account_id == account_id))
    ).scalars().all()
    assert runs == []


@pytest.mark.asyncio
async def test_run_scan_requires_auth_profile_when_configured(db_session, monkeypatch):
    account_id = 1000910
    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/auth-required",
    )
    db_session.add(endpoint)
    await db_session.commit()

    monkeypatch.setattr(tests_router.settings, "PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS", True)

    background_tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as exc:
        await tests_router.run_scan.__wrapped__(
            request=None,
            template_ids=["template-1"],
            endpoint_ids=[endpoint.id],
            background_tasks=background_tasks,
            pentest_profile_id=None,
            db=db_session,
            payload={"account_id": account_id},
        )

    assert exc.value.status_code == 400
    assert exc.value.detail["reason"] == "auth_profile_required"
    assert len(background_tasks.tasks) == 0
    runs = (
        await db_session.execute(select(models.TestRun).where(models.TestRun.account_id == account_id))
    ).scalars().all()
    assert runs == []


@pytest.mark.asyncio
async def test_run_scan_persists_authenticated_pentest_profile_for_queued_worker(db_session, monkeypatch):
    account_id = 1000920
    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/queued-auth",
    )
    auth_profile = models.AuthProfile(
        account_id=account_id,
        name="queued bearer",
        auth_mode="bearer",
        token="Bearer runtime-token",
        scope_domains=["api.example.test"],
        is_active=True,
    )
    db_session.add_all([endpoint, auth_profile])
    await db_session.flush()
    pentest_profile = models.PentestProfile(
        account_id=account_id,
        name="queued authenticated profile",
        auth_profile_id=auth_profile.id,
    )
    db_session.add(pentest_profile)
    await db_session.commit()

    monkeypatch.setattr(tests_router.settings, "PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS", True)
    monkeypatch.setattr(tests_router.settings, "PENTEST_SCAN_EXECUTION_MODE", "queued")

    background_tasks = BackgroundTasks()
    response = await tests_router.run_scan.__wrapped__(
        request=None,
        template_ids=["template-1"],
        endpoint_ids=[endpoint.id],
        background_tasks=background_tasks,
        pentest_profile_id=pentest_profile.id,
        db=db_session,
        payload={"account_id": account_id},
    )

    assert response["status"] == "scan_queued"
    assert response["pentest_profile_id"] == pentest_profile.id
    assert len(background_tasks.tasks) == 0

    stored = await db_session.get(models.TestRun, response["run_id"])
    assert stored.pentest_profile_id == pentest_profile.id
    audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.resource_id == response["run_id"],
                models.AuditLog.action == "SCAN_RUN_QUEUED",
            )
        )
    ).scalar_one()
    assert audit.details["pentest_profile_id"] == pentest_profile.id
    assert audit.details["auth_required"] is True
    assert audit.details["auth_profile_id"] == auth_profile.id
    assert audit.details["auth_profile_present"] is True
    assert audit.details["auth_mode"] == "bearer"
    assert "runtime-token" not in str(audit.details)


@pytest.mark.asyncio
async def test_run_scan_rejects_auth_profile_scope_blocked_endpoint_before_queue(db_session):
    account_id = 1000925
    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/scoped-auth",
    )
    auth_profile = models.AuthProfile(
        account_id=account_id,
        name="wrong target bearer",
        auth_mode="bearer",
        token="Bearer runtime-token",
        scope_domains=["other.example.test"],
        is_active=True,
    )
    db_session.add_all([endpoint, auth_profile])
    await db_session.flush()
    pentest_profile = models.PentestProfile(
        account_id=account_id,
        name="scoped authenticated profile",
        auth_profile_id=auth_profile.id,
    )
    db_session.add(pentest_profile)
    await db_session.commit()

    background_tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as exc:
        await tests_router.run_scan.__wrapped__(
            request=None,
            template_ids=["template-1"],
            endpoint_ids=[endpoint.id],
            background_tasks=background_tasks,
            pentest_profile_id=pentest_profile.id,
            db=db_session,
            payload={"account_id": account_id},
        )

    assert exc.value.status_code == 400
    assert exc.value.detail["reason"] == "auth_profile_scope_blocked"
    blocked_endpoint = exc.value.detail["blocked_endpoints"][0]
    assert blocked_endpoint["endpoint_id"] == endpoint.id
    policy = blocked_endpoint["auth_profile_scope_policy"]
    assert policy["policy"] == "auth_profile_scope_guard"
    assert policy["blocked"] is True
    assert policy["url"] == "https://api.example.test/scoped-auth"
    assert policy["base_url"] == "https://api.example.test/scoped-auth"
    assert policy["auth_profile_id"] == auth_profile.id
    assert policy["scope_domains_configured"] is True
    assert policy["scope_domain_count"] == 1
    assert "runtime-token" not in str(policy)
    assert len(background_tasks.tasks) == 0
    runs = (
        await db_session.execute(select(models.TestRun).where(models.TestRun.account_id == account_id))
    ).scalars().all()
    assert runs == []


@pytest.mark.asyncio
async def test_scan_runner_skips_template_endpoint_pairs_that_fail_selection(test_engine, monkeypatch):
    template = {
        "id": "only-get-endpoints",
        "info": {"severity": "LOW"},
        "api_selection_filters": {"method": {"eq": "GET"}},
        "execute": {"requests": [{"req": [{}]}]},
    }
    fake_wm = _FakeWordlistManager([template])
    _FakeExecutionEngine.calls = []
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: fake_wm)
    monkeypatch.setattr(tests_router, "ExecutionEngine", _FakeExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        get_endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/users/1",
        )
        post_endpoint = models.APIEndpoint(
            account_id=1000000,
            method="POST",
            protocol="http",
            host="api.example.test",
            path="/users",
        )
        run = models.TestRun(
            account_id=1000000,
            template_ids=[template["id"]],
            endpoint_ids=[get_endpoint.id, post_endpoint.id],
        )
        db.add_all([get_endpoint, post_endpoint, run])
        await db.commit()
        run_id = run.id
        get_endpoint_id = get_endpoint.id
        post_endpoint_id = post_endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [get_endpoint_id, post_endpoint_id],
        1000000,
        db_bind=test_engine,
    )

    assert [call["endpoint_id"] for call in _FakeExecutionEngine.calls] == [get_endpoint_id]

    async with session_factory() as db:
        run_result = await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))
        completed_run = run_result.scalar_one()
        result_rows = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()
        audit_rows = (
            await db.execute(select(models.AuditLog).where(models.AuditLog.resource_id == run_id))
        ).scalars().all()

    assert completed_run.status == "COMPLETED"
    assert completed_run.total_tests == 1
    assert len(result_rows) == 2
    skipped = [result for result in result_rows if result.skip_reason == "selection_filter"]
    executed = [result for result in result_rows if result.skip_reason is None]
    assert len(skipped) == 1
    assert skipped[0].endpoint_id == post_endpoint_id
    assert json.loads(skipped[0].evidence) == {
        "selection_filter": {"reason": "method_filter_mismatch"}
    }
    assert len(executed) == 1
    assert executed[0].sent_request["url"].endswith("token=****")
    assert executed[0].sent_request["headers"]["Authorization"] == "Bearer ****"
    assert executed[0].sent_request["headers"]["Cookie"] == "session=****"
    assert "raw-password" not in executed[0].sent_request["body"]
    assert executed[0].received_response["headers"]["Set-Cookie"] == "****"
    assert "raw-key" not in executed[0].received_response["body"]
    assert "raw-token" not in executed[0].evidence
    audit_by_action = {row.action: row.details for row in audit_rows}
    assert audit_by_action["SCAN_RUN_STARTED"]["planned_tests"] == 2
    assert audit_by_action["SCAN_RUN_COMPLETED"]["processed"] == 2
    assert audit_by_action["SCAN_RUN_COMPLETED"]["skipped"] == 1


@pytest.mark.asyncio
async def test_scan_runner_enforces_template_root_auth_selection(test_engine, monkeypatch):
    template = {
        "id": "root-auth-required",
        "auth": {"authenticated": True},
        "info": {"severity": "LOW"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    fake_wm = _FakeWordlistManager([template])
    _FakeExecutionEngine.calls = []
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: fake_wm)
    monkeypatch.setattr(tests_router, "ExecutionEngine", _FakeExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        authenticated_endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/me",
            auth_types_found=["JWT"],
        )
        anonymous_endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/public",
            auth_types_found=[],
        )
        run = models.TestRun(
            account_id=1000000,
            template_ids=[template["id"]],
            endpoint_ids=[authenticated_endpoint.id, anonymous_endpoint.id],
        )
        db.add_all([authenticated_endpoint, anonymous_endpoint, run])
        await db.commit()
        run_id = run.id
        authenticated_endpoint_id = authenticated_endpoint.id
        anonymous_endpoint_id = anonymous_endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [authenticated_endpoint_id, anonymous_endpoint_id],
        1000000,
        db_bind=test_engine,
    )

    assert [call["endpoint_id"] for call in _FakeExecutionEngine.calls] == [authenticated_endpoint_id]

    async with session_factory() as db:
        result_rows = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()

    skipped = [result for result in result_rows if result.skip_reason == "selection_filter"]
    executed = [result for result in result_rows if result.skip_reason is None]
    assert len(executed) == 1
    assert len(skipped) == 1
    assert skipped[0].endpoint_id == anonymous_endpoint_id
    assert json.loads(skipped[0].evidence) == {
        "selection_filter": {"reason": "requires_authenticated_endpoint"}
    }


@pytest.mark.asyncio
async def test_scan_runner_fails_direct_queued_run_that_exceeds_worker_budget(test_engine, monkeypatch):
    account_id = 1000930
    monkeypatch.setattr(tests_router.settings, "PENTEST_MAX_TESTS_PER_RUN", 2)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            template_ids=["template-1", "template-2"],
            endpoint_ids=["endpoint-1", "endpoint-2"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    await tests_router._run_security_tasks(
        run_id,
        ["template-1", "template-2"],
        ["endpoint-1", "endpoint-2"],
        account_id,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        result_rows = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_FAILED",
                )
            )
        ).scalar_one()

    assert stored.status == "FAILED"
    assert stored.error_count == 1
    assert result_rows == []
    assert audit.details["reason"] == "scan_budget_exceeded"
    assert audit.details["planned_tests"] == 4
    assert audit.details["max_tests_per_run"] == 2


@pytest.mark.asyncio
async def test_scan_runner_fails_unowned_endpoint_ids_before_execution(test_engine, monkeypatch):
    account_id = 1000931
    other_account_id = 1000932
    _FakeExecutionEngine.calls = []
    monkeypatch.setattr(tests_router, "ExecutionEngine", _FakeExecutionEngine)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=other_account_id,
            method="GET",
            protocol="https",
            host="api.example.test",
            path="/other-tenant",
        )
        db.add(endpoint)
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            template_ids=["template-1"],
            endpoint_ids=[endpoint.id],
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        ["template-1"],
        [endpoint_id],
        account_id,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        result_rows = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_FAILED",
                )
            )
        ).scalar_one()

    assert _FakeExecutionEngine.calls == []
    assert stored.status == "FAILED"
    assert stored.error_count == 1
    assert result_rows == []
    assert audit.details["reason"] == "endpoint_scope_invalid"
    assert audit.details["unavailable_endpoint_ids"] == [endpoint_id]


@pytest.mark.asyncio
async def test_scan_runner_fails_target_guard_blocked_endpoint_before_execution(test_engine, monkeypatch):
    account_id = 1000933
    _FakeExecutionEngine.calls = []
    guard = tests_router.TargetGuard(
        allow_private_targets=False,
        resolve_hosts=True,
        resolver=lambda _host, _port: ["127.0.0.1"],
    )
    monkeypatch.setattr(tests_router.TargetGuard, "from_settings", staticmethod(lambda: guard))
    monkeypatch.setattr(tests_router, "ExecutionEngine", _FakeExecutionEngine)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="https",
            host="api.example.test",
            path="/blocked-worker",
        )
        db.add(endpoint)
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            template_ids=["template-1"],
            endpoint_ids=[endpoint.id],
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        ["template-1"],
        [endpoint_id],
        account_id,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        result_rows = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_FAILED",
                )
            )
        ).scalar_one()

    assert _FakeExecutionEngine.calls == []
    assert stored.status == "FAILED"
    assert stored.error_count == 1
    assert result_rows == []
    assert audit.details["reason"] == "target_guard_blocked"
    assert audit.details["blocked_endpoints"][0]["endpoint_id"] == endpoint_id
    assert "private" in audit.details["blocked_endpoints"][0]["reason"]


@pytest.mark.asyncio
async def test_scan_runner_fails_tampered_scan_plan_before_execution(test_engine, monkeypatch):
    account_id = 1000934
    template = {
        "id": "tamper-aware-template",
        "security_category": "authorization",
        "auth": {"authenticated": True},
        "info": {"severity": "LOW"},
        "api_selection_filters": {"method": {"eq": "GET"}},
        "execute": {"requests": [{"req": [{}]}]},
    }
    fake_wm = _FakeWordlistManager([template])
    _FakeExecutionEngine.calls = []
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: fake_wm)
    monkeypatch.setattr(tests_router, "ExecutionEngine", _FakeExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="https",
            host="api.example.test",
            path="/accounts/123",
            last_request_body='{"account_id":"acct-123","token":"raw-plan-token"}',
            last_query_string="token=raw-plan-token",
            auth_types_found=["bearer"],
            private_variable_count=1,
        )
        db.add(endpoint)
        await db.flush()
        scan_plan = tests_router._build_scan_plan_for_run(
            templates=[template],
            template_ids=[template["id"]],
            endpoints=[endpoint],
            account_id=account_id,
            test_intensity="standard",
            profile=None,
            engine_runtime_availability={"schemathesis": False, "nuclei": False, "zap": False},
        )
        assert verify_scan_plan_integrity(scan_plan)["verified"] is True
        scan_plan["selection"]["selected_pair_count"] = 99
        run = models.TestRun(
            account_id=account_id,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
            scan_plan=scan_plan,
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    result = await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint_id],
        account_id,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        result_rows = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()
        audits = (
            await db.execute(
                select(models.AuditLog)
                .where(models.AuditLog.resource_id == run_id)
                .order_by(models.AuditLog.created_at.asc())
            )
        ).scalars().all()

    assert result == {"status": "failed", "reason": "scan_plan_integrity_mismatch", "run_id": run_id}
    assert _FakeExecutionEngine.calls == []
    assert stored.status == "FAILED"
    assert stored.error_count == 1
    assert result_rows == []
    assert [audit.action for audit in audits] == ["SCAN_RUN_FAILED"]
    failure_details = audits[0].details
    assert failure_details["reason"] == "scan_plan_integrity_mismatch"
    assert failure_details["scan_plan_integrity"]["verified"] is False
    assert failure_details["scan_plan_integrity"]["status"] == "MISMATCH"
    assert failure_details["scan_plan_integrity"]["expected_hash"] == scan_plan["scan_plan_hash"]
    assert failure_details["scan_plan_integrity"]["actual_hash"] != scan_plan["scan_plan_hash"]
    assert "raw-plan-token" not in str(failure_details)
    assert "/accounts/123" not in str(failure_details)


@pytest.mark.asyncio
async def test_scan_runner_passes_selection_extractions_into_execution_context(test_engine, monkeypatch):
    template = {
        "id": "extract-url",
        "info": {"severity": "LOW"},
        "api_selection_filters": {"url": {"extract": "urlVar"}},
        "execute": {"requests": [{"req": [{"modify_url": "${urlVar}/debug"}]}]},
    }
    fake_wm = _FakeWordlistManager([template])
    _FakeExecutionEngine.calls = []
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: fake_wm)
    monkeypatch.setattr(tests_router, "ExecutionEngine", _FakeExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/users/1",
        )
        run = models.TestRun(
            account_id=1000000,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
        )
        db.add_all([endpoint, run])
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint_id],
        1000000,
        db_bind=test_engine,
    )

    assert len(_FakeExecutionEngine.calls) == 1
    assert _FakeExecutionEngine.calls[0]["selection_context"] == {
        "urlVar": "http://api.example.test/users/1"
    }


@pytest.mark.asyncio
async def test_scan_runner_passes_profile_state_change_policy_to_execution_engine(test_engine, monkeypatch):
    template = {
        "id": "state-change-policy",
        "info": {"severity": "LOW"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    fake_wm = _FakeWordlistManager([template])
    _FakeExecutionEngine.calls = []
    _FakeExecutionEngine.init_kwargs = []
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: fake_wm)
    monkeypatch.setattr(tests_router, "ExecutionEngine", _FakeExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000300,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/policy",
        )
        profile = models.PentestProfile(
            account_id=1000300,
            name="state-change-policy-profile",
            allow_state_change=True,
        )
        run = models.TestRun(
            account_id=1000300,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
        )
        db.add_all([endpoint, profile, run])
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id
        profile_id = profile.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint_id],
        1000300,
        pentest_profile_id=profile_id,
        db_bind=test_engine,
    )

    assert _FakeExecutionEngine.init_kwargs[0]["allow_state_change"] is True


@pytest.mark.asyncio
async def test_scan_runner_counts_guarded_skip_as_skipped_not_executed(test_engine, monkeypatch):
    template = {
        "id": "guarded-skip-template",
        "info": {"severity": "LOW"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    _QueuedExecutionEngine.calls = []
    _QueuedExecutionEngine.responses = [
        {
            "is_vulnerable": False,
            "skip_reason": "state_change_guard",
            "evidence": "state_change_guard=blocked",
            "error": "destructive_method_blocked: DELETE requires explicit opt-in",
            "sent_request": {"method": "DELETE", "url": "https://api.example.test/users/1"},
            "received_response": None,
        }
    ]
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: _FakeWordlistManager([template]))
    monkeypatch.setattr(tests_router, "ExecutionEngine", _QueuedExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000500,
            method="DELETE",
            protocol="https",
            host="api.example.test",
            path="/users/1",
        )
        run = models.TestRun(
            account_id=1000500,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
        )
        db.add_all([endpoint, run])
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint_id],
        1000500,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        completed_run = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        result_row = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalar_one()
        audit_rows = (
            await db.execute(select(models.AuditLog).where(models.AuditLog.resource_id == run_id))
        ).scalars().all()

    audit_by_action = {row.action: row.details for row in audit_rows}
    assert completed_run.status == "COMPLETED"
    assert completed_run.total_tests == 0
    assert completed_run.vulnerable_count == 0
    assert completed_run.error_count == 0
    assert result_row.skip_reason == "state_change_guard"
    assert result_row.evidence == "state_change_guard=blocked"
    assert audit_by_action["SCAN_RUN_COMPLETED"]["processed"] == 1
    assert audit_by_action["SCAN_RUN_COMPLETED"]["executed"] == 0
    assert audit_by_action["SCAN_RUN_COMPLETED"]["skipped"] == 1


@pytest.mark.asyncio
async def test_scan_runner_persists_structured_auth_scope_policy_for_guarded_skip(test_engine, monkeypatch):
    template = {
        "id": "auth-scope-guarded-template",
        "info": {"severity": "LOW"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    _QueuedExecutionEngine.calls = []
    _QueuedExecutionEngine.responses = [
        {
            "is_vulnerable": False,
            "skip_reason": "auth_profile_scope_guard",
            "evidence": "auth_profile_scope_guard=blocked token=raw-scope-token",
            "error": "auth_profile_scope_blocked: Authorization: Bearer raw-scope-token",
            "sent_request": None,
            "received_response": None,
            "auth_profile_scope_policy": {
                "policy": "auth_profile_scope_guard",
                "blocked": True,
                "url": "https://evil.example.test/users?token=raw-scope-token",
                "base_url": "https://api.example.test/users?token=raw-scope-token",
                "reason": "Authorization: Bearer raw-scope-token token=raw-scope-token",
                "auth_profile_id": "auth-profile-1",
            },
        }
    ]
    monkeypatch.setattr(
        tests_router.WordlistManager,
        "get_instance",
        lambda *args, **kwargs: _FakeWordlistManager([template]),
    )
    monkeypatch.setattr(tests_router, "ExecutionEngine", _QueuedExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000502,
            method="GET",
            protocol="https",
            host="api.example.test",
            path="/users",
        )
        run = models.TestRun(
            account_id=1000502,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
        )
        db.add_all([endpoint, run])
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint_id],
        1000502,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        result_row = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalar_one()

    evidence = json.loads(result_row.evidence)
    policy = evidence["safety_policies"]["auth_profile_scope_policy"]
    assert result_row.skip_reason == "auth_profile_scope_guard"
    assert evidence["engine"] == "template"
    assert evidence["skip_reason"] == "auth_profile_scope_guard"
    assert evidence["observation"] == "auth_profile_scope_guard=blocked token=****"
    assert evidence["evidence_hash"]
    assert policy["policy"] == "auth_profile_scope_guard"
    assert policy["url"] == "https://evil.example.test/users?token=****"
    assert policy["base_url"] == "https://api.example.test/users?token=****"
    assert policy["reason"] == "Authorization: Bearer **** token=****"
    assert policy["auth_profile_id"] == "auth-profile-1"
    assert "raw-scope-token" not in result_row.evidence


@pytest.mark.asyncio
async def test_scan_runner_counts_request_budget_skip_as_skipped_not_executed(test_engine, monkeypatch):
    template = {
        "id": "request-budget-template",
        "info": {"severity": "LOW"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    _QueuedExecutionEngine.calls = []
    _QueuedExecutionEngine.responses = [
        {
            "is_vulnerable": False,
            "skip_reason": "request_budget",
            "evidence": "request_budget=exceeded",
            "error": "request_budget_exceeded: maximum active requests per test is 0",
            "sent_request": None,
            "received_response": None,
        }
    ]
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: _FakeWordlistManager([template]))
    monkeypatch.setattr(tests_router, "ExecutionEngine", _QueuedExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000501,
            method="GET",
            protocol="https",
            host="api.example.test",
            path="/users",
        )
        run = models.TestRun(
            account_id=1000501,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
        )
        db.add_all([endpoint, run])
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint_id],
        1000501,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        completed_run = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        result_row = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalar_one()
        audit_rows = (
            await db.execute(select(models.AuditLog).where(models.AuditLog.resource_id == run_id))
        ).scalars().all()

    audit_by_action = {row.action: row.details for row in audit_rows}
    assert completed_run.status == "COMPLETED"
    assert completed_run.total_tests == 0
    assert completed_run.error_count == 0
    assert result_row.skip_reason == "request_budget"
    assert result_row.evidence == "request_budget=exceeded"
    assert audit_by_action["SCAN_RUN_COMPLETED"]["executed"] == 0
    assert audit_by_action["SCAN_RUN_COMPLETED"]["skipped"] == 1


@pytest.mark.asyncio
async def test_scan_runner_stops_when_cancel_is_requested(test_engine, monkeypatch):
    template = {
        "id": "cancel-aware-template",
        "info": {"severity": "LOW"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    fake_wm = _FakeWordlistManager([template])
    _FakeExecutionEngine.calls = []
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: fake_wm)
    monkeypatch.setattr(tests_router, "ExecutionEngine", _FakeExecutionEngine)

    poll_count = {"value": 0}

    async def fake_cancel_requested(db, run_id):
        poll_count["value"] += 1
        return poll_count["value"] >= 3

    monkeypatch.setattr(tests_router, "_scan_cancel_requested", fake_cancel_requested)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        first_endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/one",
        )
        second_endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/two",
        )
        run = models.TestRun(
            account_id=1000000,
            template_ids=[template["id"]],
            endpoint_ids=[first_endpoint.id, second_endpoint.id],
        )
        db.add_all([first_endpoint, second_endpoint, run])
        await db.commit()
        run_id = run.id
        first_endpoint_id = first_endpoint.id
        second_endpoint_id = second_endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [first_endpoint_id, second_endpoint_id],
        1000000,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        completed_run = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        result_rows = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()

    assert len(_FakeExecutionEngine.calls) == 1
    assert completed_run.status == "CANCELED"
    assert completed_run.total_tests == 1
    assert len(result_rows) == 1
    assert result_rows[0].endpoint_id in {first_endpoint_id, second_endpoint_id}


@pytest.mark.asyncio
async def test_scan_runner_cancels_before_start_when_kill_switch_enabled(test_engine, monkeypatch):
    monkeypatch.setattr(tests_router.settings, "PENTEST_KILL_SWITCH_ENABLED", True)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=1000000,
            status="PENDING",
            template_ids=["template-1"],
            endpoint_ids=[],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    await tests_router._run_security_tasks(
        run_id,
        ["template-1"],
        [],
        1000000,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        completed_run = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        result_rows = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_CANCELED",
                )
            )
        ).scalar_one()

    assert completed_run.status == "CANCELED"
    assert result_rows == []
    assert audit.details["reason"] == "pentest_kill_switch_enabled"
    assert audit.details["executed"] == 0


@pytest.mark.asyncio
async def test_cancel_run_endpoint_marks_pending_run_cancel_requested(client, db_session, auth_headers):
    run = models.TestRun(
        account_id=1000000,
        status="PENDING",
        template_ids=["template-1"],
        endpoint_ids=[],
    )
    db_session.add(run)
    await db_session.commit()

    response = await client.post(f"/api/tests/runs/{run.id}/cancel", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["status"] == "cancel_requested"

    stored = await db_session.get(models.TestRun, run.id)
    assert stored.status == "CANCEL_REQUESTED"
    audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.resource_id == run.id,
                models.AuditLog.action == "SCAN_CANCEL_REQUESTED",
            )
        )
    ).scalar_one()
    assert audit.account_id == 1000000
    assert audit.user_id == "test-user"
    assert audit.details == {"previous_status": "PENDING"}


@pytest.mark.asyncio
async def test_get_run_redacts_legacy_result_text_and_filters_to_run_endpoint_scope(client, db_session, auth_headers):
    owned_endpoint = models.APIEndpoint(
        account_id=1000000,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/owned",
    )
    other_endpoint = models.APIEndpoint(
        account_id=2000000,
        method="GET",
        protocol="https",
        host="api.other.test",
        path="/other",
    )
    db_session.add_all([owned_endpoint, other_endpoint])
    await db_session.commit()

    run = models.TestRun(
        account_id=1000000,
        status="COMPLETED",
        template_ids=["auth-bypass"],
        endpoint_ids=[owned_endpoint.id],
        trigger_source="schedule",
        source_schedule_id="schedule-owned",
    )
    db_session.add(run)
    await db_session.commit()

    db_session.add_all(
        [
            models.TestResult(
                run_id=run.id,
                endpoint_id=owned_endpoint.id,
                template_id="auth-bypass",
                is_vulnerable=True,
                severity="HIGH",
                evidence="Authorization: Bearer raw-owned-token token=raw-owned-token",
                error="upstream failed with api_key=raw-owned-key",
            ),
            models.TestResult(
                run_id=run.id,
                endpoint_id=other_endpoint.id,
                template_id="cross-tenant-poison",
                is_vulnerable=True,
                severity="CRITICAL",
                evidence="Authorization: Bearer raw-other-token",
            ),
        ]
    )
    await db_session.commit()

    response = await client.get(f"/api/tests/runs/{run.id}", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["trigger_source"] == "schedule"
    assert body["source_schedule_id"] == "schedule-owned"
    assert body["dispatch_lease_expires_at"] is None
    assert body["worker_heartbeat_at"] is None
    assert body["started_at"] is None
    assert body["completed_at"] is None
    assert body["created_at"].endswith("Z")
    assert len(body["results"]) == 1
    assert body["results"][0]["endpoint_id"] == owned_endpoint.id
    assert body["results"][0]["template_id"] == "auth-bypass"
    assert "Bearer ****" in body["results"][0]["evidence"]
    assert "raw-owned-token" not in str(body)
    assert "raw-owned-key" not in str(body)
    assert "raw-other-token" not in str(body)
    assert "cross-tenant-poison" not in str(body)


@pytest.mark.asyncio
async def test_run_findings_export_filters_to_run_endpoint_scope(client, db_session, auth_headers):
    owned_endpoint = models.APIEndpoint(
        account_id=1000000,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/owned-export",
    )
    other_endpoint = models.APIEndpoint(
        account_id=2000000,
        method="GET",
        protocol="https",
        host="api.other.test",
        path="/other-export",
    )
    db_session.add_all([owned_endpoint, other_endpoint])
    await db_session.commit()

    run = models.TestRun(
        account_id=1000000,
        status="COMPLETED",
        template_ids=["auth-bypass"],
        endpoint_ids=[owned_endpoint.id],
    )
    db_session.add(run)
    await db_session.commit()

    db_session.add_all(
        [
            models.TestResult(
                run_id=run.id,
                endpoint_id=owned_endpoint.id,
                template_id="auth-bypass",
                is_vulnerable=True,
                severity="HIGH",
                evidence="Authorization: Bearer raw-owned-export-token",
            ),
            models.TestResult(
                run_id=run.id,
                endpoint_id=other_endpoint.id,
                template_id="cross-tenant-export",
                is_vulnerable=True,
                severity="CRITICAL",
                evidence="Authorization: Bearer raw-other-export-token",
            ),
        ]
    )
    await db_session.commit()

    response = await client.get(
        f"/api/tests/runs/{run.id}/findings",
        headers=auth_headers,
        params={"format": "sarif"},
    )

    assert response.status_code == 200
    body = response.json()
    blob = str(body)
    assert "auth-bypass" in blob
    assert "Bearer ****" in blob
    assert "cross-tenant-export" not in blob
    assert "raw-owned-export-token" not in blob
    assert "raw-other-export-token" not in blob


@pytest.mark.asyncio
async def test_run_scan_queued_mode_creates_pending_run_without_background_task(db_session, monkeypatch):
    endpoint = models.APIEndpoint(
        account_id=1000000,
        method="GET",
        protocol="http",
        host="api.example.test",
        path="/queued",
    )
    db_session.add(endpoint)
    await db_session.commit()

    monkeypatch.setattr(tests_router.settings, "PENTEST_SCAN_EXECUTION_MODE", "queued")
    monkeypatch.setattr(tests_router.settings, "PENTEST_MAX_TESTS_PER_RUN", 10)

    background_tasks = BackgroundTasks()
    response = await tests_router.run_scan.__wrapped__(
        request=None,
        template_ids=["template-1"],
        endpoint_ids=[endpoint.id],
        background_tasks=background_tasks,
        pentest_profile_id=None,
        db=db_session,
        payload={"account_id": 1000000},
    )

    assert response["status"] == "scan_queued"
    assert response["execution_mode"] == "queued"
    assert len(background_tasks.tasks) == 0

    stored = await db_session.get(models.TestRun, response["run_id"])
    assert stored.status == "PENDING"
    audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.resource_id == response["run_id"],
                models.AuditLog.action == "SCAN_RUN_QUEUED",
            )
        )
    ).scalar_one()
    assert audit.details["template_count"] == 1
    assert audit.details["endpoint_count"] == 1
    assert audit.details["planned_tests"] == 1
    assert audit.details["execution_mode"] == "queued"


@pytest.mark.asyncio
async def test_run_scan_persists_readable_context_aware_scan_plan(db_session, monkeypatch):
    account_id = 1000940
    template = {
        "id": "authz-private-object",
        "security_category": "authorization",
        "auth": {"authenticated": True},
        "info": {"severity": "HIGH", "name": "Object authorization"},
        "api_selection_filters": {
            "method": {"eq": "GET"},
            "private_variable_context": {"gt": 0},
            "response_payload": {"contains": ["owner_id"]},
        },
    }
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: _FakeWordlistManager([template]))
    monkeypatch.setattr(tests_router.settings, "PENTEST_SCAN_EXECUTION_MODE", "queued")

    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/accounts/123",
        auth_types_found=["bearer"],
        last_response_code=200,
        last_request_body='{"account_id":"acct-123","password":"raw-password"}',
        last_response_body='{"owner_id":"acct-123","api_key":"raw-key"}',
        private_variable_count=1,
    )
    db_session.add(endpoint)
    await db_session.commit()

    background_tasks = BackgroundTasks()
    response = await tests_router.run_scan.__wrapped__(
        request=None,
        template_ids=[template["id"]],
        endpoint_ids=[endpoint.id],
        background_tasks=background_tasks,
        pentest_profile_id=None,
        test_intensity="standard",
        db=db_session,
        payload={"account_id": account_id},
    )

    assert response["status"] == "scan_queued"
    assert response["test_intensity"] == "standard"
    assert response["scan_plan"]["schema_version"] == "scan_plan.v1"
    assert response["scan_plan"]["selection"]["selected_pair_count"] == 1
    assert response["scan_plan"]["context_inputs"]["auth"] == "available"
    assert response["scan_plan"]["context_inputs"]["sensitive_fields"] == "available"

    stored = await db_session.get(models.TestRun, response["run_id"])
    assert stored.test_intensity == "standard"
    assert stored.scan_plan == response["scan_plan"]

    audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.resource_id == response["run_id"],
                models.AuditLog.action == "SCAN_RUN_QUEUED",
            )
        )
    ).scalar_one()
    assert audit.details["test_intensity"] == "standard"
    assert audit.details["scan_plan"]["selected_pair_count"] == 1
    assert audit.details["scan_plan"]["hash_algorithm"] == "sha256"
    assert audit.details["scan_plan"]["scan_plan_hash"] == response["scan_plan"]["scan_plan_hash"]
    assert audit.details["scan_plan"]["scan_plan_integrity"] == {
        "verified": True,
        "status": "VERIFIED",
        "hash_algorithm": "sha256",
        "expected_hash": response["scan_plan"]["scan_plan_hash"],
        "actual_hash": response["scan_plan"]["scan_plan_hash"],
    }
    assert audit.details["scan_plan"]["coverage_targets"]["authorization"] == {
        "template_requested": True,
        "template_covered": True,
        "endpoint_signal_count": 1,
        "status": "available",
        "signals": ["auth_context", "private_identifier"],
        "identity_context": {
            "role_count": 0,
            "multi_identity_ready": False,
            "privileged_role_present": False,
            "low_privilege_role_present": False,
            "privilege_boundary_pair_count": 0,
        },
        "readiness": {
            "auth_context_ready": True,
            "private_identifier_context_ready": True,
            "role_context_ready": False,
            "bola_replay_testable": False,
            "bfla_replay_testable": False,
        },
    }
    assert "raw-password" not in str(response)
    assert "raw-key" not in str(audit.details)
    assert "/accounts/123" not in str(stored.scan_plan)


@pytest.mark.asyncio
async def test_run_scan_persists_multi_engine_plan_for_worker_accountability(db_session, monkeypatch):
    account_id = 1000942
    template = {
        "id": "authz-object-fuzz",
        "security_category": "authorization",
        "auth": {"authenticated": True},
        "info": {"severity": "HIGH", "name": "Object authorization fuzz"},
        "api_selection_filters": {"method": {"eq": "GET"}},
    }
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: _FakeWordlistManager([template]))
    monkeypatch.setattr(tests_router.settings, "PENTEST_SCAN_EXECUTION_MODE", "queued")
    monkeypatch.setattr(
        tests_router,
        "_scan_engine_runtime_availability",
        lambda: {"schemathesis": True, "nuclei": True, "zap": True},
        raising=False,
    )

    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/engine-plan",
    )
    auth_profile = models.AuthProfile(
        account_id=account_id,
        name="engine bearer",
        auth_mode="bearer",
        token="Bearer raw-engine-token",
        scope_domains=["api.example.test"],
        is_active=True,
    )
    openapi_spec = models.OpenAPISpec(
        account_id=account_id,
        version="engine-plan",
        spec_json={
            "openapi": "3.0.0",
            "paths": {"/engine-plan": {"get": {"responses": {"200": {"description": "OK"}}}}},
        },
    )
    db_session.add_all([endpoint, auth_profile, openapi_spec])
    await db_session.flush()
    pentest_profile = models.PentestProfile(
        account_id=account_id,
        name="all engines queued",
        auth_profile_id=auth_profile.id,
        schemathesis_enabled=True,
        nuclei_enabled=True,
        zap_enabled=True,
    )
    db_session.add(pentest_profile)
    await db_session.commit()

    background_tasks = BackgroundTasks()
    response = await tests_router.run_scan.__wrapped__(
        request=None,
        template_ids=[template["id"]],
        endpoint_ids=[endpoint.id],
        background_tasks=background_tasks,
        pentest_profile_id=pentest_profile.id,
        test_intensity="standard",
        external_engine_scope={"target_url": "https://api.example.test", "openapi_spec_id": openapi_spec.id},
        db=db_session,
        payload={"account_id": account_id},
    )

    assert response["status"] == "scan_queued"
    assert verify_scan_plan_integrity(response["scan_plan"])["verified"] is True
    engine_plan = {item["engine"]: item for item in response["scan_plan"]["engine_plan"]}
    assert engine_plan["templates"]["status"] == "ready"
    assert engine_plan["schemathesis"]["status"] == "ready"
    assert engine_plan["nuclei"]["status"] == "ready"
    assert engine_plan["zap"]["status"] == "ready"
    assert engine_plan["passive"]["status"] == "available"
    assert engine_plan["schemathesis"]["requires_openapi_spec"] is True
    assert engine_plan["nuclei"]["requires_auth_profile"] is True
    assert "raw-engine-token" not in str(response["scan_plan"])

    stored = await db_session.get(models.TestRun, response["run_id"])
    assert stored.scan_plan["engine_plan"] == response["scan_plan"]["engine_plan"]

    audit = (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.resource_id == response["run_id"],
                models.AuditLog.action == "SCAN_RUN_QUEUED",
            )
        )
    ).scalar_one()
    assert audit.details["scan_plan"]["engine_status_counts"] == {
        "ready": 4,
        "available": 1,
        "disabled": 0,
        "blocked": 1,  # authorization_replay is blocked (no test accounts configured)
    }
    assert audit.details["scan_plan"]["ready_active_engines"] == [
        "templates",
        "schemathesis",
        "nuclei",
        "zap",
    ]
    assert audit.details["scan_plan"]["continuous_engines"] == ["passive"]
    assert audit.details["scan_plan"]["required_artifacts"] == [
        {"engine": "schemathesis", "artifact_type": "schemathesis"},
        {"engine": "nuclei", "artifact_type": "nuclei_secret_file"},
        {"engine": "zap", "artifact_type": "zap_plan"},
    ]
    assert "raw-engine-token" not in str(audit.details)


@pytest.mark.asyncio
async def test_scan_runner_backfills_scan_plan_for_runs_created_by_other_paths(test_engine, monkeypatch):
    template = {
        "id": "only-get-endpoints",
        "security_category": "authorization",
        "info": {"severity": "LOW"},
        "api_selection_filters": {"method": {"eq": "GET"}},
        "execute": {"requests": [{"req": [{}]}]},
    }
    fake_wm = _FakeWordlistManager([template])
    _FakeExecutionEngine.calls = []
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: fake_wm)
    monkeypatch.setattr(tests_router, "ExecutionEngine", _FakeExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000941,
            method="GET",
            protocol="https",
            host="api.example.test",
            path="/worker-backfill",
        )
        run = models.TestRun(
            account_id=1000941,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
            trigger_source="schedule",
        )
        db.add_all([endpoint, run])
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint_id],
        1000941,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        stored = await db.get(models.TestRun, run_id)
        started_audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_STARTED",
                )
            )
        ).scalar_one()

    assert stored.scan_plan["schema_version"] == "scan_plan.v1"
    assert stored.scan_plan["selection"]["selected_pair_count"] == 1
    assert stored.test_intensity == "standard"
    assert started_audit.details["scan_plan"]["selected_pair_count"] == 1
    assert started_audit.details["test_intensity"] == "standard"


@pytest.mark.asyncio
async def test_high_severity_findings_must_pass_confirmatory_retest(test_engine, monkeypatch):
    template = {
        "id": "high-auth-bypass",
        "info": {"severity": "HIGH"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    _QueuedExecutionEngine.calls = []
    _QueuedExecutionEngine.responses = [
        {
            "is_vulnerable": True,
            "evidence": "Authorization: Bearer raw-token token=raw-token",
            "sent_request": {
                "url": "https://api.example.test/admin?token=raw-query-token",
                "headers": {"Authorization": "Bearer raw-token"},
            },
            "results": [{"vulnerable": True, "proof": "Authorization: Bearer raw-token"}],
        },
        {
            "is_vulnerable": False,
            "evidence": "second run clean token=raw-confirmation-token",
            "sent_request": {
                "url": "https://api.example.test/admin?token=raw-confirmation-query-token",
                "headers": {"Authorization": "Bearer raw-confirmation-token"},
            },
            "received_response": {"status_code": 200, "body": '{"token":"raw-confirmation-body-token"}'},
            "results": [{"vulnerable": False, "proof": "clean token=raw-confirmation-token"}],
        },
    ]
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: _FakeWordlistManager([template]))
    monkeypatch.setattr(tests_router, "ExecutionEngine", _QueuedExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/admin",
        )
        run = models.TestRun(
            account_id=1000000,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
        )
        db.add_all([endpoint, run])
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint_id],
        1000000,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        result_row = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalar_one()
        vulnerabilities = (
            await db.execute(select(models.Vulnerability).where(models.Vulnerability.endpoint_id == endpoint_id))
        ).scalars().all()

    assert len(_QueuedExecutionEngine.calls) == 2
    assert result_row.is_vulnerable is False
    assert result_row.skip_reason == "confirmatory_retest_failed"
    result_evidence = json.loads(result_row.evidence)
    evidence_blob = str(result_evidence)
    assert result_evidence["finding_status"] == "DISPROVEN"
    assert result_evidence["skip_reason"] == "confirmatory_retest_failed"
    assert result_evidence["confirmation"]["confirmed"] is False
    assert result_evidence["observation"] == "Authorization: Bearer **** token=****"
    assert result_evidence["evidence_hash"]
    assert confirmation_status_from_evidence(result_evidence) == "DISPROVEN"
    assert verify_vulnerability_evidence(result_evidence)["verified"] is True
    assert "raw-token" not in evidence_blob
    assert "raw-confirmation-token" not in evidence_blob
    assert "raw-confirmation-body-token" not in evidence_blob
    assert vulnerabilities == []


@pytest.mark.asyncio
async def test_confirmed_high_severity_finding_opens_vulnerability_with_confirmation_evidence(test_engine, monkeypatch):
    template = {
        "id": "confirmed-high-auth-bypass",
        "info": {"severity": "HIGH"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    _QueuedExecutionEngine.calls = []
    _QueuedExecutionEngine.responses = [
        {"is_vulnerable": True, "evidence": "initial signal"},
        {"is_vulnerable": True, "evidence": "confirmed signal"},
    ]
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: _FakeWordlistManager([template]))
    monkeypatch.setattr(tests_router, "ExecutionEngine", _QueuedExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/confirmed-admin",
        )
        run = models.TestRun(
            account_id=1000000,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
        )
        db.add_all([endpoint, run])
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint_id],
        1000000,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        result_row = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalar_one()
        vulnerability = (
            await db.execute(select(models.Vulnerability).where(models.Vulnerability.endpoint_id == endpoint_id))
        ).scalar_one()

    assert len(_QueuedExecutionEngine.calls) == 2
    assert result_row.is_vulnerable is True
    result_evidence = json.loads(result_row.evidence)
    assert result_evidence["confirmation"]["confirmed"] is True
    assert result_evidence["evidence_hash"]
    assert vulnerability.status == "OPEN"
    assert vulnerability.confidence == "HIGH"
    assert vulnerability.evidence["confirmation"]["confirmed"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "trigger_source",
    ["vulnerability_retest", "vulnerability_auto_retest", "vulnerability_fix_event"],
)
async def test_linked_vulnerability_retest_closes_source_when_clean(test_engine, monkeypatch, trigger_source):
    template = {
        "id": "retest-clean-auth-bypass",
        "info": {"severity": "HIGH"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    _QueuedExecutionEngine.calls = []
    _QueuedExecutionEngine.responses = [
        {"is_vulnerable": False, "evidence": "remediation clean"},
    ]
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: _FakeWordlistManager([template]))
    monkeypatch.setattr(tests_router, "ExecutionEngine", _QueuedExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/retest-clean",
        )
        db.add(endpoint)
        await db.flush()
        vulnerability = models.Vulnerability(
            account_id=1000000,
            template_id=template["id"],
            endpoint_id=endpoint.id,
            url="http://api.example.test/retest-clean",
            method="GET",
            severity="HIGH",
            type=template["id"],
            status="IN_REMEDIATION",
            evidence={"confirmation": {"confirmed": True}},
        )
        db.add(vulnerability)
        await db.flush()
        run = models.TestRun(
            account_id=1000000,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
            trigger_source=trigger_source,
            source_vulnerability_id=vulnerability.id,
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        vulnerability_id = vulnerability.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint.id],
        1000000,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        stored = await db.get(models.Vulnerability, vulnerability_id)
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == vulnerability_id,
                    models.AuditLog.action == "VULNERABILITY_RETEST_COMPLETED",
                )
            )
        ).scalar_one()

    latest = stored.evidence["latest_remediation_retest"]
    assert stored.status == "CLOSED"
    assert latest["run_id"] == run_id
    assert latest["outcome"] == "CLEAN"
    assert latest["executed"] == 1
    assert latest["vulnerable"] == 0
    assert latest["hash_algorithm"] == "sha256"
    assert latest["retest_hash"] == retest_outcome_digest(latest)
    assert audit.details["outcome"] == "CLEAN"
    assert audit.details["previous_status"] == "IN_REMEDIATION"
    assert audit.details["new_status"] == "CLOSED"
    assert audit.details["hash_algorithm"] == "sha256"
    assert audit.details["retest_hash"] == latest["retest_hash"]
    assert audit.details["retest_integrity"]["status"] == "VERIFIED"
    assert audit.details["retest_integrity"]["verified"] is True


@pytest.mark.asyncio
async def test_linked_vulnerability_retest_reopens_source_when_still_vulnerable(test_engine, monkeypatch):
    template = {
        "id": "retest-still-auth-bypass",
        "info": {"severity": "HIGH"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    _QueuedExecutionEngine.calls = []
    _QueuedExecutionEngine.responses = [
        {"is_vulnerable": True, "evidence": "initial still vulnerable"},
        {"is_vulnerable": True, "evidence": "confirmed still vulnerable"},
    ]
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: _FakeWordlistManager([template]))
    monkeypatch.setattr(tests_router, "ExecutionEngine", _QueuedExecutionEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/retest-still",
        )
        db.add(endpoint)
        await db.flush()
        vulnerability = models.Vulnerability(
            account_id=1000000,
            template_id=template["id"],
            endpoint_id=endpoint.id,
            url="http://api.example.test/retest-still",
            method="GET",
            severity="HIGH",
            type=template["id"],
            status="IN_REMEDIATION",
            evidence={"confirmation": {"confirmed": True}},
        )
        db.add(vulnerability)
        await db.flush()
        run = models.TestRun(
            account_id=1000000,
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
            trigger_source="vulnerability_retest",
            source_vulnerability_id=vulnerability.id,
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        vulnerability_id = vulnerability.id

    await tests_router._run_security_tasks(
        run_id,
        [template["id"]],
        [endpoint.id],
        1000000,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        stored = await db.get(models.Vulnerability, vulnerability_id)
        result_row = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalar_one()
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == vulnerability_id,
                    models.AuditLog.action == "VULNERABILITY_RETEST_COMPLETED",
                )
            )
        ).scalar_one()

    latest = stored.evidence["latest_remediation_retest"]
    assert result_row.is_vulnerable is True
    assert stored.status == "OPEN"
    assert stored.last_seen_at is not None
    assert latest["outcome"] == "STILL_VULNERABLE"
    assert latest["vulnerable"] == 1
    assert latest["retest_hash"] == retest_outcome_digest(latest)
    assert audit.details["outcome"] == "STILL_VULNERABLE"
    assert audit.details["previous_status"] == "IN_REMEDIATION"
    assert audit.details["new_status"] == "OPEN"
    assert audit.details["hash_algorithm"] == "sha256"
    assert audit.details["retest_hash"] == latest["retest_hash"]
    assert audit.details["retest_integrity"]["status"] == "VERIFIED"
    assert audit.details["retest_integrity"]["verified"] is True


@pytest.mark.asyncio
async def test_agentic_pass_persists_chain_detector_and_confirmed_findings_as_vulnerabilities(
    test_engine, monkeypatch
):
    """Chain/detector/LLM-confirmed findings from run_agentic_scan_async must each
    become a persisted Vulnerability (not just an in-memory dict that gets
    discarded), so they reach the dashboard/compliance/export surfaces the same
    way a template finding does."""
    monkeypatch.setattr(tests_router.settings, "AGENTIC_LLM_ENABLED", True)
    monkeypatch.setattr(tests_router.WordlistManager, "get_instance", lambda *args, **kwargs: _FakeWordlistManager([]))

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=1000000,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/agentic-wiring",
        )
        db.add(endpoint)
        await db.flush()
        run = models.TestRun(
            account_id=1000000,
            template_ids=[],
            endpoint_ids=[endpoint.id],
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        endpoint_id = endpoint.id

    async def _fake_agentic_pass(**kwargs):
        return {
            "enabled": True,
            "chain_findings": [
                {
                    "type": "BOLA",
                    "endpoint_id": str(endpoint_id),
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "rationale": "2-step chain: source exposes id, target consumes id",
                    "chain": {"engine": "attack_chain", "attacker_target_status": 200},
                }
            ],
            "detector_findings": [
                {
                    "type": "SQLI",
                    "endpoint_id": str(endpoint_id),
                    "severity": "HIGH",
                    "evidence": {"engine": "sqli_probe", "sub_type": "boolean_based"},
                }
            ],
            "outcome": {
                "confirmed_findings": [
                    {
                        "type": "BFLA",
                        "endpoint_id": str(endpoint_id),
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "rationale": "low-privilege role invoked a privileged function",
                        "evidence": {"engine": "bfla_matrix"},
                    }
                ]
            },
        }

    monkeypatch.setattr(tests_router, "_run_agentic_scan_pass", _fake_agentic_pass)

    await tests_router._run_security_tasks(
        run_id,
        [],
        [endpoint_id],
        1000000,
        db_bind=test_engine,
    )

    async with session_factory() as db:
        vulnerabilities = (
            await db.execute(
                select(models.Vulnerability).where(models.Vulnerability.endpoint_id == endpoint_id)
            )
        ).scalars().all()
        test_results = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()

    by_type = {v.type: v for v in vulnerabilities}
    assert set(by_type) == {"BOLA", "SQLI", "BFLA"}
    assert by_type["BOLA"].template_id == "AGENTIC:CHAIN:BOLA"
    assert by_type["SQLI"].template_id == "AGENTIC:DETECTOR:SQLI"
    assert by_type["BFLA"].template_id == "AGENTIC:AGENTIC:BFLA"
    for vuln in vulnerabilities:
        assert vuln.status == "OPEN"
        assert vuln.evidence["evidence_completeness"]["complete"] is True
        assert verify_vulnerability_evidence(vuln.evidence)["verified"] is True
    assert len(test_results) == 3
