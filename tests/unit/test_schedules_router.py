import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers_for_account(account_id: int, role: str = "ADMIN") -> dict[str, str]:
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
async def test_create_schedule_persists_auth_ready_safe_plan(client, db_session):
    account_id = 1003100
    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/scheduled-users",
    )
    auth_profile = models.AuthProfile(
        account_id=account_id,
        name="schedule bearer",
        auth_mode="bearer",
        token="Bearer schedule-token",
        scope_domains=["api.example.test"],
        is_active=True,
    )
    db_session.add_all([endpoint, auth_profile])
    await db_session.flush()
    pentest_profile = models.PentestProfile(
        account_id=account_id,
        name="Nightly schedule profile",
        auth_profile_id=auth_profile.id,
    )
    db_session.add(pentest_profile)
    await db_session.commit()

    response = await client.post(
        "/api/schedules/",
        headers=_headers_for_account(account_id),
        json={
            "name": "Nightly authenticated safe scan",
            "cron_expression": "0 2 * * *",
            "template_ids": ["auth-bypass"],
            "endpoint_ids": [endpoint.id],
            "pentest_profile_id": pentest_profile.id,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "created"
    assert payload["pentest_profile_id"] == pentest_profile.id
    assert payload["continuous_workflow"] == {
        "scheduled": True,
        "authenticated": True,
        "target_guard_enforced": True,
        "auth_scope_guard_enforced": True,
        "execution_mode": "background",
    }
    assert "schedule-token" not in str(payload["continuous_workflow"])
    stored = await db_session.get(models.TestSchedule, payload["id"])
    assert stored.account_id == account_id
    assert stored.template_ids == ["auth-bypass"]
    assert stored.endpoint_ids == [endpoint.id]
    assert stored.pentest_profile_id == pentest_profile.id

    list_response = await client.get("/api/schedules/", headers=_headers_for_account(account_id))
    assert list_response.status_code == 200
    listed = list_response.json()["schedules"][0]
    assert listed["id"] == payload["id"]
    assert listed["pentest_profile_id"] == pentest_profile.id
    assert listed["continuous_workflow"] == payload["continuous_workflow"]
    assert "schedule-token" not in str(listed["continuous_workflow"])


@pytest.mark.asyncio
async def test_create_schedule_rejects_target_guard_blocked_plan_before_persist(
    client,
    db_session,
    monkeypatch,
):
    account_id = 1003110
    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/blocked-schedule",
    )
    db_session.add(endpoint)
    await db_session.commit()

    monkeypatch.setattr(
        "server.modules.scheduler.test_scheduler.blocked_endpoint_targets",
        lambda _endpoints: [
            {
                "endpoint_id": endpoint.id,
                "url": "https://api.example.test/blocked-schedule",
                "reason": "target host resolved to private address",
            }
        ],
    )

    response = await client.post(
        "/api/schedules/",
        headers=_headers_for_account(account_id),
        json={
            "name": "Blocked schedule",
            "cron_expression": "0 2 * * *",
            "template_ids": ["tpl-1"],
            "endpoint_ids": [endpoint.id],
        },
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "target_guard_blocked"
    blocked_endpoint = message["blocked_endpoints"][0]
    assert blocked_endpoint["endpoint_id"] == endpoint.id
    assert blocked_endpoint["target_guard_policy"]["policy"] == "target_guard"
    assert blocked_endpoint["target_guard_policy"]["blocked"] is True
    assert blocked_endpoint["target_guard_policy"]["url"] == "https://api.example.test/blocked-schedule"
    assert "private" in blocked_endpoint["target_guard_policy"]["reason"]
    schedules = (
        await db_session.execute(
            select(models.TestSchedule).where(models.TestSchedule.account_id == account_id)
        )
    ).scalars().all()
    assert schedules == []


@pytest.mark.asyncio
async def test_create_schedule_rejects_missing_auth_profile_before_persist(client, db_session):
    account_id = 1003120
    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/auth-required-schedule",
    )
    db_session.add(endpoint)
    await db_session.commit()

    response = await client.post(
        "/api/schedules/",
        headers=_headers_for_account(account_id),
        json={
            "name": "Missing auth schedule",
            "cron_expression": "0 3 * * *",
            "template_ids": ["tpl-auth"],
            "endpoint_ids": [endpoint.id],
        },
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "auth_profile_required"
    schedules = (
        await db_session.execute(
            select(models.TestSchedule).where(models.TestSchedule.account_id == account_id)
        )
    ).scalars().all()
    assert schedules == []


@pytest.mark.asyncio
async def test_create_schedule_rejects_auth_profile_scope_blocked_plan_before_persist(client, db_session):
    account_id = 1003125
    endpoint = models.APIEndpoint(
        account_id=account_id,
        method="GET",
        protocol="https",
        host="api.example.test",
        path="/auth-scope-schedule",
    )
    auth_profile = models.AuthProfile(
        account_id=account_id,
        name="wrong schedule bearer",
        auth_mode="bearer",
        token="Bearer schedule-secret-token",
        scope_domains=["other.example.test"],
        is_active=True,
    )
    db_session.add_all([endpoint, auth_profile])
    await db_session.flush()
    pentest_profile = models.PentestProfile(
        account_id=account_id,
        name="Wrong scope schedule profile",
        auth_profile_id=auth_profile.id,
    )
    db_session.add(pentest_profile)
    await db_session.commit()

    response = await client.post(
        "/api/schedules/",
        headers=_headers_for_account(account_id),
        json={
            "name": "Wrong auth scope schedule",
            "cron_expression": "0 3 * * *",
            "template_ids": ["tpl-auth"],
            "endpoint_ids": [endpoint.id],
            "pentest_profile_id": pentest_profile.id,
        },
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "auth_profile_scope_blocked"
    blocked_endpoint = message["blocked_endpoints"][0]
    assert blocked_endpoint["endpoint_id"] == endpoint.id
    policy = blocked_endpoint["auth_profile_scope_policy"]
    assert policy["policy"] == "auth_profile_scope_guard"
    assert policy["blocked"] is True
    assert policy["url"] == "https://api.example.test/auth-scope-schedule"
    assert policy["base_url"] == "https://api.example.test/auth-scope-schedule"
    assert policy["auth_profile_id"] == auth_profile.id
    assert policy["scope_domains_configured"] is True
    assert policy["scope_domain_count"] == 1
    assert "schedule-secret-token" not in str(message)
    schedules = (
        await db_session.execute(
            select(models.TestSchedule).where(models.TestSchedule.account_id == account_id)
        )
    ).scalars().all()
    assert schedules == []


@pytest.mark.asyncio
async def test_create_schedule_rejects_invalid_cron_before_persist(client, db_session):
    account_id = 1003130
    response = await client.post(
        "/api/schedules/",
        headers=_headers_for_account(account_id),
        json={
            "name": "Invalid cron schedule",
            "cron_expression": "not-a-cron",
            "template_ids": ["tpl-1"],
            "endpoint_ids": [],
        },
    )

    assert response.status_code == 400
    assert response.json()["message"]["reason"] == "invalid_cron_expression"
    schedules = (
        await db_session.execute(
            select(models.TestSchedule).where(models.TestSchedule.account_id == account_id)
        )
    ).scalars().all()
    assert schedules == []
