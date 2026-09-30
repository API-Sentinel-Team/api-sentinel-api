"""P0-7 / ISO-1: readiness runtime claims must come from persisted facts.

These tests pin the evidence sources that back an orchestrator readiness claim:
operator-written schedules, worker-executed runs, fresh worker heartbeats,
persisted audit entries, and the worker's own engine-capability advertisement.
Function presence and config values are deliberately *not* evidence.
"""

import datetime

import pytest

from sentinel_core.models import core as models
from server.modules.pentest.runtime_facts import (
    collect_runtime_facts,
    worker_heartbeat_max_age_seconds,
)

ACCOUNT_ID = 1000431
OTHER_ACCOUNT_ID = 1000432


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


@pytest.mark.asyncio
async def test_runtime_facts_report_no_evidence_for_a_fresh_account(db_session):
    facts = await collect_runtime_facts(db_session, account_id=ACCOUNT_ID)

    assert facts["account_id"] == ACCOUNT_ID
    assert facts["evidence_observed"] is False
    assert facts["schedules"]["active_schedule_count"] == 0
    assert facts["schedules"]["authenticated_schedule_count"] == 0
    assert facts["queued"]["queued_execution_observed"] is False
    assert facts["queued"]["isolated_worker_observed"] is False
    assert facts["queued"]["isolated_worker_modes"] == []
    assert facts["queued"]["fresh_worker_count"] == 0
    assert facts["queued"]["stale_worker_count"] == 0
    assert facts["audit"]["entry_count"] == 0
    assert facts["audit"]["target_guard_block_count"] == 0
    assert facts["worker_capabilities"]["advertised"] is False
    assert facts["worker_capabilities"]["engines"] == {}


@pytest.mark.asyncio
async def test_runtime_facts_count_enabled_and_authenticated_schedules_only(db_session):
    db_session.add_all(
        [
            models.TestSchedule(
                account_id=ACCOUNT_ID,
                name="authenticated-nightly",
                cron_expression="0 2 * * *",
                pentest_profile_id="profile-authenticated",
                enabled=True,
            ),
            models.TestSchedule(
                account_id=ACCOUNT_ID,
                name="unauthenticated-nightly",
                cron_expression="0 3 * * *",
                enabled=True,
            ),
            models.TestSchedule(
                account_id=ACCOUNT_ID,
                name="disabled-schedule",
                cron_expression="0 4 * * *",
                pentest_profile_id="profile-authenticated",
                enabled=False,
            ),
            models.TestSchedule(
                account_id=OTHER_ACCOUNT_ID,
                name="other-tenant",
                cron_expression="0 5 * * *",
                pentest_profile_id="profile-other",
                enabled=True,
            ),
        ]
    )
    await db_session.commit()

    facts = await collect_runtime_facts(db_session, account_id=ACCOUNT_ID)

    assert facts["schedules"]["active_schedule_count"] == 2
    assert facts["schedules"]["authenticated_schedule_count"] == 1
    assert facts["evidence_observed"] is True



@pytest.mark.asyncio
async def test_runtime_facts_separate_executed_runs_from_heartbeat_freshness(db_session):
    now = _utc_now()
    max_age = worker_heartbeat_max_age_seconds()
    db_session.add_all(
        [
            models.TestRun(
                account_id=ACCOUNT_ID,
                status="COMPLETED",
                template_ids=["t"],
                endpoint_ids=["e"],
                worker_id="worker-completed",
                worker_heartbeat_at=now - datetime.timedelta(seconds=max_age * 4),
            ),
            models.TestRun(
                account_id=ACCOUNT_ID,
                status="RUNNING",
                template_ids=["t"],
                endpoint_ids=["e"],
                worker_id="worker-live",
                worker_heartbeat_at=now - datetime.timedelta(seconds=30),
                dispatch_lease_expires_at=now + datetime.timedelta(seconds=300),
            ),
            models.TestRun(
                account_id=ACCOUNT_ID,
                status="DISPATCHED",
                template_ids=["t"],
                endpoint_ids=["e"],
                worker_id="worker-stale",
                worker_heartbeat_at=now - datetime.timedelta(seconds=max_age * 4),
                dispatch_lease_expires_at=now + datetime.timedelta(seconds=300),
            ),
            models.TestRun(
                account_id=OTHER_ACCOUNT_ID,
                status="PENDING",
                template_ids=["t"],
                endpoint_ids=["e"],
            ),
        ]
    )
    await db_session.commit()

    facts = await collect_runtime_facts(db_session, account_id=ACCOUNT_ID, now=now)

    assert facts["queued"]["queued_execution_observed"] is True
    assert facts["queued"]["fresh_worker_count"] == 1
    assert facts["queued"]["stale_worker_count"] == 1
    assert facts["queued"]["heartbeat_max_age_seconds"] == max_age


@pytest.mark.asyncio
async def test_runtime_facts_read_worker_advertisement_from_the_claim_audit_entry(db_session):
    db_session.add(
        models.AuditLog(
            account_id=ACCOUNT_ID,
            action="SCAN_RUN_CLAIMED",
            resource_type="test_run",
            resource_id="run-advertised",
            details={
                "worker_id": "worker-1",
                "worker_capabilities": {
                    "advertised_at": "2026-09-26T00:00:00Z",
                    "engines": {
                        "schemathesis": {"available": True},
                        "nuclei": {"available": True},
                        "zap": {"available": False},
                    },
                },
            },
        )
    )
    await db_session.commit()

    facts = await collect_runtime_facts(db_session, account_id=ACCOUNT_ID)

    assert facts["worker_capabilities"]["advertised"] is True
    assert facts["worker_capabilities"]["source"] == "claim_audit"
    assert facts["worker_capabilities"]["engines"] == {
        "schemathesis": True,
        "nuclei": True,
        "zap": False,
    }


@pytest.mark.asyncio
async def test_runtime_facts_read_worker_advertisement_and_isolation_from_execution_artifact(db_session):
    db_session.add(
        models.PentestArtifact(
            account_id=ACCOUNT_ID,
            run_id="run-isolated",
            artifact_type="nuclei_execution",
            content_json={
                "artifact_type": "nuclei_execution",
                "worker_capabilities": {
                    "advertised_at": "2026-09-26T00:00:00Z",
                    "engines": {
                        "schemathesis": {"available": False},
                        "nuclei": {"available": True},
                        "zap": {"available": False},
                    },
                },
                "worker_isolation": {
                    "session": {"mode": "leased_external_worker", "worker_id": "worker-1"},
                },
            },
        )
    )
    await db_session.commit()

    facts = await collect_runtime_facts(db_session, account_id=ACCOUNT_ID)

    assert facts["worker_capabilities"]["advertised"] is True
    assert facts["worker_capabilities"]["source"] == "execution_artifact"
    assert facts["worker_capabilities"]["engines"] == {
        "schemathesis": False,
        "nuclei": True,
        "zap": False,
    }
    assert facts["queued"]["isolated_worker_observed"] is True
    assert facts["queued"]["isolated_worker_modes"] == ["leased_external_worker"]


@pytest.mark.asyncio
async def test_runtime_facts_do_not_treat_the_api_host_process_as_an_isolated_worker(db_session):
    db_session.add(
        models.PentestArtifact(
            account_id=ACCOUNT_ID,
            run_id="run-inline",
            artifact_type="templates_execution",
            content_json={
                "artifact_type": "templates_execution",
                "worker_isolation": {"session": {"mode": "background"}},
            },
        )
    )
    await db_session.commit()

    facts = await collect_runtime_facts(db_session, account_id=ACCOUNT_ID)

    assert facts["queued"]["isolated_worker_observed"] is False
    assert facts["queued"]["isolated_worker_modes"] == []


@pytest.mark.asyncio
async def test_runtime_facts_count_persisted_audit_entries(db_session):
    db_session.add_all(
        [
            models.AuditLog(account_id=ACCOUNT_ID, action="SCAN_RUN_CLAIMED", resource_type="test_run"),
            models.AuditLog(account_id=ACCOUNT_ID, action="TARGET_GUARD_BLOCKED", resource_type="endpoint"),
            models.AuditLog(account_id=OTHER_ACCOUNT_ID, action="SCAN_RUN_CLAIMED", resource_type="test_run"),
        ]
    )
    await db_session.commit()

    facts = await collect_runtime_facts(db_session, account_id=ACCOUNT_ID)

    assert facts["audit"]["entry_count"] == 2
    assert facts["audit"]["target_guard_block_count"] == 1


def test_worker_heartbeat_max_age_defaults_to_a_positive_window(monkeypatch):
    assert worker_heartbeat_max_age_seconds() > 0
    monkeypatch.setattr("sentinel_core.config.settings.PENTEST_SCAN_WORKER_HEARTBEAT_MAX_AGE_SECONDS", 42)
    assert worker_heartbeat_max_age_seconds() == 42
    monkeypatch.setattr("sentinel_core.config.settings.PENTEST_SCAN_WORKER_HEARTBEAT_MAX_AGE_SECONDS", 0)
    assert worker_heartbeat_max_age_seconds() > 0
