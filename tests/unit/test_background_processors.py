import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from server.models.core import Account
from server.modules.analytics.processor import AnalyticsProcessor
from server.modules.storage.archiver import ArchiveProcessor


@pytest.mark.asyncio
async def test_analytics_processor_all_tenants_mode_aggregates_each_account(
    db_session,
    test_engine,
    monkeypatch,
):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr("server.modules.analytics.processor.AsyncSessionLocal", session_factory)

    first_account = Account(id=2001, name="Acme")
    second_account = Account(id=2002, name="Bravo")
    db_session.add_all([first_account, second_account])
    await db_session.commit()

    calls: list[tuple[str, int]] = []

    async def fake_aggregate_hourly(db, account_id, hour_start, hour_end):
        calls.append(("hourly", account_id))

    async def fake_aggregate_alerts_daily(db, account_id, day_start, day_end):
        calls.append(("daily", account_id))

    monkeypatch.setattr("server.modules.analytics.processor.aggregate_hourly", fake_aggregate_hourly)
    monkeypatch.setattr("server.modules.analytics.processor.aggregate_alerts_daily", fake_aggregate_alerts_daily)

    processor = AnalyticsProcessor(interval_sec=60, account_id=0)
    await processor._process_once()

    target_calls = [entry for entry in calls if entry[1] in {first_account.id, second_account.id}]
    assert target_calls == [
        ("hourly", first_account.id),
        ("daily", first_account.id),
        ("hourly", second_account.id),
        ("daily", second_account.id),
    ]


@pytest.mark.asyncio
async def test_archive_processor_all_tenants_mode_runs_each_account(
    db_session,
    test_engine,
    monkeypatch,
):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr("server.modules.storage.archiver.AsyncSessionLocal", session_factory)

    db_session.add_all(
        [
            Account(id=3001, name="Acme"),
            Account(id=3002, name="Bravo"),
        ]
    )
    await db_session.commit()

    seen: list[int] = []

    async def fake_archive_once(account_id: int):
        seen.append(account_id)
        return {"status": "ok"}

    monkeypatch.setattr("server.modules.storage.archiver.archive_once", fake_archive_once)

    processor = ArchiveProcessor(interval_sec=3600, account_id=0)
    await processor._process_once()

    filtered_seen = [account_id for account_id in seen if account_id in {3001, 3002}]
    assert filtered_seen == [3001, 3002]
