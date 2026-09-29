import asyncio
import datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from server.models.core import APIEndpoint
from server.modules.api_inventory.lifecycle import EndpointLifecycleProcessor


@pytest.mark.asyncio
async def test_endpoint_lifecycle_stop_awaits_cancelled_task():
    processor = EndpointLifecycleProcessor(interval_sec=60)
    started = asyncio.Event()

    async def fake_sweep():
        started.set()
        await asyncio.sleep(60)

    processor._sweep = fake_sweep  # type: ignore[method-assign]

    await processor.start()
    await asyncio.wait_for(started.wait(), timeout=1)
    await processor.stop()

    assert processor._task is None


@pytest.mark.asyncio
async def test_endpoint_lifecycle_sweep_handles_sqlite_naive_datetimes(
    db_session,
    test_engine,
    monkeypatch,
):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "server.modules.api_inventory.lifecycle.AsyncSessionLocal",
        session_factory,
    )

    endpoint = APIEndpoint(
        id="ep-lifecycle-naive",
        account_id=1000000,
        method="GET",
        path="/stale",
        host="example.com",
        status="ACTIVE",
        last_seen=datetime.datetime.utcnow() - datetime.timedelta(days=120),
    )
    db_session.add(endpoint)
    await db_session.commit()

    processor = EndpointLifecycleProcessor(interval_sec=60)
    await processor._sweep()

    async with session_factory() as verify_db:
        result = await verify_db.execute(
            select(APIEndpoint).where(APIEndpoint.id == endpoint.id)
        )
        refreshed = result.scalar_one()

    assert refreshed.status == "ZOMBIE"


@pytest.mark.asyncio
async def test_endpoint_lifecycle_sweep_handles_mixed_tz_datetimes(
    db_session,
    test_engine,
    monkeypatch,
):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "server.modules.api_inventory.lifecycle.AsyncSessionLocal",
        session_factory,
    )

    endpoint = APIEndpoint(
        id="ep-lifecycle-aware",
        account_id=1000000,
        method="GET",
        path="/stale-aware",
        host="example.com",
        status="ACTIVE",
        last_seen=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=120),
    )
    db_session.add(endpoint)
    await db_session.commit()

    processor = EndpointLifecycleProcessor(interval_sec=60)
    await processor._sweep()

    async with session_factory() as verify_db:
        result = await verify_db.execute(
            select(APIEndpoint).where(APIEndpoint.id == endpoint.id)
        )
        refreshed = result.scalar_one()

    assert refreshed.status == "ZOMBIE"
