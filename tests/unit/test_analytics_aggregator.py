import datetime
import pytest
from sqlalchemy import select

from server.models.core import RequestLog, EndpointMetricHourly, ActorMetricHourly
from server.modules.analytics.aggregator import aggregate_hourly


@pytest.mark.asyncio
async def test_aggregate_hourly_creates_metrics(db_session):
    now = datetime.datetime.now(datetime.timezone.utc).replace(minute=30, second=0, microsecond=0)
    hour_start = now.replace(minute=0, second=0, microsecond=0)
    hour_end = hour_start + datetime.timedelta(hours=1)

    db_session.add(RequestLog(
        id="r1",
        account_id=1000000,
        endpoint_id="ep1",
        source_ip="1.1.1.1",
        response_code=200,
        response_time_ms=120,
        created_at=hour_start + datetime.timedelta(minutes=5),
    ))
    db_session.add(RequestLog(
        id="r2",
        account_id=1000000,
        endpoint_id="ep1",
        source_ip="1.1.1.1",
        response_code=500,
        response_time_ms=240,
        created_at=hour_start + datetime.timedelta(minutes=10),
    ))
    await db_session.commit()

    await aggregate_hourly(db_session, 1000000, hour_start, hour_end)
    await db_session.commit()

    result = await db_session.execute(
        select(EndpointMetricHourly).where(
            EndpointMetricHourly.endpoint_id == "ep1",
            EndpointMetricHourly.hour_ts == int(hour_start.timestamp()),
        )
    )
    metric = result.scalar_one()
    assert metric.request_count == 2

    result = await db_session.execute(
        select(ActorMetricHourly).where(
            ActorMetricHourly.actor_id == "1.1.1.1",
            ActorMetricHourly.hour_ts == int(hour_start.timestamp()),
        )
    )
    assert result.scalar_one()
