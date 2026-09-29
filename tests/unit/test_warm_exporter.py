import datetime

import pytest
from sqlalchemy import select

from server.models.core import WarmExportCursor
from server.modules.storage.warm_exporter import WarmStoreExporter


@pytest.mark.asyncio
async def test_warm_exporter_uses_global_cursor_account(db_session):
    exporter = WarmStoreExporter()
    assert exporter._cursor_account_id == 0

    timestamp = datetime.datetime.now(datetime.timezone.utc)
    await exporter._save_cursor(db_session, "endpoint_metrics_hourly", timestamp, "cursor-1")
    await db_session.commit()

    stored = await db_session.execute(
        select(WarmExportCursor).where(
            WarmExportCursor.account_id == 0,
            WarmExportCursor.table_name == "endpoint_metrics_hourly",
        )
    )
    row = stored.scalar_one()

    exporter._cursor["endpoint_metrics_hourly"] = (None, None)
    loaded = await exporter._load_cursor(db_session, "endpoint_metrics_hourly")

    assert row.account_id == 0
    assert row.last_id == "cursor-1"
    assert loaded[1] == "cursor-1"
    assert loaded[0] is not None
    assert loaded[0].replace(tzinfo=datetime.timezone.utc) == timestamp
