import pytest

from server.models.core import APIEndpoint, WarmExportCursor


@pytest.mark.asyncio
async def test_account_scoped_models_require_account_id(db_session):
    db_session.add(
        APIEndpoint(
            id="ep-missing-account",
            method="GET",
            path="/health",
            host="api.example.com",
        )
    )

    with pytest.raises(ValueError, match="account_id is required"):
        await db_session.flush()


@pytest.mark.asyncio
async def test_account_scoped_models_reject_non_positive_account_id(db_session):
    db_session.add(
        APIEndpoint(
            id="ep-zero-account",
            account_id=0,
            method="GET",
            path="/health",
            host="api.example.com",
        )
    )

    with pytest.raises(ValueError, match="account_id must be > 0"):
        await db_session.flush()


@pytest.mark.asyncio
async def test_warm_export_cursor_allows_global_account_id_zero(db_session):
    cursor = WarmExportCursor(
        account_id=0,
        table_name="endpoint_metrics_hourly",
        last_id="cursor-1",
    )
    db_session.add(cursor)
    await db_session.flush()

    assert cursor.account_id == 0
