import pytest
from sqlalchemy import select

from server.modules.enforcement.engine import rate_limit_override, circuit_breaker, token_invalidate
from server.models.core import RateLimitOverride, EndpointBlock, JWTRevokedToken


@pytest.mark.asyncio
async def test_rate_limit_override_creates_record(db_session):
    result = await rate_limit_override(
        db_session, account_id=1000000, endpoint_id="ep1", limit_rpm=10, duration_minutes=5, reason="test"
    )
    await db_session.commit()
    assert result["status"] == "SUCCESS"
    rows = (await db_session.execute(select(RateLimitOverride))).scalars().all()
    assert rows


@pytest.mark.asyncio
async def test_circuit_breaker_creates_block(db_session):
    result = await circuit_breaker(
        db_session, account_id=1000000, endpoint_id="ep2", duration_minutes=5, reason="test", blocked_by="MANUAL"
    )
    await db_session.commit()
    assert result["status"] == "SUCCESS"
    rows = (await db_session.execute(select(EndpointBlock))).scalars().all()
    assert rows


@pytest.mark.asyncio
async def test_token_invalidate_creates_revocation(db_session):
    result = await token_invalidate(
        db_session, account_id=1000000, token_jti="jti-1", expires_minutes=5
    )
    await db_session.commit()
    assert result["status"] == "SUCCESS"
    rows = (await db_session.execute(select(JWTRevokedToken))).scalars().all()
    assert rows
