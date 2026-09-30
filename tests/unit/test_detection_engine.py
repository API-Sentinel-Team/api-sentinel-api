import asyncio
import pytest
from sqlalchemy import select

from sentinel_core.config import settings
from server.modules.detection.engine import detect_api_behavior, update_actor_profile
from sentinel_core.models.core import ActorProfile, Alert, EvidenceRecord

@pytest.mark.asyncio
async def test_actor_profile_creation(db_session):
    actor_id = "1.2.3.4"
    timestamp = int(asyncio.get_event_loop().time() * 1000)
    profile, rate, _ = await update_actor_profile(
        db_session,
        account_id=1000000,
        actor_id=actor_id,
        endpoint_id="endpoint-1",
        timestamp_ms=timestamp,
        response_ms=120,
    )
    await db_session.commit()

    assert profile.actor_id == actor_id
    assert profile.total_events == 1
    assert profile.avg_response_ms == 120
    assert rate > 0

    result = await db_session.execute(select(ActorProfile))
    assert result.scalars().one()

@pytest.mark.asyncio
async def test_detect_api_behavior_triggers_alert(monkeypatch, db_session):
    # This test targets the legacy detection path; the unified pipeline (shadow default)
    # would swallow the event without writing a legacy Alert row.
    monkeypatch.setattr(settings, "UNIFIED_PIPELINE_MODE", "off")
    monkeypatch.setattr(settings, "DETECTION_WINDOW_SECONDS", 5)
    monkeypatch.setattr(settings, "DETECTION_BURST_THRESHOLD", 2)
    monkeypatch.setattr(settings, "DETECTION_ALERT_COOLDOWN_SECONDS", 0)
    actor_id = "10.0.0.1"
    path = "/login"
    ts = int(asyncio.get_event_loop().time() * 1000)

    for i in range(3):
        await detect_api_behavior(
            db_session,
            account_id=1000000,
            actor_id=actor_id,
            endpoint_id="endpoint-burst",
            path=path,
            timestamp_ms=ts + i * 10,
            latency_ms=50,
        )

    await db_session.commit()

    alert_result = await db_session.execute(select(Alert).where(Alert.account_id == 1000000))
    alerts = alert_result.scalars().all()
    assert alerts, "Expected at least one alert"
    evidence_result = await db_session.execute(select(EvidenceRecord))
    assert evidence_result.scalars().all()
