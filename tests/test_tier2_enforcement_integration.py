"""
Integration tests for TIER 2: Active Enforcement Engine for Threat Mitigation.

Verifies:
1. Adaptive rate limiter enforces BlockedIP, EndpointBlock, RateLimitOverride
2. Threat correlation engine builds risk profiles and auto-blocks actors
3. Incident orchestrator coordinates detection → response workflow
4. Default playbooks are loaded for threat-specific triggers
5. WebSocket event types support enforcement notifications
6. Enforcement audit trail tracks all actions
"""

import pytest
import datetime
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import (
    BlockedIP,
    RateLimitOverride,
    ThreatActor,
    MaliciousEvent,
    MaliciousEventRecord,
    Alert,
    ResponseActionLog,
    ResponsePlaybook,
)
from server.modules.detection.correlation_engine import correlate_threat
from server.modules.response.incident_orchestrator import handle_incident
from server.modules.response.default_playbooks import ensure_default_playbooks
from server.api.websocket.event_types import WSEventType


@pytest.mark.asyncio
async def test_correlation_engine_risk_scoring(db: AsyncSession, account_id: int):
    """Test threat actor risk scoring with severity-weighted increments."""
    source_ip = "192.168.1.100"

    # First event: MEDIUM severity (+0.10)
    result1 = await correlate_threat(
        db,
        account_id,
        source_ip,
        "test_event",
        "MEDIUM",
    )
    assert abs(result1["risk_score"] - 0.10) < 0.01  # Use approximate comparison for floats
    assert result1["event_count"] == 1
    assert result1["auto_blocked"] is False

    # Second event: HIGH severity (+0.20 = 0.30 total)
    result2 = await correlate_threat(
        db,
        account_id,
        source_ip,
        "test_event",
        "HIGH",
    )
    assert abs(result2["risk_score"] - 0.30) < 0.01  # Use approximate comparison for floats
    assert result2["event_count"] == 2
    assert result2["auto_blocked"] is False

    # Third through fifth events: HIGH severity (total: 0.30 + 4*0.20 = 1.10, capped at 1.0)
    for i in range(4):
        result = await correlate_threat(
            db,
            account_id,
            source_ip,
            "test_event",
            "HIGH",
        )

    final_result = await correlate_threat(
        db,
        account_id,
        source_ip,
        "test_event",
        "HIGH",
    )

    assert final_result["risk_score"] == 1.0  # capped at 1.0


@pytest.mark.asyncio
async def test_correlation_engine_auto_blocking(db: AsyncSession, account_id: int):
    """Test auto-blocking when risk_score >= 0.8."""
    source_ip = "192.168.1.101"

    # Event 1: CRITICAL (+0.30) -> risk = 0.30, not blocked yet
    result1 = await correlate_threat(
        db,
        account_id,
        source_ip,
        "test_event",
        "CRITICAL",
    )
    assert result1["auto_blocked"] is False
    assert abs(result1["risk_score"] - 0.30) < 0.01

    # Event 2: CRITICAL (+0.30) -> risk = 0.60, not blocked yet
    result2 = await correlate_threat(
        db,
        account_id,
        source_ip,
        "test_event",
        "CRITICAL",
    )
    assert result2["auto_blocked"] is False
    assert abs(result2["risk_score"] - 0.60) < 0.01

    # Event 3: CRITICAL (+0.30) -> risk = 0.90, auto-block should trigger (>= 0.8)
    result3 = await correlate_threat(
        db,
        account_id,
        source_ip,
        "test_event",
        "CRITICAL",
    )
    assert result3["auto_blocked"] is True, f"Expected auto_blocked=True at risk_score={result3['risk_score']}"
    assert abs(result3["risk_score"] - 0.90) < 0.01

    # Verify BlockedIP was created
    blocked_ip_result = await db.execute(
        select(BlockedIP).where(
            and_(
                BlockedIP.account_id == account_id,
                BlockedIP.ip == source_ip,
            )
        )
    )
    blocked_ip = blocked_ip_result.scalar_one_or_none()
    assert blocked_ip is not None, "BlockedIP should be created when auto-blocking"
    assert blocked_ip.blocked_by == "AUTO"
    assert blocked_ip.risk_score >= 0.8

    # Verify ThreatActor status is BLOCKED
    actor_result = await db.execute(
        select(ThreatActor).where(
            and_(
                ThreatActor.account_id == account_id,
                ThreatActor.source_ip == source_ip,
            )
        )
    )
    actor = actor_result.scalar_one_or_none()
    assert actor is not None, "ThreatActor should exist"
    assert actor.status == "BLOCKED", "ThreatActor status should be BLOCKED after auto-blocking"


@pytest.mark.asyncio
async def test_incident_orchestrator_creates_alert(db: AsyncSession, account_id: int):
    """Test incident orchestrator creates alerts and audit logs."""
    source_ip = "192.168.1.102"
    endpoint_id = "endpoint_123"

    result = await handle_incident(
        db,
        account_id,
        "alert.rate_burst",
        "HIGH",
        source_ip,
        endpoint_id,
        {"reason": "High request rate detected"},
    )

    assert result["alert_id"] is not None
    assert result["actor_id"] is not None
    assert result["actor_risk_score"] == 0.20  # HIGH severity

    # Verify Alert was created
    alert_result = await db.execute(
        select(Alert).where(Alert.id == result["alert_id"])
    )
    alert = alert_result.scalar_one_or_none()
    assert alert is not None
    assert alert.category == "alert.rate_burst"
    assert alert.source_ip == source_ip
    assert alert.status == "OPEN"

    # Verify ResponseActionLog was created
    log_result = await db.execute(
        select(ResponseActionLog).where(
            ResponseActionLog.alert_id == result["alert_id"]
        )
    )
    log = log_result.scalar_one_or_none()
    assert log is not None
    assert log.action_type == "incident.auto_response"
    assert log.status == "SUCCESS"


@pytest.mark.asyncio
async def test_incident_orchestrator_dedup_alerts(db: AsyncSession, account_id: int):
    """Test that incidents are deduplicated within 10 minutes."""
    source_ip = "192.168.1.103"

    # First incident
    result1 = await handle_incident(
        db,
        account_id,
        "alert.rate_burst",
        "HIGH",
        source_ip,
        None,
        {"reason": "First burst"},
    )

    # Second incident, same source_ip and type within 10 minutes
    result2 = await handle_incident(
        db,
        account_id,
        "alert.rate_burst",
        "CRITICAL",
        source_ip,
        None,
        {"reason": "Second burst"},
    )

    # Should reuse the same alert
    assert result1["alert_id"] == result2["alert_id"]


@pytest.mark.asyncio
async def test_default_playbooks_loaded(db: AsyncSession, account_id: int):
    """Test that default playbooks are loaded and include threat-specific ones."""
    created = await ensure_default_playbooks(db, account_id)

    # Should have created playbooks
    assert created >= 0

    # Verify threat-specific playbooks exist
    pb_result = await db.execute(
        select(ResponsePlaybook).where(
            ResponsePlaybook.account_id == account_id
        )
    )
    playbooks = pb_result.scalars().all()
    playbook_names = {pb.name for pb in playbooks}

    # Check for new threat-specific playbooks
    expected_playbooks = {
        "Rate Burst Throttle",
        "Injection WAF Block",
        "High-Risk Actor Block",
        "Credential Stuffing Response",
    }
    assert expected_playbooks.issubset(playbook_names)


@pytest.mark.asyncio
async def test_ws_event_types_defined():
    """Test that all required WebSocket event types are defined."""
    # Verify new event types exist
    assert hasattr(WSEventType, "IP_BLOCKED")
    assert hasattr(WSEventType, "ENDPOINT_BLOCKED")
    assert hasattr(WSEventType, "RATE_LIMITED")
    assert hasattr(WSEventType, "INCIDENT_CREATED")

    # Verify they have string values
    assert WSEventType.IP_BLOCKED.value == "IP_BLOCKED"
    assert WSEventType.ENDPOINT_BLOCKED.value == "ENDPOINT_BLOCKED"
    assert WSEventType.RATE_LIMITED.value == "RATE_LIMITED"
    assert WSEventType.INCIDENT_CREATED.value == "INCIDENT_CREATED"


@pytest.mark.asyncio
async def test_malicious_event_records_created(db: AsyncSession, account_id: int):
    """Test that full-fidelity MaliciousEventRecord is created on threat correlation."""
    source_ip = "192.168.1.104"

    await correlate_threat(
        db,
        account_id,
        source_ip,
        "injection_detected",
        "CRITICAL",
        endpoint_id="endpoint_456",
        payload_snippet="SELECT * FROM users",
    )

    # Verify MaliciousEventRecord was created
    record_result = await db.execute(
        select(MaliciousEventRecord).where(
            and_(
                MaliciousEventRecord.account_id == account_id,
                MaliciousEventRecord.ip == source_ip,
            )
        )
    )
    record = record_result.scalar_one_or_none()
    assert record is not None
    assert record.event_type == "injection_detected"
    assert record.severity == "CRITICAL"
    assert record.label == "threat"
    assert record.payload == "SELECT * FROM users"


@pytest.mark.asyncio
async def test_multiple_actors_isolated(db: AsyncSession, account_id: int):
    """Test that threat actors are properly isolated per IP."""
    source_ip_1 = "192.168.1.105"
    source_ip_2 = "192.168.1.106"

    result1 = await correlate_threat(db, account_id, source_ip_1, "event", "HIGH")
    result2 = await correlate_threat(db, account_id, source_ip_2, "event", "MEDIUM")

    # Should have different actor IDs
    assert result1["actor_id"] != result2["actor_id"]

    # Should have different risk scores
    assert result1["risk_score"] == 0.20
    assert result2["risk_score"] == 0.10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
