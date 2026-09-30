"""Tests for the shared Testing<->Detection risk memory (Gap B)."""
from __future__ import annotations

import datetime
import uuid

import pytest

from sentinel_core.models.core import APIEndpoint
from sentinel_core.modules.api_inventory.endpoint_risk import (
    confirmed_vuln_risk_floor,
    elevate_risk_score,
    endpoint_risk_multiplier,
    record_confirmed_vulnerability_risk,
)


# ── pure math ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "severity,expected_floor",
    [("CRITICAL", 0.95), ("HIGH", 0.80), ("MEDIUM", 0.55), ("LOW", 0.30), ("INFO", 0.15)],
)
def test_confirmed_vuln_risk_floor(severity, expected_floor):
    assert confirmed_vuln_risk_floor(severity) == expected_floor


def test_confirmed_vuln_risk_floor_unknown_defaults_low():
    assert confirmed_vuln_risk_floor("???") == 0.15
    assert confirmed_vuln_risk_floor(None) == 0.15


def test_elevate_raises_to_floor():
    assert elevate_risk_score(0.0, "CRITICAL") == 0.95
    assert elevate_risk_score(0.1, "HIGH") == 0.80


def test_elevate_never_lowers_and_bumps_when_above_floor():
    # Already above the HIGH floor -> small repeat bump, capped at 1.0.
    assert elevate_risk_score(0.9, "HIGH") == pytest.approx(0.95)
    assert elevate_risk_score(1.0, "CRITICAL") == 1.0


# ── DB flow: confirmed vuln raises endpoint risk ─────────────────────────────

def _endpoint(account_id: int, risk: float | None = None) -> APIEndpoint:
    return APIEndpoint(
        id=str(uuid.uuid4()),
        account_id=account_id,
        method="GET",
        path="/users/1",
        path_pattern="/users/{id}",
        host="api.example.com",
        protocol="https",
        risk_score=risk,
    )


@pytest.mark.asyncio
async def test_record_confirmed_vulnerability_risk_raises_score(db):
    ep = _endpoint(1000000, risk=0.1)
    db.add(ep)
    await db.flush()

    now = datetime.datetime.now(datetime.timezone.utc)
    new_score = await record_confirmed_vulnerability_risk(
        db, account_id=1000000, endpoint_id=ep.id, severity="CRITICAL", now=now
    )
    assert new_score == 0.95
    assert ep.risk_score == 0.95
    assert ep.last_tested is not None


@pytest.mark.asyncio
async def test_record_confirmed_vulnerability_risk_missing_endpoint_is_safe(db):
    result = await record_confirmed_vulnerability_risk(
        db, account_id=1000000, endpoint_id="does-not-exist", severity="HIGH"
    )
    assert result is None


@pytest.mark.asyncio
async def test_endpoint_risk_multiplier_scales_with_risk(db):
    ep = _endpoint(1000000, risk=1.0)
    db.add(ep)
    await db.flush()

    mult = await endpoint_risk_multiplier(db, account_id=1000000, endpoint_id=ep.id)
    assert mult == 3.0  # full risk -> max multiplier


@pytest.mark.asyncio
async def test_endpoint_risk_multiplier_untested_is_neutral(db):
    ep = _endpoint(1000000, risk=None)
    db.add(ep)
    await db.flush()
    mult = await endpoint_risk_multiplier(db, account_id=1000000, endpoint_id=ep.id)
    assert mult == 1.0


@pytest.mark.asyncio
async def test_endpoint_risk_multiplier_unknown_endpoint_is_neutral(db):
    assert await endpoint_risk_multiplier(db, account_id=1000000, endpoint_id="nope") == 1.0
    assert await endpoint_risk_multiplier(db, account_id=1000000, endpoint_id=None) == 1.0


@pytest.mark.asyncio
async def test_confirmed_vuln_via_store_elevates_endpoint_risk(db):
    """End-to-end: persisting a vulnerability lifts its endpoint's risk_score."""
    from sentinel_core.modules.vulnerability_detector.store import create_or_merge_vulnerability

    ep = _endpoint(1000000, risk=0.0)
    db.add(ep)
    await db.flush()

    vuln, created, _ = await create_or_merge_vulnerability(
        db,
        {
            "account_id": 1000000,
            "template_id": "BOLA_TEST",
            "endpoint_id": ep.id,
            "url": "https://api.example.com/users/1",
            "method": "GET",
            "severity": "HIGH",
            "type": "BOLA",
            "status": "OPEN",
        },
    )
    assert created is True
    await db.refresh(ep)
    assert ep.risk_score == 0.80  # HIGH floor applied through the store chokepoint


@pytest.mark.asyncio
async def test_detection_amplifies_risk_on_proven_vulnerable_endpoint(db, monkeypatch):
    """The full Gap B loop: same threat event scores higher on a proven-vulnerable
    endpoint than on an untested one — Testing's knowledge reaches Detection."""
    # correlate_threat only computes real risk on the legacy path; in shadow/active
    # mode (the default) it delegates to the unified pipeline and returns risk 0.0.
    from sentinel_core.config import settings as app_settings

    monkeypatch.setattr(app_settings, "UNIFIED_PIPELINE_MODE", "off")
    from server.modules.detection.correlation_engine import correlate_threat

    vulnerable_ep = _endpoint(1000000, risk=1.0)   # proven vulnerable
    safe_ep = _endpoint(1000000, risk=0.0)         # untested / unknown
    db.add_all([vulnerable_ep, safe_ep])
    await db.flush()

    # Same low-severity event against each endpoint, from two distinct actors.
    res_safe = await correlate_threat(
        db, account_id=1000000, source_ip="10.0.0.1",
        event_type="suspicious_access", severity="LOW", endpoint_id=safe_ep.id,
    )
    res_vuln = await correlate_threat(
        db, account_id=1000000, source_ip="10.0.0.2",
        event_type="suspicious_access", severity="LOW", endpoint_id=vulnerable_ep.id,
    )

    # The actor hitting the proven-vulnerable endpoint accrues more risk for the
    # identical event — that is the shared-memory amplification working.
    assert res_vuln["risk_score"] > res_safe["risk_score"]

