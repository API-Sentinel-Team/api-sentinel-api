"""Tests for the mitmproxy body-capture flow processor (no mitmproxy dependency)."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.sensors.keys import generate_sensor_key, hash_sensor_key
from server.modules.traffic_capture.flow_processor import (
    _headers_dict,
    _parsed_body,
    _query_dict,
    process_captured_flow,
    resolve_mitmproxy_sensor,
)


def _har_entry(
    *,
    method="POST",
    url="https://api.example.com/users/42",
    req_headers=None,
    req_body=None,
    status=200,
    resp_headers=None,
    resp_body=None,
    query=None,
):
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
            "queryString": [{"name": k, "value": v} for k, v in (query or {}).items()],
            "body": req_body,
        },
        "response": {
            "status": status,
            "headers": [{"name": k, "value": v} for k, v in (resp_headers or {}).items()],
            "content": {"text": resp_body},
        },
        "host": "api.example.com",
        "port": 443,
        "scheme": "https",
    }


async def _register_sensor(db_session, monkeypatch, *, account_id=1000000) -> str:
    raw_key = generate_sensor_key()
    db_session.add(
        models.Sensor(
            account_id=account_id,
            name="mitmproxy-test",
            sensor_key=hash_sensor_key(raw_key),
        )
    )
    await db_session.commit()
    monkeypatch.setattr(
        "server.modules.traffic_capture.flow_processor.settings.MITMPROXY_SENSOR_API_KEY", raw_key
    )
    return raw_key


# ── pure helpers ──────────────────────────────────────────────────────────────

def test_headers_dict_flattens_har_pairs():
    assert _headers_dict([{"name": "X-Foo", "value": "bar"}]) == {"X-Foo": "bar"}


def test_headers_dict_handles_non_list():
    assert _headers_dict(None) == {}
    assert _headers_dict("not-a-list") == {}


def test_query_dict_flattens_har_pairs():
    assert _query_dict([{"name": "id", "value": "42"}]) == {"id": "42"}


def test_parsed_body_parses_json_string():
    assert _parsed_body('{"a": 1}') == {"a": 1}


def test_parsed_body_wraps_non_json_string():
    assert _parsed_body("not json") == {"raw": "not json"}


def test_parsed_body_returns_none_for_empty():
    assert _parsed_body("") is None
    assert _parsed_body(None) is None


# ── resolve_mitmproxy_sensor ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_sensor_returns_none_when_key_unset(db_session, monkeypatch):
    monkeypatch.setattr(
        "server.modules.traffic_capture.flow_processor.settings.MITMPROXY_SENSOR_API_KEY", ""
    )
    assert await resolve_mitmproxy_sensor(db_session) is None


@pytest.mark.asyncio
async def test_resolve_sensor_returns_none_for_unknown_key(db_session, monkeypatch):
    monkeypatch.setattr(
        "server.modules.traffic_capture.flow_processor.settings.MITMPROXY_SENSOR_API_KEY",
        "not-a-registered-key",
    )
    assert await resolve_mitmproxy_sensor(db_session) is None


@pytest.mark.asyncio
async def test_resolve_sensor_returns_registered_sensor(db_session, monkeypatch):
    await _register_sensor(db_session, monkeypatch, account_id=1000042)
    sensor = await resolve_mitmproxy_sensor(db_session)
    assert sensor is not None
    assert sensor.account_id == 1000042


# ── process_captured_flow ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_process_captured_flow_skips_when_sensor_unresolved(db_session, monkeypatch):
    monkeypatch.setattr(
        "server.modules.traffic_capture.flow_processor.settings.MITMPROXY_SENSOR_API_KEY", ""
    )
    result = await process_captured_flow(db_session, entry=_har_entry())
    assert result["skipped"] is True
    assert result["reason"] == "sensor_not_configured_or_unknown"


@pytest.mark.asyncio
async def test_process_captured_flow_persists_endpoint_and_bodies(db_session, monkeypatch):
    await _register_sensor(db_session, monkeypatch)
    result = await process_captured_flow(
        db_session,
        entry=_har_entry(
            method="POST",
            url="https://api.example.com/users",
            req_body='{"username": "alice"}',
            status=201,
            resp_body='{"id": 42, "username": "alice"}',
        ),
    )
    await db_session.commit()

    assert result["skipped"] is False
    assert result["method"] == "POST"
    assert result["status_code"] == 201

    endpoint = await db_session.get(models.APIEndpoint, result["endpoint_id"])
    assert endpoint is not None
    assert endpoint.last_request_body is not None
    assert endpoint.last_response_body is not None
    assert "alice" in endpoint.last_request_body

    samples = (
        await db_session.execute(
            select(models.SampleData).where(models.SampleData.endpoint_id == endpoint.id)
        )
    ).scalars().all()
    assert len(samples) == 1
    assert samples[0].request["body"] is not None
    assert samples[0].response["body"] is not None


@pytest.mark.asyncio
async def test_process_captured_flow_detects_and_persists_pii_in_response(db_session, monkeypatch):
    await _register_sensor(db_session, monkeypatch)
    result = await process_captured_flow(
        db_session,
        entry=_har_entry(
            method="GET",
            url="https://api.example.com/me",
            resp_body='{"email": "victim@example.com"}',
        ),
    )
    await db_session.commit()

    assert result["pii_findings"] >= 1

    findings = (
        await db_session.execute(
            select(models.SensitiveDataFinding).where(
                models.SensitiveDataFinding.endpoint_id == result["endpoint_id"]
            )
        )
    ).scalars().all()
    assert any(f.entity_type == "EMAIL" and f.source == "response" for f in findings)
    # Raw PII value must never be persisted — only the redacted marker.
    assert all(f.sample_value != "victim@example.com" for f in findings)

    vulnerabilities = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == result["endpoint_id"]
            )
        )
    ).scalars().all()
    assert any("SENSITIVE_DATA_EXPOSURE" in v.type for v in vulnerabilities)


@pytest.mark.asyncio
async def test_process_captured_flow_redacts_bodies_by_default(db_session, monkeypatch):
    await _register_sensor(db_session, monkeypatch)
    result = await process_captured_flow(
        db_session,
        entry=_har_entry(
            method="POST",
            url="https://api.example.com/login",
            req_body='{"password": "correct-horse-battery-staple"}',
        ),
    )
    await db_session.commit()

    endpoint = await db_session.get(models.APIEndpoint, result["endpoint_id"])
    # Default tenant retention policy redacts bodies (full_payload_retention=False).
    assert "correct-horse-battery-staple" not in (endpoint.last_request_body or "")


@pytest.mark.asyncio
async def test_process_captured_flow_handles_non_json_body(db_session, monkeypatch):
    await _register_sensor(db_session, monkeypatch)
    result = await process_captured_flow(
        db_session,
        entry=_har_entry(
            method="GET",
            url="https://api.example.com/health",
            resp_body="OK",
        ),
    )
    await db_session.commit()
    assert result["skipped"] is False


@pytest.mark.asyncio
async def test_process_captured_flow_accepts_real_har_spec_postdata_shape(db_session, monkeypatch):
    """A real HAR 1.2 file (e.g. browser devtools export, uploaded via
    /traffic/har/upload) nests the request body under postData.text per spec,
    not under a top-level "body" key like HARConverter's own simplified shape."""
    await _register_sensor(db_session, monkeypatch)
    entry = {
        "request": {
            "method": "POST",
            "url": "https://api.example.com/orders",
            "headers": [],
            "postData": {"text": '{"item": "widget"}'},
        },
        "response": {"status": 201, "headers": [], "content": {"text": "{}"}},
    }
    result = await process_captured_flow(db_session, entry=entry)
    await db_session.commit()

    assert result["skipped"] is False
    endpoint = await db_session.get(models.APIEndpoint, result["endpoint_id"])
    assert "widget" in (endpoint.last_request_body or "")


@pytest.mark.asyncio
async def test_process_captured_flow_skips_entry_with_no_url(db_session, monkeypatch):
    await _register_sensor(db_session, monkeypatch)
    entry = _har_entry()
    entry["request"]["url"] = ""
    result = await process_captured_flow(db_session, entry=entry)
    assert result["skipped"] is True
    assert result["reason"] == "missing_request_url"
