"""Integration test for POST /api/traffic/har/upload — the browser-devtools-style
HAR ingestion path, which must go through the same redaction+PII-scan contract
as the mitmproxy sensor path (both call flow_processor.persist_captured_flow)."""
from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from server.models import core as models


def _har_file(entries: list[dict]) -> tuple[str, bytes, str]:
    payload = json.dumps({"log": {"entries": entries}}).encode("utf-8")
    return ("upload.har", payload, "application/json")


@pytest.mark.asyncio
async def test_har_upload_discovers_endpoint_and_stores_redacted_body(
    client, db_session, auth_headers
):
    entries = [
        {
            "request": {
                "method": "POST",
                "url": "https://api.example.com/login",
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "postData": {"text": json.dumps({"password": "correct-horse-battery-staple"})},
            },
            "response": {
                "status": 200,
                "headers": [],
                "content": {"text": json.dumps({"token": "abc"})},
            },
        }
    ]

    resp = await client.post(
        "/api/traffic/har/upload",
        headers=auth_headers,
        files={"file": _har_file(entries)},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["entries_processed"] == 1
    assert body["endpoints_discovered"] == 1
    assert body["samples_saved"] == 1

    endpoints = (
        await db_session.execute(
            select(models.APIEndpoint).where(models.APIEndpoint.account_id == 1000000)
        )
    ).scalars().all()
    assert len(endpoints) == 1
    assert endpoints[0].method == "POST"
    assert endpoints[0].path == "/login"
    # Redacted by the default tenant retention policy — the raw secret must
    # never land in the endpoint's persisted last_request_body.
    assert "correct-horse-battery-staple" not in (endpoints[0].last_request_body or "")


@pytest.mark.asyncio
async def test_har_upload_detects_and_persists_pii_in_response_body(
    client, db_session, auth_headers
):
    entries = [
        {
            "request": {"method": "GET", "url": "https://api.example.com/me", "headers": []},
            "response": {
                "status": 200,
                "headers": [],
                "content": {"text": json.dumps({"email": "victim@example.com"})},
            },
        }
    ]

    resp = await client.post(
        "/api/traffic/har/upload",
        headers=auth_headers,
        files={"file": _har_file(entries)},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["pii_findings"] >= 1

    findings = (
        await db_session.execute(
            select(models.SensitiveDataFinding).where(
                models.SensitiveDataFinding.account_id == 1000000
            )
        )
    ).scalars().all()
    assert any(f.entity_type == "EMAIL" for f in findings)


@pytest.mark.asyncio
async def test_har_upload_rejects_invalid_json(client, auth_headers):
    resp = await client.post(
        "/api/traffic/har/upload",
        headers=auth_headers,
        files={"file": ("bad.har", b"not json", "application/json")},
    )
    assert resp.status_code == 400
