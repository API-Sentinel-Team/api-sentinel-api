import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

import server.modules.ingestion.processors as processors
from server.models import core as models
from server.modules.ingestion.processors import process_event_batch, process_http_traffic, process_stream_lines
from server.modules.ingestion.redaction import redact_ingestion_path
from server.modules.ingestion.schema import APIRequest, APIResponse, APITrafficEvent, EventBatch


def test_redact_ingestion_path_preserves_shape_and_masks_query_values():
    assert (
        redact_ingestion_path("/profile?token=raw-token&account=123")
        == "/profile?token=****&account=****"
    )
    assert (
        redact_ingestion_path("/search?q=<script>alert(1)</script>&token=raw-token")
        == "/search?q=****&token=****"
    )


@pytest.mark.asyncio
async def test_stream_lines_store_redacted_request_log_path(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(processors, "AsyncSessionLocal", session_factory)

    async def noop_bump_cache_version(account_id):
        return None

    monkeypatch.setattr(processors, "bump_cache_version", noop_bump_cache_version)

    line = (
        '198.51.100.20 - - [10/Mar/2024:12:00:00 +0000] '
        '"GET /profile?token=raw-stream-token&api_key=raw-stream-key HTTP/1.1" '
        '200 128 "-" "curl"'
    )

    await process_stream_lines("redacted-stream-path-job", 1000000, {"lines": [line]})

    async with session_factory() as db:
        request_log = (
            await db.execute(
                select(models.RequestLog).where(
                    models.RequestLog.path == "/profile?token=****&api_key=****",
                )
            )
        ).scalar_one()

    assert request_log.path == "/profile?token=****&api_key=****"
    assert "raw-stream-token" not in request_log.path
    assert "raw-stream-key" not in request_log.path


@pytest.mark.asyncio
async def test_stream_lines_store_redacted_attack_records_and_alerts(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(processors, "AsyncSessionLocal", session_factory)

    async def noop_bump_cache_version(account_id):
        return None

    monkeypatch.setattr(processors, "bump_cache_version", noop_bump_cache_version)

    line = (
        '198.51.100.22 - - [10/Mar/2024:12:00:00 +0000] '
        '"GET /search?q=%27%20or%20%271%27%3D%271&token=raw-attack-token&api_key=raw-attack-key HTTP/1.1" '
        '500 128 "-" "curl"'
    )

    await process_stream_lines("redacted-stream-attack-job", 1000000, {"lines": [line]})

    async with session_factory() as db:
        event = (
            await db.execute(
                select(models.MaliciousEventRecord).where(
                    models.MaliciousEventRecord.ip == "198.51.100.22",
                )
            )
        ).scalar_one()
        alert = (
            await db.execute(
                select(models.Alert).where(
                    models.Alert.source_ip == "198.51.100.22",
                    models.Alert.endpoint == "/search?q=****&token=****&api_key=****",
                )
            )
        ).scalar_one()

    assert event.url == "/search?q=****&token=****&api_key=****"
    assert alert.endpoint == "/search?q=****&token=****&api_key=****"
    assert "raw-attack-token" not in f"{event.url} {alert.message} {alert.endpoint}"
    assert "raw-attack-key" not in f"{event.url} {alert.message} {alert.endpoint}"


@pytest.mark.asyncio
async def test_http_traffic_stores_redacted_attack_record_payloads(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(processors, "AsyncSessionLocal", session_factory)

    async def noop_bump_cache_version(account_id):
        return None

    monkeypatch.setattr(processors, "bump_cache_version", noop_bump_cache_version)

    await process_http_traffic(
        "redacted-http-traffic-job",
        1000000,
        {
            "method": "POST",
            "path": "/admin?token=raw-http-token&api_key=raw-http-key",
            "sourceIp": "198.51.100.23",
            "statusCode": 500,
            "requestPayload": "name=admin' OR 1=1 -- api_key=raw-body-key",
            "responsePayload": "token=raw-response-token",
            "requestHeaders": {
                "Authorization": "Bearer raw-http-auth",
                "X-API-Key": "raw-header-key",
            },
            "responseHeaders": {"Set-Cookie": "session=raw-cookie"},
        },
    )

    async with session_factory() as db:
        event = (
            await db.execute(
                select(models.MaliciousEventRecord).where(
                    models.MaliciousEventRecord.ip == "198.51.100.23",
                )
            )
        ).scalar_one()

    stored = str(
        {
            "url": event.url,
            "payload": event.payload,
            "metadata": event.event_metadata,
        }
    )
    assert event.url == "/admin?token=****&api_key=****"
    assert "raw-http-token" not in stored
    assert "raw-http-key" not in stored
    assert "raw-body-key" not in stored
    assert "raw-http-auth" not in stored
    assert "raw-header-key" not in stored
    assert "raw-response-token" not in stored


@pytest.mark.asyncio
async def test_event_batch_stores_redacted_request_log_path(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(processors, "AsyncSessionLocal", session_factory)

    async def noop_bump_cache_version(account_id):
        return None

    monkeypatch.setattr(processors, "bump_cache_version", noop_bump_cache_version)

    event = APITrafficEvent(
        account_id=1000000,
        observed_at=1710000000000,
        source_ip="198.51.100.21",
        request=APIRequest(
            method="GET",
            path="/orders?token=raw-event-token&session=raw-session",
            host="api.example.com",
        ),
        response=APIResponse(status_code=200),
    )

    await process_event_batch(
        "redacted-event-path-job",
        1000000,
        EventBatch(events=[event]).model_dump(mode="json"),
    )

    async with session_factory() as db:
        request_log = (
            await db.execute(
                select(models.RequestLog).where(
                    models.RequestLog.path == "/orders?token=****&session=****",
                )
            )
        ).scalar_one()

    assert request_log.path == "/orders?token=****&session=****"
    assert "raw-event-token" not in request_log.path
    assert "raw-session" not in request_log.path
