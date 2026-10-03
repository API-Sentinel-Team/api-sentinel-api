import pytest
from sqlalchemy import select

from sentinel_core.models.core import Alert, AuditLog, IngestionJob, MaliciousEventRecord, RequestLog, Sensor
from server.modules.sensors.keys import hash_sensor_key


@pytest.mark.asyncio
async def test_stream_ingest_requires_sensor_key(client):
    response = await client.post("/api/stream/ingest", json={"lines": ["127.0.0.1 - - [ok]"]})
    assert response.status_code == 403
    assert response.json()["message"] == "Sensor key required"


@pytest.mark.asyncio
async def test_stream_ingest_rejects_invalid_sensor_key(client):
    response = await client.post(
        "/api/stream/ingest",
        headers={"x-sensor-key": "bad-key"},
        json={"lines": ["127.0.0.1 - - [ok]"]},
    )
    assert response.status_code == 403
    assert response.json()["message"] == "Invalid sensor key"


@pytest.mark.asyncio
async def test_stream_ingest_uses_sensor_account(client, db_session, monkeypatch):
    raw_sensor_key = "sensor-key-2003"
    sensor = Sensor(
        id="sensor-ingest-1",
        account_id=2003,
        name="collector-1",
        host="gateway.internal",
        sensor_key=raw_sensor_key,
    )
    db_session.add(sensor)
    await db_session.commit()

    queued_items = []

    async def fake_enqueue(item):
        queued_items.append(item)
        return True

    monkeypatch.setattr("server.api.routers.stream.ingestion_queue.enqueue", fake_enqueue)

    response = await client.post(
        "/api/stream/ingest",
        headers={"x-sensor-key": sensor.sensor_key},
        json={"lines": ["127.0.0.1 - - [ok]"]},
    )
    assert response.status_code == 200
    job_id = response.json()["job_id"]

    result = await db_session.execute(select(IngestionJob).where(IngestionJob.id == job_id))
    job = result.scalar_one()
    assert job.job_type == "stream_lines"
    assert job.account_id == sensor.account_id
    assert job.job_metadata["sensor_id"] == sensor.id
    assert job.job_metadata["sensor_name"] == sensor.name
    assert raw_sensor_key not in str(job.job_metadata)

    assert len(queued_items) == 1
    queued_item = queued_items[0]
    assert queued_item.account_id == sensor.account_id
    assert queued_item.payload["sensor_id"] == sensor.id
    assert "sensor_key" not in queued_item.payload
    assert raw_sensor_key not in str(queued_item.payload)

    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.resource_id == job_id,
            AuditLog.action == "INGESTION_STREAM_ENQUEUED",
        )
    )
    audit = audit_result.scalar_one()
    assert audit.details["sensor_id"] == sensor.id
    assert audit.details["accepted"] == 1
    assert audit.details_encrypted is None
    assert raw_sensor_key not in str(audit.details)


@pytest.mark.asyncio
async def test_stream_ingest_accepts_hashed_at_rest_sensor_key(client, db_session, monkeypatch):
    raw_sensor_key = "raw-stream-hashed-sensor-key"
    sensor = Sensor(
        id="sensor-ingest-hashed",
        account_id=2004,
        name="collector-hashed",
        sensor_key=hash_sensor_key(raw_sensor_key),
    )
    db_session.add(sensor)
    await db_session.commit()

    queued_items = []

    async def fake_enqueue(item):
        queued_items.append(item)
        return True

    monkeypatch.setattr("server.api.routers.stream.ingestion_queue.enqueue", fake_enqueue)

    response = await client.post(
        "/api/stream/ingest",
        headers={"x-sensor-key": raw_sensor_key},
        json={"lines": ["127.0.0.1 - - [ok]"]},
    )

    assert response.status_code == 200
    assert queued_items[0].account_id == sensor.account_id
    assert queued_items[0].payload["sensor_id"] == sensor.id
    assert raw_sensor_key not in str(queued_items[0].payload)


@pytest.mark.asyncio
async def test_stream_ebpf_ingest_requires_sensor_key(client):
    response = await client.post("/api/stream/ingest/ebpf", json={"events": [{"path": "/health"}]})
    assert response.status_code == 403
    assert response.json()["message"] == "Sensor key required"


@pytest.mark.asyncio
async def test_stream_ebpf_redacts_query_values_in_logs_and_broadcasts(
    client,
    db_session,
    monkeypatch,
):
    raw_sensor_key = "raw-ebpf-path-redaction-key"
    sensor = Sensor(
        id="sensor-ebpf-redaction",
        account_id=1000000,
        name="ebpf-redaction",
        sensor_key=hash_sensor_key(raw_sensor_key),
    )
    db_session.add(sensor)
    await db_session.commit()

    broadcasts = []

    async def fake_broadcast(message, account_id=None):
        broadcasts.append({"message": message, "account_id": account_id})

    monkeypatch.setattr("server.api.routers.stream.ws_manager.broadcast", fake_broadcast)

    response = await client.post(
        "/api/stream/ingest/ebpf",
        headers={"Authorization": f"Bearer {raw_sensor_key}"},
        json={
            "events": [
                {
                    "method": "GET",
                    # A real customer host: host-less /admin is API Sentinel's own console and is
                    # deliberately dropped as self-traffic (server.modules.ingestion.self_traffic).
                    "host": "shop.customer-api.example.com",
                    "path": "/admin?q=<script>alert(1)</script>&token=raw-ebpf-token&api_key=raw-ebpf-key",
                    "status": 200,
                    "source_ip": "198.51.100.30",
                    "ts": 1710000000000,
                }
            ]
        },
    )

    assert response.status_code == 200
    request_log = (
        await db_session.execute(
            select(RequestLog).where(RequestLog.source_ip == "198.51.100.30")
        )
    ).scalar_one()
    assert request_log.path == "/admin?q=****&token=****&api_key=****"
    event = (
        await db_session.execute(
            select(MaliciousEventRecord).where(MaliciousEventRecord.ip == "198.51.100.30")
        )
    ).scalar_one()
    alert = (
        await db_session.execute(select(Alert).where(Alert.source_ip == "198.51.100.30"))
    ).scalar_one()
    assert event.url == "shop.customer-api.example.com/admin?q=****&token=****&api_key=****"
    assert alert.endpoint == "/admin?q=****&token=****&api_key=****"
    assert broadcasts[0]["account_id"] == sensor.account_id
    assert broadcasts[0]["message"]["data"]["path"] == "/admin?q=****&token=****&api_key=****"
    stored_and_broadcast = f"{event.url} {alert.message} {alert.endpoint} {broadcasts}"
    assert "raw-ebpf-token" not in stored_and_broadcast
    assert "raw-ebpf-key" not in stored_and_broadcast


@pytest.mark.asyncio
async def test_stream_recent_redacts_legacy_raw_query_values(client, db_session, auth_headers):
    db_session.add(
        RequestLog(
            account_id=1000000,
            source_ip="198.51.100.31",
            method="GET",
            path="/legacy?token=raw-legacy-token&session=raw-session",
            response_code=200,
        )
    )
    await db_session.commit()

    response = await client.get("/api/stream/recent", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    row = next(item for item in body if item["ip"] == "198.51.100.31")
    assert row["path"] == "/legacy?token=****&session=****"
    assert "raw-legacy-token" not in str(body)
    assert "raw-session" not in str(body)


# ---- /v1/events pre-authentication hardening ------------------------------------------------
import gzip
import zlib

from server.api.routers import stream as stream_router


async def _sensor(db_session, key="sensor-key-hardening-1"):
    sensor = Sensor(id="sensor-hardening-1", account_id=2010, name="s", host="h", sensor_key=key)
    db_session.add(sensor)
    await db_session.commit()
    return key


@pytest.mark.asyncio
async def test_v1_events_empty_batch_without_a_key_is_rejected_not_200(client):
    # It used to return 200 {"events_processed": 0} to anyone, before any authentication.
    response = await client.post("/v1/events", json={"version": "v1", "events": []})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_a_gzip_bomb_without_a_key_is_never_decompressed(client, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("an unauthenticated body must not be decompressed")

    monkeypatch.setattr(stream_router.zlib, "decompressobj", boom)
    bomb = gzip.compress(b"\0" * (100 * 1024 * 1024), compresslevel=9)
    assert len(bomb) < 200_000  # ~100 MB of zeros in ~100 KB: the classic bomb
    response = await client.post("/v1/events", content=bomb, headers={"content-encoding": "gzip"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_a_gzip_bomb_with_a_valid_key_is_cut_off_at_the_ceiling(client, db_session, monkeypatch):
    key = await _sensor(db_session)
    monkeypatch.setattr(stream_router, "_MAX_INGEST_DECOMPRESSED_BYTES", 1024 * 1024)
    bomb = gzip.compress(b"\0" * (50 * 1024 * 1024), compresslevel=9)
    response = await client.post(
        "/v1/events",
        content=bomb,
        headers={"content-encoding": "gzip", "authorization": f"Bearer {key}"},
    )
    assert response.status_code == 413


@pytest.mark.asyncio
async def test_an_oversized_body_with_a_valid_key_is_refused_up_front(client, db_session, monkeypatch):
    key = await _sensor(db_session)
    monkeypatch.setattr(stream_router, "_MAX_INGEST_BODY_BYTES", 1000)
    response = await client.post(
        "/v1/events", content=b"x" * 5000, headers={"authorization": f"Bearer {key}", "content-type": "application/json"}
    )
    assert response.status_code == 413


@pytest.mark.asyncio
async def test_corrupt_gzip_with_a_valid_key_is_a_400_not_a_500(client, db_session):
    key = await _sensor(db_session)
    response = await client.post(
        "/v1/events",
        content=b"\x1f\x8b\x08\x00 definitely not gzip",
        headers={"content-encoding": "gzip", "authorization": f"Bearer {key}"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_a_normal_gzipped_empty_batch_with_a_valid_key_still_works(client, db_session):
    key = await _sensor(db_session)
    payload = gzip.compress(b'{"version":"v1","events":[]}')
    response = await client.post(
        "/v1/events", content=payload, headers={"content-encoding": "gzip", "authorization": f"Bearer {key}"}
    )
    assert response.status_code == 200
    assert response.json()["events_processed"] == 0
