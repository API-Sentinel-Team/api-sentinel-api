import pytest
from sqlalchemy import select

from server.models.core import Sensor
from server.modules.sensors.keys import SENSOR_KEY_HASH_PREFIX, hash_sensor_key


@pytest.mark.asyncio
async def test_sensor_register_hashes_key_at_rest_and_returns_safe_urls(client, auth_headers, db_session):
    response = await client.post(
        "/api/sensors/register",
        headers=auth_headers,
        json={"name": "edge-collector", "host": "gateway.internal"},
    )

    assert response.status_code == 200
    body = response.json()
    raw_key = body["sensor_key"]
    assert body["heartbeat_url"] == "/api/sensors/heartbeat"
    assert body["status_url"] == "/api/sensors/status"
    assert raw_key not in body["heartbeat_url"]
    assert raw_key not in body["status_url"]

    stored = (
        await db_session.execute(select(Sensor).where(Sensor.id == body["sensor_id"]))
    ).scalar_one()
    assert stored.sensor_key.startswith(SENSOR_KEY_HASH_PREFIX)
    assert stored.sensor_key == hash_sensor_key(raw_key)
    assert stored.sensor_key != raw_key

    replay = await client.get("/api/sensors/status", headers={"X-Sensor-Key": stored.sensor_key})
    assert replay.status_code == 401


@pytest.mark.asyncio
async def test_sensor_heartbeat_accepts_header_key_without_url_secret(client, db_session):
    raw_key = "raw-sensor-heartbeat-key"
    sensor = Sensor(
        id="sensor-header-heartbeat",
        account_id=1000000,
        name="header-heartbeat",
        sensor_key=hash_sensor_key(raw_key),
        status="OFFLINE",
        lines_shipped=0,
        events_detected=0,
    )
    db_session.add(sensor)
    await db_session.commit()

    response = await client.post(
        "/api/sensors/heartbeat",
        headers={"X-Sensor-Key": raw_key},
        json={"lines_shipped": 12, "events_detected": 3},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "sensor_id": sensor.id}
    await db_session.refresh(sensor)
    assert sensor.status == "ONLINE"
    assert sensor.lines_shipped == 12
    assert sensor.events_detected == 3
    assert sensor.last_heartbeat is not None


@pytest.mark.asyncio
async def test_sensor_status_accepts_bearer_key_and_never_returns_key(client, db_session):
    raw_key = "raw-sensor-status-key"
    sensor = Sensor(
        id="sensor-header-status",
        account_id=1000000,
        name="header-status",
        sensor_key=hash_sensor_key(raw_key),
        status="ONLINE",
    )
    db_session.add(sensor)
    await db_session.commit()

    response = await client.get(
        "/api/sensors/status",
        headers={"Authorization": f"Bearer {raw_key}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == sensor.id
    assert "sensor_key" not in body
    assert raw_key not in str(body)


@pytest.mark.asyncio
async def test_sensor_header_routes_reject_missing_or_invalid_key(client, db_session):
    missing = await client.post("/api/sensors/heartbeat", json={})
    invalid = await client.get("/api/sensors/status", headers={"X-Sensor-Key": "invalid"})

    assert missing.status_code == 401
    assert invalid.status_code == 401

    rows = (await db_session.execute(select(Sensor))).scalars().all()
    assert all(row.sensor_key != "invalid" for row in rows)


@pytest.mark.asyncio
async def test_ingestion_v2_heartbeat_accepts_hashed_sensor_key(client, db_session):
    raw_key = "raw-v2-heartbeat-key"
    sensor = Sensor(
        id="sensor-ingestion-v2-heartbeat",
        account_id=1000000,
        name="ingestion-v2",
        sensor_key=hash_sensor_key(raw_key),
        status="OFFLINE",
    )
    db_session.add(sensor)
    await db_session.commit()

    response = await client.post(
        "/api/ingestion/v2/heartbeat",
        headers={"X-API-Key": raw_key},
        json={"metrics": {"events_captured": 8}},
    )

    assert response.status_code == 200
    await db_session.refresh(sensor)
    assert sensor.status == "ONLINE"
    assert sensor.lines_shipped == 8
