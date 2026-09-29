import pytest

from server.models.core import Sensor
from server.modules.sensors.keys import (
    SENSOR_KEY_HASH_PREFIX,
    hash_sensor_key,
    resolve_sensor_by_key,
    sensor_key_is_hashed,
)


def test_hash_sensor_key_uses_prefixed_non_bearer_format():
    raw_key = "raw-sensor-key"
    stored = hash_sensor_key(raw_key)

    assert stored.startswith(SENSOR_KEY_HASH_PREFIX)
    assert stored != raw_key
    assert sensor_key_is_hashed(stored) is True


@pytest.mark.asyncio
async def test_resolve_sensor_by_key_accepts_raw_key_but_rejects_stored_hash(db_session):
    raw_key = "raw-sensor-auth-key"
    stored = hash_sensor_key(raw_key)
    sensor = Sensor(
        id="sensor-key-helper",
        account_id=1000000,
        name="helper",
        sensor_key=stored,
    )
    db_session.add(sensor)
    await db_session.commit()

    assert await resolve_sensor_by_key(db_session, raw_key) is sensor
    assert await resolve_sensor_by_key(db_session, stored) is None
