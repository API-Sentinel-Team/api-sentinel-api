import datetime

from server.api.routers.stream import _is_http_live_method
from server.modules.ingestion.sensor_time import clamp_sensor_ts_ms, coerce_sensor_ts_ms


def test_clamp_replaces_boot_era_timestamp():
    boot = datetime.datetime(2026, 8, 9, 17, 50, 41, tzinfo=datetime.timezone.utc)
    boot_ms = int(boot.timestamp() * 1000)
    clamped = clamp_sensor_ts_ms(boot_ms)
    now = coerce_sensor_ts_ms(None)
    assert abs(clamped - now) < 5_000


def test_clamp_keeps_fresh_timestamp():
    now = coerce_sensor_ts_ms(None)
    assert clamp_sensor_ts_ms(now) == now


def test_ws_opcodes_are_not_http_live_methods():
    assert not _is_http_live_method("TEXT")
    assert not _is_http_live_method("PING")
    assert not _is_http_live_method("pong")
    assert _is_http_live_method("GET")
    assert _is_http_live_method("POST")
