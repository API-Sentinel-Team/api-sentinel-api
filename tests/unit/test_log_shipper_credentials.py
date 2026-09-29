from server.agents import log_shipper


def test_log_shipper_keeps_sensor_key_out_of_urls_and_payloads(tmp_path, monkeypatch):
    raw_key = "raw-log-shipper-sensor-key"
    shipper = log_shipper.LogShipper(
        sensor_key=raw_key,
        log_path=str(tmp_path / "access.log"),
        endpoint="https://soc.example.com/api/stream/ingest",
    )

    assert shipper.hb_url == "https://soc.example.com/api/sensors/heartbeat"
    assert raw_key not in shipper.hb_url

    calls = []

    class Response:
        status_code = 200
        text = "{}"

        def json(self):
            return {"lines_processed": 1, "threats_detected": 0}

    def fake_post(url, json, headers, timeout):
        calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        return Response()

    monkeypatch.setattr(log_shipper.requests, "post", fake_post)

    assert shipper._ship(["127.0.0.1 - - [ok]"]) is True
    assert calls[0]["url"] == "https://soc.example.com/api/stream/ingest"
    assert calls[0]["json"] == {"lines": ["127.0.0.1 - - [ok]"]}
    assert calls[0]["headers"] == {"X-Sensor-Key": raw_key}
    assert raw_key not in str(calls[0]["json"])
