from server.api.routers.stream import normalize_sensor_events


def test_v1_events_pass_through():
    payload = {
        "version": "v1",
        "events": [{"method": "GET", "path": "/health", "host": "api.example"}],
    }
    events = normalize_sensor_events(payload)
    assert len(events) == 1
    assert events[0]["path"] == "/health"


def test_session4_msgheader_batch_unwraps():
    payload = {
        "MsgHeader": {"version": "2.0", "TenantId": "default"},
        "Batch": [
            {
                "HTTPReq.Method": "GET",
                "HTTPReq.Uri": "/api/health/ready",
                "HTTPReq.Query": "",
                "Req.Header.host": "sentinel.wecrew.in",
                "Req.Header.user-agent": "curl/8.5.0",
                "HTTPResp.ResponseCode": 200,
                "DownstreamL3L4.SourceIP": "10.0.0.8",
                "L7Protocol": "HTTP/2",
                "SessionStats.StartTime": "2026-08-15T17:21:50.000Z",
            }
        ],
    }
    events = normalize_sensor_events(payload)
    assert len(events) == 1
    ev = events[0]
    assert ev["method"] == "GET"
    assert ev["path"] == "/api/health/ready"
    assert ev["host"] == "sentinel.wecrew.in"
    assert ev["source_ip"] == "10.0.0.8"
    assert ev["request"]["headers"]["user-agent"] == "curl/8.5.0"
    assert ev["response"]["status"] == 200
    assert isinstance(ev["observed_at"], int)
    assert ev["observed_at"] > 1_000_000_000_000


def test_empty_payload():
    assert normalize_sensor_events({}) == []
    assert normalize_sensor_events({"Batch": []}) == []


def test_stale_session_start_is_clamped_to_now():
    import time

    payload = {
        "Batch": [
            {
                "HTTPReq.Method": "GET",
                "HTTPReq.Uri": "/api/health/ready",
                "HTTPResp.ResponseCode": 200,
                "SessionStats.StartTime": "2026-08-09T17:50:41.000392000",
            }
        ],
    }
    events = normalize_sensor_events(payload)
    assert len(events) == 1
    # Stuck BPF boot time must not survive into ingest.
    assert events[0]["observed_at"] > (time.time() - 30) * 1000

