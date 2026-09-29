from server.modules.streaming.schema_registry import get_registry


def test_schema_registry_validation():
    reg = get_registry()
    ok, err = reg.validate("EnrichedEvent", "1.0", {
        "account_id": 1000000,
        "endpoint_id": "ep1",
        "actor_id": "1.1.1.1",
        "response_code": 200,
        "timestamp_ms": 123,
    })
    assert ok, err
