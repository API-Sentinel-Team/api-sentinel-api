import pytest

from server.modules.ingestion.schema import EventBatch, APITrafficEvent, APIRequest, APIResponse


def test_event_batch_schema_validates():
    event = APITrafficEvent(
        account_id=1000000,
        observed_at=1710000000000,
        request=APIRequest(method="GET", path="/health"),
        response=APIResponse(status_code=200),
    )
    batch = EventBatch(events=[event])
    assert batch.version == "v1"
    assert batch.events[0].account_id == 1000000
