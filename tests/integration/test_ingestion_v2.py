import pytest

from server.modules.ingestion.schema import EventBatch, APITrafficEvent, APIRequest, APIResponse


@pytest.mark.asyncio
async def test_ingestion_v2_job_lifecycle(client, auth_headers):
    event = APITrafficEvent(
        account_id=1000000,
        observed_at=1710000000000,
        request=APIRequest(method="GET", path="/health"),
        response=APIResponse(status_code=200),
    )
    payload = EventBatch(events=[event]).model_dump()

    resp = await client.post("/api/ingestion/v2/events", json=payload, headers=auth_headers)
    assert resp.status_code == 200
    job_id = resp.json().get("job_id")
    assert job_id

    job_resp = await client.get(f"/api/ingestion/jobs/{job_id}", headers=auth_headers)
    assert job_resp.status_code == 200
    data = job_resp.json()
    assert data["id"] == job_id
