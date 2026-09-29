import pytest

from server.config import settings


@pytest.mark.asyncio
async def test_detection_meta_endpoint(client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "UNIFIED_PIPELINE_MODE", "shadow")

    resp = await client.get("/api/detection/meta", headers=auth_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["mode"] == "shadow"
    assert data["health"]["db_ready"] is True
    assert data["health"]["pipeline_enabled"] is True
    assert data["knowledge_pack_version"] == settings.DETECTION_META_VERSION
    assert len(data["detectors"]) >= 5
    detector_ids = {detector["detector_id"] for detector in data["detectors"]}
    assert "injection" in detector_ids
    assert "burst" in detector_ids
    assert any(ref["name"] == "OWASP API Security Top 10 2023" for ref in data["official_references"])
