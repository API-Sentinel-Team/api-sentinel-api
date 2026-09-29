import pytest


@pytest.mark.asyncio
async def test_health_root_aliases(client):
    for path in ("/api/health", "/api/health/"):
        response = await client.get(path)
        assert response.status_code == 200
        body = response.json()
        assert "components" in body
        assert body["database"]["status"] == "connected"


@pytest.mark.asyncio
async def test_health_readiness(client):
    response = await client.get("/api/health/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_health_config_check_requires_admin(client, auth_headers):
    response = await client.get("/api/health/config-check", headers=auth_headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] in {"ok", "warning", "critical"}
