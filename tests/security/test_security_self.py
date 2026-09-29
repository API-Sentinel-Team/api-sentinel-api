import pytest
from httpx import AsyncClient
from server.modules.auth.jwt_issuer import JWTIssuer

@pytest.mark.asyncio
async def test_jwt_none_algorithm_attack(client: AsyncClient):
    # Attacking the /api/auth/me endpoint with 'none' algorithm
    payload = {"sub": "admin", "role": "ADMIN"}
    # Construct a JWT with 'none' algorithm
    header = {"alg": "none", "typ": "JWT"}
    import base64
    import json
    
    def b64_encode(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().replace("=", "")
    
    bad_token = f"{b64_encode(header)}.{b64_encode(payload)}."
    
    resp = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {bad_token}"})
    # Must be 401, not 200
    assert resp.status_code == 401

@pytest.mark.asyncio
async def test_bola_cross_tenant_isolation(client: AsyncClient):
    token_a = JWTIssuer.create_access_token({
        "sub": "tenant-a-admin",
        "email": "tenant_a@test.com",
        "account_id": 1000000,
        "role": "ADMIN",
    })
    token_b = JWTIssuer.create_access_token({
        "sub": "tenant-b-admin",
        "email": "tenant_b@test.com",
        "account_id": 2000000,
        "role": "ADMIN",
    })

    ep_a = await client.post(
        "/api/endpoints/",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"method": "GET", "path": "/a", "host": "h"},
    )
    ep_id_a = ep_a.json()["id"]

    resp = await client.get(
        f"/api/endpoints/{ep_id_a}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code in (404, 403)

@pytest.mark.asyncio
async def test_mass_assignment_on_signup(client: AsyncClient):
    resp = await client.post("/api/auth/signup", json={
        "email": "hacker@test.com",
        "password": "StrongPass1234!",
        "account_name": "HackerCorp",
        "role": "SUPER_ADMIN" # Unauthorized field injection
    })
    assert resp.status_code == 200

    profile = await client.get("/api/auth/me")
    assert profile.status_code == 200
    assert profile.json()["role"] == "ADMIN"
