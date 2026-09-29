"""
Integration tests: Multi-identity BOLA/BFLA test account management.

Covers:
- Creating test accounts for different identity roles
- Identity matrix readiness checks
- Deletion of test accounts
- Tenant isolation (accounts from one tenant cannot be read by another)
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def admin_cookies(client: AsyncClient):
    r = await client.post(
        "/api/auth/signup",
        json={
            "email": "bola_admin@test.io",
            "password": "BolaAdmin!Pass1234",
            "account_name": "BolaTestCorp",
        },
    )
    assert r.status_code in (200, 201), r.text
    return r.cookies


async def test_list_test_accounts_empty(client: AsyncClient, admin_cookies):
    r = await client.get("/api/bola/test-accounts", cookies=admin_cookies)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert data["identity_matrix"]["multi_identity_ready"] is False


async def test_create_test_account_admin(client: AsyncClient, admin_cookies):
    r = await client.post(
        "/api/bola/test-accounts",
        json={
            "name": "Admin Identity",
            "role": "ADMIN",
            "auth_token": "Bearer admin-token-abc123",
        },
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "created"
    assert data["role"] == "ADMIN"
    assert "id" in data


async def test_create_test_account_attacker(client: AsyncClient, admin_cookies):
    r = await client.post(
        "/api/bola/test-accounts",
        json={
            "name": "Low-Privilege Attacker",
            "role": "ATTACKER",
            "auth_token": "Bearer attacker-token-xyz789",
        },
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["role"] == "ATTACKER"


async def test_identity_matrix_multi_identity_ready(client: AsyncClient, admin_cookies):
    """After registering two roles, multi_identity_ready should be true."""
    # Create admin
    r1 = await client.post(
        "/api/bola/test-accounts",
        json={"name": "Admin", "role": "ADMIN", "auth_token": "Bearer tok-admin"},
        cookies=admin_cookies,
    )
    assert r1.status_code == 200

    # Create member
    r2 = await client.post(
        "/api/bola/test-accounts",
        json={"name": "Member", "role": "MEMBER", "auth_token": "Bearer tok-member"},
        cookies=admin_cookies,
    )
    assert r2.status_code == 200

    # List and check matrix
    r = await client.get("/api/bola/test-accounts", cookies=admin_cookies)
    assert r.status_code == 200
    data = r.json()
    matrix = data["identity_matrix"]
    assert matrix["multi_identity_ready"] is True
    assert matrix["role_count"] >= 2
    assert "ADMIN" in matrix["roles_present"]


async def test_auth_tokens_are_not_exposed(client: AsyncClient, admin_cookies):
    """The list endpoint must never return raw auth tokens."""
    await client.post(
        "/api/bola/test-accounts",
        json={"name": "Secret Identity", "role": "MEMBER", "auth_token": "Bearer super-secret-token"},
        cookies=admin_cookies,
    )
    r = await client.get("/api/bola/test-accounts", cookies=admin_cookies)
    body = r.text
    assert "super-secret-token" not in body
    assert "Bearer super-secret-token" not in body


async def test_delete_test_account(client: AsyncClient, admin_cookies):
    create_r = await client.post(
        "/api/bola/test-accounts",
        json={"name": "To Delete", "role": "VIEWER", "auth_token": "Bearer tok-del"},
        cookies=admin_cookies,
    )
    assert create_r.status_code == 200
    account_id = create_r.json()["id"]

    del_r = await client.delete(f"/api/bola/test-accounts/{account_id}", cookies=admin_cookies)
    assert del_r.status_code == 200
    assert del_r.json()["status"] == "deleted"

    # Verify it's gone
    list_r = await client.get("/api/bola/test-accounts", cookies=admin_cookies)
    ids = [a["id"] for a in list_r.json()["test_accounts"]]
    assert account_id not in ids


async def test_delete_nonexistent_account_returns_404(client: AsyncClient, admin_cookies):
    r = await client.delete(
        "/api/bola/test-accounts/nonexistent-uuid-here",
        cookies=admin_cookies,
    )
    assert r.status_code == 404


async def test_tenant_isolation_test_accounts(client: AsyncClient):
    """Test accounts created by one tenant must not be visible to another."""
    # Tenant A
    r_a = await client.post(
        "/api/auth/signup",
        json={
            "email": "tenant_a_bola@test.io",
            "password": "TenantA!Pass1234",
            "account_name": "TenantA",
        },
    )
    cookies_a = r_a.cookies

    # Tenant B
    r_b = await client.post(
        "/api/auth/signup",
        json={
            "email": "tenant_b_bola@test.io",
            "password": "TenantB!Pass1234",
            "account_name": "TenantB",
        },
    )
    cookies_b = r_b.cookies

    # Tenant A creates a test account
    await client.post(
        "/api/bola/test-accounts",
        json={"name": "A-Admin", "role": "ADMIN", "auth_token": "Bearer tenant-a-secret"},
        cookies=cookies_a,
    )

    # Tenant B's list should not contain Tenant A's test account
    r = await client.get("/api/bola/test-accounts", cookies=cookies_b)
    assert r.status_code == 200
    body = r.text
    assert "A-Admin" not in body
    assert "tenant-a-secret" not in body
