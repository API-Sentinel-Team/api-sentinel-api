"""
Integration tests for Row-Level Security (RLS) enforcement.

Tests verify that:
1. RLS policies prevent cross-account access
2. Account_id filtering works correctly
3. Policies enforce CRUD isolation per account
"""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

from server.models.core import Base, APIEndpoint, Vulnerability
from server.modules.rls import enable_rls_on_all_tables, set_current_account_id


@pytest_asyncio.fixture
async def postgres_db():
    """
    Create a PostgreSQL test database with RLS enabled.
    Only runs if DATABASE_URL contains postgresql.
    """
    import os
    db_url = os.getenv("DATABASE_URL", "")

    if "postgresql" not in db_url:
        pytest.skip("PostgreSQL required for RLS tests")

    # Use async test database
    test_db_url = db_url.replace("postgresql://", "postgresql+asyncpg://")
    engine = create_async_engine(test_db_url, echo=False)

    async with engine.begin() as conn:
        # Create tables
        await conn.run_sync(Base.metadata.create_all)
        # Enable RLS
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with async_session() as db:
            await enable_rls_on_all_tables(db)

    yield engine

    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.mark.asyncio
async def test_rls_prevents_cross_account_read(postgres_db):
    """Verify RLS prevents reading data from another account."""
    async_session = sessionmaker(postgres_db, class_=AsyncSession, expire_on_commit=False)

    account_1 = 1000001
    account_2 = 1000002

    # Insert endpoint for account 1
    async with async_session() as db:
        await set_current_account_id(db, account_1)
        endpoint = APIEndpoint(
            id="test-endpoint-1",
            account_id=account_1,
            method="GET",
            path="/api/users",
            host="example.com"
        )
        db.add(endpoint)
        await db.commit()

    # Try to read as account 2 (should see nothing)
    async with async_session() as db:
        await set_current_account_id(db, account_2)
        result = await db.execute(
            text("SELECT * FROM api_endpoints WHERE id = 'test-endpoint-1'")
        )
        rows = result.fetchall()
        assert len(rows) == 0, "RLS should prevent cross-account read"


@pytest.mark.asyncio
async def test_rls_allows_same_account_read(postgres_db):
    """Verify RLS allows reading data from the same account."""
    async_session = sessionmaker(postgres_db, class_=AsyncSession, expire_on_commit=False)

    account_1 = 1000001

    # Insert endpoint for account 1
    async with async_session() as db:
        await set_current_account_id(db, account_1)
        endpoint = APIEndpoint(
            id="test-endpoint-2",
            account_id=account_1,
            method="POST",
            path="/api/auth",
            host="example.com"
        )
        db.add(endpoint)
        await db.commit()

    # Read as same account (should see the endpoint)
    async with async_session() as db:
        await set_current_account_id(db, account_1)
        result = await db.execute(
            text("SELECT * FROM api_endpoints WHERE id = 'test-endpoint-2'")
        )
        rows = result.fetchall()
        assert len(rows) == 1, "RLS should allow same-account read"


@pytest.mark.asyncio
async def test_rls_prevents_cross_account_insert(postgres_db):
    """Verify RLS prevents inserting data for another account."""
    async_session = sessionmaker(postgres_db, class_=AsyncSession, expire_on_commit=False)

    account_1 = 1000001
    account_2 = 1000002

    # Try to insert endpoint with account_2 ID while authenticated as account_1
    async with async_session() as db:
        await set_current_account_id(db, account_1)
        try:
            await db.execute(
                text("""
                    INSERT INTO api_endpoints (id, account_id, method, path, host)
                    VALUES ('bad-endpoint', :account_id, 'GET', '/api/users', 'example.com')
                """),
                {"account_id": account_2}
            )
            await db.commit()
            pytest.fail("RLS should prevent cross-account insert")
        except Exception as e:
            # Expected to fail due to RLS policy
            assert "check violation" in str(e).lower() or "policy" in str(e).lower()


@pytest.mark.asyncio
async def test_rls_prevents_cross_account_update(postgres_db):
    """Verify RLS prevents updating data from another account."""
    async_session = sessionmaker(postgres_db, class_=AsyncSession, expire_on_commit=False)

    account_1 = 1000001
    account_2 = 1000002

    # Insert endpoint for account 1
    async with async_session() as db:
        await set_current_account_id(db, account_1)
        endpoint = APIEndpoint(
            id="test-endpoint-3",
            account_id=account_1,
            method="GET",
            path="/api/users",
            host="example.com"
        )
        db.add(endpoint)
        await db.commit()

    # Try to update as account 2 (should not find the row)
    async with async_session() as db:
        await set_current_account_id(db, account_2)
        result = await db.execute(
            text("UPDATE api_endpoints SET path = '/api/products' WHERE id = 'test-endpoint-3'")
        )
        # In PostgreSQL with RLS, the update should silently affect 0 rows
        assert result.rowcount == 0, "RLS should prevent cross-account update"


@pytest.mark.asyncio
async def test_rls_prevents_cross_account_delete(postgres_db):
    """Verify RLS prevents deleting data from another account."""
    async_session = sessionmaker(postgres_db, class_=AsyncSession, expire_on_commit=False)

    account_1 = 1000001
    account_2 = 1000002

    # Insert endpoint for account 1
    async with async_session() as db:
        await set_current_account_id(db, account_1)
        endpoint = APIEndpoint(
            id="test-endpoint-4",
            account_id=account_1,
            method="DELETE",
            path="/api/users/1",
            host="example.com"
        )
        db.add(endpoint)
        await db.commit()

    # Try to delete as account 2 (should not find the row)
    async with async_session() as db:
        await set_current_account_id(db, account_2)
        result = await db.execute(
            text("DELETE FROM api_endpoints WHERE id = 'test-endpoint-4'")
        )
        assert result.rowcount == 0, "RLS should prevent cross-account delete"

    # Verify endpoint still exists for account 1
    async with async_session() as db:
        await set_current_account_id(db, account_1)
        result = await db.execute(
            text("SELECT * FROM api_endpoints WHERE id = 'test-endpoint-4'")
        )
        rows = result.fetchall()
        assert len(rows) == 1, "Endpoint should still exist"


@pytest.mark.asyncio
async def test_rls_applies_to_vulnerabilities_table(postgres_db):
    """Verify RLS policies apply to vulnerabilities table."""
    async_session = sessionmaker(postgres_db, class_=AsyncSession, expire_on_commit=False)

    account_1 = 1000001
    account_2 = 1000002

    # Insert vulnerability for account 1
    async with async_session() as db:
        await set_current_account_id(db, account_1)
        vuln = Vulnerability(
            id="vuln-1",
            account_id=account_1,
            template_id="sql-injection",
            url="https://example.com/api/users",
            severity="HIGH",
            type="SQL Injection"
        )
        db.add(vuln)
        await db.commit()

    # Try to read as account 2 (should see nothing)
    async with async_session() as db:
        await set_current_account_id(db, account_2)
        result = await db.execute(
            text("SELECT * FROM vulnerabilities WHERE id = 'vuln-1'")
        )
        rows = result.fetchall()
        assert len(rows) == 0, "RLS should prevent cross-account vulnerability read"
