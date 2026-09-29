from sqlalchemy.ext.asyncio import async_sessionmaker

from server.models.core import APIEndpoint
from server.modules.enforcement.adaptive_rate_limiter import AdaptiveRequestGuard


def _patch_guard_deps(monkeypatch, session_factory):
    monkeypatch.setattr(
        "server.modules.enforcement.adaptive_rate_limiter.AsyncSessionLocal",
        session_factory,
    )

    async def no_cache(_key):
        return None

    async def noop_set(*_args, **_kwargs):
        return None

    monkeypatch.setattr(
        "server.modules.enforcement.adaptive_rate_limiter.redis_cache.get_json",
        no_cache,
    )
    monkeypatch.setattr(
        "server.modules.enforcement.adaptive_rate_limiter.redis_cache.set_json",
        noop_set,
    )


async def test_resolve_endpoint_prefers_matching_host_when_duplicates_exist(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    _patch_guard_deps(monkeypatch, session_factory)

    async with session_factory() as db:
        db.add_all(
            [
                APIEndpoint(
                    account_id=1,
                    method="GET",
                    path="/api/sensors",
                    path_pattern="/api/sensors",
                    host="unknown",
                ),
                APIEndpoint(
                    account_id=1,
                    method="GET",
                    path="/api/sensors",
                    path_pattern="/api/sensors",
                    host="sentinel.wecrew.in",
                ),
            ]
        )
        await db.commit()

    guard = AdaptiveRequestGuard(app=None)
    endpoint = await guard._resolve_endpoint(1, "GET", "/api/sensors/", "sentinel.wecrew.in")
    assert endpoint is not None
    assert endpoint.host == "sentinel.wecrew.in"


async def test_resolve_endpoint_does_not_raise_on_duplicate_hosts(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    _patch_guard_deps(monkeypatch, session_factory)

    async with session_factory() as db:
        db.add_all(
            [
                APIEndpoint(
                    account_id=1,
                    method="GET",
                    path="/api/collections",
                    path_pattern="/api/collections",
                    host="unknown",
                ),
                APIEndpoint(
                    account_id=1,
                    method="GET",
                    path="/api/collections",
                    path_pattern="/api/collections",
                    host="harbor.wecrew.in",
                ),
            ]
        )
        await db.commit()

    guard = AdaptiveRequestGuard(app=None)
    endpoint = await guard._resolve_endpoint(1, "GET", "/api/collections", "api-sentinel-backend")
    assert endpoint is not None
    assert endpoint.path_pattern == "/api/collections"
