"""Request-time guards for scan-launching API routes.

Every route that creates a scan run validates budget, target guard, auth scope and
profile here, then enqueues the run for api-sentinel-scan-worker.
"""
from __future__ import annotations

from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_core.config import settings
from sentinel_core.models.core import APIEndpoint
from sentinel_core.modules.pentest.auth_preflight import (
    ActiveScanAuthError,
    PentestProfileNotFound,
    load_profile_and_auth_for_active_scan,
)
from sentinel_core.modules.pentest.auth_scope import blocked_auth_profile_targets
from sentinel_core.modules.pentest.profiles import PentestProfileService
from sentinel_core.modules.test_executor.scan_planning import planned_test_count
from sentinel_core.modules.test_executor.target_guard import TargetGuard, blocked_endpoint_targets

_pentest_profiles = PentestProfileService()


def request_ip(request: Request | None) -> str | None:
    client = getattr(request, "client", None)
    return getattr(client, "host", None) if client else None


def validate_scan_budget(template_ids: list[str], endpoint_ids: list[str]) -> None:
    planned_count = planned_test_count(template_ids, endpoint_ids)
    max_budget = max(1, int(settings.PENTEST_MAX_TESTS_PER_RUN))
    if planned_count > max_budget:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Scan plan has {planned_count} template/endpoint combinations; "
                f"maximum budget is {max_budget}. Narrow the selection or adjust PENTEST_MAX_TESTS_PER_RUN."
            ),
        )


def validate_scan_endpoint_targets(endpoints: list[APIEndpoint]) -> None:
    blocked = blocked_endpoint_targets(endpoints, guard=TargetGuard.from_settings())
    if blocked:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Pentest target guard blocked one or more selected endpoints",
                "blocked_endpoints": blocked,
            },
        )


def validate_scan_auth_scope(endpoints: list[APIEndpoint], auth_profile: object | None) -> None:
    blocked = blocked_auth_profile_targets(auth_profile, endpoints)
    if blocked:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Auth profile scope blocked one or more selected endpoints",
                "reason": "auth_profile_scope_blocked",
                "blocked_endpoints": blocked,
            },
        )


def scan_execution_mode() -> str:
    """The API only enqueues scans; api-sentinel-scan-worker executes them."""
    mode = (settings.PENTEST_SCAN_EXECUTION_MODE or "queued").strip().lower()
    if mode != "queued":
        raise HTTPException(
            status_code=500,
            detail=(
                "PENTEST_SCAN_EXECUTION_MODE must be 'queued': scans execute only in "
                "api-sentinel-scan-worker"
            ),
        )
    return mode


async def load_scan_profile_for_execution(
    db: AsyncSession,
    *,
    account_id: int,
    pentest_profile_id: str | None = None,
):
    try:
        profile, auth_profile = await load_profile_and_auth_for_active_scan(
            db,
            account_id=account_id,
            pentest_profile_id=pentest_profile_id,
            profiles=_pentest_profiles,
        )
    except PentestProfileNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ActiveScanAuthError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from exc
    return profile, auth_profile
