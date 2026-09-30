"""BOLA (Broken Object Level Authorization) testing endpoints.

Authorization replays are queued as ``authorization_replay_matrix`` runs and
executed by api-sentinel-scan-worker; this router validates and enqueues them.
"""

import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from sentinel_core.models.core import APIEndpoint, SampleData, TestAccount, TestRun, Vulnerability
from server.modules.auth.rbac import Permission, RBAC, can_run_tests
from sentinel_core.modules.identity.replay_credentials import auth_headers_for_account
from sentinel_core.modules.persistence.database import get_db
from sentinel_core.modules.test_executor.kill_switch import (
    KILL_SWITCH_REASON,
    PentestKillSwitchError,
    guard_pentest_execution,
)
from sentinel_core.modules.test_executor.scan_plan import finalize_scan_plan_hash
from sentinel_core.modules.test_executor.scan_planning import (
    audit_scan_event,
    endpoint_scan_plan_context,
    scan_plan_audit_summary,
)
from sentinel_core.modules.utils.redactor import Redactor

router = APIRouter(tags=["bola"])

_AUTHORIZATION_REPLAY_ENGINE = "authorization_replay"
_AUTHORIZATION_REPLAY_TEMPLATE_ID = "AUTHORIZATION_REPLAY_MATRIX"
_AUTHORIZATION_REPLAY_TRIGGER = "authorization_replay_matrix"


class AuthorizationReplayOptions(BaseModel):
    attacker_role_id: str | None = None
    attacker_role_ids: list[str] = Field(default_factory=list)
    allow_state_change: bool = False
    require_response_similarity: bool = True
    body_similarity_threshold: float = Field(default=70.0, ge=0, le=100)
    schema_similarity_threshold: float = Field(default=70.0, ge=0, le=100)


class AuthorizationReplayMatrixRequest(AuthorizationReplayOptions):
    endpoint_ids: list[str] = Field(default_factory=list)
    max_endpoints: int = Field(default=25, ge=1, le=200)


def _parse_options(body: Any, *, require_attacker: bool) -> AuthorizationReplayOptions:
    if isinstance(body, str):
        return AuthorizationReplayOptions(attacker_role_id=body)
    if isinstance(body, dict):
        return AuthorizationReplayOptions(**body)
    if body is None and not require_attacker:
        return AuthorizationReplayOptions()
    raise HTTPException(status_code=400, detail="request body must be an attacker id string or options object")


def _guard_authorization_replay_execution() -> None:
    try:
        guard_pentest_execution()
    except PentestKillSwitchError as exc:
        raise HTTPException(status_code=503, detail=KILL_SWITCH_REASON) from exc


async def _load_endpoint_and_sample(
    db: AsyncSession,
    *,
    account_id: int,
    ep_id: str,
) -> tuple[APIEndpoint, SampleData]:
    ep_result = await db.execute(
        select(APIEndpoint).where(
            APIEndpoint.id == ep_id,
            APIEndpoint.account_id == account_id,
        )
    )
    endpoint = ep_result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    sample_result = await db.execute(
        select(SampleData)
        .where(
            SampleData.endpoint_id == ep_id,
            SampleData.account_id == account_id,
        )
        .order_by(SampleData.created_at.desc())
        .limit(1)
    )
    sample = sample_result.scalar_one_or_none()
    if not sample:
        raise HTTPException(status_code=400, detail="No sample data found for this endpoint. Cannot replay.")
    return endpoint, sample


async def _load_test_accounts(
    db: AsyncSession,
    *,
    account_id: int,
    requested_ids: list[str],
) -> tuple[list[TestAccount], list[TestAccount]]:
    all_result = await db.execute(
        select(TestAccount)
        .where(TestAccount.account_id == account_id)
        .order_by(TestAccount.created_at.asc())
    )
    all_accounts = all_result.scalars().all()
    replayable_accounts = [account for account in all_accounts if auth_headers_for_account(account)]

    if not requested_ids:
        return all_accounts, replayable_accounts

    requested = [account for account in replayable_accounts if account.id in set(requested_ids)]
    missing = sorted(set(requested_ids) - {account.id for account in requested})
    if missing:
        raise HTTPException(status_code=400, detail=f"Attacker role not found or has no replayable auth: {missing[0]}")
    return all_accounts, requested


async def _load_matrix_endpoint_ids(
    db: AsyncSession,
    *,
    account_id: int,
    endpoint_ids: list[str],
    max_endpoints: int,
) -> list[str]:
    if endpoint_ids:
        result = await db.execute(
            select(APIEndpoint.id).where(
                APIEndpoint.account_id == account_id,
                APIEndpoint.id.in_(endpoint_ids),
            )
        )
        found = {str(item) for item in result.scalars().all()}
        missing = sorted(set(endpoint_ids) - set(found))
        if missing:
            raise HTTPException(status_code=403, detail="Some endpoints do not belong to your account")
        return [endpoint_id for endpoint_id in endpoint_ids if endpoint_id in found][:max_endpoints]

    result = await db.execute(
        select(SampleData.endpoint_id)
        .where(
            SampleData.account_id == account_id,
            SampleData.endpoint_id.is_not(None),
        )
        .order_by(SampleData.created_at.desc())
        .limit(max_endpoints * 3)
    )
    selected: list[str] = []
    seen: set[str] = set()
    for endpoint_id in result.scalars().all():
        endpoint_id = str(endpoint_id)
        if endpoint_id in seen:
            continue
        seen.add(endpoint_id)
        selected.append(endpoint_id)
        if len(selected) >= max_endpoints:
            break
    return selected


async def _enqueue_authorization_replay_run(
    db: AsyncSession,
    *,
    account_id: int,
    endpoint_ids: list[str],
    options: AuthorizationReplayOptions,
    user_id: str | None,
) -> dict[str, Any]:
    """Persist a PENDING authorization-replay run for api-sentinel-scan-worker."""
    requested_ids = [
        id_
        for id_ in ([options.attacker_role_id] if options.attacker_role_id else []) + options.attacker_role_ids
        if id_
    ]
    _, attackers = await _load_test_accounts(db, account_id=account_id, requested_ids=requested_ids)
    if not attackers:
        raise HTTPException(status_code=400, detail="No replayable non-victim attacker test accounts configured")

    endpoints = (
        await db.execute(
            select(APIEndpoint).where(
                APIEndpoint.account_id == account_id,
                APIEndpoint.id.in_(endpoint_ids),
            )
        )
    ).scalars().all()
    endpoints_by_id = {str(endpoint.id): endpoint for endpoint in endpoints}
    scan_plan = finalize_scan_plan_hash(
        Redactor.redact_scan_result(
            {
                "schema_version": "scan_plan.v1",
                "test_intensity": "safe",
                "selection_mode": _AUTHORIZATION_REPLAY_TRIGGER,
                "selected_tests": [
                    {
                        "template_id": _AUTHORIZATION_REPLAY_TEMPLATE_ID,
                        "engine": _AUTHORIZATION_REPLAY_ENGINE,
                        "endpoint_id": endpoint_id,
                        "reason": _AUTHORIZATION_REPLAY_TRIGGER,
                    }
                    for endpoint_id in endpoint_ids
                ],
                "targets": [
                    endpoint_scan_plan_context(endpoints_by_id[endpoint_id], account_id=account_id)
                    for endpoint_id in endpoint_ids
                    if endpoint_id in endpoints_by_id
                ],
                "engine_plan": [
                    {
                        "engine": _AUTHORIZATION_REPLAY_ENGINE,
                        "display_name": "Authorization Replay Matrix",
                        "enabled": True,
                        "status": "ready",
                        "reason": "authorization_replay_matrix_available",
                        "requires_auth_profile": False,
                        "requires_test_accounts": True,
                        "artifact_type": "authorization_replay_execution",
                        "runtime_available": True,
                    }
                ],
                _AUTHORIZATION_REPLAY_ENGINE: {
                    "endpoint_ids": list(endpoint_ids),
                    "attacker_account_ids": [attacker.id for attacker in attackers] if requested_ids else [],
                    "allow_state_change": options.allow_state_change,
                    "require_response_similarity": options.require_response_similarity,
                    "body_similarity_threshold": options.body_similarity_threshold,
                    "schema_similarity_threshold": options.schema_similarity_threshold,
                },
            }
        )
    )

    run_id = str(uuid.uuid4())
    db.add(
        TestRun(
            id=run_id,
            account_id=account_id,
            status="PENDING",
            template_ids=[_AUTHORIZATION_REPLAY_TEMPLATE_ID],
            endpoint_ids=list(endpoint_ids),
            trigger_source=_AUTHORIZATION_REPLAY_TRIGGER,
            test_intensity="safe",
            scan_plan=scan_plan,
        )
    )
    await audit_scan_event(
        db,
        action="SCAN_RUN_QUEUED",
        account_id=account_id,
        run_id=run_id,
        user_id=user_id,
        details={
            "source": _AUTHORIZATION_REPLAY_TRIGGER,
            "trigger_source": _AUTHORIZATION_REPLAY_TRIGGER,
            "endpoint_count": len(endpoint_ids),
            "attacker_count": len(attackers) if requested_ids else None,
            "execution_mode": "queued",
            "scan_plan": scan_plan_audit_summary(scan_plan),
        },
    )
    await db.commit()
    return {
        "status": "scan_queued",
        "run_id": run_id,
        "execution_mode": "queued",
        "trigger_source": _AUTHORIZATION_REPLAY_TRIGGER,
        "endpoint_ids": list(endpoint_ids),
        "attacker_role_ids": requested_ids,
    }


@router.post("/scan-endpoint/{ep_id}")
async def scan_endpoint_for_bola(
    ep_id: str,
    body: Any = Body(...),
    payload: dict = Depends(can_run_tests),
    db: AsyncSession = Depends(get_db),
):
    """Queue a BOLA replay of one endpoint's latest captured request as the attacker identity.

    The replay itself runs in api-sentinel-scan-worker; poll ``/api/tests/runs/{run_id}``
    and ``/api/tests/runs/{run_id}/findings`` for the outcome.
    """
    account_id = int(payload["account_id"])
    _guard_authorization_replay_execution()

    options = _parse_options(body, require_attacker=True)
    if not options.attacker_role_id and not options.attacker_role_ids:
        raise HTTPException(status_code=400, detail="attacker_role_id is required")
    if options.attacker_role_ids and not options.attacker_role_id:
        options.attacker_role_id = options.attacker_role_ids[0]
        options.attacker_role_ids = []

    await _load_endpoint_and_sample(db, account_id=account_id, ep_id=ep_id)
    return await _enqueue_authorization_replay_run(
        db,
        account_id=account_id,
        endpoint_ids=[ep_id],
        options=options,
        user_id=payload.get("user_id"),
    )


@router.post("/scan-endpoint/{ep_id}/matrix")
async def scan_endpoint_authorization_matrix(
    ep_id: str,
    body: Any = Body(default=None),
    payload: dict = Depends(can_run_tests),
    db: AsyncSession = Depends(get_db),
):
    """Queue a replay of captured endpoint traffic across configured identities for BOLA/BFLA coverage."""

    account_id = int(payload["account_id"])
    _guard_authorization_replay_execution()
    options = _parse_options(body, require_attacker=False)
    await _load_endpoint_and_sample(db, account_id=account_id, ep_id=ep_id)
    return await _enqueue_authorization_replay_run(
        db,
        account_id=account_id,
        endpoint_ids=[ep_id],
        options=options,
        user_id=payload.get("user_id"),
    )


@router.post("/matrix")
async def scan_authorization_matrix(
    body: AuthorizationReplayMatrixRequest | None = Body(default=None),
    payload: dict = Depends(can_run_tests),
    db: AsyncSession = Depends(get_db),
):
    """Queue a replay of latest sampled traffic across endpoints and identities for BOLA/BFLA coverage."""

    account_id = int(payload["account_id"])
    _guard_authorization_replay_execution()
    body = body or AuthorizationReplayMatrixRequest()
    endpoint_ids = await _load_matrix_endpoint_ids(
        db,
        account_id=account_id,
        endpoint_ids=body.endpoint_ids,
        max_endpoints=body.max_endpoints,
    )
    if not endpoint_ids:
        raise HTTPException(status_code=400, detail="No sampled endpoints available for authorization replay")

    options = AuthorizationReplayOptions(**body.model_dump(exclude={"endpoint_ids", "max_endpoints"}))
    return await _enqueue_authorization_replay_run(
        db,
        account_id=account_id,
        endpoint_ids=endpoint_ids,
        options=options,
        user_id=payload.get("user_id"),
    )


@router.get("/vulnerabilities")
async def list_bola_vulns(
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List BOLA vulnerabilities for the authenticated tenant only."""

    account_id = int(payload["account_id"])
    result = await db.execute(
        select(Vulnerability).where(
            and_(Vulnerability.type.in_(["BOLA", "BFLA"]), Vulnerability.status != "CLOSED"),
            Vulnerability.account_id == account_id,
        )
    )
    vulnerabilities = result.scalars().all()
    return [
        {
            "id": vulnerability.id,
            "endpoint_id": vulnerability.endpoint_id,
            "url": vulnerability.url,
            "method": vulnerability.method,
            "type": vulnerability.type,
            "severity": vulnerability.severity,
            "description": vulnerability.description,
            "confidence": vulnerability.confidence,
            "status": vulnerability.status,
            "created_at": str(vulnerability.created_at),
        }
        for vulnerability in vulnerabilities
    ]


# ── Multi-Identity Test Account Management ────────────────────────────────────
# Used to configure admin/user/low-privilege/cross-tenant identity matrix for
# BOLA and BFLA replay testing.


class TestAccountCreateRequest(BaseModel):
    name: str
    role: str  # ADMIN | MEMBER | ATTACKER | VIEWER
    auth_token: str | None = None
    auth_headers: dict[str, str] | None = None


class TestAccountUpdateRequest(BaseModel):
    name: str | None = None
    role: str | None = None
    auth_token: str | None = None
    auth_headers: dict[str, str] | None = None


@router.get("/test-accounts")
async def list_test_accounts(
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List all configured test accounts (identity matrix) for BOLA/BFLA testing."""
    account_id = payload["account_id"]
    result = await db.execute(
        select(TestAccount).where(TestAccount.account_id == account_id)
        .order_by(TestAccount.created_at.desc())
    )
    accounts = result.scalars().all()
    return {
        "total": len(accounts),
        "test_accounts": [
            {
                "id": a.id,
                "name": a.name,
                "role": a.role,
                "has_auth_token": bool(a.auth_token),
                "has_auth_headers": bool(a.auth_headers),
                "created_at": str(a.created_at),
            }
            for a in accounts
        ],
        "identity_matrix": {
            "role_count": len({a.role for a in accounts if a.role}),
            "roles_present": sorted({(a.role or "").upper() for a in accounts if a.role}),
            "multi_identity_ready": len({a.role for a in accounts if a.role}) >= 2,
            "has_privileged_role": any(
                (a.role or "").upper() in {"ADMIN", "SECURITY_ENGINEER"} for a in accounts
            ),
            "has_low_privilege_role": any(
                (a.role or "").upper() in {"MEMBER", "ATTACKER", "VIEWER"} for a in accounts
            ),
        },
    }


@router.post("/test-accounts")
async def create_test_account(
    body: TestAccountCreateRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """
    Register an identity for BOLA/BFLA replay testing.

    The auth_token or auth_headers are stored encrypted and used during
    multi-identity scan runs to replay requests as different actors.
    """
    from sentinel_core.modules.identity.test_account_secrets import TestAccountSecretCodec as _Codec
    import uuid as _uuid

    account_id = payload["account_id"]
    role_upper = (body.role or "MEMBER").upper()

    auth_headers_encrypted = None
    if body.auth_headers:
        auth_headers_encrypted = _Codec.encrypt_headers(body.auth_headers)
    elif body.auth_token:
        auth_headers_encrypted = _Codec.encrypt_headers({"Authorization": f"Bearer {body.auth_token}"})

    test_account = TestAccount(
        id=str(_uuid.uuid4()),
        account_id=account_id,
        name=body.name,
        role=role_upper,
        auth_headers=auth_headers_encrypted,
        auth_token=None,  # never store plaintext token
    )
    db.add(test_account)
    await db.commit()
    await db.refresh(test_account)
    return {
        "status": "created",
        "id": test_account.id,
        "name": test_account.name,
        "role": test_account.role,
    }


@router.delete("/test-accounts/{account_id_param}")
async def delete_test_account(
    account_id_param: str,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Remove a test account from the identity matrix."""
    account_id = payload["account_id"]
    result = await db.execute(
        select(TestAccount).where(
            and_(TestAccount.id == account_id_param, TestAccount.account_id == account_id)
        )
    )
    ta = result.scalar_one_or_none()
    if ta is None:
        raise HTTPException(status_code=404, detail="Test account not found")
    await db.delete(ta)
    await db.commit()
    return {"status": "deleted", "id": account_id_param}
