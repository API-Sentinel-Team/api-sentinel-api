import uuid
import datetime
import logging
from fastapi import APIRouter, Depends, Query, HTTPException, Request, Body
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sentinel_core.modules.persistence.database import get_db
from server.modules.auth.rbac import RBAC, Permission, can_run_tests
from server.modules.validation.input_validator import InputValidator, ValidationError
from sentinel_core.modules.test_executor.wordlist_manager import WordlistManager
from sentinel_core.modules.test_executor.kill_switch import KILL_SWITCH_REASON, kill_switch_enabled
from sentinel_core.modules.test_executor.scan_plan import normalize_test_intensity
from sentinel_core.modules.test_executor.scan_planning import (
    account_has_openapi_spec,
    audit_scan_event,
    build_scan_plan_for_run,
    engine_runtime_availability,
    expand_active_business_logic_templates,
    planned_test_count,
    scan_plan_audit_summary,
)
from server.modules.test_executor.reporting import build_sarif, build_junit
from sentinel_core.models.core import APIEndpoint, OpenAPISpec, TestRun, TestResult, TestAccount
from server.api.rate_limiter import limiter
from server.api.scan_guards import (
    load_scan_profile_for_execution,
    request_ip,
    scan_execution_mode,
    validate_scan_auth_scope,
    validate_scan_budget,
    validate_scan_endpoint_targets,
)
from sentinel_core.modules.pentest.auth_preflight import active_scan_auth_audit_context
from sentinel_core.modules.identity.roles_context import RolesContextBuilder
from sentinel_core.modules.identity.eligibility import eligible_test_accounts
from sentinel_core.modules.utils.redactor import Redactor

router = APIRouter()
logger = logging.getLogger(__name__)
_TERMINAL_RUN_STATUSES = {"COMPLETED", "FAILED", "CANCELED"}


def _serialize_run(run: TestRun) -> dict:
    return {
        "id": run.id,
        "status": run.status,
        "total_tests": run.total_tests,
        "vulnerable_count": run.vulnerable_count,
        "error_count": run.error_count,
        "pentest_profile_id": run.pentest_profile_id,
        "trigger_source": run.trigger_source,
        "source_vulnerability_id": run.source_vulnerability_id,
        "source_schedule_id": run.source_schedule_id,
        "test_intensity": getattr(run, "test_intensity", "standard"),
        "scan_plan": getattr(run, "scan_plan", None),
        "worker_id": run.worker_id,
        "dispatch_lease_expires_at": _serialize_datetime(run.dispatch_lease_expires_at),
        "worker_heartbeat_at": _serialize_datetime(run.worker_heartbeat_at),
        "claim_count": run.claim_count,
        "started_at": _serialize_datetime(run.started_at),
        "completed_at": _serialize_datetime(run.completed_at),
        "created_at": _serialize_datetime(run.created_at),
    }


def _serialize_datetime(value: datetime.datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=datetime.timezone.utc)
    else:
        value = value.astimezone(datetime.timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _safe_result_text(value: str | None) -> str | None:
    if value is None:
        return None
    return Redactor.redact_text(str(value))


def _serialize_result(result: TestResult) -> dict:
    return {
        "endpoint_id": result.endpoint_id,
        "template_id": result.template_id,
        "is_vulnerable": result.is_vulnerable,
        "severity": result.severity,
        "evidence": _safe_result_text(result.evidence),
        "error": _safe_result_text(result.error),
        "skip_reason": result.skip_reason,
    }


async def _load_scoped_run_results(db: AsyncSession, run: TestRun) -> list[TestResult]:
    stmt = select(TestResult).where(TestResult.run_id == run.id)
    endpoint_scope = [str(endpoint_id) for endpoint_id in (run.endpoint_ids or []) if endpoint_id]
    if endpoint_scope:
        stmt = stmt.where(TestResult.endpoint_id.in_(endpoint_scope))
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/templates")
@limiter.limit("30/minute")
async def list_templates(
    request: Request,
    category: str = Query(None),
    severity: str = Query(None),
    search: str = Query(None),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ))
):
    try:
        # Validate string parameters
        validated_category = None
        if category:
            validated_category = InputValidator.validate_string(
                category, "category", max_length=100, allow_empty=False
            ).upper()

        validated_severity = None
        if severity:
            validated_severity = InputValidator.validate_string(
                severity, "severity", max_length=20, allow_empty=False
            ).upper()

        validated_search = None
        if search:
            validated_search = InputValidator.validate_string(
                search, "search", max_length=256, allow_empty=False
            )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    wm = WordlistManager.get_instance()
    templates = wm.templates

    if validated_category:
        templates = [t for t in templates if t.get("info", {}).get("category", {}).get("name", "").upper() == validated_category]
    if validated_severity:
        templates = [t for t in templates if t.get("info", {}).get("severity", "").upper() == validated_severity]
    if validated_search:
        term = validated_search.lower()
        templates = [t for t in templates if term in (t.get("info", {}).get("name") or "").lower()]

    return {
        "count": len(templates),
        "templates": [
            {
                "id": t["id"],
                "name": t.get("info", {}).get("name"),
                "severity": t.get("info", {}).get("severity"),
                "category": t.get("info", {}).get("category", {}).get("name"),
                "description": t.get("info", {}).get("description"),
            }
            for t in templates
        ],
    }


@router.get("/templates/{template_id}")
async def get_template(
    template_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
):
    try:
        # Validate template_id (alphanumeric with hyphens and underscores)
        validated_template_id = InputValidator.validate_string(
            template_id, "template_id", max_length=256, allow_empty=False
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    wm = WordlistManager.get_instance()
    template = next((t for t in wm.templates if t["id"] == validated_template_id), None)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template


@router.post("/run")
@limiter.limit("10/minute")
async def run_scan(
    request: Request,
    template_ids: list[str],
    endpoint_ids: list[str],
    pentest_profile_id: str | None = Body(default=None),
    test_intensity: str | None = Body(default=None),
    external_engine_scope: dict | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(can_run_tests),
):
    try:
        # Validate lists are not empty and within size limits
        InputValidator.validate_collection_size(template_ids, "template_ids", max_size=1000)
        InputValidator.validate_collection_size(endpoint_ids, "endpoint_ids", max_size=1000)
        # Validate each template_id is a valid string
        for t_id in template_ids:
            InputValidator.validate_string(t_id, "template_id", max_length=256, allow_empty=False)
        # Validate each endpoint_id is a valid UUID
        for e_id in endpoint_ids:
            InputValidator.validate_uuid(e_id, "endpoint_id")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload["account_id"]
    if kill_switch_enabled():
        raise HTTPException(status_code=503, detail=KILL_SWITCH_REASON)
    validate_scan_budget(template_ids, endpoint_ids)

    # Verify all endpoint_ids belong to this account
    result = await db.execute(
        select(APIEndpoint).where(
            and_(APIEndpoint.id.in_(endpoint_ids), APIEndpoint.account_id == account_id)
        )
    )
    endpoints = result.scalars().all()
    valid_ids = [str(endpoint.id) for endpoint in endpoints]
    if len(valid_ids) < len(endpoint_ids):
        raise HTTPException(status_code=403, detail="Some endpoints do not belong to your account")
    validate_scan_endpoint_targets(endpoints)

    pentest_profile, auth_profile = await load_scan_profile_for_execution(
        db,
        account_id=account_id,
        pentest_profile_id=pentest_profile_id,
    )
    validate_scan_auth_scope(endpoints, auth_profile)
    effective_pentest_profile_id = pentest_profile.id if pentest_profile is not None else pentest_profile_id
    try:
        effective_test_intensity = normalize_test_intensity(test_intensity, profile=pentest_profile)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    wm = WordlistManager.get_instance()
    effective_template_ids, scan_templates, generated_templates = await expand_active_business_logic_templates(
        db,
        account_id=account_id,
        template_ids=template_ids,
        endpoints=endpoints,
        base_templates=wm.templates,
        test_intensity=effective_test_intensity,
    )
    validate_scan_budget(effective_template_ids, endpoint_ids)
    test_accounts_result = await db.execute(
        select(TestAccount).where(TestAccount.account_id == account_id)
    )
    test_accounts_list = eligible_test_accounts(test_accounts_result.scalars().all())
    roles_context = RolesContextBuilder().build(test_accounts_list)
    has_openapi_spec = await account_has_openapi_spec(db, account_id=account_id)
    runtime_availability = engine_runtime_availability()
    if external_engine_scope is not None and not isinstance(external_engine_scope, dict):
        external_engine_scope = None
    if external_engine_scope:
        from sentinel_core.modules.test_executor.scan_queue import scoped_worker_spec, worker_spec_digest
        from sentinel_core.modules.pentest.target_policy import validate_pentest_target
        from sentinel_core.modules.pentest.auth_scope import validate_auth_profile_scope
        target_url = external_engine_scope.get("target_url")
        spec_id = external_engine_scope.get("openapi_spec_id")
        if not isinstance(target_url, str) or not isinstance(spec_id, str):
            raise HTTPException(status_code=400, detail="External engines require target_url and openapi_spec_id")
        spec = (await db.execute(select(OpenAPISpec).where(
            OpenAPISpec.id == spec_id, OpenAPISpec.account_id == account_id,
        ))).scalar_one_or_none()
        if spec is None:
            raise HTTPException(status_code=404, detail="OpenAPI spec not found")
        try:
            validate_pentest_target(target_url)
            validate_auth_profile_scope(auth_profile, target_url)
            scoped_worker_spec(spec.spec_json, endpoints, target_url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=Redactor.redact_text(str(exc))) from exc
        external_engine_scope = {"target_url": target_url, "openapi_spec_id": spec_id, "openapi_spec_sha256": worker_spec_digest(spec.spec_json)}
    scan_plan = build_scan_plan_for_run(
        templates=scan_templates,
        template_ids=effective_template_ids,
        endpoints=endpoints,
        account_id=account_id,
        test_intensity=effective_test_intensity,
        profile=pentest_profile,
        roles_context=roles_context,
        auth_profile=auth_profile,
        has_openapi_spec=has_openapi_spec,
        engine_availability=runtime_availability,
        generated_templates=generated_templates,
        test_accounts_count=len(test_accounts_list),
        external_engine_scope=external_engine_scope,
    )

    run_id = str(uuid.uuid4())
    run = TestRun(
        id=run_id,
        account_id=account_id,
        status="PENDING",
        template_ids=effective_template_ids,
        endpoint_ids=endpoint_ids,
        pentest_profile_id=effective_pentest_profile_id,
        trigger_source="manual",
        test_intensity=effective_test_intensity,
        scan_plan=scan_plan,
    )
    execution_mode = scan_execution_mode()
    db.add(run)
    await audit_scan_event(
        db,
        action="SCAN_RUN_QUEUED",
        account_id=account_id,
        run_id=run_id,
        user_id=payload.get("user_id"),
        details={
            "template_count": len(effective_template_ids),
            "generated_business_logic_template_count": len(generated_templates),
            "endpoint_count": len(endpoint_ids),
            "planned_tests": planned_test_count(effective_template_ids, endpoint_ids),
            "pentest_profile_id": effective_pentest_profile_id,
            **active_scan_auth_audit_context(pentest_profile, auth_profile),
            "execution_mode": execution_mode,
            "trigger_source": run.trigger_source,
            "test_intensity": effective_test_intensity,
            "scan_plan": scan_plan_audit_summary(scan_plan),
        },
        ip_address=request_ip(request),
    )
    await db.commit()
    return {
        "status": "scan_queued",
        "run_id": run_id,
        "templates": len(effective_template_ids),
        "endpoints": len(endpoint_ids),
        "pentest_profile_id": effective_pentest_profile_id,
        "execution_mode": execution_mode,
        "trigger_source": run.trigger_source,
        "test_intensity": effective_test_intensity,
        "scan_plan": scan_plan,
    }


@router.get("/runs")
async def list_runs(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ))
):
    try:
        # Validate limit parameter
        validated_limit = InputValidator.validate_integer(limit, "limit", min_value=1, max_value=1000)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload["account_id"]
    result = await db.execute(
        select(TestRun).where(TestRun.account_id == account_id)
        .order_by(TestRun.created_at.desc()).limit(validated_limit)
    )
    runs = result.scalars().all()
    return {
        "total": len(runs),
        "runs": [
            _serialize_run(r)
            for r in runs
        ],
    }


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ))
):
    try:
        # Validate run_id UUID format
        validated_run_id = InputValidator.validate_uuid(run_id, "run_id")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload["account_id"]
    result = await db.execute(
        select(TestRun).where(and_(TestRun.id == validated_run_id, TestRun.account_id == account_id))
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    results = await _load_scoped_run_results(db, run)

    return {
        **_serialize_run(run),
        "results": [_serialize_result(r) for r in results],
    }


@router.post("/runs/{run_id}/cancel")
async def cancel_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(can_run_tests),
):
    try:
        validated_run_id = InputValidator.validate_uuid(run_id, "run_id")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload["account_id"]
    result = await db.execute(
        select(TestRun).where(and_(TestRun.id == validated_run_id, TestRun.account_id == account_id))
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    current_status = (run.status or "").upper()
    if current_status in _TERMINAL_RUN_STATUSES:
        return {
            "status": "not_cancelled",
            "run_id": run.id,
            "run_status": run.status,
        }

    previous_status = current_status
    run.status = "CANCEL_REQUESTED"
    await audit_scan_event(
        db,
        action="SCAN_CANCEL_REQUESTED",
        account_id=account_id,
        run_id=run.id,
        user_id=payload.get("user_id"),
        details={"previous_status": previous_status},
    )
    await db.commit()
    return {
        "status": "cancel_requested",
        "run_id": run.id,
        "run_status": "CANCEL_REQUESTED",
    }


@router.get("/runs/{run_id}/findings")
@limiter.limit("30/minute")
async def get_run_findings(
    request: Request,
    run_id: str,
    format: str = Query("sarif"),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
):
    try:
        # Validate run_id UUID format
        validated_run_id = InputValidator.validate_uuid(run_id, "run_id")
        # Validate format parameter
        validated_format = InputValidator.validate_string(format, "format", max_length=20, allow_empty=False)
        if validated_format.lower() not in ("sarif", "junit"):
            raise ValidationError("format: Must be one of sarif, junit")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    account_id = payload["account_id"]
    result = await db.execute(
        select(TestRun).where(and_(TestRun.id == validated_run_id, TestRun.account_id == account_id))
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    results = await _load_scoped_run_results(db, run)

    fmt = validated_format.lower()
    if fmt == "sarif":
        sarif = build_sarif(run, results)
        return JSONResponse(content=sarif, media_type="application/sarif+json")
    if fmt == "junit":
        xml = build_junit(run, results)
        return PlainTextResponse(content=xml, media_type="application/xml")
    return {"error": "unsupported format", "supported": ["sarif", "junit"]}
