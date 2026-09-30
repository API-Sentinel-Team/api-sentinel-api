"""Nuclei vulnerability scanner integration."""
import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import and_, select, update, delete

from sentinel_core.modules.persistence.database import get_db
from sentinel_core.models.core import NucleiScan, NucleiTemplate
from server.modules.auth.rbac import Permission, RBAC, can_run_nuclei
from sentinel_core.modules.nuclei.findings import redact_nuclei_finding
from sentinel_core.modules.nuclei.selectors import (
    normalize_severities,
    normalize_tags,
    normalize_template_ids,
)
from sentinel_core.modules.test_executor.kill_switch import (
    KILL_SWITCH_REASON,
    PentestKillSwitchError,
    guard_pentest_execution,
)
from sentinel_core.modules.test_executor.scan_planning import engine_runtime_availability
from sentinel_core.modules.utils.redactor import Redactor

router = APIRouter(tags=["Nuclei Scanner"])


def _auth_profile_required_exception() -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "message": (
                "Legacy Nuclei scans require an authenticated pentest profile. "
                "Use /api/pentest/profiles/{profile_id}/nuclei/run, which queues the scan "
                "for api-sentinel-scan-worker."
            ),
            "reason": "auth_profile_required",
        },
    )


def _selector_exception(exc: ValueError) -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "message": str(exc),
            "reason": "invalid_nuclei_selector",
        },
    )


@router.get("/status")
async def nuclei_status(
    payload: dict = Depends(RBAC.require_permission(Permission.NUCLEI_READ)),
):
    available = engine_runtime_availability()["nuclei"]
    return {
        "nuclei_available": available,
        "mode": "live" if available else "unavailable",
        "simulation_enabled": False,
        "install_docs": "https://github.com/projectdiscovery/nuclei" if not available else None,
    }


@router.post("/scan")
async def start_scan(
    target: str = Body(..., description="Base URL to scan, e.g. https://api.example.com"),
    template_ids: List[str] = Body(default=[]),
    custom_template_ids: List[str] = Body(default=[], description="IDs from /nuclei/templates"),
    tags: List[str] = Body(default=[]),
    severity: List[str] = Body(default=[]),
    payload: dict = Depends(can_run_nuclei),
    db: AsyncSession = Depends(get_db)
):
    """Ad-hoc Nuclei scans are not executed by the API.

    Scans run only in api-sentinel-scan-worker; use the authenticated, queued
    ``/api/pentest/profiles/{profile_id}/nuclei/run`` route.
    """
    try:
        guard_pentest_execution()
    except PentestKillSwitchError as exc:
        raise HTTPException(status_code=503, detail=KILL_SWITCH_REASON) from exc
    raise _auth_profile_required_exception()


@router.get("/scans")
async def list_scans(
    limit: int = Query(50),
    payload: dict = Depends(RBAC.require_permission(Permission.NUCLEI_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(NucleiScan).where(NucleiScan.account_id == account_id)
        .order_by(NucleiScan.created_at.desc()).limit(limit)
    )
    scans = result.scalars().all()
    return {
        "total": len(scans),
        "scans": [
            {
                "id": s.id,
                "target": Redactor.redact_url(str(s.target or "")),
                "status": s.status,
                "total_found": s.total_found,
                "tags": s.tags,
                "severity_filter": s.severity_filter,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
            }
            for s in scans
        ],
    }


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.NUCLEI_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(NucleiScan).where(and_(NucleiScan.id == scan_id, NucleiScan.account_id == account_id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "id": scan.id,
        "target": Redactor.redact_url(str(scan.target or "")),
        "status": scan.status,
        "total_found": scan.total_found,
        "findings": [
            redact_nuclei_finding(finding, target=scan.target, account_id=account_id, include_fingerprint=True)
            for finding in (scan.findings or [])
        ],
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
    }


# ── Custom template management ────────────────────────────────────────────────

@router.get("/templates")
async def list_custom_templates(
    payload: dict = Depends(RBAC.require_permission(Permission.NUCLEI_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List all custom Nuclei templates uploaded for this account."""
    account_id = payload["account_id"]
    result = await db.execute(
        select(NucleiTemplate).where(NucleiTemplate.account_id == account_id)
        .order_by(NucleiTemplate.created_at.desc())
    )
    templates = result.scalars().all()
    return {"total": len(templates), "templates": [_serialize_template(template) for template in templates]}


@router.post("/templates")
async def create_custom_template(
    name: str = Body(...),
    yaml_content: str = Body(..., description="Full Nuclei YAML template content"),
    description: Optional[str] = Body(None),
    payload: dict = Depends(can_run_nuclei),
    db: AsyncSession = Depends(get_db),
):
    """Upload a custom Nuclei YAML template. Parses id/severity/tags from the content."""
    import yaml as _yaml
    account_id = payload["account_id"]
    template_id = None
    severity = "medium"
    tags = []
    try:
        parsed = _yaml.safe_load(yaml_content)
        if parsed:
            template_id = parsed.get("id")
            info = parsed.get("info", {})
            severity = info.get("severity", "medium")
            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
    except Exception:
        pass
    try:
        template_id = normalize_template_ids([template_id])[0] if template_id else None
        severity = (normalize_severities([severity]) or ["medium"])[0]
        tags = normalize_tags(tags)
    except ValueError as exc:
        raise _selector_exception(exc) from exc

    t = NucleiTemplate(
        id=str(uuid.uuid4()), account_id=account_id, name=name,
        template_id=template_id, description=description,
        severity=severity, tags=tags, yaml_content=yaml_content,
    )
    db.add(t)
    await db.commit()
    return {"id": t.id, "name": name, "template_id": template_id,
            "severity": severity, "status": "created"}


@router.patch("/templates/{template_id}")
async def toggle_custom_template(
    template_id: str,
    enabled: bool = Body(..., embed=True),
    payload: dict = Depends(can_run_nuclei),
    db: AsyncSession = Depends(get_db),
):
    """Enable or disable a custom Nuclei template."""
    account_id = payload["account_id"]
    await db.execute(
        update(NucleiTemplate)
        .where(and_(NucleiTemplate.id == template_id, NucleiTemplate.account_id == account_id))
        .values(enabled=enabled)
    )
    await db.commit()
    return {"template_id": template_id, "enabled": enabled}


@router.delete("/templates/{template_id}")
async def delete_custom_template(
    template_id: str,
    payload: dict = Depends(can_run_nuclei),
    db: AsyncSession = Depends(get_db),
):
    """Delete a custom Nuclei template."""
    account_id = payload["account_id"]
    await db.execute(
        delete(NucleiTemplate).where(
            and_(NucleiTemplate.id == template_id, NucleiTemplate.account_id == account_id)
        )
    )
    await db.commit()
    return {"deleted": template_id}


@router.get("/templates/{template_id}/content")
async def get_template_content(
    template_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.NUCLEI_RUN)),
    db: AsyncSession = Depends(get_db),
):
    """Return the raw YAML content of a custom template."""
    account_id = payload["account_id"]
    result = await db.execute(
        select(NucleiTemplate).where(
            and_(NucleiTemplate.id == template_id, NucleiTemplate.account_id == account_id)
        )
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Template not found")
    return {
        "id": t.id,
        "name": Redactor.redact_text(t.name or ""),
        "yaml_content": Redactor.redact_text(t.yaml_content or ""),
    }


def _serialize_template(template: NucleiTemplate) -> dict:
    return {
        "id": template.id,
        "name": Redactor.redact_text(template.name or ""),
        "template_id": template.template_id,
        "severity": template.severity,
        "tags": Redactor.redact_json(template.tags or []),
        "enabled": template.enabled,
        "description": Redactor.redact_text(template.description or "") if template.description else None,
        "created_at": template.created_at,
    }
