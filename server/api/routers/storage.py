"""Storage and archival endpoints.

Archiving is never executed inside a request. ``POST /archive`` records a durable, tenant-owned
job and the archiver service executes it (see ``sentinel_core.modules.storage.archive_jobs``).
"""
import os
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.auth.rbac import Permission, RBAC
from sentinel_core.modules.persistence.database import get_db
from sentinel_core.modules.storage import archive_jobs
from sentinel_core.config import settings

router = APIRouter(tags=["Storage"])


@router.post("/archive", status_code=202)
async def request_archive(
    response: Response,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
):
    """Queue an archive run for the caller's tenant.

    Returns 202 with the new job, or 200 with the job already in flight (one active job per tenant).
    """
    job, created = await archive_jobs.submit_archive_job(
        db, account_id=int(payload["account_id"]), requested_by=payload.get("user_id")
    )
    if not created:
        response.status_code = 200
    return {"created": created, "job": archive_jobs.serialize_archive_job(job)}


@router.get("/archive/jobs")
async def list_archive_jobs(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.AUDIT_READ)),
):
    jobs = await archive_jobs.list_archive_jobs(db, account_id=int(payload["account_id"]), limit=limit)
    return {"total": len(jobs), "jobs": [archive_jobs.serialize_archive_job(job) for job in jobs]}


@router.get("/archive/jobs/{job_id}")
async def get_archive_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.AUDIT_READ)),
):
    job = await archive_jobs.get_archive_job(db, account_id=int(payload["account_id"]), job_id=job_id)
    if job is None:  # also what another tenant's job id looks like
        raise HTTPException(status_code=404, detail="Archive job not found")
    return archive_jobs.serialize_archive_job(job)


@router.get("/archives")
async def list_archives(
    payload: dict = Depends(RBAC.require_permission(Permission.AUDIT_READ)),
):
    account_id = payload.get("account_id")
    base = os.path.join(settings.ARCHIVE_DIR, f"account_{account_id}")
    results = []
    if not os.path.isdir(base):
        return {"total": 0, "archives": []}
    for root, _, files in os.walk(base):
        for f in files:
            if f.endswith(".jsonl.gz"):
                path = os.path.join(root, f)
                relative_path = os.path.relpath(path, settings.ARCHIVE_DIR).replace(os.sep, "/")
                results.append({"path": relative_path, "size": os.path.getsize(path)})
    return {"total": len(results), "archives": results}
