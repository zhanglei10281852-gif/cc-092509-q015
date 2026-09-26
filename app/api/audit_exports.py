from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Query, Response, status

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.schemas.audit_export import AuditExportCreate, DownloadVerifyRequest, RuleVersionCreate
from app.services.audit_export import AuditExportService

router = APIRouter(prefix="/api/audit-exports", tags=["审计导出"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_export(payload: AuditExportCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AuditExportService(connection).create_task(principal, payload.model_dump())


@router.get("")
def list_exports(
    task_status: str | None = Query(default=None, alias="status"),
    audience: str | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    return AuditExportService(get_connection()).list_tasks(principal, status=task_status, audience=audience)


@router.get("/rules/current")
def current_rules(principal: Principal = Depends(current_principal)):
    return AuditExportService(get_connection()).get_current_rules(principal)


@router.get("/rules/versions")
def rule_versions(principal: Principal = Depends(current_principal)):
    return AuditExportService(get_connection()).list_rule_versions(principal)


@router.post("/rules/versions", status_code=status.HTTP_201_CREATED)
def register_rules(payload: RuleVersionCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AuditExportService(connection).register_rule_version(principal, payload.model_dump())


@router.post("/verify")
def verify_export(document: dict[str, Any] = Body(...), principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AuditExportService(connection).verify_uploaded(principal, document)


@router.get("/{task_id}")
def get_export(task_id: int, principal: Principal = Depends(current_principal)):
    return AuditExportService(get_connection()).get_task(principal, task_id)


@router.post("/{task_id}/claim")
def claim_export(task_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AuditExportService(connection).claim_and_run(principal, task_id)


@router.post("/{task_id}/retry")
def retry_export(task_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AuditExportService(connection).retry(principal, task_id)


@router.get("/{task_id}/download")
def download_export(task_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        text, meta = AuditExportService(connection).download(principal, task_id)
    return Response(
        content=text,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{meta["export_code"]}.json"',
            "X-Export-Code": meta["export_code"],
            "X-Export-Sha256": meta["document_sha256"],
            "X-Export-Digest": meta["file_digest"],
        },
    )


@router.post("/{task_id}/verify-download")
def verify_download(task_id: int, payload: DownloadVerifyRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AuditExportService(connection).verify_download(principal, task_id, payload.document_sha256)
