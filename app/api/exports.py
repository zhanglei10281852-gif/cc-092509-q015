from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import FileResponse

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.exports.schemas import AuditExportCreate
from app.exports.service import AuditExportService

router = APIRouter(prefix="/api/audit-exports", tags=["审计导出"])


@router.post("", status_code=status.HTTP_201_CREATED)
def request_export(payload: AuditExportCreate, principal: Principal = Depends(current_principal)):
    """申请审计导出；同一角色 + 同一筛选条件重复提交时复用已有结果。"""
    with transaction(immediate=True) as connection:
        return AuditExportService(connection).request_export(
            principal, payload.profile, payload.criteria_payload()
        )


@router.get("")
def list_exports(principal: Principal = Depends(current_principal)):
    return {"data": AuditExportService(get_connection()).list_exports(principal)}


@router.get("/{export_id}")
def get_export(export_id: int, principal: Principal = Depends(current_principal)):
    return AuditExportService(get_connection()).get_export(principal, export_id)


@router.post("/{export_id}/retry")
def retry_export(export_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AuditExportService(connection).retry_export(principal, export_id)


@router.get("/{export_id}/receipt")
def export_receipt(export_id: int, principal: Principal = Depends(current_principal)):
    """可信回执：离线核验时与导出包交叉比对的登记摘要。"""
    service = AuditExportService(get_connection())
    export = service.get_export(principal, export_id)
    return service.receipt(export)


@router.get("/{export_id}/download")
def download_export(export_id: int, principal: Principal = Depends(current_principal)):
    """下载导出包；响应头携带整包摘要与根哈希，供下载方核验。"""
    with transaction(immediate=True) as connection:
        export, path = AuditExportService(connection).bundle_path(principal, export_id)
    return FileResponse(
        path,
        media_type="application/x-tar",
        filename=path.name,
        headers={
            "X-Export-Code": export["export_code"],
            "X-Export-Sha256": export["file_digest"],
            "X-Export-Root-Hash": export["root_hash"],
            "X-Export-Rule-Version": export["rule_version"],
        },
    )


@router.get("/{export_id}/verify")
def verify_export(export_id: int, principal: Principal = Depends(current_principal)):
    """HTTP 核验接口：重算服务端导出文件全部摘要并定位问题记录。"""
    with transaction(immediate=True) as connection:
        return AuditExportService(connection).verify_completed(principal, export_id)


@router.post("/verify-upload")
async def verify_upload(request: Request, principal: Principal = Depends(current_principal)):
    """核验离线持有的导出包：请求体为 .tar 包字节，返回逐项核验结果。"""
    content = await request.body()
    with transaction(immediate=True) as connection:
        return AuditExportService(connection).verify_upload(principal, content)
