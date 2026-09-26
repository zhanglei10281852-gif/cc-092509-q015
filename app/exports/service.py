from __future__ import annotations

import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal
from app.exports.builder import build_manifest, build_pages, render_bundle, sha256_hex
from app.exports.rules import (
    PROFILE_LABEL,
    PROFILE_PERMISSION,
    PROFILES,
    RULE_VERSION,
    SECTION_ORDER,
    SECTIONS_BY_PROFILE,
    criteria_fingerprint,
    normalize_criteria,
    project_section,
)
from app.exports.snapshot import fetch_section, freeze_snapshot, snapshot_digest
from app.exports.verification import VerifyReport, verify_bundle
from app.services.audit import AuditContext, AuditService
from app.services.jobs import JobService

JOB_TYPE = "audit.export"
MAX_ATTEMPTS = 3
RETRY_SECONDS = 30
WORKER_NAME = "audit-export-worker"


def export_storage_dir() -> Path:
    raw = os.getenv("ARCHIVE_EXPORT_DIR", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    from app.database import database_path

    return database_path().parent / "exports"


class AuditExportService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.jobs = JobService(connection, self.clock)
        self.audit = AuditService(connection, self.clock)

    # ------------------------------------------------------------------ 请求

    def request_export(self, principal: Principal, profile: str, payload: dict[str, Any]) -> dict[str, Any]:
        if profile not in PROFILES:
            raise ValidationError(f"未知导出角色：{profile}")
        principal.require(PROFILE_PERMISSION[profile])
        criteria = normalize_criteria(payload)
        fingerprint = criteria_fingerprint(profile, criteria)
        existing = self.connection.execute(
            "SELECT * FROM audit_exports WHERE requested_by=? AND criteria_fingerprint=?",
            (principal.user_id, fingerprint),
        ).fetchone()
        reused = existing is not None
        if existing is not None:
            export = dict(existing)
            # 未完成或已完成一律复用；只有终态失败的旧结果在重新提交时重置重试。
            if export["status"] == "failed":
                export = self._reactivate(export["id"])
        else:
            now = to_storage(self.clock.now())
            export_code = f"AEXP-{uuid.uuid4().hex}"
            cursor = self.connection.execute(
                """INSERT INTO audit_exports(
                       export_code,requested_by,profile,criteria_json,criteria_fingerprint,
                       rule_version,status,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?, 'pending',?,?)""",
                (
                    export_code,
                    principal.user_id,
                    profile,
                    json.dumps(criteria, ensure_ascii=False, sort_keys=True),
                    fingerprint,
                    RULE_VERSION,
                    now,
                    now,
                ),
            )
            export_id = int(cursor.lastrowid)
            job = self.jobs.enqueue(
                JOB_TYPE,
                f"audit-export:{export_id}",
                {"export_id": export_id, "export_code": export_code},
            )
            self.connection.execute(
                "UPDATE audit_exports SET job_id=?,enqueued_count=enqueued_count+1,updated_at=? WHERE id=?",
                (job["id"], now, export_id),
            )
            export = dict(self.connection.execute("SELECT * FROM audit_exports WHERE id=?", (export_id,)).fetchone())
        self.audit.record(
            principal,
            "audit.export.request",
            "audit_export",
            export["id"],
            metadata={"profile": profile, "reused": reused, "export_code": export["export_code"]},
        )
        return {**self.public_view(export), "reused": reused}

    def retry_export(self, principal: Principal, export_id: int) -> dict[str, Any]:
        export = self._require_owned(principal, export_id)
        if export["status"] != "failed":
            raise ConflictError("只有失败的导出可以重试")
        result = self.public_view(self._reactivate(export_id))
        self.audit.record(
            principal, "audit.export.retry", "audit_export", export_id,
            metadata={"export_code": export["export_code"]},
        )
        return result

    def _reactivate(self, export_id: int) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        export = dict(self._row(export_id))
        if export["job_id"] is not None:
            self.connection.execute(
                "UPDATE background_jobs SET status='pending',attempts=0,available_at=?,error_message=NULL,"
                "locked_at=NULL,locked_by=NULL,updated_at=? WHERE id=?",
                (now, now, export["job_id"]),
            )
        self.connection.execute(
            "UPDATE audit_exports SET status='pending',error_message=NULL,enqueued_count=enqueued_count+1,updated_at=? WHERE id=?",
            (now, export_id),
        )
        return dict(self._row(export_id))

    # --------------------------------------------------------------- 查询列表

    @staticmethod
    def _require_export_access(principal: Principal) -> None:
        """持有任一导出相关权限即可使用导出接口（研发负责人可能只有本角色视图权限）。"""
        if principal.can("audit.export"):
            return
        if any(principal.can(permission) for permission in PROFILE_PERMISSION.values()):
            return
        raise PermissionDeniedError("缺少权限：audit.export")

    def list_exports(self, principal: Principal) -> list[dict[str, Any]]:
        self._require_export_access(principal)
        rows = self.connection.execute(
            "SELECT * FROM audit_exports WHERE requested_by=? ORDER BY id DESC LIMIT 200",
            (principal.user_id,),
        ).fetchall()
        return [self.public_view(dict(row)) for row in rows]

    def get_export(self, principal: Principal, export_id: int) -> dict[str, Any]:
        return self.public_view(self._require_owned(principal, export_id))

    def _require_owned(self, principal: Principal, export_id: int) -> dict[str, Any]:
        row = self._row(export_id)
        if row is None:
            raise NotFoundError("审计导出不存在")
        export = dict(row)
        if export["requested_by"] != principal.user_id and not principal.can("*"):
            # 导出内容按角色分级，只能由申请人本人（或系统管理员）访问，
            # 防止高密级视图经他人账号流转。
            raise PermissionDeniedError("不能访问他人的审计导出")
        return export

    def _row(self, export_id: int):
        return self.connection.execute("SELECT * FROM audit_exports WHERE id=?", (export_id,)).fetchone()

    def public_view(self, export: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": export["id"],
            "export_code": export["export_code"],
            "profile": export["profile"],
            "profile_label": PROFILE_LABEL[export["profile"]],
            "criteria": json.loads(export["criteria_json"]),
            "criteria_fingerprint": export["criteria_fingerprint"],
            "rule_version": export["rule_version"],
            "status": export["status"],
            "attempts": export["enqueued_count"],
            "snapshot_at": export["snapshot_at"],
            "snapshot_digest": export["snapshot_digest"],
            "record_count": export["record_count"],
            "page_count": export["page_count"],
            "root_hash": export["root_hash"],
            "file_digest": export["file_digest"],
            "error_message": export["error_message"],
            "created_at": export["created_at"],
            "completed_at": export["completed_at"],
            "download_ready": export["status"] == "completed",
        }

    # --------------------------------------------------------------- 任务执行

    def run_next(self, worker: str) -> dict[str, Any] | None:
        """领取一个导出任务并执行；失败按重试策略回写，返回执行结果而非抛出。"""
        job = self.jobs.claim(worker, job_type=JOB_TYPE)
        if job is None:
            return None
        payload = json.loads(job["payload_json"])
        export_id = int(payload["export_id"])
        try:
            result = self.execute_export(export_id)
        except Exception as exc:  # 任务失败不能拖垮工作进程
            attempts = int(job["attempts"])
            if attempts < MAX_ATTEMPTS:
                self.jobs.fail(job["id"], worker, str(exc), retry_seconds=RETRY_SECONDS)
                self._mark_export_retryable(export_id)
                return {"export_id": export_id, "status": "retry_scheduled", "error": str(exc)}
            self.jobs.fail(job["id"], worker, str(exc))
            self._mark_export_failed(export_id, str(exc))
            return {"export_id": export_id, "status": "failed", "error": str(exc)}
        self.jobs.complete(job["id"], worker, result["receipt"])
        return result

    def _mark_export_failed(self, export_id: int, message: str) -> None:
        now = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE audit_exports SET status='failed',error_message=?,updated_at=? WHERE id=?",
            (message[:1000], now, export_id),
        )

    def _mark_export_retryable(self, export_id: int) -> None:
        # 可重试失败：保持 pending 等待再次领取。
        now = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE audit_exports SET status='pending',updated_at=? WHERE id=? AND status='running'",
            (now, export_id),
        )

    def execute_export(self, export_id: int) -> dict[str, Any]:
        """固定快照 → 分级投影 → 分页摘要 → 写包。重复执行结果幂等。"""
        row = self._row(export_id)
        if row is None:
            raise NotFoundError("审计导出不存在")
        export = dict(row)
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        self.connection.execute(
            "UPDATE audit_exports SET status='running',updated_at=? WHERE id=? AND status IN ('pending','running','failed')",
            (now, export_id),
        )

        # 快照水位只冻结一次：条件更新保证并发/重试时不会覆盖既有水位。
        if export["snapshot_digest"] is None:
            marks = freeze_snapshot(self.connection, export["profile"])
            digest = snapshot_digest(marks)
            self.connection.execute(
                "UPDATE audit_exports SET snapshot_at=?,snapshot_max_event_id=?,"
                "snapshot_max_incident_id=?,snapshot_max_audit_event_id=?,"
                "snapshot_digest=?,updated_at=? WHERE id=? AND snapshot_digest IS NULL",
                (
                    now,
                    marks.get("dossier_events", 0),
                    marks.get("incident_cases", 0),
                    marks.get("audit_events", 0),
                    digest,
                    now,
                    export_id,
                ),
            )
        # 无论水位是否由本次执行写入，一律以数据库中已冻结的值为准。
        export = dict(self._row(export_id))
        marks = self._marks_from_export(export)
        digest = export["snapshot_digest"]

        criteria = json.loads(export["criteria_json"])
        sections: dict[str, list[dict[str, Any]]] = {}
        for section in SECTIONS_BY_PROFILE[export["profile"]]:
            raw_rows = fetch_section(self.connection, export["profile"], section, criteria, marks)
            sections[section] = project_section(export["profile"], section, raw_rows)
        pages, summaries, root_hash, record_count = build_pages(sections)

        requester = self.connection.execute(
            "SELECT id,username,display_name FROM users WHERE id=?", (export["requested_by"],)
        ).fetchone()
        generated_by = dict(requester) if requester else {"id": export["requested_by"]}
        manifest = build_manifest(
            export_code=export["export_code"],
            profile=export["profile"],
            profile_label=PROFILE_LABEL[export["profile"]],
            criteria=criteria,
            criteria_fingerprint=export["criteria_fingerprint"],
            snapshot_marks={section: marks.get(section, 0) for section in SECTION_ORDER},
            snapshot_digest=digest,
            snapshot_at=export["snapshot_at"] or now,
            pages=pages,
            summaries=summaries,
            root_hash=root_hash,
            record_count=record_count,
            generated_by=generated_by,
            generated_at=now,
        )
        bundle, _file_digests = render_bundle(manifest, pages)
        file_digest = sha256_hex(bundle)

        directory = export_storage_dir() / export["export_code"][:9].lower()
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / f"{export['export_code']}.tar"
        tmp = target.with_suffix(".tar.tmp")
        tmp.write_bytes(bundle)
        tmp.replace(target)

        completed_at = to_storage(self.clock.now())
        self.connection.execute(
            """UPDATE audit_exports SET status='completed',record_count=?,page_count=?,file_count=?,
                   root_hash=?,file_digest=?,storage_dir=?,completed_at=?,updated_at=?
               WHERE id=?""",
            (
                record_count,
                len(pages),
                len(pages) + 1,  # 分页文件 + manifest.json
                root_hash,
                file_digest,
                str(directory),
                completed_at,
                completed_at,
                export_id,
            ),
        )
        final = dict(self._row(export_id))
        self.audit.record(
            AuditContext(actor_user_id=None, actor_name="系统"),
            action="audit.export.generate",
            resource_type="audit_export",
            resource_id=export_id,
            metadata={
                "record_count": record_count,
                "page_count": len(pages),
                "rule_version": RULE_VERSION,
            },
        )
        return {"export": self.public_view(final), "receipt": self.receipt(final), "path": str(target)}

    @staticmethod
    def _marks_from_export(export: dict[str, Any]) -> dict[str, int]:
        return {
            "dossier_events": int(export["snapshot_max_event_id"] or 0),
            "incident_cases": int(export["snapshot_max_incident_id"] or 0),
            "audit_events": int(export["snapshot_max_audit_event_id"] or 0),
        }

    def receipt(self, export: dict[str, Any]) -> dict[str, Any]:
        return {
            "export_code": export["export_code"],
            "rule_version": export["rule_version"],
            "snapshot_digest": export["snapshot_digest"],
            "record_count": export["record_count"],
            "page_count": export["page_count"],
            "root_hash": export["root_hash"],
            "file_digest": export["file_digest"],
        }

    # ----------------------------------------------------------------- 下载

    def bundle_path(self, principal: Principal, export_id: int) -> tuple[dict[str, Any], Path]:
        export = self._require_owned(principal, export_id)
        if export["status"] != "completed":
            raise ConflictError("导出尚未完成，暂不能下载")
        path = Path(export["storage_dir"]) / f"{export['export_code']}.tar"
        if not path.exists():
            raise NotFoundError("导出文件缺失，请联系保密办核查存储")
        data = path.read_bytes()
        if sha256_hex(data) != export["file_digest"]:
            raise ConflictError("服务端导出文件摘要不一致，文件可能已被篡改，拒绝下载")
        self.audit.record(
            principal, "audit.export.download", "audit_export", export_id,
            metadata={"export_code": export["export_code"]},
        )
        return export, path

    # ----------------------------------------------------------------- 核验

    def verify_completed(self, principal: Principal, export_id: int) -> dict[str, Any]:
        export = self._require_owned(principal, export_id)
        if export["status"] != "completed":
            raise ConflictError("导出尚未完成，暂无可核验文件")
        path = Path(export["storage_dir"]) / f"{export['export_code']}.tar"
        report = verify_bundle(path, receipt=self.receipt(export))
        self.audit.record(
            principal, "audit.export.verify", "audit_export", export_id,
            metadata={"ok": report.ok, "issue_count": len(report.issues)},
        )
        return report.to_dict()

    def verify_upload(self, principal: Principal, content: bytes) -> dict[str, Any]:
        self._require_export_access(principal)
        report = verify_bundle(content)
        export_code = report.export_code
        receipt = None
        if export_code:
            row = self.connection.execute(
                "SELECT * FROM audit_exports WHERE export_code=?", (export_code,)
            ).fetchone()
            if row is not None:
                export = dict(row)
                if export["requested_by"] != principal.user_id and not principal.can("*"):
                    raise PermissionDeniedError("不能核验他人的审计导出")
                receipt = self.receipt(export)
        if receipt is not None:
            report = verify_bundle(content, receipt=receipt)
        self.audit.record(
            principal, "audit.export.verify_upload", "audit_export", export_code or 0,
            metadata={"ok": report.ok, "issue_count": len(report.issues)},
        )
        return report.to_dict()

    def verify_offline(self, path: Path) -> VerifyReport:
        """离线命令入口：优先包内自洽核验；能联上库时追加登记摘要交叉核验。"""
        report = verify_bundle(path)
        if report.export_code:
            row = self.connection.execute(
                "SELECT * FROM audit_exports WHERE export_code=?", (report.export_code,)
            ).fetchone()
            if row is not None:
                report = verify_bundle(path, receipt=self.receipt(dict(row)))
        return report
