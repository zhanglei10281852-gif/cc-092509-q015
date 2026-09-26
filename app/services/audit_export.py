from __future__ import annotations

import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.export_document import build_document, canonical_json, row_digest, sha256_hex, verify_document
from app.core.export_rules import (
    AUDIENCES,
    grade_event_row,
    is_patent_asset,
    rule_definition_digest,
    validate_rule_definition,
)
from app.core.security import Principal
from app.services.audit import AuditService

MAX_ATTEMPTS = 5
LEASE_SECONDS = 300
ACTIVE_STATUSES = ("pending", "running", "completed")

TASK_COLUMNS = (
    "id,export_code,deduplication_key,audience,filters_json,rule_version,rule_digest,status,"
    "snapshot_id,row_count,page_count,file_digest,document_sha256,error_message,attempts,"
    "claimed_by,claimed_at,requested_by,created_at,updated_at,completed_at,"
    "(document_json IS NOT NULL) AS has_document"
)

# 项目归属解析：资源类型 → 项目编码来源表
_PROJECT_QUERIES = {
    "receipt_batch": "SELECT id, project_code FROM intake_batches WHERE id IN ({placeholders})",
    "dossier": (
        "SELECT s.id AS id, b.project_code AS project_code FROM dossiers s "
        "JOIN intake_batches b ON b.id=s.intake_id WHERE s.id IN ({placeholders})"
    ),
    "access_loan": (
        "SELECT l.id AS id, b.project_code AS project_code FROM access_loans l "
        "JOIN dossiers s ON s.id=l.dossier_id JOIN intake_batches b ON b.id=s.intake_id "
        "WHERE l.id IN ({placeholders})"
    ),
    "incident_case": (
        "SELECT c.id AS id, b.project_code AS project_code FROM incident_cases c "
        "LEFT JOIN dossiers s ON s.id=c.dossier_id "
        "LEFT JOIN intake_batches b ON b.id=COALESCE(s.intake_id, c.intake_id) "
        "WHERE c.id IN ({placeholders})"
    ),
    "collection_event": "SELECT id, project_code FROM disclosure_events WHERE id IN ({placeholders})",
}


class AuditExportService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.audit = AuditService(connection, self.clock)

    # ---------- 规则版本 ----------

    def current_rules(self) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM export_rule_versions WHERE is_current=1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise NotFoundError("尚未配置审计导出规则版本")
        result = dict(row)
        result["definition"] = json.loads(result.pop("definition_json"))
        return result

    def get_current_rules(self, principal: Principal) -> dict[str, Any]:
        principal.require("audit_exports.manage")
        return self.current_rules()

    def list_rule_versions(self, principal: Principal) -> list[dict[str, Any]]:
        principal.require("audit_exports.manage")
        rows = self.connection.execute("SELECT * FROM export_rule_versions ORDER BY id DESC").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["definition"] = json.loads(item.pop("definition_json"))
            result.append(item)
        return result

    def register_rule_version(self, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
        principal.require("audit_exports.manage")
        version = str(payload.get("version") or "").strip()
        if not version:
            raise ValidationError("规则版本号不能为空")
        definition = payload.get("definition")
        validate_rule_definition(definition)
        activate = bool(payload.get("activate", True))
        digest = rule_definition_digest(definition)
        now = to_storage(self.clock.now())
        if activate:
            self.connection.execute("UPDATE export_rule_versions SET is_current=0")
        try:
            cursor = self.connection.execute(
                "INSERT INTO export_rule_versions(version,definition_json,rule_digest,is_current,registered_by,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (version, canonical_json(definition), digest, 1 if activate else 0, principal.user_id, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("规则版本已经存在") from exc
        record = dict(
            self.connection.execute("SELECT * FROM export_rule_versions WHERE id=?", (cursor.lastrowid,)).fetchone()
        )
        self.audit.record(
            principal,
            "audit_export_rule.register",
            "audit_export_rule",
            version,
            after={"version": version, "rule_digest": digest, "is_current": activate},
        )
        record["definition"] = json.loads(record.pop("definition_json"))
        return record

    # ---------- 导出任务 ----------

    def create_task(self, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
        principal.require("audit_exports.manage")
        rules = self.current_rules()
        filters = self._normalize_filters(payload)
        dedup_key = "audit-export:" + sha256_hex(
            canonical_json({"filters": filters, "rule_version": rules["version"]})
        )
        existing = self._active_by_dedup(dedup_key)
        if existing is not None:
            self.audit.record(
                principal,
                "audit_export.create",
                "audit_export_task",
                str(existing["id"]),
                metadata={"reused": True, "export_code": existing["export_code"]},
            )
            return {"task": self._public(existing), "reused": True}
        now = to_storage(self.clock.now())
        export_code = f"AEX-{uuid.uuid4().hex[:12]}"
        try:
            cursor = self.connection.execute(
                """INSERT INTO audit_export_tasks(export_code,deduplication_key,audience,filters_json,
                   rule_version,rule_digest,status,requested_by,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,'pending',?,?,?)""",
                (
                    export_code,
                    dedup_key,
                    filters["audience"],
                    canonical_json(filters),
                    rules["version"],
                    rules["rule_digest"],
                    principal.user_id,
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError:
            existing = self._active_by_dedup(dedup_key)
            if existing is not None:
                return {"task": self._public(existing), "reused": True}
            raise
        task = self._require(int(cursor.lastrowid))
        self.audit.record(
            principal,
            "audit_export.create",
            "audit_export_task",
            str(task["id"]),
            after={"export_code": export_code, "audience": filters["audience"], "filters": filters},
            metadata={"reused": False, "rule_version": rules["version"]},
        )
        return {"task": self._public(task), "reused": False}

    def list_tasks(self, principal: Principal, *, status: str | None = None, audience: str | None = None) -> list[dict[str, Any]]:
        principal.require("audit_exports.manage")
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(status)
        if audience:
            clauses.append("audience=?")
            params.append(audience)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.connection.execute(
            f"SELECT {TASK_COLUMNS} FROM audit_export_tasks{where} ORDER BY id DESC LIMIT 100",
            tuple(params),
        ).fetchall()
        return [self._public(dict(row)) for row in rows]

    def get_task(self, principal: Principal, task_id: int) -> dict[str, Any]:
        principal.require("audit_exports.manage")
        task = self._require(task_id)
        result = self._public(task)
        if task.get("snapshot_id"):
            snapshot = self.connection.execute(
                "SELECT * FROM export_snapshots WHERE id=?", (task["snapshot_id"],)
            ).fetchone()
            if snapshot:
                result["snapshot"] = dict(snapshot)
        return result

    def claim_and_run(self, principal: Principal, task_id: int) -> dict[str, Any]:
        principal.require("audit_exports.manage")
        worker = principal.username
        now = self.clock.now()
        stale_before = to_storage(now - timedelta(seconds=LEASE_SECONDS))
        self.connection.execute(
            "UPDATE audit_export_tasks SET status='pending',claimed_by=NULL,claimed_at=NULL,updated_at=? "
            "WHERE status='running' AND claimed_at<?",
            (to_storage(now), stale_before),
        )
        task = self._require(task_id)
        if task["status"] == "completed":
            raise ConflictError("导出任务已完成，可直接下载结果")
        if task["status"] == "failed":
            raise ConflictError("导出任务处于失败状态，请先调用重试接口")
        if task["attempts"] >= MAX_ATTEMPTS:
            raise ConflictError("导出任务重试次数已达上限")
        cursor = self.connection.execute(
            "UPDATE audit_export_tasks SET status='running',claimed_by=?,claimed_at=?,attempts=attempts+1,updated_at=? "
            "WHERE id=? AND status='pending'",
            (worker, to_storage(now), to_storage(now), task_id),
        )
        if cursor.rowcount != 1:
            raise ConflictError("导出任务已被其他执行者领取")
        self.audit.record(
            principal,
            "audit_export.claim",
            "audit_export_task",
            str(task_id),
            metadata={"worker": worker, "attempt": int(task["attempts"]) + 1},
        )
        claimed = self._require(task_id)
        try:
            self._execute(claimed, worker=worker, principal=principal)
        except Exception as exc:
            message = str(exc)[:1000]
            self.connection.execute(
                "UPDATE audit_export_tasks SET status='failed',error_message=?,claimed_by=NULL,claimed_at=NULL,updated_at=? "
                "WHERE id=?",
                (message, to_storage(self.clock.now()), task_id),
            )
            self.audit.record(
                principal,
                "audit_export.fail",
                "audit_export_task",
                str(task_id),
                outcome="failure",
                metadata={"error": message},
            )
        return self._public(self._require(task_id))

    def retry(self, principal: Principal, task_id: int) -> dict[str, Any]:
        principal.require("audit_exports.manage")
        task = self._require(task_id)
        if task["status"] != "failed":
            raise ConflictError("只有失败状态的导出任务可以重试")
        if task["attempts"] >= MAX_ATTEMPTS:
            raise ConflictError("导出任务重试次数已达上限")
        now = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "UPDATE audit_export_tasks SET status='pending',error_message=NULL,claimed_by=NULL,claimed_at=NULL,updated_at=? "
                "WHERE id=? AND status='failed'",
                (now, task_id),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("已存在相同筛选条件的进行中或已完成导出任务，无法重试") from exc
        if cursor.rowcount != 1:
            raise ConflictError("导出任务状态已变化，请刷新后重试")
        self.audit.record(principal, "audit_export.retry", "audit_export_task", str(task_id))
        return self._public(self._require(task_id))

    def download(self, principal: Principal, task_id: int) -> tuple[str, dict[str, Any]]:
        principal.require("audit_exports.manage")
        row = self.connection.execute(
            "SELECT export_code,status,file_digest,document_sha256,document_json FROM audit_export_tasks WHERE id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("导出任务不存在")
        task = dict(row)
        if task["status"] != "completed" or not task["document_json"]:
            raise ConflictError("导出任务尚未完成，无法下载")
        self.audit.record(
            principal,
            "audit_export.download",
            "audit_export_task",
            str(task_id),
            metadata={"export_code": task["export_code"], "file_digest": task["file_digest"]},
        )
        return task["document_json"], {
            "export_code": task["export_code"],
            "file_digest": task["file_digest"],
            "document_sha256": task["document_sha256"],
        }

    def verify_download(self, principal: Principal, task_id: int, provided_digest: str) -> dict[str, Any]:
        principal.require("audit_exports.manage")
        task = self._require(task_id)
        if task["status"] != "completed" or not task.get("document_sha256"):
            raise ConflictError("导出任务尚未完成，无法核验")
        expected = task["document_sha256"]
        match = hmac.compare_digest(expected, provided_digest.strip().lower())
        self.audit.record(
            principal,
            "audit_export.verify_download",
            "audit_export_task",
            str(task_id),
            outcome="success" if match else "failure",
            metadata={"export_code": task["export_code"], "match": match},
        )
        return {
            "match": match,
            "export_code": task["export_code"],
            "file_digest": task["file_digest"],
            "expected_document_sha256": expected,
            "provided_document_sha256": provided_digest,
        }

    def verify_uploaded(self, principal: Principal, document: Any) -> dict[str, Any]:
        issues = verify_document(document)
        manifest = document.get("manifest") if isinstance(document, dict) else None
        manifest = manifest if isinstance(manifest, dict) else {}
        export_code = manifest.get("export_code")
        server_record: dict[str, Any] = {"found": False}
        if export_code:
            row = self.connection.execute(
                "SELECT * FROM audit_export_tasks WHERE export_code=?", (export_code,)
            ).fetchone()
            if row:
                task = dict(row)
                digest_match = bool(task["file_digest"]) and task["file_digest"] == manifest.get("file_digest")
                server_record = {
                    "found": True,
                    "status": task["status"],
                    "rule_version": task["rule_version"],
                    "file_digest": task["file_digest"],
                    "file_digest_match": digest_match,
                    "document_sha256": task["document_sha256"],
                }
                if not digest_match:
                    issues.append(
                        {
                            "kind": "server_digest_mismatch",
                            "page": None,
                            "event_id": None,
                            "expected": task["file_digest"],
                            "actual": manifest.get("file_digest"),
                            "message": "文件摘要与服务端记录不一致",
                        }
                    )
        valid = not issues
        self.audit.record(
            principal,
            "audit_export.verify",
            "audit_export_task",
            str(export_code) if export_code else None,
            outcome="success" if valid else "failure",
            metadata={"valid": valid, "issue_count": len(issues)},
        )
        return {
            "valid": valid,
            "issues": issues,
            "export_code": export_code,
            "rule_version": manifest.get("rule_version"),
            "server_record": server_record,
        }

    # ---------- 导出执行 ----------

    def _execute(self, task: dict[str, Any], *, worker: str, principal: Principal) -> None:
        definition = self._rule_definition(task["rule_version"])
        filters = json.loads(task["filters_json"])
        now = to_storage(self.clock.now())
        boundary = int(self.connection.execute("SELECT COALESCE(MAX(id),0) FROM audit_events").fetchone()[0])
        events = self._query_events(filters, boundary)
        projects = self._resolve_projects(events)
        if filters.get("project_code"):
            events = [
                event
                for event in events
                if projects.get((event["resource_type"], str(event["resource_id"]))) == filters["project_code"]
            ]
        max_rows = int(definition.get("max_rows", 50000))
        if len(events) > max_rows:
            raise ValidationError(f"筛选命中的审计事件超过 {max_rows} 条上限，请缩小时间或项目范围")
        context = self._dossier_context(events)
        profile = definition["audiences"][task["audience"]]
        rows: list[dict[str, Any]] = []
        for event in events:
            row = grade_event_row(
                event,
                profile=profile,
                definition=definition,
                project_code=projects.get((event["resource_type"], str(event["resource_id"]))),
                patent_unpublished=self._is_unpublished_patent_event(event, context, definition),
            )
            row["row_digest"] = row_digest(row)
            rows.append(row)
        rows_digest = sha256_hex(canonical_json([row["row_digest"] for row in rows]))
        cursor = self.connection.execute(
            "INSERT INTO export_snapshots(task_id,taken_at,source_max_event_id,row_count,rows_digest) VALUES(?,?,?,?,?)",
            (task["id"], now, boundary, len(rows), rows_digest),
        )
        snapshot_id = int(cursor.lastrowid)
        for ordinal, row in enumerate(rows, start=1):
            self.connection.execute(
                "INSERT INTO export_snapshot_rows(snapshot_id,ordinal,event_id,row_json,row_digest) VALUES(?,?,?,?,?)",
                (snapshot_id, ordinal, row["event_id"], canonical_json(row), row["row_digest"]),
            )
        snapshot_info = {
            "snapshot_id": snapshot_id,
            "taken_at": now,
            "source_max_event_id": boundary,
            "row_count": len(rows),
            "rows_digest": rows_digest,
        }
        document, document_text = build_document(
            export_code=task["export_code"],
            audience=task["audience"],
            rule_version=task["rule_version"],
            rule_digest=task["rule_digest"],
            filters=filters,
            snapshot=snapshot_info,
            rows=rows,
            page_size=int(definition.get("page_size", 50)),
            generated_at=now,
            generated_by=worker,
        )
        manifest = document["manifest"]
        self.connection.execute(
            """UPDATE audit_export_tasks SET status='completed',snapshot_id=?,row_count=?,page_count=?,
               file_digest=?,document_sha256=?,document_json=?,error_message=NULL,
               claimed_by=NULL,claimed_at=NULL,completed_at=?,updated_at=? WHERE id=?""",
            (
                snapshot_id,
                len(rows),
                manifest["page_count"],
                manifest["file_digest"],
                sha256_hex(document_text),
                document_text,
                now,
                now,
                task["id"],
            ),
        )
        self.audit.record(
            principal,
            "audit_export.complete",
            "audit_export_task",
            str(task["id"]),
            after={
                "export_code": task["export_code"],
                "row_count": len(rows),
                "page_count": manifest["page_count"],
                "file_digest": manifest["file_digest"],
                "snapshot_id": snapshot_id,
            },
        )

    def _query_events(self, filters: dict[str, Any], boundary: int) -> list[dict[str, Any]]:
        clauses = ["id<=?"]
        params: list[Any] = [boundary]
        if filters.get("occurred_from"):
            clauses.append("created_at>=?")
            params.append(filters["occurred_from"])
        if filters.get("occurred_to"):
            clauses.append("created_at<=?")
            params.append(filters["occurred_to"])
        actions = filters.get("actions") or []
        if actions:
            clauses.append("action IN (" + ",".join("?" for _ in actions) + ")")
            params.extend(actions)
        rows = self.connection.execute(
            "SELECT * FROM audit_events WHERE " + " AND ".join(clauses) + " ORDER BY id ASC",
            tuple(params),
        ).fetchall()
        return [dict(row) for row in rows]

    def _resolve_projects(self, events: list[dict[str, Any]]) -> dict[tuple[str, str], str | None]:
        ids_by_type: dict[str, set[str]] = {}
        for event in events:
            resource_id = event.get("resource_id")
            if resource_id is not None and str(resource_id).isdigit():
                ids_by_type.setdefault(event["resource_type"], set()).add(str(resource_id))
        resolved: dict[tuple[str, str], str | None] = {}
        for resource_type, sql in _PROJECT_QUERIES.items():
            for resource_id, project_code in self._bulk_project_map(sql, ids_by_type.get(resource_type)).items():
                resolved[(resource_type, resource_id)] = project_code
        approval_ids = ids_by_type.get("approval_request")
        if approval_ids:
            placeholders = ",".join("?" for _ in approval_ids)
            approvals = self.connection.execute(
                f"SELECT id, resource_type, resource_id FROM approval_requests WHERE id IN ({placeholders})",
                tuple(sorted(approval_ids)),
            ).fetchall()
            extra: dict[str, set[str]] = {}
            for approval in approvals:
                target_type = approval["resource_type"]
                target_id = approval["resource_id"]
                if target_id is None:
                    continue
                key = (target_type, str(target_id))
                if target_type in _PROJECT_QUERIES and key not in resolved:
                    extra.setdefault(target_type, set()).add(str(target_id))
            for target_type, extra_ids in extra.items():
                for resource_id, project_code in self._bulk_project_map(_PROJECT_QUERIES[target_type], extra_ids).items():
                    resolved[(target_type, resource_id)] = project_code
            for approval in approvals:
                target_id = approval["resource_id"]
                resolved[("approval_request", str(approval["id"]))] = (
                    resolved.get((approval["resource_type"], str(target_id))) if target_id is not None else None
                )
        return resolved

    def _bulk_project_map(self, sql_template: str, ids: set[str] | None) -> dict[str, str | None]:
        numeric = sorted(str(value) for value in (ids or set()) if str(value).isdigit())
        if not numeric:
            return {}
        placeholders = ",".join("?" for _ in numeric)
        rows = self.connection.execute(sql_template.format(placeholders=placeholders), tuple(numeric)).fetchall()
        return {str(row["id"]): row["project_code"] for row in rows}

    def _dossier_context(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        dossier_ids: set[int] = set()
        incident_ids: set[int] = set()
        for event in events:
            resource_id = event.get("resource_id")
            if resource_id is None or not str(resource_id).isdigit():
                continue
            if event["resource_type"] == "dossier":
                dossier_ids.add(int(resource_id))
            elif event["resource_type"] == "incident_case":
                incident_ids.add(int(resource_id))
        incident_dossier: dict[int, int] = {}
        if incident_ids:
            placeholders = ",".join("?" for _ in incident_ids)
            for row in self.connection.execute(
                f"SELECT id, dossier_id FROM incident_cases WHERE id IN ({placeholders})",
                tuple(sorted(incident_ids)),
            ).fetchall():
                if row["dossier_id"] is not None:
                    incident_dossier[int(row["id"])] = int(row["dossier_id"])
                    dossier_ids.add(int(row["dossier_id"]))
        dossiers: dict[int, dict[str, Any]] = {}
        if dossier_ids:
            placeholders = ",".join("?" for _ in dossier_ids)
            for row in self.connection.execute(
                f"SELECT id, asset_type, lifecycle_state FROM dossiers WHERE id IN ({placeholders})",
                tuple(sorted(dossier_ids)),
            ).fetchall():
                dossiers[int(row["id"])] = dict(row)
        return {"dossiers": dossiers, "incident_dossier": incident_dossier}

    @staticmethod
    def _is_unpublished_patent_event(event: dict[str, Any], context: dict[str, Any], definition: dict[str, Any]) -> bool:
        resource_id = event.get("resource_id")
        if resource_id is None or not str(resource_id).isdigit():
            return False
        dossier = None
        if event["resource_type"] == "dossier":
            dossier = context["dossiers"].get(int(resource_id))
        elif event["resource_type"] == "incident_case":
            dossier_id = context["incident_dossier"].get(int(resource_id))
            dossier = context["dossiers"].get(dossier_id) if dossier_id is not None else None
        if not dossier:
            return False
        markers = definition.get("patent_asset_markers", [])
        published = set(definition.get("published_states", []))
        return is_patent_asset(dossier.get("asset_type"), markers) and dossier.get("lifecycle_state") not in published

    # ---------- 内部工具 ----------

    def _rule_definition(self, version: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT definition_json FROM export_rule_versions WHERE version=?", (version,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"规则版本不存在：{version}")
        return json.loads(row["definition_json"])

    def _require(self, task_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            f"SELECT {TASK_COLUMNS} FROM audit_export_tasks WHERE id=?", (task_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("导出任务不存在")
        return dict(row)

    def _active_by_dedup(self, dedup_key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            f"SELECT {TASK_COLUMNS} FROM audit_export_tasks WHERE deduplication_key=? "
            "AND status IN ('pending','running','completed') ORDER BY id DESC LIMIT 1",
            (dedup_key,),
        ).fetchone()
        return dict(row) if row else None

    def _normalize_filters(self, payload: dict[str, Any]) -> dict[str, Any]:
        audience = payload.get("audience")
        if audience not in AUDIENCES:
            raise ValidationError("未知的导出对象角色")
        occurred_from = self._normalize_datetime(payload.get("occurred_from"), "occurred_from")
        occurred_to = self._normalize_datetime(payload.get("occurred_to"), "occurred_to")
        if occurred_from and occurred_to and occurred_from > occurred_to:
            raise ValidationError("开始时间不能晚于结束时间")
        project_code = (payload.get("project_code") or "").strip() or None
        actions = sorted({str(item).strip() for item in (payload.get("actions") or []) if str(item).strip()})
        return {
            "audience": audience,
            "occurred_from": occurred_from,
            "occurred_to": occurred_to,
            "project_code": project_code,
            "actions": actions,
        }

    @staticmethod
    def _normalize_datetime(value: Any, field: str) -> str | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).strip())
        except ValueError as exc:
            raise ValidationError(f"{field} 必须使用 ISO 8601 时间格式") from exc
        return to_storage(parsed)

    @staticmethod
    def _public(task: dict[str, Any]) -> dict[str, Any]:
        result = {key: value for key, value in task.items() if key not in {"document_json", "deduplication_key"}}
        if "filters_json" in result:
            result["filters"] = json.loads(result.pop("filters_json"))
        result["has_document"] = bool(result.get("has_document"))
        return result
