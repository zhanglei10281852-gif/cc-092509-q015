from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from app.exports.rules import SECTION_ORDER, SECTIONS_BY_PROFILE

# 各分区用于冻结快照的水位表与主键：导出只覆盖 id <= 水位 的记录，
# 任务重试或重新执行时结果不变，新增数据不会混入已固定的快照。
SECTION_WATERMARK = {
    "dossier_events": ("dossier_events", "id"),
    "incident_cases": ("incident_cases", "id"),
    "audit_events": ("audit_events", "id"),
}

_DOSSIER_EVENT_SQL = """
SELECT e.id, e.dossier_id, e.event_type, e.actor_user_id, e.quantity_delta,
       e.from_state, e.to_state, e.details_json, e.occurred_at,
       d.dossier_code, d.vault_id,
       v.sensitivity AS vault_sensitivity, v.code AS vault_code,
       b.project_code
FROM dossier_events e
JOIN dossiers d ON d.id = e.dossier_id
JOIN intake_batches b ON b.id = d.intake_id
LEFT JOIN vault_locations v ON v.id = d.vault_id
WHERE e.id <= ?
"""

_INCIDENT_CASE_SQL = """
SELECT c.id, c.case_code, c.dossier_id, c.intake_id, c.incident_type, c.severity,
       c.state, c.detected_by, c.description, c.resolution, c.created_at,
       u.display_name AS detected_by_name,
       d.dossier_code, d.vault_id AS dossier_vault_id,
       v.sensitivity AS vault_sensitivity, v.code AS vault_code,
       b.project_code
FROM incident_cases c
LEFT JOIN users u ON u.id = c.detected_by
LEFT JOIN dossiers d ON d.id = c.dossier_id
LEFT JOIN vault_locations v ON v.id = d.vault_id
LEFT JOIN intake_batches b ON b.id = COALESCE(c.intake_id, d.intake_id)
WHERE c.id <= ?
"""

_AUDIT_EVENT_SQL = """
SELECT id, actor_user_id, actor_name, action, resource_type, resource_id,
       outcome, created_at
FROM audit_events
WHERE id <= ?
"""


def freeze_snapshot(connection: sqlite3.Connection, profile: str) -> dict[str, int]:
    """在同一事务内读取各分区最大 id，作为本次导出的固定快照水位。"""
    marks: dict[str, int] = {}
    for section in SECTIONS_BY_PROFILE[profile]:
        table, column = SECTION_WATERMARK[section]
        row = connection.execute(f"SELECT COALESCE(MAX({column}),0) FROM {table}").fetchone()
        marks[section] = int(row[0])
    return marks


def snapshot_digest(marks: dict[str, int]) -> str:
    ordered = {section: marks.get(section, 0) for section in SECTION_ORDER}
    canonical = json.dumps(ordered, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _apply_common_filters(
    sql: str, params: list[Any], criteria: dict[str, Any], *, time_column: str, project_column: str | None
) -> tuple[str, list[Any]]:
    if "events_from" in criteria:
        sql += f" AND {time_column} >= ?"
        params.append(criteria["events_from"])
    if "events_to" in criteria:
        sql += f" AND {time_column} <= ?"
        params.append(criteria["events_to"])
    if project_column and "project_codes" in criteria:
        placeholders = ",".join("?" for _ in criteria["project_codes"])
        sql += f" AND {project_column} IN ({placeholders})"
        params.extend(criteria["project_codes"])
    return sql, params


def fetch_section(
    connection: sqlite3.Connection,
    profile: str,
    section: str,
    criteria: dict[str, Any],
    marks: dict[str, int],
) -> list[dict[str, Any]]:
    if section not in SECTIONS_BY_PROFILE[profile]:
        return []
    watermark = marks[section]
    if section == "dossier_events":
        sql, params = _apply_common_filters(
            _DOSSIER_EVENT_SQL,
            [watermark],
            criteria,
            time_column="e.occurred_at",
            project_column="b.project_code",
        )
        if "event_types" in criteria:
            placeholders = ",".join("?" for _ in criteria["event_types"])
            sql += f" AND e.event_type IN ({placeholders})"
            params.extend(criteria["event_types"])
        sql += " ORDER BY e.id"
    elif section == "incident_cases":
        sql, params = _apply_common_filters(
            _INCIDENT_CASE_SQL, [watermark], criteria, time_column="c.created_at", project_column="b.project_code"
        )
        sql += " ORDER BY c.id"
    elif section == "audit_events":
        sql, params = _apply_common_filters(
            _AUDIT_EVENT_SQL, [watermark], criteria, time_column="created_at", project_column=None
        )
        sql += " ORDER BY id"
    else:  # pragma: no cover - 分区枚举固定
        return []
    rows = connection.execute(sql, params).fetchall()
    return [dict(row) for row in rows]
