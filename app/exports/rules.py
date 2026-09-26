from __future__ import annotations

from typing import Any

from app.core.errors import ValidationError
from app.core.privacy import sanitize_text, sanitize_payload
from app.core.security import request_fingerprint

# 规则版本：任何字段视图、快照口径或筛选口径变化都必须提升版本号。
# 历史导出包内始终固化生成时的版本，权限/档案状态变化不会改写旧包标注。
RULE_VERSION = "audit-export-rules-2026.09.1"
MANIFEST_VERSION = "1.0"
PAGE_SIZE = 500

PROFILES = ("internal_audit", "legal", "research_lead")
PROFILE_PERMISSION = {
    "internal_audit": "audit.export.internal_audit",
    "legal": "audit.export.legal",
    "research_lead": "audit.export.research_lead",
}
PROFILE_LABEL = {
    "internal_audit": "内审视图",
    "legal": "法务视图",
    "research_lead": "研发负责人视图",
}

# 固定的分区顺序，也是哈希链跨分区衔接的顺序。
SECTION_ORDER = ("dossier_events", "incident_cases", "audit_events")
SECTIONS_BY_PROFILE = {
    "internal_audit": ("dossier_events", "incident_cases", "audit_events"),
    "legal": ("dossier_events", "incident_cases"),
    "research_lead": ("dossier_events",),
}

# 白名单字段：未列出的列（asset_type、description 原文、phone/email 等）永不进包。
# 泄密事件信息只出现在 incident_cases 分区，不与档案事件拼接，避免重复与放大。
DOSSIER_EVENT_FIELDS = {
    "research_lead": (
        "record_id", "record_kind", "event_id", "dossier_id", "dossier_code",
        "project_code", "event_type", "occurred_at", "quantity_delta", "to_state",
    ),
    "legal": (
        "record_id", "record_kind", "event_id", "dossier_id", "dossier_code",
        "project_code", "event_type", "occurred_at", "quantity_delta",
        "from_state", "to_state", "vault_sensitivity",
    ),
    "internal_audit": (
        "record_id", "record_kind", "event_id", "dossier_id", "dossier_code",
        "project_code", "event_type", "occurred_at", "quantity_delta",
        "from_state", "to_state", "actor_user_id", "vault_id", "vault_code",
        "vault_sensitivity", "event_details",
    ),
}

INCIDENT_CASE_FIELDS = {
    # 法务为定责需要事件描述与处置结论（经过联系方式脱敏）。
    "legal": (
        "record_id", "record_kind", "case_id", "case_code", "incident_type",
        "severity", "state", "dossier_id", "dossier_code", "project_code",
        "vault_sensitivity", "detected_by_name", "occurred_at",
        "description", "resolution",
    ),
    # 内审只看结构与状态，不带走可能含未公开专利内容的描述原文。
    "internal_audit": (
        "record_id", "record_kind", "case_id", "case_code", "incident_type",
        "severity", "state", "dossier_id", "dossier_code", "project_code",
        "vault_id", "vault_code", "vault_sensitivity",
        "detected_by", "detected_by_name", "occurred_at",
    ),
}

AUDIT_EVENT_FIELDS = {
    "internal_audit": (
        "record_id", "record_kind", "audit_event_id", "actor_user_id",
        "actor_name", "action", "resource_type", "resource_id", "outcome",
        "occurred_at",
    ),
}

# 快照 SQL 中可筛选的档案事件类型；规则版本固定其取值集合。
KNOWN_EVENT_TYPES = (
    "received",
    "issue_copy.created",
    "issue_copy.source",
    "disclosed",
    "access_loaned",
    "returned",
    "vault.transferred",
    "disposed",
)

CRITERIA_FIELDS = ("events_from", "events_to", "project_codes", "event_types")


def normalize_criteria(payload: dict[str, Any]) -> dict[str, Any]:
    """校验并归一化筛选条件，返回的字典用于快照查询与指纹计算。"""
    unknown = set(payload) - set(CRITERIA_FIELDS)
    if unknown:
        raise ValidationError(f"不支持的筛选字段：{sorted(unknown)}")
    criteria: dict[str, Any] = {}
    for key in ("events_from", "events_to"):
        value = payload.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ValidationError(f"{key} 必须是 ISO 时间字符串")
        try:
            datetime_fromiso(value)
        except ValueError as exc:
            raise ValidationError(f"{key} 不是合法的 ISO 时间") from exc
        criteria[key] = value
    if "events_from" in criteria and "events_to" in criteria and criteria["events_from"] > criteria["events_to"]:
        raise ValidationError("events_from 不能晚于 events_to")
    for key in ("project_codes", "event_types"):
        values = payload.get(key)
        if values is None:
            continue
        if not isinstance(values, list) or not values or len(values) > 200:
            raise ValidationError(f"{key} 必须是非空且不超过 200 项的列表")
        if not all(isinstance(item, str) and item.strip() for item in values):
            raise ValidationError(f"{key} 只能包含非空字符串")
        cleaned = [item.strip()[:64] for item in values]
        criteria[key] = sorted(set(cleaned))
    if "event_types" in criteria:
        unsupported = sorted(set(criteria["event_types"]) - set(KNOWN_EVENT_TYPES))
        if unsupported:
            raise ValidationError(f"规则 {RULE_VERSION} 不识别的事件类型：{unsupported}")
    return criteria


def datetime_fromiso(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value)


def criteria_fingerprint(profile: str, criteria: dict[str, Any]) -> str:
    """同一角色 + 同一筛选条件得到同一指纹，作为复用与去重依据。"""
    basis = {"rule_version": RULE_VERSION, "profile": profile, "criteria": criteria}
    return request_fingerprint(basis)


def _masked_vault_code(vault_id: Any) -> str:
    return f"MASKED-{int(vault_id):04d}"


def _safe_text(value: Any) -> Any:
    """自由文本脱敏；空值（如未填写的事件处置结论）原样保留。"""
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def _project_row(profile: str, section: str, row: dict[str, Any]) -> dict[str, Any]:
    if section == "dossier_events":
        allowed = DOSSIER_EVENT_FIELDS[profile]
        record: dict[str, Any] = {
            "record_id": str(row["id"]),
            "record_kind": "dossier_event",
            "event_id": row["id"],
            "dossier_id": row["dossier_id"],
            "dossier_code": row["dossier_code"],
            "project_code": row["project_code"],
            "event_type": row["event_type"],
            "actor_user_id": row["actor_user_id"],
            "quantity_delta": row["quantity_delta"],
            "from_state": row["from_state"],
            "to_state": row["to_state"],
            "occurred_at": row["occurred_at"],
            "vault_id": row["vault_id"],
            "vault_sensitivity": row["vault_sensitivity"],
        }
        if row["vault_id"] is not None and row["vault_sensitivity"] != "normal":
            # 任何角色都拿不到受限/绝密库位的真实编码，内审也只看到替代码。
            record["vault_code"] = _masked_vault_code(row["vault_id"])
        else:
            record["vault_code"] = row.get("vault_code")
        if profile == "internal_audit":
            details = sanitize_payload(_loads(row.get("details_json")))
            record["event_details"] = details
    elif section == "incident_cases":
        allowed = INCIDENT_CASE_FIELDS[profile]
        vault_id = row.get("dossier_vault_id")
        record = {
            "record_id": f"case-{row['id']}",
            "record_kind": "incident_case",
            "case_id": row["id"],
            "case_code": row["case_code"],
            "incident_type": row["incident_type"],
            "severity": row["severity"],
            "state": row["state"],
            "dossier_id": row["dossier_id"],
            "dossier_code": row.get("dossier_code"),
            "project_code": row.get("project_code"),
            "vault_id": vault_id,
            "vault_sensitivity": row.get("vault_sensitivity"),
            "detected_by": row["detected_by"],
            "detected_by_name": _safe_text(row.get("detected_by_name")),
            "occurred_at": row["created_at"],
            "description": _safe_text(row.get("description")),
            "resolution": _safe_text(row.get("resolution")),
        }
        if vault_id is not None and row.get("vault_sensitivity") != "normal":
            record["vault_code"] = _masked_vault_code(vault_id)
        else:
            record["vault_code"] = row.get("vault_code")
    elif section == "audit_events":
        allowed = AUDIT_EVENT_FIELDS[profile]
        record = {
            "record_id": f"audit-{row['id']}",
            "record_kind": "audit_event",
            "audit_event_id": row["id"],
            "actor_user_id": row["actor_user_id"],
            "actor_name": _safe_text(row.get("actor_name")),
            "action": row["action"],
            "resource_type": row["resource_type"],
            "resource_id": row["resource_id"],
            "outcome": row["outcome"],
            "occurred_at": row["created_at"],
        }
    else:  # pragma: no cover - 分区枚举固定
        raise ValidationError(f"未知导出分区：{section}")
    return {field: record[field] for field in allowed if field in record}


def _loads(value: Any) -> dict[str, Any]:
    import json

    if not value:
        return {}
    parsed = json.loads(value)
    return parsed if isinstance(parsed, dict) else {}


def project_section(profile: str, section: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if section not in SECTIONS_BY_PROFILE[profile]:
        return []
    return [_project_row(profile, section, row) for row in rows]
