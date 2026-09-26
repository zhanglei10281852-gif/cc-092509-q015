from __future__ import annotations

import json
from typing import Any

from app.core.errors import ValidationError
from app.core.export_document import canonical_json, sha256_hex
from app.core.privacy import sanitize_payload

RULE_VERSION = "audit-export-rules/v1"

AUDIENCES = ("internal_audit", "legal", "rd_lead")

SENSITIVE_VAULT_LEVELS = ("restricted", "critical")

# 分级字段视图规则：内审可见精确库位与完整载荷，法务可见载荷但隐去受限库位与
# 未公开专利内容，研发负责人仅可见事件级摘要。所有角色一律脱敏个人联系方式。
RULE_DEFINITION: dict[str, Any] = {
    "page_size": 50,
    "max_rows": 50000,
    "contact_masking": True,
    "content_field_keys": [
        "comment",
        "content",
        "description",
        "details",
        "note",
        "payload",
        "summary",
        "technical_summary",
        "title",
    ],
    "patent_asset_markers": ["专利", "patent"],
    "published_states": ["disclosed"],
    "audiences": {
        "internal_audit": {
            "actor_user_id": True,
            "correlation_id": True,
            "payloads": True,
            "metadata": True,
            "exact_vault": True,
            "unpublished_patent_content": "show",
        },
        "legal": {
            "actor_user_id": True,
            "correlation_id": True,
            "payloads": True,
            "metadata": True,
            "exact_vault": False,
            "unpublished_patent_content": "redact",
        },
        "rd_lead": {
            "actor_user_id": False,
            "correlation_id": False,
            "payloads": False,
            "metadata": False,
            "exact_vault": False,
            "unpublished_patent_content": "redact",
        },
    },
}

_PROFILE_KEYS = ("actor_user_id", "correlation_id", "payloads", "metadata", "exact_vault", "unpublished_patent_content")


def rule_definition_digest(definition: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(definition))


def validate_rule_definition(definition: Any) -> None:
    if not isinstance(definition, dict):
        raise ValidationError("规则定义必须是 JSON 对象")
    page_size = definition.get("page_size")
    if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= 500:
        raise ValidationError("规则 page_size 必须是 1 到 500 的整数")
    max_rows = definition.get("max_rows")
    if not isinstance(max_rows, int) or isinstance(max_rows, bool) or not 1 <= max_rows <= 500000:
        raise ValidationError("规则 max_rows 必须是 1 到 500000 的整数")
    audiences = definition.get("audiences")
    if not isinstance(audiences, dict):
        raise ValidationError("规则必须包含 audiences 分级视图定义")
    for audience in AUDIENCES:
        profile = audiences.get(audience)
        if not isinstance(profile, dict):
            raise ValidationError(f"规则缺少角色 {audience} 的分级视图定义")
        for key in _PROFILE_KEYS:
            if key not in profile:
                raise ValidationError(f"角色 {audience} 的分级视图缺少字段 {key}")
        for key in ("actor_user_id", "correlation_id", "payloads", "metadata", "exact_vault"):
            if not isinstance(profile[key], bool):
                raise ValidationError(f"角色 {audience} 的 {key} 必须是布尔值")
        if profile["unpublished_patent_content"] not in ("show", "redact"):
            raise ValidationError(f"角色 {audience} 的 unpublished_patent_content 只能是 show 或 redact")
    for key in ("content_field_keys", "patent_asset_markers", "published_states"):
        value = definition.get(key)
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise ValidationError(f"规则 {key} 必须是非空字符串列表")


def mask_restricted_vaults(value: Any) -> Any:
    """递归脱敏受限库位：非授权视图只能看到替代码，看不到精确位置。"""
    if isinstance(value, dict):
        masked = {key: mask_restricted_vaults(item) for key, item in value.items()}
        sensitivity = masked.get("sensitivity") or masked.get("vault_sensitivity")
        if sensitivity in SENSITIVE_VAULT_LEVELS:
            if "building" in masked:
                masked["building"] = "受限区域"
            for key in ("room", "cabinet", "shelf"):
                if key in masked:
                    masked[key] = "***"
            if "code" in masked and "sensitivity" in value:
                vault_id = masked.get("id")
                masked["code"] = f"MASKED-{vault_id:04d}" if isinstance(vault_id, int) else "***"
            if masked.get("vault_code") is not None and "vault_code" in masked:
                vault_id = masked.get("vault_id")
                masked["vault_code"] = f"MASKED-{vault_id:04d}" if isinstance(vault_id, int) else "***"
        return masked
    if isinstance(value, list):
        return [mask_restricted_vaults(item) for item in value]
    return value


def is_patent_asset(asset_type: Any, markers: list[str]) -> bool:
    if not isinstance(asset_type, str):
        return False
    lowered = asset_type.casefold()
    return any(marker.casefold() in lowered for marker in markers)


def redact_unpublished_patent_content(value: Any, definition: dict[str, Any], *, inherited: bool = False) -> Any:
    """隐匿未公开专利的内容字段，保留可核对的内容摘要占位符。"""
    content_keys = {key.casefold() for key in definition.get("content_field_keys", [])}
    markers = definition.get("patent_asset_markers", [])
    published = set(definition.get("published_states", []))

    def is_unpublished_patent_dict(node: dict[str, Any]) -> bool:
        return is_patent_asset(node.get("asset_type"), markers) and node.get("lifecycle_state") not in published

    def walk(node: Any, flag: bool) -> Any:
        if isinstance(node, dict):
            active = flag or is_unpublished_patent_dict(node)
            result = {}
            for key, item in node.items():
                if active and key.casefold() in content_keys and isinstance(item, str) and item:
                    result[key] = f"<未公开专利内容已隐匿 sha256:{sha256_hex(item)[:12]}>"
                else:
                    result[key] = walk(item, active)
            return result
        if isinstance(node, list):
            return [walk(item, flag) for item in node]
        return node

    return walk(value, inherited)


def sanitize_for_export(value: Any, profile: dict[str, Any], definition: dict[str, Any], *, patent_unpublished: bool = False) -> Any:
    """按分级视图规则清洗单个载荷：脱敏联系方式、受限库位与未公开专利内容。"""
    result = sanitize_payload(value) if definition.get("contact_masking", True) else value
    if not profile.get("exact_vault"):
        result = mask_restricted_vaults(result)
    if profile.get("unpublished_patent_content") == "redact":
        result = redact_unpublished_patent_content(result, definition, inherited=patent_unpublished)
    return result


def grade_event_row(
    event: dict[str, Any],
    *,
    profile: dict[str, Any],
    definition: dict[str, Any],
    project_code: str | None,
    patent_unpublished: bool,
) -> dict[str, Any]:
    """把一条审计事件裁剪为指定角色可见的分级字段视图。"""
    row: dict[str, Any] = {
        "event_id": event["id"],
        "occurred_at": event["created_at"],
        "actor": event["actor_name"],
        "action": event["action"],
        "resource_type": event["resource_type"],
        "resource_id": event["resource_id"],
        "outcome": event["outcome"],
        "project_code": project_code,
    }
    if profile.get("actor_user_id"):
        row["actor_user_id"] = event["actor_user_id"]
    if profile.get("correlation_id") and event.get("correlation_id"):
        row["correlation_id"] = event["correlation_id"]
    if profile.get("payloads"):
        for key in ("before", "after"):
            raw = event.get(f"{key}_json")
            if raw:
                row[key] = sanitize_for_export(json.loads(raw), profile, definition, patent_unpublished=patent_unpublished)
    if profile.get("metadata"):
        metadata = json.loads(event.get("metadata_json") or "{}")
        if metadata:
            row["metadata"] = sanitize_for_export(metadata, profile, definition, patent_unpublished=patent_unpublished)
    return row
