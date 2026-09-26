from __future__ import annotations

import hashlib
import json
from typing import Any

DOCUMENT_FORMAT = "audit-export/v1"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def row_digest(row: dict[str, Any]) -> str:
    """单行摘要：覆盖除 row_digest 自身之外的全部字段。"""
    return sha256_hex(canonical_json({key: value for key, value in row.items() if key != "row_digest"}))


def page_digest(page_number: int, row_digests: list[str]) -> str:
    """页摘要：提交到该页有序的行摘要列表，缺页或调序都会改变结果。"""
    return sha256_hex(canonical_json({"page": page_number, "row_digests": row_digests}))


def manifest_digest(manifest: dict[str, Any]) -> str:
    """文件摘要：覆盖清单中除 file_digest 自身之外的全部字段。"""
    return sha256_hex(canonical_json({key: value for key, value in manifest.items() if key != "file_digest"}))


def build_document(
    *,
    export_code: str,
    audience: str,
    rule_version: str,
    rule_digest: str,
    filters: dict[str, Any],
    snapshot: dict[str, Any],
    rows: list[dict[str, Any]],
    page_size: int,
    generated_at: str,
    generated_by: str,
) -> tuple[dict[str, Any], str]:
    """把分级后的快照行渲染为自带清单的导出文档，返回 (文档对象, 规范化文本)。"""
    pages: list[dict[str, Any]] = []
    manifest_pages: list[dict[str, Any]] = []
    for index in range(0, len(rows), page_size):
        chunk = rows[index : index + page_size]
        number = len(pages) + 1
        digests = [str(item["row_digest"]) for item in chunk]
        pages.append({"page": number, "rows": chunk})
        manifest_pages.append(
            {
                "page": number,
                "row_count": len(chunk),
                "first_event_id": chunk[0].get("event_id"),
                "last_event_id": chunk[-1].get("event_id"),
                "digest": page_digest(number, digests),
            }
        )
    manifest: dict[str, Any] = {
        "format": DOCUMENT_FORMAT,
        "export_code": export_code,
        "audience": audience,
        "rule_version": rule_version,
        "rule_digest": rule_digest,
        "filters": filters,
        "snapshot": snapshot,
        "page_size": page_size,
        "page_count": len(pages),
        "row_count": len(rows),
        "pages": manifest_pages,
        "generated_at": generated_at,
        "generated_by": generated_by,
    }
    manifest["file_digest"] = manifest_digest(manifest)
    document = {"manifest": manifest, "pages": pages}
    return document, canonical_json(document)


def verify_document(document: Any) -> list[dict[str, Any]]:
    """离线校验导出文档，返回问题列表；每个问题尽量定位到页与事件。"""
    issues: list[dict[str, Any]] = []

    def report(kind: str, message: str, *, page: Any = None, event_id: Any = None, expected: Any = None, actual: Any = None) -> None:
        issues.append(
            {
                "kind": kind,
                "page": page,
                "event_id": event_id,
                "expected": expected,
                "actual": actual,
                "message": message,
            }
        )

    if not isinstance(document, dict):
        report("structure_invalid", "导出文件必须是 JSON 对象")
        return issues
    manifest = document.get("manifest")
    pages = document.get("pages")
    if not isinstance(manifest, dict):
        report("structure_invalid", "导出文件缺少 manifest 清单")
        return issues
    if not isinstance(pages, list):
        report("structure_invalid", "导出文件缺少 pages 分页数据", page=None)
        return issues
    if manifest.get("format") != DOCUMENT_FORMAT:
        report("format_mismatch", "导出文件格式版本不受支持", expected=DOCUMENT_FORMAT, actual=manifest.get("format"))

    declared_pages = [entry for entry in (manifest.get("pages") or []) if isinstance(entry, dict)]
    declared_by_number = {entry.get("page"): entry for entry in declared_pages}
    if manifest.get("page_count") != len(declared_pages):
        report(
            "page_count_mismatch",
            "清单登记的页数与分页目录不一致",
            expected=manifest.get("page_count"),
            actual=len(declared_pages),
        )

    seen_numbers: list[Any] = []
    total_rows = 0
    for entry in pages:
        if not isinstance(entry, dict):
            report("structure_invalid", "分页条目必须是 JSON 对象")
            continue
        number = entry.get("page")
        rows = entry.get("rows")
        if not isinstance(rows, list):
            report("structure_invalid", "分页缺少 rows 数据", page=number)
            continue
        seen_numbers.append(number)
        declared = declared_by_number.get(number)
        if declared is None:
            report("unexpected_page", f"第 {number} 页未在清单中登记", page=number)
            continue
        stored_digests: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                report("structure_invalid", "数据行必须是 JSON 对象", page=number)
                continue
            stored = row.get("row_digest")
            stored_digests.append(stored)
            actual = row_digest(row)
            if stored != actual:
                report(
                    "row_digest_mismatch",
                    "数据行内容被篡改",
                    page=number,
                    event_id=row.get("event_id"),
                    expected=stored,
                    actual=actual,
                )
        total_rows += len(rows)
        if len(rows) != declared.get("row_count"):
            report(
                "page_row_count_mismatch",
                "分页行数与清单登记不一致",
                page=number,
                expected=declared.get("row_count"),
                actual=len(rows),
            )
        actual_page_digest = page_digest(number, stored_digests)
        if actual_page_digest != declared.get("digest"):
            report(
                "page_digest_mismatch",
                "分页摘要与清单登记不一致",
                page=number,
                expected=declared.get("digest"),
                actual=actual_page_digest,
            )
        if rows and isinstance(rows[0], dict) and isinstance(rows[-1], dict):
            if declared.get("first_event_id") != rows[0].get("event_id") or declared.get("last_event_id") != rows[-1].get("event_id"):
                report(
                    "page_boundary_mismatch",
                    "分页首尾事件与清单登记不一致",
                    page=number,
                    expected={"first_event_id": declared.get("first_event_id"), "last_event_id": declared.get("last_event_id")},
                    actual={"first_event_id": rows[0].get("event_id"), "last_event_id": rows[-1].get("event_id")},
                )

    for number, declared in declared_by_number.items():
        if number not in seen_numbers:
            report("missing_page", f"第 {number} 页缺失", page=number, expected=declared.get("digest"))
    if manifest.get("row_count") != total_rows:
        report(
            "row_count_mismatch",
            "总行数与清单登记不一致",
            expected=manifest.get("row_count"),
            actual=total_rows,
        )

    stored_file_digest = manifest.get("file_digest")
    actual_file_digest = manifest_digest(manifest)
    if stored_file_digest != actual_file_digest:
        report(
            "file_digest_mismatch",
            "文件摘要与清单内容不一致",
            expected=stored_file_digest,
            actual=actual_file_digest,
        )
    return issues
