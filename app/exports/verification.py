from __future__ import annotations

import io
import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.exports.builder import GENESIS, canonical_bytes, chain_step, record_hash, sha256_hex
from app.exports.rules import SECTION_ORDER


@dataclass(slots=True)
class VerifyIssue:
    code: str
    message: str
    path: str | None = None
    record_id: str | None = None
    event_ref: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.path is not None:
            result["path"] = self.path
        if self.record_id is not None:
            result["record_id"] = self.record_id
        if self.event_ref:
            result["event_ref"] = self.event_ref
        return result


@dataclass(slots=True)
class VerifyReport:
    ok: bool = True
    issues: list[VerifyIssue] = field(default_factory=list)
    checked_files: int = 0
    checked_records: int = 0
    export_code: str | None = None
    rule_version: str | None = None
    root_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok and not self.issues,
            "export_code": self.export_code,
            "rule_version": self.rule_version,
            "root_hash": self.root_hash,
            "checked_files": self.checked_files,
            "checked_records": self.checked_records,
            "issues": [issue.as_dict() for issue in self.issues],
        }


def _event_ref(record: dict[str, Any]) -> dict[str, Any]:
    ref: dict[str, Any] = {}
    for key in ("record_id", "record_kind", "event_id", "case_id", "audit_event_id", "dossier_code", "occurred_at"):
        if key in record:
            ref[key] = record[key]
    return ref


def _load_bundle(source: bytes | Path) -> tuple[dict[str, bytes], bytes | None]:
    """读取导出包：支持 tar 包字节、tar 文件路径或已解包目录。

    返回 (文件名到内容的映射, 原始包字节)；目录形式没有可信的原始字节，
    此时跳过整包摘要比对。
    """
    if isinstance(source, Path):
        if source.is_dir():
            files: dict[str, bytes] = {}
            for item in sorted(source.rglob("*")):
                if item.is_file():
                    files[item.relative_to(source).as_posix()] = item.read_bytes()
            return files, None
        source = source.read_bytes()
    files = {}
    with tarfile.open(fileobj=io.BytesIO(source), mode="r:*") as tar:
        for member in tar.getmembers():
            if member.isfile():
                extracted = tar.extractfile(member)
                if extracted is not None:
                    files[member.name.lstrip("./")] = extracted.read()
    return files, source


def verify_bundle(source: bytes | Path, *, receipt: dict[str, Any] | None = None) -> VerifyReport:
    """离线核验导出包。

    覆盖三类问题并定位到事件：
    - 篡改：文件/页/记录摘要不一致，定位到具体记录；
    - 缺页：清单声明的页缺失、页码不连续或整分区被删除；
    - 摘要不一致：整包摘要、根哈希与可信回执（或数据库登记值）不符。
    """
    report = VerifyReport()
    try:
        files, raw_bundle = _load_bundle(source)
    except (tarfile.TarError, OSError, ValueError) as exc:
        report.issues.append(VerifyIssue("BUNDLE_UNREADABLE", f"导出包无法读取：{exc}"))
        return report

    manifest_raw = files.get("manifest.json")
    if manifest_raw is None:
        report.issues.append(VerifyIssue("MANIFEST_MISSING", "导出包缺少 manifest.json"))
        return report
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        report.issues.append(VerifyIssue("MANIFEST_CORRUPT", f"manifest.json 无法解析：{exc}", path="manifest.json"))
        return report
    report.export_code = manifest.get("export_code")
    report.rule_version = manifest.get("rule_version")
    report.root_hash = manifest.get("root_hash")
    report.checked_files = len(files)

    # 1. 清单自描述完整性：页码必须连续且与 page_count 一致。
    page_entries = manifest.get("pages") or []
    expected_indices = list(range(1, len(page_entries) + 1))
    actual_indices = [entry.get("page") for entry in page_entries]
    if actual_indices != expected_indices:
        report.issues.append(
            VerifyIssue("PAGE_SEQUENCE_BROKEN", f"清单页码不连续：{actual_indices}", path="manifest.json")
        )
    if manifest.get("page_count") != len(page_entries):
        report.issues.append(
            VerifyIssue(
                "PAGE_COUNT_MISMATCH",
                f"清单 page_count={manifest.get('page_count')} 与页条目数 {len(page_entries)} 不一致",
                path="manifest.json",
            )
        )

    # 2. 逐页核验：缺页、页摘要、记录摘要与哈希链。
    chain = GENESIS
    total_records = 0
    section_counts: dict[str, int] = {section: 0 for section in SECTION_ORDER}
    declared_paths = {entry.get("path") for entry in page_entries}
    for entry in page_entries:
        path = entry.get("path")
        content = files.get(path) if path else None
        if content is None:
            report.issues.append(
                VerifyIssue("PAGE_MISSING", f"清单声明的页文件缺失：{path}", path=path)
            )
            continue
        digest = sha256_hex(content)
        if digest != entry.get("sha256"):
            report.issues.append(
                VerifyIssue(
                    "PAGE_DIGEST_MISMATCH",
                    f"页文件摘要 {digest} 与清单声明 {entry.get('sha256')} 不一致",
                    path=path,
                )
            )
        try:
            page = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            report.issues.append(VerifyIssue("PAGE_CORRUPT", f"页文件无法解析：{exc}", path=path))
            continue
        records = page.get("records") or []
        if page.get("page") != entry.get("page") or page.get("section") != entry.get("section"):
            report.issues.append(
                VerifyIssue("PAGE_HEADER_MISMATCH", "页头与清单声明不一致", path=path)
            )
        if len(records) != entry.get("record_count"):
            report.issues.append(
                VerifyIssue(
                    "PAGE_RECORD_COUNT_MISMATCH",
                    f"页内记录数 {len(records)} 与清单声明 {entry.get('record_count')} 不一致",
                    path=path,
                )
            )
        for record in records:
            total_records += 1
            section = page.get("section")
            if section in section_counts:
                section_counts[section] += 1
            declared = record.get("hash")
            actual = record_hash(record)
            if declared != actual:
                report.issues.append(
                    VerifyIssue(
                        "RECORD_DIGEST_MISMATCH",
                        f"记录摘要被篡改：声明 {declared}，实算 {actual}",
                        path=path,
                        record_id=str(record.get("record_id")),
                        event_ref=_event_ref(record),
                    )
                )
            chain = chain_step(chain, actual)

    # 3. 未在清单中声明的多余文件（防止夹带）。
    for name in sorted(files):
        if name != "manifest.json" and name not in declared_paths:
            report.issues.append(VerifyIssue("UNDECLARED_FILE", f"导出包包含清单未声明的文件：{name}", path=name))

    # 4. 记录总数与分区计数核对（整分区被删也能发现）。
    report.checked_records = total_records
    if manifest.get("record_count") != total_records:
        report.issues.append(
            VerifyIssue(
                "RECORD_COUNT_MISMATCH",
                f"记录总数 {total_records} 与清单声明 {manifest.get('record_count')} 不一致",
                path="manifest.json",
            )
        )
    sections = manifest.get("sections") or {}
    for section in SECTION_ORDER:
        summary = sections.get(section)
        if summary is None:
            report.issues.append(
                VerifyIssue("SECTION_MISSING", f"清单缺少分区 {section} 的汇总", path="manifest.json")
            )
            continue
        if summary.get("record_count") != section_counts[section]:
            report.issues.append(
                VerifyIssue(
                    "SECTION_COUNT_MISMATCH",
                    f"分区 {section} 记录数 {section_counts[section]} 与清单声明 {summary.get('record_count')} 不一致",
                    path="manifest.json",
                )
            )

    # 5. 根哈希：覆盖全部记录顺序与内容。
    if manifest.get("root_hash") != chain:
        report.issues.append(
            VerifyIssue(
                "ROOT_HASH_MISMATCH",
                f"根哈希重算为 {chain}，与清单声明 {manifest.get('root_hash')} 不一致",
                path="manifest.json",
            )
        )

    # 6. 可信回执（来自数据库或下载响应头）交叉核验。
    if receipt:
        _cross_check_receipt(report, manifest, raw_bundle, receipt)

    report.ok = not report.issues
    return report


def _cross_check_receipt(
    report: VerifyReport, manifest: dict[str, Any], raw_bundle: bytes | None, receipt: dict[str, Any]
) -> None:
    comparisons = [
        ("root_hash", manifest.get("root_hash"), receipt.get("root_hash")),
        ("record_count", manifest.get("record_count"), receipt.get("record_count")),
        ("page_count", manifest.get("page_count"), receipt.get("page_count")),
        ("rule_version", manifest.get("rule_version"), receipt.get("rule_version")),
        ("snapshot_digest", (manifest.get("snapshot") or {}).get("snapshot_digest"), receipt.get("snapshot_digest")),
    ]
    if receipt.get("file_digest") is not None:
        actual_file_digest = sha256_hex(raw_bundle) if raw_bundle is not None else None
        if actual_file_digest is not None:
            comparisons.append(("file_digest", actual_file_digest, receipt.get("file_digest")))
        # 目录解包形式没有原始字节，整包摘要无法重算，跳过而不是误报。
    for name, actual, expected in comparisons:
        if expected is None:
            continue
        if actual != expected:
            report.issues.append(
                VerifyIssue(
                    "RECEIPT_MISMATCH",
                    f"{name} 与可信回执不一致：包内 {actual}，回执 {expected}",
                    path="manifest.json",
                )
            )
