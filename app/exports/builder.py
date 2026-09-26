from __future__ import annotations

import hashlib
import io
import json
import tarfile
from typing import Any

from app.exports.rules import MANIFEST_VERSION, PAGE_SIZE, RULE_VERSION, SECTION_ORDER

GENESIS = "0" * 64


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_hash(record: dict[str, Any]) -> str:
    """单条记录摘要：剔除 hash 字段后对规范化 JSON 取 SHA-256。"""
    body = {key: value for key, value in record.items() if key != "hash"}
    return sha256_hex(canonical_bytes(body))


def chain_step(previous: str, current: str) -> str:
    return sha256_hex(bytes.fromhex(previous) + bytes.fromhex(current))


def build_pages(
    sections: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], str, int]:
    """把各分区记录切成固定大小的页，逐条计算摘要并串成哈希链。

    返回 (页面 to 页列表, 分区汇总, 根哈希, 记录总数)。空分区也推进链，
    防止离线包被整体删掉一个分区后仍自洽。
    """
    pages: list[dict[str, Any]] = []
    summaries: dict[str, dict[str, Any]] = {}
    chain = GENESIS
    total = 0
    page_index = 0
    for section in SECTION_ORDER:
        records = sections.get(section, [])
        start_chain = chain
        count = 0
        for offset in range(0, len(records), PAGE_SIZE):
            chunk = records[offset : offset + PAGE_SIZE]
            page_records = []
            for record in chunk:
                digest = record_hash(record)
                chain = chain_step(chain, digest)
                page_records.append({**record, "hash": digest})
                count += 1
            page_index += 1
            pages.append(
                {
                    "page": page_index,
                    "section": section,
                    "records": page_records,
                }
            )
        summaries[section] = {
            "record_count": count,
            "chain_start": start_chain,
            "chain_end": chain,
        }
        total += count
    return pages, summaries, chain, total


def build_manifest(
    *,
    export_code: str,
    profile: str,
    profile_label: str,
    criteria: dict[str, Any],
    criteria_fingerprint: str,
    snapshot_marks: dict[str, int],
    snapshot_digest: str,
    snapshot_at: str,
    pages: list[dict[str, Any]],
    summaries: dict[str, dict[str, Any]],
    root_hash: str,
    record_count: int,
    generated_by: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    page_entries = []
    for page in pages:
        page_entries.append(
            {
                "page": page["page"],
                "section": page["section"],
                "path": f"pages/page-{page['page']:06d}.json",
                "record_count": len(page["records"]),
                "sha256": sha256_hex(canonical_bytes(page)),
            }
        )
    return {
        "manifest_version": MANIFEST_VERSION,
        "rule_version": RULE_VERSION,
        "export_code": export_code,
        "profile": profile,
        "profile_label": profile_label,
        "criteria": criteria,
        "criteria_fingerprint": criteria_fingerprint,
        "snapshot": {
            "snapshot_at": snapshot_at,
            "watermarks": snapshot_marks,
            "snapshot_digest": snapshot_digest,
        },
        "sections": summaries,
        "pages": page_entries,
        "page_count": len(page_entries),
        "record_count": record_count,
        "root_hash": root_hash,
        "generated_by": generated_by,
        "generated_at": generated_at,
    }


def render_bundle(manifest: dict[str, Any], pages: list[dict[str, Any]]) -> tuple[bytes, dict[str, str]]:
    """把清单与分页渲染成确定性 tar 包，返回 (包字节, 各文件摘要)。"""
    files: dict[str, bytes] = {"manifest.json": canonical_bytes(manifest)}
    for page, entry in zip(pages, manifest["pages"]):
        files[entry["path"]] = canonical_bytes(page)
    digests = {name: sha256_hex(content) for name, content in files.items()}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name in sorted(files):
            content = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue(), digests
