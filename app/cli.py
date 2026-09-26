from __future__ import annotations

import argparse
import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.database import database_path, get_connection, init_db


def command_init() -> None:
    init_db()
    print(json.dumps({"database": str(database_path()), "initialized": True}, ensure_ascii=False))


def command_check() -> None:
    init_db()
    connection = get_connection()
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    print(json.dumps({"integrity": integrity, "foreign_keys": foreign_keys, "journal_mode": journal_mode}, ensure_ascii=False))
    if integrity != "ok" or foreign_keys != 1:
        raise SystemExit(1)


def command_smoke() -> None:
    from app.main import app

    with TestClient(app) as client:
        root = client.get("/")
        health = client.get("/api/system/health")
        print(json.dumps({"root": root.status_code, "health": health.status_code, "service": root.json().get("service")}, ensure_ascii=False))
        if root.status_code != 200 or health.status_code != 200:
            raise SystemExit(1)


def command_verify_export(path: str, expect_digest: str | None = None) -> None:
    """离线校验审计导出文件：重算行、页与文件摘要，定位篡改或缺页。"""
    from app.core.export_document import verify_document

    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "error": f"无法读取导出文件：{exc}"}, ensure_ascii=False))
        raise SystemExit(2)
    issues = verify_document(document)
    manifest = document.get("manifest") if isinstance(document, dict) else None
    manifest = manifest if isinstance(manifest, dict) else {}
    if expect_digest and manifest.get("file_digest") != expect_digest:
        issues.append(
            {
                "kind": "file_digest_mismatch",
                "page": None,
                "event_id": None,
                "expected": expect_digest,
                "actual": manifest.get("file_digest"),
                "message": "文件摘要与预期摘要不一致",
            }
        )
    print(
        json.dumps(
            {
                "valid": not issues,
                "export_code": manifest.get("export_code"),
                "audience": manifest.get("audience"),
                "rule_version": manifest.get("rule_version"),
                "file_digest": manifest.get("file_digest"),
                "issue_count": len(issues),
                "issues": issues,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if issues:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="知识产权档案服务维护命令")
    parser.add_argument("command", choices=("init-db", "check-db", "smoke", "verify-export"))
    parser.add_argument("path", nargs="?", help="verify-export 待校验的导出文件路径")
    parser.add_argument("--expect-digest", default=None, help="期望的文件摘要，用于与服务端登记值比对")
    args = parser.parse_args()
    if args.command == "verify-export":
        if not args.path:
            parser.error("verify-export 需要提供导出文件路径")
        command_verify_export(args.path, expect_digest=args.expect_digest)
        return
    {"init-db": command_init, "check-db": command_check, "smoke": command_smoke}[args.command]()


if __name__ == "__main__":
    main()
