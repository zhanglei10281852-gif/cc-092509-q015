from __future__ import annotations

import argparse
import json
import sqlite3
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


def command_verify_export(args: argparse.Namespace) -> None:
    """离线核验导出包：篡改、缺页、摘要不一致都会定位到具体记录。"""
    from app.exports.verification import verify_bundle

    receipt = None
    if args.receipt:
        receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    report = verify_bundle(Path(args.path), receipt=receipt)
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    if not report.to_dict()["ok"]:
        raise SystemExit(1)


def command_run_export_jobs(args: argparse.Namespace) -> None:
    """以前台工作进程方式领取并执行审计导出任务。"""
    from app.exports.service import WORKER_NAME, AuditExportService

    init_db()
    worker = args.worker or WORKER_NAME
    processed = 0
    while True:
        service = AuditExportService(get_connection())
        result = service.run_next(worker)
        if result is None:
            break
        processed += 1
        print(json.dumps(result, ensure_ascii=False, default=str))
        if args.once:
            break
    print(json.dumps({"processed": processed, "worker": worker}, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="知识产权档案服务维护命令")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    sub.add_parser("check-db")
    sub.add_parser("smoke")
    verify = sub.add_parser("verify-export", help="离线核验审计导出包")
    verify.add_argument("path", help="导出包 .tar 路径或解包目录")
    verify.add_argument("--receipt", help="可信回执 JSON 路径（来自 /receipt 接口）", default=None)
    runner = sub.add_parser("run-export-jobs", help="领取并执行审计导出任务")
    runner.add_argument("--worker", default=None, help="执行者标识（默认 audit-export-worker）")
    runner.add_argument("--once", action="store_true", help="只执行一个任务")
    args = parser.parse_args()
    handlers = {
        "init-db": lambda: command_init(),
        "check-db": lambda: command_check(),
        "smoke": lambda: command_smoke(),
        "verify-export": lambda: command_verify_export(args),
        "run-export-jobs": lambda: command_run_export_jobs(args),
    }
    handlers[args.command]()


if __name__ == "__main__":
    main()
