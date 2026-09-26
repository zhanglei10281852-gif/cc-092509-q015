from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from app.database import get_connection
from app.exports.rules import RULE_VERSION
from app.exports.service import AuditExportService


SECRET_ASSET = "未公开专利：隐形涂层配方X-机密"
CONTACT_PHONE = "13800138000"


def _make_role(client, admin, code, permissions):
    response = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": code, "name": code, "permission_codes": permissions},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _make_user(client, admin, username, role_codes, *, phone=CONTACT_PHONE, email="lead@example.com"):
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username,
            "password": "Research!23456",
            "display_name": f"用户-{username}",
            "phone": phone,
            "email": email,
            "role_codes": role_codes,
        },
    )
    assert response.status_code == 201, response.text
    login = client.post(
        "/api/auth/login",
        json={"username": username, "password": "Research!23456", "client_label": "tests"},
    )
    assert login.status_code == 200, login.text
    body = login.json()
    return {"id": body["user"]["id"], "headers": {"Authorization": f"Bearer {body['token']}"}}


def _seed_archive(client, admin, *, project="PATENT-A", restricted=False):
    vault_payload = {
        "code": f"RES-{project}" if restricted else f"NOR-{project}",
        "building": "涉密档案楼" if restricted else "普通档案楼",
        "room": "机密库" if restricted else "常温库",
        "cabinet": "一号柜",
        "shelf": "一层",
        "sensitivity": "restricted" if restricted else "normal",
        "capacity_units": 50,
    }
    vault = client.post("/api/dossiers/vaults", headers=admin["headers"], json=vault_payload).json()
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": f"BATCH-{project}", "project_code": project, "expected_count": 1},
    ).json()
    dossier = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": f"DOS-{project}",
            "intake_id": batch["id"],
            "asset_type": SECRET_ASSET,
            "quantity": 10,
            "unit": "份",
            "vault_id": vault["id"],
        },
    ).json()
    return vault, batch, dossier


def _seed_incident(client, admin, dossier):
    response = client.post(
        "/api/dossiers/incidents",
        headers=admin["headers"],
        json={
            "dossier_id": dossier["id"],
            "incident_type": "违规外发",
            "severity": "high",
            "description": f"调查中发现外发痕迹，经办人电话{CONTACT_PHONE}，内容涉及未公开申请",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _request_export(client, headers, profile, criteria=None):
    response = client.post(
        "/api/audit-exports",
        headers=headers,
        json={"profile": profile, **(criteria or {})},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _run_jobs(client, admin, *, maximum=5):
    results = []
    for _ in range(maximum):
        response = client.post("/api/system/jobs/run-exports", headers=admin["headers"])
        assert response.status_code == 200, response.text
        body = response.json()
        if not body.get("claimed"):
            break
        results.append(body)
    return results


def _extract_tar(content: bytes) -> dict[str, bytes]:
    files = {}
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as tar:
        for member in tar.getmembers():
            if member.isfile():
                files[member.name] = tar.extractfile(member).read()
    return files


def _manifest_and_records(content: bytes):
    files = _extract_tar(content)
    manifest = json.loads(files["manifest.json"].decode())
    records = []
    for entry in manifest["pages"]:
        page = json.loads(files[entry["path"]].decode())
        records.extend(page["records"])
    return manifest, files, records


def _download(client, headers, export_id):
    response = client.get(f"/api/audit-exports/{export_id}/download", headers=headers)
    assert response.status_code == 200, response.text
    return response


def test_graded_views_exclude_restricted_vault_contacts_and_secret_content(client, admin):
    _make_role(client, admin, "role.rlead", ["audit.export.research_lead"])
    _make_role(client, admin, "role.legal", ["audit.export.legal"])
    _make_role(client, admin, "role.iaudit", ["audit.export.internal_audit"])
    lead = _make_user(client, admin, "lead.user", ["role.rlead"])
    legal = _make_user(client, admin, "legal.user", ["role.legal"])
    auditor = _make_user(client, admin, "audit.user", ["role.iaudit"])
    _seed_archive(client, admin, project="PATENT-A", restricted=True)
    dossier = client.get("/api/dossiers", headers=admin["headers"]).json()[0]
    _seed_incident(client, admin, dossier)

    exports = {}
    for profile, requester in (
        ("research_lead", lead),
        ("legal", legal),
        ("internal_audit", auditor),
    ):
        exports[profile] = _request_export(client, requester["headers"], profile)
    _run_jobs(client, admin)

    bundles = {}
    for profile, requester in (
        ("research_lead", lead),
        ("legal", legal),
        ("internal_audit", auditor),
    ):
        export = client.get(f"/api/audit-exports/{exports[profile]['id']}", headers=requester["headers"]).json()
        assert export["status"] == "completed"
        assert export["rule_version"] == RULE_VERSION
        response = _download(client, requester["headers"], export["id"])
        bundles[profile] = response.content

    lead_manifest, _, lead_records = _manifest_and_records(bundles["research_lead"])
    legal_manifest, _, legal_records = _manifest_and_records(bundles["legal"])
    audit_manifest, _, audit_records = _manifest_and_records(bundles["internal_audit"])

    # 分级分区：研发负责人只有档案事件；法务含泄密事件；内审额外含审计事件。
    assert set(lead_manifest["sections"]) == {"dossier_events", "incident_cases", "audit_events"}
    assert lead_manifest["sections"]["incident_cases"]["record_count"] == 0
    assert lead_manifest["sections"]["audit_events"]["record_count"] == 0
    assert legal_manifest["sections"]["incident_cases"]["record_count"] >= 1
    assert audit_manifest["sections"]["audit_events"]["record_count"] >= 1

    # 受限库位：任何角色都拿不到真实库位编码/位置，内审只看到替代码。
    for content in bundles.values():
        assert "RES-PATENT-A".encode() not in content
        assert "机密库".encode() not in content
    assert any(record.get("vault_code", "").startswith("MASKED-") for record in audit_records)
    assert all("vault_code" not in record for record in lead_records)

    # 未公开专利内容（asset_type 原文）不出现在任何导出包。
    for content in bundles.values():
        assert SECRET_ASSET.encode() not in content

    # 个人联系方式不进任何导出包；法务事件描述中的电话被脱敏。
    for content in bundles.values():
        assert CONTACT_PHONE.encode() not in content
        assert b"lead@example.com" not in content
    incident = next(record for record in legal_records if record["record_kind"] == "incident_case")
    assert CONTACT_PHONE not in incident["description"]
    assert "138****8000" in incident["description"]
    assert incident["resolution"] is None


def test_same_criteria_reuses_pending_and_completed_results(client, admin):
    _make_role(client, admin, "role.rlead2", ["audit.export.research_lead"])
    lead = _make_user(client, admin, "lead.reuse", ["role.rlead2"], phone="13900139000", email="r@example.com")
    _seed_archive(client, admin, project="PATENT-B")

    criteria = {"project_codes": ["PATENT-B"], "event_types": ["received"]}
    first = _request_export(client, lead["headers"], "research_lead", criteria)
    second = _request_export(client, lead["headers"], "research_lead", criteria)
    assert second["reused"] is True
    assert second["id"] == first["id"]

    _run_jobs(client, admin)
    completed = client.get(f"/api/audit-exports/{first['id']}", headers=lead["headers"]).json()
    assert completed["status"] == "completed"
    first_digest = completed["file_digest"]

    # 完成后再次同条件提交仍复用，即使库里又新增了档案事件。
    client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": "BATCH-PATENT-B-2", "project_code": "PATENT-B", "expected_count": 1},
    )
    third = _request_export(client, lead["headers"], "research_lead", criteria)
    assert third["reused"] is True
    assert third["file_digest"] == first_digest

    # 完成的任务不允许重试。
    response = client.post(f"/api/audit-exports/{first['id']}/retry", headers=lead["headers"])
    assert response.status_code == 409


def test_snapshot_is_fixed_and_filtered_by_project_and_time(client, admin):
    _seed_archive(client, admin, project="PROJ-X")
    _seed_archive(client, admin, project="PROJ-Y")

    export = _request_export(
        client, admin["headers"], "internal_audit",
        {"project_codes": ["PROJ-X"], "events_from": "2000-01-01T00:00:00+00:00"},
    )
    _run_jobs(client, admin)
    response = _download(client, admin["headers"], export["id"])
    manifest, _, records = _manifest_and_records(response.content)
    dossier_events = [record for record in records if record["record_kind"] == "dossier_event"]
    assert dossier_events
    assert {record["project_code"] for record in dossier_events} == {"PROJ-X"}

    # 清单携带固定快照水位与规则版本。
    assert manifest["rule_version"] == RULE_VERSION
    assert manifest["snapshot"]["snapshot_digest"]
    assert manifest["snapshot"]["watermarks"]["dossier_events"] >= 1


def test_failure_retries_three_times_then_manual_retry_succeeds(client, admin, monkeypatch):
    _seed_archive(client, admin, project="PROJ-R")
    export = _request_export(client, admin["headers"], "research_lead")

    import app.exports.service as service_module

    def boom(*args, **kwargs):
        raise RuntimeError("快照库暂时不可用")

    monkeypatch.setattr(service_module, "fetch_section", boom)
    monkeypatch.setattr(service_module, "RETRY_SECONDS", 0)
    service = AuditExportService(get_connection())
    first = service.run_next("test-worker")
    second = service.run_next("test-worker")
    third = service.run_next("test-worker")
    assert first["status"] == "retry_scheduled"
    assert second["status"] == "retry_scheduled"
    assert third["status"] == "failed"

    failed = client.get(f"/api/audit-exports/{export['id']}", headers=admin["headers"]).json()
    assert failed["status"] == "failed"
    assert failed["error_message"] == "快照库暂时不可用"

    monkeypatch.undo()
    retried = client.post(f"/api/audit-exports/{export['id']}/retry", headers=admin["headers"])
    assert retried.status_code == 200
    _run_jobs(client, admin)
    completed = client.get(f"/api/audit-exports/{export['id']}", headers=admin["headers"]).json()
    assert completed["status"] == "completed"
    # 快照水位在首次失败执行时已冻结，最终结果沿用同一快照。
    assert completed["snapshot_digest"]


def test_http_and_offline_verification_detect_tamper_missing_page_and_mismatch(client, admin, tmp_path):
    _seed_archive(client, admin, project="PROJ-V")
    _seed_archive(client, admin, project="PROJ-W")
    export = _request_export(client, admin["headers"], "internal_audit")
    _run_jobs(client, admin)
    response = _download(client, admin["headers"], export["id"])
    good = response.content
    receipt = client.get(f"/api/audit-exports/{export['id']}/receipt", headers=admin["headers"]).json()
    assert receipt["file_digest"] == response.headers["X-Export-Sha256"]

    # 好包：HTTP 接口（含数据库回执交叉核验）通过。
    verify_ok = client.post(
        "/api/audit-exports/verify-upload",
        headers={**admin["headers"], "Content-Type": "application/octet-stream"},
        content=good,
    )
    assert verify_ok.status_code == 200
    assert verify_ok.json()["ok"] is True

    manifest, files, _ = _manifest_and_records(good)

    # 篡改某一页的记录值并重新打包：必须定位到具体档案事件。
    first_page_path = manifest["pages"][0]["path"]
    page = json.loads(files[first_page_path].decode())
    original_event = page["records"][0]["event_id"]
    page["records"][0]["to_state"] = "tampered-state"
    files[first_page_path] = json.dumps(page, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    tampered = _repack(files)
    report = client.post(
        "/api/audit-exports/verify-upload",
        headers={**admin["headers"], "Content-Type": "application/octet-stream"},
        content=tampered,
    ).json()
    assert report["ok"] is False
    codes = {issue["code"] for issue in report["issues"]}
    assert "RECORD_DIGEST_MISMATCH" in codes
    assert "ROOT_HASH_MISMATCH" in codes
    located = next(issue for issue in report["issues"] if issue["code"] == "RECORD_DIGEST_MISMATCH")
    assert located["event_ref"]["event_id"] == original_event

    # 缺页：删除清单声明的页文件。
    missing_files = dict(files)
    missing_files.pop(first_page_path, None)
    missing = _repack(missing_files)
    report = client.post(
        "/api/audit-exports/verify-upload",
        headers={**admin["headers"], "Content-Type": "application/octet-stream"},
        content=missing,
    ).json()
    assert "PAGE_MISSING" in {issue["code"] for issue in report["issues"]}

    # 整包摘要不一致：用旧回执核对被改过的包。
    from app.exports.verification import verify_bundle

    report_local = verify_bundle(tampered, receipt=receipt).to_dict()
    assert report_local["ok"] is False
    assert "RECEIPT_MISMATCH" in {issue["code"] for issue in report_local["issues"]}

    # 离线命令：好包退出码 0，篡改包退出码 1（全程不连接数据库）。
    good_path = tmp_path / "good.tar"
    bad_path = tmp_path / "bad.tar"
    good_path.write_bytes(good)
    bad_path.write_bytes(tampered)
    env = {"PATH": "/usr/bin:/bin", "ARCHIVE_DATABASE_PATH": str(tmp_path / "offline-unused.db")}
    ok_run = subprocess.run(
        [sys.executable, "-m", "app.cli", "verify-export", str(good_path)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        env={**_clean_env(), **env},
    )
    bad_run = subprocess.run(
        [sys.executable, "-m", "app.cli", "verify-export", str(bad_path)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        env={**_clean_env(), **env},
    )
    assert ok_run.returncode == 0, ok_run.stderr
    assert json.loads(ok_run.stdout)["ok"] is True
    assert bad_run.returncode == 1
    assert not json.loads(bad_run.stdout)["ok"]


def test_permissions_and_ownership_are_enforced(client, admin):
    _make_role(client, admin, "role.rlead3", ["audit.export.research_lead"])
    lead = _make_user(client, admin, "lead.owned", ["role.rlead3"], phone="13700137000", email="o@example.com")
    _make_role(client, admin, "role.plain", ["dossiers.read"])
    other = _make_user(client, admin, "plain.user", ["role.plain"], phone="13600136000", email="p@example.com")
    _seed_archive(client, admin, project="PROJ-P")

    # 无导出权限不能申请。
    denied = client.post(
        "/api/audit-exports", headers=other["headers"], json={"profile": "research_lead"}
    )
    assert denied.status_code == 403

    # 仅有研发负责人视图权限不能申请内审/法务视图。
    wrong_profile = client.post(
        "/api/audit-exports", headers=lead["headers"], json={"profile": "internal_audit"}
    )
    assert wrong_profile.status_code == 403

    export = _request_export(client, lead["headers"], "research_lead")
    _run_jobs(client, admin)

    # 仅有角色视图权限的账号可以列出并查看自己的导出。
    mine = client.get("/api/audit-exports", headers=lead["headers"])
    assert mine.status_code == 200
    assert [item["id"] for item in mine.json()["data"]] == [export["id"]]

    # 他人不能查看、下载、核验该导出。
    for suffix in ("", "/download", "/verify", "/receipt"):
        response = client.get(f"/api/audit-exports/{export['id']}{suffix}", headers=other["headers"])
        assert response.status_code == 403, suffix


def test_invalid_criteria_rejected(client, admin):
    response = client.post(
        "/api/audit-exports",
        headers=admin["headers"],
        json={"profile": "research_lead", "event_types": ["not-a-real-event"]},
    )
    assert response.status_code == 422
    response = client.post(
        "/api/audit-exports",
        headers=admin["headers"],
        json={"profile": "research_lead", "events_from": "2026-09-10T00:00:00+00:00",
              "events_to": "2026-09-01T00:00:00+00:00"},
    )
    assert response.status_code == 422


def _repack(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name in sorted(files):
            info = tarfile.TarInfo(name)
            info.size = len(files[name])
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(files[name]))
    return buffer.getvalue()


def _clean_env() -> dict[str, str]:
    import os

    keep = ("HOME", "LANG", "LC_ALL", "PYTHONPATH", "VIRTUAL_ENV", "PATH")
    return {key: value for key, value in os.environ.items() if key in keep}


@pytest.fixture(autouse=True)
def _isolate_export_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCHIVE_EXPORT_DIR", str(tmp_path / "exports"))
    yield
