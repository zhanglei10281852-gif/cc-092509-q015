from __future__ import annotations

import copy
import hashlib
import json

import pytest

from app.core.export_document import verify_document
from app.core.export_rules import RULE_DEFINITION


def _setup_archives(client, admin):
    vault = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": "SEC-01",
            "building": "保密楼",
            "room": "地下一层",
            "cabinet": "甲柜",
            "shelf": "三层",
            "sensitivity": "restricted",
            "capacity_units": 20,
        },
    ).json()
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": "EXP-B1", "project_code": "PRJ-X", "expected_count": 2},
    ).json()
    patent = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": "PAT-001",
            "intake_id": batch["id"],
            "asset_type": "专利交底书",
            "quantity": 5,
            "unit": "份",
            "vault_id": vault["id"],
        },
    ).json()
    document = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": "DOC-001",
            "intake_id": batch["id"],
            "asset_type": "工艺技术文档",
            "quantity": 3,
            "unit": "册",
            "vault_id": vault["id"],
        },
    ).json()
    other_batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": "EXP-B2", "project_code": "PRJ-Y", "expected_count": 1},
    ).json()
    client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": "DOC-101",
            "intake_id": other_batch["id"],
            "asset_type": "实验记录",
            "quantity": 1,
            "unit": "册",
        },
    )
    return vault, batch, patent, document


def _craft_patent_event(dossier_id, lifecycle_state="available"):
    from app.database import transaction
    from app.services.audit import AuditContext, AuditService

    with transaction(immediate=True) as connection:
        AuditService(connection).record(
            AuditContext(None, "保密办专员"),
            action="dossier.annotate",
            resource_type="dossier",
            resource_id=dossier_id,
            after={
                "dossier_code": "PAT-001",
                "asset_type": "专利交底书",
                "lifecycle_state": lifecycle_state,
                "technical_summary": "一种耐高温合金配方",
                "note": "联系人 13812345678，邮箱 zhangsan@example.com",
            },
            metadata={"phone": "13911112222", "email": "lisi@example.com"},
        )


def _create_export(client, admin, **payload):
    response = client.post("/api/audit-exports", headers=admin["headers"], json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _complete_export(client, admin, task_id):
    response = client.post(f"/api/audit-exports/{task_id}/claim", headers=admin["headers"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "completed", body
    return body


def _download(client, admin, task_id):
    response = client.get(f"/api/audit-exports/{task_id}/download", headers=admin["headers"])
    assert response.status_code == 200, response.text
    return response


def _rows(document):
    return [row for page in document["pages"] for row in page["rows"]]


def _find_row(document, action, resource_id=None):
    for row in _rows(document):
        if row["action"] == action and (resource_id is None or str(row["resource_id"]) == str(resource_id)):
            return row
    return None


def test_export_create_deduplicates(client, admin):
    _setup_archives(client, admin)
    first = _create_export(client, admin, audience="legal", project_code="PRJ-X")
    assert first["reused"] is False
    task = first["task"]
    assert task["status"] == "pending"
    assert task["rule_version"] == "audit-export-rules/v1"
    assert task["filters"]["project_code"] == "PRJ-X"

    again = _create_export(client, admin, audience="legal", project_code="PRJ-X")
    assert again["reused"] is True
    assert again["task"]["id"] == task["id"]

    other = _create_export(client, admin, audience="rd_lead", project_code="PRJ-X")
    assert other["reused"] is False
    assert other["task"]["id"] != task["id"]

    _complete_export(client, admin, task["id"])
    third = _create_export(client, admin, audience="legal", project_code="PRJ-X")
    assert third["reused"] is True
    assert third["task"]["status"] == "completed"

    listed = client.get("/api/audit-exports", headers=admin["headers"], params={"status": "completed"})
    assert listed.status_code == 200
    assert all(item["status"] == "completed" for item in listed.json())
    assert any(item["id"] == task["id"] for item in listed.json())


def test_claim_download_and_verify(client, admin):
    _setup_archives(client, admin)
    task = _create_export(client, admin, audience="internal_audit")["task"]

    early = client.get(f"/api/audit-exports/{task['id']}/download", headers=admin["headers"])
    assert early.status_code == 409

    completed = _complete_export(client, admin, task["id"])
    assert completed["row_count"] > 0
    assert completed["file_digest"]
    assert completed["has_document"] is True

    detail = client.get(f"/api/audit-exports/{task['id']}", headers=admin["headers"]).json()
    assert detail["snapshot"]["row_count"] == completed["row_count"]
    assert detail["snapshot"]["source_max_event_id"] > 0

    response = _download(client, admin, task["id"])
    assert response.headers["X-Export-Sha256"] == detail["document_sha256"]
    assert response.headers["X-Export-Digest"] == detail["file_digest"]
    assert hashlib.sha256(response.content).hexdigest() == detail["document_sha256"]

    document = response.json()
    manifest = document["manifest"]
    assert manifest["file_digest"] == detail["file_digest"]
    assert manifest["rule_version"] == "audit-export-rules/v1"
    assert manifest["snapshot"]["row_count"] == manifest["row_count"]
    assert verify_document(document) == []

    ok = client.post(
        f"/api/audit-exports/{task['id']}/verify-download",
        headers=admin["headers"],
        json={"document_sha256": detail["document_sha256"]},
    )
    assert ok.status_code == 200
    assert ok.json()["match"] is True
    bad = client.post(
        f"/api/audit-exports/{task['id']}/verify-download",
        headers=admin["headers"],
        json={"document_sha256": "0" * 64},
    )
    assert bad.json()["match"] is False

    verified = client.post("/api/audit-exports/verify", headers=admin["headers"], json=document)
    assert verified.status_code == 200
    body = verified.json()
    assert body["valid"] is True
    assert body["issues"] == []
    assert body["server_record"]["found"] is True
    assert body["server_record"]["file_digest_match"] is True


def test_graded_views_by_audience(client, admin):
    vault, _, patent, _ = _setup_archives(client, admin)
    _craft_patent_event(patent["id"])
    documents = {}
    for audience in ("internal_audit", "legal", "rd_lead"):
        task = _create_export(client, admin, audience=audience)["task"]
        _complete_export(client, admin, task["id"])
        documents[audience] = _download(client, admin, task["id"]).json()

    # 内审：精确库位与完整载荷可见，个人联系方式仍脱敏
    audit_vault = _find_row(documents["internal_audit"], "vault.create")
    assert audit_vault["after"]["building"] == "保密楼"
    assert audit_vault["after"]["code"] == "SEC-01"
    audit_note = _find_row(documents["internal_audit"], "dossier.annotate", patent["id"])
    assert audit_note["after"]["technical_summary"] == "一种耐高温合金配方"
    assert "138****5678" in audit_note["after"]["note"]
    assert "13812345678" not in audit_note["after"]["note"]
    assert audit_note["metadata"]["phone"] == "139****2222"
    audit_register = _find_row(documents["internal_audit"], "dossier.register", patent["id"])
    assert audit_register["after"]["vault_code"] == "SEC-01"

    # 法务：载荷可见，但受限库位与未公开专利内容被隐匿
    legal_vault = _find_row(documents["legal"], "vault.create")
    assert legal_vault["after"]["building"] == "受限区域"
    assert legal_vault["after"]["room"] == "***"
    assert legal_vault["after"]["code"].startswith("MASKED-")
    legal_note = _find_row(documents["legal"], "dossier.annotate", patent["id"])
    assert legal_note["after"]["technical_summary"].startswith("<未公开专利内容已隐匿")
    assert legal_note["after"]["note"].startswith("<未公开专利内容已隐匿")
    assert legal_note["metadata"]["phone"] == "139****2222"
    legal_register = _find_row(documents["legal"], "dossier.register", patent["id"])
    assert legal_register["after"]["vault_code"] == f"MASKED-{vault['id']:04d}"

    # 研发负责人：仅事件级摘要，无载荷与联系方式
    rd_note = _find_row(documents["rd_lead"], "dossier.annotate", patent["id"])
    assert rd_note is not None
    assert "before" not in rd_note
    assert "after" not in rd_note
    assert "metadata" not in rd_note
    assert "actor_user_id" not in rd_note
    assert rd_note["project_code"] == "PRJ-X"
    rd_vault = _find_row(documents["rd_lead"], "vault.create")
    assert "after" not in rd_vault


def test_published_patent_content_not_redacted(client, admin):
    _, _, patent, _ = _setup_archives(client, admin)
    disclosed = client.post(
        f"/api/dossiers/{patent['id']}/disclosures",
        headers=admin["headers"],
        json={"recipient_code": "PARTNER-1", "quantity": 5, "idempotency_key": "disc-0001"},
    )
    assert disclosed.status_code == 201, disclosed.text
    assert disclosed.json()["dossier"]["lifecycle_state"] == "disclosed"
    _craft_patent_event(patent["id"], lifecycle_state="disclosed")

    task = _create_export(client, admin, audience="legal", actions=["dossier.annotate"])["task"]
    _complete_export(client, admin, task["id"])
    document = _download(client, admin, task["id"]).json()
    row = _find_row(document, "dossier.annotate", patent["id"])
    assert row["after"]["technical_summary"] == "一种耐高温合金配方"
    assert "138****5678" in row["after"]["note"]


def test_filters_by_project_action_and_time(client, admin):
    _setup_archives(client, admin)

    by_project = _create_export(client, admin, audience="internal_audit", project_code="PRJ-X")["task"]
    _complete_export(client, admin, by_project["id"])
    rows = _rows(_download(client, admin, by_project["id"]).json())
    assert rows
    assert all(row["project_code"] == "PRJ-X" for row in rows)

    by_action = _create_export(client, admin, audience="internal_audit", actions=["dossier.register"])["task"]
    _complete_export(client, admin, by_action["id"])
    rows = _rows(_download(client, admin, by_action["id"]).json())
    assert rows
    assert all(row["action"] == "dossier.register" for row in rows)

    future = _create_export(client, admin, audience="internal_audit", occurred_from="2999-01-01T00:00:00+00:00")["task"]
    _complete_export(client, admin, future["id"])
    document = _download(client, admin, future["id"]).json()
    assert document["manifest"]["row_count"] == 0
    assert document["pages"] == []
    assert verify_document(document) == []

    unknown_project = _create_export(client, admin, audience="internal_audit", project_code="PRJ-NONE")["task"]
    _complete_export(client, admin, unknown_project["id"])
    document = _download(client, admin, unknown_project["id"]).json()
    assert document["manifest"]["row_count"] == 0
    assert verify_document(document) == []


def test_invalid_filters_rejected(client, admin):
    bad_time = client.post(
        "/api/audit-exports", headers=admin["headers"], json={"audience": "legal", "occurred_from": "not-a-time"}
    )
    assert bad_time.status_code == 422
    inverted = client.post(
        "/api/audit-exports",
        headers=admin["headers"],
        json={
            "audience": "legal",
            "occurred_from": "2026-09-02T00:00:00+00:00",
            "occurred_to": "2026-09-01T00:00:00+00:00",
        },
    )
    assert inverted.status_code == 422
    unknown_audience = client.post("/api/audit-exports", headers=admin["headers"], json={"audience": "outsider"})
    assert unknown_audience.status_code == 422


def test_tamper_and_missing_page_detection(client, admin):
    _setup_archives(client, admin)
    definition = dict(RULE_DEFINITION, page_size=2)
    registered = client.post(
        "/api/audit-exports/rules/versions",
        headers=admin["headers"],
        json={"version": "audit-export-rules/v2-small-pages", "definition": definition, "activate": True},
    )
    assert registered.status_code == 201, registered.text

    task = _create_export(client, admin, audience="legal")["task"]
    assert task["rule_version"] == "audit-export-rules/v2-small-pages"
    _complete_export(client, admin, task["id"])
    document = _download(client, admin, task["id"]).json()
    assert document["manifest"]["page_count"] >= 2
    assert verify_document(document) == []

    # 篡改行内容：定位到事件
    tampered = copy.deepcopy(document)
    target = tampered["pages"][0]["rows"][0]
    target["actor"] = "被篡改的操作人"
    issues = verify_document(tampered)
    located = [issue for issue in issues if issue["kind"] == "row_digest_mismatch"]
    assert located
    assert located[0]["event_id"] == target["event_id"]
    assert located[0]["page"] == 1

    # 缺页：定位到页码
    missing = copy.deepcopy(document)
    removed = missing["pages"].pop(1)
    issues = verify_document(missing)
    kinds = {issue["kind"] for issue in issues}
    assert "missing_page" in kinds
    assert "row_count_mismatch" in kinds
    assert any(issue["page"] == removed["page"] for issue in issues if issue["kind"] == "missing_page")

    # 清单页摘要被改：页级与文件级摘要同时失效
    forged = copy.deepcopy(document)
    forged["manifest"]["pages"][0]["digest"] = "0" * 64
    issues = verify_document(forged)
    kinds = {issue["kind"] for issue in issues}
    assert "page_digest_mismatch" in kinds
    assert "file_digest_mismatch" in kinds


def test_failed_task_retry_and_attempt_cap(client, admin, monkeypatch):
    _setup_archives(client, admin)
    from app.database import transaction
    from app.services.audit_export import AuditExportService

    def boom(self, task, *, worker, principal):
        raise RuntimeError("模拟渲染失败")

    monkeypatch.setattr(AuditExportService, "_execute", boom)
    task = _create_export(client, admin, audience="legal")["task"]
    claimed = client.post(f"/api/audit-exports/{task['id']}/claim", headers=admin["headers"])
    assert claimed.status_code == 200
    assert claimed.json()["status"] == "failed"
    assert "模拟渲染失败" in claimed.json()["error_message"]

    # 失败任务必须先重试再领取
    again = client.post(f"/api/audit-exports/{task['id']}/claim", headers=admin["headers"])
    assert again.status_code == 409

    monkeypatch.undo()
    retried = client.post(f"/api/audit-exports/{task['id']}/retry", headers=admin["headers"])
    assert retried.status_code == 200
    assert retried.json()["status"] == "pending"
    completed = _complete_export(client, admin, task["id"])
    assert completed["status"] == "completed"

    # 重试次数达到上限后禁止再重试
    other = _create_export(client, admin, audience="rd_lead")["task"]
    with transaction(immediate=True) as connection:
        connection.execute(
            "UPDATE audit_export_tasks SET status='failed', attempts=5, error_message='x' WHERE id=?",
            (other["id"],),
        )
    capped = client.post(f"/api/audit-exports/{other['id']}/retry", headers=admin["headers"])
    assert capped.status_code == 409


def test_failed_task_not_reused_and_retry_conflict(client, admin, monkeypatch):
    _setup_archives(client, admin)
    from app.services.audit_export import AuditExportService

    def boom(self, task, *, worker, principal):
        raise RuntimeError("模拟渲染失败")

    monkeypatch.setattr(AuditExportService, "_execute", boom)
    first = _create_export(client, admin, audience="legal", project_code="PRJ-X")["task"]
    claimed = client.post(f"/api/audit-exports/{first['id']}/claim", headers=admin["headers"])
    assert claimed.json()["status"] == "failed"
    monkeypatch.undo()

    # 失败结果不复用：相同筛选条件创建新任务
    second = _create_export(client, admin, audience="legal", project_code="PRJ-X")
    assert second["reused"] is False
    assert second["task"]["id"] != first["id"]

    # 已有同条件的进行中任务时，旧失败任务不能再重试
    conflict = client.post(f"/api/audit-exports/{first['id']}/retry", headers=admin["headers"])
    assert conflict.status_code == 409


def test_stale_running_task_can_be_reclaimed(client, admin):
    _setup_archives(client, admin)
    from app.database import transaction

    task = _create_export(client, admin, audience="legal")["task"]
    with transaction(immediate=True) as connection:
        connection.execute(
            "UPDATE audit_export_tasks SET status='running', claimed_by='ghost', claimed_at=? WHERE id=?",
            ("2000-01-01T00:00:00+00:00", task["id"]),
        )
    completed = _complete_export(client, admin, task["id"])
    assert completed["status"] == "completed"
    assert completed["attempts"] == 1


def test_rule_version_change_creates_new_task_and_keeps_old(client, admin):
    _setup_archives(client, admin)
    first = _create_export(client, admin, audience="legal", project_code="PRJ-X")["task"]
    _complete_export(client, admin, first["id"])

    definition = dict(RULE_DEFINITION, page_size=10)
    registered = client.post(
        "/api/audit-exports/rules/versions",
        headers=admin["headers"],
        json={"version": "audit-export-rules/v2", "definition": definition},
    )
    assert registered.status_code == 201, registered.text
    current = client.get("/api/audit-exports/rules/current", headers=admin["headers"])
    assert current.json()["version"] == "audit-export-rules/v2"

    second = _create_export(client, admin, audience="legal", project_code="PRJ-X")
    assert second["reused"] is False
    assert second["task"]["id"] != first["id"]
    assert second["task"]["rule_version"] == "audit-export-rules/v2"

    old = client.get(f"/api/audit-exports/{first['id']}", headers=admin["headers"]).json()
    assert old["rule_version"] == "audit-export-rules/v1"
    document = _download(client, admin, first["id"]).json()
    assert document["manifest"]["rule_version"] == "audit-export-rules/v1"
    assert verify_document(document) == []


def test_verify_endpoint_cross_checks_server_record(client, admin):
    _setup_archives(client, admin)
    task = _create_export(client, admin, audience="legal")["task"]
    _complete_export(client, admin, task["id"])
    document = _download(client, admin, task["id"]).json()

    forged = copy.deepcopy(document)
    forged["manifest"]["file_digest"] = "0" * 64
    response = client.post("/api/audit-exports/verify", headers=admin["headers"], json=forged)
    body = response.json()
    assert body["valid"] is False
    assert body["server_record"]["file_digest_match"] is False
    kinds = {issue["kind"] for issue in body["issues"]}
    assert "file_digest_mismatch" in kinds
    assert "server_digest_mismatch" in kinds

    unknown = copy.deepcopy(document)
    unknown["manifest"]["export_code"] = "AEX-ffffffffffff"
    response = client.post("/api/audit-exports/verify", headers=admin["headers"], json=unknown)
    assert response.json()["server_record"]["found"] is False


def test_export_requires_permission(client, admin):
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "lab.reader", "name": "只读查看员", "permission_codes": ["dossiers.read"]},
    )
    assert role.status_code == 201, role.text
    user = client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": "reader.one", "password": "Reader!23456", "display_name": "查看员", "role_codes": ["lab.reader"]},
    )
    assert user.status_code == 201, user.text
    login = client.post(
        "/api/auth/login",
        json={"username": "reader.one", "password": "Reader!23456", "client_label": "tests"},
    )
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    assert client.post("/api/audit-exports", headers=headers, json={"audience": "legal"}).status_code == 403
    assert client.get("/api/audit-exports", headers=headers).status_code == 403
    assert client.post("/api/audit-exports", json={"audience": "legal"}).status_code == 401


def test_cli_verify_export(client, admin, tmp_path, capsys):
    from app.cli import command_verify_export

    _setup_archives(client, admin)
    task = _create_export(client, admin, audience="legal")["task"]
    _complete_export(client, admin, task["id"])
    document = _download(client, admin, task["id"]).json()

    path = tmp_path / "export.json"
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    command_verify_export(str(path))
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is True
    assert output["rule_version"] == "audit-export-rules/v1"

    tampered = copy.deepcopy(document)
    row = tampered["pages"][0]["rows"][0]
    row["outcome"] = "denied" if row["outcome"] == "success" else "success"
    bad_path = tmp_path / "tampered.json"
    bad_path.write_text(json.dumps(tampered, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(SystemExit) as tampered_exit:
        command_verify_export(str(bad_path))
    assert tampered_exit.value.code == 1
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is False
    assert any(issue["kind"] == "row_digest_mismatch" for issue in output["issues"])
    assert any(issue["event_id"] == row["event_id"] for issue in output["issues"])

    with pytest.raises(SystemExit) as missing_exit:
        command_verify_export(str(tmp_path / "missing.json"))
    assert missing_exit.value.code == 2

    with pytest.raises(SystemExit) as digest_exit:
        command_verify_export(str(path), expect_digest="0" * 64)
    assert digest_exit.value.code == 1
