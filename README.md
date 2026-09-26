# 专利与技术秘密档案管理服务

这是一个面向研发机构、法务部门和保密办公室的模块化后端，集中管理专利交底资料、技术秘密载体、移交批次、受控副本签发、查阅借阅、对外披露、归还、合规处置、载体盘点、版本与载体来源、密级库位、泄密事件、登录权限、审计以及可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 已有能力

- 身份与权限：支持引导管理员、登录、会话、用户、角色和细粒度权限。
- 批次与二维码：移交批次保存项目、数量和稳定二维码载荷。
- 档案登记：登记专利交底、工艺文档、源代码介质等资产，保存密级库位和生命周期状态。
- 受控副本签发：一次事务内扣减来源载体、创建副本、记录损耗和版本来源事件。
- 查阅借阅归还：保存查阅用途、到期时间、部分归还和最终归还状态。
- 对外披露登记：使用幂等键登记合作方、披露范围和载体消耗，防止重复请求二次扣减。
- 位置脱敏：普通权限只能看到受限库位的替代码，授权人员可查看精确位置。
- 双人审批：合规处置、敏感库位解密等高风险操作要求申请人与审批人分离，并累计不同审批人的决定。
- 泄密事件追踪：事件可以关联档案或移交批次，保存严重度、调查状态和处置结果。
- 审计与任务：关键身份及业务操作留痕，后台任务支持去重、领取与完成。
- 审计导出：按时间、项目、事件类型和角色（内审/法务/研发负责人）生成分级字段视图；导出前固定查询快照并逐页计算摘要；同一筛选条件重复提交自动复用结果；任务支持领取、失败重试与下载核验；导出包固化生成时的规则版本，篡改、缺页、摘要不一致均可被离线命令或 HTTP 接口检出并定位到具体事件。受限库位、个人联系方式与未公开专利内容不会进入无权角色的导出包。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `./data/archives.db`，可用 `ARCHIVE_DATABASE_PATH` 指定其他路径。

## 初始化与完整性检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动 API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 测试

```bash
python -m pytest
```

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
```

## 审计导出

申请导出（`profile` 为 `internal_audit`、`legal` 或 `research_lead`，筛选条件可选 `events_from`、`events_to`、`project_codes`、`event_types`）：

```bash
curl -X POST http://localhost:8000/api/audit-exports \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"profile": "internal_audit", "project_codes": ["PATENT-A"], "events_from": "2026-01-01T00:00:00+00:00"}'
```

每个角色视图由独立权限控制（`audit.export.internal_audit`、`audit.export.legal`、`audit.export.research_lead`）。相同角色与筛选条件重复提交会复用未完成或已完成的结果；失败的任务可通过 `POST /api/audit-exports/{id}/retry` 重试。

执行导出任务（二选一）：

```bash
# HTTP：由具备 jobs.run 权限的账号逐个领取执行
curl -X POST http://localhost:8000/api/system/jobs/run-exports -H "Authorization: Bearer $TOKEN"
# CLI：前台工作进程，执行队列中全部导出任务
python -m app.cli run-export-jobs
```

下载与核验：

```bash
# 下载导出包（响应头 X-Export-Sha256 / X-Export-Root-Hash 携带登记摘要）
curl -OJ http://localhost:8000/api/audit-exports/1/download -H "Authorization: Bearer $TOKEN"
# 获取可信回执，供离线交叉核验
curl http://localhost:8000/api/audit-exports/1/receipt -H "Authorization: Bearer $TOKEN" > receipt.json
# HTTP 核验服务端文件或上传的离线包
curl http://localhost:8000/api/audit-exports/1/verify -H "Authorization: Bearer $TOKEN"
curl -X POST http://localhost:8000/api/audit-exports/verify-upload \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
  --data-binary @AEXP-xxx.tar
# 离线核验（不依赖服务在线；--receipt 可选）
python -m app.cli verify-export AEXP-xxx.tar --receipt receipt.json
```

导出包为 tar 文件，内含 `manifest.json`（清单：规则版本、快照水位、分页摘要、根哈希）与 `pages/page-*.json`（分页记录，逐条带 SHA-256 摘要并串成哈希链）。核验会发现并定位：记录篡改（`RECORD_DIGEST_MISMATCH`，含档案事件 id）、缺页（`PAGE_MISSING`）、整包/根哈希与登记摘要不一致（`RECEIPT_MISMATCH`）等问题。导出文件默认保存在数据库同级 `exports/` 目录，可用 `ARCHIVE_EXPORT_DIR` 指定其他位置。
