# 全球数字贸易合作运营平台

本项目是一套可离线运行的 Python 服务端平台，用于管理跨境数字合作中的资源流转、项目证据评估和统计资料质量。平台把运营节点、合作通道、资源申请、项目版本、分析决定、样本观测、权限和审计事件持久化到 SQLite，供秘书处、项目办公室、数据团队和审计人员协作使用。

## 目录

- src/trade_flow/：运营节点、合作通道、资源批次、额度申请、分配和情景分析；
- src/cooperation_assurance/：合作项目、证据版本、评估协议、观测导入、分析任务、准入决定与分级披露；
- src/metric_quality/：统计样本批次、指标观测、质量分析、账号权限和审批；
- fixtures/：离线验收使用的评估协议与结构化观测；
- tests/：领域规则、错误边界、事务、权限、HTTP API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

    PYTHONPATH=src python3 -m unittest discover -s tests -v

## 构建检查

    python3 -m compileall -q src tests

## 离线验收

    PYTHONPATH=src python3 -m trade_flow.acceptance --workspace .
    PYTHONPATH=src python3 -m cooperation_assurance.acceptance --workspace .
    PYTHONPATH=src python3 -m metric_quality.acceptance

三条命令会在临时 SQLite 数据库中完成合作资源流转、项目证据评估、分级披露全生命周期（签发、读取、撤回、重签、辖区收紧、决定失效、合规台账）和统计资料质量流程，不访问外部网络。

## 分级披露

`cooperation_assurance` 在内部完整报告之外，向境外投资人（investor）、属地监管机构（regulator）和独立评估方（assessor）提供内容冻结的披露包。责任方（approver 角色）签发时确定：

- 确定版本的项目结论（批次修订号、证据/协议/分析输入/分析结果/决定的内容摘要锚点）；
- 使用目的 `purpose`、接收主体 `recipient`、允许声明 `allowed_statements`；
- 遮蔽规则 `redaction_rules`（缺省按接收主体画像：投资人遮蔽商业身份与分层细节，评估方遮蔽商业身份与审批理由，监管机构不遮蔽）；
- 数据驻留区域 `data_regions` 与有效期限 `expires_at`。

披露包是 `manifest + document + attestation` 的冻结 JSON：`document` 中被遮蔽字段替换为
`{"__redacted__": true, "sha256": ...}`，摘要锚定该字段原内容，因此声明与原证据保持可验证关联；
包内不含内部行号或链接，接收方无法沿引用访问未授权记录。`package_sha256` 供任何人校验内容冻结，
`HMAC-SHA256` 签名（密钥存于 `disclosure_keys`，可轮换且旧签名持续可验）证明来源，
`scope_sha256` 只覆盖授权范围，重签续期保持不变。

门控规则：授权到期（惰性）、主动撤回、项目决定失效、辖区驻留限制变化都会阻止后续读取；
每次读取尝试（含被拒绝的尝试）都永久记入 `disclosure_accesses`，已交付的冻结摘要不受影响。
审计人员通过 `GET /disclosures/ledger` 回答“谁在何时因何目的看到哪些内容”，台账同时校验
重试幂等、重签不扩大范围（`scope_integrity`）。

主要接口：`POST /disclosures`、`POST /disclosures/{id}/read`、`POST /disclosures/{id}/revoke`、
`POST /disclosures/{id}/resign`、`GET /disclosures/{id}/verify`、`GET /disclosures/ledger`、
`POST /jurisdiction_restrictions`、`POST /decisions/{id}/invalidate`。

## HTTP 服务

    PYTHONPATH=src python3 -m trade_flow.api --database trade-flow.sqlite3 --host 127.0.0.1 --port 8080
    PYTHONPATH=src python3 -m cooperation_assurance.api --database cooperation-assurance.sqlite3 --host 127.0.0.1 --port 8081
    PYTHONPATH=src python3 -m metric_quality.api --database metric-quality.sqlite3 --host 127.0.0.1 --port 8082

服务提供 JSON 接口与健康检查。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。
