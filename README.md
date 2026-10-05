# 全球数字贸易合作运营平台

本项目是一套可离线运行的 Python 服务端平台，用于管理跨境数字合作中的资源流转、项目证据评估和统计资料质量。平台把运营节点、合作通道、资源申请、项目版本、分析决定、样本观测、权限和审计事件持久化到 SQLite，供秘书处、项目办公室、数据团队和审计人员协作使用。

## 目录

- src/trade_flow/：运营节点、合作通道、资源批次、额度申请、分配和情景分析；
- src/cooperation_assurance/：合作项目、证据版本、评估协议、观测导入、分析任务、准入决定与分级披露；
- src/metric_quality/：统计样本批次、指标观测、质量分析、账号权限和审批；
- fixtures/：离线验收使用的评估协议与结构化观测；
- tests/：领域规则、错误边界、事务、权限、HTTP API 和命令行验收测试。

## 分级披露

`cooperation_assurance.disclosure` 让责任方（`compliance` 角色）把确定版本的项目结论按接收主体分级外发：

- 责任方选择结论版本（批次当前生效的分析与决定）、使用目的（尽调/监管备案/独立评估）、
  接收主体类别（境外投资人/属地监管机构/独立评估方）、允许声明、字段遮蔽规则、
  生效与到期时间、证据保留期限和授权辖区；
- 披露包内容冻结为规范化 JSON，计算 SHA-256 指纹并用平台封签密钥 HMAC-SHA256 签名，
  接收方可经 `GET /disclosure_packages/{id}/verify` 校验来源与效力；
- 字段默认全部遮蔽，只有显式放开的字段可见；被遮蔽字段以 HMAC 承诺值保留与原证据
  （证据版本、分析输入摘要）的可验证关联，原始观测永不进入包内，包内锚点只是哈希、不是访问入口；
- 授权到期、主动撤回、项目决定失效或辖区限制收窄都会阻止后续读取；每次读取尝试
  （含被拒绝的原因）都写入访问台账并保留到保留期限，已交付摘要与访问事实不随撤回删除；
- 同一 `attempt_id` 的重试只回放既有结论；密钥轮换后的重签只更换签名块，
  载荷字节、包指纹与范围指纹保持不变；
- `GET /disclosure_ledger`（审计与合规角色）回答“谁在何时因何目的看到哪些字段”，
  并校验重试、撤回与重签没有扩大披露范围。

### 披露相关 HTTP 接口

- `POST /signing_keys/rotate`：轮换封签密钥（合规角色）
- `POST /disclosure_packages`：冻结并签发披露包，返回每个接收主体的不透明投递令牌
- `POST /disclosure_packages/{id}/read`：接收主体凭令牌、辖区与 attempt_id 读取
- `POST /disclosure_packages/{id}/revoke`：主动撤回
- `POST /disclosure_packages/{id}/restrict`：在原授权范围内收窄辖区
- `POST /disclosure_packages/{id}/resign`：密钥轮换后重签（范围不变）
- `GET  /disclosure_packages/{id}/verify`：公开来源与效力校验
- `GET  /disclosure_packages/{id}/redactions`：遮蔽承诺与原证据锚点复核
- `GET  /disclosure_ledger[ /packages/{id}]`：合规访问台账

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

三条命令会在临时 SQLite 数据库中完成合作资源流转、项目证据评估和统计资料质量流程，不访问外部网络。

## HTTP 服务

    PYTHONPATH=src python3 -m trade_flow.api --database trade-flow.sqlite3 --host 127.0.0.1 --port 8080
    PYTHONPATH=src python3 -m cooperation_assurance.api --database cooperation-assurance.sqlite3 --host 127.0.0.1 --port 8081
    PYTHONPATH=src python3 -m metric_quality.api --database metric-quality.sqlite3 --host 127.0.0.1 --port 8082

服务提供 JSON 接口与健康检查。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。
