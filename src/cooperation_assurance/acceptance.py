"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import timedelta
from pathlib import Path

from .jsonio import load_json
from .service import AssuranceService
from .storage import connect, inspect_schema


def run(workspace: Path) -> dict[str, object]:
    fixtures = workspace / "fixtures"
    protocol = load_json(fixtures / "demo_protocol.json")
    observation_rows = [
        json.loads(line)
        for line in (fixtures / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with tempfile.TemporaryDirectory(prefix="cooperation-assurance-") as temporary:
        database = Path(temporary) / "foundation.sqlite3"
        connection = connect(database)
        try:
            service = AssuranceService(connection)
            service.create_user("operator-1", "测试操作员", "operator")
            service.create_user("stat-1", "统计负责人", "statistician")
            service.create_user("approver-1", "分析准入审批人", "approver")
            service.create_user("auditor-1", "审计人员", "auditor")
            service.create_user("compliance-1", "披露责任方", "compliance")
            service.register_program("operator-1", "program-a", "跨境数据服务合作项目", "示例牵头机构")
            service.register_evidence_revision("operator-1", "evidence_revision-a1", "program-a", "1.0.0", "a" * 64)
            service.publish_protocol("stat-1", protocol)
            service.create_batch("operator-1", "batch-demo", protocol["protocol_id"], protocol["version"], "evidence_revision-a1")
            service.start_batch("operator-1", "batch-demo", 1)
            imported = service.import_observations(
                "operator-1", "batch-demo", "demo-import-1", observation_rows
            )
            service.seal_batch("stat-1", "batch-demo", 2)
            job = service.claim_job("worker-1", lease_seconds=60)
            if job is None:
                raise RuntimeError("未能领取分析任务")
            analysis = service.complete_job("worker-1", job["job_id"], "stat-1")
            decision_value = "approved" if analysis["result"]["conclusion"] == "pass" else "rejected"
            service.decide(
                "approver-1", "batch-demo", analysis["analysis_id"], decision_value, "离线验收决定"
            )
            report = service.report("auditor-1", "batch-demo")

            # 分级披露：三类接收主体、不同字段、目的与期限，冻结并封签。
            service.rotate_signing_key("compliance-1")
            decision_id = report["decision"]["decision_id"]
            issues = []
            recipient_specs = [
                (
                    "disc-investor", "foreign_investor", "due_diligence", "境外投资人尽职调查",
                    [{"recipient_id": "investor-1", "name": "境外基金", "jurisdiction": "SG"}], ["SG"],
                    ["analysis.result.conclusion", "decision.decision"],
                ),
                (
                    "disc-regulator", "local_regulator", "regulatory_filing", "属地监管备案",
                    [{"recipient_id": "regulator-1", "name": "属地监管局", "jurisdiction": "CN"}], ["CN"],
                    [
                        "analysis.result.conclusion", "decision.decision", "decision.reason",
                        "analysis.result.aggregate", "analysis.result.rules", "analysis.result.included_count",
                    ],
                ),
                (
                    "disc-assessor", "independent_assessor", "independent_assessment", "第三方独立评估",
                    [{"recipient_id": "assessor-1", "name": "独立评估机构", "jurisdiction": "HK"}], ["HK"],
                    [
                        "analysis.result.conclusion", "analysis.result.aggregate", "analysis.result.rules",
                        "protocol.title", "protocol.task_family", "analysis.algorithm_version",
                    ],
                ),
            ]
            for package_id, klass, purpose, detail, recipients, jurisdictions, reveal_paths in recipient_specs:
                issued = service.create_disclosure_package("compliance-1", {
                    "package_id": package_id,
                    "batch_id": "batch-demo",
                    "analysis_id": analysis["analysis_id"],
                    "decision_id": decision_id,
                    "purpose_code": purpose,
                    "purpose_detail": detail,
                    "recipient_class": klass,
                    "recipients": recipients,
                    "allowed_statements": ["本项目已通过合作准入评估"],
                    "jurisdictions": jurisdictions,
                    "field_policy": {"reveal_paths": reveal_paths, "redact_paths": []},
                    "expires_at": (service.clock.now() + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
                })
                token = issued["deliveries"][0]["token"]
                envelope = service.read_disclosure_package(
                    package_id, recipients[0]["recipient_id"], token, jurisdictions[0],
                    f"{package_id}-initial",
                )
                verification = service.verify_disclosure_package(package_id)
                redaction_check = service.verify_disclosure_redactions("compliance-1", package_id)
                issues.append({
                    "package_id": package_id,
                    "digest_valid": verification["digest_valid"],
                    "signature_valid": verification["signature_valid"],
                    "commitments_valid": redaction_check["commitments_valid"],
                    "anchors_valid": redaction_check["anchors_valid"],
                    "conclusion": envelope["payload"]["content"]["analysis"]["result"]["conclusion"],
                    "scope_fingerprint": issued["scope_fingerprint"],
                })

            # 撤回投资人披露包：后续读取被拒，已交付事实保留；再轮换密钥并重签监管包。
            service.revoke_disclosure_package("compliance-1", "disc-investor", "尽调终止")
            service.rotate_signing_key("compliance-1")
            resigned = service.resign_disclosure_package("compliance-1", "disc-regulator")
            ledger = service.disclosure_ledger("auditor-1")
            schema = inspect_schema(connection)
        finally:
            connection.close()
    if schema["missing_tables"] or schema["schema_version"] != "3":
        raise RuntimeError("SQLite 基础结构检查失败")
    if not all(item["digest_valid"] and item["signature_valid"] and item["commitments_valid"]
               and item["anchors_valid"] for item in issues):
        raise RuntimeError("披露包冻结、封签或遮蔽承诺校验失败")
    investor_entry = next(item for item in ledger["packages"] if item["package_id"] == "disc-investor")
    if investor_entry["state"] != "revoked" or investor_entry["delivered_count"] != 1:
        raise RuntimeError("撤回后访问事实未保留")
    regulator_entry = next(item for item in ledger["packages"] if item["package_id"] == "disc-regulator")
    if not regulator_entry["scope_unchanged"] or resigned["package_sha256"] != regulator_entry["package_sha256"]:
        raise RuntimeError("重签扩大了披露范围")
    fingerprints = {item["scope_fingerprint"] for item in issues}
    if len(fingerprints) != 3:
        raise RuntimeError("三类接收主体的披露范围应当不同")
    return {
        "status": "ok",
        "protocol": f"{protocol['protocol_id']}@{protocol['version']}",
        "observation_count": imported["inserted"],
        "analysis_id": analysis["analysis_id"],
        "input_sha256": analysis["input_sha256"],
        "conclusion": analysis["result"]["conclusion"],
        "decision": report["decision"]["decision"],
        "event_count": len(report["events"]),
        "disclosures": issues,
        "ledger_summary": {
            item["package_id"]: {
                "state": item["state"],
                "delivered": item["delivered_count"],
                "denied": item["denied_count"],
                "scope_unchanged": item["scope_unchanged"],
            }
            for item in ledger["packages"]
        },
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行校准数据基础工具的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
