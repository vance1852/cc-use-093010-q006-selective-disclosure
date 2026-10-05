"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .errors import DisclosureDenied, Forbidden
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
            decision_id = report["decision"]["decision_id"]
            disclosure_summary = _run_disclosure_flow(
                service,
                batch_id="batch-demo",
                analysis_id=analysis["analysis_id"],
                decision_id=decision_id,
            )
            schema = inspect_schema(connection)
        finally:
            connection.close()
    if schema["missing_tables"] or schema["schema_version"] != "3":
        raise RuntimeError("SQLite 基础结构检查失败")
    return {
        "status": "ok",
        "protocol": f"{protocol['protocol_id']}@{protocol['version']}",
        "observation_count": imported["inserted"],
        "analysis_id": analysis["analysis_id"],
        "input_sha256": analysis["input_sha256"],
        "conclusion": analysis["result"]["conclusion"],
        "decision": report["decision"]["decision"],
        "event_count": len(report["events"]),
        "disclosure": disclosure_summary,
        "schema": schema,
    }


def _run_disclosure_flow(
    service: AssuranceService, *, batch_id: str, analysis_id: int, decision_id: int
) -> dict[str, object]:
    base = {
        "batch_id": batch_id,
        "analysis_id": analysis_id,
        "decision_id": decision_id,
        "allowed_statements": ["项目已完成预注册协议下的独立评估"],
        "data_regions": ["CN", "SG"],
    }
    investor = service.issue_disclosure(
        "approver-1",
        purpose="境外投资人尽调",
        recipient={"id": "investor-x", "kind": "investor", "jurisdiction": "sg"},
        expires_at="2026-12-31T23:59:59Z",
        **base,
    )
    regulator = service.issue_disclosure(
        "approver-1",
        purpose="属地监管例行核查",
        recipient={"id": "regulator-cn", "kind": "regulator", "jurisdiction": "cn"},
        expires_at="2027-12-31T23:59:59Z",
        **base,
    )
    assessor = service.issue_disclosure(
        "approver-1",
        purpose="独立第三方评估",
        recipient={"id": "assessor-iso", "kind": "assessor", "jurisdiction": "de"},
        expires_at="2027-06-30T23:59:59Z",
        **base,
    )
    # 同请求重试必须幂等，不产生第二个包。
    replay = service.issue_disclosure(
        "approver-1",
        purpose="境外投资人尽调",
        recipient={"id": "investor-x", "kind": "investor", "jurisdiction": "sg"},
        expires_at="2026-12-31T23:59:59Z",
        **base,
    )
    if not replay["replayed"] or replay["package_id"] != investor["package_id"]:
        raise RuntimeError("披露签发重试没有返回原包")
    # 投资人读取：商业敏感字段必须以摘要锚点遮蔽。
    view = service.read_disclosure("investor-x", investor["package_id"])
    document = view["envelope"]["document"]
    if document["program"]["lead_organization"].get("__redacted__") is not True:
        raise RuntimeError("投资人包未遮蔽牵头机构")
    if document["analysis"]["conclusion"] != "pass":
        raise RuntimeError("投资人包缺少总体结论")
    # 错误接收主体读取必须被拒绝并留痕。
    try:
        service.read_disclosure("intruder", investor["package_id"])
        raise RuntimeError("非授权接收主体竟能读取披露包")
    except Forbidden:
        pass
    verification = service.verify_disclosure("auditor-1", investor["package_id"])
    if not (
        verification["signature_valid"]
        and verification["package_sha256_match"]
        and verification["document_sha256_match"]
        and verification["scope_sha256_match"]
        and verification["redaction_anchors_verified"]
        and verification["evidence_anchors_verified"]
    ):
        raise RuntimeError("披露包来源或锚点校验失败")
    # 主动撤回后不能再读，但访问事实保留。
    service.revoke_disclosure("approver-1", regulator["package_id"], "核查提前结束")
    try:
        service.read_disclosure("regulator-cn", regulator["package_id"])
        raise RuntimeError("撤回后竟能读取披露包")
    except DisclosureDenied:
        pass
    # 重签续期不得改变范围指纹。
    resigned = service.resign_disclosure(
        "approver-1", assessor["package_id"],
        new_expires_at="2028-06-30T23:59:59Z", reason="评估周期延长",
    )
    service.read_disclosure("assessor-iso", resigned["package_id"])
    # 辖区限制变化：只允许驻留 CN，SG 境外包立即受阻；到期门控由时钟演示。
    blocked = service.set_jurisdiction_restriction("approver-1", "SG", ["CN"])
    try:
        service.read_disclosure("investor-x", investor["package_id"])
        raise RuntimeError("辖区限制变化后竟能读取披露包")
    except DisclosureDenied:
        pass
    # 决定失效：其余有效包立即失效。
    invalidated = service.invalidate_decision("approver-1", decision_id, "复议后撤销原准入决定")
    ledger = service.disclosure_ledger("auditor-1")
    if not ledger["scope_integrity"]:
        raise RuntimeError("台账检测到范围指纹不一致")
    if not all(item["scope_unchanged"] for item in ledger["resignings"]):
        raise RuntimeError("重签扩大了授权范围")
    denied_after_gate = [a for a in ledger["accesses"] if a["outcome"] == "denied"]
    return {
        "issued": 3,
        "investor_package": investor["package_id"],
        "resigned_package": resigned["package_id"],
        "revoked_packages": [regulator["package_id"]],
        "jurisdiction_blocked": blocked["affected_packages"],
        "decision_invalidated_packages": invalidated["affected_packages"],
        "delivered_count": len([a for a in ledger["accesses"] if a["outcome"] == "delivered"]),
        "denied_count": len(denied_after_gate),
        "scope_integrity": ledger["scope_integrity"],
        "ledger_packages": len(ledger["packages"]),
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
