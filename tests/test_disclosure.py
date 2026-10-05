from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cooperation_assurance.clock import FrozenClock
from cooperation_assurance.errors import Forbidden, InvalidState, NotFound, ValidationFailed
from cooperation_assurance.jsonio import canonical_json, load_json
from cooperation_assurance.service import AssuranceService

ROOT = Path(__file__).resolve().parents[1]


class DisclosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc))
        self.service = AssuranceService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
            ("compl", "compliance"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_program("operator", "program-a", "跨境数据服务项目", "牵头机构")
        self.service.register_evidence_revision("operator", "ev-a", "program-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", self.protocol)
        self.service.create_batch("operator", "batch-a", "demo-cooperation-v1", 1, "ev-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_observations("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 30)
        self.analysis = self.service.complete_job("worker", job["job_id"], "stat")
        self.service.decide("approver", "batch-a", self.analysis["analysis_id"], "approved", "满足规则")
        self.service.rotate_signing_key("compl")
        self.expires = self._iso(days=30)

    def tearDown(self) -> None:
        self.connection.close()

    def _iso(self, days: float = 0, hours: float = 0) -> str:
        value = self.clock.now() + timedelta(days=days, hours=hours)
        return value.isoformat().replace("+00:00", "Z")

    def _issue(
        self,
        package_id: str = "disc-1",
        *,
        actor: str = "compl",
        recipient_class: str = "foreign_investor",
        purpose: str = "due_diligence",
        recipients=None,
        jurisdictions=None,
        reveal_paths=None,
        redact_paths=None,
        expires_at=None,
        retain_days: int = 365,
        statements=("项目已通过准入评估",),
    ):
        if recipients is None:
            recipients = [{"recipient_id": "inv-1", "name": "境外基金", "jurisdiction": "SG"}]
        if jurisdictions is None:
            jurisdictions = ["SG"]
        if reveal_paths is None:
            reveal_paths = ["analysis.result.conclusion", "decision.decision"]
        return self.service.create_disclosure_package(actor, {
            "package_id": package_id,
            "batch_id": "batch-a",
            "analysis_id": self.analysis["analysis_id"],
            "decision_id": 1,
            "purpose_code": purpose,
            "purpose_detail": f"{purpose} 用途说明",
            "recipient_class": recipient_class,
            "recipients": recipients,
            "allowed_statements": list(statements),
            "jurisdictions": jurisdictions,
            "field_policy": {"reveal_paths": reveal_paths, "redact_paths": redact_paths or []},
            "effective_at": self._iso(),
            "expires_at": expires_at or self.expires,
            "retain_days": retain_days,
        })

    def test_issue_freezes_package_with_redactions_and_anchors(self) -> None:
        issued = self._issue()
        self.assertEqual(len(issued["package_sha256"]), 64)
        self.assertEqual(len(issued["scope_fingerprint"]), 64)
        token = issued["deliveries"][0]["token"]
        envelope = self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "a-1")

        payload = envelope["payload"]
        result = payload["content"]["analysis"]["result"]
        self.assertEqual(result["conclusion"], "pass")
        self.assertEqual(payload["content"]["decision"]["decision"], "approved")
        # 未放开字段被遮蔽，仅留承诺，不泄露底层统计或商业字段。
        self.assertTrue(result["aggregate"]["redacted"])
        self.assertEqual(len(result["aggregate"]["commitment"]), 64)
        self.assertTrue(payload["content"]["decision"]["reason"]["redacted"])
        self.assertTrue(payload["content"]["program"]["program_name"]["redacted"])
        # 字段清单逐项记录状态。
        statuses = {entry["path"]: entry["status"] for entry in payload["field_manifest"]}
        self.assertEqual(statuses["analysis.result.conclusion"], "revealed")
        self.assertEqual(statuses["decision.reason"], "redacted")
        # 原证据锚点保留，但不是可访问记录。
        anchors = payload["anchors"]
        self.assertEqual(anchors["evidence_sha256"], "b" * 64)
        self.assertEqual(anchors["analysis_input_sha256"], self.analysis["input_sha256"])
        serialized = canonical_json(envelope)
        for secret_like in ("42.8", "75.0", "partner-a-20260921", "牵头机构", "满足规则"):
            self.assertNotIn(secret_like, serialized)

    def test_signature_and_digest_verify(self) -> None:
        self._issue()
        verification = self.service.verify_disclosure_package("disc-1")
        self.assertTrue(verification["digest_valid"])
        self.assertTrue(verification["signature_valid"])
        self.assertTrue(verification["decision_effective"])
        self.assertTrue(verification["within_validity"])

    def test_three_recipient_classes_get_different_scopes(self) -> None:
        investor = self._issue(
            "disc-investor",
            reveal_paths=["analysis.result.conclusion", "decision.decision"],
            statements=("本项目通过准入",),
        )
        regulator = self._issue(
            "disc-regulator",
            recipient_class="local_regulator",
            purpose="regulatory_filing",
            recipients=[{"recipient_id": "reg-1", "name": "属地监管局", "jurisdction_ignored": None,
                          "jurisdiction": "CN"}],
            jurisdictions=["CN"],
            reveal_paths=[
                "analysis.result.conclusion", "decision.decision", "decision.reason",
                "analysis.result.aggregate", "analysis.result.rules", "analysis.result.included_count",
            ],
        )
        assessor = self._issue(
            "disc-assessor",
            recipient_class="independent_assessor",
            purpose="independent_assessment",
            recipients=[{"recipient_id": "asnpo-1", "name": "独立评估机构", "jurisdiction": "HK"}],
            jurisdictions=["HK", "SG"],
            reveal_paths=[
                "analysis.result.conclusion", "analysis.result.aggregate", "analysis.result.rules",
                "protocol.title", "protocol.task_family", "analysis.algorithm_version",
            ],
        )
        inv_env = self.service.read_disclosure_package(
            "disc-investor", "inv-1", investor["deliveries"][0]["token"], "SG", "i-1")
        reg_env = self.service.read_disclosure_package(
            "disc-regulator", "reg-1", regulator["deliveries"][0]["token"], "CN", "r-1")
        asn_env = self.service.read_disclosure_package(
            "disc-assessor", "asnpo-1", assessor["deliveries"][0]["token"], "HK", "a-1")
        # 投资人看不到理由；监管可以；评估方可以复核算法但看不到决定理由。
        self.assertTrue(inv_env["payload"]["content"]["decision"]["reason"]["redacted"])
        self.assertEqual(reg_env["payload"]["content"]["decision"]["reason"], "满足规则")
        self.assertTrue(asn_env["payload"]["content"]["decision"]["reason"]["redacted"])
        self.assertEqual(
            asn_env["payload"]["content"]["analysis"]["algorithm_version"],
            self.analysis["result"]["algorithm_version"],
        )
        # 三个包范围指纹互不相同。
        fingerprints = {investor["scope_fingerprint"], regulator["scope_fingerprint"], assessor["scope_fingerprint"]}
        self.assertEqual(len(fingerprints), 3)

    def test_wrong_token_and_unknown_recipient_are_denied_and_logged(self) -> None:
        self._issue()
        with self.assertRaises(Forbidden):
            self.service.read_disclosure_package("disc-1", "inv-1", "wrong-token", "SG", "d-1")
        with self.assertRaises(Forbidden):
            self.service.read_disclosure_package("disc-1", "intruder", "x", "SG", "d-2")
        ledger = self.service.disclosure_ledger("auditor", "disc-1")["packages"][0]
        self.assertEqual(ledger["delivered_count"], 0)
        self.assertEqual(ledger["denied_count"], 2)
        self.assertEqual(ledger["deny_reasons"], ["authentication_failed"])

    def test_recipient_cannot_use_another_packages_token(self) -> None:
        first = self._issue("disc-1")
        second = self._issue(
            "disc-2",
            recipients=[{"recipient_id": "inv-2", "name": "第二只基金", "jurisdiction": "US"}],
            jurisdictions=["US"],
        )
        with self.assertRaises(Forbidden):
            self.service.read_disclosure_package(
                "disc-2", "inv-1", first["deliveries"][0]["token"], "US", "x-1")
        # 锚点只是哈希，无法换成内部读取入口。
        with self.assertRaises(NotFound):
            self.service.get_batch("b" * 64)

    def test_retry_replays_without_expanding_scope(self) -> None:
        issued = self._issue()
        token = issued["deliveries"][0]["token"]
        first = self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "same-attempt")
        second = self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "same-attempt")
        self.assertEqual(first, second)
        ledger = self.service.disclosure_ledger("auditor", "disc-1")["packages"][0]
        self.assertEqual(ledger["delivered_count"], 1)
        self.assertEqual(ledger["accesses"][0]["fields_seen"],
                         ["analysis.result.conclusion", "decision.decision"])
        # 被拒绝的尝试用同一 attempt_id 重试，结论保持拒绝，且不新增台账行。
        with self.assertRaises(Forbidden):
            self.service.read_disclosure_package("disc-1", "inv-1", "bad", "SG", "denied-attempt")
        with self.assertRaises(Forbidden):
            self.service.read_disclosure_package("disc-1", "inv-1", "bad", "SG", "denied-attempt")
        ledger = self.service.disclosure_ledger("auditor", "disc-1")["packages"][0]
        self.assertEqual(ledger["denied_count"], 1)

    def test_replay_without_valid_token_is_rejected(self) -> None:
        # 知道 attempt_id 不构成访问凭证：重放也必须通过投递令牌认证。
        issued = self._issue()
        token = issued["deliveries"][0]["token"]
        self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "a-1")
        with self.assertRaises(Forbidden):
            self.service.read_disclosure_package("disc-1", "inv-1", "stolen", "SG", "a-1")
        # 合法令牌 + 新 attempt_id 构成一次新的合法交付，不能被错误拒绝。
        self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "a-2")
        ledger = self.service.disclosure_ledger("auditor", "disc-1")["packages"][0]
        self.assertEqual(ledger["delivered_count"], 2)
        self.assertEqual(ledger["denied_count"], 0)
        # 审计流水中仍能看到这次失败的认证尝试。
        denied_events = self.connection.execute(
            "SELECT count(*) FROM audit_events "
            "WHERE entity_type='disclosure_package' AND event_type='disclosure.access_denied'"
        ).fetchone()[0]
        self.assertEqual(denied_events, 1)

    def test_expiry_blocks_reads_but_keeps_delivery_facts(self) -> None:
        issued = self._issue(expires_at=self._iso(hours=24), retain_days=90)
        token = issued["deliveries"][0]["token"]
        self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "before-expiry")
        self.clock.advance(hours=25)
        with self.assertRaises(Forbidden):
            self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "after-expiry")
        row = self.service.disclosure_ledger("auditor", "disc-1")["packages"][0]
        self.assertEqual(row["delivered_count"], 1)
        self.assertEqual(row["deny_reasons"], ["expired"])
        # 保留期限晚于到期；访问事实仍在。
        accesses = self.connection.execute(
            "SELECT count(*) FROM disclosure_accesses WHERE package_id='disc-1'").fetchone()[0]
        self.assertEqual(accesses, 2)
        package = self.connection.execute(
            "SELECT retain_until,expires_at FROM disclosure_packages WHERE package_id='disc-1'").fetchone()
        self.assertGreater(package["retain_until"], package["expires_at"])

    def test_revocation_blocks_reads_but_keeps_history(self) -> None:
        issued = self._issue()
        token = issued["deliveries"][0]["token"]
        self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "a-1")
        self.service.revoke_disclosure_package("compl", "disc-1", "商业情况变化")
        with self.assertRaises(Forbidden):
            self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "a-2")
        verification = self.service.verify_disclosure_package("disc-1")
        self.assertEqual(verification["state"], "revoked")
        self.assertTrue(verification["signature_valid"])
        row = self.service.disclosure_ledger("auditor", "disc-1")["packages"][0]
        self.assertEqual(row["state"], "revoked")
        self.assertEqual(row["revocation_reason"], "商业情况变化")
        self.assertEqual(row["delivered_count"], 1)
        self.assertEqual(row["deny_reasons"], ["revoked"])

    def test_decision_becoming_ineffective_blocks_reads(self) -> None:
        issued = self._issue()
        token = issued["deliveries"][0]["token"]
        # 模拟项目决定在后续流程中失效（批次状态离开 decided）。
        self.connection.execute(
            "UPDATE batches SET state='sealed' WHERE batch_id='batch-a'")
        with self.assertRaises(Forbidden) as caught:
            self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "a-2")
        self.assertIn("decision_no_longer_effective", str(caught.exception))
        verification = self.service.verify_disclosure_package("disc-1")
        self.assertFalse(verification["decision_effective"])

    def test_jurisdiction_restriction_can_only_narrow(self) -> None:
        issued = self._issue(jurisdictions=["SG", "HK"])
        token = issued["deliveries"][0]["token"]
        result = self.service.restrict_disclosure_jurisdictions("compl", "disc-1", ["SG"])
        self.assertEqual(result["jurisdictions"], ["SG"])
        with self.assertRaises(Forbidden):
            self.service.read_disclosure_package("disc-1", "inv-1", token, "HK", "hk-1")
        self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "sg-1")
        with self.assertRaises(ValidationFailed):
            self.service.restrict_disclosure_jurisdictions("compl", "disc-1", ["SG", "HK"])
        with self.assertRaises(ValidationFailed):
            self.service.restrict_disclosure_jurisdictions("compl", "disc-1", ["SG", "US"])

    def test_resign_after_key_rotation_keeps_payload_and_scope(self) -> None:
        issued = self._issue()
        token = issued["deliveries"][0]["token"]
        self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "a-1")
        self.service.rotate_signing_key("compl")
        resigned = self.service.resign_disclosure_package("compl", "disc-1")
        self.assertEqual(resigned["package_sha256"], issued["package_sha256"])
        self.assertEqual(resigned["scope_fingerprint"], issued["scope_fingerprint"])
        self.assertEqual(resigned["sign_key_seq"], 2)
        verification = self.service.verify_disclosure_package("disc-1")
        self.assertTrue(verification["signature_valid"])
        self.assertEqual(verification["sign_key_id"], "seal-key-2")
        # 重签不扩大范围：重试旧 attempt 仍返回同一冻结内容。
        replay = self.service.read_disclosure_package("disc-1", "inv-1", token, "SG", "a-1")
        self.assertEqual(
            replay["payload"]["scope_fingerprint"], issued["scope_fingerprint"])
        ledger = self.service.disclosure_ledger("auditor", "disc-1")["packages"][0]
        self.assertTrue(ledger["scope_unchanged"])
        self.assertEqual(ledger["sign_key_seq"], 2)

    def test_redaction_commitments_recompute_against_source(self) -> None:
        self._issue()
        checked = self.service.verify_disclosure_redactions("compl", "disc-1")
        self.assertTrue(checked["commitments_valid"])
        self.assertTrue(checked["frozen_content_matches_source"])
        self.assertTrue(checked["anchors_valid"])
        self.assertIn("decision.reason", checked["redacted_fields"])
        # 篡改字段清单中的遮蔽承诺后复核必须失败。
        row = self.connection.execute(
            "SELECT envelope_json FROM disclosure_packages WHERE package_id='disc-1'").fetchone()
        envelope = json.loads(row["envelope_json"])
        for entry in envelope["payload"]["field_manifest"]:
            if entry["path"] == "decision.reason":
                entry["commitment"] = "0" * 64
        self.connection.execute(
            "UPDATE disclosure_packages SET envelope_json=? WHERE package_id='disc-1'",
            (canonical_json(envelope),))
        checked = self.service.verify_disclosure_redactions("compl", "disc-1")
        self.assertFalse(checked["commitments_valid"])
        self.assertIn("decision.reason", checked["mismatched_fields"])

    def test_role_separation_for_disclosure(self) -> None:
        for actor in ("operator", "stat", "approver"):
            with self.assertRaises(Forbidden):
                self._issue(package_id=f"disc-{actor}", actor=actor)
        with self.assertRaises(Forbidden):
            self.service.disclosure_ledger("operator")
        with self.assertRaises(Forbidden):
            self.service.verify_disclosure_redactions("operator", "disc-1")
        # 合规角色不能反向读取完整内部报告。
        with self.assertRaises(Forbidden):
            self.service.report("compl", "batch-a")
        # 审计可读台账但不能签发。
        with self.assertRaises(Forbidden):
            self._issue(package_id="disc-auditor", actor="auditor")
        self.service.disclosure_ledger("auditor")

    def test_field_policy_validation(self) -> None:
        with self.assertRaises(ValidationFailed):
            self._issue(package_id="bad-1", reveal_paths=["analysis.result.unknown"])
        with self.assertRaises(ValidationFailed):
            self._issue(package_id="bad-2", reveal_paths=[])
        with self.assertRaises(ValidationFailed):
            self._issue(
                package_id="bad-3",
                reveal_paths=["analysis.result.conclusion", "analysis.result.aggregate.conclusion_ignored"],
            )
        with self.assertRaises(ValidationFailed):
            self._issue(
                package_id="bad-4",
                reveal_paths=["analysis.result.conclusion", "analysis.result.aggregate"],
                redact_paths=["analysis.result.aggregate"],
            )
        # 父路径被遮蔽时不能单独放开子路径。
        with self.assertRaises(ValidationFailed):
            self._issue(
                package_id="bad-5",
                reveal_paths=["analysis.result.conclusion", "analysis.result.aggregate"],
                redact_paths=["analysis.result"],
            )

    def test_cannot_freeze_superseded_or_undecided_version(self) -> None:
        # 未形成决定的批次不能披露。
        self.service.register_evidence_revision("operator", "ev-b", "program-a", "2.0", "c" * 64)
        self.service.create_batch("operator", "batch-b", "demo-cooperation-v1", 1, "ev-b")
        with self.assertRaises(InvalidState):
            self.service.create_disclosure_package("compl", {
                "package_id": "disc-premature",
                "batch_id": "batch-b",
                "analysis_id": self.analysis["analysis_id"],
                "decision_id": 1,
                "purpose_code": "due_diligence",
                "purpose_detail": "x",
                "recipient_class": "foreign_investor",
                "recipients": [{"recipient_id": "inv-9", "name": "基金", "jurisdiction": "SG"}],
                "allowed_statements": ["s"],
                "jurisdictions": ["SG"],
                "field_policy": {"reveal_paths": ["analysis.result.conclusion"]},
                "expires_at": self.expires,
            })

    def test_issue_requires_active_sealing_key(self) -> None:
        # 停用全部封签密钥后，签发必须被阻止而不是产出无来源证明的披露包。
        self.connection.execute("UPDATE sealing_keys SET state='retired'")
        with self.assertRaises(InvalidState):
            self._issue(package_id="disc-no-key")


if __name__ == "__main__":
    unittest.main()
