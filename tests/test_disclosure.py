from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cooperation_assurance import disclosure
from cooperation_assurance.clock import FrozenClock
from cooperation_assurance.errors import (
    Conflict,
    DisclosureDenied,
    Forbidden,
    InvalidState,
    NotFound,
    ValidationFailed,
)
from cooperation_assurance.jsonio import canonical_json, load_json
from cooperation_assurance.service import AssuranceService


ROOT = Path(__file__).resolve().parents[1]


class DisclosureFixture:
    def __init__(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = AssuranceService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text().splitlines()
            if line.strip()
        ]
        self.service.register_program("operator", "program-a", "跨境数据服务项目", "牵头机构")
        self.service.register_evidence_revision("operator", "evidence-a", "program-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", protocol)
        self.service.create_batch("operator", "batch-a", "demo-cooperation-v1", 1, "evidence-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_observations("operator", "batch-a", "key-1", rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 30)
        self.analysis = self.service.complete_job("worker", job["job_id"], "stat")
        self.service.decide(
            "approver", "batch-a", self.analysis["analysis_id"], "approved", "满足准入规则"
        )
        decision = self.connection.execute(
            "SELECT decision_id FROM decisions WHERE batch_id='batch-a'"
        ).fetchone()
        self.decision_id = decision["decision_id"]

    def close(self) -> None:
        self.connection.close()

    def issue(
        self,
        *,
        recipient_id: str = "investor-x",
        kind: str = "investor",
        jurisdiction: str = "SG",
        purpose: str = "境外投资人尽调",
        statements=("项目已完成独立评估",),
        regions=("CN", "SG"),
        rules=None,
        expires_at: str = "2026-12-31T23:59:59Z",
    ):
        return self.service.issue_disclosure(
            "approver",
            batch_id="batch-a",
            analysis_id=self.analysis["analysis_id"],
            decision_id=self.decision_id,
            purpose=purpose,
            recipient={"id": recipient_id, "kind": kind, "jurisdiction": jurisdiction},
            allowed_statements=list(statements),
            data_regions=list(regions),
            expires_at=expires_at,
            redaction_rules=rules,
        )


class PureDisclosureTests(unittest.TestCase):
    def test_redaction_replaces_value_with_content_anchor(self) -> None:
        document = {"program": {"program_id": "p1", "program_name": "名", "lead_organization": "牵头"},
                    "evidence": {"revision": "1.0", "content_sha256": "a" * 64},
                    "protocol": {"protocol_id": "pr", "version": 1, "sha256": "c" * 64},
                    "analysis": {"conclusion": "pass", "included_count": 6, "excluded_count": 0,
                                 "aggregate": {}, "rules": [], "strata": {}},
                    "decision": {"decision": "approved", "reason": "r"}}
        redacted = disclosure.apply_redactions(document, ("/program/program_id",))
        marker = redacted["program"]["program_id"]
        self.assertTrue(marker["__redacted__"])
        import hashlib
        self.assertEqual(
            marker["sha256"],
            hashlib.sha256(canonical_json("p1").encode()).hexdigest(),
        )
        self.assertEqual(redacted["program"]["program_name"], "名")
        self.assertEqual(document["program"]["program_id"], "p1")  # 原件不变

    def test_unknown_redaction_path_rejected(self) -> None:
        with self.assertRaises(disclosure.DisclosureError):
            disclosure.normalize_redaction_rules(("/program/secret_bank_account",), "investor")

    def test_scope_fingerprint_stable_but_distinguishes_scope(self) -> None:
        recipient = {"id": "r", "kind": "investor", "jurisdiction": "SG"}
        common = dict(
            purpose="尽调",
            recipient=recipient,
            allowed_statements=("声明一",),
            redaction_rules=("/decision/reason",),
            data_regions=("CN", "SG"),
        )
        first = disclosure.scope_fingerprint(**common)
        # 参数顺序不同不应改变范围指纹。
        reordered = dict(common)
        reordered["allowed_statements"] = ("声明一",)
        self.assertEqual(first, disclosure.scope_fingerprint(**reordered))
        wider = dict(common)
        wider["data_regions"] = ("CN", "SG", "US")
        self.assertNotEqual(first, disclosure.scope_fingerprint(**wider))

    def test_sign_and_verify_roundtrip(self) -> None:
        key = disclosure.generate_signing_key()
        package = {"manifest": {"package_id": "dp-1"}, "document": {"conclusion": "pass"}}
        signature = disclosure.sign_package(package, key)
        self.assertTrue(disclosure.verify_signature(package, signature, key))
        tampered = {"manifest": {"package_id": "dp-1"}, "document": {"conclusion": "fail"}}
        self.assertFalse(disclosure.verify_signature(tampered, signature, key))


class DisclosureServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = DisclosureFixture()
        self.service = self.fixture.service
        self.clock = self.fixture.clock

    def tearDown(self) -> None:
        self.fixture.close()

    def test_tiered_profiles_expose_different_fields(self) -> None:
        investor = self.fixture.issue(kind="investor")
        regulator = self.fixture.issue(
            recipient_id="reg-cn", kind="regulator", jurisdiction="CN",
            purpose="属地监管核查", regions=("CN",), expires_at="2027-01-01T00:00:00Z",
        )
        assessor = self.fixture.issue(
            recipient_id="assessor-1", kind="assessor", jurisdiction="DE",
            purpose="独立评估", expires_at="2027-01-01T00:00:00Z",
        )
        inv_doc = investor["envelope"]["document"]
        reg_doc = regulator["envelope"]["document"]
        ass_doc = assessor["envelope"]["document"]
        # 投资人：商业身份与分层细节遮蔽，但总体结论可见。
        self.assertTrue(inv_doc["program"]["lead_organization"]["__redacted__"])
        self.assertTrue(inv_doc["analysis"]["strata"]["__redacted__"])
        self.assertEqual(inv_doc["analysis"]["conclusion"], "pass")
        # 监管机构：不默认遮蔽任何字段。
        self.assertEqual(reg_doc["program"]["lead_organization"], "牵头机构")
        self.assertIn("verified-channel", reg_doc["analysis"]["strata"])
        # 独立评估方：看得到方法细节，看不到项目商业身份和决定理由。
        self.assertIn("verified-channel", ass_doc["analysis"]["strata"])
        self.assertTrue(ass_doc["program"]["program_name"]["__redacted__"])
        self.assertTrue(ass_doc["decision"]["reason"]["__redacted__"])
        self.assertEqual(ass_doc["decision"]["decision"], "approved")

    def test_package_has_no_internal_identifiers_or_links(self) -> None:
        issued = self.fixture.issue()
        text = canonical_json(issued["envelope"])
        for forbidden in ("batch_id", "analysis_id", "decision_id", "observation_id", "http://", "https://"):
            self.assertNotIn(forbidden, text)

    def test_wrong_recipient_denied_and_recorded(self) -> None:
        issued = self.fixture.issue()
        with self.assertRaises(Forbidden):
            self.service.read_disclosure("intruder", issued["package_id"])
        ledger = self.service.disclosure_ledger("auditor")
        denied = [a for a in ledger["accesses"] if a["outcome"] == "denied"]
        self.assertEqual(denied[0]["recipient_id"], "intruder")
        self.assertIn("不匹配", denied[0]["deny_reason"])

    def test_expiry_blocks_reads_but_keeps_delivered_history(self) -> None:
        issued = self.fixture.issue()
        self.service.read_disclosure("investor-x", issued["package_id"])
        self.clock.advance(days=100)
        with self.assertRaises(DisclosureDenied) as caught:
            self.service.read_disclosure("investor-x", issued["package_id"])
        self.assertIn("到期", caught.exception.reason)
        row = self.service.get_disclosure_envelope("approver", issued["package_id"])
        self.assertEqual(row["status"], "expired")
        # 已交付的冻结摘要仍然保留。
        self.assertEqual(row["envelope"]["document"]["analysis"]["conclusion"], "pass")
        ledger = self.service.disclosure_ledger("auditor")
        outcomes = [a["outcome"] for a in ledger["accesses"]]
        self.assertEqual(outcomes, ["delivered", "denied"])

    def test_revocation_blocks_reads(self) -> None:
        issued = self.fixture.issue()
        self.service.read_disclosure("investor-x", issued["package_id"])
        self.service.revoke_disclosure("approver", issued["package_id"], "尽调终止")
        with self.assertRaises(DisclosureDenied):
            self.service.read_disclosure("investor-x", issued["package_id"])
        with self.assertRaises(InvalidState):
            self.service.revoke_disclosure("approver", issued["package_id"], "再次撤回")

    def test_decision_invalidation_blocks_related_packages(self) -> None:
        issued = self.fixture.issue()
        self.service.invalidate_decision("approver", self.fixture.decision_id, "复议撤销")
        with self.assertRaises(DisclosureDenied) as caught:
            self.service.read_disclosure("investor-x", issued["package_id"])
        self.assertIn("决定", caught.exception.reason)

    def test_jurisdiction_change_blocks_existing_and_new_packages(self) -> None:
        issued = self.fixture.issue()
        affected = self.service.set_jurisdiction_restriction("approver", "SG", ["CN"])
        self.assertEqual(affected["affected_packages"], [issued["package_id"]])
        with self.assertRaises(DisclosureDenied):
            self.service.read_disclosure("investor-x", issued["package_id"])
        with self.assertRaises(ValidationFailed):
            self.fixture.issue()  # SG 接收主体 + SG 驻留不再被允许
        # 收紧后的范围内仍可签发。
        domestic = self.fixture.issue(
            recipient_id="reg-cn", kind="regulator", jurisdiction="CN",
            purpose="属地监管核查", regions=("CN",), expires_at="2027-01-01T00:00:00Z",
        )
        self.assertEqual(domestic["status"], "active")

    def test_retry_is_idempotent_and_resign_keeps_scope(self) -> None:
        issued = self.fixture.issue()
        replay = self.fixture.issue()
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["package_id"], issued["package_id"])
        # 扩大范围（增加驻留区域）产生新的范围指纹，而不是复用旧包。
        wider = self.fixture.issue(regions=("CN", "SG", "US"))
        self.assertFalse(wider["replayed"])
        self.assertNotEqual(wider["package_id"], issued["package_id"])
        self.assertNotEqual(
            wider["envelope"]["manifest"]["scope_sha256"],
            issued["envelope"]["manifest"]["scope_sha256"],
        )
        resigned = self.service.resign_disclosure(
            "approver", issued["package_id"],
            new_expires_at="2027-06-30T23:59:59Z", reason="尽调延期",
        )
        self.service.read_disclosure("investor-x", resigned["package_id"])
        with self.assertRaises(DisclosureDenied):
            self.service.read_disclosure("investor-x", issued["package_id"])
        ledger = self.service.disclosure_ledger("auditor")
        self.assertEqual(len(ledger["resignings"]), 1)
        self.assertTrue(ledger["resignings"][0]["scope_unchanged"])
        self.assertTrue(ledger["scope_integrity"])

    def test_resign_cannot_shorten_validity(self) -> None:
        issued = self.fixture.issue()
        with self.assertRaises(ValidationFailed):
            self.service.resign_disclosure(
                "approver", issued["package_id"],
                new_expires_at="2026-10-01T00:00:00Z", reason="提前",
            )

    def test_verification_detects_tampering_and_confirms_anchors(self) -> None:
        issued = self.fixture.issue()
        verified = self.service.verify_disclosure("auditor", issued["package_id"])
        self.assertTrue(verified["signature_valid"])
        self.assertTrue(verified["package_sha256_match"])
        self.assertTrue(verified["document_sha256_match"])
        self.assertTrue(verified["scope_sha256_match"])
        self.assertTrue(verified["redaction_anchors_verified"])
        self.assertTrue(verified["evidence_anchors_verified"])
        paths = {item["path"] for item in verified["redaction_anchors"]}
        self.assertIn("/program/lead_organization", paths)
        # 篡改冻结信封后内容摘要和签名都必须失配。
        tampered = json.loads(
            self.fixture.connection.execute(
                "SELECT frozen_json FROM disclosure_packages WHERE package_id=?",
                (issued["package_id"],),
            ).fetchone()["frozen_json"]
        )
        tampered["document"]["analysis"]["conclusion"] = "fail"
        self.fixture.connection.execute(
            "UPDATE disclosure_packages SET frozen_json=? WHERE package_id=?",
            (canonical_json(tampered), issued["package_id"]),
        )
        checked = self.service.verify_disclosure("auditor", issued["package_id"])
        self.assertFalse(checked["package_sha256_match"])
        self.assertFalse(checked["document_sha256_match"])

    def test_ledger_answers_who_what_when_why(self) -> None:
        issued = self.fixture.issue()
        self.service.read_disclosure("investor-x", issued["package_id"])
        ledger = self.service.disclosure_ledger("auditor")
        entry = ledger["delivered_view"][0]
        self.assertEqual(entry["recipient_id"], "investor-x")
        self.assertEqual(entry["purpose"], "境外投资人尽调")
        self.assertEqual(len(entry["document_sha256"]), 64)
        self.assertIn("/program/lead_organization", entry["redaction_rules"])
        self.assertEqual(entry["accessed_at"], "2026-09-24T08:00:00Z")

    def test_role_separation(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.issue_disclosure(
                "operator",
                batch_id="batch-a", analysis_id=self.fixture.analysis["analysis_id"],
                decision_id=self.fixture.decision_id, purpose="x",
                recipient={"id": "r", "kind": "investor", "jurisdiction": "SG"},
                allowed_statements=["s"], data_regions=["CN"],
                expires_at="2027-01-01T00:00:00Z",
            )
        with self.assertRaises(Forbidden):
            self.service.disclosure_ledger("operator")
        with self.assertRaises(Forbidden):
            self.service.verify_disclosure("approver", "whatever")

    def test_missing_package_and_expired_issuance_rejected(self) -> None:
        with self.assertRaises(NotFound):
            self.service.read_disclosure("investor-x", "dp-nope")
        with self.assertRaises(ValidationFailed):
            self.fixture.issue(expires_at="2026-01-01T00:00:00Z")

    def test_ledger_shows_effective_expiry_without_read(self) -> None:
        issued = self.fixture.issue(expires_at="2026-09-30T00:00:00Z")
        self.clock.advance(days=10)
        # 到期后从未读取：存储状态不变，但台账生效状态必须反映到期。
        stored = self.fixture.connection.execute(
            "SELECT status FROM disclosure_packages WHERE package_id=?", (issued["package_id"],)
        ).fetchone()["status"]
        self.assertEqual(stored, "active")
        ledger = self.service.disclosure_ledger("auditor")
        package = next(p for p in ledger["packages"] if p["package_id"] == issued["package_id"])
        self.assertEqual(package["effective_status"], "expired")
        self.assertEqual(package["status"], "active")

    def test_key_rotation_keeps_old_signatures_valid(self) -> None:
        issued = self.fixture.issue()
        self.service.rotate_disclosure_key("approver")
        verified = self.service.verify_disclosure("auditor", issued["package_id"])
        self.assertTrue(verified["signature_valid"])
        later = self.fixture.issue(
            recipient_id="investor-y", purpose="另一项尽调",
            expires_at="2027-01-01T00:00:00Z",
        )
        self.assertTrue(
            self.service.verify_disclosure("auditor", later["package_id"])["signature_valid"]
        )

    def test_invalidating_twice_conflicts(self) -> None:
        self.service.invalidate_decision("approver", self.fixture.decision_id, "撤销")
        with self.assertRaises(Conflict):
            self.service.invalidate_decision("approver", self.fixture.decision_id, "再次撤销")


if __name__ == "__main__":
    unittest.main()
