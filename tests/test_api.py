from __future__ import annotations

import json
import sqlite3
import unittest
from pathlib import Path

from cooperation_assurance.api import JsonApplication
from cooperation_assurance.service import AssuranceService


ROOT2 = Path(__file__).resolve().parents[1]


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(AssuranceService(self.connection))

    def tearDown(self) -> None:
        self.connection.close()

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_json_error_shape(self) -> None:
        response = self.app.handle("POST", "/users", body=b"not-json")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_user_route(self) -> None:
        payload = json.dumps({"user_id": "u1", "display_name": "操作员", "role": "operator"}).encode()
        response = self.app.handle("POST", "/users", body=payload)
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["role"], "operator")


class DisclosureApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.service = AssuranceService(self.connection)
        self.app = JsonApplication(self.service)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.service.register_program("operator", "program-a", "项目", "牵头")
        self.service.register_evidence_revision("operator", "ev-a", "program-a", "1.0", "b" * 64)
        protocol = json.loads((ROOT2 / "fixtures" / "demo_protocol.json").read_text())
        self.service.publish_protocol("stat", protocol)
        self.service.create_batch("operator", "batch-a", "demo-cooperation-v1", 1, "ev-a")
        self.service.start_batch("operator", "batch-a", 1)
        rows = [
            json.loads(line)
            for line in (ROOT2 / "fixtures" / "demo_observations.jsonl").read_text().splitlines()
            if line.strip()
        ]
        self.service.import_observations("operator", "batch-a", "k1", rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 60)
        analysis = self.service.complete_job("worker", job["job_id"], "stat")
        self.analysis_id = analysis["analysis_id"]
        decision = self.service.decide(
            "approver", "batch-a", self.analysis_id, "approved", "通过"
        )
        self.decision_id = self.connection.execute(
            "SELECT decision_id FROM decisions WHERE batch_id='batch-a'"
        ).fetchone()["decision_id"]

    def tearDown(self) -> None:
        self.connection.close()

    def _issue(self, headers=None) -> Response:
        payload = json.dumps({
            "batch_id": "batch-a",
            "analysis_id": self.analysis_id,
            "decision_id": self.decision_id,
            "purpose": "境外投资人尽调",
            "recipient": {"id": "inv-1", "kind": "investor", "jurisdiction": "sg"},
            "allowed_statements": ["项目已完成独立评估"],
            "data_regions": ["CN", "SG"],
            "expires_at": "2027-01-01T00:00:00Z",
        }).encode()
        return self.app.handle(
            "POST", "/disclosures", headers=headers or {"X-Actor-Id": "approver"}, body=payload
        )

    def test_issue_read_verify_and_deny_over_http(self) -> None:
        issued = self._issue()
        self.assertEqual(issued.status, 201)
        package_id = issued.body["package_id"]
        self.assertTrue(issued.body["envelope"]["document"]["program"]["program_id"]["__redacted__"])
        read_body = json.dumps({"recipient_id": "inv-1"}).encode()
        delivered = self.app.handle(
            "POST", f"/disclosures/{package_id}/read", body=read_body
        )
        self.assertEqual(delivered.status, 200)
        self.assertEqual(delivered.body["status"], "active")
        wrong = self.app.handle(
            "POST", f"/disclosures/{package_id}/read",
            body=json.dumps({"recipient_id": "someone-else"}).encode(),
        )
        self.assertEqual(wrong.status, 403)
        self.assertEqual(wrong.body["error"]["code"], "forbidden")
        verified = self.app.handle(
            "GET", f"/disclosures/{package_id}/verify", headers={"X-Actor-Id": "auditor"}
        )
        self.assertEqual(verified.status, 200)
        self.assertTrue(verified.body["signature_valid"])
        revoked = self.app.handle(
            "POST", f"/disclosures/{package_id}/revoke",
            headers={"X-Actor-Id": "approver"},
            body=json.dumps({"reason": "终止"}).encode(),
        )
        self.assertEqual(revoked.status, 200)
        denied = self.app.handle(
            "POST", f"/disclosures/{package_id}/read", body=read_body
        )
        self.assertEqual(denied.status, 403)
        self.assertEqual(denied.body["error"]["code"], "disclosure_denied")
        ledger = self.app.handle(
            "GET", "/disclosures/ledger", headers={"X-Actor-Id": "auditor"}
        )
        self.assertEqual(ledger.status, 200)
        self.assertTrue(ledger.body["scope_integrity"])
        outcomes = [a["outcome"] for a in ledger.body["accesses"]]
        self.assertEqual(outcomes, ["delivered", "denied", "denied"])

    def test_issue_requires_responsibility_role(self) -> None:
        response = self._issue(headers={"X-Actor-Id": "operator"})
        self.assertEqual(response.status, 403)

    def test_jurisdiction_change_blocks_later_read(self) -> None:
        package_id = self._issue().body["package_id"]
        response = self.app.handle(
            "POST", "/jurisdiction_restrictions",
            headers={"X-Actor-Id": "approver"},
            body=json.dumps({"jurisdiction": "SG", "allowed_regions": ["CN"]}).encode(),
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["affected_packages"], [package_id])
        read = self.app.handle(
            "POST", f"/disclosures/{package_id}/read",
            body=json.dumps({"recipient_id": "inv-1"}).encode(),
        )
        self.assertEqual(read.status, 403)


if __name__ == "__main__":
    unittest.main()
