from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cooperation_assurance.api import JsonApplication
from cooperation_assurance.clock import FrozenClock
from cooperation_assurance.jsonio import load_json
from cooperation_assurance.service import AssuranceService

ROOT = Path(__file__).resolve().parents[1]


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc))
        self.service = AssuranceService(self.connection, self.clock)
        self.app = JsonApplication(self.service)

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


def _post(app, path, payload, actor=None):
    headers = {"Content-Type": "application/json"}
    if actor:
        headers["X-Actor-Id"] = actor
    return app.handle("POST", path, headers=headers, body=json.dumps(payload).encode("utf-8"))


class DisclosureApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc))
        self.service = AssuranceService(self.connection, self.clock)
        self.app = JsonApplication(self.service)
        for user_id, role in (
            ("operator", "operator"), ("stat", "statistician"),
            ("approver", "approver"), ("auditor", "auditor"), ("compl", "compliance"),
        ):
            self.service.create_user(user_id, user_id, role)
        protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_program("operator", "program-a", "跨境数据服务项目", "牵头机构")
        self.service.register_evidence_revision("operator", "ev-a", "program-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", protocol)
        self.service.create_batch("operator", "batch-a", "demo-cooperation-v1", 1, "ev-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_observations("operator", "batch-a", "key-1", rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 30)
        self.analysis = self.service.complete_job("worker", job["job_id"], "stat")
        self.service.decide("approver", "batch-a", self.analysis["analysis_id"], "approved", "满足规则")

    def tearDown(self) -> None:
        self.connection.close()

    def _issue(self):
        response = _post(self.app, "/signing_keys/rotate", {}, actor="compl")
        self.assertEqual(response.status, 200)
        expires = (self.clock.now() + timedelta(days=30)).isoformat().replace("+00:00", "Z")
        payload = {
            "package_id": "disc-1",
            "batch_id": "batch-a",
            "analysis_id": self.analysis["analysis_id"],
            "decision_id": 1,
            "purpose_code": "due_diligence",
            "purpose_detail": "境外投资人尽职调查",
            "recipient_class": "foreign_investor",
            "recipients": [{"recipient_id": "inv-1", "name": "境外基金", "jurisdiction": "SG"}],
            "allowed_statements": ["项目已通过准入评估"],
            "jurisdictions": ["SG"],
            "field_policy": {"reveal_paths": ["analysis.result.conclusion", "decision.decision"]},
            "expires_at": expires,
        }
        response = _post(self.app, "/disclosure_packages", payload, actor="compl")
        self.assertEqual(response.status, 201, response.body)
        return response.body

    def test_disclosure_http_lifecycle(self) -> None:
        issued = self._issue()
        token = issued["deliveries"][0]["token"]
        read = _post(self.app, "/disclosure_packages/disc-1/read", {
            "recipient_id": "inv-1", "token": token, "jurisdiction": "SG", "attempt_id": "http-1",
        })
        self.assertEqual(read.status, 200)
        self.assertEqual(read.body["payload"]["content"]["analysis"]["result"]["conclusion"], "pass")

        verify = self.app.handle("GET", "/disclosure_packages/disc-1/verify")
        self.assertEqual(verify.status, 200)
        self.assertTrue(verify.body["signature_valid"])

        ledger = self.app.handle(
            "GET", "/disclosure_ledger", headers={"X-Actor-Id": "auditor"})
        self.assertEqual(ledger.status, 200)
        self.assertEqual(len(ledger.body["packages"]), 1)

        revoke = _post(self.app, "/disclosure_packages/disc-1/revoke", {"reason": "终止"}, actor="compl")
        self.assertEqual(revoke.status, 200)
        blocked = _post(self.app, "/disclosure_packages/disc-1/read", {
            "recipient_id": "inv-1", "token": token, "jurisdiction": "SG", "attempt_id": "http-2",
        })
        self.assertEqual(blocked.status, 403)
        self.assertEqual(blocked.body["error"]["code"], "forbidden")

        ledger = self.app.handle(
            "GET", "/disclosure_ledger/packages/disc-1", headers={"X-Actor-Id": "auditor"})
        self.assertEqual(ledger.body["packages"][0]["deny_reasons"], ["revoked"])

    def test_disclosure_routes_require_role(self) -> None:
        response = _post(self.app, "/signing_keys/rotate", {}, actor="operator")
        self.assertEqual(response.status, 403)
        ledger = self.app.handle(
            "GET", "/disclosure_ledger", headers={"X-Actor-Id": "operator"})
        self.assertEqual(ledger.status, 403)


if __name__ == "__main__":
    unittest.main()
