from __future__ import annotations

import unittest
from pathlib import Path

from cooperation_assurance.acceptance import run


ROOT = Path(__file__).resolve().parents[1]


class AcceptanceTests(unittest.TestCase):
    def test_offline_acceptance(self) -> None:
        result = run(ROOT)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["observation_count"], 6)
        self.assertEqual(result["schema"]["missing_tables"], [])
        self.assertEqual(result["conclusion"], "pass")
        self.assertEqual(result["decision"], "approved")
        self.assertEqual(len(result["input_sha256"]), 64)
        # 三类接收主体各获得一份冻结、封签且遮蔽承诺有效的披露包，范围互不相同。
        disclosures = result["disclosures"]
        self.assertEqual({item["package_id"] for item in disclosures}, {
            "disc-investor", "disc-regulator", "disc-assessor"})
        for item in disclosures:
            self.assertTrue(item["digest_valid"])
            self.assertTrue(item["signature_valid"])
            self.assertTrue(item["commitments_valid"])
            self.assertTrue(item["anchors_valid"])
        self.assertEqual(len({item["scope_fingerprint"] for item in disclosures}), 3)
        # 撤回后已交付事实保留；重签未改变监管包摘要。
        self.assertEqual(result["ledger_summary"]["disc-investor"]["state"], "revoked")
        self.assertEqual(result["ledger_summary"]["disc-investor"]["delivered"], 1)
        self.assertTrue(result["ledger_summary"]["disc-regulator"]["scope_unchanged"])


if __name__ == "__main__":
    unittest.main()
