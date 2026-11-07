"""
End-to-End Accuracy & Benchmark Validation Test.
Validates detection of all 5 attack vectors and 0 false positives on Cultive8_Workspace_Agrigen_Server.log.
"""
import unittest
import os
from backend.analyzer import pipeline
from backend.schemas import SeverityEnum

class TestBenchmarkAccuracy(unittest.TestCase):
    def test_full_pipeline_on_benchmark_log(self):
        log_file = "Cultive8_Workspace_Agrigen_Server.log"
        self.assertTrue(os.path.exists(log_file), "Benchmark log file missing")

        # Run streaming pipeline
        last_event = None
        for event in pipeline.analyze_file_streaming(log_file):
            last_event = event

        self.assertIsNotNone(last_event)
        self.assertEqual(last_event["type"], "complete")
        report = last_event["report"]

        # 1. Total chunks and lines
        self.assertEqual(report["total_lines"], 258)
        self.assertGreater(report["total_chunks"], 15)

        # 2. Check summary counts
        findings = report["findings"]
        findings_by_ip = {f["target_or_id"]: f for f in findings}

        # 5 True Attack Vectors must be detected:
        # Attack 1: 203.0.113.44 (Brute Force + Account Compromise + Exfiltration)
        self.assertIn("203.0.113.44", findings_by_ip)
        f_bf = findings_by_ip["203.0.113.44"]
        self.assertEqual(f_bf["severity"], "Critical")
        self.assertIn("Exfiltration", f_bf["attack_type"])
        # Must link failed logins (e.g. 5, 13, 23, 50...) and successful login (196) and exfil (201)
        self.assertIn(196, f_bf["evidence_lines"])
        self.assertIn(201, f_bf["evidence_lines"])
        self.assertIn(5, f_bf["evidence_lines"])

        # Attack 2: 203.0.113.72 (SQL Injection)
        self.assertIn("203.0.113.72", findings_by_ip)
        f_sqli = findings_by_ip["203.0.113.72"]
        self.assertEqual(f_sqli["severity"], "High")
        self.assertIn("SQL Injection", f_sqli["attack_type"])
        self.assertIn(29, f_sqli["evidence_lines"])
        self.assertIn(30, f_sqli["evidence_lines"])
        self.assertIn(32, f_sqli["evidence_lines"])
        self.assertIn(222, f_sqli["evidence_lines"])

        # Attack 3: 203.0.113.90 (Path Traversal & Reconnaissance)
        self.assertIn("203.0.113.90", findings_by_ip)
        f_trav = findings_by_ip["203.0.113.90"]
        self.assertEqual(f_trav["severity"], "High")
        self.assertIn(54, f_trav["evidence_lines"])
        self.assertIn(99, f_trav["evidence_lines"])
        self.assertIn(101, f_trav["evidence_lines"])

        # Attack 4: 203.0.113.155 (Rate Limiting / DoS burst)
        self.assertIn("203.0.113.155", findings_by_ip)
        f_dos = findings_by_ip["203.0.113.155"]
        self.assertEqual(f_dos["severity"], "Medium")
        self.assertIn(162, f_dos["evidence_lines"])

        # Attack 5: 203.0.113.201 (Prompt Injection / Log Poisoning)
        self.assertIn("203.0.113.201", findings_by_ip)
        f_inj = findings_by_ip["203.0.113.201"]
        self.assertIn(217, f_inj["evidence_lines"])

        # NEGATIVE CONTROLS VERIFICATION:
        # User field.officer typo (198.51.100.96) must NOT be an attack finding!
        self.assertNotIn("198.51.100.96", findings_by_ip)

        # Health monitor (192.0.2.10) must NOT be an attack finding!
        self.assertNotIn("192.0.2.10", findings_by_ip)

        # Total confirmed attacks should be exactly 5
        self.assertEqual(len(findings), 5)
        print(f"[TEST PASS] Successfully verified 5 confirmed attacks and 0 false positives on benchmark log!")

if __name__ == "__main__":
    unittest.main()
