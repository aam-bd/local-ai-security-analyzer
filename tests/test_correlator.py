"""
Unit tests for the Cross-Chunk Correlator.
Verifies multi-stage attack linking across chunks and negative control suppression.
"""
import unittest
from backend.correlator import CrossChunkCorrelator
from backend.chunker import LogEntry
from backend.schemas import SeverityEnum

class TestCrossChunkCorrelator(unittest.TestCase):
    def setUp(self):
        self.correlator = CrossChunkCorrelator()

    def test_multi_stage_brute_force_and_compromise(self):
        """
        Verify that failed logins across early parts, success in late part,
        and data exfiltration are linked into a single CRITICAL finding.
        """
        # Chunk 1: Failed logins
        chunk1_entries = [
            LogEntry(1, '{"time":"2026-11-01T08:00:00Z","client_ip":"1.2.3.4","path":"/api/v1/auth/login","status":401,"username":"admin"}', 30),
            LogEntry(2, '{"time":"2026-11-01T08:05:00Z","client_ip":"1.2.3.4","path":"/api/v1/auth/login","status":401,"username":"admin"}', 30),
            LogEntry(3, '{"time":"2026-11-01T08:10:00Z","client_ip":"1.2.3.4","path":"/api/v1/auth/login","status":401,"username":"admin"}', 30),
        ]
        self.correlator.register_chunk_logs(chunk1_entries)

        # Chunk 2: More failed logins
        chunk2_entries = [
            LogEntry(40, '{"time":"2026-11-01T08:40:00Z","client_ip":"1.2.3.4","path":"/api/v1/auth/login","status":401,"username":"admin"}', 30),
            LogEntry(45, '{"time":"2026-11-01T08:45:00Z","client_ip":"1.2.3.4","path":"/api/v1/auth/login","status":401,"username":"admin"}', 30),
        ]
        self.correlator.register_chunk_logs(chunk2_entries)

        # Chunk 3: Successful login, admin recon, and data export
        chunk3_entries = [
            LogEntry(90, '{"time":"2026-11-01T09:30:00Z","client_ip":"1.2.3.4","path":"/api/v1/auth/login","status":200,"username":"admin","auth_result":"success","session_id":"sess-99"}', 30),
            LogEntry(92, '{"time":"2026-11-01T09:32:00Z","client_ip":"1.2.3.4","path":"/api/v1/admin/users","status":200,"username":"admin"}', 30),
            LogEntry(95, '{"time":"2026-11-01T09:35:00Z","client_ip":"1.2.3.4","path":"/api/v1/workspaces/7/export?format=csv","status":200,"response_bytes":2000000,"username":"admin"}', 30),
        ]
        self.correlator.register_chunk_logs(chunk3_entries)

        report = self.correlator.generate_final_report(
            filename="test.log",
            total_lines=100,
            total_chunks=3,
            total_tokens=300,
            duration_seconds=1.0,
            model_name="test-model",
            peak_ram_mb=50.0
        )

        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.severity, SeverityEnum.CRITICAL)
        self.assertEqual(finding.target_or_id, "1.2.3.4")
        self.assertIn("Distributed Brute Force", finding.attack_type)
        self.assertIn("Exfiltration", finding.attack_type)
        self.assertEqual(finding.evidence_lines, [1, 2, 3, 40, 45, 90, 92, 95])

    def test_negative_control_suppression(self):
        """Verify normal single typo followed by success is NOT flagged as an attack."""
        entries = [
            LogEntry(10, '{"time":"2026-11-01T08:00:00Z","client_ip":"9.9.9.9","path":"/api/v1/auth/login","status":401,"username":"normal.user"}', 30),
            LogEntry(11, '{"time":"2026-11-01T08:00:30Z","client_ip":"9.9.9.9","path":"/api/v1/auth/login","status":200,"username":"normal.user","auth_result":"success"}', 30),
        ]
        self.correlator.register_chunk_logs(entries)

        report = self.correlator.generate_final_report(
            filename="test.log",
            total_lines=20,
            total_chunks=1,
            total_tokens=60,
            duration_seconds=0.1,
            model_name="test-model",
            peak_ram_mb=30.0
        )

        self.assertEqual(len(report.findings), 0)

if __name__ == "__main__":
    unittest.main()

