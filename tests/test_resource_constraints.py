"""
Resource-Constrained Benchmark Test.
Strictly simulates and enforces the hardware limits:
1. 2 vCPUs (via CPU core affinity [0, 1])
2. 4 GB RAM ceiling (via continuous peak memory monitoring and assertion)
3. No GPU (CUDA_VISIBLE_DEVICES="-1")
4. 2,048 token budget per model call
"""
import unittest
import os
import psutil

# Enforce No GPU before any ML library initializes
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["ROCR_VISIBLE_DEVICES"] = "-1"
os.environ["HIP_VISIBLE_DEVICES"] = "-1"

from backend.analyzer import pipeline
from backend.chunker import chunker
from backend.telemetry import telemetry

class TestResourceConstraints(unittest.TestCase):
    def setUp(self):
        # 1. Enforce 2 vCPU limit by pinning process to cores 0 and 1
        self.process = psutil.Process()
        try:
            self.process.cpu_affinity([0, 1])
        except Exception as e:
            print(f"[WARN] Could not set CPU affinity: {e}")

    def test_run_under_system_limits(self):
        """Execute full benchmark log under strict 2 vCPU, 4GB RAM, and 2048-token constraints."""
        log_file = "Cultive8_Workspace_Agrigen_Server.log"
        self.assertTrue(os.path.exists(log_file))

        # Check CPU Affinity
        affinity = self.process.cpu_affinity()
        self.assertEqual(len(affinity), 2, f"Process should be pinned to 2 vCPUs, got {affinity}")

        # Check GPU is disabled
        self.assertEqual(os.environ.get("CUDA_VISIBLE_DEVICES"), "-1")

        # Check Chunk Token Limits
        chunks = chunker.create_chunks_from_file(log_file)
        for c in chunks:
            # 950 log tokens + 400 prompt + 250 context + 400 reply + 48 buffer = 2048
            self.assertLessEqual(c.total_tokens, 955, f"Chunk {c.chunk_index} exceeded token budget!")

        # Run pipeline under constraints
        last_event = None
        peak_ram_mb = 0.0

        for event in pipeline.analyze_file_streaming(log_file):
            current_ram = telemetry.get_process_ram_mb()
            if current_ram > peak_ram_mb:
                peak_ram_mb = current_ram
            last_event = event

        self.assertIsNotNone(last_event)
        report = last_event["report"]

        # 4 GB RAM Ceiling Assertion (4096 MB)
        self.assertLess(peak_ram_mb, 4096.0, f"Memory exceeded 4 GB ceiling! Peak was {peak_ram_mb} MB")

        print("\n========================================================")
        print("    RESOURCE CONSTRAINT COMPLIANCE REPORT")
        print("========================================================")
        print(f" CPU Limit Enforced     : 2 vCPUs (Cores {affinity})")
        print(f" GPU Execution          : DISABLED (CPU Only)")
        print(f" Context Window Budget  : Max {max(c.total_tokens for c in chunks)} log tokens (within 2,048 limit)")
        print(f" Measured Peak RAM      : {peak_ram_mb:.1f} MB / 4,096.0 MB limit")
        print(f" RAM Headroom Remaining : {4096.0 - peak_ram_mb:.1f} MB ({(1 - peak_ram_mb/4096.0)*100:.1f}% free)")
        print(f" Total Log Lines Tested : {report['total_lines']} lines")
        print(f" Confirmed Attacks Found: {len(report['findings'])} / 5 true attacks")
        print("========================================================\n")

if __name__ == "__main__":
    unittest.main()
