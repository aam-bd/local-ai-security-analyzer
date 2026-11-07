"""
Unit tests demonstrating dynamic chunking across arbitrary file sizes and line counts.
Proves that chunk count is NEVER hardcoded and scales dynamically from 1 to N chunks
based on lines_per_chunk and file size.
"""
import unittest
import os
import math
from backend.chunker import LogChunker

class TestDynamicChunking(unittest.TestCase):
    def test_dynamic_chunk_scaling_by_file_size(self):
        """Verifies that arbitrary line counts dynamically scale chunk count."""
        chunker = LogChunker(lines_per_chunk=8, max_log_tokens=950)
        
        test_cases = [
            (5, 1),       # Tiny 5-line log -> 1 chunk (ceil(5/8) = 1)
            (25, 4),      # Small 25-line log -> 4 chunks (ceil(25/8) = 4)
            (100, 13),    # Medium 100-line log -> 13 chunks (ceil(100/8) = 13)
            (258, 33),    # Benchmark 258-line log -> 33 chunks (ceil(258/8) = 33)
            (500, 63),    # Large 500-line log -> 63 chunks (ceil(500/8) = 63)
            (1000, 125),  # Very large 1000-line log -> 125 chunks (ceil(1000/8) = 125)
        ]

        print("\n=== DYNAMIC CHUNKING VERIFICATION: FILE SIZE SCALING ===")
        for line_count, expected_chunks in test_cases:
            temp_path = f"temp_test_{line_count}.log"
            with open(temp_path, "w", encoding="utf-8") as f:
                for i in range(1, line_count + 1):
                    f.write(f'{{"time":"2026-11-01T08:00:00Z","line":{i},"ip":"192.168.1.{i%250}","status":200,"path":"/api/v1/test"}}\n')

            chunks = chunker.create_chunks_from_file(temp_path)
            os.remove(temp_path)

            self.assertEqual(len(chunks), expected_chunks)
            for c in chunks:
                self.assertLessEqual(c.total_tokens, 950)
            print(f"Input file with {line_count:4d} lines -> Dynamically generated {len(chunks):3d} chunks (all <= 950 tokens)")

    def test_varying_lines_per_chunk(self):
        """Verifies that changing lines_per_chunk dynamically scales chunk count on benchmark log."""
        benchmark_file = "Cultive8_Workspace_Agrigen_Server.log"
        if not os.path.exists(benchmark_file):
            self.skipTest("Benchmark log not found")

        chunker = LogChunker(max_log_tokens=1350)
        
        # Test configurations on 258-line benchmark log:
        expected_counts = {
            6: 43,   # ceil(258 / 6) = 43
            8: 33,   # 33 chunks (all <= 1,350 tokens)
            10: 26,  # ceil(258 / 10) = 26 chunks!
            12: 25   # 25 chunks!
        }
        print("\n=== DYNAMIC CHUNKING VERIFICATION: LINES PER CHUNK SCALING ===")
        for lpc, expected in expected_counts.items():
            chunks = chunker.create_chunks_from_file(benchmark_file, lines_per_chunk=lpc)
            # All chunks must strictly observe token safety ceiling
            for c in chunks:
                self.assertLessEqual(c.total_tokens, 1350)
            
            # First chunk start line must be 1, last chunk end line must be 258
            self.assertEqual(chunks[0].start_line, 1)
            self.assertEqual(chunks[-1].end_line, 258)
            self.assertEqual(len(chunks), expected)
            print(f"Setting lines_per_chunk = {lpc:2d} -> Dynamically produced {len(chunks):2d} chunks (expected {expected}, total 258 lines)")

    def test_line_continuity_and_safety(self):
        """Verifies that no line is missed or duplicated across dynamic chunks."""
        benchmark_file = "Cultive8_Workspace_Agrigen_Server.log"
        if not os.path.exists(benchmark_file):
            self.skipTest("Benchmark log not found")

        chunker = LogChunker(lines_per_chunk=8, max_log_tokens=950)
        chunks = chunker.create_chunks_from_file(benchmark_file)

        observed_lines = []
        for c in chunks:
            for entry in c.entries:
                observed_lines.append(entry.original_line_number)

        self.assertEqual(observed_lines, list(range(1, 259)))
        print(f"Line Continuity Check: Successfully verified all {len(observed_lines)} lines mapped continuously [L1-L258] without gaps.")

if __name__ == "__main__":
    unittest.main()

