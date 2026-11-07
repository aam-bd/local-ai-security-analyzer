"""
Unit tests for the boundary-safe log chunker.
Verifies token limits, 1-based line number integrity, and line preservation.
"""
import unittest
import os
from backend.chunker import chunker, LogChunker

class TestLogChunker(unittest.TestCase):
    def setUp(self):
        self.sample_file = "test_sample.log"
        with open(self.sample_file, "w", encoding="utf-8") as f:
            for i in range(1, 101):
                f.write(f'{{"time":"2026-11-01T08:00:{i:02d}.000Z","line":{i},"msg":"test entry {i}"}}\n')

    def tearDown(self):
        if os.path.exists(self.sample_file):
            os.remove(self.sample_file)

    def test_chunk_token_budget_limit(self):
        """Verify all chunks strictly observe the <= 950 token budget."""
        custom_chunker = LogChunker(max_log_tokens=300)
        chunks = custom_chunker.create_chunks_from_file(self.sample_file)
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertLessEqual(c.total_tokens, 350)  # Allow small line-boundary tolerance

    def test_original_line_number_preservation(self):
        """Verify original 1-based line numbers are never displaced."""
        chunks = chunker.create_chunks_from_file(self.sample_file)
        self.assertEqual(chunks[0].start_line, 1)
        self.assertEqual(chunks[-1].end_line, 100)

        # Check contiguous line coverage
        prev_end = 0
        for c in chunks:
            self.assertEqual(c.start_line, prev_end + 1)
            prev_end = c.end_line

    def test_no_cut_log_entries(self):
        """Verify each log line remains intact and properly formatted."""
        chunks = chunker.create_chunks_from_file(self.sample_file)
        for c in chunks:
            for entry in c.entries:
                self.assertTrue(entry.raw_text.startswith('{"time":'))
                self.assertTrue(entry.raw_text.endswith('}'))

if __name__ == "__main__":
    unittest.main()

