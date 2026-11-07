"""
Boundary-safe log splitting engine.
Splits log files into chunks respecting the token budget (<= 950 tokens),
preserves 1-based original line numbers, and never cuts log entries across lines.
"""
from typing import List, Generator, Tuple
from dataclasses import dataclass, field
import os
from backend.tokenizer_service import tokenizer

@dataclass
class LogEntry:
    original_line_number: int
    raw_text: str
    tokens: int

@dataclass
class LogChunk:
    chunk_index: int
    total_chunks: int = 1
    start_line: int = 1
    end_line: int = 1
    entries: List[LogEntry] = field(default_factory=list)
    total_tokens: int = 0
    formatted_text: str = ""

    def rebuild_formatted(self):
        """Construct prompt-ready string with ground-truth line prefixes."""
        lines = [f"[L{e.original_line_number}] {e.raw_text}" for e in self.entries]
        self.formatted_text = "\n".join(lines)
        self.total_tokens = tokenizer.count_tokens(self.formatted_text)
        if self.entries:
            self.start_line = self.entries[0].original_line_number
            self.end_line = self.entries[-1].original_line_number

class LogChunker:
    def __init__(self, lines_per_chunk: int = 8, max_log_tokens: int = 950):
        # Primary splitting parameter: lines per chunk (default: 8 lines)
        self.lines_per_chunk = lines_per_chunk
        # Safety token ceiling to strictly protect the 2,048-token context window
        self.max_log_tokens = max_log_tokens

    def stream_entries(self, file_path: str) -> Generator[LogEntry, None, None]:
        """Stream log lines lazily to preserve memory (RAM budget < 4 GB)."""
        line_num = 1
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line_text = raw_line.rstrip("\r\n")
                if line_text.strip():  # Skip empty lines but keep ground-truth line index
                    formatted_line = f"[L{line_num}] {line_text}"
                    token_count = tokenizer.count_tokens(formatted_line)
                    yield LogEntry(
                        original_line_number=line_num,
                        raw_text=line_text,
                        tokens=token_count
                    )
                line_num += 1

    def create_chunks_from_file(self, file_path: str, lines_per_chunk: int = None) -> List[LogChunk]:
        """
        Split a file dynamically into chunks based on lines_per_chunk.
        Total number of chunks is dynamically calculated as ceil(total_lines / lines_per_chunk).
        Token threshold acts as a safety guard for unusually large log lines.
        """
        target_lines = lines_per_chunk if lines_per_chunk is not None else self.lines_per_chunk
        chunks: List[LogChunk] = []
        current_chunk_entries: List[LogEntry] = []
        current_tokens = 0
        chunk_idx = 1

        for entry in self.stream_entries(file_path):
            reached_line_limit = len(current_chunk_entries) >= target_lines
            exceeds_token_limit = (current_tokens + entry.tokens) > self.max_log_tokens

            # Break chunk if line target reached OR token safety threshold exceeded
            if current_chunk_entries and (reached_line_limit or exceeds_token_limit):
                chunk = LogChunk(
                    chunk_index=chunk_idx,
                    entries=current_chunk_entries
                )
                chunk.rebuild_formatted()
                chunks.append(chunk)

                chunk_idx += 1
                current_chunk_entries = [entry]
                current_tokens = entry.tokens
            else:
                current_chunk_entries.append(entry)
                current_tokens += entry.tokens

        # Flush final chunk
        if current_chunk_entries:
            chunk = LogChunk(
                chunk_index=chunk_idx,
                entries=current_chunk_entries
            )
            chunk.rebuild_formatted()
            chunks.append(chunk)

        # Update total_chunks metadata dynamically across all chunks
        total = len(chunks)
        for c in chunks:
            c.total_chunks = total

        return chunks

# Singleton chunker instance with default 8 lines per chunk
chunker = LogChunker(lines_per_chunk=8, max_log_tokens=950)

