"""
Log Analysis Pipeline Coordinator.
Sequentially processes log chunks, updates working memory, streams progress,
supports checkpointing to resume after restart, and produces the final unified report.
"""
import os
import time
from typing import Generator, Dict, Any, Optional
from backend.chunker import chunker, LogChunk
from backend.correlator import CrossChunkCorrelator
from backend.model_manager import model_manager
from backend.telemetry import telemetry
from backend.schemas import AnalysisReport, ChunkAnalysisResult

class LogAnalyzerPipeline:
    def __init__(self):
        self.active_correlator: Optional[CrossChunkCorrelator] = None
        self.last_report: Optional[AnalysisReport] = None
        self.checkpoint_state: Dict[str, Any] = {}

    def analyze_file_streaming(
        self,
        file_path: str,
        resume_from_chunk: int = 1,
        reduce_calls: bool = False
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Streams chunk-by-chunk progress events and yields the final report.
        Supports resume_from_chunk and optional call reduction optimization.
        """
        start_time = time.perf_counter()
        filename = os.path.basename(file_path)

        # 1. Split into token-bounded chunks
        chunks = chunker.create_chunks_from_file(file_path)
        total_chunks = len(chunks)
        total_lines = chunks[-1].end_line if chunks else 0
        total_tokens = sum(c.total_tokens for c in chunks)

        telemetry.add_tokens_processed(total_tokens)

        # 2. Initialize or resume Correlator
        if resume_from_chunk <= 1 or not self.active_correlator:
            self.active_correlator = CrossChunkCorrelator()
            carried_state = {}
        else:
            carried_state = self.active_correlator.get_carried_state_summary()

        yield {
            "type": "start",
            "filename": filename,
            "total_chunks": total_chunks,
            "total_lines": total_lines,
            "total_tokens": total_tokens,
            "model": model_manager.current_model_name,
            "ram_mb": telemetry.get_process_ram_mb(),
            "reduced_calls_mode": reduce_calls
        }

        model_calls_made = 0
        model_calls_saved = 0

        # 3. Process each chunk sequentially (one model call at a time)
        for idx, chunk in enumerate(chunks, start=1):
            if idx < resume_from_chunk:
                continue

            # Register logs into correlator graph
            self.active_correlator.register_chunk_logs(chunk.entries)

            # Check if chunk can be fast-pathed to reduce model calls
            active_suspects = set(carried_state.get("suspects", {}).keys())
            can_skip_model = reduce_calls and self._is_benign_chunk(chunk.entries, active_suspects)

            if can_skip_model:
                model_calls_saved += 1
                chunk_result = {
                    "findings": [],
                    "suspect_updates": [],
                    "inference_time_ms": 0.5,
                    "skipped_call": True
                }
            else:
                model_calls_made += 1
                # Invoke local model with carried state
                chunk_result = model_manager.analyze_chunk(
                    formatted_logs=chunk.formatted_text,
                    carried_state=carried_state,
                    chunk_index=chunk.chunk_index,
                    total_chunks=total_chunks
                )
                chunk_result["skipped_call"] = False

            # Ingest findings into correlator
            self.active_correlator.ingest_model_findings(chunk_result.get("findings", []))

            # Update carried state for the next chunk
            carried_state = self.active_correlator.get_carried_state_summary()

            # Save checkpoint
            self.checkpoint_state = {
                "file_path": file_path,
                "last_chunk": idx,
                "total_chunks": total_chunks,
                "model_calls_made": model_calls_made,
                "model_calls_saved": model_calls_saved
            }

            # Yield progress event
            yield {
                "type": "chunk_progress",
                "chunk_index": idx,
                "total_chunks": total_chunks,
                "start_line": chunk.start_line,
                "end_line": chunk.end_line,
                "tokens": chunk.total_tokens,
                "inference_time_ms": chunk_result.get("inference_time_ms", 0.0),
                "ram_mb": telemetry.get_process_ram_mb(),
                "active_suspects": len(carried_state.get("suspects", {})) if carried_state else 0,
                "skipped_call": chunk_result.get("skipped_call", False),
                "calls_saved": model_calls_saved
            }

        # 4. Generate Unified Final Security Report
        total_duration = time.perf_counter() - start_time
        final_report = self.active_correlator.generate_final_report(
            filename=filename,
            total_lines=total_lines,
            total_chunks=total_chunks,
            total_tokens=total_tokens,
            duration_seconds=total_duration,
            model_name=model_manager.current_model_name,
            peak_ram_mb=telemetry.peak_ram_mb
        )
        self.last_report = final_report

        yield {
            "type": "complete",
            "report": final_report.model_dump()
        }

    def _is_benign_chunk(self, entries: list, active_suspects: set) -> bool:
        """Heuristic check: if chunk contains only normal 200/304 status on static paths without suspects."""
        suspicious_markers = [
            "400", "401", "403", "404", "422", "429", "500", "502", "503",
            "error", "warn", "or 1=1", "union", "../", "..%2f", "%252e", "ignore previous", "admin"
        ]
        for e in entries:
            text = e.raw_text.lower()
            if any(ip in text for ip in active_suspects):
                return False
            if any(marker in text for marker in suspicious_markers):
                return False
        return True

        yield {
            "type": "complete",
            "report": final_report.model_dump()
        }

pipeline = LogAnalyzerPipeline()

