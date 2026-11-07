"""
System telemetry & resource monitor.
Tracks resident RAM usage, 4 GB threshold headroom, CPU consumption,
and model inference latency.
"""
import os
import time
import psutil
from backend.schemas import SystemMetrics

class TelemetryService:
    def __init__(self, ram_limit_mb: float = 4096.0):
        self.ram_limit_mb = ram_limit_mb
        self.process = psutil.Process(os.getpid())
        self.peak_ram_mb = 0.0
        self.last_inference_ms = 0.0
        self.total_tokens_processed = 0
        self.active_model_name = "Local Model"

    def get_process_ram_mb(self) -> float:
        """Get resident set size (RSS) memory in megabytes."""
        try:
            rss_bytes = self.process.memory_info().rss
            mb = rss_bytes / (1024 * 1024)
            if mb > self.peak_ram_mb:
                self.peak_ram_mb = mb
            return round(mb, 2)
        except Exception:
            return 0.0

    def get_system_metrics(self) -> SystemMetrics:
        """Snapshot current resource utilization."""
        current_ram = self.get_process_ram_mb()
        percent_of_4gb = round((current_ram / self.ram_limit_mb) * 100, 1)
        
        try:
            cpu = psutil.cpu_percent(interval=None)
        except Exception:
            cpu = 0.0

        return SystemMetrics(
            process_ram_mb=current_ram,
            ram_percentage_of_4gb=percent_of_4gb,
            cpu_percent=cpu,
            loaded_model=self.active_model_name,
            total_tokens_processed=self.total_tokens_processed,
            model_inference_ms=self.last_inference_ms
        )

    def record_inference_time(self, ms: float):
        self.last_inference_ms = round(ms, 1)

    def add_tokens_processed(self, count: int):
        self.total_tokens_processed += count

    def set_model_name(self, name: str):
        self.active_model_name = name

# Singleton instance
telemetry = TelemetryService()

