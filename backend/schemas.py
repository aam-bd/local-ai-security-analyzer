from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum

class SeverityEnum(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class EvidenceItem(BaseModel):
    line_number: int
    timestamp: Optional[str] = None
    raw_snippet: str

class Finding(BaseModel):
    id: str
    attack_type: str
    severity: SeverityEnum
    target_or_id: str
    evidence: List[EvidenceItem] = Field(default_factory=list)
    evidence_lines: List[int] = Field(default_factory=list)
    reason: str
    suggested_action: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

class SuspectEntity(BaseModel):
    ip: str
    failed_logins: int = 0
    successful_logins: int = 0
    usernames: List[str] = Field(default_factory=list)
    suspicious_paths: List[str] = Field(default_factory=list)
    sqli_attempts: int = 0
    traversal_attempts: int = 0
    rapid_requests: int = 0
    prompt_injections: int = 0
    line_numbers: List[int] = Field(default_factory=list)
    status: str = "observing"

class CarriedState(BaseModel):
    suspects: Dict[str, SuspectEntity] = Field(default_factory=dict)
    total_lines_analyzed: int = 0
    active_attack_chains: List[str] = Field(default_factory=list)

class ChunkAnalysisResult(BaseModel):
    chunk_index: int
    total_chunks: int
    start_line: int
    end_line: int
    token_count: int
    findings: List[Finding] = Field(default_factory=list)
    carried_state: Dict[str, Any] = Field(default_factory=dict)
    inference_time_ms: float = 0.0
    status: str = "completed"

class SystemMetrics(BaseModel):
    process_ram_mb: float
    ram_percentage_of_4gb: float
    cpu_percent: float
    loaded_model: str
    total_tokens_processed: int
    model_inference_ms: float = 0.0

class AnalysisReport(BaseModel):
    filename: str
    total_lines: int
    total_chunks: int
    total_tokens: int
    total_duration_seconds: float
    findings: List[Finding] = Field(default_factory=list)
    summary_counts: Dict[str, int] = Field(
        default_factory=lambda: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Total": 0}
    )
    peak_ram_mb: float = 0.0
    model_used: str = "Local Model"
    status: str = "completed"
