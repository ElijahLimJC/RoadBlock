"""Chat and session models for RoadBlock pipeline."""

from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import Optional

from models.ioc_models import IoCCategory, BaseIoC


class ChatMessage(BaseModel):
    """A single message in the conversation history."""

    model_config = ConfigDict(frozen=True)

    sender: str  # "scammer" or "persona"
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    was_sanitized: bool = False
    was_blocked: bool = False


class SessionMetrics(BaseModel):
    """Stalling metrics for the active session. Mutable for turn tracking."""

    turn_count: int = 0
    start_time: Optional[datetime] = None
    last_message_time: Optional[datetime] = None

    def total_time_wasted_seconds(self) -> int:
        """Calculate elapsed wall-clock seconds between first and last scammer message."""
        if self.start_time is None or self.last_message_time is None:
            return 0
        return int((self.last_message_time - self.start_time).total_seconds())

    def formatted_time_wasted(self) -> str:
        """Return Total Scammer Time Wasted as 'HH:MM:SS'."""
        total = self.total_time_wasted_seconds()
        hours, remainder = divmod(total, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


class RejectionLogEntry(BaseModel):
    """A rejected IoC candidate with the reason for rejection."""

    model_config = ConfigDict(frozen=True)

    candidate: str
    rejection_reason: str
    ioc_category: IoCCategory
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ExtractionResult(BaseModel):
    """Output of ThreatParser.extract_iocs() — validated IoCs and rejections."""

    iocs: list[BaseIoC] = []
    rejections: list[RejectionLogEntry] = []


class ScanResult(BaseModel):
    """Output of SafetyFilter.scan() — contains sanitized content and detection metadata."""

    model_config = ConfigDict(frozen=True)

    sanitized_content: str
    detected_patterns: list[str] = []  # Names of detected injection patterns
    is_blocked: bool = False  # True when ≥80% tokens are injection


class PersonaResponse(BaseModel):
    """Output of PersonaEngine.generate_response()."""

    model_config = ConfigDict(frozen=True)

    content: str
    is_fallback: bool = False  # True if this was a pre-written fallback response
    stalling_tactic_used: Optional[str] = None
    generation_time_ms: Optional[float] = None
