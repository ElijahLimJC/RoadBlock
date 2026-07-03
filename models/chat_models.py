"""Chat and session models for RoadBlock pipeline."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from models import APP_TIMEZONE
from models.ioc_models import BaseIoC, IoCCategory


class ChatMessage(BaseModel):
    """A single message in the conversation history."""

    model_config = ConfigDict(frozen=True)

    sender: Literal["scammer", "persona"] = Field(
        description="Message sender role"
    )
    content: str = Field(description="Message text content")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(APP_TIMEZONE),
        description="When the message was sent",
    )
    was_sanitized: bool = Field(
        default=False, description="Whether input was sanitized"
    )
    was_blocked: bool = Field(
        default=False,
        description="Whether message was blocked by safety filter",
    )


class SessionMetrics(BaseModel):
    """Stalling metrics for the active session. Mutable for turn tracking."""

    model_config = ConfigDict(frozen=False)  # Mutable: requires turn count updates

    turn_count: int = Field(
        default=0, description="Number of conversation turns completed"
    )
    start_time: Optional[datetime] = Field(
        default=None, description="Timestamp of first scammer message"
    )
    last_message_time: Optional[datetime] = Field(
        default=None, description="Timestamp of most recent message"
    )

    def total_time_wasted_seconds(self) -> int:
        """Calculate elapsed wall-clock seconds between first and last scammer message."""
        if self.start_time is None or self.last_message_time is None:
            return 0
        return int(
            (self.last_message_time - self.start_time).total_seconds()
        )

    def formatted_time_wasted(self) -> str:
        """Return Total Scammer Time Wasted as 'HH:MM:SS'."""
        total = self.total_time_wasted_seconds()
        hours, remainder = divmod(total, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


class RejectionLogEntry(BaseModel):
    """A rejected IoC candidate with the reason for rejection."""

    model_config = ConfigDict(frozen=True)

    candidate: str = Field(
        description="The raw candidate string that was rejected"
    )
    rejection_reason: str = Field(
        description="Reason the candidate was rejected"
    )
    ioc_category: IoCCategory = Field(
        description="IoC category the candidate was evaluated for"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(APP_TIMEZONE),
        description="When the rejection occurred",
    )


class ExtractionResult(BaseModel):
    """Output of ThreatParser.extract_iocs() — validated IoCs and rejections."""

    model_config = ConfigDict(frozen=True)

    iocs: list[BaseIoC] = Field(
        default_factory=list,
        description="List of validated IoC instances",
    )
    rejections: list[RejectionLogEntry] = Field(
        default_factory=list,
        description="List of rejected candidates with reasons",
    )


class ScanResult(BaseModel):
    """Output of SafetyFilter.scan() — contains sanitized content and detection metadata."""

    model_config = ConfigDict(frozen=True)

    sanitized_content: str = Field(
        description="Content after sanitization processing"
    )
    detected_patterns: list[str] = Field(
        default_factory=list,
        description="Names of detected injection patterns",
    )
    is_blocked: bool = Field(
        default=False,
        description="True when >=80% tokens are injection",
    )


class PersonaResponse(BaseModel):
    """Output of PersonaEngine.generate_response()."""

    model_config = ConfigDict(frozen=True)

    content: str = Field(description="Generated persona response text")
    is_fallback: bool = Field(
        default=False,
        description="True if this was a pre-written fallback response",
    )
    stalling_tactic_used: Optional[str] = Field(
        default=None,
        description="Name of the stalling tactic employed",
    )
    generation_time_ms: Optional[float] = Field(
        default=None,
        description="Time taken to generate response in milliseconds",
    )


# Trigger model_rebuild for forward reference resolution
import models.lookup_models  # noqa: E402, F401
