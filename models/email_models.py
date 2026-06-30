"""Email ingestion Pydantic models for RoadBlock scam detection pipeline."""

from pydantic import BaseModel, Field, ConfigDict, field_validator
from datetime import datetime
from typing import Literal, Optional
import re


class EmailMessage(BaseModel):
    """Parsed email representation with validated fields per RFC 5322."""

    model_config = ConfigDict(frozen=True)

    sender: str  # RFC 5322 addr-spec, max 254 chars
    subject: str = ""  # max 998 chars
    body: str  # non-empty after strip, max 1_000_000 chars
    message_id: str = ""
    reply_to: str = ""
    date_header: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("sender")
    @classmethod
    def validate_sender_email(cls, v: str) -> str:
        """Validate RFC 5322 addr-spec format with max 254 characters."""
        if len(v) > 254:
            raise ValueError("Sender address exceeds 254 characters")
        # Simplified RFC 5322 addr-spec validation
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Invalid email address format")
        return v

    @field_validator("subject")
    @classmethod
    def validate_subject_length(cls, v: str) -> str:
        """Validate subject does not exceed 998 characters."""
        if len(v) > 998:
            raise ValueError("Subject exceeds 998 characters")
        return v

    @field_validator("body")
    @classmethod
    def validate_body(cls, v: str) -> str:
        """Validate body is non-empty after strip and within 1,000,000 chars."""
        if not v.strip():
            raise ValueError("Body cannot be empty after stripping whitespace")
        if len(v) > 1_000_000:
            raise ValueError("Body exceeds 1,000,000 characters")
        return v


class ClassificationResult(BaseModel):
    """Output of the Scam_Classifier two-stage pipeline."""

    model_config = ConfigDict(frozen=True)

    verdict: Literal["scam", "not_scam"]
    confidence: float = Field(ge=0.0, le=1.0)
    determining_stage: Literal["stage_1", "stage_2"]
    matched_patterns: list[str] = Field(default_factory=list)
    llm_reasoning: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    sender: str = ""
    subject: str = ""


class ScamPattern(BaseModel):
    """A single regex pattern for scam detection with weight and category."""

    model_config = ConfigDict(frozen=True)

    name: str
    regex: str  # Raw regex string (compiled at classifier init)
    category: Literal["urgency", "financial_lure", "impersonation", "phishing"]
    weight: float = Field(ge=0.0, le=1.0)


class OutboundEmail(BaseModel):
    """An outbound email message queued for SMTP delivery."""

    model_config = ConfigDict(frozen=True)

    to_address: str
    subject: str = ""  # "Re: " + original subject, max 255 chars
    body: str
    in_reply_to: str = ""
    references: str = ""
    status: Literal[
        "pending", "pending_retry", "sent", "failed_permanent", "dropped_queue_full"
    ] = "pending"
    retry_count: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_attempt_at: Optional[datetime] = None

    @field_validator("subject")
    @classmethod
    def validate_subject_length(cls, v: str) -> str:
        """Validate outbound subject does not exceed 255 characters."""
        if len(v) > 255:
            raise ValueError("Outbound subject exceeds 255 characters")
        return v


class EmailThreadMetadata(BaseModel):
    """Metadata for tracking email conversation threads by sender."""

    model_config = ConfigDict(frozen=True)

    sender_address: str
    subject: str = ""
    message_ids: list[str] = Field(default_factory=list)
    source_channel: Literal["email"] = "email"
    message_count: int = 0
