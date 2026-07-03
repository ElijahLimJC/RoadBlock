"""Email ingestion Pydantic models for RoadBlock scam detection pipeline."""

import re
from datetime import datetime
from typing import Literal, Optional

from models import APP_TIMEZONE

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EmailMessage(BaseModel):
    """Parsed email representation with validated fields per RFC 5322."""

    model_config = ConfigDict(frozen=True)

    sender: str = Field(description="RFC 5322 addr-spec sender address")
    subject: str = Field(
        default="", description="Email subject line (max 998 chars)"
    )
    body: str = Field(
        description="Email body text (non-empty after strip)"
    )
    message_id: str = Field(
        default="", description="RFC 5322 Message-ID header"
    )
    reply_to: str = Field(
        default="", description="Reply-To header address"
    )
    date_header: str = Field(
        default="", description="Date header value"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(APP_TIMEZONE),
        description="When the email was received",
    )

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
            raise ValueError(
                "Body cannot be empty after stripping whitespace"
            )
        if len(v) > 1_000_000:
            raise ValueError("Body exceeds 1,000,000 characters")
        return v


class ClassificationResult(BaseModel):
    """Output of the Scam_Classifier two-stage pipeline."""

    model_config = ConfigDict(frozen=True)

    verdict: Literal["scam", "not_scam"] = Field(
        description="Classification verdict"
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Classification confidence score"
    )
    determining_stage: Literal["stage_1", "stage_2"] = Field(
        description="Which stage determined the verdict"
    )
    matched_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns that matched",
    )
    llm_reasoning: str = Field(
        default="",
        description="LLM reasoning for Stage 2 decisions",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(APP_TIMEZONE),
        description="When classification occurred",
    )
    sender: str = Field(default="", description="Email sender address")
    subject: str = Field(default="", description="Email subject line")


class ScamPattern(BaseModel):
    """A single regex pattern for scam detection with weight and category."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Pattern identifier name")
    regex: str = Field(
        description="Raw regex string (compiled at classifier init)"
    )
    category: Literal[
        "urgency", "financial_lure", "impersonation", "phishing"
    ] = Field(description="Scam category this pattern detects")
    weight: float = Field(
        ge=0.0,
        le=1.0,
        description="Contribution weight to confidence score",
    )


class OutboundEmail(BaseModel):
    """An outbound email message queued for SMTP delivery."""

    model_config = ConfigDict(frozen=True)

    to_address: str = Field(description="Recipient email address")
    subject: str = Field(
        default="",
        description="Email subject (Re: + original, max 255 chars)",
    )
    body: str = Field(description="Email body content")
    in_reply_to: str = Field(
        default="", description="In-Reply-To header value"
    )
    references: str = Field(
        default="", description="References header value"
    )
    status: Literal[
        "pending",
        "pending_retry",
        "sent",
        "failed_permanent",
        "dropped_queue_full",
    ] = Field(default="pending", description="Current delivery status")
    retry_count: int = Field(
        default=0, ge=0, description="Number of delivery attempts"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(APP_TIMEZONE),
        description="When the email was queued",
    )
    last_attempt_at: Optional[datetime] = Field(
        default=None, description="Timestamp of last delivery attempt"
    )

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

    sender_address: str = Field(
        description="Thread originator email address"
    )
    subject: str = Field(default="", description="Thread subject line")
    message_ids: list[str] = Field(
        default_factory=list,
        description="Message-IDs in this thread",
    )
    source_channel: Literal["email"] = Field(
        default="email", description="Communication channel"
    )
    message_count: int = Field(
        default=0, description="Number of messages in thread"
    )
