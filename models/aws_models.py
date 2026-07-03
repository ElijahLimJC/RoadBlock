"""Mock AWS payload models for GuardDuty findings and WAF IP set updates."""

import uuid
from datetime import datetime
from models import APP_TIMEZONE
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MockAWSPayload(BaseModel):
    """Wrapper model for mock AWS notification payloads."""

    model_config = ConfigDict(frozen=True)

    payload_type: str = Field(
        description="Type of AWS payload (guardduty_finding or waf_ipset_update)"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(APP_TIMEZONE),
        description="When the payload was generated",
    )
    severity: str = Field(
        description="Severity level (CRITICAL, HIGH, MEDIUM, LOW)"
    )
    summary: str = Field(
        description="Human-readable summary of the notification"
    )
    raw_payload: dict[str, Any] = Field(
        description="Raw AWS-format payload data"
    )


class WAFPayload(BaseModel):
    """Mock AWS WAF UpdateIPSet payload for phishing domain blocking."""

    model_config = ConfigDict(frozen=True)

    Name: str = Field(
        default="RoadBlock-PhishingDomains",
        description="WAF IP set name",
    )
    Scope: str = Field(
        default="REGIONAL",
        description="WAF scope (REGIONAL or CLOUDFRONT)",
    )
    Id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique IP set identifier",
    )
    Addresses: list[str] = Field(description="List of addresses to block")
    LockToken: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Optimistic concurrency lock token",
    )


class GuardDutyFinding(BaseModel):
    """Mock AWS GuardDuty finding payload for IoC-triggered alerts."""

    model_config = ConfigDict(frozen=True)

    SchemaVersion: str = Field(
        default="2.0", description="GuardDuty schema version"
    )
    AccountId: str = Field(
        default="123456789012", description="AWS account ID"
    )
    Region: str = Field(default="us-east-1", description="AWS region")
    Type: str = Field(description="GuardDuty finding type")
    Resource: dict[str, Any] = Field(
        default_factory=lambda: {"ResourceType": "Instance"},
        description="Affected AWS resource",
    )
    Service: dict[str, Any] = Field(
        default_factory=lambda: {"ServiceName": "guardduty"},
        description="Service that generated the finding",
    )
    Severity: float = Field(description="Numeric severity score (0-10)")
    Title: str = Field(description="Finding title")
    Description: str = Field(description="Detailed finding description")
    CreatedAt: datetime = Field(
        default_factory=lambda: datetime.now(APP_TIMEZONE),
        description="When the finding was created",
    )
