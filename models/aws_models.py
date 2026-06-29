"""Mock AWS payload models for GuardDuty findings and WAF IP set updates."""

from datetime import datetime
from typing import Any
import uuid

from pydantic import BaseModel, ConfigDict, Field


class MockAWSPayload(BaseModel):
    """Wrapper model for mock AWS notification payloads."""

    model_config = ConfigDict(frozen=True)

    payload_type: str  # "guardduty_finding" or "waf_ipset_update"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: str
    summary: str
    raw_payload: dict[str, Any]


class WAFPayload(BaseModel):
    """Mock AWS WAF UpdateIPSet payload for phishing domain blocking."""

    model_config = ConfigDict(frozen=True)

    Name: str = "RoadBlock-PhishingDomains"
    Scope: str = "REGIONAL"
    Id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    Addresses: list[str]
    LockToken: str = Field(default_factory=lambda: str(uuid.uuid4()))


class GuardDutyFinding(BaseModel):
    """Mock AWS GuardDuty finding payload for IoC-triggered alerts."""

    model_config = ConfigDict(frozen=True)

    SchemaVersion: str = "2.0"
    AccountId: str = "123456789012"
    Region: str = "us-east-1"
    Type: str
    Resource: dict[str, Any] = Field(
        default_factory=lambda: {"ResourceType": "Instance"}
    )
    Service: dict[str, Any] = Field(
        default_factory=lambda: {"ServiceName": "guardduty"}
    )
    Severity: float
    Title: str
    Description: str
    CreatedAt: datetime = Field(default_factory=datetime.utcnow)
