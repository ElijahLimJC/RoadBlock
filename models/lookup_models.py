"""MCP IoC lookup result models for the RoadBlock pipeline."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from models.ioc_models import IoCCategory


class LookupStatus(str, Enum):
    """Status of an IoC lookup against the MCP threat intelligence server."""

    KNOWN = "known"
    NEW = "new"
    UNKNOWN = "unknown"  # MCP server unreachable or timed out


class IoCLookupResult(BaseModel):
    """Result of looking up an IoC against the MCP threat intelligence database."""

    model_config = ConfigDict(frozen=True)

    ioc_value: str
    ioc_category: IoCCategory
    lookup_status: LookupStatus
    is_known: bool = False
    first_seen: Optional[datetime] = None
    times_reported: int = 0
    reporting_sources: list[str] = Field(default_factory=list)
    severity_assessment: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    lookup_timestamp: datetime = Field(default_factory=datetime.utcnow)
    lookup_duration_ms: Optional[float] = None  # For performance tracking
