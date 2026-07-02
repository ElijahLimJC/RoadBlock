"""MCP IoC lookup result models for the RoadBlock pipeline."""

from datetime import datetime, timezone
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

    ioc_value: str = Field(
        description="The IoC value that was looked up"
    )
    ioc_category: IoCCategory = Field(
        description="Category of the IoC"
    )
    lookup_status: LookupStatus = Field(
        description="Result status from threat intel lookup"
    )
    is_known: bool = Field(
        default=False,
        description="Whether the IoC is already known in threat intel",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="When the IoC was first observed",
    )
    times_reported: int = Field(
        default=0,
        description="Number of times this IoC has been reported",
    )
    reporting_sources: list[str] = Field(
        default_factory=list,
        description="Sources that reported this IoC",
    )
    severity_assessment: Optional[str] = Field(
        default=None, description="Assessed severity level"
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Classification tags for this IoC",
    )
    lookup_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the lookup was performed",
    )
    lookup_duration_ms: Optional[float] = Field(
        default=None,
        description="Lookup duration in milliseconds for performance tracking",
    )


# Resolve forward reference in BaseIoC.lookup_result now that
# IoCLookupResult is defined.
from models.ioc_models import (  # noqa: E402
    BaseIoC,
    CryptoWalletIoC,
    MuleBankAccountIoC,
    PhishingDomainIoC,
    PhoneNumberIoC,
)

BaseIoC.model_rebuild()
CryptoWalletIoC.model_rebuild()
PhishingDomainIoC.model_rebuild()
PhoneNumberIoC.model_rebuild()
MuleBankAccountIoC.model_rebuild()
