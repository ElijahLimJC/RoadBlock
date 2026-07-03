"""IoC Pydantic models for RoadBlock threat intelligence extraction."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from models import APP_TIMEZONE


class IoCCategory(str, Enum):
    """Categories of Indicators of Compromise."""

    CRYPTOCURRENCY_WALLET = "cryptocurrency_wallet"
    PHISHING_DOMAIN = "phishing_domain"
    PHONE_NUMBER = "phone_number"
    MULE_BANK_ACCOUNT = "mule_bank_account"


class WalletType(str, Enum):
    """Cryptocurrency wallet address types."""

    BITCOIN_BASE58 = "bitcoin_base58"
    BITCOIN_BECH32 = "bitcoin_bech32"
    ETHEREUM = "ethereum"


class BaseIoC(BaseModel):
    """Base model for all Indicators of Compromise."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this IoC",
    )
    category: IoCCategory
    extracted_value: str = Field(
        description="The raw extracted indicator value"
    )
    source_message: str = Field(
        description="Source message text containing the IoC"
    )
    extracted_at: datetime = Field(
        default_factory=lambda: datetime.now(APP_TIMEZONE),
        description="Timestamp when IoC was extracted",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        default=1.0,
        description="Confidence score for extraction accuracy",
    )
    lookup_result: Optional["IoCLookupResult"] = None  # noqa: F821


class CryptoWalletIoC(BaseIoC):
    """Cryptocurrency wallet IoC with wallet type and address."""

    category: IoCCategory = IoCCategory.CRYPTOCURRENCY_WALLET
    wallet_type: WalletType = Field(
        description="Type of cryptocurrency wallet"
    )
    address: str = Field(description="The wallet address string")

    @field_validator("address")
    @classmethod
    def validate_address_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Address cannot be empty")
        return v


class PhishingDomainIoC(BaseIoC):
    """Phishing domain IoC with normalized domain and original form."""

    category: IoCCategory = IoCCategory.PHISHING_DOMAIN
    domain: str = Field(description="Normalized domain name")
    original_form: str = Field(
        description="Original defanged form from source"
    )

    @field_validator("domain")
    @classmethod
    def validate_domain_normalized(cls, v: str) -> str:
        if v != v.lower() or v.endswith("."):
            raise ValueError(
                "Domain must be lowercase without trailing dot"
            )
        return v


class PhoneNumberIoC(BaseIoC):
    """Phone number IoC in E.164 format."""

    category: IoCCategory = IoCCategory.PHONE_NUMBER
    e164_number: str = Field(
        description="Phone number in E.164 format"
    )
    original_form: str = Field(
        description="Original form as found in text"
    )

    @field_validator("e164_number")
    @classmethod
    def validate_e164_format(cls, v: str) -> str:
        if not v.startswith("+") or not v[1:].isdigit() or len(v) > 16:
            raise ValueError("Must be valid E.164 format")
        return v


class MuleBankAccountIoC(BaseIoC):
    """Mule bank account IoC with bank name, account number, and routing number."""

    category: IoCCategory = IoCCategory.MULE_BANK_ACCOUNT
    bank_name: str = Field(
        description="Name of the financial institution"
    )
    account_number: str = Field(
        description="Bank account number (4-17 digits)"
    )
    routing_number: str = Field(
        description="ABA routing number (9 digits)"
    )

    @field_validator("routing_number")
    @classmethod
    def validate_aba_checksum(cls, v: str) -> str:
        if len(v) != 9 or not v.isdigit():
            raise ValueError("Routing number must be exactly 9 digits")
        weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
        checksum = sum(int(d) * w for d, w in zip(v, weights))
        if checksum % 10 != 0:
            raise ValueError("Routing number fails ABA checksum")
        return v

    @field_validator("account_number")
    @classmethod
    def validate_account_length(cls, v: str) -> str:
        digits = "".join(c for c in v if c.isdigit())
        if len(digits) < 4 or len(digits) > 17:
            raise ValueError("Account number must be 4-17 digits")
        return v


# Deferred import to avoid circular dependency — IoCLookupResult
# is defined in models/lookup_models.py but referenced as a forward
# ref string annotation in BaseIoC.lookup_result above.
# The model_rebuild() call is performed in lookup_models.py after
# IoCLookupResult is defined.
