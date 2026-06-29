"""IoC Pydantic models for RoadBlock threat intelligence extraction."""

from pydantic import BaseModel, Field, field_validator, ConfigDict
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


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

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: IoCCategory
    extracted_value: str
    source_message: str
    extracted_at: datetime = Field(default_factory=datetime.utcnow)
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    lookup_result: Optional["IoCLookupResult"] = None  # Populated after MCP lookup


class CryptoWalletIoC(BaseIoC):
    """Cryptocurrency wallet IoC with wallet type and address."""

    category: IoCCategory = IoCCategory.CRYPTOCURRENCY_WALLET
    wallet_type: WalletType
    address: str

    @field_validator("address")
    @classmethod
    def validate_address_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Address cannot be empty")
        return v


class PhishingDomainIoC(BaseIoC):
    """Phishing domain IoC with normalized domain and original form."""

    category: IoCCategory = IoCCategory.PHISHING_DOMAIN
    domain: str
    original_form: str  # Before defanging reversal

    @field_validator("domain")
    @classmethod
    def validate_domain_normalized(cls, v: str) -> str:
        if v != v.lower() or v.endswith("."):
            raise ValueError("Domain must be lowercase without trailing dot")
        return v


class PhoneNumberIoC(BaseIoC):
    """Phone number IoC in E.164 format."""

    category: IoCCategory = IoCCategory.PHONE_NUMBER
    e164_number: str  # +{country_code}{subscriber_number}
    original_form: str

    @field_validator("e164_number")
    @classmethod
    def validate_e164_format(cls, v: str) -> str:
        if not v.startswith("+") or not v[1:].isdigit() or len(v) > 16:
            raise ValueError("Must be valid E.164 format")
        return v


class MuleBankAccountIoC(BaseIoC):
    """Mule bank account IoC with bank name, account number, and routing number."""

    category: IoCCategory = IoCCategory.MULE_BANK_ACCOUNT
    bank_name: str
    account_number: str
    routing_number: str

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


# Forward reference for BaseIoC.lookup_result
# This will be properly defined in models/lookup_models.py
# For now, use a placeholder to avoid circular imports
class IoCLookupResult(BaseModel):
    """Placeholder for IoC lookup result — full definition in models/lookup_models.py."""

    ioc_value: str = ""
    ioc_category: IoCCategory = IoCCategory.CRYPTOCURRENCY_WALLET
    lookup_status: str = "unknown"
    is_known: bool = False


# Rebuild models to resolve forward references
BaseIoC.model_rebuild()
