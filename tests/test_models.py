"""Property-based tests for Pydantic model serialization round-trips.

Validates: Requirements 3.4, 6.6, 10.6
"""

from datetime import datetime
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from models.ioc_models import (
    CryptoWalletIoC,
    IoCCategory,
    MuleBankAccountIoC,
    PhishingDomainIoC,
    PhoneNumberIoC,
    WalletType,
)
from models.aws_models import MockAWSPayload


# ---------------------------------------------------------------------------
# Hypothesis strategies for generating valid model instances
# ---------------------------------------------------------------------------

# Strategy for non-empty stripped strings (used for addresses, etc.)
non_empty_text = st.text(
    alphabet=st.characters(categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=50,
).filter(lambda s: len(s.strip()) > 0)

# Strategy for generating valid datetime values
valid_datetimes = st.datetimes(
    min_value=datetime(2000, 1, 1),
    max_value=datetime(2030, 12, 31),
)

# Strategy for confidence values
confidence_values = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)


@st.composite
def crypto_wallet_iocs(draw: st.DrawFn) -> CryptoWalletIoC:
    """Generate valid CryptoWalletIoC instances."""
    wallet_type = draw(st.sampled_from(WalletType))
    # Address must be non-empty after stripping
    address = draw(
        st.text(
            alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            min_size=1,
            max_size=62,
        )
    )
    return CryptoWalletIoC(
        category=IoCCategory.CRYPTOCURRENCY_WALLET,
        wallet_type=wallet_type,
        address=address,
        extracted_value=address,
        source_message=draw(non_empty_text),
        extracted_at=draw(valid_datetimes),
        confidence=draw(confidence_values),
    )


@st.composite
def phishing_domain_iocs(draw: st.DrawFn) -> PhishingDomainIoC:
    """Generate valid PhishingDomainIoC instances.

    Domain must be lowercase with no trailing dot.
    """
    # Generate a valid-ish domain: lowercase labels separated by dots
    label_chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    label = st.text(
        alphabet=st.sampled_from(label_chars),
        min_size=1,
        max_size=20,
    )

    labels = draw(st.lists(label, min_size=2, max_size=4))
    domain = ".".join(labels)
    # Ensure no trailing dot and is lowercase (already lowercase from charset)
    domain = domain.rstrip(".")

    return PhishingDomainIoC(
        category=IoCCategory.PHISHING_DOMAIN,
        domain=domain,
        original_form=draw(non_empty_text),
        extracted_value=domain,
        source_message=draw(non_empty_text),
        extracted_at=draw(valid_datetimes),
        confidence=draw(confidence_values),
    )


@st.composite
def phone_number_iocs(draw: st.DrawFn) -> PhoneNumberIoC:
    """Generate valid PhoneNumberIoC instances.

    e164_number must start with + followed by digits, max 16 chars total.
    """
    # Generate digits for the number (1-15 digits after the +)
    digit_count = draw(st.integers(min_value=1, max_value=15))
    digits = draw(
        st.text(
            alphabet=st.sampled_from("0123456789"),
            min_size=digit_count,
            max_size=digit_count,
        )
    )
    e164_number = f"+{digits}"

    return PhoneNumberIoC(
        category=IoCCategory.PHONE_NUMBER,
        e164_number=e164_number,
        original_form=draw(non_empty_text),
        extracted_value=e164_number,
        source_message=draw(non_empty_text),
        extracted_at=draw(valid_datetimes),
        confidence=draw(confidence_values),
    )


@st.composite
def valid_aba_routing_numbers(draw: st.DrawFn) -> str:
    """Generate a valid 9-digit ABA routing number that passes checksum.

    Weights: [3, 7, 1, 3, 7, 1, 3, 7, 1], sum mod 10 == 0.
    We generate the first 8 digits and calculate the 9th to satisfy the checksum.
    """
    weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    first_8 = draw(
        st.text(
            alphabet=st.sampled_from("0123456789"),
            min_size=8,
            max_size=8,
        )
    )
    # Calculate partial sum for first 8 digits
    partial_sum = sum(int(d) * w for d, w in zip(first_8, weights[:8]))
    # Find the 9th digit such that (partial_sum + digit * 1) % 10 == 0
    # Weight for position 9 is 1
    remainder = partial_sum % 10
    ninth_digit = (10 - remainder) % 10
    return first_8 + str(ninth_digit)


@st.composite
def mule_bank_account_iocs(draw: st.DrawFn) -> MuleBankAccountIoC:
    """Generate valid MuleBankAccountIoC instances.

    routing_number: exactly 9 digits passing ABA checksum.
    account_number: 4-17 digit characters.
    """
    routing_number = draw(valid_aba_routing_numbers())

    # Account number: 4-17 digits
    account_length = draw(st.integers(min_value=4, max_value=17))
    account_number = draw(
        st.text(
            alphabet=st.sampled_from("0123456789"),
            min_size=account_length,
            max_size=account_length,
        )
    )

    bank_name = draw(non_empty_text)

    return MuleBankAccountIoC(
        category=IoCCategory.MULE_BANK_ACCOUNT,
        bank_name=bank_name,
        account_number=account_number,
        routing_number=routing_number,
        extracted_value=f"{bank_name} {account_number}",
        source_message=draw(non_empty_text),
        extracted_at=draw(valid_datetimes),
        confidence=draw(confidence_values),
    )


@st.composite
def mock_aws_payloads(draw: st.DrawFn) -> MockAWSPayload:
    """Generate valid MockAWSPayload instances.

    raw_payload must be a dict.
    """
    payload_type = draw(st.sampled_from(["guardduty_finding", "waf_ipset_update"]))
    severity = draw(st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
    summary = draw(non_empty_text)
    # Generate a simple JSON-serializable dict for raw_payload
    raw_payload: dict[str, Any] = draw(
        st.dictionaries(
            keys=st.text(
                alphabet=st.characters(categories=("L",)),
                min_size=1,
                max_size=10,
            ),
            values=st.one_of(
                st.text(min_size=0, max_size=20),
                st.integers(min_value=-1000, max_value=1000),
                st.booleans(),
                st.floats(allow_nan=False, allow_infinity=False),
            ),
            min_size=0,
            max_size=5,
        )
    )

    return MockAWSPayload(
        payload_type=payload_type,
        timestamp=draw(valid_datetimes),
        severity=severity,
        summary=summary,
        raw_payload=raw_payload,
    )


# ---------------------------------------------------------------------------
# Property 7: IoC Pydantic Model Round-Trip Serialization
# ---------------------------------------------------------------------------


class TestRoundTripSerialization:
    """Property 7: IoC Pydantic Model Round-Trip Serialization.

    **Validates: Requirements 3.4, 6.6, 10.6**

    For any valid IoC instance or MockAWSPayload, serializing the model to JSON
    and deserializing back SHALL produce an object with identical field values.
    """

    @given(instance=crypto_wallet_iocs())
    @settings(max_examples=200)
    def test_crypto_wallet_ioc_round_trip(self, instance: CryptoWalletIoC) -> None:
        """CryptoWalletIoC survives JSON round-trip serialization."""
        json_str = instance.model_dump_json()
        restored = CryptoWalletIoC.model_validate_json(json_str)
        assert restored == instance

    @given(instance=phishing_domain_iocs())
    @settings(max_examples=200)
    def test_phishing_domain_ioc_round_trip(self, instance: PhishingDomainIoC) -> None:
        """PhishingDomainIoC survives JSON round-trip serialization."""
        json_str = instance.model_dump_json()
        restored = PhishingDomainIoC.model_validate_json(json_str)
        assert restored == instance

    @given(instance=phone_number_iocs())
    @settings(max_examples=200)
    def test_phone_number_ioc_round_trip(self, instance: PhoneNumberIoC) -> None:
        """PhoneNumberIoC survives JSON round-trip serialization."""
        json_str = instance.model_dump_json()
        restored = PhoneNumberIoC.model_validate_json(json_str)
        assert restored == instance

    @given(instance=mule_bank_account_iocs())
    @settings(max_examples=200)
    def test_mule_bank_account_ioc_round_trip(
        self, instance: MuleBankAccountIoC
    ) -> None:
        """MuleBankAccountIoC survives JSON round-trip serialization."""
        json_str = instance.model_dump_json()
        restored = MuleBankAccountIoC.model_validate_json(json_str)
        assert restored == instance

    @given(instance=mock_aws_payloads())
    @settings(max_examples=200)
    def test_mock_aws_payload_round_trip(self, instance: MockAWSPayload) -> None:
        """MockAWSPayload survives JSON round-trip serialization."""
        json_str = instance.model_dump_json()
        restored = MockAWSPayload.model_validate_json(json_str)
        assert restored == instance


# ---------------------------------------------------------------------------
# Property 12: ABA Routing Number Checksum Validation
# ---------------------------------------------------------------------------


class TestABARoutingNumberChecksum:
    """Property 12: ABA Routing Number Checksum Validation.

    **Validates: Requirements 6.2**

    For any 9-digit string, MuleBankAccountIoC SHALL accept it as a valid
    routing number if and only if sum(digit[i] * weight[i]) % 10 == 0
    where weights are [3, 7, 1, 3, 7, 1, 3, 7, 1].
    """

    ABA_WEIGHTS = [3, 7, 1, 3, 7, 1, 3, 7, 1]

    def _is_valid_aba(self, routing: str) -> bool:
        """Compute expected ABA checksum validity."""
        return sum(int(d) * w for d, w in zip(routing, self.ABA_WEIGHTS)) % 10 == 0

    def _build_mule_account(self, routing_number: str) -> MuleBankAccountIoC:
        """Build a MuleBankAccountIoC with a given routing number and valid defaults."""
        return MuleBankAccountIoC(
            extracted_value=f"account-{routing_number}",
            source_message="test message",
            bank_name="Test Bank",
            account_number="123456789",
            routing_number=routing_number,
        )

    @given(routing=st.text(alphabet="0123456789", min_size=9, max_size=9))
    @settings(max_examples=200)
    def test_aba_checksum_acceptance(self, routing: str) -> None:
        """MuleBankAccountIoC accepts iff ABA checksum passes."""
        expected_valid = self._is_valid_aba(routing)

        if expected_valid:
            model = self._build_mule_account(routing)
            assert model.routing_number == routing
        else:
            with pytest.raises(ValidationError) as exc_info:
                self._build_mule_account(routing)
            assert "ABA checksum" in str(exc_info.value) or "routing" in str(
                exc_info.value
            ).lower()


# ---------------------------------------------------------------------------
# Property 18: Notification Routing Correctness
# ---------------------------------------------------------------------------


class TestNotificationRoutingProperty:
    """Property 18: Notification Routing Correctness.

    **Validates: Requirements 10.1, 10.2, 10.3, 10.4**

    For any valid IoC, the Notification_Module SHALL generate a payload with
    the correct severity and finding type:
    - PhishingDomain → WAF payload (payload_type="waf_ipset_update", severity="HIGH")
    - CryptoWallet → GuardDuty HIGH, Type "CryptoCurrency:EC2/BitcoinTool.B"
    - MuleBankAccount → GuardDuty CRITICAL, Type "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
    - PhoneNumber → GuardDuty MEDIUM, Type "Recon:EC2/PortProbeUnprotectedPort"
    """

    @given(ioc=phishing_domain_iocs())
    @settings(max_examples=200)
    def test_phishing_domain_routes_to_waf_payload(
        self, ioc: PhishingDomainIoC
    ) -> None:
        """PhishingDomainIoC generates a WAF IP set update with severity HIGH."""
        from components.notification_module import NotificationModule

        module = NotificationModule()
        payload = module.generate_notification(ioc)

        assert payload.payload_type == "waf_ipset_update"
        assert payload.severity == "HIGH"

    @given(ioc=crypto_wallet_iocs())
    @settings(max_examples=200)
    def test_crypto_wallet_routes_to_guardduty_high(
        self, ioc: CryptoWalletIoC
    ) -> None:
        """CryptoWalletIoC generates GuardDuty finding with HIGH severity and correct Type."""
        from components.notification_module import NotificationModule

        module = NotificationModule()
        payload = module.generate_notification(ioc)

        assert payload.payload_type == "guardduty_finding"
        assert payload.severity == "HIGH"
        assert payload.raw_payload["Type"] == "CryptoCurrency:EC2/BitcoinTool.B"
        assert payload.raw_payload["Severity"] == 7.0

    @given(ioc=mule_bank_account_iocs())
    @settings(max_examples=200)
    def test_mule_bank_account_routes_to_guardduty_critical(
        self, ioc: MuleBankAccountIoC
    ) -> None:
        """MuleBankAccountIoC generates GuardDuty finding with CRITICAL severity."""
        from components.notification_module import NotificationModule

        module = NotificationModule()
        payload = module.generate_notification(ioc)

        assert payload.payload_type == "guardduty_finding"
        assert payload.severity == "CRITICAL"
        assert (
            payload.raw_payload["Type"]
            == "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
        )
        assert payload.raw_payload["Severity"] == 9.0

    @given(ioc=phone_number_iocs())
    @settings(max_examples=200)
    def test_phone_number_routes_to_guardduty_medium(
        self, ioc: PhoneNumberIoC
    ) -> None:
        """PhoneNumberIoC generates GuardDuty finding with MEDIUM severity."""
        from components.notification_module import NotificationModule

        module = NotificationModule()
        payload = module.generate_notification(ioc)

        assert payload.payload_type == "guardduty_finding"
        assert payload.severity == "MEDIUM"
        assert (
            payload.raw_payload["Type"] == "Recon:EC2/PortProbeUnprotectedPort"
        )
        assert payload.raw_payload["Severity"] == 5.0
