"""Tests for the NotificationModule component."""

import pytest
from datetime import datetime

from components.notification_module import NotificationModule
from models.aws_models import GuardDutyFinding, MockAWSPayload, WAFPayload
from models.ioc_models import (
    CryptoWalletIoC,
    IoCCategory,
    MuleBankAccountIoC,
    PhishingDomainIoC,
    PhoneNumberIoC,
    WalletType,
)


@pytest.fixture
def module():
    return NotificationModule()


@pytest.fixture
def phishing_ioc():
    return PhishingDomainIoC(
        category=IoCCategory.PHISHING_DOMAIN,
        extracted_value="evil.com",
        source_message="Visit evil.com for free money",
        domain="evil.com",
        original_form="evil[.]com",
    )


@pytest.fixture
def crypto_ioc():
    return CryptoWalletIoC(
        category=IoCCategory.CRYPTOCURRENCY_WALLET,
        extracted_value="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        source_message="Send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        wallet_type=WalletType.BITCOIN_BASE58,
        address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    )


@pytest.fixture
def mule_ioc():
    return MuleBankAccountIoC(
        category=IoCCategory.MULE_BANK_ACCOUNT,
        extracted_value="Chase 123456789 021000021",
        source_message="Send to Chase account 123456789 routing 021000021",
        bank_name="Chase",
        account_number="123456789",
        routing_number="021000021",
    )


@pytest.fixture
def phone_ioc():
    return PhoneNumberIoC(
        category=IoCCategory.PHONE_NUMBER,
        extracted_value="+14155551234",
        source_message="Call me at +1 415-555-1234",
        e164_number="+14155551234",
        original_form="+1 415-555-1234",
    )


class TestGenerateNotificationRouting:
    """Tests for IoC routing to the correct payload generator."""

    def test_phishing_domain_routes_to_waf(self, module, phishing_ioc):
        result = module.generate_notification(phishing_ioc)
        assert result.payload_type == "waf_ipset_update"
        assert result.severity == "HIGH"
        assert "evil.com" in result.summary

    def test_crypto_wallet_routes_to_guardduty_high(self, module, crypto_ioc):
        result = module.generate_notification(crypto_ioc)
        assert result.payload_type == "guardduty_finding"
        assert result.severity == "HIGH"
        assert result.raw_payload["Type"] == "CryptoCurrency:EC2/BitcoinTool.B"
        assert result.raw_payload["Severity"] == 7.0

    def test_mule_account_routes_to_guardduty_critical(self, module, mule_ioc):
        result = module.generate_notification(mule_ioc)
        assert result.payload_type == "guardduty_finding"
        assert result.severity == "CRITICAL"
        assert (
            result.raw_payload["Type"]
            == "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
        )
        assert result.raw_payload["Severity"] == 9.0

    def test_phone_number_routes_to_guardduty_medium(self, module, phone_ioc):
        result = module.generate_notification(phone_ioc)
        assert result.payload_type == "guardduty_finding"
        assert result.severity == "MEDIUM"
        assert result.raw_payload["Type"] == "Recon:EC2/PortProbeUnprotectedPort"
        assert result.raw_payload["Severity"] == 5.0


class TestGenerateWafPayload:
    """Tests for WAF payload generation."""

    def test_waf_payload_has_correct_name(self, module, phishing_ioc):
        payload = module.generate_waf_payload(phishing_ioc)
        assert payload.Name == "RoadBlock-PhishingDomains"

    def test_waf_payload_has_regional_scope(self, module, phishing_ioc):
        payload = module.generate_waf_payload(phishing_ioc)
        assert payload.Scope == "REGIONAL"

    def test_waf_payload_addresses_contains_domain(self, module, phishing_ioc):
        payload = module.generate_waf_payload(phishing_ioc)
        assert payload.Addresses == ["evil.com"]

    def test_waf_payload_has_uuid_id(self, module, phishing_ioc):
        payload = module.generate_waf_payload(phishing_ioc)
        # UUID format: 8-4-4-4-12 hex chars
        assert len(payload.Id) == 36
        assert payload.Id.count("-") == 4

    def test_waf_payload_has_uuid_lock_token(self, module, phishing_ioc):
        payload = module.generate_waf_payload(phishing_ioc)
        assert len(payload.LockToken) == 36
        assert payload.LockToken.count("-") == 4


class TestGenerateGuarddutyPayload:
    """Tests for GuardDuty payload generation."""

    def test_guardduty_schema_version(self, module, crypto_ioc):
        finding = module.generate_guardduty_payload(
            crypto_ioc, severity=7.0, finding_type="CryptoCurrency:EC2/BitcoinTool.B"
        )
        assert finding.SchemaVersion == "2.0"

    def test_guardduty_account_id(self, module, crypto_ioc):
        finding = module.generate_guardduty_payload(
            crypto_ioc, severity=7.0, finding_type="CryptoCurrency:EC2/BitcoinTool.B"
        )
        assert finding.AccountId == "123456789012"

    def test_guardduty_region(self, module, crypto_ioc):
        finding = module.generate_guardduty_payload(
            crypto_ioc, severity=7.0, finding_type="CryptoCurrency:EC2/BitcoinTool.B"
        )
        assert finding.Region == "us-east-1"

    def test_guardduty_type_matches_input(self, module, crypto_ioc):
        finding = module.generate_guardduty_payload(
            crypto_ioc, severity=7.0, finding_type="CryptoCurrency:EC2/BitcoinTool.B"
        )
        assert finding.Type == "CryptoCurrency:EC2/BitcoinTool.B"

    def test_guardduty_severity_matches_input(self, module, mule_ioc):
        finding = module.generate_guardduty_payload(
            mule_ioc,
            severity=9.0,
            finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        )
        assert finding.Severity == 9.0

    def test_guardduty_title_contains_ioc_value(self, module, phone_ioc):
        finding = module.generate_guardduty_payload(
            phone_ioc,
            severity=5.0,
            finding_type="Recon:EC2/PortProbeUnprotectedPort",
        )
        assert phone_ioc.extracted_value in finding.Title

    def test_guardduty_description_contains_category(self, module, crypto_ioc):
        finding = module.generate_guardduty_payload(
            crypto_ioc, severity=7.0, finding_type="CryptoCurrency:EC2/BitcoinTool.B"
        )
        assert "cryptocurrency_wallet" in finding.Description

    def test_guardduty_has_created_at(self, module, crypto_ioc):
        finding = module.generate_guardduty_payload(
            crypto_ioc, severity=7.0, finding_type="CryptoCurrency:EC2/BitcoinTool.B"
        )
        assert isinstance(finding.CreatedAt, datetime)

    def test_guardduty_resource_field(self, module, crypto_ioc):
        finding = module.generate_guardduty_payload(
            crypto_ioc, severity=7.0, finding_type="CryptoCurrency:EC2/BitcoinTool.B"
        )
        assert finding.Resource == {"ResourceType": "Instance"}

    def test_guardduty_service_field(self, module, crypto_ioc):
        finding = module.generate_guardduty_payload(
            crypto_ioc, severity=7.0, finding_type="CryptoCurrency:EC2/BitcoinTool.B"
        )
        assert finding.Service == {"ServiceName": "guardduty"}


class TestMockAWSPayloadWrapper:
    """Tests for the MockAWSPayload wrapper returned by generate_notification."""

    def test_payload_has_timestamp(self, module, phishing_ioc):
        result = module.generate_notification(phishing_ioc)
        assert isinstance(result.timestamp, datetime)

    def test_payload_raw_payload_is_dict(self, module, crypto_ioc):
        result = module.generate_notification(crypto_ioc)
        assert isinstance(result.raw_payload, dict)

    def test_payload_summary_is_descriptive(self, module, mule_ioc):
        result = module.generate_notification(mule_ioc)
        assert len(result.summary) > 10
