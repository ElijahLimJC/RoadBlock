"""Mock AWS notification module for IoC-triggered GuardDuty findings and WAF IP set updates."""

import logging
from datetime import datetime

from models.aws_models import GuardDutyFinding, MockAWSPayload, WAFPayload
from models.ioc_models import (
    BaseIoC,
    CryptoWalletIoC,
    IoCCategory,
    MuleBankAccountIoC,
    PhishingDomainIoC,
    PhoneNumberIoC,
)

logger = logging.getLogger(__name__)


class NotificationModule:
    """Routes extracted IoCs to the appropriate mock AWS payload generator."""

    def generate_notification(self, ioc: BaseIoC) -> MockAWSPayload:
        """
        Route IoC to appropriate payload generator based on category.

        - PhishingDomain → WAF UpdateIPSet payload
        - CryptoWallet → GuardDuty HIGH severity
        - MuleBankAccount → GuardDuty CRITICAL severity
        - PhoneNumber → GuardDuty MEDIUM severity
        """
        try:
            if ioc.category == IoCCategory.PHISHING_DOMAIN:
                assert isinstance(ioc, PhishingDomainIoC)
                waf_payload = self.generate_waf_payload(ioc)
                return MockAWSPayload(
                    payload_type="waf_ipset_update",
                    timestamp=datetime.utcnow(),
                    severity="HIGH",
                    summary=f"WAF IP set update: blocked phishing domain {ioc.domain}",
                    raw_payload=waf_payload.model_dump(),
                )

            elif ioc.category == IoCCategory.CRYPTOCURRENCY_WALLET:
                finding = self.generate_guardduty_payload(
                    ioc,
                    severity=7.0,
                    finding_type="CryptoCurrency:EC2/BitcoinTool.B",
                )
                return MockAWSPayload(
                    payload_type="guardduty_finding",
                    timestamp=datetime.utcnow(),
                    severity="HIGH",
                    summary=(
                        f"GuardDuty finding: cryptocurrency wallet detected"
                        f" {ioc.extracted_value}"
                    ),
                    raw_payload=finding.model_dump(mode="json"),
                )

            elif ioc.category == IoCCategory.MULE_BANK_ACCOUNT:
                finding = self.generate_guardduty_payload(
                    ioc,
                    severity=9.0,
                    finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
                )
                return MockAWSPayload(
                    payload_type="guardduty_finding",
                    timestamp=datetime.utcnow(),
                    severity="CRITICAL",
                    summary=(
                        f"GuardDuty finding: mule bank account detected"
                        f" {ioc.extracted_value}"
                    ),
                    raw_payload=finding.model_dump(mode="json"),
                )

            elif ioc.category == IoCCategory.PHONE_NUMBER:
                finding = self.generate_guardduty_payload(
                    ioc,
                    severity=5.0,
                    finding_type="Recon:EC2/PortProbeUnprotectedPort",
                )
                return MockAWSPayload(
                    payload_type="guardduty_finding",
                    timestamp=datetime.utcnow(),
                    severity="MEDIUM",
                    summary=(
                        f"GuardDuty finding: suspicious phone number detected"
                        f" {ioc.extracted_value}"
                    ),
                    raw_payload=finding.model_dump(mode="json"),
                )

            else:
                logger.warning(f"Unknown IoC category: {ioc.category}")
                raise ValueError(f"Unsupported IoC category: {ioc.category}")

        except Exception as e:
            logger.error(f"Error generating notification for IoC {ioc.id}: {e}")
            raise

    def generate_waf_payload(self, domain_ioc: PhishingDomainIoC) -> WAFPayload:
        """Generate mock AWS WAF UpdateIPSet payload for a phishing domain."""
        try:
            return WAFPayload(
                Name="RoadBlock-PhishingDomains",
                Scope="REGIONAL",
                Addresses=[domain_ioc.domain],
            )
        except Exception as e:
            logger.error(f"Error generating WAF payload for {domain_ioc.domain}: {e}")
            raise

    def generate_guardduty_payload(
        self, ioc: BaseIoC, severity: float, finding_type: str
    ) -> GuardDutyFinding:
        """Generate mock AWS GuardDuty finding payload."""
        try:
            title = f"RoadBlock IoC Alert: {finding_type} — {ioc.extracted_value}"
            description = (
                f"Automated IoC extraction detected a {ioc.category.value} indicator "
                f"(value: {ioc.extracted_value}) from scammer communication. "
                f"Source message context available in session state."
            )

            return GuardDutyFinding(
                SchemaVersion="2.0",
                AccountId="123456789012",
                Region="us-east-1",
                Type=finding_type,
                Severity=severity,
                Title=title,
                Description=description,
            )
        except Exception as e:
            logger.error(
                f"Error generating GuardDuty payload for {ioc.extracted_value}: {e}"
            )
            raise
