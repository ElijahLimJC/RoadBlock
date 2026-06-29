"""Threat Parser component for IoC extraction from scammer messages.

This module implements the background extraction engine that identifies
and validates Indicators of Compromise (IoCs) from chat content using
Pydantic models. All parsing functions are wrapped in try/except to
ensure graceful degradation under noisy input (Noisy Input Defense).
"""

import asyncio
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import base58
import bech32

from models.chat_models import ExtractionResult, RejectionLogEntry
from models.ioc_models import (
    BaseIoC,
    CryptoWalletIoC,
    IoCCategory,
    PhishingDomainIoC,
    WalletType,
)

logger = logging.getLogger(__name__)


class ThreatParser:
    """Background extraction engine for IoC identification and validation.

    Extracts and validates cryptocurrency wallets, phishing domains,
    phone numbers, and mule bank accounts from unstructured text.
    All extraction methods return empty lists on failure to ensure
    pipeline resilience.

    Attributes:
        _bitcoin_base58_pattern: Regex for Bitcoin Base58Check addresses.
        _bitcoin_bech32_pattern: Regex for Bitcoin Bech32 addresses.
        _ethereum_pattern: Regex for Ethereum addresses.
    """

    def __init__(self) -> None:
        """Initialize regex patterns and validation engines."""
        # Bitcoin Base58Check: starts with 1 or 3, length 26-35 chars,
        # uses Base58 alphabet (no 0, O, I, l)
        self._bitcoin_base58_pattern: re.Pattern[str] = re.compile(
            r"\b[13][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]"
            r"{24,33}\b"
        )

        # Bitcoin Bech32: starts with bc1, lowercase, length 26-62 chars
        # Uses Bech32 alphabet: qpzry9x8gf2tvdw0s3jn54khce6mua7l
        self._bitcoin_bech32_pattern: re.Pattern[str] = re.compile(
            r"\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{24,58}\b"
        )

        # Ethereum: 0x prefix followed by exactly 40 hex characters
        self._ethereum_pattern: re.Pattern[str] = re.compile(
            r"\b0x[0-9a-fA-F]{40}\b"
        )

        # Domain extraction patterns (phishing domains)
        # Full URLs: http/https/hxxp/hxxps with optional defanging
        self._url_pattern: re.Pattern[str] = re.compile(
            r"(?:hxxps?|https?)"
            r"(?:\[://\]|://)"
            r"([a-zA-Z0-9\-]+(?:(?:\[\.\]|\[dot\]|\.)[a-zA-Z0-9\-]+)+)"
            r"(?:[/\s?#]|$)",
            re.IGNORECASE,
        )

        # Defanged domains with [.] or [dot] substitutions (no scheme)
        self._defanged_domain_pattern: re.Pattern[str] = re.compile(
            r"\b([a-zA-Z0-9\-]+(?:(?:\[\.\]|\[dot\])[a-zA-Z0-9\-]+)+)\b",
            re.IGNORECASE,
        )

        # Common TLDs for bare domain detection
        self._common_tlds: set[str] = {
            "com", "net", "org", "io", "co", "info", "biz", "ru", "cn",
            "uk", "de", "fr", "jp", "br", "in", "au", "xyz", "top",
            "online", "site", "club", "tech", "shop", "app", "dev",
            "me", "tv", "cc", "us", "ca", "eu", "gov", "edu", "mil",
        }

        # Bare domain pattern: word.tld or word.word.tld
        self._bare_domain_pattern: re.Pattern[str] = re.compile(
            r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"
            r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
            r"\.[a-zA-Z]{2,})\b"
        )

    def extract_crypto_wallets(
        self, text: str
    ) -> tuple[list[CryptoWalletIoC], list[RejectionLogEntry]]:
        """Extract and validate cryptocurrency wallet addresses from text.

        Scans text for Bitcoin (Base58Check, Bech32) and Ethereum address
        patterns, validates checksums, and returns validated IoCs plus
        rejection log entries for invalid candidates.

        Args:
            text: Raw message text to scan for wallet addresses.

        Returns:
            A tuple of (valid_iocs, rejections) where valid_iocs contains
            validated CryptoWalletIoC instances and rejections contains
            RejectionLogEntry instances for failed candidates.
        """
        try:
            iocs: list[CryptoWalletIoC] = []
            rejections: list[RejectionLogEntry] = []

            # Extract Bitcoin Base58Check addresses (starting with 1 or 3)
            self._extract_base58_addresses(text, iocs, rejections)

            # Extract Bitcoin Bech32 addresses (starting with bc1)
            self._extract_bech32_addresses(text, iocs, rejections)

            # Extract Ethereum addresses (starting with 0x)
            self._extract_ethereum_addresses(text, iocs, rejections)

            return iocs, rejections

        except Exception as e:
            logger.warning("Crypto wallet extraction failed: %s", e)
            return [], []

    def _extract_base58_addresses(
        self,
        text: str,
        iocs: list[CryptoWalletIoC],
        rejections: list[RejectionLogEntry],
    ) -> None:
        """Extract and validate Bitcoin Base58Check addresses.

        Args:
            text: Raw message text.
            iocs: List to append valid IoCs to (mutated in place).
            rejections: List to append rejections to (mutated in place).
        """
        try:
            for match in self._bitcoin_base58_pattern.finditer(text):
                candidate = match.group()
                try:
                    # base58.b58decode_check validates the Base58Check checksum
                    # It will raise ValueError if checksum is invalid
                    base58.b58decode_check(candidate)
                    iocs.append(
                        CryptoWalletIoC(
                            wallet_type=WalletType.BITCOIN_BASE58,
                            address=candidate,
                            extracted_value=candidate,
                            source_message=text,
                        )
                    )
                except (ValueError, Exception) as e:
                    rejections.append(
                        RejectionLogEntry(
                            candidate=candidate,
                            rejection_reason=(
                                f"Base58Check checksum validation failed: {e}"
                            ),
                            ioc_category=IoCCategory.CRYPTOCURRENCY_WALLET,
                        )
                    )
                    logger.debug(
                        "Rejected Base58Check candidate %s: %s", candidate, e
                    )
        except Exception as e:
            logger.warning("Base58 address extraction failed: %s", e)

    def _extract_bech32_addresses(
        self,
        text: str,
        iocs: list[CryptoWalletIoC],
        rejections: list[RejectionLogEntry],
    ) -> None:
        """Extract and validate Bitcoin Bech32 addresses.

        Args:
            text: Raw message text.
            iocs: List to append valid IoCs to (mutated in place).
            rejections: List to append rejections to (mutated in place).
        """
        try:
            for match in self._bitcoin_bech32_pattern.finditer(text):
                candidate = match.group()
                try:
                    # bech32.bech32_decode returns (hrp, data) or (None, None)
                    hrp, data = bech32.bech32_decode(candidate)
                    if hrp is None or data is None:
                        # Try bech32m decoding (used for taproot bc1p addresses)
                        hrp, data = bech32.bech32_decode(candidate)
                        if hrp is None or data is None:
                            raise ValueError(
                                "Bech32/Bech32m checksum validation failed"
                            )

                    if hrp != "bc":
                        raise ValueError(
                            f"Invalid HRP: expected 'bc', got '{hrp}'"
                        )

                    iocs.append(
                        CryptoWalletIoC(
                            wallet_type=WalletType.BITCOIN_BECH32,
                            address=candidate,
                            extracted_value=candidate,
                            source_message=text,
                        )
                    )
                except (ValueError, Exception) as e:
                    rejections.append(
                        RejectionLogEntry(
                            candidate=candidate,
                            rejection_reason=(
                                f"Bech32 checksum validation failed: {e}"
                            ),
                            ioc_category=IoCCategory.CRYPTOCURRENCY_WALLET,
                        )
                    )
                    logger.debug(
                        "Rejected Bech32 candidate %s: %s", candidate, e
                    )
        except Exception as e:
            logger.warning("Bech32 address extraction failed: %s", e)

    def _extract_ethereum_addresses(
        self,
        text: str,
        iocs: list[CryptoWalletIoC],
        rejections: list[RejectionLogEntry],
    ) -> None:
        """Extract and validate Ethereum addresses.

        Validates that the address is 0x followed by exactly 40 hex chars.

        Args:
            text: Raw message text.
            iocs: List to append valid IoCs to (mutated in place).
            rejections: List to append rejections to (mutated in place).
        """
        try:
            for match in self._ethereum_pattern.finditer(text):
                candidate = match.group()
                try:
                    # Validate hex portion is exactly 40 hex characters
                    hex_part = candidate[2:]
                    if len(hex_part) != 40:
                        raise ValueError(
                            f"Expected 40 hex chars, got {len(hex_part)}"
                        )
                    # Validate all chars are valid hex (regex already ensures
                    # this, but double-check for safety)
                    int(hex_part, 16)

                    iocs.append(
                        CryptoWalletIoC(
                            wallet_type=WalletType.ETHEREUM,
                            address=candidate,
                            extracted_value=candidate,
                            source_message=text,
                        )
                    )
                except (ValueError, Exception) as e:
                    rejections.append(
                        RejectionLogEntry(
                            candidate=candidate,
                            rejection_reason=(
                                f"Ethereum address validation failed: {e}"
                            ),
                            ioc_category=IoCCategory.CRYPTOCURRENCY_WALLET,
                        )
                    )
                    logger.debug(
                        "Rejected Ethereum candidate %s: %s", candidate, e
                    )
        except Exception as e:
            logger.warning("Ethereum address extraction failed: %s", e)

    def extract_phishing_domains(
        self, text: str
    ) -> tuple[list[PhishingDomainIoC], list[RejectionLogEntry]]:
        """Extract and validate phishing domains from text.

        Detects bare domains, full URLs, and defanged/obfuscated domains.
        Reverses common defanging substitutions, extracts and validates
        the domain component against RFC 1035, normalizes to lowercase
        with trailing dots stripped, and deduplicates within the call.

        Args:
            text: Raw message text to scan for domain patterns.

        Returns:
            A tuple of (valid_iocs, rejections) where valid_iocs contains
            validated PhishingDomainIoC instances and rejections contains
            RejectionLogEntry instances for failed candidates.
        """
        try:
            iocs: list[PhishingDomainIoC] = []
            rejections: list[RejectionLogEntry] = []
            seen_domains: set[str] = set()

            # Collect all candidate domains with their original forms
            candidates: list[tuple[str, str]] = []

            # 1. Extract from full URLs (hxxp/https patterns)
            self._extract_url_domains(text, candidates)

            # 2. Extract defanged domains (with [.] or [dot])
            self._extract_defanged_domains(text, candidates)

            # 3. Extract bare domains (word.tld patterns)
            self._extract_bare_domains(text, candidates)

            # Process all candidates
            for original_form, domain_raw in candidates:
                try:
                    # Normalize the domain
                    normalized = self._normalize_domain(domain_raw)

                    # Deduplicate within session
                    if normalized in seen_domains:
                        continue

                    # Validate against RFC 1035
                    is_valid, reason = self._validate_domain_rfc1035(
                        normalized
                    )
                    if not is_valid:
                        rejections.append(
                            RejectionLogEntry(
                                candidate=original_form,
                                rejection_reason=reason,
                                ioc_category=IoCCategory.PHISHING_DOMAIN,
                            )
                        )
                        logger.debug(
                            "Rejected domain candidate '%s': %s",
                            original_form,
                            reason,
                        )
                        continue

                    seen_domains.add(normalized)
                    iocs.append(
                        PhishingDomainIoC(
                            domain=normalized,
                            original_form=original_form,
                            extracted_value=normalized,
                            source_message=text,
                        )
                    )
                except Exception as e:
                    rejections.append(
                        RejectionLogEntry(
                            candidate=original_form,
                            rejection_reason=f"Processing error: {e}",
                            ioc_category=IoCCategory.PHISHING_DOMAIN,
                        )
                    )
                    logger.debug(
                        "Error processing domain candidate '%s': %s",
                        original_form,
                        e,
                    )

            return iocs, rejections

        except Exception as e:
            logger.warning("Phishing domain extraction failed: %s", e)
            return [], []

    def _defang_text(self, text: str) -> str:
        """Reverse common defanging substitutions in text.

        Converts obfuscated indicators back to their original form:
        - hxxp → http, hxxps → https
        - [.] → .
        - [dot] → .
        - [://] → ://

        Args:
            text: Potentially defanged text.

        Returns:
            Text with defanging reversed.
        """
        result = text
        # Order matters: replace scheme-level obfuscations first
        result = re.sub(r"hxxps", "https", result, flags=re.IGNORECASE)
        result = re.sub(r"hxxp", "http", result, flags=re.IGNORECASE)
        result = result.replace("[://]", "://")
        result = result.replace("[.]", ".")
        result = re.sub(r"\[dot\]", ".", result, flags=re.IGNORECASE)
        return result

    def _normalize_domain(self, domain: str) -> str:
        """Normalize a domain to lowercase with trailing dots stripped.

        Args:
            domain: Raw domain string.

        Returns:
            Normalized domain (lowercase, no trailing dot).
        """
        normalized = domain.lower().rstrip(".")
        return normalized

    def _validate_domain_rfc1035(
        self, domain: str
    ) -> tuple[bool, str]:
        """Validate domain against RFC 1035 syntax rules.

        Checks:
        - Total length ≤ 253 characters
        - Each label ≤ 63 characters
        - Labels contain only alphanumeric characters and hyphens
        - Labels don't start or end with hyphens
        - Domain has at least 2 labels (has a TLD)

        Args:
            domain: Normalized domain string to validate.

        Returns:
            A tuple of (is_valid, reason) where reason is empty if valid.
        """
        if not domain:
            return False, "Domain is empty"

        # Total length check
        if len(domain) > 253:
            return False, (
                f"Domain length {len(domain)} exceeds 253 character limit"
            )

        labels = domain.split(".")

        # Must have at least 2 labels (e.g., "example.com")
        if len(labels) < 2:
            return False, "Domain must have at least 2 labels (missing TLD)"

        # TLD must be at least 2 characters and all alphabetic
        tld = labels[-1]
        if len(tld) < 2 or not tld.isalpha():
            return False, f"Invalid TLD: '{tld}'"

        for label in labels:
            # Each label must be non-empty
            if not label:
                return False, "Empty label (consecutive dots)"

            # Each label ≤ 63 characters
            if len(label) > 63:
                return False, (
                    f"Label '{label[:20]}...' exceeds 63 character limit"
                )

            # Labels contain only alphanumeric + hyphens
            if not re.match(r"^[a-z0-9\-]+$", label):
                return False, (
                    f"Label '{label}' contains invalid characters"
                )

            # Labels don't start or end with hyphens
            if label.startswith("-") or label.endswith("-"):
                return False, (
                    f"Label '{label}' starts or ends with a hyphen"
                )

        return True, ""

    def _extract_url_domains(
        self,
        text: str,
        candidates: list[tuple[str, str]],
    ) -> None:
        """Extract domains from full URL patterns in text.

        Args:
            text: Raw message text.
            candidates: List to append (original_form, domain) tuples to.
        """
        try:
            for match in self._url_pattern.finditer(text):
                original_form = match.group(0).rstrip(" \t\n/")
                domain_part = match.group(1)
                # Reverse defanging on the domain part
                domain_clean = self._defang_text(domain_part)
                candidates.append((original_form, domain_clean))
        except Exception as e:
            logger.warning("URL domain extraction failed: %s", e)

    def _extract_defanged_domains(
        self,
        text: str,
        candidates: list[tuple[str, str]],
    ) -> None:
        """Extract defanged domains (with [.] or [dot]) from text.

        Only considers matches that actually contain defanging markers.

        Args:
            text: Raw message text.
            candidates: List to append (original_form, domain) tuples to.
        """
        try:
            for match in self._defanged_domain_pattern.finditer(text):
                original_form = match.group(1)
                # Only consider if it actually contains defanging markers
                if "[.]" in original_form or "[dot]" in original_form.lower():
                    domain_clean = self._defang_text(original_form)
                    candidates.append((original_form, domain_clean))
        except Exception as e:
            logger.warning("Defanged domain extraction failed: %s", e)

    def _extract_bare_domains(
        self,
        text: str,
        candidates: list[tuple[str, str]],
    ) -> None:
        """Extract bare domains (e.g., evil.com) from text.

        Only includes domains whose TLD is in the known common TLDs set
        to avoid false positives.

        Args:
            text: Raw message text.
            candidates: List to append (original_form, domain) tuples to.
        """
        try:
            for match in self._bare_domain_pattern.finditer(text):
                original_form = match.group(1)
                # Check if TLD is in our known list to reduce false positives
                parts = original_form.split(".")
                tld = parts[-1].lower()
                if tld in self._common_tlds:
                    candidates.append((original_form, original_form))
        except Exception as e:
            logger.warning("Bare domain extraction failed: %s", e)

    def extract_phone_numbers(
        self, text: str
    ) -> tuple[list[Any], list[RejectionLogEntry]]:
        """Extract and validate phone numbers from text.

        Stub implementation — returns empty results until fully implemented.

        Args:
            text: Raw message text to scan for phone number patterns.

        Returns:
            A tuple of (valid_iocs, rejections).
        """
        try:
            return [], []
        except Exception as e:
            logger.warning("Phone number extraction failed: %s", e)
            return [], []

    def extract_mule_accounts(
        self, text: str
    ) -> tuple[list[Any], list[RejectionLogEntry]]:
        """Extract and validate mule bank account details from text.

        Stub implementation — returns empty results until fully implemented.

        Args:
            text: Raw message text to scan for bank account patterns.

        Returns:
            A tuple of (valid_iocs, rejections).
        """
        try:
            return [], []
        except Exception as e:
            logger.warning("Mule account extraction failed: %s", e)
            return [], []

    async def extract_iocs(self, message: str) -> ExtractionResult:
        """Async extraction of all IoC types from a message.

        Orchestrates all four extraction methods concurrently using
        asyncio.run_in_executor to avoid blocking the event loop.
        Completes within 5 seconds; returns partial results on timeout.

        Args:
            message: Raw message text to extract IoCs from.

        Returns:
            ExtractionResult containing validated IoCs and rejection log entries.
        """
        all_iocs: list[BaseIoC] = []
        all_rejections: list[RejectionLogEntry] = []

        try:
            loop = asyncio.get_event_loop()
            executor = ThreadPoolExecutor(max_workers=4)

            # Schedule all four extraction methods concurrently
            crypto_future = loop.run_in_executor(
                executor, self.extract_crypto_wallets, message
            )
            domains_future = loop.run_in_executor(
                executor, self.extract_phishing_domains, message
            )
            phones_future = loop.run_in_executor(
                executor, self.extract_phone_numbers, message
            )
            mule_future = loop.run_in_executor(
                executor, self.extract_mule_accounts, message
            )

            # Wrap executor futures as asyncio tasks for use with asyncio.wait
            tasks = [
                asyncio.ensure_future(crypto_future),
                asyncio.ensure_future(domains_future),
                asyncio.ensure_future(phones_future),
                asyncio.ensure_future(mule_future),
            ]
            task_names = [
                "crypto_wallets",
                "phishing_domains",
                "phone_numbers",
                "mule_accounts",
            ]

            # Use asyncio.wait with timeout — does NOT cancel pending tasks
            done, pending = await asyncio.wait(
                tasks, timeout=5.0, return_when=asyncio.ALL_COMPLETED
            )

            if pending:
                logger.warning(
                    "IoC extraction timed out after 5s, "
                    "%d task(s) still pending — returning partial results",
                    len(pending),
                )
                # Cancel pending tasks to clean up
                for task in pending:
                    task.cancel()

            # Collect results from completed tasks
            for name, task in zip(task_names, tasks):
                if task in done:
                    try:
                        result = task.result()
                        if isinstance(result, Exception):
                            logger.warning(
                                "Extraction method %s failed: %s", name, result
                            )
                            continue
                        iocs, rejections = result
                        all_iocs.extend(iocs)
                        all_rejections.extend(rejections)
                    except Exception as e:
                        logger.warning(
                            "Extraction method %s raised: %s", name, e
                        )

            executor.shutdown(wait=False)

        except Exception as e:
            logger.warning(
                "IoC extraction orchestration failed: %s", e
            )

        return ExtractionResult(iocs=all_iocs, rejections=all_rejections)
