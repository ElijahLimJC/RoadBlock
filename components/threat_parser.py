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
import phonenumbers

from models.chat_models import ExtractionResult, RejectionLogEntry
from models.ioc_models import (
    BaseIoC,
    CryptoWalletIoC,
    IoCCategory,
    MuleBankAccountIoC,
    PhishingDomainIoC,
    PhoneNumberIoC,
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

        # Mule bank account detection patterns
        self._bank_names: list[str] = [
            "Chase", "Wells Fargo", "Bank of America", "Citibank",
            "Capital One", "PNC Bank", "US Bank", "TD Bank",
            "Truist", "Fifth Third", "Regions Bank", "KeyBank",
            "Huntington", "M&T Bank", "Ally Bank", "Citizens Bank",
            "BMO Harris", "Santander", "HSBC", "Goldman Sachs",
            "Morgan Stanley", "Charles Schwab", "Navy Federal",
            "USAA", "Discover Bank", "Synchrony", "American Express",
            "Barclays", "Deutsche Bank", "Credit Suisse",
            "JPMorgan", "Comerica", "Zions Bank", "First Republic",
            "Silicon Valley Bank", "Signature Bank", "Popular Bank",
            "East West Bank", "Webster Bank", "Valley National Bank",
            "BNY Mellon", "State Street", "Northern Trust",
        ]
        # Build a case-insensitive regex for bank name detection
        escaped_names = [re.escape(name) for name in self._bank_names]
        self._bank_name_pattern: re.Pattern[str] = re.compile(
            r"\b(" + "|".join(escaped_names) + r")\b",
            re.IGNORECASE,
        )

        # Routing number: exactly 9 consecutive digits
        self._routing_number_pattern: re.Pattern[str] = re.compile(
            r"\b(\d{9})\b"
        )

        # Account number: 4-17 consecutive digits
        # We need to avoid matching routing numbers (exactly 9 digits) as
        # account numbers, so we'll collect all digit sequences and filter
        self._account_number_pattern: re.Pattern[str] = re.compile(
            r"\b(\d{4,17})\b"
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
    ) -> tuple[list[PhoneNumberIoC], list[RejectionLogEntry]]:
        """Extract and validate phone numbers from text.

        Only considers digit sequences that contain recognized separator
        patterns (spaces, hyphens, dots, parentheses) or an explicit plus
        prefix. Bare digit sequences are ignored to prevent false positives
        from unrelated numeric strings (e.g., timestamps, IDs).

        Valid candidates are parsed and normalized to E.164 format using the
        phonenumbers library. Ambiguous country codes and invalid digit counts
        (<7 or >15) are rejected with specific reasons logged.

        Args:
            text: Raw message text to scan for phone number patterns.

        Returns:
            A tuple of (valid_iocs, rejections) where valid_iocs contains
            validated PhoneNumberIoC instances and rejections contains
            RejectionLogEntry instances for failed candidates.
        """
        try:
            iocs: list[PhoneNumberIoC] = []
            rejections: list[RejectionLogEntry] = []
            seen_e164: set[str] = set()

            # Find phone number candidates that have separators or plus prefix.
            # This pattern matches sequences with:
            #   - A plus prefix followed by digits (with optional separators)
            #   - Digit sequences that contain at least one separator
            #     (space, hyphen, dot, or parentheses)
            # This avoids matching bare digit sequences without any formatting.
            candidates = self._find_phone_candidates(text)

            for original_form in candidates:
                self._process_phone_candidate(
                    original_form, text, iocs, rejections, seen_e164
                )

            return iocs, rejections

        except Exception as e:
            logger.warning("Phone number extraction failed: %s", e)
            return [], []

    def _find_phone_candidates(self, text: str) -> list[str]:
        """Find phone number candidates with separators or plus prefix.

        Only returns candidates that have recognized formatting characters
        (spaces, hyphens, dots, parentheses) or start with a plus sign.
        Bare digit sequences are excluded to prevent false positives.
        Overlapping matches are suppressed: if a shorter candidate is fully
        contained within an already-captured longer candidate's text span,
        it is skipped.

        Args:
            text: Raw message text.

        Returns:
            List of candidate phone number strings.
        """
        candidates: list[str] = []
        # Track matched spans to prevent overlapping extractions
        matched_spans: list[tuple[int, int]] = []

        def _overlaps_existing(start: int, end: int) -> bool:
            """Check if a span overlaps with any already-captured span."""
            for s, e in matched_spans:
                if start >= s and end <= e:
                    return True
                if s >= start and e <= end:
                    return True
            return False

        # Pattern 1: Plus prefix followed by digits with optional separators
        # e.g., +1-555-123-4567, +44 20 7946 0958, +49.30.12345678
        plus_pattern = re.compile(
            r"\+[\d][\d\s\-\.\(\)]{5,18}\d"
        )

        # Pattern 2: Digits with parentheses (common US format)
        # e.g., (555) 123-4567, (020) 7946 0958
        paren_pattern = re.compile(
            r"\([\d]{1,5}\)[\s\-\.]?[\d][\d\s\-\.\(\)]{4,14}\d"
        )

        # Pattern 3: Digit sequences with at least one separator
        # (space, hyphen, or dot between digit groups)
        # e.g., 555-123-4567, 020.7946.0958, 555 123 4567
        sep_pattern = re.compile(
            r"\b\d[\d\s\-\.]{5,18}\d\b"
        )

        # Collect plus-prefixed candidates (highest priority)
        for match in plus_pattern.finditer(text):
            candidate = match.group().strip()
            candidates.append(candidate)
            matched_spans.append((match.start(), match.end()))

        # Collect parenthesized candidates
        for match in paren_pattern.finditer(text):
            candidate = match.group().strip()
            if _overlaps_existing(match.start(), match.end()):
                continue
            if candidate not in candidates:
                candidates.append(candidate)
                matched_spans.append((match.start(), match.end()))

        # Collect separator-containing candidates (must have at least one
        # separator and must not overlap with already-captured spans)
        for match in sep_pattern.finditer(text):
            candidate = match.group().strip()
            if _overlaps_existing(match.start(), match.end()):
                continue
            # Only include if it contains at least one recognized separator
            if self._has_phone_separator(candidate) and candidate not in candidates:
                candidates.append(candidate)
                matched_spans.append((match.start(), match.end()))

        return candidates

    def _has_phone_separator(self, candidate: str) -> bool:
        """Check if a candidate string contains recognized phone separators.

        A candidate must contain at least one space, hyphen, dot, or
        parenthesis to be considered a phone number (as opposed to a
        bare digit sequence).

        Args:
            candidate: Potential phone number string.

        Returns:
            True if the candidate has at least one separator character.
        """
        separators = set(" -.()")
        return any(c in separators for c in candidate)

    def _process_phone_candidate(
        self,
        original_form: str,
        source_text: str,
        iocs: list[PhoneNumberIoC],
        rejections: list[RejectionLogEntry],
        seen_e164: set[str],
    ) -> None:
        """Process a single phone number candidate.

        Parses the candidate using the phonenumbers library, validates it,
        and either adds it to the IoC list or logs a rejection.

        Args:
            original_form: The raw candidate string from text.
            source_text: Full source message for context.
            iocs: List to append valid IoCs to (mutated in place).
            rejections: List to append rejections to (mutated in place).
            seen_e164: Set of already-seen E.164 numbers for deduplication.
        """
        try:
            # Strip digits to count them
            digits_only = re.sub(r"[^\d]", "", original_form)

            # Quick reject: fewer than 7 or more than 15 digits
            if len(digits_only) < 7:
                rejections.append(
                    RejectionLogEntry(
                        candidate=original_form,
                        rejection_reason=(
                            f"Too few digits ({len(digits_only)}): "
                            f"minimum 7 required"
                        ),
                        ioc_category=IoCCategory.PHONE_NUMBER,
                    )
                )
                logger.debug(
                    "Rejected phone candidate '%s': too few digits (%d)",
                    original_form,
                    len(digits_only),
                )
                return

            if len(digits_only) > 15:
                rejections.append(
                    RejectionLogEntry(
                        candidate=original_form,
                        rejection_reason=(
                            f"Too many digits ({len(digits_only)}): "
                            f"maximum 15 allowed"
                        ),
                        ioc_category=IoCCategory.PHONE_NUMBER,
                    )
                )
                logger.debug(
                    "Rejected phone candidate '%s': too many digits (%d)",
                    original_form,
                    len(digits_only),
                )
                return

            # Attempt to parse the phone number
            # If it starts with '+', parse directly; otherwise try with None region
            parsed = None
            if original_form.strip().startswith("+"):
                try:
                    parsed = phonenumbers.parse(original_form, None)
                except phonenumbers.NumberParseException as e:
                    rejections.append(
                        RejectionLogEntry(
                            candidate=original_form,
                            rejection_reason=f"Parse failed: {e}",
                            ioc_category=IoCCategory.PHONE_NUMBER,
                        )
                    )
                    logger.debug(
                        "Rejected phone candidate '%s': parse error: %s",
                        original_form,
                        e,
                    )
                    return
            else:
                # Without a plus prefix, we cannot reliably determine
                # the country code — try common regions
                parsed = self._try_parse_without_plus(
                    original_form, rejections
                )
                if parsed is None:
                    return

            # Validate the parsed number
            if not phonenumbers.is_valid_number(parsed):
                rejections.append(
                    RejectionLogEntry(
                        candidate=original_form,
                        rejection_reason=(
                            "Invalid phone number: "
                            "fails phonenumbers library validation"
                        ),
                        ioc_category=IoCCategory.PHONE_NUMBER,
                    )
                )
                logger.debug(
                    "Rejected phone candidate '%s': invalid number",
                    original_form,
                )
                return

            # Check for ambiguous country code
            # is_valid_number already ensures the number resolves to a
            # single valid interpretation. If we couldn't parse at all,
            # we already returned above.

            # Normalize to E.164
            e164 = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            )

            # Final digit count validation on normalized E.164
            e164_digits = re.sub(r"[^\d]", "", e164)
            if len(e164_digits) < 7 or len(e164_digits) > 15:
                rejections.append(
                    RejectionLogEntry(
                        candidate=original_form,
                        rejection_reason=(
                            f"E.164 digit count out of range "
                            f"({len(e164_digits)}): must be 7-15"
                        ),
                        ioc_category=IoCCategory.PHONE_NUMBER,
                    )
                )
                logger.debug(
                    "Rejected phone candidate '%s': E.164 digit count %d",
                    original_form,
                    len(e164_digits),
                )
                return

            # Deduplicate
            if e164 in seen_e164:
                return

            seen_e164.add(e164)
            iocs.append(
                PhoneNumberIoC(
                    e164_number=e164,
                    original_form=original_form,
                    extracted_value=e164,
                    source_message=source_text,
                )
            )

        except Exception as e:
            rejections.append(
                RejectionLogEntry(
                    candidate=original_form,
                    rejection_reason=f"Unexpected error: {e}",
                    ioc_category=IoCCategory.PHONE_NUMBER,
                )
            )
            logger.warning(
                "Unexpected error processing phone candidate '%s': %s",
                original_form,
                e,
            )

    def _try_parse_without_plus(
        self,
        candidate: str,
        rejections: list[RejectionLogEntry],
    ) -> "phonenumbers.PhoneNumber | None":
        """Attempt to parse a phone number without a plus prefix.

        Tries parsing with common default regions (US, GB, DE, AU, IN).
        If parsing succeeds with exactly one valid interpretation, returns
        the parsed number. If ambiguous (multiple valid results from
        different regions) or no valid parse, logs a rejection and
        returns None.

        Args:
            candidate: Phone number string without plus prefix.
            rejections: List to append rejections to if parsing fails.

        Returns:
            Parsed PhoneNumber object if unambiguous, or None.
        """
        # Try a set of common regions to see if the number resolves
        # unambiguously to a single E.164 representation
        common_regions = ["US", "GB", "DE", "AU", "IN", "FR", "JP", "BR"]
        valid_e164_results: set[str] = set()

        for region in common_regions:
            try:
                parsed = phonenumbers.parse(candidate, region)
                if phonenumbers.is_valid_number(parsed):
                    e164 = phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.E164
                    )
                    valid_e164_results.add(e164)
            except phonenumbers.NumberParseException:
                continue

        if len(valid_e164_results) == 0:
            rejections.append(
                RejectionLogEntry(
                    candidate=candidate,
                    rejection_reason=(
                        "Unrecognizable format: could not parse as a "
                        "valid phone number in any common region"
                    ),
                    ioc_category=IoCCategory.PHONE_NUMBER,
                )
            )
            logger.debug(
                "Rejected phone candidate '%s': no valid parse in any region",
                candidate,
            )
            return None

        if len(valid_e164_results) > 1:
            rejections.append(
                RejectionLogEntry(
                    candidate=candidate,
                    rejection_reason=(
                        f"Ambiguous country code: resolves to "
                        f"{len(valid_e164_results)} different E.164 numbers "
                        f"({', '.join(sorted(valid_e164_results))})"
                    ),
                    ioc_category=IoCCategory.PHONE_NUMBER,
                )
            )
            logger.debug(
                "Rejected phone candidate '%s': ambiguous (%d results)",
                candidate,
                len(valid_e164_results),
            )
            return None

        # Exactly one valid result — parse it again with the matching region
        target_e164 = next(iter(valid_e164_results))
        for region in common_regions:
            try:
                parsed = phonenumbers.parse(candidate, region)
                if phonenumbers.is_valid_number(parsed):
                    e164 = phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.E164
                    )
                    if e164 == target_e164:
                        return parsed
            except phonenumbers.NumberParseException:
                continue

        return None

    def extract_mule_accounts(
        self, text: str
    ) -> tuple[list[MuleBankAccountIoC], list[RejectionLogEntry]]:
        """Extract and validate mule bank account details from text.

        Detects bank name, account number (4-17 digits), and routing number
        (9 digits with valid ABA checksum) within 500-character proximity.
        Extracts multiple independent triplets from a single message.

        Args:
            text: Raw message text to scan for bank account patterns.

        Returns:
            A tuple of (valid_iocs, rejections) where valid_iocs contains
            validated MuleBankAccountIoC instances and rejections contains
            RejectionLogEntry instances for failed candidates.
        """
        try:
            iocs: list[MuleBankAccountIoC] = []
            rejections: list[RejectionLogEntry] = []

            # Find all bank name mentions with positions
            bank_matches = [
                (m.group(), m.start(), m.end())
                for m in self._bank_name_pattern.finditer(text)
            ]

            # Fallback: if no recognized bank name, look for contextual
            # keywords like "bank", "routing", "account" near digit sequences
            if not bank_matches:
                # Check for generic bank-related keywords
                generic_bank_pattern = re.compile(
                    r"\b(bank|routing\s*(?:number|no|#)?|account\s*(?:number|no|#)?|"
                    r"receiving\s*bank|wire\s*transfer)\b",
                    re.IGNORECASE,
                )
                generic_matches = [
                    (m.group(), m.start(), m.end())
                    for m in generic_bank_pattern.finditer(text)
                ]
                if generic_matches:
                    # Use the first keyword match as a pseudo "bank name"
                    # to anchor the proximity search
                    bank_matches = [
                        ("Unknown Bank", generic_matches[0][1], generic_matches[0][2])
                    ]
                else:
                    return iocs, rejections

            # Find all digit sequences in the text
            digit_matches = [
                (m.group(), m.start(), m.end())
                for m in re.finditer(r"\b(\d+)\b", text)
            ]

            # Track which digit sequences have been consumed to avoid reuse
            used_routing: set[int] = set()
            used_account: set[int] = set()

            for bank_name, bank_start, bank_end in bank_matches:
                # Define the 500-character proximity window around the bank name
                window_start = max(0, bank_start - 500)
                window_end = min(len(text), bank_end + 500)

                # Find candidate routing numbers (exactly 9 digits) in proximity
                candidate_routings: list[tuple[str, int]] = []
                for digits, d_start, d_end in digit_matches:
                    if len(digits) == 9 and d_start >= window_start and d_end <= window_end:
                        candidate_routings.append((digits, d_start))

                # Find candidate account numbers (4-17 digits, not 9) in proximity
                candidate_accounts: list[tuple[str, int]] = []
                for digits, d_start, d_end in digit_matches:
                    if 4 <= len(digits) <= 17 and d_start >= window_start and d_end <= window_end:
                        candidate_accounts.append((digits, d_start))

                # Try to form valid triplets
                for routing_num, routing_pos in candidate_routings:
                    if routing_pos in used_routing:
                        continue

                    # Validate ABA checksum
                    is_valid_aba, aba_reason = self._validate_aba_checksum(
                        routing_num
                    )
                    if not is_valid_aba:
                        rejections.append(
                            RejectionLogEntry(
                                candidate=(
                                    f"bank={bank_name}, routing={routing_num}"
                                ),
                                rejection_reason=aba_reason,
                                ioc_category=IoCCategory.MULE_BANK_ACCOUNT,
                            )
                        )
                        logger.debug(
                            "Rejected routing number %s: %s",
                            routing_num,
                            aba_reason,
                        )
                        used_routing.add(routing_pos)
                        continue

                    # Find a valid account number for this routing number
                    for account_num, account_pos in candidate_accounts:
                        if account_pos in used_account:
                            continue
                        # Skip if the account number IS the routing number
                        if account_pos == routing_pos:
                            continue

                        # Validate account number length (4-17 digits)
                        digit_count = len(account_num)
                        if digit_count < 4 or digit_count > 17:
                            rejections.append(
                                RejectionLogEntry(
                                    candidate=(
                                        f"bank={bank_name}, "
                                        f"account={account_num}"
                                    ),
                                    rejection_reason=(
                                        f"Account number has {digit_count} "
                                        f"digits, must be 4-17"
                                    ),
                                    ioc_category=IoCCategory.MULE_BANK_ACCOUNT,
                                )
                            )
                            logger.debug(
                                "Rejected account number %s: invalid length %d",
                                account_num,
                                digit_count,
                            )
                            continue

                        # All validations passed — create IoC
                        try:
                            ioc = MuleBankAccountIoC(
                                bank_name=bank_name,
                                account_number=account_num,
                                routing_number=routing_num,
                                extracted_value=(
                                    f"{bank_name}:{account_num}:{routing_num}"
                                ),
                                source_message=text,
                            )
                            iocs.append(ioc)
                            used_routing.add(routing_pos)
                            used_account.add(account_pos)
                            break  # Move to next routing number
                        except Exception as e:
                            rejections.append(
                                RejectionLogEntry(
                                    candidate=(
                                        f"bank={bank_name}, "
                                        f"account={account_num}, "
                                        f"routing={routing_num}"
                                    ),
                                    rejection_reason=(
                                        f"Model validation failed: {e}"
                                    ),
                                    ioc_category=IoCCategory.MULE_BANK_ACCOUNT,
                                )
                            )
                            logger.debug(
                                "Rejected mule account triplet: %s", e
                            )

            return iocs, rejections

        except Exception as e:
            logger.warning("Mule account extraction failed: %s", e)
            return [], []

    def _validate_aba_checksum(self, routing_number: str) -> tuple[bool, str]:
        """Validate ABA routing number checksum.

        Uses the standard ABA checksum algorithm with weights
        [3, 7, 1, 3, 7, 1, 3, 7, 1]. The weighted sum of all 9 digits
        must be divisible by 10.

        Args:
            routing_number: A 9-digit string to validate.

        Returns:
            A tuple of (is_valid, reason) where reason is empty if valid.
        """
        if len(routing_number) != 9 or not routing_number.isdigit():
            return False, (
                f"Routing number must be exactly 9 digits, "
                f"got '{routing_number}'"
            )

        weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
        checksum = sum(
            int(d) * w for d, w in zip(routing_number, weights)
        )
        if checksum % 10 != 0:
            return False, (
                f"ABA checksum failed for routing number {routing_number} "
                f"(weighted sum {checksum} mod 10 = {checksum % 10})"
            )

        return True, ""

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
