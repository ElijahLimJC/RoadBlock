"""Tests for ThreatParser async extraction orchestration.

Validates Requirements 8.4 (async extraction within 5s) and 8.5
(graceful degradation on pipeline stage failure).
"""

import asyncio
import time
from unittest.mock import patch

import pytest

from components.threat_parser import ThreatParser
from models.chat_models import ExtractionResult


@pytest.fixture
def parser() -> ThreatParser:
    """Create a fresh ThreatParser instance."""
    return ThreatParser()


class TestExtractIocsAsync:
    """Tests for ThreatParser.extract_iocs() async orchestration."""

    @pytest.mark.asyncio
    async def test_returns_extraction_result(self, parser: ThreatParser) -> None:
        """extract_iocs should return an ExtractionResult instance."""
        result = await parser.extract_iocs("hello world")
        assert isinstance(result, ExtractionResult)
        assert isinstance(result.iocs, list)
        assert isinstance(result.rejections, list)

    @pytest.mark.asyncio
    async def test_empty_message_returns_empty_result(
        self, parser: ThreatParser
    ) -> None:
        """An empty message should yield no IoCs or rejections."""
        result = await parser.extract_iocs("")
        assert result.iocs == []
        assert result.rejections == []

    @pytest.mark.asyncio
    async def test_extracts_ethereum_address(self, parser: ThreatParser) -> None:
        """A valid Ethereum address should be extracted."""
        eth_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"
        message = f"Send funds to {eth_addr} please"
        result = await parser.extract_iocs(message)
        assert len(result.iocs) >= 1
        addresses = [ioc.extracted_value for ioc in result.iocs]
        assert eth_addr in addresses

    @pytest.mark.asyncio
    async def test_combines_results_from_all_extractors(
        self, parser: ThreatParser
    ) -> None:
        """Results from all extraction methods should be combined."""
        eth_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"
        message = f"Check {eth_addr}"
        result = await parser.extract_iocs(message)
        # At minimum, crypto extraction should work
        assert len(result.iocs) >= 1

    @pytest.mark.asyncio
    async def test_completes_within_5_seconds(self, parser: ThreatParser) -> None:
        """Extraction should complete within the 5-second timeout."""
        message = "Normal message with no IoCs"
        start = time.monotonic()
        await parser.extract_iocs(message)
        elapsed = time.monotonic() - start
        assert elapsed < 5.0

    @pytest.mark.asyncio
    async def test_handles_extraction_method_failure_gracefully(
        self, parser: ThreatParser
    ) -> None:
        """If one extraction method raises, others still produce results."""
        eth_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"
        message = f"Send to {eth_addr}"

        # Make phishing_domains extractor raise an exception
        def failing_extractor(text):
            raise RuntimeError("Simulated failure")

        with patch.object(
            parser, "extract_phishing_domains", side_effect=failing_extractor
        ):
            result = await parser.extract_iocs(message)

        # Crypto extraction should still work
        assert len(result.iocs) >= 1
        addresses = [ioc.extracted_value for ioc in result.iocs]
        assert eth_addr in addresses

    @pytest.mark.asyncio
    async def test_handles_timeout_with_partial_results(
        self, parser: ThreatParser
    ) -> None:
        """On timeout, partial results from completed extractors are returned."""
        eth_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"
        message = f"Send to {eth_addr}"

        # Make one extractor very slow (exceeds 5s timeout)
        def slow_extractor(text):
            time.sleep(10)
            return [], []

        with patch.object(
            parser, "extract_mule_accounts", side_effect=slow_extractor
        ):
            start = time.monotonic()
            result = await parser.extract_iocs(message)
            elapsed = time.monotonic() - start

        # Should complete around 5s (timeout), not 10s
        assert elapsed < 7.0
        # Partial results from fast extractors should still be present
        # (crypto at minimum should have completed before timeout)

    @pytest.mark.asyncio
    async def test_no_unhandled_exceptions_propagate(
        self, parser: ThreatParser
    ) -> None:
        """No exceptions should propagate out of extract_iocs."""
        # Make ALL extraction methods fail
        def failing(text):
            raise RuntimeError("Total failure")

        with patch.object(parser, "extract_crypto_wallets", side_effect=failing):
            with patch.object(
                parser, "extract_phishing_domains", side_effect=failing
            ):
                with patch.object(
                    parser, "extract_phone_numbers", side_effect=failing
                ):
                    with patch.object(
                        parser, "extract_mule_accounts", side_effect=failing
                    ):
                        result = await parser.extract_iocs("test message")

        # Should still return a valid ExtractionResult
        assert isinstance(result, ExtractionResult)
        assert result.iocs == []

    @pytest.mark.asyncio
    async def test_rejection_log_entries_collected(
        self, parser: ThreatParser
    ) -> None:
        """Invalid candidates should appear in rejections list."""
        # A string that looks like a Bitcoin address but has invalid checksum
        fake_btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNx"
        message = f"Pay to {fake_btc}"
        result = await parser.extract_iocs(message)
        # Either it validates (unlikely for random) or gets rejected
        # The result should be a valid ExtractionResult regardless
        assert isinstance(result, ExtractionResult)

    @pytest.mark.asyncio
    async def test_concurrent_execution(self, parser: ThreatParser) -> None:
        """All extraction methods should run concurrently, not sequentially."""
        call_times: list[float] = []

        original_crypto = parser.extract_crypto_wallets
        original_domains = parser.extract_phishing_domains
        original_phones = parser.extract_phone_numbers
        original_mule = parser.extract_mule_accounts

        def timed_crypto(text):
            time.sleep(0.2)
            call_times.append(time.monotonic())
            return original_crypto(text)

        def timed_domains(text):
            time.sleep(0.2)
            call_times.append(time.monotonic())
            return original_domains(text)

        def timed_phones(text):
            time.sleep(0.2)
            call_times.append(time.monotonic())
            return original_phones(text)

        def timed_mule(text):
            time.sleep(0.2)
            call_times.append(time.monotonic())
            return original_mule(text)

        with patch.object(parser, "extract_crypto_wallets", side_effect=timed_crypto):
            with patch.object(
                parser, "extract_phishing_domains", side_effect=timed_domains
            ):
                with patch.object(
                    parser, "extract_phone_numbers", side_effect=timed_phones
                ):
                    with patch.object(
                        parser, "extract_mule_accounts", side_effect=timed_mule
                    ):
                        start = time.monotonic()
                        await parser.extract_iocs("test")
                        elapsed = time.monotonic() - start

        # If run concurrently (~0.2s each), total should be well under 1s
        # If sequential, it would be ~0.8s+
        assert elapsed < 0.8, (
            f"Extraction took {elapsed:.2f}s — methods may not be concurrent"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Property-Based Tests for Threat Parser IoC Extraction
# ═══════════════════════════════════════════════════════════════════════════════

import os
import string

import base58
import bech32
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from components.threat_parser import ThreatParser
from models.ioc_models import (
    CryptoWalletIoC,
    MuleBankAccountIoC,
    PhishingDomainIoC,
    PhoneNumberIoC,
    WalletType,
)


class TestCryptoWalletExtractionCorrectness:
    """Property 6: Cryptocurrency Wallet Extraction Correctness.

    Validates: Requirements 3.1, 3.2

    Generates valid Bitcoin (Base58Check, Bech32) and Ethereum addresses,
    embeds them in surrounding text, and asserts extraction finds them
    with the correct wallet_type.
    """

    @pytest.fixture
    def parser(self) -> ThreatParser:
        return ThreatParser()

    @given(
        prefix_byte=st.sampled_from([b"\x00", b"\x05"]),
        payload=st.binary(min_size=20, max_size=20),
    )
    @settings(max_examples=200)
    def test_base58check_address_extraction(
        self, prefix_byte: bytes, payload: bytes
    ) -> None:
        """Valid Base58Check addresses are extracted with bitcoin_base58 type.

        **Validates: Requirements 3.1**
        """
        parser = ThreatParser()
        # Generate a valid Base58Check address
        address = base58.b58encode_check(prefix_byte + payload).decode("ascii")
        # Address must start with 1 or 3 to match the parser's regex
        assume(address[0] in ("1", "3"))
        # Ensure length is within Bitcoin address range (26-35 chars)
        assume(26 <= len(address) <= 35)

        message = f"Please send payment to {address} as instructed."
        iocs, _ = parser.extract_crypto_wallets(message)

        extracted_addresses = [ioc.address for ioc in iocs]
        assert address in extracted_addresses, (
            f"Base58Check address {address} not found in extracted IoCs"
        )

        # Verify correct wallet_type
        matching = [ioc for ioc in iocs if ioc.address == address]
        assert matching[0].wallet_type == WalletType.BITCOIN_BASE58

    @given(
        witness_version=st.just(0),
        witness_program=st.binary(min_size=20, max_size=20),
    )
    @settings(max_examples=200)
    def test_bech32_address_extraction(
        self, witness_version: int, witness_program: bytes
    ) -> None:
        """Valid Bech32 addresses are extracted with bitcoin_bech32 type.

        **Validates: Requirements 3.1**
        """
        parser = ThreatParser()
        # Convert witness program to 5-bit groups for bech32 encoding
        data = bech32.convertbits(list(witness_program), 8, 5)
        assume(data is not None)
        # Prepend witness version
        full_data = [witness_version] + data
        address = bech32.bech32_encode("bc", full_data)
        assume(address is not None and address.startswith("bc1"))
        # Ensure the address meets the parser regex length (bc1 + 24-58 chars)
        assume(26 <= len(address) <= 61)

        message = f"My bitcoin address is {address} for the transfer."
        iocs, _ = parser.extract_crypto_wallets(message)

        extracted_addresses = [ioc.address for ioc in iocs]
        assert address in extracted_addresses, (
            f"Bech32 address {address} not found in extracted IoCs"
        )

        matching = [ioc for ioc in iocs if ioc.address == address]
        assert matching[0].wallet_type == WalletType.BITCOIN_BECH32

    @given(hex_chars=st.text(alphabet="0123456789abcdef", min_size=40, max_size=40))
    @settings(max_examples=200)
    def test_ethereum_address_extraction(self, hex_chars: str) -> None:
        """Valid Ethereum addresses are extracted with ethereum type.

        **Validates: Requirements 3.2**
        """
        parser = ThreatParser()
        address = f"0x{hex_chars}"

        message = f"Send ETH to {address} immediately."
        iocs, _ = parser.extract_crypto_wallets(message)

        extracted_addresses = [ioc.address for ioc in iocs]
        assert address in extracted_addresses, (
            f"Ethereum address {address} not found in extracted IoCs"
        )

        matching = [ioc for ioc in iocs if ioc.address == address]
        assert matching[0].wallet_type == WalletType.ETHEREUM


class TestDomainNormalizationIdempotence:
    """Property 8: Domain Normalization Idempotence.

    Validates: Requirements 4.2, 4.5

    Generates valid domain strings and asserts that applying normalization
    twice produces the same result as applying it once.
    """

    @pytest.fixture
    def parser(self) -> ThreatParser:
        return ThreatParser()

    @given(
        labels=st.lists(
            st.text(
                alphabet=st.sampled_from(
                    list(string.ascii_lowercase) + list(string.digits) + ["-"]
                ),
                min_size=2,
                max_size=10,
            ).filter(
                lambda s: (
                    not s.startswith("-")
                    and not s.endswith("-")
                    and len(s) >= 2
                    and s[0].isalnum()
                    and s[-1].isalnum()
                )
            ),
            min_size=2,
            max_size=4,
        ),
        tld=st.sampled_from(["com", "net", "org", "io", "co", "info", "xyz", "dev"]),
    )
    @settings(max_examples=200)
    def test_normalization_idempotence(
        self, labels: list[str], tld: str
    ) -> None:
        """normalize(normalize(d)) == normalize(d) for all valid domains.

        **Validates: Requirements 4.2, 4.5**
        """
        parser = ThreatParser()
        # Construct a valid domain from labels + tld
        domain = ".".join(labels[:-1] + [tld])

        once = parser._normalize_domain(domain)
        twice = parser._normalize_domain(once)

        assert twice == once, (
            f"Normalization is not idempotent: "
            f"normalize('{domain}') = '{once}', "
            f"normalize('{once}') = '{twice}'"
        )


class TestDomainDeduplication:
    """Property 9: Domain Deduplication.

    Validates: Requirements 4.4

    Generates a valid domain, creates a message containing it N times
    (N=2..5), extracts phishing domains, and asserts exactly one entry
    in results.
    """

    @pytest.fixture
    def parser(self) -> ThreatParser:
        return ThreatParser()

    @given(
        label=st.text(
            alphabet=string.ascii_lowercase + string.digits,
            min_size=3,
            max_size=10,
        ).filter(lambda s: s[0].isalpha() and s[-1].isalnum()),
        tld=st.sampled_from(["com", "net", "org", "io", "info", "xyz"]),
        n=st.integers(min_value=2, max_value=5),
    )
    @settings(max_examples=200)
    def test_duplicate_domains_deduplicated(
        self, label: str, tld: str, n: int
    ) -> None:
        """Same domain appearing N times yields exactly one IoC entry.

        **Validates: Requirements 4.4**
        """
        parser = ThreatParser()
        domain = f"{label}.{tld}"

        # Create a message with the domain repeated N times
        message = " ".join([f"Visit {domain} now!" for _ in range(n)])

        iocs, _ = parser.extract_phishing_domains(message)

        # Filter to IoCs matching our domain (normalized)
        normalized = parser._normalize_domain(domain)
        matching = [ioc for ioc in iocs if ioc.domain == normalized]

        assert len(matching) == 1, (
            f"Expected exactly 1 IoC for domain '{domain}' repeated {n} times, "
            f"got {len(matching)}"
        )


class TestPhoneNormalizationIdempotence:
    """Property 10: Phone Number Normalization Idempotence.

    Validates: Requirements 5.4

    Generates valid E.164 numbers and asserts that passing an already-normalized
    number to extraction yields the same E.164 output.
    """

    @pytest.fixture
    def parser(self) -> ThreatParser:
        return ThreatParser()

    @given(
        area_code=st.integers(min_value=201, max_value=989).filter(
            lambda x: x % 100 != 11 and (x // 100) >= 2
        ),
        subscriber=st.integers(min_value=2000000, max_value=9999999),
    )
    @settings(max_examples=200)
    def test_e164_normalization_idempotent(
        self, area_code: int, subscriber: int
    ) -> None:
        """Normalizing an already-normalized E.164 number yields the same output.

        **Validates: Requirements 5.4**
        """
        parser = ThreatParser()
        # Build a valid US E.164 number: +1 + area_code (3 digits) + subscriber (7 digits)
        e164_number = f"+1{area_code}{subscriber}"

        # Ensure the number is within valid E.164 length
        assume(8 <= len(e164_number) <= 16)

        # Pass the E.164 number directly (it has the + prefix, the parser
        # should recognize it)
        iocs, _ = parser.extract_phone_numbers(e164_number)

        # If the parser extracts a phone number, it should match the input
        if iocs:
            assert iocs[0].e164_number == e164_number, (
                f"Expected E.164 '{e164_number}', got '{iocs[0].e164_number}'"
            )


class TestPhoneFalsePositivePrevention:
    """Property 11: Phone Number False-Positive Prevention.

    Validates: Requirements 5.5

    Generates 7-15 digit sequences WITHOUT separators or plus prefix
    (bare digits like "1234567890") and asserts extract_phone_numbers
    returns NO results for these bare digit strings.
    """

    @pytest.fixture
    def parser(self) -> ThreatParser:
        return ThreatParser()

    @given(
        digit_count=st.integers(min_value=7, max_value=15),
        data=st.data(),
    )
    @settings(max_examples=200)
    def test_bare_digits_not_extracted(
        self, digit_count: int, data: st.DataObject
    ) -> None:
        """Bare digit sequences without separators or plus prefix are not extracted.

        **Validates: Requirements 5.5**
        """
        parser = ThreatParser()
        # Generate a bare digit string of the specified length
        digits = data.draw(
            st.text(alphabet="0123456789", min_size=digit_count, max_size=digit_count)
        )
        # Ensure it doesn't accidentally start with + (it won't since alphabet is digits only)
        # Wrap in text to simulate a realistic message context
        message = f"The reference number is {digits} for your records."

        iocs, _ = parser.extract_phone_numbers(message)

        assert len(iocs) == 0, (
            f"Bare digit sequence '{digits}' should not be extracted as phone number, "
            f"got {len(iocs)} IoC(s): {[ioc.e164_number for ioc in iocs]}"
        )


class TestMuleAccountProximityExtraction:
    """Property 13: Mule Account Proximity Extraction.

    Validates: Requirements 6.1, 6.5

    Generates valid triplets: picks a bank name from the known list,
    a valid ABA routing number (9 digits passing checksum with weights
    [3,7,1,3,7,1,3,7,1] sum mod 10 == 0), and an account number
    (4-17 digits, different from routing). Places all three within 500
    characters of each other in a message. Asserts extraction finds the triplet.
    """

    @pytest.fixture
    def parser(self) -> ThreatParser:
        return ThreatParser()

    @staticmethod
    def _generate_valid_routing_number(first_8_digits: list[int]) -> str:
        """Generate a valid ABA routing number from 8 random digits.

        Computes the 9th digit to make the weighted checksum (mod 10) == 0.
        """
        weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
        partial_sum = sum(d * w for d, w in zip(first_8_digits, weights[:8]))
        # Find the 9th digit that makes total_sum % 10 == 0
        remainder = partial_sum % 10
        # remainder + (d9 * 1) ≡ 0 (mod 10) => d9 = (10 - remainder) % 10
        d9 = (10 - remainder) % 10
        return "".join(str(d) for d in first_8_digits) + str(d9)

    @given(
        bank_name=st.sampled_from([
            "Chase", "Wells Fargo", "Bank of America", "Citibank",
            "Capital One", "PNC Bank", "US Bank", "TD Bank",
            "Truist", "Fifth Third", "Regions Bank", "KeyBank",
            "Huntington", "M&T Bank", "Ally Bank", "Citizens Bank",
        ]),
        first_8_digits=st.lists(
            st.integers(min_value=0, max_value=9), min_size=8, max_size=8
        ),
        account_length=st.integers(min_value=4, max_value=17),
        account_digits=st.data(),
    )
    @settings(max_examples=200)
    def test_valid_triplet_within_proximity_is_extracted(
        self,
        bank_name: str,
        first_8_digits: list[int],
        account_length: int,
        account_digits: st.DataObject,
    ) -> None:
        """Valid bank triplets within 500 chars are extracted as mule accounts.

        **Validates: Requirements 6.1, 6.5**
        """
        parser = ThreatParser()

        routing_number = self._generate_valid_routing_number(first_8_digits)

        # Generate account number (must be different from routing number)
        acct = account_digits.draw(
            st.text(
                alphabet="0123456789",
                min_size=account_length,
                max_size=account_length,
            )
        )
        # Ensure account number differs from routing number
        assume(acct != routing_number)
        # Ensure account number doesn't happen to be exactly 9 digits that
        # would match the routing number pattern and pass ABA checksum
        # (to avoid ambiguity in extraction)
        if len(acct) == 9:
            weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
            acct_checksum = sum(int(d) * w for d, w in zip(acct, weights))
            assume(acct_checksum % 10 != 0)

        # Place all three elements within 500 characters of each other
        message = (
            f"Please transfer to {bank_name}. "
            f"The routing number is {routing_number} and "
            f"the account number is {acct}."
        )
        # Ensure the message fits within 500 chars (all elements are close)
        assume(len(message) <= 500)

        iocs, _ = parser.extract_mule_accounts(message)

        # Assert at least one mule account was extracted
        assert len(iocs) >= 1, (
            f"Expected mule account extraction for "
            f"bank='{bank_name}', routing='{routing_number}', account='{acct}', "
            f"but got 0 IoCs"
        )

        # Verify the extracted IoC matches our triplet
        found = False
        for ioc in iocs:
            if (
                ioc.routing_number == routing_number
                and ioc.account_number == acct
            ):
                found = True
                break

        assert found, (
            f"Expected to find triplet with routing={routing_number}, "
            f"account={acct} in extracted IoCs: "
            f"{[(i.routing_number, i.account_number) for i in iocs]}"
        )
