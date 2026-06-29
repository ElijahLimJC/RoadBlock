"""Property-based tests for MCP IoC Lookup Client.

Tests graceful degradation on server failures and lookup idempotence via caching.
"""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from components.ioc_lookup_mcp import IoCLookupMCPClient
from models.ioc_models import IoCCategory
from models.lookup_models import IoCLookupResult, LookupStatus


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

ioc_values = st.text(
    alphabet=st.characters(categories=("L", "N", "P")),
    min_size=1,
    max_size=80,
).filter(lambda s: len(s.strip()) > 0)

ioc_categories = st.sampled_from(list(IoCCategory))

# Strategies for simulating different server failure modes
failure_exceptions = st.sampled_from([
    httpx.TimeoutException("Connection timed out"),
    httpx.ConnectError("Connection refused"),
    httpx.NetworkError("Network unreachable"),
])


# ---------------------------------------------------------------------------
# Property 19: MCP Lookup Graceful Degradation
# ---------------------------------------------------------------------------


class TestMCPGracefulDegradation:
    """Property 19: MCP Lookup Graceful Degradation.

    **Validates: Requirements 3.4, 6.6**

    For any valid IoC submitted for MCP lookup, if the MCP server is unreachable
    or times out, the IoC SHALL still be stored with lookup_status="unknown"
    and all other IoC fields intact.
    """

    @given(
        ioc_value=ioc_values,
        ioc_category=ioc_categories,
        failure=failure_exceptions,
    )
    @settings(max_examples=200)
    async def test_server_failure_returns_unknown_status(
        self,
        ioc_value: str,
        ioc_category: IoCCategory,
        failure: Exception,
    ) -> None:
        """On server exceptions, lookup returns unknown status with IoC fields intact."""
        client = IoCLookupMCPClient(mcp_server_url="http://fake-mcp-server:9999")
        cache: dict[str, IoCLookupResult] = {}

        # Patch the internal httpx client's post method to raise the failure
        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = failure

            result = await client.check_known_ioc(ioc_value, ioc_category, cache)

        # Assert graceful degradation
        assert result.lookup_status == LookupStatus.UNKNOWN
        assert result.is_known is False
        assert result.ioc_value == ioc_value
        assert result.ioc_category == ioc_category
        assert result.lookup_duration_ms is not None
        assert result.lookup_duration_ms >= 0

        await client.close()

    @given(
        ioc_value=ioc_values,
        ioc_category=ioc_categories,
        status_code=st.sampled_from([400, 401, 403, 404, 500, 502, 503]),
    )
    @settings(max_examples=200)
    async def test_non_200_response_returns_unknown_status(
        self,
        ioc_value: str,
        ioc_category: IoCCategory,
        status_code: int,
    ) -> None:
        """On non-200 HTTP responses, lookup returns unknown status with IoC fields intact."""
        client = IoCLookupMCPClient(mcp_server_url="http://fake-mcp-server:9999")
        cache: dict[str, IoCLookupResult] = {}

        mock_response = httpx.Response(status_code=status_code, request=httpx.Request("POST", "http://fake"))

        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            result = await client.check_known_ioc(ioc_value, ioc_category, cache)

        assert result.lookup_status == LookupStatus.UNKNOWN
        assert result.is_known is False
        assert result.ioc_value == ioc_value
        assert result.ioc_category == ioc_category

        await client.close()

    @given(
        ioc_value=ioc_values,
        ioc_category=ioc_categories,
    )
    @settings(max_examples=200)
    async def test_invalid_json_response_returns_unknown_status(
        self,
        ioc_value: str,
        ioc_category: IoCCategory,
    ) -> None:
        """On invalid JSON response body, lookup returns unknown status."""
        client = IoCLookupMCPClient(mcp_server_url="http://fake-mcp-server:9999")
        cache: dict[str, IoCLookupResult] = {}

        # Return 200 but with invalid data (is_known is not a bool)
        mock_response = httpx.Response(
            status_code=200,
            json={"is_known": "not_a_bool", "garbage": True},
            request=httpx.Request("POST", "http://fake"),
        )

        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            result = await client.check_known_ioc(ioc_value, ioc_category, cache)

        assert result.lookup_status == LookupStatus.UNKNOWN
        assert result.is_known is False
        assert result.ioc_value == ioc_value
        assert result.ioc_category == ioc_category

        await client.close()


# ---------------------------------------------------------------------------
# Property 20: MCP Lookup Idempotence
# ---------------------------------------------------------------------------


class TestMCPLookupIdempotence:
    """Property 20: MCP Lookup Idempotence.

    **Validates: Requirements 4.4**

    For any IoC value that has already been looked up (result cached),
    a subsequent lookup of the same value SHALL return the cached result
    without making a new MCP server request.
    """

    @given(
        ioc_value=ioc_values,
        ioc_category=ioc_categories,
    )
    @settings(max_examples=200)
    async def test_cached_result_returned_without_server_call(
        self,
        ioc_value: str,
        ioc_category: IoCCategory,
    ) -> None:
        """Second lookup of same IoC returns cached result without HTTP request."""
        client = IoCLookupMCPClient(mcp_server_url="http://fake-mcp-server:9999")
        cache: dict[str, IoCLookupResult] = {}

        # Simulate a successful first lookup by mocking the server response
        mock_response = httpx.Response(
            status_code=200,
            json={
                "is_known": True,
                "first_seen": "2024-01-15T08:30:00Z",
                "times_reported": 5,
                "reporting_sources": ["FBI IC3"],
                "severity_assessment": "HIGH",
                "tags": ["crypto_drain"],
            },
            request=httpx.Request("POST", "http://fake"),
        )

        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            # First lookup — should hit the server
            result1 = await client.check_known_ioc(ioc_value, ioc_category, cache)
            assert mock_post.call_count == 1

            # Second lookup — should use cache, no new server call
            result2 = await client.check_known_ioc(ioc_value, ioc_category, cache)
            assert mock_post.call_count == 1  # Still 1, no additional call

        # Results should be identical
        assert result1 == result2
        assert result1.ioc_value == ioc_value
        assert result1.ioc_category == ioc_category
        assert result1.lookup_status == LookupStatus.KNOWN
        assert result1.is_known is True

        await client.close()

    @given(
        ioc_value=ioc_values,
        ioc_category=ioc_categories,
        failure=failure_exceptions,
    )
    @settings(max_examples=200)
    async def test_failed_lookup_cached_prevents_retry(
        self,
        ioc_value: str,
        ioc_category: IoCCategory,
        failure: Exception,
    ) -> None:
        """Failed lookups are also cached — second call uses cache without retrying."""
        client = IoCLookupMCPClient(mcp_server_url="http://fake-mcp-server:9999")
        cache: dict[str, IoCLookupResult] = {}

        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = failure

            # First lookup — fails but caches the unknown result
            result1 = await client.check_known_ioc(ioc_value, ioc_category, cache)
            assert mock_post.call_count == 1

            # Second lookup — should use cached unknown result
            result2 = await client.check_known_ioc(ioc_value, ioc_category, cache)
            assert mock_post.call_count == 1  # No retry

        assert result1 == result2
        assert result1.lookup_status == LookupStatus.UNKNOWN
        assert result1.ioc_value == ioc_value

        await client.close()
