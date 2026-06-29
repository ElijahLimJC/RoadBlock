"""MCP IoC Lookup Client for RoadBlock threat intelligence enrichment.

Queries an external MCP (Model Context Protocol) server to check whether
extracted IoCs are already known in a shared threat intelligence database.
Implements session-level caching and graceful degradation on server failures.
"""

import time
import logging
from datetime import datetime
from typing import Optional

import httpx

from models.ioc_models import IoCCategory, BaseIoC
from models.lookup_models import IoCLookupResult, LookupStatus

logger = logging.getLogger(__name__)


class IoCLookupMCPClient:
    """Client for querying the MCP threat intelligence server.

    The MCP server exposes a `lookup_ioc` tool that accepts an IoC value
    and category, returning whether it's known along with metadata.

    Graceful degradation: connection refused, timeout, or invalid response
    format all result in lookup_status="unknown".
    """

    def __init__(self, mcp_server_url: str, timeout: float = 3.0):
        """Initialize MCP client with server endpoint and timeout.

        Args:
            mcp_server_url: Base URL of the MCP threat intelligence server.
            timeout: Request timeout in seconds (default 3.0).
        """
        self.mcp_server_url = mcp_server_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    async def check_known_ioc(
        self,
        ioc_value: str,
        ioc_category: IoCCategory,
        cache: Optional[dict[str, IoCLookupResult]] = None,
    ) -> IoCLookupResult:
        """Query the MCP server to determine if this IoC has been previously recorded.

        Checks the cache first. If found, returns cached result without making
        a server request. Otherwise queries the MCP server and caches the result.

        Args:
            ioc_value: The IoC value to look up (wallet address, domain, etc.).
            ioc_category: The category of the IoC.
            cache: Session-level cache dict keyed by ioc_value. If provided,
                   results are cached here for subsequent lookups.

        Returns:
            IoCLookupResult with is_known flag and metadata. On timeout/error,
            returns result with lookup_status="unknown" and is_known=False.
        """
        # Check cache first
        if cache is not None and ioc_value in cache:
            return cache[ioc_value]

        start_time = time.perf_counter()

        try:
            response = await self._client.post(
                f"{self.mcp_server_url}/tools/lookup_ioc",
                json={
                    "ioc_value": ioc_value,
                    "ioc_category": ioc_category.value,
                },
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if response.status_code != 200:
                logger.warning(
                    "MCP server returned status %d for IoC %s",
                    response.status_code,
                    ioc_value,
                )
                return self._unknown_result(
                    ioc_value, ioc_category, elapsed_ms, cache
                )

            data = response.json()
            result = self._parse_response(
                data, ioc_value, ioc_category, elapsed_ms
            )

            # Cache the successful result
            if cache is not None:
                cache[ioc_value] = result

            return result

        except httpx.TimeoutException:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.warning(
                "MCP server timeout after %.1fms for IoC %s",
                elapsed_ms,
                ioc_value,
            )
            return self._unknown_result(
                ioc_value, ioc_category, elapsed_ms, cache
            )

        except (httpx.ConnectError, httpx.NetworkError, OSError) as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.warning(
                "MCP server connection error for IoC %s: %s",
                ioc_value,
                str(e),
            )
            return self._unknown_result(
                ioc_value, ioc_category, elapsed_ms, cache
            )

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.warning(
                "Unexpected error during MCP lookup for IoC %s: %s",
                ioc_value,
                str(e),
            )
            return self._unknown_result(
                ioc_value, ioc_category, elapsed_ms, cache
            )

    async def batch_check(
        self,
        iocs: list[BaseIoC],
        cache: Optional[dict[str, IoCLookupResult]] = None,
    ) -> list[IoCLookupResult]:
        """Batch lookup for multiple IoCs.

        Checks each IoC against the MCP server, using the cache to avoid
        duplicate requests for previously looked-up values.

        Args:
            iocs: List of BaseIoC instances to look up.
            cache: Session-level cache dict keyed by ioc_value.

        Returns:
            List of IoCLookupResult, one per input IoC.
        """
        results: list[IoCLookupResult] = []
        for ioc in iocs:
            result = await self.check_known_ioc(
                ioc.extracted_value, ioc.category, cache
            )
            results.append(result)
        return results

    async def is_available(self) -> bool:
        """Health check — returns True if MCP server is reachable."""
        try:
            response = await self._client.get(
                f"{self.mcp_server_url}/health",
                timeout=self.timeout,
            )
            return response.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    def _parse_response(
        self,
        data: dict,
        ioc_value: str,
        ioc_category: IoCCategory,
        elapsed_ms: float,
    ) -> IoCLookupResult:
        """Parse MCP server response into IoCLookupResult.

        Expected response format:
        {
            "is_known": bool,
            "first_seen": datetime_str,
            "times_reported": int,
            "reporting_sources": list[str],
            "severity_assessment": str,
            "tags": list[str]
        }

        On invalid format, returns unknown status.
        """
        try:
            is_known = data.get("is_known", False)
            if not isinstance(is_known, bool):
                raise ValueError("is_known must be a boolean")

            first_seen = None
            if data.get("first_seen"):
                first_seen = datetime.fromisoformat(
                    str(data["first_seen"]).replace("Z", "+00:00")
                )

            times_reported = int(data.get("times_reported", 0))
            reporting_sources = data.get("reporting_sources", [])
            if not isinstance(reporting_sources, list):
                reporting_sources = []

            severity_assessment = data.get("severity_assessment")
            if severity_assessment is not None:
                severity_assessment = str(severity_assessment)

            tags = data.get("tags", [])
            if not isinstance(tags, list):
                tags = []

            lookup_status = LookupStatus.KNOWN if is_known else LookupStatus.NEW

            return IoCLookupResult(
                ioc_value=ioc_value,
                ioc_category=ioc_category,
                lookup_status=lookup_status,
                is_known=is_known,
                first_seen=first_seen,
                times_reported=times_reported,
                reporting_sources=[str(s) for s in reporting_sources],
                severity_assessment=severity_assessment,
                tags=[str(t) for t in tags],
                lookup_timestamp=datetime.utcnow(),
                lookup_duration_ms=elapsed_ms,
            )

        except (ValueError, TypeError, KeyError) as e:
            logger.warning(
                "Invalid MCP response format for IoC %s: %s", ioc_value, str(e)
            )
            return IoCLookupResult(
                ioc_value=ioc_value,
                ioc_category=ioc_category,
                lookup_status=LookupStatus.UNKNOWN,
                is_known=False,
                lookup_timestamp=datetime.utcnow(),
                lookup_duration_ms=elapsed_ms,
            )

    def _unknown_result(
        self,
        ioc_value: str,
        ioc_category: IoCCategory,
        elapsed_ms: float,
        cache: Optional[dict[str, IoCLookupResult]] = None,
    ) -> IoCLookupResult:
        """Create an IoCLookupResult with unknown status for error cases."""
        result = IoCLookupResult(
            ioc_value=ioc_value,
            ioc_category=ioc_category,
            lookup_status=LookupStatus.UNKNOWN,
            is_known=False,
            lookup_timestamp=datetime.utcnow(),
            lookup_duration_ms=elapsed_ms,
        )
        # Cache unknown results too so we don't retry failed lookups
        if cache is not None:
            cache[ioc_value] = result
        return result
