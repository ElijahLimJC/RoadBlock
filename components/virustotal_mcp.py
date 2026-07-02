"""VirusTotal MCP client for RoadBlock IoC enrichment.

Connects to the VirusTotal MCP server (@burtthecoder/mcp-virustotal) via the
MCP SDK to enrich extracted IoCs with threat intelligence data. Maps VT
responses into RoadBlock's IoCLookupResult model.

Supports domain, IP, URL, and file hash lookups with graceful degradation
on connection failures or timeouts.
"""

import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from models.ioc_models import BaseIoC, IoCCategory
from models.lookup_models import IoCLookupResult, LookupStatus

logger = logging.getLogger(__name__)

# Timeout for individual VT lookups (seconds)
_VT_LOOKUP_TIMEOUT = 30.0


class VirusTotalMCPClient:
    """Client that queries VirusTotal via MCP server for IoC enrichment.

    Uses the @burtthecoder/mcp-virustotal MCP server tools:
    - get_domain_report: for phishing domain IoCs
    - get_ip_report: for IP-based IoCs
    - get_url_report: for URL IoCs
    - search_vt: for crypto wallets, phone numbers, bank accounts (general search)

    Graceful degradation: any MCP connection or tool call failure results
    in lookup_status=UNKNOWN, is_known=False.
    """

    def __init__(self, api_key: Optional[str] = None):
        """Initialize VirusTotal MCP client.

        Args:
            api_key: VirusTotal API key. If None, reads from VIRUSTOTAL_API_KEY env var.
        """
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        self._server_params = StdioServerParameters(
            command="npx",
            args=["-y", "@burtthecoder/mcp-virustotal"],
            env={
                **os.environ,
                "VIRUSTOTAL_API_KEY": self.api_key,
            },
        )

    def is_configured(self) -> bool:
        """Check if the client has a valid API key configured."""
        return bool(self.api_key and len(self.api_key) >= 32)

    async def lookup_ioc(
        self,
        ioc: BaseIoC,
        cache: Optional[dict[str, IoCLookupResult]] = None,
    ) -> IoCLookupResult:
        """Look up a single IoC against VirusTotal via MCP.

        Args:
            ioc: The IoC to enrich.
            cache: Optional session-level cache keyed by extracted_value.

        Returns:
            IoCLookupResult with VirusTotal enrichment data.
        """
        ioc_value = ioc.extracted_value

        # Check cache first
        if cache is not None and ioc_value in cache:
            return cache[ioc_value]

        start_time = time.perf_counter()

        if not self.is_configured():
            logger.warning("VirusTotal API key not configured, skipping lookup")
            return self._unknown_result(ioc_value, ioc.category, 0.0, cache)

        try:
            result = await self._call_vt_tool(ioc)
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if result is None:
                return self._unknown_result(
                    ioc_value, ioc.category, elapsed_ms, cache
                )

            lookup_result = self._parse_vt_response(
                result, ioc_value, ioc.category, elapsed_ms
            )

            # Cache the result
            if cache is not None:
                cache[ioc_value] = lookup_result

            return lookup_result

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.warning(
                "VirusTotal MCP lookup failed for %s: %s", ioc_value, e
            )
            return self._unknown_result(
                ioc_value, ioc.category, elapsed_ms, cache
            )

    async def batch_lookup(
        self,
        iocs: list[BaseIoC],
        cache: Optional[dict[str, IoCLookupResult]] = None,
    ) -> list[IoCLookupResult]:
        """Batch lookup for multiple IoCs against VirusTotal.

        Processes IoCs sequentially to respect VT rate limits (4 req/min
        on free tier). Uses cache to avoid duplicate lookups.

        Args:
            iocs: List of IoCs to enrich.
            cache: Optional session-level cache.

        Returns:
            List of IoCLookupResult, one per input IoC.
        """
        results: list[IoCLookupResult] = []
        for ioc in iocs:
            result = await self.lookup_ioc(ioc, cache)
            results.append(result)
        return results

    async def _call_vt_tool(self, ioc: BaseIoC) -> Optional[dict]:
        """Call the appropriate VT MCP tool based on IoC category.

        Args:
            ioc: The IoC to look up.

        Returns:
            Parsed response dict from the MCP tool, or None on failure.
        """
        tool_name, tool_args = self._resolve_tool(ioc)
        if tool_name is None:
            return None

        try:
            async with stdio_client(self._server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()

                    result = await session.call_tool(tool_name, tool_args)

                    # MCP tool results come as content list
                    if result and result.content:
                        for content_block in result.content:
                            if hasattr(content_block, "text"):
                                import json
                                try:
                                    return json.loads(content_block.text)
                                except (json.JSONDecodeError, TypeError):
                                    # Return raw text wrapped in dict
                                    return {"raw_response": content_block.text}
                    return None

        except Exception as e:
            logger.warning(
                "MCP tool call failed (tool=%s, ioc=%s): %s",
                tool_name,
                ioc.extracted_value,
                e,
            )
            return None

    def _resolve_tool(self, ioc: BaseIoC) -> tuple[Optional[str], dict]:
        """Determine which VT MCP tool to call for a given IoC.

        Args:
            ioc: The IoC to look up.

        Returns:
            Tuple of (tool_name, tool_arguments). tool_name is None if
            no suitable tool exists for this IoC type.
        """
        if ioc.category == IoCCategory.PHISHING_DOMAIN:
            domain = getattr(ioc, "domain", ioc.extracted_value)
            return "get_domain_report", {"domain": domain}

        elif ioc.category == IoCCategory.CRYPTOCURRENCY_WALLET:
            # Use search for crypto addresses
            return "search_vt", {
                "query": ioc.extracted_value,
                "limit": 5,
            }

        elif ioc.category == IoCCategory.PHONE_NUMBER:
            # VT doesn't natively support phone lookups; use search
            return "search_vt", {
                "query": ioc.extracted_value,
                "limit": 5,
            }

        elif ioc.category == IoCCategory.MULE_BANK_ACCOUNT:
            # VT doesn't natively support bank account lookups; use search
            return "search_vt", {
                "query": ioc.extracted_value,
                "limit": 5,
            }

        return None, {}

    def _parse_vt_response(
        self,
        data: dict,
        ioc_value: str,
        ioc_category: IoCCategory,
        elapsed_ms: float,
    ) -> IoCLookupResult:
        """Parse VirusTotal MCP response into IoCLookupResult.

        Extracts detection stats, reputation, and tags from VT response
        to determine if the IoC is known malicious.

        Args:
            data: Raw response dict from VT MCP tool.
            ioc_value: The IoC value looked up.
            ioc_category: Category of the IoC.
            elapsed_ms: Lookup duration.

        Returns:
            IoCLookupResult with enrichment data.
        """
        try:
            # Handle raw text response (non-JSON)
            if "raw_response" in data:
                raw = data["raw_response"]
                # If VT returned text mentioning detections, mark as known
                is_known = any(
                    kw in raw.lower()
                    for kw in ["malicious", "phishing", "malware", "suspicious"]
                )
                return IoCLookupResult(
                    ioc_value=ioc_value,
                    ioc_category=ioc_category,
                    lookup_status=LookupStatus.KNOWN if is_known else LookupStatus.NEW,
                    is_known=is_known,
                    reporting_sources=["VirusTotal"],
                    severity_assessment="malicious" if is_known else "clean",
                    tags=["virustotal"],
                    lookup_timestamp=datetime.now(timezone.utc),
                    lookup_duration_ms=elapsed_ms,
                )

            # Parse structured VT response
            # VT domain/IP/URL reports have attributes.last_analysis_stats
            attributes = data.get("data", {}).get("attributes", {})
            if not attributes:
                # Try top-level attributes (some tools flatten)
                attributes = data.get("attributes", data)

            last_analysis_stats = attributes.get("last_analysis_stats", {})
            malicious_count = int(last_analysis_stats.get("malicious", 0))
            suspicious_count = int(last_analysis_stats.get("suspicious", 0))
            total_detections = malicious_count + suspicious_count

            # Reputation score (lower/negative = more malicious)
            reputation = attributes.get("reputation", 0)

            # Determine if known threat
            is_known = total_detections > 0 or reputation < -5

            # Extract tags
            tags = attributes.get("tags", [])
            if not isinstance(tags, list):
                tags = []
            tags = ["virustotal"] + [str(t) for t in tags[:10]]

            # Extract reporting sources from last_analysis_results
            reporting_sources = ["VirusTotal"]
            analysis_results = attributes.get("last_analysis_results", {})
            if isinstance(analysis_results, dict):
                # Get engines that flagged as malicious
                malicious_engines = [
                    engine
                    for engine, result in analysis_results.items()
                    if isinstance(result, dict)
                    and result.get("category") == "malicious"
                ][:5]  # Limit to 5 sources
                reporting_sources.extend(malicious_engines)

            # Determine severity
            if malicious_count >= 10:
                severity = "critical"
            elif malicious_count >= 5:
                severity = "high"
            elif total_detections >= 1:
                severity = "medium"
            else:
                severity = "clean"

            # Times reported = total positive detections
            times_reported = total_detections

            # First seen date
            first_seen = None
            creation_date = attributes.get("creation_date")
            if creation_date and isinstance(creation_date, (int, float)):
                first_seen = datetime.fromtimestamp(
                    creation_date, tz=timezone.utc
                )

            lookup_status = LookupStatus.KNOWN if is_known else LookupStatus.NEW

            return IoCLookupResult(
                ioc_value=ioc_value,
                ioc_category=ioc_category,
                lookup_status=lookup_status,
                is_known=is_known,
                first_seen=first_seen,
                times_reported=times_reported,
                reporting_sources=reporting_sources,
                severity_assessment=severity,
                tags=tags,
                lookup_timestamp=datetime.now(timezone.utc),
                lookup_duration_ms=elapsed_ms,
            )

        except Exception as e:
            logger.warning(
                "Failed to parse VT response for %s: %s", ioc_value, e
            )
            return IoCLookupResult(
                ioc_value=ioc_value,
                ioc_category=ioc_category,
                lookup_status=LookupStatus.UNKNOWN,
                is_known=False,
                reporting_sources=["VirusTotal"],
                tags=["virustotal", "parse_error"],
                lookup_timestamp=datetime.now(timezone.utc),
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
            lookup_timestamp=datetime.now(timezone.utc),
            lookup_duration_ms=elapsed_ms,
        )
        if cache is not None:
            cache[ioc_value] = result
        return result
