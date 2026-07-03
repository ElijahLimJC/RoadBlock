"""VirusTotal MCP client for RoadBlock IoC enrichment.

Connects to the VirusTotal MCP server (@burtthecoder/mcp-virustotal) via the
MCP SDK to enrich extracted IoCs with threat intelligence data. Maps VT
responses into RoadBlock's IoCLookupResult model.

Spawns the MCP server process ONCE per batch to avoid repeated 10-second
npx startup costs. Supports domain, IP, URL, and file hash lookups with
graceful degradation on connection failures or timeouts.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from models import APP_TIMEZONE
from models.ioc_models import BaseIoC, IoCCategory
from models.lookup_models import IoCLookupResult, LookupStatus

logger = logging.getLogger(__name__)


class VirusTotalMCPClient:
    """Client that queries VirusTotal via MCP server for IoC enrichment.

    Uses the @burtthecoder/mcp-virustotal MCP server tools:
    - get_domain_report: for phishing domain IoCs
    - get_ip_report: for IP-based IoCs
    - get_url_report: for URL IoCs
    - search_vt: for crypto wallets, phone numbers, bank accounts (general search)

    Spawns the MCP server process once per batch_lookup call. Individual
    lookup_ioc calls also spawn a process (use batch_lookup for efficiency).
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

        Note: This spawns an MCP server process. For multiple IoCs, prefer
        batch_lookup which reuses a single server process.

        Args:
            ioc: The IoC to enrich.
            cache: Optional session-level cache keyed by extracted_value.

        Returns:
            IoCLookupResult with VirusTotal enrichment data.
        """
        ioc_value = ioc.extracted_value

        if cache is not None and ioc_value in cache:
            return cache[ioc_value]

        start_time = time.perf_counter()

        if not self.is_configured():
            logger.warning("VirusTotal API key not configured, skipping lookup")
            return self._unknown_result(ioc_value, ioc.category, 0.0, cache)

        try:
            tool_name, tool_args = self._resolve_tool(ioc)
            if tool_name is None:
                return self._unknown_result(
                    ioc_value, ioc.category, 0.0, cache
                )

            async with stdio_client(self._server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    raw_result = await self._call_tool(session, tool_name, tool_args)

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if raw_result is None:
                return self._unknown_result(
                    ioc_value, ioc.category, elapsed_ms, cache
                )

            lookup_result = self._parse_vt_response(
                raw_result, ioc_value, ioc.category, elapsed_ms
            )

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

        Spawns the MCP server process ONCE and runs all tool calls within
        that single session. This avoids the ~10 second npx startup cost
        per IoC.

        Args:
            iocs: List of IoCs to enrich.
            cache: Optional session-level cache.

        Returns:
            List of IoCLookupResult, one per input IoC.
        """
        if not self.is_configured():
            logger.warning("VirusTotal API key not configured, skipping batch")
            return [
                self._unknown_result(ioc.extracted_value, ioc.category, 0.0, cache)
                for ioc in iocs
            ]

        # Filter out cached IoCs
        uncached_indices: list[int] = []
        results: list[Optional[IoCLookupResult]] = [None] * len(iocs)

        for i, ioc in enumerate(iocs):
            if cache is not None and ioc.extracted_value in cache:
                results[i] = cache[ioc.extracted_value]
            else:
                uncached_indices.append(i)

        if not uncached_indices:
            return results  # type: ignore[return-value]

        # Spawn MCP server once for all uncached lookups
        batch_start = time.perf_counter()
        try:
            async with stdio_client(self._server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    logger.info(
                        "VT MCP session started, processing %d IoCs",
                        len(uncached_indices),
                    )

                    for idx in uncached_indices:
                        ioc = iocs[idx]
                        ioc_start = time.perf_counter()

                        tool_name, tool_args = self._resolve_tool(ioc)
                        if tool_name is None:
                            results[idx] = self._unknown_result(
                                ioc.extracted_value, ioc.category, 0.0, cache
                            )
                            continue

                        try:
                            raw_result = await self._call_tool(
                                session, tool_name, tool_args
                            )
                            elapsed_ms = (
                                time.perf_counter() - ioc_start
                            ) * 1000

                            if raw_result is None:
                                results[idx] = self._unknown_result(
                                    ioc.extracted_value,
                                    ioc.category,
                                    elapsed_ms,
                                    cache,
                                )
                            else:
                                lookup_result = self._parse_vt_response(
                                    raw_result,
                                    ioc.extracted_value,
                                    ioc.category,
                                    elapsed_ms,
                                )
                                results[idx] = lookup_result
                                if cache is not None:
                                    cache[ioc.extracted_value] = lookup_result

                            logger.debug(
                                "VT lookup for %s: %s (%.0fms)",
                                ioc.extracted_value,
                                results[idx].lookup_status.value,  # type: ignore
                                elapsed_ms,
                            )

                        except Exception as e:
                            elapsed_ms = (
                                time.perf_counter() - ioc_start
                            ) * 1000
                            logger.warning(
                                "VT tool call failed for %s: %s",
                                ioc.extracted_value,
                                e,
                            )
                            results[idx] = self._unknown_result(
                                ioc.extracted_value,
                                ioc.category,
                                elapsed_ms,
                                cache,
                            )

        except Exception as e:
            # MCP server failed to start or session crashed
            total_ms = (time.perf_counter() - batch_start) * 1000
            logger.warning(
                "VT MCP session failed after %.0fms: %s", total_ms, e
            )
            for idx in uncached_indices:
                if results[idx] is None:
                    results[idx] = self._unknown_result(
                        iocs[idx].extracted_value,
                        iocs[idx].category,
                        total_ms,
                        cache,
                    )

        return results  # type: ignore[return-value]

    async def _call_tool(
        self,
        session: ClientSession,
        tool_name: str,
        tool_args: dict,
    ) -> Optional[dict]:
        """Call an MCP tool within an existing session.

        Args:
            session: Active MCP ClientSession.
            tool_name: Name of the tool to call.
            tool_args: Arguments for the tool.

        Returns:
            Parsed response dict, or None on failure.
        """
        result = await session.call_tool(tool_name, tool_args)

        if result and result.content:
            for content_block in result.content:
                if hasattr(content_block, "text"):
                    try:
                        return json.loads(content_block.text)
                    except (json.JSONDecodeError, TypeError):
                        return {"raw_response": content_block.text}
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
            return "search_vt", {
                "query": ioc.extracted_value,
                "limit": 5,
            }

        elif ioc.category == IoCCategory.PHONE_NUMBER:
            return "search_vt", {
                "query": ioc.extracted_value,
                "limit": 5,
            }

        elif ioc.category == IoCCategory.MULE_BANK_ACCOUNT:
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
        """
        try:
            # Handle raw text response (non-JSON)
            if "raw_response" in data:
                raw = data["raw_response"]
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
                    lookup_timestamp=datetime.now(APP_TIMEZONE),
                    lookup_duration_ms=elapsed_ms,
                )

            # Parse structured VT response
            attributes = data.get("data", {}).get("attributes", {})
            if not attributes:
                attributes = data.get("attributes", data)

            last_analysis_stats = attributes.get("last_analysis_stats", {})
            malicious_count = int(last_analysis_stats.get("malicious", 0))
            suspicious_count = int(last_analysis_stats.get("suspicious", 0))
            total_detections = malicious_count + suspicious_count

            reputation = attributes.get("reputation", 0)
            is_known = total_detections > 0 or reputation < -5

            tags = attributes.get("tags", [])
            if not isinstance(tags, list):
                tags = []
            tags = ["virustotal"] + [str(t) for t in tags[:10]]

            reporting_sources = ["VirusTotal"]
            analysis_results = attributes.get("last_analysis_results", {})
            if isinstance(analysis_results, dict):
                malicious_engines = [
                    engine
                    for engine, result in analysis_results.items()
                    if isinstance(result, dict)
                    and result.get("category") == "malicious"
                ][:5]
                reporting_sources.extend(malicious_engines)

            if malicious_count >= 10:
                severity = "critical"
            elif malicious_count >= 5:
                severity = "high"
            elif total_detections >= 1:
                severity = "medium"
            else:
                severity = "clean"

            times_reported = total_detections

            first_seen = None
            creation_date = attributes.get("creation_date")
            if creation_date and isinstance(creation_date, (int, float)):
                first_seen = datetime.fromtimestamp(
                    creation_date, tz=APP_TIMEZONE
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
