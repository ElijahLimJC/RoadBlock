"""Debug script to test VirusTotal MCP client directly."""
import asyncio
import os
import sys
import logging

sys.path.insert(0, r"C:\Users\HackT\Downloads\kiro\kiro")
logging.basicConfig(level=logging.DEBUG)

from dotenv import load_dotenv
load_dotenv(r"C:\Users\HackT\Downloads\kiro\kiro\.env")

from components.virustotal_mcp import VirusTotalMCPClient
from models.ioc_models import IoCCategory, PhishingDomainIoC

client = VirusTotalMCPClient()
print(f"API key configured: {client.is_configured()}")
print(f"API key length: {len(client.api_key)}")

ioc = PhishingDomainIoC(
    category=IoCCategory.PHISHING_DOMAIN,
    extracted_value="evil.com",
    source_message="visit evil.com",
    domain="evil.com",
    original_form="evil[.]com",
)


async def test():
    print("\n--- Attempting VT lookup ---")
    result = await client.lookup_ioc(ioc)
    print(f"Status: {result.lookup_status}")
    print(f"Is known: {result.is_known}")
    print(f"Duration: {result.lookup_duration_ms:.0f}ms")
    print(f"Sources: {result.reporting_sources}")
    print(f"Severity: {result.severity_assessment}")
    print(f"Tags: {result.tags}")


asyncio.run(test())
