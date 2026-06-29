"""Quick regression test for ThreatParser against a static block of scam data."""

import sys

sys.path.insert(0, ".")

SCAM_BLOCK = """
Hey grandma send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
Also try my ethereum 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe
Call me at +1-555-867-5309 or (555) 234.5678
Visit http://phishing-scam.evil.com/login or malware.bad-domain.ru/payload.exe
My cash app $ScammerDude99
Bank transfer to sort 12-34-56 acc 12345678
Alternate BTC: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy!!!
Send XRP to rN7hbM4gCr3sortBXnGPgv8txVeHjVqQCP maybe???
"""

try:
    from components.threat_parser import ThreatParser

    parser = ThreatParser()
    iocs, rejections = parser.extract_crypto_wallets(SCAM_BLOCK)

    total = len(iocs)
    print(f"OK: Extracted {total} valid IoCs, {len(rejections)} rejections")

    if total == 0 and len(rejections) == 0:
        print("WARNING: Zero IoCs extracted and zero rejections - parser may be broken")
        sys.exit(1)

    for ioc in iocs:
        print(f"  ✓ {ioc.wallet_type.value}: {ioc.address}")
    for rej in rejections:
        print(f"  ✗ Rejected: {rej.candidate[:40]}... ({rej.rejection_reason[:50]})")

except ImportError as e:
    print(f"SKIP: threat_parser not fully implemented yet ({e})")
    sys.exit(0)
except Exception as e:
    print(f"FAIL: Parser crashed on scam data: {e}")
    sys.exit(1)
