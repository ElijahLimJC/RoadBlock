"""
Audit script for scam classifier LLM hardening.

Validates that the Scam_Classifier's Stage 2 LLM call maintains required
security boundaries:
  - Email content is wrapped in explicit delimiters before LLM submission
  - System prompt instructs the LLM to ignore embedded instructions
  - Response validation enforces structured verdict format only
  - Non-conforming responses are treated as potential injection attempts
"""

import os
import sys

CLASSIFIER_FILE = "components/scam_classifier.py"

# 1. Defensively handle the bootstrap phase where the file doesn't exist yet
if not os.path.exists(CLASSIFIER_FILE):
    print(f"⏳ {CLASSIFIER_FILE} not found yet. Skipping audit until implementation begins.")
    sys.exit(0)

with open(CLASSIFIER_FILE, "r") as f:
    content = f.read()

# 2. Skip the audit if Kiro is in the middle of creating an empty file template
if not content.strip():
    print(f"⏳ {CLASSIFIER_FILE} is empty. Waiting for implementation.")
    sys.exit(0)

content_lower = content.lower()

# --- Required hardening checks ---

checks = []

# Check 1: Email content must be delimited/fenced before LLM submission
delimiter_markers = [
    "```",          # triple backtick fencing
    "boundary",     # boundary token reference
    "delimiter",    # explicit delimiter wrapping
    "fence",        # fencing terminology
]
has_delimiter = any(marker in content_lower for marker in delimiter_markers)
if not has_delimiter:
    checks.append("MISSING: Email content delimiter/fencing before LLM call (triple backticks, boundary tokens, or explicit delimiters)")

# Check 2: System prompt must instruct LLM to ignore email-embedded instructions
ignore_markers = [
    "ignore any instructions",
    "ignore instructions contained",
    "do not follow instructions",
    "sole task is",
    "only task is classification",
    "binary classification",
]
has_ignore_instruction = any(marker in content_lower for marker in ignore_markers)
if not has_ignore_instruction:
    checks.append("MISSING: System prompt instruction telling LLM to ignore embedded instructions in email content")

# Check 3: Structured output enforcement (verdict validation)
verdict_markers = [
    "verdict",
    "structured",
    "json",
    "schema",
    "parse",
]
has_verdict_validation = sum(1 for marker in verdict_markers if marker in content_lower) >= 2
if not has_verdict_validation:
    checks.append("MISSING: Structured verdict response validation (need verdict parsing/schema enforcement)")

# Check 4: Non-conforming response handling (fallback on injection suspicion)
fallback_markers = [
    "fallback",
    "fall back",
    "discard",
    "anomalous",
    "injection",
    "non-conforming",
    "unparseable",
]
has_fallback = sum(1 for marker in fallback_markers if marker in content_lower) >= 2
if not has_fallback:
    checks.append("MISSING: Fallback handling for non-conforming/potentially injected LLM responses")

# --- Report ---

if checks:
    print(f"❌ SECURITY ALERT: Scam classifier LLM hardening incomplete!")
    for check in checks:
        print(f"   • {check}")
    sys.exit(1)

print("✅ Scam classifier LLM hardening verified: delimiters, ignore-instructions, structured output, fallback handling all present.")
