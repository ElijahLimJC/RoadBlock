"""Safety Filter component for prompt injection detection and sanitization.

This module implements the input defense boundary that screens inbound
scammer messages for prompt injection attacks before forwarding to the
Persona_Engine. Detection is pattern-based and deterministic (not ML-based).
"""

import logging
import re
import threading
from dataclasses import dataclass

from models.chat_models import ScanResult

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class InjectionPattern:
    """A single injection detection pattern.

    Attributes:
        name: Human-readable identifier for this pattern.
        pattern: Compiled regex pattern for matching.
        category: Detection category (instruction_override, role_reassignment,
                  system_prompt_extraction, obfuscated_payload).
    """

    name: str
    pattern: re.Pattern[str]
    category: str


@dataclass(frozen=True)
class PatternMatch:
    """A detected injection pattern match within a message.

    Attributes:
        pattern_name: Name of the matched InjectionPattern.
        matched_text: The actual text that matched.
        start: Start index of the match in the original message.
        end: End index of the match in the original message.
    """

    pattern_name: str
    matched_text: str
    start: int
    end: int


# Default timeout for scanning operations (seconds)
_SCAN_TIMEOUT_SECONDS = 2.0


def _build_default_patterns() -> list[InjectionPattern]:
    """Build the default set of injection detection patterns.

    Returns:
        List of InjectionPattern instances covering instruction overrides,
        role reassignment, system prompt extraction, and obfuscated payloads.
    """
    patterns: list[InjectionPattern] = []

    # --- Instruction Override Patterns ---
    instruction_overrides = [
        (
            "ignore_previous_instructions",
            r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.]{0,30}"
            r"\b(?:previous|prior|above|earlier|all|system|original)\b[^.]{0,30}"
            r"\b(?:instructions?|prompts?|rules?|guidelines?|directives?)\b",
        ),
        (
            "disregard_above",
            r"(?i)\b(?:disregard|ignore|forget)\b[^.]{0,20}\b(?:above|everything|all)\b",
        ),
        (
            "new_instructions",
            r"(?i)\b(?:new|updated|revised|real)\s+(?:instructions?|rules?|directives?)\b",
        ),
        (
            "do_not_follow",
            r"(?i)\bdo\s+not\s+follow\b[^.]{0,30}\b(?:instructions?|rules?|prompts?)\b",
        ),
    ]
    for name, pat in instruction_overrides:
        try:
            patterns.append(
                InjectionPattern(
                    name=name,
                    pattern=re.compile(pat),
                    category="instruction_override",
                )
            )
        except re.error as e:
            logger.warning("Failed to compile pattern %s: %s", name, e)

    # --- Role Reassignment Patterns ---
    role_reassignment = [
        (
            "you_are_now",
            r"(?i)\byou\s+are\s+now\b",
        ),
        (
            "act_as",
            r"(?i)\bact\s+as\b",
        ),
        (
            "pretend_to_be",
            r"(?i)\bpretend\s+(?:to\s+be|you(?:'re|\s+are))\b",
        ),
        (
            "roleplay_as",
            r"(?i)\b(?:roleplay|role[\s-]?play)\s+(?:as|being)\b",
        ),
        (
            "switch_persona",
            r"(?i)\b(?:switch|change|adopt)\s+(?:your\s+)?(?:persona|role|character|identity)\b",
        ),
        (
            "from_now_on",
            r"(?i)\bfrom\s+now\s+on\b[^.]{0,40}\byou\s+(?:are|will|must|should)\b",
        ),
    ]
    for name, pat in role_reassignment:
        try:
            patterns.append(
                InjectionPattern(
                    name=name,
                    pattern=re.compile(pat),
                    category="role_reassignment",
                )
            )
        except re.error as e:
            logger.warning("Failed to compile pattern %s: %s", name, e)

    # --- System Prompt Extraction Patterns ---
    system_prompt_extraction = [
        (
            "repeat_system_prompt",
            r"(?i)\b(?:repeat|show|display|print|output|reveal|tell\s+me)\b[^.]{0,30}"
            r"\b(?:system\s+prompt|instructions?|initial\s+prompt|hidden\s+prompt)\b",
        ),
        (
            "show_instructions",
            r"(?i)\b(?:show|reveal|display|give)\s+(?:me\s+)?(?:your\s+)?"
            r"(?:instructions?|rules?|prompt|configuration|directives?)\b",
        ),
        (
            "what_are_your_instructions",
            r"(?i)\bwhat\s+(?:are|were)\s+(?:your|the)\s+"
            r"(?:instructions?|rules?|prompts?|guidelines?|directives?)\b",
        ),
        (
            "system_message_leak",
            r"(?i)\b(?:system|developer|hidden|secret)\s+"
            r"(?:message|prompt|instructions?|text)\b",
        ),
    ]
    for name, pat in system_prompt_extraction:
        try:
            patterns.append(
                InjectionPattern(
                    name=name,
                    pattern=re.compile(pat),
                    category="system_prompt_extraction",
                )
            )
        except re.error as e:
            logger.warning("Failed to compile pattern %s: %s", name, e)

    # --- Obfuscated Payload Patterns ---
    obfuscated_payloads = [
        (
            "base64_payload",
            r"(?i)(?:base64|b64|encoded)[\s:]*[A-Za-z0-9+/]{20,}={0,2}",
        ),
        (
            "base64_raw_long",
            r"[A-Za-z0-9+/]{40,}={0,2}",
        ),
        (
            "hex_payload",
            r"(?i)(?:hex|0x|\\x)[\s:]*(?:[0-9a-fA-F]{2}[\s,]*){10,}",
        ),
        (
            "markdown_code_fence",
            r"```(?:system|prompt|instructions?|ignore|override)[^`]*```",
        ),
        (
            "code_fence_injection",
            r"```[^`]*(?:ignore|disregard|you\s+are\s+now|act\s+as|system\s+prompt)[^`]*```",
        ),
    ]
    for name, pat in obfuscated_payloads:
        try:
            patterns.append(
                InjectionPattern(
                    name=name,
                    pattern=re.compile(pat, re.DOTALL),
                    category="obfuscated_payload",
                )
            )
        except re.error as e:
            logger.warning("Failed to compile pattern %s: %s", name, e)

    # --- Social Engineering / Manipulation Patterns ---
    social_engineering = [
        (
            "developer_claim",
            r"(?i)\bi\s+am\s+(?:your\s+)?(?:developer|creator|programmer|admin)\b",
        ),
        (
            "red_team_exercise",
            r"(?i)\b(?:red[\s-]?team|penetration\s+test|security\s+test)\b",
        ),
        (
            "drop_character",
            r"(?i)\b(?:drop|break|stop|end|quit|exit)\s+(?:your\s+)?"
            r"(?:character|persona|act|acting|pretending|roleplay)\b",
        ),
        (
            "game_over",
            r"(?i)\b(?:game|exercise|simulation|test|experiment)\s+"
            r"(?:is\s+)?(?:over|ended|done|finished|complete)\b",
        ),
        (
            "stop_pretending",
            r"(?i)\bstop\s+(?:pretending|acting|faking|playing)\b",
        ),
        (
            "you_are_ai",
            r"(?i)\byou\s+(?:are|'re)\s+(?:actually\s+)?(?:an?\s+)?"
            r"(?:AI|bot|chatbot|program|machine|artificial)\b",
        ),
        (
            "i_know_you_are",
            r"(?i)\bi\s+know\s+(?:you\s+(?:are|'re)|that\s+you)\s+"
            r"(?:an?\s+)?(?:AI|bot|not\s+(?:real|human))\b",
        ),
        (
            "hypothetical_scenario",
            r"(?i)\b(?:hypothetical|imagine|suppose|what\s+if)\b[^.]{0,30}"
            r"\b(?:uncensored|unrestricted|no\s+(?:rules|limits|filters))\b",
        ),
        (
            "academic_framing",
            r"(?i)\b(?:academic|research|study|paper|screenplay|fiction)\b[^.]{0,80}"
            r"\b(?:AI|drops?\s+(?:its?|their)\s+guard|reveals?|breaks?\s+character)\b",
        ),
        (
            "ai_drops_guard",
            r"(?i)\b(?:AI|bot|system)\s+(?:drops?|lowers?|removes?)\s+"
            r"(?:its?|their|the)\s+(?:guard|defenses?|filters?|safety)\b",
        ),
        (
            "authority_impersonation",
            r"(?i)\b(?:police|FBI|SPF|government|authority|officer)\b[^.]{0,40}"
            r"\b(?:verify|confirm|state|reveal)\s+(?:your|identity|nature)\b",
        ),
        (
            "confirm_understand",
            r"(?i)\b(?:confirm|acknowledge|verify)\s+(?:you\s+)?understand\b",
        ),
        (
            "talk_normally",
            r"(?i)\b(?:talk|speak|respond|answer)\s+(?:to\s+me\s+)?"
            r"(?:normally|directly|honestly|like\s+(?:a\s+normal|ChatGPT))\b",
        ),
    ]
    for name, pat in social_engineering:
        try:
            patterns.append(
                InjectionPattern(
                    name=name,
                    pattern=re.compile(pat),
                    category="social_engineering",
                )
            )
        except re.error as e:
            logger.warning("Failed to compile pattern %s: %s", name, e)

    return patterns


class SafetyFilter:
    """Input defense boundary for prompt injection detection and sanitization.

    Screens inbound scammer messages for prompt injection attacks using
    deterministic pattern matching. Provides scan, sanitize, and blocking
    functionality per the RoadBlock pipeline requirements.

    Attributes:
        injection_patterns: List of InjectionPattern instances used for detection.
    """

    def __init__(
        self, injection_patterns: list[InjectionPattern] | None = None
    ) -> None:
        """Initialize the SafetyFilter with injection detection patterns.

        Args:
            injection_patterns: Optional list of custom InjectionPattern instances.
                If None, uses the default built-in pattern set covering instruction
                overrides, role reassignment, system prompt extraction, and
                obfuscated payloads.
        """
        if injection_patterns is not None:
            self.injection_patterns = injection_patterns
        else:
            self.injection_patterns = _build_default_patterns()

    def scan(self, raw_message: str) -> ScanResult:
        """Scan a message for injection patterns within a 2-second timeout.

        Runs all configured patterns against the raw message. If scanning
        exceeds the timeout, returns results gathered so far.

        Args:
            raw_message: The raw, unprocessed scammer message.

        Returns:
            ScanResult containing sanitized content, list of detected pattern
            names, and whether the message is fully blocked.
        """
        try:
            matches: list[PatternMatch] = []
            detected_names: list[str] = []

            # Use a threading timer for timeout enforcement
            timed_out = threading.Event()
            timer = threading.Timer(_SCAN_TIMEOUT_SECONDS, timed_out.set)
            timer.start()

            try:
                for pattern in self.injection_patterns:
                    if timed_out.is_set():
                        logger.warning(
                            "Safety filter scan timed out after %ss",
                            _SCAN_TIMEOUT_SECONDS,
                        )
                        break
                    try:
                        for match in pattern.pattern.finditer(raw_message):
                            matches.append(
                                PatternMatch(
                                    pattern_name=pattern.name,
                                    matched_text=match.group(),
                                    start=match.start(),
                                    end=match.end(),
                                )
                            )
                            if pattern.name not in detected_names:
                                detected_names.append(pattern.name)
                    except Exception as e:
                        logger.warning(
                            "Error scanning pattern %s: %s", pattern.name, e
                        )
                        continue
            finally:
                timer.cancel()

            # Sanitize the message
            sanitized = self.sanitize(raw_message, matches)

            # Build initial scan result to check blocking
            scan_result = ScanResult(
                sanitized_content=sanitized,
                detected_patterns=detected_names,
                is_blocked=False,
            )

            # Determine if fully blocked
            is_blocked = self.is_fully_blocked(scan_result, raw_message, matches)

            return ScanResult(
                sanitized_content=sanitized,
                detected_patterns=detected_names,
                is_blocked=is_blocked,
            )

        except Exception as e:
            logger.error("Safety filter scan failed: %s", e)
            # On any failure, return the original message unsanitized
            # to avoid blocking legitimate messages
            return ScanResult(
                sanitized_content=raw_message,
                detected_patterns=[],
                is_blocked=False,
            )

    def sanitize(
        self, raw_message: str, detected_patterns: list[PatternMatch]
    ) -> str:
        """Strip adversarial tokens while preserving legitimate content.

        Removes detected injection pattern matches from the message,
        preserving the remaining legitimate content. Overlapping matches
        are merged before removal to prevent index corruption. Cleans up
        extra whitespace left by removals.

        Args:
            raw_message: The original unprocessed message.
            detected_patterns: List of PatternMatch instances to remove.

        Returns:
            The sanitized message with adversarial tokens stripped.
        """
        try:
            if not detected_patterns:
                return raw_message

            # Merge overlapping/adjacent spans to avoid index corruption
            sorted_matches = sorted(detected_patterns, key=lambda m: m.start)
            merged_spans: list[tuple[int, int]] = []
            for match in sorted_matches:
                if merged_spans and match.start <= merged_spans[-1][1]:
                    # Overlapping or adjacent — extend the existing span
                    merged_spans[-1] = (
                        merged_spans[-1][0],
                        max(merged_spans[-1][1], match.end),
                    )
                else:
                    merged_spans.append((match.start, match.end))

            # Remove merged spans from end to start to preserve indices
            result = raw_message
            for start, end in reversed(merged_spans):
                result = result[:start] + " " + result[end:]

            # Clean up multiple consecutive spaces and strip
            result = re.sub(r"\s{2,}", " ", result).strip()

            return result

        except Exception as e:
            logger.error("Sanitization failed: %s", e)
            return raw_message

    def is_fully_blocked(
        self,
        scan_result: ScanResult,
        raw_message: str | None = None,
        matches: list[PatternMatch] | None = None,
    ) -> bool:
        """Determine if a message should be fully blocked.

        Returns True when ≥80% of the message tokens match injection
        patterns, indicating no legitimate conversational content.

        A token is considered part of an injection if it is directly
        covered by a pattern match OR if it sits between two injection
        matches (serving as a connector word within injection context).

        Args:
            scan_result: The ScanResult from scanning.
            raw_message: The original raw message (for token counting).
                If None, uses scan_result.sanitized_content for estimation.
            matches: The list of PatternMatch instances found during scan.
                If None, uses heuristic based on sanitized content.

        Returns:
            True if ≥80% of tokens are injection patterns.
        """
        try:
            # If no patterns detected, not blocked
            if not scan_result.detected_patterns:
                return False

            # Tokenize the original message (whitespace-delimited)
            if raw_message is None:
                return False

            original_tokens = raw_message.split()
            total_token_count = len(original_tokens)

            if total_token_count == 0:
                return False

            if matches is not None and matches:
                # Build a set of character positions covered by matches
                covered_positions: set[int] = set()
                for match in matches:
                    for i in range(match.start, match.end):
                        covered_positions.add(i)

                # Find each token's position and whether it's directly covered
                token_infos: list[tuple[int, int, bool]] = []
                for token_match in re.finditer(r"\S+", raw_message):
                    token_start = token_match.start()
                    token_end = token_match.end()
                    token_len = token_end - token_start

                    overlap = sum(
                        1 for i in range(token_start, token_end)
                        if i in covered_positions
                    )
                    directly_covered = overlap > token_len * 0.5
                    token_infos.append((token_start, token_end, directly_covered))

                # Mark tokens between two directly-covered tokens as injection
                # context (connector words that are part of the injection phrase)
                injection_flags = [info[2] for info in token_infos]
                for i in range(len(injection_flags)):
                    if not injection_flags[i]:
                        # Check if there's a covered token before and after
                        has_before = any(
                            injection_flags[j] for j in range(max(0, i - 3), i)
                        )
                        has_after = any(
                            injection_flags[j]
                            for j in range(i + 1, min(len(injection_flags), i + 4))
                        )
                        if has_before and has_after:
                            injection_flags[i] = True

                injection_token_count = sum(injection_flags)
                ratio = injection_token_count / total_token_count
            else:
                # Heuristic: compare sanitized tokens to original tokens
                sanitized_tokens = scan_result.sanitized_content.split()
                remaining_count = len(sanitized_tokens)
                removed_count = total_token_count - remaining_count
                ratio = (
                    removed_count / total_token_count
                    if total_token_count > 0
                    else 0.0
                )

            return ratio >= 0.80

        except Exception as e:
            logger.error("Blocking check failed: %s", e)
            return False
