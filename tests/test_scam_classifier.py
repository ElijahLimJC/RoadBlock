"""Property-based tests for ScamClassifier.

Validates correctness properties defined in the email-scam-ingestion design document.
"""

from typing import Literal

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from components.scam_classifier import ScamClassifier
from models.email_models import ScamPattern

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Strategy for generating valid ScamPattern instances with random weights
scam_pattern_strategy = st.builds(
    ScamPattern,
    name=st.text(min_size=1, max_size=20, alphabet=st.characters(categories=("L", "N"))),
    regex=st.sampled_from([
        r"urgent",
        r"act now",
        r"limited time",
        r"verify your account",
        r"congratulations",
        r"winner",
        r"click here",
        r"bank transfer",
        r"western union",
        r"bitcoin",
    ]),
    category=st.sampled_from(["urgency", "financial_lure", "impersonation", "phishing"]),
    weight=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
)

# Strategy for generating lists of ScamPatterns
pattern_list_strategy = st.lists(scam_pattern_strategy, min_size=1, max_size=10)

# Strategy for email content
email_subject_strategy = st.text(min_size=0, max_size=200)
email_body_strategy = st.text(min_size=0, max_size=500)


# ---------------------------------------------------------------------------
# Property 3: Confidence score bounded output (Task 2.2)
# ---------------------------------------------------------------------------


class TestConfidenceScoreBounded:
    """Property 3: Confidence score bounded output.

    **Validates: Requirements 7.6**

    For any set of patterns with weights in [0.0, 1.0] and any email content,
    _stage_1_regex SHALL always return a value >= 0.0 and <= 1.0.
    """

    @given(
        patterns=pattern_list_strategy,
        subject=email_subject_strategy,
        body=email_body_strategy,
    )
    @settings(max_examples=200)
    def test_stage_1_score_always_bounded(
        self, patterns: list[ScamPattern], subject: str, body: str
    ) -> None:
        """_stage_1_regex always returns a score in [0.0, 1.0]."""
        classifier = ScamClassifier(
            patterns=patterns,
            llm_client=None,
            confidence_threshold=0.7,
            fallback_threshold=0.3,
        )

        score = classifier._stage_1_regex(subject, body)

        assert score >= 0.0, f"Score {score} is below 0.0"
        assert score <= 1.0, f"Score {score} exceeds 1.0"


# ---------------------------------------------------------------------------
# Property 4: Zero-weight pattern invariant (Task 2.3)
# ---------------------------------------------------------------------------


class TestZeroWeightPatternInvariant:
    """Property 4: Zero-weight pattern invariant.

    **Validates: Requirements 7.5**

    For any set of patterns and email content, adding a pattern with weight 0.0
    SHALL NOT change the confidence score.
    """

    @given(
        patterns=pattern_list_strategy,
        subject=email_subject_strategy,
        body=email_body_strategy,
        zero_pattern_name=st.text(
            min_size=1, max_size=10, alphabet=st.characters(categories=("L", "N"))
        ),
        zero_pattern_regex=st.sampled_from([
            r"zero_weight_pattern_xyzzy",
            r"noop_match_qwerty",
            r"placeholder_abc123",
        ]),
        zero_pattern_category=st.sampled_from([
            "urgency", "financial_lure", "impersonation", "phishing"
        ]),
    )
    @settings(max_examples=200)
    def test_zero_weight_pattern_does_not_change_score(
        self,
        patterns: list[ScamPattern],
        subject: str,
        body: str,
        zero_pattern_name: str,
        zero_pattern_regex: str,
        zero_pattern_category: Literal[
            "urgency", "financial_lure", "impersonation", "phishing"
        ],
    ) -> None:
        """Adding a zero-weight pattern leaves the confidence score unchanged."""
        classifier_without = ScamClassifier(
            patterns=patterns,
            llm_client=None,
            confidence_threshold=0.7,
            fallback_threshold=0.3,
        )
        score_without = classifier_without._stage_1_regex(subject, body)

        zero_pattern = ScamPattern(
            name=zero_pattern_name,
            regex=zero_pattern_regex,
            category=zero_pattern_category,
            weight=0.0,
        )
        patterns_with_zero = patterns + [zero_pattern]

        classifier_with = ScamClassifier(
            patterns=patterns_with_zero,
            llm_client=None,
            confidence_threshold=0.7,
            fallback_threshold=0.3,
        )
        score_with = classifier_with._stage_1_regex(subject, body)

        assert score_with == score_without, (
            f"Score changed from {score_without} to {score_with} "
            f"after adding zero-weight pattern"
        )


# ---------------------------------------------------------------------------
# Property 5: Stage 1 classification determinism (Task 2.4)
# ---------------------------------------------------------------------------


class TestStage1Determinism:
    """Property 5: Stage 1 classification determinism.

    **Validates: Requirements 2.11**

    For any email and fixed classifier config, classifying the same email
    twice SHALL produce identical confidence scores from _stage_1_regex.
    """

    @given(
        patterns=pattern_list_strategy,
        subject=email_subject_strategy,
        body=email_body_strategy,
    )
    @settings(max_examples=200)
    def test_same_input_produces_same_score(
        self, patterns: list[ScamPattern], subject: str, body: str
    ) -> None:
        """_stage_1_regex is deterministic: same inputs yield same output."""
        classifier = ScamClassifier(
            patterns=patterns,
            llm_client=None,
            confidence_threshold=0.7,
            fallback_threshold=0.3,
        )

        score_1 = classifier._stage_1_regex(subject, body)
        score_2 = classifier._stage_1_regex(subject, body)

        assert score_1 == score_2, (
            f"Non-deterministic: first call returned {score_1}, "
            f"second call returned {score_2}"
        )


# ---------------------------------------------------------------------------
# Property 7: Threshold validation rejects invalid ranges (Task 2.5)
# ---------------------------------------------------------------------------


class TestThresholdValidationRejectsInvalid:
    """Property 7: Threshold validation rejects invalid ranges.

    **Validates: Requirements 3.5, 3.6**

    For any float outside [0.0, 1.0], ScamClassifier SHALL raise ValueError
    at init for invalid confidence or fallback thresholds.
    """

    @given(
        invalid_confidence=st.floats(allow_nan=False, allow_infinity=False).filter(
            lambda x: x < 0.0 or x > 1.0
        ),
    )
    @settings(max_examples=200)
    def test_invalid_confidence_threshold_raises(
        self, invalid_confidence: float
    ) -> None:
        """ScamClassifier raises ValueError for confidence_threshold outside [0.0, 1.0]."""
        with pytest.raises(ValueError):
            ScamClassifier(
                patterns=[],
                llm_client=None,
                confidence_threshold=invalid_confidence,
                fallback_threshold=0.3,
            )

    @given(
        invalid_fallback=st.floats(allow_nan=False, allow_infinity=False).filter(
            lambda x: x < 0.0 or x > 1.0
        ),
    )
    @settings(max_examples=200)
    def test_invalid_fallback_threshold_raises(
        self, invalid_fallback: float
    ) -> None:
        """ScamClassifier raises ValueError for fallback_threshold outside [0.0, 1.0]."""
        with pytest.raises(ValueError):
            ScamClassifier(
                patterns=[],
                llm_client=None,
                confidence_threshold=0.7,
                fallback_threshold=invalid_fallback,
            )


# ---------------------------------------------------------------------------
# Property 8: Fallback-greater-than-confidence rejection (Task 2.6)
# ---------------------------------------------------------------------------


class TestFallbackGreaterThanConfidenceRejection:
    """Property 8: Fallback-greater-than-confidence rejection.

    **Validates: Requirements 3.7**

    For any pair of floats where Fallback_Threshold > Confidence_Threshold
    (both in [0.0, 1.0]), attempting to initialize the Scam_Classifier SHALL
    raise a validation error.
    """

    @given(
        fallback=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
        confidence=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    )
    @settings(max_examples=200)
    def test_raises_valueerror_when_fallback_exceeds_confidence(
        self, fallback: float, confidence: float
    ) -> None:
        """ScamClassifier raises ValueError when fallback_threshold > confidence_threshold."""
        assume(fallback > confidence)

        with pytest.raises(ValueError):
            ScamClassifier(
                patterns=[],
                llm_client=None,
                confidence_threshold=confidence,
                fallback_threshold=fallback,
            )


# ---------------------------------------------------------------------------
# Property 6: Threshold routing correctness (Task 4.3)
# ---------------------------------------------------------------------------


class TestThresholdRoutingCorrectness:
    """Property 6: Threshold routing correctness.

    **Validates: Requirements 2.3, 2.4, 3.3, 3.4**

    For any valid EmailMessage and valid threshold configuration:
    - If Stage 1 confidence >= threshold, determining_stage == "stage_1"
      (scam classified without LLM).
    - If Stage 1 confidence < threshold, Stage 2 LLM is invoked.
    """

    @given(
        patterns=pattern_list_strategy,
        subject=st.text(min_size=1, max_size=100),
        body=st.text(min_size=1, max_size=300).filter(lambda x: x.strip() != ""),
        confidence_threshold=st.floats(
            min_value=0.01, max_value=0.99, allow_nan=False, allow_infinity=False
        ),
    )
    @settings(max_examples=200)
    def test_high_confidence_skips_llm(
        self,
        patterns: list[ScamPattern],
        subject: str,
        body: str,
        confidence_threshold: float,
    ) -> None:
        """If Stage 1 confidence >= threshold, result uses stage_1 without LLM."""
        from unittest.mock import MagicMock

        from models.email_models import EmailMessage

        mock_llm = MagicMock()

        classifier = ScamClassifier(
            patterns=patterns,
            llm_client=mock_llm,
            confidence_threshold=confidence_threshold,
            fallback_threshold=0.0,
        )

        # Compute what Stage 1 would produce
        stage_1_score = classifier._stage_1_regex(subject, body)

        # Build a valid EmailMessage
        try:
            email = EmailMessage(
                sender="test@example.com",
                subject=subject,
                body=body,
            )
        except Exception:
            # If EmailMessage validation rejects the generated content, skip
            assume(False)
            return

        result = classifier.classify(email)

        if stage_1_score >= confidence_threshold:
            assert result.determining_stage == "stage_1", (
                f"Expected stage_1 when score {stage_1_score} >= "
                f"threshold {confidence_threshold}, "
                f"got {result.determining_stage}"
            )
            # LLM should NOT have been called
            mock_llm.generate_content.assert_not_called()

    @given(
        patterns=pattern_list_strategy,
        subject=st.text(min_size=1, max_size=100),
        body=st.text(min_size=1, max_size=300).filter(lambda x: x.strip() != ""),
        confidence_threshold=st.floats(
            min_value=0.01, max_value=0.99, allow_nan=False, allow_infinity=False
        ),
    )
    @settings(max_examples=200)
    def test_low_confidence_invokes_llm(
        self,
        patterns: list[ScamPattern],
        subject: str,
        body: str,
        confidence_threshold: float,
    ) -> None:
        """If Stage 1 confidence < threshold, Stage 2 LLM is invoked."""
        from unittest.mock import MagicMock

        from models.email_models import EmailMessage

        # Mock LLM that returns a valid JSON response
        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '{"verdict": "scam", "reasoning": "test reasoning"}'
        mock_llm.generate_content.return_value = mock_response

        classifier = ScamClassifier(
            patterns=patterns,
            llm_client=mock_llm,
            confidence_threshold=confidence_threshold,
            fallback_threshold=0.0,
        )

        # Compute what Stage 1 would produce
        stage_1_score = classifier._stage_1_regex(subject, body)

        # Build a valid EmailMessage
        try:
            email = EmailMessage(
                sender="test@example.com",
                subject=subject,
                body=body,
            )
        except Exception:
            assume(False)
            return

        result = classifier.classify(email)

        if stage_1_score < confidence_threshold:
            # LLM should have been called
            mock_llm.generate_content.assert_called_once()
            assert result.determining_stage == "stage_2", (
                f"Expected stage_2 when score {stage_1_score} < "
                f"threshold {confidence_threshold}, "
                f"got {result.determining_stage}"
            )


# ---------------------------------------------------------------------------
# Property 9: LLM response validation rejects non-conforming output (Task 4.4)
# ---------------------------------------------------------------------------


class TestLLMResponseValidationRejectsNonConforming:
    """Property 9: LLM response validation rejects non-conforming output.

    **Validates: Requirements 2.7, 2.9**

    For any string that does not conform to the expected JSON schema,
    _validate_llm_response SHALL return None.
    """

    @given(
        arbitrary_text=st.text(min_size=0, max_size=500),
    )
    @settings(max_examples=200)
    def test_non_json_strings_rejected(self, arbitrary_text: str) -> None:
        """Non-JSON strings are rejected by _validate_llm_response."""
        import json

        # Filter out strings that happen to be valid conforming JSON
        try:
            data = json.loads(arbitrary_text)
            if (
                isinstance(data, dict)
                and data.get("verdict") in ("scam", "not-scam")
                and isinstance(data.get("reasoning"), str)
            ):
                assume(False)
        except (json.JSONDecodeError, TypeError):
            pass  # This is what we want: non-JSON strings

        classifier = ScamClassifier(
            patterns=[],
            llm_client=None,
            confidence_threshold=0.7,
            fallback_threshold=0.3,
        )

        result = classifier._validate_llm_response(arbitrary_text)
        assert result is None, (
            f"Expected None for non-conforming input, got {result}"
        )

    @given(
        wrong_verdict=st.text(min_size=1, max_size=50).filter(
            lambda x: x not in ("scam", "not-scam")
        ),
        reasoning=st.text(min_size=1, max_size=100),
    )
    @settings(max_examples=200)
    def test_json_with_wrong_verdict_rejected(
        self, wrong_verdict: str, reasoning: str
    ) -> None:
        """JSON with invalid verdict values is rejected."""
        import json

        payload = json.dumps({"verdict": wrong_verdict, "reasoning": reasoning})

        classifier = ScamClassifier(
            patterns=[],
            llm_client=None,
            confidence_threshold=0.7,
            fallback_threshold=0.3,
        )

        result = classifier._validate_llm_response(payload)
        assert result is None, (
            f"Expected None for wrong verdict '{wrong_verdict}', got {result}"
        )

    @given(
        verdict=st.sampled_from(["scam", "not-scam"]),
    )
    @settings(max_examples=200)
    def test_json_missing_reasoning_rejected(self, verdict: str) -> None:
        """JSON without 'reasoning' field is rejected."""
        import json

        payload = json.dumps({"verdict": verdict})

        classifier = ScamClassifier(
            patterns=[],
            llm_client=None,
            confidence_threshold=0.7,
            fallback_threshold=0.3,
        )

        result = classifier._validate_llm_response(payload)
        assert result is None, (
            f"Expected None for missing reasoning, got {result}"
        )

    @given(
        verdict=st.sampled_from(["scam", "not-scam"]),
        non_string_reasoning=st.one_of(
            st.integers(),
            st.floats(allow_nan=False),
            st.booleans(),
            st.lists(st.integers(), max_size=3),
            st.none(),
        ),
    )
    @settings(max_examples=200)
    def test_json_with_non_string_reasoning_rejected(
        self, verdict: str, non_string_reasoning: object
    ) -> None:
        """JSON with non-string 'reasoning' field is rejected."""
        import json

        payload = json.dumps({"verdict": verdict, "reasoning": non_string_reasoning})

        classifier = ScamClassifier(
            patterns=[],
            llm_client=None,
            confidence_threshold=0.7,
            fallback_threshold=0.3,
        )

        result = classifier._validate_llm_response(payload)
        assert result is None, (
            f"Expected None for non-string reasoning "
            f"{type(non_string_reasoning).__name__}, got {result}"
        )

    @given(
        data=st.one_of(
            st.integers(),
            st.floats(allow_nan=False),
            st.booleans(),
            st.lists(st.integers(), max_size=3),
        ),
    )
    @settings(max_examples=200)
    def test_valid_json_but_not_dict_rejected(self, data: object) -> None:
        """Valid JSON that is not a dict is rejected."""
        import json

        payload = json.dumps(data)

        classifier = ScamClassifier(
            patterns=[],
            llm_client=None,
            confidence_threshold=0.7,
            fallback_threshold=0.3,
        )

        result = classifier._validate_llm_response(payload)
        assert result is None, (
            f"Expected None for non-dict JSON ({type(data).__name__}), "
            f"got {result}"
        )
