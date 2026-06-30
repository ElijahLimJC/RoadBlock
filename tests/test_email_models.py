"""Property-based tests for email ingestion Pydantic models.

Validates: Requirements 1.7, 6.6, 6.7
"""

from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from models.email_models import ClassificationResult, EmailMessage


# ---------------------------------------------------------------------------
# Hypothesis strategies for generating valid EmailMessage instances
# ---------------------------------------------------------------------------

# Strategy for valid RFC 5322 addr-spec addresses matching ^[^@\s]+@[^@\s]+\.[^@\s]+$
_local_part_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!#$%&'*+/=?^_`{|}~-"
_domain_label_chars = "abcdefghijklmnopqrstuvwxyz0123456789"


@st.composite
def rfc5322_addresses(draw: st.DrawFn) -> str:
    """Generate valid email addresses matching the EmailMessage sender regex.

    Format: local@domain.tld where no whitespace or @ in parts,
    and domain has at least one dot.
    """
    local_part = draw(
        st.text(
            alphabet=st.sampled_from(_local_part_chars),
            min_size=1,
            max_size=64,
        )
    )
    # Domain label (before dot)
    domain_label = draw(
        st.text(
            alphabet=st.sampled_from(_domain_label_chars),
            min_size=1,
            max_size=63,
        )
    )
    # TLD (after dot)
    tld = draw(
        st.text(
            alphabet=st.sampled_from(_domain_label_chars),
            min_size=2,
            max_size=10,
        )
    )
    address = f"{local_part}@{domain_label}.{tld}"
    # Enforce max 254 chars per RFC 5321
    if len(address) > 254:
        address = address[:254]
        # Re-validate structure after truncation; just regenerate a short one
        address = f"{local_part[:10]}@{domain_label[:10]}.{tld[:5]}"
    return address


@st.composite
def valid_subjects(draw: st.DrawFn) -> str:
    """Generate valid subject strings (max 998 chars)."""
    return draw(
        st.text(
            alphabet=st.characters(categories=("L", "N", "P", "S", "Z")),
            min_size=0,
            max_size=998,
        )
    )


@st.composite
def valid_bodies(draw: st.DrawFn) -> str:
    """Generate valid body strings (non-empty after strip, max 1,000,000 chars).

    We generate printable content with at least one non-whitespace character.
    """
    # Generate a non-whitespace core to guarantee body.strip() is non-empty
    core = draw(
        st.text(
            alphabet=st.characters(categories=("L", "N", "P", "S")),
            min_size=1,
            max_size=1000,
        ).filter(lambda s: len(s.strip()) > 0)
    )
    # Optionally wrap with leading/trailing whitespace
    leading = draw(st.text(alphabet=st.just(" "), min_size=0, max_size=5))
    trailing = draw(st.text(alphabet=st.just(" "), min_size=0, max_size=5))
    return leading + core + trailing


# Strategy for valid datetime values (avoid timezone edge cases with naive UTC)
valid_datetimes = st.datetimes(
    min_value=datetime(2000, 1, 1),
    max_value=datetime(2030, 12, 31),
)


@st.composite
def valid_email_messages(draw: st.DrawFn) -> EmailMessage:
    """Generate valid EmailMessage instances with arbitrary fields."""
    sender = draw(rfc5322_addresses())
    subject = draw(valid_subjects())
    body = draw(valid_bodies())
    message_id = draw(st.text(min_size=0, max_size=50))
    reply_to = draw(st.text(min_size=0, max_size=50))
    date_header = draw(st.text(min_size=0, max_size=50))
    timestamp = draw(valid_datetimes)

    return EmailMessage(
        sender=sender,
        subject=subject,
        body=body,
        message_id=message_id,
        reply_to=reply_to,
        date_header=date_header,
        timestamp=timestamp,
    )


# ---------------------------------------------------------------------------
# Property 1: Email_Message serialization round-trip
# ---------------------------------------------------------------------------


class TestEmailMessageRoundTrip:
    """Property 1: Email_Message serialization round-trip.

    **Validates: Requirements 1.7, 6.6**

    For any valid EmailMessage instance, serializing to JSON and deserializing
    back SHALL produce an object with identical sender, subject, body, and
    timestamp.
    """

    @given(email=valid_email_messages())
    @settings(max_examples=200)
    def test_email_message_serialization_round_trip(self, email: EmailMessage) -> None:
        """EmailMessage survives JSON round-trip for sender, subject, body, timestamp."""
        json_str = email.model_dump_json()
        restored = EmailMessage.model_validate_json(json_str)

        assert restored.sender == email.sender
        assert restored.subject == email.subject
        assert restored.body == email.body
        assert restored.timestamp == email.timestamp


# ---------------------------------------------------------------------------
# Hypothesis strategies for generating valid ClassificationResult instances
# ---------------------------------------------------------------------------

classification_verdicts = st.sampled_from(["scam", "not_scam"])
classification_stages = st.sampled_from(["stage_1", "stage_2"])
confidence_scores = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
classification_timestamps = st.datetimes(
    min_value=datetime(2000, 1, 1),
    max_value=datetime(2030, 12, 31),
    timezones=st.just(timezone.utc),
)
pattern_names = st.lists(st.text(min_size=1, max_size=50), max_size=10)
reasoning_strings = st.text(max_size=200)
sender_strings = st.text(max_size=100)
subject_strings = st.text(max_size=200)


@st.composite
def valid_classification_results(draw: st.DrawFn) -> ClassificationResult:
    """Generate valid ClassificationResult instances with sampled verdicts and stages."""
    return ClassificationResult(
        verdict=draw(classification_verdicts),
        confidence=draw(confidence_scores),
        determining_stage=draw(classification_stages),
        matched_patterns=draw(pattern_names),
        llm_reasoning=draw(reasoning_strings),
        timestamp=draw(classification_timestamps),
        sender=draw(sender_strings),
        subject=draw(subject_strings),
    )


# ---------------------------------------------------------------------------
# Property 2: Classification_Result serialization round-trip
# ---------------------------------------------------------------------------


class TestClassificationResultRoundTrip:
    """Property 2: Classification_Result serialization round-trip.

    **Validates: Requirements 6.7**

    For any valid ClassificationResult instance, serializing to JSON and
    deserializing back SHALL produce an object with identical verdict,
    confidence, and determining_stage.
    """

    @given(result=valid_classification_results())
    @settings(max_examples=200)
    def test_classification_result_serialization_round_trip(
        self, result: ClassificationResult
    ) -> None:
        """ClassificationResult survives JSON round-trip for verdict, confidence, stage."""
        json_str = result.model_dump_json()
        restored = ClassificationResult.model_validate_json(json_str)

        assert restored.verdict == result.verdict
        assert restored.confidence == result.confidence
        assert restored.determining_stage == result.determining_stage
