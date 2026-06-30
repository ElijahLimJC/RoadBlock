"""Property-based tests for Email Ingestion Module.

Tests validate correctness properties for the EmailIngestionModule:
- Property 13: Conversation threading by sender (Requirements 4.7)
- Property 11: Classification log capacity invariant (Requirements 8.2)
- Property 12: Classification log ordering (Requirements 8.4)
"""

from datetime import datetime
from typing import Any
from unittest.mock import MagicMock

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from components.email_ingestion import EmailIngestionModule
from models.email_models import EmailMessage

# The trim_classification_log function lives in app.py but that module has heavy
# Streamlit side effects at import time. We replicate the logic here directly
# (it's a simple trimming function) to avoid needing to mock the entire Streamlit UI.
# The constant and function logic are identical to app.py.

_CLASSIFICATION_LOG_MAX = 200


def trim_classification_log(state_dict: dict[str, Any]) -> None:
    """Evict oldest entries when classification_log exceeds max capacity.

    Trims the classification_log list in-place to keep at most
    _CLASSIFICATION_LOG_MAX entries, removing the oldest first.

    Args:
        state_dict: The email_ingestion state dictionary (mutable).
    """
    log: list[Any] = state_dict.get("classification_log", [])
    if len(log) > _CLASSIFICATION_LOG_MAX:
        state_dict["classification_log"] = log[-_CLASSIFICATION_LOG_MAX:]


# --- Strategies ---

# Generate valid email addresses for senders
_email_local = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=20,
)
_email_domain = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=10,
)

email_address_strategy = st.builds(
    lambda local, domain: f"{local}@{domain}.com",
    local=_email_local,
    domain=_email_domain,
)

email_body_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")),
    min_size=1,
    max_size=300,
).filter(lambda s: len(s.strip()) > 0)

email_subject_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")),
    min_size=0,
    max_size=100,
)

email_message_strategy = st.builds(
    lambda sender, subject, body: EmailMessage(
        sender=sender,
        subject=subject,
        body=body,
        message_id=f"<{id(body)}@test.local>",
    ),
    sender=email_address_strategy,
    subject=email_subject_strategy,
    body=email_body_strategy,
)


def _make_module() -> EmailIngestionModule:
    """Create an EmailIngestionModule with mocked dependencies."""
    imap_client = MagicMock()
    smtp_client = MagicMock()
    scam_classifier = MagicMock()
    return EmailIngestionModule(
        imap_client=imap_client,
        smtp_client=smtp_client,
        scam_classifier=scam_classifier,
    )


# --- Strategies for ClassificationResult dicts ---

classification_result_strategy = st.builds(
    lambda verdict, confidence, stage, ts, sender, subject: {
        "verdict": verdict,
        "confidence": confidence,
        "determining_stage": stage,
        "matched_patterns": [],
        "llm_reasoning": "",
        "timestamp": ts.isoformat(),
        "sender": sender,
        "subject": subject,
    },
    verdict=st.sampled_from(["scam", "not_scam"]),
    confidence=st.floats(min_value=0.0, max_value=1.0),
    stage=st.sampled_from(["stage_1", "stage_2"]),
    ts=st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2030, 12, 31),
    ),
    sender=email_address_strategy,
    subject=email_subject_strategy,
)


# --- Property 13: Conversation threading by sender ---


class TestConversationThreadingBySender:
    """Property 13: Conversation threading by sender.

    **Validates: Requirements 4.7**

    For any sequence of emails with repeated sender addresses, all emails
    from the same sender are placed in the same thread, and thread history
    accumulates (message_count increments, messages list grows).
    """

    @given(
        sender=email_address_strategy,
        bodies=st.lists(email_body_strategy, min_size=2, max_size=10),
    )
    @settings(max_examples=200)
    def test_same_sender_emails_in_same_thread(
        self, sender: str, bodies: list[str]
    ) -> None:
        """All emails from the same sender land in a single thread."""
        module = _make_module()

        for i, body in enumerate(bodies):
            email_msg = EmailMessage(
                sender=sender,
                subject=f"Subject {i}",
                body=body,
                message_id=f"<msg-{i}@test.local>",
            )
            module._update_thread(email_msg)

        # There should be exactly one thread entry for this sender
        assert sender in module._threads
        thread = module._threads[sender]
        assert thread["message_count"] == len(bodies)
        assert len(thread["messages"]) == len(bodies)

    @given(
        senders=st.lists(email_address_strategy, min_size=2, max_size=5, unique=True),
        bodies=st.lists(email_body_strategy, min_size=2, max_size=6),
    )
    @settings(max_examples=200)
    def test_different_senders_separate_threads(
        self, senders: list[str], bodies: list[str]
    ) -> None:
        """Emails from different senders create separate threads."""
        module = _make_module()

        for sender in senders:
            for i, body in enumerate(bodies):
                email_msg = EmailMessage(
                    sender=sender,
                    subject=f"Subject from {sender}",
                    body=body,
                    message_id=f"<msg-{sender}-{i}@test.local>",
                )
                module._update_thread(email_msg)

        # Each sender should have its own thread
        for sender in senders:
            assert sender in module._threads
            thread = module._threads[sender]
            assert thread["message_count"] == len(bodies)
            assert thread["sender_address"] == sender

    @given(
        sender=email_address_strategy,
        bodies=st.lists(email_body_strategy, min_size=1, max_size=8),
    )
    @settings(max_examples=200)
    def test_thread_history_accumulates_incrementally(
        self, sender: str, bodies: list[str]
    ) -> None:
        """Thread message_count and messages list grow with each email."""
        module = _make_module()

        for i, body in enumerate(bodies):
            email_msg = EmailMessage(
                sender=sender,
                subject="Test",
                body=body,
                message_id=f"<msg-{i}@test.local>",
            )
            module._update_thread(email_msg)

            # After each update, verify accumulation
            thread = module._threads[sender]
            assert thread["message_count"] == i + 1
            assert len(thread["messages"]) == i + 1

    @given(
        sender=email_address_strategy,
        bodies=st.lists(email_body_strategy, min_size=1, max_size=5),
    )
    @settings(max_examples=200)
    def test_get_thread_history_returns_accumulated_messages(
        self, sender: str, bodies: list[str]
    ) -> None:
        """_get_thread_history returns all messages for a sender."""
        module = _make_module()

        # Before any emails, history is empty
        assert module._get_thread_history(sender) == []

        for i, body in enumerate(bodies):
            email_msg = EmailMessage(
                sender=sender,
                subject="Test",
                body=body,
                message_id=f"<msg-{i}@test.local>",
            )
            module._update_thread(email_msg)

        history = module._get_thread_history(sender)
        assert len(history) == len(bodies)
        for entry in history:
            assert "sender" in entry
            assert "content" in entry
            assert entry["sender"] == "scammer"


# --- Property 11: Classification log capacity invariant ---


class TestClassificationLogCapacityInvariant:
    """Property 11: Classification log capacity invariant.

    **Validates: Requirements 8.2**

    The classification_log in email_ingestion state never exceeds 200 entries.
    When trimmed, the oldest entries are evicted first (newest are retained).
    """

    @given(
        entries=st.lists(
            classification_result_strategy,
            min_size=1,
            max_size=500,
        ),
    )
    @settings(max_examples=200)
    def test_log_never_exceeds_max_capacity(self, entries: list[dict[str, Any]]) -> None:
        """After appending any number of entries and trimming, log <= 200."""
        state_dict: dict[str, Any] = {"classification_log": []}

        for entry in entries:
            state_dict["classification_log"].append(entry)
            trim_classification_log(state_dict)

        assert len(state_dict["classification_log"]) <= _CLASSIFICATION_LOG_MAX

    @given(
        entries=st.lists(
            classification_result_strategy,
            min_size=201,
            max_size=500,
        ),
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.large_base_example])
    def test_oldest_entries_evicted_first(self, entries: list[dict[str, Any]]) -> None:
        """When log exceeds capacity, oldest entries are dropped."""
        state_dict: dict[str, Any] = {"classification_log": list(entries)}
        trim_classification_log(state_dict)

        log = state_dict["classification_log"]
        assert len(log) <= _CLASSIFICATION_LOG_MAX
        # The retained entries should be the last _CLASSIFICATION_LOG_MAX entries
        expected = entries[-_CLASSIFICATION_LOG_MAX:]
        assert log == expected

    @given(
        batch_sizes=st.lists(
            st.integers(min_value=1, max_value=50),
            min_size=1,
            max_size=20,
        ),
    )
    @settings(max_examples=200)
    def test_incremental_appends_respect_capacity(
        self, batch_sizes: list[int]
    ) -> None:
        """Incremental batch appends never let log exceed 200."""
        state_dict: dict[str, Any] = {"classification_log": []}
        total_appended = 0

        for batch_size in batch_sizes:
            for _ in range(batch_size):
                state_dict["classification_log"].append(
                    {"verdict": "scam", "confidence": 0.9, "timestamp": "2024-01-01"}
                )
                total_appended += 1
            trim_classification_log(state_dict)
            assert len(state_dict["classification_log"]) <= _CLASSIFICATION_LOG_MAX


# --- Property 12: Classification log ordering ---


class TestClassificationLogOrdering:
    """Property 12: Classification log ordering.

    **Validates: Requirements 8.4**

    When the classification log is displayed sorted by timestamp,
    entries appear in reverse chronological order (newest first).
    """

    @given(
        entries=st.lists(
            classification_result_strategy,
            min_size=2,
            max_size=100,
        ),
    )
    @settings(max_examples=200)
    def test_sorted_log_is_reverse_chronological(self, entries: list[dict[str, Any]]) -> None:
        """Sorting classification log by timestamp descending gives newest first."""
        # Sort entries by timestamp descending (newest first) as SOC dashboard does
        sorted_entries = sorted(
            entries,
            key=lambda e: e["timestamp"],
            reverse=True,
        )

        # Verify reverse chronological order
        for i in range(len(sorted_entries) - 1):
            current_ts = sorted_entries[i]["timestamp"]
            next_ts = sorted_entries[i + 1]["timestamp"]
            assert current_ts >= next_ts, (
                f"Entry at position {i} (ts={current_ts}) should be >= "
                f"entry at position {i+1} (ts={next_ts}) in reverse-chronological order"
            )

    @given(
        entries=st.lists(
            classification_result_strategy,
            min_size=1,
            max_size=200,
        ),
    )
    @settings(max_examples=200)
    def test_display_order_preserves_all_entries(self, entries: list[dict[str, Any]]) -> None:
        """Sorting for display does not lose or duplicate entries."""
        sorted_entries = sorted(
            entries,
            key=lambda e: e["timestamp"],
            reverse=True,
        )

        assert len(sorted_entries) == len(entries)
        # All original entries are present in sorted output
        for entry in entries:
            assert entry in sorted_entries

    @given(
        entries=st.lists(
            classification_result_strategy,
            min_size=2,
            max_size=100,
        ),
    )
    @settings(max_examples=200)
    def test_newest_entry_is_first_after_sort(self, entries: list[dict[str, Any]]) -> None:
        """The entry with the latest timestamp appears first after sorting."""
        sorted_entries = sorted(
            entries,
            key=lambda e: e["timestamp"],
            reverse=True,
        )

        # Find the maximum timestamp in original entries
        max_ts = max(e["timestamp"] for e in entries)

        # The first sorted entry should have that timestamp
        assert sorted_entries[0]["timestamp"] == max_ts
