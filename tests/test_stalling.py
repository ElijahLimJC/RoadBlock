"""Unit and property-based tests for StallingTracker component."""

import time
from datetime import datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from components.stalling_tracker import StallingTracker
from models.chat_models import SessionMetrics


@pytest.fixture
def tracker() -> StallingTracker:
    """Create a fresh StallingTracker instance."""
    return StallingTracker()


@pytest.fixture
def chat_state() -> dict:
    """Create a minimal chat_state dict with default metrics."""
    return {"metrics": SessionMetrics()}


class TestInitialize:
    """Tests for StallingTracker.initialize()."""

    def test_sets_turn_count_to_zero(self, tracker: StallingTracker) -> None:
        state: dict = {}
        tracker.initialize(state)
        metrics = state["metrics"]
        assert metrics.turn_count == 0

    def test_sets_start_time_to_none(self, tracker: StallingTracker) -> None:
        state: dict = {}
        tracker.initialize(state)
        metrics = state["metrics"]
        assert metrics.start_time is None

    def test_formatted_time_is_zero(self, tracker: StallingTracker) -> None:
        state: dict = {}
        tracker.initialize(state)
        assert tracker.get_formatted_duration(state) == "00:00:00"

    def test_resets_existing_metrics(self, tracker: StallingTracker) -> None:
        state: dict = {
            "metrics": SessionMetrics(
                turn_count=5,
                start_time=datetime(2024, 1, 1),
                last_message_time=datetime(2024, 1, 1, 0, 5, 0),
            )
        }
        tracker.initialize(state)
        metrics = state["metrics"]
        assert metrics.turn_count == 0
        assert metrics.start_time is None
        assert metrics.last_message_time is None


class TestRecordTurn:
    """Tests for StallingTracker.record_turn()."""

    def test_increments_turn_count(
        self, tracker: StallingTracker, chat_state: dict
    ) -> None:
        tracker.record_turn(chat_state)
        assert chat_state["metrics"].turn_count == 1

    def test_multiple_turns_increment_correctly(
        self, tracker: StallingTracker, chat_state: dict
    ) -> None:
        for _ in range(5):
            tracker.record_turn(chat_state)
        assert chat_state["metrics"].turn_count == 5

    def test_first_turn_sets_start_time(
        self, tracker: StallingTracker, chat_state: dict
    ) -> None:
        tracker.record_turn(chat_state)
        assert chat_state["metrics"].start_time is not None

    def test_subsequent_turns_preserve_start_time(
        self, tracker: StallingTracker, chat_state: dict
    ) -> None:
        tracker.record_turn(chat_state)
        first_start = chat_state["metrics"].start_time
        tracker.record_turn(chat_state)
        assert chat_state["metrics"].start_time == first_start

    def test_last_message_time_updates_each_turn(
        self, tracker: StallingTracker, chat_state: dict
    ) -> None:
        tracker.record_turn(chat_state)
        first_last = chat_state["metrics"].last_message_time
        # Small sleep to ensure timestamp difference
        time.sleep(0.01)
        tracker.record_turn(chat_state)
        assert chat_state["metrics"].last_message_time >= first_last

    def test_handles_dict_metrics(self, tracker: StallingTracker) -> None:
        """Handles the case where metrics is stored as a dict (serialized)."""
        state = {"metrics": SessionMetrics().model_dump()}
        tracker.record_turn(state)
        assert state["metrics"].turn_count == 1


class TestGetFormattedDuration:
    """Tests for StallingTracker.get_formatted_duration()."""

    def test_zero_duration_on_fresh_state(
        self, tracker: StallingTracker, chat_state: dict
    ) -> None:
        assert tracker.get_formatted_duration(chat_state) == "00:00:00"

    def test_zero_when_only_start_time_set(
        self, tracker: StallingTracker
    ) -> None:
        state = {
            "metrics": SessionMetrics(
                turn_count=1,
                start_time=datetime(2024, 1, 1, 12, 0, 0),
                last_message_time=None,
            )
        }
        assert tracker.get_formatted_duration(state) == "00:00:00"

    def test_formats_seconds_correctly(self, tracker: StallingTracker) -> None:
        start = datetime(2024, 1, 1, 12, 0, 0)
        end = start + timedelta(seconds=45)
        state = {
            "metrics": SessionMetrics(
                turn_count=3,
                start_time=start,
                last_message_time=end,
            )
        }
        assert tracker.get_formatted_duration(state) == "00:00:45"

    def test_formats_minutes_correctly(self, tracker: StallingTracker) -> None:
        start = datetime(2024, 1, 1, 12, 0, 0)
        end = start + timedelta(minutes=7, seconds=30)
        state = {
            "metrics": SessionMetrics(
                turn_count=10,
                start_time=start,
                last_message_time=end,
            )
        }
        assert tracker.get_formatted_duration(state) == "00:07:30"

    def test_formats_hours_correctly(self, tracker: StallingTracker) -> None:
        start = datetime(2024, 1, 1, 12, 0, 0)
        end = start + timedelta(hours=2, minutes=15, seconds=5)
        state = {
            "metrics": SessionMetrics(
                turn_count=50,
                start_time=start,
                last_message_time=end,
            )
        }
        assert tracker.get_formatted_duration(state) == "02:15:05"

    def test_leading_zeros(self, tracker: StallingTracker) -> None:
        start = datetime(2024, 1, 1, 12, 0, 0)
        end = start + timedelta(hours=1, minutes=2, seconds=3)
        state = {
            "metrics": SessionMetrics(
                turn_count=5,
                start_time=start,
                last_message_time=end,
            )
        }
        assert tracker.get_formatted_duration(state) == "01:02:03"

    def test_returns_default_when_no_metrics_key(
        self, tracker: StallingTracker
    ) -> None:
        state: dict = {}
        assert tracker.get_formatted_duration(state) == "00:00:00"

    def test_handles_large_durations(self, tracker: StallingTracker) -> None:
        start = datetime(2024, 1, 1, 0, 0, 0)
        end = start + timedelta(hours=99, minutes=59, seconds=59)
        state = {
            "metrics": SessionMetrics(
                turn_count=1000,
                start_time=start,
                last_message_time=end,
            )
        }
        assert tracker.get_formatted_duration(state) == "99:59:59"


class TestTurnCountProperty:
    """Property-based tests for Stalling Tracker turn count invariant.

    **Validates: Requirements 2.1**
    """

    @given(n=st.integers(min_value=0, max_value=100))
    @settings(max_examples=200)
    def test_turn_count_equals_n_after_n_turns(self, n: int) -> None:
        """Property 4: Stalling Tracker Turn Count Invariant.

        For any sequence of N completed chat turns applied to an initialized
        Chat_State, the Stalling_Tracker turn count SHALL equal N.

        **Validates: Requirements 2.1**
        """
        tracker = StallingTracker()
        chat_state: dict = {}
        tracker.initialize(chat_state)

        for _ in range(n):
            tracker.record_turn(chat_state)

        assert chat_state["metrics"].turn_count == n


# --- Property-Based Tests ---

from hypothesis import given, settings
from hypothesis import strategies as st


class TestTimeDurationProperty:
    """Property 5: Time Duration Formatting.

    **Validates: Requirements 2.2, 2.4**

    For any non-negative integer S representing elapsed seconds,
    the formatted time wasted string SHALL equal
    f"{S//3600:02d}:{(S%3600)//60:02d}:{S%60:02d}".
    """

    @given(seconds=st.integers(min_value=0, max_value=360000))
    @settings(max_examples=200)
    def test_formatted_duration_matches_expected(self, seconds: int) -> None:
        """Assert tracker formatting matches the canonical formula."""
        tracker = StallingTracker()

        start = datetime(2024, 1, 1, 0, 0, 0)
        end = start + timedelta(seconds=seconds)

        state = {
            "metrics": SessionMetrics(
                turn_count=1,
                start_time=start,
                last_message_time=end,
            )
        }

        result = tracker.get_formatted_duration(state)
        expected = f"{seconds // 3600:02d}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"

        assert result == expected, (
            f"For {seconds}s: got '{result}', expected '{expected}'"
        )
