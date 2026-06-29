"""Stalling Tracker — conversation engagement metrics for RoadBlock.

Records turn counts and wall-clock duration to measure how long the
honeypot persona keeps a scammer engaged.
"""

import logging
from datetime import datetime
from typing import Any

from models.chat_models import SessionMetrics

logger = logging.getLogger(__name__)

# Type alias for the dict-like Streamlit session state object.
ChatState = Any


class StallingTracker:
    """Metrics subsystem recording conversation engagement statistics.

    All state is persisted in the provided chat_state dict under the
    'metrics' key as a SessionMetrics instance (or its dict representation).
    """

    def initialize(self, chat_state: ChatState) -> None:
        """Reset all stalling metrics to initial values.

        Sets turn_count=0, start_time=None, and total_time='00:00:00'
        in the chat_state metrics.

        Args:
            chat_state: Dict-like session state (st.session_state).
        """
        try:
            chat_state["metrics"] = SessionMetrics(
                turn_count=0,
                start_time=None,
                last_message_time=None,
            )
        except Exception as exc:
            logger.warning("StallingTracker.initialize failed: %s", exc)

    def record_turn(self, chat_state: ChatState) -> None:
        """Record a completed chat turn — increment count and update timestamps.

        On the first turn, sets start_time to now. On every turn, updates
        last_message_time to now and increments turn_count by 1.

        Args:
            chat_state: Dict-like session state (st.session_state).
        """
        try:
            metrics = self._get_metrics(chat_state)
            now = datetime.utcnow()

            metrics.turn_count += 1

            if metrics.start_time is None:
                metrics.start_time = now

            metrics.last_message_time = now

            chat_state["metrics"] = metrics
        except Exception as exc:
            logger.warning("StallingTracker.record_turn failed: %s", exc)

    def get_formatted_duration(self, chat_state: ChatState) -> str:
        """Return Total Scammer Time Wasted as 'HH:MM:SS'.

        Uses whole-second precision with leading zeros on all segments.

        Args:
            chat_state: Dict-like session state (st.session_state).

        Returns:
            Formatted duration string in 'HH:MM:SS' format.
            Returns '00:00:00' if metrics are unavailable or uninitialized.
        """
        try:
            metrics = self._get_metrics(chat_state)
            return metrics.formatted_time_wasted()
        except Exception as exc:
            logger.warning("StallingTracker.get_formatted_duration failed: %s", exc)
            return "00:00:00"

    def _get_metrics(self, chat_state: ChatState) -> SessionMetrics:
        """Retrieve or reconstruct SessionMetrics from chat_state.

        Handles both cases where metrics is stored as a SessionMetrics
        instance or as a serialized dict.

        Args:
            chat_state: Dict-like session state (st.session_state).

        Returns:
            A mutable SessionMetrics instance.
        """
        raw = chat_state.get("metrics")

        if isinstance(raw, SessionMetrics):
            return raw

        if isinstance(raw, dict):
            return SessionMetrics.model_validate(raw)

        # Fallback: no metrics present yet — return fresh instance.
        return SessionMetrics()
