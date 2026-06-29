"""Tests for the SOC Dashboard rendering module.

Tests verify:
- Empty state handling (no crashes on empty lists/dicts)
- Parser error banner display
- Correct delegation to sub-render methods
- Helper function correctness (timestamp formatting, time calculation)
"""

from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest

from dashboard.soc_dashboard import (
    SOCDashboard,
    _format_timestamp,
    _calculate_time_wasted,
    _get_field,
    _get_known_status,
    _severity_icon,
)


# --- Helper function unit tests (no Streamlit needed) ---


class TestFormatTimestamp:
    """Tests for _format_timestamp helper."""

    def test_none_returns_na(self):
        assert _format_timestamp(None) == "N/A"

    def test_datetime_object(self):
        dt = datetime(2024, 3, 15, 10, 30, 45)
        assert _format_timestamp(dt) == "2024-03-15 10:30:45"

    def test_iso_string(self):
        result = _format_timestamp("2024-03-15T10:30:45")
        assert result == "2024-03-15 10:30:45"

    def test_iso_string_with_z(self):
        result = _format_timestamp("2024-03-15T10:30:45Z")
        assert result == "2024-03-15 10:30:45"

    def test_invalid_string_returns_as_is(self):
        assert _format_timestamp("not-a-date") == "not-a-date"


class TestCalculateTimeWasted:
    """Tests for _calculate_time_wasted helper."""

    def test_none_start_returns_zero(self):
        assert _calculate_time_wasted(None, datetime.now()) == "00:00:00"

    def test_none_end_returns_zero(self):
        assert _calculate_time_wasted(datetime.now(), None) == "00:00:00"

    def test_both_none_returns_zero(self):
        assert _calculate_time_wasted(None, None) == "00:00:00"

    def test_valid_timestamps(self):
        start = datetime(2024, 1, 1, 10, 0, 0)
        end = datetime(2024, 1, 1, 11, 23, 45)
        assert _calculate_time_wasted(start, end) == "01:23:45"

    def test_iso_strings(self):
        start = "2024-01-01T10:00:00"
        end = "2024-01-01T10:05:30"
        assert _calculate_time_wasted(start, end) == "00:05:30"

    def test_zero_duration(self):
        now = datetime(2024, 1, 1, 12, 0, 0)
        assert _calculate_time_wasted(now, now) == "00:00:00"

    def test_negative_duration_clamps_to_zero(self):
        start = datetime(2024, 1, 1, 12, 0, 0)
        end = datetime(2024, 1, 1, 11, 0, 0)
        assert _calculate_time_wasted(start, end) == "00:00:00"


class TestGetField:
    """Tests for _get_field helper."""

    def test_dict_access(self):
        assert _get_field({"key": "value"}, "key") == "value"

    def test_dict_missing_key(self):
        assert _get_field({"key": "value"}, "missing", "default") == "default"

    def test_object_access(self):
        class Obj:
            key = "value"
        assert _get_field(Obj(), "key") == "value"

    def test_object_missing_attr(self):
        class Obj:
            pass
        assert _get_field(Obj(), "missing", "default") == "default"


class TestGetKnownStatus:
    """Tests for _get_known_status helper."""

    def test_no_lookup_result(self):
        assert _get_known_status({"lookup_result": None}) == "🔵 Unknown"

    def test_known_ioc(self):
        ioc = {"lookup_result": {"is_known": True}}
        assert _get_known_status(ioc) == "🟡 Known"

    def test_new_ioc(self):
        ioc = {"lookup_result": {"is_known": False}}
        assert _get_known_status(ioc) == "🟢 New"

    def test_missing_lookup_result_key(self):
        assert _get_known_status({}) == "🔵 Unknown"


class TestSeverityIcon:
    """Tests for _severity_icon helper."""

    def test_critical(self):
        assert _severity_icon("CRITICAL") == "🔴"

    def test_high(self):
        assert _severity_icon("HIGH") == "🟠"

    def test_medium(self):
        assert _severity_icon("MEDIUM") == "🟡"

    def test_low(self):
        assert _severity_icon("LOW") == "🟢"

    def test_unknown(self):
        assert _severity_icon("SOMETHING") == "⚪"

    def test_case_insensitive(self):
        assert _severity_icon("high") == "🟠"
        assert _severity_icon("Critical") == "🔴"


# --- Dashboard rendering tests (mock Streamlit) ---


def _make_mock_st():
    """Create a mock streamlit module with proper context manager support."""
    mock_st = MagicMock()

    # columns needs to return the right number of column mocks based on arg
    def _columns_side_effect(n):
        return tuple(MagicMock() for _ in range(n))

    mock_st.columns.side_effect = _columns_side_effect
    # expander returns a context manager
    mock_st.expander.return_value.__enter__ = MagicMock(return_value=mock_st)
    mock_st.expander.return_value.__exit__ = MagicMock(return_value=False)
    return mock_st


class TestSOCDashboardRender:
    """Tests for SOCDashboard rendering with mocked Streamlit."""

    def _empty_chat_state(self) -> dict:
        """Return a minimal empty chat state."""
        return {
            "conversation_history": [],
            "iocs": {
                "cryptocurrency_wallets": [],
                "phishing_domains": [],
                "phone_numbers": [],
                "mule_bank_accounts": [],
            },
            "metrics": {
                "turn_count": 0,
                "start_time": None,
                "last_message_time": None,
            },
            "notifications": [],
            "parser_status": "idle",
            "last_error": None,
            "known_ioc_count": 0,
            "new_ioc_count": 0,
        }

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_empty_state_no_crash(self):
        """Empty state should render without raising exceptions."""
        import importlib
        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        dashboard = mod.SOCDashboard()
        state = self._empty_chat_state()
        # Should not raise
        dashboard.render(state)

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_error_banner_shown(self):
        """Error banner should appear when parser_status is 'error'."""
        import importlib
        import sys
        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = self._empty_chat_state()
        state["parser_status"] = "error"
        state["last_error"] = "Connection timeout"
        dashboard.render(state)
        mock_st.error.assert_called()
        error_call = mock_st.error.call_args[0][0]
        assert "Connection timeout" in error_call

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_no_error_banner_when_idle(self):
        """No error banner when parser status is idle."""
        import importlib
        import sys
        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = self._empty_chat_state()
        dashboard.render(state)
        mock_st.error.assert_not_called()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_conversation_log_empty(self):
        """Empty conversation log shows info message."""
        import importlib
        import sys
        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        dashboard.render_conversation_log([])
        mock_st.info.assert_called()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_conversation_log_with_messages(self):
        """Messages render with sender attribution."""
        import importlib
        import sys
        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        messages = [
            {
                "sender": "scammer",
                "content": "Hello, send me money",
                "timestamp": "2024-01-01T10:00:00",
            },
            {
                "sender": "persona",
                "content": "Oh dear, what was that?",
                "timestamp": "2024-01-01T10:00:30",
            },
        ]
        dashboard.render_conversation_log(messages)
        assert mock_st.markdown.call_count >= 2

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_metrics_zero_state(self):
        """Metrics should show zero values without error."""
        import importlib
        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        dashboard = mod.SOCDashboard()
        metrics = {"turn_count": 0, "start_time": None, "last_message_time": None}
        chat_state = self._empty_chat_state()
        dashboard.render_metrics(metrics, chat_state)

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_notification_log_empty(self):
        """Empty notification log shows info message."""
        import importlib
        import sys
        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        dashboard.render_notification_log([])
        mock_st.info.assert_called()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_notification_log_with_entries(self):
        """Notification entries render with severity and summary."""
        import importlib
        import sys
        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        notifications = [
            {
                "timestamp": "2024-01-01T10:00:00",
                "severity": "HIGH",
                "payload_type": "guardduty_finding",
                "summary": "Crypto wallet detected: 1A1zP1...",
            }
        ]
        dashboard.render_notification_log(notifications)
        mock_st.markdown.assert_called()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_ioc_panel_empty(self):
        """IoC panel with empty categories should not crash."""
        import importlib
        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        dashboard = mod.SOCDashboard()
        iocs = {
            "cryptocurrency_wallets": [],
            "phishing_domains": [],
            "phone_numbers": [],
            "mule_bank_accounts": [],
        }
        dashboard.render_ioc_panel(iocs)

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_handles_missing_state_keys(self):
        """Dashboard should not crash with missing state keys."""
        import importlib
        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        dashboard = mod.SOCDashboard()
        # Minimal state — missing most keys
        state = {}
        dashboard.render(state)
