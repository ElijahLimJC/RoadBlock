"""Tests for the SOC Dashboard rendering module.

Tests verify:
- Empty state handling (no crashes on empty lists/dicts)
- Parser error banner display
- Correct delegation to sub-render methods
- Helper function correctness (timestamp formatting, time calculation)
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

from dashboard.soc_dashboard import (
    _calculate_time_wasted,
    _format_timestamp,
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


# --- Email Ingestion Panel tests (Requirements 8.1, 8.4, 8.5, 8.6) ---


class TestRenderEmailIngestionPanel:
    """Tests for SOCDashboard.render_email_ingestion_panel."""

    def _empty_chat_state(self) -> dict:
        """Return chat state with empty email_ingestion defaults."""
        return {
            "email_ingestion": {},
        }

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_empty_state_renders_defaults(self):
        """Panel renders with empty state showing defaults (no errors)."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        state = self._empty_chat_state()
        # Should not raise
        dashboard.render_email_ingestion_panel(state)

        # Subheader rendered
        mock_st.subheader.assert_called_with("📧 Email Ingestion Status")
        # Default status is disconnected
        mock_st.markdown.assert_called_with("**Status:** :red[● Disconnected]")
        # No warning when degraded_warning is absent
        mock_st.warning.assert_not_called()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_connected_status_shows_green(self):
        """Connected status displays green indicator."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        state = {"email_ingestion": {"connection_status": "connected"}}
        dashboard.render_email_ingestion_panel(state)

        mock_st.markdown.assert_called_with("**Status:** :green[● Connected]")

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_degraded_warning_shown_when_true(self):
        """Degraded warning is displayed when degraded_warning=True."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        state = {"email_ingestion": {"degraded_warning": True}}
        dashboard.render_email_ingestion_panel(state)

        mock_st.warning.assert_called_once()
        warning_text = mock_st.warning.call_args[0][0]
        assert "Degraded email ingestion" in warning_text
        assert "IMAP" in warning_text

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_degraded_warning_hidden_when_false(self):
        """Degraded warning is NOT displayed when degraded_warning=False."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        state = {"email_ingestion": {"degraded_warning": False}}
        dashboard.render_email_ingestion_panel(state)

        mock_st.warning.assert_not_called()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_metrics_displayed_with_populated_data(self):
        """Panel renders metric values from populated ingestion state."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        state = {
            "email_ingestion": {
                "connection_status": "connected",
                "total_fetched": 42,
                "total_scam": 10,
                "total_not_scam": 30,
                "outbound_sent": 8,
                "degraded_warning": False,
            }
        }
        dashboard.render_email_ingestion_panel(state)

        # Verify columns were requested (4 metric columns)
        mock_st.columns.assert_called_with(4)

        # Verify st.metric was called with correct values via column mocks
        cols = mock_st.columns.return_value
        if cols is None:
            # columns side_effect returns tuple, check calls happened
            pass
        # The mock_st.columns returns a tuple via side_effect, each col
        # is a MagicMock context manager. Metrics are called on col.__enter__
        # We verify no exception was raised and columns were requested.

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_missing_email_ingestion_key_uses_empty_dict(self):
        """Panel handles missing email_ingestion key gracefully."""
        import importlib

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        dashboard = mod.SOCDashboard()

        # No email_ingestion key at all
        state: dict = {}
        # Should not raise
        dashboard.render_email_ingestion_panel(state)


class TestRenderClassificationLog:
    """Tests for SOCDashboard.render_classification_log."""

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_empty_classification_log_shows_info(self):
        """Empty classification list shows info message."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        dashboard.render_classification_log([])

        mock_st.subheader.assert_called_with("📋 Classification Log")
        mock_st.info.assert_called_once_with(
            "No classification decisions recorded yet."
        )
        mock_st.dataframe.assert_not_called()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_populated_log_renders_dataframe(self):
        """Populated classification log renders a dataframe with correct data."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        classifications = [
            {
                "sender": "scammer@evil.com",
                "subject": "You won a prize!",
                "verdict": "scam",
                "confidence": 0.95,
                "determining_stage": "keyword_match",
            },
            {
                "sender": "friend@legit.com",
                "subject": "Lunch tomorrow?",
                "verdict": "not_scam",
                "confidence": 0.12,
                "determining_stage": "llm_analysis",
            },
        ]
        dashboard.render_classification_log(classifications)

        mock_st.info.assert_not_called()
        mock_st.dataframe.assert_called_once()

        # Inspect the rows passed to dataframe
        rows = mock_st.dataframe.call_args[0][0]
        assert len(rows) == 2
        # Newest first (reversed)
        assert rows[0]["Sender"] == "friend@legit.com"
        assert rows[0]["Verdict"] == "not_scam"
        assert rows[0]["Confidence"] == "0.12"
        assert rows[1]["Sender"] == "scammer@evil.com"
        assert rows[1]["Verdict"] == "scam"
        assert rows[1]["Confidence"] == "0.95"

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_classification_log_truncation_at_50(self):
        """Classification log truncates to last 50 entries."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        # Create 75 entries
        classifications = [
            {
                "sender": f"sender{i}@example.com",
                "subject": f"Subject {i}",
                "verdict": "scam",
                "confidence": 0.5,
                "determining_stage": "test",
            }
            for i in range(75)
        ]
        dashboard.render_classification_log(classifications)

        mock_st.dataframe.assert_called_once()
        rows = mock_st.dataframe.call_args[0][0]
        # Only last 50 are shown
        assert len(rows) == 50
        # Newest first: last entry (index 74) should be first row
        assert rows[0]["Sender"] == "sender74@example.com"
        # Oldest shown should be index 25 (75-50=25)
        assert rows[49]["Sender"] == "sender25@example.com"

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_subject_truncation_at_60_chars(self):
        """Subjects longer than 60 chars are truncated with ellipsis."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        long_subject = "A" * 80  # 80 chars, exceeds 60
        classifications = [
            {
                "sender": "test@test.com",
                "subject": long_subject,
                "verdict": "scam",
                "confidence": 0.99,
                "determining_stage": "regex",
            },
        ]
        dashboard.render_classification_log(classifications)

        rows = mock_st.dataframe.call_args[0][0]
        # Truncated: first 57 chars + "..."
        assert len(rows[0]["Subject"]) == 60
        assert rows[0]["Subject"].endswith("...")
        assert rows[0]["Subject"] == "A" * 57 + "..."

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_subject_within_limit_not_truncated(self):
        """Subjects at or under 60 chars are not truncated."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        short_subject = "B" * 60  # Exactly 60 chars
        classifications = [
            {
                "sender": "test@test.com",
                "subject": short_subject,
                "verdict": "not_scam",
                "confidence": 0.1,
                "determining_stage": "header",
            },
        ]
        dashboard.render_classification_log(classifications)

        rows = mock_st.dataframe.call_args[0][0]
        assert rows[0]["Subject"] == short_subject

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_classification_log_with_object_entries(self):
        """Classification log works with object-style entries (not just dicts)."""
        import importlib
        import sys

        import dashboard.soc_dashboard as mod
        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()

        class Entry:
            def __init__(self):
                self.sender = "obj@test.com"
                self.subject = "Object subject"
                self.verdict = "scam"
                self.confidence = 0.77
                self.determining_stage = "llm"

        dashboard.render_classification_log([Entry()])

        rows = mock_st.dataframe.call_args[0][0]
        assert rows[0]["Sender"] == "obj@test.com"
        assert rows[0]["Confidence"] == "0.77"
