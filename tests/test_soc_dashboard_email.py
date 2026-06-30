"""Tests for SOC Dashboard email ingestion panel rendering.

Tests verify:
- Empty state handling (no crashes, shows zeros)
- Populated classification log rendering
- Degraded warning display and clearing
- Classification log truncation at 50 displayed entries

Requirements: 8.1, 8.4, 8.5, 8.6
"""

import importlib
import sys
from unittest.mock import MagicMock, patch


def _make_mock_st():
    """Create a mock streamlit module with proper context manager support."""
    mock_st = MagicMock()

    def _columns_side_effect(n):
        return tuple(MagicMock() for _ in range(n))

    mock_st.columns.side_effect = _columns_side_effect
    mock_st.expander.return_value.__enter__ = MagicMock(return_value=mock_st)
    mock_st.expander.return_value.__exit__ = MagicMock(return_value=False)
    return mock_st


def _empty_email_ingestion_state() -> dict:
    """Return an empty email ingestion state matching session_state defaults."""
    return {
        "connection_status": "disconnected",
        "total_fetched": 0,
        "total_scam": 0,
        "total_not_scam": 0,
        "outbound_sent": 0,
        "consecutive_failures": 0,
        "degraded_warning": False,
        "classification_log": [],
        "outbound_queue": [],
        "threads": {},
    }


def _empty_chat_state() -> dict:
    """Return a minimal empty chat state with email_ingestion subdict."""
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
        "email_ingestion": _empty_email_ingestion_state(),
    }


def _make_classification_entry(
    sender: str = "scammer@evil.com",
    subject: str = "You won a prize!",
    verdict: str = "scam",
    confidence: float = 0.85,
    determining_stage: str = "stage_1",
) -> dict:
    """Create a classification log entry dict."""
    return {
        "sender": sender,
        "subject": subject,
        "verdict": verdict,
        "confidence": confidence,
        "determining_stage": determining_stage,
        "matched_patterns": ["urgency_keywords"],
        "timestamp": "2024-03-15T10:00:00",
    }


class TestEmailIngestionPanelEmptyState:
    """Test panel renders with empty state (no crashes, shows zeros)."""

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_email_ingestion_panel_empty_no_crash(self):
        """Empty email ingestion state should render without exceptions."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        dashboard = mod.SOCDashboard()
        state = _empty_chat_state()
        # Should not raise
        dashboard.render_email_ingestion_panel(state)

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_email_ingestion_panel_shows_disconnected(self):
        """Empty state shows disconnected status."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = _empty_chat_state()
        dashboard.render_email_ingestion_panel(state)
        # Should call markdown with disconnected indicator
        markdown_calls = [
            str(c) for c in mock_st.markdown.call_args_list
        ]
        found_disconnected = any("Disconnected" in c for c in markdown_calls)
        assert found_disconnected

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_email_ingestion_panel_shows_zero_metrics(self):
        """Empty state shows zero for all metric values."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = _empty_chat_state()
        dashboard.render_email_ingestion_panel(state)
        # st.metric should be called with zero values
        metric_calls = mock_st.metric.call_args_list
        assert len(metric_calls) >= 4
        # All second args (values) should be 0
        for call in metric_calls:
            args = call[0]
            assert args[1] == 0

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_classification_log_empty_shows_info(self):
        """Empty classification log shows info message."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        dashboard.render_classification_log([])
        mock_st.info.assert_called()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_email_ingestion_panel_no_degraded_warning(self):
        """Empty state (no failures) should not show degraded warning."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = _empty_chat_state()
        dashboard.render_email_ingestion_panel(state)
        mock_st.warning.assert_not_called()


class TestEmailIngestionPanelPopulated:
    """Test panel renders with populated classification log."""

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_classification_log_with_entries(self):
        """Populated classification log renders dataframe."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        entries = [
            _make_classification_entry(
                sender=f"scammer{i}@evil.com", subject=f"Subject {i}"
            )
            for i in range(5)
        ]
        dashboard.render_classification_log(entries)
        mock_st.dataframe.assert_called_once()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_classification_log_dataframe_rows(self):
        """Dataframe has correct number of rows for small log."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        entries = [_make_classification_entry() for _ in range(3)]
        dashboard.render_classification_log(entries)
        # Check the dataframe call received correct row count
        call_args = mock_st.dataframe.call_args
        rows = call_args[0][0]
        assert len(rows) == 3

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_email_ingestion_panel_connected_status(self):
        """Connected status shows green indicator."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = _empty_chat_state()
        state["email_ingestion"]["connection_status"] = "connected"
        dashboard.render_email_ingestion_panel(state)
        markdown_calls = [
            str(c) for c in mock_st.markdown.call_args_list
        ]
        found_connected = any("Connected" in c for c in markdown_calls)
        assert found_connected

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_render_email_ingestion_panel_populated_metrics(self):
        """Populated metrics show correct values."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = _empty_chat_state()
        state["email_ingestion"]["total_fetched"] = 42
        state["email_ingestion"]["total_scam"] = 30
        state["email_ingestion"]["total_not_scam"] = 12
        state["email_ingestion"]["outbound_sent"] = 25
        dashboard.render_email_ingestion_panel(state)
        metric_calls = mock_st.metric.call_args_list
        values = [call[0][1] for call in metric_calls]
        assert 42 in values
        assert 30 in values
        assert 12 in values
        assert 25 in values


class TestEmailIngestionDegradedWarning:
    """Test degraded warning display and clearing."""

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_degraded_warning_shown_when_flag_true(self):
        """Degraded warning should be displayed when degraded_warning is True."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = _empty_chat_state()
        state["email_ingestion"]["degraded_warning"] = True
        dashboard.render_email_ingestion_panel(state)
        mock_st.warning.assert_called_once()
        warning_text = mock_st.warning.call_args[0][0]
        assert "Degraded" in warning_text or "degraded" in warning_text.lower()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_degraded_warning_not_shown_when_flag_false(self):
        """No degraded warning when degraded_warning is False."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = _empty_chat_state()
        state["email_ingestion"]["degraded_warning"] = False
        dashboard.render_email_ingestion_panel(state)
        mock_st.warning.assert_not_called()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_degraded_warning_cleared_on_recovery(self):
        """After clearing degraded_warning, warning disappears."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = _empty_chat_state()

        # First render: degraded
        state["email_ingestion"]["degraded_warning"] = True
        dashboard.render_email_ingestion_panel(state)
        mock_st.warning.assert_called_once()

        # Reset mock
        mock_st.reset_mock()
        mock_st.columns.side_effect = lambda n: tuple(
            MagicMock() for _ in range(n)
        )

        # Second render: recovered
        state["email_ingestion"]["degraded_warning"] = False
        dashboard.render_email_ingestion_panel(state)
        mock_st.warning.assert_not_called()

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_degraded_warning_mentions_imap(self):
        """Degraded warning text mentions IMAP failures."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        state = _empty_chat_state()
        state["email_ingestion"]["degraded_warning"] = True
        dashboard.render_email_ingestion_panel(state)
        warning_text = mock_st.warning.call_args[0][0]
        assert "IMAP" in warning_text


class TestClassificationLogTruncation:
    """Test classification log truncation at 50 displayed entries."""

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_classification_log_shows_max_50_entries(self):
        """Classification log should display at most 50 entries."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        # Create 100 entries
        entries = [
            _make_classification_entry(
                sender=f"scammer{i}@evil.com", subject=f"Subject {i}"
            )
            for i in range(100)
        ]
        dashboard.render_classification_log(entries)
        # Dataframe should have exactly 50 rows
        call_args = mock_st.dataframe.call_args
        rows = call_args[0][0]
        assert len(rows) == 50

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_classification_log_shows_newest_first(self):
        """Classification log displays entries newest first (reverse chronological)."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        entries = [
            _make_classification_entry(
                sender=f"scammer{i}@evil.com", subject=f"Subject {i}"
            )
            for i in range(10)
        ]
        dashboard.render_classification_log(entries)
        call_args = mock_st.dataframe.call_args
        rows = call_args[0][0]
        # First row should be the last entry (newest)
        assert rows[0]["Subject"] == "Subject 9"
        assert rows[-1]["Subject"] == "Subject 0"

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_classification_log_truncates_from_oldest(self):
        """When > 50 entries, oldest entries beyond 50 are not shown."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        # Create 60 entries
        entries = [
            _make_classification_entry(
                sender=f"scammer{i}@evil.com", subject=f"Subject {i}"
            )
            for i in range(60)
        ]
        dashboard.render_classification_log(entries)
        call_args = mock_st.dataframe.call_args
        rows = call_args[0][0]
        assert len(rows) == 50
        # First displayed should be entry 59 (newest of last 50)
        assert rows[0]["Subject"] == "Subject 59"
        # Last displayed should be entry 10 (oldest of last 50)
        assert rows[-1]["Subject"] == "Subject 10"

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_classification_log_subject_truncation_at_60_chars(self):
        """Subjects longer than 60 chars are truncated with ellipsis."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        long_subject = "A" * 80
        entries = [_make_classification_entry(subject=long_subject)]
        dashboard.render_classification_log(entries)
        call_args = mock_st.dataframe.call_args
        rows = call_args[0][0]
        subject_displayed = rows[0]["Subject"]
        assert len(subject_displayed) <= 60
        assert subject_displayed.endswith("...")

    @patch.dict("sys.modules", {"streamlit": _make_mock_st()})
    def test_classification_log_exactly_50_entries(self):
        """Exactly 50 entries should all be displayed without truncation."""
        import dashboard.soc_dashboard as mod

        importlib.reload(mod)
        mock_st = sys.modules["streamlit"]
        dashboard = mod.SOCDashboard()
        entries = [
            _make_classification_entry(
                sender=f"scammer{i}@evil.com", subject=f"Subject {i}"
            )
            for i in range(50)
        ]
        dashboard.render_classification_log(entries)
        call_args = mock_st.dataframe.call_args
        rows = call_args[0][0]
        assert len(rows) == 50
