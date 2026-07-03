"""SOC Dashboard rendering module for RoadBlock pipeline.

Pure rendering layer — reads from chat_state (dict-like) and renders
Streamlit widgets. No business logic or state mutation.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any


class SOCDashboard:
    """Real-time SOC Dashboard renderer for the RoadBlock pipeline.

    All methods accept a chat_state dict (mirroring st.session_state) and
    render Streamlit widgets. Streamlit is imported inside methods to keep
    the module testable without a running Streamlit context.
    """

    def render(self, chat_state: dict[str, Any]) -> None:
        """Main render method called on each Streamlit cycle.

        Renders all dashboard panels: error banner (if applicable),
        metrics, conversation log, IoC panel, and notification log.
        """
        import streamlit as st

        # Error banner if parser is in error state
        parser_status = chat_state.get("parser_status", "idle")
        last_error = chat_state.get("last_error")
        if parser_status == "error" and last_error:
            st.error(f"⚠️ Parser Error: {last_error}")

        # Metrics section
        metrics = chat_state.get("metrics", {})
        st.markdown(
            '<div class="section-header">Session Metrics</div>',
            unsafe_allow_html=True,
        )
        self.render_metrics(metrics, chat_state)

        # Two-column layout: conversation log and IoC panel
        col_left, col_right = st.columns([3, 2])

        with col_left:
            st.markdown(
                '<div class="section-header">Conversation Log</div>',
                unsafe_allow_html=True,
            )
            messages = chat_state.get("conversation_history", [])
            self.render_conversation_log(messages)

        with col_right:
            st.markdown(
                '<div class="section-header">Indicators of Compromise</div>',
                unsafe_allow_html=True,
            )
            iocs = chat_state.get("iocs", {})
            self.render_ioc_panel(iocs, chat_state)

        # Notification log
        st.markdown(
            '<div class="section-header">Notifications</div>',
            unsafe_allow_html=True,
        )
        notifications = chat_state.get("notifications", [])
        self.render_notification_log(notifications)

    def render_conversation_log(self, messages: list[dict[str, Any]]) -> None:
        """Display chat messages with sender attribution and timestamps."""
        import streamlit as st

        if not messages:
            st.caption("No messages yet. Waiting for scammer engagement...")
            return

        for msg in messages:
            sender = (
                msg.get("sender", "unknown")
                if isinstance(msg, dict)
                else getattr(msg, "sender", "unknown")
            )
            content = (
                msg.get("content", "")
                if isinstance(msg, dict)
                else getattr(msg, "content", "")
            )
            content = html.escape(content)
            timestamp = (
                msg.get("timestamp", None)
                if isinstance(msg, dict)
                else getattr(msg, "timestamp", None)
            )

            ts_str = _format_timestamp(timestamp)

            if sender == "scammer":
                st.markdown(
                    f'<div class="chat-scammer">'
                    f'<div class="chat-sender">🔴 Scammer</div>'
                    f'{content}'
                    f'<div class="chat-time">{ts_str}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f'<div class="chat-persona">'
                    f'<div class="chat-sender">🟢 Ah Ma</div>'
                    f'{content}'
                    f'<div class="chat-time">{ts_str}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    def render_ioc_panel(
        self, iocs: dict[str, list[Any]], chat_state: dict[str, Any] | None = None
    ) -> None:
        """Display IoCs grouped by category with extracted values and known/new status."""
        import streamlit as st

        # Default empty structure
        crypto_wallets = iocs.get("cryptocurrency_wallets", [])
        phishing_domains = iocs.get("phishing_domains", [])
        phone_numbers = iocs.get("phone_numbers", [])
        mule_accounts = iocs.get("mule_bank_accounts", [])

        # Cryptocurrency Wallets
        with st.expander(
            f"💰 Cryptocurrency Wallets ({len(crypto_wallets)})", expanded=False
        ):
            if not crypto_wallets:
                st.write("No cryptocurrency wallets detected.")
            else:
                for ioc in crypto_wallets:
                    _render_ioc_badge(st, ioc)

        # Phishing Domains
        with st.expander(
            f"🌐 Phishing Domains ({len(phishing_domains)})", expanded=False
        ):
            if not phishing_domains:
                st.write("No phishing domains detected.")
            else:
                for ioc in phishing_domains:
                    _render_ioc_badge(st, ioc)

        # Phone Numbers
        with st.expander(
            f"📞 Phone Numbers ({len(phone_numbers)})", expanded=False
        ):
            if not phone_numbers:
                st.write("No phone numbers detected.")
            else:
                for ioc in phone_numbers:
                    _render_ioc_badge(st, ioc)

        # Mule Bank Accounts
        with st.expander(
            f"🏦 Mule Bank Accounts ({len(mule_accounts)})", expanded=False
        ):
            if not mule_accounts:
                st.write("No mule bank accounts detected.")
            else:
                for ioc in mule_accounts:
                    _render_ioc_badge(st, ioc)

    def render_metrics(
        self, metrics: dict[str, Any] | Any, chat_state: dict[str, Any] | None = None
    ) -> None:
        """Display turn count, Total Scammer Time Wasted, and IoC counts."""
        import streamlit as st

        # Extract metric values defensively
        if isinstance(metrics, dict):
            turn_count = metrics.get("turn_count", 0)
            start_time = metrics.get("start_time")
            last_message_time = metrics.get("last_message_time")
        else:
            turn_count = getattr(metrics, "turn_count", 0)
            start_time = getattr(metrics, "start_time", None)
            last_message_time = getattr(metrics, "last_message_time", None)

        # Calculate time wasted
        time_wasted = _calculate_time_wasted(start_time, last_message_time)

        # IoC counts from chat_state
        if chat_state is None:
            chat_state = {}
        iocs = chat_state.get("iocs", {})
        crypto_count = len(iocs.get("cryptocurrency_wallets", []))
        domain_count = len(iocs.get("phishing_domains", []))
        phone_count = len(iocs.get("phone_numbers", []))
        mule_count = len(iocs.get("mule_bank_accounts", []))

        known_count = chat_state.get("known_ioc_count", 0)
        new_count = chat_state.get("new_ioc_count", 0)

        # Row 1: Primary engagement metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Turns", turn_count)
        with col2:
            st.metric("Time Wasted", time_wasted)
        with col3:
            st.metric("Known IoCs", known_count)
        with col4:
            st.metric("New IoCs", new_count)

        # Row 2: IoC breakdown by category
        col5, col6, col7, col8 = st.columns(4)
        with col5:
            st.metric("Wallets", crypto_count)
        with col6:
            st.metric("Domains", domain_count)
        with col7:
            st.metric("Phones", phone_count)
        with col8:
            st.metric("Mule Accts", mule_count)

    def render_email_ingestion_panel(self, chat_state: dict[str, Any]) -> None:
        """Render email ingestion status: connection, counts, and degraded warning.

        Displays connection status with color indicator, email processing
        metrics (fetched, scam, not-scam, outbound sent), and a degraded
        ingestion warning when consecutive IMAP failures exceed threshold.
        """
        import streamlit as st

        st.subheader("📧 Email Ingestion Status")

        ingestion = chat_state.get("email_ingestion", {})

        # Connection status with color indicator
        connection_status = ingestion.get("connection_status", "disconnected")
        if connection_status == "connected":
            st.markdown("**Status:** :green[● Connected]")
        else:
            st.markdown("**Status:** :red[● Disconnected]")

        # Degraded ingestion warning
        if ingestion.get("degraded_warning", False):
            st.warning(
                "⚠️ Degraded email ingestion: multiple consecutive IMAP "
                "connection failures detected."
            )

        # Metrics in columns
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Fetched", ingestion.get("total_fetched", 0))
        with col2:
            st.metric("Scam", ingestion.get("total_scam", 0))
        with col3:
            st.metric("Not Scam", ingestion.get("total_not_scam", 0))
        with col4:
            st.metric("Outbound Sent", ingestion.get("outbound_sent", 0))

    def render_classification_log(
        self, classifications: list[dict[str, Any] | Any]
    ) -> None:
        """Display recent classification decisions in reverse chronological order.

        Shows the last 50 entries with sender, subject (truncated to 60 chars),
        verdict, confidence, and determining stage. Handles empty list gracefully.
        """
        import streamlit as st

        st.subheader("📋 Classification Log")

        if not classifications:
            st.info("No classification decisions recorded yet.")
            return

        # Take last 50 in reverse chronological order (newest first)
        recent = list(reversed(classifications[-50:]))

        # Build table data
        rows: list[dict[str, Any]] = []
        for entry in recent:
            sender = _get_field(entry, "sender", "")
            subject = _get_field(entry, "subject", "")
            # Truncate subject to 60 characters
            if len(subject) > 60:
                subject = subject[:57] + "..."
            verdict = _get_field(entry, "verdict", "")
            confidence = _get_field(entry, "confidence", 0.0)
            stage = _get_field(entry, "determining_stage", "")

            rows.append({
                "Sender": sender,
                "Subject": subject,
                "Verdict": verdict,
                "Confidence": f"{confidence:.2f}",
                "Stage": stage,
            })

        st.dataframe(rows, width="stretch")

    def render_notification_log(
        self, notifications: list[dict[str, Any] | Any]
    ) -> None:
        """Display mock AWS notifications with timestamp, severity, type, and summary."""
        import streamlit as st

        if not notifications:
            st.caption("No notifications generated yet.")
            return

        for notification in reversed(notifications):
            timestamp = _get_field(notification, "timestamp", None)
            severity = _get_field(notification, "severity", "UNKNOWN")
            payload_type = _get_field(notification, "payload_type", "unknown")
            summary = _get_field(notification, "summary", "No summary available")
            summary = html.escape(summary)

            ts_str = _format_timestamp(timestamp)

            # Severity color coding
            severity_icon = _severity_icon(severity)

            severity_lower = severity.lower() if isinstance(severity, str) else "low"
            notif_class = (
                f"notif-{severity_lower}"
                if severity_lower in ("critical", "high", "medium", "low")
                else "notif-low"
            )
            st.markdown(
                f'<div class="notif-card {notif_class}">'
                f'<strong>{severity_icon} [{severity}]</strong> <code>{payload_type}</code><br>'
                f'{summary}<br>'
                f'<small style="opacity:0.5">{ts_str}</small>'
                f'</div>',
                unsafe_allow_html=True,
            )


# --- Module-level helper functions (not part of the class) ---


def _render_ioc_badge(st_module: Any, ioc: Any) -> None:
    """Render an IoC value with a styled badge indicating known/new status."""
    import streamlit as _st

    value = _get_field(ioc, "extracted_value", "N/A")
    value = html.escape(str(value))

    # Check VT lookup cache for known status
    vt_cache = _st.session_state.get("vt_lookup_cache", {})
    cached_result = vt_cache.get(value if isinstance(value, str) else str(value))

    if cached_result is not None:
        is_known = _get_field(cached_result, "is_known", False)
        if is_known:
            badge_class = "ioc-known"
            badge_label = "KNOWN"
        else:
            badge_class = "ioc-new"
            badge_label = "NEW"
    else:
        # Fallback to lookup_result field on the IoC itself
        status = _get_known_status(ioc)
        if "New" in status:
            badge_class = "ioc-new"
            badge_label = "NEW"
        elif "Known" in status:
            badge_class = "ioc-known"
            badge_label = "KNOWN"
        else:
            badge_class = "ioc-unknown"
            badge_label = "UNKNOWN"

    st_module.markdown(
        f'<code>{value}</code> '
        f'<span class="ioc-badge {badge_class}">'
        f'{badge_label}</span>',
        unsafe_allow_html=True,
    )


def _format_timestamp(ts: Any) -> str:
    """Format a timestamp for display. Handles datetime objects, ISO strings, and None."""
    if ts is None:
        return "N/A"
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return ts
    return str(ts)


def _calculate_time_wasted(
    start_time: Any, last_message_time: Any
) -> str:
    """Calculate Total Scammer Time Wasted as HH:MM:SS."""
    if start_time is None or last_message_time is None:
        return "00:00:00"

    # Handle ISO string timestamps
    if isinstance(start_time, str):
        try:
            start_time = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return "00:00:00"
    if isinstance(last_message_time, str):
        try:
            last_message_time = datetime.fromisoformat(
                last_message_time.replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            return "00:00:00"

    if not isinstance(start_time, datetime) or not isinstance(last_message_time, datetime):
        return "00:00:00"

    total_seconds = max(0, int((last_message_time - start_time).total_seconds()))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _get_field(obj: Any, field: str, default: Any = None) -> Any:
    """Get a field from either a dict or an object with attributes."""
    if isinstance(obj, dict):
        return obj.get(field, default)
    return getattr(obj, field, default)


def _get_known_status(ioc: Any) -> str:
    """Return a status indicator string for known/new IoCs."""
    lookup_result = _get_field(ioc, "lookup_result")
    if lookup_result is None:
        return "🔵 Unknown"

    is_known = _get_field(lookup_result, "is_known", False)
    if is_known:
        return "🟡 Known"
    return "🟢 New"


def _severity_icon(severity: str) -> str:
    """Return an emoji icon based on severity level."""
    severity_upper = severity.upper() if isinstance(severity, str) else "UNKNOWN"
    if severity_upper == "CRITICAL":
        return "🔴"
    elif severity_upper == "HIGH":
        return "🟠"
    elif severity_upper == "MEDIUM":
        return "🟡"
    elif severity_upper == "LOW":
        return "🟢"
    return "⚪"
