"""SOC Dashboard rendering module for RoadBlock pipeline.

Pure rendering layer — reads from chat_state (dict-like) and renders
Streamlit widgets. No business logic or state mutation.
"""

from __future__ import annotations

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

        st.title("🛡️ RoadBlock SOC Dashboard")

        # Error banner if parser is in error state
        parser_status = chat_state.get("parser_status", "idle")
        last_error = chat_state.get("last_error")
        if parser_status == "error" and last_error:
            st.error(f"⚠️ Parser Error: {last_error}")

        # Metrics section
        metrics = chat_state.get("metrics", {})
        self.render_metrics(metrics, chat_state)

        st.divider()

        # Two-column layout: conversation log and IoC panel
        col_left, col_right = st.columns(2)

        with col_left:
            messages = chat_state.get("conversation_history", [])
            self.render_conversation_log(messages)

        with col_right:
            iocs = chat_state.get("iocs", {})
            self.render_ioc_panel(iocs, chat_state)

        st.divider()

        # Notification log
        notifications = chat_state.get("notifications", [])
        self.render_notification_log(notifications)

    def render_conversation_log(self, messages: list[dict[str, Any]]) -> None:
        """Display chat messages with sender attribution and timestamps.

        Messages are displayed in chronological order. Each message shows
        the sender (scammer/persona) and timestamp.
        """
        import streamlit as st

        st.subheader("💬 Conversation Log")

        if not messages:
            st.info("No messages yet. Waiting for scammer engagement...")
            return

        for msg in messages:
            sender = msg.get("sender", "unknown") if isinstance(msg, dict) else getattr(msg, "sender", "unknown")
            content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
            timestamp = msg.get("timestamp", None) if isinstance(msg, dict) else getattr(msg, "timestamp", None)

            # Format timestamp
            ts_str = _format_timestamp(timestamp)

            # Determine display style based on sender
            if sender == "scammer":
                icon = "🔴"
                label = "Scammer"
            else:
                icon = "🟢"
                label = "Persona"

            st.markdown(f"**{icon} {label}** — {ts_str}")
            st.text(content)
            st.markdown("---")

    def render_ioc_panel(
        self, iocs: dict[str, list[Any]], chat_state: dict[str, Any] | None = None
    ) -> None:
        """Display IoCs grouped by category with extracted values and known/new status.

        Categories: Cryptocurrency Wallets, Phishing Domains, Phone Numbers,
        Mule Bank Accounts.
        """
        import streamlit as st

        st.subheader("🎯 Indicators of Compromise")

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
                    value = _get_field(ioc, "extracted_value", "N/A")
                    status = _get_known_status(ioc)
                    st.write(f"• `{value}` {status}")

        # Phishing Domains
        with st.expander(
            f"🌐 Phishing Domains ({len(phishing_domains)})", expanded=False
        ):
            if not phishing_domains:
                st.write("No phishing domains detected.")
            else:
                for ioc in phishing_domains:
                    value = _get_field(ioc, "extracted_value", "N/A")
                    status = _get_known_status(ioc)
                    st.write(f"• `{value}` {status}")

        # Phone Numbers
        with st.expander(
            f"📞 Phone Numbers ({len(phone_numbers)})", expanded=False
        ):
            if not phone_numbers:
                st.write("No phone numbers detected.")
            else:
                for ioc in phone_numbers:
                    value = _get_field(ioc, "extracted_value", "N/A")
                    status = _get_known_status(ioc)
                    st.write(f"• `{value}` {status}")

        # Mule Bank Accounts
        with st.expander(
            f"🏦 Mule Bank Accounts ({len(mule_accounts)})", expanded=False
        ):
            if not mule_accounts:
                st.write("No mule bank accounts detected.")
            else:
                for ioc in mule_accounts:
                    value = _get_field(ioc, "extracted_value", "N/A")
                    status = _get_known_status(ioc)
                    st.write(f"• `{value}` {status}")

    def render_metrics(
        self, metrics: dict[str, Any] | Any, chat_state: dict[str, Any] | None = None
    ) -> None:
        """Display turn count, Total Scammer Time Wasted, and IoC counts.

        Metrics displayed:
        - Turn count
        - Total Scammer Time Wasted (HH:MM:SS)
        - IoC counts per category
        - Known vs New IoC counts
        """
        import streamlit as st

        st.subheader("📊 Session Metrics")

        # Extract metric values defensively
        if isinstance(metrics, dict):
            turn_count = metrics.get("turn_count", 0)
            start_time = metrics.get("start_time")
            last_message_time = metrics.get("last_message_time")
        else:
            # Pydantic model or similar object
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

        # Render metrics in columns
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Turn Count", turn_count)
        with col2:
            st.metric("Time Wasted", time_wasted)
        with col3:
            st.metric("Known IoCs", known_count)
        with col4:
            st.metric("New IoCs", new_count)

        # IoC counts per category
        col5, col6, col7, col8 = st.columns(4)
        with col5:
            st.metric("💰 Wallets", crypto_count)
        with col6:
            st.metric("🌐 Domains", domain_count)
        with col7:
            st.metric("📞 Phones", phone_count)
        with col8:
            st.metric("🏦 Mule Accts", mule_count)

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

        st.dataframe(rows, use_container_width=True)

    def render_notification_log(
        self, notifications: list[dict[str, Any] | Any]
    ) -> None:
        """Display mock AWS notifications with timestamp, severity, type, and summary.

        Notifications are displayed in reverse chronological order (newest first).
        """
        import streamlit as st

        st.subheader("🔔 Notification Log")

        if not notifications:
            st.info("No notifications generated yet.")
            return

        for notification in reversed(notifications):
            timestamp = _get_field(notification, "timestamp", None)
            severity = _get_field(notification, "severity", "UNKNOWN")
            payload_type = _get_field(notification, "payload_type", "unknown")
            summary = _get_field(notification, "summary", "No summary available")

            ts_str = _format_timestamp(timestamp)

            # Severity color coding
            severity_icon = _severity_icon(severity)

            st.markdown(
                f"{severity_icon} **[{severity}]** `{payload_type}` — {summary}  \n"
                f"<small>{ts_str}</small>",
                unsafe_allow_html=True,
            )


# --- Module-level helper functions (not part of the class) ---


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
