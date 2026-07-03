"""Email Ingestion — Monitor and manage email-based scam engagement."""

import streamlit as st

from app import initialize_chat_state, initialize_email_ingestion
from dashboard.soc_dashboard import SOCDashboard
from dashboard.styles import inject_custom_css
from models.chat_models import ChatMessage

st.set_page_config(page_title="RoadBlock — Email Ingestion", layout="wide")
inject_custom_css()
initialize_chat_state()

# Initialize email ingestion if not already done
if "email_ingestion_module" not in st.session_state:
    st.session_state.email_ingestion_module = initialize_email_ingestion()

st.markdown(
    '<div class="roadblock-header">'
    "<h1>📧 Email Ingestion</h1>"
    "<p>Monitor inbound scam email processing and outbound engagement</p>"
    "</div>",
    unsafe_allow_html=True,
)

_dashboard = SOCDashboard()

if st.session_state.get("email_ingestion_module") is not None:
    _email_module = st.session_state.email_ingestion_module
    _email_module.flush_to_session_state(st.session_state.email_ingestion)

    # Merge staged conversation messages
    _staged_msgs = st.session_state.email_ingestion.pop("_staged_messages", [])
    if _staged_msgs:
        from datetime import datetime
        from models import APP_TIMEZONE

        for _msg_data in _staged_msgs:
            _chat_msg = ChatMessage(
                sender=_msg_data.get("sender", "scammer"),
                content=_msg_data.get("content", ""),
                timestamp=datetime.now(APP_TIMEZONE),
            )
            st.session_state["conversation_history"].append(_chat_msg)

    # Apply pending turn updates to stalling metrics
    _pending_turns = st.session_state.email_ingestion.pop("_pending_turns", 0)
    if _pending_turns > 0:
        from components.stalling_tracker import StallingTracker

        _tracker = StallingTracker()
        for _ in range(_pending_turns):
            _tracker.record_turn(st.session_state)

    # Merge staged IoCs with deduplication
    _staged_iocs = st.session_state.email_ingestion.pop("_staged_iocs", [])
    if _staged_iocs:
        _iocs_state = st.session_state.get("iocs", {})
        _new_count = 0
        for _ioc_data in _staged_iocs:
            _cat = _ioc_data.get("category", "")
            _value = _ioc_data.get("extracted_value")
            if _cat == "cryptocurrency_wallet":
                _target = _iocs_state.setdefault("cryptocurrency_wallets", [])
            elif _cat == "phishing_domain":
                _target = _iocs_state.setdefault("phishing_domains", [])
            elif _cat == "phone_number":
                _target = _iocs_state.setdefault("phone_numbers", [])
            elif _cat == "mule_bank_account":
                _target = _iocs_state.setdefault("mule_bank_accounts", [])
            else:
                continue
            # Deduplicate by extracted_value
            _existing = {
                (d.get("extracted_value") if isinstance(d, dict)
                 else getattr(d, "extracted_value", None))
                for d in _target
            }
            if _value not in _existing:
                _target.append(_ioc_data)
                _new_count += 1
        st.session_state["iocs"] = _iocs_state
        if _new_count > 0:
            st.session_state["new_ioc_count"] = (
                st.session_state.get("new_ioc_count", 0) + _new_count
            )

    # Render panels
    _dashboard.render_email_ingestion_panel(dict(st.session_state))
    st.divider()
    _dashboard.render_classification_log(
        st.session_state.email_ingestion.get("classification_log", [])
    )

    # Show email conversation log
    st.divider()
    st.subheader("💬 Email Conversations")
    messages = st.session_state.get("conversation_history", [])
    _dashboard.render_conversation_log(messages)

    # Auto-refresh for real-time updates
    from streamlit_autorefresh import st_autorefresh

    st_autorefresh(interval=5000, limit=None, key="email_page_refresh")
else:
    st.info(
        "📭 Email ingestion is not configured. "
        "Set IMAP_HOST, IMAP_PORT, IMAP_USERNAME, IMAP_PASSWORD "
        "environment variables to enable."
    )
