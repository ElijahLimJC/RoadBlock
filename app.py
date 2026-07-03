"""RoadBlock — Main landing page (SOC Dashboard overview).

This is the Streamlit entry point. Interactive pages live in pages/.
All shared pipeline logic is in pipeline.py (imported by pages too).
"""

import atexit
import logging

import streamlit as st

from dashboard.soc_dashboard import SOCDashboard
from dashboard.styles import inject_custom_css
from pipeline import (
    PipelineError,
    PipelineResult,
    _get_default_blocked_response,
    _run_extraction_pipeline,
    _store_ioc,
    flush_email_ingestion_state,
    initialize_chat_state,
    initialize_email_ingestion,
    process_scammer_message,
    trim_classification_log,
)

# Re-export pipeline symbols for backward compatibility
__all__ = [
    "PipelineError",
    "PipelineResult",
    "_get_default_blocked_response",
    "_run_extraction_pipeline",
    "_store_ioc",
    "flush_email_ingestion_state",
    "initialize_chat_state",
    "initialize_email_ingestion",
    "process_scammer_message",
    "trim_classification_log",
]

logger = logging.getLogger(__name__)

# Page config MUST be the first Streamlit command
st.set_page_config(page_title="RoadBlock", layout="wide")
inject_custom_css()

# Initialize session state defaults
initialize_chat_state()

# Initialize email ingestion (optional, depends on env vars)
if "email_ingestion_module" not in st.session_state:
    st.session_state.email_ingestion_module = initialize_email_ingestion()


def _cleanup_email_ingestion() -> None:
    """Stop email ingestion polling on session teardown to prevent ghost threads."""
    module = st.session_state.get("email_ingestion_module")
    if module is not None:
        module.stop_polling()


# Register cleanup so the poll thread is stopped when the session ends
if st.session_state.get("email_ingestion_module") is not None:
    if not st.session_state.get("_email_cleanup_registered"):
        atexit.register(_cleanup_email_ingestion)
        st.session_state["_email_cleanup_registered"] = True

# Flush email ingestion results into session state each render cycle
# NOTE: flush_email_ingestion_state() runs during initialization phase (before render).
# This is acceptable per Streamlit's execution model — it synchronizes background
# thread results into session_state before any widgets are rendered.
flush_email_ingestion_state()

# --- SOC Dashboard ---
_dashboard = SOCDashboard()

# --- Header ---
st.markdown(
    '<div class="roadblock-header">'
    '<h1>🛡️ RoadBlock</h1>'
    '<p>Automated Social Honeypot — Engage scammers • Extract IoCs • '
    'Waste their time</p>'
    '</div>',
    unsafe_allow_html=True,
)

# --- Status Indicators Row ---
status_col1, status_col2, status_col3 = st.columns(3)

with status_col1:
    parser_status = st.session_state.get("parser_status", "idle")
    if parser_status == "running":
        st.markdown(
            '<span class="status-pill status-running">'
            '⏳ Parser: Extracting</span>',
            unsafe_allow_html=True,
        )
    elif parser_status == "error":
        st.markdown(
            '<span class="status-pill status-disconnected">'
            '⚠️ Parser: Error</span>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<span class="status-pill status-idle">✓ Parser: Idle</span>',
            unsafe_allow_html=True,
        )
with status_col2:
    vt_status = st.session_state.get("vt_server_status", "unknown")
    vt_configured = st.session_state.get("virustotal_client") is not None
    if vt_status == "connected":
        st.markdown(
            '<span class="status-pill status-connected">'
            '● VT: Connected</span>',
            unsafe_allow_html=True,
        )
    elif vt_status in ("timeout", "error"):
        st.markdown(
            '<span class="status-pill status-disconnected">'
            '● VT: Error</span>',
            unsafe_allow_html=True,
        )
    elif vt_configured:
        st.markdown(
            '<span class="status-pill status-idle">'
            '○ VT: Ready</span>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<span class="status-pill status-disconnected">'
            '○ VT: No API key</span>',
            unsafe_allow_html=True,
        )
with status_col3:
    if st.session_state.get("email_ingestion_module") is not None:
        email_status = st.session_state.email_ingestion.get(
            "connection_status", "disconnected"
        )
        if email_status == "connected":
            st.markdown(
                '<span class="status-pill status-connected">'
                '● Email: Connected</span>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<span class="status-pill status-disconnected">'
                '● Email: Disconnected</span>',
                unsafe_allow_html=True,
            )

# --- Auto-refresh when email ingestion is active ---
if st.session_state.get("email_ingestion_module") is not None:
    from streamlit_autorefresh import st_autorefresh

    st_autorefresh(interval=5000, limit=None, key="email_ingestion_refresh")

st.divider()

# --- SOC Dashboard (read-only overview) ---
_dashboard.render(dict(st.session_state))

# Show email ingestion panel on main page too
if st.session_state.get("email_ingestion_module") is not None:
    st.divider()
    _dashboard.render_email_ingestion_panel(dict(st.session_state))

# Show last error if any
last_error = st.session_state.get("last_error")
if last_error:
    st.error(f"Last pipeline error: {last_error}")
