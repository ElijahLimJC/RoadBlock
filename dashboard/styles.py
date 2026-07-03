"""Custom CSS styles for the RoadBlock SOC Dashboard."""

import streamlit as st


def inject_custom_css() -> None:
    """Inject custom CSS into the Streamlit page for professional styling."""
    st.markdown(_CUSTOM_CSS, unsafe_allow_html=True)


_CUSTOM_CSS = """
<style>
/* Tighter top padding */
.main .block-container {
    padding-top: 0.5rem;
    max-width: 1200px;
}

/* --- Hero Block --- */
.roadblock-hero {
    background: linear-gradient(135deg, #1e1e2e 0%, #11111b 100%);
    border: 1px solid #313244;
    border-radius: 12px;
    padding: 24px 32px 16px;
    margin-bottom: 20px;
    text-align: center;
}

.hero-title {
    font-size: 2rem;
    font-weight: 700;
    color: #cdd6f4;
    margin: 0 0 2px;
}

.hero-subtitle {
    font-size: 0.85rem;
    color: #6c7086;
    margin: 0 0 14px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}

.hero-status {
    display: flex;
    justify-content: center;
    gap: 10px;
    flex-wrap: wrap;
}

/* --- Status pills --- */
.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 12px;
    border-radius: 14px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.3px;
}

.status-connected {
    background: rgba(166, 227, 161, 0.12);
    color: #a6e3a1;
    border: 1px solid rgba(166, 227, 161, 0.3);
}

.status-disconnected {
    background: rgba(243, 139, 168, 0.12);
    color: #f38ba8;
    border: 1px solid rgba(243, 139, 168, 0.3);
}

.status-idle {
    background: rgba(137, 180, 250, 0.10);
    color: #89b4fa;
    border: 1px solid rgba(137, 180, 250, 0.25);
}

.status-running {
    background: rgba(249, 226, 175, 0.12);
    color: #f9e2af;
    border: 1px solid rgba(249, 226, 175, 0.3);
}

/* --- Section headers --- */
.section-header {
    font-size: 1rem;
    font-weight: 600;
    color: #a6adc8;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin: 20px 0 10px;
    padding-bottom: 6px;
    border-bottom: 1px solid #313244;
}

/* --- Metric cards --- */
div[data-testid="stMetric"] {
    background: #181825;
    border: 1px solid #313244;
    border-radius: 10px;
    padding: 14px 16px;
    transition: border-color 0.2s ease;
}

div[data-testid="stMetric"]:hover {
    border-color: #45475a;
}

div[data-testid="stMetric"] label {
    color: #6c7086;
    font-size: 0.75rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: #cdd6f4;
    font-weight: 700;
    font-size: 1.6rem;
}

/* --- Chat bubbles --- */
.chat-scammer {
    background: linear-gradient(135deg, #302030 0%, #281a28 100%);
    border-left: 3px solid #f38ba8;
    border-radius: 0 10px 10px 10px;
    padding: 10px 14px;
    margin: 5px 0;
    color: #f5e0dc;
    font-size: 0.88rem;
    line-height: 1.4;
}

.chat-persona {
    background: linear-gradient(135deg, #1a2e24 0%, #162820 100%);
    border-left: 3px solid #a6e3a1;
    border-radius: 10px 0 10px 10px;
    padding: 10px 14px;
    margin: 5px 0;
    color: #d9f2d0;
    font-size: 0.88rem;
    line-height: 1.4;
}

.chat-sender {
    font-size: 0.7rem;
    font-weight: 700;
    margin-bottom: 3px;
    opacity: 0.7;
    text-transform: uppercase;
    letter-spacing: 0.3px;
}

.chat-time {
    font-size: 0.65rem;
    opacity: 0.4;
    margin-top: 4px;
}

/* --- IoC badges --- */
.ioc-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 0.7rem;
    font-weight: 700;
    margin-left: 6px;
    vertical-align: middle;
    letter-spacing: 0.3px;
}

.ioc-new {
    background: rgba(166, 227, 161, 0.15);
    color: #a6e3a1;
    border: 1px solid rgba(64, 160, 43, 0.4);
}

.ioc-known {
    background: rgba(249, 226, 175, 0.15);
    color: #f9e2af;
    border: 1px solid rgba(223, 142, 29, 0.4);
}

.ioc-unknown {
    background: rgba(137, 180, 250, 0.12);
    color: #89b4fa;
    border: 1px solid rgba(59, 130, 246, 0.3);
}

/* --- Notification cards --- */
.notif-card {
    border-radius: 8px;
    padding: 10px 14px;
    margin: 5px 0;
    border-left: 3px solid;
    font-size: 0.85rem;
    line-height: 1.4;
}

.notif-critical { border-color: #f38ba8; background: rgba(243, 139, 168, 0.08); }
.notif-high { border-color: #fab387; background: rgba(250, 179, 135, 0.08); }
.notif-medium { border-color: #f9e2af; background: rgba(249, 226, 175, 0.08); }
.notif-low { border-color: #a6e3a1; background: rgba(166, 227, 161, 0.08); }

/* --- Sidebar --- */
section[data-testid="stSidebar"] {
    background-color: #11111b;
}

/* --- Expander styling --- */
div[data-testid="stExpander"] {
    border: 1px solid #313244;
    border-radius: 8px;
    margin-bottom: 6px;
}

div[data-testid="stExpander"] summary {
    font-weight: 600;
    font-size: 0.85rem;
}

/* --- Divider subtlety --- */
hr {
    border-color: #313244;
    opacity: 0.5;
    margin: 16px 0;
}

/* Reduce gap between metric columns */
div[data-testid="stHorizontalBlock"] {
    gap: 0.6rem;
}
</style>
"""
