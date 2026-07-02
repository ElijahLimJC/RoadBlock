"""Custom CSS styles for the RoadBlock SOC Dashboard."""

import streamlit as st


def inject_custom_css() -> None:
    """Inject custom CSS into the Streamlit page for professional styling."""
    st.markdown(_CUSTOM_CSS, unsafe_allow_html=True)


_CUSTOM_CSS = """
<style>
/* Dark accent header bar */
.main .block-container {
    padding-top: 1rem;
}

/* Metric cards */
div[data-testid="stMetric"] {
    background-color: #1e1e2e;
    border: 1px solid #313244;
    border-radius: 8px;
    padding: 12px 16px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.2);
}

div[data-testid="stMetric"] label {
    color: #a6adc8;
    font-size: 0.85rem;
}

div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: #cdd6f4;
    font-weight: 600;
}

/* Chat bubbles */
.chat-scammer {
    background: linear-gradient(135deg, #45243c 0%, #3b1f34 100%);
    border-left: 3px solid #f38ba8;
    border-radius: 0 12px 12px 12px;
    padding: 10px 14px;
    margin: 6px 0;
    color: #f5e0dc;
    font-size: 0.9rem;
}

.chat-persona {
    background: linear-gradient(135deg, #1e3a2e 0%, #1a332a 100%);
    border-left: 3px solid #a6e3a1;
    border-radius: 12px 0 12px 12px;
    padding: 10px 14px;
    margin: 6px 0;
    color: #d9f2d0;
    font-size: 0.9rem;
}

.chat-sender {
    font-size: 0.75rem;
    font-weight: 600;
    margin-bottom: 4px;
    opacity: 0.8;
}

.chat-time {
    font-size: 0.7rem;
    opacity: 0.5;
    margin-top: 4px;
}

/* IoC badges */
.ioc-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    margin-left: 6px;
}

.ioc-new {
    background: #1e4620;
    color: #a6e3a1;
    border: 1px solid #40a02b;
}

.ioc-known {
    background: #4a3f00;
    color: #f9e2af;
    border: 1px solid #df8e1d;
}

.ioc-unknown {
    background: #1e2a3a;
    color: #89b4fa;
    border: 1px solid #3b82f6;
}

/* Status pills */
.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 16px;
    font-size: 0.8rem;
    font-weight: 500;
}

.status-connected {
    background: #1e4620;
    color: #a6e3a1;
}

.status-disconnected {
    background: #4a1a1a;
    color: #f38ba8;
}

.status-idle {
    background: #1e2a3a;
    color: #89b4fa;
}

.status-running {
    background: #3a2e1e;
    color: #f9e2af;
}

/* Notification cards */
.notif-card {
    border-radius: 8px;
    padding: 10px 14px;
    margin: 6px 0;
    border-left: 3px solid;
}

.notif-critical { border-color: #f38ba8; background: #2a1520; }
.notif-high { border-color: #fab387; background: #2a2015; }
.notif-medium { border-color: #f9e2af; background: #2a2810; }
.notif-low { border-color: #a6e3a1; background: #152a1e; }

/* Sidebar styling */
section[data-testid="stSidebar"] {
    background-color: #11111b;
}

section[data-testid="stSidebar"] .stMetric {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 6px;
    padding: 8px;
}

/* Header branding */
.roadblock-header {
    background: linear-gradient(135deg, #1e1e2e 0%, #181825 100%);
    border: 1px solid #313244;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 16px;
    text-align: center;
}

.roadblock-header h1 {
    margin: 0;
    font-size: 1.8rem;
}

.roadblock-header p {
    margin: 4px 0 0;
    opacity: 0.7;
    font-size: 0.9rem;
}
</style>
"""
