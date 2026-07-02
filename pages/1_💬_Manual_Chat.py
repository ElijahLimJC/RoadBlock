"""Manual Chat — Submit scammer messages directly for pipeline processing."""

import os

import streamlit as st

from app import initialize_chat_state, process_scammer_message
from components.persona_engine import PersonaEngine
from dashboard.soc_dashboard import SOCDashboard
from dashboard.styles import inject_custom_css

st.set_page_config(page_title="RoadBlock — Manual Chat", layout="wide")
inject_custom_css()
initialize_chat_state()

st.markdown(
    '<div class="roadblock-header">'
    "<h1>💬 Manual Chat</h1>"
    "<p>Submit scammer messages directly to the RoadBlock pipeline</p>"
    "</div>",
    unsafe_allow_html=True,
)

# --- Input Form ---
with st.form("scammer_input_form", clear_on_submit=True):
    raw_message = st.text_area(
        "Enter scammer message:",
        height=150,
        placeholder="Paste or type a scammer message here...",
    )
    submitted = st.form_submit_button("🚀 Process Message", width="stretch")

if submitted and raw_message.strip():
    with st.spinner("Processing message through pipeline..."):
        persona = None
        mistral_key = os.environ.get("MISTRAL_API_KEY", "").strip()
        if mistral_key:
            try:
                import httpx
                from mistralai.client import Mistral

                ssl_verify = os.environ.get("ROADBLOCK_SSL_VERIFY", "true").lower() != "false"
                http_client = httpx.Client(verify=ssl_verify)
                client = Mistral(api_key=mistral_key, client=http_client)
                persona = PersonaEngine(llm_client=client)
            except Exception:
                pass
        if persona is None:
            persona = PersonaEngine(llm_client=None)

        process_scammer_message(
            raw_message=raw_message.strip(),
            persona_engine=persona,
        )
    st.rerun()
elif submitted:
    st.warning("Please enter a message before submitting.")

# --- Show last error ---
last_error = st.session_state.get("last_error")
if last_error:
    st.error(f"Last pipeline error: {last_error}")

# --- Conversation Log ---
st.divider()
_dashboard = SOCDashboard()
messages = st.session_state.get("conversation_history", [])
_dashboard.render_conversation_log(messages)
