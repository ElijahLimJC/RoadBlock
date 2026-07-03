"""Manual Chat — Submit scammer messages directly for pipeline processing."""

import os

import streamlit as st

from pipeline import initialize_chat_state, process_scammer_message
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
    submitted = st.form_submit_button("🚀 Process Message", use_container_width=True)

# --- Golden Path Presets (for demo/judging) ---
with st.expander("📋 Sample Scammer Messages (click to send)", expanded=False):
    _PRESETS = [
        (
            "🏦 Bank Transfer Scam",
            "Dear valued customer, your account has been compromised. "
            "Please transfer your remaining balance to our secure holding "
            "account at Chase Bank, routing number 021000021, account "
            "1234567890 immediately to prevent further unauthorized access.",
        ),
        (
            "💰 Crypto Investment Scam",
            "Hello! I am a senior investment advisor. Send 0.5 BTC to "
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and I will return 5 BTC "
            "within 24 hours. This is a verified Binance promotion. "
            "You can also visit claim-btc-reward.com to verify.",
        ),
        (
            "📞 Tech Support Scam",
            "URGENT: Your computer has been infected with a trojan virus! "
            "Call our Microsoft certified technicians immediately at "
            "+1-888-555-0147. Visit fix-your-pc-now.net to download our "
            "remote access tool. Your Windows license will be revoked in "
            "24 hours if you do not comply.",
        ),
        (
            "🎁 Lottery / Prize Scam",
            "Congratulations! You have won $2,500,000 in the International "
            "Online Lottery. To claim your prize, send a processing fee of "
            "0.1 ETH to 0x71C7656EC7ab88b098defB751B7401B5f6d8976F or wire "
            "transfer $500 to Wells Fargo routing 121000248 account "
            "9876543210. Contact us at prizes@lottery-winner-intl.com.",
        ),
        (
            "🔓 Account Phishing",
            "We detected suspicious login to your PayPal account from "
            "Nigeria. Click here to verify: paypal-secure-login.xyz/verify "
            "If you do not verify within 2 hours, your account will be "
            "permanently locked. Call +44-20-7946-0958 for support.",
        ),
    ]
    for label, preset_msg in _PRESETS:
        if st.button(label, key=f"preset_{label}", use_container_width=True):
            st.session_state["_pending_preset"] = preset_msg
            st.rerun()

# --- Process pending preset automatically ---
if "_pending_preset" in st.session_state:
    _preset_to_send = st.session_state.pop("_pending_preset")
    with st.spinner("Processing preset message through pipeline..."):
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
            raw_message=_preset_to_send,
            persona_engine=persona,
        )
    st.rerun()

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

# --- Pipeline status ---
vt_status = st.session_state.get("vt_server_status", "unknown")
vt_client = st.session_state.get("virustotal_client")
iocs = st.session_state.get("iocs", {})
total_iocs = sum(len(v) for v in iocs.values())
known_count = st.session_state.get("known_ioc_count", 0)
new_count = st.session_state.get("new_ioc_count", 0)

if total_iocs > 0:
    st.success(
        f"IoCs extracted: {total_iocs} | Known: {known_count} | New: {new_count} | "
        f"VT: {vt_status}"
    )

# --- Conversation Log ---
st.divider()
_dashboard = SOCDashboard()
messages = st.session_state.get("conversation_history", [])
_dashboard.render_conversation_log(messages)
