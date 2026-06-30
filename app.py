"""RoadBlock — Streamlit entry point.

Pipeline orchestration for the automated social honeypot. Wires the
sequential flow: Scammer Input → Safety Filter → Persona Engine →
Chat State → Threat Parser → MCP Lookup → Notifications → Dashboard.
"""

import asyncio
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

import streamlit as st

from components.email_ingestion import EmailIngestionModule
from components.imap_client import IMAPClient
from components.ioc_lookup_mcp import IoCLookupMCPClient
from components.notification_module import NotificationModule
from components.persona_engine import PersonaEngine
from components.safety_filter import SafetyFilter
from components.scam_classifier import ScamClassifier
from components.smtp_client import SMTPClient
from components.stalling_tracker import StallingTracker
from components.threat_parser import ThreatParser
from models.chat_models import ChatMessage, SessionMetrics
from models.email_models import ScamPattern

logger = logging.getLogger(__name__)

# --- Pipeline timeout (seconds), excluding async parser ---
_PIPELINE_TIMEOUT_SECONDS = 15.0

# --- Thread pool for async threat parsing ---
_extraction_executor = ThreadPoolExecutor(max_workers=2)


class PipelineError(Exception):
    """Domain-specific error for pipeline stage failures."""

    def __init__(self, stage: str, message: str, original_error: Optional[Exception] = None):
        self.stage = stage
        self.message = message
        self.original_error = original_error
        super().__init__(f"[{stage}] {message}")


def initialize_chat_state() -> None:
    """Initialize all Chat_State keys to empty defaults.

    Called once per new Streamlit session. Preserves existing values
    on Streamlit reruns (only sets key if not already in session_state).
    """
    defaults = {
        "conversation_history": [],
        "iocs": {
            "cryptocurrency_wallets": [],
            "phishing_domains": [],
            "phone_numbers": [],
            "mule_bank_accounts": [],
        },
        "metrics": SessionMetrics().model_dump(),
        "notifications": [],
        "rejection_log": [],
        "parser_status": "idle",
        "last_error": None,
        "mcp_lookup_cache": {},
        "mcp_server_status": "unknown",
        "known_ioc_count": 0,
        "new_ioc_count": 0,
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default

    # Email ingestion state (Task 9.1)
    if "email_ingestion" not in st.session_state:
        st.session_state.email_ingestion = {
            "connection_status": "disconnected",
            "total_fetched": 0,
            "total_scam": 0,
            "total_not_scam": 0,
            "outbound_sent": 0,
            "consecutive_failures": 0,
            "degraded_warning": False,
            "classification_log": [],  # max 200 ClassificationResult entries
            "outbound_queue": [],      # max 100 OutboundEmail entries
            "threads": {},             # sender_address -> EmailThreadMetadata
        }


# Max capacity for email ingestion classification log
_CLASSIFICATION_LOG_MAX = 200


def trim_classification_log(state_dict: dict) -> None:
    """Evict oldest entries when classification_log exceeds max capacity.

    Trims the classification_log list in-place to keep at most
    _CLASSIFICATION_LOG_MAX entries, removing the oldest first.

    Args:
        state_dict: The email_ingestion state dictionary (mutable).
    """
    log = state_dict.get("classification_log", [])
    if len(log) > _CLASSIFICATION_LOG_MAX:
        state_dict["classification_log"] = log[-_CLASSIFICATION_LOG_MAX:]


def _get_default_scam_patterns() -> list[ScamPattern]:
    """Return a default list of common scam indicator patterns.

    These patterns cover urgency, financial lures, impersonation, and
    phishing indicators commonly seen in scam emails.

    Returns:
        List of ScamPattern instances with regex and weight.
    """
    return [
        ScamPattern(
            name="urgency_keywords",
            regex=r"(?i)\b(urgent|immediately|act now|limited time|expire)\b",
            category="urgency",
            weight=0.2,
        ),
        ScamPattern(
            name="financial_lure",
            regex=r"(?i)\b(lottery|winner|prize|inheritance|million|transfer)\b",
            category="financial_lure",
            weight=0.25,
        ),
        ScamPattern(
            name="authority_impersonation",
            regex=r"(?i)\b(bank|irs|fbi|government|official|attorney)\b",
            category="impersonation",
            weight=0.15,
        ),
        ScamPattern(
            name="payment_request",
            regex=r"(?i)\b(wire transfer|bitcoin|gift card|western union|crypto)\b",
            category="financial_lure",
            weight=0.3,
        ),
        ScamPattern(
            name="phishing_link",
            regex=r"(?i)(click here|verify your account|confirm your identity|login)",
            category="phishing",
            weight=0.2,
        ),
        ScamPattern(
            name="threat_language",
            regex=r"(?i)\b(suspended|locked|seized|arrested|legal action)\b",
            category="urgency",
            weight=0.2,
        ),
    ]


def initialize_email_ingestion() -> "EmailIngestionModule | None":
    """Initialize the email ingestion module from environment variables.

    Creates IMAPClient, SMTPClient, ScamClassifier, and EmailIngestionModule
    instances. Stores the module in st.session_state.email_ingestion_module
    and starts the polling loop.

    If any required IMAP/SMTP environment variables are missing, logs at
    info level and returns None (email ingestion is optional).

    Returns:
        The initialized EmailIngestionModule, or None if env vars are missing.
    """
    if st.session_state.get("email_ingestion_module") is not None:
        module: EmailIngestionModule = st.session_state.email_ingestion_module
        return module

    required_vars = ["IMAP_HOST", "IMAP_PORT", "IMAP_USERNAME", "IMAP_PASSWORD"]
    missing = [v for v in required_vars if not os.environ.get(v)]
    if missing:
        logger.info(
            "Email ingestion disabled: missing env vars %s", ", ".join(missing)
        )
        return None

    imap_client = IMAPClient(
        host=os.environ["IMAP_HOST"],
        port=int(os.environ.get("IMAP_PORT", "993")),
        username=os.environ.get("IMAP_USERNAME", ""),
        password=os.environ.get("IMAP_PASSWORD", ""),
    )

    smtp_host = os.environ.get("SMTP_HOST", "")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_username = os.environ.get("SMTP_USERNAME", "")
    smtp_password = os.environ.get("SMTP_PASSWORD", "")
    smtp_sender = os.environ.get("SMTP_SENDER", "")

    if not smtp_host:
        logger.info("SMTP not configured; outbound replies will be disabled")

    smtp_client = SMTPClient(
        host=smtp_host,
        port=smtp_port,
        username=smtp_username,
        password=smtp_password,
        sender_address=smtp_sender,
    )

    patterns = _get_default_scam_patterns()

    # Initialize LLM client for Stage 2 classification if API key available
    llm_client = None
    gemini_api_key = os.environ.get("GEMINI_API_KEY", "")
    if gemini_api_key:
        try:
            import google.generativeai as genai

            genai.configure(api_key=gemini_api_key)
            llm_client = genai.GenerativeModel("gemini-1.5-flash")
            logger.info("Stage 2 LLM classification enabled (Gemini)")
        except Exception as e:
            logger.warning("Failed to initialize Gemini LLM client: %s", e)
    else:
        logger.info(
            "GEMINI_API_KEY not set; Stage 2 LLM disabled, "
            "falling back to regex-only classification"
        )

    scam_classifier = ScamClassifier(
        patterns=patterns,
        llm_client=llm_client,
        confidence_threshold=0.7,
        fallback_threshold=0.3,
    )

    module = EmailIngestionModule(
        imap_client=imap_client,
        smtp_client=smtp_client,
        scam_classifier=scam_classifier,
        polling_interval=30,
    )

    st.session_state.email_ingestion_module = module
    module.start_polling()
    return module


def _get_default_blocked_response() -> str:
    """Generate a default confused-elder response for blocked messages.

    Used when the Safety Filter blocks a message (≥80% injection)
    so the Persona Engine is not invoked.
    """
    return (
        "Oh dear, I'm sorry, I don't quite understand what you're saying. "
        "Could you try saying that again in simpler words? My grandson Tommy "
        "says I need to be more careful about what I read on the computer. "
        "Anyway, what was it you needed help with?"
    )


def process_scammer_message(
    raw_message: str,
    safety_filter: Optional[SafetyFilter] = None,
    persona_engine: Optional[PersonaEngine] = None,
    stalling_tracker: Optional[StallingTracker] = None,
    threat_parser: Optional[ThreatParser] = None,
    mcp_client: Optional[IoCLookupMCPClient] = None,
    notification_module: Optional[NotificationModule] = None,
) -> None:
    """Process a scammer message through the full RoadBlock pipeline.

    Sequential flow:
    1. Safety_Filter.scan(raw_message)
    2. Branch: blocked → default response; safe/partial → Persona_Engine
    3. Update Chat_State with message pair
    4. Stalling_Tracker.record_turn()
    5. Trigger async Threat_Parser extraction via ThreadPoolExecutor
    6. On extraction complete: MCP lookup → notifications for NEW IoCs → update state

    Error handling wraps each stage in try/except, logs PipelineError,
    and preserves Chat_State on failure.

    Enforces 15s end-to-end timeout (excluding async parser).

    Args:
        raw_message: The raw scammer input text.
        safety_filter: SafetyFilter instance (created if None).
        persona_engine: PersonaEngine instance (created if None).
        stalling_tracker: StallingTracker instance (created if None).
        threat_parser: ThreatParser instance (created if None).
        mcp_client: IoCLookupMCPClient instance (optional, skips MCP if None).
        notification_module: NotificationModule instance (created if None).
    """
    pipeline_start = time.time()

    # Initialize components with defaults if not provided
    if safety_filter is None:
        safety_filter = SafetyFilter()
    if stalling_tracker is None:
        stalling_tracker = StallingTracker()
    if threat_parser is None:
        threat_parser = ThreatParser()
    if notification_module is None:
        notification_module = NotificationModule()

    # --- Stage 1: Safety Filter ---
    scan_result = None
    try:
        scan_result = safety_filter.scan(raw_message)
    except Exception as e:
        error = PipelineError("Safety_Filter", f"Scan failed: {e}", e)
        logger.error(str(error), exc_info=True)
        st.session_state["last_error"] = str(error)
        # On safety filter failure, treat message as safe (pass through)
        # to avoid blocking legitimate messages
        from models.chat_models import ScanResult
        scan_result = ScanResult(
            sanitized_content=raw_message,
            detected_patterns=[],
            is_blocked=False,
        )

    # --- Stage 2: Response Generation (branch on blocked vs safe) ---
    response_content: str = ""
    is_blocked = scan_result.is_blocked
    sanitized_message = scan_result.sanitized_content

    if is_blocked:
        # Blocked: generate default response, skip Persona_Engine
        try:
            response_content = _get_default_blocked_response()
        except Exception as e:
            error = PipelineError(
                "Default_Response", f"Failed to generate default response: {e}", e
            )
            logger.error(str(error), exc_info=True)
            st.session_state["last_error"] = str(error)
            response_content = "Oh my, I'm a bit confused. Could you say that again?"
    else:
        # Safe/partial: invoke Persona_Engine
        if persona_engine is not None:
            try:
                persona_response = persona_engine.generate_response(
                    sanitized_message,
                    st.session_state.get("conversation_history", []),
                )
                response_content = persona_response.content
            except Exception as e:
                error = PipelineError(
                    "Persona_Engine", f"Response generation failed: {e}", e
                )
                logger.error(str(error), exc_info=True)
                st.session_state["last_error"] = str(error)
                response_content = _get_default_blocked_response()
        else:
            # No persona engine available — use fallback
            response_content = _get_default_blocked_response()

    # --- Stage 3: Update Chat_State with message pair ---
    try:
        scammer_msg = ChatMessage(
            sender="scammer",
            content=sanitized_message,
            timestamp=datetime.utcnow(),
            was_sanitized=len(scan_result.detected_patterns) > 0,
            was_blocked=is_blocked,
        )
        persona_msg = ChatMessage(
            sender="persona",
            content=response_content,
            timestamp=datetime.utcnow(),
        )
        st.session_state["conversation_history"].append(scammer_msg)
        st.session_state["conversation_history"].append(persona_msg)
    except Exception as e:
        error = PipelineError("Chat_State_Update", f"State update failed: {e}", e)
        logger.error(str(error), exc_info=True)
        st.session_state["last_error"] = str(error)

    # --- Stage 4: Stalling Tracker ---
    try:
        stalling_tracker.record_turn(st.session_state)
    except Exception as e:
        error = PipelineError("Stalling_Tracker", f"Record turn failed: {e}", e)
        logger.error(str(error), exc_info=True)
        st.session_state["last_error"] = str(error)

    # --- Check 15s timeout before async stage ---
    elapsed = time.time() - pipeline_start
    if elapsed >= _PIPELINE_TIMEOUT_SECONDS:
        logger.warning(
            "Pipeline timeout reached (%.1fs) before async extraction", elapsed
        )
        st.session_state["last_error"] = (
            f"Pipeline timeout: synchronous stages took {elapsed:.1f}s"
        )
        return

    # --- Stage 5: Trigger async Threat_Parser extraction ---
    # Use the original raw message for extraction (captures IoCs even in blocked messages)
    message_for_extraction = raw_message

    try:
        st.session_state["parser_status"] = "running"
        # Submit extraction to thread pool (non-blocking for Streamlit)
        future = _extraction_executor.submit(
            _run_extraction_pipeline,
            message_for_extraction,
            threat_parser,
            mcp_client,
            notification_module,
        )
        # Wait for extraction to complete (with remaining time budget)
        # The async parser has its own 5s internal timeout
        # We give it up to 10s from the thread pool perspective
        remaining_time = max(1.0, 10.0)
        try:
            future.result(timeout=remaining_time)
        except Exception as e:
            logger.warning("Async extraction did not complete in time: %s", e)
            st.session_state["parser_status"] = "error"
            st.session_state["last_error"] = f"Extraction timeout: {e}"
    except Exception as e:
        error = PipelineError("Threat_Parser", f"Extraction dispatch failed: {e}", e)
        logger.error(str(error), exc_info=True)
        st.session_state["parser_status"] = "error"
        st.session_state["last_error"] = str(error)


def _run_extraction_pipeline(
    message: str,
    threat_parser: ThreatParser,
    mcp_client: Optional[IoCLookupMCPClient],
    notification_module: NotificationModule,
) -> None:
    """Run the extraction pipeline in a background thread.

    Executes:
    1. ThreatParser.extract_iocs(message)
    2. MCP lookup for each extracted IoC
    3. Generate notifications for NEW IoCs only
    4. Update Chat_State with results

    Args:
        message: The raw message to extract IoCs from.
        threat_parser: ThreatParser instance.
        mcp_client: Optional MCP client for IoC lookups.
        notification_module: NotificationModule for generating alerts.
    """
    try:
        # Run async extraction in a new event loop (since we're in a thread)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            extraction_result = loop.run_until_complete(
                threat_parser.extract_iocs(message)
            )
        finally:
            loop.close()

        # Update rejection log
        if extraction_result.rejections:
            st.session_state["rejection_log"].extend(extraction_result.rejections)

        if not extraction_result.iocs:
            st.session_state["parser_status"] = "idle"
            return

        # --- MCP Lookup for each IoC ---
        cache = st.session_state.get("mcp_lookup_cache", {})
        lookup_results = []

        if mcp_client is not None:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    lookup_results = loop.run_until_complete(
                        mcp_client.batch_check(extraction_result.iocs, cache)
                    )
                finally:
                    loop.close()
                st.session_state["mcp_lookup_cache"] = cache
                st.session_state["mcp_server_status"] = "connected"
            except Exception as e:
                logger.warning("MCP batch lookup failed: %s", e)
                st.session_state["mcp_server_status"] = "disconnected"
                # Continue without lookup results — IoCs still stored

        # --- Store IoCs and generate notifications for NEW ones ---
        for i, ioc in enumerate(extraction_result.iocs):
            # Determine if IoC is known or new
            is_known = False
            if i < len(lookup_results):
                is_known = lookup_results[i].is_known
                if is_known:
                    st.session_state["known_ioc_count"] = (
                        st.session_state.get("known_ioc_count", 0) + 1
                    )
                else:
                    st.session_state["new_ioc_count"] = (
                        st.session_state.get("new_ioc_count", 0) + 1
                    )
            else:
                # No lookup result — treat as new
                st.session_state["new_ioc_count"] = (
                    st.session_state.get("new_ioc_count", 0) + 1
                )

            # Store IoC in appropriate category list
            _store_ioc(ioc)

            # Generate notification only for NEW IoCs (not previously known)
            if not is_known:
                try:
                    notification = notification_module.generate_notification(ioc)
                    st.session_state["notifications"].append(notification)
                except Exception as e:
                    logger.warning(
                        "Notification generation failed for IoC %s: %s",
                        ioc.extracted_value,
                        e,
                    )

        st.session_state["parser_status"] = "idle"

    except Exception as e:
        logger.error("Extraction pipeline failed: %s", e, exc_info=True)
        st.session_state["parser_status"] = "error"
        st.session_state["last_error"] = f"Extraction error: {e}"


def _store_ioc(ioc) -> None:
    """Store an extracted IoC in the appropriate session state category list.

    Args:
        ioc: A BaseIoC subclass instance to store.
    """
    from models.ioc_models import (
        IoCCategory,
    )

    iocs = st.session_state.get("iocs", {})

    if ioc.category == IoCCategory.CRYPTOCURRENCY_WALLET:
        iocs.setdefault("cryptocurrency_wallets", []).append(ioc)
    elif ioc.category == IoCCategory.PHISHING_DOMAIN:
        iocs.setdefault("phishing_domains", []).append(ioc)
    elif ioc.category == IoCCategory.PHONE_NUMBER:
        iocs.setdefault("phone_numbers", []).append(ioc)
    elif ioc.category == IoCCategory.MULE_BANK_ACCOUNT:
        iocs.setdefault("mule_bank_accounts", []).append(ioc)

    st.session_state["iocs"] = iocs


# ---------------------------------------------------------------------------
# Streamlit UI Layout
# ---------------------------------------------------------------------------

# Page config MUST be the first Streamlit command
st.set_page_config(page_title="RoadBlock", layout="wide")

# Initialize session state defaults
initialize_chat_state()

# Initialize email ingestion (optional, depends on env vars)
if "email_ingestion_module" not in st.session_state:
    st.session_state.email_ingestion_module = initialize_email_ingestion()

# Flush email ingestion results into session state each render cycle
if st.session_state.get("email_ingestion_module") is not None:
    _email_module = st.session_state.email_ingestion_module
    _email_module.flush_to_session_state(st.session_state.email_ingestion)
    _email_module._smtp_client.process_retry_queue()

# --- Import SOC Dashboard ---
from dashboard.soc_dashboard import SOCDashboard

_dashboard = SOCDashboard()

# --- Header ---
st.title("🛡️ RoadBlock — Automated Social Honeypot")
st.caption("Engage scammers • Extract IoCs • Waste their time")

# --- Status Indicators Row ---
status_col1, status_col2 = st.columns(2)

with status_col1:
    parser_status = st.session_state.get("parser_status", "idle")
    if parser_status == "running":
        st.status("🔄 Threat Parser: Extracting IoCs...", state="running")
    elif parser_status == "error":
        st.error("⚠️ Threat Parser: Error during extraction")
    else:
        st.success("✅ Threat Parser: Idle")

with status_col2:
    mcp_status = st.session_state.get("mcp_server_status", "unknown")
    if mcp_status == "connected":
        st.success("🟢 MCP Server: Connected")
    elif mcp_status == "disconnected":
        st.error("🔴 MCP Server: Disconnected")
    else:
        st.info("⚪ MCP Server: Not connected")

st.divider()

# --- Main Layout: Input + Dashboard ---
input_col, dashboard_col = st.columns([1, 2])

with input_col:
    st.subheader("📨 Scammer Message Input")

    with st.form("scammer_input_form", clear_on_submit=True):
        raw_message = st.text_area(
            "Enter scammer message:",
            height=150,
            placeholder="Paste or type a scammer message here...",
        )
        submitted = st.form_submit_button("🚀 Process Message", use_container_width=True)

    if submitted and raw_message.strip():
        with st.spinner("Processing message through pipeline..."):
            # Attempt to create a PersonaEngine if API key is available
            persona = None
            try:
                persona = PersonaEngine()
            except Exception:
                # No API key or init failure - persona will be None, fallback used
                pass

            process_scammer_message(
                raw_message=raw_message.strip(),
                persona_engine=persona,
            )

            # Wire SMTP delivery for email-sourced messages
            if st.session_state.get("email_ingestion_module") is not None:
                _module = st.session_state.email_ingestion_module
                outbound_queue = st.session_state.email_ingestion.get(
                    "outbound_queue", []
                )
                sent_count = 0
                remaining_queue: list = []
                for outbound in outbound_queue:
                    to_addr = outbound.get("to_address", "") if isinstance(
                        outbound, dict
                    ) else getattr(outbound, "to_address", "")
                    subject = outbound.get("subject", "") if isinstance(
                        outbound, dict
                    ) else getattr(outbound, "subject", "")
                    body = outbound.get("body", "") if isinstance(
                        outbound, dict
                    ) else getattr(outbound, "body", "")
                    in_reply_to = outbound.get("in_reply_to", "") if isinstance(
                        outbound, dict
                    ) else getattr(outbound, "in_reply_to", "")

                    success = _module._smtp_client.send_reply(
                        to_address=to_addr,
                        subject=subject,
                        body=body,
                        in_reply_to=in_reply_to or None,
                    )
                    if success:
                        sent_count += 1
                    else:
                        remaining_queue.append(outbound)

                st.session_state.email_ingestion["outbound_queue"] = remaining_queue
                if sent_count > 0:
                    st.session_state.email_ingestion["outbound_sent"] = (
                        st.session_state.email_ingestion.get("outbound_sent", 0)
                        + sent_count
                    )

        # Rerun to refresh dashboard with new IoCs and conversation
        st.rerun()

    elif submitted and not raw_message.strip():
        st.warning("Please enter a message before submitting.")

    # Show last error if any
    last_error = st.session_state.get("last_error")
    if last_error:
        st.error(f"Last pipeline error: {last_error}")

with dashboard_col:
    # Render SOC Dashboard with current session state
    _dashboard.render(dict(st.session_state))

    # Render email ingestion panel if module is active
    if st.session_state.get("email_ingestion_module") is not None:
        st.divider()
        _dashboard.render_email_ingestion_panel(dict(st.session_state))
        _dashboard.render_classification_log(
            st.session_state.email_ingestion.get("classification_log", [])
        )
