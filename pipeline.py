"""RoadBlock — Shared pipeline logic.

Contains all pipeline orchestration functions, state initialization,
and email ingestion setup. Imported by app.py and page scripts.

This module has NO Streamlit UI calls (no st.set_page_config, no st.markdown, etc.)
so it can be safely imported without triggering render-time side effects.
"""

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

import streamlit as st
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

from models import APP_TIMEZONE

from components.email_ingestion import EmailIngestionModule
from components.imap_client import IMAPClient
from components.virustotal_mcp import VirusTotalMCPClient
from components.notification_module import NotificationModule
from components.persona_engine import PersonaEngine
from components.safety_filter import SafetyFilter
from components.scam_classifier import ScamClassifier
from components.smtp_client import SMTPClient
from components.stalling_tracker import StallingTracker
from components.threat_parser import ThreatParser
from models.chat_models import ChatMessage, SessionMetrics
from models.email_models import ScamPattern

load_dotenv()

logger = logging.getLogger(__name__)

# --- Pipeline timeout (seconds), excluding parser stage ---
_PIPELINE_TIMEOUT_SECONDS = 15.0


class PipelineError(Exception):
    """Domain-specific error for pipeline stage failures."""

    def __init__(self, stage: str, message: str, original_error: Optional[Exception] = None):
        self.stage = stage
        self.message = message
        self.original_error = original_error
        super().__init__(f"[{stage}] {message}")


class PipelineResult(BaseModel):
    """Structured result from pipeline execution."""

    model_config = ConfigDict(frozen=True)

    success: bool = Field(
        description="Whether the pipeline completed without critical errors"
    )
    error: Optional[str] = Field(
        default=None, description="Error message if pipeline failed"
    )
    error_stage: Optional[str] = Field(
        default=None,
        description="Pipeline stage where error occurred",
    )
    response_content: str = Field(
        default="",
        description="Generated persona response content",
    )
    was_blocked: bool = Field(
        default=False,
        description="Whether the input was blocked by safety filter",
    )


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
        "vt_lookup_cache": {},
        "vt_server_status": "unknown",
        "known_ioc_count": 0,
        "new_ioc_count": 0,
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default

    if "threat_parser_instance" not in st.session_state:
        st.session_state["threat_parser_instance"] = ThreatParser()

    if "virustotal_client" not in st.session_state:
        vt_client = VirusTotalMCPClient()
        if vt_client.is_configured():
            st.session_state["virustotal_client"] = vt_client
            logger.info("VirusTotal MCP client initialized")
        else:
            st.session_state["virustotal_client"] = None
            logger.info("VirusTotal API key not configured, VT enrichment disabled")

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
    """Return a default list of common scam indicator patterns."""
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
    missing = [v for v in required_vars if not os.environ.get(v, "").strip()]
    if missing:
        logger.info(
            "Email ingestion disabled: missing env vars %s", ", ".join(missing)
        )
        return None

    imap_client = IMAPClient(
        host=os.environ["IMAP_HOST"].strip(),
        port=int(os.environ.get("IMAP_PORT", "993").strip()),
        username=os.environ.get("IMAP_USERNAME", "").strip(),
        password=os.environ.get("IMAP_PASSWORD", "").strip(),
    )

    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587").strip())
    smtp_username = os.environ.get("SMTP_USERNAME", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    smtp_sender = os.environ.get("SMTP_SENDER", "").strip()

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
    mistral_api_key = os.environ.get("MISTRAL_API_KEY", "")
    if mistral_api_key:
        try:
            import httpx
            from mistralai.client import Mistral

            ssl_verify = os.environ.get("ROADBLOCK_SSL_VERIFY", "true").lower() != "false"
            http_client = httpx.Client(verify=ssl_verify)
            llm_client = Mistral(api_key=mistral_api_key, client=http_client)
            logger.info("Stage 2 LLM classification enabled (Mistral)")
        except Exception as e:
            logger.warning("Failed to initialize Mistral LLM client: %s", e)
    else:
        logger.info(
            "MISTRAL_API_KEY not set; Stage 2 LLM disabled, "
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
        polling_interval=5,
    )

    st.session_state.email_ingestion_module = module
    module.start_polling()
    return module


def _get_default_blocked_response() -> str:
    """Generate a default confused-elder response for blocked messages.

    Used when the Safety Filter blocks a message (>=80% injection)
    so the Persona Engine is not invoked.
    """
    return (
        "Aiyoh sorry ah, I don't understand what you typing leh. Can you say "
        "again in simpler words? My grandson Jia Wei always tell me, 'Ah Ma, "
        "don't anyhow read things on the phone, later kena scam.' Anyway, "
        "what was it you want to ask me ah?"
    )


def process_scammer_message(
    raw_message: str,
    safety_filter: Optional[SafetyFilter] = None,
    persona_engine: Optional[PersonaEngine] = None,
    stalling_tracker: Optional[StallingTracker] = None,
    threat_parser: Optional[ThreatParser] = None,
    notification_module: Optional[NotificationModule] = None,
    virustotal_client: Optional[VirusTotalMCPClient] = None,
) -> PipelineResult:
    """Process a scammer message through the full RoadBlock pipeline.

    Sequential flow:
    1. Safety_Filter.scan(raw_message)
    2. Branch: blocked -> default response; safe/partial -> Persona_Engine
    3. Update Chat_State with message pair
    4. Stalling_Tracker.record_turn()
    5. Threat_Parser extraction (direct call, synchronous)
    6. On extraction complete: VirusTotal lookup -> notifications for NEW IoCs

    Args:
        raw_message: The raw scammer input text.
        safety_filter: SafetyFilter instance (created if None).
        persona_engine: PersonaEngine instance (created if None).
        stalling_tracker: StallingTracker instance (created if None).
        threat_parser: ThreatParser instance (uses session singleton if None).
        notification_module: NotificationModule instance (created if None).
        virustotal_client: VirusTotalMCPClient instance (optional, skips VT if None).
    """
    pipeline_start = time.time()

    # Initialize components with defaults if not provided
    if safety_filter is None:
        safety_filter = SafetyFilter()
    if stalling_tracker is None:
        stalling_tracker = StallingTracker()
    if threat_parser is None:
        threat_parser = st.session_state.get(
            "threat_parser_instance", ThreatParser()
        )
    if notification_module is None:
        notification_module = NotificationModule()
    if virustotal_client is None:
        virustotal_client = st.session_state.get("virustotal_client")

    # --- Stage 1: Safety Filter ---
    scan_result = None
    try:
        scan_result = safety_filter.scan(raw_message)
    except Exception as e:
        error = PipelineError("Safety_Filter", f"Scan failed: {e}", e)
        logger.error(str(error), exc_info=True)
        st.session_state["last_error"] = str(error)
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
            response_content = _get_default_blocked_response()

    # --- Stage 3: Update Chat_State with message pair ---
    try:
        scammer_msg = ChatMessage(
            sender="scammer",
            content=sanitized_message,
            timestamp=datetime.now(APP_TIMEZONE),
            was_sanitized=len(scan_result.detected_patterns) > 0,
            was_blocked=is_blocked,
        )
        persona_msg = ChatMessage(
            sender="persona",
            content=response_content,
            timestamp=datetime.now(APP_TIMEZONE),
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
        return PipelineResult(
            success=False,
            error=f"Pipeline timeout: synchronous stages took {elapsed:.1f}s",
            error_stage="timeout",
            response_content=response_content,
            was_blocked=is_blocked,
        )

    # --- Stage 5: Threat_Parser extraction + MCP lookup ---
    message_for_extraction = raw_message

    try:
        st.session_state["parser_status"] = "running"
        _run_extraction_pipeline(
            message_for_extraction,
            threat_parser,
            notification_module,
            st.session_state,
            virustotal_client,
        )
    except Exception as e:
        error = PipelineError("Threat_Parser", f"Extraction failed: {e}", e)
        logger.error(str(error), exc_info=True)
        st.session_state["parser_status"] = "error"
        st.session_state["last_error"] = str(error)

    return PipelineResult(
        success=True,
        response_content=response_content,
        was_blocked=is_blocked,
    )


def _run_extraction_pipeline(
    message: str,
    threat_parser: ThreatParser,
    notification_module: NotificationModule,
    state: Any = None,
    virustotal_client: Optional[VirusTotalMCPClient] = None,
) -> None:
    """Run the extraction pipeline.

    Executes:
    1. ThreatParser.extract_iocs(message)
    2. VirusTotal MCP enrichment for each extracted IoC
    3. Generate notifications for NEW IoCs only
    4. Update Chat_State with results

    Args:
        message: The raw message to extract IoCs from.
        threat_parser: ThreatParser instance.
        notification_module: NotificationModule for generating alerts.
        state: Session state reference.
        virustotal_client: Optional VirusTotal MCP client for enrichment.
    """
    if state is None:
        try:
            state = st.session_state
        except Exception:
            logger.warning("No session state available in background thread")
            return

    try:
        extraction_result = threat_parser.extract_iocs(message)

        if extraction_result.rejections:
            state["rejection_log"].extend(extraction_result.rejections)

        if not extraction_result.iocs:
            state["parser_status"] = "idle"
            return

        # --- VirusTotal MCP enrichment ---
        cache = state.get("vt_lookup_cache", {})
        vt_results = []

        logger.info(
            "Extraction found %d IoCs, VT client configured: %s",
            len(extraction_result.iocs),
            virustotal_client is not None
            and virustotal_client.is_configured()
            if virustotal_client
            else False,
        )

        if virustotal_client is not None and virustotal_client.is_configured():
            try:
                # Windows requires ProactorEventLoop for subprocess spawning
                import sys
                if sys.platform == "win32":
                    asyncio.set_event_loop_policy(
                        asyncio.WindowsProactorEventLoopPolicy()
                    )
                vt_loop = asyncio.new_event_loop()
                try:
                    vt_results = vt_loop.run_until_complete(
                        asyncio.wait_for(
                            virustotal_client.batch_lookup(
                                extraction_result.iocs, cache
                            ),
                            timeout=60.0,
                        )
                    )
                finally:
                    vt_loop.close()
                state["vt_lookup_cache"] = cache
                state["vt_server_status"] = "connected"
            except asyncio.TimeoutError:
                logger.warning("VirusTotal batch lookup timed out after 60s")
                state["vt_server_status"] = "timeout"
            except Exception as e:
                logger.warning("VirusTotal batch lookup failed: %s", e)
                state["vt_server_status"] = "error"

        # --- Store IoCs and generate notifications for NEW ones ---
        for i, ioc in enumerate(extraction_result.iocs):
            is_known = False
            if i < len(vt_results):
                is_known = vt_results[i].is_known

            # Store IoC (deduplicates by extracted_value)
            was_stored = _store_ioc(ioc, state)

            if not was_stored:
                # Duplicate IoC — count as known (already seen)
                state["known_ioc_count"] = (
                    state.get("known_ioc_count", 0) + 1
                )
            elif is_known:
                # MCP confirmed as known threat intel
                state["known_ioc_count"] = (
                    state.get("known_ioc_count", 0) + 1
                )
            else:
                # New IoC — first time seen
                state["new_ioc_count"] = (
                    state.get("new_ioc_count", 0) + 1
                )

            # Generate notification only for genuinely new IoCs
            if was_stored and not is_known:
                try:
                    notification = notification_module.generate_notification(ioc)
                    state["notifications"].append(notification)
                except Exception as e:
                    logger.warning(
                        "Notification generation failed for IoC %s: %s",
                        ioc.extracted_value,
                        e,
                    )

        state["parser_status"] = "idle"

    except Exception as e:
        logger.error("Extraction pipeline failed: %s", e, exc_info=True)
        state["parser_status"] = "error"
        state["last_error"] = f"Extraction error: {e}"


def _store_ioc(ioc, state=None) -> bool:
    """Store an extracted IoC in the appropriate session state category list.

    Deduplicates by extracted_value — if the same IoC value already exists
    in the category list, it is not added again.

    Args:
        ioc: A BaseIoC subclass instance to store.
        state: Session state reference (uses st.session_state if None).

    Returns:
        True if the IoC was new and stored, False if it was a duplicate.
    """
    from models.ioc_models import IoCCategory

    if state is None:
        state = st.session_state

    iocs = state.get("iocs", {})

    # Determine the target list
    if ioc.category == IoCCategory.CRYPTOCURRENCY_WALLET:
        target_list = iocs.setdefault("cryptocurrency_wallets", [])
    elif ioc.category == IoCCategory.PHISHING_DOMAIN:
        target_list = iocs.setdefault("phishing_domains", [])
    elif ioc.category == IoCCategory.PHONE_NUMBER:
        target_list = iocs.setdefault("phone_numbers", [])
    elif ioc.category == IoCCategory.MULE_BANK_ACCOUNT:
        target_list = iocs.setdefault("mule_bank_accounts", [])
    else:
        state["iocs"] = iocs
        return False

    # Check for duplicates by extracted_value
    ioc_value = getattr(ioc, "extracted_value", None)
    if ioc_value is not None:
        existing_values = set()
        for existing in target_list:
            if isinstance(existing, dict):
                existing_values.add(existing.get("extracted_value"))
            else:
                existing_values.add(getattr(existing, "extracted_value", None))
        if ioc_value in existing_values:
            # Duplicate — don't store
            state["iocs"] = iocs
            return False

    target_list.append(ioc)
    state["iocs"] = iocs
    return True


def flush_email_ingestion_state() -> None:
    """Flush email ingestion results into session state.

    Called each render cycle to merge background thread results (IoCs,
    messages, outbound queue) into the main session state. Also handles
    SMTP delivery for pending outbound emails.
    """
    if st.session_state.get("email_ingestion_module") is None:
        return

    _email_module = st.session_state.email_ingestion_module
    _email_module.flush_to_session_state(st.session_state.email_ingestion)

    # Merge staged IoCs from email ingestion into top-level iocs state
    _staged_iocs = st.session_state.email_ingestion.pop("_staged_iocs", [])
    if _staged_iocs:
        _iocs_state = st.session_state.get("iocs", {})
        _new_count = 0
        _known_count = 0
        _notif_module = NotificationModule()
        for _ioc_data in _staged_iocs:
            _cat = _ioc_data.get("category", "")
            _value = _ioc_data.get("extracted_value")

            # Determine target list
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

            # Dedup by extracted_value
            _existing = {
                (d.get("extracted_value") if isinstance(d, dict)
                 else getattr(d, "extracted_value", None))
                for d in _target
            }
            if _value in _existing:
                _known_count += 1
            else:
                _target.append(_ioc_data)
                _new_count += 1

                # Generate GuardDuty/WAF notification for new IoCs
                try:
                    from models.ioc_models import ioc_from_dict
                    _ioc_obj = ioc_from_dict(_ioc_data)
                    if _ioc_obj is not None:
                        _notification = _notif_module.generate_notification(_ioc_obj)
                        st.session_state["notifications"].append(_notification)
                except Exception as _e:
                    logger.warning(
                        "Notification generation failed for email IoC %s: %s",
                        _value,
                        _e,
                    )

        st.session_state["iocs"] = _iocs_state
        if _new_count > 0:
            st.session_state["new_ioc_count"] = (
                st.session_state.get("new_ioc_count", 0) + _new_count
            )
        if _known_count > 0:
            st.session_state["known_ioc_count"] = (
                st.session_state.get("known_ioc_count", 0) + _known_count
            )

    # Merge staged conversation messages into top-level conversation_history
    _staged_msgs = st.session_state.email_ingestion.pop("_staged_messages", [])
    if _staged_msgs:
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

    # Use module's internal state for connection status
    if _email_module._polling and _email_module._consecutive_failures == 0:
        st.session_state.email_ingestion["connection_status"] = "connected"
    elif _email_module._consecutive_failures >= 3:
        st.session_state.email_ingestion["connection_status"] = "disconnected"

    # Send any pending outbound emails via SMTP
    _outbound_queue = st.session_state.email_ingestion.get("outbound_queue", [])
    _sent_indices: list[int] = []
    for _idx, _outbound in enumerate(_outbound_queue):
        if isinstance(_outbound, dict) and _outbound.get("status") in (
            "pending", "pending_retry"
        ):
            _success = _email_module._smtp_client.send_reply(
                to_address=_outbound.get("to_address", ""),
                subject=_outbound.get("subject", ""),
                body=_outbound.get("body", ""),
                in_reply_to=_outbound.get("in_reply_to") or None,
                references=_outbound.get("references") or None,
            )
            if _success:
                _outbound["status"] = "sent"
                st.session_state.email_ingestion["outbound_sent"] = (
                    st.session_state.email_ingestion.get("outbound_sent", 0) + 1
                )
                _sent_indices.append(_idx)
            else:
                _outbound["retry_count"] = _outbound.get("retry_count", 0) + 1
                if _outbound["retry_count"] >= 3:
                    _outbound["status"] = "failed_permanent"
                    _sent_indices.append(_idx)
                else:
                    _outbound["status"] = "pending_retry"

    # Remove sent/failed messages from queue
    for _idx in sorted(_sent_indices, reverse=True):
        _outbound_queue.pop(_idx)
    st.session_state.email_ingestion["outbound_queue"] = _outbound_queue

    _email_module._smtp_client.process_retry_queue()
