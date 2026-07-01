"""Email Ingestion Module for automated IMAP polling and scam classification.

This module orchestrates the email ingestion pipeline: polls an IMAP mailbox
for unread emails, parses MIME content into EmailMessage models, classifies
them via the two-stage ScamClassifier, and routes confirmed scams into the
engagement pipeline. Runs as a background daemon thread within the monolithic
Streamlit process.
"""

import asyncio
import email
import logging
import re
import threading
import time
from email.utils import parseaddr
from typing import TYPE_CHECKING, Any

from models.email_models import (
    ClassificationResult,
    EmailMessage,
    OutboundEmail,
)

if TYPE_CHECKING:
    from components.imap_client import IMAPClient
    from components.scam_classifier import ScamClassifier
    from components.smtp_client import SMTPClient

logger = logging.getLogger(__name__)

# Bounds for polling interval in seconds
_MIN_POLLING_INTERVAL = 5
_MAX_POLLING_INTERVAL = 300

# Consecutive failure threshold for degraded warning
_DEGRADED_FAILURE_THRESHOLD = 3

# Capacity limits for pending results
_MAX_CLASSIFICATION_LOG = 200
_MAX_OUTBOUND_QUEUE = 100

# Default confused-elder response for blocked messages
_DEFAULT_BLOCKED_RESPONSE = (
    "Oh dear, I'm sorry, I don't quite understand what you're saying. "
    "Could you try saying that again in simpler words? My grandson Tommy "
    "says I need to be more careful about what I read on the computer. "
    "Anyway, what was it you needed help with?"
)


class EmailIngestionModule:
    """Background email ingestion with IMAP polling, parsing, and classification.

    Polls an IMAP mailbox at a configurable interval, parses raw MIME bytes
    into EmailMessage models, classifies each via ScamClassifier, and routes
    confirmed scams through the Safety Filter, Persona Engine, and Threat
    Parser pipeline. Tracks consecutive polling failures and sets a degraded
    warning flag after 3 consecutive failures.

    Since this runs in a background thread that cannot directly access
    st.session_state, pipeline results are buffered in _pending_results
    and flushed to session state during the Streamlit render cycle via
    flush_to_session_state().

    Attributes:
        polling_interval: Seconds between poll cycles (10-300).
        degraded: True when consecutive failures >= 3.
    """

    def __init__(
        self,
        imap_client: "IMAPClient",
        smtp_client: "SMTPClient",
        scam_classifier: "ScamClassifier",
        polling_interval: int = 30,
    ) -> None:
        """Initialize EmailIngestionModule with client dependencies.

        Args:
            imap_client: IMAPClient instance for fetching unread emails.
            smtp_client: SMTPClient instance for outbound delivery.
            scam_classifier: ScamClassifier instance for two-stage classification.
            polling_interval: Seconds between poll cycles. Must be between
                10 and 300 inclusive.

        Raises:
            ValueError: If polling_interval is outside [10, 300].
        """
        if not (_MIN_POLLING_INTERVAL <= polling_interval <= _MAX_POLLING_INTERVAL):
            raise ValueError(
                f"polling_interval must be between {_MIN_POLLING_INTERVAL} and "
                f"{_MAX_POLLING_INTERVAL}, got {polling_interval}"
            )

        self._imap_client = imap_client
        self._smtp_client = smtp_client
        self._scam_classifier = scam_classifier
        self.polling_interval = polling_interval

        # State tracking
        self._polling = False
        self._poll_thread: threading.Thread | None = None
        self._consecutive_failures = 0
        self.degraded = False

        # Thread-safe pending results buffer (Task 8.2)
        self._lock = threading.Lock()
        self._pending_results: list[dict[str, Any]] = []

        # Internal thread state for counters and threads (Task 8.3)
        self._total_fetched = 0
        self._total_scam = 0
        self._total_not_scam = 0
        self._outbound_sent = 0
        self._threads: dict[str, dict[str, Any]] = {}

    def start_polling(self) -> None:
        """Launch background daemon thread running the poll loop.

        If already polling, this is a no-op. The thread is set as a daemon
        so it won't prevent process exit.
        """
        if self._polling:
            logger.warning("Polling already active, ignoring start_polling call")
            return

        self._polling = True
        self._poll_thread = threading.Thread(
            target=self._poll_loop, name="email-ingestion-poll", daemon=True
        )
        self._poll_thread.start()
        logger.info(
            "Email ingestion polling started (interval=%ds)", self.polling_interval
        )

    def stop_polling(self) -> None:
        """Stop the polling loop and disconnect IMAP.

        Sets the polling flag to False, joins the thread with a timeout
        equal to polling_interval + 5s, then disconnects the IMAP client.
        """
        self._polling = False

        if self._poll_thread is not None and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=self.polling_interval + 5)
            if self._poll_thread.is_alive():
                logger.warning("Poll thread did not terminate within timeout")

        self._poll_thread = None
        self._imap_client.disconnect()
        logger.info("Email ingestion polling stopped")

    def flush_to_session_state(self, state_dict: dict[str, Any]) -> None:
        """Flush buffered pipeline results into the session state dict.

        Called from the main Streamlit thread during the render cycle to
        safely transfer background results into st.session_state.

        Args:
            state_dict: The email_ingestion sub-dict from st.session_state.
        """
        with self._lock:
            pending = self._pending_results[:]
            self._pending_results.clear()

        for result in pending:
            result_type = result.get("type")

            if result_type == "classification":
                log = state_dict.get("classification_log", [])
                log.append(result["data"])
                if len(log) > _MAX_CLASSIFICATION_LOG:
                    state_dict["classification_log"] = log[-_MAX_CLASSIFICATION_LOG:]
                else:
                    state_dict["classification_log"] = log

            elif result_type == "outbound":
                queue = state_dict.get("outbound_queue", [])
                if len(queue) < _MAX_OUTBOUND_QUEUE:
                    queue.append(result["data"])
                state_dict["outbound_queue"] = queue

            elif result_type == "thread_update":
                threads = state_dict.get("threads", {})
                sender = result["sender"]
                threads[sender] = result["data"]
                state_dict["threads"] = threads

            elif result_type == "iocs":
                # Stage extracted IoCs for merging into top-level state
                staged = state_dict.get("_staged_iocs", [])
                ioc_list = result.get("data", [])
                staged.extend(ioc_list)
                state_dict["_staged_iocs"] = staged

            elif result_type == "counters":
                state_dict["connection_status"] = result.get(
                    "connection_status", state_dict.get("connection_status", "disconnected")
                )
                state_dict["total_fetched"] = result.get(
                    "total_fetched", state_dict.get("total_fetched", 0)
                )
                state_dict["total_scam"] = result.get(
                    "total_scam", state_dict.get("total_scam", 0)
                )
                state_dict["total_not_scam"] = result.get(
                    "total_not_scam", state_dict.get("total_not_scam", 0)
                )
                state_dict["outbound_sent"] = result.get(
                    "outbound_sent", state_dict.get("outbound_sent", 0)
                )
                state_dict["consecutive_failures"] = self._consecutive_failures
                state_dict["degraded_warning"] = self.degraded

    def _parse_email(self, raw_bytes: bytes) -> EmailMessage | None:
        """Parse raw MIME bytes into an EmailMessage model.

        Extracts text/plain content preferentially. Falls back to text/html
        with HTML tag stripping via regex. Skips emails with neither content
        type available.

        Args:
            raw_bytes: Raw RFC822 email bytes from IMAP fetch.

        Returns:
            Parsed EmailMessage on success, None on parse failure or
            missing text content.
        """
        msg_id_for_logging = "<unknown>"
        try:
            msg = email.message_from_bytes(raw_bytes)
            msg_id_for_logging = msg.get("Message-ID", "<unknown>")

            # Extract sender
            _, sender_addr = parseaddr(msg.get("From", ""))
            if not sender_addr:
                logger.warning(
                    "Email %s has no valid sender address, skipping",
                    msg_id_for_logging,
                )
                return None

            subject = msg.get("Subject", "") or ""
            reply_to = msg.get("Reply-To", "") or ""
            date_header = msg.get("Date", "") or ""
            message_id = msg.get("Message-ID", "") or ""

            # Extract body: prefer text/plain, fallback to text/html stripped
            body = self._extract_body(msg)
            if not body or not body.strip():
                logger.warning(
                    "Email %s has no extractable text content, skipping",
                    msg_id_for_logging,
                )
                return None

            return EmailMessage(
                sender=sender_addr,
                subject=subject,
                body=body,
                message_id=message_id,
                reply_to=reply_to,
                date_header=date_header,
            )

        except Exception as e:
            logger.warning(
                "Failed to parse email (Message-ID: %s): %s", msg_id_for_logging, e
            )
            return None

    def _extract_body(self, msg: email.message.Message) -> str:
        """Extract text body from email message, preferring plain text.

        Args:
            msg: Parsed email.message.Message object.

        Returns:
            Extracted text content, or empty string if no text parts found.
        """
        text_plain = ""
        text_html = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                # Skip attachments
                if part.get("Content-Disposition", "").startswith("attachment"):
                    continue

                if content_type == "text/plain" and not text_plain:
                    raw_payload = part.get_payload(decode=True)
                    if isinstance(raw_payload, bytes):
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            text_plain = raw_payload.decode(
                                charset, errors="replace"
                            )
                        except (LookupError, UnicodeDecodeError):
                            text_plain = raw_payload.decode(
                                "utf-8", errors="replace"
                            )

                elif content_type == "text/html" and not text_html:
                    raw_payload = part.get_payload(decode=True)
                    if isinstance(raw_payload, bytes):
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            text_html = raw_payload.decode(
                                charset, errors="replace"
                            )
                        except (LookupError, UnicodeDecodeError):
                            text_html = raw_payload.decode(
                                "utf-8", errors="replace"
                            )
        else:
            content_type = msg.get_content_type()
            raw_payload = msg.get_payload(decode=True)
            if isinstance(raw_payload, bytes):
                charset = msg.get_content_charset() or "utf-8"
                try:
                    decoded = raw_payload.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    decoded = raw_payload.decode("utf-8", errors="replace")

                if content_type == "text/plain":
                    text_plain = decoded
                elif content_type == "text/html":
                    text_html = decoded

        # Prefer plain text; fallback to stripped HTML
        if text_plain:
            return text_plain
        if text_html:
            return self._strip_html_tags(text_html)
        return ""

    @staticmethod
    def _strip_html_tags(html: str) -> str:
        """Strip HTML tags from content using regex substitution.

        Args:
            html: Raw HTML string.

        Returns:
            Plain text with HTML tags removed.
        """
        # Remove script and style blocks entirely
        text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.DOTALL)
        # Remove all remaining tags
        text = re.sub(r"<[^>]+>", "", text)
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def _poll_loop(self) -> None:
        """Main polling loop running in background thread.

        Fetches unread emails, parses each, and processes them through
        classification. Handles IMAP connection loss by logging and
        attempting reconnection on the next interval. Tracks consecutive
        failures and sets degraded flag after 3.
        """
        while self._polling:
            try:
                # Ensure connection
                if not self._imap_client.is_connected:
                    logger.info("IMAP not connected, attempting reconnect")
                    self._imap_client.connect()
                    if not self._imap_client.is_connected:
                        raise ConnectionError("IMAP reconnection failed")

                raw_emails = self._imap_client.fetch_unread()

                for uid, raw_bytes in raw_emails:
                    email_msg = self._parse_email(raw_bytes)
                    if email_msg is not None:
                        self._total_fetched += 1
                        self.process_email(email_msg)
                    # Mark as read regardless (REQ 1.4 + REQ 1.6: even malformed get marked)
                    mark_ok = self._imap_client.mark_as_read(uid)
                    if not mark_ok:
                        logger.warning(
                            "Failed to mark UID %s as read; will re-fetch next cycle",
                            uid,
                        )

                # Success: reset failure counter and degraded flag
                self._consecutive_failures = 0
                self.degraded = False
                self._enqueue_counter_update()

            except Exception as e:
                self._consecutive_failures += 1
                logger.warning(
                    "Poll cycle failed (consecutive failures: %d): %s",
                    self._consecutive_failures,
                    e,
                )

                if self._consecutive_failures >= _DEGRADED_FAILURE_THRESHOLD:
                    self.degraded = True
                    logger.warning(
                        "Email ingestion degraded: %d consecutive failures",
                        self._consecutive_failures,
                    )

                self._enqueue_counter_update()

            # Sleep in small increments to allow responsive shutdown
            self._interruptible_sleep(self.polling_interval)

    def _interruptible_sleep(self, seconds: int) -> None:
        """Sleep for the given duration, checking _polling flag each second.

        Args:
            seconds: Total seconds to sleep.
        """
        for _ in range(seconds):
            if not self._polling:
                break
            time.sleep(1)

    def process_email(self, email_msg: EmailMessage) -> None:
        """Process a parsed email through classification and pipeline.

        Classifies the email via ScamClassifier. Scam verdicts are routed
        through the engagement pipeline (Safety Filter, Persona Engine,
        Threat Parser). Non-scam verdicts are logged at debug level.

        Args:
            email_msg: Parsed and validated EmailMessage to process.
        """
        try:
            result = self._scam_classifier.classify(email_msg)
            logger.info(
                "Classified email from %s: verdict=%s, confidence=%.2f, stage=%s",
                email_msg.sender,
                result.verdict,
                result.confidence,
                result.determining_stage,
            )

            if result.verdict == "scam":
                self._total_scam += 1
                self._feed_to_pipeline(email_msg, result)
            else:
                self._total_not_scam += 1
                logger.debug(
                    "Email from %s classified as not_scam, skipping pipeline",
                    email_msg.sender,
                )

            # Store classification in pending results
            self._enqueue_result("classification", result.model_dump())

        except Exception as e:
            logger.warning(
                "Failed to classify email from %s: %s", email_msg.sender, e
            )

    def _feed_to_pipeline(
        self, email_msg: EmailMessage, classification: ClassificationResult
    ) -> None:
        """Route a confirmed scam email through the engagement pipeline.

        Steps:
        1. Run Safety Filter scan on email body
        2. If blocked (>=80% injection tokens): call _handle_blocked_message
        3. Generate persona response with thread context
        4. Queue outbound response immediately after generation
        5. Extract IoCs via Threat Parser (best-effort, isolated)
        6. Update thread (best-effort, isolated)

        Args:
            email_msg: The confirmed scam email.
            classification: The ClassificationResult from the classifier.
        """
        from components.safety_filter import SafetyFilter
        from components.threat_parser import ThreatParser

        try:
            # Step 1: Safety Filter scan
            safety_filter = SafetyFilter()
            scan_result = safety_filter.scan(email_msg.body)

            # Step 2: Branch on blocked status
            if scan_result.is_blocked:
                self._handle_blocked_message(email_msg)
                return

            # Step 3: Generate persona response with thread context
            thread_history = self._get_thread_history(email_msg.sender)
            response_content = self._generate_persona_response(
                scan_result.sanitized_content, thread_history
            )

            # Add persona response to thread history
            if email_msg.sender in self._threads:
                self._threads[email_msg.sender].setdefault("messages", []).append(
                    {"sender": "persona", "content": response_content}
                )

            # Step 4: Queue outbound response immediately after generation
            outbound = OutboundEmail(
                to_address=email_msg.reply_to or email_msg.sender,
                subject=self._smtp_client.compose_reply_subject(email_msg.subject),
                body=response_content,
                in_reply_to=email_msg.message_id,
            )
            self._enqueue_result("outbound", outbound.model_dump())

            # Step 5: Extract IoCs via Threat Parser (best-effort)
            try:
                threat_parser = ThreatParser()
                extraction_result = self._run_extraction(
                    threat_parser, email_msg.body
                )

                if extraction_result and extraction_result.iocs:
                    logger.info(
                        "Extracted %d IoCs from scam email (sender=%s)",
                        len(extraction_result.iocs),
                        email_msg.sender,
                    )
                    # Enqueue IoCs for session state sync
                    ioc_data_list = [
                        ioc.model_dump() for ioc in extraction_result.iocs
                    ]
                    self._enqueue_result("iocs", ioc_data_list)
            except Exception as e:
                logger.warning(
                    "IoC extraction failed for email from %s: %s",
                    email_msg.sender,
                    e,
                )

            # Step 6: Update thread (best-effort)
            try:
                self._update_thread(email_msg)
            except Exception as e:
                logger.warning(
                    "Thread update failed for email from %s: %s",
                    email_msg.sender,
                    e,
                )

        except Exception as e:
            logger.warning(
                "Pipeline processing failed for email from %s: %s",
                email_msg.sender,
                e,
            )

    def _handle_blocked_message(self, email_msg: EmailMessage) -> None:
        """Handle an email that was fully blocked by the Safety Filter.

        Stores a default confused-elder response and still invokes
        Threat Parser for IoC extraction.

        Args:
            email_msg: The blocked email message.
        """
        from components.threat_parser import ThreatParser

        try:
            # Store default response as outbound
            outbound = OutboundEmail(
                to_address=email_msg.reply_to or email_msg.sender,
                subject=self._smtp_client.compose_reply_subject(email_msg.subject),
                body=_DEFAULT_BLOCKED_RESPONSE,
                in_reply_to=email_msg.message_id,
            )
            self._enqueue_result("outbound", outbound.model_dump())

            # Add default persona response to thread history
            if email_msg.sender in self._threads:
                self._threads[email_msg.sender].setdefault("messages", []).append(
                    {"sender": "persona", "content": _DEFAULT_BLOCKED_RESPONSE}
                )

            # Still extract IoCs from the blocked message
            threat_parser = ThreatParser()
            extraction_result = self._run_extraction(
                threat_parser, email_msg.body
            )

            if extraction_result and extraction_result.iocs:
                logger.info(
                    "Extracted %d IoCs from blocked email (sender=%s)",
                    len(extraction_result.iocs),
                    email_msg.sender,
                )
                # Enqueue IoCs for session state sync
                ioc_data_list = [
                    ioc.model_dump() for ioc in extraction_result.iocs
                ]
                self._enqueue_result("iocs", ioc_data_list)

            # Update thread even for blocked messages
            self._update_thread(email_msg)

        except Exception as e:
            logger.warning(
                "Blocked message handling failed for %s: %s",
                email_msg.sender,
                e,
            )

    def _generate_persona_response(
        self, sanitized_content: str, thread_history: list[dict[str, str]]
    ) -> str:
        """Generate a persona response using the PersonaEngine.

        Falls back to the default blocked response if PersonaEngine
        initialization or generation fails.

        Args:
            sanitized_content: The safety-filtered email body.
            thread_history: Previous messages in this thread for context.

        Returns:
            The generated or fallback response string.
        """
        from models.chat_models import ChatMessage

        try:
            from components.persona_engine import PersonaEngine

            persona = PersonaEngine(llm_client=None)

            # Build conversation history from thread
            history: list[ChatMessage] = []
            for entry in thread_history:
                history.append(ChatMessage(
                    sender=entry.get("sender", "scammer"),
                    content=entry.get("content", ""),
                ))

            response = persona.generate_response(sanitized_content, history)
            return response.content

        except Exception as e:
            logger.warning("Persona generation failed, using fallback: %s", e)
            return _DEFAULT_BLOCKED_RESPONSE

    def _run_extraction(self, threat_parser: Any, message_body: str) -> Any:
        """Run async IoC extraction in a new event loop.

        Args:
            threat_parser: ThreatParser instance.
            message_body: The raw email body to extract from.

        Returns:
            ExtractionResult or None on failure.
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(
                    threat_parser.extract_iocs(message_body)
                )
                return result
            finally:
                loop.close()
        except Exception as e:
            logger.warning("IoC extraction failed: %s", e)
            return None

    # --- Thread Management (Task 8.3) ---

    def _get_thread_history(self, sender: str) -> list[dict[str, str]]:
        """Get conversation history for a sender's thread.

        Args:
            sender: The sender email address.

        Returns:
            List of message dicts with 'sender' and 'content' keys.
        """
        thread = self._threads.get(sender)
        if thread is None:
            return []
        messages: list[dict[str, str]] = thread.get("messages", [])
        return messages

    def _update_thread(self, email_msg: EmailMessage) -> None:
        """Update or create a conversation thread for the sender.

        If the sender already has a thread, appends to it. Otherwise
        creates a new thread entry.

        Args:
            email_msg: The email message to add to the thread.
        """
        sender = email_msg.sender

        if sender not in self._threads:
            self._threads[sender] = {
                "sender_address": sender,
                "subject": email_msg.subject,
                "message_ids": [email_msg.message_id],
                "source_channel": "email",
                "message_count": 1,
                "messages": [
                    {"sender": "scammer", "content": email_msg.body}
                ],
            }
        else:
            thread = self._threads[sender]
            thread["message_count"] = thread.get("message_count", 0) + 1
            if email_msg.message_id:
                thread.setdefault("message_ids", []).append(
                    email_msg.message_id
                )
            thread.setdefault("messages", []).append(
                {"sender": "scammer", "content": email_msg.body}
            )

        # Enqueue thread update for session state sync
        thread_data = {
            "sender_address": sender,
            "subject": self._threads[sender].get("subject", ""),
            "message_ids": self._threads[sender].get("message_ids", []),
            "source_channel": "email",
            "message_count": self._threads[sender].get("message_count", 0),
        }
        self._enqueue_result("thread_update", thread_data, sender=sender)

    # --- Internal helpers ---

    def _enqueue_result(
        self, result_type: str, data: Any, sender: str | None = None
    ) -> None:
        """Thread-safe enqueue of a pipeline result.

        Args:
            result_type: One of 'classification', 'outbound', 'thread_update',
                'counters'.
            data: The serializable result data.
            sender: Sender address (required for thread_update type).
        """
        entry: dict[str, Any] = {"type": result_type, "data": data}
        if sender is not None:
            entry["sender"] = sender
        with self._lock:
            self._pending_results.append(entry)

    def _enqueue_counter_update(self) -> None:
        """Enqueue a counter snapshot for session state sync."""
        connection = "connected" if self._imap_client.is_connected else "disconnected"
        entry: dict[str, Any] = {
            "type": "counters",
            "data": None,
            "total_fetched": self._total_fetched,
            "total_scam": self._total_scam,
            "total_not_scam": self._total_not_scam,
            "outbound_sent": self._outbound_sent,
            "connection_status": connection,
        }
        with self._lock:
            self._pending_results.append(entry)
