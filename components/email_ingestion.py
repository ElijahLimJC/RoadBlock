"""Email Ingestion Module for automated IMAP polling and scam classification.

This module orchestrates the email ingestion pipeline: polls an IMAP mailbox
for unread emails, parses MIME content into EmailMessage models, classifies
them via the two-stage ScamClassifier, and routes confirmed scams into the
engagement pipeline. Runs as a background daemon thread within the monolithic
Streamlit process.
"""

import email
import logging
import re
import threading
import time
from email.utils import parseaddr
from typing import TYPE_CHECKING

from models.email_models import EmailMessage

if TYPE_CHECKING:
    from components.imap_client import IMAPClient
    from components.scam_classifier import ScamClassifier
    from components.smtp_client import SMTPClient

logger = logging.getLogger(__name__)

# Bounds for polling interval in seconds
_MIN_POLLING_INTERVAL = 10
_MAX_POLLING_INTERVAL = 300

# Consecutive failure threshold for degraded warning
_DEGRADED_FAILURE_THRESHOLD = 3


class EmailIngestionModule:
    """Background email ingestion with IMAP polling, parsing, and classification.

    Polls an IMAP mailbox at a configurable interval, parses raw MIME bytes
    into EmailMessage models, classifies each via ScamClassifier, and logs
    results. Tracks consecutive polling failures and sets a degraded warning
    flag after 3 consecutive failures.

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

                for raw_bytes in raw_emails:
                    email_msg = self._parse_email(raw_bytes)
                    if email_msg is not None:
                        self.process_email(email_msg)

                # Success: reset failure counter and degraded flag
                self._consecutive_failures = 0
                self.degraded = False

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
        """Process a parsed email through classification.

        Placeholder for full pipeline integration (task 8.2). Currently
        classifies the email and logs the result.

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
        except Exception as e:
            logger.warning(
                "Failed to classify email from %s: %s", email_msg.sender, e
            )
