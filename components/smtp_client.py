"""SMTP client component for outbound persona response delivery with rate limiting and retry logic."""

import logging
import smtplib
import time
from collections import deque
from datetime import datetime
from email.mime.text import MIMEText
from typing import Optional

from models.email_models import OutboundEmail

logger = logging.getLogger(__name__)


class SMTPClient:
    """SMTP connection wrapper with TLS, per-recipient rate limiting, and retry queue.

    Handles outbound email delivery for the RoadBlock honeypot pipeline,
    including threading headers (In-Reply-To, References), rate limiting
    per recipient, and a bounded retry queue with permanent failure tracking.
    """

    def __init__(
        self,
        host: str,
        port: int = 587,
        username: str = "",
        password: str = "",
        sender_address: str = "",
        timeout: float = 30.0,
        rate_limit_seconds: int = 60,
        max_queue_size: int = 100,
    ) -> None:
        """Initialize SMTP client with connection parameters and rate limiting config.

        Args:
            host: SMTP server hostname (from env: SMTP_HOST).
            port: SMTP server port (from env: SMTP_PORT, default 587).
            username: SMTP authentication username (from env: SMTP_USERNAME).
            password: SMTP authentication password (from env: SMTP_PASSWORD).
            sender_address: From address for outbound emails (from env: SMTP_SENDER).
            timeout: Connection timeout in seconds (default 30s).
            rate_limit_seconds: Per-recipient cooldown in seconds (default 60).
            max_queue_size: Maximum retry queue capacity (default 100).
        """
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._sender_address = sender_address
        self._timeout = timeout
        self._rate_limit_seconds = rate_limit_seconds
        self._max_queue_size = max_queue_size

        # Per-recipient last send timestamps for rate limiting
        self._last_send_times: dict[str, float] = {}

        # Retry queue: bounded deque of (OutboundEmail, consecutive_failure_count)
        self._retry_queue: deque[tuple[OutboundEmail, int]] = deque()

    @staticmethod
    def compose_reply_subject(original_subject: str) -> str:
        """Compose reply subject with "Re: " prefix, truncated to max 255 chars.

        Args:
            original_subject: The original email subject line.

        Returns:
            Reply subject string of at most 255 characters total.
        """
        prefix = "Re: "
        max_original_length = 255 - len(prefix)
        truncated = original_subject[:max_original_length]
        return prefix + truncated

    def _is_rate_limited(self, recipient: str) -> bool:
        """Check if a recipient is currently rate-limited.

        Args:
            recipient: The recipient email address.

        Returns:
            True if the recipient was sent to within the rate limit window.
        """
        last_sent = self._last_send_times.get(recipient)
        if last_sent is None:
            return False
        elapsed = time.time() - last_sent
        return elapsed < self._rate_limit_seconds

    def _record_send(self, recipient: str) -> None:
        """Record a successful send timestamp for rate limiting."""
        self._last_send_times[recipient] = time.time()

    def send_reply(
        self,
        to_address: str,
        subject: str,
        body: str,
        in_reply_to: Optional[str] = None,
        references: Optional[str] = None,
    ) -> bool:
        """Send a reply email with STARTTLS/TLS and threading headers.

        Composes and sends an email with proper In-Reply-To and References
        headers for thread continuity. Uses STARTTLS for transport encryption.

        Args:
            to_address: Recipient email address.
            subject: Already-composed reply subject (should be <= 255 chars).
            body: Plain-text email body content.
            in_reply_to: Original Message-ID for In-Reply-To header.
            references: Message-ID chain for References header.

        Returns:
            True if email was sent successfully, False otherwise.
        """
        try:
            msg = MIMEText(body, "plain", "utf-8")
            msg["From"] = self._sender_address
            msg["To"] = to_address
            msg["Subject"] = subject

            if in_reply_to:
                msg["In-Reply-To"] = in_reply_to
            if references:
                msg["References"] = references

            with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as server:
                server.starttls()
                if self._username and self._password:
                    server.login(self._username, self._password)
                server.sendmail(self._sender_address, [to_address], msg.as_string())

            self._record_send(to_address)
            logger.info(
                f"Successfully sent reply to {to_address}, "
                f"In-Reply-To: {in_reply_to or 'none'}"
            )
            return True

        except (smtplib.SMTPException, OSError, TimeoutError) as e:
            logger.warning(f"SMTP send failed for {to_address}: {e}")
            return False

    def queue_message(self, message: OutboundEmail) -> OutboundEmail:
        """Queue a message for deferred delivery.

        Adds message to the retry queue if capacity allows. If the queue
        is full (100 messages), rejects the message with "dropped_queue_full" status.

        Args:
            message: The OutboundEmail to queue.

        Returns:
            Updated OutboundEmail with status reflecting queue outcome:
            - "pending_retry" if queued successfully
            - "dropped_queue_full" if queue is at capacity
        """
        if len(self._retry_queue) >= self._max_queue_size:
            logger.warning(
                f"Outbound queue full ({self._max_queue_size}), "
                f"dropping message to {message.to_address}"
            )
            return message.model_copy(update={"status": "dropped_queue_full"})

        updated = message.model_copy(update={"status": "pending_retry"})
        self._retry_queue.append((updated, updated.retry_count))
        return updated

    def process_retry_queue(self) -> list[OutboundEmail]:
        """Process the retry queue, attempting delivery within rate limits.

        Iterates through queued messages and attempts to send those whose
        recipients are not rate-limited. Messages that fail 3 consecutive
        times are marked "failed_permanent" and removed from the queue.

        Returns:
            List of OutboundEmail objects with updated statuses reflecting
            delivery outcomes (sent, pending_retry, or failed_permanent).
        """
        results: list[OutboundEmail] = []
        remaining: deque[tuple[OutboundEmail, int]] = deque()

        while self._retry_queue:
            message, failure_count = self._retry_queue.popleft()

            # Skip rate-limited recipients, re-queue them
            if self._is_rate_limited(message.to_address):
                remaining.append((message, failure_count))
                continue

            # Attempt delivery
            success = self.send_reply(
                to_address=message.to_address,
                subject=message.subject,
                body=message.body,
                in_reply_to=message.in_reply_to or None,
                references=message.references or None,
            )

            now = datetime.utcnow()

            if success:
                updated = message.model_copy(
                    update={"status": "sent", "last_attempt_at": now}
                )
                results.append(updated)
            else:
                new_failure_count = failure_count + 1
                if new_failure_count >= 3:
                    updated = message.model_copy(
                        update={
                            "status": "failed_permanent",
                            "retry_count": new_failure_count,
                            "last_attempt_at": now,
                        }
                    )
                    results.append(updated)
                    logger.warning(
                        f"Message to {message.to_address} failed permanently "
                        f"after {new_failure_count} attempts"
                    )
                else:
                    updated = message.model_copy(
                        update={
                            "status": "pending_retry",
                            "retry_count": new_failure_count,
                            "last_attempt_at": now,
                        }
                    )
                    remaining.append((updated, new_failure_count))
                    results.append(updated)

        self._retry_queue = remaining
        return results

    @property
    def queue_size(self) -> int:
        """Current number of messages in the retry queue."""
        return len(self._retry_queue)

    @property
    def max_queue_size(self) -> int:
        """Maximum retry queue capacity."""
        return self._max_queue_size
