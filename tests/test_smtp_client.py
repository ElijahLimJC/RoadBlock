"""Tests for SMTPClient: property-based subject invariant and unit tests.

Validates requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.8
"""

from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from components.smtp_client import SMTPClient
from models.email_models import OutboundEmail

# ---------------------------------------------------------------------------
# Task 6.2 - Property 10: Outbound subject line length invariant
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(subject=st.text(min_size=0, max_size=1500))
def test_compose_reply_subject_never_exceeds_255_chars(subject: str) -> None:
    """Property: compose_reply_subject output never exceeds 255 characters.

    Validates: Requirement 5.1
    """
    result = SMTPClient.compose_reply_subject(subject)
    assert len(result) <= 255


# ---------------------------------------------------------------------------
# Task 6.3 - Unit tests for SMTP_Client
# ---------------------------------------------------------------------------


@pytest.fixture
def smtp_client() -> SMTPClient:
    """Create an SMTPClient instance with default test settings."""
    return SMTPClient(
        host="smtp.test.local",
        port=587,
        username="testuser",
        password="testpass",
        sender_address="honeypot@test.local",
        rate_limit_seconds=60,
        max_queue_size=100,
    )


class TestSendReplyWithThreadingHeaders:
    """Test successful send with threading headers (In-Reply-To, References).

    Validates: Requirement 5.2
    """

    @patch("components.smtp_client.smtplib.SMTP")
    def test_successful_send_with_threading_headers(
        self, mock_smtp_class: MagicMock, smtp_client: SMTPClient
    ) -> None:
        """Verify send_reply sets In-Reply-To and References headers correctly."""
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        result = smtp_client.send_reply(
            to_address="scammer@evil.com",
            subject="Re: You won a prize",
            body="Oh dear, what prize?",
            in_reply_to="<original-msg-id@evil.com>",
            references="<original-msg-id@evil.com>",
        )

        assert result is True
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("testuser", "testpass")
        mock_server.sendmail.assert_called_once()

        # Verify the message content includes threading headers
        call_args = mock_server.sendmail.call_args
        msg_string = call_args[0][2]
        assert "In-Reply-To: <original-msg-id@evil.com>" in msg_string
        assert "References: <original-msg-id@evil.com>" in msg_string


class TestRateLimiting:
    """Test rate limiting enforcement.

    Validates: Requirement 5.3
    """

    @patch("components.smtp_client.smtplib.SMTP")
    def test_second_send_within_window_is_blocked(
        self, mock_smtp_class: MagicMock, smtp_client: SMTPClient
    ) -> None:
        """Second send to same recipient within rate limit window is blocked."""
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        # First send succeeds
        result1 = smtp_client.send_reply(
            to_address="scammer@evil.com",
            subject="Re: Hello",
            body="First reply",
        )
        assert result1 is True

        # Verify rate limiting is active
        assert smtp_client._is_rate_limited("scammer@evil.com") is True

        # Queue a message for the same recipient, then process retry queue
        msg = OutboundEmail(
            to_address="scammer@evil.com",
            subject="Re: Hello again",
            body="Second reply",
        )
        queued = smtp_client.queue_message(msg)
        assert queued.status == "pending_retry"

        # Process retry queue - message should stay queued due to rate limit
        smtp_client.process_retry_queue()
        # Message remains in queue (rate limited), not delivered
        assert smtp_client.queue_size == 1


class TestQueueSaturation:
    """Test queue saturation at 100 messages (101st rejected).

    Validates: Requirement 5.4
    """

    def test_101st_message_rejected_with_dropped_queue_full(
        self, smtp_client: SMTPClient
    ) -> None:
        """101st message is rejected with 'dropped_queue_full' status."""
        # Fill the queue to capacity (100)
        for i in range(100):
            msg = OutboundEmail(
                to_address=f"scammer{i}@evil.com",
                subject=f"Re: Msg {i}",
                body=f"Body {i}",
            )
            result = smtp_client.queue_message(msg)
            assert result.status == "pending_retry"

        assert smtp_client.queue_size == 100

        # 101st message should be rejected
        overflow_msg = OutboundEmail(
            to_address="overflow@evil.com",
            subject="Re: Overflow",
            body="This should be dropped",
        )
        result = smtp_client.queue_message(overflow_msg)
        assert result.status == "dropped_queue_full"
        assert smtp_client.queue_size == 100


class TestRetryLogicAndPermanentFailure:
    """Test retry logic and permanent failure after 3 attempts.

    Validates: Requirement 5.5
    """

    @patch("components.smtp_client.smtplib.SMTP")
    def test_permanent_failure_after_3_attempts(
        self, mock_smtp_class: MagicMock, smtp_client: SMTPClient
    ) -> None:
        """Message fails permanently after 3 consecutive failed attempts."""
        # Make SMTP always fail
        mock_smtp_class.return_value.__enter__ = MagicMock(
            side_effect=Exception("Connection refused")
        )
        mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

        # Override to make send_reply always fail
        smtp_client.send_reply = MagicMock(return_value=False)  # type: ignore[method-assign]

        msg = OutboundEmail(
            to_address="scammer@evil.com",
            subject="Re: Test",
            body="Retry test",
        )

        # Queue the message
        queued = smtp_client.queue_message(msg)
        assert queued.status == "pending_retry"

        # Process retry queue 3 times - each time should fail
        for attempt in range(3):
            results = smtp_client.process_retry_queue()
            assert len(results) >= 1

        # After 3 failures, the message should be marked permanent failure
        # Reset: queue a message with retry_count already at 2 (simulate 2 prior failures)
        smtp_client._retry_queue.clear()
        msg_with_retries = OutboundEmail(
            to_address="scammer@evil.com",
            subject="Re: Test",
            body="Retry test",
            retry_count=2,
        )
        smtp_client._retry_queue.append((msg_with_retries, 2))

        results = smtp_client.process_retry_queue()
        assert len(results) == 1
        assert results[0].status == "failed_permanent"
        assert results[0].retry_count == 3


class TestConnectionFailureHandling:
    """Test connection failure handling.

    Validates: Requirement 5.6
    """

    @patch("components.smtp_client.smtplib.SMTP")
    def test_connection_failure_returns_false_and_logs_warning(
        self, mock_smtp_class: MagicMock, smtp_client: SMTPClient
    ) -> None:
        """Connection failure returns False and logs warning."""
        mock_smtp_class.side_effect = OSError("Connection refused")

        with patch("components.smtp_client.logger") as mock_logger:
            result = smtp_client.send_reply(
                to_address="scammer@evil.com",
                subject="Re: Test",
                body="Connection test",
            )

            assert result is False
            mock_logger.warning.assert_called_once()
            assert "scammer@evil.com" in mock_logger.warning.call_args[0][0]


class TestComposeReplySubjectTruncation:
    """Test compose_reply_subject truncation at boundary.

    Validates: Requirement 5.1
    """

    def test_subject_exactly_at_boundary(self) -> None:
        """Subject of exactly 251 chars (+ 'Re: ' = 255) is not truncated."""
        subject = "A" * 251
        result = SMTPClient.compose_reply_subject(subject)
        assert result == "Re: " + "A" * 251
        assert len(result) == 255

    def test_subject_exceeding_boundary_is_truncated(self) -> None:
        """Subject exceeding 251 chars is truncated to fit within 255 total."""
        subject = "B" * 300
        result = SMTPClient.compose_reply_subject(subject)
        assert len(result) == 255
        assert result.startswith("Re: ")
        assert result == "Re: " + "B" * 251

    def test_empty_subject(self) -> None:
        """Empty subject produces just 'Re: '."""
        result = SMTPClient.compose_reply_subject("")
        assert result == "Re: "
        assert len(result) == 4

    def test_short_subject_unchanged(self) -> None:
        """Short subject is prefixed with 'Re: ' without truncation."""
        result = SMTPClient.compose_reply_subject("Hello")
        assert result == "Re: Hello"
        assert len(result) == 9
