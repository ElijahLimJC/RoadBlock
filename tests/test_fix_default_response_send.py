"""Property-based tests for fix: default response send bug.

Property 1: Bug Condition - Outbound Email Lost When Downstream Steps Throw.

When _run_extraction or _update_thread raises an exception after persona response
generation, the outbound email MUST still be enqueued. On unfixed code, the outer
try/except in _feed_to_pipeline catches the exception and returns before reaching
the outbound enqueue at Step 6, silently dropping the reply.

This test MUST FAIL on unfixed code - failure confirms the bug exists.
"""

import asyncio
from unittest.mock import MagicMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from components.email_ingestion import EmailIngestionModule
from models.chat_models import ScanResult
from models.email_models import ClassificationResult, EmailMessage

# --- Strategies ---

_email_local = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=20,
)
_email_domain = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=10,
)

email_address_strategy = st.builds(
    lambda local, domain: f"{local}@{domain}.com",
    local=_email_local,
    domain=_email_domain,
)

email_body_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")),
    min_size=1,
    max_size=300,
).filter(lambda s: len(s.strip()) > 0)

email_subject_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")),
    min_size=0,
    max_size=100,
)

# Exception types that downstream steps may raise
exception_type_strategy = st.sampled_from(
    [RuntimeError, KeyError, asyncio.TimeoutError, ValueError]
)

# Failure point: which downstream step(s) throw
failure_point_strategy = st.sampled_from(
    ["extraction_only", "thread_only", "both"]
)


def _make_module() -> EmailIngestionModule:
    """Create an EmailIngestionModule with mocked dependencies."""
    imap_client = MagicMock()
    smtp_client = MagicMock()
    smtp_client.compose_reply_subject = MagicMock(
        side_effect=lambda subj: f"Re: {subj}"
    )
    scam_classifier = MagicMock()
    return EmailIngestionModule(
        imap_client=imap_client,
        smtp_client=smtp_client,
        scam_classifier=scam_classifier,
        polling_interval=10,
    )


class TestOutboundEnqueuedDespiteDownstreamFailure:
    """Property 1: Bug Condition - Outbound Email Lost When Downstream Steps Throw.

    CRITICAL: This test MUST FAIL on unfixed code.

    For any email processed through _feed_to_pipeline where the safety filter
    does not block and persona response generation succeeds, the outbound email
    SHALL be enqueued regardless of whether _run_extraction or _update_thread
    succeeds or fails.

    Validates: Requirements 1.1, 1.2, 1.3
    """

    @given(
        sender=email_address_strategy,
        subject=email_subject_strategy,
        body=email_body_strategy,
        exc_type=exception_type_strategy,
        failure_point=failure_point_strategy,
    )
    @settings(max_examples=200)
    def test_outbound_enqueued_despite_downstream_failure(
        self,
        sender: str,
        subject: str,
        body: str,
        exc_type: type,
        failure_point: str,
    ) -> None:
        """Outbound email is enqueued even when _run_extraction or _update_thread throws.

        On UNFIXED code this test FAILS because _enqueue_result("outbound", ...)
        is never called when the outer try/except catches a downstream exception.
        """
        module = _make_module()

        # Construct valid EmailMessage
        email_msg = EmailMessage(
            sender=sender,
            subject=subject,
            body=body,
            message_id=f"<test-{id(body)}@test.local>",
        )

        # Construct valid ClassificationResult with verdict="scam"
        classification = ClassificationResult(
            verdict="scam",
            confidence=0.95,
            determining_stage="stage_1",
            sender=sender,
            subject=subject,
        )

        # Known response string from persona engine
        known_response = "Oh my, that sounds very confusing dear."

        # Non-blocked ScanResult
        non_blocked_scan = ScanResult(
            sanitized_content=body,
            detected_patterns=[],
            is_blocked=False,
        )

        # Determine which downstream steps throw
        extraction_raises = failure_point in ("extraction_only", "both")
        thread_raises = failure_point in ("thread_only", "both")

        def mock_run_extraction(threat_parser: object, message_body: str) -> None:
            if extraction_raises:
                raise exc_type("simulated extraction failure")
            return None

        def mock_update_thread(email_msg_arg: object) -> None:
            if thread_raises:
                raise exc_type("simulated thread update failure")

        with (
            patch(
                "components.safety_filter.SafetyFilter"
            ) as mock_sf_class,
            patch.object(
                module,
                "_generate_persona_response",
                return_value=known_response,
            ),
            patch.object(
                module,
                "_run_extraction",
                side_effect=mock_run_extraction,
            ),
            patch.object(
                module,
                "_update_thread",
                side_effect=mock_update_thread,
            ),
            patch.object(
                module,
                "_enqueue_result",
                wraps=module._enqueue_result,
            ) as mock_enqueue,
        ):
            # Configure SafetyFilter.scan to return non-blocked result
            mock_sf_instance = MagicMock()
            mock_sf_instance.scan.return_value = non_blocked_scan
            mock_sf_class.return_value = mock_sf_instance

            # Execute the pipeline
            module._feed_to_pipeline(email_msg, classification)

        # Assert: _enqueue_result was called with type "outbound" and body
        # matching the known response
        outbound_calls = [
            c for c in mock_enqueue.call_args_list
            if c[0][0] == "outbound"
        ]

        assert len(outbound_calls) >= 1, (
            f"Expected _enqueue_result to be called with type 'outbound' "
            f"but it was not. failure_point={failure_point}, "
            f"exc_type={exc_type.__name__}. "
            f"All calls: {mock_enqueue.call_args_list}"
        )

        # Verify the outbound body matches the known response
        outbound_data = outbound_calls[0][0][1]  # Second positional arg is data dict
        assert outbound_data["body"] == known_response, (
            f"Expected outbound body to be '{known_response}' "
            f"but got '{outbound_data.get('body')}'"
        )


class TestPreservationProperties:
    """Property 2: Preservation - Happy Path and Blocked Path Behavior Unchanged.

    These tests verify existing behavior on UNFIXED code to establish baseline.
    They MUST PASS on the current code.

    Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5
    """

    @given(
        sender=email_address_strategy,
        subject=email_subject_strategy,
        body=email_body_strategy,
        response_content=email_body_strategy,
    )
    @settings(max_examples=200)
    def test_happy_path_outbound_content_matches_response(
        self,
        sender: str,
        subject: str,
        body: str,
        response_content: str,
    ) -> None:
        """Property 2a: On happy path (no exceptions), outbound body matches persona response.

        For all inputs where safety filter does not block AND no exceptions are raised:
        - _enqueue_result is called with type "outbound" and body == generated response
        - _run_extraction is called
        - _update_thread is called
        """
        module = _make_module()

        email_msg = EmailMessage(
            sender=sender,
            subject=subject,
            body=body,
            message_id=f"<msg-{id(body)}@test.local>",
        )

        classification = ClassificationResult(
            verdict="scam",
            confidence=0.92,
            determining_stage="stage_1",
            sender=sender,
            subject=subject,
        )

        non_blocked_scan = ScanResult(
            sanitized_content=body,
            detected_patterns=[],
            is_blocked=False,
        )

        with (
            patch(
                "components.safety_filter.SafetyFilter"
            ) as mock_sf_class,
            patch.object(
                module,
                "_generate_persona_response",
                return_value=response_content,
            ),
            patch.object(
                module,
                "_run_extraction",
                return_value=None,
            ) as mock_extraction,
            patch.object(
                module,
                "_update_thread",
            ) as mock_update_thread,
            patch.object(
                module,
                "_enqueue_result",
                wraps=module._enqueue_result,
            ) as mock_enqueue,
        ):
            mock_sf_instance = MagicMock()
            mock_sf_instance.scan.return_value = non_blocked_scan
            mock_sf_class.return_value = mock_sf_instance

            module._feed_to_pipeline(email_msg, classification)

        # Assert: outbound enqueued with body == response_content
        outbound_calls = [
            c for c in mock_enqueue.call_args_list
            if c[0][0] == "outbound"
        ]
        assert len(outbound_calls) == 1, (
            f"Expected exactly 1 outbound enqueue call, got {len(outbound_calls)}"
        )
        outbound_data = outbound_calls[0][0][1]
        assert outbound_data["body"] == response_content, (
            f"Outbound body mismatch: expected '{response_content}', "
            f"got '{outbound_data.get('body')}'"
        )

        # Assert: _run_extraction was called
        mock_extraction.assert_called_once()

        # Assert: _update_thread was called
        mock_update_thread.assert_called_once()

    @given(
        sender=email_address_strategy,
        subject=email_subject_strategy,
        body=email_body_strategy,
    )
    @settings(max_examples=200)
    def test_blocked_path_uses_default_response(
        self,
        sender: str,
        subject: str,
        body: str,
    ) -> None:
        """Property 2b: When safety filter blocks, _handle_blocked_message is called.

        For all inputs where safety filter returns is_blocked=True:
        - _handle_blocked_message is called
        - The outbound body == _DEFAULT_BLOCKED_RESPONSE
        """
        from components.email_ingestion import _DEFAULT_BLOCKED_RESPONSE

        module = _make_module()

        email_msg = EmailMessage(
            sender=sender,
            subject=subject,
            body=body,
            message_id=f"<msg-{id(body)}@test.local>",
        )

        classification = ClassificationResult(
            verdict="scam",
            confidence=0.90,
            determining_stage="stage_2",
            sender=sender,
            subject=subject,
        )

        blocked_scan = ScanResult(
            sanitized_content="",
            detected_patterns=["injection_detected"],
            is_blocked=True,
        )

        with (
            patch(
                "components.safety_filter.SafetyFilter"
            ) as mock_sf_class,
            patch.object(
                module,
                "_handle_blocked_message",
                wraps=module._handle_blocked_message,
            ) as mock_handle_blocked,
            patch.object(
                module,
                "_run_extraction",
                return_value=None,
            ),
            patch.object(
                module,
                "_update_thread",
            ),
            patch.object(
                module,
                "_enqueue_result",
                wraps=module._enqueue_result,
            ) as mock_enqueue,
        ):
            mock_sf_instance = MagicMock()
            mock_sf_instance.scan.return_value = blocked_scan
            mock_sf_class.return_value = mock_sf_instance

            module._feed_to_pipeline(email_msg, classification)

        # Assert: _handle_blocked_message was called
        mock_handle_blocked.assert_called_once_with(email_msg)

        # Assert: outbound enqueued with body == _DEFAULT_BLOCKED_RESPONSE
        outbound_calls = [
            c for c in mock_enqueue.call_args_list
            if c[0][0] == "outbound"
        ]
        assert len(outbound_calls) == 1, (
            f"Expected exactly 1 outbound enqueue call on blocked path, "
            f"got {len(outbound_calls)}"
        )
        outbound_data = outbound_calls[0][0][1]
        assert outbound_data["body"] == _DEFAULT_BLOCKED_RESPONSE, (
            f"Blocked outbound body mismatch: expected default blocked response, "
            f"got '{outbound_data.get('body')}'"
        )

    @given(
        sender=email_address_strategy,
        subject=email_subject_strategy,
        body=email_body_strategy,
        response_content=email_body_strategy,
        reply_to=st.one_of(st.just(""), email_address_strategy),
    )
    @settings(max_examples=200)
    def test_outbound_fields_integrity(
        self,
        sender: str,
        subject: str,
        body: str,
        response_content: str,
        reply_to: str,
    ) -> None:
        """Property 2c: Outbound email has correct to_address, subject, and in_reply_to.

        The outbound email has:
        - Correct to_address (reply_to if present, else sender)
        - Correct subject (composed via smtp_client.compose_reply_subject)
        - Correct in_reply_to (message_id)
        """
        module = _make_module()

        message_id = f"<integrity-{id(body)}@test.local>"

        email_msg = EmailMessage(
            sender=sender,
            subject=subject,
            body=body,
            message_id=message_id,
            reply_to=reply_to,
        )

        classification = ClassificationResult(
            verdict="scam",
            confidence=0.88,
            determining_stage="stage_1",
            sender=sender,
            subject=subject,
        )

        non_blocked_scan = ScanResult(
            sanitized_content=body,
            detected_patterns=[],
            is_blocked=False,
        )

        with (
            patch(
                "components.safety_filter.SafetyFilter"
            ) as mock_sf_class,
            patch.object(
                module,
                "_generate_persona_response",
                return_value=response_content,
            ),
            patch.object(
                module,
                "_run_extraction",
                return_value=None,
            ),
            patch.object(
                module,
                "_update_thread",
            ),
            patch.object(
                module,
                "_enqueue_result",
                wraps=module._enqueue_result,
            ) as mock_enqueue,
        ):
            mock_sf_instance = MagicMock()
            mock_sf_instance.scan.return_value = non_blocked_scan
            mock_sf_class.return_value = mock_sf_instance

            module._feed_to_pipeline(email_msg, classification)

        # Retrieve the outbound call
        outbound_calls = [
            c for c in mock_enqueue.call_args_list
            if c[0][0] == "outbound"
        ]
        assert len(outbound_calls) == 1, (
            f"Expected exactly 1 outbound enqueue call, got {len(outbound_calls)}"
        )
        outbound_data = outbound_calls[0][0][1]

        # Verify to_address: reply_to if present, else sender
        expected_to = reply_to if reply_to else sender
        assert outbound_data["to_address"] == expected_to, (
            f"to_address mismatch: expected '{expected_to}', "
            f"got '{outbound_data.get('to_address')}'"
        )

        # Verify subject: composed via smtp_client.compose_reply_subject
        expected_subject = f"Re: {subject}"
        assert outbound_data["subject"] == expected_subject, (
            f"subject mismatch: expected '{expected_subject}', "
            f"got '{outbound_data.get('subject')}'"
        )

        # Verify in_reply_to: message_id
        assert outbound_data["in_reply_to"] == message_id, (
            f"in_reply_to mismatch: expected '{message_id}', "
            f"got '{outbound_data.get('in_reply_to')}'"
        )
