# Bugfix Requirements Document

## Introduction

When the PersonaEngine fails and `_generate_persona_response` falls back to the default confused-elder response, the outbound reply email is not sent to the scammer. This happens because `_feed_to_pipeline` enqueues the outbound email at the very end (Step 6), after IoC extraction (Step 4) and thread update (Step 5). If either of those downstream steps throws an exception, the outer `try/except` catches it and returns, skipping the outbound enqueue entirely. The reply is lost silently.

In contrast, `_handle_blocked_message` enqueues the outbound email first (before IoC extraction), so blocked messages always get their default reply queued regardless of downstream failures.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN the PersonaEngine fails and `_generate_persona_response` returns the fallback response, AND a subsequent step (IoC extraction or thread update) throws an exception, THEN the system silently skips the outbound email enqueue and the reply is never sent to the scammer

1.2 WHEN `_run_extraction` raises an unhandled exception after persona response generation THEN the system catches the exception in the outer try/except and returns without enqueuing the outbound email

1.3 WHEN `_update_thread` raises an unhandled exception after persona response generation THEN the system catches the exception in the outer try/except and returns without enqueuing the outbound email

### Expected Behavior (Correct)

2.1 WHEN the PersonaEngine fails and `_generate_persona_response` returns the fallback response THEN the system SHALL enqueue the outbound reply email before attempting IoC extraction or thread update, ensuring the reply is always queued for SMTP delivery

2.2 WHEN `_run_extraction` raises an exception after the outbound email has been enqueued THEN the system SHALL log the extraction failure but the outbound reply SHALL already be in the queue and unaffected

2.3 WHEN `_update_thread` raises an exception after the outbound email has been enqueued THEN the system SHALL log the thread update failure but the outbound reply SHALL already be in the queue and unaffected

### Unchanged Behavior (Regression Prevention)

3.1 WHEN the PersonaEngine succeeds and generates a normal persona response THEN the system SHALL CONTINUE TO enqueue the outbound email with the generated response content

3.2 WHEN the Safety Filter blocks a message (>=80% injection tokens) THEN the system SHALL CONTINUE TO enqueue the default blocked response via `_handle_blocked_message` as it does today

3.3 WHEN IoC extraction succeeds without error THEN the system SHALL CONTINUE TO extract and log IoCs from the scam email body

3.4 WHEN thread update succeeds without error THEN the system SHALL CONTINUE TO update the conversation thread for the sender

3.5 WHEN the outbound email is enqueued THEN the system SHALL CONTINUE TO include correct reply-to address, composed subject, in-reply-to header, and response body
