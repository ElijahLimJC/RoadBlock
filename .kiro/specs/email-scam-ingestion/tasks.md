# Implementation Plan: Email Scam Ingestion

## Overview

This plan implements an automated email ingestion pipeline for RoadBlock. The pipeline connects to an IMAP mailbox, classifies incoming emails through a two-stage scam detection engine (regex + hardened LLM), feeds confirmed scams into the existing engagement pipeline, and delivers persona responses via SMTP. All new state lives in `st.session_state` following the monolithic architecture, and new components follow the one-component-per-module convention.

## Tasks

- [ ] 1. Create Pydantic data models for email ingestion
  - [x] 1.1 Create `models/email_models.py` with EmailMessage, ClassificationResult, ScamPattern, OutboundEmail, and EmailThreadMetadata models
    - Implement `EmailMessage` with RFC 5322 sender validation (max 254 chars), subject (max 998 chars), body (non-empty, max 1,000,000 chars), message_id, reply_to, date_header, and UTC timestamp
    - Implement `ClassificationResult` with Literal verdict ("scam"/"not_scam"), confidence (0.0–1.0), determining_stage (Literal "stage_1"/"stage_2"), matched_patterns list, llm_reasoning string, timestamp, sender, subject
    - Implement `ScamPattern` with name, regex string, category (Literal urgency/financial_lure/impersonation/phishing), weight (0.0–1.0)
    - Implement `OutboundEmail` with to_address, subject (max 255 chars), body, in_reply_to, references, status Literal, retry_count, created_at, last_attempt_at
    - Implement `EmailThreadMetadata` with sender_address, subject, message_ids list, source_channel Literal "email", message_count
    - All models use `ConfigDict(frozen=True)` and Pydantic v2 field_validators
    - _Requirements: 6.1, 6.2, 6.3, 6.5, 6.6, 6.7, 1.3, 5.1_

  - [x] 1.2 Write property test: EmailMessage serialization round-trip (Property 1)
    - **Property 1: Email_Message serialization round-trip**
    - Use Hypothesis to generate valid EmailMessage instances with arbitrary RFC 5322 addresses, subjects, bodies
    - Assert `EmailMessage.model_validate_json(email.model_dump_json())` produces identical sender, subject, body, timestamp
    - **Validates: Requirements 1.7, 6.6**

  - [x] 1.3 Write property test: ClassificationResult serialization round-trip (Property 2)
    - **Property 2: Classification_Result serialization round-trip**
    - Use Hypothesis to generate valid ClassificationResult instances with sampled verdicts, float confidences, stages
    - Assert round-trip JSON serialization/deserialization preserves verdict, confidence, determining_stage
    - **Validates: Requirements 6.7**

- [ ] 2. Implement the Scam_Classifier regex engine (Stage 1)
  - [x] 2.1 Create `components/scam_classifier.py` with ScamClassifier class and Stage 1 regex scoring
    - Implement `__init__` accepting patterns list, llm_client, confidence_threshold (default 0.7), fallback_threshold (default 0.3), llm_timeout (10s)
    - Add threshold validation: both must be in [0.0, 1.0], fallback must not exceed confidence threshold — raise ValueError on violation
    - Compile all regex patterns at init; log warning and skip invalid patterns; if zero valid patterns remain, return 0.0 for all Stage 1 calls
    - Implement `_stage_1_regex(subject, body)` computing weighted confidence as sum of matched pattern weights, each contributing at most once, capped at 1.0
    - Treat missing/empty subject as empty string for matching
    - _Requirements: 2.1, 2.2, 2.3, 2.12, 3.1, 3.2, 3.5, 3.6, 3.7, 7.1, 7.2, 7.3, 7.4_

  - [ ] 2.2 Write property test: Confidence score bounded output (Property 3)
    - **Property 3: Confidence score bounded output**
    - Use Hypothesis to generate arbitrary pattern sets with random weights and email content
    - Assert Stage 1 confidence score is always >= 0.0 and <= 1.0
    - **Validates: Requirements 7.6**

  - [ ] 2.3 Write property test: Zero-weight pattern invariant (Property 4)
    - **Property 4: Zero-weight pattern invariant**
    - Use Hypothesis to generate pattern sets and emails, then add a pattern with weight 0.0
    - Assert confidence score is unchanged after adding the zero-weight pattern
    - **Validates: Requirements 7.5**

  - [ ] 2.4 Write property test: Stage 1 classification determinism (Property 5)
    - **Property 5: Stage 1 regex classification determinism**
    - Use Hypothesis to generate emails and fixed classifier configs
    - Assert classifying the same email twice produces identical verdict, confidence, determining_stage
    - **Validates: Requirements 2.11**

  - [ ] 2.5 Write property test: Threshold validation rejects invalid ranges (Property 7)
    - **Property 7: Threshold validation rejects invalid ranges**
    - Use Hypothesis to generate float values outside [0.0, 1.0]
    - Assert ScamClassifier raises ValueError at init for invalid confidence or fallback thresholds
    - **Validates: Requirements 3.5, 3.6**

  - [x] 2.6 Write property test: Fallback-greater-than-confidence rejection (Property 8)
    - **Property 8: Fallback-greater-than-confidence rejection**
    - Use Hypothesis to generate pairs where fallback > confidence (both in [0.0, 1.0])
    - Assert ScamClassifier raises ValueError at init
    - **Validates: Requirements 3.7**

- [ ] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Implement Scam_Classifier Stage 2 (hardened LLM classification)
  - [ ] 4.1 Implement Stage 2 LLM classification with prompt hardening in `components/scam_classifier.py`
    - Implement `_build_hardened_prompt(subject, body)` that wraps email content in triple-backtick fenced blocks with unique boundary tokens
    - Implement `_stage_2_llm(subject, body, stage_1_confidence)` invoking the LLM with a system prompt instructing binary classification only, ignoring embedded instructions
    - Implement `_validate_llm_response(response_text)` checking JSON schema: "verdict" field ("scam"/"not-scam"), "reasoning" field (string), extra fields ignored
    - On LLM failure (timeout 10s, network error, empty/unparseable response): fall back to Stage 1 — classify as scam if confidence >= fallback_threshold, else not-scam
    - Unparseable LLM response treated as potential injection success — log at warning
    - _Requirements: 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.12, 3.3, 3.4_

  - [ ] 4.2 Implement the top-level `classify(email)` method orchestrating Stage 1 → Stage 2 routing
    - If Stage 1 confidence >= confidence_threshold: return scam verdict with stage_1
    - If Stage 1 confidence < confidence_threshold: invoke Stage 2
    - Return full ClassificationResult with all fields populated
    - _Requirements: 2.3, 2.4, 2.12_

  - [ ] 4.3 Write property test: Threshold routing correctness (Property 6)
    - **Property 6: Threshold routing correctness**
    - Use Hypothesis to generate emails and valid thresholds
    - Assert: if confidence >= threshold then determining_stage == "stage_1"; if < threshold then Stage 2 was invoked
    - **Validates: Requirements 2.3, 2.4, 3.3, 3.4**

  - [ ] 4.4 Write property test: LLM response validation rejects non-conforming output (Property 9)
    - **Property 9: LLM response validation rejects non-conforming output**
    - Use Hypothesis to generate arbitrary strings that don't conform to expected JSON schema
    - Assert `_validate_llm_response` returns None for all non-conforming inputs
    - **Validates: Requirements 2.7, 2.9**

- [ ] 5. Implement IMAP_Client component
  - [x] 5.1 Create `components/imap_client.py` with IMAPClient class
    - Implement `__init__` loading host, port, username, password from environment variables with 10s connection timeout
    - Implement `connect()` establishing SSL/TLS connection and authenticating
    - Implement `fetch_unread()` returning list of raw email bytes for all unread messages
    - Implement `mark_as_read(message_uid)` setting \\Seen flag, returning success bool
    - Implement `disconnect()` for graceful connection teardown
    - Implement `is_connected` property for status checking
    - Handle connection failures: log at warning, no crash propagation
    - Handle mark-as-read failures: log at warning, return False
    - _Requirements: 1.1, 1.2, 1.4, 1.5, 1.8, 1.9_

  - [ ] 5.2 Write unit tests for IMAP_Client
    - Mock `imaplib.IMAP4_SSL` for all tests
    - Test successful connection and authentication
    - Test connection failure handling (timeout, auth error)
    - Test fetch_unread with multiple messages
    - Test mark_as_read success and failure paths
    - Test disconnection during poll cycle
    - _Requirements: 1.1, 1.4, 1.5, 1.8, 1.9_

- [ ] 6. Implement SMTP_Client component
  - [x] 6.1 Create `components/smtp_client.py` with SMTPClient class
    - Implement `__init__` loading host, port, username, password, sender_address from environment variables with 30s timeout
    - Implement `send_reply(to_address, subject, body, in_reply_to, references)` composing reply with STARTTLS/TLS, In-Reply-To and References headers
    - Implement reply subject: "Re: " + original subject truncated to combined max 255 chars
    - Implement per-recipient rate limiting (default 1 email per 60s, configurable)
    - Implement `queue_message(message)` with max 100 queue size; reject with "dropped_queue_full" when full
    - Implement `process_retry_queue()` for deferred delivery within rate limits
    - After 3 consecutive failures for same message: mark "failed_permanent", cease retries
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8_

  - [ ] 6.2 Write property test: Outbound subject line length invariant (Property 10)
    - **Property 10: Outbound subject line length invariant**
    - Use Hypothesis to generate arbitrary subject strings of varying length
    - Assert composed reply subject ("Re: " + truncated original) never exceeds 255 characters
    - **Validates: Requirements 5.1**

  - [ ] 6.3 Write unit tests for SMTP_Client
    - Mock `smtplib.SMTP` for all tests
    - Test successful send with threading headers
    - Test rate limiting enforcement (defer when exceeded)
    - Test queue saturation at 100 messages (rejection)
    - Test retry logic and permanent failure after 3 attempts
    - Test connection failure handling
    - _Requirements: 5.2, 5.3, 5.4, 5.5, 5.6, 5.8_

- [ ] 7. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Implement Email_Ingestion_Module orchestrator
  - [ ] 8.1 Create `components/email_ingestion.py` with EmailIngestionModule class
    - Implement `__init__` accepting imap_client, smtp_client, scam_classifier, polling_interval (default 30s, min 10, max 300)
    - Implement `start_polling()` launching background thread with configurable interval
    - Implement `stop_polling()` for graceful shutdown
    - Implement email parsing: MIME → EmailMessage (text/plain preferred, HTML tag-strip fallback, skip if neither)
    - Mark emails as read after successful fetch; skip on mark-as-read failure with reattempt next cycle
    - Handle malformed emails: mark as read, log at warning with Message-ID, skip
    - Handle IMAP connection loss during poll: abort fetch, log, reconnect next interval
    - Track consecutive failures: after 3, set degraded_warning in Chat_State; clear on reconnect
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.8, 1.9, 6.3, 6.4, 8.5, 8.6_

  - [ ] 8.2 Implement pipeline integration in EmailIngestionModule
    - Implement `process_email(email_msg)` calling classify → route based on verdict
    - Implement `_feed_to_pipeline(email_msg, classification)` forwarding scam emails through Safety_Filter → Persona_Engine → Chat_State → Threat_Parser
    - Implement `_handle_blocked_message(email_msg)` storing default confused-elder response and still invoking Threat_Parser for IoC extraction
    - Tag email-sourced messages with metadata (source_channel="email", sender, subject, Message-ID)
    - On pipeline error: log warning, skip email, continue with next
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.8_

  - [ ] 8.3 Implement conversation threading by sender address
    - Match emails from same sender to existing thread in Chat_State (keyed by sender_address)
    - Append each email to thread's conversation history
    - Pass accumulated thread history to Persona_Engine for context
    - Store EmailThreadMetadata in Chat_State email_ingestion.threads dict
    - _Requirements: 4.7_

  - [ ] 8.4 Write property test: Conversation threading by sender (Property 13)
    - **Property 13: Conversation threading by sender**
    - Use Hypothesis to generate sequences of emails with repeated sender addresses
    - Assert all emails from the same sender are in the same thread and thread history accumulates
    - **Validates: Requirements 4.7**

- [ ] 9. Extend Chat_State for email ingestion
  - [ ] 9.1 Update `app.py` `initialize_chat_state()` to include email ingestion state keys
    - Add "email_ingestion" dict with: connection_status, total_fetched, total_scam, total_not_scam, outbound_sent, consecutive_failures, degraded_warning, classification_log (max 200), outbound_queue (max 100), threads dict
    - Implement classification log capacity management (evict oldest when > 200)
    - _Requirements: 8.1, 8.2_

  - [ ] 9.2 Write property test: Classification log capacity invariant (Property 11)
    - **Property 11: Classification log capacity invariant**
    - Use Hypothesis to generate sequences of ClassificationResults appended to the log
    - Assert log never exceeds 200 entries and oldest are evicted first
    - **Validates: Requirements 8.2**

  - [ ] 9.3 Write property test: Classification log ordering (Property 12)
    - **Property 12: Classification log ordering**
    - Use Hypothesis to generate sets of ClassificationResults with varying timestamps
    - Assert displayed entries are in reverse chronological order (newest first)
    - **Validates: Requirements 8.4**

- [ ] 10. Implement SOC Dashboard email ingestion panel
  - [ ] 10.1 Add `render_email_ingestion_panel()` and `render_classification_log()` methods to `dashboard/soc_dashboard.py`
    - Display connection status (connected/disconnected), total fetched, scam count, not-scam count, outbound sent
    - Display degraded ingestion warning when active
    - Display last 50 classification decisions in reverse chronological order: sender, subject (truncated 60 chars), verdict, confidence, determining_stage
    - Reflect connection status changes within rendering cycle
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

  - [ ] 10.2 Write unit tests for SOC Dashboard email ingestion panel
    - Test panel renders with empty state
    - Test panel renders with populated classification log
    - Test degraded warning display/clear
    - Test classification log truncation at 50 displayed entries
    - _Requirements: 8.1, 8.4, 8.5, 8.6_

- [ ] 11. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 12. Wire up email ingestion into app.py and integrate all components
  - [ ] 12.1 Integrate EmailIngestionModule into `app.py`
    - Import and instantiate IMAPClient, SMTPClient, ScamClassifier, EmailIngestionModule
    - Load credentials from environment variables (IMAP_HOST, IMAP_PORT, IMAP_USERNAME, IMAP_PASSWORD, SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_SENDER)
    - Start polling on app initialization; stop on session cleanup
    - Add email ingestion panel to the SOC Dashboard rendering
    - Wire SMTP delivery trigger after persona response generation for email-sourced messages
    - Process retry queue on each poll cycle
    - _Requirements: 1.1, 4.1, 5.1, 5.2, 8.1_

  - [ ] 12.2 Write integration tests for full email pipeline flow
    - Test end-to-end: email fetch → classify → Safety_Filter → Persona_Engine → SMTP reply
    - Test blocked message flow: Safety_Filter blocks → default response → IoC extraction still runs
    - Test LLM fallback scenarios: timeout, malformed response, injection-like response
    - Test degraded warning lifecycle: 3 failures → warning → reconnect → clear
    - Mock IMAP and SMTP servers; mock LLM client
    - _Requirements: 4.1, 4.5, 4.6, 2.8, 8.5, 8.6_

- [ ] 13. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document (Properties 1–13)
- Unit tests validate specific examples and edge cases
- All components follow the one-module-per-component convention
- All state flows through `st.session_state` — no external databases
- Python with Pydantic v2, Hypothesis for PBT, pytest for test runner
- Tests go in `tests/` directory mirroring source structure (e.g., `tests/test_scam_classifier.py`, `tests/test_imap_client.py`)

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3", "2.1", "5.1", "6.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.4", "2.5", "2.6", "5.2", "6.2", "6.3"] },
    { "id": 3, "tasks": ["4.1", "4.2"] },
    { "id": 4, "tasks": ["4.3", "4.4", "8.1"] },
    { "id": 5, "tasks": ["8.2", "8.3", "9.1"] },
    { "id": 6, "tasks": ["8.4", "9.2", "9.3", "10.1"] },
    { "id": 7, "tasks": ["10.2", "12.1"] },
    { "id": 8, "tasks": ["12.2"] }
  ]
}
```
