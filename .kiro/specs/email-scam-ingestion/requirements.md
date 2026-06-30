# Requirements Document

## Introduction

This feature adds an automated email ingestion pipeline to RoadBlock, enabling the honeypot to intercept scammer emails from an IMAP mailbox, classify them as scams via a two-stage detection pipeline (regex pattern matching followed by a lightweight LLM call), and feed confirmed scam emails into the existing RoadBlock engagement loop. Outbound persona responses are delivered back to the scammer via SMTP, creating a fully automated email-based honeypot channel alongside the existing Streamlit-based manual input.

## Glossary

- **Email_Ingestion_Module**: The component responsible for connecting to an IMAP server, fetching unread emails, and forwarding them into the preprocessing pipeline.
- **Scam_Classifier**: The upstream two-stage preprocessing module that determines whether an ingested email is a scam. Stage 1 uses regex pattern matching; Stage 2 uses a lightweight LLM call for confirmation.
- **Classification_Result**: The output of the Scam_Classifier containing a verdict (scam or not-scam), confidence score, the stage at which classification was determined, and the matched patterns or LLM reasoning.
- **Email_Message**: A Pydantic model representing a parsed email with fields for sender address, subject, body text, headers, and timestamp.
- **IMAP_Client**: The interface wrapping Python's `imaplib` for connecting to, authenticating with, and fetching messages from the IMAP server.
- **SMTP_Client**: The interface wrapping Python's `smtplib` for sending outbound persona response emails to scammers.
- **Confidence_Threshold**: A configurable numeric value (0.0–1.0) that determines whether the regex stage alone is sufficient to classify an email as a scam without invoking the LLM stage.
- **Fallback_Threshold**: A configurable numeric value (0.0–1.0) that determines the minimum Stage 1 confidence score required to classify as scam when the Stage 2 LLM call fails.
- **RoadBlock_System**: The existing core application pipeline (Safety_Filter → Persona_Engine → Chat_State → Threat_Parser → SOC_Dashboard).
- **Persona_Engine**: The existing LLM-driven conversational module embodying the "Tech-Illiterate Confused Elder" character.

## Requirements

### Requirement 1: IMAP Email Fetching

**User Story:** As a security operator, I want the system to connect to an IMAP mailbox and fetch unread emails, so that scammer emails are automatically ingested without manual intervention.

#### Acceptance Criteria

1. WHEN the Email_Ingestion_Module is started, THE IMAP_Client SHALL connect to the configured IMAP server over SSL/TLS using the provided host, port, username, and password credentials stored in environment variables, with a connection timeout of 10 seconds.
2. WHEN the IMAP_Client is connected, THE Email_Ingestion_Module SHALL poll the inbox at a configurable interval (default 30 seconds, minimum 10 seconds, maximum 300 seconds) to fetch all unread emails.
3. WHEN one or more unread emails are fetched, THE Email_Ingestion_Module SHALL parse each email into an Email_Message model containing the sender address, subject line (maximum 998 characters), plain-text body (maximum 1,000,000 characters), relevant headers (Date, Message-ID, Reply-To), and reception timestamp.
4. WHEN an email is successfully fetched and parsed, THE Email_Ingestion_Module SHALL mark the email as read on the IMAP server to prevent duplicate processing.
5. IF the IMAP_Client fails to connect or authenticate, THEN THE Email_Ingestion_Module SHALL log the error at warning level and retry connection after the configured polling interval without crashing the application.
6. IF an individual email fails to parse (malformed MIME, encoding errors), THEN THE Email_Ingestion_Module SHALL mark the email as read on the IMAP server to prevent infinite retry, skip the email, log the parsing failure with the Message-ID at warning level, and continue processing remaining emails.
7. FOR ALL valid Email_Message objects, serializing the model to JSON and deserializing back SHALL produce an object with identical field values for sender, subject, body, and timestamp (round-trip property).
8. IF the mark-as-read operation fails for a fetched email, THEN THE Email_Ingestion_Module SHALL log the failure at warning level, skip processing that email in the current poll cycle, and reattempt marking on the next poll cycle.
9. IF the IMAP_Client connection is lost during a poll cycle, THEN THE Email_Ingestion_Module SHALL abort the current fetch operation, log the disconnection at warning level, and attempt reconnection on the next polling interval.

### Requirement 2: Two-Stage Scam Classification

**User Story:** As a security operator, I want ingested emails to be classified as scam or not-scam through a two-stage pipeline, so that only confirmed scam emails enter the honeypot engagement loop.

#### Acceptance Criteria

1. WHEN the Email_Ingestion_Module provides an Email_Message to the Scam_Classifier, THE Scam_Classifier SHALL execute Stage 1 regex pattern matching against the email subject and body text, treating a missing or empty subject as an empty string for matching purposes.
2. THE Scam_Classifier SHALL maintain a configurable set of regex patterns targeting common scam indicators including: urgency language (e.g., "act now", "limited time"), financial lure phrases (e.g., "wire transfer", "bitcoin payment", "gift card"), impersonation markers (e.g., "IRS", "Microsoft Support", "your account has been"), and phishing patterns (e.g., "verify your identity", "click here immediately").
3. WHEN Stage 1 regex matching produces a confidence score at or above the configured Confidence_Threshold, THE Scam_Classifier SHALL classify the email as scam without invoking Stage 2, and record that classification was determined at Stage 1.
4. WHEN Stage 1 regex matching produces a confidence score below the Confidence_Threshold, THE Scam_Classifier SHALL invoke Stage 2 by sending the email subject and body to a lightweight LLM with a hardened classification prompt that instructs the LLM to respond with a structured verdict of either "scam" or "not-scam" along with a reasoning string, and THE Scam_Classifier SHALL parse the LLM response to extract the binary verdict.
5. WHEN constructing the Stage 2 LLM prompt, THE Scam_Classifier SHALL sanitize the email content by escaping or wrapping it in explicit delimiters (e.g., triple-backtick fenced blocks with a unique boundary token) so that instructions embedded within the email body cannot override the classification system prompt.
6. THE Scam_Classifier's Stage 2 system prompt SHALL instruct the LLM that its sole task is binary classification, that it must ignore any instructions contained within the email content, and that it must respond only with the structured verdict format (verdict + reasoning). The system prompt SHALL NOT be included in or derivable from the email content passed to the LLM.
7. IF the Stage 2 LLM response contains content that does not conform to the expected structured verdict format (i.e., is not parseable as a "scam" or "not-scam" verdict with reasoning), THEN THE Scam_Classifier SHALL treat the response as a potential injection success, discard it, log the anomalous response at warning level, and apply the fallback logic defined in criterion 8.
8. IF Stage 2 LLM call fails due to a network error, returns an empty response, returns an unparseable response, or does not complete within 10 seconds, THEN THE Scam_Classifier SHALL fall back to the Stage 1 regex result: classify as scam if Stage 1 confidence is above the configured Fallback_Threshold, otherwise classify as not-scam.
9. THE Scam_Classifier SHALL validate the Stage 2 LLM response by checking that it conforms to the expected JSON schema (containing exactly a "verdict" field with value "scam" or "not-scam" and a "reasoning" field with a string value) before accepting the classification. Any additional or unexpected fields SHALL be ignored but not treated as a failure.
10. WHEN an email is classified as not-scam, THE Scam_Classifier SHALL not forward the email to the RoadBlock_System pipeline and SHALL log the classification decision including sender address and subject at debug level.
11. FOR ALL emails processed by the Scam_Classifier, classifying the same email twice with identical classifier configuration SHALL produce the same verdict (determinism property for Stage 1; noted as best-effort for Stage 2 LLM).
12. THE Scam_Classifier SHALL return a Classification_Result containing the verdict (scam or not-scam), confidence score (0.0–1.0), determining stage (1 or 2), matched regex patterns as a list of pattern names (empty list if none matched), and LLM reasoning as a string (empty string if Stage 2 was not invoked).

### Requirement 3: Configurable Classification Thresholds

**User Story:** As a security operator, I want to configure the confidence thresholds for scam classification, so that I can tune the sensitivity of the detection pipeline.

#### Acceptance Criteria

1. THE Scam_Classifier SHALL expose a Confidence_Threshold parameter (default 0.7) that determines the minimum Stage 1 confidence score required to skip Stage 2 LLM classification. The parameter SHALL be set at initialization time and remain immutable for the lifetime of the classifier instance.
2. THE Scam_Classifier SHALL expose a Fallback_Threshold parameter (default 0.3) that determines the minimum Stage 1 confidence score required to classify as scam when the Stage 2 LLM call fails. The parameter SHALL be set at initialization time and remain immutable for the lifetime of the classifier instance.
3. WHEN the Confidence_Threshold is set to 1.0, THE Scam_Classifier SHALL always invoke Stage 2 for all emails regardless of Stage 1 results.
4. WHEN the Confidence_Threshold is set to 0.0, THE Scam_Classifier SHALL classify all emails that have a Stage 1 confidence score greater than 0.0 (at least one weighted regex pattern matched) as scam without invoking Stage 2.
5. IF the Confidence_Threshold is set to a value outside the range 0.0–1.0 inclusive, THEN THE Scam_Classifier SHALL raise a validation error at initialization time before processing any emails.
6. IF the Fallback_Threshold is set to a value outside the range 0.0–1.0 inclusive, THEN THE Scam_Classifier SHALL raise a validation error at initialization time before processing any emails.
7. IF the Fallback_Threshold is set to a value greater than the Confidence_Threshold, THEN THE Scam_Classifier SHALL raise a validation error at initialization time indicating an invalid threshold relationship.

### Requirement 4: Pipeline Integration for Scam Emails

**User Story:** As a security operator, I want confirmed scam emails to be fed into the existing RoadBlock pipeline, so that the honeypot persona engages scammers via email using the same engagement logic.

#### Acceptance Criteria

1. WHEN the Scam_Classifier produces a scam verdict for an email, THE Email_Ingestion_Module SHALL extract the plain-text body and forward it to the RoadBlock_System pipeline entry point (Safety_Filter) as a string input, preserving the same sequential processing stages (Safety_Filter → Persona_Engine → Chat_State update → Threat_Parser) defined for manually-entered messages.
2. WHEN the RoadBlock_System pipeline produces a persona response for an email-sourced message, THE Email_Ingestion_Module SHALL store the response content in Chat_State along with the original sender address, subject line, and Message-ID, making it available for outbound SMTP delivery.
3. THE Email_Ingestion_Module SHALL tag email-sourced messages in Chat_State with metadata indicating the source channel (email), original sender address, subject line, and Message-ID, to distinguish them from Streamlit UI-sourced messages.
4. WHEN an email-sourced message is processed through the pipeline, THE Threat_Parser SHALL extract IoCs from the email body using the same extraction logic applied to manually-entered messages.
5. IF the RoadBlock_System pipeline raises an error while processing an email-sourced message, THEN THE Email_Ingestion_Module SHALL log the error at warning level, skip the failed email, and continue processing subsequent emails without crashing.
6. IF the Safety_Filter blocks an email-sourced message entirely (per the 80% injection-token threshold), THEN THE Email_Ingestion_Module SHALL store a default confused-elder response in Chat_State for outbound delivery and still invoke the Threat_Parser on the original email body to capture any IoCs.
7. WHEN multiple emails are received from the same sender address, THE Email_Ingestion_Module SHALL append each email to the same conversation thread in Chat_State (matched by sender address), so that the Persona_Engine receives prior conversation context when generating responses.
8. WHEN the Email_Ingestion_Module forwards a message to the pipeline, THE RoadBlock_System SHALL complete processing (excluding the asynchronous Threat_Parser) within 15 seconds, consistent with the pipeline timeout defined for manually-entered messages.

### Requirement 5: Outbound SMTP Response Delivery

**User Story:** As a security operator, I want the honeypot persona responses sent back to scammers via email, so that the engagement loop continues automatically without manual intervention.

#### Acceptance Criteria

1. WHEN a persona response is generated for an email-sourced scam message, THE SMTP_Client SHALL compose a reply email with the persona response as the body, the From address set to the configured sender identity stored in environment variables, addressed to the original sender, with a subject line consisting of "Re: " followed by the original subject truncated to a combined maximum of 255 characters.
2. WHEN the SMTP_Client initiates a connection, THE SMTP_Client SHALL connect to the configured SMTP server using the provided host, port, username, and password credentials stored in environment variables, using STARTTLS or implicit TLS for transport encryption, with a connection timeout of 30 seconds.
3. WHEN the SMTP_Client sends a reply, THE SMTP_Client SHALL set the In-Reply-To and References headers to the original email's Message-ID to maintain email thread continuity.
4. IF the SMTP_Client fails to send a reply (connection failure, authentication failure, timeout, or SMTP error), THEN THE SMTP_Client SHALL log the error at warning level, store the unsent response in Chat_State with a status of "pending_retry", and continue processing subsequent messages without crashing.
5. WHILE the per-recipient rate limit is exceeded (default: maximum 1 outbound email per 60 seconds per recipient, configurable), THE SMTP_Client SHALL queue the outbound message in Chat_State (maximum 100 queued messages) and defer delivery until the rate limit window allows sending.
6. IF the outbound message queue reaches 100 messages, THEN THE SMTP_Client SHALL reject additional outbound messages, log a warning indicating queue saturation, and mark the rejected response in Chat_State with a status of "dropped_queue_full".
7. WHEN the SMTP_Client successfully delivers a reply, THE Email_Ingestion_Module SHALL log the delivery at info level with the recipient address and Message-ID.
8. IF a message stored with "pending_retry" status has failed delivery 3 consecutive times, THEN THE SMTP_Client SHALL mark the message status as "failed_permanent" in Chat_State and cease further retry attempts for that message.

### Requirement 6: Email Parsing and Model Validation

**User Story:** As a developer, I want email data represented as validated Pydantic models, so that downstream components receive well-structured, type-safe data.

#### Acceptance Criteria

1. THE Email_Message model SHALL validate that the sender field contains a syntactically valid email address conforming to RFC 5322 addr-spec format with a maximum length of 254 characters.
2. THE Email_Message model SHALL validate that the body field is a non-empty string after stripping leading and trailing whitespace, with a maximum length of 1,000,000 characters, raising a validation error if the stripped body is empty or exceeds the maximum length.
3. THE Email_Message model SHALL store the timestamp as a UTC datetime, converting from the email Date header timezone if present; IF the Date header is absent or cannot be parsed, THEN THE Email_Message model SHALL use the current UTC time at the moment of parsing as the timestamp.
4. IF an email contains multipart MIME content, THEN THE Email_Ingestion_Module SHALL extract the text/plain part as the body, falling back to stripping HTML tags from text/html if no plain-text part exists; IF neither text/plain nor text/html parts exist, THEN THE Email_Ingestion_Module SHALL treat the email as a parse failure and skip it per the malformed email handling behavior.
5. THE Classification_Result model SHALL validate that the confidence field is a float between 0.0 and 1.0 inclusive, that the verdict field is one of the literal values "scam" or "not_scam", and that the determining_stage field is one of the literal values "stage_1" or "stage_2".
6. FOR ALL valid Email_Message objects, parsing the raw email bytes then serializing the model to JSON and deserializing back SHALL produce an object with identical field values for sender, subject, body, and timestamp (round-trip property).
7. FOR ALL valid Classification_Result objects, serializing to JSON and deserializing back SHALL produce an object with identical field values for verdict, confidence, and determining_stage (round-trip property).

### Requirement 7: Regex Pattern Engine for Scam Detection

**User Story:** As a security analyst, I want the regex-based scam detection patterns to be maintainable and extensible, so that new scam patterns can be added without code changes.

#### Acceptance Criteria

1. THE Scam_Classifier SHALL load regex patterns from a configurable list of pattern definitions, where each definition includes a pattern name, compiled regex, category (urgency, financial_lure, impersonation, phishing), and weight (0.0–1.0) contributing to the confidence score.
2. WHEN Stage 1 executes, THE Scam_Classifier SHALL compute the confidence score as the sum of weights of all matched patterns (each pattern contributing its weight at most once regardless of how many times it matches within the email), capped at 1.0.
3. THE Scam_Classifier SHALL compile all regex patterns at initialization time and reuse the compiled patterns across all classification calls.
4. IF a regex pattern fails to compile at initialization, THEN THE Scam_Classifier SHALL log a warning with the pattern name and compilation error, skip the invalid pattern, and continue with the remaining valid patterns. IF zero valid patterns remain after compilation, THE Scam_Classifier SHALL return a confidence score of 0.0 for all emails at Stage 1.
5. FOR ALL pattern sets, adding a pattern with weight 0.0 SHALL not change the confidence score for any email (zero-weight invariant).
6. FOR ALL emails, the computed confidence score SHALL be greater than or equal to 0.0 and less than or equal to 1.0 (bounded output invariant).

### Requirement 8: Email Ingestion Observability

**User Story:** As a SOC analyst, I want visibility into the email ingestion pipeline status, so that I can monitor email processing, classification decisions, and delivery success.

#### Acceptance Criteria

1. THE SOC_Dashboard SHALL display an email ingestion status panel showing: connection status (connected/disconnected), total emails fetched, emails classified as scam, emails classified as not-scam, and outbound replies sent.
2. WHEN an email is classified by the Scam_Classifier, THE Email_Ingestion_Module SHALL store the Classification_Result in Chat_State so it is accessible to the SOC_Dashboard, retaining at most 200 classification results and discarding the oldest when the limit is exceeded.
3. WHEN the IMAP_Client connection status changes (connected to disconnected or vice versa), THE SOC_Dashboard SHALL reflect the updated status within 5 seconds.
4. THE SOC_Dashboard SHALL display a log of the most recent 50 classification decisions in reverse chronological order (newest first), showing the sender address, subject line (truncated to 60 characters), verdict, confidence score, and determining stage.
5. IF the Email_Ingestion_Module encounters repeated IMAP connection failures (3 consecutive failures), THEN THE Email_Ingestion_Module SHALL emit a warning visible on the SOC_Dashboard indicating degraded email ingestion.
6. WHEN the IMAP_Client successfully reconnects after the degraded ingestion warning has been emitted, THE Email_Ingestion_Module SHALL clear the degraded warning on the SOC_Dashboard and reset the consecutive failure counter to zero.
