# Requirements Document

## Introduction

RoadBlock is a single-process, automated social honeypot pipeline built with Python and Streamlit. It intercepts unstructured text streams from scammers, engages them using a jailbreak-resistant AI persona ("The Tech-Illiterate Confused Elder") to waste their time, and simultaneously runs a real-time data engineering pipeline to extract validated Threat Intelligence Indicators of Compromise (IoCs). The system operates as a monolithic Python runtime with Streamlit for UI, asynchronous event loops for concurrency, and in-memory state management via `st.session_state`.

## Glossary

- **RoadBlock_System**: The complete single-process application encompassing the persona engine, parsing pipeline, and dashboard UI.
- **Persona_Engine**: The master LLM-driven conversational module embodying "The Tech-Illiterate Confused Elder" character designed to stall scammers.
- **Safety_Filter**: The input sanitization boundary that screens inbound scammer messages for prompt injection attacks before forwarding to the Persona_Engine.
- **Threat_Parser**: The background Pydantic-based extraction engine that identifies and validates IoCs from chat log content.
- **SOC_Dashboard**: The real-time Streamlit view displaying extracted IoCs, conversation metrics, and notification status.
- **Stalling_Tracker**: The metrics subsystem that records chat turn counts, timestamps, and cumulative scammer time wasted.
- **Notification_Module**: The mock integration layer simulating ingestion of IoC data into AWS GuardDuty findings and AWS WAF IP block rules.
- **IoC**: Indicator of Compromise — a validated artifact (wallet address, domain, phone number, or mule account) extracted from scammer communications.
- **Scammer_Input_Stream**: The inbound text channel carrying raw, unstructured messages from the adversarial actor.
- **Chat_State**: The in-memory session state (`st.session_state`) holding conversation history, extracted entities, and metrics.

## Requirements

### Requirement 1: Conversational Persona Generation

**User Story:** As a security operator, I want the system to generate convincing responses as a confused elderly person, so that scammers are engaged in prolonged, time-wasting conversations.

#### Acceptance Criteria

1. WHEN a sanitized scammer message is received, THE Persona_Engine SHALL generate a response within 10 seconds that maintains the "Tech-Illiterate Confused Elder" character and is between 20 and 300 words in length.
2. THE Persona_Engine SHALL maintain character consistency across all turns within a single conversation session, where consistency is defined as: the response never acknowledges being an AI or automated system, never uses technical jargon correctly, and never provides accurate step-by-step instructions.
3. WHEN the scammer asks technical questions, THE Persona_Engine SHALL respond with confused, off-topic, or circular replies that prolong the conversation without providing actionable information, where actionable information is defined as: valid credentials, correct technical procedures, real financial details, or system architecture details.
4. THE Persona_Engine SHALL include at least one stalling tactic per response, selected from: asking the scammer to repeat themselves, introducing irrelevant anecdotes, expressing confusion about technology, or requesting unnecessary clarifications.
5. IF the Persona_Engine fails to generate a response within 10 seconds or the LLM is unavailable, THEN THE Persona_Engine SHALL return a pre-written fallback response that maintains the "Tech-Illiterate Confused Elder" character and includes a stalling tactic.

### Requirement 2: Conversational Stalling Metrics

**User Story:** As a security analyst, I want to see how much scammer time has been wasted, so that I can quantify the operational impact of the honeypot.

#### Acceptance Criteria

1. WHEN a chat turn is completed (one scammer message followed by one persona response stored in Chat_State), THE Stalling_Tracker SHALL increment the turn count for the active session by one.
2. WHEN a chat turn is completed, THE Stalling_Tracker SHALL record the timestamp of the turn and calculate the elapsed wall-clock duration between the first scammer message timestamp and the most recent scammer message timestamp as "Total Scammer Time Wasted," stored with whole-second precision.
3. THE Stalling_Tracker SHALL persist turn count and duration metrics in Chat_State for the lifetime of the session, retaining values across successive Streamlit render cycles until the session is terminated.
4. WHEN the SOC_Dashboard is rendered, THE RoadBlock_System SHALL display the current turn count and Total Scammer Time Wasted formatted as "HH:MM:SS" (hours, minutes, and seconds with leading zeros).
5. WHEN a new Streamlit session begins and no chat turns have been completed, THE Stalling_Tracker SHALL initialize the turn count to zero and Total Scammer Time Wasted to "00:00:00."

### Requirement 3: Threat Intelligence Extraction — Cryptocurrency Wallets

**User Story:** As a threat intelligence analyst, I want cryptocurrency wallet addresses automatically extracted from chat logs, so that I can track financial IoCs without manual review.

#### Acceptance Criteria

1. WHEN a chat message contains one or more strings matching a Bitcoin address pattern (base58 starting with 1 or 3 using Base58Check encoding, or Bech32 starting with bc1, length 26–62 characters), THE Threat_Parser SHALL extract each matching candidate, validate it using the Base58Check checksum (for addresses starting with 1 or 3) or Bech32 checksum (for addresses starting with bc1), and store each valid address as a Cryptocurrency Wallet IoC in Chat_State.
2. WHEN a chat message contains one or more strings matching an Ethereum address pattern (0x followed by exactly 40 hexadecimal characters, case-insensitive), THE Threat_Parser SHALL extract each matching candidate, validate that it contains exactly 40 characters in the range [0-9a-fA-F] after the 0x prefix, and store each valid address as a Cryptocurrency Wallet IoC in Chat_State.
3. IF the Threat_Parser extracts a wallet address candidate that fails its applicable checksum or format validation, THEN THE Threat_Parser SHALL discard the candidate and record the rejection reason (including the invalid candidate string and the validation rule that failed) in Chat_State so that it is visible on the SOC_Dashboard notification log.
4. FOR ALL valid extracted wallet addresses, parsing the raw message then serializing the IoC Pydantic model to JSON and deserializing back into the model SHALL produce an object with identical field values for wallet type, address string, and source message reference (round-trip property).

### Requirement 4: Threat Intelligence Extraction — Phishing Domains

**User Story:** As a threat intelligence analyst, I want phishing domains automatically extracted from chat content, so that I can feed them into blocking infrastructure.

#### Acceptance Criteria

1. WHEN a chat message contains a bare domain (e.g., evil.com), a full URL (e.g., http://evil.com/path), or a defanged/obfuscated domain (e.g., hxxp://evil[.]com), THE Threat_Parser SHALL detect the domain-like string, reverse common defanging substitutions (hxxp to http, [.] to ., [://] to ://), extract the domain component, and validate it against RFC 1035 domain name syntax (labels up to 63 characters, total length up to 253 characters).
2. THE Threat_Parser SHALL normalize extracted domains to lowercase and strip any trailing dots before storing them as Phishing Domain IoCs.
3. IF a candidate domain string fails RFC 1035 validation, THEN THE Threat_Parser SHALL discard the candidate and log the rejection reason.
4. IF the Threat_Parser extracts a domain that already exists in the current session's Phishing Domain IoC list (compared after normalization), THEN THE Threat_Parser SHALL discard the duplicate without creating a new IoC entry.
5. FOR ALL valid extracted domains, normalization applied twice SHALL produce the same result as normalization applied once (idempotence property).

### Requirement 5: Threat Intelligence Extraction — Phone Numbers

**User Story:** As a threat intelligence analyst, I want phone numbers automatically extracted from chat content, so that I can identify communication channels used by scammers.

#### Acceptance Criteria

1. WHEN a chat message contains one or more strings matching a phone number pattern of at least 7 digits (excluding formatting characters) with an identifiable country code prefix, THE Threat_Parser SHALL extract all matching instances and normalize each to E.164 format (+ followed by country code and subscriber number, maximum 15 digits total).
2. IF a candidate phone number string does not resolve to a valid E.164 number after normalization (due to invalid country code, digit count below 7 or above 15, or unrecognizable format), THEN THE Threat_Parser SHALL discard the candidate and log the rejection reason.
3. IF a candidate phone number string lacks an explicit country code prefix and cannot be unambiguously resolved to a single E.164 number, THEN THE Threat_Parser SHALL discard the candidate and log the rejection reason indicating an ambiguous country code.
4. FOR ALL valid extracted phone numbers, normalizing an already-normalized number SHALL produce the same output (idempotence property).
5. THE Threat_Parser SHALL only consider digit sequences as phone number candidates when they contain recognized separator patterns (spaces, hyphens, dots, parentheses) or an explicit plus prefix, to avoid false-positive extraction from unrelated numeric strings such as account numbers or cryptocurrency addresses.

### Requirement 6: Threat Intelligence Extraction — Mule Bank Accounts

**User Story:** As a threat intelligence analyst, I want mule bank account details automatically extracted from chat content, so that I can report financial fraud infrastructure.

#### Acceptance Criteria

1. WHEN a chat message contains a bank name, account number (between 4 and 17 digits), and routing number in proximity (within 500 characters of each other), THE Threat_Parser SHALL extract the triplet as a Mule Bank Account IoC.
2. THE Threat_Parser SHALL validate that the routing number is exactly 9 digits and passes the ABA checksum algorithm (multiply each digit by weight [3,7,1,3,7,1,3,7,1], sum results, valid if sum mod 10 == 0).
3. IF a candidate routing number fails the ABA checksum validation, THEN THE Threat_Parser SHALL discard the entire Mule Bank Account candidate and log the rejection reason.
4. IF the account number contains fewer than 4 digits or more than 17 digits, THEN THE Threat_Parser SHALL discard the candidate and log the rejection reason indicating an invalid account number length.
5. WHEN multiple bank account triplets appear within a single message, THE Threat_Parser SHALL extract each triplet independently, validating each routing number separately.
6. FOR ALL valid Mule Bank Account IoCs, serializing to the Pydantic model and deserializing back SHALL produce an equivalent object (round-trip property).

### Requirement 7: Input Defense Boundary

**User Story:** As a security engineer, I want the system to resist prompt injection attacks, so that the persona never breaks character or leaks the system prompt.

#### Acceptance Criteria

1. WHEN the Safety_Filter receives inbound scammer text, THE Safety_Filter SHALL scan the message within 2 seconds for prompt injection patterns across the following categories: instruction override attempts (e.g., "ignore previous instructions"), role reassignment commands (e.g., "you are now..."), system prompt extraction requests (e.g., "repeat your system prompt"), and obfuscated payloads including base64-encoded instructions, hex-encoded instructions, and markdown/code-fence injection wrappers.
2. IF a prompt injection pattern is detected in a message that also contains legitimate conversational content, THEN THE Safety_Filter SHALL strip or escape the adversarial tokens while preserving the non-adversarial portion, and forward the sanitized message to the Persona_Engine.
3. THE Persona_Engine SHALL never include any portion of its system prompt text in its generated responses, regardless of conversational input received.
4. WHEN the scammer explicitly or indirectly requests the system prompt text or attempts role reassignment through any phrasing, THE Persona_Engine SHALL respond in character as the confused elder without acknowledging the existence of a system prompt, instructions, or AI identity.
5. IF the Safety_Filter determines that 80% or more of the inbound message tokens match injection patterns with no legitimate conversational content, THEN THE Safety_Filter SHALL generate a default confused-elder response without invoking the Persona_Engine LLM.
6. IF a message bypasses the Safety_Filter and the Persona_Engine generates a response that would contain system prompt content or break character, THEN THE Persona_Engine SHALL fall back to a pre-defined confused-elder response that maintains character integrity.

### Requirement 8: Data Flow Pipeline

**User Story:** As a system architect, I want a clearly defined data flow from scammer input to dashboard display, so that all components interact through well-defined boundaries.

#### Acceptance Criteria

1. WHEN a scammer message arrives, THE RoadBlock_System SHALL process it through the following sequential stages: Safety_Filter, then Persona_Engine, then Chat_State update, then Threat_Parser, then SOC_Dashboard refresh.
2. THE Safety_Filter SHALL complete processing of each inbound message before the Persona_Engine receives the sanitized output.
3. WHEN the Persona_Engine generates a response, THE RoadBlock_System SHALL update Chat_State with both the sanitized scammer message and the generated response before invoking the Threat_Parser.
4. THE Threat_Parser SHALL operate asynchronously relative to the Streamlit render cycle, completing extraction within 5 seconds of being invoked, allowing the SOC_Dashboard to remain responsive during extraction processing.
5. IF any pipeline stage raises an unhandled exception, THEN THE RoadBlock_System SHALL log the error with the stage name, message context, and stack trace, preserve all existing Chat_State data, and continue processing subsequent messages without crashing.
6. WHEN the Safety_Filter blocks a message entirely (per Requirement 7 criterion 5), THE pipeline SHALL short-circuit: the generated default response is stored in Chat_State and the Threat_Parser is still invoked on the original scammer message to capture any IoCs, but the Persona_Engine is not called.
7. THE end-to-end pipeline from scammer message receipt to Chat_State update (excluding the asynchronous Threat_Parser) SHALL complete within 15 seconds under normal operating conditions.

### Requirement 9: Real-Time SOC Dashboard

**User Story:** As a SOC analyst, I want a real-time dashboard showing extracted IoCs and conversation metrics, so that I can monitor active honeypot engagements.

#### Acceptance Criteria

1. THE SOC_Dashboard SHALL display all extracted IoCs grouped by category: Cryptocurrency Wallets, Phishing Domains, Phone Numbers, and Mule Bank Accounts, with each IoC labeled by its category and showing its extracted value.
2. WHEN a new IoC is extracted by the Threat_Parser, THE SOC_Dashboard SHALL reflect the new IoC within 5 seconds of extraction without requiring a manual page refresh.
3. WHEN a new chat turn is completed, THE SOC_Dashboard SHALL update the conversation log within 5 seconds to display the new scammer message and persona response in chronological order, with each message attributed to its sender (scammer or persona).
4. THE SOC_Dashboard SHALL display the current session metrics: turn count, Total Scammer Time Wasted formatted as hours, minutes, and seconds, and count of IoCs extracted per category.
5. WHEN a new Streamlit session begins with no conversation history, THE SOC_Dashboard SHALL render the IoC section with zero entries per category, an empty conversation log, and session metrics initialized to zero.
6. IF the Threat_Parser raises an error during extraction, THEN THE SOC_Dashboard SHALL continue displaying the most recent successfully extracted IoCs and conversation log without interruption.

### Requirement 10: Mock AWS Notification Module

**User Story:** As a security engineer, I want mock notifications simulating AWS GuardDuty findings and WAF blocks, so that I can validate the integration pattern before connecting real infrastructure.

#### Acceptance Criteria

1. WHEN a Phishing Domain IoC is extracted, THE Notification_Module SHALL generate a mock AWS WAF UpdateIPSet payload containing the following fields: Name, Scope (set to "REGIONAL"), Id (generated UUID), Addresses (list containing the domain), and LockToken (generated UUID), with a timestamp, and store it in Chat_State.
2. WHEN a Cryptocurrency Wallet IoC is extracted, THE Notification_Module SHALL generate a mock AWS GuardDuty finding payload with severity level "HIGH" containing fields: SchemaVersion, AccountId, Region, Type (set to "CryptoCurrency:EC2/BitcoinTool.B"), Resource, Service, Severity, Title, Description, and CreatedAt.
3. WHEN a Mule Bank Account IoC is extracted, THE Notification_Module SHALL generate a mock AWS GuardDuty finding payload with severity level "CRITICAL" containing the same field structure as criterion 2 with Type set to "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration".
4. WHEN a Phone Number IoC is extracted, THE Notification_Module SHALL generate a mock AWS GuardDuty finding payload with severity level "MEDIUM" containing the same field structure as criterion 2 with Type set to "Recon:EC2/PortProbeUnprotectedPort".
5. THE SOC_Dashboard SHALL display a notification log showing all mock AWS notifications with their timestamps, severity level, type, and a one-line summary of the IoC that triggered the notification.
6. FOR ALL generated mock payloads, serializing the payload to JSON and deserializing back SHALL produce an equivalent object (round-trip property).

### Requirement 11: Session State Management

**User Story:** As a developer, I want all application state managed in-memory via Streamlit session state, so that the system operates without external database dependencies.

#### Acceptance Criteria

1. THE RoadBlock_System SHALL store all conversation history, extracted IoCs, stalling metrics, and mock notifications exclusively in `st.session_state`, with no writes to external databases, files, or caching services for state persistence.
2. WHEN a new Streamlit session begins and Chat_State keys do not yet exist in `st.session_state`, THE RoadBlock_System SHALL initialize Chat_State with the following keys set to empty defaults: `conversation_history` (empty list), `iocs` (dict with empty lists for each category: cryptocurrency_wallets, phishing_domains, phone_numbers, mule_bank_accounts), `metrics` (dict with turn_count set to 0 and start_time set to null), and `notifications` (empty list).
3. IF Chat_State keys already exist in `st.session_state` during a Streamlit rerun, THEN THE RoadBlock_System SHALL preserve the existing values without re-initialization.
4. THE RoadBlock_System SHALL maintain independent Chat_State per concurrent Streamlit session without cross-session data leakage, such that no session can read or modify another session's Chat_State keys.
5. IF a Streamlit session is terminated, THEN THE RoadBlock_System SHALL release all associated Chat_State memory upon session expiry as managed by the Streamlit server runtime, without requiring explicit cleanup by the operator.
