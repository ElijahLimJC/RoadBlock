# Implementation Plan: Tarpit Honeypot Pipeline (RoadBlock)

## Overview

This plan breaks down the RoadBlock automated social honeypot pipeline into incremental coding tasks. Each task builds on previous steps, starting with foundational data models and project setup, progressing through core components (Safety Filter, Persona Engine, Threat Parser, MCP Client, Notification Module, Stalling Tracker), and culminating in the SOC Dashboard and Streamlit app wiring. Property-based tests validate correctness properties defined in the design document.

## Tasks

- [ ] 1. Set up project structure, dependencies, and Pydantic data models
  - [x] 1.1 Create project configuration and dependencies
    - Create `pyproject.toml` with project metadata, Python ≥3.11 requirement
    - Create `requirements.txt` with: streamlit, pydantic, hypothesis, pytest, asyncio, phonenumbers, base58, bech32, openai (or anthropic SDK), httpx
    - Create empty `__init__.py` files in `components/`, `models/`, `dashboard/`, `tests/`
    - _Requirements: 11.1_

  - [x] 1.2 Implement IoC Pydantic models in `models/ioc_models.py`
    - Define `IoCCategory` enum (cryptocurrency_wallet, phishing_domain, phone_number, mule_bank_account)
    - Define `WalletType` enum (bitcoin_base58, bitcoin_bech32, ethereum)
    - Define `BaseIoC` model with id, category, extracted_value, source_message, extracted_at, confidence, lookup_result
    - Define `CryptoWalletIoC(BaseIoC)` with wallet_type, address, and address validator
    - Define `PhishingDomainIoC(BaseIoC)` with domain, original_form, and lowercase/no-trailing-dot validator
    - Define `PhoneNumberIoC(BaseIoC)` with e164_number, original_form, and E.164 format validator
    - Define `MuleBankAccountIoC(BaseIoC)` with bank_name, account_number, routing_number, ABA checksum validator, and account length validator
    - _Requirements: 3.1, 3.2, 3.4, 4.2, 5.1, 5.4, 6.1, 6.2, 6.4, 6.6_

  - [x] 1.3 Implement chat and session models in `models/chat_models.py`
    - Define `ChatMessage` model with sender, content, timestamp, was_sanitized, was_blocked
    - Define `SessionMetrics` model with turn_count, start_time, last_message_time, total_time_wasted_seconds(), formatted_time_wasted()
    - Define `RejectionLogEntry` model with candidate, rejection_reason, ioc_category, timestamp
    - Define `ExtractionResult` model with iocs list and rejections list
    - Define `ScanResult` model for Safety_Filter output (sanitized_content, detected_patterns, is_blocked)
    - Define `PersonaResponse` model for Persona_Engine output
    - _Requirements: 2.1, 2.2, 2.4, 2.5, 8.3_

  - [x] 1.4 Implement AWS mock payload models in `models/aws_models.py`
    - Define `MockAWSPayload` model with payload_type, timestamp, severity, summary, raw_payload
    - Define `WAFPayload` model with Name, Scope, Id, Addresses, LockToken
    - Define `GuardDutyFinding` model with SchemaVersion, AccountId, Region, Type, Resource, Service, Severity, Title, Description, CreatedAt
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.6_

  - [x] 1.5 Implement MCP lookup models in `models/lookup_models.py`
    - Define `LookupStatus` enum (known, new, unknown)
    - Define `IoCLookupResult` model with ioc_value, ioc_category, lookup_status, is_known, first_seen, times_reported, reporting_sources, severity_assessment, tags, lookup_timestamp, lookup_duration_ms
    - _Requirements: 3.4, 6.6_

  - [x] 1.6 Write property tests for model serialization round-trips in `tests/test_models.py`
    - **Property 7: IoC Pydantic Model Round-Trip Serialization**
    - **Validates: Requirements 3.4, 6.6, 10.6**
    - Use Hypothesis to generate valid instances of CryptoWalletIoC, PhishingDomainIoC, PhoneNumberIoC, MuleBankAccountIoC, and MockAWSPayload
    - Assert `Model.model_validate_json(instance.model_dump_json()) == instance` for each

  - [x] 1.7 Write property test for ABA routing number checksum in `tests/test_models.py`
    - **Property 12: ABA Routing Number Checksum Validation**
    - **Validates: Requirements 6.2**
    - Use Hypothesis to generate random 9-digit strings
    - Assert MuleBankAccountIoC accepts iff `sum(digit[i] * weight[i]) % 10 == 0` where weights = [3,7,1,3,7,1,3,7,1]

- [ ] 2. Implement Safety Filter component
  - [x] 2.1 Implement `components/safety_filter.py`
    - Define `InjectionPattern` dataclass with name, regex pattern, category
    - Define `PatternMatch` dataclass with pattern_name, matched_text, start, end
    - Implement `SafetyFilter.__init__` with default injection patterns: instruction overrides, role reassignment, system prompt extraction, obfuscated payloads (base64, hex, markdown/code-fence)
    - Implement `SafetyFilter.scan(raw_message) -> ScanResult` that runs all patterns within 2s timeout
    - Implement `SafetyFilter.sanitize(raw_message, detected_patterns) -> str` that strips adversarial tokens while preserving legitimate content
    - Implement `SafetyFilter.is_fully_blocked(scan_result) -> bool` returning True when ≥80% of tokens match injection patterns
    - _Requirements: 7.1, 7.2, 7.5, 8.2_

  - [x] 2.2 Write property tests for Safety Filter in `tests/test_safety_filter.py`
    - **Property 14: Safety Filter Injection Detection**
    - **Validates: Requirements 7.1**
    - Generate messages containing known injection patterns; assert all are detected in ScanResult

  - [x] 2.3 Write property test for sanitization preservation in `tests/test_safety_filter.py`
    - **Property 15: Safety Filter Sanitization Preserves Legitimate Content**
    - **Validates: Requirements 7.2**
    - Generate messages with both injection and legitimate portions; assert legitimate content survives sanitization

  - [x] 2.4 Write property test for blocking threshold in `tests/test_safety_filter.py`
    - **Property 16: Safety Filter Blocking Threshold**
    - **Validates: Requirements 7.5**
    - Generate messages where ≥80% tokens are injection patterns; assert is_fully_blocked returns True

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Implement Persona Engine component
  - [x] 4.1 Implement `components/persona_engine.py`
    - Implement `PersonaEngine.__init__` with LLM client, system prompt (confused elder character), and pool of 20+ fallback responses
    - Implement `PersonaEngine.generate_response(sanitized_message, conversation_history) -> PersonaResponse` with 10s timeout, 20-300 word bounds, stalling tactic inclusion
    - Implement `PersonaEngine.validate_response(response) -> bool` checking no AI acknowledgment, no correct jargon, no actionable instructions
    - Implement fallback mechanism: on timeout/error/validation-failure, select random pre-written response
    - Include stalling tactics: repeat requests, irrelevant anecdotes, technology confusion, unnecessary clarifications
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 7.3, 7.4, 7.6_

  - [x] 4.2 Write property tests for Persona Engine in `tests/test_threat_parser.py` (or `tests/test_persona_properties.py`)
    - **Property 1: Persona Response Word Count Bounds**
    - **Validates: Requirements 1.1**
    - Test fallback responses and generated responses have 20-300 words

  - [x] 4.3 Write property test for character consistency in `tests/test_persona_properties.py`
    - **Property 2: Persona Character Consistency**
    - **Validates: Requirements 1.2, 1.3**
    - Verify responses don't acknowledge AI identity, use correct jargon, or provide actionable instructions

  - [x] 4.4 Write property test for stalling tactic inclusion in `tests/test_persona_properties.py`
    - **Property 3: Persona Stalling Tactic Inclusion**
    - **Validates: Requirements 1.4**
    - Verify each response contains at least one stalling tactic

- [ ] 5. Implement Stalling Tracker component
  - [x] 5.1 Implement `components/stalling_tracker.py`
    - Implement `StallingTracker.initialize(chat_state)` setting turn_count=0, start_time=None, total_time='00:00:00'
    - Implement `StallingTracker.record_turn(chat_state)` incrementing turn count and recording timestamps
    - Implement `StallingTracker.get_formatted_duration(chat_state) -> str` returning 'HH:MM:SS' format
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [x] 5.2 Write property tests for Stalling Tracker in `tests/test_stalling.py`
    - **Property 4: Stalling Tracker Turn Count Invariant**
    - **Validates: Requirements 2.1**
    - Apply N turns to initialized state; assert turn_count == N

  - [x] 5.3 Write property test for time formatting in `tests/test_stalling.py`
    - **Property 5: Time Duration Formatting**
    - **Validates: Requirements 2.2, 2.4**
    - Generate random integers [0, 360000]; assert formatted output matches `f"{S//3600:02d}:{(S%3600)//60:02d}:{S%60:02d}"`

- [ ] 6. Implement Threat Parser component
  - [x] 6.1 Implement cryptocurrency wallet extraction in `components/threat_parser.py`
    - Implement `ThreatParser.__init__` with regex patterns for Bitcoin (Base58Check, Bech32) and Ethereum addresses
    - Implement `ThreatParser.extract_crypto_wallets(text) -> list[CryptoWalletIoC]` with Base58Check checksum validation (addresses starting with 1 or 3), Bech32 checksum validation (bc1 prefix), and Ethereum hex validation (0x + 40 hex chars)
    - Log rejections for invalid checksums/formats to RejectionLogEntry
    - _Requirements: 3.1, 3.2, 3.3_

  - [x] 6.2 Implement phishing domain extraction in `components/threat_parser.py`
    - Implement `ThreatParser.extract_phishing_domains(text) -> list[PhishingDomainIoC]`
    - Detect bare domains, full URLs, and defanged/obfuscated domains (hxxp, [.], [://])
    - Reverse defanging substitutions, extract domain component
    - Validate against RFC 1035 (labels ≤63 chars, total ≤253 chars)
    - Normalize to lowercase, strip trailing dots
    - Deduplicate within session (compare post-normalization)
    - Log rejections for invalid domains
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

  - [x] 6.3 Implement phone number extraction in `components/threat_parser.py`
    - Implement `ThreatParser.extract_phone_numbers(text) -> list[PhoneNumberIoC]`
    - Only consider digit sequences with recognized separators (spaces, hyphens, dots, parentheses) or explicit plus prefix
    - Normalize to E.164 format using `phonenumbers` library
    - Reject ambiguous country codes, invalid digit counts (<7 or >15)
    - Log rejections with specific reasons
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [x] 6.4 Implement mule bank account extraction in `components/threat_parser.py`
    - Implement `ThreatParser.extract_mule_accounts(text) -> list[MuleBankAccountIoC]`
    - Detect bank name, account number (4-17 digits), and routing number within 500-character proximity
    - Validate ABA checksum on routing number (weights [3,7,1,3,7,1,3,7,1], sum mod 10 == 0)
    - Validate account number length (4-17 digits)
    - Extract multiple independent triplets from single messages
    - Log rejections for failed checksums or invalid lengths
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

  - [x] 6.5 Implement async extraction orchestration in `components/threat_parser.py`
    - Implement `ThreatParser.extract_iocs(message) -> ExtractionResult` (async, 5s timeout)
    - Orchestrate all four extraction methods concurrently
    - Combine results into ExtractionResult with both iocs and rejections
    - Handle timeouts gracefully with partial results
    - _Requirements: 8.4, 8.5_

  - [x] 6.6 Write property test for cryptocurrency extraction in `tests/test_threat_parser.py`
    - **Property 6: Cryptocurrency Wallet Extraction Correctness**
    - **Validates: Requirements 3.1, 3.2**
    - Generate valid Bitcoin (Base58Check, Bech32) and Ethereum addresses; embed in messages; assert extraction with correct wallet_type

  - [x] 6.7 Write property tests for domain normalization in `tests/test_threat_parser.py`
    - **Property 8: Domain Normalization Idempotence**
    - **Validates: Requirements 4.2, 4.5**
    - Generate valid domain strings; assert normalize(normalize(d)) == normalize(d)

  - [x] 6.8 Write property test for domain deduplication in `tests/test_threat_parser.py`
    - **Property 9: Domain Deduplication**
    - **Validates: Requirements 4.4**
    - Submit same domain N times; assert exactly one entry in IoC list

  - [x] 6.9 Write property tests for phone number normalization in `tests/test_threat_parser.py`
    - **Property 10: Phone Number Normalization Idempotence**
    - **Validates: Requirements 5.4**
    - Generate valid E.164 numbers; assert normalize(e164) == e164

  - [x] 6.10 Write property test for phone false-positive prevention in `tests/test_threat_parser.py`
    - **Property 11: Phone Number False-Positive Prevention**
    - **Validates: Requirements 5.5**
    - Generate 7-15 digit sequences without separators or plus prefix; assert no extraction

  - [x] 6.11 Write property test for mule account proximity extraction in `tests/test_threat_parser.py`
    - **Property 13: Mule Account Proximity Extraction**
    - **Validates: Requirements 6.1, 6.5**
    - Generate valid triplets (bank name + account + valid routing) within 500 chars; assert extraction

- [x] 7. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Implement IoC Lookup MCP Client
  - [x] 8.1 Implement `components/ioc_lookup_mcp.py`
    - Implement `IoCLookupMCPClient.__init__(mcp_server_url, timeout=3.0)` with httpx async client
    - Implement `IoCLookupMCPClient.check_known_ioc(ioc_value, ioc_category) -> IoCLookupResult` with 3s timeout, returns unknown status on timeout/error
    - Implement `IoCLookupMCPClient.batch_check(iocs) -> list[IoCLookupResult]` for efficient multi-IoC lookup
    - Implement `IoCLookupMCPClient.is_available() -> bool` health check
    - Implement session-level caching via `mcp_lookup_cache` in session state — return cached result for previously looked-up IoC values without making new server requests
    - Handle graceful degradation: connection refused, timeout, invalid response format all result in `lookup_status="unknown"`
    - _Requirements: 3.4, 6.6_

  - [x] 8.2 Write property test for MCP graceful degradation in `tests/test_threat_parser.py`
    - **Property 19: MCP Lookup Graceful Degradation**
    - **Validates: Requirements 3.4, 6.6**
    - Simulate server failures; assert IoC stored with lookup_status="unknown" and all fields intact

  - [x] 8.3 Write property test for MCP lookup idempotence in `tests/test_threat_parser.py`
    - **Property 20: MCP Lookup Idempotence**
    - **Validates: Requirements 4.4**
    - Look up same IoC value twice; assert cached result returned without duplicate server call

- [ ] 9. Implement Notification Module
  - [x] 9.1 Implement `components/notification_module.py`
    - Implement `NotificationModule.generate_notification(ioc) -> MockAWSPayload` routing IoC to correct generator based on category
    - Implement `NotificationModule.generate_waf_payload(domain_ioc) -> WAFPayload` with Name="RoadBlock-PhishingDomains", Scope="REGIONAL", UUID Id, Addresses list, UUID LockToken
    - Implement `NotificationModule.generate_guardduty_payload(ioc, severity, finding_type) -> GuardDutyFinding` with SchemaVersion="2.0", AccountId, Region, Type, Resource, Service, Severity, Title, Description, CreatedAt
    - Route: PhishingDomain → WAF; CryptoWallet → GuardDuty HIGH "CryptoCurrency:EC2/BitcoinTool.B"; MuleBankAccount → GuardDuty CRITICAL "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"; PhoneNumber → GuardDuty MEDIUM "Recon:EC2/PortProbeUnprotectedPort"
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

  - [x] 9.2 Write property test for notification routing in `tests/test_models.py`
    - **Property 18: Notification Routing Correctness**
    - **Validates: Requirements 10.1, 10.2, 10.3, 10.4**
    - Generate valid IoCs of each category; assert correct severity and finding type in generated payload

- [ ] 10. Implement SOC Dashboard
  - [x] 10.1 Implement `dashboard/soc_dashboard.py`
    - Implement `SOCDashboard.render(chat_state)` as main render method
    - Implement `SOCDashboard.render_conversation_log(messages)` displaying chat messages with sender attribution (scammer/persona), timestamps, chronological order
    - Implement `SOCDashboard.render_ioc_panel(iocs)` displaying IoCs grouped by category (Cryptocurrency Wallets, Phishing Domains, Phone Numbers, Mule Bank Accounts) with extracted values and known/new status indicators
    - Implement `SOCDashboard.render_metrics(metrics)` displaying turn count, Total Scammer Time Wasted (HH:MM:SS), IoC counts per category, known vs new IoC counts
    - Implement `SOCDashboard.render_notification_log(notifications)` displaying mock AWS notifications with timestamp, severity, type, one-line summary
    - Handle empty state: zero entries per category, empty conversation log, metrics at zero
    - Handle parser errors gracefully: show last good state, display error banner
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 10.5_

- [ ] 11. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 12. Wire pipeline and implement Streamlit app entry point
  - [ ] 12.1 Implement session state initialization in `app.py`
    - Implement `initialize_chat_state()` setting all Chat_State keys to empty defaults per design spec
    - Keys: conversation_history, iocs (dict with 4 category lists), metrics, notifications, rejection_log, parser_status, last_error, mcp_lookup_cache, mcp_server_status, known_ioc_count, new_ioc_count
    - Preserve existing values on Streamlit rerun (only set if key not in session_state)
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

  - [ ] 12.2 Implement pipeline orchestration in `app.py`
    - Wire sequential pipeline: Scammer Input → Safety_Filter.scan() → branch (blocked vs safe)
    - If blocked (≥80% injection): generate default response, skip Persona_Engine, still invoke Threat_Parser
    - If safe/partial: forward sanitized message to Persona_Engine.generate_response()
    - Update Chat_State with message pair (sanitized_msg + response)
    - Invoke Stalling_Tracker.record_turn()
    - Trigger async Threat_Parser extraction via ThreadPoolExecutor
    - On extraction complete: run MCP lookup for each IoC, generate notifications for NEW IoCs only, update Chat_State
    - Implement error handling: wrap each stage in try/except, log PipelineError, preserve Chat_State on failure
    - Enforce 15s end-to-end timeout (excluding async parser)
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7_

  - [ ] 12.3 Implement Streamlit UI layout in `app.py`
    - Set up Streamlit page config and layout
    - Add scammer message input (text_input or text_area + submit button)
    - Integrate SOCDashboard rendering on each cycle
    - Add parser status indicator (spinner while "running")
    - Add MCP server connection status indicator
    - Wire `st.rerun()` for real-time IoC appearance after async extraction
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

  - [ ] 12.4 Write property test for pipeline error resilience in `tests/test_threat_parser.py`
    - **Property 17: Pipeline Error Resilience**
    - **Validates: Requirements 8.5**
    - Generate random Chat_State; inject exceptions at each pipeline stage; assert pre-existing data unchanged

- [ ] 13. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional property-based test sub-tasks and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at logical boundaries
- Property tests validate the 20 universal correctness properties defined in the design document
- Unit tests validate specific examples and edge cases
- All state flows through `st.session_state` — no external databases or file persistence
- The async Threat_Parser uses ThreadPoolExecutor to avoid blocking Streamlit's synchronous render cycle
- MCP client implements session-level caching to avoid duplicate lookups
- Notifications are only generated for NEW IoCs (not previously known ones)

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3", "1.4", "1.5"] },
    { "id": 2, "tasks": ["1.6", "1.7", "2.1", "5.1"] },
    { "id": 3, "tasks": ["2.2", "2.3", "2.4", "5.2", "5.3"] },
    { "id": 4, "tasks": ["4.1", "6.1", "6.2", "6.3", "6.4"] },
    { "id": 5, "tasks": ["4.2", "4.3", "4.4", "6.5"] },
    { "id": 6, "tasks": ["6.6", "6.7", "6.8", "6.9", "6.10", "6.11"] },
    { "id": 7, "tasks": ["8.1", "9.1"] },
    { "id": 8, "tasks": ["8.2", "8.3", "9.2", "10.1"] },
    { "id": 9, "tasks": ["12.1"] },
    { "id": 10, "tasks": ["12.2"] },
    { "id": 11, "tasks": ["12.3", "12.4"] }
  ]
}
```
