# Implementation Plan

## Overview

Fix for the outbound email being silently dropped when `_run_extraction` or `_update_thread` throws an exception in `_feed_to_pipeline`. The fix moves the outbound enqueue to immediately after response generation and wraps downstream steps in isolated try/except blocks.

## Task Dependency Graph

```json
{
  "waves": [
    {"tasks": ["1", "2"]},
    {"tasks": ["3.1"]},
    {"tasks": ["3.2", "3.3"]},
    {"tasks": ["4"]}
  ]
}
```

## Tasks

- [ ] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Outbound Email Lost When Downstream Steps Throw
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the outbound enqueue is skipped when `_run_extraction` or `_update_thread` raises
  - **Scoped PBT Approach**: Scope the property to concrete failing cases: mock `_run_extraction` to raise `RuntimeError`, mock `_update_thread` to raise `KeyError`, and combinations thereof
  - Test setup: construct a valid `EmailMessage` and `ClassificationResult`, patch `SafetyFilter.scan` to return non-blocked, patch `_generate_persona_response` to return a known response string
  - Use Hypothesis `@given` to generate random exception types from `[RuntimeError, KeyError, asyncio.TimeoutError, ValueError]` and random failure points (`extraction_only`, `thread_only`, `both`)
  - Assert: `_enqueue_result` is called with type `"outbound"` and body matching the generated response (from Bug Condition + Expected Behavior in design)
  - Run test on UNFIXED code
  - **EXPECTED OUTCOME**: Test FAILS because `_enqueue_result("outbound", ...)` is never called when downstream steps throw (this proves the bug exists)
  - Document counterexamples: e.g., `_run_extraction` raises `RuntimeError` -> `_enqueue_result` never called with "outbound"
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Happy Path and Blocked Path Behavior Unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - Observe on UNFIXED code: when no exceptions are raised, `_feed_to_pipeline` enqueues outbound with body == persona response
  - Observe on UNFIXED code: when safety filter blocks (`is_blocked=True`), `_handle_blocked_message` enqueues outbound with body == `_DEFAULT_BLOCKED_RESPONSE`
  - Write property-based test with Hypothesis: generate random `EmailMessage` inputs (random sender, subject, body), random persona response strings
  - Property 2a - Happy path preservation: for all inputs where safety filter does not block AND no exceptions are raised, outbound is enqueued with body == generated response, `_run_extraction` is called, `_update_thread` is called
  - Property 2b - Blocked path preservation: for all inputs where safety filter blocks, `_handle_blocked_message` is called and outbound body == `_DEFAULT_BLOCKED_RESPONSE`
  - Property 2c - Outbound content integrity: outbound email has correct `to_address` (reply_to or sender), correct subject (composed via `_smtp_client.compose_reply_subject`), correct `in_reply_to` (message_id)
  - Verify all tests PASS on UNFIXED code (confirms baseline behavior)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] 3. Fix for outbound email lost when downstream steps throw in `_feed_to_pipeline`

  - [ ] 3.1 Implement the fix in `components/email_ingestion.py`
    - Move `OutboundEmail` creation and `_enqueue_result("outbound", ...)` to immediately after `response_content` is set (after Step 3), before IoC extraction (Step 4) and thread update (Step 5)
    - Wrap `_run_extraction(threat_parser, email_msg.body)` in its own `try/except Exception` block; log warning on failure but do not propagate
    - Wrap `_update_thread(email_msg)` in its own `try/except Exception` block; log warning on failure but do not propagate
    - Remove the outbound enqueue from Step 6 (it no longer exists as a separate step)
    - Resulting order: Safety Filter -> Generate Response -> Enqueue Outbound -> Extract IoCs (best-effort) -> Update Thread (best-effort)
    - _Bug_Condition: isBugCondition(input) where safety filter not blocked AND response generated AND (_run_extraction raises OR _update_thread raises)_
    - _Expected_Behavior: outbound email always enqueued once response_content is set, regardless of downstream failures_
    - _Preservation: _handle_blocked_message unchanged; happy-path outbound content identical; extraction and thread update still execute on success_
    - _Requirements: 2.1, 2.2, 2.3, 3.1, 3.3, 3.4, 3.5_

  - [ ] 3.2 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Outbound Always Enqueued After Response Generation
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 encodes the expected behavior (outbound enqueued regardless of downstream failures)
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2, 2.3_

  - [ ] 3.3 Verify preservation tests still pass
    - **Property 2: Preservation** - Happy Path and Blocked Path Behavior Unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm happy-path outbound content, blocked-path behavior, extraction calls, and thread update calls all remain identical
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] 4. Checkpoint - Ensure all tests pass
  - Run full test suite: `pytest tests/ --hypothesis-show-statistics`
  - Ensure Property 1 (bug condition/expected behavior) passes
  - Ensure Property 2 (preservation) passes
  - Ensure no existing tests regressed
  - Ask the user if questions arise

## Notes

- Test file location: `tests/test_fix_default_response_send.py`
- The bug only affects the non-blocked branch of `_feed_to_pipeline`; `_handle_blocked_message` already enqueues before extraction
- Property-based tests use Hypothesis with `@settings(max_examples=200)` per project conventions
- The fix mirrors the pattern already established in `_handle_blocked_message`
