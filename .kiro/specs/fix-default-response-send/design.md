# Fix Default Response Send - Bugfix Design

## Overview

`_feed_to_pipeline` enqueues the outbound email at Step 6, after IoC extraction (Step 4) and thread update (Step 5). If either throws, the outer `try/except` catches the exception and returns, silently dropping the reply. The fix moves the OutboundEmail creation and `_enqueue_result("outbound", ...)` to immediately after persona response generation, matching the pattern already used in `_handle_blocked_message`.

## Glossary

- **Bug_Condition (C)**: Any execution of `_feed_to_pipeline` where `_run_extraction` or `_update_thread` raises an exception after response generation but before the outbound enqueue at Step 6
- **Property (P)**: The outbound email is always enqueued once a response is generated, regardless of downstream failures
- **Preservation**: `_handle_blocked_message` behavior, successful-path ordering of extraction/thread update, and outbound email content remain unchanged
- **`_feed_to_pipeline`**: Method in `components/email_ingestion.py` that routes confirmed scam emails through the engagement pipeline
- **`_handle_blocked_message`**: Method that handles safety-blocked emails; already enqueues outbound before extraction

## Bug Details

### Bug Condition

The bug manifests when `_feed_to_pipeline` generates a persona response (or fallback) but a subsequent step throws before the outbound enqueue at Step 6.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type (EmailMessage, ClassificationResult)
  OUTPUT: boolean

  RETURN safetyFilter.scan(input.email.body).is_blocked == FALSE
         AND _generate_persona_response(...) returns successfully
         AND (_run_extraction(...) raises Exception
              OR _update_thread(...) raises Exception)
END FUNCTION
```

### Examples

- Persona response generated successfully, `_run_extraction` raises `asyncio.TimeoutError` -> outbound never enqueued, reply lost
- Persona response generated successfully, `_update_thread` raises `KeyError` on malformed thread data -> outbound never enqueued, reply lost
- Persona response falls back to `_DEFAULT_BLOCKED_RESPONSE` due to LLM failure, then `_run_extraction` raises -> outbound never enqueued, fallback reply lost

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- `_handle_blocked_message` continues to enqueue outbound before extraction (already correct)
- The outbound email body matches the generated persona response exactly
- IoC extraction and thread update still execute (best-effort) after enqueue
- OutboundEmail fields (to_address, subject, body, in_reply_to) are constructed identically

**Scope:**
All inputs where safety filter blocks the message (`is_blocked == True`) are unaffected. The fix only reorders steps within the non-blocked branch of `_feed_to_pipeline`.

## Hypothesized Root Cause

The ordering in `_feed_to_pipeline` was written with the assumption that Steps 4-5 (extraction, thread update) would not throw, or that failures there were acceptable losses. In practice, `_run_extraction` wraps async operations that can timeout or fail, and `_update_thread` manipulates dict state that can raise on malformed data.

The root cause is simply that the outbound enqueue is placed after fallible operations instead of before them.

## Correctness Properties

Property 1: Bug Condition - Outbound Enqueue Invariant

_For any_ email processed through `_feed_to_pipeline` where the safety filter does not block and persona response generation succeeds, the outbound email SHALL be enqueued regardless of whether `_run_extraction` or `_update_thread` succeeds or fails.

**Validates: Requirements 2.1, 2.2, 2.3**

Property 2: Preservation - Response Content Integrity

_For any_ email processed through `_feed_to_pipeline`, the outbound email body SHALL match the generated persona response (or fallback) exactly, preserving the same content that would have been enqueued in the original code on the happy path.

**Validates: Requirements 3.1, 3.5**

Property 3: Preservation - Blocked Message Path Unchanged

_For any_ email where the safety filter blocks the message, `_handle_blocked_message` SHALL continue to enqueue the default response before extraction, producing identical behavior to the unfixed code.

**Validates: Requirements 3.2**

## Fix Implementation

### Changes Required

**File**: `components/email_ingestion.py`

**Function**: `_feed_to_pipeline`

**Specific Changes**:
1. **Move outbound enqueue to immediately after response generation**: Create and enqueue the `OutboundEmail` right after `response_content` is set (after Step 3), before Step 4 (extraction) and Step 5 (thread update).

2. **Wrap extraction and thread update in isolated try/except**: Steps 4 and 5 should each have their own exception handling so one failing doesn't prevent the other from running. Log warnings on failure but don't propagate.

3. **Remove the outbound enqueue from Step 6**: It no longer exists as a separate step; it's part of Step 3.

4. **Keep thread history append before extraction**: The persona response thread append stays in its current position since it doesn't throw in a meaningful way.

The resulting order mirrors `_handle_blocked_message`:
```
1. Safety Filter scan
2. Generate persona response
3. Enqueue outbound email  <-- moved here
4. Extract IoCs (best-effort, isolated try/except)
5. Update thread (best-effort, isolated try/except)
```

## Testing Strategy

### Validation Approach

Two-phase: first demonstrate the bug exists on unfixed code, then verify the fix resolves it and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Confirm that on unfixed code, an exception in `_run_extraction` or `_update_thread` causes the outbound enqueue to be skipped.

**Test Plan**: Mock `_run_extraction` to raise an exception, call `_feed_to_pipeline`, and assert that `_enqueue_result("outbound", ...)` was never called.

**Test Cases**:
1. **Extraction failure**: Mock `_run_extraction` to raise `RuntimeError` -> outbound not enqueued (will fail on unfixed code)
2. **Thread update failure**: Mock `_update_thread` to raise `KeyError` -> outbound not enqueued (will fail on unfixed code)
3. **Both fail**: Mock both to raise -> outbound not enqueued (will fail on unfixed code)

**Expected Counterexamples**:
- `_enqueue_result` is never called with type "outbound" when downstream steps throw

### Fix Checking

**Goal**: After fix, verify outbound is always enqueued when response generation succeeds.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  result := _feed_to_pipeline_fixed(input)
  ASSERT "outbound" in enqueued_results
  ASSERT enqueued_results["outbound"].body == response_content
END FOR
```

### Preservation Checking

**Goal**: Verify that on the happy path (no exceptions), the fixed code produces identical outbound emails and still runs extraction/thread update.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT _feed_to_pipeline_fixed(input) produces same outbound email as original
  ASSERT _run_extraction is still called
  ASSERT _update_thread is still called
END FOR
```

**Testing Approach**: Property-based testing generates random EmailMessage inputs and verifies the outbound email is always enqueued with correct content, regardless of whether downstream steps throw.

**Test Cases**:
1. **Happy path preservation**: No mocks throwing, verify outbound enqueued with correct body
2. **Blocked message unchanged**: Safety filter blocks, verify `_handle_blocked_message` still called identically
3. **Outbound content matches response**: For any generated response, outbound body == response_content

### Unit Tests

- Mock `_run_extraction` to raise, verify outbound still enqueued
- Mock `_update_thread` to raise, verify outbound still enqueued
- Mock both to raise, verify outbound still enqueued
- Happy path: verify all steps execute and outbound matches response

### Property-Based Tests

- Generate random EmailMessage inputs with Hypothesis, mock extraction to randomly succeed or fail, assert outbound is always enqueued when response generation succeeds
- Generate random response strings, verify outbound body always equals the response content exactly

### Integration Tests

- End-to-end: feed a real-ish email through the pipeline with a flaky ThreatParser mock, verify outbound is queued
- Verify `_handle_blocked_message` path is completely untouched by the change
