---
inclusion: always
version: 1.0.0
---

# EARS - Easy Approach to Requirements Syntax

Reference for writing unambiguous, testable acceptance criteria in Kiro specs.

## EARS Patterns

### Event-Driven (WHEN/SHALL)
`WHEN <trigger>, THE <system> SHALL <response>`
Example: WHEN a user submits a scam message, THE System SHALL extract all IoCs and display them in the SOC panel.

### Conditional (IF/THEN/SHALL)
`IF <condition>, THEN THE <system> SHALL <response>`
Example: IF the message contains a prompt injection pattern, THEN THE System SHALL sanitize the input before passing to the LLM.

### State-Driven (WHILE/SHALL)
`WHILE <state>, THE <system> SHALL <behavior>`
Example: WHILE the persona engine is in conversation mode, THE System SHALL maintain the confused elder character without breaking.

### Optional/Variant (WHERE/SHALL)
`WHERE <option/variant>, THE <system> SHALL <behavior>`
Example: WHERE the IoC is a cryptocurrency wallet, THE System SHALL validate the address checksum before reporting.

### Compound
Combine patterns: `WHILE <state>, WHEN <trigger>, IF <condition>, THEN THE <system> SHALL <response>`

## Conversion Rules

- Identify the trigger, condition, or state that activates the behavior
- Use SHALL for mandatory behavior (not "should", "may", "might")
- One behavior per criterion (split compound requirements)
- Make every criterion testable with a clear pass/fail outcome
- Avoid vague terms ("user-friendly", "fast", "efficient") — specify exact behaviors

## Property Extraction Patterns

When writing design.md, extract correctness properties from testable acceptance criteria:

### Round-Trip
*For any* X, applying operation then its inverse should return equivalent X.
Use for: serialization/deserialization, Pydantic model JSON round-trips.

### Invariant
*For any* X, after operation Y, property Z should still hold.
Use for: IoC extraction always returns valid Pydantic models, safety filter never passes injection.

### Validation
*For any* invalid input X, operation should reject it.
Use for: malformed wallet addresses, invalid phone numbers, injection patterns.

### State Transition
*For any* state X, transition Y should result in valid state Z.
Use for: conversation state changes, stalling metric updates.

Each property must reference specific requirements (e.g., "Validates: Requirements 1.2, 3.4").
