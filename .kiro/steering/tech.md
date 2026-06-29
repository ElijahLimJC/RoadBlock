# Tech Stack

## Language & Runtime

- **Python** (primary language)
- **asyncio** for concurrent threat parsing within the Streamlit event loop

## Frameworks & Libraries

- **Streamlit** — UI framework, session state management, real-time dashboard
- **Pydantic** — Data models, validation, IoC schema definitions
- **LLM client** (Google Gemini via `google-generativeai` SDK) — Persona response generation
- **phonenumbers** (expected) — E.164 phone number parsing and validation
- **base58** / **bech32** (expected) — Cryptocurrency address checksum validation
- **MCP client** — Model Context Protocol integration for IoC lookups against external threat intel

## Architecture Pattern

- Monolithic single-process app
- Streamlit session-based state (`st.session_state`)
- Async extraction pipeline via `asyncio.run_in_executor` or `asyncio.create_task`
- Pattern-based prompt injection detection (deterministic, not ML-based)

## Common Commands

```bash
# Run the application
streamlit run app.py

# Run tests (when test suite exists)
pytest

# Run tests with property-based testing
pytest --hypothesis-show-statistics

# Type checking
mypy .

# Linting
ruff check .
```

## Testing Strategy

- **Property-based testing** is a core methodology for this project
- Use **Hypothesis** (or equivalent) for PBT of IoC extraction, normalization idempotence, serialization round-trips, and validation logic
- Correctness properties are formally defined in the design document and must be encoded as executable tests
