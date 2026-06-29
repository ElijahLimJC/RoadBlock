# Conventions

## Code Style

- Use **type hints** on all function signatures and class attributes
- Prefer `snake_case` for functions, variables, and modules; `PascalCase` for classes
- Maximum line length: 100 characters (enforced via Ruff)
- Use `"""docstrings"""` on all public functions and classes — one-liner for trivial helpers, multi-line (Google style) for complex logic
- Imports ordered: stdlib → third-party → local, separated by blank lines (enforced via Ruff `isort`)

## Scope Containment (Monolithic Lock)

- **Single process only** — all UI logic, background parsing loops, and state manipulation run within one Streamlit process. No microservices, no worker queues, no external process spawning.
- **State lives in `st.session_state` exclusively** — no external state stores, no Redis, no file-based caching.
- **Zero persistence** — never generate SQLAlchemy models, SQLite connectors, database migrations, or external ORM setups. All data remains in-memory for the session lifetime.
- **No Docker/infrastructure scaffolding** — no Dockerfiles, docker-compose, or deployment configs unless explicitly requested.

## Pydantic Models

- All data models inherit from `pydantic.BaseModel`
- Use `Field(...)` with descriptions for fields that appear in serialized output
- Validators use `@field_validator` (Pydantic v2 style), not legacy `@validator`
- Models are immutable by default (`model_config = ConfigDict(frozen=True)`) unless mutation is explicitly needed
- Prefer `Literal` and `Enum` types over raw strings for finite value sets
- **Strict separation** — Pydantic schemas handle validation only; never mix model definitions with UI rendering logic

## Noisy Input Defenses (Parser Shield)

- **Total exception isolation** — every text-parsing function in `threat_parser.py` must be wrapped in an explicit `try/except Exception` block. No unguarded regex or string operations.
- **Safe fallbacks** — if a regex match or Pydantic validation fails, return an empty list (`[]`) or `None`. Never let a parser crash propagate to the calling thread.
- **Graceful degradation over correctness** — a missed IoC is acceptable; a crashed pipeline is not. Partial extraction results are always returned.
- **Unicode-safe** — all string operations must handle arbitrary Unicode input without raising encoding errors.

## LLM Configuration (Character Lock)

- **Prompt externalization** — the persona system prompt must live as a standalone string variable in `persona_engine.py` (or a dedicated `.txt` asset). Never embed prompt text inline within UI layout functions.
- **Token/memory truncation** — chat memory management must use aggressive truncation: keep only the last 10 conversation turns before sending to the LLM. This prevents context-limit errors mid-session.
- **Prompt construction is deterministic** — build the final prompt from (system_prompt + truncated_history + current_message). No dynamic prompt assembly scattered across modules.

## UI Rendering (Crash Prevention)

- **Defensive initialization** — every `st.session_state.variable` access must be preceded by an initialization guard at the top of `app.py`:
  ```python
  if "variable" not in st.session_state:
      st.session_state.variable = default_value
  ```
- **Callback separation** — structural state mutations (clear chat, append metrics, reset session) must occur inside dedicated Streamlit callback functions (`on_change`, `on_click`). Never mutate state inline during the render pass.
- **Top-down safety** — assume the entire script re-executes on every interaction. No code path should depend on execution order beyond what Streamlit guarantees.
- **No nested `st.rerun()` chains** — if a rerun is needed, it must be the last statement in a callback, never inside a loop or conditional tree.

## Error Handling

- Never swallow exceptions silently — at minimum log at `warning` level
- Use domain-specific exception classes (e.g., `ExtractionError`, `ValidationError`) rather than bare `Exception`
- Streamlit-facing code catches exceptions and renders user-friendly messages via `st.error()`
- Pipeline stages return `Result`-style objects (success/failure) rather than raising on expected failures

## Async Patterns

- Async functions are prefixed with `async_` only when a sync counterpart exists in the same module
- Use `asyncio.TaskGroup` (Python 3.11+) for concurrent IoC extraction tasks
- Never block the Streamlit main thread — offload CPU/IO work via `run_in_executor`
- Timeouts are mandatory on all external calls (LLM, MCP lookups) — default 30s

## Testing

- Test files mirror source: `components/threat_parser.py` → `tests/test_threat_parser.py`
- Property-based tests use `@given` with explicit `@settings(max_examples=200)` unless overridden
- Use `@pytest.mark.parametrize` for example-based edge cases alongside Hypothesis properties
- Fixtures go in `tests/conftest.py` — no fixture duplication across test files
- All Pydantic models must have a round-trip serialization property test

## Environment

- **All code runs inside a conda virtual environment** — never install packages globally or use system Python.
- Activate the conda env before running any commands: `conda activate roadblock`
- If the environment doesn't exist, create it: `conda create -n roadblock python=3.11 -y`
- Install dependencies into the conda env: `pip install -r requirements.txt` (after activation)
- Never use `sudo pip install` or install outside the conda env boundary.

## Git & Commits

- Commit messages follow Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`
- One logical change per commit — don't bundle unrelated edits
- Branch naming: `feature/<short-slug>`, `fix/<short-slug>`, `chore/<short-slug>`

## Security

- All scammer input is untrusted — sanitize before any LLM prompt inclusion
- Prompt injection patterns are checked deterministically before LLM calls, never after
- No secrets in source — use environment variables or `.env` (excluded from git)
- Log scammer messages at `debug` level only; never echo raw input to `info` or higher
