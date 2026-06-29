"""Property-based tests for Persona Engine.

Tests validate correctness properties for the PersonaEngine component:
- Property 1: Persona Response Word Count Bounds (Requirements 1.1)
- Property 2: Persona Character Consistency (Requirements 1.2, 1.3)
- Property 3: Persona Stalling Tactic Inclusion (Requirements 1.4)
"""

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from components.persona_engine import FALLBACK_RESPONSES, STALLING_TACTICS, PersonaEngine
from models.chat_models import ChatMessage, PersonaResponse


# --- Strategies ---

scammer_messages = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")),
    min_size=1,
    max_size=500,
)

chat_message_strategy = st.builds(
    ChatMessage,
    sender=st.sampled_from(["scammer", "persona"]),
    content=st.text(min_size=1, max_size=200),
)

conversation_history_strategy = st.lists(
    chat_message_strategy,
    min_size=0,
    max_size=10,
)


# --- Property 1: Persona Response Word Count Bounds ---


class TestPersonaResponseWordCountBounds:
    """Property 1: Persona Response Word Count Bounds.

    **Validates: Requirements 1.1**

    All fallback responses and generated responses (in fallback-only mode)
    must have a word count between 20 and 300, inclusive.
    """

    @given(index=st.integers(min_value=0, max_value=len(FALLBACK_RESPONSES) - 1))
    @settings(max_examples=200)
    def test_fallback_responses_word_count_within_bounds(self, index: int) -> None:
        """Every pre-written fallback response has 20-300 words."""
        fallback = FALLBACK_RESPONSES[index]
        content = fallback["content"]
        word_count = len(content.split())
        assert 20 <= word_count <= 300, (
            f"Fallback response at index {index} has {word_count} words, "
            f"expected 20-300. Content: {content!r:.100}"
        )

    @given(
        sanitized_message=scammer_messages,
        conversation_history=conversation_history_strategy,
    )
    @settings(max_examples=200)
    def test_generate_response_word_count_within_bounds(
        self,
        sanitized_message: str,
        conversation_history: list[ChatMessage],
    ) -> None:
        """generate_response in fallback-only mode returns 20-300 word responses."""
        assume(len(sanitized_message.strip()) > 0)

        engine = PersonaEngine(llm_client=None)
        response = engine.generate_response(sanitized_message, conversation_history)

        assert isinstance(response, PersonaResponse)
        word_count = len(response.content.split())
        assert 20 <= word_count <= 300, (
            f"Response has {word_count} words, expected 20-300. "
            f"Content: {response.content!r:.100}"
        )


# --- Property 2: Persona Character Consistency ---


class TestPersonaCharacterConsistency:
    """Property 2: Persona Character Consistency.

    **Validates: Requirements 1.2, 1.3**

    For any conversation history and any sanitized input message, the
    Persona_Engine response SHALL NOT contain:
    (a) acknowledgment of being an AI or automated system,
    (b) correctly used technical jargon,
    (c) accurate step-by-step technical instructions,
    (d) valid credentials or real financial details.
    """

    def test_all_fallback_responses_pass_validation(self) -> None:
        """ALL fallback responses must pass validate_response().

        **Validates: Requirements 1.2, 1.3**
        """
        engine = PersonaEngine(llm_client=None)

        for i, fallback in enumerate(FALLBACK_RESPONSES):
            content = fallback["content"]
            assert engine.validate_response(content), (
                f"Fallback response #{i} failed validation: {content[:80]}..."
            )

    @given(
        message=st.text(min_size=1, max_size=200),
    )
    @settings(max_examples=200)
    def test_fallback_mode_always_produces_valid_responses(
        self, message: str
    ) -> None:
        """generate_response in fallback-only mode always passes validate_response().

        **Validates: Requirements 1.2, 1.3**
        """
        engine = PersonaEngine(llm_client=None)
        history: list[ChatMessage] = []

        response = engine.generate_response(message, history)

        assert engine.validate_response(response.content), (
            f"Fallback response failed validation for input '{message[:50]}': "
            f"{response.content[:80]}..."
        )

    @given(
        message=st.text(min_size=1, max_size=200),
        history_size=st.integers(min_value=0, max_value=5),
    )
    @settings(max_examples=200)
    def test_fallback_mode_with_history_produces_valid_responses(
        self, message: str, history_size: int
    ) -> None:
        """generate_response with conversation history passes validation.

        **Validates: Requirements 1.2, 1.3**
        """
        engine = PersonaEngine(llm_client=None)

        history: list[ChatMessage] = []
        for i in range(history_size):
            history.append(
                ChatMessage(sender="scammer", content=f"Scammer message {i}")
            )
            history.append(
                ChatMessage(sender="persona", content=f"Oh dear, what was that?")
            )

        response = engine.generate_response(message, history)

        assert engine.validate_response(response.content), (
            f"Fallback response failed validation with history_size={history_size}, "
            f"input='{message[:50]}': {response.content[:80]}..."
        )



# --- Property 3: Persona Stalling Tactic Inclusion ---


class TestStallingTacticInclusion:
    """Property 3: Persona Stalling Tactic Inclusion.

    **Validates: Requirements 1.4**

    For any generated Persona_Engine response, the response SHALL contain
    at least one recognizable stalling tactic from the defined set:
    repetition_request, irrelevant_anecdote, technology_confusion,
    unnecessary_clarification, deliberate_misunderstanding.
    """

    @given(idx=st.integers(min_value=0, max_value=len(FALLBACK_RESPONSES) - 1))
    @settings(max_examples=200)
    def test_all_fallback_responses_have_valid_tactic_field(self, idx: int) -> None:
        """Every fallback response has a 'tactic' key mapping to a valid STALLING_TACTICS value.

        **Validates: Requirements 1.4**
        """
        fallback = FALLBACK_RESPONSES[idx]
        assert "tactic" in fallback, f"Fallback at index {idx} missing 'tactic' key"
        assert fallback["tactic"] in STALLING_TACTICS, (
            f"Fallback at index {idx} has invalid tactic '{fallback['tactic']}'. "
            f"Expected one of {STALLING_TACTICS}"
        )

    @given(idx=st.integers(min_value=0, max_value=len(FALLBACK_RESPONSES) - 1))
    @settings(max_examples=200)
    def test_identify_stalling_tactic_returns_valid_tactic_for_fallbacks(
        self, idx: int
    ) -> None:
        """_identify_stalling_tactic returns a value from STALLING_TACTICS for every fallback response.

        **Validates: Requirements 1.4**
        """
        engine = PersonaEngine(llm_client=None)
        fallback = FALLBACK_RESPONSES[idx]
        identified_tactic = engine._identify_stalling_tactic(fallback["content"])
        assert identified_tactic in STALLING_TACTICS, (
            f"_identify_stalling_tactic returned '{identified_tactic}' for fallback "
            f"at index {idx}, which is not in STALLING_TACTICS"
        )

    @given(message=scammer_messages, history=conversation_history_strategy)
    @settings(max_examples=200)
    def test_generate_response_fallback_mode_always_has_stalling_tactic(
        self, message: str, history: list[ChatMessage]
    ) -> None:
        """generate_response in fallback-only mode always returns PersonaResponse
        with a non-empty stalling_tactic_used from STALLING_TACTICS.

        **Validates: Requirements 1.4**
        """
        assume(len(message.strip()) > 0)
        engine = PersonaEngine(llm_client=None)
        response = engine.generate_response(message, history)

        assert isinstance(response, PersonaResponse)
        assert response.stalling_tactic_used is not None, (
            "generate_response returned PersonaResponse with stalling_tactic_used=None"
        )
        assert response.stalling_tactic_used != "", (
            "generate_response returned PersonaResponse with empty stalling_tactic_used"
        )
        assert response.stalling_tactic_used in STALLING_TACTICS, (
            f"stalling_tactic_used '{response.stalling_tactic_used}' is not in STALLING_TACTICS"
        )
