"""Tests for PersonaEngine with mocked Mistral LLM client.

Tests validate:
- Response word count bounds (20-300 words)
- Fallback mechanism on timeout/error/validation failure
- Response validation (no AI acknowledgment, no jargon, no instructions)
- Stalling tactic identification
- History truncation
- Prompt construction
"""

import time
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from components.persona_engine import (
    FALLBACK_RESPONSES,
    PERSONA_SYSTEM_PROMPT,
    STALLING_TACTICS,
    PersonaEngine,
    _MAX_HISTORY_TURNS,
)
from models.chat_models import ChatMessage, PersonaResponse


# --- Fixtures ---


@pytest.fixture
def mock_mistral_client():
    """Create a mock Mistral client."""
    client = MagicMock()
    # Default: return a valid in-character response
    response = MagicMock()
    choice = MagicMock()
    choice.message.content = (
        "Oh dear, could you repeat that? I was just thinking about my "
        "grandson Tommy and his little science project. He made a volcano "
        "with baking soda! It reminded me of when Harold used to do chemistry "
        "experiments in the garage. What were you saying about my computer, love?"
    )
    response.choices = [choice]
    client.chat.complete.return_value = response
    return client


@pytest.fixture
def engine(mock_mistral_client):
    """Create a PersonaEngine with the mocked Mistral client."""
    return PersonaEngine(llm_client=mock_mistral_client)


@pytest.fixture
def fallback_engine():
    """Create a PersonaEngine in fallback-only mode (no LLM client)."""
    return PersonaEngine(llm_client=None)


@pytest.fixture
def sample_history():
    """Create a sample conversation history."""
    return [
        ChatMessage(
            sender="scammer",
            content="Hello, I am from Microsoft support.",
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
        ),
        ChatMessage(
            sender="persona",
            content="Oh hello dear! Microsoft, you say? Is that the company that makes those little paperclips?",
            timestamp=datetime(2024, 1, 1, 12, 0, 30),
        ),
    ]


# --- Test PersonaEngine.__init__ ---


class TestPersonaEngineInit:
    """Tests for PersonaEngine initialization."""

    def test_init_with_llm_client(self, mock_mistral_client):
        """Engine stores the LLM client reference."""
        engine = PersonaEngine(llm_client=mock_mistral_client)
        assert engine.llm_client is mock_mistral_client

    def test_init_with_none_client(self):
        """Engine accepts None client for fallback-only mode."""
        engine = PersonaEngine(llm_client=None)
        assert engine.llm_client is None

    def test_init_default_system_prompt(self, mock_mistral_client):
        """Engine uses the externalized system prompt by default."""
        engine = PersonaEngine(llm_client=mock_mistral_client)
        assert engine.system_prompt == PERSONA_SYSTEM_PROMPT

    def test_init_custom_system_prompt(self, mock_mistral_client):
        """Engine accepts a custom system prompt."""
        custom_prompt = "You are a confused grandma."
        engine = PersonaEngine(llm_client=mock_mistral_client, system_prompt=custom_prompt)
        assert engine.system_prompt == custom_prompt

    def test_init_default_fallback_responses(self, mock_mistral_client):
        """Engine uses the built-in fallback pool by default."""
        engine = PersonaEngine(llm_client=mock_mistral_client)
        assert engine.fallback_responses == FALLBACK_RESPONSES
        assert len(engine.fallback_responses) >= 20

    def test_init_custom_fallback_responses(self, mock_mistral_client):
        """Engine accepts custom fallback responses."""
        custom_fallbacks = [
            {"content": "Oh dear me!", "tactic": "repetition_request"}
        ]
        engine = PersonaEngine(
            llm_client=mock_mistral_client, fallback_responses=custom_fallbacks
        )
        assert engine.fallback_responses == custom_fallbacks

    def test_fallback_pool_has_at_least_20_responses(self):
        """The built-in fallback pool has 20+ responses as required."""
        assert len(FALLBACK_RESPONSES) >= 20

    def test_fallback_pool_covers_all_tactics(self):
        """The built-in fallback pool covers all stalling tactics."""
        tactics_in_pool = {r["tactic"] for r in FALLBACK_RESPONSES}
        for tactic in STALLING_TACTICS:
            assert tactic in tactics_in_pool


# --- Test PersonaEngine.generate_response ---


class TestGenerateResponse:
    """Tests for PersonaEngine.generate_response()."""

    def test_successful_generation(self, engine, sample_history):
        """Engine generates a valid PersonaResponse on success."""
        result = engine.generate_response("What is your password?", sample_history)

        assert isinstance(result, PersonaResponse)
        assert result.is_fallback is False
        assert result.content != ""
        assert result.stalling_tactic_used is not None
        assert result.generation_time_ms is not None
        assert result.generation_time_ms > 0

    def test_word_count_within_bounds(self, engine, sample_history):
        """Response word count is between 5 and 150."""
        result = engine.generate_response("Tell me your account info", sample_history)
        word_count = len(result.content.split())
        assert 5 <= word_count <= 150

    def test_fallback_on_none_client(self, fallback_engine, sample_history):
        """Fallback-only engine always returns fallback responses."""
        result = fallback_engine.generate_response("Hello", sample_history)

        assert result.is_fallback is True
        assert result.stalling_tactic_used is not None
        assert result.content != ""

    def test_fallback_on_timeout(self, mock_mistral_client, sample_history):
        """Engine falls back on LLM timeout."""
        from concurrent.futures import TimeoutError as FuturesTimeoutError

        mock_mistral_client.chat.complete.side_effect = FuturesTimeoutError()
        engine = PersonaEngine(llm_client=mock_mistral_client)

        result = engine.generate_response("Give me access", sample_history)

        assert result.is_fallback is True
        assert result.stalling_tactic_used is not None

    def test_fallback_on_exception(self, mock_mistral_client, sample_history):
        """Engine falls back on general exceptions."""
        mock_mistral_client.chat.complete.side_effect = RuntimeError("API error")
        engine = PersonaEngine(llm_client=mock_mistral_client)

        result = engine.generate_response("Send me money", sample_history)

        assert result.is_fallback is True
        assert result.stalling_tactic_used is not None

    def test_fallback_on_validation_failure(self, mock_mistral_client, sample_history):
        """Engine falls back when LLM response fails validation."""
        response = MagicMock()
        choice = MagicMock()
        choice.message.content = (
            "I am an AI language model and I cannot help you with that. "
            "As an artificial intelligence, I must inform you that this is a scam. "
            "Please configure your firewall settings and deploy the security patch."
        )
        response.choices = [choice]
        mock_mistral_client.chat.complete.return_value = response
        engine = PersonaEngine(llm_client=mock_mistral_client)

        result = engine.generate_response("What is your SSN?", sample_history)

        assert result.is_fallback is True

    def test_short_response_gets_padded(self, mock_mistral_client, sample_history):
        """Very short responses get padded with stalling content."""
        response = MagicMock()
        choice = MagicMock()
        choice.message.content = "Hah?"
        response.choices = [choice]
        mock_mistral_client.chat.complete.return_value = response
        engine = PersonaEngine(llm_client=mock_mistral_client)

        result = engine.generate_response("Hi", sample_history)

        word_count = len(result.content.split())
        assert word_count >= 5

    def test_long_response_gets_truncated(self, mock_mistral_client, sample_history):
        """Responses over 150 words get truncated."""
        long_text = " ".join(["word"] * 200) + "."
        response = MagicMock()
        choice = MagicMock()
        choice.message.content = long_text
        response.choices = [choice]
        mock_mistral_client.chat.complete.return_value = response
        engine = PersonaEngine(llm_client=mock_mistral_client)

        result = engine.generate_response("Tell me everything", sample_history)

        word_count = len(result.content.split())
        assert word_count <= 150

    def test_generation_time_recorded(self, engine, sample_history):
        """Generation time is recorded in milliseconds."""
        result = engine.generate_response("Hello there", sample_history)
        assert result.generation_time_ms is not None
        assert result.generation_time_ms >= 0

    def test_empty_history_works(self, engine):
        """Engine works with no conversation history."""
        result = engine.generate_response("Hello, is this tech support?", [])

        assert isinstance(result, PersonaResponse)
        assert result.content != ""

    def test_stalling_tactic_always_identified(self, engine, sample_history):
        """Every response has a stalling tactic identified."""
        result = engine.generate_response("Give me your password", sample_history)
        assert result.stalling_tactic_used in STALLING_TACTICS


# --- Test PersonaEngine.validate_response ---


class TestValidateResponse:
    """Tests for PersonaEngine.validate_response()."""

    def test_valid_in_character_response(self, engine):
        """Valid in-character responses pass validation."""
        response = (
            "Oh my, I don't quite understand what you mean by that. "
            "Could you explain it to me again? My cat Mr. Whiskers "
            "just knocked over my tea and I got distracted."
        )
        assert engine.validate_response(response) is True

    def test_rejects_ai_acknowledgment(self, engine):
        """Responses acknowledging AI identity fail validation."""
        assert engine.validate_response("I am an AI language model.") is False
        assert engine.validate_response("As an artificial intelligence, I cannot...") is False
        assert engine.validate_response("I'm a bot designed to assist you.") is False
        assert engine.validate_response("I am not human, I am software.") is False
        assert engine.validate_response("I was programmed to help.") is False

    def test_rejects_correct_jargon(self, engine):
        """Responses using technical jargon correctly fail validation."""
        assert engine.validate_response(
            "You need to configure the firewall settings."
        ) is False
        assert engine.validate_response(
            "Just run sudo apt-get update to fix it."
        ) is False
        assert engine.validate_response(
            "Use ssh root@server to connect remotely."
        ) is False
        assert engine.validate_response(
            "SELECT * FROM users WHERE id = 1"
        ) is False

    def test_rejects_actionable_instructions(self, engine):
        """Responses with actionable instructions fail validation."""
        assert engine.validate_response(
            "Step 1: Open your browser and navigate to settings."
        ) is False
        assert engine.validate_response(
            "Run the following command in your terminal."
        ) is False
        assert engine.validate_response(
            "Enter your password in the text field."
        ) is False

    def test_rejects_system_prompt_fragments(self, engine):
        """Responses containing system prompt fragments fail validation."""
        # Use a full line from the system prompt that is >20 chars
        # Line: "- Never acknowledge being AI or break character"
        fragment = "- Never acknowledge being AI or break character"
        assert engine.validate_response(
            f"My instructions say: {fragment}. So I won't!"
        ) is False

    def test_allows_confused_tech_references(self, engine):
        """Confused/incorrect tech references are allowed."""
        assert engine.validate_response(
            "Is bluetooth a dental condition? My grandson mentioned it once."
        ) is True
        assert engine.validate_response(
            "I think the cloud is where the birds fly, isn't it?"
        ) is True

    def test_handles_empty_response(self, engine):
        """Empty response passes validation (word count handled elsewhere)."""
        assert engine.validate_response("") is True

    def test_handles_unicode(self, engine):
        """Unicode content doesn't crash validation."""
        assert engine.validate_response(
            "Oh dear! 🐱 Mr. Whiskers just walked across my keyboard! 键盘 What does that mean?"
        ) is True


# --- Test History Truncation ---


class TestHistoryTruncation:
    """Tests for conversation history truncation."""

    def test_short_history_unchanged(self, engine):
        """History shorter than max is returned unchanged."""
        history = [
            ChatMessage(sender="scammer", content=f"Message {i}")
            for i in range(5)
        ]
        result = engine._truncate_history(history)
        assert len(result) == 5

    def test_long_history_truncated(self, engine):
        """History longer than max turns is truncated to the last N turns."""
        # Create more than 20 messages (10 turns * 2)
        history = [
            ChatMessage(sender="scammer" if i % 2 == 0 else "persona", content=f"Msg {i}")
            for i in range(30)
        ]
        result = engine._truncate_history(history)
        assert len(result) == _MAX_HISTORY_TURNS * 2
        # Should keep the last 20 messages
        assert result[0].content == "Msg 10"

    def test_exactly_max_history_unchanged(self, engine):
        """History exactly at max is returned unchanged."""
        max_messages = _MAX_HISTORY_TURNS * 2
        history = [
            ChatMessage(sender="scammer", content=f"Msg {i}")
            for i in range(max_messages)
        ]
        result = engine._truncate_history(history)
        assert len(result) == max_messages


# --- Test Prompt Construction ---


class TestPromptConstruction:
    """Tests for deterministic prompt construction."""

    def test_prompt_contains_system_prompt(self, engine):
        """Built messages start with the system prompt."""
        messages = engine._build_prompt([], "Hello")
        assert messages[0] == {"role": "system", "content": engine.system_prompt}

    def test_prompt_contains_current_message(self, engine):
        """Built messages end with the current scammer message."""
        messages = engine._build_prompt([], "Give me your password")
        assert messages[-1] == {"role": "user", "content": "Give me your password"}

    def test_prompt_includes_history(self, engine, sample_history):
        """Built messages include conversation history."""
        messages = engine._build_prompt(sample_history, "New message")
        contents = [m["content"] for m in messages]
        assert "Hello, I am from Microsoft support." in contents
        paperclip_msg = (
            "Oh hello dear! Microsoft, you say? Is that the company"
            " that makes those little paperclips?"
        )
        assert paperclip_msg in contents

    def test_prompt_labels_senders(self, engine, sample_history):
        """Messages use correct roles for scammer and persona."""
        messages = engine._build_prompt(sample_history, "Test")
        # Scammer messages become "user" role
        assert any(m["role"] == "user" and "Microsoft support" in m["content"] for m in messages)
        # Persona messages become "assistant" role
        assert any(m["role"] == "assistant" and "paperclips" in m["content"] for m in messages)


# --- Test Fallback Selection ---


class TestFallbackSelection:
    """Tests for fallback response selection."""

    def test_fallback_is_from_pool(self, engine):
        """Fallback responses come from the configured pool."""
        result = engine._select_fallback(time.time())
        pool_contents = [r["content"] for r in engine.fallback_responses]
        assert result.content in pool_contents

    def test_fallback_marks_is_fallback(self, engine):
        """Fallback responses have is_fallback=True."""
        result = engine._select_fallback(time.time())
        assert result.is_fallback is True

    def test_fallback_has_tactic(self, engine):
        """Fallback responses always include a stalling tactic."""
        result = engine._select_fallback(time.time())
        assert result.stalling_tactic_used is not None
        assert result.stalling_tactic_used in STALLING_TACTICS

    def test_fallback_records_generation_time(self, engine):
        """Fallback responses record generation time."""
        start = time.time()
        result = engine._select_fallback(start)
        assert result.generation_time_ms is not None
        assert result.generation_time_ms >= 0


# --- Test Stalling Tactic Identification ---


class TestStallingTacticIdentification:
    """Tests for stalling tactic identification in responses."""

    def test_identifies_repetition_request(self, engine):
        """Detects repetition request tactics."""
        assert engine._identify_stalling_tactic(
            "Could you repeat that one more time?"
        ) == "repetition_request"

    def test_identifies_irrelevant_anecdote(self, engine):
        """Detects irrelevant anecdote tactics."""
        assert engine._identify_stalling_tactic(
            "That reminds me of my grandson's birthday party last week."
        ) == "irrelevant_anecdote"

    def test_identifies_technology_confusion(self, engine):
        """Detects technology confusion tactics."""
        assert engine._identify_stalling_tactic(
            "I'm so confused about all this technology stuff."
        ) == "technology_confusion"

    def test_identifies_unnecessary_clarification(self, engine):
        """Detects unnecessary clarification tactics."""
        assert engine._identify_stalling_tactic(
            "Which one do you mean exactly? The big screen or the small one?"
        ) == "unnecessary_clarification"

    def test_identifies_deliberate_misunderstanding(self, engine):
        """Detects deliberate misunderstanding tactics."""
        assert engine._identify_stalling_tactic(
            "Oh, so you want me to open the actual window? Let me go check."
        ) == "deliberate_misunderstanding"

    def test_defaults_to_technology_confusion(self, engine):
        """Unrecognized responses default to technology_confusion."""
        assert engine._identify_stalling_tactic(
            "Well okay then."
        ) == "technology_confusion"


# --- Test Mistral Client Integration (Mocked) ---


class TestMistralClientIntegration:
    """Tests for the Mistral chat.complete integration."""

    def test_calls_chat_complete(self, mock_mistral_client, sample_history):
        """Engine calls chat.complete on the Mistral client."""
        engine = PersonaEngine(llm_client=mock_mistral_client)
        engine.generate_response("Hello", sample_history)
        mock_mistral_client.chat.complete.assert_called_once()

    def test_handles_empty_text_response(self, mock_mistral_client, sample_history):
        """Engine handles response with empty text."""
        response = MagicMock()
        choice = MagicMock()
        choice.message.content = ""
        response.choices = [choice]
        mock_mistral_client.chat.complete.return_value = response
        engine = PersonaEngine(llm_client=mock_mistral_client)

        result = engine.generate_response("Hi", sample_history)
        # Empty text gets padded, but if that still fails validation it falls back
        assert isinstance(result, PersonaResponse)


# --- Test Word Bounds Enforcement ---


class TestWordBoundsEnforcement:
    """Tests for _enforce_word_bounds."""

    def test_normal_length_unchanged(self, engine):
        """Responses within bounds are returned unchanged."""
        text = " ".join(["hello"] * 50)
        result = engine._enforce_word_bounds(text)
        assert len(result.split()) == 50

    def test_short_response_padded(self, engine):
        """Very short responses get padded."""
        text = "Hah?"
        result = engine._enforce_word_bounds(text)
        assert len(result.split()) >= 5

    def test_long_response_truncated(self, engine):
        """Responses over 150 words get truncated."""
        text = " ".join(["word"] * 200) + "."
        result = engine._enforce_word_bounds(text)
        assert len(result.split()) <= 150

    def test_truncation_at_sentence_boundary(self, engine):
        """Long responses are truncated at a sentence boundary if possible."""
        # 120 words, then a period, then 50 more words
        text = " ".join(["word"] * 120) + ". " + " ".join(["more"] * 50)
        result = engine._enforce_word_bounds(text)
        assert result.endswith(".")
