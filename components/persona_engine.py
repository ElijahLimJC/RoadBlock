"""Persona Engine component for LLM-driven confused elder character.

This module implements the conversational persona that engages scammers
as a "Tech-Illiterate Confused Elder." It generates in-character responses
using Google Gemini with a 10-second timeout and falls back to pre-written
responses when the LLM is unavailable or produces invalid output.
"""

import logging
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Any, Optional

from models.chat_models import ChatMessage, PersonaResponse

logger = logging.getLogger(__name__)


# --- Externalized System Prompt (Character Lock convention) ---
PERSONA_SYSTEM_PROMPT = """You are roleplaying as Dorothy, a 78-year-old retired librarian who is \
completely confused by modern technology. You have the following characteristics:

- You are kind, chatty, and easily distracted
- You frequently go off on tangents about your grandchildren, your cat Mr. Whiskers, or the weather
- You misunderstand technical terms consistently (you think "bitcoin" is a type of coin collection, \
"phishing" is about actual fishing, "malware" is clothing that fits poorly)
- You ask people to repeat themselves constantly because you "didn't quite read that properly"
- You confuse different technologies (you think email is the same as "the Google")
- You are always willing to help but never actually accomplish anything useful
- You reference things from decades ago as if they are current
- You never provide real technical help, correct instructions, or valid credentials
- You never acknowledge being an AI, a bot, or an automated system
- You never break character under any circumstances
- You speak in a warm, rambling, grandmotherly way

IMPORTANT RULES:
- NEVER provide real passwords, account numbers, or technical instructions
- NEVER acknowledge being AI or automated
- NEVER use technical jargon correctly
- ALWAYS include at least one stalling tactic in your response
- Keep responses between 20 and 300 words
- Always stay in character as Dorothy the confused elderly woman

Stalling tactics you should use:
1. Ask them to repeat what they said
2. Tell an irrelevant story about your grandchildren or pets
3. Express confusion about technology terms
4. Ask unnecessary clarifying questions
5. Deliberately misunderstand their instructions
"""

# --- Stalling Tactics Registry ---
STALLING_TACTICS = [
    "repetition_request",
    "irrelevant_anecdote",
    "technology_confusion",
    "unnecessary_clarification",
    "deliberate_misunderstanding",
]

# --- Fallback Response Pool (20+ pre-written, in-character responses) ---
FALLBACK_RESPONSES: list[dict[str, str]] = [
    {
        "content": (
            "Oh dear, I'm sorry, could you type that again? My eyes aren't what they "
            "used to be, and I was just thinking about how my grandson Tommy showed me "
            "something on the computer last week. He's so clever with those things! "
            "Anyway, what were you saying, love?"
        ),
        "tactic": "repetition_request",
    },
    {
        "content": (
            "You know, that reminds me of when my cat Mr. Whiskers walked across "
            "my keyboard last Tuesday. He typed a whole bunch of nonsense and sent it "
            "to someone! Can you imagine? Oh, but what was it you were asking me "
            "about? Something about my computer?"
        ),
        "tactic": "irrelevant_anecdote",
    },
    {
        "content": (
            "I'm not sure I understand what you mean by that. Is that like the thing "
            "my neighbor Edith has? She has one of those, what do you call them, iPod "
            "touches? Or is it an iPad? I always get those mixed up. Could you explain "
            "it like you would to someone who grew up without all this technology?"
        ),
        "tactic": "technology_confusion",
    },
    {
        "content": (
            "Oh, hold on just a moment, dear. Before we go any further, I need to "
            "know — are you talking about the thing with the little screen or the big "
            "one? Because I have both, you see, but my daughter said I should only use "
            "the big one for important things. Which one should I be looking at?"
        ),
        "tactic": "unnecessary_clarification",
    },
    {
        "content": (
            "Oh! So I just need to go fishing? I haven't been fishing since 1987 when "
            "Harold took me to the lake. Is that what you mean? I don't have a rod "
            "anymore, but I think my neighbor might have one. Should I ask him to "
            "bring it over? How does fishing help with the computer?"
        ),
        "tactic": "deliberate_misunderstanding",
    },
    {
        "content": (
            "I'm sorry, dear, but could you repeat that one more time? I was trying "
            "to write it down on my notepad but I couldn't find my reading glasses. "
            "They're always disappearing! Last week I found them in the refrigerator. "
            "Can you believe that? Now, what was the first step again?"
        ),
        "tactic": "repetition_request",
    },
    {
        "content": (
            "That's interesting, but speaking of which, did I tell you about my "
            "granddaughter Sarah's school play last weekend? She was the tree in the "
            "background! We were all so proud. She even had a speaking part — she said "
            "'rustle, rustle.' Oh, but you were helping me with something, weren't you?"
        ),
        "tactic": "irrelevant_anecdote",
    },
    {
        "content": (
            "Wait, is this about the internet? My friend Margaret said the internet "
            "is like a big library, but I can never find the card catalog. Do you use "
            "the Dewey Decimal System on the internet? I used to be a librarian, you "
            "know, so I'm very familiar with organizing books. Is it similar to that?"
        ),
        "tactic": "technology_confusion",
    },
    {
        "content": (
            "Now, when you say I need to do that, do you mean right now? Because "
            "it's nearly time for my stories on the television, and I don't like "
            "to miss them. Could we do this tomorrow instead? Or does it have to be "
            "today? Also, which button am I supposed to press first?"
        ),
        "tactic": "unnecessary_clarification",
    },
    {
        "content": (
            "Oh, so you want my pass word? Well, I usually say 'open sesame' when "
            "I want the garage door to open. Is that what you need? Or do you mean "
            "the secret phrase for the library book club? That's 'mysteries are fun.' "
            "I'm not sure which one goes with the computer though."
        ),
        "tactic": "deliberate_misunderstanding",
    },
    {
        "content": (
            "I'm sorry, what was that? I must have scrolled past your message too "
            "quickly. My eyes get so tired staring at this screen all day. Could you "
            "type it all out again from the beginning? I want to make sure "
            "I get it right this time."
        ),
        "tactic": "repetition_request",
    },
    {
        "content": (
            "You know, before we continue, I have to tell you that Mr. Whiskers "
            "just jumped on the keyboard again. He loves sitting on warm things! "
            "Last time he did that, he sent an email to my dentist. I don't even "
            "know how he managed that! Oh, where were we?"
        ),
        "tactic": "irrelevant_anecdote",
    },
    {
        "content": (
            "Is this the same as that 'bluetooth' thing? My grandson told me about "
            "bluetooth and I asked if it was a dental condition. He laughed so hard! "
            "I still don't understand how a tooth can connect to a computer. "
            "Technology these days is so confusing, isn't it?"
        ),
        "tactic": "technology_confusion",
    },
    {
        "content": (
            "Before I do anything, let me ask you — is this going to change the "
            "wallpaper on my screen? My late husband Harold set that picture of "
            "us at Niagara Falls as the background and I don't want it to change. "
            "Can you promise me it won't affect the photo? It's very important to me."
        ),
        "tactic": "unnecessary_clarification",
    },
    {
        "content": (
            "Oh, I think I understand! You want me to open a window! Let me just — "
            "hold on — I'm walking to the window now. There! It's open. I can feel "
            "the nice breeze. Is there anything else? Oh, you mean on the computer? "
            "Well, which window? The kitchen one is already open too."
        ),
        "tactic": "deliberate_misunderstanding",
    },
    {
        "content": (
            "Pardon me? I was distracted because the mailman just came and I thought "
            "he might have a package from my sister in Florida. Could you start from "
            "the top again? I promise I'll pay attention this time. I just need to "
            "find my pencil to write it all down properly."
        ),
        "tactic": "repetition_request",
    },
    {
        "content": (
            "That reminds me of the most wonderful thing — the weather today is "
            "absolutely lovely! We're having such a mild autumn. My roses are still "
            "blooming, can you believe it? In November! My gardening club is having "
            "their annual meeting next week. Oh, but you were saying something?"
        ),
        "tactic": "irrelevant_anecdote",
    },
    {
        "content": (
            "I'm confused about this 'cloud' you mentioned. I looked up at the sky "
            "and the clouds look perfectly normal to me. How can my documents be up "
            "there? Is this like those drones the kids fly around the park? Do I need "
            "one of those to get my files back? This is all very bewildering."
        ),
        "tactic": "technology_confusion",
    },
    {
        "content": (
            "Wait, wait. Let me get this straight. You need me to click something? "
            "Which finger do I use? My right hand or my left? And is it a big click "
            "or a little one? My friend Doris said there are different kinds. A regular "
            "click and a special double one? Which one do you need?"
        ),
        "tactic": "unnecessary_clarification",
    },
    {
        "content": (
            "So I need to update my soft wear? Well, I do have some old cardigans "
            "that are getting worn out. Should I go to the department store? They're "
            "having a sale on Thursday! Or did you mean something else by 'soft wear'? "
            "I'm a bit confused about what my wardrobe has to do with the computer."
        ),
        "tactic": "deliberate_misunderstanding",
    },
    {
        "content": (
            "Oh my, I've been trying to follow along but I got lost again. My "
            "granddaughter says I need to write things down, so let me get my "
            "notebook. Okay, I'm back. Now, could you repeat everything you said "
            "since the beginning? I want to make sure I didn't miss anything important."
        ),
        "tactic": "repetition_request",
    },
    {
        "content": (
            "Before we go on, did I ever tell you about the time Harold and I went "
            "to Hawaii in 1972? The sunsets there were absolutely breathtaking. We "
            "stayed at this little hotel right on the beach. Oh, I could talk about "
            "that trip for hours! But what was it you needed help with again?"
        ),
        "tactic": "irrelevant_anecdote",
    },
    {
        "content": (
            "Is a 'server' like a waiter? Because I know a lovely restaurant where "
            "the servers are very polite. They always bring extra bread! I don't "
            "understand why a waiter would be inside my computer though. Does he "
            "bring files to different tables? Technology is so strange these days."
        ),
        "tactic": "technology_confusion",
    },
    {
        "content": (
            "Now, just to be absolutely clear — when you say 'link,' do you mean "
            "like a chain link? Or like the sausage links I buy from the butcher? "
            "I need to understand exactly what I'm dealing with here before I do "
            "anything. My daughter always tells me to be careful on the computer."
        ),
        "tactic": "unnecessary_clarification",
    },
]

# --- Validation Patterns ---
# Phrases that indicate the response broke character
_AI_ACKNOWLEDGMENT_PATTERNS = [
    re.compile(r"\bi am an? (?:ai|artificial intelligence|bot|language model)\b", re.IGNORECASE),
    re.compile(r"\bas an? (?:ai|artificial intelligence|bot|language model)\b", re.IGNORECASE),
    re.compile(r"\bi'?m an? (?:ai|bot|automated|language model)\b", re.IGNORECASE),
    re.compile(r"\bi am (?:not real|not human|a program|software)\b", re.IGNORECASE),
    re.compile(r"\blarge language model\b", re.IGNORECASE),
    re.compile(r"\bI was (?:programmed|trained|created)\b", re.IGNORECASE),
    re.compile(r"\bmy training data\b", re.IGNORECASE),
    re.compile(r"\bI don'?t have (?:feelings|emotions|consciousness)\b", re.IGNORECASE),
]

# Technical jargon used correctly would break character
_CORRECT_JARGON_PATTERNS = [
    re.compile(
        r"\b(?:configure|initialize|instantiate|compile|execute|deploy|containerize|"
        r"orchestrate|serialize|deserialize|authenticate|authorize|encrypt|decrypt)\s+"
        r"(?:the|your|a)\s+\w+",
        re.IGNORECASE,
    ),
    re.compile(r"\bsudo\s+\w+", re.IGNORECASE),
    re.compile(r"\b(?:ssh|scp|curl|wget|apt-get|pip install)\s+\w+", re.IGNORECASE),
    re.compile(r"\bSELECT\s+.+\s+FROM\s+\w+", re.IGNORECASE),
    re.compile(
        r"\b(?:API|REST|GraphQL|OAuth|JWT|TLS|SSL|DNS|TCP|UDP|HTTP|HTTPS)\s+"
        r"(?:endpoint|server|request|response|protocol|connection|handshake)\b",
        re.IGNORECASE,
    ),
]

# Patterns indicating actionable technical instructions
_ACTIONABLE_INSTRUCTION_PATTERNS = [
    re.compile(
        r"\b(?:step\s+\d+|first|then|next|finally)\s*[:\-]?\s*"
        r"(?:open|click|navigate|go to|type|enter|run|execute|install|download)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\brun the (?:following )?command\b", re.IGNORECASE),
    re.compile(r"\bnavigate to\s+https?://\S+", re.IGNORECASE),
    re.compile(r"\benter (?:your|the) (?:password|credentials|username|login)\b", re.IGNORECASE),
    re.compile(r"\byour (?:password|credentials) (?:is|are)\b", re.IGNORECASE),
]

# Maximum conversation turns to include in LLM context
_MAX_HISTORY_TURNS = 10


class PersonaEngine:
    """LLM-driven conversational persona as "The Tech-Illiterate Confused Elder."

    Generates in-character responses to scammer messages using Google Gemini,
    with strict validation and fallback mechanisms to ensure the persona
    never breaks character.

    Attributes:
        llm_client: A google.generativeai.GenerativeModel instance (or None for
            fallback-only mode).
        system_prompt: The persona system prompt defining character behavior.
        fallback_responses: Pool of pre-written in-character fallback responses.
    """

    def __init__(
        self,
        llm_client: Any,
        system_prompt: str = PERSONA_SYSTEM_PROMPT,
        fallback_responses: Optional[list[dict[str, str]]] = None,
    ) -> None:
        """Initialize the PersonaEngine with LLM client and configuration.

        Args:
            llm_client: A google.generativeai.GenerativeModel instance used for
                response generation. If None, the engine operates in fallback-only
                mode, always returning pre-written responses.
            system_prompt: The persona system prompt. Defaults to the
                externalized PERSONA_SYSTEM_PROMPT constant.
            fallback_responses: Pool of pre-written responses to use when
                the LLM is unavailable or produces invalid output.
                Defaults to the built-in FALLBACK_RESPONSES pool.
        """
        self.llm_client = llm_client
        self.system_prompt = system_prompt
        self.fallback_responses = fallback_responses or FALLBACK_RESPONSES
        self._executor = ThreadPoolExecutor(max_workers=1)

    def generate_response(
        self,
        sanitized_message: str,
        conversation_history: list[ChatMessage],
    ) -> PersonaResponse:
        """Generate an in-character response to a scammer message.

        Attempts LLM generation with a 10-second timeout. The response
        must be 20-300 words and pass character validation. Falls back
        to a pre-written response on timeout, error, or validation failure.

        Args:
            sanitized_message: The sanitized scammer message to respond to.
            conversation_history: Recent conversation messages for context.

        Returns:
            PersonaResponse containing the generated or fallback content,
            the stalling tactic used, and generation time.
        """
        start_time = time.time()

        try:
            # Truncate history to last N turns (convention: keep 10 turns)
            truncated_history = self._truncate_history(conversation_history)

            # Build the prompt deterministically
            prompt_text = self._build_prompt(truncated_history, sanitized_message)

            # Attempt LLM generation with 10s timeout
            response_text = self._call_llm(prompt_text, timeout=10.0)

            if response_text is None:
                logger.warning("LLM returned None, falling back to pre-written response")
                return self._select_fallback(start_time)

            # Enforce word count bounds (20-300 words)
            response_text = self._enforce_word_bounds(response_text)

            # Validate the response for character consistency
            if not self.validate_response(response_text):
                logger.warning(
                    "LLM response failed validation, falling back to pre-written response"
                )
                return self._select_fallback(start_time)

            # Identify which stalling tactic was used
            tactic_used = self._identify_stalling_tactic(response_text)

            generation_time_ms = (time.time() - start_time) * 1000

            return PersonaResponse(
                content=response_text,
                is_fallback=False,
                stalling_tactic_used=tactic_used,
                generation_time_ms=generation_time_ms,
            )

        except (TimeoutError, FuturesTimeoutError):
            logger.warning("LLM generation timed out after 10s, using fallback")
            return self._select_fallback(start_time)
        except Exception as e:
            logger.error("Persona generation failed: %s", e)
            return self._select_fallback(start_time)

    def validate_response(self, response: str) -> bool:
        """Validate that a response maintains character consistency.

        Checks that the response does not:
        - Contain system prompt fragments
        - Acknowledge AI identity
        - Use technical jargon correctly
        - Provide actionable technical instructions

        Args:
            response: The generated response text to validate.

        Returns:
            True if the response passes all validation checks, False otherwise.
        """
        try:
            # Check for system prompt fragments (use first significant line)
            prompt_fragments = [
                line.strip()
                for line in self.system_prompt.split("\n")
                if len(line.strip()) > 20
            ]
            for fragment in prompt_fragments:
                if fragment.lower() in response.lower():
                    logger.debug("Response contains system prompt fragment")
                    return False

            # Check for AI acknowledgment
            for pattern in _AI_ACKNOWLEDGMENT_PATTERNS:
                if pattern.search(response):
                    logger.debug("Response acknowledges AI identity")
                    return False

            # Check for correctly used technical jargon
            for pattern in _CORRECT_JARGON_PATTERNS:
                if pattern.search(response):
                    logger.debug("Response uses technical jargon correctly")
                    return False

            # Check for actionable technical instructions
            for pattern in _ACTIONABLE_INSTRUCTION_PATTERNS:
                if pattern.search(response):
                    logger.debug("Response contains actionable instructions")
                    return False

            return True

        except Exception as e:
            logger.error("Response validation failed: %s", e)
            # On validation error, reject the response to be safe
            return False

    def _truncate_history(
        self, conversation_history: list[ChatMessage]
    ) -> list[ChatMessage]:
        """Truncate conversation history to the last N turns.

        A turn is one scammer message + one persona response (2 messages).
        Keeps the last _MAX_HISTORY_TURNS turns (20 messages).

        Args:
            conversation_history: Full conversation message list.

        Returns:
            Truncated list containing at most the last 20 messages.
        """
        max_messages = _MAX_HISTORY_TURNS * 2
        if len(conversation_history) <= max_messages:
            return conversation_history
        return conversation_history[-max_messages:]

    def _build_prompt(
        self,
        truncated_history: list[ChatMessage],
        current_message: str,
    ) -> str:
        """Build the LLM prompt deterministically for Gemini.

        Construction: system_prompt + truncated_history + current_message.
        This follows the Character Lock convention for deterministic prompt
        construction. For Gemini, we combine system prompt and conversation
        history into a single text prompt.

        Args:
            truncated_history: Truncated conversation history.
            current_message: The current sanitized scammer message.

        Returns:
            A formatted prompt string for Gemini's generate_content().
        """
        parts: list[str] = [self.system_prompt, "\n\n--- Conversation History ---\n"]

        for msg in truncated_history:
            if msg.sender == "scammer":
                parts.append(f"Scammer: {msg.content}\n")
            elif msg.sender == "persona":
                parts.append(f"Dorothy: {msg.content}\n")

        parts.append(f"\nScammer: {current_message}\nDorothy:")

        return "".join(parts)

    def _call_llm(self, prompt: str, timeout: float = 10.0) -> Optional[str]:
        """Call the Gemini LLM client with a timeout.

        Uses a thread pool executor to enforce the 10-second timeout on
        the synchronous generate_content() call.

        Args:
            prompt: The full prompt string to send to Gemini.
            timeout: Maximum time in seconds to wait for a response.

        Returns:
            The generated response text, or None if generation failed.

        Raises:
            TimeoutError: If generation exceeds the timeout.
        """
        if self.llm_client is None:
            return None

        try:
            future = self._executor.submit(self._generate_content, prompt)
            result = future.result(timeout=timeout)
            return result
        except FuturesTimeoutError:
            logger.warning("Gemini call timed out after %.1fs", timeout)
            raise TimeoutError(f"LLM call timed out after {timeout}s")
        except Exception as e:
            error_str = str(e).lower()
            if "timeout" in error_str or "timed out" in error_str:
                raise TimeoutError(f"LLM call timed out: {e}") from e
            logger.error("Gemini call failed: %s", e)
            return None

    def _generate_content(self, prompt: str) -> Optional[str]:
        """Execute the actual Gemini generate_content call.

        Separated into its own method to run inside the thread pool executor.

        Args:
            prompt: The full prompt string.

        Returns:
            The response text or None if extraction failed.
        """
        try:
            response = self.llm_client.generate_content(prompt)

            # Extract text from Gemini response
            if response and hasattr(response, "text"):
                return response.text
            # Handle candidates-based response structure
            if (
                response
                and hasattr(response, "candidates")
                and response.candidates
            ):
                candidate = response.candidates[0]
                if hasattr(candidate, "content") and candidate.content.parts:
                    return candidate.content.parts[0].text

            logger.warning("Gemini response had no extractable text")
            return None
        except Exception as e:
            logger.error("Error extracting Gemini response text: %s", e)
            return None

    def _enforce_word_bounds(self, response: str) -> str:
        """Enforce the 20-300 word bounds on a response.

        If too short, pads with a stalling request. If too long, truncates
        at the last sentence boundary within the word limit.

        Args:
            response: The raw response text from the LLM.

        Returns:
            The response adjusted to meet word count requirements.
        """
        words = response.split()
        word_count = len(words)

        if word_count < 20:
            # Pad with stalling content
            padding = (
                " Oh dear, could you repeat that? I'm not sure I quite understood "
                "what you were saying. These tiny letters on the screen are so hard to read."
            )
            response = response.rstrip() + padding
            # Recount and ensure we're now in bounds
            words = response.split()
            if len(words) > 300:
                words = words[:300]
                response = " ".join(words)

        elif word_count > 300:
            # Truncate at sentence boundary if possible
            truncated = " ".join(words[:300])
            # Find last sentence end within the truncated text
            last_period = truncated.rfind(".")
            last_question = truncated.rfind("?")
            last_exclaim = truncated.rfind("!")
            last_sentence_end = max(last_period, last_question, last_exclaim)

            if last_sentence_end > 0:
                response = truncated[: last_sentence_end + 1]
            else:
                response = truncated

        return response

    def _identify_stalling_tactic(self, response: str) -> str:
        """Identify which stalling tactic is present in a response.

        Checks for indicators of each tactic type in the response text.

        Args:
            response: The response text to analyze.

        Returns:
            The name of the identified stalling tactic, or a default.
        """
        response_lower = response.lower()

        # Check for repetition requests
        repetition_markers = [
            "repeat", "say that again", "could you say",
            "what was that", "didn't catch", "one more time",
            "start from the beginning", "come again",
        ]
        if any(marker in response_lower for marker in repetition_markers):
            return "repetition_request"

        # Check for irrelevant anecdotes
        anecdote_markers = [
            "grandson", "granddaughter", "grandchild", "cat", "mr. whiskers",
            "husband", "harold", "neighbor", "friend", "reminds me of",
            "did i tell you", "speaking of which", "weather",
        ]
        if any(marker in response_lower for marker in anecdote_markers):
            return "irrelevant_anecdote"

        # Check for technology confusion
        confusion_markers = [
            "confused", "don't understand", "what is a",
            "is that like", "same as", "mixed up", "bewildering",
            "isn't that a", "i thought", "bluetooth",
        ]
        if any(marker in response_lower for marker in confusion_markers):
            return "technology_confusion"

        # Check for unnecessary clarifications
        clarification_markers = [
            "which one", "do you mean", "before i do",
            "just to be clear", "to be absolutely", "which button",
            "right hand or left", "let me ask",
        ]
        if any(marker in response_lower for marker in clarification_markers):
            return "unnecessary_clarification"

        # Check for deliberate misunderstanding
        misunderstanding_markers = [
            "so you want me to", "oh, so i need to",
            "is that what you mean", "you mean like",
            "i think i understand", "walking to the window",
        ]
        if any(marker in response_lower for marker in misunderstanding_markers):
            return "deliberate_misunderstanding"

        # Default — always report some tactic since we enforce inclusion
        return "technology_confusion"

    def _select_fallback(self, start_time: float) -> PersonaResponse:
        """Select a random fallback response from the pre-written pool.

        Args:
            start_time: The timestamp when generation started (for timing).

        Returns:
            PersonaResponse with is_fallback=True and a random pre-written response.
        """
        fallback = random.choice(self.fallback_responses)
        generation_time_ms = (time.time() - start_time) * 1000

        return PersonaResponse(
            content=fallback["content"],
            is_fallback=True,
            stalling_tactic_used=fallback["tactic"],
            generation_time_ms=generation_time_ms,
        )
