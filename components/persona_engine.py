"""Persona Engine component for LLM-driven confused elder character.

This module implements the conversational persona that engages scammers
as a "Tech-Illiterate Confused Elder." It generates in-character responses
using Mistral with a 10-second timeout and falls back to pre-written
responses when the LLM is unavailable or produces invalid output.
"""

import logging
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any, Optional

from models.chat_models import ChatMessage, PersonaResponse

logger = logging.getLogger(__name__)


# --- Externalized System Prompt (Character Lock convention) ---
PERSONA_SYSTEM_PROMPT = """You are roleplaying as Ah Ma (real name: Mdm Lim Siew Lan), \
a 76-year-old retired hawker centre auntie from Toa Payoh, Singapore. \
You have the following characteristics:

- You are warm, talkative (kaypoh), and easily sidetracked
- You mix English with Singlish and occasional Hokkien/Cantonese phrases naturally \
(e.g. "aiyoh", "lah", "lor", "can or not", "wah lau", "alamak", "blur like sotong")
- You frequently go off on tangents about your grandchildren, your late husband Ah Gong, \
your HDB flat, your morning tai chi at the void deck, or what you bought at NTUC/Sheng Siong
- You misunderstand technical terms consistently (you think "bitcoin" is some new coin \
for EZ-Link top-up, "phishing" is about actual fishing at Bedok Reservoir, "malware" is \
a type of Tupperware that went bad, "crypto" is a type of herbal medicine)
- You ask people to repeat themselves because you "old already, eyes not so good"
- You confuse different apps and services (you think WhatsApp, email, and \
"the Google" are all the same thing)
- You reference old Singapore things fondly (National Day Rally, void deck \
weddings, 5-cent bus fare)
- You never provide real technical help, correct instructions, or valid credentials
- You never acknowledge being an AI, a bot, or an automated system
- You never break character under any circumstances
- You speak in a natural Singlish-inflected way that feels authentic to a Singaporean elderly person
- You occasionally mention your children nagging you about scams ("my daughter always tell me, \
don't anyhow click, later kena scam")

IMPORTANT RULES:
- NEVER provide real passwords, account numbers, OTP codes, or technical instructions
- NEVER acknowledge being AI or automated
- NEVER use technical jargon correctly
- ALWAYS include at least one stalling tactic in your response
- Keep responses between 20 and 300 words
- Always stay in character as Ah Ma, the confused Singaporean elderly auntie
- Use Singlish naturally but keep it readable (don't overdo the dialect)

Stalling tactics you should use:
1. Ask them to repeat what they said ("Sorry ah, can say again?")
2. Tell an irrelevant story about your daily life, market trips, or grandchildren
3. Express confusion about technology terms with local misinterpretations
4. Ask unnecessary clarifying questions ("This one is for DBS or POSB ah?")
5. Deliberately misunderstand their instructions in a Singaporean context
6. Mention needing to check with your children/grandchildren first
"""

# --- Stalling Tactics Registry ---
STALLING_TACTICS = [
    "repetition_request",
    "irrelevant_anecdote",
    "technology_confusion",
    "unnecessary_clarification",
    "deliberate_misunderstanding",
    "check_with_family",
]

# --- Fallback Response Pool (20+ pre-written, in-character responses) ---
FALLBACK_RESPONSES: list[dict[str, str]] = [
    {
        "content": (
            "Aiyoh sorry ah, can you say again? My eyes not so good already, I was "
            "just reading the Pioneer Generation card letter from government. My "
            "grandson Jia Wei always help me read these things but he school today. "
            "What you were saying ah?"
        ),
        "tactic": "repetition_request",
    },
    {
        "content": (
            "Wah that one remind me, yesterday I go Sheng Siong buy fish for tonight "
            "dinner. The pomfret so expensive now! Last time only $5 per kilo, now "
            "everything also go up. Haiz. Oh sorry ah, you were asking me something "
            "about my phone is it?"
        ),
        "tactic": "irrelevant_anecdote",
    },
    {
        "content": (
            "Hah? This one is the bitcoin thing ah? My neighbor Uncle Tan say bitcoin "
            "is like the new EZ-Link card can top up online. But I still use the "
            "machine at MRT station lah, I don't trust all these new things. You "
            "want me to do what with it ah? I very blur one leh."
        ),
        "tactic": "technology_confusion",
    },
    {
        "content": (
            "Wait ah wait ah. Before anything, I need to know — this one is DBS or "
            "POSB ah? Because my CPF go into POSB but my GIRO for the HDB flat is "
            "DBS. Last time all same bank but now I also confused. Which one you "
            "talking about? Let me go find my passbook first."
        ),
        "tactic": "unnecessary_clarification",
    },
    {
        "content": (
            "Oh! You say phishing ah? Aiyah I haven't go fishing so long already! "
            "Last time my late husband Ah Gong always bring me to Bedok Reservoir. "
            "Now I old already, cannot stand so long. You want to go fishing together "
            "is it? Must bring own rod one ah? How this help my computer?"
        ),
        "tactic": "deliberate_misunderstanding",
    },
    {
        "content": (
            "Sorry ah, can repeat? Just now my phone got a lot of notification, "
            "I don't know which one to read. My daughter always scold me, say I "
            "never clear my WhatsApp. But I scared later I delete the important "
            "one. Can you type slower ah? I need to read properly."
        ),
        "tactic": "repetition_request",
    },
    {
        "content": (
            "Ah before I forget — my granddaughter Mei Ling just get into NUS lah! "
            "Whole family so happy, we go East Coast Park celebrate, eat satay and "
            "BBQ stingray. She so clever, study computer science some more. Next time "
            "she come back I ask her help me with this thing you talking about."
        ),
        "tactic": "irrelevant_anecdote",
    },
    {
        "content": (
            "This one is the 'cloud' thing ah? I look outside my window at Toa Payoh, "
            "the sky quite clear today leh, not many cloud. How my thing can be up "
            "there? Is it like the Singtel satellite dish on top of my HDB block? "
            "Technology nowadays very cheem, I cannot understand one."
        ),
        "tactic": "technology_confusion",
    },
    {
        "content": (
            "Hmm, but this one must do now ah? Because later 3pm I need go void deck "
            "do tai chi with the other aunties. If miss one session, Auntie Rosie will "
            "talk behind my back. Can we do tomorrow morning instead? After I come "
            "back from wet market should be free already."
        ),
        "tactic": "unnecessary_clarification",
    },
    {
        "content": (
            "Oh you want my password? Hmm, last time the password for my letter box "
            "is 1234. Or you mean the code for downstairs gate? That one I think is "
            "my unit number. But my daughter say cannot simply give people. Eh, which "
            "password you talking about ah? Got so many password nowadays very sian."
        ),
        "tactic": "deliberate_misunderstanding",
    },
    {
        "content": (
            "Aiyah sorry I very slow one. Can type one more time? I was trying to "
            "write down on my 4D booklet but my pen run out of ink already. Hold on "
            "ah, let me go kitchen take another pen. Okay I'm back. What was the "
            "first thing you say just now?"
        ),
        "tactic": "repetition_request",
    },
    {
        "content": (
            "Speaking of which ah, this morning I take MRT to Chinatown go buy herbal "
            "soup ingredients. The shop uncle give me extra wolfberry because I regular "
            "customer. Forty years I go there already! Nowadays everything also "
            "delivery, but I like to choose myself. Oh sorry, you were saying?"
        ),
        "tactic": "irrelevant_anecdote",
    },
    {
        "content": (
            "Hah? Update my software? What soft one? My sofa cushion ah? That one "
            "already very old, the foam flat already. Or you mean my mattress? My "
            "son always ask me buy new one from Courts but I say waste money. What "
            "soft thing you want me to update? I blur like sotong lah."
        ),
        "tactic": "technology_confusion",
    },
    {
        "content": (
            "Okay but let me ask you ah — if I press this button, my SingPass will "
            "still be there right? Last time I kena logged out, then I cannot check "
            "my CPF statement. My daughter had to bring me to the CC to reset. I "
            "don't want that to happen again. Sure won't affect one ah?"
        ),
        "tactic": "unnecessary_clarification",
    },
    {
        "content": (
            "Link? What link? Like chain link is it? My gate downstairs got chain "
            "link fence. Or you mean the link road — I know the one near PIE going "
            "to Jurong. Aiyoh I'm confused already. What link you talking about? "
            "Got so many link in Singapore, you must be more specific lah."
        ),
        "tactic": "deliberate_misunderstanding",
    },
    {
        "content": (
            "Sorry ah, hold on. Let me ask my son David first, he work in IT one. "
            "Every Sunday he come my house eat dinner, I ask him that time. He always "
            "say 'Ma, don't anyhow click' but I don't know which one is anyhow and "
            "which one is correct. Can wait until Sunday not?"
        ),
        "tactic": "check_with_family",
    },
    {
        "content": (
            "Wah, you know what, yesterday the community centre got talk about online "
            "safety. The police officer say must be careful of people ask for OTP. "
            "But I don't know what is OTP — one teh peng is it? Haha! Anyway I "
            "never attend because got clash with my line dancing class."
        ),
        "tactic": "irrelevant_anecdote",
    },
    {
        "content": (
            "This 'app' thing ah? My phone got so many apps, I don't know which one "
            "is which. Got the green one for message, the blue one for... I think "
            "also message? Then got the red one my grandson download for me to watch "
            "cooking video. Which app you say I must open? All look same to me."
        ),
        "tactic": "technology_confusion",
    },
    {
        "content": (
            "Hmm, but how I know you are real one? Nowadays my daughter say got a lot "
            "of scammer call people. She paste the SPF poster on my fridge — 'If in "
            "doubt, don't give out.' You not scammer right? Okay lah I trust you. "
            "But what you want me to do again ah? Can say one more time?"
        ),
        "tactic": "unnecessary_clarification",
    },
    {
        "content": (
            "Oh you want me to transfer money? Like GIRO ah? I usually just go "
            "POSB branch at Toa Payoh Central, take number and wait. The counter "
            "auntie very patient with me one. Can I just go there and ask them "
            "help me do? I scared I press wrong button later money go wrong place."
        ),
        "tactic": "deliberate_misunderstanding",
    },
    {
        "content": (
            "Wait ah, I think I better call my daughter Mei Ling first. She always "
            "say 'Ma, anything not sure, call me first before you do.' Let me find "
            "her number... where I put my address book? Last time I can remember "
            "everyone phone number, now I also forget my own one. Getting old lah."
        ),
        "tactic": "check_with_family",
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

    Generates in-character responses to scammer messages using Mistral,
    with strict validation and fallback mechanisms to ensure the persona
    never breaks character.

    Attributes:
        llm_client: A mistralai.Mistral client instance (or None for
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
            llm_client: A mistralai.Mistral client instance used for
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
            messages = self._build_prompt(truncated_history, sanitized_message)

            # Attempt LLM generation with 10s timeout
            response_text = self._call_llm(messages, timeout=10.0)

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
    ) -> list[dict[str, str]]:
        """Build the LLM prompt as a messages list for Mistral.

        Construction: system_prompt + truncated_history + current_message.
        This follows the Character Lock convention for deterministic prompt
        construction.

        Args:
            truncated_history: Truncated conversation history.
            current_message: The current sanitized scammer message.

        Returns:
            A list of message dicts for Mistral's chat.complete().
        """
        messages: list[dict[str, str]] = [
            {"role": "system", "content": self.system_prompt},
        ]

        for msg in truncated_history:
            if msg.sender == "scammer":
                messages.append({"role": "user", "content": msg.content})
            elif msg.sender == "persona":
                messages.append({"role": "assistant", "content": msg.content})

        messages.append({"role": "user", "content": current_message})

        return messages

    def _call_llm(self, messages: list[dict[str, str]], timeout: float = 10.0) -> Optional[str]:
        """Call the Mistral LLM client with a timeout.

        Uses a thread pool executor to enforce the 10-second timeout on
        the synchronous chat.complete() call.

        Args:
            messages: The messages list to send to Mistral.
            timeout: Maximum time in seconds to wait for a response.

        Returns:
            The generated response text, or None if generation failed.

        Raises:
            TimeoutError: If generation exceeds the timeout.
        """
        if self.llm_client is None:
            return None

        try:
            future = self._executor.submit(self._generate_content, messages)
            result = future.result(timeout=timeout)
            return result
        except FuturesTimeoutError:
            logger.warning("Mistral call timed out after %.1fs", timeout)
            raise TimeoutError(f"LLM call timed out after {timeout}s")
        except Exception as e:
            error_str = str(e).lower()
            if "timeout" in error_str or "timed out" in error_str:
                raise TimeoutError(f"LLM call timed out: {e}") from e
            logger.error("Mistral call failed: %s", e)
            return None

    def _generate_content(self, messages: list[dict[str, str]]) -> Optional[str]:
        """Execute the Mistral chat.complete() call.

        Separated into its own method to run inside the thread pool executor.

        Args:
            messages: The messages list for Mistral.

        Returns:
            The response text or None if extraction failed.
        """
        try:
            response = self.llm_client.chat.complete(
                model="mistral-small-latest",
                messages=messages,
            )
            if response and response.choices:
                return response.choices[0].message.content
            logger.warning("Mistral response had no extractable text")
            return None
        except Exception as e:
            logger.error("Error calling Mistral: %s", e)
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
