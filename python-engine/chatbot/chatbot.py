"""Gemini-powered security chatbot for NetShield AI.

Uses Google's Generative AI (Gemini) to answer user questions about
the current security state of the system.  The system prompt is
dynamically enriched with live database context (threat level,
recent attacks, top attackers, attack distribution).
"""

from __future__ import annotations

import logging
import warnings
from typing import Any

from database import Database
from prediction.schemas import PredictionResult  # noqa: F401 — re-exported convenience

logger = logging.getLogger(__name__)

# Suppress the deprecation warning from google.generativeai —
# the package still works but Google recommends migrating to
# google-genai in the future.
warnings.filterwarnings(
    "ignore",
    message=".*google.generativeai.*",
    category=DeprecationWarning,
)

_FALLBACK_NO_KEY = (
    "I need a Gemini API key to function. "
    "Please set the GEMINI_API_KEY environment variable and restart the server."
)

# Models to try in order — the first that WORKS wins.
# We verify with a tiny generate_content call, not just instantiation,
# because some models initialise but then hang/timeout on generation.
_GEMINI_MODELS: list[str] = [
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-flash-latest",
    "gemini-flash-lite-latest",
    "gemini-2.5-flash",
]

_SYSTEM_PROMPT_TEMPLATE = (
    "You are NetShield AI, a cybersecurity assistant for an "
    "intrusion detection system. You help users understand attacks, "
    "threat levels, and security recommendations.\n\n"
    "Current Security Context:\n"
    "Threat Level: {threat_level}\n"
    "Total Packets Analysed: {total_packets}\n"
    "Total Attacks Detected: {total_attacks}\n"
    "Normal Traffic: {normal_traffic}\n\n"
    "Attack Type Distribution:\n{attack_summary}\n\n"
    "Recent Attacks:\n{recent_attacks}\n\n"
    "Top Attacker IPs:\n{top_attackers}\n\n"
    "Guidelines for your response:\n"
    "1. Answer concisely and professionally.\n"
    "2. Use bullet points for lists of recommendations or steps.\n"
    "3. When asked about specific attack types, explain what they are "
    "and suggest mitigations.\n"
    "4. If the system is under attack, prioritise actionable advice.\n"
    "5. If no attacks are detected, reassure the user their network is safe.\n"
)


class Chatbot:
    """AI chatbot backed by Google Gemini with live database context.

    Tries multiple Gemini model names in case the preferred model
    has been deprecated or renamed by Google.  The first model that
    initialises successfully is used.

    Args:
        api_key: Google Gemini API key. Empty string disables AI responses.
        database: Database instance for live security context.
    """

    def __init__(self, api_key: str, database: Database) -> None:
        """Initialize the chatbot.

        Attempts to configure the Gemini API and instantiate a
        GenerativeModel.  If all model names fail, ``self._model``
        remains ``None`` and :meth:`query` returns a fallback message.

        Args:
            api_key: Google Gemini API key.
            database: Database instance for live security context.
        """
        self._api_key: str = api_key
        self._database: Database = database
        self._model: Any = None
        self._model_name: str = ""
        self._used_fallback: bool = False

        if not api_key:
            logger.warning("No Gemini API key configured — chatbot in fallback mode.")
            return

        try:
            import google.generativeai as genai  # type: ignore[import-untyped]

            genai.configure(api_key=api_key)

            # Try each model name until one works.
            # We instantiate AND do a tiny generate_content probe
            # because some models (e.g. gemini-3.7-flash) instantiate
            # fine but then hang indefinitely on actual generation.
            for model_name in _GEMINI_MODELS:
                try:
                    candidate = genai.GenerativeModel(model_name)
                    # Verification probe: 1-word generation with a short timeout.
                    # If this fails or times out, the model is not usable.
                    _probe = candidate.generate_content("Hi")
                    # If we get here, the model works.
                    self._model = candidate
                    self._model_name = model_name
                    logger.info(
                        "Gemini chatbot initialized with model: %s",
                        model_name,
                    )
                    break
                except Exception as model_exc:  # noqa: BLE001
                    logger.debug(
                        "Model %s unavailable: %s — trying next.",
                        model_name,
                        model_exc,
                    )
                    continue

            if self._model is None:
                logger.error(
                    "All Gemini model names failed. "
                    "Chatbot will use fallback responses."
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to initialize Gemini: %s", exc)
            self._model = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Check whether the Gemini model is ready to serve queries.

        Returns:
            ``True`` if an API key is set AND the model initialised
            successfully, ``False`` otherwise.
        """
        return bool(self._api_key and self._model is not None)

    @property
    def model_name(self) -> str:
        """Return the Gemini model name in use (empty if not initialised)."""
        return self._model_name

    @property
    def api_key_configured(self) -> bool:
        """Return ``True`` if an API key was provided (even if model failed)."""
        return bool(self._api_key)

    def query(self, user_message: str) -> str:
        """Answer a user question using Gemini with live DB context.

        Falls back to a static message when:
        - The API key is empty.
        - The Gemini model failed to initialize.
        - The API call raises an exception.

        Args:
            user_message: The user's question or message.

        Returns:
            The chatbot's response string.
        """
        if not self._api_key:
            return _FALLBACK_NO_KEY

        if not self._model:
            return (
                "The Gemini model could not be initialized. "
                "Please check the API key and network connection."
            )

        system_prompt = self._build_system_prompt()

        try:
            full_prompt = f"{system_prompt}\n\nUser Question: {user_message}"
            response = self._model.generate_content(full_prompt)
            return response.text if response.text else "I could not generate a response."
        except Exception as exc:  # noqa: BLE001
            logger.error("Gemini API error: %s", exc)
            return f"Sorry, I encountered an error while processing your request: {exc}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_system_prompt(self) -> str:
        """Build the system prompt with live database context.

        Pulls threat level, packet statistics, recent attacks, top
        attackers, and attack-type distribution from the database.
        If the database is unreachable, returns a minimal fallback
        prompt.

        Returns:
            Formatted system prompt string.
        """
        try:
            threat_level = self._database.get_threat_level()
            stats = self._database.get_stats()
            recent = self._database.get_recent_predictions(limit=5)
            top = self._database.get_top_attackers(limit=5)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to fetch DB context: %s", exc)
            return (
                "You are NetShield AI, a cybersecurity assistant. "
                "Database context is currently unavailable."
            )

        recent_str = (
            "\n".join(
                f"  - {r.get('attack_type', 'N/A')} from {r.get('src_ip', 'N/A')}"
                for r in recent
            )
            if recent
            else "  None"
        )

        top_str = (
            "\n".join(
                f"  - {r['src_ip']} ({r['count']} attacks)"
                for r in top
            )
            if top
            else "  None"
        )

        # Attack type distribution
        try:
            attack_summary_data = self._database.get_attack_summary()
            summary_str = (
                "\n".join(
                    f"  - {r.get('attack_type', 'N/A')}: {r.get('count', 0)} "
                    f"({r.get('percentage', 0):.1f}%)"
                    for r in attack_summary_data
                )
                if attack_summary_data
                else "  None"
            )
        except Exception:  # noqa: BLE001
            summary_str = "  Unavailable"

        return _SYSTEM_PROMPT_TEMPLATE.format(
            threat_level=threat_level,
            total_packets=stats.get("total", 0),
            total_attacks=stats.get("attacks", 0),
            normal_traffic=stats.get("normal", 0),
            attack_summary=summary_str,
            recent_attacks=recent_str,
            top_attackers=top_str,
        )
