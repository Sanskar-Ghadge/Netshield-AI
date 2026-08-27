"""Gemini-powered security chatbot for NetShield AI.

Uses Google's Generative AI (Gemini) to answer user questions about
the current security state of the system.  The system prompt is
dynamically enriched with live database context (threat level,
recent attacks, top attackers, attack distribution).

Rate-limit handling:
    If the primary model hits a 429 (quota exceeded), the chatbot
    automatically falls back to the next model in the priority list.
    If ALL models are rate-limited, a user-friendly message is
    returned instead of the raw API error.
"""

from __future__ import annotations

import logging
import re
import time
import warnings
from typing import Any, Optional

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

_FALLBACK_RATE_LIMITED = (
    "I'm currently experiencing high demand and my API quota has been "
    "temporarily reached. Please try again in a minute or two. "
    "Your network is still being monitored — only the chatbot is affected."
)

_FALLBACK_MODEL_ERROR = (
    "The AI model could not generate a response right now. "
    "Please try again shortly. Your network monitoring is unaffected."
)

# Models to try in order — the first that WORKS wins.
# If a model hits a 429 rate limit during a query, we fall back
# to the next one automatically.
_GEMINI_MODELS: list[str] = [
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-flash-latest",
    "gemini-flash-lite-latest",
    "gemini-2.5-flash",
]

# Regex to detect 429 / quota-exceeded errors from the Gemini SDK.
_RATE_LIMIT_PATTERN = re.compile(r"429|quota.*exceeded|rate.*limit|RESOURCE_EXHAUSTED", re.IGNORECASE)


def _is_rate_limit_error(exc: Exception) -> bool:
    """Check whether an exception is a Gemini rate-limit / quota error.

    Args:
        exc: The caught exception.

    Returns:
        ``True`` if the error indicates a 429 / quota / rate-limit.
    """
    msg = str(exc)
    if _RATE_LIMIT_PATTERN.search(msg):
        return True
    # The google-generativeai SDK raises google.api_core.exceptions.ResourceExhausted
    # which has a .code attribute or is a subclass we can detect.
    exc_type = type(exc).__name__.lower()
    if "resourceexhausted" in exc_type or "rate" in exc_type:
        return True
    return False


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
    has been deprecated, renamed, or rate-limited by Google.
    The first model that initialises successfully is used as primary.
    If it hits a 429 during a query, the next model is tried.

    Args:
        api_key: Google Gemini API key. Empty string disables AI responses.
        database: Database instance for live security context.
    """

    def __init__(self, api_key: str, database: Database) -> None:
        """Initialize the chatbot.

        Attempts to configure the Gemini API and instantiate a
        GenerativeModel for each model name in priority order.
        The first model that successfully responds to a tiny probe
        becomes the primary.  All working models are kept in a pool
        so we can fall back if the primary is rate-limited.

        Args:
            api_key: Google Gemini API key.
            database: Database instance for live security context.
        """
        self._api_key: str = api_key
        self._database: Database = database
        self._models: list[Any] = []
        self._model_names: list[str] = []
        self._primary_index: int = -1
        self._used_fallback: bool = False

        if not api_key:
            logger.warning("No Gemini API key configured — chatbot in fallback mode.")
            return

        try:
            import google.generativeai as genai  # type: ignore[import-untyped]

            genai.configure(api_key=api_key)

            # Probe each model — keep all that work, not just the first.
            for model_name in _GEMINI_MODELS:
                try:
                    candidate = genai.GenerativeModel(model_name)
                    _probe = candidate.generate_content("Hi")
                    self._models.append(candidate)
                    self._model_names.append(model_name)
                    logger.info("Model %s: OK", model_name)
                except Exception as model_exc:  # noqa: BLE001
                    is_rl = _is_rate_limit_error(model_exc)
                    level = logging.WARNING if is_rl else logging.DEBUG
                    logger.log(
                        level,
                        "Model %s %s: %s",
                        model_name,
                        "rate-limited" if is_rl else "unavailable",
                        model_exc,
                    )
                    # If rate-limited, still add it to the pool — it may
                    # become available later.
                    if is_rl:
                        self._models.append(candidate)
                        self._model_names.append(model_name)
                    continue

            if self._models:
                self._primary_index = 0
                logger.info(
                    "Gemini chatbot initialized — primary: %s (%d model(s) in pool)",
                    self._model_names[0],
                    len(self._models),
                )
            else:
                logger.error(
                    "All Gemini model names failed. "
                    "Chatbot will use fallback responses."
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to initialize Gemini: %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Check whether at least one Gemini model is ready to serve queries.

        Returns:
            ``True`` if an API key is set AND at least one model is in the pool.
        """
        return bool(self._api_key and self._models)

    @property
    def model_name(self) -> str:
        """Return the Gemini model name in use (empty if not initialised)."""
        if self._primary_index >= 0 and self._primary_index < len(self._model_names):
            return self._model_names[self._primary_index]
        return ""

    @property
    def api_key_configured(self) -> bool:
        """Return ``True`` if an API key was provided (even if model failed)."""
        return bool(self._api_key)

    def query(self, user_message: str) -> str:
        """Answer a user question using Gemini with live DB context.

        Tries the primary model first.  If it returns a 429 (rate limit),
        automatically falls back to the next model in the pool.
        If ALL models are rate-limited, returns a user-friendly message
        instead of the raw API error.

        Falls back to a static message when:
        - The API key is empty.
        - No models are in the pool.

        Args:
            user_message: The user's question or message.

        Returns:
            The chatbot's response string.
        """
        if not self._api_key:
            return _FALLBACK_NO_KEY

        if not self._models:
            return _FALLBACK_MODEL_ERROR

        system_prompt = self._build_system_prompt()
        full_prompt = f"{system_prompt}\n\nUser Question: {user_message}"

        # Try each model in the pool; skip rate-limited ones.
        for i, model in enumerate(self._models):
            model_name = self._model_names[i] if i < len(self._model_names) else f"model-{i}"
            try:
                response = model.generate_content(full_prompt)
                if response.text:
                    logger.info("Chatbot responded via %s", model_name)
                    return response.text
                # Empty response — try next model
                logger.warning("Model %s returned empty response, trying next.", model_name)
            except Exception as exc:  # noqa: BLE001
                if _is_rate_limit_error(exc):
                    logger.warning(
                        "Model %s rate-limited, trying next model.", model_name
                    )
                    continue
                # Non-rate-limit error (e.g. 500, network) — try next model
                logger.error("Model %s error: %s — trying next.", model_name, exc)
                continue

        # All models exhausted
        logger.warning("All Gemini models rate-limited or failed.")
        return _FALLBACK_RATE_LIMITED

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
