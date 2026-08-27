"""Voice alert channel for NetShield AI.

Uses the offline pyttsx3 text-to-speech engine to announce attacks
audibly.  Announcements run in a separate thread so the caller is
never blocked.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

from config import Settings
from prediction.schemas import PredictionResult

logger = logging.getLogger(__name__)


class VoiceAlerter:
    """Announces attacks using offline text-to-speech.

    Args:
        settings: Application settings (uses ``voice_alerts`` flag).
    """

    def __init__(self, settings: Settings) -> None:
        """Initialize the voice alerter.

        Args:
            settings: Application settings instance.
        """
        self._enabled: bool = settings.voice_alerts

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        """Return ``True`` if voice alerts are enabled in settings."""
        return self._enabled

    def test_connection(self) -> dict[str, Any]:
        """Announce a test message to verify TTS works.

        Runs in a background thread so the caller is never blocked.

        Returns:
            Dictionary with keys:
                - ``configured``: bool — voice alerts are enabled.
                - ``sent``: bool — announcement was queued.
                - ``error``: str | None — error message if any.
        """
        if not self._enabled:
            return {
                "configured": False,
                "sent": False,
                "error": "Voice alerts are disabled in settings.",
            }

        test_message = "NetShield AI voice alerts are now active."
        thread = threading.Thread(
            target=self._speak, args=(test_message,), daemon=True
        )
        thread.start()
        logger.info("Voice test queued: %s", test_message)
        return {
            "configured": True,
            "sent": True,
            "error": None,
        }

    def send_alert(self, result: PredictionResult) -> bool:
        """Announce an attack via text-to-speech in a background thread.

        Does nothing when:
        - Voice alerts are disabled in settings.
        - The prediction is benign or rejected.
        - pyttsx3 is not installed.

        Args:
            result: The PredictionResult to announce.

        Returns:
            True if an announcement was queued, False otherwise.
        """
        if not self._enabled:
            return False

        if not result.is_attack:
            return False

        ctx = result.context
        src_ip = ctx.src_ip if ctx else "unknown"
        message = f"Warning! {result.label} detected from IP {src_ip}"

        thread = threading.Thread(
            target=self._speak, args=(message,), daemon=True
        )
        thread.start()
        logger.info("Voice alert queued: %s", message)
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _speak(message: str) -> None:
        """Run the TTS engine in the calling thread.

        Args:
            message: The text to speak.
        """
        try:
            import pyttsx3  # type: ignore[import-untyped]

            engine = pyttsx3.init()
            engine.say(message)
            engine.runAndWait()
            engine.stop()
        except Exception as exc:  # noqa: BLE001
            logger.error("Voice alert failed: %s", exc)
