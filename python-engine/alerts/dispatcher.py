"""Alert dispatcher that fans out attack alerts to all channels.

Instantiates Telegram, Email, and Voice alterers and calls each one
in sequence.  Each channel is wrapped in a try/except so a failure
in one channel never prevents the others from firing.
"""

from __future__ import annotations

import logging
from typing import Any

from alerts.email_alert import EmailAlerter
from alerts.telegram_alert import TelegramAlerter
from alerts.voice_alert import VoiceAlerter
from config import Settings
from prediction.schemas import PredictionResult

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """Dispatches attack alerts to Telegram, Email, and Voice channels.

    Args:
        settings: Application settings for configuring each alerter.
    """

    def __init__(self, settings: Settings) -> None:
        """Initialize all three alterers.

        Args:
            settings: Application settings instance.
        """
        self._telegram: TelegramAlerter = TelegramAlerter(settings)
        self._email: EmailAlerter = EmailAlerter(settings)
        self._voice: VoiceAlerter = VoiceAlerter(settings)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(self, result: PredictionResult) -> None:
        """Send an alert through all configured channels.

        Each channel is called independently with its own try/except
        so a failure in one does not affect the others.

        Args:
            result: The PredictionResult to alert on.
        """
        self._dispatch_channel("telegram", self._telegram.send_alert, result)
        self._dispatch_channel("email", self._email.send_alert, result)
        self._dispatch_channel("voice", self._voice.send_alert, result)

    def test_all(self) -> dict[str, dict[str, Any]]:
        """Test all alert channels and return their status.

        Calls ``test_connection()`` on each alerter. Each channel
        is wrapped in its own try/except so a crash in one channel
        does not prevent the others from being tested.

        Returns:
            Dictionary with keys ``"telegram"``, ``"email"``,
            ``"voice"`` — each mapping to a result dict with
            ``configured``, ``sent``, ``error``, and optionally
            ``bot_info``.
        """
        results: dict[str, dict[str, Any]] = {}

        for name, alerter in (
            ("telegram", self._telegram),
            ("email", self._email),
            ("voice", self._voice),
        ):
            try:
                results[name] = alerter.test_connection()
            except Exception as exc:  # noqa: BLE001
                logger.error("Test for channel '%s' raised: %s", name, exc)
                results[name] = {
                    "configured": getattr(alerter, "is_configured", False),
                    "sent": False,
                    "error": f"Unexpected error: {exc}",
                }

        return results

    def get_channel_status(self) -> dict[str, bool]:
        """Return a quick boolean for each channel's configured state.

        Returns:
            Dictionary like ``{"telegram": True, "email": False, "voice": True}``.
        """
        return {
            "telegram": self._telegram.is_configured,
            "email": self._email.is_configured,
            "voice": self._voice.is_configured,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dispatch_channel(
        name: str,
        send_func: callable,
        result: PredictionResult,
    ) -> None:
        """Call a single alerter's send method with graceful fallback.

        Args:
            name: Channel name for logging.
            send_func: Callable that takes a PredictionResult.
            result: The prediction result.
        """
        try:
            send_func(result)
        except Exception as exc:  # noqa: BLE001
            logger.error("Alert channel '%s' raised: %s", name, exc)
