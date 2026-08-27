"""Telegram alert channel for NetShield AI.

Sends attack alerts to a configured Telegram chat via the Bot API.
Respects a per-alterter cooldown so a flood of identical attacks
does not spam the chat.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from config import Settings
from prediction.schemas import PredictionResult

logger = logging.getLogger(__name__)

_TELEGRAM_API_BASE = "https://api.telegram.org"


class TelegramAlerter:
    """Sends attack alerts to a Telegram chat.

    Args:
        settings: Application settings containing the bot token and chat ID.
    """

    def __init__(self, settings: Settings) -> None:
        """Initialize the alerter.

        Args:
            settings: Application settings instance.
        """
        self._token: str = settings.telegram_bot_token
        self._chat_id: str = settings.telegram_chat_id
        self._cooldown_s: int = settings.alert_cooldown_s
        self._last_sent: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        """Return ``True`` if both bot token and chat ID are set."""
        return bool(self._token and self._chat_id)

    def test_connection(self) -> dict[str, Any]:
        """Send a test message to verify Telegram connectivity.

        Bypasses the cooldown mechanism since this is a manual test.
        Calls the Telegram Bot API ``sendMessage`` endpoint with a
        fixed test message.

        Returns:
            Dictionary with keys:
                - ``configured``: bool — credentials are present.
                - ``sent``: bool — message was accepted by Telegram.
                - ``error``: str | None — error message if any.
                - ``bot_info``: dict | None — bot identity from getMe.
        """
        if not self.is_configured:
            return {
                "configured": False,
                "sent": False,
                "error": "Bot token or chat ID not set.",
                "bot_info": None,
            }

        # First, verify the bot identity via getMe
        bot_info: dict[str, Any] | None = None
        try:
            me_url = f"{_TELEGRAM_API_BASE}/bot{self._token}/getMe"
            me_resp = requests.get(me_url, timeout=10)
            if me_resp.status_code == 200:
                me_data = me_resp.json()
                if me_data.get("ok"):
                    bot_info = me_data.get("result", {})
            else:
                return {
                    "configured": True,
                    "sent": False,
                    "error": f"Telegram getMe failed: HTTP {me_resp.status_code}",
                    "bot_info": None,
                }
        except Exception as exc:  # noqa: BLE001
            return {
                "configured": True,
                "sent": False,
                "error": f"Connection error during getMe: {exc}",
                "bot_info": None,
            }

        # Send the test message
        test_text = (
            "🟢 <b>NetShield AI</b>\n"
            "Telegram alerts are now <b>active</b>.\n"
            f"Bot: @{bot_info.get('username', 'unknown')}\n"
            "You will receive alerts when attacks are detected."
        )
        url = f"{_TELEGRAM_API_BASE}/bot{self._token}/sendMessage"

        try:
            resp = requests.post(
                url,
                data={
                    "chat_id": self._chat_id,
                    "text": test_text,
                    "parse_mode": "HTML",
                },
                timeout=10,
            )
            if resp.status_code != 200:
                return {
                    "configured": True,
                    "sent": False,
                    "error": f"Telegram sendMessage failed: HTTP {resp.status_code} — {resp.text}",
                    "bot_info": bot_info,
                }
            logger.info("Telegram test message sent successfully.")
            return {
                "configured": True,
                "sent": True,
                "error": None,
                "bot_info": bot_info,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "configured": True,
                "sent": False,
                "error": f"Connection error during sendMessage: {exc}",
                "bot_info": bot_info,
            }

    def send_alert(self, result: PredictionResult) -> bool:
        """Send a Telegram alert for an attack prediction.

        Returns early (without sending) when:
        - The bot token or chat ID is empty.
        - The prediction is benign or rejected.
        - The cooldown period has not elapsed since the last send.

        Args:
            result: The PredictionResult to alert on.

        Returns:
            True if a message was sent successfully, False otherwise.
        """
        if not self.is_configured:
            logger.warning("Telegram credentials not configured; skipping alert.")
            return False

        if not result.is_attack:
            return False

        now = time.time()
        if now - self._last_sent < self._cooldown_s:
            logger.debug("Telegram alert on cooldown; skipping.")
            return False

        text = self._format_message(result)
        url = f"{_TELEGRAM_API_BASE}/bot{self._token}/sendMessage"

        try:
            resp = requests.post(
                url,
                data={"chat_id": self._chat_id, "text": text, "parse_mode": "HTML"},
                timeout=10,
            )
            if resp.status_code != 200:
                logger.error(
                    "Telegram API error %d: %s", resp.status_code, resp.text
                )
                return False
            self._last_sent = now
            logger.info("Telegram alert sent for %s.", result.label)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to send Telegram alert: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_message(result: PredictionResult) -> str:
        """Build the HTML-formatted Telegram message body.

        Args:
            result: The attack prediction result.

        Returns:
            HTML string for Telegram's parse_mode=HTML.
        """
        ctx = result.context
        src_ip = ctx.src_ip if ctx else "unknown"
        dst_ip = ctx.dst_ip if ctx else "unknown"
        src_port = ctx.src_port if ctx else 0
        dst_port = ctx.dst_port if ctx else 0

        return (
            "<b>⚠️ Attack Detected</b>\n"
            f"<b>Type:</b> {result.label}\n"
            f"<b>Confidence:</b> {result.confidence:.2%}\n"
            f"<b>Source:</b> {src_ip}:{src_port}\n"
            f"<b>Destination:</b> {dst_ip}:{dst_port}\n"
            f"<b>Time (UTC):</b> {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(result.timestamp_utc))}"
        )
