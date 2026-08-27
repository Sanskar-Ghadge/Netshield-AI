"""Tests for the AlertDispatcher and individual alterers.

Tests graceful skip on empty credentials, cooldown logic, and
that voice alerts run in a separate thread.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from alerts.dispatcher import AlertDispatcher
from alerts.email_alert import EmailAlerter
from alerts.telegram_alert import TelegramAlerter
from alerts.voice_alert import VoiceAlerter
from config import Settings
from prediction.schemas import FlowContext, PredictionResult, PredictionStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_attack_result(
    label: str = "DDoS",
    src_ip: str = "192.168.1.100",
) -> PredictionResult:
    """Build a PredictionResult representing an attack.

    Args:
        label: Attack label.
        src_ip: Source IP for the flow context.

    Returns:
        A PredictionResult with is_attack=True.
    """
    ctx = FlowContext(
        flow_id="flow-1",
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        src_port=44332,
        dst_port=80,
        protocol=6,
    )
    return PredictionResult(
        timestamp_utc=time.time(),
        status=PredictionStatus.ATTACK,
        class_id=3,
        label=label,
        is_attack=True,
        confidence=0.95,
        class_probabilities={label: 0.95, "BENIGN": 0.05},
        feature_quality=__import__("prediction.schemas", fromlist=["FeatureQuality"]).FeatureQuality.COMPLETE,
        missing_fields=(),
        imputed_fields=(),
        rejected_fields=(),
        context=ctx,
        model_version="v3",
        preprocessing_version=3,
        inference_ms=1.5,
        is_partial_flow=False,
        known_attack_model=True,
        generalization_warning="warning",
        error="",
    )


def _make_benign_result() -> PredictionResult:
    """Build a PredictionResult representing benign traffic."""
    from prediction.schemas import FeatureQuality

    ctx = FlowContext(
        flow_id="flow-2",
        src_ip="192.168.1.50",
        dst_ip="10.0.0.2",
        src_port=44333,
        dst_port=443,
        protocol=6,
    )
    return PredictionResult(
        timestamp_utc=time.time(),
        status=PredictionStatus.BENIGN,
        class_id=0,
        label="BENIGN",
        is_attack=False,
        confidence=0.99,
        class_probabilities={"BENIGN": 0.99},
        feature_quality=FeatureQuality.COMPLETE,
        missing_fields=(),
        imputed_fields=(),
        rejected_fields=(),
        context=ctx,
        model_version="v3",
        preprocessing_version=3,
        inference_ms=1.0,
        is_partial_flow=False,
        known_attack_model=True,
        generalization_warning="warning",
        error="",
    )


# ---------------------------------------------------------------------------
# TelegramAlerter tests
# ---------------------------------------------------------------------------


class TestTelegramAlerter:
    """Tests for TelegramAlerter."""

    def test_empty_token_skips(self) -> None:
        """Empty bot token should log a warning and return False."""
        settings = Settings(telegram_bot_token="", telegram_chat_id="123")
        alerter = TelegramAlerter(settings)
        result = alerter.send_alert(_make_attack_result())
        assert result is False

    def test_empty_chat_id_skips(self) -> None:
        """Empty chat ID should skip."""
        settings = Settings(telegram_bot_token="token", telegram_chat_id="")
        alerter = TelegramAlerter(settings)
        result = alerter.send_alert(_make_attack_result())
        assert result is False

    def test_benign_skips(self) -> None:
        """Benign predictions should not trigger a Telegram alert."""
        settings = Settings(telegram_bot_token="token", telegram_chat_id="123")
        alerter = TelegramAlerter(settings)
        result = alerter.send_alert(_make_benign_result())
        assert result is False

    def test_cooldown_blocks_second_send(self) -> None:
        """Second send within cooldown should be blocked."""
        settings = Settings(
            telegram_bot_token="token",
            telegram_chat_id="123",
            alert_cooldown_s=3600,
        )
        alerter = TelegramAlerter(settings)
        with patch("alerts.telegram_alert.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_post.return_value = mock_resp

            first = alerter.send_alert(_make_attack_result())
            assert first is True

            second = alerter.send_alert(_make_attack_result())
            assert second is False  # blocked by cooldown

    def test_successful_send(self) -> None:
        """A valid attack with good credentials should send."""
        settings = Settings(
            telegram_bot_token="valid_token",
            telegram_chat_id="123456",
            alert_cooldown_s=0,
        )
        alerter = TelegramAlerter(settings)
        with patch("alerts.telegram_alert.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_post.return_value = mock_resp
            result = alerter.send_alert(_make_attack_result())
            assert result is True
            assert mock_post.called

    def test_api_error_returns_false(self) -> None:
        """A non-200 API response should return False."""
        settings = Settings(
            telegram_bot_token="token",
            telegram_chat_id="123",
            alert_cooldown_s=0,
        )
        alerter = TelegramAlerter(settings)
        with patch("alerts.telegram_alert.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 401
            mock_resp.text = "Unauthorized"
            mock_post.return_value = mock_resp
            result = alerter.send_alert(_make_attack_result())
            assert result is False

    def test_network_exception_returns_false(self) -> None:
        """A network exception should not propagate."""
        settings = Settings(
            telegram_bot_token="token",
            telegram_chat_id="123",
            alert_cooldown_s=0,
        )
        alerter = TelegramAlerter(settings)
        with patch("alerts.telegram_alert.requests.post", side_effect=ConnectionError("network down")):
            result = alerter.send_alert(_make_attack_result())
            assert result is False


# ---------------------------------------------------------------------------
# EmailAlerter tests
# ---------------------------------------------------------------------------


class TestEmailAlerter:
    """Tests for EmailAlerter."""

    def test_empty_password_skips(self) -> None:
        """Empty password should skip."""
        settings = Settings(
            email_sender="a@b.com",
            email_password="",
            email_recipient="c@d.com",
        )
        alerter = EmailAlerter(settings)
        result = alerter.send_alert(_make_attack_result())
        assert result is False

    def test_empty_sender_skips(self) -> None:
        """Empty sender should skip."""
        settings = Settings(
            email_sender="",
            email_password="pass",
            email_recipient="c@d.com",
        )
        alerter = EmailAlerter(settings)
        result = alerter.send_alert(_make_attack_result())
        assert result is False

    def test_empty_recipient_skips(self) -> None:
        """Empty recipient should skip."""
        settings = Settings(
            email_sender="a@b.com",
            email_password="pass",
            email_recipient="",
        )
        alerter = EmailAlerter(settings)
        result = alerter.send_alert(_make_attack_result())
        assert result is False

    def test_benign_skips(self) -> None:
        """Benign predictions should not trigger an email."""
        settings = Settings(
            email_sender="a@b.com",
            email_password="pass",
            email_recipient="c@d.com",
        )
        alerter = EmailAlerter(settings)
        result = alerter.send_alert(_make_benign_result())
        assert result is False

    def test_cooldown_blocks_second_send(self) -> None:
        """Second send within 5-minute cooldown should be blocked."""
        settings = Settings(
            email_sender="a@b.com",
            email_password="pass",
            email_recipient="c@d.com",
        )
        alerter = EmailAlerter(settings)
        with patch("alerts.email_alert._COOLDOWN_S", 999999):
            with patch("alerts.email_alert.smtplib.SMTP") as mock_smtp:
                mock_server = MagicMock()
                mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
                mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

                first = alerter.send_alert(_make_attack_result())
                assert first is True

                second = alerter.send_alert(_make_attack_result())
                assert second is False

    def test_smtp_exception_returns_false(self) -> None:
        """An SMTP exception should not propagate."""
        settings = Settings(
            email_sender="a@b.com",
            email_password="pass",
            email_recipient="c@d.com",
        )
        alerter = EmailAlerter(settings)
        with patch("alerts.email_alert.smtplib.SMTP", side_effect=Exception("SMTP error")):
            result = alerter.send_alert(_make_attack_result())
            assert result is False


# ---------------------------------------------------------------------------
# VoiceAlerter tests
# ---------------------------------------------------------------------------


class TestVoiceAlerter:
    """Tests for VoiceAlerter."""

    def test_disabled_voice_skips(self) -> None:
        """When voice_alerts=False, no alert should fire."""
        settings = Settings(voice_alerts=False)
        alerter = VoiceAlerter(settings)
        result = alerter.send_alert(_make_attack_result())
        assert result is False

    def test_benign_skips(self) -> None:
        """Benign predictions should not trigger voice alert."""
        settings = Settings(voice_alerts=True)
        alerter = VoiceAlerter(settings)
        result = alerter.send_alert(_make_benign_result())
        assert result is False

    def test_voice_runs_in_thread(self) -> None:
        """Voice alert should run in a separate thread."""
        settings = Settings(voice_alerts=True)
        alerter = VoiceAlerter(settings)

        started_threads: list[threading.Thread] = []

        original_thread_init = threading.Thread.__init__

        def capture_thread(self_thread, *args, **kwargs):
            """Capture thread creation."""
            original_thread_init(self_thread, *args, **kwargs)
            started_threads.append(self_thread)

        with patch.object(threading.Thread, "__init__", capture_thread):
            with patch.object(VoiceAlerter, "_speak") as mock_speak:
                result = alerter.send_alert(_make_attack_result())
                assert result is True
                assert len(started_threads) == 1

    def test_no_cooldown(self) -> None:
        """Voice alerts should have no cooldown — multiple sends allowed."""
        settings = Settings(voice_alerts=True)
        alerter = VoiceAlerter(settings)
        with patch.object(VoiceAlerter, "_speak"):
            r1 = alerter.send_alert(_make_attack_result())
            r2 = alerter.send_alert(_make_attack_result())
            assert r1 is True
            assert r2 is True


# ---------------------------------------------------------------------------
# AlertDispatcher tests
# ---------------------------------------------------------------------------


class TestAlertDispatcher:
    """Tests for AlertDispatcher."""

    def test_dispatch_calls_all_channels(self) -> None:
        """dispatch() should call Telegram, Email, and Voice alterers."""
        settings = Settings(
            telegram_bot_token="token",
            telegram_chat_id="123",
            email_sender="a@b.com",
            email_password="pass",
            email_recipient="c@d.com",
            voice_alerts=True,
            alert_cooldown_s=0,
        )
        dispatcher = AlertDispatcher(settings)

        with patch.object(dispatcher._telegram, "send_alert", return_value=False) as mock_t, \
             patch.object(dispatcher._email, "send_alert", return_value=False) as mock_e, \
             patch.object(dispatcher._voice, "send_alert", return_value=False) as mock_v:
            dispatcher.dispatch(_make_attack_result())
            assert mock_t.called
            assert mock_e.called
            assert mock_v.called

    def test_dispatch_channel_failure_does_not_block_others(self) -> None:
        """If one channel raises, others should still be called."""
        settings = Settings(
            telegram_bot_token="token",
            telegram_chat_id="123",
            email_sender="a@b.com",
            email_password="pass",
            email_recipient="c@d.com",
            voice_alerts=True,
        )
        dispatcher = AlertDispatcher(settings)

        with patch.object(dispatcher._telegram, "send_alert", side_effect=RuntimeError("boom")), \
             patch.object(dispatcher._email, "send_alert", return_value=False) as mock_e, \
             patch.object(dispatcher._voice, "send_alert", return_value=False) as mock_v:
            # Should not raise
            dispatcher.dispatch(_make_attack_result())
            assert mock_e.called
            assert mock_v.called

    def test_dispatch_empty_credentials_graceful(self) -> None:
        """With all credentials empty, dispatch should not raise."""
        settings = Settings(
            telegram_bot_token="",
            telegram_chat_id="",
            email_sender="",
            email_password="",
            email_recipient="",
            voice_alerts=False,
        )
        dispatcher = AlertDispatcher(settings)
        # Should not raise
        dispatcher.dispatch(_make_attack_result())
