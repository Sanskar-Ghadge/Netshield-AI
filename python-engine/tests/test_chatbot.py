"""Tests for the Chatbot class.

Tests empty-key fallback and that query() returns a string.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from chatbot.chatbot import Chatbot
from database import Database
from prediction.schemas import FeatureQuality, FlowContext, PredictionResult, PredictionStatus


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db() -> MagicMock:
    """Return a mock Database."""
    db = MagicMock(spec=Database)
    db.get_threat_level.return_value = "ELEVATED"
    db.get_stats.return_value = {
        "total": 100,
        "normal": 80,
        "attacks": 20,
        "attack_distribution": [],
    }
    db.get_recent_predictions.return_value = [
        {"attack_type": "DDoS", "src_ip": "10.0.0.1"},
        {"attack_type": "PortScan", "src_ip": "10.0.0.2"},
    ]
    db.get_top_attackers.return_value = [
        {"src_ip": "10.0.0.1", "count": 15},
        {"src_ip": "10.0.0.2", "count": 5},
    ]
    return db


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestChatbot:
    """Tests for the Chatbot class."""

    def test_empty_key_returns_fallback(self, mock_db: MagicMock) -> None:
        """With an empty API key, query should return the fallback message."""
        bot = Chatbot(api_key="", database=mock_db)
        response = bot.query("What attacks happened?")
        assert isinstance(response, str)
        assert "Gemini API key" in response

    def test_query_returns_string(self, mock_db: MagicMock) -> None:
        """query() should always return a string."""
        bot = Chatbot(api_key="", database=mock_db)
        response = bot.query("any question")
        assert isinstance(response, str)

    def test_empty_key_does_not_call_gemini(self, mock_db: MagicMock) -> None:
        """With an empty key, the Gemini library should not be loaded."""
        with patch("google.generativeai.configure") as mock_configure:
            bot = Chatbot(api_key="", database=mock_db)
            assert mock_configure.call_count == 0

    def test_model_not_initialized_returns_fallback(self, mock_db: MagicMock) -> None:
        """If model init fails, query should return an error message."""
        with patch("google.generativeai.configure", side_effect=Exception("init failed")):
            bot = Chatbot(api_key="fake_key", database=mock_db)
            response = bot.query("hello")
            assert isinstance(response, str)
            assert "could not generate a response" in response.lower()

    def test_successful_query(self, mock_db: MagicMock) -> None:
        """A successful Gemini call should return the model's text."""
        with patch("google.generativeai.configure"), \
             patch("google.generativeai.GenerativeModel") as mock_model_cls:
            mock_model = MagicMock()
            mock_response = MagicMock()
            mock_response.text = "DDoS is a distributed denial of service attack."
            mock_model.generate_content.return_value = mock_response
            mock_model_cls.return_value = mock_model

            bot = Chatbot(api_key="fake_key", database=mock_db)
            response = bot.query("What is DDoS?")
            assert isinstance(response, str)
            assert "DDoS" in response

    def test_api_error_returns_graceful_message(self, mock_db: MagicMock) -> None:
        """If the Gemini API raises, query should return a graceful message."""
        with patch("google.generativeai.configure"), \
             patch("google.generativeai.GenerativeModel") as mock_model_cls:
            mock_model = MagicMock()
            mock_model.generate_content.side_effect = Exception("API rate limit")
            mock_model_cls.return_value = mock_model

            bot = Chatbot(api_key="fake_key", database=mock_db)
            response = bot.query("tell me about attacks")
            assert isinstance(response, str)
            assert "quota" in response.lower() or "demand" in response.lower()


    def test_system_prompt_contains_db_context(self, mock_db: MagicMock) -> None:
        """The system prompt should include threat level and recent attacks."""
        with patch("google.generativeai.configure"), \
             patch("google.generativeai.GenerativeModel") as mock_model_cls:
            mock_model = MagicMock()
            mock_response = MagicMock()
            mock_response.text = "Response"
            mock_model.generate_content.return_value = mock_response
            mock_model_cls.return_value = mock_model

            bot = Chatbot(api_key="fake_key", database=mock_db)
            bot.query("test")

            # Check the prompt passed to generate_content
            call_args = mock_model.generate_content.call_args
            prompt = call_args[0][0] if call_args[0] else call_args[1].get("prompt", "")
            assert "ELEVATED" in prompt
            assert "100" in prompt  # total packets
            assert "10.0.0.1" in prompt  # top attacker

    def test_db_error_handled(self, mock_db: MagicMock) -> None:
        """If DB queries fail, the chatbot should still return a string."""
        mock_db.get_threat_level.side_effect = Exception("DB down")
        with patch("google.generativeai.configure"), \
             patch("google.generativeai.GenerativeModel") as mock_model_cls:
            mock_model = MagicMock()
            mock_response = MagicMock()
            mock_response.text = "Database context unavailable."
            mock_model.generate_content.return_value = mock_response
            mock_model_cls.return_value = mock_model

            bot = Chatbot(api_key="fake_key", database=mock_db)
            response = bot.query("status")
            assert isinstance(response, str)
