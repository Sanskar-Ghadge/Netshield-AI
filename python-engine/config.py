"""Centralised configuration for NetShield AI.

All settings are loaded from environment variables and/or a ``.env`` file
at the project root.  Every default is safe: empty strings for API keys
and credentials mean the feature gracefully skips, and ``capture_enabled``
can be turned off for testing.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root (two levels up from python-engine/)
_PROJECT_ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    """Application-wide settings loaded from ``.env``.

    Attributes:
        host: Bind address for the FastAPI server.
        python_port: Port for the FastAPI server.
        node_port: Port for the Node.js server (informational).
        db_path: Path to the SQLite database file.
        model_path: Override path for the XGBoost model artifact.
        preprocessor_path: Override path for the preprocessor artifact.
        encoder_path: Override path for the label encoder artifact.
        metadata_path: Override path for the JSON metadata.
        capture_enabled: Whether to start live packet capture on startup.
        capture_interface: Network interface to sniff (None = Scapy default).
        capture_bpf_filter: Optional BPF filter string.
        idle_timeout_s: Idle-flow eviction threshold in seconds.
        attack_confidence_threshold: Minimum confidence (0–1) for an
            attack prediction to be accepted. Below this, downgraded to
            BENIGN. Prevents false positives from near-50% guesses.
        gemini_api_key: Google Gemini API key (empty = chatbot disabled).
        telegram_bot_token: Telegram bot token (empty = Telegram disabled).
        telegram_chat_id: Telegram chat ID to send alerts to.
        email_sender: Gmail address for email alerts (empty = disabled).
        email_password: Gmail app password for email alerts.
        email_recipient: Recipient email address for alerts.
        alert_cooldown_s: Minimum seconds between Telegram/Email alerts.
        voice_alerts: Whether to announce attacks via pyttsx3.
        report_dir: Directory for generated PDF reports.
    """

    # ── Server ──────────────────────────────────────────────────
    host: str = "0.0.0.0"
    python_port: int = 8000
    node_port: int = 3001

    # ── Database ────────────────────────────────────────────────
    db_path: str = str(_PROJECT_ROOT / "python-engine" / "netshield.db")

    # ── Model artifacts (v3 defaults) ────────────────────────────
    model_path: str = ""
    preprocessor_path: str = ""
    encoder_path: str = ""
    metadata_path: str = ""

    # ── Live capture ─────────────────────────────────────────────
    capture_enabled: bool = True
    capture_interface: str | None = None
    capture_bpf_filter: str | None = None
    idle_timeout_s: float = 120.0

    # ── Prediction filtering ─────────────────────────────────────
    # Minimum confidence (0–1) for an attack classification to be
    # accepted. Predictions below this threshold are downgraded to BENIGN.
    attack_confidence_threshold: float = 0.80

    # ── Gemini chatbot ──────────────────────────────────────────
    gemini_api_key: str = ""

    # ── Telegram alerts ──────────────────────────────────────────
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    # ── Email alerts ─────────────────────────────────────────────
    email_sender: str = ""
    email_password: str = ""
    email_recipient: str = ""

    # ── Alert behaviour ──────────────────────────────────────────
    alert_cooldown_s: int = 30
    voice_alerts: bool = True

    # ── Reports ─────────────────────────────────────────────────
    report_dir: str = str(_PROJECT_ROOT / "reports")

    # ── Pydantic settings ───────────────────────────────────────
    model_config = SettingsConfigDict(
        env_file=str(_PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Convenience: resolved artifact paths
    # ------------------------------------------------------------------

    def resolved_model_path(self) -> Path:
        """Return the model artifact path (override or v3 default)."""
        if self.model_path:
            return Path(self.model_path)
        return _PROJECT_ROOT / "python-engine" / "models" / "v3" / "intrusion_model_v3.pkl"

    def resolved_preprocessor_path(self) -> Path:
        """Return the preprocessor artifact path."""
        if self.preprocessor_path:
            return Path(self.preprocessor_path)
        return _PROJECT_ROOT / "python-engine" / "models" / "v3" / "preprocessor_v3.pkl"

    def resolved_encoder_path(self) -> Path:
        """Return the label encoder artifact path."""
        if self.encoder_path:
            return Path(self.encoder_path)
        return _PROJECT_ROOT / "python-engine" / "models" / "v3" / "label_encoder_v3.pkl"

    def resolved_metadata_path(self) -> Path:
        """Return the metadata JSON path."""
        if self.metadata_path:
            return Path(self.metadata_path)
        return _PROJECT_ROOT / "python-engine" / "models" / "v3" / "preprocessing_metadata_v3.json"


def get_settings() -> Settings:
    """Factory that returns a fresh ``Settings`` instance.

    Returns:
        Settings populated from the environment and ``.env`` file.
    """
    return Settings()
