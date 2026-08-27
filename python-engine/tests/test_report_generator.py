"""Tests for the ReportGenerator class.

Tests that the PDF file is created, non-empty, and starts with the
%PDF magic bytes.
"""

from __future__ import annotations

import os
import tempfile
import time
from unittest.mock import MagicMock

import pytest

from database import Database
from prediction.schemas import FeatureQuality, FlowContext, PredictionResult, PredictionStatus
from reports.generate_pdf import ReportGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _log_attack(db: Database, label: str, src_ip: str) -> None:
    """Log a single attack prediction into the database.

    Args:
        db: Database instance.
        label: Attack label.
        src_ip: Source IP address.
    """
    ctx = FlowContext(
        flow_id=f"flow-{label}-{src_ip}",
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        src_port=40000,
        dst_port=80,
        protocol=6,
    )
    result = PredictionResult(
        timestamp_utc=time.time(),
        status=PredictionStatus.ATTACK,
        class_id=3,
        label=label,
        is_attack=True,
        confidence=0.95,
        class_probabilities={label: 0.95, "BENIGN": 0.05},
        feature_quality=FeatureQuality.COMPLETE,
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
    db.log_prediction(result)


def _log_benign(db: Database, src_ip: str = "192.168.1.1") -> None:
    """Log a single benign prediction into the database.

    Args:
        db: Database instance.
        src_ip: Source IP address.
    """
    ctx = FlowContext(
        flow_id=f"benign-{src_ip}",
        src_ip=src_ip,
        dst_ip="10.0.0.2",
        src_port=40001,
        dst_port=443,
        protocol=6,
    )
    result = PredictionResult(
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
    db.log_prediction(result)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path) -> Database:
    """Return a Database backed by a temporary file."""
    db_path = str(tmp_path / "test_report.db")
    db = Database(db_path=db_path)
    yield db
    db.close()


@pytest.fixture
def empty_db(tmp_path) -> Database:
    """Return an empty Database."""
    db_path = str(tmp_path / "empty_report.db")
    db = Database(db_path=db_path)
    yield db
    db.close()


@pytest.fixture
def populated_db(tmp_path) -> Database:
    """Return a Database pre-populated with attack data."""
    db_path = str(tmp_path / "populated_report.db")
    db = Database(db_path=db_path)
    _log_attack(db, "DDoS", "10.0.0.1")
    _log_attack(db, "DDoS", "10.0.0.1")
    _log_attack(db, "PortScan", "10.0.0.2")
    _log_attack(db, "BruteForce", "10.0.0.3")
    _log_benign(db, "192.168.1.1")
    _log_benign(db, "192.168.1.2")
    yield db
    db.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReportGenerator:
    """Tests for the ReportGenerator class."""

    def test_generates_valid_pdf(self, populated_db: Database, tmp_path) -> None:
        """Generated file should exist, be non-empty, and start with %PDF."""
        generator = ReportGenerator(populated_db)
        output_dir = str(tmp_path / "reports")
        filepath = generator.generate(output_dir=output_dir)

        assert os.path.exists(filepath)
        with open(filepath, "rb") as f:
            content = f.read()
        assert len(content) > 0
        assert content[:5] == b"%PDF-"

    def test_empty_db_report(self, empty_db: Database, tmp_path) -> None:
        """Generating a report from an empty DB should still produce a valid PDF."""
        generator = ReportGenerator(empty_db)
        output_dir = str(tmp_path / "empty_reports")
        filepath = generator.generate(output_dir=output_dir)

        assert os.path.exists(filepath)
        with open(filepath, "rb") as f:
            content = f.read()
        assert len(content) > 0
        assert content[:5] == b"%PDF-"

    def test_creates_output_dir(self, populated_db: Database, tmp_path) -> None:
        """The output directory should be created if it does not exist."""
        generator = ReportGenerator(populated_db)
        output_dir = str(tmp_path / "nested" / "deep" / "reports")
        filepath = generator.generate(output_dir=output_dir)

        assert os.path.exists(filepath)
        assert os.path.isdir(output_dir)

    def test_returns_absolute_path(self, populated_db: Database, tmp_path) -> None:
        """The returned path should be absolute."""
        generator = ReportGenerator(populated_db)
        filepath = generator.generate(output_dir=str(tmp_path / "r"))
        assert os.path.isabs(filepath)

    def test_report_with_various_attacks(self, populated_db: Database, tmp_path) -> None:
        """A report with DDoS, PortScan, and BruteForce should generate cleanly."""
        generator = ReportGenerator(populated_db)
        filepath = generator.generate(output_dir=str(tmp_path / "varied"))
        assert os.path.exists(filepath)

        # Verify file size is reasonable (at least a few KB for a multi-page PDF)
        file_size = os.path.getsize(filepath)
        assert file_size > 1000

    def test_mock_db_exception_handled(self, tmp_path) -> None:
        """If DB methods raise, the generator should still produce a PDF."""
        mock_db = MagicMock(spec=Database)
        mock_db.get_stats.side_effect = Exception("DB error")
        mock_db.get_threat_level.side_effect = Exception("DB error")
        mock_db.get_attack_summary.side_effect = Exception("DB error")
        mock_db.get_top_attackers.side_effect = Exception("DB error")

        generator = ReportGenerator(mock_db)
        filepath = generator.generate(output_dir=str(tmp_path / "mock"))
        assert os.path.exists(filepath)
        with open(filepath, "rb") as f:
            assert f.read()[:5] == b"%PDF-"
