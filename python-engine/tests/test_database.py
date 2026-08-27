"""Tests for the SQLite Database layer (Stage 5.2)."""

from __future__ import annotations

import os
import sys
import tempfile
import time

import pytest

_ENGINE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ENGINE_ROOT not in sys.path:
    sys.path.insert(0, _ENGINE_ROOT)

from database import Database
from prediction.schemas import (
    FlowContext,
    PredictionResult,
    PredictionStatus,
    FeatureQuality,
)


def _make_result(
    label: str = "BENIGN",
    is_attack: bool = False,
    confidence: float = 0.95,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: int = 6,
    timestamp: float | None = None,
) -> PredictionResult:
    ctx = FlowContext(
        flow_id=f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        total_packets=5,
        flow_duration_us=1_000_000,
        is_completed=True,
    )
    return PredictionResult(
        timestamp_utc=timestamp if timestamp is not None else time.time(),
        status=PredictionStatus.ATTACK if is_attack else PredictionStatus.BENIGN,
        class_id=0,
        label=label,
        is_attack=is_attack,
        confidence=confidence,
        class_probabilities={"BENIGN": confidence},
        feature_quality=FeatureQuality.COMPLETE,
        missing_fields=(),
        imputed_fields=(),
        rejected_fields=(),
        context=ctx,
        model_version="test",
        preprocessing_version=3,
        inference_ms=1.0,
        is_partial_flow=False,
        known_attack_model=True,
        generalization_warning="test",
        error="",
    )


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test.db")
    d = Database(db_path)
    yield d
    d.close()


class TestDatabaseInit:
    def test_init_creates_tables(self, db):
        cur = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = [r["name"] for r in cur.fetchall()]
        assert "attacks" in tables
        assert "traffic_stats" in tables

    def test_empty_db_stats(self, db):
        stats = db.get_stats()
        assert stats["total"] == 0
        assert stats["normal"] == 0
        assert stats["attacks"] == 0
        assert stats["attack_distribution"] == []


class TestLogAndQuery:
    def test_log_one_benign(self, db):
        result = _make_result()
        db.log_prediction(result)
        rows = db.get_attacks()
        assert len(rows) == 1
        assert rows[0]["attack_type"] == "BENIGN"
        assert rows[0]["is_attack"] == 0

    def test_log_one_attack(self, db):
        result = _make_result(label="DDoS", is_attack=True)
        db.log_prediction(result)
        rows = db.get_attacks()
        assert len(rows) == 1
        assert rows[0]["attack_type"] == "DDoS"
        assert rows[0]["is_attack"] == 1

    def test_log_multiple(self, db):
        for i in range(10):
            r = _make_result(
                label="DDoS" if i % 2 == 0 else "BENIGN",
                is_attack=(i % 2 == 0),
            )
            db.log_prediction(r)
        stats = db.get_stats()
        assert stats["total"] == 10
        assert stats["normal"] == 5
        assert stats["attacks"] == 5

    def test_pagination(self, db):
        for i in range(20):
            db.log_prediction(_make_result())
        page1 = db.get_attacks(limit=10, offset=0)
        page2 = db.get_attacks(limit=10, offset=10)
        assert len(page1) == 10
        assert len(page2) == 10

    def test_filter_by_attack_type(self, db):
        db.log_prediction(_make_result(label="BENIGN"))
        db.log_prediction(_make_result(label="DDoS", is_attack=True))
        rows = db.get_attacks(attack_type="DDoS")
        assert len(rows) == 1
        assert rows[0]["attack_type"] == "DDoS"


class TestStats:
    def test_attack_summary(self, db):
        db.log_prediction(_make_result(label="DDoS", is_attack=True))
        db.log_prediction(_make_result(label="DDoS", is_attack=True))
        db.log_prediction(_make_result(label="PortScan", is_attack=True))
        summary = db.get_attack_summary()
        assert len(summary) == 2
        assert summary[0]["attack_type"] == "DDoS"
        assert summary[0]["count"] == 2

    def test_top_attackers(self, db):
        db.log_prediction(_make_result(label="DDoS", is_attack=True, src_ip="1.1.1.1"))
        db.log_prediction(_make_result(label="DDoS", is_attack=True, src_ip="1.1.1.1"))
        db.log_prediction(_make_result(label="DDoS", is_attack=True, src_ip="2.2.2.2"))
        top = db.get_top_attackers()
        assert len(top) == 2
        assert top[0]["src_ip"] == "1.1.1.1"
        assert top[0]["count"] == 2

    def test_recent_predictions(self, db):
        for i in range(5):
            db.log_prediction(_make_result(timestamp=float(i)))
        recent = db.get_recent_predictions(limit=3)
        assert len(recent) == 3
        assert recent[0]["timestamp_utc"] >= recent[1]["timestamp_utc"]


class TestThreatLevel:
    def test_safe_zero_attacks(self, db):
        assert db.get_threat_level() == "SAFE"

    def test_safe_only_benign(self, db):
        db.log_prediction(_make_result())
        assert db.get_threat_level() == "SAFE"

    def test_elevated(self, db):
        for _ in range(3):
            db.log_prediction(_make_result(label="DDoS", is_attack=True))
        assert db.get_threat_level() == "ELEVATED"

    def test_critical(self, db):
        for _ in range(7):
            db.log_prediction(_make_result(label="DDoS", is_attack=True))
        assert db.get_threat_level() == "CRITICAL"

    def test_old_attacks_not_counted(self, db):
        old_ts = time.time() - 120
        db.log_prediction(_make_result(label="DDoS", is_attack=True, timestamp=old_ts))
        assert db.get_threat_level() == "SAFE"
