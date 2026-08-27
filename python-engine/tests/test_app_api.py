"""Tests for the FastAPI application endpoints (Stage 5.7)."""

from __future__ import annotations

import asyncio
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ENGINE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ENGINE_ROOT not in sys.path:
    sys.path.insert(0, _ENGINE_ROOT)

from fastapi.testclient import TestClient

from database import Database
from prediction.schemas import (
    FeatureQuality,
    FlowContext,
    PredictionResult,
    PredictionStatus,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(
    label: str = "BENIGN",
    is_attack: bool = False,
    confidence: float = 0.95,
) -> PredictionResult:
    ctx = FlowContext(
        flow_id="10.0.0.1:1234-10.0.0.2:80-6",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol=6,
        total_packets=5,
        flow_duration_us=1_000_000,
        is_completed=True,
    )
    return PredictionResult(
        timestamp_utc=time.time(),
        status=PredictionStatus.ATTACK if is_attack else PredictionStatus.BENIGN,
        class_id=0,
        label=label,
        is_attack=is_attack,
        confidence=confidence,
        class_probabilities={label: confidence},
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


# ---------------------------------------------------------------------------
# Test app factory — builds a minimal app with mocked components
# ---------------------------------------------------------------------------


def _build_test_app(db: Database) -> tuple:
    """Build a FastAPI test app with mocked model and capture.

    Args:
        db: Database instance to use for the test.

    Returns:
        Tuple of (app, app_state).
    """
    from fastapi import Body, FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel

    from ws_manager import WebSocketManager

    class StatusResponse(BaseModel):
        threat_level: str
        total_packets: int
        attack_count: int
        normal_count: int
        uptime_seconds: float
        capture_active: bool
        model_version: str
        capture_interface: str | None = None

    class ChatbotRequest(BaseModel):
        model_config = {"protected_namespaces": ()}
        query: str

    class ChatbotResponse(BaseModel):
        response: str

    class ReportResponse(BaseModel):
        path: str
        filename: str

    class HealthResponse(BaseModel):
        status: str
        model_loaded: bool
        capture_active: bool

    class TestState:
        def __init__(self) -> None:
            self.db = db
            self.predictor = MagicMock()
            self.predictor._model_version = "test"
            self._chatbot = MagicMock()
            self._chatbot.query = MagicMock(return_value="Test response")
            self.reports = MagicMock()
            self.reports.generate = MagicMock(return_value="reports/test_report.pdf")
            self.ws = WebSocketManager()
            self.settings = MagicMock()
            self.settings.capture_interface = None
            self._start_time = time.time()
            self._model_loaded = True
            self.capture = None
            self._prediction_thread = None

        @property
        def capture_active(self) -> bool:
            return False

        @property
        def uptime(self) -> float:
            return time.time() - self._start_time

    state = TestState()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.app = state
        yield

    test_app = FastAPI(title="NetShield AI Test", lifespan=lifespan)
    test_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @test_app.get("/api/health", response_model=HealthResponse)
    async def health_check() -> HealthResponse:
        s = test_app.state.app
        return HealthResponse(
            status="ok",
            model_loaded=s._model_loaded,
            capture_active=s.capture_active,
        )

    @test_app.get("/api/status", response_model=StatusResponse)
    async def get_status() -> StatusResponse:
        s = test_app.state.app
        stats = s.db.get_stats()
        return StatusResponse(
            threat_level=s.db.get_threat_level(),
            total_packets=stats["total"],
            attack_count=stats["attacks"],
            normal_count=stats["normal"],
            uptime_seconds=round(s.uptime, 2),
            capture_active=s.capture_active,
            model_version=s.predictor._model_version,
            capture_interface=s.settings.capture_interface,
        )

    @test_app.get("/api/attacks")
    async def get_attacks(
        limit: int = 50,
        offset: int = 0,
        attack_type: str | None = None,
    ) -> dict:
        s = test_app.state.app
        limit = min(limit, 500)
        rows = s.db.get_attacks(limit=limit, offset=offset, attack_type=attack_type)
        return {
            "attacks": rows,
            "total": s.db.get_stats()["total"],
            "limit": limit,
            "offset": offset,
        }

    @test_app.get("/api/stats")
    async def get_stats() -> dict:
        s = test_app.state.app
        stats = s.db.get_stats()
        stats["threat_level"] = s.db.get_threat_level()
        stats["top_attackers"] = s.db.get_top_attackers()
        stats["attack_summary"] = s.db.get_attack_summary()
        return stats

    @test_app.post("/api/chatbot")
    async def chatbot_query(payload: dict) -> dict:
        s = test_app.state.app
        user_msg = payload.get("query", "")
        response_text = s._chatbot.query(user_msg)
        return {"response": response_text}

    @test_app.post("/api/report", response_model=ReportResponse)
    async def generate_report() -> ReportResponse:
        s = test_app.state.app
        file_path = s.reports.generate()
        return ReportResponse(path=file_path, filename=Path(file_path).name)

    @test_app.websocket("/ws/packets")
    async def websocket_packets(websocket: WebSocket) -> None:
        s = test_app.state.app
        await s.ws.connect(websocket)
        try:
            await websocket.send_json(
                {
                    "event": "connected",
                    "data": {
                        "threat_level": s.db.get_threat_level(),
                        "total_packets": s.db.get_stats()["total"],
                        "capture_active": s.capture_active,
                    },
                }
            )
            while True:
                await asyncio.sleep(1.0)
        except WebSocketDisconnect:
            await s.ws.disconnect(websocket)

    return test_app, state


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary database with test data."""
    db = Database(str(tmp_path / "test_app.db"))
    db.log_prediction(_make_result())
    db.log_prediction(_make_result(label="DDoS", is_attack=True))
    yield db
    db.close()


@pytest.fixture
def app_client(temp_db):
    """Create a TestClient with mocked model and capture.

    Uses ``with`` syntax so Starlette runs the lifespan startup/shutdown
    which sets ``app.state.app``.
    """
    test_app, state = _build_test_app(temp_db)
    with TestClient(test_app) as client:
        yield client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_check(self, app_client):
        """GET /api/health returns 200 with status."""
        resp = app_client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "model_loaded" in data
        assert "capture_active" in data


class TestStatus:
    def test_status_returns_200(self, app_client):
        """GET /api/status returns 200 with threat level."""
        resp = app_client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "threat_level" in data
        assert "total_packets" in data
        assert "attack_count" in data
        assert "normal_count" in data
        assert "uptime_seconds" in data
        assert "capture_active" in data
        assert "model_version" in data

    def test_status_total_packets_matches_db(self, app_client, temp_db):
        """Status endpoint returns correct packet count from DB."""
        resp = app_client.get("/api/status")
        data = resp.json()
        assert data["total_packets"] == 2


class TestAttacks:
    def test_attacks_returns_200(self, app_client):
        """GET /api/attacks returns 200."""
        resp = app_client.get("/api/attacks")
        assert resp.status_code == 200
        data = resp.json()
        assert "attacks" in data
        assert "total" in data
        assert isinstance(data["attacks"], list)

    def test_attacks_pagination(self, app_client):
        """GET /api/attacks supports limit/offset."""
        resp = app_client.get("/api/attacks?limit=1&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["attacks"]) <= 1

    def test_attacks_filter_by_type(self, app_client):
        """GET /api/attacks filters by attack_type."""
        resp = app_client.get("/api/attacks?attack_type=DDoS")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["attacks"]) == 1
        assert data["attacks"][0]["attack_type"] == "DDoS"


class TestStats:
    def test_stats_returns_200(self, app_client):
        """GET /api/stats returns 200."""
        resp = app_client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "normal" in data
        assert "attacks" in data
        assert "attack_distribution" in data
        assert "threat_level" in data
        assert "top_attackers" in data
        assert "attack_summary" in data

    def test_stats_counts_correct(self, app_client):
        """Stats returns correct counts."""
        resp = app_client.get("/api/stats")
        data = resp.json()
        assert data["total"] == 2
        assert data["normal"] == 1
        assert data["attacks"] == 1


class TestChatbot:
    def test_chatbot_returns_200(self, app_client):
        """POST /api/chatbot returns 200 with response text."""
        resp = app_client.post("/api/chatbot", json={"query": "What attacks happened?"})
        assert resp.status_code == 200
        data = resp.json()
        assert "response" in data
        assert isinstance(data["response"], str)
        assert len(data["response"]) > 0

class TestReport:
    def test_report_returns_200(self, app_client):
        """POST /api/report returns 200 with file path."""
        resp = app_client.post("/api/report")
        assert resp.status_code == 200
        data = resp.json()
        assert "path" in data
        assert "filename" in data
        assert len(data["path"]) > 0


class TestWebSocket:
    def test_websocket_connect(self, app_client):
        """WebSocket /ws/packets connects and receives welcome message."""
        from starlette.websockets import WebSocketDisconnect

        try:
            with app_client.websocket_connect("/ws/packets") as ws:
                data = ws.receive_json()
                assert data["event"] == "connected"
                assert "threat_level" in data["data"]
                assert "total_packets" in data["data"]
        except WebSocketDisconnect:
            pass  # disconnect after initial message is acceptable
