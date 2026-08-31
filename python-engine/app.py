"""NetShield AI — FastAPI microservice entry point.

Loads model, starts live packet capture, serves REST + WebSocket endpoints,
logs predictions to SQLite, and dispatches alerts on attacks.

Run::

    uvicorn app:app --host 0.0.0.0 --port 8000
    # or
    py -m uvicorn app:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import logging
import queue
import sys
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure python-engine root is on sys.path
_ENGINE_ROOT = Path(__file__).resolve().parent
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

from alerts.dispatcher import AlertDispatcher
from chatbot.chatbot import Chatbot
from config import Settings, get_settings
from database import Database
from packet_capture.capture import CaptureController
from packet_capture.sources import LiveCaptureSource
from prediction.filter import TrafficFilter, should_flag_as_attack
from prediction.flow_adapter import FlowPredictionAdapter
from prediction.predict import ArtifactPaths, IntrusionPredictor
from reports.generate_pdf import ReportGenerator
from ws_manager import WebSocketManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netshield")

# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------


class StatusResponse(BaseModel):
    """Response model for ``GET /api/status``."""

    threat_level: str
    total_packets: int
    attack_count: int
    normal_count: int
    uptime_seconds: float
    capture_active: bool
    model_version: str
    capture_interface: Optional[str] = None
    alert_channels: Optional[dict[str, bool]] = None


class ChatbotRequest(BaseModel):
    """Request body for ``POST /api/chatbot``."""

    query: str


class ChatbotResponse(BaseModel):
    """Response model for ``POST /api/chatbot``."""

    response: str


class ChatbotStatusResponse(BaseModel):
    """Response model for ``GET /api/chatbot/status``."""

    available: bool
    model: str = ""
    api_key_configured: bool = False


class ReportResponse(BaseModel):
    """Response model for ``POST /api/report``."""

    path: str
    filename: str


class HealthResponse(BaseModel):
    """Response model for ``GET /api/health``."""

    status: str
    model_loaded: bool
    capture_active: bool


# ---------------------------------------------------------------------------
# Application state container
# ---------------------------------------------------------------------------


class AppState:
    """Holds all initialised components for the FastAPI app.

    Attributes:
        settings: Application settings.
        db: SQLite database.
        predictor: ML inference engine.
        adapter: Flow-to-prediction adapter.
        alerts: Alert dispatcher.
        chatbot: Gemini chatbot.
        reports: PDF report generator.
        ws: WebSocket manager.
        capture: Capture controller.
        capture_source: Live capture source (if started).
    """

    def __init__(self) -> None:
        self.settings: Settings = get_settings()
        self.db: Database = Database(self.settings.db_path)
        self.predictor: Optional[IntrusionPredictor] = None
        self.adapter: Optional[FlowPredictionAdapter] = None
        self.traffic_filter: Optional[TrafficFilter] = None
        self.attack_confidence_threshold: float = self.settings.attack_confidence_threshold
        self.alerts: Optional[AlertDispatcher] = None
        self.chatbot: Optional[Chatbot] = None
        self.reports: Optional[ReportGenerator] = None
        self.ws: WebSocketManager = WebSocketManager()
        self.capture: Optional[CaptureController] = None
        self.capture_source: Optional[LiveCaptureSource] = None
        self._stop_event: threading.Event = threading.Event()
        self._prediction_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._start_time: float = 0.0
        self._model_loaded: bool = False

    @property
    def capture_active(self) -> bool:
        """True if the capture controller is running."""
        return (
            self.capture is not None
            and self._prediction_thread is not None
            and self._prediction_thread.is_alive()
        )

    @property
    def uptime(self) -> float:
        """Server uptime in seconds."""
        if self._start_time == 0:
            return 0.0
        return time.time() - self._start_time


# ---------------------------------------------------------------------------
# Lifespan context manager
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle for the FastAPI app.

    Startup:
        1. Get settings.
        2. Init database.
        3. Load model + adapter.
        4. Init alerts, chatbot, reports.
        5. Capture event loop for cross-thread broadcasts.
        6. Start live capture (if enabled).
        7. Start prediction consumer thread.

    Shutdown:
        1. Stop capture.
        2. Drain remaining predictions.
        3. Close database.
    """
    state = AppState()
    state._start_time = time.time()
    state._loop = asyncio.get_running_loop()
    app.state.app = state

    logger.info("NetShield AI starting up...")

    # 1. Load model
    try:
        paths = ArtifactPaths(
            model=Path(state.settings.resolved_model_path()),
            preprocessor=Path(state.settings.resolved_preprocessor_path()),
            encoder=Path(state.settings.resolved_encoder_path()),
            metadata=Path(state.settings.resolved_metadata_path()),
        )
        paths.validate()
        state.predictor = IntrusionPredictor(paths)
        state.adapter = FlowPredictionAdapter(state.predictor)
        state._model_loaded = True
        logger.info("Model loaded: %s", state.predictor.class_names)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Model load failed: %s — endpoints will return 503", exc)
        state._model_loaded = False

    # 1b. Create traffic filter (after model is loaded so we have the version)
    if state._model_loaded and state.predictor is not None:
        state.traffic_filter = TrafficFilter(
            model_version=state.predictor._model_version,
            preprocessing_version=state.predictor._version,
        )
        logger.info(
            "Traffic filter active (attack confidence threshold: %.0f%%)",
            state.attack_confidence_threshold * 100,
        )

    # 2. Init alerts, chatbot, reports
    state.alerts = AlertDispatcher(state.settings)
    state.chatbot = Chatbot(state.settings.gemini_api_key, state.db)
    state.reports = ReportGenerator(state.db)

    # 3. Start live capture
    if state.settings.capture_enabled and state._model_loaded:
        try:
            state.capture = CaptureController(
                idle_timeout_us=state.settings.idle_timeout_s * 1_000_000
            )
            state.capture_source = LiveCaptureSource(
                iface=state.settings.capture_interface,
                bpf_filter=state.settings.capture_bpf_filter,
            )
            # Start the Scapy sniffing thread FIRST so it begins filling
            # the packet queue before the ingest thread tries to drain it.
            state.capture_source.start()
            state.capture.start(state.capture_source)
            logger.info(
                "Live capture started on: %s",
                state.settings.capture_interface or "default",
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Capture startup failed: %s", exc)
            state.capture = None
    else:
        logger.info("Live capture disabled or model not loaded")

    # 4. Start prediction consumer thread
    if state.capture is not None:
        state._stop_event.clear()
        state._prediction_thread = threading.Thread(
            target=_prediction_loop,
            args=(state,),
            daemon=True,
            name="prediction-consumer",
        )
        state._prediction_thread.start()
        logger.info("Prediction consumer thread started")

    yield

    # --- Shutdown ---
    logger.info("NetShield AI shutting down...")
    state._stop_event.set()

    if state.capture is not None:
        if state.capture_source is not None:
            state.capture_source.stop()
        state.capture.stop()
        logger.info("Capture stopped")

    if state._prediction_thread is not None:
        state._prediction_thread.join(timeout=5.0)

    state.db.close()
    logger.info("Database closed")


# ---------------------------------------------------------------------------
# Prediction consumer thread
# ---------------------------------------------------------------------------


def _prediction_loop(state: "AppState") -> None:
    """Background thread: drain completed flows → filter → predict → log → broadcast.

    Processing pipeline per flow:
        1. TrafficFilter: bypass the model for ICMP, IGMP, DHCP,
           broadcast/multicast, and link-local discovery traffic.
        2. If not bypassed: run the ML model via the flow adapter.
        3. Confidence threshold: if the model predicts an attack but
           confidence is below ``attack_confidence_threshold``, downgrade
           to BENIGN.
        4. Log to database, broadcast via WebSocket, dispatch alerts.

    Args:
        state: Application state with all initialised components.
    """
    assert state.adapter is not None
    assert state.capture is not None
    assert state._loop is not None

    while not state._stop_event.is_set():
        try:
            flow = state.capture.completed_flows.get(timeout=1.0)
        except queue.Empty:
            continue

        try:
            # ── Step 1: Traffic pre-filter ────────────────────────────
            # Bypass the model for traffic it cannot meaningfully classify.
            if state.traffic_filter is not None:
                bypassed = state.traffic_filter.evaluate(flow)
                if bypassed is not None:
                    result = bypassed
                else:
                    # ── Step 2: ML prediction ─────────────────────────
                    result = state.adapter.predict(flow)
            else:
                result = state.adapter.predict(flow)

            # ── Step 3: Confidence threshold + rule-based detection ────
            # Downgrade low-confidence attack predictions to BENIGN.
            # Also run rule-based detection for patterns the ML model
            # misses (e.g. SYN floods with no backward packets).
            result = should_flag_as_attack(
                result, state.attack_confidence_threshold,
                raw_features=dict(flow.features) if flow.features else None,
            )

            # ── Step 4: Log, broadcast, alert ─────────────────────────
            state.db.log_prediction(result)

            # Broadcast via asyncio from this sync thread
            asyncio.run_coroutine_threadsafe(
                state.ws.broadcast(result.to_dict()),
                state._loop,
            )

            if result.is_attack and state.alerts is not None:
                state.alerts.dispatch(result)
                asyncio.run_coroutine_threadsafe(
                    state.ws.broadcast_attack_alert(result.to_dict()),
                    state._loop,
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("Prediction error: %s", exc)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="NetShield AI",
    description="Real-time ML-powered network intrusion detection system",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _get_state(request) -> AppState:
    """Return the AppState from the FastAPI app instance.

    Args:
        request: The Starlette/FastAPI request object.

    Returns:
        The AppState instance.
    """
    return request.app.state.app


def _require_model(state: AppState) -> Optional[dict]:
    """Return a 503 error dict if model is not loaded.

    Args:
        state: Application state.

    Returns:
        None if OK, or a dict for JSONResponse if model not loaded.
    """
    if not state._model_loaded:
        return {"detail": "Model not loaded"}
    return None


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint.

    Returns:
        HealthResponse with model and capture status.
    """
    from fastapi import Request

    # We can't inject Request here directly, use app.state
    state: AppState = app.state.app
    return HealthResponse(
        status="ok",
        model_loaded=state._model_loaded,
        capture_active=state.capture_active,
    )


@app.get("/api/status", response_model=StatusResponse)
async def get_status() -> StatusResponse:
    """Return current system status including threat level and packet counts.

    Returns:
        StatusResponse with all status fields.
    """
    state: AppState = app.state.app
    stats = state.db.get_stats()
    alert_channels = None
    if state.alerts is not None:
        alert_channels = state.alerts.get_channel_status()
    return StatusResponse(
        threat_level=state.db.get_threat_level(),
        total_packets=stats["total"],
        attack_count=stats["attacks"],
        normal_count=stats["normal"],
        uptime_seconds=round(state.uptime, 2),
        capture_active=state.capture_active,
        model_version=state.predictor._model_version if state.predictor else "",
        capture_interface=state.settings.capture_interface,
        alert_channels=alert_channels,
    )


@app.get("/api/attacks")
async def get_attacks(
    limit: int = 50,
    offset: int = 0,
    attack_type: Optional[str] = None,
) -> dict[str, Any]:
    """Return paginated attack/prediction history.

    Args:
        limit: Maximum rows (default 50, max 500).
        offset: Pagination offset.
        attack_type: Optional filter by label.

    Returns:
        Dictionary with rows, total, limit, offset.
    """
    state: AppState = app.state.app
    limit = min(limit, 500)
    rows = state.db.get_attacks(limit=limit, offset=offset, attack_type=attack_type)
    return {
        "attacks": rows,
        "total": state.db.get_stats()["total"],
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/stats")
async def get_stats() -> dict[str, Any]:
    """Return aggregate statistics and attack-type distribution.

    Returns:
        Dictionary with total, normal, attacks, attack_distribution.
    """
    state: AppState = app.state.app
    stats = state.db.get_stats()
    stats["threat_level"] = state.db.get_threat_level()
    stats["top_attackers"] = state.db.get_top_attackers()
    stats["attack_summary"] = state.db.get_attack_summary()
    return stats


@app.post("/api/chatbot", response_model=ChatbotResponse)
async def chatbot_query(req: ChatbotRequest) -> ChatbotResponse:
    """Query the Gemini-powered chatbot with live security context.

    The underlying ``chatbot.query()`` call is synchronous (it blocks
    on the Gemini HTTP API), so we offload it to a thread-pool
    executor to avoid stalling the asyncio event loop.

    Args:
        req: ChatbotRequest with user query.

    Returns:
        ChatbotResponse with the AI's response.
    """
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    state: AppState = app.state.app
    assert state.chatbot is not None
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=2) as pool:
        response_text = await loop.run_in_executor(
            pool, state.chatbot.query, req.query
        )
    return ChatbotResponse(response=response_text)


@app.get("/api/chatbot/status", response_model=ChatbotStatusResponse)
async def chatbot_status() -> ChatbotStatusResponse:
    """Return whether the Gemini chatbot is available.

    Returns:
        ChatbotStatusResponse with availability, model name, and key status.
    """
    state: AppState = app.state.app
    assert state.chatbot is not None
    return ChatbotStatusResponse(
        available=state.chatbot.is_available(),
        model=state.chatbot.model_name,
        api_key_configured=state.chatbot.api_key_configured,
    )


@app.post("/api/alerts/test")
async def test_alerts() -> dict[str, Any]:
    """Test all alert channels (Telegram, Email, Voice).

    Sends a test message through each configured channel and returns
    the results.

    Returns:
        Dictionary with keys ``"telegram"``, ``"email"``, ``"voice"``,
        each mapping to a result dict.
    """
    state: AppState = app.state.app
    if state.alerts is None:
        return {"error": "Alert dispatcher not initialised."}
    return state.alerts.test_all()


@app.get("/api/alerts/status")
async def alerts_status() -> dict[str, Any]:
    """Return which alert channels are configured.

    Returns:
        Dictionary with ``"channels"`` mapping each channel name to
        a boolean indicating whether it is configured.
    """
    state: AppState = app.state.app
    if state.alerts is None:
        return {"channels": {"telegram": False, "email": False, "voice": False}}
    return {"channels": state.alerts.get_channel_status()}


@app.post("/api/report", response_model=ReportResponse)
async def generate_report() -> ReportResponse:
    """Trigger PDF report generation and return the file path.

    Returns:
        ReportResponse with path and filename.
    """
    state: AppState = app.state.app
    assert state.reports is not None
    file_path = state.reports.generate(output_dir=state.settings.report_dir)
    filename = Path(file_path).name
    return ReportResponse(path=file_path, filename=filename)


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@app.websocket("/ws/packets")
async def websocket_packets(websocket: WebSocket) -> None:
    """Stream live packet predictions to connected clients.

    On connect, sends a welcome message with current status.
    Continuously broadcasts prediction results and attack alerts.
    """
    state: AppState = app.state.app
    await state.ws.connect(websocket)
    try:
        # Send initial status
        await websocket.send_json(
            {
                "event": "connected",
                "data": {
                    "threat_level": state.db.get_threat_level(),
                    "total_packets": state.db.get_stats()["total"],
                    "capture_active": state.capture_active,
                },
            }
        )
        # Keep connection open; client just receives broadcasts
        while True:
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        await state.ws.disconnect(websocket)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the FastAPI server with uvicorn."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app:app",
        host=settings.host,
        port=settings.python_port,
        reload=False,
    )


if __name__ == "__main__":
    main()
