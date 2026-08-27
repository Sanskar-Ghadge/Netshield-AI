"""Tests for the WebSocketManager class.

Uses mock WebSocket objects to verify connect, disconnect, broadcast
to 0/1/2 clients, and error handling.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ws_manager import WebSocketManager


class MockWebSocket:
    """Minimal mock WebSocket for testing.

    Attributes:
        accepted: Whether accept() was called.
        sent_messages: List of messages sent via send_json.
        should_fail: If True, send_json raises an exception.
    """

    def __init__(self, should_fail: bool = False) -> None:
        """Initialize the mock.

        Args:
            should_fail: If True, send_json raises RuntimeError.
        """
        self.accepted: bool = False
        self.sent_messages: list[dict[str, Any]] = []
        self.should_fail: bool = should_fail

    async def accept(self) -> None:
        """Mock accept."""
        self.accepted = True

    async def send_json(self, message: dict[str, Any]) -> None:
        """Mock send_json, optionally raising an error.

        Args:
            message: The dict to "send".

        Raises:
            RuntimeError: If should_fail is True.
        """
        if self.should_fail:
            raise RuntimeError("Simulated send failure")
        self.sent_messages.append(message)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ws_manager() -> WebSocketManager:
    """Return a fresh WebSocketManager."""
    return WebSocketManager()


@pytest.fixture
def mock_ws() -> MockWebSocket:
    """Return a single mock WebSocket."""
    return MockWebSocket()


@pytest.fixture
def event_loop():
    """Create a new event loop for each test."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Connect tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_accepts_and_adds(ws_manager: WebSocketManager, mock_ws: MockWebSocket) -> None:
    """connect() should call accept() and add the client."""
    await ws_manager.connect(mock_ws)
    assert mock_ws.accepted is True
    assert mock_ws in ws_manager.active_connections
    assert len(ws_manager.active_connections) == 1


@pytest.mark.asyncio
async def test_connect_multiple(ws_manager: WebSocketManager) -> None:
    """connect() should handle multiple clients."""
    ws1 = MockWebSocket()
    ws2 = MockWebSocket()
    ws3 = MockWebSocket()
    await ws_manager.connect(ws1)
    await ws_manager.connect(ws2)
    await ws_manager.connect(ws3)
    assert len(ws_manager.active_connections) == 3


# ---------------------------------------------------------------------------
# Disconnect tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disconnect_removes_client(ws_manager: WebSocketManager, mock_ws: MockWebSocket) -> None:
    """disconnect() should remove the client from the set."""
    await ws_manager.connect(mock_ws)
    assert len(ws_manager.active_connections) == 1
    await ws_manager.disconnect(mock_ws)
    assert len(ws_manager.active_connections) == 0


@pytest.mark.asyncio
async def test_disconnect_not_in_set(ws_manager: WebSocketManager, mock_ws: MockWebSocket) -> None:
    """disconnect() should be safe when the client was never connected."""
    await ws_manager.disconnect(mock_ws)
    assert len(ws_manager.active_connections) == 0


@pytest.mark.asyncio
async def test_disconnect_one_of_many(ws_manager: WebSocketManager) -> None:
    """disconnect() should remove only the specified client."""
    ws1 = MockWebSocket()
    ws2 = MockWebSocket()
    await ws_manager.connect(ws1)
    await ws_manager.connect(ws2)
    await ws_manager.disconnect(ws1)
    assert ws1 not in ws_manager.active_connections
    assert ws2 in ws_manager.active_connections
    assert len(ws_manager.active_connections) == 1


# ---------------------------------------------------------------------------
# Broadcast tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadcast_zero_clients(ws_manager: WebSocketManager) -> None:
    """broadcast() to zero clients should not raise."""
    await ws_manager.broadcast({"test": "data"})
    assert len(ws_manager.active_connections) == 0


@pytest.mark.asyncio
async def test_broadcast_single_client(ws_manager: WebSocketManager, mock_ws: MockWebSocket) -> None:
    """broadcast() should send the message to one client."""
    await ws_manager.connect(mock_ws)
    msg = {"event": "test", "data": "hello"}
    await ws_manager.broadcast(msg)
    assert len(mock_ws.sent_messages) == 1
    assert mock_ws.sent_messages[0] == msg


@pytest.mark.asyncio
async def test_broadcast_two_clients(ws_manager: WebSocketManager) -> None:
    """broadcast() should send to all connected clients."""
    ws1 = MockWebSocket()
    ws2 = MockWebSocket()
    await ws_manager.connect(ws1)
    await ws_manager.connect(ws2)
    msg = {"event": "ping", "count": 1}
    await ws_manager.broadcast(msg)
    assert len(ws1.sent_messages) == 1
    assert len(ws2.sent_messages) == 1
    assert ws1.sent_messages[0] == msg
    assert ws2.sent_messages[0] == msg


@pytest.mark.asyncio
async def test_broadcast_error_handling(ws_manager: WebSocketManager) -> None:
    """broadcast() should silently remove broken clients."""
    good_ws = MockWebSocket()
    bad_ws = MockWebSocket(should_fail=True)
    await ws_manager.connect(good_ws)
    await ws_manager.connect(bad_ws)
    msg = {"event": "test"}
    await ws_manager.broadcast(msg)
    # Good client should still have received the message
    assert len(good_ws.sent_messages) == 1
    # Bad client should have been removed
    assert bad_ws not in ws_manager.active_connections
    assert good_ws in ws_manager.active_connections


# ---------------------------------------------------------------------------
# broadcast_attack_alert tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadcast_attack_alert_envelope(ws_manager: WebSocketManager, mock_ws: MockWebSocket) -> None:
    """broadcast_attack_alert() should wrap the message in an attack:alert envelope."""
    await ws_manager.connect(mock_ws)
    payload = {"attack_type": "DDoS", "src_ip": "10.0.0.1"}
    await ws_manager.broadcast_attack_alert(payload)
    assert len(mock_ws.sent_messages) == 1
    envelope = mock_ws.sent_messages[0]
    assert envelope["event"] == "attack:alert"
    assert envelope["data"] == payload


@pytest.mark.asyncio
async def test_broadcast_attack_alert_zero_clients(ws_manager: WebSocketManager) -> None:
    """broadcast_attack_alert() with no clients should not raise."""
    await ws_manager.broadcast_attack_alert({"attack_type": "DDoS"})


@pytest.mark.asyncio
async def test_broadcast_attack_alert_multiple(ws_manager: WebSocketManager) -> None:
    """broadcast_attack_alert() should reach all connected clients."""
    ws1 = MockWebSocket()
    ws2 = MockWebSocket()
    ws3 = MockWebSocket()
    await ws_manager.connect(ws1)
    await ws_manager.connect(ws2)
    await ws_manager.connect(ws3)
    await ws_manager.broadcast_attack_alert({"attack_type": "DoS"})
    for ws in [ws1, ws2, ws3]:
        assert len(ws.sent_messages) == 1
        assert ws.sent_messages[0]["event"] == "attack:alert"
