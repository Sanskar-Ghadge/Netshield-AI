"""WebSocket connection manager for real-time alert broadcasting.

Maintains a set of connected WebSocket clients and provides methods
to accept/disconnect clients and broadcast JSON messages to all of them.
All I/O is async (asyncio) so it integrates cleanly with FastAPI's
event loop.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket client connections and broadcasts messages.

    This class is designed to be instantiated once and shared across
    the FastAPI application via dependency injection or a module-level
    singleton.

    Attributes:
        active_connections: Set of currently connected WebSocket objects.
    """

    def __init__(self) -> None:
        """Initialize with an empty client set."""
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection and register it.

        Args:
            websocket: The incoming WebSocket connection.
        """
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info("WebSocket client connected; total=%d", len(self.active_connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection from the active set.

        Safe to call even if the websocket was never added.

        Args:
            websocket: The WebSocket connection to remove.
        """
        self.active_connections.discard(websocket)
        logger.info("WebSocket client disconnected; total=%d", len(self.active_connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Send a JSON message to all connected clients.

        Clients that raise an exception during send are silently
        discarded so one broken connection does not block others.

        Args:
            message: Dictionary payload to JSON-encode and send.
        """
        if not self.active_connections:
            return
        # Snapshot to avoid mutation during iteration
        dead: list[WebSocket] = []
        tasks = [self._safe_send(ws, message, dead) for ws in self.active_connections]
        await asyncio.gather(*tasks)
        for ws in dead:
            self.active_connections.discard(ws)

    async def broadcast_attack_alert(self, message: dict[str, Any]) -> None:
        """Broadcast an attack alert with the ``attack:alert`` event type.

        Wraps the provided message inside an event envelope so that
        clients can distinguish alert messages from other broadcasts.

        Args:
            message: Attack alert payload.
        """
        envelope = {"event": "attack:alert", "data": message}
        await self.broadcast(envelope)

    async def _safe_send(
        self,
        websocket: WebSocket,
        message: dict[str, Any],
        dead: list[WebSocket],
    ) -> None:
        """Attempt to send a JSON message to one client, ignoring errors.

        Args:
            websocket: The target WebSocket connection.
            message: Dictionary payload.
            dead: List to append broken connections to.
        """
        try:
            await websocket.send_json(message)
        except Exception as exc:  # noqa: BLE001 — intentionally broad
            logger.warning("Failed to send to a WebSocket client: %s", exc)
            dead.append(websocket)
