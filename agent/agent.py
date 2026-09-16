"""NetShield AI — Standalone Client Laptop Agent.

Monitors local network interfaces, performs ML threat detection,
and pairs with the NetShield AI web dashboard via API Key.

Controls:
    - Receives remote START_SNIFFING and STOP_SNIFFING signals from web tab.
    - Sends live attack alerts and packet statistics to the user's dashboard.

Usage:
    py agent/agent.py --key ns_live_8f3a9b1c2d3e4f5a...
    py agent/agent.py --server http://localhost:3001 --key <YOUR_API_KEY>
"""

import argparse
import asyncio
import json
import logging
import os
import platform
import socket
import sys
import threading
import time
from typing import Optional

import requests
import socketio
from dotenv import load_dotenv

# Add parent directory to path to import python-engine modules if run locally
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "python-engine")))

try:
    from capture.sniffer import PacketSniffer
    from prediction.pipeline import ThreatPredictor
    from prediction.filter import PortScanTracker
except ImportError:
    # Standalone mode fallback
    PacketSniffer = None
    ThreatPredictor = None
    PortScanTracker = None

# ── Logging setup ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [NetShieldAgent] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("NetShieldAgent")

load_dotenv()


class NetShieldAgent:
    """Client Laptop Agent for NetShield AI."""

    def __init__(self, server_url: str, api_key: str, iface: Optional[str] = None) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.iface = iface

        self.hostname = socket.gethostname()
        self.local_ip = self._get_local_ip()

        self.is_sniffing = False
        self.sniffer: Optional[Any] = None
        self.predictor: Optional[Any] = None

        # Socket.io client for real-time bidirectional messaging with Node backend
        self.sio = socketio.Client(reconnection=True, reconnection_delay=2)
        self._register_socket_events()

    def _get_local_ip(self) -> str:
        """Get current local network IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _register_socket_events(self) -> None:
        """Register Socket.io event handlers for remote web commands."""

        @self.sio.event
        def connect():
            logger.info("Connected to NetShield Central Server!")
            # Send Agent Authentication Handshake
            self.sio.emit(
                "agent:handshake",
                {
                    "apiKey": self.api_key,
                    "hostname": self.hostname,
                    "ip": self.local_ip,
                    "os": platform.system(),
                    "osRelease": platform.release(),
                    "status": "STANDBY",
                },
            )

        @self.sio.event
        def disconnect():
            logger.warning("Disconnected from NetShield Central Server. Retrying...")

        @self.sio.on("agent:control")
        def on_agent_control(data):
            """Handle remote commands from the web dashboard."""
            action = data.get("action")
            logger.info(f"Received web control action: {action}")

            if action == "START_SNIFFING":
                self.start_sniffing()
            elif action == "STOP_SNIFFING":
                self.stop_sniffing()
            elif action == "STATUS_QUERY":
                self._report_status()

        @self.sio.on("agent:handshake_ack")
        def on_handshake_ack(data):
            if data.get("success"):
                logger.info(f"Successfully paired with account: {data.get('user', {}).get('username')}")
                if data.get("autoStart"):
                    self.start_sniffing()
            else:
                logger.error(f"Handshake failed: {data.get('error')}")

    def _on_packet_callback(self, prediction_result) -> None:
        """Callback triggered for every processed packet flow."""
        if not self.sio.connected:
            return

        payload = {
            "apiKey": self.api_key,
            "label": prediction_result.label,
            "confidence": float(prediction_result.confidence),
            "is_attack": bool(prediction_result.is_attack),
            "timestamp_utc": float(prediction_result.timestamp_utc),
            "context": (
                {
                    "src_ip": prediction_result.context.src_ip,
                    "dst_ip": prediction_result.context.dst_ip,
                    "src_port": prediction_result.context.src_port,
                    "dst_port": prediction_result.context.dst_port,
                    "protocol": prediction_result.context.protocol,
                    "flow_id": prediction_result.context.flow_id,
                }
                if prediction_result.context
                else None
            ),
        }

        # Stream packet prediction to server
        self.sio.emit("agent:packet", payload)

        if prediction_result.is_attack:
            logger.warning(
                f"🚨 ATTACK DETECTED [{prediction_result.label}] "
                f"from {prediction_result.context.src_ip if prediction_result.context else 'unknown'}"
            )
            self.sio.emit("agent:attack_alert", payload)

    def start_sniffing(self) -> None:
        """Start local packet capture and ML inference."""
        if self.is_sniffing:
            logger.info("Sniffing is already active.")
            return

        logger.info("Starting packet capture engine...")
        try:
            if PacketSniffer is not None and ThreatPredictor is not None:
                # Load ML Predictor
                model_dir = os.path.abspath(
                    os.path.join(os.path.dirname(__file__), "..", "python-engine", "models")
                )
                self.predictor = ThreatPredictor(model_dir=model_dir)

                # Start Packet Sniffer
                self.sniffer = PacketSniffer(
                    predictor=self.predictor,
                    callback=self._on_packet_callback,
                    iface=self.iface,
                )
                self.sniffer.start()

            self.is_sniffing = True
            logger.info("🟢 Protection ACTIVE — Sniffing live traffic...")

            if self.sio.connected:
                self.sio.emit("agent:status_update", {"apiKey": self.api_key, "status": "SNIFFING"})
        except Exception as e:
            logger.error(f"Failed to start packet capture: {e}")

    def stop_sniffing(self) -> None:
        """Pause local packet capture."""
        if not self.is_sniffing:
            logger.info("Sniffing is already stopped.")
            return

        logger.info("Pausing packet capture engine...")
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None

        self.is_sniffing = False
        logger.info("🟡 Protection PAUSED — Standby mode.")

        if self.sio.connected:
            self.sio.emit("agent:status_update", {"apiKey": self.api_key, "status": "STANDBY"})

    def _report_status(self) -> None:
        """Send status update to server."""
        if self.sio.connected:
            self.sio.emit(
                "agent:status_update",
                {
                    "apiKey": self.api_key,
                    "status": "SNIFFING" if self.is_sniffing else "STANDBY",
                    "hostname": self.hostname,
                    "ip": self.local_ip,
                },
            )

    def run(self) -> None:
        """Connect to server and enter event loop."""
        logger.info("=" * 60)
        logger.info(f"  NetShield AI Client Laptop Agent")
        logger.info(f"  Hostname:  {self.hostname}")
        logger.info(f"  Local IP:  {self.local_ip}")
        logger.info(f"  API Key:   {self.api_key[:12]}...")
        logger.info(f"  Server:    {self.server_url}")
        logger.info("=" * 60)

        try:
            self.sio.connect(self.server_url, transports=["websocket", "polling"])
            self.sio.wait()
        except KeyboardInterrupt:
            logger.info("Stopping NetShield Agent...")
            self.stop_sniffing()
            if self.sio.connected:
                self.sio.disconnect()
        except Exception as e:
            logger.error(f"Agent connection error: {e}")


def main():
    parser = argparse.ArgumentParser(description="NetShield AI Client Laptop Agent")
    parser.add_argument(
        "--server",
        default=os.getenv("NETSHIELD_SERVER_URL", "http://localhost:3001"),
        help="NetShield Central Server URL (default: http://localhost:3001)",
    )
    parser.add_argument(
        "--key",
        default=os.getenv("NETSHIELD_API_KEY"),
        help="Agent API Key from your web dashboard profile",
    )
    parser.add_argument(
        "--iface",
        default=os.getenv("NETSHIELD_IFACE"),
        help="Network interface to sniff on (optional)",
    )

    args = parser.parse_args()

    if not args.key:
        logger.error("❌ Error: Missing API Key!")
        logger.error("Please provide your Agent API Key using: py agent/agent.py --key ns_live_...")
        sys.exit(1)

    agent = NetShieldAgent(server_url=args.server, api_key=args.key, iface=args.iface)
    agent.run()


if __name__ == "__main__":
    main()
