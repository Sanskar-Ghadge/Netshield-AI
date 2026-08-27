"""Flow table — manages FlowAccumulator instances for all active flows.

Provides thread-safe ingest, idle-timeout expiry, and flush-on-shutdown.
The table uses a single lock to protect the dict; individual accumulators
are NOT wrapped with per-flow locks to keep the critical section short.

Capacity: 100,000 flows.  When full, the flow with the oldest
``last_packet_time`` is evicted before a new one is created.
"""

from __future__ import annotations

import threading
from typing import Optional

from packet_capture.flow import FlowAccumulator
from packet_capture.schemas import FlowKey, FlowResult, FlowState, PacketRecord

_MAX_FLOWS: int = 100_000
_IDLE_TIMEOUT_US: float = 120_000_000.0  # 2 minutes in microseconds


class FlowTable:
    """Thread-safe table of active bidirectional flows.

    Attributes:
        _table: Maps FlowKey to (FlowAccumulator, threading.Lock).
        _lock: Table-level lock protecting the dict.
    """

    def __init__(self) -> None:
        self._table: dict[FlowKey, tuple[FlowAccumulator, threading.Lock]] = {}
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, pkt: PacketRecord) -> Optional[FlowResult]:
        """Ingest one packet into the appropriate flow.

        Finds or creates the FlowAccumulator for *pkt*'s 5-tuple, ingests
        the packet, and returns a ``FlowResult`` if the flow is now complete
        (RST seen, or FIN observed in both directions). Returns ``None``
        otherwise.

        Args:
            pkt: Parsed packet record from a capture source.

        Returns:
            A ``FlowResult`` if the flow completed, else ``None``.
        """
        key = FlowKey.from_endpoints(
            pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol
        )

        with self._lock:
            if key in self._table:
                acc, flow_lock = self._table[key]
            else:
                # Enforce capacity limit
                if len(self._table) >= _MAX_FLOWS:
                    self._evict_oldest_locked()
                acc = FlowAccumulator(key=key)
                flow_lock = threading.Lock()
                self._table[key] = (acc, flow_lock)

        with flow_lock:
            acc.ingest(pkt)
            if acc.is_terminal:
                result = acc.to_flow_result()
                result.state = FlowState.COMPLETED
                result.context = result.to_context_dict()
                with self._lock:
                    self._table.pop(key, None)
                return result

        return None

    def expire_flows(
        self,
        current_time_us: float,
        idle_timeout_us: float = _IDLE_TIMEOUT_US,
    ) -> list[FlowResult]:
        """Evict flows that have been idle for longer than *idle_timeout_us*.

        Args:
            current_time_us: Current wall-clock time in microseconds.
            idle_timeout_us: Maximum allowed idle duration in microseconds.

        Returns:
            List of ``FlowResult`` objects for all evicted flows.
        """
        results: list[FlowResult] = []

        with self._lock:
            expired_keys = [
                k
                for k, (acc, _) in self._table.items()
                if (current_time_us - acc.last_packet_time) > idle_timeout_us
            ]
            expired_items = []
            for k in expired_keys:
                expired_items.append(self._table.pop(k))

        for acc, flow_lock in expired_items:
            with flow_lock:
                result = acc.to_flow_result()
                result.state = FlowState.TIMEOUT
                result.context = result.to_context_dict()
                results.append(result)

        return results

    def flush_all(self) -> list[FlowResult]:
        """Evict every active flow and return their ``FlowResult`` objects.

        Intended for clean shutdown.  After this call the table is empty.

        Returns:
            List of ``FlowResult`` for all flows that were active.
        """
        results: list[FlowResult] = []

        with self._lock:
            items = list(self._table.values())
            self._table.clear()

        for acc, flow_lock in items:
            with flow_lock:
                result = acc.to_flow_result()
                result.state = FlowState.COMPLETED
                result.context = result.to_context_dict()
                results.append(result)

        return results

    # ------------------------------------------------------------------
    # Internal helpers (must be called with _lock held)
    # ------------------------------------------------------------------

    def _evict_oldest_locked(self) -> None:
        """Remove the flow with the smallest ``last_packet_time``.

        Must be called while ``self._lock`` is held.
        """
        if not self._table:
            return
        oldest_key = min(
            self._table,
            key=lambda k: self._table[k][0].last_packet_time,
        )
        self._table.pop(oldest_key)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        """Return the number of active flows."""
        with self._lock:
            return len(self._table)
