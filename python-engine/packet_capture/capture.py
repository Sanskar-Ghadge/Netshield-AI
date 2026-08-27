"""Capture controller — orchestrates packet sources and the flow table.

``CaptureController`` ties together a packet source (``PcapReplaySource`` or
``LiveCaptureSource``) and a ``FlowTable``.  Completed flows are placed onto
``completed_flows`` for downstream consumers such as the prediction engine.

Architecture:

    source  ──packets──▶  FlowTable.ingest  ──FlowResult──▶  completed_flows
                                 │
                     (background) expire sweep every 10 s
                                 │
                         FlowTable.flush_all  (on stop)

Thread model:
    - Main ingest thread: pulls records from the source and calls ingest().
    - Expiry thread: calls expire_flows() every ``_EXPIRE_INTERVAL_S`` seconds.
    - Both threads are daemon threads so they die with the process.

Deterministic replay (``replay_pcap``) runs entirely on the calling thread
with no background threads, no wall-clock expiry, and no sleeps.  It is
suitable for unit testing and CI.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from typing import Optional

from packet_capture.aggregator import FlowTable
from packet_capture.schemas import (
    Direction,
    FlowResult,
    FlowState,
    PacketRecord,
    ReplayResult,
)

_EXPIRE_INTERVAL_S: float = 10.0
_IDLE_TIMEOUT_US: float = 120_000_000.0  # 2 minutes


class CaptureController:
    """Controller that wires a packet source to the flow aggregation table.

    Args:
        idle_timeout_us: Idle-flow eviction threshold in microseconds.
        expire_interval_s: How often (seconds) to run the expiry sweep.

    Attributes:
        completed_flows: Queue of ``FlowResult`` objects ready for the
            prediction engine.  Consumers should read from this queue.

    Example (PCAP replay):

        from packet_capture.sources import PcapReplaySource
        ctrl = CaptureController()
        ctrl.start(PcapReplaySource("/tmp/capture.pcap"))
        while True:
            result = ctrl.completed_flows.get(timeout=5)
            predictor.predict(result)

    Example (deterministic replay):

        ctrl = CaptureController()
        stats = ctrl.replay_pcap("/tmp/capture.pcap")
        for flow_result in stats.completed_flows:
            predictor.predict(flow_result)
    """

    def __init__(
        self,
        idle_timeout_us: float = _IDLE_TIMEOUT_US,
        expire_interval_s: float = _EXPIRE_INTERVAL_S,
    ) -> None:
        self._idle_timeout_us = idle_timeout_us
        self._expire_interval_s = expire_interval_s

        self.completed_flows: queue.Queue[FlowResult] = queue.Queue()
        self._flow_table: FlowTable = FlowTable()

        self._stop_event: threading.Event = threading.Event()
        self._ingest_thread: Optional[threading.Thread] = None
        self._expire_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public control API — live/threaded mode
    # ------------------------------------------------------------------

    def start(self, source: object) -> None:
        """Start packet ingestion from *source* in background threads.

        Launches:
        - An ingest thread that pulls packets from the source.
        - A background expiry-sweep thread.

        Args:
            source: A ``PcapReplaySource`` or ``LiveCaptureSource`` instance.
                Anything with a ``packets()`` generator or a ``packet_queue``
                attribute is accepted; detection is duck-typed.
        """
        self._stop_event.clear()
        self._source = source

        self._expire_thread = threading.Thread(
            target=self._expire_loop,
            daemon=True,
            name="CaptureController-expire",
        )
        self._expire_thread.start()

        self._ingest_thread = threading.Thread(
            target=self._ingest_loop,
            args=(source,),
            daemon=True,
            name="CaptureController-ingest",
        )
        self._ingest_thread.start()

    def stop(self) -> None:
        """Signal all threads to stop, flush remaining flows, and drain.

        After this call ``completed_flows`` will contain every FlowResult
        that was still active at shutdown.  The controller can be restarted
        by calling ``start()`` again.
        """
        self._stop_event.set()

        # Wait for the ingest thread to notice the stop signal
        if self._ingest_thread is not None:
            self._ingest_thread.join(timeout=10.0)
            self._ingest_thread = None

        # Wait for the expiry thread
        if self._expire_thread is not None:
            self._expire_thread.join(timeout=5.0)
            self._expire_thread = None

        # Flush remaining flows into the output queue
        remaining = self._flow_table.flush_all()
        for result in remaining:
            self.completed_flows.put(result)

    # ------------------------------------------------------------------
    # Deterministic synchronous replay
    # ------------------------------------------------------------------

    def replay_pcap(self, path: str) -> ReplayResult:
        """Replay a PCAP file deterministically and return flow statistics.

        This is a fully synchronous, single-threaded method with no
        background threads, no wall-clock expiry, and no sleeps.  It is
        designed for unit testing, CI, and deterministic feature
        verification.

        Processing steps:
            1. Validate the file path and open with Scapy's ``PcapReader``.
            2. Stream every packet from the PCAP one-at-a-time.
            3. Skip non-IP packets (counted as *skipped*); count any
               conversion exceptions as *parse_error*.
            4. Ingest accepted ``PacketRecord`` objects into a private
               ``FlowTable`` (isolated from the controller's live table).
            5. Collect flows that complete naturally during ingestion
               (TCP RST or bidirectional FIN).
            6. At EOF, close the reader, then flush all remaining active
               flows in deterministic order (sorted by ``FlowKey``).
            7. Return a ``ReplayResult`` with full statistics.

        Args:
            path: Filesystem path to the ``.pcap``/``.pcapng`` file.

        Returns:
            A ``ReplayResult`` with packet/flow statistics and the ordered
            list of all ``FlowResult`` objects produced during the replay
            (naturally-completed flows first, then EOF-flushed flows).

        Raises:
            FileNotFoundError: If *path* does not exist.
            ValueError: If *path* points to a directory.
            RuntimeError: If scapy is not installed or cannot be imported.
            Exception: Propagates Scapy parsing errors for corrupt PCAPs.
        """
        # --- Validate path -------------------------------------------------
        if not os.path.exists(path):
            raise FileNotFoundError(f"PCAP file not found: {path!r}")
        if os.path.isdir(path):
            raise ValueError(f"Path is a directory, not a PCAP file: {path!r}")

        # Ensure scapy is available (raises RuntimeError if not)
        from packet_capture.sources import _check_scapy  # noqa: PLC0415
        _check_scapy()

        from scapy.all import PcapReader  # type: ignore[import]
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore[import]

        # --- Private flow table for this deterministic run -----------------
        replay_table: FlowTable = FlowTable()

        packets_read: int = 0
        packets_accepted: int = 0
        packets_skipped: int = 0
        packets_parse_error: int = 0

        # Flows that completed naturally during ingestion (TCP RST / FIN)
        naturally_completed: list[FlowResult] = []

        # --- Stream packets to EOF -----------------------------------------
        reader = PcapReader(path)
        try:
            for pkt in reader:
                packets_read += 1

                # ---- Convert to PacketRecord --------------------------------
                try:
                    if not pkt.haslayer(IP):
                        packets_skipped += 1
                        continue

                    ip = pkt[IP]
                    timestamp_us: float = float(pkt.time) * 1_000_000.0
                    src_ip: str = str(ip.src)
                    dst_ip: str = str(ip.dst)
                    protocol: int = int(ip.proto)
                    ip_total_length: int = int(ip.len)
                    ip_header_length: int = int(ip.ihl) * 4

                    src_port: int = 0
                    dst_port: int = 0
                    transport_header_length: int = 0
                    tcp_flags: int = 0
                    tcp_window: int = 0
                    tcp_data_offset: int = 0

                    if protocol == 6 and pkt.haslayer(TCP):
                        tcp = pkt[TCP]
                        src_port = int(tcp.sport)
                        dst_port = int(tcp.dport)
                        tcp_data_offset = int(tcp.dataofs)
                        transport_header_length = tcp_data_offset * 4
                        tcp_flags = int(tcp.flags)
                        tcp_window = int(tcp.window)
                    elif protocol == 17 and pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        src_port = int(udp.sport)
                        dst_port = int(udp.dport)
                        transport_header_length = 8
                    elif protocol == 1 and pkt.haslayer(ICMP):
                        transport_header_length = 8

                    payload_length = max(
                        ip_total_length - ip_header_length - transport_header_length,
                        0,
                    )

                    record = PacketRecord(
                        timestamp_us=timestamp_us,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        ip_total_length=ip_total_length,
                        ip_header_length=ip_header_length,
                        transport_header_length=transport_header_length,
                        payload_length=payload_length,
                        tcp_flags=tcp_flags,
                        tcp_window=tcp_window,
                        tcp_data_offset=tcp_data_offset,
                        direction=Direction.UNKNOWN,
                    )
                except Exception:
                    packets_parse_error += 1
                    continue

                packets_accepted += 1

                # ---- Ingest and collect naturally-completed flows -----------
                result: Optional[FlowResult] = replay_table.ingest(record)
                if result is not None:
                    naturally_completed.append(result)
        finally:
            reader.close()

        # --- EOF: flush remaining active flows in deterministic order -------
        # ``FlowTable.flush_all`` returns items in arbitrary dict-iteration
        # order.  We sort by the FlowKey fields for determinism.
        eof_raw: list[FlowResult] = replay_table.flush_all()
        eof_flushed: list[FlowResult] = sorted(
            eof_raw,
            key=lambda r: (r.key.ip_a, r.key.port_a, r.key.ip_b, r.key.port_b, r.key.protocol),
        )
        for fr in eof_flushed:
            fr.state = FlowState.COMPLETED  # mark EOF-flushed as completed too

        all_flows: list[FlowResult] = naturally_completed + eof_flushed

        return ReplayResult(
            packets_read=packets_read,
            packets_accepted=packets_accepted,
            packets_skipped=packets_skipped,
            packets_parse_error=packets_parse_error,
            flows_naturally_completed=len(naturally_completed),
            flows_eof_flushed=len(eof_flushed),
            flows_total=len(all_flows),
            completed_flows=all_flows,
        )

    # ------------------------------------------------------------------
    # Internal threads — live mode
    # ------------------------------------------------------------------

    def _ingest_loop(self, source: object) -> None:
        """Pull packets from *source* and ingest them into the flow table.

        Supports two source interfaces:
        - ``packets()`` generator (PcapReplaySource / any iterable).
        - ``packet_queue`` attribute (LiveCaptureSource).

        Args:
            source: The packet source to drain.
        """
        if hasattr(source, "packets"):
            # Iterable / PCAP-replay source
            for record in source.packets():  # type: ignore[union-attr]
                if self._stop_event.is_set():
                    break
                self._process(record)
        elif hasattr(source, "packet_queue"):
            # Live-capture source: drain the queue until stopped
            pq: queue.Queue = source.packet_queue  # type: ignore[union-attr]
            while not self._stop_event.is_set():
                try:
                    record: PacketRecord = pq.get(timeout=0.5)
                    self._process(record)
                except queue.Empty:
                    continue
        else:
            raise TypeError(
                f"Unsupported source type {type(source)}: "
                "must have a 'packets()' generator or 'packet_queue' attribute."
            )

    def _expire_loop(self) -> None:
        """Periodically evict idle flows and push their results to the queue."""
        while not self._stop_event.is_set():
            # Sleep in short intervals so stop() is responsive
            for _ in range(int(self._expire_interval_s / 0.25)):
                if self._stop_event.is_set():
                    break
                time.sleep(0.25)

            if not self._stop_event.is_set():
                current_us = time.time() * 1_000_000.0
                expired = self._flow_table.expire_flows(
                    current_us, self._idle_timeout_us
                )
                for result in expired:
                    self.completed_flows.put(result)

    def _process(self, record: PacketRecord) -> None:
        """Ingest one packet; push a completed FlowResult if one is returned.

        Args:
            record: The ``PacketRecord`` to ingest.
        """
        result = self._flow_table.ingest(record)
        if result is not None:
            self.completed_flows.put(result)
