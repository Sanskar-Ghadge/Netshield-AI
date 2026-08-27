"""Packet capture sources — PCAP replay and live Scapy sniffing.

Both sources convert raw Scapy packets into ``PacketRecord`` objects.
Scapy is imported lazily at instantiation time so that the module can be
imported without scapy installed (useful for unit-test environments where
only the flow-feature logic is under test).

Supported protocols: TCP (6), UDP (17), ICMP (1).
Non-TCP/UDP protocols use port=0.

Payload length formula:
    payload_length = IP.len - IP.ihl*4 - transport_header_len

TCP transport_header_len  = TCP.dataofs * 4
UDP transport_header_len  = 8
ICMP transport_header_len = 8
"""

from __future__ import annotations

import queue
from typing import Generator, Optional

from packet_capture.schemas import Direction, PacketRecord

# ---------------------------------------------------------------------------
# Lazy scapy import — never at module level
# ---------------------------------------------------------------------------
_scapy_available: Optional[bool] = None
_scapy_error: Optional[str] = None


def _check_scapy() -> None:
    """Raise RuntimeError if scapy cannot be imported."""
    global _scapy_available, _scapy_error
    if _scapy_available is None:
        try:
            import scapy.all  # noqa: F401
            _scapy_available = True
        except Exception as exc:  # ImportError, OSError, …
            _scapy_available = False
            _scapy_error = str(exc)
    if not _scapy_available:
        raise RuntimeError(
            f"scapy is required for packet capture but could not be imported: "
            f"{_scapy_error}.  Install it with: pip install scapy"
        )


# ---------------------------------------------------------------------------
# Internal conversion helper
# ---------------------------------------------------------------------------

def _scapy_to_record(pkt) -> Optional[PacketRecord]:  # type: ignore[no-untyped-def]
    """Convert a Scapy packet to a ``PacketRecord``.

    Args:
        pkt: A Scapy packet object.

    Returns:
        A ``PacketRecord``, or ``None`` if the packet has no IP layer.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except ImportError:
        from scapy.all import IP, TCP, UDP, ICMP  # type: ignore[no-redef]

    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    timestamp_us = float(pkt.time) * 1_000_000.0

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

    if protocol == 6 and pkt.haslayer(TCP):  # TCP
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_data_offset = int(tcp.dataofs)
        transport_header_length = tcp_data_offset * 4
        # Scapy stores flags as a FlagValue; convert to int
        tcp_flags = int(tcp.flags)
        tcp_window = int(tcp.window)

    elif protocol == 17 and pkt.haslayer(UDP):  # UDP
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        transport_header_length = 8

    elif protocol == 1 and pkt.haslayer(ICMP):  # ICMP
        transport_header_length = 8

    payload_length = max(
        ip_total_length - ip_header_length - transport_header_length, 0
    )

    return PacketRecord(
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


# ---------------------------------------------------------------------------
# PCAP replay source
# ---------------------------------------------------------------------------

class PcapReplaySource:
    """Read a PCAP file and yield ``PacketRecord`` objects in order.

    Uses Scapy's ``PcapReader`` for lazy streaming — packets are read
    one-at-a-time rather than loading the entire file into memory via
    ``rdpcap``.  The reader is opened lazily when iteration starts and is
    closed deterministically when the generator is exhausted, explicitly
    closed, or garbage-collected.

    Scapy is imported at instantiation time; a helpful ``RuntimeError`` is
    raised if scapy is not installed.

    Args:
        path: Path to the ``.pcap`` or ``.pcapng`` file.

    Example::

        src = PcapReplaySource("/path/to/capture.pcap")
        for record in src.packets():
            flow_table.ingest(record)
    """

    def __init__(self, path: str) -> None:
        _check_scapy()
        self._path = path

    def packets(self) -> Generator[PacketRecord, None, None]:
        """Yield ``PacketRecord`` objects for every IP packet in the PCAP.

        Non-IP packets (ARP, etc.) are silently skipped.

        Yields:
            ``PacketRecord`` instances in PCAP order.
        """
        from scapy.all import PcapReader  # type: ignore[import]

        reader = PcapReader(self._path)
        try:
            for pkt in reader:
                record = _scapy_to_record(pkt)
                if record is not None:
                    yield record
        finally:
            reader.close()


# ---------------------------------------------------------------------------
# Live capture source
# ---------------------------------------------------------------------------

class LiveCaptureSource:
    """Capture live packets using Scapy's ``sniff`` function.

    Packets are converted to ``PacketRecord`` objects and placed into a
    ``queue.Queue`` so that the capture thread and the consumer thread are
    decoupled.

    Scapy is imported at instantiation time; a helpful ``RuntimeError`` is
    raised if scapy is not installed.

    Args:
        iface: Network interface to sniff on (e.g. ``"eth0"``).  If
            ``None``, Scapy chooses the default interface.
        bpf_filter: Optional BPF filter string (e.g. ``"tcp port 80"``).
        packet_queue: Optional external queue.  If not supplied a new
            ``queue.Queue`` is created.

    Example::

        src = LiveCaptureSource(iface="eth0")
        src.start()
        while True:
            record = src.get(timeout=1.0)
            if record:
                flow_table.ingest(record)
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packet_queue: Optional[queue.Queue] = None,
    ) -> None:
        _check_scapy()
        self._iface = iface
        self._bpf_filter = bpf_filter
        self._queue: queue.Queue = packet_queue if packet_queue is not None else queue.Queue()
        self._stop_event: Optional[object] = None
        self._sniff_thread: Optional[object] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def packet_queue(self) -> queue.Queue:
        """The queue into which ``PacketRecord`` objects are placed."""
        return self._queue

    def start(self) -> None:
        """Begin sniffing in a background thread."""
        import threading

        self._stop_event = threading.Event()
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="LiveCaptureSource"
        )
        self._sniff_thread.start()

    def stop(self) -> None:
        """Signal the sniffer to stop and wait for it to exit."""
        if self._stop_event is not None:
            self._stop_event.set()
        if self._sniff_thread is not None:
            self._sniff_thread.join(timeout=5.0)

    def get(self, timeout: float = 1.0) -> Optional[PacketRecord]:
        """Retrieve the next ``PacketRecord`` from the queue.

        Args:
            timeout: Seconds to wait before returning ``None``.

        Returns:
            A ``PacketRecord`` or ``None`` on timeout.
        """
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _sniff_loop(self) -> None:
        """Background thread: sniff packets and put records in the queue."""
        from scapy.all import sniff  # type: ignore[import]

        stop_event = self._stop_event

        def _stop_filter(_pkt) -> bool:  # type: ignore[no-untyped-def]
            return stop_event is not None and stop_event.is_set()  # type: ignore[union-attr]

        def _process(pkt) -> None:  # type: ignore[no-untyped-def]
            record = _scapy_to_record(pkt)
            if record is not None:
                self._queue.put(record)

        kwargs: dict = {
            "prn": _process,
            "stop_filter": _stop_filter,
            "store": False,
        }
        if self._iface is not None:
            kwargs["iface"] = self._iface
        if self._bpf_filter is not None:
            kwargs["filter"] = self._bpf_filter

        sniff(**kwargs)
