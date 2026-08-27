"""Data types for the packet capture and flow aggregation layer.

These schemas define the intermediate representation between raw packet
capture (PCAP replay or live Scapy sniffing) and the prediction engine.
The flow calculator consumes ``PacketRecord`` objects and produces
``FlowResult`` objects whose ``features`` dict is consumed by
``RuntimePreprocessor``.

All timing values are in microseconds to match CICIDS2017 v3 semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Direction(IntEnum):
    """Direction of a packet relative to the flow's forward direction.

    Attributes:
        FORWARD: Packet travels from initiator to responder.
        BACKWARD: Packet travels from responder to initiator.
        UNKNOWN: Direction not yet determined (first packet sets it).
    """

    UNKNOWN = 0
    FORWARD = 1
    BACKWARD = 2


class FlowState(IntEnum):
    """Lifecycle state of a flow in the aggregation table.

    Attributes:
        NEW: First packet seen but no SYN yet (or non-TCP).
        ESTABLISHED: SYN and SYN-ACK both seen (TCP only).
        CLOSING: FIN or RST seen; flow is terminating.
        COMPLETED: Flow has been evicted from the table.
        TIMEOUT: Flow evicted due to inactivity.
    """

    NEW = 0
    ESTABLISHED = 1
    CLOSING = 2
    COMPLETED = 3
    TIMEOUT = 4


@dataclass(frozen=True)
class FlowKey:
    """Bidirectional 5-tuple key that uniquely identifies a flow.

    Two flows share the same key if their endpoint pairs match regardless
    of which side initiated (initiator→responder == responder→initiator).

    Attributes:
        ip_a: The smaller IP address string (lexicographic order).
        ip_b: The larger IP address string.
        port_a: The port corresponding to ip_a.
        port_b: The port corresponding to ip_b.
        protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP).
    """

    ip_a: str
    ip_b: str
    port_a: int
    port_b: int
    protocol: int

    @classmethod
    def from_endpoints(
        cls,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
    ) -> "FlowKey":
        """Construct a canonical flow key from raw packet endpoints.

        The endpoint tuples are compared as complete ``(IP, port)`` pairs.
        This is essential when both endpoints use the same IP address.

        Args:
            src_ip: Source IP of the packet.
            dst_ip: Destination IP of the packet.
            src_port: Source port (0 for protocols without ports).
            dst_port: Destination port (0 for protocols without ports).
            protocol: IP protocol number.

        Returns:
            A normalized FlowKey.
        """
        source = (src_ip, src_port)
        destination = (dst_ip, dst_port)
        if source <= destination:
            return cls(src_ip, dst_ip, src_port, dst_port, protocol)
        return cls(dst_ip, src_ip, dst_port, src_port, protocol)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the key."""
        return {
            "ip_a": self.ip_a,
            "ip_b": self.ip_b,
            "port_a": self.port_a,
            "port_b": self.port_b,
            "protocol": self.protocol,
        }

    @property
    def initiator_port(self) -> int:
        """Return the port on the initiator side (ip_a)."""
        return self.port_a

    @property
    def responder_port(self) -> int:
        """Return the port on the responder side (ip_b)."""
        return self.port_b


@dataclass(frozen=True)
class PacketRecord:
    """Parsed packet data produced by a capture source.

    Attributes:
        timestamp_us: Packet timestamp in microseconds (epoch).
        src_ip: Source IP address string.
        dst_ip: Destination IP address string.
        src_port: Source port (0 for non-TCP/UDP).
        dst_port: Destination port (0 for non-TCP/UDP).
        protocol: IP protocol number.
        ip_total_length: Total IP packet length (header + payload) in bytes.
        ip_header_length: IP header length in bytes (IHL × 4).
        transport_header_length: TCP/UDP/ICMP header length in bytes.
        payload_length: IP payload length (ip_total_length - ip_header_length - transport_header_length).
        tcp_flags: TCP flags bitmask (FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32). 0 for non-TCP.
        tcp_window: TCP window size value. 0 for non-TCP.
        tcp_data_offset: TCP data offset in 32-bit words (0 for non-TCP).
        direction: Direction relative to the flow's forward direction.
    """

    timestamp_us: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    ip_total_length: int
    ip_header_length: int
    transport_header_length: int
    payload_length: int
    tcp_flags: int = 0
    tcp_window: int = 0
    tcp_data_offset: int = 0
    direction: Direction = Direction.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the packet."""
        return {
            "timestamp_us": self.timestamp_us,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "ip_total_length": self.ip_total_length,
            "ip_header_length": self.ip_header_length,
            "transport_header_length": self.transport_header_length,
            "payload_length": self.payload_length,
            "tcp_flags": self.tcp_flags,
            "tcp_window": self.tcp_window,
            "tcp_data_offset": self.tcp_data_offset,
            "direction": int(self.direction),
        }


@dataclass
class FlowResult:
    """Output of the flow feature calculator for one completed flow.

    Attributes:
        key: The FlowKey identifying this flow.
        features: Dict of CICIDS2017 feature name → numeric value.
        context: FlowContext-compatible metadata for the prediction engine.
        packet_count: Total packets processed for this flow.
        start_timestamp_us: Timestamp of the first packet.
        end_timestamp_us: Timestamp of the last packet.
        state: Final flow lifecycle state.
        initiator_ip: Source IP of the first packet.
        responder_ip: Destination IP of the first packet.
        initiator_port: Source port of the first packet.
        responder_port: Destination port of the first packet.
    """

    key: FlowKey
    features: dict[str, float] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    packet_count: int = 0
    start_timestamp_us: float = 0.0
    end_timestamp_us: float = 0.0
    state: FlowState = FlowState.NEW
    initiator_ip: str = ""
    responder_ip: str = ""
    initiator_port: int = 0
    responder_port: int = 0

    def to_prediction_input(self) -> dict[str, Any]:
        """Return the features dict ready for ``IntrusionPredictor.predict_one``."""
        return dict(self.features)

    def to_context_dict(self) -> dict[str, Any]:
        """Return flow metadata using first-packet endpoint orientation."""
        src_ip = self.initiator_ip or self.key.ip_a
        dst_ip = self.responder_ip or self.key.ip_b
        src_port = self.initiator_port if self.initiator_ip else self.key.port_a
        dst_port = self.responder_port if self.responder_ip else self.key.port_b
        return {
            "flow_id": f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{self.key.protocol}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": self.key.protocol,
            "total_packets": self.packet_count,
            "flow_duration_us": self.end_timestamp_us - self.start_timestamp_us,
            "is_completed": self.state in (FlowState.COMPLETED, FlowState.TIMEOUT),
        }


@dataclass(frozen=True)
class ReplayResult:
    """Statistics returned by ``CaptureController.replay_pcap``.

    All counts refer to a single deterministic synchronous replay run.

    Attributes:
        packets_read: Total raw packets read from the PCAP (including
            non-IP packets).
        packets_accepted: IP packets successfully converted to
            ``PacketRecord`` objects and ingested into the flow table.
        packets_skipped: Non-IP packets that were silently ignored.
        packets_parse_error: Packets that raised an exception during
            conversion and were counted as errors.
        flows_naturally_completed: Flows that completed in-stream
            (e.g. TCP RST, or bidirectional FIN) before EOF.
        flows_eof_flushed: Active flows forcibly flushed at EOF.
        flows_total: Total flows produced (naturally_completed +
            eof_flushed).
        completed_flows: Ordered list of every ``FlowResult`` produced
            during the replay (naturally-completed then EOF-flushed).
    """

    packets_read: int
    packets_accepted: int
    packets_skipped: int
    packets_parse_error: int
    flows_naturally_completed: int
    flows_eof_flushed: int
    flows_total: int
    completed_flows: list
