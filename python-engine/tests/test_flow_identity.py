"""Tests for canonical flow identity and first-packet orientation."""

from __future__ import annotations

from packet_capture.flow import FlowAccumulator
from packet_capture.schemas import FlowKey, PacketRecord


def _packet(
    timestamp_us: float,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    protocol: int = 6,
    flags: int = 0,
    window: int = 0,
) -> PacketRecord:
    """Build a minimal packet record for flow tests."""
    transport_length = 20 if protocol == 6 else 8
    return PacketRecord(
        timestamp_us=timestamp_us,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        ip_total_length=20 + transport_length,
        ip_header_length=20,
        transport_header_length=transport_length,
        payload_length=0,
        tcp_flags=flags,
        tcp_window=window,
        tcp_data_offset=5 if protocol == 6 else 0,
    )


def test_flow_key_canonicalizes_complete_same_ip_endpoints() -> None:
    """Reverse packets on one IP produce the same canonical key."""
    forward = FlowKey.from_endpoints("127.0.0.1", "127.0.0.1", 50000, 443, 6)
    backward = FlowKey.from_endpoints("127.0.0.1", "127.0.0.1", 443, 50000, 6)

    assert forward == backward
    assert (forward.ip_a, forward.port_a) == ("127.0.0.1", 443)
    assert (forward.ip_b, forward.port_b) == ("127.0.0.1", 50000)


def test_first_packet_orientation_is_independent_of_canonical_order() -> None:
    """Features and context retain actual initiator/responder endpoints."""
    first = _packet(1.0, "10.0.0.9", "10.0.0.1", 51000, 80, flags=0x02)
    key = FlowKey.from_endpoints(
        first.src_ip, first.dst_ip, first.src_port, first.dst_port, first.protocol
    )
    accumulator = FlowAccumulator(key)
    accumulator.ingest(first)
    accumulator.ingest(
        _packet(2.0, "10.0.0.1", "10.0.0.9", 80, 51000, flags=0x12)
    )

    result = accumulator.to_flow_result()
    assert result.features["Destination Port"] == 80.0
    assert result.features["Total Fwd Packets"] == 1.0
    assert result.features["Total Backward Packets"] == 1.0
    assert result.initiator_ip == "10.0.0.9"
    assert result.responder_ip == "10.0.0.1"
    assert result.to_context_dict()["src_port"] == 51000
    assert result.to_context_dict()["dst_port"] == 80


def test_initial_tcp_windows_include_literal_zero() -> None:
    """A first zero window cannot be replaced by a later nonzero value."""
    first = _packet(1.0, "10.0.0.1", "10.0.0.2", 12345, 443, window=0)
    key = FlowKey.from_endpoints(
        first.src_ip, first.dst_ip, first.src_port, first.dst_port, first.protocol
    )
    accumulator = FlowAccumulator(key)
    accumulator.ingest(first)
    accumulator.ingest(
        _packet(2.0, "10.0.0.1", "10.0.0.2", 12345, 443, window=4096)
    )
    accumulator.ingest(
        _packet(3.0, "10.0.0.2", "10.0.0.1", 443, 12345, window=0)
    )
    accumulator.ingest(
        _packet(4.0, "10.0.0.2", "10.0.0.1", 443, 12345, window=8192)
    )

    features = accumulator.compute_features()
    assert features["Init_Win_bytes_forward"] == 0.0
    assert features["Init_Win_bytes_backward"] == 0.0
