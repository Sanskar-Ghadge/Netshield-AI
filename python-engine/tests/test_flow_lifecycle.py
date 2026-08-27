"""Tests for protocol-specific flow lifecycle behavior."""

from __future__ import annotations

from packet_capture.aggregator import FlowTable
from packet_capture.schemas import FlowState, PacketRecord


def _packet(
    timestamp_us: float,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    *,
    protocol: int = 6,
    flags: int = 0,
) -> PacketRecord:
    """Build a minimal packet record for lifecycle tests."""
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
        tcp_data_offset=5 if protocol == 6 else 0,
    )


def test_rst_completes_immediately() -> None:
    """TCP RST returns a completed flow and removes it from the table."""
    table = FlowTable()
    result = table.ingest(_packet(1.0, flags=0x04))

    assert result is not None
    assert result.state == FlowState.COMPLETED
    assert result.context["is_completed"] is True
    assert len(table) == 0


def test_fin_requires_both_directions() -> None:
    """One FIN remains active until a reverse-direction FIN arrives."""
    table = FlowTable()
    assert table.ingest(_packet(1.0, flags=0x02)) is None
    assert table.ingest(_packet(2.0, flags=0x11)) is None
    assert len(table) == 1

    result = table.ingest(
        _packet(
            3.0,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=12345,
            flags=0x11,
        )
    )
    assert result is not None
    assert result.state == FlowState.COMPLETED
    assert result.packet_count == 3
    assert len(table) == 0


def test_single_fin_times_out() -> None:
    """A half-closed TCP flow remains until timeout and reports TIMEOUT."""
    table = FlowTable()
    assert table.ingest(_packet(1.0, flags=0x11)) is None

    results = table.expire_flows(12.0, idle_timeout_us=10.0)
    assert len(results) == 1
    assert results[0].state == FlowState.TIMEOUT
    assert results[0].context["is_completed"] is True


def test_udp_and_icmp_only_complete_on_timeout_or_flush() -> None:
    """Connectionless flows do not complete during packet ingestion."""
    table = FlowTable()
    assert table.ingest(_packet(1.0, protocol=17, src_port=53, dst_port=50000)) is None
    assert table.ingest(_packet(2.0, protocol=1, src_port=0, dst_port=0)) is None
    assert len(table) == 2

    flushed = table.flush_all()
    assert len(flushed) == 2
    assert all(result.state == FlowState.COMPLETED for result in flushed)
    assert all(result.context["is_completed"] is True for result in flushed)
    assert len(table) == 0
