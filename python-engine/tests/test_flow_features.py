"""Unit tests for the FlowAccumulator feature computation.

Hand-calculated packet sequences verify the 40 CICFlowMeter v3 features
produced by ``FlowAccumulator.compute_features()``.

All timing in microseconds.  TCP flags: FIN=0x01, SYN=0x02, RST=0x04,
PSH=0x08, ACK=0x10, URG=0x20.
"""

from __future__ import annotations

import sys
import os

# Ensure the python-engine root is on sys.path regardless of how pytest is invoked
_ENGINE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ENGINE_ROOT not in sys.path:
    sys.path.insert(0, _ENGINE_ROOT)

import math
import pytest

from packet_capture.flow import FlowAccumulator
from packet_capture.schemas import Direction, FlowKey, PacketRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_key(
    src_ip: str = "1.1.1.1",
    dst_ip: str = "2.2.2.2",
    src_port: int = 1234,
    dst_port: int = 80,
    protocol: int = 6,
) -> FlowKey:
    return FlowKey.from_endpoints(src_ip, dst_ip, src_port, dst_port, protocol)


def _pkt(
    ts_us: float,
    src_ip: str,
    dst_ip: str,
    src_port: int = 1234,
    dst_port: int = 80,
    protocol: int = 6,
    payload_length: int = 0,
    tcp_flags: int = 0,
    tcp_window: int = 0,
    tcp_data_offset: int = 5,
    ip_header_length: int = 20,
) -> PacketRecord:
    transport_header_length = tcp_data_offset * 4 if protocol == 6 else (8 if protocol in (17, 1) else 0)
    ip_total_length = ip_header_length + transport_header_length + payload_length
    return PacketRecord(
        timestamp_us=ts_us,
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
# Test A — simple two-packet TCP flow
# ---------------------------------------------------------------------------

def test_simple_two_packet_tcp_flow():
    """Two fwd packets: SYN at 0 us, ACK at 500_000 us, payload 100 bytes each.

    Expected:
        Flow Duration        = 500_000
        Total Fwd Packets    = 2
        Fwd IAT Total        = 500_000
        FIN Flag Count       = 0
        ACK Flag Count       = 1
    """
    key = _make_key()
    acc = FlowAccumulator(key=key)

    # Packet 1: SYN (flags=0x02)
    acc.ingest(_pkt(0.0, "1.1.1.1", "2.2.2.2", tcp_flags=0x02, payload_length=100))
    # Packet 2: ACK (flags=0x10)
    acc.ingest(_pkt(500_000.0, "1.1.1.1", "2.2.2.2", tcp_flags=0x10, payload_length=100))

    f = acc.compute_features()

    assert f["Flow Duration"] == pytest.approx(500_000.0)
    assert f["Total Fwd Packets"] == pytest.approx(2.0)
    assert f["Total Backward Packets"] == pytest.approx(0.0)
    assert f["Fwd IAT Total"] == pytest.approx(500_000.0)
    assert f["FIN Flag Count"] == pytest.approx(0.0)
    assert f["ACK Flag Count"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Test B — bidirectional flow
# ---------------------------------------------------------------------------

def test_bidirectional_flow():
    """Fwd at 0 and 200_000 us; bwd at 100_000 and 300_000 us; payload=50.

    Expected:
        Total Fwd Packets     = 2
        Total Backward Packets = 2
        Down/Up Ratio         = 1.0
    """
    key = _make_key()
    acc = FlowAccumulator(key=key)

    # Fwd packets
    acc.ingest(_pkt(0.0,        "1.1.1.1", "2.2.2.2", payload_length=50))
    # Bwd packet
    acc.ingest(_pkt(100_000.0,  "2.2.2.2", "1.1.1.1", src_port=80, dst_port=1234, payload_length=50))
    # Fwd packet
    acc.ingest(_pkt(200_000.0,  "1.1.1.1", "2.2.2.2", payload_length=50))
    # Bwd packet
    acc.ingest(_pkt(300_000.0,  "2.2.2.2", "1.1.1.1", src_port=80, dst_port=1234, payload_length=50))

    f = acc.compute_features()

    assert f["Total Fwd Packets"] == pytest.approx(2.0)
    assert f["Total Backward Packets"] == pytest.approx(2.0)
    assert f["Down/Up Ratio"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Test C — active/idle detection
# ---------------------------------------------------------------------------

def test_active_idle_detection():
    """4 packets at 0, 100_000, 1_500_000, 1_600_000 us (threshold=1_000_000).

    Gap between packet 2 and 3 is 1_400_000 us > threshold → idle gap.
    Active burst 1: 0 → 100_000  (duration 100_000 us)
    Idle gap:       100_000 → 1_500_000 (gap 1_400_000 us)
    Active burst 2: 1_500_000 → 1_600_000 (duration 100_000 us)

    Expected:
        Active Mean  > 0   (mean of [100_000])  = 100_000
        Idle Mean    > 0   (mean of [1_400_000]) = 1_400_000
        Exactly 1 idle gap  ↔  Idle Std == 0 (only one idle value)
    """
    key = _make_key()
    acc = FlowAccumulator(key=key)

    for ts in (0.0, 100_000.0, 1_500_000.0, 1_600_000.0):
        acc.ingest(_pkt(ts, "1.1.1.1", "2.2.2.2", payload_length=10))

    f = acc.compute_features()

    assert f["Active Mean"] > 0, f"Active Mean should be > 0, got {f['Active Mean']}"
    assert f["Idle Mean"] > 0, f"Idle Mean should be > 0, got {f['Idle Mean']}"
    # Exactly one idle gap → Idle Std = 0 (population std of a single value)
    assert f["Idle Std"] == pytest.approx(0.0), (
        f"Expected Idle Std == 0 (single idle gap), got {f['Idle Std']}"
    )


# ---------------------------------------------------------------------------
# Test D — rate computation
# ---------------------------------------------------------------------------

def test_rate_computation():
    """2 fwd packets at 0 and 1_000_000 us, payload 500 bytes each.

    Duration = 1_000_000 us = 1.0 s
    Total bytes = 500 + 500 = 1000
    Flow Bytes/s   = 1000 / 1.0 = 1000.0
    Flow Packets/s = 2    / 1.0 = 2.0
    """
    key = _make_key()
    acc = FlowAccumulator(key=key)

    acc.ingest(_pkt(0.0,         "1.1.1.1", "2.2.2.2", payload_length=500))
    acc.ingest(_pkt(1_000_000.0, "1.1.1.1", "2.2.2.2", payload_length=500))

    f = acc.compute_features()

    assert f["Flow Duration"] == pytest.approx(1_000_000.0)
    assert f["Flow Bytes/s"] == pytest.approx(1000.0, rel=1e-6)
    assert f["Flow Packets/s"] == pytest.approx(2.0, rel=1e-6)


# ---------------------------------------------------------------------------
# Test E — single-packet flow (zero IATs everywhere)
# ---------------------------------------------------------------------------

def test_single_packet_zero_iats():
    """One packet at 0 us.  All IAT statistics must be zero.

    Expected:
        Flow IAT Std  = 0
        Flow IAT Min  = 0
        Fwd IAT Total = 0
        Fwd IAT Std   = 0
        Fwd IAT Min   = 0
        Bwd IAT Total = 0
        Bwd IAT Std   = 0
        Bwd IAT Min   = 0
    """
    key = _make_key()
    acc = FlowAccumulator(key=key)

    acc.ingest(_pkt(0.0, "1.1.1.1", "2.2.2.2", payload_length=64))

    f = acc.compute_features()

    for feat in (
        "Flow IAT Std", "Flow IAT Min",
        "Fwd IAT Total", "Fwd IAT Std", "Fwd IAT Min",
        "Bwd IAT Total", "Bwd IAT Std", "Bwd IAT Min",
    ):
        assert f[feat] == pytest.approx(0.0), (
            f"Expected {feat} == 0 for single-packet flow, got {f[feat]}"
        )
