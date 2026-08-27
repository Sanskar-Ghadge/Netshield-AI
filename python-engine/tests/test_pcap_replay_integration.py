"""Integration tests: PCAP-to-flow-feature pipeline (Stage 4.5.5).

Hand-calculated packet-parsing and flow-feature assertions for the TCP
and UDP PCAP fixtures produced by ``tests/pcap_fixtures.py``.

All expected values are derived independently by hand — no production
feature helpers are used to compute them.  Only ``pytest.approx()`` is
used where floating-point arithmetic (division, square-root) requires it.

TCP fixture characteristics
---------------------------
Packets (7 total, timestamps in microseconds):

    #  t(us)   direction  flags      payload  window
    ─  ──────  ─────────  ─────────  ───────  ──────
    1       0  FWD (C→S)  SYN            0    8192
    2  100000  BWD (S→C)  SYN-ACK        0   65535
    3  200000  FWD (C→S)  ACK            0    8192
    4  300000  FWD (C→S)  PSH-ACK      100    8192
    5  400000  BWD (S→C)  PSH-ACK      200   65535
    6  500000  FWD (C→S)  FIN-ACK        0    8192
    7  600000  BWD (S→C)  FIN-ACK        0   65535

UDP fixture characteristics
---------------------------
Packets (2 total, timestamps in microseconds):

    #  t(us)   direction  payload
    ─  ──────  ─────────  ───────
    1       0  FWD (C→S)      50
    2   50000  BWD (S→C)     100
"""

from __future__ import annotations

import math
import os
import sys

import pytest

# Ensure python-engine root is on sys.path regardless of how pytest is invoked
_ENGINE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ENGINE_ROOT not in sys.path:
    sys.path.insert(0, _ENGINE_ROOT)

# Guard: skip entire module if scapy is not installed
pytest.importorskip("scapy")

from tests.pcap_fixtures import (  # noqa: E402
    TCP_CLIENT_IP,
    TCP_CLIENT_PORT,
    TCP_SERVER_IP,
    TCP_SERVER_PORT,
    TCP_FWD_WINDOW,
    TCP_BWD_WINDOW,
    TCP_FWD_PAYLOAD,
    TCP_BWD_PAYLOAD,
    UDP_SERVER_PORT,
    create_tcp_fixture_pcap,
    create_udp_fixture_pcap,
)

from packet_capture.capture import CaptureController  # noqa: E402
from packet_capture.flow import FEATURE_NAMES  # noqa: E402
from packet_capture.schemas import ReplayResult  # noqa: E402


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tcp_replay_result(tmp_path_factory: pytest.TempPathFactory) -> ReplayResult:
    """Replay the deterministic TCP fixture and return the ReplayResult.

    Scoped to the module so the PCAP is written and replayed only once.

    Args:
        tmp_path_factory: Pytest factory for temporary directories.

    Returns:
        ReplayResult from replaying the TCP fixture.
    """
    tmp_dir = str(tmp_path_factory.mktemp("pcap_tcp"))
    pcap_path = create_tcp_fixture_pcap(tmp_dir)
    ctrl = CaptureController()
    return ctrl.replay_pcap(pcap_path)


@pytest.fixture(scope="module")
def udp_replay_result(tmp_path_factory: pytest.TempPathFactory) -> ReplayResult:
    """Replay the deterministic UDP fixture and return the ReplayResult.

    Args:
        tmp_path_factory: Pytest factory for temporary directories.

    Returns:
        ReplayResult from replaying the UDP fixture.
    """
    tmp_dir = str(tmp_path_factory.mktemp("pcap_udp"))
    pcap_path = create_udp_fixture_pcap(tmp_dir)
    ctrl = CaptureController()
    return ctrl.replay_pcap(pcap_path)


# ---------------------------------------------------------------------------
# Helper: independent population std-dev (ddof=0)
# ---------------------------------------------------------------------------

def _pop_std(vals: list[float]) -> float:
    """Independently compute population std-dev (ddof=0).

    Args:
        vals: List of numeric values.

    Returns:
        Population std-dev, or 0.0 for fewer than 2 values.
    """
    n = len(vals)
    if n < 2:
        return 0.0
    mu = sum(vals) / n
    return math.sqrt(sum((x - mu) ** 2 for x in vals) / n)


# ===========================================================================
# ── TCP fixture tests ───────────────────────────────────────────────────────
# ===========================================================================


class TestTcpReplayMechanics:
    """Verify packet/flow counts for the TCP fixture replay."""

    def test_all_seven_packets_accepted(
        self, tcp_replay_result: ReplayResult
    ) -> None:
        """All 7 packets in the fixture must be accepted (none skipped)."""
        r = tcp_replay_result
        assert r.packets_read == 7
        assert r.packets_accepted == 7
        assert r.packets_skipped == 0
        assert r.packets_parse_error == 0

    def test_tcp_flow_completes_naturally(
        self, tcp_replay_result: ReplayResult
    ) -> None:
        """Bidirectional FIN-ACK must cause natural completion (not EOF flush)."""
        r = tcp_replay_result
        assert r.flows_naturally_completed == 1
        assert r.flows_eof_flushed == 0
        assert r.flows_total == 1

    def test_exactly_one_completed_flow(
        self, tcp_replay_result: ReplayResult
    ) -> None:
        """Exactly one FlowResult must be present in completed_flows."""
        assert len(tcp_replay_result.completed_flows) == 1

    def test_all_forty_feature_names_present(
        self, tcp_replay_result: ReplayResult
    ) -> None:
        """The flow's features dict must contain all 40 FEATURE_NAMES keys."""
        features = tcp_replay_result.completed_flows[0].features
        for name in FEATURE_NAMES:
            assert name in features, f"Missing feature: {name!r}"
        assert len(features) == 40

    def test_all_feature_values_are_finite(
        self, tcp_replay_result: ReplayResult
    ) -> None:
        """Every feature value must be a finite float (no NaN, no Inf)."""
        features = tcp_replay_result.completed_flows[0].features
        for name, value in features.items():
            assert math.isfinite(value), (
                f"Feature {name!r} has non-finite value: {value}"
            )


class TestTcpFlowFeatureValues:
    """Exact hand-calculated feature assertions for the TCP fixture flow.

    Derivations use the following known packet layout:
        FWD payloads: [0, 0, 100, 0]  (pkts 1, 3, 4, 6)
        BWD payloads: [0, 200, 0]     (pkts 2, 5, 7)
        FWD ts (us):  [0, 200000, 300000, 500000]
        BWD ts (us):  [100000, 400000, 600000]
        ALL ts (us):  [0, 100000, 200000, 300000, 400000, 500000, 600000]
    """

    def test_destination_port(self, tcp_replay_result: ReplayResult) -> None:
        """Destination Port = responder_port = 8080."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Destination Port"] == TCP_SERVER_PORT

    def test_flow_duration(self, tcp_replay_result: ReplayResult) -> None:
        """Flow Duration = last_ts - first_ts = 600000 - 0 = 600000 us."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Flow Duration"] == 600_000.0

    def test_total_fwd_packets(self, tcp_replay_result: ReplayResult) -> None:
        """Total Fwd Packets = 4 (pkts 1, 3, 4, 6 are FWD)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Total Fwd Packets"] == 4.0

    def test_total_bwd_packets(self, tcp_replay_result: ReplayResult) -> None:
        """Total Backward Packets = 3 (pkts 2, 5, 7 are BWD)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Total Backward Packets"] == 3.0

    def test_total_length_fwd(self, tcp_replay_result: ReplayResult) -> None:
        """Total Length of Fwd Packets = 0+0+100+0 = 100."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Total Length of Fwd Packets"] == 100.0

    def test_total_length_bwd(self, tcp_replay_result: ReplayResult) -> None:
        """Total Length of Bwd Packets = 0+200+0 = 200."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Total Length of Bwd Packets"] == 200.0

    def test_fwd_packet_length_max(self, tcp_replay_result: ReplayResult) -> None:
        """Fwd Packet Length Max = max([0, 0, 100, 0]) = 100."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Fwd Packet Length Max"] == 100.0

    def test_fwd_packet_length_min(self, tcp_replay_result: ReplayResult) -> None:
        """Fwd Packet Length Min = min([0, 0, 100, 0]) = 0."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Fwd Packet Length Min"] == 0.0

    def test_fwd_packet_length_mean(self, tcp_replay_result: ReplayResult) -> None:
        """Fwd Packet Length Mean = (0+0+100+0)/4 = 25.0."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Fwd Packet Length Mean"] == pytest.approx(25.0)

    def test_fwd_packet_length_std(self, tcp_replay_result: ReplayResult) -> None:
        """Fwd Packet Length Std = pop_std([0, 0, 100, 0]).

        mu = 25; sum_sq_dev = 25²+25²+75²+25² = 625+625+5625+625 = 7500
        variance = 7500/4 = 1875; std = sqrt(1875) = 25*sqrt(3)
        """
        expected = _pop_std([0.0, 0.0, 100.0, 0.0])  # ≈ 43.3013
        f = tcp_replay_result.completed_flows[0].features
        assert f["Fwd Packet Length Std"] == pytest.approx(expected, rel=1e-6)

    def test_bwd_packet_length_min(self, tcp_replay_result: ReplayResult) -> None:
        """Bwd Packet Length Min = min([0, 200, 0]) = 0."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Bwd Packet Length Min"] == 0.0

    def test_bwd_packet_length_std(self, tcp_replay_result: ReplayResult) -> None:
        """Bwd Packet Length Std = pop_std([0, 200, 0]).

        mu = 200/3; sum_sq_dev = (200/3)²+(400/3)²+(200/3)² = 26666.67/3
        std = sqrt(8888.89) ≈ 94.2809
        """
        expected = _pop_std([0.0, 200.0, 0.0])
        f = tcp_replay_result.completed_flows[0].features
        assert f["Bwd Packet Length Std"] == pytest.approx(expected, rel=1e-6)

    def test_flow_bytes_per_second(self, tcp_replay_result: ReplayResult) -> None:
        """Flow Bytes/s = (100+200) / 0.6 = 500.0."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Flow Bytes/s"] == pytest.approx(500.0, rel=1e-6)

    def test_flow_packets_per_second(self, tcp_replay_result: ReplayResult) -> None:
        """Flow Packets/s = 7 / 0.6 ≈ 11.6667."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Flow Packets/s"] == pytest.approx(7.0 / 0.6, rel=1e-6)

    def test_flow_iat_std(self, tcp_replay_result: ReplayResult) -> None:
        """Flow IAT Std = pop_std([100k]*6) = 0.0 (all gaps equal)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Flow IAT Std"] == pytest.approx(0.0, abs=1e-6)

    def test_flow_iat_min(self, tcp_replay_result: ReplayResult) -> None:
        """Flow IAT Min = 100000 us (all consecutive gaps are 100 ms)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Flow IAT Min"] == 100_000.0

    def test_fwd_iat_total(self, tcp_replay_result: ReplayResult) -> None:
        """Fwd IAT Total = fwd_ts[-1] - fwd_ts[0] = 500000 - 0 = 500000 us."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Fwd IAT Total"] == 500_000.0

    def test_fwd_iat_std(self, tcp_replay_result: ReplayResult) -> None:
        """Fwd IAT Std = pop_std([200000, 100000, 200000]).

        FWD ts: [0, 200000, 300000, 500000]
        IATs:   [200000, 100000, 200000]
        mu = 500000/3; variance = (sum_sq_dev)/3
        sum_sq_dev = (100000/3)² + (200000/3)² + (100000/3)²
                   = (10^10 + 4*10^10 + 10^10)/9 = 6*10^10/9
        variance = 6*10^10/27 = 2*10^10/9
        std = sqrt(2*10^10/9) = sqrt(2)*10^5/3 ≈ 47140.45
        """
        expected = _pop_std([200_000.0, 100_000.0, 200_000.0])
        f = tcp_replay_result.completed_flows[0].features
        assert f["Fwd IAT Std"] == pytest.approx(expected, rel=1e-6)

    def test_fwd_iat_min(self, tcp_replay_result: ReplayResult) -> None:
        """Fwd IAT Min = min([200000, 100000, 200000]) = 100000 us."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Fwd IAT Min"] == 100_000.0

    def test_bwd_iat_total(self, tcp_replay_result: ReplayResult) -> None:
        """Bwd IAT Total = bwd_ts[-1] - bwd_ts[0] = 600000 - 100000 = 500000 us."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Bwd IAT Total"] == 500_000.0

    def test_bwd_iat_std(self, tcp_replay_result: ReplayResult) -> None:
        """Bwd IAT Std = pop_std([300000, 200000]).

        BWD ts: [100000, 400000, 600000]
        IATs:   [300000, 200000]
        mu = 250000; variance = (50000²+50000²)/2 = 2500000000
        std = 50000
        """
        expected = _pop_std([300_000.0, 200_000.0])  # = 50000.0
        f = tcp_replay_result.completed_flows[0].features
        assert f["Bwd IAT Std"] == pytest.approx(expected, rel=1e-6)

    def test_bwd_iat_min(self, tcp_replay_result: ReplayResult) -> None:
        """Bwd IAT Min = min([300000, 200000]) = 200000 us."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Bwd IAT Min"] == 200_000.0

    def test_fwd_header_length(self, tcp_replay_result: ReplayResult) -> None:
        """Fwd Header Length = sum(ip_hdr + tcp_hdr) for FWD packets.

        Default Scapy TCP: IHL=5→20 bytes IP, dataofs=5→20 bytes TCP.
        4 FWD packets × (20+20) = 160.
        """
        f = tcp_replay_result.completed_flows[0].features
        assert f["Fwd Header Length"] == 160.0

    def test_bwd_header_length(self, tcp_replay_result: ReplayResult) -> None:
        """Bwd Header Length = sum(ip_hdr + tcp_hdr) for BWD packets.

        3 BWD packets × (20+20) = 120.
        """
        f = tcp_replay_result.completed_flows[0].features
        assert f["Bwd Header Length"] == 120.0

    def test_bwd_packets_per_second(self, tcp_replay_result: ReplayResult) -> None:
        """Bwd Packets/s = 3 / 0.6 = 5.0."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Bwd Packets/s"] == pytest.approx(5.0, rel=1e-6)

    def test_max_packet_length(self, tcp_replay_result: ReplayResult) -> None:
        """Max Packet Length = max(all payloads) = 200."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Max Packet Length"] == 200.0

    def test_packet_length_mean(self, tcp_replay_result: ReplayResult) -> None:
        """Packet Length Mean = (0+0+0+100+200+0+0)/7 = 300/7 ≈ 42.8571."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Packet Length Mean"] == pytest.approx(300.0 / 7.0, rel=1e-6)

    def test_packet_length_std(self, tcp_replay_result: ReplayResult) -> None:
        """Packet Length Std = pop_std([0,0,0,100,200,0,0]).

        mu = 300/7
        sum_sq_dev = 5*(300/7)² + (100-300/7)² + (200-300/7)²
                   = 5*(300/7)² + (400/7)² + (1100/7)²
                   = [5*90000 + 160000 + 1210000] / 49
                   = [450000+160000+1210000] / 49
                   = 1820000/49
        Wait: 5 zero payloads → devs = -(300/7) each (5 of them)
        Let me recount: pkts with payloads [0,0,0,100,200,0,0] → 5 zeros, 1×100, 1×200
        sum_sq_dev for zeros: 5*(300/7)²
        sum_sq_dev for 100: (100-300/7)² = (400/7)²
        sum_sq_dev for 200: (200-300/7)² = (1100/7)²
        total = [5*90000 + 160000 + 1210000] / 49 = 1820000/49
        But wait there are 7 packets not 7...actually [0,0,0,100,200,0,0] that is
        5 zeros+1×100+1×200=7 values. sum_sq_dev = 5*(300/7)² + (400/7)² + (1100/7)²
        = (5*90000+160000+1210000)/49 = (450000+160000+1210000)/49 = 1820000/49
        Hmm but earlier I computed 1910000/49. Let me recheck.
        Actually: The 7 payloads are [0, 0, 0, 100, 200, 0, 0] (pkts 1-7):
        P1(FWD,SYN)=0, P2(BWD,SYN-ACK)=0, P3(FWD,ACK)=0, P4(FWD,data)=100,
        P5(BWD,data)=200, P6(FWD,FIN)=0, P7(BWD,FIN)=0 → 5 zeros, 100, 200 ✓
        mu = 300/7; sum_sq_dev = 5*(300/7)²+(400/7)²+(1100/7)²
        = [5*90000+160000+1210000]/49 = [450000+160000+1210000]/49 = 1820000/49
        variance = (1820000/49)/7 = 1820000/343
        std = sqrt(1820000/343)
        """
        all_payloads = [0.0, 0.0, 0.0, 100.0, 200.0, 0.0, 0.0]
        expected = _pop_std(all_payloads)
        f = tcp_replay_result.completed_flows[0].features
        assert f["Packet Length Std"] == pytest.approx(expected, rel=1e-6)

    def test_fin_flag_count(self, tcp_replay_result: ReplayResult) -> None:
        """FIN Flag Count = 1 (FIN seen in pkts 6 and 7; capped at 1)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["FIN Flag Count"] == 1.0

    def test_psh_flag_count(self, tcp_replay_result: ReplayResult) -> None:
        """PSH Flag Count = 1 (PSH seen in pkts 4 and 5; capped at 1)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["PSH Flag Count"] == 1.0

    def test_ack_flag_count(self, tcp_replay_result: ReplayResult) -> None:
        """ACK Flag Count = 1 (ACK seen in pkts 2-7; capped at 1)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["ACK Flag Count"] == 1.0

    def test_urg_flag_count(self, tcp_replay_result: ReplayResult) -> None:
        """URG Flag Count = 0 (no URG flag in any packet)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["URG Flag Count"] == 0.0

    def test_down_up_ratio(self, tcp_replay_result: ReplayResult) -> None:
        """Down/Up Ratio = n_bwd / n_fwd = 3 / 4 = 0.75."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Down/Up Ratio"] == pytest.approx(0.75)

    def test_init_win_bytes_forward(self, tcp_replay_result: ReplayResult) -> None:
        """Init_Win_bytes_forward = TCP window of first FWD packet = 8192."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Init_Win_bytes_forward"] == TCP_FWD_WINDOW

    def test_init_win_bytes_backward(self, tcp_replay_result: ReplayResult) -> None:
        """Init_Win_bytes_backward = TCP window of first BWD packet = 65535."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Init_Win_bytes_backward"] == TCP_BWD_WINDOW

    def test_act_data_pkt_fwd(self, tcp_replay_result: ReplayResult) -> None:
        """act_data_pkt_fwd = FWD packets with payload >= 1 = 1 (only pkt 4)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["act_data_pkt_fwd"] == 1.0

    def test_min_seg_size_forward(self, tcp_replay_result: ReplayResult) -> None:
        """min_seg_size_forward = min(tcp_data_offset * 4) over FWD packets.

        Default Scapy TCP data offset = 5 words → 5*4 = 20 bytes.
        """
        f = tcp_replay_result.completed_flows[0].features
        assert f["min_seg_size_forward"] == 20.0

    def test_active_mean(self, tcp_replay_result: ReplayResult) -> None:
        """Active Mean = 600000 us.

        All 7 packets fall within a single burst (all gaps < 1,000,000 us).
        Burst: b_start=0, b_last=600000 → dur=600000 → active=[600000].
        """
        f = tcp_replay_result.completed_flows[0].features
        assert f["Active Mean"] == pytest.approx(600_000.0)

    def test_idle_mean(self, tcp_replay_result: ReplayResult) -> None:
        """Idle Mean = 0.0 (no gaps exceed the 1,000,000 us threshold)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Idle Mean"] == pytest.approx(0.0, abs=1e-6)

    def test_idle_std(self, tcp_replay_result: ReplayResult) -> None:
        """Idle Std = 0.0 (no idle gaps recorded)."""
        f = tcp_replay_result.completed_flows[0].features
        assert f["Idle Std"] == pytest.approx(0.0, abs=1e-6)


# ===========================================================================
# ── UDP fixture tests ───────────────────────────────────────────────────────
# ===========================================================================


class TestUdpReplayMechanics:
    """Verify packet/flow counts for the UDP fixture replay."""

    def test_both_packets_accepted(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Both UDP packets must be accepted with zero skipped or errors."""
        r = udp_replay_result
        assert r.packets_read == 2
        assert r.packets_accepted == 2
        assert r.packets_skipped == 0
        assert r.packets_parse_error == 0

    def test_udp_flow_eof_flushed(self, udp_replay_result: ReplayResult) -> None:
        """UDP has no terminal signal; the flow is flushed at EOF."""
        r = udp_replay_result
        assert r.flows_naturally_completed == 0
        assert r.flows_eof_flushed == 1
        assert r.flows_total == 1

    def test_all_forty_feature_names_present_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """The UDP flow's features dict must contain all 40 FEATURE_NAMES keys."""
        features = udp_replay_result.completed_flows[0].features
        for name in FEATURE_NAMES:
            assert name in features, f"Missing feature: {name!r}"

    def test_all_udp_feature_values_are_finite(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Every UDP feature value must be a finite float."""
        features = udp_replay_result.completed_flows[0].features
        for name, value in features.items():
            assert math.isfinite(value), (
                f"Feature {name!r} has non-finite value: {value}"
            )


class TestUdpFlowFeatureValues:
    """Exact hand-calculated feature assertions for the UDP fixture flow.

    Packet layout:
        FWD payloads: [50]   (pkt 1, C→S at t=0)
        BWD payloads: [100]  (pkt 2, S→C at t=50000)
    """

    def test_destination_port_udp(self, udp_replay_result: ReplayResult) -> None:
        """Destination Port = responder port = 53."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Destination Port"] == UDP_SERVER_PORT

    def test_flow_duration_udp(self, udp_replay_result: ReplayResult) -> None:
        """Flow Duration = 50000 - 0 = 50000 us."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Flow Duration"] == 50_000.0

    def test_total_fwd_packets_udp(self, udp_replay_result: ReplayResult) -> None:
        """Total Fwd Packets = 1."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Total Fwd Packets"] == 1.0

    def test_total_bwd_packets_udp(self, udp_replay_result: ReplayResult) -> None:
        """Total Backward Packets = 1."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Total Backward Packets"] == 1.0

    def test_total_length_fwd_udp(self, udp_replay_result: ReplayResult) -> None:
        """Total Length of Fwd Packets = 50."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Total Length of Fwd Packets"] == 50.0

    def test_total_length_bwd_udp(self, udp_replay_result: ReplayResult) -> None:
        """Total Length of Bwd Packets = 100."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Total Length of Bwd Packets"] == 100.0

    def test_fwd_packet_length_mean_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Fwd Packet Length Mean = 50 / 1 = 50.0."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Fwd Packet Length Mean"] == pytest.approx(50.0)

    def test_fwd_packet_length_std_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Fwd Packet Length Std = pop_std([50]) = 0.0 (only one packet)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Fwd Packet Length Std"] == pytest.approx(0.0, abs=1e-9)

    def test_bwd_packet_length_min_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Bwd Packet Length Min = min([100]) = 100."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Bwd Packet Length Min"] == 100.0

    def test_bwd_packet_length_std_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Bwd Packet Length Std = pop_std([100]) = 0.0 (only one packet)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Bwd Packet Length Std"] == pytest.approx(0.0, abs=1e-9)

    def test_flow_bytes_per_second_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Flow Bytes/s = (50+100) / 0.05 = 3000.0."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Flow Bytes/s"] == pytest.approx(3000.0, rel=1e-6)

    def test_flow_packets_per_second_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Flow Packets/s = 2 / 0.05 = 40.0."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Flow Packets/s"] == pytest.approx(40.0, rel=1e-6)

    def test_flow_iat_min_udp(self, udp_replay_result: ReplayResult) -> None:
        """Flow IAT Min = 50000 us (one IAT: t2 - t1 = 50000)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Flow IAT Min"] == 50_000.0

    def test_flow_iat_std_udp(self, udp_replay_result: ReplayResult) -> None:
        """Flow IAT Std = pop_std([50000]) = 0.0 (only one IAT)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Flow IAT Std"] == pytest.approx(0.0, abs=1e-9)

    def test_fwd_iat_total_udp(self, udp_replay_result: ReplayResult) -> None:
        """Fwd IAT Total = 0.0 (only one FWD packet, no IATs)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Fwd IAT Total"] == 0.0

    def test_bwd_iat_total_udp(self, udp_replay_result: ReplayResult) -> None:
        """Bwd IAT Total = 0.0 (only one BWD packet, no IATs)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Bwd IAT Total"] == 0.0

    def test_fwd_header_length_udp(self, udp_replay_result: ReplayResult) -> None:
        """Fwd Header Length = ip_hdr(20) + udp_hdr(8) = 28 for the 1 FWD packet."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Fwd Header Length"] == 28.0

    def test_bwd_header_length_udp(self, udp_replay_result: ReplayResult) -> None:
        """Bwd Header Length = ip_hdr(20) + udp_hdr(8) = 28 for the 1 BWD packet."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Bwd Header Length"] == 28.0

    def test_bwd_packets_per_second_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Bwd Packets/s = 1 / 0.05 = 20.0."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Bwd Packets/s"] == pytest.approx(20.0, rel=1e-6)

    def test_max_packet_length_udp(self, udp_replay_result: ReplayResult) -> None:
        """Max Packet Length = max([50, 100]) = 100."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Max Packet Length"] == 100.0

    def test_packet_length_mean_udp(self, udp_replay_result: ReplayResult) -> None:
        """Packet Length Mean = (50+100)/2 = 75.0."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Packet Length Mean"] == pytest.approx(75.0)

    def test_packet_length_std_udp(self, udp_replay_result: ReplayResult) -> None:
        """Packet Length Std = pop_std([50, 100]).

        mu = 75; variance = (25²+25²)/2 = 625; std = 25.0
        """
        expected = _pop_std([50.0, 100.0])  # = 25.0
        f = udp_replay_result.completed_flows[0].features
        assert f["Packet Length Std"] == pytest.approx(expected, rel=1e-6)

    def test_fin_flag_count_udp(self, udp_replay_result: ReplayResult) -> None:
        """FIN Flag Count = 0 for UDP flow."""
        f = udp_replay_result.completed_flows[0].features
        assert f["FIN Flag Count"] == 0.0

    def test_psh_flag_count_udp(self, udp_replay_result: ReplayResult) -> None:
        """PSH Flag Count = 0 for UDP flow."""
        f = udp_replay_result.completed_flows[0].features
        assert f["PSH Flag Count"] == 0.0

    def test_ack_flag_count_udp(self, udp_replay_result: ReplayResult) -> None:
        """ACK Flag Count = 0 for UDP flow."""
        f = udp_replay_result.completed_flows[0].features
        assert f["ACK Flag Count"] == 0.0

    def test_urg_flag_count_udp(self, udp_replay_result: ReplayResult) -> None:
        """URG Flag Count = 0 for UDP flow."""
        f = udp_replay_result.completed_flows[0].features
        assert f["URG Flag Count"] == 0.0

    def test_down_up_ratio_udp(self, udp_replay_result: ReplayResult) -> None:
        """Down/Up Ratio = n_bwd / n_fwd = 1 / 1 = 1.0."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Down/Up Ratio"] == pytest.approx(1.0)

    def test_init_win_bytes_forward_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Init_Win_bytes_forward = 0 for UDP (TCP-only field)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Init_Win_bytes_forward"] == 0.0

    def test_init_win_bytes_backward_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """Init_Win_bytes_backward = 0 for UDP (TCP-only field)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Init_Win_bytes_backward"] == 0.0

    def test_act_data_pkt_fwd_udp(self, udp_replay_result: ReplayResult) -> None:
        """act_data_pkt_fwd = 0 for UDP (TCP-only counter)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["act_data_pkt_fwd"] == 0.0

    def test_min_seg_size_forward_udp(
        self, udp_replay_result: ReplayResult
    ) -> None:
        """min_seg_size_forward = 0 for UDP (TCP data-offset never set)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["min_seg_size_forward"] == 0.0

    def test_active_mean_udp(self, udp_replay_result: ReplayResult) -> None:
        """Active Mean = 50000 us.

        Both packets fall in one burst (gap 50000 < 1000000 threshold).
        Burst: b_start=0, b_last=50000 → dur=50000 → active=[50000].
        """
        f = udp_replay_result.completed_flows[0].features
        assert f["Active Mean"] == pytest.approx(50_000.0)

    def test_idle_mean_udp(self, udp_replay_result: ReplayResult) -> None:
        """Idle Mean = 0.0 (no gap exceeds the 1,000,000 us threshold)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Idle Mean"] == pytest.approx(0.0, abs=1e-6)

    def test_idle_std_udp(self, udp_replay_result: ReplayResult) -> None:
        """Idle Std = 0.0 (no idle gaps recorded)."""
        f = udp_replay_result.completed_flows[0].features
        assert f["Idle Std"] == pytest.approx(0.0, abs=1e-6)
