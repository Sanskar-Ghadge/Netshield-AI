"""Focused tests for the deterministic PCAP replay mechanics (Stage 4.5.3).

These tests verify that ``CaptureController.replay_pcap``:
- Processes PCAPs to EOF without background threads.
- Returns accurate ``ReplayResult`` statistics.
- Handles TCP flows that complete naturally (RST).
- Handles flows that are still active at EOF (flushed).
- Handles UDP and ICMP flows.
- Handles empty PCAPs (zero packets).
- Handles missing files, directories, and corrupt files.
- Produces deterministic ordering of EOF-flushed flows.

The full hand-calculated TCP/UDP prediction integration suite is reserved
for a later stage; these tests focus purely on replay mechanics.
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile

import pytest

# Ensure the python-engine root is on sys.path regardless of how pytest is invoked
_ENGINE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ENGINE_ROOT not in sys.path:
    sys.path.insert(0, _ENGINE_ROOT)

from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap  # type: ignore[import]

from packet_capture.capture import CaptureController
from packet_capture.schemas import FlowState, ReplayResult


# ---------------------------------------------------------------------------
# Helper: build a small PCAP in a temp file and return the path
# ---------------------------------------------------------------------------

def _write_pcap(packets: list, tmp_path: str) -> str:
    """Write a list of Scapy packets to a ``.pcap`` file.

    Args:
        packets: List of Scapy packet objects.
        tmp_path: Directory path for the temp file.

    Returns:
        Absolute path to the written ``.pcap`` file.
    """
    pcap_path = os.path.join(tmp_path, "test_replay.pcap")
    wrpcap(pcap_path, packets)
    return pcap_path


# ---------------------------------------------------------------------------
# Basic replay tests
# ---------------------------------------------------------------------------

class TestReplayBasic:
    """Basic replay mechanics: packet counting, flow collection."""

    def test_single_tcp_rst_flow_completes_naturally(self, tmp_path: str) -> None:
        """A single TCP packet with RST flag completes naturally during ingest.

        Expected: 1 packet read, 1 accepted, 0 skipped, 0 parse errors,
        1 naturally completed, 0 EOF flushed, 1 total flow.
        """
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=12345, dport=80, flags="R"
        )
        pcap_path = _write_pcap([pkt], str(tmp_path))

        ctrl = CaptureController()
        result = ctrl.replay_pcap(pcap_path)

        assert isinstance(result, ReplayResult)
        assert result.packets_read == 1
        assert result.packets_accepted == 1
        assert result.packets_skipped == 0
        assert result.packets_parse_error == 0
        assert result.flows_naturally_completed == 1
        assert result.flows_eof_flushed == 0
        assert result.flows_total == 1
        assert len(result.completed_flows) == 1
        assert result.completed_flows[0].state == FlowState.COMPLETED

    def test_two_packets_one_flow_eof_flushed(self, tmp_path: str) -> None:
        """Two TCP data packets without RST/FIN: flow is flushed at EOF.

        Expected: 2 packets read, 2 accepted, 1 EOF-flushed flow.
        """
        pkt1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=12345, dport=80, flags="PA"
        )
        pkt2 = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(
            sport=80, dport=12345, flags="PA"
        )
        pcap_path = _write_pcap([pkt1, pkt2], str(tmp_path))

        ctrl = CaptureController()
        result = ctrl.replay_pcap(pcap_path)

        assert result.packets_read == 2
        assert result.packets_accepted == 2
        assert result.packets_skipped == 0
        assert result.flows_naturally_completed == 0
        assert result.flows_eof_flushed == 1
        assert result.flows_total == 1
        assert result.completed_flows[0].state == FlowState.COMPLETED

    def test_mixed_natural_and_eof_flows(self, tmp_path: str) -> None:
        """One RST flow (naturally completed) + one data-only flow (EOF flushed).

        Expected: 2 flows total, 1 naturally completed, 1 EOF flushed.
        """
        # Flow A: RST → completes naturally
        pkt_a = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=12345, dport=80, flags="R"
        )
        # Flow B: SYN → stays active at EOF
        pkt_b = Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / TCP(
            sport=54321, dport=443, flags="S"
        )
        pcap_path = _write_pcap([pkt_a, pkt_b], str(tmp_path))

        ctrl = CaptureController()
        result = ctrl.replay_pcap(pcap_path)

        assert result.packets_read == 2
        assert result.packets_accepted == 2
        assert result.flows_naturally_completed == 1
        assert result.flows_eof_flushed == 1
        assert result.flows_total == 2

    def test_non_ip_packets_are_skipped(self, tmp_path: str) -> None:
        """ARP-only PCAP: 0 accepted, all skipped, 0 flows.

        We use a bare Ether frame (no IP layer) which Scapy will
        classify as non-IP.
        """
        pkt = Ether(type=0x0806)  # ARP type, no ARP layer defined
        pcap_path = _write_pcap([pkt], str(tmp_path))

        ctrl = CaptureController()
        result = ctrl.replay_pcap(pcap_path)

        assert result.packets_read == 1
        assert result.packets_accepted == 0
        assert result.packets_skipped == 1
        assert result.flows_total == 0

    def test_empty_pcap_produces_zero_stats(self, tmp_path: str) -> None:
        """An empty PCAP file yields all-zero statistics.

        Expected: packets_read=0, flows_total=0.
        """
        pcap_path = _write_pcap([], str(tmp_path))

        ctrl = CaptureController()
        result = ctrl.replay_pcap(pcap_path)

        assert result.packets_read == 0
        assert result.packets_accepted == 0
        assert result.packets_skipped == 0
        assert result.packets_parse_error == 0
        assert result.flows_naturally_completed == 0
        assert result.flows_eof_flushed == 0
        assert result.flows_total == 0
        assert result.completed_flows == []

    def test_udp_flow_eof_flushed(self, tmp_path: str) -> None:
        """A UDP flow has no terminal flags; it is always flushed at EOF.

        Expected: 1 packet accepted, 1 EOF-flushed flow.
        """
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(
            sport=53, dport=50000
        )
        pcap_path = _write_pcap([pkt], str(tmp_path))

        ctrl = CaptureController()
        result = ctrl.replay_pcap(pcap_path)

        assert result.packets_read == 1
        assert result.packets_accepted == 1
        assert result.flows_eof_flushed == 1
        assert result.flows_total == 1

    def test_icmp_flow_eof_flushed(self, tmp_path: str) -> None:
        """An ICMP flow is always flushed at EOF.

        Expected: 1 packet accepted, 1 EOF-flushed flow.
        """
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        pcap_path = _write_pcap([pkt], str(tmp_path))

        ctrl = CaptureController()
        result = ctrl.replay_pcap(pcap_path)

        assert result.packets_read == 1
        assert result.packets_accepted == 1
        assert result.flows_eof_flushed == 1
        assert result.flows_total == 1

    def test_multiple_eof_flushed_flows_are_sorted(self, tmp_path: str) -> None:
        """Multiple EOF-flushed flows are returned in deterministic sorted order.

        We create 3 flows that will all be flushed at EOF and verify they
        are sorted by (ip_a, port_a, ip_b, port_b, protocol).
        """
        packets = []
        # Flow C (large IP)
        packets.append(
            Ether() / IP(src="10.0.0.9", dst="10.0.0.10") / TCP(sport=40000, dport=80, flags="S")
        )
        # Flow A (small IP)
        packets.append(
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=10000, dport=80, flags="S")
        )
        # Flow B (mid IP)
        packets.append(
            Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / TCP(sport=20000, dport=80, flags="S")
        )
        pcap_path = _write_pcap(packets, str(tmp_path))

        ctrl = CaptureController()
        result = ctrl.replay_pcap(pcap_path)

        assert result.flows_eof_flushed == 3
        # Verify sorted order: A (10.0.0.1), B (10.0.0.5), C (10.0.0.9)
        keys = [(fr.key.ip_a, fr.key.port_a) for fr in result.completed_flows]
        assert keys == sorted(keys)

    def test_bidirectional_tcp_fin_completes_naturally(self, tmp_path: str) -> None:
        """TCP FIN in both directions completes the flow naturally during ingest.

        Expected: 1 naturally completed flow, 0 EOF flushed.
        """
        # SYN →
        p1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")
        # SYN-ACK ←
        p2 = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345, flags="SA")
        # ACK →
        p3 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="A")
        # FIN-ACK →
        p4 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="FA")
        # FIN-ACK ←
        p5 = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345, flags="FA")
        pcap_path = _write_pcap([p1, p2, p3, p4, p5], str(tmp_path))

        ctrl = CaptureController()
        result = ctrl.replay_pcap(pcap_path)

        assert result.packets_accepted == 5
        assert result.flows_naturally_completed == 1
        assert result.flows_eof_flushed == 0
        assert result.flows_total == 1


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------

class TestReplayErrors:
    """Error handling: missing files, directories, corrupt files."""

    def test_missing_file_raises_filenotfound(self, tmp_path: str) -> None:
        """Non-existent file path raises ``FileNotFoundError``."""
        ctrl = CaptureController()
        with pytest.raises(FileNotFoundError, match="PCAP file not found"):
            ctrl.replay_pcap(os.path.join(str(tmp_path), "nonexistent.pcap"))

    def test_directory_raises_valueerror(self, tmp_path: str) -> None:
        """A directory path raises ``ValueError``."""
        ctrl = CaptureController()
        with pytest.raises(ValueError, match="directory"):
            ctrl.replay_pcap(str(tmp_path))

    def test_corrupt_file_raises_exception(self, tmp_path: str) -> None:
        """A file with invalid PCAP content raises an exception.

        We write random bytes to a file and expect Scapy to fail.
        """
        corrupt_path = os.path.join(str(tmp_path), "corrupt.pcap")
        with open(corrupt_path, "wb") as f:
            f.write(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" * 100)

        ctrl = CaptureController()
        with pytest.raises(Exception):
            ctrl.replay_pcap(corrupt_path)


# ---------------------------------------------------------------------------
# Isolation test
# ---------------------------------------------------------------------------

class TestReplayIsolation:
    """Verify that ``replay_pcap`` does not affect the live flow table."""

    def test_replay_does_not_pollute_live_table(self, tmp_path: str) -> None:
        """``replay_pcap`` uses a private FlowTable, not the controller's.

        After replay, the controller's ``completed_flows`` queue should
        be empty (replay results are in ``ReplayResult.completed_flows``).
        """
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=12345, dport=80, flags="R"
        )
        pcap_path = _write_pcap([pkt], str(tmp_path))

        ctrl = CaptureController()
        ctrl.replay_pcap(pcap_path)

        # The live queue should be empty
        assert ctrl.completed_flows.empty()

    def test_replay_is_deterministic_across_runs(self, tmp_path: str) -> None:
        """Running ``replay_pcap`` twice produces identical results."""
        packets = [
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="PA"),
            Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=54321, dport=443, flags="PA"),
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="R"),
        ]
        pcap_path = _write_pcap(packets, str(tmp_path))

        ctrl = CaptureController()
        result1 = ctrl.replay_pcap(pcap_path)
        result2 = ctrl.replay_pcap(pcap_path)

        assert result1.packets_read == result2.packets_read
        assert result1.packets_accepted == result2.packets_accepted
        assert result1.flows_naturally_completed == result2.flows_naturally_completed
        assert result1.flows_eof_flushed == result2.flows_eof_flushed
        assert result1.flows_total == result2.flows_total
        assert len(result1.completed_flows) == len(result2.completed_flows)

        # Compare flow keys in order
        keys1 = [r.key for r in result1.completed_flows]
        keys2 = [r.key for r in result2.completed_flows]
        assert keys1 == keys2
