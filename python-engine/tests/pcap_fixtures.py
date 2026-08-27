"""Deterministic PCAP test fixtures generated with Scapy.

This module provides functions to create deterministic TCP and UDP PCAP
files with known packet layouts, payloads, TCP windows, and timestamps
for use in integration tests.  All fixtures are written to disk and read
back through Scapy's ``PcapReader`` to ensure end-to-end fidelity — they
are never passed directly as in-memory packet lists.

TCP fixture layout (7 packets, all timestamps in microseconds):
    ┌────┬───────────┬───────────────────┬──────────┬─────────┬──────────┐
    │ # │ t (us)    │ src → dst         │ flags    │ payload │ window   │
    ├────┼───────────┼───────────────────┼──────────┼─────────┼──────────┤
    │  1 │         0 │ client → server   │ SYN      │       0 │    8192  │
    │  2 │    100000 │ server → client   │ SYN-ACK  │       0 │   65535  │
    │  3 │    200000 │ client → server   │ ACK      │       0 │    8192  │
    │  4 │    300000 │ client → server   │ PSH-ACK  │     100 │    8192  │
    │  5 │    400000 │ server → client   │ PSH-ACK  │     200 │   65535  │
    │  6 │    500000 │ client → server   │ FIN-ACK  │       0 │    8192  │
    │  7 │    600000 │ server → client   │ FIN-ACK  │       0 │   65535  │
    └────┴───────────┴───────────────────┴──────────┴─────────┴──────────┘

UDP fixture layout (2 packets):
    ┌────┬───────────┬───────────────────┬─────────┐
    │ # │ t (us)    │ src → dst         │ payload │
    ├────┼───────────┼───────────────────┼─────────┤
    │  1 │         0 │ client → server   │      50 │
    │  2 │    50000  │ server → client   │     100 │
    └────┴───────────┴───────────────────┴─────────┘
"""

from __future__ import annotations

import os

import pytest

# Guard: skip every test that imports this module if scapy is unavailable.
pytest.importorskip("scapy")

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # type: ignore[import]

# ---------------------------------------------------------------------------
# TCP fixture constants
# ---------------------------------------------------------------------------

TCP_CLIENT_IP: str = "10.10.0.1"
TCP_SERVER_IP: str = "10.10.0.2"
TCP_CLIENT_PORT: int = 51000
TCP_SERVER_PORT: int = 8080
TCP_FWD_WINDOW: int = 8192
TCP_BWD_WINDOW: int = 65535
TCP_FWD_PAYLOAD: int = 100
TCP_BWD_PAYLOAD: int = 200
TCP_TIMESTAMPS_US: tuple[int, ...] = (
    0, 100_000, 200_000, 300_000, 400_000, 500_000, 600_000,
)
TCP_PACKET_COUNT: int = 7

# ---------------------------------------------------------------------------
# UDP fixture constants
# ---------------------------------------------------------------------------

UDP_CLIENT_IP: str = "10.20.0.1"
UDP_SERVER_IP: str = "10.20.0.2"
UDP_CLIENT_PORT: int = 53000
UDP_SERVER_PORT: int = 53
UDP_REQ_PAYLOAD: int = 50
UDP_RESP_PAYLOAD: int = 100
UDP_TIMESTAMPS_US: tuple[int, ...] = (0, 50_000)
UDP_PACKET_COUNT: int = 2


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _set_time(pkt: object, ts_us: int) -> None:
    """Set a Scapy packet's timestamp from microseconds.

    Args:
        pkt: Scapy packet object (mutated in place).
        ts_us: Timestamp in microseconds since epoch.
    """
    pkt.time = ts_us / 1_000_000.0  # Scapy uses seconds (float)


def create_tcp_fixture_pcap(
    output_dir: str,
    filename: str = "tcp_fixture.pcap",
) -> str:
    """Create a deterministic TCP PCAP fixture on disk and return its path.

    The fixture contains a complete TCP connection:
    SYN → SYN-ACK → ACK → FWD data → BWD data → FWD FIN-ACK → BWD FIN-ACK
    with fixed timestamps, explicit TCP windows, and explicit payloads.

    Args:
        output_dir: Directory in which to write the PCAP file.
        filename: Name of the PCAP file (default ``tcp_fixture.pcap``).

    Returns:
        Absolute path to the written ``.pcap`` file.
    """
    client = TCP_CLIENT_IP
    server = TCP_SERVER_IP
    cport = TCP_CLIENT_PORT
    sport = TCP_SERVER_PORT
    fwd_win = TCP_FWD_WINDOW
    bwd_win = TCP_BWD_WINDOW

    packets = []

    # Packet 1 (t=0): SYN  client → server
    p1 = Ether() / IP(src=client, dst=server) / TCP(
        sport=cport, dport=sport, flags="S", window=fwd_win
    )
    _set_time(p1, 0)
    packets.append(p1)

    # Packet 2 (t=100000): SYN-ACK  server → client
    p2 = Ether() / IP(src=server, dst=client) / TCP(
        sport=sport, dport=cport, flags="SA", window=bwd_win
    )
    _set_time(p2, 100_000)
    packets.append(p2)

    # Packet 3 (t=200000): ACK  client → server
    p3 = Ether() / IP(src=client, dst=server) / TCP(
        sport=cport, dport=sport, flags="A", window=fwd_win
    )
    _set_time(p3, 200_000)
    packets.append(p3)

    # Packet 4 (t=300000): PSH-ACK data  client → server  (100-byte payload)
    p4 = Ether() / IP(src=client, dst=server) / TCP(
        sport=cport, dport=sport, flags="PA", window=fwd_win
    ) / Raw(load=b"A" * TCP_FWD_PAYLOAD)
    _set_time(p4, 300_000)
    packets.append(p4)

    # Packet 5 (t=400000): PSH-ACK data  server → client  (200-byte payload)
    p5 = Ether() / IP(src=server, dst=client) / TCP(
        sport=sport, dport=cport, flags="PA", window=bwd_win
    ) / Raw(load=b"B" * TCP_BWD_PAYLOAD)
    _set_time(p5, 400_000)
    packets.append(p5)

    # Packet 6 (t=500000): FIN-ACK  client → server
    p6 = Ether() / IP(src=client, dst=server) / TCP(
        sport=cport, dport=sport, flags="FA", window=fwd_win
    )
    _set_time(p6, 500_000)
    packets.append(p6)

    # Packet 7 (t=600000): FIN-ACK  server → client
    p7 = Ether() / IP(src=server, dst=client) / TCP(
        sport=sport, dport=cport, flags="FA", window=bwd_win
    )
    _set_time(p7, 600_000)
    packets.append(p7)

    pcap_path = os.path.join(output_dir, filename)
    wrpcap(pcap_path, packets)
    return pcap_path


def create_udp_fixture_pcap(
    output_dir: str,
    filename: str = "udp_fixture.pcap",
) -> str:
    """Create a deterministic UDP PCAP fixture on disk and return its path.

    The fixture contains one DNS-style request and one response:
    client → server (50-byte payload), server → client (100-byte payload).

    Args:
        output_dir: Directory in which to write the PCAP file.
        filename: Name of the PCAP file (default ``udp_fixture.pcap``).

    Returns:
        Absolute path to the written ``.pcap`` file.
    """
    client = UDP_CLIENT_IP
    server = UDP_SERVER_IP
    cport = UDP_CLIENT_PORT
    sport = UDP_SERVER_PORT

    packets = []

    # Packet 1 (t=0): request  client → server  (50-byte payload)
    p1 = Ether() / IP(src=client, dst=server) / UDP(
        sport=cport, dport=sport
    ) / Raw(load=b"Q" * UDP_REQ_PAYLOAD)
    _set_time(p1, 0)
    packets.append(p1)

    # Packet 2 (t=50000): response  server → client  (100-byte payload)
    p2 = Ether() / IP(src=server, dst=client) / UDP(
        sport=sport, dport=cport
    ) / Raw(load=b"R" * UDP_RESP_PAYLOAD)
    _set_time(p2, 50_000)
    packets.append(p2)

    pcap_path = os.path.join(output_dir, filename)
    wrpcap(pcap_path, packets)
    return pcap_path
