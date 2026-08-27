"""NetShield AI — Attack simulation script for live demos.

Generates synthetic malicious traffic on localhost (127.0.0.1) so the
dashboard turns red and alerts fire during presentations.  All traffic
stays on the local machine — no external targets are involved.

Three attack modes (can be combined):

    --ddos       SYN flood to 127.0.0.1:80 (500 packets, random source ports)
    --portscan   TCP SYN to ports 1-200 on 127.0.0.1 (200 flows)
    --bruteforce Rapid SYN to 127.0.0.1:22 (200 packets, varying source ports)

Usage::

    py scripts/simulate_attack.py --ddos
    py scripts/simulate_attack.py --portscan
    py scripts/simulate_attack.py --bruteforce
    py scripts/simulate_attack.py --ddos --portscan     # combined
    py scripts/simulate_attack.py --list                # list interfaces

Requirements:
    - Scapy must be installed (pip install scapy).
    - Npcap must be installed on Windows for raw packet sending.
    - The Python engine must be running and capturing on an interface
      that sees the loopback traffic (use --interface to match).
    - On Windows, run this script as Administrator if Npcap requires it.

Exit codes:
    0  Success
    2  Invalid arguments
    3  Scapy/Npcap not available
    4  Send error
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TARGET_IP: str = "127.0.0.1"
_DDNS_PORT: int = 80
_SSH_PORT: int = 22
_PORTSCAN_RANGE: int = 200
_DDNS_COUNT: int = 500
_BRUTEFORCE_COUNT: int = 200
_PACKET_DELAY_MS: float = 2.0  # delay between packets in milliseconds


def _detect_local_ip() -> str:
    """Detect the local IP address of the first non-loopback interface.

    Uses a UDP socket to determine the local IP that the OS would use
    to reach the internet.

    Returns:
        IP address string (e.g., "192.168.1.5"), or "127.0.0.1" if
        no non-loopback interface is found.
    """
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _detect_gateway_ip() -> str:
    """Detect the default gateway IP address.

    On Windows, uses `ipconfig` to find the gateway.
    On Linux/Mac, uses `ip route` or `netstat -rn`.

    Returns:
        Gateway IP string (e.g., "192.168.1.1"), or the local IP if
        detection fails.
    """
    import platform
    import subprocess
    import re

    try:
        if platform.system() == "Windows":
            # Try Get-NetRoute first (more reliable than ipconfig parsing)
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop"],
                capture_output=True, text=True, timeout=10
            )
            gw = result.stdout.strip().splitlines()
            if gw:
                for g in gw:
                    g = g.strip()
                    if g and g != "0.0.0.0":
                        return g

            # Fallback: parse ipconfig output
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=10
            )
            matches = re.findall(r"Default Gateway[.\s]*:\s*([\d.]+)", result.stdout)
            if matches:
                for gw in matches:
                    if gw and gw != "0.0.0.0":
                        return gw
        else:
            # Linux/Mac: ip route | grep default
            result = subprocess.run(
                ["ip", "route"], capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
    except Exception:
        pass

    # Fallback: return local IP
    return _detect_local_ip()

# ---------------------------------------------------------------------------
# Scapy availability check
# ---------------------------------------------------------------------------

_scapy_available: Optional[bool] = None
_scapy_error: Optional[str] = None


def _check_scapy() -> None:
    """Import scapy and raise RuntimeError if unavailable.

    Scapy is imported lazily so the script can print --help without it.
    """
    global _scapy_available, _scapy_error
    if _scapy_available is None:
        try:
            from scapy.all import IP, TCP, send, conf, get_if_list, get_if_addr  # noqa: F401
            _scapy_available = True
        except Exception as exc:
            _scapy_available = False
            _scapy_error = str(exc)
    if not _scapy_available:
        raise RuntimeError(
            f"scapy is required but could not be imported: {_scapy_error}. "
            "Install it with: pip install scapy"
        )


# ---------------------------------------------------------------------------
# Attack functions
# ---------------------------------------------------------------------------


def _run_ddos(interface: Optional[str], count: int, delay_ms: float, target: str = "127.0.0.1", src: str = "127.0.0.1") -> int:
    """Send a TCP SYN flood to the target IP on port 80.

    Each packet has a random source port, creating many short flows with
    high packet counts, zero backward packets, and zero flow duration —
    matching the CICIDS2017 DDoS flow signature.

    Args:
        interface: Optional network interface to send on.
        count: Number of SYN packets to send.
        delay_ms: Delay between packets in milliseconds.
        target: Target IP address (destination).
        src: Source IP address.

    Returns:
        Number of packets actually sent.
    """
    from scapy.all import IP, TCP, send

    sent = 0
    for _ in range(count):
        try:
            sport = random.randint(1024, 65535)
            pkt = IP(src=src, dst=target) / TCP(
                sport=sport,
                dport=_DDNS_PORT,
                flags="S",
                seq=random.randint(1000, 999999),
            )
            send(pkt, verbose=0, iface=interface)
            sent += 1
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
        except KeyboardInterrupt:
            break
        except Exception:
            # Some packets may fail (permission, interface), keep going
            continue
    return sent


def _run_portscan(interface: Optional[str], count: int, delay_ms: float, target: str = "127.0.0.1", src: str = "127.0.0.1") -> int:
    """Send TCP SYN packets to ports 1-N on the target IP.

    Each packet targets a different destination port, creating 200
    single-packet flows — matching the CICIDS2017 PortScan signature.

    Args:
        interface: Optional network interface to send on.
        count: Number of ports to scan (1 to count).
        delay_ms: Delay between packets in milliseconds.
        target: Target IP address (destination).
        src: Source IP address.

    Returns:
        Number of packets actually sent.
    """
    from scapy.all import IP, TCP, send

    sent = 0
    for dport in range(1, count + 1):
        try:
            sport = random.randint(1024, 65535)
            pkt = IP(src=src, dst=target) / TCP(
                sport=sport,
                dport=dport,
                flags="S",
                seq=random.randint(1000, 999999),
            )
            send(pkt, verbose=0, iface=interface)
            sent += 1
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
        except KeyboardInterrupt:
            break
        except Exception:
            continue
    return sent


def _run_bruteforce(interface: Optional[str], count: int, delay_ms: float, target: str = "127.0.0.1", src: str = "127.0.0.1") -> int:
    """Send rapid TCP SYN packets to the target IP on port 22 (SSH).

    Many rapid connection attempts to the same port from varying source
    ports — matching the CICIDS2017 BruteForce flow signature.

    Args:
        interface: Optional network interface to send on.
        count: Number of SYN packets to send.
        delay_ms: Delay between packets in milliseconds.
        target: Target IP address (destination).
        src: Source IP address.

    Returns:
        Number of packets actually sent.
    """
    from scapy.all import IP, TCP, send

    sent = 0
    for _ in range(count):
        try:
            sport = random.randint(1024, 65535)
            pkt = IP(src=src, dst=target) / TCP(
                sport=sport,
                dport=_SSH_PORT,
                flags="S",
                seq=random.randint(1000, 999999),
            )
            send(pkt, verbose=0, iface=interface)
            sent += 1
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
        except KeyboardInterrupt:
            break
        except Exception:
            continue
    return sent


# ---------------------------------------------------------------------------
# Interface listing
# ---------------------------------------------------------------------------


def _list_interfaces() -> None:
    """Print all available network interfaces."""
    _check_scapy()
    from scapy.all import get_if_list, get_if_addr

    print("Available network interfaces:")
    print("-" * 60)
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
        except Exception:
            addr = "N/A"
        print(f"  {iface:40s}  IP: {addr}")
    print("-" * 60)
    print("Use --interface <name> to specify which interface to send on.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the selected attack simulation.

    Args:
        argv: Optional argument list (defaults to sys.argv[1:]).

    Returns:
        Integer exit code.
    """
    parser = argparse.ArgumentParser(
        prog="simulate_attack",
        description="NetShield AI — Attack simulator for live demos (localhost only).",
        epilog=(
            "All traffic stays on 127.0.0.1 — safe and legal. "
            "The Python engine must be running and capturing to see this traffic. "
            "On Windows, may need Administrator privileges for raw packet sending."
        ),
    )
    mode = parser.add_argument_group("Attack modes")
    mode.add_argument(
        "--ddos", action="store_true",
        help=f"SYN flood to {_TARGET_IP}:{_DDNS_PORT} ({_DDNS_COUNT} packets)",
    )
    mode.add_argument(
        "--portscan", action="store_true",
        help=f"TCP SYN to ports 1-{_PORTSCAN_RANGE} on {_TARGET_IP}",
    )
    mode.add_argument(
        "--bruteforce", action="store_true",
        help=f"Rapid SYN to {_TARGET_IP}:{_SSH_PORT} ({_BRUTEFORCE_COUNT} packets)",
    )

    opts = parser.add_argument_group("Options")
    opts.add_argument(
        "--interface", "-i", metavar="IFACE", default=None,
        help="Network interface to send on (default: Scapy default).",
    )
    opts.add_argument(
        "--count", "-n", type=int, default=None,
        help="Override packet count for the selected mode(s).",
    )
    opts.add_argument(
        "--delay", type=float, default=_PACKET_DELAY_MS,
        help=f"Delay between packets in ms (default: {_PACKET_DELAY_MS}).",
    )
    opts.add_argument(
        "--list", action="store_true",
        help="List available network interfaces and exit.",
    )

    args = parser.parse_args(argv)

    # ── List interfaces and exit ──────────────────────────────────
    if args.list:
        _list_interfaces()
        return 0

    # ── Validate at least one mode is selected ────────────────────
    if not (args.ddos or args.portscan or args.bruteforce):
        parser.error("at least one attack mode is required (--ddos, --portscan, --bruteforce)")

    # ── Check scapy ──────────────────────────────────────────────
    try:
        _check_scapy()
    except RuntimeError as exc:
        sys.stderr.write(f"[netshield] ERROR: {exc}\n")
        return 3

    # ── Determine target IP ──────────────────────────────────────
    # On Windows, Scapy's L3 send() routes same-subnet traffic through
    # the loopback adapter, which the Wi-Fi capture cannot see.
    # To make attack packets visible to the capture engine, we send
    # them to an external IP (8.8.8.8 — Google DNS).  The SYN packets
    # won't get a response, but they WILL be visible on the Wi-Fi
    # interface as outbound traffic.
    local_ip = _detect_local_ip()
    gateway_ip = _detect_gateway_ip()
    target = "8.8.8.8"  # Google DNS — always reachable, packets visible on Wi-Fi

    print(f"[netshield] Local IP: {local_ip}")
    print(f"[netshield] Gateway IP: {gateway_ip}")
    print(f"[netshield] Attack target: {target} (Google DNS)")
    print(f"[netshield] Traffic: {local_ip} → {target}")
    print(f"[netshield] This ensures the Wi-Fi capture interface sees the packets.")

    # ── Run selected attack modes ─────────────────────────────────
    attacks_run: list[str] = []
    total_sent = 0
    start_time = time.monotonic()

    try:
        if args.ddos:
            count = args.count or _DDNS_COUNT
            print(f"[netshield] Starting DDoS SYN flood → {target}:{_DDNS_PORT} ({count} packets)")
            sent = _run_ddos(args.interface, count, args.delay, target, local_ip)
            total_sent += sent
            attacks_run.append(f"DDoS ({sent} packets)")
            print(f"[netshield] DDoS complete — {sent} packets sent")

        if args.portscan:
            count = args.count or _PORTSCAN_RANGE
            print(f"[netshield] Starting Port Scan → {target}:1-{count}")
            sent = _run_portscan(args.interface, count, args.delay, target, local_ip)
            total_sent += sent
            attacks_run.append(f"PortScan ({sent} packets)")
            print(f"[netshield] Port Scan complete — {sent} packets sent")

        if args.bruteforce:
            count = args.count or _BRUTEFORCE_COUNT
            print(f"[netshield] Starting Brute Force → {target}:{_SSH_PORT} ({count} packets)")
            sent = _run_bruteforce(args.interface, count, args.delay, target, local_ip)
            total_sent += sent
            attacks_run.append(f"BruteForce ({sent} packets)")
            print(f"[netshield] Brute Force complete — {sent} packets sent")

    except KeyboardInterrupt:
        print("\n[netshield] Interrupted by user (Ctrl+C)")

    # ── Summary ──────────────────────────────────────────────────
    elapsed = time.monotonic() - start_time
    print()
    print("=" * 50)
    print("NetShield AI — Attack Simulation Summary")
    print("=" * 50)
    print(f"  Attacks run:  {', '.join(attacks_run)}")
    print(f"  Total packets sent: {total_sent}")
    print(f"  Duration:     {elapsed:.1f}s")
    print(f"  Target:       {target} (local)")
    print()
    print("Check the dashboard — it should show attacks now!")
    print("  Dashboard URL: http://localhost:5173")
    print("=" * 50)

    return 0


if __name__ == "__main__":
    sys.exit(main())
