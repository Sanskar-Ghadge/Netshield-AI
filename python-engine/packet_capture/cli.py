"""Command-line interface for NetShield AI Phase 4 packet capture and prediction.

Two subcommands:
    pcap    Analyse a saved PCAP file deterministically and print JSON results.
    live    Capture live traffic from a network interface and print JSON Lines.

Exit codes:
    0  Success (may have zero flows if no IP traffic).
    2  Invalid arguments.
    3  Input file problem (missing, unreadable, corrupt).
    4  Model artifact problem (missing or incompatible).
    5  Capture dependency / permission problem.
    6  Runtime processing failure.

Example usage::

    py -m packet_capture pcap --file traffic.pcap
    py -m packet_capture pcap --file traffic.pcap --output results.jsonl
    py -m packet_capture live --interface "Wi-Fi" --duration 30
    py -m packet_capture live --interface eth0 --bpf "tcp port 80"
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional, TextIO

_ENGINE_ROOT = Path(__file__).resolve().parents[1]
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_BAD_ARGS = 2
EXIT_FILE_ERROR = 3
EXIT_ARTIFACT_ERROR = 4
EXIT_CAPTURE_ERROR = 5
EXIT_RUNTIME_ERROR = 6


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _emit(obj: dict[str, Any], out: TextIO, *, pretty: bool = False) -> None:
    """Write one JSON object to *out*, followed by a newline.

    Args:
        obj: JSON-serializable dictionary.
        out: Output stream.
        pretty: If True, emit indented JSON; otherwise emit compact JSONL.
    """
    if pretty:
        out.write(json.dumps(obj, indent=2))
        out.write("\n")
    else:
        out.write(json.dumps(obj, separators=(",", ":")))
        out.write("\n")
    out.flush()


def _err(msg: str) -> None:
    """Write an error message to stderr."""
    sys.stderr.write(f"[netshield] ERROR: {msg}\n")
    sys.stderr.flush()


def _warn(msg: str) -> None:
    """Write a warning message to stderr."""
    sys.stderr.write(f"[netshield] WARN:  {msg}\n")
    sys.stderr.flush()


def _info(msg: str) -> None:
    """Write an informational message to stderr."""
    sys.stderr.write(f"[netshield] INFO:  {msg}\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Shared: load predictor and adapter
# ---------------------------------------------------------------------------


def _load_pipeline(
    model: Optional[str],
    preprocessor: Optional[str],
    encoder: Optional[str],
    metadata: Optional[str],
    quiet: bool,
) -> "tuple[Any, Any]":
    """Load IntrusionPredictor and FlowPredictionAdapter.

    Args:
        model: Optional path override for the XGBoost model.
        preprocessor: Optional path override for the preprocessor.
        encoder: Optional path override for the label encoder.
        metadata: Optional path override for the JSON metadata.
        quiet: Suppress informational messages if True.

    Returns:
        Tuple of (IntrusionPredictor, FlowPredictionAdapter).

    Raises:
        SystemExit: With EXIT_ARTIFACT_ERROR on any artifact problem.
    """
    from prediction.flow_adapter import FlowPredictionAdapter
    from prediction.predict import ArtifactPaths, IntrusionPredictor

    try:
        paths = ArtifactPaths(
            model=Path(model) if model else None,
            preprocessor=Path(preprocessor) if preprocessor else None,
            encoder=Path(encoder) if encoder else None,
            metadata=Path(metadata) if metadata else None,
        )
        paths.validate()
        predictor = IntrusionPredictor(paths)
        adapter = FlowPredictionAdapter(predictor)
        if not quiet:
            _info(f"Model loaded: {paths.model.name}")
        return predictor, adapter
    except FileNotFoundError as exc:
        _err(f"Artifact not found: {exc}")
        sys.exit(EXIT_ARTIFACT_ERROR)
    except ValueError as exc:
        _err(f"Artifact incompatible: {exc}")
        sys.exit(EXIT_ARTIFACT_ERROR)
    except Exception as exc:  # noqa: BLE001
        _err(f"Failed to load model: {exc}")
        sys.exit(EXIT_ARTIFACT_ERROR)


# ---------------------------------------------------------------------------
# pcap subcommand
# ---------------------------------------------------------------------------


def cmd_pcap(args: argparse.Namespace, out: TextIO) -> int:
    """Analyse a PCAP file and emit one JSON object per predicted flow.

    Args:
        args: Parsed CLI arguments.
        out: Output stream for JSON Lines.

    Returns:
        Exit code integer.
    """
    pcap_path: str = args.file

    # Validate input file
    if not Path(pcap_path).exists():
        _err(f"File not found: {pcap_path}")
        return EXIT_FILE_ERROR
    if not Path(pcap_path).is_file():
        _err(f"Not a file: {pcap_path}")
        return EXIT_FILE_ERROR

    # Load model
    _, adapter = _load_pipeline(
        args.model, args.preprocessor, args.encoder, args.metadata, args.quiet
    )

    # Replay
    from packet_capture.capture import CaptureController

    try:
        ctrl = CaptureController()
        if not args.quiet:
            _info(f"Replaying PCAP: {pcap_path}")
        replay = ctrl.replay_pcap(pcap_path)
    except FileNotFoundError as exc:
        _err(f"Cannot open PCAP: {exc}")
        return EXIT_FILE_ERROR
    except ValueError as exc:
        _err(f"Invalid PCAP path: {exc}")
        return EXIT_FILE_ERROR
    except Exception as exc:  # noqa: BLE001
        _err(f"PCAP replay error: {exc}")
        return EXIT_RUNTIME_ERROR

    if not args.quiet:
        _info(
            f"Packets: {replay.packets_read} read, "
            f"{replay.packets_accepted} accepted, "
            f"{replay.packets_skipped} skipped, "
            f"{replay.packets_parse_error} errors"
        )
        _info(
            f"Flows: {replay.flows_naturally_completed} natural, "
            f"{replay.flows_eof_flushed} EOF-flushed, "
            f"{replay.flows_total} total"
        )

    # Predict and emit
    n_emitted = 0
    pretty: bool = getattr(args, "pretty", False)
    for flow in replay.completed_flows:
        if args.max_flows is not None and n_emitted >= args.max_flows:
            break
        try:
            result = adapter.predict(flow)
            row = result.to_dict()
            if not args.all_probs:
                row.pop("class_probabilities", None)
            _emit(row, out, pretty=pretty)
            n_emitted += 1
        except Exception as exc:  # noqa: BLE001
            _warn(f"Prediction error for flow {flow.key}: {exc}")

    if not args.quiet:
        _info(f"Emitted {n_emitted} predictions")

    return EXIT_OK


# ---------------------------------------------------------------------------
# live subcommand
# ---------------------------------------------------------------------------


def cmd_live(args: argparse.Namespace, out: TextIO) -> int:
    """Capture live traffic and emit predictions as JSONL.

    Args:
        args: Parsed CLI arguments.
        out: Output stream for JSON Lines.

    Returns:
        Exit code integer.
    """
    # Check scapy + live-capture availability early
    try:
        import scapy.all  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        _err(
            f"Scapy is not available or could not load capture drivers: {exc}\n"
            "On Windows, install Npcap from https://npcap.com/ and run as administrator."
        )
        return EXIT_CAPTURE_ERROR

    # Load model
    _, adapter = _load_pipeline(
        args.model, args.preprocessor, args.encoder, args.metadata, args.quiet
    )

    from packet_capture.capture import CaptureController
    from packet_capture.sources import LiveCaptureSource

    iface: Optional[str] = getattr(args, "interface", None)
    bpf: Optional[str] = getattr(args, "bpf", None)
    duration: Optional[float] = getattr(args, "duration", None)
    max_packets: Optional[int] = getattr(args, "max_packets", None)
    idle_timeout_us: float = getattr(args, "idle_timeout", 120.0) * 1_000_000.0
    pretty: bool = getattr(args, "pretty", False)

    ctrl = CaptureController(idle_timeout_us=idle_timeout_us)

    try:
        src = LiveCaptureSource(iface=iface, bpf_filter=bpf)
    except RuntimeError as exc:
        _err(f"Cannot initialise live capture: {exc}")
        return EXIT_CAPTURE_ERROR

    if not args.quiet:
        _info(f"Starting live capture on: {iface or 'default interface'}")
        if bpf:
            _info(f"BPF filter: {bpf}")
        if duration:
            _info(f"Duration limit: {duration}s")
        if max_packets:
            _info(f"Packet limit: {max_packets}")

    src.start()
    ctrl.start(src)

    start_time = time.monotonic()
    n_emitted = 0
    n_packets_seen = 0

    try:
        while True:
            # Check duration limit
            if duration is not None and (time.monotonic() - start_time) >= duration:
                break

            # Check packet limit (approximated via flows emitted, not raw packets)
            if max_packets is not None and n_packets_seen >= max_packets:
                break

            # Drain completed flows
            try:
                import queue
                flow = ctrl.completed_flows.get(timeout=0.5)
                n_packets_seen += flow.packet_count
                if args.max_flows is not None and n_emitted >= args.max_flows:
                    continue
                result = adapter.predict(flow)
                row = result.to_dict()
                if not args.all_probs:
                    row.pop("class_probabilities", None)
                _emit(row, out, pretty=pretty)
                n_emitted += 1
            except queue.Empty:
                pass

    except KeyboardInterrupt:
        if not args.quiet:
            _info("Interrupted by user (Ctrl+C)")
    finally:
        if not args.quiet:
            _info("Stopping capture...")
        src.stop()
        ctrl.stop()
        # Drain any remaining flushed flows
        try:
            import queue
            while True:
                flow = ctrl.completed_flows.get_nowait()
                if args.max_flows is None or n_emitted < args.max_flows:
                    try:
                        result = adapter.predict(flow)
                        row = result.to_dict()
                        if not args.all_probs:
                            row.pop("class_probabilities", None)
                        _emit(row, out, pretty=pretty)
                        n_emitted += 1
                    except Exception as exc:  # noqa: BLE001
                        _warn(f"Prediction error during shutdown: {exc}")
        except queue.Empty:
            pass
        if not args.quiet:
            _info(f"Emitted {n_emitted} predictions")

    return EXIT_OK


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level argument parser.

    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog="python -m packet_capture",
        description="NetShield AI -- packet capture and intrusion detection",
    )
    subparsers = parser.add_subparsers(dest="subcommand", metavar="subcommand")
    subparsers.required = True

    # -- shared artifact overrides ----------------------------------------
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument(
        "--model", metavar="PATH", help="Override default model artifact path."
    )
    shared.add_argument(
        "--preprocessor", metavar="PATH", help="Override default preprocessor path."
    )
    shared.add_argument(
        "--encoder", metavar="PATH", help="Override default label encoder path."
    )
    shared.add_argument(
        "--metadata", metavar="PATH", help="Override default metadata JSON path."
    )
    shared.add_argument(
        "--output", "-o", metavar="PATH",
        help="Write JSONL output to a file instead of stdout."
    )
    shared.add_argument(
        "--max-flows", type=int, default=None, metavar="N",
        help="Emit at most N predictions."
    )
    shared.add_argument(
        "--all-probs", action="store_true",
        help="Include all nine class probabilities in each output record."
    )
    shared.add_argument(
        "--pretty", action="store_true",
        help="Emit indented JSON (one flow per block) instead of compact JSONL."
    )
    shared.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress informational messages."
    )

    # -- pcap subcommand --------------------------------------------------
    sp_pcap = subparsers.add_parser(
        "pcap",
        parents=[shared],
        help="Analyse a saved PCAP file.",
        description="Replay a PCAP file through the full detection pipeline.",
    )
    sp_pcap.add_argument(
        "--file", "-f", required=True, metavar="PATH",
        help="Path to the .pcap or .pcapng file to analyse."
    )

    # -- live subcommand --------------------------------------------------
    sp_live = subparsers.add_parser(
        "live",
        parents=[shared],
        help="Capture live traffic from a network interface.",
        description="Sniff live packets and emit intrusion detection results.",
    )
    sp_live.add_argument(
        "--interface", "-i", metavar="IFACE", default=None,
        help="Network interface to sniff (default: Scapy's default)."
    )
    sp_live.add_argument(
        "--bpf", metavar="FILTER", default=None,
        help="BPF filter string, e.g. 'tcp port 80'."
    )
    sp_live.add_argument(
        "--duration", "-d", type=float, default=None, metavar="SECONDS",
        help="Stop after this many seconds."
    )
    sp_live.add_argument(
        "--max-packets", type=int, default=None, metavar="N",
        help="Approximate packet count limit (checked per completed flow)."
    )
    sp_live.add_argument(
        "--idle-timeout", type=float, default=120.0, metavar="SECONDS",
        help="Idle flow eviction timeout in seconds (default: 120)."
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the correct subcommand.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        Integer exit code.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Open output stream
    out_path: Optional[str] = getattr(args, "output", None)
    if out_path:
        try:
            out_file = open(out_path, "w", encoding="utf-8")
        except OSError as exc:
            _err(f"Cannot open output file: {exc}")
            return EXIT_FILE_ERROR
    else:
        out_file = sys.stdout

    try:
        if args.subcommand == "pcap":
            code = cmd_pcap(args, out_file)
        elif args.subcommand == "live":
            code = cmd_live(args, out_file)
        else:
            _err(f"Unknown subcommand: {args.subcommand}")
            code = EXIT_BAD_ARGS
    finally:
        if out_path and out_file is not sys.stdout:
            out_file.close()

    return code


if __name__ == "__main__":
    sys.exit(main())
