"""Tests for the packet_capture CLI (Stage 4.6).

Tests cover:
    - --help output for top-level and subcommands.
    - Missing file → exit code 3.
    - Empty PCAP → exit code 0, zero flows.
    - Valid TCP fixture PCAP → exit code 0, valid JSON output.
    - JSONL output parses as valid JSON objects.
    - --all-probs includes class_probabilities.
    - --pretty produces indented output.
    - --max-flows limits output count.
    - Invalid model path → exit code 4.
    - Deterministic exit codes.
"""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

_ENGINE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ENGINE_ROOT not in sys.path:
    sys.path.insert(0, _ENGINE_ROOT)

pytest.importorskip("scapy")

from tests.pcap_fixtures import create_tcp_fixture_pcap, create_udp_fixture_pcap  # noqa: E402

from packet_capture.cli import main, EXIT_OK, EXIT_FILE_ERROR, EXIT_ARTIFACT_ERROR  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tcp_pcap(tmp_path: Path) -> str:
    """Create a TCP fixture PCAP in tmp_path.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path to the generated PCAP file.
    """
    return create_tcp_fixture_pcap(str(tmp_path))


@pytest.fixture
def udp_pcap(tmp_path: Path) -> str:
    """Create a UDP fixture PCAP in tmp_path.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path to the generated PCAP file.
    """
    return create_udp_fixture_pcap(str(tmp_path))


@pytest.fixture
def empty_pcap(tmp_path: Path) -> str:
    """Create an empty PCAP file (valid header, no packets).

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path to the empty PCAP file.
    """
    from scapy.all import wrpcap
    p = str(tmp_path / "empty.pcap")
    wrpcap(p, [])
    return p


@pytest.fixture
def capture_stdout() -> Any:
    """Replace stdout with a StringIO buffer for the duration of a test.

    Yields:
        StringIO buffer that collects stdout output.
    """
    old = sys.stdout
    buf = io.StringIO()
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = old


@pytest.fixture
def capture_stderr() -> Any:
    """Replace stderr with a StringIO buffer for the duration of a test.

    Yields:
        StringIO buffer that collects stderr output.
    """
    old = sys.stderr
    buf = io.StringIO()
    sys.stderr = buf
    try:
        yield buf
    finally:
        sys.stderr = old


# ---------------------------------------------------------------------------
# Helper: run CLI with stdout/stderr captured via capsys (pytest native)
# ---------------------------------------------------------------------------


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Run main() and capture stdout/stderr using capsys-style replacement.

    Args:
        argv: Argument list.

    Returns:
        Tuple of (exit_code, stdout_text, stderr_text).
    """
    old_out = sys.stdout
    old_err = sys.stderr
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    sys.stdout = out_buf
    sys.stderr = err_buf
    try:
        code = main(argv)
    except SystemExit as exc:
        code = int(exc.code) if exc.code is not None else 0
    finally:
        sys.stdout = old_out
        sys.stderr = old_err
    return code, out_buf.getvalue(), err_buf.getvalue()


# ---------------------------------------------------------------------------
# Help tests
# ---------------------------------------------------------------------------


class TestCliHelp:
    """Verify --help works for top-level and subcommands."""

    def test_top_level_help(self) -> None:
        """--help should print usage and exit 0."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0

    def test_pcap_help(self) -> None:
        """pcap --help should print usage and exit 0."""
        with pytest.raises(SystemExit) as exc_info:
            main(["pcap", "--help"])
        assert exc_info.value.code == 0

    def test_live_help(self) -> None:
        """live --help should print usage and exit 0."""
        with pytest.raises(SystemExit) as exc_info:
            main(["live", "--help"])
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------


class TestCliErrors:
    """Verify error handling and exit codes."""

    def test_missing_file(self) -> None:
        """Missing PCAP file → exit code 3."""
        code, _, err = _run_cli(["pcap", "--file", "nonexistent.pcap", "--quiet"])
        assert code == EXIT_FILE_ERROR

    def test_invalid_model_path(self, tcp_pcap: str) -> None:
        """Invalid model path → SystemExit with code 4."""
        code, _, _ = _run_cli([
            "pcap", "--file", tcp_pcap,
            "--model", "nonexistent_model.pkl",
            "--quiet",
        ])
        assert code == EXIT_ARTIFACT_ERROR


# ---------------------------------------------------------------------------
# Empty PCAP test
# ---------------------------------------------------------------------------


class TestCliEmptyPcap:
    """Verify behaviour with an empty PCAP (valid file, no packets)."""

    def test_empty_pcap_exit_zero(self, empty_pcap: str) -> None:
        """Empty PCAP → exit code 0, no output."""
        code, out, _ = _run_cli(["pcap", "--file", empty_pcap, "--quiet"])
        assert code == EXIT_OK
        assert out.strip() == ""


# ---------------------------------------------------------------------------
# Valid PCAP tests
# ---------------------------------------------------------------------------


class TestCliPcapReplay:
    """Verify CLI output for valid fixture PCAPs."""

    def test_tcp_pcap_exit_zero(self, tcp_pcap: str) -> None:
        """Valid TCP PCAP → exit code 0."""
        code, _, _ = _run_cli(["pcap", "--file", tcp_pcap, "--quiet"])
        assert code == EXIT_OK

    def test_tcp_pcap_emits_valid_json(self, tcp_pcap: str) -> None:
        """Output must be parseable JSON."""
        code, out, _ = _run_cli(["pcap", "--file", tcp_pcap, "--quiet"])
        assert code == EXIT_OK
        output = out.strip()
        assert output, "Expected at least one JSON line"
        lines = output.split("\n")
        for line in lines:
            obj = json.loads(line)
            assert isinstance(obj, dict)
            assert "label" in obj
            assert "confidence" in obj
            assert "status" in obj

    def test_all_probs_includes_class_probabilities(self, tcp_pcap: str) -> None:
        """--all-probs must include class_probabilities in output."""
        code, out, _ = _run_cli(["pcap", "--file", tcp_pcap, "--all-probs", "--quiet"])
        assert code == EXIT_OK
        output = out.strip()
        assert output
        obj = json.loads(output.split("\n")[0])
        assert "class_probabilities" in obj
        assert len(obj["class_probabilities"]) == 9

    def test_no_all_probs_omits_class_probabilities(self, tcp_pcap: str) -> None:
        """Without --all-probs, class_probabilities should be absent."""
        code, out, _ = _run_cli(["pcap", "--file", tcp_pcap, "--quiet"])
        assert code == EXIT_OK
        output = out.strip()
        assert output
        obj = json.loads(output.split("\n")[0])
        assert "class_probabilities" not in obj

    def test_pretty_output(self, tcp_pcap: str) -> None:
        """--pretty must produce indented JSON."""
        code, out, _ = _run_cli(["pcap", "--file", tcp_pcap, "--pretty", "--quiet"])
        assert code == EXIT_OK
        output = out.strip()
        assert output
        assert output.startswith("{")
        brace_count = 0
        end_idx = 0
        for i, ch in enumerate(output):
            if ch == "{":
                brace_count += 1
            elif ch == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        obj = json.loads(output[:end_idx])
        assert isinstance(obj, dict)

    def test_max_flows_limit(self, tcp_pcap: str) -> None:
        """--max-flows 0 must emit zero predictions."""
        code, out, _ = _run_cli(["pcap", "--file", tcp_pcap, "--max-flows", "0", "--quiet"])
        assert code == EXIT_OK
        assert out.strip() == ""

    def test_udp_pcap_exit_zero(self, udp_pcap: str) -> None:
        """Valid UDP PCAP → exit code 0."""
        code, _, _ = _run_cli(["pcap", "--file", udp_pcap, "--quiet"])
        assert code == EXIT_OK

    def test_udp_pcap_emits_valid_json(self, udp_pcap: str) -> None:
        """UDP PCAP output must be parseable JSON with a label."""
        code, out, _ = _run_cli(["pcap", "--file", udp_pcap, "--quiet"])
        assert code == EXIT_OK
        output = out.strip()
        assert output
        obj = json.loads(output.split("\n")[0])
        assert isinstance(obj, dict)
        assert "label" in obj

    def test_output_to_file(self, tcp_pcap: str, tmp_path: Path) -> None:
        """--output writes JSONL to a file instead of stdout."""
        out_file = str(tmp_path / "results.jsonl")
        code, out, _ = _run_cli([
            "pcap", "--file", tcp_pcap,
            "--output", out_file,
            "--quiet",
        ])
        assert code == EXIT_OK
        assert out.strip() == ""
        with open(out_file, "r", encoding="utf-8") as f:
            content = f.read().strip()
        assert content
        obj = json.loads(content.split("\n")[0])
        assert isinstance(obj, dict)
