"""Integration tests: full PCAP → FlowResult → PredictionResult pipeline (Stage 4.5.6).

Replays the deterministic TCP and UDP PCAP fixtures produced by
``tests/pcap_fixtures.py``, passes each ``FlowResult`` through
``FlowPredictionAdapter``, and validates all ``PredictionResult`` invariants.

Invariants verified for every non-REJECTED result:
    - ``label`` is one of the nine ``CANONICAL_CLASSES``.
    - ``confidence`` is in [0, 1].
    - ``class_probabilities`` has exactly nine entries summing to ~1.0.
    - ``is_attack`` is consistent with ``label != "BENIGN"``.
    - ``to_dict()`` returns a JSON-serialisable dictionary.
    - ``is_partial_flow`` reflects flow completion state correctly.
    - ``context`` is a non-None ``FlowContext``.

No specific attack label is required — the model prediction is accepted as-is.
"""

from __future__ import annotations

import json
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
    create_tcp_fixture_pcap,
    create_udp_fixture_pcap,
)

from packet_capture.capture import CaptureController  # noqa: E402
from packet_capture.schemas import FlowResult, FlowState  # noqa: E402
from prediction.flow_adapter import FlowPredictionAdapter  # noqa: E402
from prediction.predict import IntrusionPredictor  # noqa: E402
from prediction.schemas import (  # noqa: E402
    CANONICAL_CLASSES,
    EXPECTED_CLASS_COUNT,
    FlowContext,
    PredictionResult,
    PredictionStatus,
)


# ---------------------------------------------------------------------------
# Module-scoped shared predictor and adapter
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def predictor() -> IntrusionPredictor:
    """Load the v3 IntrusionPredictor once for all tests in this module.

    Returns:
        A ready-to-use ``IntrusionPredictor`` instance.
    """
    return IntrusionPredictor()


@pytest.fixture(scope="module")
def adapter(predictor: IntrusionPredictor) -> FlowPredictionAdapter:
    """Wrap the predictor in a ``FlowPredictionAdapter``.

    Args:
        predictor: The module-scoped predictor fixture.

    Returns:
        A ``FlowPredictionAdapter`` ready to process ``FlowResult`` objects.
    """
    return FlowPredictionAdapter(predictor)


# ---------------------------------------------------------------------------
# Flow replay helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tcp_flow_result(tmp_path_factory: pytest.TempPathFactory) -> FlowResult:
    """Replay the TCP fixture and return its single completed ``FlowResult``.

    Args:
        tmp_path_factory: Pytest factory for temporary directories.

    Returns:
        The single ``FlowResult`` produced by the TCP fixture replay.
    """
    tmp_dir = str(tmp_path_factory.mktemp("pred_tcp"))
    pcap_path = create_tcp_fixture_pcap(tmp_dir)
    ctrl = CaptureController()
    replay = ctrl.replay_pcap(pcap_path)
    assert len(replay.completed_flows) == 1, (
        f"Expected 1 TCP flow, got {len(replay.completed_flows)}"
    )
    return replay.completed_flows[0]


@pytest.fixture(scope="module")
def udp_flow_result(tmp_path_factory: pytest.TempPathFactory) -> FlowResult:
    """Replay the UDP fixture and return its single completed ``FlowResult``.

    Args:
        tmp_path_factory: Pytest factory for temporary directories.

    Returns:
        The single ``FlowResult`` produced by the UDP fixture replay.
    """
    tmp_dir = str(tmp_path_factory.mktemp("pred_udp"))
    pcap_path = create_udp_fixture_pcap(tmp_dir)
    ctrl = CaptureController()
    replay = ctrl.replay_pcap(pcap_path)
    assert len(replay.completed_flows) == 1, (
        f"Expected 1 UDP flow, got {len(replay.completed_flows)}"
    )
    return replay.completed_flows[0]


@pytest.fixture(scope="module")
def tcp_prediction(
    adapter: FlowPredictionAdapter,
    tcp_flow_result: FlowResult,
) -> PredictionResult:
    """Run the TCP flow through the adapter and return the PredictionResult.

    Args:
        adapter: The module-scoped adapter fixture.
        tcp_flow_result: The TCP fixture FlowResult.

    Returns:
        ``PredictionResult`` for the TCP fixture flow.
    """
    return adapter.predict(tcp_flow_result)


@pytest.fixture(scope="module")
def udp_prediction(
    adapter: FlowPredictionAdapter,
    udp_flow_result: FlowResult,
) -> PredictionResult:
    """Run the UDP flow through the adapter and return the PredictionResult.

    Args:
        adapter: The module-scoped adapter fixture.
        udp_flow_result: The UDP fixture FlowResult.

    Returns:
        ``PredictionResult`` for the UDP fixture flow.
    """
    return adapter.predict(udp_flow_result)


# ---------------------------------------------------------------------------
# Helper: validate all PredictionResult invariants for a single result
# ---------------------------------------------------------------------------


def _assert_prediction_invariants(
    result: PredictionResult,
    *,
    expected_is_partial: bool,
) -> None:
    """Assert all invariants for a non-REJECTED PredictionResult.

    Args:
        result: The prediction to validate.
        expected_is_partial: Expected value of ``is_partial_flow``.

    Raises:
        AssertionError: If any invariant is violated.
    """
    # Must not be REJECTED for fixture flows (they have valid features)
    assert result.status != PredictionStatus.REJECTED, (
        f"Flow was unexpectedly rejected: {result.error}"
    )

    # Label invariants
    assert result.label in CANONICAL_CLASSES, (
        f"label {result.label!r} not in CANONICAL_CLASSES"
    )

    # Confidence in [0, 1]
    assert 0.0 <= result.confidence <= 1.0, (
        f"confidence {result.confidence} not in [0, 1]"
    )

    # Nine class probabilities present
    assert len(result.class_probabilities) == EXPECTED_CLASS_COUNT, (
        f"Expected {EXPECTED_CLASS_COUNT} probabilities, "
        f"got {len(result.class_probabilities)}"
    )

    # Class probabilities sum to ~1.0
    prob_sum = sum(result.class_probabilities.values())
    assert abs(prob_sum - 1.0) < 1e-4, (
        f"class_probabilities sum to {prob_sum}, expected ~1.0"
    )

    # All individual probabilities are finite and in [0, 1]
    for cls, prob in result.class_probabilities.items():
        assert math.isfinite(prob), f"Probability for {cls!r} is non-finite: {prob}"
        assert 0.0 <= prob <= 1.0, f"Probability for {cls!r} = {prob} not in [0, 1]"

    # is_attack consistent with label
    expected_is_attack = result.label != "BENIGN"
    assert result.is_attack == expected_is_attack, (
        f"is_attack={result.is_attack} inconsistent with label={result.label!r}"
    )

    # is_partial_flow reflects flow state
    assert result.is_partial_flow == expected_is_partial, (
        f"is_partial_flow={result.is_partial_flow}, expected {expected_is_partial}"
    )

    # context is a non-None FlowContext
    assert result.context is not None, "context must not be None"
    assert isinstance(result.context, FlowContext), (
        f"context must be a FlowContext, got {type(result.context)}"
    )

    # to_dict() is JSON-serialisable
    result_dict = result.to_dict()
    assert isinstance(result_dict, dict), "to_dict() must return a dict"
    try:
        json.dumps(result_dict)
    except (TypeError, ValueError) as exc:
        raise AssertionError(f"to_dict() is not JSON-serialisable: {exc}") from exc


# ===========================================================================
# ── TCP pipeline tests ──────────────────────────────────────────────────────
# ===========================================================================


class TestTcpFlowPrediction:
    """Validate PredictionResult invariants for the TCP fixture flow."""

    def test_tcp_adapter_returns_prediction_result(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """The adapter must return a ``PredictionResult`` instance."""
        assert isinstance(tcp_prediction, PredictionResult)

    def test_tcp_prediction_not_rejected(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """The TCP flow must not be rejected (it has valid features)."""
        assert tcp_prediction.status != PredictionStatus.REJECTED, (
            f"TCP prediction rejected: {tcp_prediction.error}"
        )

    def test_tcp_label_is_canonical(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """The predicted label must be one of the nine CANONICAL_CLASSES."""
        assert tcp_prediction.label in CANONICAL_CLASSES

    def test_tcp_confidence_in_range(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """Confidence must lie in [0.0, 1.0]."""
        assert 0.0 <= tcp_prediction.confidence <= 1.0

    def test_tcp_nine_class_probabilities(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """There must be exactly nine class probability entries."""
        assert len(tcp_prediction.class_probabilities) == EXPECTED_CLASS_COUNT

    def test_tcp_probabilities_sum_to_one(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """Class probabilities must sum to approximately 1.0."""
        total = sum(tcp_prediction.class_probabilities.values())
        assert abs(total - 1.0) < 1e-4

    def test_tcp_is_attack_consistent(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """is_attack must be True iff label != 'BENIGN'."""
        assert tcp_prediction.is_attack == (tcp_prediction.label != "BENIGN")

    def test_tcp_is_not_partial_flow(
        self, tcp_flow_result: FlowResult, tcp_prediction: PredictionResult
    ) -> None:
        """TCP flow closed with bidirectional FIN → state COMPLETED → not partial."""
        assert tcp_flow_result.state == FlowState.COMPLETED
        assert tcp_prediction.is_partial_flow is False

    def test_tcp_context_is_flow_context(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """Result context must be a non-None FlowContext instance."""
        assert tcp_prediction.context is not None
        assert isinstance(tcp_prediction.context, FlowContext)

    def test_tcp_context_src_ip(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """Context src_ip must be the TCP fixture client IP."""
        assert tcp_prediction.context is not None
        assert tcp_prediction.context.src_ip == "10.10.0.1"

    def test_tcp_context_dst_ip(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """Context dst_ip must be the TCP fixture server IP."""
        assert tcp_prediction.context is not None
        assert tcp_prediction.context.dst_ip == "10.10.0.2"

    def test_tcp_context_protocol(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """Context protocol must be 6 (TCP)."""
        assert tcp_prediction.context is not None
        assert tcp_prediction.context.protocol == 6

    def test_tcp_context_total_packets(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """Context total_packets must be 7."""
        assert tcp_prediction.context is not None
        assert tcp_prediction.context.total_packets == 7

    def test_tcp_to_dict_json_safe(
        self, tcp_prediction: PredictionResult
    ) -> None:
        """to_dict() must produce a dict serialisable with json.dumps()."""
        result_dict = tcp_prediction.to_dict()
        assert isinstance(result_dict, dict)
        json.dumps(result_dict)  # raises TypeError if not JSON-safe

    def test_tcp_all_invariants(
        self, tcp_prediction: PredictionResult, tcp_flow_result: FlowResult
    ) -> None:
        """Run the full invariant suite for the TCP prediction."""
        expected_partial = tcp_flow_result.state not in (
            FlowState.COMPLETED, FlowState.TIMEOUT
        )
        _assert_prediction_invariants(
            tcp_prediction, expected_is_partial=expected_partial
        )


# ===========================================================================
# ── UDP pipeline tests ──────────────────────────────────────────────────────
# ===========================================================================


class TestUdpFlowPrediction:
    """Validate PredictionResult invariants for the UDP fixture flow."""

    def test_udp_adapter_returns_prediction_result(
        self, udp_prediction: PredictionResult
    ) -> None:
        """The adapter must return a ``PredictionResult`` instance."""
        assert isinstance(udp_prediction, PredictionResult)

    def test_udp_prediction_not_rejected(
        self, udp_prediction: PredictionResult
    ) -> None:
        """The UDP flow must not be rejected (it has valid features)."""
        assert udp_prediction.status != PredictionStatus.REJECTED, (
            f"UDP prediction rejected: {udp_prediction.error}"
        )

    def test_udp_label_is_canonical(
        self, udp_prediction: PredictionResult
    ) -> None:
        """The predicted label must be one of the nine CANONICAL_CLASSES."""
        assert udp_prediction.label in CANONICAL_CLASSES

    def test_udp_confidence_in_range(
        self, udp_prediction: PredictionResult
    ) -> None:
        """Confidence must lie in [0.0, 1.0]."""
        assert 0.0 <= udp_prediction.confidence <= 1.0

    def test_udp_nine_class_probabilities(
        self, udp_prediction: PredictionResult
    ) -> None:
        """There must be exactly nine class probability entries."""
        assert len(udp_prediction.class_probabilities) == EXPECTED_CLASS_COUNT

    def test_udp_probabilities_sum_to_one(
        self, udp_prediction: PredictionResult
    ) -> None:
        """Class probabilities must sum to approximately 1.0."""
        total = sum(udp_prediction.class_probabilities.values())
        assert abs(total - 1.0) < 1e-4

    def test_udp_is_attack_consistent(
        self, udp_prediction: PredictionResult
    ) -> None:
        """is_attack must be True iff label != 'BENIGN'."""
        assert udp_prediction.is_attack == (udp_prediction.label != "BENIGN")

    def test_udp_is_partial_flow_correct(
        self, udp_flow_result: FlowResult, udp_prediction: PredictionResult
    ) -> None:
        """UDP flow flushed at EOF → state COMPLETED → not partial."""
        assert udp_flow_result.state == FlowState.COMPLETED
        assert udp_prediction.is_partial_flow is False

    def test_udp_context_is_flow_context(
        self, udp_prediction: PredictionResult
    ) -> None:
        """Result context must be a non-None FlowContext instance."""
        assert udp_prediction.context is not None
        assert isinstance(udp_prediction.context, FlowContext)

    def test_udp_context_protocol(
        self, udp_prediction: PredictionResult
    ) -> None:
        """Context protocol must be 17 (UDP)."""
        assert udp_prediction.context is not None
        assert udp_prediction.context.protocol == 17

    def test_udp_context_total_packets(
        self, udp_prediction: PredictionResult
    ) -> None:
        """Context total_packets must be 2."""
        assert udp_prediction.context is not None
        assert udp_prediction.context.total_packets == 2

    def test_udp_to_dict_json_safe(
        self, udp_prediction: PredictionResult
    ) -> None:
        """to_dict() must produce a dict serialisable with json.dumps()."""
        result_dict = udp_prediction.to_dict()
        assert isinstance(result_dict, dict)
        json.dumps(result_dict)

    def test_udp_all_invariants(
        self, udp_prediction: PredictionResult, udp_flow_result: FlowResult
    ) -> None:
        """Run the full invariant suite for the UDP prediction."""
        expected_partial = udp_flow_result.state not in (
            FlowState.COMPLETED, FlowState.TIMEOUT
        )
        _assert_prediction_invariants(
            udp_prediction, expected_is_partial=expected_partial
        )


# ===========================================================================
# ── Adapter unit tests ──────────────────────────────────────────────────────
# ===========================================================================


class TestFlowPredictionAdapterUnit:
    """Unit-level tests for FlowPredictionAdapter internal logic."""

    def test_adapter_is_partial_completed(
        self, adapter: FlowPredictionAdapter
    ) -> None:
        """_is_partial returns False for COMPLETED flows."""
        from packet_capture.schemas import FlowKey, FlowResult, FlowState

        key = FlowKey.from_endpoints("1.1.1.1", "2.2.2.2", 1234, 80, 6)
        result = FlowResult(
            key=key,
            features={},
            state=FlowState.COMPLETED,
            initiator_ip="1.1.1.1",
            responder_ip="2.2.2.2",
            initiator_port=1234,
            responder_port=80,
        )
        assert FlowPredictionAdapter._is_partial(result) is False

    def test_adapter_is_partial_timeout(
        self, adapter: FlowPredictionAdapter
    ) -> None:
        """_is_partial returns False for TIMEOUT flows."""
        from packet_capture.schemas import FlowKey, FlowResult, FlowState

        key = FlowKey.from_endpoints("1.1.1.1", "2.2.2.2", 1234, 80, 6)
        result = FlowResult(
            key=key,
            features={},
            state=FlowState.TIMEOUT,
            initiator_ip="1.1.1.1",
            responder_ip="2.2.2.2",
            initiator_port=1234,
            responder_port=80,
        )
        assert FlowPredictionAdapter._is_partial(result) is False

    def test_adapter_is_partial_new(
        self, adapter: FlowPredictionAdapter
    ) -> None:
        """_is_partial returns True for NEW flows (not yet completed)."""
        from packet_capture.schemas import FlowKey, FlowResult, FlowState

        key = FlowKey.from_endpoints("1.1.1.1", "2.2.2.2", 1234, 80, 6)
        result = FlowResult(
            key=key,
            features={},
            state=FlowState.NEW,
            initiator_ip="1.1.1.1",
            responder_ip="2.2.2.2",
            initiator_port=1234,
            responder_port=80,
        )
        assert FlowPredictionAdapter._is_partial(result) is True

    def test_adapter_is_partial_closing(
        self, adapter: FlowPredictionAdapter
    ) -> None:
        """_is_partial returns True for CLOSING flows."""
        from packet_capture.schemas import FlowKey, FlowResult, FlowState

        key = FlowKey.from_endpoints("1.1.1.1", "2.2.2.2", 1234, 80, 6)
        result = FlowResult(
            key=key,
            features={},
            state=FlowState.CLOSING,
            initiator_ip="1.1.1.1",
            responder_ip="2.2.2.2",
            initiator_port=1234,
            responder_port=80,
        )
        assert FlowPredictionAdapter._is_partial(result) is True

    def test_build_context_fields(
        self, adapter: FlowPredictionAdapter
    ) -> None:
        """_build_context must populate FlowContext from FlowResult correctly."""
        from packet_capture.schemas import FlowKey, FlowResult, FlowState

        key = FlowKey.from_endpoints("10.0.0.1", "10.0.0.2", 5555, 443, 6)
        flow = FlowResult(
            key=key,
            features={},
            state=FlowState.COMPLETED,
            packet_count=5,
            start_timestamp_us=0.0,
            end_timestamp_us=1_000_000.0,
            initiator_ip="10.0.0.1",
            responder_ip="10.0.0.2",
            initiator_port=5555,
            responder_port=443,
        )
        flow.context = flow.to_context_dict()

        ctx = FlowPredictionAdapter._build_context(flow)

        assert isinstance(ctx, FlowContext)
        assert ctx.src_ip == "10.0.0.1"
        assert ctx.dst_ip == "10.0.0.2"
        assert ctx.src_port == 5555
        assert ctx.dst_port == 443
        assert ctx.protocol == 6
        assert ctx.total_packets == 5
        assert ctx.flow_duration_us == pytest.approx(1_000_000.0)
        assert ctx.is_completed is True
