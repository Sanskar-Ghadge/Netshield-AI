"""Tests for the traffic pre-filter and confidence threshold logic.

Covers:
  - ICMP flows are bypassed to BENIGN
  - IGMP flows are bypassed to BENIGN
  - DHCP (broadcast) flows are bypassed to BENIGN
  - SSDP/mDNS/LLMNR discovery flows are bypassed to BENIGN
  - Broadcast/multicast destinations are bypassed
  - Normal TCP flows are NOT bypassed (proceed to model)
  - Normal UDP flows are NOT bypassed (proceed to model)
  - Confidence threshold downgrades low-confidence attacks
  - Confidence threshold passes high-confidence attacks
  - BENIGN predictions are unaffected by the threshold
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure python-engine root is on sys.path
_ENGINE_ROOT = Path(__file__).resolve().parents[1]
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

from packet_capture.schemas import FlowKey, FlowResult, FlowState
from prediction.filter import TrafficFilter, should_flag_as_attack
from prediction.schemas import (
    CANONICAL_CLASSES,
    FeatureQuality,
    FlowContext,
    PredictionResult,
    PredictionStatus,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_flow(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    src_port: int = 50000,
    dst_port: int = 80,
    protocol: int = 6,
    packet_count: int = 5,
) -> FlowResult:
    """Create a minimal FlowResult for testing."""
    key = FlowKey.from_endpoints(src_ip, dst_ip, src_port, dst_port, protocol)
    return FlowResult(
        key=key,
        features={},
        context={},
        packet_count=packet_count,
        start_timestamp_us=1000000.0,
        end_timestamp_us=1600000.0,
        state=FlowState.COMPLETED,
        initiator_ip=src_ip,
        responder_ip=dst_ip,
        initiator_port=src_port,
        responder_port=dst_port,
    )


def _make_attack_prediction(
    label: str = "DoS",
    confidence: float = 0.95,
) -> PredictionResult:
    """Create a mock attack PredictionResult for threshold testing."""
    class_id = CANONICAL_CLASSES.index(label) if label in CANONICAL_CLASSES else 4
    probs = {c: 0.0 for c in CANONICAL_CLASSES}
    probs[label] = confidence
    probs["BENIGN"] = 1.0 - confidence
    return PredictionResult(
        timestamp_utc=1000.0,
        status=PredictionStatus.ATTACK,
        class_id=class_id,
        label=label,
        is_attack=True,
        confidence=confidence,
        class_probabilities=probs,
        feature_quality=FeatureQuality.COMPLETE,
        missing_fields=(),
        imputed_fields=(),
        rejected_fields=(),
        context=FlowContext(),
        model_version="test_model",
        preprocessing_version=3,
        inference_ms=0.01,
        is_partial_flow=False,
        known_attack_model=True,
        generalization_warning="test",
        error="",
    )


# ---------------------------------------------------------------------------
# TrafficFilter tests
# ---------------------------------------------------------------------------

class TestTrafficFilter:
    """Tests for the TrafficFilter class."""

    def setup_method(self) -> None:
        self.filt = TrafficFilter(
            model_version="test_model", preprocessing_version=3
        )

    def test_icmp_bypassed(self) -> None:
        """ICMP flows (protocol 1) should be bypassed to BENIGN."""
        flow = _make_flow(
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=0,
            dst_port=0,
            protocol=1,
            packet_count=2,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.status == PredictionStatus.BENIGN
        assert result.is_attack is False
        assert "ICMP" in result.error

    def test_igmp_bypassed(self) -> None:
        """IGMP flows (protocol 2) should be bypassed to BENIGN."""
        flow = _make_flow(
            src_ip="10.20.27.85",
            dst_ip="224.0.0.22",
            src_port=0,
            dst_port=0,
            protocol=2,
            packet_count=1,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.status == PredictionStatus.BENIGN
        assert "IGMP" in result.error

    def test_dhcp_broadcast_bypassed(self) -> None:
        """DHCP discovery (0.0.0.0:68 → 255.255.255.255:67) should be bypassed."""
        flow = _make_flow(
            src_ip="0.0.0.0",
            dst_ip="255.255.255.255",
            src_port=68,
            dst_port=67,
            protocol=17,
            packet_count=1,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.status == PredictionStatus.BENIGN
        assert "bypass" in result.error.lower()

    def test_dhcp_response_bypassed(self) -> None:
        """DHCP response (router:67 → client:68) should be bypassed."""
        flow = _make_flow(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.36",
            src_port=67,
            dst_port=68,
            protocol=17,
            packet_count=1,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.status == PredictionStatus.BENIGN
        assert "Link-local" in result.error or "bypass" in result.error.lower()

    def test_ssdp_bypassed(self) -> None:
        """SSDP (UDP port 1900) should be bypassed."""
        flow = _make_flow(
            src_ip="10.224.91.204",
            dst_ip="239.255.255.250",
            src_port=61478,
            dst_port=1900,
            protocol=17,
            packet_count=1,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.status == PredictionStatus.BENIGN

    def test_mdns_bypassed(self) -> None:
        """mDNS (UDP port 5353 to multicast) should be bypassed."""
        flow = _make_flow(
            src_ip="10.224.91.204",
            dst_ip="224.0.0.252",
            src_port=57217,
            dst_port=5355,
            protocol=17,
            packet_count=1,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.status == PredictionStatus.BENIGN

    def test_multicast_bypassed(self) -> None:
        """Any UDP to a multicast address should be bypassed."""
        flow = _make_flow(
            src_ip="10.0.0.1",
            dst_ip="239.1.1.1",
            src_port=12345,
            dst_port=9999,
            protocol=17,
            packet_count=3,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.status == PredictionStatus.BENIGN
        assert "Broadcast/multicast" in result.error

    def test_broadcast_bypassed(self) -> None:
        """UDP to 255.255.255.255 should be bypassed."""
        flow = _make_flow(
            src_ip="10.20.21.25",
            dst_ip="255.255.255.255",
            src_port=0,
            dst_port=0,
            protocol=17,
            packet_count=1,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.status == PredictionStatus.BENIGN

    def test_normal_tcp_not_bypassed(self) -> None:
        """Normal TCP web traffic should NOT be bypassed."""
        flow = _make_flow(
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
            src_port=50000,
            dst_port=80,
            protocol=6,
            packet_count=10,
        )
        result = self.filt.evaluate(flow)
        assert result is None, "Normal TCP flow should proceed to model"

    def test_normal_udp_not_bypassed(self) -> None:
        """Normal UDP DNS traffic should NOT be bypassed (port 53 is not in bypass list)."""
        flow = _make_flow(
            src_ip="192.168.1.10",
            dst_ip="10.224.91.57",
            src_port=58679,
            dst_port=53,
            protocol=17,
            packet_count=2,
        )
        result = self.filt.evaluate(flow)
        assert result is None, "Normal DNS UDP flow should proceed to model"

    def test_normal_tcp_https_not_bypassed(self) -> None:
        """Normal TCP HTTPS traffic should NOT be bypassed."""
        flow = _make_flow(
            src_ip="10.224.91.181",
            dst_ip="115.112.38.38",
            src_port=49305,
            dst_port=443,
            protocol=6,
            packet_count=8,
        )
        result = self.filt.evaluate(flow)
        assert result is None, "Normal HTTPS TCP flow should proceed to model"

    def test_bypass_result_has_context(self) -> None:
        """Bypassed results should include the flow context metadata."""
        flow = _make_flow(
            src_ip="192.168.1.10",
            dst_ip="255.255.255.255",
            src_port=0,
            dst_port=0,
            protocol=1,
            packet_count=1,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.context is not None
        assert result.context.src_ip == "192.168.1.10"
        assert result.context.dst_ip == "255.255.255.255"
        assert result.context.protocol == 1

    def test_bypass_result_confidence_is_1(self) -> None:
        """Bypassed BENIGN results should have confidence=1.0."""
        flow = _make_flow(
            src_ip="192.168.1.10",
            dst_ip="224.0.0.22",
            src_port=0,
            dst_port=0,
            protocol=2,
            packet_count=1,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.confidence == 1.0

    def test_bypass_result_class_probabilities(self) -> None:
        """Bypassed results should have BENIGN=1.0, all others=0.0."""
        flow = _make_flow(
            src_ip="0.0.0.0",
            dst_ip="255.255.255.255",
            src_port=68,
            dst_port=67,
            protocol=17,
            packet_count=1,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.class_probabilities["BENIGN"] == 1.0
        for cls in CANONICAL_CLASSES:
            if cls == "BENIGN":
                continue
            assert result.class_probabilities[cls] == 0.0

    def test_link_local_bypassed(self) -> None:
        """Link-local addresses (169.254.x.x) should be bypassed."""
        flow = _make_flow(
            src_ip="169.254.1.1",
            dst_ip="10.0.0.1",
            src_port=50000,
            dst_port=80,
            protocol=17,
            packet_count=2,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.status == PredictionStatus.BENIGN

    def test_snmp_bypassed(self) -> None:
        """SNMP (UDP port 161) should be bypassed."""
        flow = _make_flow(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=161,
            protocol=17,
            packet_count=2,
        )
        result = self.filt.evaluate(flow)
        assert result is not None
        assert result.status == PredictionStatus.BENIGN


# ---------------------------------------------------------------------------
# Confidence threshold tests
# ---------------------------------------------------------------------------

class TestConfidenceThreshold:
    """Tests for should_flag_as_attack confidence thresholding."""

    def test_high_confidence_attack_passes(self) -> None:
        """Attack with confidence >= threshold should pass through."""
        pred = _make_attack_prediction(label="DDoS", confidence=0.95)
        result = should_flag_as_attack(pred, confidence_threshold=0.80)
        assert result.is_attack is True
        assert result.label == "DDoS"
        assert result.confidence == 0.95

    def test_low_confidence_attack_downgraded(self) -> None:
        """Attack with confidence < threshold should be downgraded to BENIGN."""
        pred = _make_attack_prediction(label="DoS", confidence=0.50)
        result = should_flag_as_attack(pred, confidence_threshold=0.80)
        assert result.is_attack is False
        assert result.label == "BENIGN"
        assert result.status == PredictionStatus.BENIGN
        assert "Downgraded" in result.error

    def test_exact_threshold_passes(self) -> None:
        """Attack with confidence exactly == threshold should pass."""
        pred = _make_attack_prediction(label="DDoS", confidence=0.80)
        result = should_flag_as_attack(pred, confidence_threshold=0.80)
        assert result.is_attack is True
        assert result.label == "DDoS"

    def test_benign_unaffected(self) -> None:
        """BENIGN predictions should be unaffected by the threshold."""
        benign = PredictionResult.benign(
            reason="test",
            context=FlowContext(),
            model_version="test",
        )
        result = should_flag_as_attack(benign, confidence_threshold=0.80)
        assert result.is_attack is False
        assert result.label == "BENIGN"

    def test_rejected_unaffected(self) -> None:
        """REJECTED predictions should be unaffected by the threshold."""
        rejected = PredictionResult.rejected(
            reason="test",
            context=FlowContext(),
            model_version="test",
        )
        result = should_flag_as_attack(rejected, confidence_threshold=0.80)
        assert result.is_attack is False
        assert result.label == "REJECTED"

    def test_very_low_confidence_downgraded(self) -> None:
        """Confidence of 0.47 (like our false positives) should be downgraded."""
        pred = _make_attack_prediction(label="DoS", confidence=0.47)
        result = should_flag_as_attack(pred, confidence_threshold=0.80)
        assert result.is_attack is False
        assert result.label == "BENIGN"

    def test_downgraded_preserves_context(self) -> None:
        """Downgraded results should preserve the original flow context."""
        ctx = FlowContext(
            flow_id="192.168.1.1:80-10.0.0.1:443-6",
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=443,
            protocol=6,
            total_packets=5,
            flow_duration_us=600000.0,
            is_completed=True,
        )
        pred = _make_attack_prediction(label="DoS", confidence=0.50)
        pred_with_ctx = PredictionResult(
            timestamp_utc=pred.timestamp_utc,
            status=pred.status,
            class_id=pred.class_id,
            label=pred.label,
            is_attack=pred.is_attack,
            confidence=pred.confidence,
            class_probabilities=pred.class_probabilities,
            feature_quality=pred.feature_quality,
            missing_fields=pred.missing_fields,
            imputed_fields=pred.imputed_fields,
            rejected_fields=pred.rejected_fields,
            context=ctx,
            model_version=pred.model_version,
            preprocessing_version=pred.preprocessing_version,
            inference_ms=pred.inference_ms,
            is_partial_flow=pred.is_partial_flow,
            known_attack_model=pred.known_attack_model,
            generalization_warning=pred.generalization_warning,
            error=pred.error,
        )
        result = should_flag_as_attack(pred_with_ctx, confidence_threshold=0.80)
        assert result.is_attack is False
        assert result.context is not None
        assert result.context.flow_id == "192.168.1.1:80-10.0.0.1:443-6"


# ---------------------------------------------------------------------------
# PredictionResult.benign() factory tests
# ---------------------------------------------------------------------------

class TestBenignFactory:
    """Tests for the PredictionResult.benign() factory method."""

    def test_benign_factory_creates_valid_result(self) -> None:
        """benign() should produce a valid BENIGN PredictionResult."""
        result = PredictionResult.benign(
            reason="test bypass",
            context=FlowContext(src_ip="10.0.0.1"),
            model_version="test_model",
        )
        assert result.status == PredictionStatus.BENIGN
        assert result.is_attack is False
        assert result.confidence == 1.0
        assert result.label == "BENIGN"
        assert result.class_probabilities["BENIGN"] == 1.0
        assert result.error == "test bypass"

    def test_benign_factory_to_dict(self) -> None:
        """benign().to_dict() should produce valid JSON-serializable output."""
        result = PredictionResult.benign(reason="ICMP bypass")
        d = result.to_dict()
        assert d["status"] == "BENIGN"
        assert d["is_attack"] is False
        assert d["confidence"] == 1.0
        assert d["label"] == "BENIGN"
        assert d["error"] == "ICMP bypass"


# ---------------------------------------------------------------------------
# PortScanTracker & PortScan detection tests
# ---------------------------------------------------------------------------

class TestPortScanTracker:
    """Tests for stateful PortScan detection."""

    def test_single_port_access_not_flagged(self) -> None:
        """Repeated access to port 443 (Chrome HTTPS) should NOT trigger PortScan."""
        from prediction.filter import PortScanTracker
        tracker = PortScanTracker(time_window=1.5, min_distinct_ports=5)

        # 10 access attempts to port 443 from same IP
        for _ in range(10):
            is_ps, count = tracker.record_and_check("192.168.1.50", 443)
            assert is_ps is False
            assert count == 0

    def test_multi_port_access_flagged(self) -> None:
        """Accessing >= 5 distinct non-standard ports should trigger PortScan."""
        from prediction.filter import PortScanTracker
        tracker = PortScanTracker(time_window=1.5, min_distinct_ports=5)

        ports = [1001, 1002, 1003, 1004, 1005]
        for idx, port in enumerate(ports):
            is_ps, count = tracker.record_and_check("192.168.1.100", port)
            if idx < 4:
                assert is_ps is False
                assert count == idx + 1
            else:
                assert is_ps is True
                assert count == 5

    def test_rule_based_portscan_override(self) -> None:
        """should_flag_as_attack should override BENIGN to PortScan when distinct ports >= 5."""
        from prediction.filter import PortScanTracker
        tracker = PortScanTracker(time_window=1.5, min_distinct_ports=5)

        for idx, port in enumerate([1001, 1002, 1003, 1004, 1005]):
            ctx = FlowContext(
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                src_port=54321,
                dst_port=port,
                protocol=6,
            )
            benign_pred = PredictionResult.benign(reason="test", context=ctx)
            raw = {
                "Total Fwd Packets": 1.0,
                "Total Backward Packets": 0.0,
                "Total Length of Fwd Packets": 0.0,
                "ACK Flag Count": 0.0,
            }
            res = should_flag_as_attack(
                benign_pred,
                confidence_threshold=0.80,
                raw_features=raw,
                port_scan_tracker=tracker,
            )
            if idx < 4:
                assert res.is_attack is False
            else:
                assert res.is_attack is True
                assert res.label == "PortScan"

    def test_cooldown_prevents_alert_flooding(self) -> None:
        """After triggering PortScan, subsequent accesses in cooldown window should return False."""
        from prediction.filter import PortScanTracker
        tracker = PortScanTracker(time_window=1.5, min_distinct_ports=5, cooldown_seconds=5.0)

        # Trigger PortScan on ports 1001..1005 at t=100.0s
        for p in [1001, 1002, 1003, 1004, 1005]:
            is_ps, _ = tracker.record_and_check("192.168.1.100", p, timestamp=100.0)

        assert is_ps is True

        # Packets arriving immediately after during cooldown (t=101.0s)
        for p in range(1006, 1020):
            is_ps_cooldown, _ = tracker.record_and_check("192.168.1.100", p, timestamp=101.0)
            assert is_ps_cooldown is False

        # Access arriving after cooldown expires (at t=106.0s)
        # History was reset, so port 2000 is distinct port #1
        is_ps_after, count = tracker.record_and_check("192.168.1.100", 2000, timestamp=106.0)
        assert is_ps_after is False
        assert count == 1



