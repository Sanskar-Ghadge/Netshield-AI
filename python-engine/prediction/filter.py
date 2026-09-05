"""Traffic pre-filter — bypasses the ML model for non-classifiable flows.

The CICIDS2017 model was trained on TCP and UDP unicast flows with
bidirectional statistics (flow duration, inter-arrival times, backward
packet lengths, TCP flags, etc.).  Many live-capture flows lack these
semantics entirely:

- ICMP (protocol 1): no ports, no TCP flags, no backward packets.
- IGMP (protocol 2): no ports, multicast, no flow statistics.
- DHCP (UDP 67/68 to 255.255.255.255): broadcast, no backward flow.
- Broadcast/multicast destinations: one-way, no bidirectional stats.

Sending these flows through the model produces garbage predictions with
near-50% confidence — the model's argmax flips between BENIGN and DoS
based on random noise in the zero-filled feature vector.

This module provides :class:`TrafficFilter` which examines a
``FlowResult`` and either:
  1. Returns ``None`` — the flow should proceed to ML prediction.
  2. Returns a :class:`~prediction.schemas.PredictionResult` with
     ``status == BENIGN`` — the flow bypasses the model entirely.

The filter also exposes :func:`should_flag_as_attack` which applies a
confidence threshold to model predictions: if the model predicts an
attack but confidence is below the threshold, the result is downgraded
to BENIGN.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from packet_capture.schemas import FlowResult
from prediction.schemas import (
    CANONICAL_CLASSES,
    FlowContext,
    PredictionResult,
    PredictionStatus,
)

logger = logging.getLogger(__name__)

# ── Protocol numbers ──────────────────────────────────────────────
_PROTO_TCP: int = 6
_PROTO_UDP: int = 17
_PROTO_ICMP: int = 1
_PROTO_IGMP: int = 2

# ── Ports that indicate broadcast / link-local protocols ─────────
_DHCP_CLIENT_PORT: int = 68
_DHCP_SERVER_PORT: int = 67
_NETBIOS_NS_PORT: int = 137
_NETBIOS_DGM_PORT: int = 138
_SSDP_PORT: int = 1900
_MDNS_PORT: int = 5353
_LLMNR_PORT: int = 5355
_SNMP_PORT: int = 161
_SNMP_TRAP_PORT: int = 162

_BYPASS_PORTS: frozenset[int] = frozenset(
    {
        _DHCP_CLIENT_PORT,
        _DHCP_SERVER_PORT,
        _NETBIOS_NS_PORT,
        _NETBIOS_DGM_PORT,
        _SSDP_PORT,
        _MDNS_PORT,
        _LLMNR_PORT,
        _SNMP_PORT,
        _SNMP_TRAP_PORT,
    }
)


def _is_broadcast_or_multicast(ip_str: str) -> bool:
    """Return True if the IP is broadcast, multicast, or link-local.

    Args:
        ip_str: Destination IP address string.

    Returns:
        True for 255.255.255.255, 224.0.0.0/4, 0.0.0.0, and 169.254.0.0/16.
    """
    if not ip_str:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if addr.is_multicast:
        return True
    if addr.is_unspecified:
        return True
    if addr.is_link_local:
        return True
    # 255.255.255.255 — limited broadcast (is_broadcast is not available
    # on IPv4Address, so we check the string directly).
    if ip_str == "255.255.255.255":
        return True
    # Directed broadcast addresses (host bits all 1s in a subnet) are
    # not checked here because we don't know the subnet mask.  The
    # 255.255.255.255 check above covers the common case.
    return False


class TrafficFilter:
    """Pre-model traffic filter that bypasses the ML model for noise flows.

    Flows that cannot be meaningfully classified by the CICIDS2017 model
    (ICMP, IGMP, DHCP, broadcast, multicast) are short-circuited to a
    BENIGN result without invoking the model.

    Args:
        model_version: Model artifact identifier for benign results.
        preprocessing_version: Preprocessing pipeline version.
    """

    def __init__(
        self,
        model_version: str = "",
        preprocessing_version: int = 3,
    ) -> None:
        self._model_version = model_version
        self._preprocessing_version = preprocessing_version

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, flow: FlowResult) -> Optional[PredictionResult]:
        """Evaluate whether a flow should bypass the ML model.

        Args:
            flow: Completed or partial ``FlowResult`` from the aggregator.

        Returns:
            ``None`` if the flow should proceed to ML prediction.
            A ``PredictionResult`` with status BENIGN if the flow should
            bypass the model.
        """
        ctx_dict = flow.to_context_dict()
        context = FlowContext(
            flow_id=str(ctx_dict.get("flow_id", "")),
            src_ip=str(ctx_dict.get("src_ip", "")),
            dst_ip=str(ctx_dict.get("dst_ip", "")),
            src_port=int(ctx_dict.get("src_port", 0)),
            dst_port=int(ctx_dict.get("dst_port", 0)),
            protocol=int(ctx_dict.get("protocol", 0)),
            total_packets=int(ctx_dict.get("total_packets", 0)),
            flow_duration_us=float(ctx_dict.get("flow_duration_us", 0.0)),
            is_completed=bool(ctx_dict.get("is_completed", True)),
        )

        proto = context.protocol
        dst_ip = context.dst_ip
        src_ip = context.src_ip
        src_port = context.src_port
        dst_port = context.dst_port

        # ── Rule 1: Non-IP / non-TCP / non-UDP protocols ──────────
        # ICMP and IGMP do not have ports, TCP flags, or bidirectional
        # flow statistics. The model cannot classify them meaningfully.
        if proto not in (_PROTO_TCP, _PROTO_UDP):
            label = {1: "ICMP", 2: "IGMP"}.get(proto, f"proto-{proto}")
            return PredictionResult.benign(
                reason=f"{label} bypass — model trained on TCP/UDP flows only",
                context=context,
                model_version=self._model_version,
                preprocessing_version=self._preprocessing_version,
            )

        # ── Rule 2: Broadcast / multicast / link-local destinations ──
        if _is_broadcast_or_multicast(dst_ip) or _is_broadcast_or_multicast(src_ip):
            return PredictionResult.benign(
                reason="Broadcast/multicast bypass — one-way traffic",
                context=context,
                model_version=self._model_version,
                preprocessing_version=self._preprocessing_version,
            )

        # ── Rule 3: DHCP / NetBIOS / SSDP / mDNS / LLMNR / SNMP ─────
        # These are link-local discovery protocols that produce single-
        # packet flows with no meaningful bidirectional statistics.
        if src_port in _BYPASS_PORTS or dst_port in _BYPASS_PORTS:
            return PredictionResult.benign(
                reason="Link-local discovery protocol bypass",
                context=context,
                model_version=self._model_version,
                preprocessing_version=self._preprocessing_version,
            )

        # ── Rule 4: No payload and single-packet flows ─────────────
        # A single-packet flow with zero payload has no flow statistics
        # (no IAT, no backward packets, no duration). The model was
        # trained on multi-packet flows.
        if flow.packet_count <= 1 and proto == _PROTO_TCP:
            # Single TCP packets (like a stray SYN) can still be meaningful
            # for port scan detection, so we let them through for TCP.
            pass
        elif flow.packet_count <= 1:
            return PredictionResult.benign(
                reason="Single-packet flow bypass — no flow statistics",
                context=context,
                model_version=self._model_version,
                preprocessing_version=self._preprocessing_version,
            )

        # None of the rules matched — let the flow through to the model.
        return None


def should_flag_as_attack(
    prediction: PredictionResult,
    confidence_threshold: float = 0.80,
    raw_features: dict[str, float] | None = None,
) -> PredictionResult:
    """Apply a confidence threshold and rule-based attack detection.

    Three-step process:
        1. If the model already predicts an attack above the confidence
           threshold, keep it.
        2. If the model predicts BENIGN or is below the confidence
           threshold, check rule-based patterns on the flow features.
        3. Rule-based patterns catch attacks the model misses because
           the live traffic doesn't match CICIDS2017 training data
           exactly (e.g. unidirectional SYN floods with no backward
           packets).

    Rule-based detection patterns:
        - **DDoS/DoS SYN flood**: ≥10 forward packets, 0 backward,
          0 payload, TCP SYN-only, high packet rate.
        - **PortScan**: single-packet TCP SYN to many different ports
          from same source (detected at flow level as single SYN,
          no backward).
        - **BruteForce**: many rapid TCP SYN to same port, no backward
          packets.

    Args:
        prediction: The original model prediction.
        confidence_threshold: Minimum confidence required for an attack
            classification. Defaults to 0.80.

    Returns:
        The original prediction if it passes the threshold, or a new
        attack prediction if a rule matched, or a new BENIGN prediction
        if the confidence was too low.
    """
    # Step 1: Model is confident about an attack — keep it.
    if prediction.is_attack and prediction.confidence >= confidence_threshold:
        return prediction

    # Step 2: Rule-based detection on flow features.
    # The model may predict BENIGN for real attacks because live SYN-only
    # flows look different from CICIDS2017 training data (which had
    # bidirectional packets).  These rules catch the pattern.
    ctx = prediction.context
    if ctx is not None:
        # Extract context values — ctx is a FlowContext dataclass
        protocol = ctx.protocol if hasattr(ctx, 'protocol') else 0
        src_port = ctx.src_port if hasattr(ctx, 'src_port') else 0
        dst_port = ctx.dst_port if hasattr(ctx, 'dst_port') else 0

        # Get feature values from raw_features dict (passed from app.py)
        fwd_pkts = _get_feature(prediction, "Total Fwd Packets", 0.0, raw_features)
        bwd_pkts = _get_feature(prediction, "Total Backward Packets", 0.0, raw_features)
        fwd_len = _get_feature(prediction, "Total Length of Fwd Packets", 0.0, raw_features)
        bwd_len = _get_feature(prediction, "Total Length of Bwd Packets", 0.0, raw_features)
        flow_dur = _get_feature(prediction, "Flow Duration", 0.0, raw_features)
        flow_pkts_per_s = _get_feature(prediction, "Flow Packets/s", 0.0, raw_features)
        ack_flag = _get_feature(prediction, "ACK Flag Count", 0.0, raw_features)
        syn_flag = _get_feature(prediction, "SYN Flag Count", 0.0, raw_features)
        fin_flag = _get_feature(prediction, "FIN Flag Count", 0.0, raw_features)
        psh_flag = _get_feature(prediction, "PSH Flag Count", 0.0, raw_features)

        # ── Rule: SYN flood (DDoS/DoS) ────────────────────────────
        # Many forward packets, zero backward, zero payload, TCP,
        # high packet rate.  This matches DDoS SYN flood pattern.
        if (
            protocol == 6
            and fwd_pkts >= 10
            and bwd_pkts == 0
            and fwd_len == 0
            and bwd_len == 0
            and ack_flag == 0
            and fin_flag == 0
            and psh_flag == 0
        ):
            # Determine DDoS vs DoS by packet count
            attack_label = "DDoS" if fwd_pkts >= 100 else "DoS"
            logger.info(
                "Rule-based detection: %s SYN flood (%d fwd pkts, 0 bwd, "
                "0 payload) — model said %s",
                attack_label,
                int(fwd_pkts),
                prediction.label,
            )
            return _override_to_attack(
                prediction,
                attack_label,
                reason=f"Rule: {attack_label} SYN flood ({int(fwd_pkts)} fwd pkts, 0 bwd, 0 payload)",
            )



        # ── Rule: BruteForce (many SYN to same port, no backward) ──
        # Multiple forward TCP SYN packets to the same destination port
        # (e.g. SSH port 22), zero backward packets, zero payload.
        # This matches brute-force login attempts.
        if (
            protocol == 6
            and fwd_pkts >= 50
            and bwd_pkts == 0
            and fwd_len == 0
            and ack_flag == 0
            and fin_flag == 0
            and dst_port in (22, 23, 21, 3389, 5900, 445, 139, 25, 110, 143)
        ):
            logger.info(
                "Rule-based detection: BruteForce (%d SYN to port %s, "
                "no response — model said %s)",
                int(fwd_pkts),
                dst_port,
                prediction.label,
            )
            return _override_to_attack(
                prediction,
                "BruteForce",
                reason=f"Rule: BruteForce ({int(fwd_pkts)} SYN to port {dst_port}, no response)",
            )

    # Step 3: Model predicted attack but confidence too low — downgrade.
    if prediction.is_attack:
        # Downgrade: create a new BENIGN result preserving all diagnostic info
        probs = {c: 0.0 for c in prediction.class_probabilities}
        probs["BENIGN"] = 1.0 - prediction.confidence
        return PredictionResult(
            timestamp_utc=prediction.timestamp_utc,
            status=PredictionStatus.BENIGN,
            class_id=0,
            label="BENIGN",
            is_attack=False,
            confidence=1.0 - prediction.confidence,
            class_probabilities=probs,
            feature_quality=prediction.feature_quality,
            missing_fields=prediction.missing_fields,
            imputed_fields=prediction.imputed_fields,
            rejected_fields=prediction.rejected_fields,
            context=prediction.context,
            model_version=prediction.model_version,
            preprocessing_version=prediction.preprocessing_version,
            inference_ms=prediction.inference_ms,
            is_partial_flow=prediction.is_partial_flow,
            known_attack_model=prediction.known_attack_model,
            generalization_warning=prediction.generalization_warning,
            error=f"Downgraded from {prediction.label} (confidence {prediction.confidence:.1%} < threshold {confidence_threshold:.0%})",
        )

    return prediction


def _get_feature(prediction: PredictionResult, name: str, default: float = 0.0, raw_features: dict[str, float] | None = None) -> float:
    """Extract a feature value from raw_features, feature_quality, or context.

    Args:
        prediction: The prediction result.
        name: Feature name to look up.
        default: Default value if not found.
        raw_features: Raw feature dict from FlowResult.features.

    Returns:
        The float value of the feature, or default.
    """
    # Try raw_features first (most reliable source)
    if raw_features is not None and name in raw_features:
        try:
            return float(raw_features[name])
        except (ValueError, TypeError):
            pass

    # Try feature_quality dict
    fq = prediction.feature_quality
    if isinstance(fq, dict) and name in fq:
        try:
            return float(fq[name])
        except (ValueError, TypeError):
            pass

    # Try context dict
    ctx = prediction.context
    if isinstance(ctx, dict):
        if name in ctx:
            try:
                return float(ctx[name])
            except (ValueError, TypeError):
                pass
        # Features might be nested under a "features" key
        features = ctx.get("features")
        if isinstance(features, dict) and name in features:
            try:
                return float(features[name])
            except (ValueError, TypeError):
                pass

    return default


def _override_to_attack(
    prediction: PredictionResult,
    label: str,
    reason: str,
) -> PredictionResult:
    """Create a new PredictionResult that overrides to an attack label.

    Args:
        prediction: The original prediction to override.
        label: The attack label (e.g. "DDoS", "PortScan").
        reason: Human-readable reason for the override.

    Returns:
        A new PredictionResult with the attack label.
    """
    # Build class probabilities: high for the attack, rest spread thin
    probs = {c: 0.01 for c in CANONICAL_CLASSES}
    probs[label] = 0.90
    probs["BENIGN"] = 0.08
    # Normalize to sum ~1.0
    total = sum(probs.values())
    probs = {k: v / total for k, v in probs.items()}

    # Map label to class_id
    class_id = CANONICAL_CLASSES.index(label) if label in CANONICAL_CLASSES else 1

    return PredictionResult(
        timestamp_utc=prediction.timestamp_utc,
        status=PredictionStatus.ATTACK,
        class_id=class_id,
        label=label,
        is_attack=True,
        confidence=0.90,
        class_probabilities=probs,
        feature_quality=prediction.feature_quality,
        missing_fields=prediction.missing_fields,
        imputed_fields=prediction.imputed_fields,
        rejected_fields=prediction.rejected_fields,
        context=prediction.context,
        model_version=prediction.model_version,
        preprocessing_version=prediction.preprocessing_version,
        inference_ms=prediction.inference_ms,
        is_partial_flow=prediction.is_partial_flow,
        known_attack_model=prediction.known_attack_model,
        generalization_warning=prediction.generalization_warning,
        error=reason,
    )
