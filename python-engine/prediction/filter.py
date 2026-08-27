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
) -> PredictionResult:
    """Apply a confidence threshold to an attack prediction.

    If the model predicts an attack but confidence is below the threshold,
    the result is downgraded to BENIGN. This prevents the model from
    flagging normal traffic as an attack when it is essentially guessing
    (confidence near 50%).

    The original :class:`PredictionResult` is frozen/immutable, so a new
    instance is created when downgrading.

    Args:
        prediction: The original model prediction.
        confidence_threshold: Minimum confidence required for an attack
            classification. Defaults to 0.80.

    Returns:
        The original prediction if it passes the threshold, or a new
        BENIGN prediction if the confidence was too low.
    """
    if not prediction.is_attack:
        return prediction
    if prediction.confidence >= confidence_threshold:
        return prediction

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
