"""Flow feature calculator — CICFlowMeter v3 compatible.

Ingests ``PacketRecord`` objects and computes the 40 CICIDS2017 v3 features
required by the intrusion detection model.

Key implementation rules (docs/phase4_feature_contract.md):
- Timing in microseconds.
- TCP flag counts capped at 1 (CICFlowMeter bug parity).
- Population std dev (ddof=0).
- Zero-fill for missing sequences (no NaN/Inf).
- Active/Idle threshold = 1,000,000 us.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from packet_capture.schemas import FlowKey, FlowResult, FlowState, PacketRecord

FEATURE_NAMES: tuple[str, ...] = (
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Min", "Bwd Packet Length Std", "Flow Bytes/s",
    "Flow Packets/s", "Flow IAT Std", "Flow IAT Min", "Fwd IAT Total",
    "Fwd IAT Std", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Std",
    "Bwd IAT Min", "Fwd Header Length", "Bwd Header Length", "Bwd Packets/s",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "FIN Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "Down/Up Ratio", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Idle Mean",
    "Idle Std",
)

_THRESHOLD_US: float = 1_000_000.0
_FLAG_FIN = 0x01
_FLAG_SYN = 0x02
_FLAG_RST = 0x04
_FLAG_PSH = 0x08
_FLAG_ACK = 0x10
_FLAG_URG = 0x20


def _pop_std(vals: list[float]) -> float:
    """Population standard deviation (ddof=0), or 0 for fewer than 2 values."""
    n = len(vals)
    if n < 2:
        return 0.0
    mu = sum(vals) / n
    return math.sqrt(sum((x - mu) ** 2 for x in vals) / n)


def _iat(ts: list[float]) -> list[float]:
    """Consecutive inter-arrival times from a sorted timestamp list."""
    return [ts[i] - ts[i - 1] for i in range(1, len(ts))]


def _mean(vals: list[float]) -> float:
    """Mean or 0.0 for an empty list."""
    return sum(vals) / len(vals) if vals else 0.0


def _active_idle(
    ts: list[float], threshold: float = _THRESHOLD_US
) -> tuple[list[float], list[float]]:
    """CICFlowMeter-style active burst and idle gap computation.

    Args:
        ts: Sorted packet timestamps in microseconds.
        threshold: Gap threshold (us) separating active from idle.

    Returns:
        (active_durations, idle_durations) in microseconds.
    """
    if len(ts) < 2:
        return [], []
    active: list[float] = []
    idle: list[float] = []
    b_start = ts[0]
    b_last = ts[0]
    for t in ts[1:]:
        gap = t - b_last
        if gap < threshold:
            b_last = t
        else:
            dur = b_last - b_start
            if dur > 0:
                active.append(dur)
            idle.append(gap)
            b_start = t
            b_last = t
    dur = b_last - b_start
    if dur > 0:
        active.append(dur)
    return active, idle


@dataclass
class FlowAccumulator:
    """Stateful accumulator for one bidirectional network flow.

    Not thread-safe on its own. The aggregator wraps it with a per-flow lock.

    Args:
        key: Canonical 5-tuple flow key.
    """

    key: FlowKey
    state: FlowState = FlowState.NEW
    initiator_ip: str = ""
    responder_ip: str = ""
    initiator_port: int = 0
    responder_port: int = 0
    _fwd_ts: list[float] = field(default_factory=list)
    _bwd_ts: list[float] = field(default_factory=list)
    _all_ts: list[float] = field(default_factory=list)
    _fwd_pl: list[float] = field(default_factory=list)
    _bwd_pl: list[float] = field(default_factory=list)
    _all_pl: list[float] = field(default_factory=list)
    _fwd_hdr: float = 0.0
    _bwd_hdr: float = 0.0
    _fwd_win: int = 0
    _bwd_win: int = 0
    _fwd_win_seen: bool = False
    _bwd_win_seen: bool = False
    _fwd_data: int = 0
    _fwd_min_off: int = 0xFFFF
    _flags: int = 0
    _fin_forward: bool = False
    _fin_backward: bool = False
    _rst_seen: bool = False

    def ingest(self, pkt: PacketRecord) -> None:
        """Incorporate one packet into accumulated flow state.

        Args:
            pkt: Parsed packet record.
        """
        ts = pkt.timestamp_us
        pl = float(max(pkt.payload_length, 0))
        hdr = float(pkt.ip_header_length + pkt.transport_header_length)

        self._all_ts.append(ts)
        self._all_pl.append(pl)

        if not self.initiator_ip:
            self.initiator_ip = pkt.src_ip
            self.responder_ip = pkt.dst_ip
            self.initiator_port = pkt.src_port
            self.responder_port = pkt.dst_port
        is_fwd = (
            pkt.src_ip == self.initiator_ip
            and pkt.src_port == self.initiator_port
            and pkt.dst_ip == self.responder_ip
            and pkt.dst_port == self.responder_port
        )

        if is_fwd:
            self._fwd_ts.append(ts)
            self._fwd_pl.append(pl)
            self._fwd_hdr += hdr
            if pkt.protocol == 6 and not self._fwd_win_seen:
                self._fwd_win = pkt.tcp_window
                self._fwd_win_seen = True
            if pkt.protocol == 6 and pl >= 1:
                self._fwd_data += 1
            if pkt.protocol == 6 and pkt.tcp_data_offset > 0:
                self._fwd_min_off = min(self._fwd_min_off, pkt.tcp_data_offset)
        else:
            self._bwd_ts.append(ts)
            self._bwd_pl.append(pl)
            self._bwd_hdr += hdr
            if pkt.protocol == 6 and not self._bwd_win_seen:
                self._bwd_win = pkt.tcp_window
                self._bwd_win_seen = True

        self._flags |= pkt.tcp_flags

        if pkt.protocol == 6:
            if self.state == FlowState.NEW and (pkt.tcp_flags & _FLAG_SYN):
                self.state = FlowState.ESTABLISHED
            if pkt.tcp_flags & _FLAG_RST:
                self._rst_seen = True
                self.state = FlowState.CLOSING
            if pkt.tcp_flags & _FLAG_FIN:
                if is_fwd:
                    self._fin_forward = True
                else:
                    self._fin_backward = True
                self.state = FlowState.CLOSING

    def compute_features(self) -> dict[str, float]:
        """Compute all 40 CICIDS2017 v3 model features.

        Returns:
            Dict of feature_name -> float. All values are finite.
        """
        n_fwd = len(self._fwd_ts)
        n_bwd = len(self._bwd_ts)
        n_all = len(self._all_ts)

        dur_us = (self._all_ts[-1] - self._all_ts[0]) if n_all > 1 else 0.0
        dur_s = dur_us / 1_000_000.0

        tfb = float(sum(self._fwd_pl))
        tbb = float(sum(self._bwd_pl))

        fiats = _iat(self._all_ts)
        fwiats = _iat(self._fwd_ts)
        bwiats = _iat(self._bwd_ts)

        act_d, idle_d = _active_idle(self._all_ts)

        fin = 1 if (self._flags & _FLAG_FIN) else 0
        psh = 1 if (self._flags & _FLAG_PSH) else 0
        ack = 1 if (self._flags & _FLAG_ACK) else 0
        urg = 1 if (self._flags & _FLAG_URG) else 0

        return {
            "Destination Port": float(self.responder_port if self.initiator_ip else self.key.port_b),
            "Flow Duration": float(dur_us),
            "Total Fwd Packets": float(n_fwd),
            "Total Backward Packets": float(n_bwd),
            "Total Length of Fwd Packets": tfb,
            "Total Length of Bwd Packets": tbb,
            "Fwd Packet Length Max": float(max(self._fwd_pl)) if n_fwd else 0.0,
            "Fwd Packet Length Min": float(min(self._fwd_pl)) if n_fwd else 0.0,
            "Fwd Packet Length Mean": _mean(self._fwd_pl),
            "Fwd Packet Length Std": _pop_std(self._fwd_pl),
            "Bwd Packet Length Min": float(min(self._bwd_pl)) if n_bwd else 0.0,
            "Bwd Packet Length Std": _pop_std(self._bwd_pl),
            "Flow Bytes/s": (tfb + tbb) / dur_s if dur_s > 0 else 0.0,
            "Flow Packets/s": float(n_all) / dur_s if dur_s > 0 else 0.0,
            "Flow IAT Std": _pop_std(fiats),
            "Flow IAT Min": float(min(fiats)) if fiats else 0.0,
            "Fwd IAT Total": (self._fwd_ts[-1] - self._fwd_ts[0]) if n_fwd >= 2 else 0.0,
            "Fwd IAT Std": _pop_std(fwiats),
            "Fwd IAT Min": float(min(fwiats)) if fwiats else 0.0,
            "Bwd IAT Total": (self._bwd_ts[-1] - self._bwd_ts[0]) if n_bwd >= 2 else 0.0,
            "Bwd IAT Std": _pop_std(bwiats),
            "Bwd IAT Min": float(min(bwiats)) if bwiats else 0.0,
            "Fwd Header Length": self._fwd_hdr,
            "Bwd Header Length": self._bwd_hdr,
            "Bwd Packets/s": float(n_bwd) / dur_s if dur_s > 0 else 0.0,
            "Max Packet Length": float(max(self._all_pl)) if n_all else 0.0,
            "Packet Length Mean": _mean(self._all_pl),
            "Packet Length Std": _pop_std(self._all_pl),
            "FIN Flag Count": float(fin),
            "PSH Flag Count": float(psh),
            "ACK Flag Count": float(ack),
            "URG Flag Count": float(urg),
            "Down/Up Ratio": float(n_bwd) / float(n_fwd) if n_fwd > 0 else 0.0,
            "Init_Win_bytes_forward": float(self._fwd_win),
            "Init_Win_bytes_backward": float(self._bwd_win),
            "act_data_pkt_fwd": float(self._fwd_data),
            "min_seg_size_forward": float(
                self._fwd_min_off * 4 if self._fwd_min_off != 0xFFFF else 0
            ),
            "Active Mean": _mean(act_d),
            "Idle Mean": _mean(idle_d),
            "Idle Std": _pop_std(idle_d),
        }

    def to_flow_result(self) -> FlowResult:
        """Finalise the flow and return a prediction-ready FlowResult.

        Returns:
            FlowResult with features and context metadata.
        """
        n = len(self._all_ts)
        result = FlowResult(
            key=self.key,
            features=self.compute_features(),
            packet_count=n,
            start_timestamp_us=self._all_ts[0] if n else 0.0,
            end_timestamp_us=self._all_ts[-1] if n else 0.0,
            state=self.state,
            initiator_ip=self.initiator_ip,
            responder_ip=self.responder_ip,
            initiator_port=self.initiator_port,
            responder_port=self.responder_port,
        )
        result.context = result.to_context_dict()
        return result

    @property
    def is_terminal(self) -> bool:
        """Return whether TCP termination is complete and immediately evictable."""
        return self._rst_seen or (self._fin_forward and self._fin_backward)

    @property
    def is_half_open(self) -> bool:
        """Return whether this is a half-open SYN-only flow (no backward traffic).

        A half-open flow has:
        - At least 1 forward packet
        - Zero backward packets
        - No RST or FIN flags
        These are typical of SYN floods, port scans, and brute-force attacks
        where the target never responds.

        Returns:
            ``True`` if the flow is half-open (forward-only, no teardown flags).
        """
        return (
            len(self._fwd_ts) > 0
            and len(self._bwd_ts) == 0
            and not self._rst_seen
            and not self._fin_forward
            and not self._fin_backward
        )

    @property
    def last_packet_time(self) -> float:
        """Timestamp of the most recently ingested packet."""
        return self._all_ts[-1] if self._all_ts else 0.0

    @property
    def packet_count(self) -> int:
        """Total number of ingested packets."""
        return len(self._all_ts)
