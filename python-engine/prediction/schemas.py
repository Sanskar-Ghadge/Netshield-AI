"""Dataclasses and enumerations for the NetShield AI v3 prediction pipeline.

These types are framework-independent and serializable. They form the
interface between the inference engine and any consuming code (FastAPI,
tests, CLI).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Version that the runtime preprocessor and predictor must see in metadata.
REQUIRED_PREPROCESSING_VERSION: int = 3
#: Expected number of features after the full v3 preprocessing pipeline.
EXPECTED_FEATURE_COUNT: int = 40
#: Expected number of classes produced by the model.
EXPECTED_CLASS_COUNT: int = 9
#: Canonical ordered class names (must match label_encoder_v3.pkl).
CANONICAL_CLASSES: tuple[str, ...] = (
    "BENIGN",
    "Bot",
    "BruteForce",
    "DDoS",
    "DoS",
    "Heartbleed",
    "Infiltration",
    "PortScan",
    "WebAttack",
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PredictionStatus(str, Enum):
    """High-level status of a single prediction.

    Attributes:
        BENIGN: The model predicts normal traffic.
        ATTACK: The model predicts one of the eight attack classes.
        REJECTED: The input could not be transformed to a valid feature
            vector. No prediction was attempted.
    """

    BENIGN = "BENIGN"
    ATTACK = "ATTACK"
    REJECTED = "REJECTED"


class FeatureQuality(str, Enum):
    """Data completeness of the input feature vector.

    Attributes:
        COMPLETE: All 75 raw input features were present and valid.
        PARTIAL: Some features were missing and replaced by training medians.
        DEGRADED: A significant number of features were missing.
        INVALID: The input could not be mapped to any usable feature vector.
    """

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    DEGRADED = "DEGRADED"
    INVALID = "INVALID"


# ---------------------------------------------------------------------------
# Flow context
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FlowContext:
    """Optional metadata attached to a prediction request by the flow layer.

    Attributes:
        flow_id: Unique identifier of the originating network flow.
        src_ip: Source IP address string.
        dst_ip: Destination IP address string.
        src_port: Source port (0 for protocols without ports).
        dst_port: Destination port (0 for protocols without ports).
        protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP).
        total_packets: Total packets in the flow at prediction time.
        flow_duration_us: Flow duration in microseconds.
        is_completed: True if the flow ended normally.
    """

    flow_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    total_packets: int = 0
    flow_duration_us: float = 0.0
    is_completed: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "total_packets": self.total_packets,
            "flow_duration_us": self.flow_duration_us,
            "is_completed": self.is_completed,
        }


# ---------------------------------------------------------------------------
# Transform result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransformResult:
    """Outcome of applying the v3 runtime preprocessor to raw input features.

    Attributes:
        success: True if transformation produced a valid float32 vector.
        scaled_vector: numpy float32 array shape (40,), or None on failure.
        feature_quality: Data completeness assessment.
        missing_fields: Input fields absent from the raw mapping.
        imputed_fields: Fields filled by training-set median.
        rejected_fields: Fields that were invalid and could not be imputed.
        error: Human-readable error message when success is False.
    """

    success: bool
    scaled_vector: Any = None
    feature_quality: FeatureQuality = FeatureQuality.COMPLETE
    missing_fields: tuple[str, ...] = ()
    imputed_fields: tuple[str, ...] = ()
    rejected_fields: tuple[str, ...] = ()
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary (excludes numpy array)."""
        return {
            "success": self.success,
            "feature_quality": self.feature_quality.value,
            "missing_fields": list(self.missing_fields),
            "imputed_fields": list(self.imputed_fields),
            "rejected_fields": list(self.rejected_fields),
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Prediction result
# ---------------------------------------------------------------------------

_GENERALIZATION_WARNING = (
    "This model was trained on a closed set of known attack types. "
    "Cross-attack evaluation detected only 2.17% of entirely unseen "
    "attack classes. Do not treat high confidence as reliable novelty "
    "detection."
)


@dataclass(frozen=True)
class PredictionResult:
    """Complete result of one intrusion-detection prediction.

    Attributes:
        timestamp_utc: Unix epoch (seconds) when prediction was generated.
        status: BENIGN, ATTACK, or REJECTED.
        class_id: Encoded class index (-1 when rejected).
        label: Human-readable class name.
        is_attack: True when status is ATTACK.
        confidence: Probability of the predicted class (0–1).
        class_probabilities: Mapping of each class name to its probability.
        feature_quality: Input data completeness.
        missing_fields: Fields absent from raw input.
        imputed_fields: Fields replaced by training-set median.
        rejected_fields: Fields that were invalid.
        context: Optional FlowContext supplied by the capture layer.
        model_version: Artifact identifier string.
        preprocessing_version: Version of the preprocessing pipeline.
        inference_ms: Wall-clock inference time in milliseconds.
        is_partial_flow: True when the flow had not yet closed.
        known_attack_model: Always True; closed-set classifier.
        generalization_warning: Limitation description.
        error: Non-empty only when status is REJECTED.
    """

    timestamp_utc: float
    status: PredictionStatus
    class_id: int
    label: str
    is_attack: bool
    confidence: float
    class_probabilities: dict[str, float]
    feature_quality: FeatureQuality
    missing_fields: tuple[str, ...]
    imputed_fields: tuple[str, ...]
    rejected_fields: tuple[str, ...]
    context: FlowContext | None
    model_version: str
    preprocessing_version: int
    inference_ms: float
    is_partial_flow: bool
    known_attack_model: bool
    generalization_warning: str
    error: str

    @classmethod
    def rejected(
        cls,
        reason: str,
        context: FlowContext | None = None,
        model_version: str = "",
        preprocessing_version: int = 3,
        rejected_fields: tuple[str, ...] = (),
    ) -> "PredictionResult":
        """Create a REJECTED result for an input that could not be processed.

        Args:
            reason: Human-readable explanation of the rejection.
            context: Optional flow context.
            model_version: Model artifact identifier.
            preprocessing_version: Preprocessing pipeline version.
            rejected_fields: Fields that caused the rejection.

        Returns:
            A PredictionResult with status REJECTED and no class prediction.
        """
        return cls(
            timestamp_utc=time.time(),
            status=PredictionStatus.REJECTED,
            class_id=-1,
            label="REJECTED",
            is_attack=False,
            confidence=0.0,
            class_probabilities={c: 0.0 for c in CANONICAL_CLASSES},
            feature_quality=FeatureQuality.INVALID,
            missing_fields=(),
            imputed_fields=(),
            rejected_fields=rejected_fields,
            context=context,
            model_version=model_version,
            preprocessing_version=preprocessing_version,
            inference_ms=0.0,
            is_partial_flow=False,
            known_attack_model=True,
            generalization_warning=_GENERALIZATION_WARNING,
            error=reason,
        )

    @classmethod
    def benign(
        cls,
        reason: str = "",
        context: FlowContext | None = None,
        model_version: str = "",
        preprocessing_version: int = 3,
    ) -> "PredictionResult":
        """Create a BENIGN result without running the model.

        Used for traffic that should bypass the ML model entirely because
        the model cannot meaningfully classify it — e.g. ICMP pings, DHCP
        broadcasts, IGMP, and multicast traffic that lack the TCP/UDP flow
        semantics the model was trained on.

        Args:
            reason: Human-readable explanation of why the flow was
                short-circuited (e.g. "ICMP bypass").
            context: Optional flow context from the capture layer.
            model_version: Model artifact identifier.
            preprocessing_version: Preprocessing pipeline version.

        Returns:
            A PredictionResult with status BENIGN, confidence 1.0, and
            full class probabilities (BENIGN=1.0, all others 0.0).
        """
        probs = {c: 0.0 for c in CANONICAL_CLASSES}
        probs["BENIGN"] = 1.0
        return cls(
            timestamp_utc=time.time(),
            status=PredictionStatus.BENIGN,
            class_id=0,
            label="BENIGN",
            is_attack=False,
            confidence=1.0,
            class_probabilities=probs,
            feature_quality=FeatureQuality.COMPLETE,
            missing_fields=(),
            imputed_fields=(),
            rejected_fields=(),
            context=context,
            model_version=model_version,
            preprocessing_version=preprocessing_version,
            inference_ms=0.0,
            is_partial_flow=False,
            known_attack_model=True,
            generalization_warning=_GENERALIZATION_WARNING,
            error=reason,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation.

        Returns:
            Dictionary with all prediction fields.
        """
        return {
            "timestamp_utc": self.timestamp_utc,
            "status": self.status.value,
            "class_id": self.class_id,
            "label": self.label,
            "is_attack": self.is_attack,
            "confidence": round(self.confidence, 6),
            "class_probabilities": {
                k: round(v, 6) for k, v in self.class_probabilities.items()
            },
            "feature_quality": self.feature_quality.value,
            "missing_fields": list(self.missing_fields),
            "imputed_fields": list(self.imputed_fields),
            "rejected_fields": list(self.rejected_fields),
            "context": self.context.to_dict() if self.context else None,
            "model_version": self.model_version,
            "preprocessing_version": self.preprocessing_version,
            "inference_ms": round(self.inference_ms, 4),
            "is_partial_flow": self.is_partial_flow,
            "known_attack_model": self.known_attack_model,
            "generalization_warning": self.generalization_warning,
            "error": self.error,
        }
