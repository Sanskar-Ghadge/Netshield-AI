"""NetShield AI v3 intrusion-detection inference engine.

Loads model, preprocessor, label encoder, and metadata once, validates their
compatibility, and exposes thread-safe single and batch prediction APIs.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np

_ENGINE_ROOT = Path(__file__).resolve().parents[1]
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

# preprocessing/ now lives in ml-model/ but is needed at runtime for
# FittedPreprocessor type checking during pickle deserialization.
_ML_MODEL_ROOT = _ENGINE_ROOT.parent / "ml-model"
if str(_ML_MODEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_ML_MODEL_ROOT))

from prediction.schemas import (
    CANONICAL_CLASSES,
    EXPECTED_CLASS_COUNT,
    EXPECTED_FEATURE_COUNT,
    REQUIRED_PREPROCESSING_VERSION,
    FlowContext,
    PredictionResult,
    PredictionStatus,
    _GENERALIZATION_WARNING,
)
from prediction.transform import RuntimePreprocessor

_DEFAULT_MODEL_DIR = _ENGINE_ROOT / "models" / "v3"


class ArtifactPaths:
    """Locations of the required v3 model artifacts.

    Args:
        model: Path to the trained XGBoost model.
        preprocessor: Path to the fitted v3 preprocessor.
        encoder: Path to the fitted v3 label encoder.
        metadata: Path to the v3 JSON metadata.
    """

    def __init__(
        self,
        model: Path | None = None,
        preprocessor: Path | None = None,
        encoder: Path | None = None,
        metadata: Path | None = None,
    ) -> None:
        self.model = Path(model or _DEFAULT_MODEL_DIR / "intrusion_model_v3.pkl")
        self.preprocessor = Path(preprocessor or _DEFAULT_MODEL_DIR / "preprocessor_v3.pkl")
        self.encoder = Path(encoder or _DEFAULT_MODEL_DIR / "label_encoder_v3.pkl")
        self.metadata = Path(metadata or _DEFAULT_MODEL_DIR / "preprocessing_metadata_v3.json")

    def validate(self) -> None:
        """Raise FileNotFoundError when one or more artifacts are missing."""
        missing = [
            str(path)
            for path in (self.model, self.preprocessor, self.encoder, self.metadata)
            if not path.is_file()
        ]
        if missing:
            raise FileNotFoundError(f"Missing v3 artifacts: {missing}")


class IntrusionPredictor:
    """Thread-safe predictor using the validated NetShield AI v3 artifacts.

    Args:
        paths: Optional paths overriding the default ``models/v3`` artifacts.

    Raises:
        FileNotFoundError: If a required artifact is missing.
        ValueError: If artifacts are version, class, or feature incompatible.
    """

    def __init__(self, paths: ArtifactPaths | None = None) -> None:
        self._paths = paths or ArtifactPaths()
        self._paths.validate()
        self._model = joblib.load(self._paths.model)
        self._runtime_preprocessor = RuntimePreprocessor(
            joblib.load(self._paths.preprocessor)
        )
        self._encoder = joblib.load(self._paths.encoder)
        with self._paths.metadata.open("r", encoding="utf-8") as handle:
            self._metadata: dict[str, Any] = json.load(handle)
        self._validate_compatibility()
        self._class_names = [str(value) for value in self._encoder.classes_]
        self._model_version = str(
            self._metadata.get("deployment_model", {}).get(
                "artifact", self._paths.model.name
            )
        )
        self._version = int(self._metadata["version"])
        self._lock = threading.Lock()

    def _validate_compatibility(self) -> None:
        """Validate artifact versions, classes, and input dimensions.

        Raises:
            ValueError: If any artifact does not match the v3 contract.
        """
        metadata = self._metadata
        if metadata.get("version") != REQUIRED_PREPROCESSING_VERSION:
            raise ValueError("Metadata is not preprocessing version 3")
        if metadata.get("phase3_status") != "COMPLETE":
            raise ValueError("Phase 3 is incomplete; refusing to predict")
        if metadata.get("leakage_safe") is not True:
            raise ValueError("Metadata is not marked leakage-safe")
        if tuple(str(x) for x in self._encoder.classes_) != CANONICAL_CLASSES:
            raise ValueError("Label encoder classes do not match v3 contract")
        if len(self._encoder.classes_) != EXPECTED_CLASS_COUNT:
            raise ValueError("Label encoder does not contain nine classes")
        selected = metadata.get("selected_features", [])
        if len(selected) != EXPECTED_FEATURE_COUNT:
            raise ValueError("Metadata does not contain forty selected features")
        if self._runtime_preprocessor.selected_features != selected:
            raise ValueError("Preprocessor selected feature order differs from metadata")
        if hasattr(self._model, "n_features_in_") and self._model.n_features_in_ != EXPECTED_FEATURE_COUNT:
            raise ValueError("Model input dimension differs from v3 feature count")
        if hasattr(self._model, "n_classes_") and self._model.n_classes_ != EXPECTED_CLASS_COUNT:
            raise ValueError("Model class count differs from v3 class count")

    @property
    def class_names(self) -> list[str]:
        """Return model output class names in encoded order."""
        return list(self._class_names)

    def predict_one(
        self,
        features: Mapping[str, Any],
        *,
        context: FlowContext | None = None,
        is_partial_flow: bool = False,
    ) -> PredictionResult:
        """Transform and classify one raw CICIDS2017-style flow mapping.

        Args:
            features: Raw feature name-to-value mapping.
            context: Optional flow metadata from the capture layer.
            is_partial_flow: Whether the flow is an early snapshot.

        Returns:
            A prediction or a REJECTED diagnostic result.
        """
        return self.predict_batch(
            [features], contexts=[context], is_partial_flow=is_partial_flow
        )[0]

    def predict_batch(
        self,
        rows: Sequence[Mapping[str, Any]],
        *,
        contexts: Sequence[FlowContext | None] | None = None,
        is_partial_flow: bool = False,
    ) -> list[PredictionResult]:
        """Transform and classify a batch of raw flow mappings.

        Args:
            rows: Raw CICIDS2017-style flow mappings.
            contexts: Optional same-length flow-context sequence.
            is_partial_flow: Whether all flows are early snapshots.

        Returns:
            One PredictionResult for every input row.

        Raises:
            ValueError: If contexts has a different length than rows.
        """
        if not rows:
            return []
        context_list = list(contexts) if contexts is not None else [None] * len(rows)
        if len(context_list) != len(rows):
            raise ValueError("contexts length must match rows length")

        # Pre-filter: None rows are rejected before reaching the transformer.
        none_indices = {i for i, r in enumerate(rows) if r is None}
        if none_indices:
            non_none_rows = [r for i, r in enumerate(rows) if i not in none_indices]
            non_none_ctx = [c for i, c in enumerate(context_list) if i not in none_indices]
        else:
            non_none_rows = list(rows)
            non_none_ctx = context_list

        transformed = self._runtime_preprocessor.transform_batch(non_none_rows)
        valid_indices = [
            index for index, result in enumerate(transformed)
            if result.success and result.scaled_vector is not None
        ]
        probabilities: np.ndarray | None = None
        inference_ms = 0.0
        if valid_indices:
            matrix = np.stack(
                [transformed[index].scaled_vector for index in valid_indices]
            ).astype(np.float32)
            started = time.perf_counter()
            with self._lock:
                probabilities = np.asarray(self._model.predict_proba(matrix), dtype=np.float64)
            inference_ms = (time.perf_counter() - started) * 1000.0 / len(valid_indices)

        output: list[PredictionResult] = []
        prediction_cursor = 0
        transform_cursor = 0
        for index in range(len(rows)):
            context = context_list[index]
            if index in none_indices:
                output.append(
                    PredictionResult.rejected(
                        "Input row is None",
                        context=context,
                        model_version=self._model_version,
                        preprocessing_version=self._version,
                        rejected_fields=(),
                    )
                )
                continue
            transform = transformed[transform_cursor]
            transform_cursor += 1
            if not transform.success:
                output.append(
                    PredictionResult.rejected(
                        transform.error or "Feature transformation failed",
                        context=context,
                        model_version=self._model_version,
                        preprocessing_version=self._version,
                        rejected_fields=transform.rejected_fields,
                    )
                )
                continue

            assert probabilities is not None
            row_probabilities = probabilities[prediction_cursor]
            prediction_cursor += 1
            class_id = int(np.argmax(row_probabilities))
            label = self._class_names[class_id]
            is_attack = label != "BENIGN"
            output.append(
                PredictionResult(
                    timestamp_utc=time.time(),
                    status=PredictionStatus.ATTACK if is_attack else PredictionStatus.BENIGN,
                    class_id=class_id,
                    label=label,
                    is_attack=is_attack,
                    confidence=float(row_probabilities[class_id]),
                    class_probabilities={
                        name: float(probability)
                        for name, probability in zip(self._class_names, row_probabilities)
                    },
                    feature_quality=transform.feature_quality,
                    missing_fields=transform.missing_fields,
                    imputed_fields=transform.imputed_fields,
                    rejected_fields=transform.rejected_fields,
                    context=context,
                    model_version=self._model_version,
                    preprocessing_version=self._version,
                    inference_ms=inference_ms,
                    is_partial_flow=is_partial_flow,
                    known_attack_model=True,
                    generalization_warning=_GENERALIZATION_WARNING,
                    error="",
                )
            )
        return output


def main() -> None:
    """Load artifacts and print predictor readiness information."""
    predictor = IntrusionPredictor()
    print("NetShield AI v3 predictor ready")
    print(f"Classes: {predictor.class_names}")


if __name__ == "__main__":
    main()
