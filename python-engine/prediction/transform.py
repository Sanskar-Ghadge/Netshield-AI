"""Runtime v3 preprocessing — exact inference-time replica of the training pipeline.

Transformation sequence (must match v3 training exactly):
  1. Validate and order the 75 raw input features.
  2. Replace invalid/out-of-domain values with NaN.
  3. Drop training all-null columns.
  4. Impute missing values with training-fitted medians.
  5. Drop training constant columns.
  6. Apply log1p to fitted log columns.
  7. Clip to fitted 0.1%/99.9% quantile bounds.
  8. Drop fitted correlated columns.
  9. Apply the fitted SelectKBest selector.
  10. Apply the fitted RobustScaler.
  11. Validate a finite float32 (40,) vector.

All parameters come from preprocessor_v3.pkl — nothing is recomputed.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

_ENGINE_ROOT = Path(__file__).resolve().parents[1]
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

# preprocessing/ now lives in ml-model/ but is needed at runtime for
# FittedPreprocessor type checking during pickle deserialization.
_ML_MODEL_ROOT = _ENGINE_ROOT.parent / "ml-model"
if str(_ML_MODEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_ML_MODEL_ROOT))

from preprocessing.preprocessor_types import FittedPreprocessor
from prediction.schemas import EXPECTED_FEATURE_COUNT, FeatureQuality, TransformResult

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# Fraction of raw input features that may be missing before the result
# is classified DEGRADED rather than PARTIAL.
_DEGRADED_FRACTION: float = 0.20

# Features where negative values are physically impossible and must be
# treated as missing (imputed from the training median).
_NON_NEGATIVE_FEATURES: frozenset[str] = frozenset(
    {
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        "Bwd Packet Length Max",
        "Bwd Packet Length Min",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Std",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Fwd Header Length",
        "Bwd Header Length",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Max Packet Length",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        "Average Packet Size",
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        "Subflow Fwd Bytes",
        "Subflow Bwd Bytes",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
    }
)

# Port number features: must be integers in [0, 65535].
_PORT_FEATURES: frozenset[str] = frozenset({"Source Port", "Destination Port"})


# ---------------------------------------------------------------------------
# Scalar parsing
# ---------------------------------------------------------------------------


def _to_float(raw: Any) -> float | None:
    """Convert a raw value to a finite float, or return None.

    Accepts int, float, bool, and numeric strings. Returns None for None,
    NaN, infinity, non-numeric strings, and any other type.

    Args:
        raw: Value from the raw feature mapping.

    Returns:
        Finite float, or None when the value cannot be used.
    """
    if raw is None:
        return None
    if isinstance(raw, bool):
        return float(raw)  # True→1.0, False→0.0
    if isinstance(raw, (int, float)):
        if math.isnan(raw) or math.isinf(raw):
            return None
        return float(raw)
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        try:
            value = float(stripped)
            if math.isnan(value) or math.isinf(value):
                return None
            return value
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# RuntimePreprocessor
# ---------------------------------------------------------------------------


class RuntimePreprocessor:
    """Applies the exact v3 training transformation sequence at inference time.

    Wraps a ``FittedPreprocessor`` loaded from ``preprocessor_v3.pkl`` and
    exposes a clean API for single-flow and batch transformation. The
    underlying artifact is read-only and safe to share across threads.

    Args:
        preprocessor: Deserialized FittedPreprocessor artifact.

    Raises:
        TypeError: If the argument is not a FittedPreprocessor.
        ValueError: If the artifact is internally inconsistent.
    """

    def __init__(self, preprocessor: FittedPreprocessor) -> None:
        if not isinstance(preprocessor, FittedPreprocessor):
            raise TypeError(
                f"Expected FittedPreprocessor, got {type(preprocessor).__name__}"
            )
        self._p = preprocessor
        self._validate()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self) -> None:
        """Verify that the artifact is internally consistent.

        Raises:
            ValueError: On detected inconsistency.
        """
        p = self._p
        if not p.input_features:
            raise ValueError("preprocessor.input_features is empty")
        if not p.selected_features:
            raise ValueError("preprocessor.selected_features is empty")
        if len(p.selected_features) != EXPECTED_FEATURE_COUNT:
            raise ValueError(
                f"Expected {EXPECTED_FEATURE_COUNT} selected features, "
                f"got {len(p.selected_features)}"
            )
        if not p.medians:
            raise ValueError("preprocessor.medians is empty")
        if p.scaler is None:
            raise ValueError("preprocessor.scaler is None")
        if p.selector is None:
            raise ValueError("preprocessor.selector is None")
        support_count = int(p.selector.get_support().sum())
        if support_count != EXPECTED_FEATURE_COUNT:
            raise ValueError(
                f"Selector support mask selects {support_count} features; "
                f"expected {EXPECTED_FEATURE_COUNT}"
            )

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def input_features(self) -> list[str]:
        """Ordered list of raw input feature names expected in mappings."""
        return list(self._p.input_features)

    @property
    def selected_features(self) -> list[str]:
        """Ordered list of the 40 selected feature names after transform."""
        return list(self._p.selected_features)

    # ------------------------------------------------------------------
    # Public transform API
    # ------------------------------------------------------------------

    def transform_one(self, features: Mapping[str, Any]) -> TransformResult:
        """Transform one raw feature mapping into a scaled v3 vector.

        Keys must be CICIDS2017 feature names. Missing keys are imputed
        using training-set medians. Extra keys are ignored.

        Args:
            features: Raw feature name -> value mapping.

        Returns:
            TransformResult with a (40,) float32 array on success.
        """
        if features is None:
            return TransformResult(
                success=False,
                feature_quality=FeatureQuality.INVALID,
                error="Input mapping is None",
            )
        return self._transform_rows([features])[0]

    def transform_batch(
        self, rows: Sequence[Mapping[str, Any]]
    ) -> list[TransformResult]:
        """Transform a batch of raw feature mappings.

        Args:
            rows: Sequence of raw feature mappings.

        Returns:
            List of TransformResult, one per input row.
        """
        if not rows:
            return []
        return self._transform_rows(list(rows))

    # ------------------------------------------------------------------
    # Core transform implementation
    # ------------------------------------------------------------------

    def _transform_rows(
        self, rows: list[Mapping[str, Any]]
    ) -> list[TransformResult]:
        """Apply the complete v3 sequence to a list of raw mappings.

        Args:
            rows: Raw feature mappings.

        Returns:
            One TransformResult per input row.
        """
        p = self._p
        n = len(rows)
        input_names = p.input_features
        n_input = len(input_names)

        # ── Step 1: parse raw values into a float matrix ─────────────
        raw = np.full((n, n_input), np.nan, dtype=np.float64)
        per_missing: list[list[str]] = [[] for _ in range(n)]
        per_rejected: list[list[str]] = [[] for _ in range(n)]

        for ri, row in enumerate(rows):
            if row is None:
                per_missing[ri].extend(input_names)
                continue
            for ci, name in enumerate(input_names):
                raw_val = row.get(name)
                if raw_val is None:
                    per_missing[ri].append(name)
                    continue
                value = _to_float(raw_val)
                if value is None:
                    per_rejected[ri].append(name)
                    continue
                # Domain validation
                if name in _PORT_FEATURES and not (0 <= value <= 65535):
                    per_rejected[ri].append(name)
                    continue
                if name in _NON_NEGATIVE_FEATURES and value < 0:
                    per_missing[ri].append(name)   # treat as missing, impute
                    continue
                raw[ri, ci] = value

        # ── Step 2: drop all-null columns ─────────────────────────────
        null_set = set(p.all_null_columns)
        keep_null = [name not in null_set for name in input_names]
        work = raw[:, keep_null].astype(np.float32)
        work_names = [n for n, k in zip(input_names, keep_null) if k]

        # ── Step 3: impute missing values with training medians ───────
        per_imputed: list[list[str]] = [[] for _ in range(n)]
        name_to_col = {name: ci for ci, name in enumerate(work_names)}
        for name, median in p.medians.items():
            ci = name_to_col.get(name)
            if ci is None:
                continue
            nan_rows = np.where(np.isnan(work[:, ci]))[0]
            for ri in nan_rows:
                work[ri, ci] = float(median)
                if name in per_missing[ri] or name in per_rejected[ri]:
                    per_imputed[ri].append(name)

        # ── Step 4: drop constant columns ─────────────────────────────
        const_set = set(p.constant_columns)
        keep_const = [name not in const_set for name in work_names]
        work = work[:, keep_const]
        work_names = [n for n, k in zip(work_names, keep_const) if k]

        # ── Step 5: log1p on fitted log columns ───────────────────────
        log_set = set(p.log_columns)
        for ci, name in enumerate(work_names):
            if name in log_set:
                work[:, ci] = np.log1p(np.maximum(work[:, ci], 0.0))

        # ── Step 6: clip to fitted quantile bounds ────────────────────
        for ci, name in enumerate(work_names):
            lo = p.clip_lower.get(name)
            hi = p.clip_upper.get(name)
            if lo is not None and hi is not None:
                work[:, ci] = np.clip(work[:, ci], lo, hi)

        # ── Step 7: drop correlated columns ───────────────────────────
        corr_set = set(p.correlated_columns)
        keep_corr = [name not in corr_set for name in work_names]
        work = work[:, keep_corr]
        work_names = [n for n, k in zip(work_names, keep_corr) if k]

        # ── Step 8: SelectKBest selector ──────────────────────────────
        # Wrap in a DataFrame so sklearn feature-name validation passes
        # cleanly (SelectKBest was fitted on a named DataFrame).
        work_df = pd.DataFrame(work, columns=work_names)
        try:
            work = p.selector.transform(work_df).astype(np.float32)
        except Exception as exc:
            return [
                TransformResult(
                    success=False,
                    feature_quality=FeatureQuality.INVALID,
                    error=f"SelectKBest transform failed: {exc}",
                )
                for _ in range(n)
            ]

        if work.shape[1] != EXPECTED_FEATURE_COUNT:
            return [
                TransformResult(
                    success=False,
                    feature_quality=FeatureQuality.INVALID,
                    error=(
                        f"Selector produced {work.shape[1]} columns; "
                        f"expected {EXPECTED_FEATURE_COUNT}"
                    ),
                )
                for _ in range(n)
            ]

        # ── Step 9: RobustScaler ──────────────────────────────────────
        # Wrap in a DataFrame with selected feature names so sklearn
        # feature-name validation passes cleanly (RobustScaler was fitted
        # on a named DataFrame).
        scaled_df = pd.DataFrame(work, columns=p.selected_features)
        try:
            scaled = p.scaler.transform(scaled_df).astype(np.float32)
        except Exception as exc:
            return [
                TransformResult(
                    success=False,
                    feature_quality=FeatureQuality.INVALID,
                    error=f"RobustScaler transform failed: {exc}",
                )
                for _ in range(n)
            ]

        # ── Step 10: finiteness check ─────────────────────────────────
        finite_mask = np.isfinite(scaled).all(axis=1)

        # ── Assemble per-row results ───────────────────────────────────
        n_raw_used = n_input - len(p.all_null_columns)

        # For quality assessment, a missing field only counts as "bad" if it
        # is one of the features that the preprocessor actually uses downstream
        # (i.e. it survives all-null, constant, and correlated column drops
        # and is selected by SelectKBest).  Missing non-selected raw columns
        # are imputed silently and do NOT degrade quality — this is the normal
        # path for live capture, which produces only the 40 selected features.
        selected_set: set[str] = set(p.selected_features)
        # Build the set of raw columns that survive to the selector input.
        surviving_cols: set[str] = set()
        for name in input_names:
            if name in null_set:
                continue
            if name in const_set:
                continue
            if name in corr_set:
                continue
            surviving_cols.add(name)

        results: list[TransformResult] = []
        for ri in range(n):
            missing = tuple(per_missing[ri])
            imputed = tuple(per_imputed[ri])
            rejected = tuple(per_rejected[ri])

            if not finite_mask[ri]:
                results.append(
                    TransformResult(
                        success=False,
                        feature_quality=FeatureQuality.INVALID,
                        missing_fields=missing,
                        imputed_fields=imputed,
                        rejected_fields=rejected,
                        error="Non-finite value survived preprocessing",
                    )
                )
                continue

            # Only count missing/rejected fields that survive to the selector
            # stage as quality-degrading.  Missing non-selected raw columns
            # are imputed silently and do not degrade quality — this is the
            # normal path for live capture, which produces only the 40
            # selected features.
            relevant_missing = [f for f in per_missing[ri] if f in surviving_cols]
            relevant_rejected = [f for f in per_rejected[ri] if f in surviving_cols]
            n_bad = len(relevant_missing) + len(relevant_rejected)
            n_relevant = len(surviving_cols)
            frac = n_bad / max(n_relevant, 1)
            if n_bad == 0:
                quality = FeatureQuality.COMPLETE
            elif frac >= _DEGRADED_FRACTION:
                quality = FeatureQuality.DEGRADED
            else:
                quality = FeatureQuality.PARTIAL
            results.append(
                TransformResult(
                    success=True,
                    scaled_vector=scaled[ri],
                    feature_quality=quality,
                    missing_fields=missing,
                    imputed_fields=imputed,
                    rejected_fields=rejected,
                )
            )
        return results
