"""Importable type definitions for the v3 preprocessing pipeline.

These dataclasses and helper functions live in a stable, importable module so
that pickled artifacts (``preprocessor_v3.pkl``) can be deserialised from any
entry point — not only when the pipeline script itself is ``__main__``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.preprocessing import RobustScaler

#: Fixed random seed used throughout the pipeline for reproducibility.
RANDOM_STATE: int = 42


def mutual_info_scorer(x: np.ndarray, y: np.ndarray) -> np.ndarray:
    """Score features with mutual information using a picklable reference.

    This function must live in an importable module (not ``__main__``) so
    that ``SelectKBest`` objects fitted with it can be unpickled from any
    context.

    Args:
        x: Feature matrix.
        y: Encoded labels.

    Returns:
        Per-feature mutual information scores.
    """
    return mutual_info_classif(
        x, y, discrete_features=False, random_state=RANDOM_STATE, n_jobs=-1
    )


@dataclass(frozen=True)
class FittedPreprocessor:
    """All train-fitted transformations required for live inference.

    Attributes:
        input_features: Ordered feature names from the cleaned dataset.
        all_null_columns: Columns that were entirely NaN in training.
        medians: Training-set medians used for imputation.
        constant_columns: Zero-variance columns dropped after imputation.
        log_columns: Right-skewed features that received ``log1p``.
        clip_lower: Lower clipping bounds learned from training quantiles.
        clip_upper: Upper clipping bounds learned from training quantiles.
        correlated_columns: Redundant features removed by correlation filter.
        selected_features: Ordered names of the final selected features.
        selector: Fitted ``SelectKBest`` mutual-information selector.
        scaler: Fitted ``RobustScaler`` for the selected features.
    """

    input_features: list[str]
    all_null_columns: list[str]
    medians: dict[str, float]
    constant_columns: list[str]
    log_columns: list[str]
    clip_lower: dict[str, float]
    clip_upper: dict[str, float]
    correlated_columns: list[str]
    selected_features: list[str]
    selector: SelectKBest
    scaler: RobustScaler
