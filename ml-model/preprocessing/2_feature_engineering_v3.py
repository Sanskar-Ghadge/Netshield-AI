"""Leakage-safe CICIDS2017 v3 preprocessing pipeline.

The module splits the cleaned dataset before learning any statistics, learns
imputation/constant/log/clipping/correlation/selection/scaling transformations
from training rows only, and writes versioned artifacts without touching the
legacy model bundle.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_selection import SelectKBest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, RobustScaler

# Ensure the python-engine root is on sys.path so that the pickle stores the
# class under its fully-qualified import path ``preprocessing.preprocessor_types``
# regardless of how the script is invoked.
_ENGINE_ROOT = Path(__file__).resolve().parent.parent
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

from preprocessing.preprocessor_types import (  # noqa: E402
    FittedPreprocessor,
    mutual_info_scorer,
)

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
INPUT_FILE: Final[Path] = (
    PROJECT_ROOT / "dataset" / "processed" / "v3" / "cleaned_dataset_v3.parquet"
)
OUTPUT_DIR: Final[Path] = PROJECT_ROOT / "dataset" / "processed" / "v3"
MODEL_DIR: Final[Path] = PROJECT_ROOT / "python-engine" / "models" / "v3"
TARGET: Final[str] = "Label"
PROVENANCE: Final[tuple[str, ...]] = (
    "_source_file",
    "_capture_day",
    "_source_row",
)
RANDOM_STATE: Final[int] = 42
TEST_SIZE: Final[float] = 0.20
CORRELATION_THRESHOLD: Final[float] = 0.98
MAX_FEATURES: Final[int] = 40
LOWER_QUANTILE: Final[float] = 0.001
UPPER_QUANTILE: Final[float] = 0.999
SKEW_THRESHOLD: Final[float] = 1.0

EXCLUDED_FROM_LOG: Final[frozenset[str]] = frozenset(
    {
        "Destination Port",
        "Fwd PSH Flags",
        "Bwd PSH Flags",
        "Fwd URG Flags",
        "Bwd URG Flags",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
        "CWE Flag Count",
        "ECE Flag Count",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
        "min_seg_size_forward",
    }
)


@dataclass(frozen=True)
class PreprocessingMetadata:
    """Serializable summary of the fitted v3 preprocessing pipeline."""

    version: int
    leakage_safe: bool
    split_strategy: str
    random_state: int
    train_rows: int
    test_rows: int
    classes: dict[str, int]
    input_features: list[str]
    all_null_columns: list[str]
    constant_columns: list[str]
    log_columns: list[str]
    clipped_columns: list[str]
    correlated_columns: list[str]
    selected_features: list[str]
    correlation_threshold: float
    clipping_quantiles: list[float]
    phase3_status: str
    caveats: list[str]


def save_json(path: Path, payload: object) -> None:
    """Save a JSON payload atomically.

    Args:
        path: Output JSON path.
        payload: JSON-serializable object.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    temporary.replace(path)


def load_cleaned_data(path: Path) -> pd.DataFrame:
    """Load and validate the v3 cleaned dataset.

    Args:
        path: Cleaned Parquet path.

    Returns:
        Validated DataFrame.

    Raises:
        FileNotFoundError: If Phase 1 has not run.
        ValueError: If required columns or values are invalid.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Run 1_data_cleaning_v3.py first: {path}")
    data = pd.read_parquet(path)
    required = {TARGET, *PROVENANCE}
    missing = sorted(required - set(data.columns))
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    if data.empty or data[TARGET].isna().any():
        raise ValueError("Cleaned dataset is empty or contains missing labels")
    return data


def explain_day_holdout_limit(data: pd.DataFrame) -> dict[str, list[str]]:
    """Report classes confined to particular capture days.

    Args:
        data: Cleaned dataset with capture-day provenance.

    Returns:
        Mapping from each class to days on which it occurs.
    """
    return {
        str(label): sorted(group["_capture_day"].unique().tolist())
        for label, group in data.groupby(TARGET, sort=True)
    }


def split_before_fitting(
    data: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.DataFrame, pd.DataFrame]:
    """Create a reproducible stratified holdout before learned operations.

    A pure day holdout cannot evaluate multiclass CICIDS2017 because attacks are
    confined to particular days. Exact duplicate flows were already removed in
    Phase 1, so stratification is used while provenance remains available for
    day-stratified reporting.

    Args:
        data: Cleaned dataset.

    Returns:
        Training/test features, labels, and provenance frames.
    """
    feature_names = [
        column for column in data.columns if column != TARGET and column not in PROVENANCE
    ]
    labels = data[TARGET].astype("string")
    counts = labels.value_counts()
    if counts.min() < 2:
        raise ValueError("Every class needs at least two records for stratification")
    indices = np.arange(len(data))
    train_indices, test_indices = train_test_split(
        indices,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=labels,
    )
    train = data.iloc[train_indices]
    test = data.iloc[test_indices]
    return (
        train[feature_names].copy(),
        test[feature_names].copy(),
        train[TARGET].copy(),
        test[TARGET].copy(),
        train[list(PROVENANCE)].copy(),
        test[list(PROVENANCE)].copy(),
    )


def encode_labels(
    y_train: pd.Series, y_test: pd.Series
) -> tuple[np.ndarray, np.ndarray, LabelEncoder]:
    """Fit label encoding on training classes and transform both partitions.

    Args:
        y_train: Training string labels.
        y_test: Holdout string labels.

    Returns:
        Encoded labels and fitted encoder.
    """
    encoder = LabelEncoder()
    train_encoded = encoder.fit_transform(y_train)
    unknown = sorted(set(y_test) - set(encoder.classes_))
    if unknown:
        raise ValueError(f"Holdout contains unknown classes: {unknown}")
    return train_encoded, encoder.transform(y_test), encoder


def fit_imputation(
    train: pd.DataFrame, test: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame, list[str], dict[str, float]]:
    """Fit training medians and impute both partitions.

    Args:
        train: Training features.
        test: Holdout features.

    Returns:
        Imputed frames, all-null columns, and training medians.
    """
    all_null = train.columns[train.isna().all()].tolist()
    train = train.drop(columns=all_null)
    test = test.drop(columns=all_null)
    medians = train.median(axis=0, skipna=True)
    if medians.isna().any():
        raise ValueError(f"Invalid training medians: {medians[medians.isna()].index.tolist()}")
    train = train.fillna(medians).astype(np.float32)
    test = test.fillna(medians).astype(np.float32)
    return train, test, all_null, {key: float(value) for key, value in medians.items()}


def fit_constant_filter(
    train: pd.DataFrame, test: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    """Remove zero-variance columns learned from training data.

    Args:
        train: Imputed training data.
        test: Imputed holdout data.

    Returns:
        Filtered frames and removed columns.
    """
    constants = [column for column in train if train[column].nunique() <= 1]
    return train.drop(columns=constants), test.drop(columns=constants), constants


def fit_outlier_transform(
    train: pd.DataFrame, test: pd.DataFrame
) -> tuple[
    pd.DataFrame,
    pd.DataFrame,
    list[str],
    dict[str, float],
    dict[str, float],
]:
    """Fit log transforms and conservative clipping on training data.

    Only nonnegative, right-skewed continuous features receive ``log1p``.
    Clipping bounds are learned after transformation and do not delete rows.

    Args:
        train: Nonconstant training data.
        test: Corresponding holdout data.

    Returns:
        Transformed frames, log columns, and lower/upper clipping bounds.
    """
    log_columns: list[str] = []
    for column in train.columns:
        if column in EXCLUDED_FROM_LOG:
            continue
        values = train[column]
        if values.min() >= 0 and values.nunique() > 20 and abs(float(values.skew())) >= SKEW_THRESHOLD:
            log_columns.append(column)

    transformed_train = train.copy()
    transformed_test = test.copy()
    if log_columns:
        transformed_train[log_columns] = np.log1p(transformed_train[log_columns])
        transformed_test[log_columns] = np.log1p(transformed_test[log_columns])

    continuous = [
        column
        for column in transformed_train.columns
        if column not in EXCLUDED_FROM_LOG and transformed_train[column].nunique() > 20
    ]
    lower_series = transformed_train[continuous].quantile(LOWER_QUANTILE)
    upper_series = transformed_train[continuous].quantile(UPPER_QUANTILE)
    for column in continuous:
        transformed_train[column] = transformed_train[column].clip(
            lower=lower_series[column], upper=upper_series[column]
        )
        transformed_test[column] = transformed_test[column].clip(
            lower=lower_series[column], upper=upper_series[column]
        )
    return (
        transformed_train.astype(np.float32),
        transformed_test.astype(np.float32),
        log_columns,
        {key: float(value) for key, value in lower_series.items()},
        {key: float(value) for key, value in upper_series.items()},
    )


def fit_correlation_filter(
    train: pd.DataFrame, test: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    """Remove redundant features using training-only absolute correlation.

    Args:
        train: Transformed training data.
        test: Transformed holdout data.

    Returns:
        Filtered frames and dropped feature names.
    """
    correlation = train.corr().abs()
    upper = correlation.where(np.triu(np.ones(correlation.shape), k=1).astype(bool))
    dropped = [column for column in upper if (upper[column] > CORRELATION_THRESHOLD).any()]
    return train.drop(columns=dropped), test.drop(columns=dropped), dropped


def fit_feature_selection(
    train: pd.DataFrame, test: pd.DataFrame, y_train: np.ndarray
) -> tuple[pd.DataFrame, pd.DataFrame, SelectKBest, list[str]]:
    """Select features with training-only mutual information scores.

    Args:
        train: Correlation-filtered training features.
        test: Correlation-filtered holdout features.
        y_train: Encoded training labels.

    Returns:
        Selected frames, fitted selector, and ordered selected names.
    """
    k = min(MAX_FEATURES, train.shape[1])
    selector = SelectKBest(
        score_func=mutual_info_scorer,
        k=k,
    )
    train_values = selector.fit_transform(train, y_train).astype(np.float32)
    test_values = selector.transform(test).astype(np.float32)
    names = train.columns[selector.get_support()].tolist()
    return (
        pd.DataFrame(train_values, columns=names, index=train.index),
        pd.DataFrame(test_values, columns=names, index=test.index),
        selector,
        names,
    )


def fit_scaling(
    train: pd.DataFrame, test: pd.DataFrame
) -> tuple[np.ndarray, np.ndarray, RobustScaler]:
    """Fit a robust scaler on training data and transform both partitions.

    Args:
        train: Selected training features.
        test: Selected holdout features.

    Returns:
        Scaled arrays and fitted scaler.
    """
    scaler = RobustScaler(quantile_range=(25.0, 75.0))
    train_scaled = scaler.fit_transform(train).astype(np.float32)
    test_scaled = scaler.transform(test).astype(np.float32)
    if not np.isfinite(train_scaled).all() or not np.isfinite(test_scaled).all():
        raise ValueError("Non-finite values remain after preprocessing")
    return train_scaled, test_scaled, scaler


def main() -> None:
    """Run complete leakage-safe v3 preprocessing."""
    started = time.perf_counter()
    data = load_cleaned_data(INPUT_FILE)
    day_coverage = explain_day_holdout_limit(data)
    input_features = [
        column for column in data.columns if column != TARGET and column not in PROVENANCE
    ]
    X_train, X_test, y_train_text, y_test_text, p_train, p_test = split_before_fitting(data)
    y_train, y_test, encoder = encode_labels(y_train_text, y_test_text)

    X_train, X_test, all_null, medians = fit_imputation(X_train, X_test)
    X_train, X_test, constants = fit_constant_filter(X_train, X_test)
    X_train, X_test, log_columns, clip_lower, clip_upper = fit_outlier_transform(
        X_train, X_test
    )
    X_train, X_test, correlated = fit_correlation_filter(X_train, X_test)
    X_train, X_test, selector, selected = fit_feature_selection(
        X_train, X_test, y_train
    )
    train_scaled, test_scaled, scaler = fit_scaling(X_train, X_test)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    np.save(OUTPUT_DIR / "X_train_v3.npy", train_scaled)
    np.save(OUTPUT_DIR / "X_test_v3.npy", test_scaled)
    np.save(OUTPUT_DIR / "y_train_v3.npy", y_train.astype(np.int64))
    np.save(OUTPUT_DIR / "y_test_v3.npy", y_test.astype(np.int64))
    p_train.assign(Label=y_train_text.values).to_parquet(
        OUTPUT_DIR / "train_provenance_v3.parquet", index=False
    )
    p_test.assign(Label=y_test_text.values).to_parquet(
        OUTPUT_DIR / "test_provenance_v3.parquet", index=False
    )

    preprocessor = FittedPreprocessor(
        input_features=input_features,
        all_null_columns=all_null,
        medians=medians,
        constant_columns=constants,
        log_columns=log_columns,
        clip_lower=clip_lower,
        clip_upper=clip_upper,
        correlated_columns=correlated,
        selected_features=selected,
        selector=selector,
        scaler=scaler,
    )
    joblib.dump(preprocessor, MODEL_DIR / "preprocessor_v3.pkl")
    joblib.dump(encoder, MODEL_DIR / "label_encoder_v3.pkl")

    class_map = {str(index): str(label) for index, label in enumerate(encoder.classes_)}
    metadata = PreprocessingMetadata(
        version=3,
        leakage_safe=True,
        split_strategy="stratified random holdout after global exact deduplication",
        random_state=RANDOM_STATE,
        train_rows=len(train_scaled),
        test_rows=len(test_scaled),
        classes=class_map,
        input_features=input_features,
        all_null_columns=all_null,
        constant_columns=constants,
        log_columns=log_columns,
        clipped_columns=sorted(clip_lower),
        correlated_columns=correlated,
        selected_features=selected,
        correlation_threshold=CORRELATION_THRESHOLD,
        clipping_quantiles=[LOWER_QUANTILE, UPPER_QUANTILE],
        phase3_status="RETRAIN_REQUIRED",
        caveats=[
            "Pure day holdout is unsuitable for multiclass evaluation because attack classes are day-confounded.",
            "Heartbleed and Infiltration have very small support; per-class metrics are unstable.",
            "Live flow extraction must implement every selected feature with matching CICFlowMeter semantics.",
        ],
    )
    save_json(MODEL_DIR / "preprocessing_metadata_v3.json", asdict(metadata))
    save_json(OUTPUT_DIR / "class_day_coverage.json", day_coverage)
    save_json(
        OUTPUT_DIR / "split_audit_v3.json",
        {
            "train_labels": {
                str(k): int(v) for k, v in y_train_text.value_counts().sort_index().items()
            },
            "test_labels": {
                str(k): int(v) for k, v in y_test_text.value_counts().sort_index().items()
            },
            "train_files": {
                str(k): int(v) for k, v in p_train["_source_file"].value_counts().items()
            },
            "test_files": {
                str(k): int(v) for k, v in p_test["_source_file"].value_counts().items()
            },
        },
    )
    print(f"Saved v3 arrays: train={train_scaled.shape}, test={test_scaled.shape}")
    print(f"Constant columns removed: {constants}")
    print(f"Log-transformed columns: {len(log_columns)}")
    print(f"Selected features: {selected}")
    print(f"Phase 3 status: RETRAIN_REQUIRED")
    print(f"Elapsed: {time.perf_counter() - started:.1f} seconds")


if __name__ == "__main__":
    main()
