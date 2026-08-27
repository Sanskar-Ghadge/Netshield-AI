"""Phase 3 v3 — Fair comparison and deployment training on the v3 dataset.

This script trains four classifiers on the exact same class-aware 50,000-row
subset (fair comparison), evaluates each on the full v3 holdout, then
retrains the best scalable model on the full v3 training set for deployment.

All artifacts are written to ``models/v3/`` and ``training/v3/`` — legacy
Phase 3 outputs in ``models/`` and ``training/`` are never touched.

Run from ``python-engine`` with:
    py training/train_model_v3.py
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import joblib
import matplotlib
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.neural_network import MLPClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

matplotlib.use("Agg")

# ---------------------------------------------------------------------------
# Ensure the python-engine root is on sys.path so that pickled objects
# stored under preprocessing.preprocessor_types can be deserialised.
# ---------------------------------------------------------------------------
_ENGINE_ROOT = Path(__file__).resolve().parent.parent.parent / "python-engine"
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

# preprocessing/ now lives alongside us in ml-model/
_ML_MODEL_ROOT = Path(__file__).resolve().parent.parent
if str(_ML_MODEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_ML_MODEL_ROOT))

PROJECT_ROOT = _ML_MODEL_ROOT.parent
PROCESSED_DIR = PROJECT_ROOT / "dataset" / "processed" / "v3"
MODELS_DIR = _ML_MODEL_ROOT / "models" / "v3"
TRAINING_DIR = _ML_MODEL_ROOT / "training" / "v3"
RANDOM_STATE = 42
FAIR_SUBSET_SIZE = 50_000


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelSpec:
    """Describe one comparison model and its training behavior.

    Attributes:
        name: Human-readable model name.
        filename: Filename for the comparison model artifact.
        factory: Callable that creates an unfitted estimator.
        scalable: Whether the algorithm is practical on the full dataset.
        pass_sample_weight: Whether balanced sample weights are passed to fit.
    """

    name: str
    filename: str
    factory: Callable[[], Any]
    scalable: bool
    pass_sample_weight: bool


@dataclass
class EvaluationResult:
    """Hold evaluation metrics and predictions for one fitted model.

    Attributes:
        name: Human-readable model name.
        model: Fitted estimator.
        training_samples: Number of rows used for fitting.
        training_seconds: Wall-clock fit duration.
        prediction_ms: Average prediction latency per sample.
        accuracy: Overall classification accuracy.
        balanced_accuracy: Mean per-class recall.
        macro_precision: Unweighted mean per-class precision.
        macro_recall: Unweighted mean per-class recall.
        macro_f1: Unweighted mean per-class F1.
        weighted_f1: Support-weighted F1.
        predictions: Predicted labels for the holdout set.
        matrix: Raw confusion matrix.
        normalized_matrix: Row-normalized confusion matrix.
        report: Per-class classification report dictionary.
    """

    name: str
    model: Any
    training_samples: int
    training_seconds: float
    prediction_ms: float
    accuracy: float
    balanced_accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    weighted_f1: float
    predictions: np.ndarray
    matrix: np.ndarray
    normalized_matrix: np.ndarray
    report: dict[str, Any]

    def metrics(self) -> dict[str, Any]:
        """Return JSON-serializable summary metrics.

        Returns:
            Dictionary containing sample counts, timing, and classification metrics.
        """
        return {
            "training_samples": self.training_samples,
            "training_seconds": round(self.training_seconds, 2),
            "prediction_ms_per_sample": round(self.prediction_ms, 6),
            "accuracy": round(self.accuracy, 6),
            "balanced_accuracy": round(self.balanced_accuracy, 6),
            "macro_precision": round(self.macro_precision, 6),
            "macro_recall": round(self.macro_recall, 6),
            "macro_f1": round(self.macro_f1, 6),
            "weighted_f1": round(self.weighted_f1, 6),
        }


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------


def load_inputs() -> tuple[
    np.ndarray, np.ndarray, np.ndarray, np.ndarray, dict[str, Any], Any
]:
    """Load and validate v3 Phase 2 arrays and metadata.

    Returns:
        Training features, holdout features, training labels, holdout labels,
        preprocessing metadata, and label encoder.

    Raises:
        FileNotFoundError: If any required v3 artifact is missing.
        RuntimeError: If the v3 pipeline is not leakage-safe.
        ValueError: If array shapes, values, or class mappings are invalid.
    """
    paths = [
        PROCESSED_DIR / "X_train_v3.npy",
        PROCESSED_DIR / "X_test_v3.npy",
        PROCESSED_DIR / "y_train_v3.npy",
        PROCESSED_DIR / "y_test_v3.npy",
        MODELS_DIR / "preprocessing_metadata_v3.json",
        MODELS_DIR / "label_encoder_v3.pkl",
    ]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing v3 artifacts: {missing}")

    X_train = np.load(paths[0])
    X_test = np.load(paths[1])
    y_train = np.load(paths[2])
    y_test = np.load(paths[3])
    with paths[4].open("r", encoding="utf-8") as handle:
        metadata = json.load(handle)
    encoder = joblib.load(paths[5])

    if metadata.get("leakage_safe") is not True:
        raise RuntimeError("Refusing to train: v3 pipeline is not leakage-safe")
    if X_train.ndim != 2 or X_test.ndim != 2 or X_train.shape[1] != X_test.shape[1]:
        raise ValueError("Training and holdout feature arrays are incompatible")
    if len(X_train) != len(y_train) or len(X_test) != len(y_test):
        raise ValueError("Feature and target row counts do not match")
    if not np.isfinite(X_train).all() or not np.isfinite(X_test).all():
        raise ValueError("Feature arrays contain NaN or infinite values")

    expected_classes = np.arange(len(encoder.classes_))
    train_classes = np.unique(y_train)
    if not np.array_equal(train_classes, expected_classes):
        raise ValueError(
            f"Training labels missing classes. Expected {expected_classes.tolist()}, "
            f"got {train_classes.tolist()}"
        )
    test_classes = np.unique(y_test)
    if not np.array_equal(test_classes, expected_classes):
        raise ValueError(
            f"Test labels missing classes. Expected {expected_classes.tolist()}, "
            f"got {test_classes.tolist()}"
        )

    print("=" * 76)
    print("PHASE 3 v3 — FAIR COMPARISON AND DEPLOYMENT TRAINING")
    print("=" * 76)
    print(f"Training data: {X_train.shape} {X_train.dtype}")
    print(f"Holdout data:  {X_test.shape} {X_test.dtype}")
    print(f"Classes:       {list(encoder.classes_)}")
    print(f"Features:      {X_train.shape[1]}")
    return X_train, X_test, y_train, y_test, metadata, encoder


# ---------------------------------------------------------------------------
# Fair comparison subset
# ---------------------------------------------------------------------------


def create_class_aware_subset(
    X: np.ndarray,
    y: np.ndarray,
    size: int,
    random_state: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Create one reproducible subset shared by every comparison model.

    Every class is guaranteed representation. Remaining rows are allocated
    approximately in proportion to class frequencies. Extremely rare classes
    (≤100 samples) are retained completely.

    Args:
        X: Complete training features.
        y: Complete training labels.
        size: Requested subset size.
        random_state: Reproducible random seed.

    Returns:
        Subset features, labels, and original row indices.

    Raises:
        ValueError: If size is invalid or cannot represent every class.
    """
    if size <= 0 or size > len(y):
        raise ValueError("Subset size must be in the range [1, len(y)]")
    classes, counts = np.unique(y, return_counts=True)
    if size < len(classes):
        raise ValueError("Subset is too small to represent every class")

    rng = np.random.default_rng(random_state)
    proportions = counts / counts.sum()
    allocations = np.floor(proportions * size).astype(int)
    allocations = np.maximum(allocations, 1)
    allocations = np.minimum(allocations, counts)

    # Preserve all extremely rare examples so Heartbleed/Infiltration diversity
    # is not lost to sampling variance.
    rare_mask = counts <= 100
    allocations[rare_mask] = counts[rare_mask]

    while allocations.sum() > size:
        candidates = np.where((allocations > 1) & ~rare_mask)[0]
        if candidates.size == 0:
            raise ValueError("Unable to reduce allocations to requested size")
        index = candidates[np.argmax(allocations[candidates])]
        allocations[index] -= 1
    while allocations.sum() < size:
        capacity = counts - allocations
        candidates = np.where(capacity > 0)[0]
        if candidates.size == 0:
            break
        priority = proportions[candidates] * capacity[candidates]
        index = candidates[np.argmax(priority)]
        allocations[index] += 1

    selected: list[np.ndarray] = []
    for class_value, allocation in zip(classes, allocations):
        class_indices = np.flatnonzero(y == class_value)
        selected.append(
            rng.choice(class_indices, size=int(allocation), replace=False)
        )
    indices = np.concatenate(selected)
    rng.shuffle(indices)

    print(f"\nFair comparison subset: {len(indices):,} identical rows per model")
    for class_value, allocation in zip(classes, allocations):
        print(f"  Class {int(class_value)}: {int(allocation):,}")
    return X[indices], y[indices], indices


# ---------------------------------------------------------------------------
# Model specifications
# ---------------------------------------------------------------------------


def build_specs(num_classes: int) -> list[ModelSpec]:
    """Create the four model specifications used in fair comparison.

    Args:
        num_classes: Number of encoded output classes.

    Returns:
        Model specifications in reporting order.
    """
    return [
        ModelSpec(
            name="Random Forest",
            filename="rf_model_v3.pkl",
            factory=lambda: RandomForestClassifier(
                n_estimators=160,
                max_depth=20,
                class_weight="balanced",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
            scalable=True,
            pass_sample_weight=False,
        ),
        ModelSpec(
            name="XGBoost",
            filename="xgb_model_v3.pkl",
            factory=lambda: XGBClassifier(
                n_estimators=220,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                objective="multi:softprob",
                eval_metric="mlogloss",
                tree_method="hist",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
            scalable=True,
            pass_sample_weight=True,
        ),
        ModelSpec(
            name="Neural Network (MLP)",
            filename="mlp_model_v3.pkl",
            factory=lambda: MLPClassifier(
                hidden_layer_sizes=(96, 48, 24),
                batch_size=512,
                max_iter=100,
                early_stopping=True,
                validation_fraction=0.1,
                n_iter_no_change=8,
                random_state=RANDOM_STATE,
            ),
            scalable=True,
            pass_sample_weight=True,
        ),
        ModelSpec(
            name="SVM (Linear)",
            filename="svm_model_v3.pkl",
            factory=lambda: CalibratedClassifierCV(
                LinearSVC(
                    C=1.0,
                    class_weight="balanced",
                    dual="auto",
                    max_iter=5000,
                    random_state=RANDOM_STATE,
                ),
                cv=3,
            ),
            scalable=True,
            pass_sample_weight=False,
        ),
    ]


# ---------------------------------------------------------------------------
# Training and evaluation
# ---------------------------------------------------------------------------


def fit_and_evaluate(
    spec: ModelSpec,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    labels: np.ndarray,
    display_name: str | None = None,
) -> EvaluationResult:
    """Fit one model and evaluate it on the complete untouched holdout.

    Args:
        spec: Model construction and fit behavior.
        X_train: Model training features.
        y_train: Model training labels.
        X_test: Complete holdout features.
        y_test: Complete holdout labels.
        labels: Ordered encoded class labels.
        display_name: Optional name override for deployment reporting.

    Returns:
        Complete evaluation result.
    """
    name = display_name or spec.name
    model = spec.factory()
    print(f"\n{'-' * 76}")
    print(f"Training {name} on {len(y_train):,} samples")
    print(f"{'-' * 76}")

    fit_kwargs: dict[str, Any] = {}
    if spec.pass_sample_weight:
        fit_kwargs["sample_weight"] = compute_sample_weight("balanced", y_train)

    started = time.perf_counter()
    model.fit(X_train, y_train, **fit_kwargs)
    training_seconds = time.perf_counter() - started

    started = time.perf_counter()
    predictions = np.asarray(model.predict(X_test), dtype=np.int64)
    prediction_seconds = time.perf_counter() - started
    prediction_ms = prediction_seconds * 1000.0 / len(y_test)

    matrix = confusion_matrix(y_test, predictions, labels=labels)
    normalized = confusion_matrix(
        y_test, predictions, labels=labels, normalize="true"
    )
    result = EvaluationResult(
        name=name,
        model=model,
        training_samples=len(y_train),
        training_seconds=training_seconds,
        prediction_ms=prediction_ms,
        accuracy=accuracy_score(y_test, predictions),
        balanced_accuracy=balanced_accuracy_score(y_test, predictions),
        macro_precision=precision_score(
            y_test, predictions, average="macro", zero_division=0
        ),
        macro_recall=recall_score(
            y_test, predictions, average="macro", zero_division=0
        ),
        macro_f1=f1_score(y_test, predictions, average="macro", zero_division=0),
        weighted_f1=f1_score(
            y_test, predictions, average="weighted", zero_division=0
        ),
        predictions=predictions,
        matrix=matrix,
        normalized_matrix=normalized,
        report=classification_report(
            y_test, predictions, labels=labels, output_dict=True, zero_division=0
        ),
    )
    print(
        f"Accuracy={result.accuracy:.4f} | "
        f"Balanced accuracy={result.balanced_accuracy:.4f} | "
        f"Macro F1={result.macro_f1:.4f} | "
        f"Weighted F1={result.weighted_f1:.4f} | "
        f"Latency={result.prediction_ms:.4f} ms/sample"
    )
    return result


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------


def save_confusion_plots(
    result: EvaluationResult,
    class_names: list[str],
    prefix: str,
) -> None:
    """Save raw and normalized confusion-matrix images.

    Args:
        result: Model evaluation result.
        class_names: Ordered display labels.
        prefix: Safe filename prefix.
    """
    TRAINING_DIR.mkdir(parents=True, exist_ok=True)
    for matrix_data, normalized, suffix, fmt in [
        (result.matrix, False, "raw", "d"),
        (result.normalized_matrix, True, "normalized", ".2f"),
    ]:
        fig_width = max(11, len(class_names) * 1.2)
        fig_height = max(8, len(class_names) * 0.9)
        plt.figure(figsize=(fig_width, fig_height))
        sns.heatmap(
            matrix_data,
            annot=True,
            fmt=fmt,
            cmap="Blues",
            xticklabels=class_names,
            yticklabels=class_names,
            vmin=0 if normalized else None,
            vmax=1 if normalized else None,
        )
        plt.title(
            f"{result.name} — "
            f"{'Normalized' if normalized else 'Raw'} Confusion Matrix"
        )
        plt.xlabel("Predicted class")
        plt.ylabel("Actual class")
        plt.xticks(rotation=45, ha="right")
        plt.yticks(rotation=0)
        plt.tight_layout()
        plt.savefig(
            TRAINING_DIR / f"confusion_matrix_{prefix}_{suffix}.png", dpi=160
        )
        plt.close()


def save_comparison_outputs(
    results: list[EvaluationResult],
    class_names: list[str],
) -> None:
    """Save fair-comparison tables, reports, and visualizations.

    Args:
        results: Fair-comparison evaluation results.
        class_names: Ordered class names.
    """
    TRAINING_DIR.mkdir(parents=True, exist_ok=True)

    # CSV comparison table
    rows = [{"Model": result.name, **result.metrics()} for result in results]
    table = pd.DataFrame(rows)
    table.to_csv(TRAINING_DIR / "model_comparison_v3.csv", index=False)

    # JSON classification reports
    report_payload = {
        result.name: {"metrics": result.metrics(), "per_class": result.report}
        for result in results
    }
    with (TRAINING_DIR / "classification_reports_v3.json").open(
        "w", encoding="utf-8"
    ) as handle:
        json.dump(report_payload, handle, indent=2)

    # Bar chart comparing all models
    metrics_keys = [
        "accuracy",
        "balanced_accuracy",
        "macro_f1",
        "weighted_f1",
    ]
    chart_labels = ["Accuracy", "Balanced Accuracy", "Macro F1", "Weighted F1"]
    x = np.arange(len(metrics_keys))
    width = 0.8 / len(results)
    plt.figure(figsize=(13, 7))
    for index, result in enumerate(results):
        values = [getattr(result, key) for key in metrics_keys]
        bars = plt.bar(x + index * width, values, width, label=result.name)
        for bar, value in zip(bars, values):
            plt.text(
                bar.get_x() + bar.get_width() / 2,
                value + 0.006,
                f"{value:.3f}",
                ha="center",
                fontsize=7,
            )
    plt.xticks(x + width * (len(results) - 1) / 2, chart_labels)
    plt.ylim(0, 1.15)
    plt.ylabel("Score")
    plt.title(
        f"v3 Fair Model Comparison — All 4 Models on {FAIR_SUBSET_SIZE:,} Rows"
    )
    plt.legend()
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(TRAINING_DIR / "model_comparison_v3.png", dpi=160)
    plt.close()

    # Individual confusion matrices
    for result in results:
        safe = result.name.lower().replace(" ", "_").replace("(", "").replace(")", "")
        save_confusion_plots(result, class_names, safe)

    print("\nFair comparison results:")
    print(table.to_string(index=False))


# ---------------------------------------------------------------------------
# Deployment artifact persistence
# ---------------------------------------------------------------------------


def save_deployment_outputs(
    comparison_results: list[EvaluationResult],
    deployment_result: EvaluationResult,
    deployment_spec: ModelSpec,
    metadata: dict[str, Any],
    subset_indices: np.ndarray,
    class_names: list[str],
    cross_attack_result: dict[str, Any] | None = None,
) -> None:
    """Persist model artifacts and update v3 deployment metadata.

    Writes:
    - Individual comparison model pickles (``rf_model_v3.pkl``, etc.)
    - Deployment model (``intrusion_model_v3.pkl``)
    - Updated ``preprocessing_metadata_v3.json`` with Phase 3 results
    - Deployment confusion-matrix plots
    - Cross-attack evaluation results and chart

    Legacy ``models/model_info.json`` and ``models/intrusion_model.pkl`` are
    never touched.

    Args:
        comparison_results: Results from the fair experiment.
        deployment_result: Full-training winner result.
        deployment_spec: Winning scalable model specification.
        metadata: Existing leakage-safe v3 preprocessing metadata.
        subset_indices: Original indices used by every comparison model.
        class_names: Ordered class names.
        cross_attack_result: Optional cross-attack generalization results.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    TRAINING_DIR.mkdir(parents=True, exist_ok=True)

    # Save individual comparison models
    for result, spec in zip(comparison_results, build_specs(len(class_names))):
        joblib.dump(result.model, MODELS_DIR / spec.filename)

    # Save deployment model
    joblib.dump(
        deployment_result.model, MODELS_DIR / "intrusion_model_v3.pkl"
    )

    # Save deployment confusion matrices
    save_confusion_plots(
        deployment_result, class_names, "deployment_model_v3"
    )

    # Update metadata atomically
    metadata.update(
        {
            "phase3_status": "COMPLETE",
            "comparison_protocol": {
                "fair_subset_size": FAIR_SUBSET_SIZE,
                "same_rows_for_all_models": True,
                "subset_index_checksum": int(
                    np.sum(subset_indices, dtype=np.int64)
                ),
                "evaluation_samples": int(len(deployment_result.predictions)),
                "selection_metric": "macro_f1",
                "svm_variant": "LinearSVC (replaces RBF — scales to millions of rows)",
                "imbalance_handling": {
                    "Random Forest": "class_weight=balanced",
                    "XGBoost": "balanced sample weights",
                    "Neural Network (MLP)": "balanced sample weights",
                    "SVM (Linear)": "class_weight=balanced",
                },
            },
            "fair_comparison": {
                result.name: result.metrics() for result in comparison_results
            },
            "fair_comparison_winner": max(
                comparison_results, key=lambda item: item.macro_f1
            ).name,
            "best_model": deployment_spec.name,
            "cross_attack_evaluation": cross_attack_result,
            "deployment_model": {
                **deployment_result.metrics(),
                "artifact": "intrusion_model_v3.pkl",
                "trained_on_full_v3_training_set": True,
                "selection_rule": (
                    "highest fair-comparison macro F1 among scalable models"
                ),
            },
        }
    )
    temporary = MODELS_DIR / "preprocessing_metadata_v3.json.tmp"
    final = MODELS_DIR / "preprocessing_metadata_v3.json"
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2, sort_keys=True)
    temporary.replace(final)


# ---------------------------------------------------------------------------
# Cross-attack generalization evaluation
# ---------------------------------------------------------------------------

# Encoded class indices (matches label_encoder_v3 ordering):
# 0=BENIGN, 1=Bot, 2=BruteForce, 3=DDoS, 4=DoS,
# 5=Heartbleed, 6=Infiltration, 7=PortScan, 8=WebAttack

# Attacks the model is trained on:
CROSS_TRAIN_CLASSES: list[int] = [0, 1, 2, 3, 4, 5]
# Attacks the model has never seen (must detect as "unknown/anomaly"):
CROSS_TEST_ATTACKS: list[int] = [6, 7, 8]
# BENIGN is included in both train and test to measure false-positive rate.


def run_cross_attack_evaluation(
    spec: ModelSpec,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    labels: np.ndarray,
    class_names: list[str],
) -> dict[str, Any]:
    """Train on BENIGN + 5 attack types, test on 3 unseen attack types.

    This evaluates whether the model truly generalises to novel attacks or
    merely memorises signatures. We train on BENIGN, Bot, BruteForce, DDoS,
    DoS, and Heartbleed, then test on Infiltration, PortScan, and WebAttack
    — attacks the model has never encountered.

    For unseen attacks, correct behaviour is either:
    a) Predict the attack as BENIGN (missed attack — bad),
    b) Predict as one of the known attack classes (partial generalisation),
    c) Have low confidence (uncertain — acceptable).

    Metrics reported:
    - Detection rate on unseen attacks (1 - false_negative_rate)
    - False alarm rate on BENIGN
    - Confidence distribution for unseen vs. known attacks

    Args:
        spec: Model specification for the fair-comparison winner.
        X_train: Full training features.
        y_train: Full training labels.
        X_test: Full holdout features.
        y_test: Full holdout labels.
        labels: Ordered class indices.
        class_names: Ordered class name strings.

    Returns:
        Dictionary with cross-attack evaluation results for metadata.
    """
    print("\n" + "=" * 76)
    print("CROSS-ATTACK GENERALIZATION EVALUATION")
    print("=" * 76)

    train_names = [class_names[c] for c in CROSS_TRAIN_CLASSES]
    test_attack_names = [class_names[c] for c in CROSS_TEST_ATTACKS]
    print(f"Trained on:        {train_names}")
    print(f"Unseen attacks:    {test_attack_names}")

    # Filter training data to only the training classes
    train_mask = np.isin(y_train, CROSS_TRAIN_CLASSES)
    X_cross_train = X_train[train_mask]
    y_cross_train = y_train[train_mask]

    # Remap labels to 0..len(CROSS_TRAIN_CLASSES)-1 for training
    label_map = {orig: new for new, orig in enumerate(CROSS_TRAIN_CLASSES)}
    y_cross_train_remapped = np.vectorize(label_map.get)(y_cross_train).astype(np.int64)

    # Filter test data: BENIGN (for false alarm) + unseen attacks
    test_classes_needed = [0] + CROSS_TEST_ATTACKS  # BENIGN + unseen
    test_mask = np.isin(y_test, test_classes_needed)
    X_cross_test = X_test[test_mask]
    y_cross_test_original = y_test[test_mask]

    # Train the model
    model = spec.factory()
    fit_kwargs: dict[str, Any] = {}
    if spec.pass_sample_weight:
        fit_kwargs["sample_weight"] = compute_sample_weight(
            "balanced", y_cross_train_remapped
        )

    print(f"Training {spec.name} on {len(y_cross_train):,} rows "
          f"({len(CROSS_TRAIN_CLASSES)} classes)...")
    started = time.perf_counter()
    model.fit(X_cross_train, y_cross_train_remapped, **fit_kwargs)
    train_seconds = time.perf_counter() - started
    print(f"Training completed in {train_seconds:.1f}s")

    # Predict
    started = time.perf_counter()
    predictions_remapped = np.asarray(
        model.predict(X_cross_test), dtype=np.int64
    )
    predict_seconds = time.perf_counter() - started

    # Map predictions back to original class indices
    reverse_map = {new: orig for orig, new in label_map.items()}
    predictions_original = np.vectorize(reverse_map.get)(predictions_remapped)

    # Get prediction probabilities (confidence)
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X_cross_test)
        max_proba = proba.max(axis=1)
    elif hasattr(model, "decision_function"):
        decision = model.decision_function(X_cross_test)
        max_proba = np.max(decision, axis=1)
        # Normalize to 0-1 range
        if max_proba.size > 0:
            max_proba = (max_proba - max_proba.min()) / (
                max_proba.max() - max_proba.min() + 1e-10
            )
    else:
        max_proba = np.ones(len(predictions_original))

    # Compute metrics
    benign_mask = y_cross_test_original == 0
    attack_mask = ~benign_mask

    # Detection rate: unseen attacks NOT classified as BENIGN
    attack_preds = predictions_original[attack_mask]
    detected = np.sum(attack_preds != 0)
    total_attacks = np.sum(attack_mask)
    detection_rate = detected / total_attacks if total_attacks > 0 else 0.0

    # False alarm rate: BENIGN classified as an attack
    benign_preds = predictions_original[benign_mask]
    false_alarms = np.sum(benign_preds != 0)
    total_benign = np.sum(benign_mask)
    false_alarm_rate = false_alarms / total_benign if total_benign > 0 else 0.0

    # Confidence stats
    attack_confidence = max_proba[attack_mask]
    benign_confidence = max_proba[benign_mask]

    # How were unseen attacks classified?
    attack_class_dist = {}
    for cls in range(len(class_names)):
        count = np.sum(predictions_original[attack_mask] == cls)
        if count > 0:
            attack_class_dist[class_names[cls]] = int(count)

    result = {
        "train_classes": train_names,
        "unseen_attack_classes": test_attack_names,
        "train_rows": int(len(y_cross_train)),
        "test_rows": int(len(y_cross_test_original)),
        "test_attack_rows": int(total_attacks),
        "test_benign_rows": int(total_benign),
        "training_seconds": round(train_seconds, 2),
        "prediction_ms_per_sample": round(
            predict_seconds * 1000.0 / len(y_cross_test_original), 6
        ),
        "detection_rate_on_unseen_attacks": round(detection_rate, 6),
        "false_alarm_rate_on_benign": round(false_alarm_rate, 6),
        "unseen_attack_classification_distribution": attack_class_dist,
        "mean_confidence_on_unseen_attacks": round(
            float(np.mean(attack_confidence)), 6
        ) if attack_confidence.size > 0 else 0.0,
        "mean_confidence_on_benign": round(
            float(np.mean(benign_confidence)), 6
        ) if benign_confidence.size > 0 else 0.0,
        "interpretation": (
            "detection_rate_on_unseen_attacks measures whether the model "
            "flags unseen attack traffic as non-BENIGN. A high value means "
            "the model generalises; a low value means it memorises signatures "
            "and misses novel attacks."
        ),
    }

    print(f"\nCross-Attack Results:")
    print(f"  Detection rate (unseen attacks):  {detection_rate:.4%}")
    print(f"  False alarm rate (BENIGN):        {false_alarm_rate:.4%}")
    print(f"  Mean confidence (unseen attacks): {result['mean_confidence_on_unseen_attacks']:.4f}")
    print(f"  Mean confidence (BENIGN):         {result['mean_confidence_on_benign']:.4f}")
    print(f"  Unseen attacks classified as:")
    for cls_name, count in attack_class_dist.items():
        print(f"    {cls_name}: {count}")

    # Save cross-attack confusion matrix
    save_cross_attack_plot(
        predictions_original,
        y_cross_test_original,
        max_proba,
        class_names,
        spec.name,
    )

    return result


def save_cross_attack_plot(
    predictions: np.ndarray,
    y_true: np.ndarray,
    confidence: np.ndarray,
    class_names: list[str],
    model_name: str,
) -> None:
    """Save a bar chart showing how unseen attacks were classified.

    Args:
        predictions: Predicted class indices (original encoding).
        y_true: True class indices.
        confidence: Max prediction probability for each sample.
        class_names: Ordered class name strings.
        model_name: Model name for the title.
    """
    TRAINING_DIR.mkdir(parents=True, exist_ok=True)

    attack_mask = y_true != 0
    attack_preds = predictions[attack_mask]
    pred_counts = np.bincount(attack_preds, minlength=len(class_names))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

    # Left: How unseen attacks were classified
    non_zero = pred_counts > 0
    bars = ax1.bar(
        [class_names[i] for i in range(len(class_names)) if non_zero[i]],
        [pred_counts[i] for i in range(len(class_names)) if non_zero[i]],
        color=["#ef4444" if i == 0 else "#3b82f6" for i in range(len(class_names)) if non_zero[i]],
    )
    ax1.set_title(f"Cross-Attack: How Unseen Attacks Were Classified\n({model_name})")
    ax1.set_xlabel("Predicted Class")
    ax1.set_ylabel("Count")
    ax1.tick_params(axis='x', rotation=45)
    for bar, count in zip(bars, [pred_counts[i] for i in range(len(class_names)) if non_zero[i]]):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                 f"{count}", ha="center", fontsize=9)

    # Right: Confidence distribution: unseen attacks vs BENIGN
    benign_conf = confidence[~attack_mask]
    attack_conf = confidence[attack_mask]
    ax2.hist(benign_conf, bins=30, alpha=0.6, color="#22c55e", label="BENIGN (known)")
    ax2.hist(attack_conf, bins=30, alpha=0.6, color="#ef4444", label="Unseen attacks")
    ax2.set_title("Prediction Confidence Distribution")
    ax2.set_xlabel("Max prediction probability")
    ax2.set_ylabel("Count")
    ax2.legend()

    plt.tight_layout()
    plt.savefig(TRAINING_DIR / "cross_attack_evaluation_v3.png", dpi=160)
    plt.close()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run fair comparison, cross-attack evaluation, and deployment training."""
    X_train, X_test, y_train, y_test, metadata, encoder = load_inputs()
    labels = np.arange(len(encoder.classes_), dtype=np.int64)
    class_names = [str(value) for value in encoder.classes_]

    # ------------------------------------------------------------------
    # 1. Fair comparison: all 4 models on identical 50K subset, full holdout
    # ------------------------------------------------------------------
    X_fair, y_fair, subset_indices = create_class_aware_subset(
        X_train, y_train, FAIR_SUBSET_SIZE, RANDOM_STATE
    )
    specs = build_specs(len(labels))

    comparison_results: list[EvaluationResult] = []
    for spec in specs:
        result = fit_and_evaluate(
            spec, X_fair, y_fair, X_test, y_test, labels
        )
        comparison_results.append(result)

    save_comparison_outputs(comparison_results, class_names)

    # Select best scalable model by macro F1 (all 4 are now scalable)
    winner_spec, fair_winner = max(
        zip(specs, comparison_results), key=lambda pair: pair[1].macro_f1
    )
    print(
        f"\nFair winner: {winner_spec.name} "
        f"(macro F1={fair_winner.macro_f1:.4f})"
    )

    # ------------------------------------------------------------------
    # 2. Cross-attack generalization: train on BENIGN + 5 attack types,
    #    test on 3 unseen attack types. Reveals whether the model truly
    #    generalises or just memorises attack signatures.
    # ------------------------------------------------------------------
    cross_result = run_cross_attack_evaluation(
        winner_spec, X_train, y_train, X_test, y_test, labels, class_names
    )

    # ------------------------------------------------------------------
    # 3. Deployment: retrain winner on the full v3 training set
    # ------------------------------------------------------------------
    deployment_result = fit_and_evaluate(
        winner_spec,
        X_train,
        y_train,
        X_test,
        y_test,
        labels,
        display_name=f"{winner_spec.name} Deployment (v3)",
    )

    save_deployment_outputs(
        comparison_results,
        deployment_result,
        winner_spec,
        metadata,
        subset_indices,
        class_names,
        cross_attack_result=cross_result,
    )

    # Final summary
    print("\n" + "=" * 76)
    print("PHASE 3 v3 COMPLETE")
    print("=" * 76)
    fair_best = max(comparison_results, key=lambda item: item.macro_f1)
    print(f"Fair comparison winner:  {fair_best.name}")
    print(f"  macro F1:              {fair_best.macro_f1:.4f}")
    print(f"Deployment algorithm:   {winner_spec.name}")
    print(f"Deployment accuracy:    {deployment_result.accuracy:.4%}")
    print(
        f"Deployment balanced acc: {deployment_result.balanced_accuracy:.4f}"
    )
    print(f"Deployment macro F1:    {deployment_result.macro_f1:.4f}")
    print(f"Deployment weighted F1: {deployment_result.weighted_f1:.4f}")
    print(
        f"Deployment latency:     {deployment_result.prediction_ms:.4f} ms/sample"
    )
    print(f"\nCross-attack generalization:")
    print(
        f"  Detection rate (unseen): {cross_result['detection_rate_on_unseen_attacks']:.4%}"
    )
    print(
        f"  False alarm rate:        {cross_result['false_alarm_rate_on_benign']:.4%}"
    )
    print("\nArtifacts saved:")
    print(f"  {MODELS_DIR / 'intrusion_model_v3.pkl'}")
    print(f"  {MODELS_DIR / 'preprocessing_metadata_v3.json'}")
    print(f"  {TRAINING_DIR / 'model_comparison_v3.csv'}")
    print(f"  {TRAINING_DIR / 'model_comparison_v3.png'}")
    print(f"  {TRAINING_DIR / 'cross_attack_evaluation_v3.png'}")
    print(f"  + individual model pickles and confusion matrices")
    print("\nPhase 4 (packet capture) may begin after artifact verification.")


if __name__ == "__main__":
    main()
