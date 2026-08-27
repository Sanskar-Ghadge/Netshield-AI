"""Unit tests for the v3 IntrusionPredictor.

Run from python-engine/:
    py -m pytest tests/test_predict_v3.py -v
"""

from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from prediction.predict import ArtifactPaths, IntrusionPredictor
from prediction.schemas import (
    EXPECTED_CLASS_COUNT,
    EXPECTED_FEATURE_COUNT,
    PredictionStatus,
    FeatureQuality,
)

P3 = ROOT.parent / "dataset" / "processed" / "v3"
MV3 = ROOT / "models" / "v3"
DROP_COLUMNS = ("_source_file", "_capture_day", "_source_row", "Label")


def load_predictor() -> IntrusionPredictor:
    """Return an IntrusionPredictor from the default v3 artifact directory."""
    return IntrusionPredictor()


def load_valid_row() -> dict[str, object]:
    """Return one raw feature mapping from the cleaned dataset."""
    ds = pd.read_parquet(P3 / "cleaned_dataset_v3.parquet")
    row = ds.iloc[0].to_dict()
    for column in DROP_COLUMNS:
        row.pop(column, None)
    return row


# ---------------------------------------------------------------------------
# Artifact loading and compatibility
# ---------------------------------------------------------------------------

class TestArtifactLoading(unittest.TestCase):
    """Validate that artifact loading and compatibility checks work."""

    def test_default_paths_load_successfully(self) -> None:
        """Predictor must load without error from the default artifact directory."""
        predictor = load_predictor()
        self.assertIsNotNone(predictor)

    def test_class_names_match_canonical_order(self) -> None:
        """Class names must match the nine canonical v3 label names."""
        predictor = load_predictor()
        expected = [
            "BENIGN", "Bot", "BruteForce", "DDoS", "DoS",
            "Heartbleed", "Infiltration", "PortScan", "WebAttack",
        ]
        self.assertEqual(predictor.class_names, expected)

    def test_missing_model_raises_file_not_found(self) -> None:
        """Missing model artifact must raise FileNotFoundError on init."""
        bad_paths = ArtifactPaths(model=Path("/nonexistent/model.pkl"))
        with self.assertRaises(FileNotFoundError):
            IntrusionPredictor(bad_paths)

    def test_missing_preprocessor_raises_file_not_found(self) -> None:
        """Missing preprocessor must raise FileNotFoundError on init."""
        bad_paths = ArtifactPaths(preprocessor=Path("/nonexistent/prep.pkl"))
        with self.assertRaises(FileNotFoundError):
            IntrusionPredictor(bad_paths)


# ---------------------------------------------------------------------------
# Single and batch prediction APIs
# ---------------------------------------------------------------------------

class TestPredictionAPIs(unittest.TestCase):
    """Validate the predict_one and predict_batch interfaces."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.predictor = load_predictor()
        cls.valid_row = load_valid_row()

    def test_predict_one_returns_single_result(self) -> None:
        """predict_one must return a PredictionResult that is not REJECTED."""
        result = self.predictor.predict_one(self.valid_row)
        self.assertIn(result.status, (PredictionStatus.BENIGN, PredictionStatus.ATTACK))
        self.assertNotEqual(result.status, PredictionStatus.REJECTED)

    def test_predict_batch_returns_same_count(self) -> None:
        """predict_batch output length must equal input length."""
        rows = [self.valid_row] * 10
        results = self.predictor.predict_batch(rows)
        self.assertEqual(len(results), 10)

    def test_predict_batch_empty_returns_empty(self) -> None:
        """Empty batch must produce an empty list rather than raising."""
        self.assertEqual(self.predictor.predict_batch([]), [])

    def test_confidence_is_between_zero_and_one(self) -> None:
        """Confidence probability must be in the interval [0.0, 1.0]."""
        result = self.predictor.predict_one(self.valid_row)
        if result.status != PredictionStatus.REJECTED:
            self.assertGreaterEqual(result.confidence, 0.0)
            self.assertLessEqual(result.confidence, 1.0)

    def test_class_probabilities_sum_to_one(self) -> None:
        """All per-class probabilities in one result must sum to approximately 1."""
        result = self.predictor.predict_one(self.valid_row)
        if result.status != PredictionStatus.REJECTED:
            total = sum(result.class_probabilities.values())
            self.assertAlmostEqual(total, 1.0, places=4)

    def test_class_probabilities_have_correct_count(self) -> None:
        """class_probabilities dict must contain one entry per class."""
        result = self.predictor.predict_one(self.valid_row)
        if result.status != PredictionStatus.REJECTED:
            self.assertEqual(len(result.class_probabilities), EXPECTED_CLASS_COUNT)

    def test_labeled_class_is_highest_probability(self) -> None:
        """The returned label must correspond to argmax of class_probabilities."""
        result = self.predictor.predict_one(self.valid_row)
        if result.status != PredictionStatus.REJECTED:
            top_class = max(result.class_probabilities, key=result.class_probabilities.__getitem__)
            self.assertEqual(result.label, top_class)

    def test_predict_one_and_batch_agree(self) -> None:
        """predict_one must give the same label as the first slot of predict_batch."""
        rows = [self.valid_row] * 3
        single = self.predictor.predict_one(self.valid_row)
        batch = self.predictor.predict_batch(rows)
        if single.status != PredictionStatus.REJECTED and batch[0].status != PredictionStatus.REJECTED:
            self.assertEqual(single.label, batch[0].label)

    def test_contexts_length_mismatch_raises(self) -> None:
        """Mismatched contexts list must raise ValueError."""
        with self.assertRaises(ValueError):
            self.predictor.predict_batch(
                [self.valid_row, self.valid_row], contexts=[None]
            )


# ---------------------------------------------------------------------------
# REJECTED path for invalid input
# ---------------------------------------------------------------------------

class TestRejectedResults(unittest.TestCase):
    """Verify that invalid input produces a REJECTED result, not an exception."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.predictor = load_predictor()

    def test_none_input_is_rejected(self) -> None:
        """None input must yield REJECTED status without raising."""
        result = self.predictor.predict_one(None)  # type: ignore[arg-type]
        self.assertEqual(result.status, PredictionStatus.REJECTED)
        self.assertFalse(result.is_attack)
        self.assertEqual(result.label, "REJECTED")
        self.assertEqual(result.confidence, 0.0)

    def test_rejected_result_has_error_message(self) -> None:
        """A REJECTED result must include a non-empty error string."""
        result = self.predictor.predict_one(None)  # type: ignore[arg-type]
        self.assertIsNotNone(result.error)
        self.assertGreater(len(result.error), 0)

    def test_batch_with_one_bad_row_rejected_individually(self) -> None:
        """A batch containing one None must reject only that slot."""
        valid_row = load_valid_row()
        rows = [valid_row, None, valid_row]  # type: ignore[list-item]
        results = self.predictor.predict_batch(rows)
        self.assertEqual(len(results), 3)
        self.assertNotEqual(results[0].status, PredictionStatus.REJECTED)
        self.assertEqual(results[1].status, PredictionStatus.REJECTED)
        self.assertNotEqual(results[2].status, PredictionStatus.REJECTED)


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

class TestResultSerialisation(unittest.TestCase):
    """Verify PredictionResult.to_dict() produces a JSON-safe structure."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.predictor = load_predictor()
        cls.valid_row = load_valid_row()

    def test_to_dict_returns_dict(self) -> None:
        result = self.predictor.predict_one(self.valid_row)
        d = result.to_dict()
        self.assertIsInstance(d, dict)

    def test_to_dict_contains_required_keys(self) -> None:
        result = self.predictor.predict_one(self.valid_row)
        d = result.to_dict()
        for key in ("status", "label", "confidence", "is_attack", "class_probabilities"):
            self.assertIn(key, d, f"key '{key}' missing from to_dict()")

    def test_rejected_to_dict_has_error(self) -> None:
        result = self.predictor.predict_one(None)  # type: ignore[arg-type]
        d = result.to_dict()
        self.assertIn("error", d)

    def test_to_dict_values_are_json_serialisable(self) -> None:
        """Verify values are basic Python types, not numpy arrays or scalars."""
        import json
        result = self.predictor.predict_one(self.valid_row)
        try:
            json.dumps(result.to_dict())
        except (TypeError, ValueError) as exc:
            self.fail(f"to_dict() is not JSON-serialisable: {exc}")


# ---------------------------------------------------------------------------
# Thread-safety
# ---------------------------------------------------------------------------

class TestThreadSafety(unittest.TestCase):
    """Concurrent prediction calls must not corrupt each other."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.predictor = load_predictor()
        cls.valid_row = load_valid_row()

    def test_concurrent_predictions_are_stable(self) -> None:
        """Twenty threads each making 5 predictions must all agree."""
        n_threads = 20
        n_per_thread = 5
        reference = self.predictor.predict_one(self.valid_row)
        if reference.status == PredictionStatus.REJECTED:
            self.skipTest("Reference prediction was rejected")

        errors: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            for _ in range(n_per_thread):
                result = self.predictor.predict_one(self.valid_row)
                if result.label != reference.label:
                    with lock:
                        errors.append(
                            f"expected {reference.label} got {result.label}"
                        )

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [], f"Thread-safety errors: {errors}")


# ---------------------------------------------------------------------------
# Known-holdout verification
# ---------------------------------------------------------------------------

class TestKnownHoldoutMatch(unittest.TestCase):
    """Runtime prediction on a holdout sample must match direct model prediction."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.predictor = load_predictor()
        cls.model = joblib.load(MV3 / "intrusion_model_v3.pkl")
        cls.encoder = joblib.load(MV3 / "label_encoder_v3.pkl")
        cls.x_test = np.load(P3 / "X_test_v3.npy")
        cls.y_test = np.load(P3 / "y_test_v3.npy")
        cls.provenance = pd.read_parquet(P3 / "test_provenance_v3.parquet")
        cls.dataset = pd.read_parquet(P3 / "cleaned_dataset_v3.parquet")

    def test_label_matches_direct_model_on_holdout_sample(self) -> None:
        """Predictor label must match direct model.predict on the same X_test row."""
        rows_tried = 0
        mismatches = 0
        for index, (_, prov) in enumerate(self.provenance.iterrows()):
            if rows_tried >= 50:
                break
            m = self.dataset[
                (self.dataset["_source_file"] == prov["_source_file"])
                & (self.dataset["_source_row"] == prov["_source_row"])
            ]
            if m.empty:
                continue
            raw = m.iloc[0].to_dict()
            for col in DROP_COLUMNS:
                raw.pop(col, None)

            result = self.predictor.predict_one(raw)
            if result.status == PredictionStatus.REJECTED:
                continue

            # Direct model output using the stored scaled vector
            direct_class_id = int(self.model.predict(self.x_test[index : index + 1])[0])
            direct_label = str(self.encoder.classes_[direct_class_id])
            if result.label != direct_label:
                mismatches += 1
            rows_tried += 1

        self.assertGreaterEqual(rows_tried, 10, "Not enough holdout rows verified")
        self.assertEqual(mismatches, 0, f"{mismatches}/{rows_tried} holdout labels differ")


if __name__ == "__main__":
    unittest.main(verbosity=2)