"""Validation tests for the CICIDS2017 v3 data pipeline."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

# preprocessing/ now lives in ml-model/
ML_MODEL_ROOT = ROOT.parent / "ml-model"

# Ensure ml-model is on sys.path so preprocessing.preprocessor_types resolves
if str(ML_MODEL_ROOT) not in sys.path:
    sys.path.insert(0, str(ML_MODEL_ROOT))


def load_module(name: str, path: Path) -> ModuleType:
    """Load a Python module from a numeric-prefixed script filename.

    Args:
        name: Synthetic import name.
        path: Script path.

    Returns:
        Loaded module object.
    """
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


cleaning = load_module(
    "cleaning_v3", ML_MODEL_ROOT / "preprocessing" / "1_data_cleaning_v3.py"
)
preprocessing = load_module(
    "preprocessing_v3", ML_MODEL_ROOT / "preprocessing" / "2_feature_engineering_v3.py"
)


class CleaningTests(unittest.TestCase):
    """Test deterministic Phase 1 cleaning behavior."""

    def test_all_known_labels_are_mapped(self) -> None:
        """Map normal, corrupted web, Bot, and grouped attack labels."""
        cases = {
            " BENIGN ": "BENIGN",
            "Bot": "Bot",
            "DoS Hulk": "DoS",
            "FTP-Patator": "BruteForce",
            "Web Attack � XSS": "WebAttack",
            "Web Attack – Sql Injection": "WebAttack",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(cleaning.normalize_label(raw), expected)

    def test_unknown_label_fails_closed(self) -> None:
        """Reject unknown labels instead of silently creating a class."""
        with self.assertRaises(ValueError):
            cleaning.normalize_label("UnknownAttack")

    def test_duplicate_and_conflicting_rows_are_removed(self) -> None:
        """Keep one exact row and remove all ambiguous feature groups."""
        frame = pd.DataFrame(
            {
                "A": [1.0, 1.0, 2.0, 2.0, 3.0],
                "B": [5.0, 5.0, 6.0, 6.0, 7.0],
                "_source_file": ["a", "a", "a", "b", "b"],
                "_capture_day": ["m", "m", "m", "t", "t"],
                "_source_row": [0, 1, 2, 3, 4],
                "Label": ["BENIGN", "BENIGN", "BENIGN", "DDoS", "Bot"],
            }
        )
        audit = cleaning.CleaningAudit(version=3)
        result = cleaning.remove_duplicates_and_conflicts(frame, audit)
        self.assertEqual(len(result), 2)
        self.assertEqual(audit.exact_duplicates_removed, 1)
        self.assertEqual(audit.conflicting_feature_rows_removed, 2)
        self.assertEqual(set(result["A"]), {1.0, 3.0})

    def test_duplicate_features_require_exact_equality(self) -> None:
        """Drop only candidate features proven exactly equal."""
        frame = pd.DataFrame(
            {
                "Fwd Header Length": [1.0, np.nan, 3.0],
                "Fwd Header Length.1": [1.0, np.nan, 3.0],
                "Total Fwd Packets": [1.0, 2.0, 3.0],
                "Subflow Fwd Packets": [1.0, 2.0, 4.0],
            }
        )
        audit = cleaning.CleaningAudit(version=3)
        result = cleaning.remove_verified_duplicate_features(frame, audit)
        self.assertNotIn("Fwd Header Length.1", result)
        self.assertIn("Subflow Fwd Packets", result)


class PreprocessingTests(unittest.TestCase):
    """Test leakage-safe fitted transformation behavior."""

    def test_imputation_uses_training_median_only(self) -> None:
        """Ensure holdout values cannot change learned medians."""
        train = pd.DataFrame({"A": [1.0, np.nan, 3.0], "B": [0.0, 1.0, 2.0]})
        test = pd.DataFrame({"A": [1_000_000.0, np.nan], "B": [3.0, 4.0]})
        train_result, test_result, all_null, medians = preprocessing.fit_imputation(
            train, test
        )
        self.assertEqual(all_null, [])
        self.assertEqual(medians["A"], 2.0)
        self.assertEqual(float(train_result.iloc[1]["A"]), 2.0)
        self.assertEqual(float(test_result.iloc[1]["A"]), 2.0)

    def test_constant_filter_is_training_fitted(self) -> None:
        """Drop a train-constant column even if holdout values vary."""
        train = pd.DataFrame({"constant": [0.0, 0.0], "useful": [1.0, 2.0]})
        test = pd.DataFrame({"constant": [0.0, 1.0], "useful": [3.0, 4.0]})
        filtered_train, filtered_test, constants = preprocessing.fit_constant_filter(
            train, test
        )
        self.assertEqual(constants, ["constant"])
        self.assertNotIn("constant", filtered_train)
        self.assertNotIn("constant", filtered_test)

    def test_outlier_transform_preserves_rows_and_finite_values(self) -> None:
        """Compress and clip extremes without deleting observations."""
        durations = np.arange(30, dtype=np.float32)
        durations[-1] = 100_000_000
        train = pd.DataFrame(
            {
                "Flow Duration": durations,
                "Destination Port": np.arange(30, dtype=np.float32),
            }
        )
        test = pd.DataFrame(
            {"Flow Duration": [1_000_000_000.0], "Destination Port": [443.0]}
        )
        transformed_train, transformed_test, logs, lower, upper = (
            preprocessing.fit_outlier_transform(train, test)
        )
        self.assertEqual(len(transformed_train), len(train))
        self.assertEqual(len(transformed_test), len(test))
        self.assertTrue(np.isfinite(transformed_train.to_numpy()).all())
        self.assertTrue(np.isfinite(transformed_test.to_numpy()).all())
        self.assertIn("Flow Duration", logs)
        self.assertLessEqual(
            float(transformed_test["Flow Duration"].iloc[0]), upper["Flow Duration"]
        )
        self.assertNotIn("Destination Port", lower)


if __name__ == "__main__":
    unittest.main(verbosity=2)
