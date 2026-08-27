"""Runtime preprocessing parity and validation tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from prediction.schemas import EXPECTED_FEATURE_COUNT, FeatureQuality
from prediction.transform import RuntimePreprocessor

P3 = ROOT.parent / "dataset" / "processed" / "v3"
MV3 = ROOT / "models" / "v3"
DROP_COLUMNS = ("_source_file", "_capture_day", "_source_row", "Label")


def load_transformer() -> RuntimePreprocessor:
    """Load the persisted v3 runtime preprocessor."""
    return RuntimePreprocessor(joblib.load(MV3 / "preprocessor_v3.pkl"))


class TestRuntimeTransform(unittest.TestCase):
    """Validate runtime output against training-time stored arrays."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load source artifacts once for all parity checks."""
        cls.transformer = load_transformer()
        cls.x_test = np.load(P3 / "X_test_v3.npy")
        cls.provenance = pd.read_parquet(P3 / "test_provenance_v3.parquet")
        cls.dataset = pd.read_parquet(P3 / "cleaned_dataset_v3.parquet")

    def reconstruct_rows(self, count: int) -> tuple[list[dict[str, object]], list[int]]:
        """Reconstruct raw holdout rows from provenance references.

        Args:
            count: Number of rows to reconstruct.

        Returns:
            Raw feature mappings and matching X_test_v3 row indexes.
        """
        rows: list[dict[str, object]] = []
        indexes: list[int] = []
        for index, (_, provenance) in enumerate(self.provenance.iterrows()):
            if len(rows) >= count:
                break
            match = self.dataset[
                (self.dataset["_source_file"] == provenance["_source_file"])
                & (self.dataset["_source_row"] == provenance["_source_row"])
            ]
            if match.empty:
                continue
            row = match.iloc[0].to_dict()
            for column in DROP_COLUMNS:
                row.pop(column, None)
            rows.append(row)
            indexes.append(index)
        return rows, indexes

    def test_parity_on_one_thousand_rows(self) -> None:
        """Runtime preprocessing must match training-time X_test_v3 values."""
        rows, indexes = self.reconstruct_rows(1000)
        self.assertEqual(len(rows), 1000)
        results = self.transformer.transform_batch(rows)
        for row_number, (result, array_index) in enumerate(zip(results, indexes)):
            self.assertTrue(result.success, f"row {row_number}: {result.error}")
            np.testing.assert_allclose(
                result.scaled_vector,
                self.x_test[array_index],
                atol=1e-4,
                rtol=1e-3,
                err_msg=f"row {row_number} differs from X_test_v3",
            )

    def test_output_shape_dtype_and_finiteness(self) -> None:
        """Successful transforms must be finite float32 vectors of length 40."""
        rows, _ = self.reconstruct_rows(25)
        for result in self.transformer.transform_batch(rows):
            self.assertTrue(result.success, result.error)
            self.assertEqual(result.scaled_vector.shape, (EXPECTED_FEATURE_COUNT,))
            self.assertEqual(result.scaled_vector.dtype, np.float32)
            self.assertTrue(np.isfinite(result.scaled_vector).all())

    def test_single_and_batch_are_identical(self) -> None:
        """Single-row and batch transformation paths must agree exactly."""
        rows, _ = self.reconstruct_rows(10)
        batch = self.transformer.transform_batch(rows)
        for row, expected in zip(rows, batch):
            actual = self.transformer.transform_one(row)
            self.assertTrue(actual.success)
            np.testing.assert_array_equal(actual.scaled_vector, expected.scaled_vector)

    def test_invalid_values_are_imputed_without_nonfinite_output(self) -> None:
        """Invalid numerical values must be safely imputed from fitted medians."""
        rows, _ = self.reconstruct_rows(1)
        row = rows[0]
        row["Flow Duration"] = float("inf")
        row["Destination Port"] = 99999
        result = self.transformer.transform_one(row)
        self.assertTrue(result.success, result.error)
        self.assertIn("Flow Duration", result.rejected_fields + result.imputed_fields)
        self.assertIn("Destination Port", result.rejected_fields + result.imputed_fields)
        self.assertTrue(np.isfinite(result.scaled_vector).all())

    def test_empty_input_is_degraded_but_transformable(self) -> None:
        """An empty mapping uses fitted medians and reports degraded quality."""
        result = self.transformer.transform_one({})
        self.assertTrue(result.success, result.error)
        self.assertEqual(result.feature_quality, FeatureQuality.DEGRADED)
        self.assertGreater(len(result.imputed_fields), 0)

    def test_none_input_is_rejected(self) -> None:
        """None must fail cleanly instead of raising an exception."""
        result = self.transformer.transform_one(None)  # type: ignore[arg-type]
        self.assertFalse(result.success)
        self.assertEqual(result.feature_quality, FeatureQuality.INVALID)


if __name__ == "__main__":
    unittest.main(verbosity=2)