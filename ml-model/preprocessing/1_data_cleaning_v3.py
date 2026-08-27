"""Auditable CICIDS2017 raw-data cleaning pipeline.

This module reads all eight MachineLearningCSV files, records their hashes and
schema, repairs labels and invalid values, removes duplicate/conflicting rows,
and writes a versioned Parquet dataset. It never modifies raw inputs or legacy
artifacts.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

import numpy as np
import pandas as pd

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
RAW_DIR: Final[Path] = PROJECT_ROOT / "CICIDS2017"
OUTPUT_DIR: Final[Path] = PROJECT_ROOT / "dataset" / "processed" / "v3"
OUTPUT_FILE: Final[Path] = OUTPUT_DIR / "cleaned_dataset_v3.parquet"
MANIFEST_FILE: Final[Path] = OUTPUT_DIR / "raw_manifest.json"
AUDIT_FILE: Final[Path] = OUTPUT_DIR / "cleaning_audit.json"
CHUNK_SIZE: Final[int] = 100_000
TARGET: Final[str] = "Label"
PROVENANCE_COLUMNS: Final[tuple[str, ...]] = (
    "_source_file",
    "_capture_day",
    "_source_row",
)
EXPECTED_FILE_COUNT: Final[int] = 8
EXPECTED_COLUMN_COUNT: Final[int] = 79

LABEL_MAP: Final[dict[str, str]] = {
    "BENIGN": "BENIGN",
    "Bot": "Bot",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "Infiltration": "Infiltration",
    "Heartbleed": "Heartbleed",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
}

NONNEGATIVE_PATTERNS: Final[tuple[str, ...]] = (
    "Duration",
    "Packets",
    "Packet",
    "Bytes",
    "Length",
    "IAT",
    "Header",
    "Active",
    "Idle",
    "Bulk",
    "Segment",
    "Subflow",
)
NONNEGATIVE_EXCEPTIONS: Final[frozenset[str]] = frozenset(
    {"Init_Win_bytes_forward", "Init_Win_bytes_backward"}
)
FLAG_COLUMNS: Final[frozenset[str]] = frozenset(
    {
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
    }
)


@dataclass(frozen=True)
class RawFileManifest:
    """Immutable metadata for one raw dataset file."""

    filename: str
    sha256: str
    bytes: int
    rows: int
    columns: int
    labels: dict[str, int]


@dataclass
class CleaningAudit:
    """Counters and decisions produced by the cleaning run."""

    version: int
    raw_rows: int = 0
    output_rows: int = 0
    numeric_parse_failures: int = 0
    infinite_values_replaced: int = 0
    invalid_negative_values_replaced: int = 0
    invalid_ports_replaced: int = 0
    missing_label_rows_removed: int = 0
    exact_duplicates_removed: int = 0
    conflicting_feature_rows_removed: int = 0
    duplicate_feature_columns_removed: list[str] | None = None
    all_zero_columns_observed: list[str] | None = None
    output_label_counts: dict[str, int] | None = None

    def __post_init__(self) -> None:
        """Initialize mutable collection fields safely."""
        if self.duplicate_feature_columns_removed is None:
            self.duplicate_feature_columns_removed = []
        if self.all_zero_columns_observed is None:
            self.all_zero_columns_observed = []
        if self.output_label_counts is None:
            self.output_label_counts = {}


def sha256_file(path: Path) -> str:
    """Calculate the SHA-256 digest of a file.

    Args:
        path: File to hash.

    Returns:
        Lowercase hexadecimal SHA-256 digest.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_label(value: object) -> str | None:
    """Repair encoding/spacing and map one raw label to a grouped class.

    Args:
        value: Raw label value.

    Returns:
        Grouped class name, or ``None`` for a missing label.

    Raises:
        ValueError: If a nonempty label is unknown.
    """
    if value is None or pd.isna(value):
        return None
    label = str(value).strip()
    if not label:
        return None
    label = re.sub(r"[\u2013\u2014\ufffd\u00adï¿½]+", " - ", label)
    label = re.sub(r"\s*-\s*", "-", label)
    label = re.sub(r"^Web Attack-", "Web Attack - ", label)
    label = re.sub(r"\s+", " ", label).strip()
    if label not in LABEL_MAP:
        raise ValueError(f"Unknown CICIDS2017 label: {label!r}")
    return LABEL_MAP[label]


def capture_day(filename: str) -> str:
    """Extract the weekday represented by a CICIDS2017 filename.

    Args:
        filename: Raw CSV filename.

    Returns:
        Lowercase weekday name.
    """
    return filename.split("-", maxsplit=1)[0].lower()


def discover_raw_files(raw_dir: Path) -> list[Path]:
    """Find and validate the complete set of raw CSV files.

    Args:
        raw_dir: Directory containing raw CSV files.

    Returns:
        Sorted list of exactly eight CSV paths.

    Raises:
        FileNotFoundError: If the directory does not exist.
        ValueError: If the file count is not eight.
    """
    if not raw_dir.is_dir():
        raise FileNotFoundError(f"Raw dataset directory not found: {raw_dir}")
    files = sorted(raw_dir.glob("*.csv"))
    if len(files) != EXPECTED_FILE_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_FILE_COUNT} raw CSV files, found {len(files)}"
        )
    return files


def inspect_raw_file(path: Path) -> RawFileManifest:
    """Collect schema, row, label, and checksum metadata for one CSV.

    Args:
        path: Raw CICIDS2017 CSV.

    Returns:
        Manifest record.
    """
    rows = 0
    labels: dict[str, int] = {}
    observed_columns: list[str] | None = None
    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        if observed_columns is None:
            observed_columns = chunk.columns.tolist()
        elif chunk.columns.tolist() != observed_columns:
            raise ValueError(f"Schema changed inside {path.name}")
        if TARGET not in chunk.columns:
            raise ValueError(f"Missing {TARGET!r} in {path.name}")
        rows += len(chunk)
        for label, count in chunk[TARGET].astype("string").str.strip().value_counts().items():
            labels[str(label)] = labels.get(str(label), 0) + int(count)
    columns = len(observed_columns or [])
    if columns != EXPECTED_COLUMN_COUNT:
        raise ValueError(
            f"{path.name} has {columns} columns; expected {EXPECTED_COLUMN_COUNT}"
        )
    return RawFileManifest(
        filename=path.name,
        sha256=sha256_file(path),
        bytes=path.stat().st_size,
        rows=rows,
        columns=columns,
        labels=labels,
    )


def load_and_clean_file(path: Path, audit: CleaningAudit) -> pd.DataFrame:
    """Load one raw CSV and apply deterministic, non-learned repairs.

    Args:
        path: Raw CSV path.
        audit: Mutable run audit counters.

    Returns:
        Cleaned frame including provenance columns.
    """
    frames: list[pd.DataFrame] = []
    source_row = 0
    for raw in pd.read_csv(path, chunksize=CHUNK_SIZE, low_memory=False):
        raw.columns = raw.columns.str.strip()
        if raw.columns.duplicated().any():
            duplicates = raw.columns[raw.columns.duplicated()].tolist()
            raise ValueError(f"Duplicate column names in {path.name}: {duplicates}")
        audit.raw_rows += len(raw)
        raw[TARGET] = raw[TARGET].map(normalize_label)
        missing_labels = int(raw[TARGET].isna().sum())
        audit.missing_label_rows_removed += missing_labels
        raw = raw.loc[raw[TARGET].notna()].copy()

        feature_columns = [column for column in raw.columns if column != TARGET]
        original_nonmissing = raw[feature_columns].notna()
        raw[feature_columns] = raw[feature_columns].apply(pd.to_numeric, errors="coerce")
        audit.numeric_parse_failures += int(
            (original_nonmissing & raw[feature_columns].isna()).sum().sum()
        )

        numeric = raw[feature_columns]
        infinity_mask = np.isinf(numeric.to_numpy(dtype=np.float64, copy=False))
        audit.infinite_values_replaced += int(infinity_mask.sum())
        raw[feature_columns] = numeric.replace([np.inf, -np.inf], np.nan)

        for column in feature_columns:
            if column in NONNEGATIVE_EXCEPTIONS:
                continue
            if column in FLAG_COLUMNS or any(
                token in column for token in NONNEGATIVE_PATTERNS
            ) or column in {"Flow Bytes/s", "Flow Packets/s", "Down/Up Ratio", "act_data_pkt_fwd"}:
                invalid = raw[column] < 0
                count = int(invalid.sum())
                if count:
                    raw.loc[invalid, column] = np.nan
                    audit.invalid_negative_values_replaced += count

        if "Destination Port" in raw.columns:
            bad_port = raw["Destination Port"].notna() & ~raw[
                "Destination Port"
            ].between(0, 65535)
            audit.invalid_ports_replaced += int(bad_port.sum())
            raw.loc[bad_port, "Destination Port"] = np.nan

        row_count = len(raw)
        raw["_source_file"] = path.name
        raw["_capture_day"] = capture_day(path.name)
        raw["_source_row"] = np.arange(
            source_row, source_row + row_count, dtype=np.int64
        )
        source_row += len(raw) + missing_labels
        frames.append(raw)
    if not frames:
        raise ValueError(f"No rows loaded from {path.name}")
    return pd.concat(frames, ignore_index=True)


def remove_verified_duplicate_features(
    data: pd.DataFrame, audit: CleaningAudit
) -> pd.DataFrame:
    """Remove feature columns that are exactly equal, including missingness.

    Args:
        data: Combined cleaned dataset.
        audit: Mutable run audit.

    Returns:
        Dataset without verified duplicate features.
    """
    candidates = {
        "Fwd Header Length.1": "Fwd Header Length",
        "Subflow Fwd Packets": "Total Fwd Packets",
        "Subflow Fwd Bytes": "Total Length of Fwd Packets",
        "Subflow Bwd Packets": "Total Backward Packets",
        "Subflow Bwd Bytes": "Total Length of Bwd Packets",
    }
    dropped: list[str] = []
    for duplicate, canonical in candidates.items():
        if duplicate not in data.columns or canonical not in data.columns:
            continue
        if data[duplicate].equals(data[canonical]):
            dropped.append(duplicate)
    audit.duplicate_feature_columns_removed = dropped
    return data.drop(columns=dropped)


def remove_duplicates_and_conflicts(
    data: pd.DataFrame, audit: CleaningAudit
) -> pd.DataFrame:
    """Remove exact duplicates and feature-identical conflicting labels.

    A stable 64-bit pandas fingerprint is used to make the operation tractable;
    potential conflict groups are then identified by fingerprint and removed in
    full. Provenance is excluded from fingerprints.

    Args:
        data: Combined dataset.
        audit: Mutable run audit.

    Returns:
        Deduplicated, conflict-free frame.
    """
    features = [
        column
        for column in data.columns
        if column != TARGET and column not in PROVENANCE_COLUMNS
    ]
    feature_hash = pd.util.hash_pandas_object(data[features], index=False)
    exact_hash = pd.util.hash_pandas_object(data[features + [TARGET]], index=False)
    duplicate_mask = exact_hash.duplicated(keep="first")
    audit.exact_duplicates_removed = int(duplicate_mask.sum())
    data = data.loc[~duplicate_mask].copy()
    feature_hash = feature_hash.loc[~duplicate_mask]

    label_counts = data.groupby(feature_hash, sort=False)[TARGET].nunique()
    conflict_hashes = label_counts.index[label_counts > 1]
    conflict_mask = feature_hash.isin(conflict_hashes)
    audit.conflicting_feature_rows_removed = int(conflict_mask.sum())
    data = data.loc[~conflict_mask].copy()
    return data.reset_index(drop=True)


def find_all_zero_columns(data: pd.DataFrame) -> list[str]:
    """Find globally all-zero features for audit only.

    Args:
        data: Cleaned dataset.

    Returns:
        Sorted all-zero feature names.
    """
    features = [
        column
        for column in data.columns
        if column != TARGET and column not in PROVENANCE_COLUMNS
    ]
    return sorted(
        column
        for column in features
        if data[column].notna().any() and data[column].fillna(0).eq(0).all()
    )


def save_json(path: Path, payload: object) -> None:
    """Write JSON atomically through a temporary file.

    Args:
        path: Destination path.
        payload: JSON-serializable value.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    temporary.replace(path)


def main() -> None:
    """Run the complete auditable Phase 1 cleaning pipeline."""
    started = time.perf_counter()
    files = discover_raw_files(RAW_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Validating and hashing all {len(files)} raw files...")
    manifests = [inspect_raw_file(path) for path in files]
    save_json(
        MANIFEST_FILE,
        {
            "dataset": "CICIDS2017 MachineLearningCSV",
            "file_count": len(manifests),
            "total_rows": sum(item.rows for item in manifests),
            "files": [asdict(item) for item in manifests],
        },
    )

    audit = CleaningAudit(version=3)
    frames: list[pd.DataFrame] = []
    for path in files:
        print(f"Cleaning {path.name}...")
        frames.append(load_and_clean_file(path, audit))
    data = pd.concat(frames, ignore_index=True)
    del frames

    data = remove_verified_duplicate_features(data, audit)
    data = remove_duplicates_and_conflicts(data, audit)
    audit.all_zero_columns_observed = find_all_zero_columns(data)
    audit.output_rows = len(data)
    audit.output_label_counts = {
        str(label): int(count)
        for label, count in data[TARGET].value_counts().sort_index().items()
    }

    ordered = [
        column
        for column in data.columns
        if column not in PROVENANCE_COLUMNS and column != TARGET
    ] + list(PROVENANCE_COLUMNS) + [TARGET]
    data = data[ordered]
    data.to_parquet(OUTPUT_FILE, index=False, engine="pyarrow", compression="zstd")
    save_json(AUDIT_FILE, asdict(audit))

    print(f"Saved {len(data):,} rows to {OUTPUT_FILE}")
    print(f"Labels: {audit.output_label_counts}")
    print(f"All-zero columns observed: {audit.all_zero_columns_observed}")
    print(f"Elapsed: {time.perf_counter() - started:.1f} seconds")


if __name__ == "__main__":
    main()
