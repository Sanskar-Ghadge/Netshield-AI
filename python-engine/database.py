"""SQLite database layer for NetShield AI.

Thread-safe singleton that logs predictions, queries attack history,
and computes summary statistics and threat levels.

Tables:
    attacks       — one row per predicted flow (attack or benign).
    traffic_stats — per-minute aggregate counters.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Any, Optional

from prediction.schemas import PredictionResult

_THREAT_SAFE: int = 0
_THREAT_ELEVATED_THRESHOLD: int = 1
_THREAT_CRITICAL_THRESHOLD: int = 6
_WINDOW_SECONDS: float = 60.0


class Database:
    """Thread-safe SQLite wrapper for prediction logging and queries.

    Args:
        db_path: Filesystem path to the SQLite database.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        # Ensure the parent directory exists before opening the connection
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn: sqlite3.Connection = sqlite3.connect(
            db_path, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._init_tables()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_tables(self) -> None:
        """Create tables if they do not exist."""
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attack_type TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    is_attack INTEGER NOT NULL,
                    flow_id TEXT,
                    timestamp_utc REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    total_packets INTEGER NOT NULL,
                    normal_count INTEGER NOT NULL,
                    attack_count INTEGER NOT NULL,
                    timestamp_utc REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_attacks_ts
                    ON attacks(timestamp_utc);
                CREATE INDEX IF NOT EXISTS idx_attacks_type
                    ON attacks(attack_type);
                CREATE INDEX IF NOT EXISTS idx_attacks_src
                    ON attacks(src_ip);
                """
            )
            self._conn.commit()

    def clear_all_data(self) -> None:
        """Clear all stored attacks and traffic stats from the database."""
        with self._lock:
            self._conn.executescript(
                """
                DELETE FROM attacks;
                DELETE FROM traffic_stats;
                """
            )
            self._conn.commit()
            self._conn.execute("VACUUM;")

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log_prediction(self, result: PredictionResult) -> None:
        """Insert one prediction result into the database.

        Args:
            result: A PredictionResult from the inference engine.
        """
        ctx = result.context
        src_ip = ctx.src_ip if ctx else ""
        dst_ip = ctx.dst_ip if ctx else ""
        src_port = ctx.src_port if ctx else 0
        dst_port = ctx.dst_port if ctx else 0
        protocol = ctx.protocol if ctx else 0
        flow_id = ctx.flow_id if ctx else ""

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO attacks
                    (attack_type, src_ip, dst_ip, src_port, dst_port,
                     protocol, confidence, is_attack, flow_id, timestamp_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.label,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    result.confidence,
                    1 if result.is_attack else 0,
                    flow_id,
                    result.timestamp_utc,
                ),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_attacks(
        self,
        limit: int = 50,
        offset: int = 0,
        attack_type: Optional[str] = None,
        only_attacks: bool = False,
    ) -> list[dict[str, Any]]:
        """Return paginated attack/prediction records.

        Args:
            limit: Maximum number of rows.
            offset: Pagination offset.
            attack_type: Optional filter by label (e.g. "DDoS").
            only_attacks: If True (default), filter by is_attack = 1.

        Returns:
            List of row dictionaries.
        """
        with self._lock:
            if attack_type and attack_type != "All":
                cur = self._conn.execute(
                    """
                    SELECT * FROM attacks
                    WHERE attack_type = ?
                    ORDER BY timestamp_utc DESC
                    LIMIT ? OFFSET ?
                    """,
                    (attack_type, limit, offset),
                )
            elif only_attacks:
                cur = self._conn.execute(
                    """
                    SELECT * FROM attacks
                    WHERE is_attack = 1
                    ORDER BY timestamp_utc DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            else:
                cur = self._conn.execute(
                    """
                    SELECT * FROM attacks
                    ORDER BY timestamp_utc DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            rows = cur.fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict[str, Any]:
        """Return aggregate statistics.

        Returns:
            Dictionary with total, normal, attack counts and
            attack-type distribution.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(*) AS c FROM attacks"
            )
            total = cur.fetchone()["c"]

            cur = self._conn.execute(
                "SELECT COUNT(*) AS c FROM attacks WHERE is_attack = 0"
            )
            normal = cur.fetchone()["c"]

            cur = self._conn.execute(
                "SELECT COUNT(*) AS c FROM attacks WHERE is_attack = 1"
            )
            attacks = cur.fetchone()["c"]

            cur = self._conn.execute(
                """
                SELECT attack_type, COUNT(*) AS cnt
                FROM attacks
                WHERE is_attack = 1
                GROUP BY attack_type
                ORDER BY cnt DESC
                """
            )
            distribution = [
                {"attack_type": r["attack_type"], "count": r["cnt"]}
                for r in cur.fetchall()
            ]

        return {
            "total": total,
            "normal": normal,
            "attacks": attacks,
            "attack_distribution": distribution,
        }

    def get_attack_summary(self) -> list[dict[str, Any]]:
        """Return per-attack-type summary with counts and percentages.

        Returns:
            List of dictionaries with attack_type, count, percentage.
        """
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT attack_type, COUNT(*) AS cnt
                FROM attacks WHERE is_attack = 1
                GROUP BY attack_type
                ORDER BY cnt DESC
                """
            )
            rows = cur.fetchall()
            total = sum(r["cnt"] for r in rows)

        result: list[dict[str, Any]] = []
        for r in rows:
            pct = (r["cnt"] / total * 100) if total > 0 else 0.0
            result.append(
                {
                    "attack_type": r["attack_type"],
                    "count": r["cnt"],
                    "percentage": round(pct, 2),
                }
            )
        return result

    def get_top_attackers(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return top attacker IPs by frequency.

        Args:
            limit: Maximum number of entries.

        Returns:
            List of dictionaries with src_ip, count.
        """
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT src_ip, COUNT(*) AS cnt
                FROM attacks WHERE is_attack = 1
                GROUP BY src_ip
                ORDER BY cnt DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cur.fetchall()
        return [{"src_ip": r["src_ip"], "count": r["cnt"]} for r in rows]

    def get_recent_predictions(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the most recent prediction records.

        Args:
            limit: Maximum number of rows.

        Returns:
            List of row dictionaries.
        """
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT * FROM attacks
                ORDER BY timestamp_utc DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cur.fetchall()
        return [dict(r) for r in rows]

    def get_threat_level(self) -> str:
        """Return the current threat level based on attacks in the last 60s.

        Returns:
            "SAFE" (0 attacks), "ELEVATED" (1-5), or "CRITICAL" (6+).
        """
        cutoff = time.time() - _WINDOW_SECONDS
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT COUNT(*) AS c FROM attacks
                WHERE is_attack = 1 AND timestamp_utc >= ?
                """,
                (cutoff,),
            )
            count = cur.fetchone()["c"]
        if count >= _THREAT_CRITICAL_THRESHOLD:
            return "CRITICAL"
        if count >= _THREAT_ELEVATED_THRESHOLD:
            return "ELEVATED"
        return "SAFE"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._conn.close()
