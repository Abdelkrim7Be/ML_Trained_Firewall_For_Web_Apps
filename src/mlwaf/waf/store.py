"""The decision log.

SQLite in WAL mode: one file, no second service to run, and decisions survive a
restart. Every decision keeps its score, which is what makes the console's
threshold slider possible: changing the threshold is a query over stored scores,
not a replay of traffic.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id    TEXT    NOT NULL,
    ts            REAL    NOT NULL,
    method        TEXT    NOT NULL,
    path          TEXT    NOT NULL,
    query         TEXT    NOT NULL DEFAULT '',
    body_preview  TEXT    NOT NULL DEFAULT '',
    client        TEXT    NOT NULL DEFAULT '',
    verdict       TEXT    NOT NULL,
    would_block   INTEGER NOT NULL,
    score         REAL    NOT NULL,
    attack_class  TEXT    NOT NULL,
    threshold     REAL    NOT NULL,
    latency_ms    REAL    NOT NULL,
    cached        INTEGER NOT NULL DEFAULT 0,
    degraded      INTEGER NOT NULL DEFAULT 0,
    reason        TEXT    NOT NULL DEFAULT '',
    decode_depth  INTEGER NOT NULL DEFAULT 0,
    canonical     TEXT    NOT NULL DEFAULT '',
    explanation   TEXT    NOT NULL DEFAULT '',
    feedback      TEXT    NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_score ON decisions(score DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_would_block ON decisions(would_block, ts DESC);
"""


@dataclass
class DecisionRecord:
    request_id: str
    method: str
    path: str
    query: str
    body_preview: str
    client: str
    verdict: str
    would_block: bool
    score: float
    attack_class: str
    threshold: float
    latency_ms: float
    cached: bool
    degraded: bool
    reason: str
    decode_depth: int
    canonical: str
    explanation: dict[str, Any]
    ts: float = 0.0
    id: int | None = None


class Store:
    def __init__(self, path: str, retention_rows: int = 200_000):
        self.path = path
        self.retention_rows = retention_rows
        # One connection guarded by a lock. Writes here are small and infrequent
        # relative to request handling, and a lock is easier to reason about than
        # a pool for a single node service.
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._writes_since_trim = 0

    def connect(self) -> None:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # WAL lets the console read while the proxy writes.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # --- writes --------------------------------------------------------------
    def insert(self, record: DecisionRecord) -> int:
        record.ts = record.ts or time.time()
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO decisions (
                    request_id, ts, method, path, query, body_preview, client,
                    verdict, would_block, score, attack_class, threshold,
                    latency_ms, cached, degraded, reason, decode_depth,
                    canonical, explanation
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    record.request_id, record.ts, record.method, record.path,
                    record.query, record.body_preview, record.client,
                    record.verdict, int(record.would_block), record.score,
                    record.attack_class, record.threshold, record.latency_ms,
                    int(record.cached), int(record.degraded), record.reason,
                    record.decode_depth, record.canonical,
                    json.dumps(record.explanation),
                ),
            )
            self._conn.commit()
            self._writes_since_trim += 1
            if self._writes_since_trim >= 1000:
                self._trim()
            return int(cur.lastrowid)

    def _trim(self) -> None:
        """Keep the log bounded so a long run cannot fill the disk."""
        self._writes_since_trim = 0
        self._conn.execute(
            """
            DELETE FROM decisions WHERE id <= (
                SELECT id FROM decisions ORDER BY id DESC LIMIT 1 OFFSET ?
            )
            """,
            (self.retention_rows,),
        )
        self._conn.commit()

    def set_feedback(self, decision_id: int, label: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE decisions SET feedback = ? WHERE id = ?", (label, decision_id)
            )
            self._conn.commit()
            return cur.rowcount > 0

    # --- reads ---------------------------------------------------------------
    def recent(self, limit: int = 100, verdict: str | None = None,
               attack_class: str | None = None, only_flagged: bool = False,
               search: str | None = None) -> list[dict]:
        clauses, params = [], []
        if verdict:
            clauses.append("verdict = ?")
            params.append(verdict)
        if attack_class:
            clauses.append("attack_class = ?")
            params.append(attack_class)
        if only_flagged:
            clauses.append("would_block = 1")
        if search:
            clauses.append("(path LIKE ? OR query LIKE ?)")
            params += [f"%{search}%", f"%{search}%"]

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM decisions {where} ORDER BY id DESC LIMIT ?", params
            ).fetchall()
        return [self._row(r) for r in rows]

    def get(self, decision_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM decisions WHERE id = ?", (decision_id,)
            ).fetchone()
        return self._row(row) if row else None

    def summary(self, window_s: float = 300.0) -> dict:
        since = time.time() - window_s
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*)                                    AS total,
                       SUM(verdict = 'block')                      AS blocked,
                       SUM(would_block)                            AS flagged,
                       SUM(degraded)                               AS degraded,
                       AVG(latency_ms)                             AS avg_latency,
                       MAX(latency_ms)                             AS max_latency
                FROM decisions WHERE ts >= ?
                """,
                (since,),
            ).fetchone()
            classes = self._conn.execute(
                """
                SELECT attack_class, COUNT(*) AS n FROM decisions
                WHERE ts >= ? AND would_block = 1 GROUP BY attack_class
                """,
                (since,),
            ).fetchall()
        return {
            "window_seconds": window_s,
            "total": row["total"] or 0,
            "blocked": row["blocked"] or 0,
            "flagged": row["flagged"] or 0,
            "degraded": row["degraded"] or 0,
            "avg_latency_ms": round(row["avg_latency"] or 0.0, 3),
            "max_latency_ms": round(row["max_latency"] or 0.0, 3),
            "by_class": {r["attack_class"]: r["n"] for r in classes},
        }

    def traffic_series(self, buckets: int = 60, bucket_s: float = 5.0) -> list[dict]:
        """Recent volume, bucketed, for the console sparkline."""
        now = time.time()
        start = now - buckets * bucket_s
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT CAST((? - ts) / ? AS INTEGER) AS bucket,
                       COUNT(*) AS total,
                       SUM(would_block) AS flagged
                FROM decisions WHERE ts >= ? GROUP BY bucket
                """,
                (now, bucket_s, start),
            ).fetchall()
        counts = {r["bucket"]: (r["total"], r["flagged"] or 0) for r in rows}
        return [
            {"bucket": i,
             "total": counts.get(buckets - 1 - i, (0, 0))[0],
             "flagged": counts.get(buckets - 1 - i, (0, 0))[1]}
            for i in range(buckets)
        ]

    def threshold_impact(self, threshold: float, window_s: float = 3600.0) -> dict:
        """What a different threshold would have done to traffic already seen.

        This is the whole reason scores are stored rather than just verdicts. The
        operator moves a slider and gets an answer computed over real traffic
        instead of a promise.
        """
        since = time.time() - window_s
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(score >= ?) AS would_block_now,
                       SUM(would_block) AS would_block_current
                FROM decisions WHERE ts >= ?
                """,
                (threshold, since),
            ).fetchone()
            flips = self._conn.execute(
                """
                SELECT id, path, query, score, attack_class, would_block
                FROM decisions
                WHERE ts >= ? AND (score >= ?) != (would_block = 1)
                ORDER BY score DESC LIMIT 25
                """,
                (since, threshold),
            ).fetchall()
        return {
            "threshold": threshold,
            "window_seconds": window_s,
            "total": row["total"] or 0,
            "blocked_at_this_threshold": row["would_block_now"] or 0,
            "blocked_at_current_threshold": row["would_block_current"] or 0,
            "flips": [dict(f) for f in flips],
        }

    def feedback_counts(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT feedback, COUNT(*) AS n FROM decisions "
                "WHERE feedback IS NOT NULL GROUP BY feedback"
            ).fetchall()
        return {r["feedback"]: r["n"] for r in rows}

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["would_block"] = bool(d["would_block"])
        d["cached"] = bool(d["cached"])
        d["degraded"] = bool(d["degraded"])
        try:
            d["explanation"] = json.loads(d["explanation"] or "{}")
        except json.JSONDecodeError:
            d["explanation"] = {}
        return d
