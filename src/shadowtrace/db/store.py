"""SQLite persistence for events, fingerprints, and actor clusters."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    event_type TEXT NOT NULL,
    username TEXT,
    path TEXT,
    tool_hint TEXT,
    raw_json TEXT,
    session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    event_count INTEGER DEFAULT 0,
    vector_json TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    summary_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clusters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL UNIQUE,
    confidence REAL NOT NULL,
    member_ips_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS attributions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_a TEXT NOT NULL,
    ip_b TEXT NOT NULL,
    score REAL NOT NULL,
    breakdown_json TEXT NOT NULL,
    same_actor INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    ts: str
    src_ip: str
    event_type: str
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    username: str | None = None
    path: str | None = None
    tool_hint: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    session_id: str | None = None


class Store:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init(self) -> None:
        with self.connection() as conn:
            conn.executescript(SCHEMA)

    def clear_all(self) -> None:
        with self.connection() as conn:
            for table in ("events", "fingerprints", "clusters", "attributions", "meta"):
                conn.execute(f"DELETE FROM {table}")

    def insert_events(self, events: list[Event]) -> int:
        if not events:
            return 0
        rows = [
            (
                e.ts,
                e.src_ip,
                e.dst_ip,
                e.dst_port,
                e.protocol,
                e.event_type,
                e.username,
                e.path,
                e.tool_hint,
                json.dumps(e.raw),
                e.session_id,
            )
            for e in events
        ]
        with self.connection() as conn:
            conn.executemany(
                """INSERT INTO events
                   (ts, src_ip, dst_ip, dst_port, protocol, event_type,
                    username, path, tool_hint, raw_json, session_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
        return len(rows)

    def list_events(
        self,
        src_ip: str | None = None,
        limit: int = 5000,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        sql = f"SELECT * FROM events {where} ORDER BY ts ASC LIMIT ?"
        with self.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def distinct_ips(self) -> list[str]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT src_ip FROM events ORDER BY src_ip"
            ).fetchall()
        return [r["src_ip"] for r in rows]

    def event_counts_by_ip(self) -> dict[str, int]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT src_ip, COUNT(*) AS c FROM events GROUP BY src_ip"
            ).fetchall()
        return {r["src_ip"]: r["c"] for r in rows}

    def upsert_fingerprint(
        self,
        src_ip: str,
        vector: dict[str, float],
        labels: dict[str, str],
        summary: dict[str, Any],
        event_count: int,
    ) -> None:
        now = utcnow()
        payload = (
            src_ip,
            now,
            now,
            event_count,
            json.dumps(vector),
            json.dumps(labels),
            json.dumps(summary),
        )
        with self.connection() as conn:
            existing = conn.execute(
                "SELECT id FROM fingerprints WHERE src_ip = ?", (src_ip,)
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE fingerprints SET updated_at=?, event_count=?,
                       vector_json=?, labels_json=?, summary_json=? WHERE src_ip=?""",
                    (
                        now,
                        event_count,
                        json.dumps(vector),
                        json.dumps(labels),
                        json.dumps(summary),
                        src_ip,
                    ),
                )
            else:
                conn.execute(
                    """INSERT INTO fingerprints
                       (src_ip, created_at, updated_at, event_count,
                        vector_json, labels_json, summary_json)
                       VALUES (?,?,?,?,?,?,?)""",
                    payload,
                )

    def get_fingerprint(self, src_ip: str) -> Optional[dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM fingerprints WHERE src_ip = ?", (src_ip,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["vector"] = json.loads(d.pop("vector_json"))
        d["labels"] = json.loads(d.pop("labels_json"))
        d["summary"] = json.loads(d.pop("summary_json"))
        return d

    def list_fingerprints(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM fingerprints ORDER BY src_ip"
            ).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["vector"] = json.loads(d.pop("vector_json"))
            d["labels"] = json.loads(d.pop("labels_json"))
            d["summary"] = json.loads(d.pop("summary_json"))
            out.append(d)
        return out

    def replace_clusters(self, clusters: list[dict[str, Any]]) -> None:
        with self.connection() as conn:
            conn.execute("DELETE FROM clusters")
            for c in clusters:
                conn.execute(
                    """INSERT INTO clusters
                       (label, confidence, member_ips_json, created_at, notes)
                       VALUES (?,?,?,?,?)""",
                    (
                        c["label"],
                        c["confidence"],
                        json.dumps(c["members"]),
                        utcnow(),
                        c.get("notes", ""),
                    ),
                )

    def list_clusters(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM clusters ORDER BY label"
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["members"] = json.loads(d.pop("member_ips_json"))
            out.append(d)
        return out

    def replace_attributions(self, pairs: list[dict[str, Any]]) -> None:
        with self.connection() as conn:
            conn.execute("DELETE FROM attributions")
            for p in pairs:
                conn.execute(
                    """INSERT INTO attributions
                       (ip_a, ip_b, score, breakdown_json, same_actor, created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        p["ip_a"],
                        p["ip_b"],
                        p["score"],
                        json.dumps(p["breakdown"]),
                        1 if p["same_actor"] else 0,
                        utcnow(),
                    ),
                )

    def list_attributions(self, min_score: float = 0.0) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM attributions WHERE score >= ? ORDER BY score DESC",
                (min_score,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["breakdown"] = json.loads(d.pop("breakdown_json"))
            d["same_actor"] = bool(d["same_actor"])
            out.append(d)
        return out

    def set_meta(self, key: str, value: str) -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def stats(self) -> dict[str, Any]:
        with self.connection() as conn:
            events = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
            fps = conn.execute("SELECT COUNT(*) AS c FROM fingerprints").fetchone()["c"]
            clusters = conn.execute("SELECT COUNT(*) AS c FROM clusters").fetchone()["c"]
            attrs = conn.execute(
                "SELECT COUNT(*) AS c FROM attributions WHERE same_actor=1"
            ).fetchone()["c"]
        return {
            "events": events,
            "fingerprints": fps,
            "clusters": clusters,
            "same_actor_pairs": attrs,
            "ips": len(self.distinct_ips()),
        }
