"""Orchestrator-owned SQLite WAL blackboard (design §3.4, §5.2).

Workers never touch this database: they submit events through the bounded
control channel and the orchestrator performs every write. Task claiming uses
``BEGIN IMMEDIATE`` plus leases, so at-least-once execution is explicit and
result insertion stays idempotent.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

from .models import CoverageRow, Event, TaskRecord, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    engagement TEXT NOT NULL,
    tier TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    enforcement TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    pid INTEGER,
    heartbeat_at TEXT
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    hostname TEXT,
    source TEXT NOT NULL DEFAULT 'discovery',
    first_seen TEXT NOT NULL,
    UNIQUE (run_id, ip)
);
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL DEFAULT 'tcp',
    name TEXT,
    banner_sha256 TEXT,
    product TEXT,
    version TEXT,
    extrainfo TEXT,
    source TEXT,
    UNIQUE (run_id, asset_id, port, proto)
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    normalized TEXT NOT NULL,
    UNIQUE (run_id, normalized)
);
CREATE TABLE IF NOT EXISTS binaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    format TEXT NOT NULL DEFAULT 'unknown',
    state TEXT NOT NULL DEFAULT 'present',
    UNIQUE (run_id, sha256)
);
CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    dedup_key TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    asset_id INTEGER,
    service_id INTEGER,
    endpoint_id INTEGER,
    claim TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'candidate',
    ptes_phase TEXT NOT NULL DEFAULT 'vulnerability_analysis',
    created_at TEXT NOT NULL,
    UNIQUE (run_id, dedup_key)
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    candidate_id INTEGER REFERENCES candidates(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    path TEXT,
    sha256 TEXT,
    ptes_phase TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS validations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    verdict TEXT NOT NULL CHECK (verdict IN ('confirmed', 'rejected', 'inconclusive')),
    oracle TEXT NOT NULL,
    control_kind TEXT NOT NULL DEFAULT '',
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    agent TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    ptes_phase TEXT NOT NULL,
    priority REAL NOT NULL,
    min_seconds REAL NOT NULL DEFAULT 0,
    dedup_key TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    lease_expires_at TEXT,
    UNIQUE (run_id, dedup_key)
);
CREATE TABLE IF NOT EXISTS work_registry (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    dedup_key TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (run_id, dedup_key)
);
CREATE TABLE IF NOT EXISTS coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL DEFAULT 0,
    attack_class TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('tested', 'skipped', 'untested', 'failed')),
    reason TEXT NOT NULL DEFAULT '',
    UNIQUE (run_id, asset_id, attack_class)
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    agent TEXT NOT NULL,
    type TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    ptes_phase TEXT NOT NULL,
    dedup_key TEXT
);
CREATE TABLE IF NOT EXISTS scope_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    sent_outside INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    secret_ref TEXT NOT NULL,
    source TEXT NOT NULL,
    service_id INTEGER,
    confidence TEXT NOT NULL DEFAULT 'static',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    value_sha256 TEXT NOT NULL,
    source TEXT NOT NULL,
    captured_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    nodes_json TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'confirmed',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_run_ts ON events(run_id, ts);
CREATE INDEX IF NOT EXISTS idx_tasks_claim ON tasks(run_id, state, priority DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(run_id, agent, state);
CREATE INDEX IF NOT EXISTS idx_coverage_run ON coverage(run_id);
"""


class Store:
    """Single writer for the run's authoritative state."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(SCHEMA)
        self._ensure_service_columns()
        self._ensure_candidate_columns()
        self._ensure_run_columns()
        self._ensure_task_columns()
        self._ensure_binary_columns()

    def _ensure_service_columns(self) -> None:
        """Add columns introduced after the first schema version, in place."""
        existing = {row["name"] for row in self.conn.execute("PRAGMA table_info(services)")}
        for name in ("product", "version", "extrainfo", "source"):
            if name not in existing:
                self.conn.execute(f"ALTER TABLE services ADD COLUMN {name} TEXT")

    def _ensure_candidate_columns(self) -> None:
        """Candidates carry the structured target details the verifier needs."""
        existing = {row["name"] for row in self.conn.execute("PRAGMA table_info(candidates)")}
        if "details_json" not in existing:
            self.conn.execute("ALTER TABLE candidates ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}'")

    def _ensure_run_columns(self) -> None:
        """Older blackboards predate the heartbeat used to reconcile abandoned runs."""
        existing = {row["name"] for row in self.conn.execute("PRAGMA table_info(runs)")}
        for name, kind in (("pid", "INTEGER"), ("heartbeat_at", "TEXT")):
            if name not in existing:
                self.conn.execute(f"ALTER TABLE runs ADD COLUMN {name} {kind}")

    def _ensure_task_columns(self) -> None:
        """Tasks record the task that caused them, so the dashboard can draw the discovery chain."""
        existing = {row["name"] for row in self.conn.execute("PRAGMA table_info(tasks)")}
        if "parent_task_id" not in existing:
            self.conn.execute("ALTER TABLE tasks ADD COLUMN parent_task_id TEXT")

    def _ensure_binary_columns(self) -> None:
        """Binary rows carry the triage and analysis outcome, so the dashboard can show what each step did."""
        existing = {row["name"] for row in self.conn.execute("PRAGMA table_info(binaries)")}
        if "details_json" not in existing:
            self.conn.execute("ALTER TABLE binaries ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}'")

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def create_run(
        self,
        run_id: str,
        *,
        engagement: str,
        tier: str,
        scope_hash: str,
        manifest_sha256: str,
        enforcement: str,
        started_at: str | None = None,
        pid: int | None = None,
    ) -> None:
        started = started_at or utcnow()
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO runs (id, engagement, tier, scope_hash, manifest_sha256,"
                " enforcement, status, started_at, finished_at, pid, heartbeat_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, engagement, tier, scope_hash, manifest_sha256, enforcement, "running", started,
                 None, pid if pid is not None else os.getpid(), started),
            )

    def finish_run(self, run_id: str, status: str, *, finished_at: str | None = None) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE runs SET status=?, finished_at=? WHERE id=?",
                (status, finished_at or utcnow(), run_id),
            )

    def resume_run(self, run_id: str, *, pid: int | None = None) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE runs SET status='running', finished_at=NULL, pid=?, heartbeat_at=? WHERE id=?",
                (pid if pid is not None else os.getpid(), utcnow(), run_id),
            )

    def heartbeat_run(self, run_id: str, *, pid: int | None = None) -> None:
        """Refresh the liveness marker; safe to call from a dedicated heartbeat thread."""
        with self._tx() as conn:
            if pid is None:
                conn.execute("UPDATE runs SET heartbeat_at=? WHERE id=? AND status='running'",
                             (utcnow(), run_id))
            else:
                conn.execute("UPDATE runs SET heartbeat_at=?, pid=? WHERE id=? AND status='running'",
                             (utcnow(), pid, run_id))

    def get_run(self, run_id: str) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown run {run_id!r}")
        return row

    # -- events ------------------------------------------------------------
    def add_event(self, event: Event) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO events (id, run_id, ts, agent, type, payload_json, ptes_phase, dedup_key)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (
                    event.id,
                    event.run_id,
                    event.ts,
                    event.agent,
                    event.type,
                    json.dumps(event.payload, sort_keys=True),
                    event.ptes_phase,
                    event.dedup_key,
                ),
            )

    def events(self, run_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM events WHERE run_id=? ORDER BY ts, rowid", (run_id,)
        ).fetchall()

    # -- work registry and tasks ------------------------------------------
    def register_work(self, run_id: str, dedup_key: str, *, now: str | None = None) -> bool:
        """Register a normalized work key; False when it was already known."""
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO work_registry (run_id, dedup_key, first_seen) VALUES (?,?,?)",
                (run_id, dedup_key, now or utcnow()),
            )
            return cur.rowcount == 1

    def schedule(self, task: TaskRecord) -> bool:
        """Persist a task unless its dedup key is already registered."""
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO work_registry (run_id, dedup_key, first_seen) VALUES (?,?,?)",
                (task.run_id, task.dedup_key, task.created_at),
            )
            if cur.rowcount == 0:
                return False
            conn.execute(
                "INSERT INTO tasks (id, run_id, agent, kind, payload_json, ptes_phase, priority,"
                " min_seconds, dedup_key, state, attempts, created_at, parent_task_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,'pending',0,?,?)",
                (
                    task.id,
                    task.run_id,
                    task.agent,
                    task.kind,
                    json.dumps(task.payload, sort_keys=True),
                    task.ptes_phase,
                    task.priority,
                    task.min_seconds,
                    task.dedup_key,
                    task.created_at,
                    task.parent_task_id,
                ),
            )
        return True

    def claim(
        self,
        run_id: str,
        agents: Sequence[str],
        *,
        now: str | None = None,
        lease_seconds: float = 60.0,
    ) -> sqlite3.Row | None:
        """Lease the highest-priority runnable task for one of ``agents``."""
        if not agents:
            return None
        stamp = now or utcnow()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        placeholders = ",".join("?" for _ in agents)
        with self._tx() as conn:
            row = conn.execute(
                f"SELECT * FROM tasks WHERE run_id=? AND state IN ('pending','leased')"
                f" AND (lease_expires_at IS NULL OR lease_expires_at <= ?)"
                f" AND agent IN ({placeholders})"
                f" ORDER BY priority DESC, created_at ASC, rowid ASC LIMIT 1",
                (run_id, stamp, *agents),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE tasks SET state='leased', lease_expires_at=?, attempts=attempts+1 WHERE id=?",
                (expires, row["id"]),
            )
            return conn.execute("SELECT * FROM tasks WHERE id=?", (row["id"],)).fetchone()

    def complete(self, task_id: str, state: str = "done") -> None:
        with self._tx() as conn:
            conn.execute("UPDATE tasks SET state=?, lease_expires_at=NULL WHERE id=?", (state, task_id))

    def start_task(self, task_id: str) -> None:
        """Mark a task as running so dashboards can show agents at work."""
        with self._tx() as conn:
            conn.execute("UPDATE tasks SET state='running', attempts=attempts+1 WHERE id=?", (task_id,))

    def task_counts(self, run_id: str) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT state, COUNT(*) AS n FROM tasks WHERE run_id=? GROUP BY state", (run_id,)
        ).fetchall()
        return {row["state"]: row["n"] for row in rows}

    def tasks(self, run_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM tasks WHERE run_id=? ORDER BY created_at, rowid", (run_id,)
        ).fetchall()

    def task_id_for(self, run_id: str, dedup_key: str) -> str | None:
        row = self.conn.execute(
            "SELECT id FROM tasks WHERE run_id=? AND dedup_key=?", (run_id, dedup_key)
        ).fetchone()
        return row["id"] if row else None

    # -- inventory ---------------------------------------------------------
    def upsert_asset(self, run_id: str, ip: str, *, hostname: str | None = None, source: str = "discovery") -> int:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO assets (run_id, ip, hostname, source, first_seen) VALUES (?,?,?,?,?)"
                " ON CONFLICT(run_id, ip) DO UPDATE SET hostname=COALESCE(excluded.hostname, assets.hostname)",
                (run_id, ip, hostname, source, utcnow()),
            )
            return conn.execute("SELECT id FROM assets WHERE run_id=? AND ip=?", (run_id, ip)).fetchone()["id"]

    def upsert_service(
        self, run_id: str, asset_id: int, port: int, *, proto: str = "tcp", name: str | None = None,
        product: str | None = None, version: str | None = None, extrainfo: str | None = None,
        source: str | None = None,
    ) -> int:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO services (run_id, asset_id, port, proto, name, product, version, extrainfo, source)"
                " VALUES (?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(run_id, asset_id, port, proto) DO UPDATE SET"
                " name=COALESCE(excluded.name, services.name),"
                " product=COALESCE(excluded.product, services.product),"
                " version=COALESCE(excluded.version, services.version),"
                " extrainfo=COALESCE(excluded.extrainfo, services.extrainfo),"
                " source=COALESCE(excluded.source, services.source)",
                (run_id, asset_id, port, proto, name, product, version, extrainfo, source),
            )
            return conn.execute(
                "SELECT id FROM services WHERE run_id=? AND asset_id=? AND port=? AND proto=?",
                (run_id, asset_id, port, proto),
            ).fetchone()["id"]

    def upsert_endpoint(self, run_id: str, service_id: int | None, method: str, url: str, normalized: str) -> int:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO endpoints (run_id, service_id, method, url, normalized) VALUES (?,?,?,?,?)"
                " ON CONFLICT(run_id, normalized) DO NOTHING",
                (run_id, service_id, method.upper(), url, normalized),
            )
            return conn.execute(
                "SELECT id FROM endpoints WHERE run_id=? AND normalized=?", (run_id, normalized)
            ).fetchone()["id"]

    def upsert_binary(
        self, run_id: str, sha256: str, path: str, size: int, *, format: str = "unknown", state: str = "present",
        details: dict[str, Any] | None = None,
    ) -> int:
        payload = json.dumps(details or {}, sort_keys=True, default=str)
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO binaries (run_id, sha256, path, size, format, state, details_json)"
                " VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(run_id, sha256) DO UPDATE SET path=excluded.path, state=excluded.state,"
                " details_json=excluded.details_json",
                (run_id, sha256, path, size, format, state, payload),
            )
            return conn.execute("SELECT id FROM binaries WHERE run_id=? AND sha256=?", (run_id, sha256)).fetchone()["id"]

    def add_binary_source(self, run_id: str, sha256: str, source: str) -> None:
        """Record another place where the same bytes were found, for example a web copy of a supplied binary."""
        with self._tx() as conn:
            row = conn.execute("SELECT details_json FROM binaries WHERE run_id=? AND sha256=?",
                               (run_id, sha256)).fetchone()
            if row is None:
                return
            details = json.loads(row["details_json"] or "{}")
            sources = [*details.get("sources", []), details.get("source", ""), source]
            details["sources"] = list(dict.fromkeys(item for item in sources if item))
            conn.execute("UPDATE binaries SET details_json=? WHERE run_id=? AND sha256=?",
                         (json.dumps(details, sort_keys=True, default=str), run_id, sha256))

    def binaries(self, run_id: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM binaries WHERE run_id=? ORDER BY id", (run_id,)).fetchall()

    def upsert_coverage(self, row: CoverageRow) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO coverage (run_id, asset_id, attack_class, state, reason) VALUES (?,?,?,?,?)"
                " ON CONFLICT(run_id, asset_id, attack_class) DO UPDATE SET state=excluded.state, reason=excluded.reason",
                (row.run_id, row.asset_id or 0, row.attack_class, row.state, row.reason),
            )

    def coverage(self, run_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM coverage WHERE run_id=? ORDER BY attack_class, asset_id", (run_id,)
        ).fetchall()

    # -- findings ----------------------------------------------------------
    def add_candidate(
        self,
        run_id: str,
        *,
        dedup_key: str,
        vuln_class: str,
        claim: str = "",
        asset_id: int | None = None,
        service_id: int | None = None,
        endpoint_id: int | None = None,
        ptes_phase: str = "vulnerability_analysis",
        details: dict[str, Any] | None = None,
    ) -> int | None:
        """Insert a lead; returns None when the same dedup key already exists."""
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO candidates (run_id, dedup_key, vuln_class, asset_id, service_id,"
                " endpoint_id, claim, ptes_phase, created_at, details_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (run_id, dedup_key, vuln_class, asset_id, service_id, endpoint_id, claim, ptes_phase,
                 utcnow(), json.dumps(details or {}, sort_keys=True)),
            )
            if cur.rowcount == 0:
                return None
            return cur.lastrowid

    def candidate_by_key(self, run_id: str, dedup_key: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM candidates WHERE run_id=? AND dedup_key=?", (run_id, dedup_key)
        ).fetchone()

    # -- scope, credentials, flags, paths ------------------------------------
    def record_scope_event(self, run_id: str, kind: str, detail: str = "", *, sent_outside: int = 0) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO scope_events (run_id, ts, kind, detail, sent_outside) VALUES (?,?,?,?,?)",
                (run_id, utcnow(), kind, detail[:300], sent_outside),
            )

    def add_credential(
        self, run_id: str, *, kind: str, secret_ref: str, source: str,
        service_id: int | None = None, confidence: str = "static",
    ) -> int:
        """Store a reference only; the value lives in the run's private secret file."""
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO credentials (run_id, kind, secret_ref, source, service_id, confidence, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (run_id, kind, secret_ref, source, service_id, confidence, utcnow()),
            )
            return int(cur.lastrowid)

    def credentials(self, run_id: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM credentials WHERE run_id=? ORDER BY id", (run_id,)).fetchall()

    def add_flag(self, run_id: str, *, value_sha256: str, source: str) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO flags (run_id, value_sha256, source, captured_at) VALUES (?,?,?,?)",
                (run_id, value_sha256, source, utcnow()),
            )
            return int(cur.lastrowid)

    def flags(self, run_id: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM flags WHERE run_id=? ORDER BY id", (run_id,)).fetchall()

    def add_attack_path(self, run_id: str, nodes_json: str, confidence: str) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO attack_paths (run_id, nodes_json, confidence, created_at) VALUES (?,?,?,?)",
                (run_id, nodes_json, confidence, utcnow()),
            )
            return int(cur.lastrowid)

    def attack_paths(self, run_id: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM attack_paths WHERE run_id=? ORDER BY id", (run_id,)).fetchall()

    def add_validation(
        self, run_id: str, candidate_id: int, *, verdict: str, oracle: str,
        control_kind: str = "", evidence_id: int | None = None,
    ) -> int:
        if verdict == "confirmed":
            if not evidence_id or not control_kind:
                raise ValueError("confirmation requires retained evidence and a control")
            match = self.conn.execute(
                "SELECT 1 FROM evidence WHERE id=? AND run_id=? AND candidate_id=?",
                (evidence_id, run_id, candidate_id),
            ).fetchone()
            if match is None:
                raise ValueError("confirmation evidence must belong to the candidate")
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO validations (run_id, candidate_id, verdict, oracle, control_kind, evidence_id, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (run_id, candidate_id, verdict, oracle, control_kind, evidence_id, utcnow()),
            )
            conn.execute("UPDATE candidates SET state=? WHERE id=? AND run_id=?", (verdict, candidate_id, run_id))
            return cur.lastrowid

    def add_evidence(
        self, run_id: str, *, type: str, candidate_id: int | None, ptes_phase: str, path: str | None = None,
        sha256: str | None = None, payload: dict[str, Any] | None = None,
    ) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO evidence (run_id, candidate_id, type, path, sha256, ptes_phase, payload_json, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (run_id, candidate_id, type, path, sha256, ptes_phase, json.dumps(payload or {}, sort_keys=True), utcnow()),
            )
            return cur.lastrowid

    # -- reporting ---------------------------------------------------------
    def candidates(self, run_id: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM candidates WHERE run_id=? ORDER BY id", (run_id,)).fetchall()

    def validations(self, run_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM validations WHERE run_id=? ORDER BY id", (run_id,)
        ).fetchall()

    def evidence(self, run_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM evidence WHERE run_id=? ORDER BY id", (run_id,)
        ).fetchall()

    def skip_remaining(self, run_id: str, state: str = "skipped_deadline") -> int:
        """Mark pending/leased work as skipped when the deadline is reached."""
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE tasks SET state=?, lease_expires_at=NULL"
                " WHERE run_id=? AND state IN ('pending','leased')",
                (state, run_id),
            )
            return cur.rowcount

    def aggregate(self, run_id: str) -> dict[str, Any]:
        def scalar(sql: str) -> int:
            return int(self.conn.execute(sql, (run_id,)).fetchone()[0])

        return {
            "run": dict(self.get_run(run_id)),
            "assets": scalar("SELECT COUNT(*) FROM assets WHERE run_id=?"),
            "services": scalar("SELECT COUNT(*) FROM services WHERE run_id=?"),
            "endpoints": scalar("SELECT COUNT(*) FROM endpoints WHERE run_id=?"),
            "binaries": scalar("SELECT COUNT(*) FROM binaries WHERE run_id=?"),
            "candidates": scalar("SELECT COUNT(*) FROM candidates WHERE run_id=?"),
            "confirmed": scalar(
                "SELECT COUNT(*) FROM candidates c WHERE c.run_id=? AND c.state='confirmed'"
            ),
            "validations": scalar("SELECT COUNT(*) FROM validations WHERE run_id=?"),
            "inconclusive": scalar(
                "SELECT COUNT(*) FROM candidates c WHERE c.run_id=? AND c.state='inconclusive'"
            ),
            "events": scalar("SELECT COUNT(*) FROM events WHERE run_id=?"),
            "tasks": self.task_counts(run_id),
            "coverage": [dict(row) for row in self.coverage(run_id)],
            "scope_events": scalar("SELECT COALESCE(SUM(sent_outside), 0) FROM scope_events WHERE run_id=?"),
        }


#: A run that has not refreshed its heartbeat for this long is treated as abandoned.
STALE_RUN_SECONDS = 300.0


def _process_alive(pid: int) -> bool:
    """Best-effort liveness check that avoids trusting a recycled PID blindly."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    proc = Path(f"/proc/{pid}/cmdline")
    if proc.exists():
        try:
            command = proc.read_bytes().replace(b"\x00", b" ")
        except OSError:
            return True
        return b"mitigata" in command or b"python" in command or b"pytest" in command
    return True


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def reconcile_stale_runs(out_dir: Path, *, older_than_seconds: float = STALE_RUN_SECONDS) -> list[str]:
    """Finalize runs left in ``running`` by a killed process.

    A run is only touched when its recorded process is gone *and* its heartbeat is older than
    ``older_than_seconds``. That keeps a live scan and a second dashboard from being marked
    abandoned. Returns the ids that were reconciled.
    """
    repaired: list[str] = []
    if not out_dir.is_dir():
        return repaired
    now = datetime.now(timezone.utc)
    for entry in sorted(out_dir.iterdir()):
        database = entry / "blackboard.db"
        if not entry.is_dir() or entry.is_symlink() or not database.is_file() or database.is_symlink():
            continue
        store: Store | None = None
        try:
            store = Store(database)
            row = store.conn.execute(
                "SELECT id, status, started_at, heartbeat_at, pid FROM runs WHERE id=?", (entry.name,)
            ).fetchone()
            if row is None or row["status"] != "running":
                continue
            pid = int(row["pid"]) if row["pid"] is not None else 0
            if pid and _process_alive(pid):
                continue
            heartbeat = _parse_timestamp(row["heartbeat_at"]) or _parse_timestamp(row["started_at"])
            if heartbeat is not None and (now - heartbeat).total_seconds() < older_than_seconds:
                continue
            reason = (
                f"no live process (pid {pid}) and no heartbeat since "
                f"{row['heartbeat_at'] or row['started_at']}"
            )
            store.add_event(Event(
                id=f"ev-{secrets.token_hex(8)}", run_id=str(row["id"]), agent="orchestrator",
                type="run.abandoned", payload={"reason": reason, "pid": pid}, ptes_phase="reporting",
            ))
            store.finish_run(str(row["id"]), "abandoned", finished_at=utcnow())
            repaired.append(str(row["id"]))
        except (sqlite3.Error, OSError, ValueError):
            continue
        finally:
            if store is not None:
                store.close()
    return repaired
