from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from mitigata import dedup
from mitigata.models import CoverageRow, Event, TaskRecord
from mitigata.store import Store, reconcile_stale_runs


@pytest.fixture
def store(tmp_path):
    handle = Store(tmp_path / "blackboard.db")
    handle.create_run(
        "run-1",
        engagement="unit",
        tier="recon",
        scope_hash="a" * 64,
        manifest_sha256="b" * 64,
        enforcement="installed",
    )
    yield handle
    handle.close()


def _task(task_id: str, *, key: str | None = None, priority: float = 1.0, kind: str = "preflight") -> TaskRecord:
    return TaskRecord(
        id=task_id,
        run_id="run-1",
        agent="preflight-agent",
        kind=kind,
        priority=priority,
        dedup_key=key or dedup.task("run-1", task_id),
    )


def test_wal_mode_and_foreign_keys(store):
    assert store.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert store.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_schedule_is_idempotent_per_dedup_key(store):
    first = _task("t1", key=dedup.task("run-1", "preflight"))
    duplicate = _task("t2", key=dedup.task("run-1", "preflight"))
    assert store.schedule(first) is True
    assert store.schedule(duplicate) is False
    assert [row["id"] for row in store.tasks("run-1")] == ["t1"]


def test_claim_is_exclusive_within_the_lease(store):
    store.schedule(_task("t1"))
    row = store.claim("run-1", ["preflight-agent"], lease_seconds=60)
    assert row is not None and row["id"] == "t1"
    assert row["attempts"] == 1
    assert store.claim("run-1", ["preflight-agent"], lease_seconds=60) is None


def test_expired_lease_is_reclaimable_and_counts_attempts(store):
    store.schedule(_task("t1"))
    store.claim("run-1", ["preflight-agent"], lease_seconds=60)
    future = "2099-01-01T00:00:00Z"
    row = store.claim("run-1", ["preflight-agent"], now=future, lease_seconds=60)
    assert row is not None and row["id"] == "t1"
    assert row["attempts"] == 2


def test_claim_respects_agent_filter_and_priority(store):
    store.schedule(_task("low", priority=1.0))
    store.schedule(
        TaskRecord(
            id="high",
            run_id="run-1",
            agent="reporter-agent",
            kind="report",
            priority=50.0,
            dedup_key=dedup.task("run-1", "report"),
        )
    )
    assert store.claim("run-1", ["preflight-agent"])["id"] == "low"
    assert store.claim("run-1", ["reporter-agent"])["id"] == "high"


def test_completed_task_leaves_the_pool(store):
    store.schedule(_task("t1"))
    store.claim("run-1", ["preflight-agent"])
    store.complete("t1", "done")
    assert store.claim("run-1", ["preflight-agent"]) is None
    assert store.task_counts("run-1") == {"done": 1}


def test_skip_remaining_marks_pending_and_leased(store):
    store.schedule(_task("t1"))
    store.schedule(_task("t2"))
    store.claim("run-1", ["preflight-agent"])
    assert store.skip_remaining("run-1") == 2
    assert store.task_counts("run-1") == {"skipped_deadline": 2}


def test_events_roundtrip_in_order(store):
    for index in range(3):
        store.add_event(
            Event(
                id=f"ev-{index}",
                run_id="run-1",
                ts=f"2026-10-31T10:00:0{index}Z",
                agent="preflight-agent",
                type="scope.audit",
                payload={"n": index},
                ptes_phase="pre_engagement",
            )
        )
    rows = store.events("run-1")
    assert [row["ts"] for row in rows] == sorted(row["ts"] for row in rows)
    assert '"n": 2' in rows[-1]["payload_json"]


def test_coverage_upsert_keeps_one_row_per_class(store):
    for state in ("untested", "tested"):
        store.upsert_coverage(CoverageRow(run_id="run-1", asset_id=0, attack_class="web", state=state, reason="r"))
    rows = store.coverage("run-1")
    assert len(rows) == 1 and rows[0]["state"] == "tested"


def test_candidate_validation_promotes_state(store):
    candidate_id = store.add_candidate("run-1", dedup_key="k" * 64, vuln_class="sqli", claim="error-based")
    assert isinstance(candidate_id, int)
    assert store.add_candidate("run-1", dedup_key="k" * 64, vuln_class="sqli") is None  # idempotent
    evidence_id = store.add_evidence(
        "run-1", type="oracle_replay", candidate_id=candidate_id,
        ptes_phase="exploitation", payload={"observed": "marker", "control": "benign"},
    )
    store.add_validation(
        "run-1", candidate_id, verdict="confirmed", oracle="marker",
        control_kind="benign", evidence_id=evidence_id,
    )
    aggregate = store.aggregate("run-1")
    assert aggregate["candidates"] == 1
    assert aggregate["confirmed"] == 1


def test_confirmation_without_evidence_is_refused(store):
    candidate_id = store.add_candidate("run-1", dedup_key="m" * 64, vuln_class="reflection")
    with pytest.raises(ValueError, match="evidence and a control"):
        store.add_validation("run-1", candidate_id, verdict="confirmed", oracle="echo")
    assert store.aggregate("run-1")["confirmed"] == 0


def test_unknown_run_is_an_error(store):
    with pytest.raises(KeyError):
        store.get_run("missing")


def test_service_metadata_round_trips(store):
    asset_id = store.upsert_asset("run-1", "10.10.5.2")
    store.upsert_service(
        "run-1", asset_id, 445, name="microsoft-ds",
        product="Samba", version="4.15.13", extrainfo="Ubuntu", source="nmap",
    )
    # A later connect scan must not erase nmap detail.
    store.upsert_service("run-1", asset_id, 445, name="microsoft-ds", source="connect")
    row = store.conn.execute("SELECT * FROM services").fetchone()
    assert (row["product"], row["version"], row["extrainfo"], row["source"]) == (
        "Samba", "4.15.13", "Ubuntu", "connect",
    )


def test_existing_blackboards_gain_service_metadata_columns(tmp_path):
    import sqlite3

    database = tmp_path / "old.db"
    conn = sqlite3.connect(database)
    conn.execute(
        "CREATE TABLE services (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,"
        " asset_id INTEGER NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL DEFAULT 'tcp',"
        " name TEXT, banner_sha256 TEXT, UNIQUE (run_id, asset_id, port, proto))"
    )
    conn.commit()
    conn.close()

    store = Store(database)
    try:
        columns = {row["name"] for row in store.conn.execute("PRAGMA table_info(services)")}
    finally:
        store.close()
    assert {"product", "version", "extrainfo", "source"} <= columns


def _create_run(store: Store, run_id: str, *, pid: int) -> None:
    store.create_run(
        run_id,
        engagement="unit",
        tier="recon",
        scope_hash="a" * 64,
        manifest_sha256="b" * 64,
        enforcement="installed",
        pid=pid,
    )


def test_run_heartbeat_is_refreshed(store):
    store.conn.execute("UPDATE runs SET heartbeat_at='2000-01-01T00:00:00Z' WHERE id='run-1'")
    store.heartbeat_run("run-1")
    row = store.get_run("run-1")
    assert row["heartbeat_at"] != "2000-01-01T00:00:00Z"
    assert row["pid"] == os.getpid()


def test_stale_run_is_finalized_as_abandoned(tmp_path):
    run_dir = tmp_path / "run-stale"
    run_dir.mkdir()
    store = Store(run_dir / "blackboard.db")
    _create_run(store, "run-stale", pid=999_999_999)
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    store.conn.execute("UPDATE runs SET heartbeat_at=? WHERE id='run-stale'", (old,))
    store.close()

    repaired = reconcile_stale_runs(tmp_path, older_than_seconds=60)

    assert repaired == ["run-stale"]
    reopened = Store(run_dir / "blackboard.db")
    try:
        row = reopened.get_run("run-stale")
        assert row["status"] == "abandoned"
        assert row["finished_at"]
        event = reopened.conn.execute(
            "SELECT type FROM events WHERE run_id='run-stale' ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        assert event["type"] == "run.abandoned"
    finally:
        reopened.close()


def test_live_process_is_not_reconciled(tmp_path):
    import os

    run_dir = tmp_path / "run-live"
    run_dir.mkdir()
    store = Store(run_dir / "blackboard.db")
    _create_run(store, "run-live", pid=os.getpid())
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    store.conn.execute("UPDATE runs SET heartbeat_at=? WHERE id='run-live'", (old,))
    store.close()

    assert reconcile_stale_runs(tmp_path, older_than_seconds=60) == []
    reopened = Store(run_dir / "blackboard.db")
    try:
        assert reopened.get_run("run-live")["status"] == "running"
    finally:
        reopened.close()
