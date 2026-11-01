"""The attempt ledger: a deleted run's counts are counted once, from the ledger, never from disk again."""

from __future__ import annotations

import json
import sqlite3

import pytest

from mitigata.pipeline import engagement


def _make_run(out, run_id, accounts, blocked=(), fingerprints=()):
    run_dir = out / run_id
    run_dir.mkdir(parents=True)
    con = sqlite3.connect(run_dir / "blackboard.db")
    con.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, type TEXT, candidate_id INTEGER, payload_json TEXT)")
    payload = {"accounts": accounts, "blocked_accounts": list(blocked), "credential_fingerprints": list(fingerprints)}
    con.execute("INSERT INTO evidence (type, candidate_id, payload_json) VALUES ('verification', 1, ?)",
                (json.dumps(payload),))
    con.commit()
    con.close()
    return run_dir


def test_archiving_then_deleting_keeps_the_counts_exactly_once(tmp_path):
    out = tmp_path / "runs"
    run_dir = _make_run(out, "run-20261101T000000Z-aaaaaa", {"passkey:h:8833": 3}, blocked=["basic:x"],
                        fingerprints=["f1"])
    before = engagement.engagement_state(out)
    assert before.attempts == {"passkey:h:8833": 3}

    assert engagement.archive_run_attempts(out, run_dir.name) is True
    assert engagement.archive_run_attempts(out, run_dir.name) is True  # safe to repeat
    import shutil
    shutil.rmtree(run_dir)

    after = engagement.engagement_state(out)
    assert after.attempts == {"passkey:h:8833": 3}  # not 0 (lost) and not 6 (double counted)
    assert after.blocked == {"basic:x"} and after.tried_fingerprints == {"f1"}


def test_a_run_whose_history_cannot_be_read_is_not_archived(tmp_path):
    out = tmp_path / "runs"
    run_dir = out / "run-20261101T000000Z-bbbbbb"
    run_dir.mkdir(parents=True)
    (run_dir / "blackboard.db").write_bytes(b"not a database")
    with pytest.raises(RuntimeError, match="cannot be read"):
        engagement.archive_run_attempts(out, run_dir.name)
    assert not (out / engagement.LEDGER_NAME).exists()


def test_an_unreadable_ledger_stops_the_engagement_instead_of_resetting_the_cap(tmp_path):
    out = tmp_path / "runs"
    out.mkdir()
    (out / engagement.LEDGER_NAME).write_text("{ broken", encoding="utf-8")
    with pytest.raises(RuntimeError, match="ledger"):
        engagement.engagement_state(out)
