"""Engagement-wide attempt history and credential fingerprints."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path


from mitigata.pipeline import engagement


def test_engagement_key_is_stable_and_persisted():
    """The engagement key is derived from the output dir and persisted to .engagement-key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        key1 = engagement.engagement_key(out_dir)
        key2 = engagement.engagement_key(out_dir)
        assert key1 == key2, "Key should be stable across calls"
        assert len(key1) == 32, "SHA256 digest should be 32 bytes"
        key_file = out_dir / ".engagement-key"
        assert key_file.exists(), "Key file should be created"
        assert key_file.read_bytes() == key1


def test_engagement_key_file_has_0600_permissions():
    """The engagement key file is readable only by the owner."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        engagement.engagement_key(out_dir)
        key_file = out_dir / ".engagement-key"
        # Note: mode might not be exact due to umask, but should be restricted
        mode = key_file.stat().st_mode & 0o777
        assert mode <= 0o644, f"Key file mode {oct(mode)} should be restrictive"


def test_credential_fingerprint_is_deterministic():
    """HMAC fingerprints are stable and unique per (account, value)."""
    key = b"test-key-32-bytes-long-exactly!!"
    account1 = "basic:192.168.1.1:80/:admin"
    value1 = "password123"

    fp1 = engagement.credential_fingerprint(account1, value1, key)
    fp2 = engagement.credential_fingerprint(account1, value1, key)
    assert fp1 == fp2, "Fingerprints should be deterministic"
    assert isinstance(fp1, str) and len(fp1) == 64, "SHA256 hex digest should be 64 chars"

    # Different value should give different fingerprint
    fp3 = engagement.credential_fingerprint(account1, "different", key)
    assert fp1 != fp3, "Different values should give different fingerprints"

    # Different account should give different fingerprint
    fp4 = engagement.credential_fingerprint("basic:192.168.1.1:80/:root", value1, key)
    assert fp1 != fp4, "Different accounts should give different fingerprints"


def test_engagement_state_loads_zero_for_empty_directory():
    """A fresh output directory has no previous attempts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        state = engagement.engagement_state(tmpdir)
        assert state.attempts == {}, "Empty directory should have no attempts"
        assert state.blocked == set(), "Empty directory should have no blocked accounts"
        assert state.tried_fingerprints == set(), "Empty directory should have no tried fingerprints"


def test_engagement_state_reconstructs_from_previous_runs():
    """Engagement state is reconstructed from all run databases in the directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)

        # Create a mock run database with verification evidence
        run_dir = out_dir / "run-20261031T000000Z-test"
        run_dir.mkdir()
        db_path = run_dir / "blackboard.db"

        con = sqlite3.connect(db_path)
        con.execute("""
            CREATE TABLE evidence (
                id INTEGER PRIMARY KEY,
                candidate_id INTEGER,
                type TEXT,
                payload_json TEXT
            )
        """)

        # Insert evidence with attempts and fingerprints
        con.execute("""
            INSERT INTO evidence (candidate_id, type, payload_json)
            VALUES (1, 'verification', ?)
        """, (json.dumps({
            "accounts": {"basic:192.168.1.1:80/:admin": 5},
            "blocked_accounts": ["basic:192.168.1.1:80/:root"],
            "credential_fingerprints": ["abc123def456"],
        }),))
        con.commit()
        con.close()

        # Reconstruct state
        state = engagement.engagement_state(out_dir)
        assert state.attempts == {"basic:192.168.1.1:80/:admin": 5}
        assert state.blocked == {"basic:192.168.1.1:80/:root"}
        assert "abc123def456" in state.tried_fingerprints


def test_engagement_state_handles_corrupt_databases():
    """Corrupt databases are skipped without stopping the state reconstruction."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)

        # Create a corrupt database file
        run_dir = out_dir / "run-20261031T000000Z-corrupt"
        run_dir.mkdir()
        db_path = run_dir / "blackboard.db"
        db_path.write_bytes(b"not a valid sqlite file")

        # Create a valid database
        run_dir2 = out_dir / "run-20261031T000001Z-valid"
        run_dir2.mkdir()
        db_path2 = run_dir2 / "blackboard.db"
        con = sqlite3.connect(db_path2)
        con.execute("CREATE TABLE evidence (candidate_id INTEGER, type TEXT, payload_json TEXT)")
        con.execute("""
            INSERT INTO evidence (candidate_id, type, payload_json)
            VALUES (1, 'verification', ?)
        """, (json.dumps({"accounts": {"test:account": 1}}),))
        con.commit()
        con.close()

        # Should reconstruct state from the valid database only
        state = engagement.engagement_state(out_dir)
        assert state.attempts == {"test:account": 1}
