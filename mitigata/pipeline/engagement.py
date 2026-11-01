"""Engagement state: per-account attempt history, HMAC key, and blocked accounts across all runs.

Each engagement (discovery + multiple target passes on the same output directory)
shares one attempt cap per account, so a credential is never tried twice on the
same (IP, port, endpoint, user) tuple across the whole engagement.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class EngagementState:
    """Attempt history and credential fingerprints across an engagement."""

    attempts: dict[str, int] = field(default_factory=dict)  # account -> total attempts across all runs
    blocked: set[str] = field(default_factory=set)  # account names blocked by rate limiting
    tried_fingerprints: set[str] = field(default_factory=set)  # HMAC(key, account:value) for credentials already sent


def engagement_key(out_dir: str | Path) -> bytes:
    """Per-engagement HMAC key, stored as runs/.engagement-key (0600).

    The key is derived from the output directory path and a fixed salt,
    so it is stable across sessions. It is never printed or sent.
    """
    key_file = Path(out_dir) / ".engagement-key"
    if key_file.exists():
        with open(key_file, "rb") as f:
            return f.read()
    # New engagement: generate a key and store it
    key = hashlib.sha256((str(out_dir) + "\x00salt").encode()).digest()
    try:
        key_file.write_bytes(key)
        key_file.chmod(0o600)
    except Exception:
        pass  # read-only, temp, or concurrent write; use the key anyway
    return key


def engagement_state(out_dir: str | Path) -> EngagementState:
    """Reconstruct the engagement state from all previous runs in the output directory."""
    out_dir = Path(out_dir)
    state = EngagementState()
    key = engagement_key(out_dir)
    archived = set(_ledger(out_dir))  # deleted runs are counted from the ledger below, never twice

    for run_dir in sorted(out_dir.glob("run-*")):
        db_path = run_dir / "blackboard.db"
        if run_dir.name in archived or not db_path.exists():
            continue
        try:
            con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            con.row_factory = sqlite3.Row
            for row in con.execute(
                "SELECT payload_json FROM evidence WHERE type='verification' AND candidate_id IS NOT NULL"
            ):
                payload = json.loads(row[0] or "{}")
                # Reconstruct per-account attempt counts from the evidence
                for account, count in (payload.get("accounts") or {}).items():
                    state.attempts[account] = state.attempts.get(account, 0) + count
                # Track blocked accounts
                state.blocked.update(payload.get("blocked_accounts") or [])
                # Track HMAC fingerprints of credentials tested
                # Format: HMAC(key, account:value) encoded as hex
                for fingerprint in payload.get("credential_fingerprints") or []:
                    state.tried_fingerprints.add(fingerprint)
            con.close()
        except Exception:
            pass  # unreadable DB, corrupt, or missing; skip it
    for entry in _ledger(out_dir).values():  # runs deleted from disk keep their counts in the ledger
        for account, count in (entry.get("attempts") or {}).items():
            state.attempts[account] = state.attempts.get(account, 0) + int(count)
        state.blocked.update(entry.get("blocked") or [])
        state.tried_fingerprints.update(entry.get("fingerprints") or [])
    return state


def credential_fingerprint(account: str, value: str, key: bytes) -> str:
    """HMAC(key, account:value) to identify a credential without storing the value."""
    message = f"{account}:{value}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


LEDGER_NAME = ".engagement-ledger.json"


def _ledger(out_dir: str | Path) -> dict[str, dict[str, Any]]:
    """Attempt counts of runs deleted from disk: {run_id: {attempts, blocked, fingerprints}}."""
    path = Path(out_dir) / LEDGER_NAME
    if not path.exists():
        return {}
    try:
        return dict(json.loads(path.read_text(encoding="utf-8")).get("runs", {}))
    except (OSError, ValueError, AttributeError):
        # Fail closed: without the ledger the attempt cap cannot be enforced, so nothing is started.
        raise RuntimeError(f"the engagement ledger {path} is unreadable; fix or restore it before continuing") from None


def _write_ledger(out_dir: Path, runs: dict[str, dict[str, Any]]) -> None:
    path = out_dir / LEDGER_NAME
    temporary = path.with_name(LEDGER_NAME + ".tmp")
    temporary.write_text(json.dumps({"runs": runs}, indent=2, sort_keys=True), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def archive_run_attempts(out_dir: str | Path, run_id: str) -> bool:
    """Move one run's attempt counts into the ledger before its files are deleted. Safe to repeat.

    Raises RuntimeError when the run's history cannot be read, so a run is never deleted with its counts unknown:
    deleting it would hand its accounts their attempts back.
    """
    out_dir = Path(out_dir)
    runs = _ledger(out_dir)
    if run_id in runs:
        return True
    db_path = out_dir / run_id / "blackboard.db"
    attempts: dict[str, int] = {}
    blocked: set[str] = set()
    fingerprints: set[str] = set()
    if db_path.exists():
        try:
            con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                for (payload_json,) in con.execute(
                    "SELECT payload_json FROM evidence WHERE type='verification' AND candidate_id IS NOT NULL"
                ):
                    payload = json.loads(payload_json or "{}")
                    for account, count in (payload.get("accounts") or {}).items():
                        attempts[account] = attempts.get(account, 0) + int(count)
                    blocked.update(payload.get("blocked_accounts") or [])
                    fingerprints.update(payload.get("credential_fingerprints") or [])
            finally:
                con.close()
        except (sqlite3.Error, ValueError) as exc:
            raise RuntimeError(f"the attempt history of {run_id} cannot be read ({type(exc).__name__}); not deleted") from None
    runs[run_id] = {"attempts": attempts, "blocked": sorted(blocked), "fingerprints": sorted(fingerprints)}
    _write_ledger(out_dir, runs)
    return True
