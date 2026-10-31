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

    for run_dir in sorted(out_dir.glob("run-*")):
        db_path = run_dir / "blackboard.db"
        if not db_path.exists():
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
    return state


def credential_fingerprint(account: str, value: str, key: bytes) -> str:
    """HMAC(key, account:value) to identify a credential without storing the value."""
    message = f"{account}:{value}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()
