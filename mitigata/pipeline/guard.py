"""Scope guard and firewall layer (diagram stage 1).

Every target-facing call in the pipeline asks this guard first. A refused target
never receives traffic: it is recorded in ``scope_events`` with
``sent_outside=0`` and ``ScopeViolation`` is raised. The guard runs in-process,
so it stops an agent from reaching out of scope because of a bug; it is not a
kernel-level egress policy (that is the separate ``--netns`` profile).

Worker threads must not touch the SQLite connection, so refusals are queued in
memory and flushed to the blackboard by the orchestrator thread.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from ..discovery import in_scope
from ..scope import CompiledScope
from ..store import Store


class ScopeViolation(RuntimeError):
    """A target fell outside the compiled scope; nothing was sent."""


@dataclass
class ScopeGuard:
    scope: CompiledScope
    allowed: int = 0
    #: Minimum spacing between two target-facing operations on the same host (manifest limit).
    http_interval: float = 0.2
    _refusals: list[str] = field(default_factory=list)
    _next_slot: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def pace(self, ip: str) -> None:
        """Reserve the next time slot for ``ip`` and wait for it, so concurrent agents share the limit."""
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot.get(ip, 0.0))
            self._next_slot[ip] = slot + self.http_interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)

    def permits(self, ip: str) -> bool:
        try:
            return in_scope(self.scope, ip)
        except ValueError:
            return False

    def require(self, ip: str, *, purpose: str, port: int | None = None) -> None:
        """Raise unless ``ip`` is an in-scope, usable host; call before every connect."""
        target = ip if port is None else f"{ip}:{port}"
        if not self.permits(ip):
            self._refuse(target, purpose)
            raise ScopeViolation(f"{target} is outside the authorised scope; refused ({purpose})")
        with self._lock:
            self.allowed += 1

    def filter(self, ips: list[str], *, purpose: str) -> list[str]:
        kept: list[str] = []
        for ip in ips:
            if self.permits(ip):
                kept.append(ip)
            else:
                self._refuse(ip, purpose)
        with self._lock:
            self.allowed += len(kept)
        return kept

    def _refuse(self, target: str, purpose: str) -> None:
        with self._lock:
            if len(self._refusals) < 500:
                self._refusals.append(f"{purpose}: {target}")

    def flush(self, store: Store, run_id: str) -> int:
        """Persist queued refusals; call from the orchestrator thread only."""
        with self._lock:
            pending, self._refusals = self._refusals, []
        for detail in pending:
            store.record_scope_event(run_id, "refused", detail, sent_outside=0)
        return len(pending)
