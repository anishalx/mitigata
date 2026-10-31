"""Deadline-aware deterministic dispatch (design §3.5).

Priority is ``(yield x exposure) / (seconds + 1)``; work is admitted only when
its ``min_seconds`` fits the remaining wall clock. Worker budgets are enforced
here, not by the worker.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field

from .agents.base import AgentRegistry, RunContext
from .agents.preflight import PreflightError
from .models import Event


@dataclass
class SchedulerStats:
    completed: int = 0
    failed: int = 0
    skipped_deadline: int = 0
    steps: dict[str, int] = field(default_factory=dict)
    stopped: list[str] = field(default_factory=list)


class Scheduler:
    def __init__(self, ctx: RunContext, registry: AgentRegistry, *, lease_seconds: float = 60.0) -> None:
        self.ctx = ctx
        self.registry = registry
        self.lease_seconds = lease_seconds
        self.stats = SchedulerStats()
        self._spent: dict[str, float] = {}

    def _eligible(self, now: float) -> list[str]:
        eligible: list[str] = []
        for agent in self.registry.all():
            cid = agent.contract.id
            if cid in self.stats.stopped:
                continue
            budget = agent.contract.budget
            steps = self.stats.steps.get(cid, 0)
            spent = self._spent.get(cid, 0.0)
            if steps >= budget.max_steps or spent >= budget.max_seconds:
                self.stats.stopped.append(cid)
                self._emit(
                    "agent.budget_exhausted",
                    {"agent": cid, "steps": steps, "seconds": round(spent, 3)},
                )
                continue
            eligible.append(cid)
        return eligible

    def _emit(self, type: str, payload: dict, ptes_phase: str = "pre_engagement") -> None:
        self.ctx.store.add_event(
            Event(
                id=f"ev-{secrets.token_hex(8)}",
                run_id=self.ctx.run_id,
                agent="orchestrator",
                type=type,
                payload=payload,
                ptes_phase=ptes_phase,  # type: ignore[arg-type]
            )
        )

    async def drain(self) -> SchedulerStats:
        for _ in range(10_000):
            now = time.monotonic()
            if now >= self.ctx.deadline:
                self.stats.skipped_deadline += self.ctx.store.skip_remaining(self.ctx.run_id)
                break
            eligible = self._eligible(now)
            if not eligible:
                break
            row = self.ctx.store.claim(self.ctx.run_id, eligible, lease_seconds=self.lease_seconds)
            if row is None:
                break
            agent = self.registry.get(row["agent"])
            payload = json.loads(row["payload_json"])
            if row["min_seconds"] > self.ctx.deadline - now:
                self.ctx.store.complete(row["id"], "skipped_deadline")
                self.stats.skipped_deadline += 1
                continue
            started = time.monotonic()
            try:
                events = await agent.handle(payload, self.ctx)
            except PreflightError:
                self.ctx.store.complete(row["id"], "failed")
                self.stats.failed += 1
                raise
            except Exception as exc:  # degrade, do not abort unrelated work
                self.ctx.store.complete(row["id"], "failed")
                self.stats.failed += 1
                self._emit(
                    "task.failed",
                    {"task_id": row["id"], "agent": row["agent"], "kind": row["kind"], "error": str(exc)[:500]},
                    ptes_phase=row["ptes_phase"],
                )
                continue
            for event in events:
                self.ctx.store.add_event(event)
            self.ctx.store.complete(row["id"], "done")
            self.stats.completed += 1
            cid = agent.contract.id
            self.stats.steps[cid] = self.stats.steps.get(cid, 0) + 1
            self._spent[cid] = self._spent.get(cid, 0.0) + (time.monotonic() - started)
        return self.stats
