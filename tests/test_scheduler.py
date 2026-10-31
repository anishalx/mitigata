from __future__ import annotations

import asyncio
import time

import pytest

from mitigata.agents.base import Agent, AgentRegistry, RunContext
from mitigata.agents.preflight import PreflightError
from mitigata.models import AgentBudget, AgentContract, TaskRecord
from mitigata.scheduler import Scheduler
from mitigata.scope import compile_scope
from mitigata.store import Store

from .conftest import make_manifest


class Recorder(Agent):
    def __init__(self, *, agent_id: str = "recorder-agent", max_steps: int = 10, kinds: tuple[str, ...] = ("work",)):
        self.order: list[str] = []
        self.contract = AgentContract(
            id=agent_id,
            role="recorder",
            tools=["none"],
            subscribes=["run.started"],
            publishes=["work.done"],
            budget=AgentBudget(max_steps=max_steps, max_seconds=30, max_llm_calls=0),
        )
        self.kinds = kinds

    async def handle(self, task, ctx):
        self.order.append(task["label"])
        return [self.make_event(ctx, "work.done", {"label": task["label"]})]


class Boom(Recorder):
    async def handle(self, task, ctx):
        raise RuntimeError("tool crashed")


class Refusing(Recorder):
    async def handle(self, task, ctx):
        raise PreflightError("enforcement unavailable")


def build(tmp_path, agents, *, deadline_seconds: float = 30.0):
    store = Store(tmp_path / "blackboard.db")
    store.create_run(
        "run-1",
        engagement="unit",
        tier="recon",
        scope_hash="a" * 64,
        manifest_sha256="b" * 64,
        enforcement="installed",
    )
    ctx = RunContext(
        run_id="run-1",
        scope=compile_scope(make_manifest()),
        store=store,
        out_dir=tmp_path,
        evidence_dir=tmp_path,
        profile="no-target",
        deadline=time.monotonic() + deadline_seconds,
    )
    registry = AgentRegistry()
    for agent in agents:
        registry.register(agent)
    return store, ctx, registry


def schedule(store: Store, label: str, priority: float, *, agent: str = "recorder-agent", min_seconds: float = 0.0):
    return store.schedule(
        TaskRecord(
            id=f"t-{label}",
            run_id="run-1",
            agent=agent,
            kind="work",
            payload={"label": label},
            priority=priority,
            min_seconds=min_seconds,
            dedup_key=f"key-{label}",
        )
    )


def test_highest_priority_runs_first(tmp_path):
    store, ctx, registry = build(tmp_path, [Recorder()])
    schedule(store, "low", 1.0)
    schedule(store, "high", 9.0)
    stats = asyncio.run(Scheduler(ctx, registry).drain())
    agent = registry.get("recorder-agent")
    assert agent.order == ["high", "low"]
    assert stats.completed == 2
    assert store.task_counts("run-1") == {"done": 2}


def test_deadline_skips_remaining_work(tmp_path):
    store, ctx, registry = build(tmp_path, [Recorder()], deadline_seconds=-1)
    schedule(store, "a", 1.0)
    schedule(store, "b", 1.0)
    stats = asyncio.run(Scheduler(ctx, registry).drain())
    assert stats.completed == 0
    assert store.task_counts("run-1") == {"skipped_deadline": 2}


def test_task_with_insufficient_remaining_time_is_skipped(tmp_path):
    store, ctx, registry = build(tmp_path, [Recorder()], deadline_seconds=5)
    schedule(store, "slow", 1.0, min_seconds=60.0)
    asyncio.run(Scheduler(ctx, registry).drain())
    assert store.task_counts("run-1") == {"skipped_deadline": 1}


def test_agent_budget_step_cap_stops_dispatch(tmp_path):
    store, ctx, registry = build(tmp_path, [Recorder(max_steps=1)])
    for label in ("a", "b", "c"):
        schedule(store, label, 1.0)
    stats = asyncio.run(Scheduler(ctx, registry).drain())
    assert stats.completed == 1
    assert "recorder-agent" in stats.stopped
    assert store.task_counts("run-1") == {"done": 1, "pending": 2}
    types = {row["type"] for row in store.events("run-1")}
    assert "agent.budget_exhausted" in types


def test_handler_failure_is_recorded_and_others_continue(tmp_path):
    store, ctx, registry = build(tmp_path, [Boom(agent_id="boom-agent", kinds=("work",)), Recorder()])
    schedule(store, "boom", 5.0, agent="boom-agent")
    schedule(store, "ok", 1.0)
    stats = asyncio.run(Scheduler(ctx, registry).drain())
    assert stats.failed == 1 and stats.completed == 1
    types = {row["type"] for row in store.events("run-1")}
    assert "task.failed" in types
    assert "work.done" in types


def test_preflight_refusal_aborts_the_drain(tmp_path):
    store, ctx, registry = build(tmp_path, [Refusing(kinds=("work",))])
    schedule(store, "refuse", 1.0, agent="recorder-agent")
    with pytest.raises(PreflightError, match="enforcement unavailable"):
        asyncio.run(Scheduler(ctx, registry).drain())
    assert store.task_counts("run-1") == {"failed": 1}
