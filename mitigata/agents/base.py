"""Worker base classes and the orchestrator-owned run context (design §3.3)."""

from __future__ import annotations

import secrets
from abc import ABC
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..models import AgentContract, Event
from ..scope import CompiledScope
from ..store import Store


class RegistryError(RuntimeError):
    """An agent contract is inconsistent with the rest of the team."""


@dataclass(frozen=True)
class RunContext:
    run_id: str
    scope: CompiledScope
    store: Store
    out_dir: Path
    evidence_dir: Path
    profile: str
    deadline: float  # time.monotonic() based

    def remaining(self, now: float) -> float:
        return max(0.0, self.deadline - now)


class Agent(ABC):
    """A worker: declared contract, declared kinds, no direct database access."""

    contract: AgentContract
    kinds: tuple[str, ...] = ()
    target_route: bool = False

    async def handle(self, task: Mapping[str, Any], ctx: RunContext) -> list[Event]:
        raise NotImplementedError

    def make_event(
        self,
        ctx: RunContext,
        type: str,
        payload: dict[str, Any] | None = None,
        *,
        ptes_phase: str = "pre_engagement",
        dedup_key: str | None = None,
    ) -> Event:
        return Event(
            id=f"ev-{secrets.token_hex(8)}",
            run_id=ctx.run_id,
            agent=self.contract.id,
            type=type,
            payload=payload or {},
            ptes_phase=ptes_phase,  # type: ignore[arg-type]
            dedup_key=dedup_key,
        )


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, Agent] = {}

    def register(self, agent: Agent) -> None:
        contract = agent.contract
        if contract.id in self._agents:
            raise RegistryError(f"duplicate agent id {contract.id!r}")
        if not agent.kinds:
            raise RegistryError(f"{contract.id}: at least one task kind must be declared")
        self._agents[contract.id] = agent

    def validate_closed(self) -> None:
        """Every subscribed event must be published by someone or the orchestrator."""
        from ..models import ORCHESTRATOR_EVENTS

        published = set(ORCHESTRATOR_EVENTS)
        for agent in self._agents.values():
            published.update(agent.contract.publishes)
        for agent in self._agents.values():
            unresolved = set(agent.contract.subscribes) - published
            if unresolved:
                raise RegistryError(f"{agent.contract.id} subscribes to unpublished events: {sorted(unresolved)}")

    def get(self, agent_id: str) -> Agent:
        try:
            return self._agents[agent_id]
        except KeyError as exc:
            raise RegistryError(f"unknown agent {agent_id!r}") from exc

    def all(self) -> list[Agent]:
        return list(self._agents.values())

    def ids(self) -> list[str]:
        return list(self._agents)

    def target_routed(self) -> list[str]:
        return [agent.contract.id for agent in self._agents.values() if agent.target_route]
