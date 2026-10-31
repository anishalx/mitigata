"""Reporter agent: deterministic template, no LLM prose in this build."""

from __future__ import annotations

from typing import Any, Mapping

from ..models import AgentBudget, AgentContract, Event
from ..report.render import build_report, write_report
from .base import Agent, RunContext


class ReporterAgent(Agent):
    contract = AgentContract(
        id="reporter-agent",
        role="reporter",
        tools=["jinja2"],
        subscribes=["run.finalizing"],
        publishes=["report.ready"],
        budget=AgentBudget(max_steps=2, max_seconds=60, max_llm_calls=0),
    )
    kinds = ("report",)
    target_route = False

    async def handle(self, task: Mapping[str, Any], ctx: RunContext) -> list[Event]:
        payload = dict(task or {})
        formats = list(payload.get("formats") or ["md", "json"])
        model = build_report(
            ctx.store,
            ctx.run_id,
            ctx.out_dir,
            status=payload.get("status"),
            finished_at=payload.get("finished_at"),
        )
        paths = write_report(model, ctx.out_dir, formats)
        return [
            self.make_event(
                ctx,
                "report.ready",
                {"formats": formats, "paths": {name: str(path) for name, path in paths.items()}},
                ptes_phase="reporting",
                dedup_key=f"{ctx.run_id}:report:ready",
            )
        ]
