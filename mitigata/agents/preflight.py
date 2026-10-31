"""Preflight agent: validate authorization, binaries and egress enforcement.

Deterministic, no LLM, no target traffic. Any failure is fail-closed: the run is
refused rather than degraded (design §1.2, §3.3, §6.2).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .. import policy
from ..config import load_manifest, manifest_hash
from ..models import AgentBudget, AgentContract, Event
from ..scope import compile_scope
from .base import Agent, RunContext

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


class PreflightError(RuntimeError):
    """The run cannot proceed safely; nothing has been sent."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


class PreflightAgent(Agent):
    contract = AgentContract(
        id="preflight-agent",
        role="preflight",
        tools=["python", "nft", "hashlib"],
        subscribes=["run.started"],
        publishes=["scope.compiled", "scope.audit"],
        budget=AgentBudget(max_steps=4, max_seconds=30, max_llm_calls=0),
    )
    kinds = ("preflight",)
    target_route = False

    async def handle(self, task: Mapping[str, Any], ctx: RunContext) -> list[Event]:
        payload = dict(task or {})
        manifest_path = Path(payload["manifest_path"])
        expected_hash = payload["manifest_sha256"]
        profile = payload.get("profile", ctx.profile)
        control_ips = payload.get("control_ips", [])

        manifest, raw = load_manifest(manifest_path)
        if manifest_hash(raw) != expected_hash:
            raise PreflightError("scope manifest changed between compile and preflight; refusing to run")
        compiled = compile_scope(manifest)
        if compiled.scope_hash != ctx.scope.scope_hash:
            raise PreflightError("compiled scope differs from the reviewed scope; refusing to run")

        events: list[Event] = []
        start, end = manifest.engagement.window_bounds
        now = _now()
        if not start <= now <= end:
            raise PreflightError(
                f"engagement window {manifest.engagement.window} does not cover {now.isoformat()}; refusing to run"
            )


        hashed = self._hash_binaries(manifest_path, list(payload.get("binaries") or manifest.scope.binaries), ctx)
        events.append(
            self.make_event(
                ctx,
                "scope.audit",
                {"binaries_hashed": len(hashed), "binaries": hashed},
                ptes_phase="intelligence_gathering",
                dedup_key=f"{ctx.run_id}:audit:binaries",
            )
        )
        enforcement = self._enforce(ctx, profile, control_ips, payload.get("worker_netns"))
        events.append(
            self.make_event(
                ctx,
                "scope.audit",
                {"enforcement": enforcement, "profile": profile,
                 "table": policy.namespace_table(ctx.scope) if profile == "enforce" else None},
                ptes_phase="pre_engagement",
                dedup_key=f"{ctx.run_id}:audit:enforcement",
            )
        )
        events.append(
            self.make_event(
                ctx,
                "scope.compiled",
                {
                    "scope_hash": compiled.scope_hash,
                    "allowlist": [str(net) for net in compiled.allowlist],
                    "exclude": [str(net) for net in compiled.exclude],
                    "block_ipv6": compiled.block_ipv6,
                    "allow_public": compiled.allow_public,
                    "dns_resolver": compiled.dns_resolver,
                    "enforcement": enforcement,
                    "profile": profile,
                    "tier": manifest.engagement.tier,
                    "manifest_sha256": expected_hash,
                },
                ptes_phase="pre_engagement",
                dedup_key=f"{ctx.run_id}:scope:compiled",
            )
        )
        return events

    @staticmethod
    def _enforce(
        ctx: RunContext, profile: str, control_ips: list[str], worker_netns: str | None,
    ) -> str:
        if profile == "enforce":
            if not worker_netns:
                raise PreflightError("--netns is required for target-facing assessment")
            try:
                policy.install_in_namespace(ctx.scope, worker_netns, control_ips=control_ips)
            except policy.PolicyError as exc:
                raise PreflightError(str(exc)) from exc
            return "installed_in_namespace"
        if profile == "no-target":
            if worker_netns:
                raise PreflightError(
                    "profile 'no-target' must not name a worker namespace; target traffic would be possible"
                )
            return "not_required_no_workers"
        raise PreflightError(f"unknown enforcement profile {profile!r}")

    @staticmethod
    def _hash_binaries(manifest_path: Path, patterns: list[str], ctx: RunContext) -> list[dict[str, Any]]:
        base = manifest_path.parent
        hashed: list[dict[str, Any]] = []
        for pattern in patterns:
            for candidate in sorted(base.glob(pattern)):
                if not candidate.is_file():
                    continue
                size = candidate.stat().st_size
                if size > MAX_ARTIFACT_BYTES:
                    raise PreflightError(f"{candidate} is {size} bytes and exceeds the 64 MiB ingest cap")
                digest = hashlib.sha256()
                with candidate.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                sha256 = digest.hexdigest()
                ctx.store.upsert_binary(ctx.run_id, sha256, str(candidate), size)
                hashed.append({"path": str(candidate), "sha256": sha256, "size": size})
        return hashed
