"""Typed schemas shared by the orchestrator and workers (design §3.3, §5.2).

Only the orchestrator writes authoritative rows; workers exchange these models
over the bounded control channel.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PTES_PHASES = (
    "pre_engagement",
    "intelligence_gathering",
    "threat_modeling",
    "vulnerability_analysis",
    "exploitation",
    "post_exploitation",
    "reporting",
)
PtesPhase = Literal[*PTES_PHASES]

TIERS = ("recon", "breach", "deep")
Tier = Literal[*TIERS]

#: Events the orchestrator or scheduler emits itself, so no agent contract
#: has to declare them (§3.3, §3.4).
ORCHESTRATOR_EVENTS = frozenset(
    {
        "run.started",
        "run.finalizing",
        "binary.ingested",
        "binary.rejected",
        "binary.deferred",
        "validation.passed",
        "validation.failed",
    }
)


def utcnow() -> str:
    """Second-resolution UTC timestamp; ISO strings sort lexicographically."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Engagement(_Frozen):
    name: str = Field(min_length=1)
    tier: Tier
    authorised_by: str = Field(min_length=1)
    window: str = Field(min_length=1)
    description: str = ""

    @field_validator("window")
    @classmethod
    def _window(cls, value: str) -> str:
        start, sep, end = value.partition("/")
        if not sep:
            raise ValueError("window must be '<start>/<end>' (ISO-8601)")
        try:
            begin = datetime.fromisoformat(start.replace("Z", "+00:00"))
            finish = datetime.fromisoformat(end.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"window is not ISO-8601: {exc}") from exc
        if begin.tzinfo is None or finish.tzinfo is None:
            raise ValueError("window endpoints must include a timezone offset or Z")
        if finish <= begin:
            raise ValueError("window end must be after start")
        return value

    @property
    def window_bounds(self) -> tuple[datetime, datetime]:
        start, _, end = self.window.partition("/")
        return (
            datetime.fromisoformat(start.replace("Z", "+00:00")),
            datetime.fromisoformat(end.replace("Z", "+00:00")),
        )


class ScopeSection(_Frozen):
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    binaries: list[str] = Field(default_factory=list)
    allow_public: bool = False
    dns_resolver: str | None = None

    @field_validator("domains")
    @classmethod
    def _domains(cls, values: list[str]) -> list[str]:
        for value in values:
            if "*" in value:
                raise ValueError(f"wildcard domains are unsupported: {value!r}")
            if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
                raise ValueError(f"invalid domain: {value!r}")
        return values


class Limits(_Frozen):
    max_rate_pps: int = Field(default=1000, gt=0)
    max_concurrent_hosts: int = Field(default=8, gt=0)
    max_http_rps_per_host: int = Field(default=10, gt=0)
    max_auth_attempts_per_account: int = Field(default=3, gt=0)
    max_payload_bytes: int = Field(default=1_048_576, gt=0)
    destructive: bool = False

    @field_validator("destructive")
    @classmethod
    def _no_destruction(cls, value: bool) -> bool:
        if value:
            raise ValueError("destructive testing is a hard constraint of this engine (§1.2)")
        return value


class HeaderTrustSection(_Frozen):
    """Explicit RoE permission for forged forwarded-address headers: a few GETs per listed host, never fuzzing."""

    enabled: bool = False
    #: IPv4 addresses that may receive the header test. The focus host is the usual single entry.
    hosts: list[str] = Field(default_factory=list)
    #: Hard cap on requests per host and path, control request included.
    max_requests: int = Field(default=30, ge=3, le=60)


class Checks(_Frozen):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    #: Explicit RoE permission for default-credential and passkey verification.
    #: Off by default; the verification agent refuses authentication attempts
    #: unless the manifest opts in, and every attempt is capped per account.
    auth_tests: bool = False
    #: Forwarded-address trust test (web.header_trust). Off unless the manifest names it and its hosts.
    header_trust: HeaderTrustSection = Field(default_factory=HeaderTrustSection)


class FlagsSection(_Frozen):
    patterns: list[str] = Field(default_factory=list)

    @field_validator("patterns")
    @classmethod
    def _compile(cls, values: list[str]) -> list[str]:
        for value in values:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid flag pattern {value!r}: {exc}") from exc
        return values


class CrownJewel(_Frozen):
    hosts: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)


class ReportSection(_Frozen):
    formats: list[Literal["md", "html", "json"]] = Field(default_factory=lambda: ["md", "json"])
    redact_secrets: bool = True
    include_flags: bool = False


class LLMSection(_Frozen):
    """Optional planner on the DeepSeek API. Off by default: enabling it sends redacted target excerpts to base_url."""

    enabled: bool = False
    provider: Literal["deepseek"] = "deepseek"
    model: Literal["deepseek-flash", "deepseek-v4-pro"] = "deepseek-flash"
    base_url: str = "https://api.deepseek.com"
    #: Name of the environment variable that holds the key. The key itself is never written to a manifest.
    api_key_env: str = Field(default="DEEPSEEK_API_KEY", pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    max_calls: int = Field(default=4, ge=0, le=20)
    max_excerpt_chars: int = Field(default=4000, ge=500, le=20000)

    @field_validator("base_url")
    @classmethod
    def _https_only(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("the planner endpoint must use https")
        return value


class ScopeManifest(_Frozen):
    engagement: Engagement
    scope: ScopeSection
    limits: Limits = Field(default_factory=Limits)
    checks: Checks = Field(default_factory=Checks)
    flags: FlagsSection = Field(default_factory=FlagsSection)
    crown_jewel: CrownJewel = Field(default_factory=CrownJewel)
    report: ReportSection = Field(default_factory=ReportSection)
    llm: LLMSection = Field(default_factory=LLMSection)


class Event(_Frozen):
    """Blackboard event (§3.3 event schema)."""

    id: str
    run_id: str
    ts: str = Field(default_factory=utcnow)
    agent: str
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    ptes_phase: PtesPhase = "pre_engagement"
    dedup_key: str | None = None

    @field_validator("type")
    @classmethod
    def _typed(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+", value):
            raise ValueError(f"event type must be dotted lower_snake: {value!r}")
        return value


class AgentBudget(_Frozen):
    max_steps: int = Field(default=30, gt=0)
    max_seconds: float = Field(default=360.0, gt=0)
    max_llm_calls: int = Field(default=0, ge=0)
    max_artifacts: int | None = Field(default=None, gt=0)


class AgentContract(_Frozen):
    """Declared worker contract; the registry rejects unknown event names."""

    id: str
    role: str
    tools: list[str] = Field(default_factory=list)
    subscribes: list[str] = Field(default_factory=list)
    publishes: list[str] = Field(default_factory=list)
    budget: AgentBudget = Field(default_factory=AgentBudget)
    stop_conditions: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9-]*-agent", value):
            raise ValueError(f"agent id must look like '<role>-agent': {value!r}")
        return value

    @model_validator(mode="after")
    def _events(self) -> "AgentContract":
        for event in [*self.subscribes, *self.publishes]:
            if not re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+", event):
                raise ValueError(f"invalid event name {event!r}")
        if not self.publishes:
            raise ValueError("an agent must declare at least one published event")
        return self


class TaskRecord(_Frozen):
    """A unit of scheduled work with its idempotency key (§3.4)."""

    id: str
    run_id: str
    agent: str
    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)
    ptes_phase: PtesPhase = "pre_engagement"
    priority: float = 1.0
    min_seconds: float = 0.0
    dedup_key: str
    #: The task whose result caused this one (lineage for the dashboard's discovery chain).
    parent_task_id: str | None = None
    created_at: str = Field(default_factory=utcnow)


class CoverageRow(_Frozen):
    run_id: str
    asset_id: int | None
    attack_class: str
    state: Literal["tested", "skipped", "untested", "failed"]
    reason: str = ""
