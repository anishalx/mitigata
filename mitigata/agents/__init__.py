"""Agent package: in-process preflight and reporter workers.

Target-facing discovery and web workers are separate namespace-isolated
processes under ``mitigata.surfaces``; the orchestrator only launches them.
"""

from .base import Agent, AgentRegistry, RegistryError, RunContext
from .preflight import PreflightAgent, PreflightError
from .reporter import ReporterAgent

__all__ = [
    "Agent",
    "AgentRegistry",
    "RegistryError",
    "RunContext",
    "PreflightAgent",
    "PreflightError",
    "ReporterAgent",
    "default_registry",
]


def default_registry() -> AgentRegistry:
    registry = AgentRegistry()
    registry.register(PreflightAgent())
    registry.register(ReporterAgent())
    registry.validate_closed()
    return registry
