from __future__ import annotations

import copy
from typing import Any

import pytest

from mitigata.models import ScopeManifest

BASE: dict[str, Any] = {
    "engagement": {
        "name": "unit-test",
        "tier": "recon",
        "authorised_by": "test harness",
        "window": "2020-01-01T00:00:00Z/2035-01-01T00:00:00Z",
        "description": "offline unit-test scope",
    },
    "scope": {
        "ipv4": ["10.10.5.0/24"],
        "ipv6": [],
        "domains": [],
        "exclude": ["10.10.5.1", "10.10.5.255"],
        "binaries": [],
        "allow_public": False,
        "dns_resolver": "10.10.5.53",
    },
    "limits": {},
    "checks": {},
    "flags": {"patterns": [r"flag\{[^}]+\}"]},
    "crown_jewel": {},
    "report": {"formats": ["md", "json"]},
}


def manifest_dict(**scope_overrides: Any) -> dict[str, Any]:
    data = copy.deepcopy(BASE)
    data["scope"].update(scope_overrides)
    return data


def make_manifest(**scope_overrides: Any) -> ScopeManifest:
    return ScopeManifest.model_validate(manifest_dict(**scope_overrides))


@pytest.fixture
def manifest() -> ScopeManifest:
    return make_manifest()


@pytest.fixture(scope="module")
def lab_run(tmp_path_factory):
    """One complete hunt against the loopback lab simulator, shared by the pipeline and API tests."""
    from mitigata.pipeline import HuntOptions, run_hunt

    from .lab_sim import LabSim, write_lab_manifest

    work = tmp_path_factory.mktemp("lab")
    out = tmp_path_factory.mktemp("runs")
    with LabSim(work) as lab:
        manifest = write_lab_manifest(work / "scope.yaml")
        ports = ",".join(str(port) for port in lab.ports.values())
        summary = run_hunt(HuntOptions(scope_path=manifest, out_dir=out, ports=ports, full_scan=False,
                                       deadline_seconds=300, auth_hosts=["127.0.0.1"]))
        yield {"summary": summary, "out": out, "work": work, "ports": lab.ports, "manifest": manifest}
