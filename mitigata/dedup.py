"""Deduplication keys (design §3.4).

Every scheduled check and observation is registered under one of these keys, so
retries and duplicate discoveries collapse to a single work item.
"""

from __future__ import annotations

import hashlib
from typing import Any


def _key(*parts: Any) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(str(part).encode())
        digest.update(b"\x00")
    return digest.hexdigest()


def port(run_id: str, ip: str, port: int, proto: str) -> str:
    return _key(run_id, "port", ip, port, proto)


def endpoint(run_id: str, service_id: int | None, method: str, normalized_url: str) -> str:
    return _key(run_id, "endpoint", service_id, method.upper(), normalized_url)


def check(run_id: str, asset_id: int | None, service_id: int | None, check_id: str, normalized_param: str) -> str:
    return _key(run_id, "check", asset_id, service_id, check_id, normalized_param)


def candidate(
    run_id: str,
    asset_id: int | None,
    service_id: int | None,
    endpoint_id: int | None,
    vuln_class: str,
    parameter: str,
) -> str:
    return _key(run_id, "candidate", asset_id, service_id, endpoint_id, vuln_class, parameter)


def binary_artifact(run_id: str, sha256: str) -> str:
    return _key(run_id, "binary", sha256)


def decompiled_function(run_id: str, binary_sha256: str, function_addr: int) -> str:
    return _key(run_id, "decomp", binary_sha256, function_addr)


def reachability(run_id: str, binary_sha256: str, target_addr: int | None, target_kind: str) -> str:
    return _key(run_id, "reach", binary_sha256, target_addr, target_kind)


def credential_reuse(run_id: str, credential_id: int | None, service_id: int | None) -> str:
    return _key(run_id, "reuse", credential_id, service_id)


def task(run_id: str, kind: str) -> str:
    """Orchestrator-internal work item key (preflight, report rendering)."""
    return _key(run_id, "task", kind)
