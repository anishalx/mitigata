"""Bounded, event-backed assessment of authorised hosts and supplied binaries.

Network-facing workers run only inside the named, policy-protected namespace.
The orchestrator owns SQLite writes; unverified observations remain candidates.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import dedup, policy
from .models import CoverageRow, Event, TaskRecord
from .scope import CompiledScope
from .store import Store
from .surfaces.binary import analyze_binary
from .tools.runner import run


DEFAULT_PORTS = "21,22,80,139,443,445,3000,3306,5432,6379,8000,8080,8443"
MAX_HOSTS = 1024
MAX_PORTS = 2048


class AssessmentError(RuntimeError):
    """A trusted assessment boundary or worker contract failed."""


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    for item in value.split(","):
        parts = item.strip().split("-")
        if len(parts) not in (1, 2) or not all(p.isascii() and p.isdecimal() for p in parts):
            raise ValueError(f"invalid TCP port/range: {item!r}")
        lo, hi = int(parts[0]), int(parts[-1])
        if not 1 <= lo <= hi <= 65535 or len(ports) + hi - lo + 1 > MAX_PORTS:
            raise ValueError(f"port range must be 1–65535 and at most {MAX_PORTS} ports")
        ports.update(range(lo, hi + 1))
    if not ports:
        raise ValueError("at least one TCP port must be selected")
    return sorted(ports)


def _allowed_blocks(scope: CompiledScope) -> Iterator[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Subtract exclusions as networks, not by walking potentially enormous CIDRs."""
    for allowed in scope.allowlist:
        blocks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [allowed]
        for excluded in scope.exclude:
            if excluded.version != allowed.version:
                continue
            remaining: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
            for block in blocks:
                if block.version == 4:
                    current = cast(ipaddress.IPv4Network, block)
                    denied = cast(ipaddress.IPv4Network, excluded)
                else:
                    current = cast(ipaddress.IPv6Network, block)
                    denied = cast(ipaddress.IPv6Network, excluded)
                if current.subnet_of(denied):
                    continue
                if denied.subnet_of(current):
                    remaining.extend(current.address_exclude(denied))
                else:
                    remaining.append(current)
            blocks = remaining
        yield from sorted(blocks, key=lambda network: int(network.network_address))


def _usable_host(
    scope: CompiledScope, address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Apply host semantics from the original allowlist after CIDR subtraction."""
    for network in scope.allowlist:
        if network.version != address.version or address not in network:
            continue
        if address == network.network_address and network.prefixlen < network.max_prefixlen - 1:
            continue
        if (
            isinstance(network, ipaddress.IPv4Network)
            and network.prefixlen < 31
            and address == network.broadcast_address
        ):
            continue
        return True
    return False


def allowed_hosts(scope: CompiledScope, limit: int) -> tuple[list[str], bool]:
    if not 1 <= limit <= MAX_HOSTS:
        raise ValueError(f"max-hosts must be 1–{MAX_HOSTS}")
    hosts: list[str] = []
    seen: set[str] = set()
    for block in _allowed_blocks(scope):
        for address in block:
            host = str(address)
            if host in seen or not _usable_host(scope, address):
                continue
            seen.add(host)
            if len(hosts) >= limit:
                return hosts, True
            hosts.append(host)
    return hosts, False


def _redacted_url(raw: str) -> str:
    """Retain route and parameter names while discarding every query value."""
    parsed = urlsplit(raw)
    names = sorted({
        re.sub(r"[^A-Za-z0-9_.-]", "", name)[:64]
        for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
    } - {""})
    query = urlencode([(name, "<redacted>") for name in names])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, ""))


def _event(store: Store, run_id: str, agent: str, kind: str, payload: dict[str, Any], phase: str) -> None:
    store.add_event(Event(
        id=f"ev-{secrets.token_hex(8)}", run_id=run_id, agent=agent,
        type=kind, payload=payload, ptes_phase=phase,  # type: ignore[arg-type]
    ))


def _task(store: Store, run_id: str, agent: str, kind: str, key: str, payload: dict[str, Any], phase: str) -> None:
    store.schedule(TaskRecord(
        id=f"task-{secrets.token_hex(8)}", run_id=run_id, agent=agent,
        kind=kind, dedup_key=key, payload=payload, ptes_phase=phase,  # type: ignore[arg-type]
    ))


def _worker(namespace: str, scope: CompiledScope, module: str, args: list[str], timeout: float) -> dict[str, Any]:
    command = policy.worker_command(namespace, scope, module, args)
    result = run(command, timeout=max(1.0, timeout))
    if result.timed_out:
        raise AssessmentError(f"{module} worker timed out")
    if len(result.stdout) > 1_048_576:
        raise AssessmentError(f"{module} worker exceeded the result cap")
    if result.returncode != 0:
        raise AssessmentError(f"{module} worker failed: {result.stderr.strip()[:200] or result.stdout.strip()[:200]}")
    try:
        parsed = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise AssessmentError(f"{module} worker emitted invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise AssessmentError(f"{module} worker result must be a JSON object")
    return parsed


def analyze_supplied_binaries(store: Store, run_id: str, evidence_dir: Path) -> dict[str, int]:
    """Quarantine validated ELF/PE files; never execute or disclose credential values."""
    counts = {"binaries_analyzed": 0, "binary_candidates": 0, "binaries_rejected": 0}
    for row in list(store.binaries(run_id))[:4]:
        path = Path(row["path"])
        result = analyze_binary(str(path))
        if not result["format"] or result["sha256"] != row["sha256"]:
            counts["binaries_rejected"] += 1
            _event(store, run_id, "binary-agent", "binary.rejected", {
                "source_sha256": row["sha256"], "reason": result["errors"][0] if result["errors"] else "hash_changed",
            }, "intelligence_gathering")
            continue
        sha = result["sha256"]
        dest = evidence_dir / "binaries" / sha / "artifact"
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name("artifact.tmp")
        digest = hashlib.sha256()
        with path.open("rb") as source, tmp.open("wb") as target:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                target.write(chunk)
                if target.tell() > 64 * 1024 * 1024:
                    raise AssessmentError("binary changed during quarantine: too large")
        if digest.hexdigest() != sha:
            tmp.unlink(missing_ok=True)
            raise AssessmentError("binary changed during quarantine: hash mismatch")
        os.chmod(tmp, 0o400)
        os.replace(tmp, dest)
        store.upsert_binary(run_id, sha, str(dest), result["size"], format=result["format"], state="analyzed_static")
        counts["binaries_analyzed"] += 1
        _event(store, run_id, "orchestrator", "binary.ingested", {
            "sha256": sha, "size": result["size"], "format": result["format"],
        }, "intelligence_gathering")
        for lead in result["secret_candidates"]:
            key = dedup.candidate(run_id, None, None, None, "hardcoded_secret", f"{sha}:{lead['offset']}")
            candidate_id = store.add_candidate(run_id, dedup_key=key, vuln_class="hardcoded_secret",
                claim=f"Static {lead['secret_type']} indicator in binary {sha[:12]} at offset {lead['offset']} (unverified)")
            if candidate_id is not None:
                counts["binary_candidates"] += 1
                _event(store, run_id, "binary-agent", "candidate.created", {
                    "candidate_id": candidate_id, "class": "hardcoded_secret", "binary_sha256": sha,
                    "offset": lead["offset"], "status": "unverified",
                }, "vulnerability_analysis")
        for name in result["unsafe_imports"]:
            key = dedup.candidate(run_id, None, None, None, "unsafe_function", f"{sha}:{name}")
            candidate_id = store.add_candidate(run_id, dedup_key=key, vuln_class="unsafe_function",
                claim=f"Static {name} string in binary {sha[:12]} (reachability unverified)")
            if candidate_id is not None:
                counts["binary_candidates"] += 1
                _event(store, run_id, "binary-agent", "candidate.created", {
                    "candidate_id": candidate_id, "class": "unsafe_function", "binary_sha256": sha,
                    "status": "unverified",
                }, "vulnerability_analysis")
        _event(store, run_id, "binary-agent", "binary.analyzed", {
            "sha256": sha, "format": result["format"], "unsafe_imports": result["unsafe_imports"],
            "secret_candidate_count": len(result["secret_candidates"]), "limitations": result["errors"],
        }, "vulnerability_analysis")
    remaining = max(0, len(store.binaries(run_id)) - 4)
    if remaining:
        _event(store, run_id, "orchestrator", "binary.deferred", {
            "count": remaining, "reason": "max_artifacts",
        }, "intelligence_gathering")
    return counts


def _retain_reflection_evidence(
    store: Store, run_id: str, candidate_id: int, evidence_dir: Path,
    payload: dict[str, Any],
) -> int:
    """Write the oracle record, then register it as candidate-owned evidence."""
    directory = evidence_dir / "reflections"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{candidate_id}.json"
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    path.write_text(encoded, encoding="utf-8")
    return store.add_evidence(
        run_id, type="reflection_canary", candidate_id=candidate_id,
        ptes_phase="vulnerability_analysis", path=str(path),
        sha256=hashlib.sha256(encoded.encode()).hexdigest(), payload=payload,
    )


def _ingest_web_result(
    store: Store, run_id: str, evidence_dir: Path, ip: str, port: int,
    asset_id: int, service_id: int, result: dict[str, Any], max_pages: int,
) -> dict[str, int]:
    """Persist endpoints, confirm paired-canary reflections, record coverage."""
    counts = {"endpoints": 0, "candidates": 0, "confirmed": 0}
    for endpoint in result.get("endpoints", []):
        parsed = urlsplit(endpoint.get("url", ""))
        if parsed.hostname != ip or parsed.port != port or parsed.scheme not in ("http", "https"):
            continue
        normalized = _redacted_url(endpoint["url"])
        store.upsert_endpoint(run_id, service_id, "GET", normalized, normalized)
        counts["endpoints"] += 1
        _event(store, run_id, "web-agent", "endpoint.discovered", {
            "ip": ip, "port": port, "url": normalized, "status": endpoint.get("status"),
        }, "intelligence_gathering")
    for lead in result.get("candidates", []):
        evidence = lead.get("evidence")
        if lead.get("type") != "raw_html_reflection" or lead.get("verified") is not True:
            continue
        param = re.sub(r"[^A-Za-z0-9_.-]", "", str(lead.get("parameter", "")))[:64]
        if not param or not isinstance(evidence, dict):
            continue
        path = re.sub(r"[^A-Za-z0-9_./-]", "", str(evidence.get("path", "")))[:128] or "/"
        key = dedup.candidate(run_id, asset_id, service_id, None, "raw_html_reflection", param)
        candidate_id = store.add_candidate(run_id, dedup_key=key, vuln_class="raw_html_reflection",
            claim=(f"Parameter {param} is returned unescaped in the HTML body of {path} "
                   f"on {ip}:{port}; script execution not tested"),
            asset_id=asset_id, service_id=service_id)
        if candidate_id is None:
            continue
        payload = {
            "ip": ip, "port": port, "path": path, "parameter": param,
            "oracle": str(evidence.get("oracle", ""))[:200],
            "probe_status": evidence.get("probe_status"),
            "control_status": evidence.get("control_status"),
            "probe_sha256": str(evidence.get("probe_sha256", ""))[:64],
            "control_sha256": str(evidence.get("control_sha256", ""))[:64],
        }
        evidence_id = _retain_reflection_evidence(store, run_id, candidate_id, evidence_dir, payload)
        store.add_validation(
            run_id, candidate_id, verdict="confirmed",
            oracle="paired_canary_get", control_kind="distinct_marker",
            evidence_id=evidence_id,
        )
        counts["candidates"] += 1
        counts["confirmed"] += 1
        _event(store, run_id, "web-agent", "candidate.confirmed", {
            "candidate_id": candidate_id, "class": "raw_html_reflection",
            "parameter": param, "evidence_id": evidence_id,
        }, "vulnerability_analysis")
    store.upsert_coverage(CoverageRow(run_id=run_id, asset_id=asset_id,
        attack_class="web.unauthenticated_inventory", state="tested",
        reason=f"bounded crawl of at most {max_pages} pages on {ip}:{port}; no authentication or exploitation"))
    return counts


def run_assessment(
    store: Store, run_id: str, scope: CompiledScope, evidence_dir: Path, *,
    namespace: str | None, ports: list[int], max_hosts: int, max_pages: int,
    max_workers: int, deadline: float, analyze_binaries: bool,
) -> dict[str, Any]:
    summary: dict[str, Any] = {"hosts_planned": 0, "hosts_scanned": 0, "hosts_deferred": 0,
        "host_cap_reached": False, "services": 0, "web_services": 0, "endpoints": 0,
        "candidates": 0, "confirmed": 0, "errors": [],
        "ports_per_host": len(ports), "max_hosts": max_hosts}
    if analyze_binaries:
        summary.update(analyze_supplied_binaries(store, run_id, evidence_dir))
    if namespace is None:
        _event(store, run_id, "orchestrator", "assessment.summary", summary, "reporting")
        return summary
    hosts, truncated = allowed_hosts(scope, max_hosts)
    summary["hosts_planned"] = len(hosts)
    summary["host_cap_reached"] = truncated
    if truncated:
        summary["errors"].append(f"host cap {max_hosts} reached; remaining hosts untested")
    pending_web: list[tuple[str, int, int, int, bool]] = []
    jobs = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for ip in hosts:
            if time.monotonic() + 1 >= deadline:
                summary["errors"].append("deadline reached before completing host discovery")
                break
            key = dedup.task(run_id, f"network:{ip}:{','.join(map(str, ports))}")
            _task(store, run_id, "discovery-agent", "scan_host", key, {"ip": ip, "ports": ports}, "intelligence_gathering")
            claimed = store.claim(run_id, ["discovery-agent"])
            if claimed is None:
                raise AssessmentError("new discovery task could not be claimed")
            budget = min(30.0, max(1.0, deadline - time.monotonic()))
            future = pool.submit(_worker, namespace, scope, "mitigata.surfaces.network", [
                "--ip", ip, "--ports", ",".join(map(str, ports)), "--timeout", "0.35",
                "--budget", str(budget),
            ], budget + 5)
            jobs.append((future, claimed["id"], ip))
        for future, task_id, ip in jobs:
            try:
                result = future.result()
                if (
                    result.get("ip") != ip
                    or not isinstance(result.get("services"), list)
                    or not isinstance(result.get("reachable"), bool)
                ):
                    raise AssessmentError("network worker result did not match scheduled target")
                summary["hosts_scanned"] += 1
                services = result["services"]
                if result.get("errors"):
                    summary["errors"].append(f"{ip}: {len(result['errors'])} port checks were uncertain")
                asset_id = store.upsert_asset(run_id, ip)
                _event(store, run_id, "discovery-agent", "asset.discovered", {
                    "ip": ip, "asset_id": asset_id, "reachable": result["reachable"],
                    "open_services": len(services),
                }, "intelligence_gathering")
                for service in services:
                    port = service.get("port")
                    if not isinstance(port, int) or port not in ports:
                        raise AssessmentError("network worker returned an unscheduled port")
                    name = str(service.get("name", "tcp"))
                    service_id = store.upsert_service(run_id, asset_id, port, name=name)
                    summary["services"] += 1
                    _event(store, run_id, "discovery-agent", "service.identified", {
                        "ip": ip, "port": port, "service_id": service_id, "name": name,
                    }, "intelligence_gathering")
                    if name in ("http", "https"):
                        pending_web.append((ip, port, asset_id, service_id, name == "https"))
                store.upsert_coverage(CoverageRow(run_id=run_id, asset_id=asset_id,
                    attack_class="network.tcp_inventory",
                    state="tested" if result["reachable"] else "untested",
                    reason=(
                        f"tested {len(ports)} configured TCP ports; no UDP or full-port claim"
                        if result["reachable"] else
                        f"no TCP response on {len(ports)} configured ports; host did not answer"
                    )))
                store.complete(task_id)
            except Exception as exc:
                store.complete(task_id, "failed")
                summary["errors"].append(f"discovery {ip}: {str(exc)[:160]}")
    jobs = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for ip, port, asset_id, service_id, tls in pending_web:
            if time.monotonic() + 1 >= deadline:
                summary["errors"].append("deadline reached before web inventory")
                break
            key = dedup.task(run_id, f"web:{ip}:{port}:{tls}")
            _task(store, run_id, "web-agent", "inspect_site", key, {"ip": ip, "port": port}, "intelligence_gathering")
            claimed = store.claim(run_id, ["web-agent"])
            if claimed is None:
                raise AssessmentError("new web task could not be claimed")
            args = ["--ip", ip, "--port", str(port), "--max-pages", str(max_pages), "--timeout", "3"]
            if tls:
                args.append("--tls")
            future = pool.submit(_worker, namespace, scope, "mitigata.surfaces.web", args,
                min(max_pages * 4.0 + 5.0, max(1.0, deadline - time.monotonic())))
            jobs.append((future, claimed["id"], ip, port, asset_id, service_id))
        for future, task_id, ip, port, asset_id, service_id in jobs:
            try:
                result = future.result()
                if result.get("ip") != ip or result.get("port") != port:
                    raise AssessmentError("web worker result did not match scheduled service")
                summary["web_services"] += 1
                counts = _ingest_web_result(
                    store, run_id, evidence_dir, ip, port, asset_id, service_id, result, max_pages,
                )
                for key in ("endpoints", "candidates", "confirmed"):
                    summary[key] += counts[key]
                if result.get("errors"):
                    summary["errors"].append(f"web {ip}:{port}: {len(result['errors'])} page checks failed")
                store.complete(task_id)
            except Exception as exc:
                store.complete(task_id, "failed")
                summary["errors"].append(f"web {ip}:{port}: {str(exc)[:160]}")
    summary["hosts_deferred"] += max(0, len(hosts) - summary["hosts_scanned"])
    _event(store, run_id, "orchestrator", "assessment.summary", summary, "reporting")
    return summary
