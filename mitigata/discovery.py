"""Host-direct discovery: shared by the CLI script and the local GUI.

Every run created here carries ``host_direct_unenforced``: probes use the host
network with no namespace and no egress policy. Scope enforcement is handled by
refusing targets outside the compiled manifest allowlist, and the run record
states the missing enforcement explicitly.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

from . import dedup
from .models import CoverageRow, Event, TaskRecord, utcnow
from .report.render import build_report, write_report
from .config import load_manifest
from .scope import CompiledScope, compile_scope
from .store import Store
from .surfaces.network import scan_host

MODE = "host_direct_unenforced"
MAX_HOSTS = 256
RUN_ID = re.compile(r"run-[A-Za-z0-9_-]{1,80}\Z")


def parse_range(spec: str) -> list[str]:
    """Accept ``192.168.60.0/24``, ``192.168.60.1-254``, or a single IPv4 address.

    A bare IPv4 address expands to its ``/24`` so a single host input still
    discovers the surrounding network; a bare IPv6 address stays a single host.
    """
    spec = spec.strip()
    if "/" not in spec and "-" not in spec:
        try:
            address = ipaddress.ip_address(spec)
        except ValueError as exc:
            raise ValueError(f"not an address, CIDR, or A.B.C.N-M range: {spec!r}") from exc
        return parse_range(f"{address}/24") if address.version == 4 else [str(address)]
    if "/" in spec:
        network = ipaddress.ip_network(spec, strict=False)
        hosts: list[str] = []
        for address in network:
            if address.version == 4:
                if network.prefixlen < 31 and address in (network.network_address, network.broadcast_address):
                    continue
            elif network.prefixlen < 127 and address == network.network_address:
                continue
            hosts.append(str(address))
        return hosts
    base, _, span = spec.rpartition(".")
    low, _, high = span.partition("-")
    if not (base and span and low.isdecimal() and high.isdecimal()):
        raise ValueError(f"range must be a CIDR or A.B.C.N-M form, got {spec!r}")
    first, last = int(low), int(high)
    if not 0 <= first <= last <= 255:
        raise ValueError(f"octet range must satisfy 0 <= first <= last <= 255, got {span!r}")
    network = ipaddress.ip_network(f"{base}.0/24", strict=False)
    return [f"{base}.{index}" for index in range(first, last + 1) if ipaddress.ip_address(f"{base}.{index}") in network]


def in_scope(scope: CompiledScope, ip: str) -> bool:
    """True when the address is inside an allowed network and is a usable host."""
    address = ipaddress.ip_address(ip)
    if any(address.version == net.version and address in net for net in scope.exclude):
        return False
    for network in scope.allowlist:
        if address.version != network.version or address not in network:
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


def filter_scope(scope: CompiledScope, hosts: Iterable[str]) -> list[str]:
    selected: list[str] = []
    for ip in hosts:
        try:
            if in_scope(scope, ip):
                selected.append(ip)
        except ValueError:
            continue
    return selected


MAX_RANGE_HOSTS = 4096


def resolve_range(scope_path: Path | None, spec: str, *, limit: int = MAX_RANGE_HOSTS) -> list[str]:
    """Expand a user range and keep only the addresses the manifest allows. Any refusal raises ValueError."""
    if scope_path is None:
        raise ValueError("no scope manifest is loaded; start the dashboard with --scope")
    manifest, _ = load_manifest(scope_path)
    scope = compile_scope(manifest)
    hosts = parse_range(spec)
    if not hosts:
        raise ValueError("the range contains no usable host addresses")
    if len(hosts) > limit:
        raise ValueError(f"the range has {len(hosts)} addresses; the limit is {limit}")
    allowed = filter_scope(scope, hosts)
    if len(allowed) != len(hosts):
        raise ValueError(f"{len(hosts) - len(allowed)} address(es) are outside the manifest scope or excluded")
    return allowed


def probe(
    ip: str, ports: list[int], *, timeout_s: float = 0.35, budget_s: float = 8.0,
    liveness_only: bool = False,
) -> dict[str, Any]:
    try:
        result = scan_host(
            ip, ports, timeout_s=timeout_s, budget_s=budget_s,
            stop_on_response=liveness_only,
        )
        if liveness_only:
            result["services"] = []
            if result["reachable"]:
                result["errors"] = []
        return result
    except (OSError, ValueError) as exc:
        return {"ip": ip, "reachable": False, "services": [], "errors": [f"{type(exc).__name__}: {exc}"]}


def iterate(
    hosts: Iterable[str], ports: list[int], *, workers: int, timeout_s: float, budget_s: float,
    liveness_only: bool = False,
) -> Iterator[dict[str, Any]]:
    """Yield results as probes finish, so callers can update progress live."""
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [
            pool.submit(
                probe, ip, ports, timeout_s=timeout_s, budget_s=budget_s,
                liveness_only=liveness_only,
            )
            for ip in hosts
        ]
        for future in as_completed(futures):
            yield future.result()


def _text(value: Any) -> str | None:
    return value.strip()[:200] if isinstance(value, str) and value.strip() else None


def untested_hosts(store: Store, run_id: str) -> list[str]:
    """Addresses without a response during host discovery or legacy TCP inventory."""
    rows = store.conn.execute(
        "SELECT a.ip FROM coverage c JOIN assets a ON a.id = c.asset_id"
        " WHERE c.run_id=? AND c.attack_class IN ('network.host_discovery', 'network.tcp_inventory')"
        " AND c.state='untested' AND NOT EXISTS (SELECT 1 FROM coverage ok"
        " WHERE ok.asset_id=a.id AND ok.state='tested'"
        " AND ok.attack_class IN ('network.host_discovery', 'network.tcp_inventory',"
        " 'network.tcp_full_inventory')) ORDER BY a.id",
        (run_id,),
    ).fetchall()
    return [str(row["ip"]) for row in rows]


def run_ports(store: Store, run_id: str) -> list[int]:
    """Reuse the port list recorded by the run's last assessment summary."""
    row = store.conn.execute(
        "SELECT payload_json FROM events WHERE run_id=? AND type='assessment.summary'"
        " ORDER BY rowid DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    if row is not None:
        try:
            payload = json.loads(row["payload_json"])
        except (ValueError, TypeError):
            payload = {}
        recorded = payload.get("ports") if isinstance(payload, dict) else None
        if isinstance(recorded, list) and recorded and all(type(port) is int and 1 <= port <= 65535 for port in recorded):
            return list(recorded)
    from .assessment import DEFAULT_PORTS, parse_ports

    return parse_ports(DEFAULT_PORTS)


def _event(run_id: str, agent: str, type: str, payload: dict[str, Any], phase: str) -> Event:
    return Event(
        id=f"ev-{secrets.token_hex(8)}", run_id=run_id, agent=agent,
        type=type, payload=payload, ptes_phase=phase,  # type: ignore[arg-type]
    )


def create_run(
    out_dir: Path, manifest: Any, scope: CompiledScope, manifest_sha256: str,
) -> tuple[str, Store, Path]:
    run_id = f"run-{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"
    run_dir = out_dir.resolve() / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    store = Store(run_dir / "blackboard.db")
    try:
        store.create_run(
            run_id, engagement=manifest.engagement.name, tier=manifest.engagement.tier,
            scope_hash=scope.scope_hash, manifest_sha256=manifest_sha256,
            enforcement=MODE, started_at=utcnow(),
        )
    except Exception:
        store.close()
        raise
    store.add_event(_event(run_id, "orchestrator", "scope.compiled", {
        "scope_hash": scope.scope_hash,
        "allowlist": [str(net) for net in scope.allowlist],
        "exclude": [str(net) for net in scope.exclude],
        "block_ipv6": scope.block_ipv6,
        "allow_public": scope.allow_public,
        "dns_resolver": scope.dns_resolver,
        "enforcement": MODE,
        "profile": "host-direct",
        "tier": manifest.engagement.tier,
        "manifest_sha256": manifest_sha256,
    }, "pre_engagement"))
    return run_id, store, run_dir


def open_run(out_dir: Path, run_id: str) -> Store:
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("invalid run id")
    database = out_dir.resolve() / run_id / "blackboard.db"
    if not database.is_file():
        raise ValueError("unknown run")
    return Store(database)


def record_result(
    store: Store, run_id: str, result: dict[str, Any], ports: list[int], *,
    liveness_only: bool = False,
) -> dict[str, Any]:
    """Persist one probe result and return progress information."""
    ip = result.get("ip")
    if not isinstance(ip, str) or not ip:
        raise ValueError("result has no ip")
    key = dedup.task(run_id, f"network:{ip}:{','.join(map(str, ports))}:{'live' if liveness_only else 'inventory'}")
    store.schedule(TaskRecord(
        id=f"task-{secrets.token_hex(8)}", run_id=run_id, agent="discovery-agent",
        kind="probe_host" if liveness_only else "scan_host",
        payload={"ip": ip, "ports": ports, "mode": MODE},
        priority=100.0, dedup_key=key, ptes_phase="intelligence_gathering",
    ))
    task_id = store.task_id_for(run_id, key)
    services = [] if liveness_only else (result.get("services") or [])
    asset_id = store.upsert_asset(run_id, ip)
    store.add_event(_event(run_id, "discovery-agent", "asset.discovered", {
        "ip": ip, "asset_id": asset_id, "reachable": bool(result.get("reachable")),
        "open_services": len(services),
    }, "intelligence_gathering"))
    stored_ports: list[dict[str, Any]] = []
    for service in services:
        port = service.get("port")
        if not isinstance(port, int) or port not in ports:
            continue
        name = str(service.get("name", "tcp"))
        product = _text(service.get("product"))
        version = _text(service.get("version"))
        extrainfo = _text(service.get("extrainfo"))
        store.upsert_service(
            run_id, asset_id, port, name=name, product=product, version=version,
            extrainfo=extrainfo, source=_text(service.get("source")) or "connect",
        )
        stored_ports.append({
            "port": port, "name": name, "product": product,
            "version": version, "extrainfo": extrainfo,
        })
        store.add_event(_event(run_id, "discovery-agent", "service.identified", {
            "ip": ip, "port": port, "name": name,
        }, "intelligence_gathering"))
    store.upsert_coverage(CoverageRow(
        run_id=run_id, asset_id=asset_id,
        attack_class="network.host_discovery" if liveness_only else "network.tcp_inventory",
        state="tested" if result.get("reachable") else "untested",
        reason=(
            "host answered a configured TCP reachability probe" if result.get("reachable")
            else "no TCP response on configured probes; host reachability unknown"
        ) if liveness_only else (
            f"tested {len(ports)} configured TCP ports from the host network"
            if result.get("reachable") else "no TCP response on the configured ports"
        ),
    ))
    if task_id:
        store.complete(task_id)
    return {"ip": ip, "reachable": bool(result.get("reachable")), "ports": stored_ports}


def finalize(
    store: Store, run_id: str, run_dir: Path, manifest: Any, *,
    planned: int, scanned: int, ports: list[int], errors: list[str],
    timeout_s: float, workers: int,
) -> str:
    summary = {
        "mode": MODE, "hosts_planned": planned, "hosts_scanned": scanned,
        "hosts_deferred": max(0, planned - scanned), "host_cap_reached": False,
        "services": int(store.aggregate(run_id)["services"]),
        "candidates": 0, "confirmed": 0, "errors": errors[:50],
        "ports_per_host": len(ports), "ports": list(ports), "max_hosts": MAX_HOSTS,
        "timeout_s": timeout_s, "workers": workers,
    }
    store.add_event(_event(run_id, "orchestrator", "assessment.summary", summary, "reporting"))
    finished_at = utcnow()
    status = "partial" if errors else "complete"
    store.add_event(_event(run_id, "orchestrator", "run.finalizing", {"reason": "discovery_complete"}, "reporting"))
    store.finish_run(run_id, status, finished_at=finished_at)
    model = build_report(store, run_id, run_dir, status=status, finished_at=finished_at)
    write_report(model, run_dir, list(manifest.report.formats))
    return status
