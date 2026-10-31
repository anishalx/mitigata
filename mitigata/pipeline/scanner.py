"""Discovery agent: nmap host discovery, top-port inventory and chunked full-range scans.

nmap runs as an argv subprocess with a hard timeout. Targets are written to an
explicit target file after the scope guard has filtered them, so nmap never
receives an address the guard did not approve. Scans are connect-based with no
service-version probes and no NSE scripts: identifying services is left to the
passive network and web agents, which keep the traffic sent to any single
service (for example an authentication protocol that rate-limits abusive
sources) to the minimum needed.

When nmap is not installed the module degrades to the engine's TCP connect
checks over a short port list, and the run records that degradation.
"""

from __future__ import annotations

import ipaddress
import shutil
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ..tools.runner import run
from .guard import ScopeGuard, ScopeViolation

#: Chunks of the 65,535-port space, scanned in order of how often services sit there.
FULL_RANGE_CHUNKS = ("1-16384", "16385-32768", "32769-49152", "49153-65535")
LIVENESS_PORTS = "22,80,443,8080"
FALLBACK_PORTS = (21, 22, 80, 139, 443, 445, 1111, 3000, 3306, 5432, 6379, 8000, 8080, 8443, 8833)


class ScanError(RuntimeError):
    """A discovery step could not produce a trustworthy result."""


def nmap_available(binary: str = "nmap") -> bool:
    return shutil.which(binary) is not None


def parse_hosts_xml(xml_text: str) -> list[dict[str, Any]]:
    """Normalise every IPv4 host in an nmap XML document (open ports only are listed)."""
    if not xml_text.strip():
        return []
    root = ET.fromstring(xml_text)
    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        ip = next(
            (node.get("addr") for node in host.findall("address")
             if node.get("addrtype") == "ipv4" and node.get("addr")),
            None,
        )
        if not ip:
            continue
        status = host.find("status")
        up = status is not None and status.get("state") == "up"
        ports: list[dict[str, Any]] = []
        closed = filtered = 0
        ports_element = host.find("ports")
        if ports_element is not None:
            for extra in ports_element.findall("extraports"):
                try:
                    count = int(extra.get("count", "0"))
                except ValueError:
                    count = 0
                if extra.get("state") == "closed":
                    closed += count
                elif extra.get("state") == "filtered":
                    filtered += count
            for port in ports_element.iter("port"):
                state = port.find("state")
                state_name = state.get("state") if state is not None else ""
                if state_name == "closed":
                    closed += 1
                elif state_name == "filtered":
                    filtered += 1
                elif state_name == "open":
                    service = port.find("service")
                    ports.append({
                        "port": int(port.get("portid", "0")),
                        "proto": port.get("protocol", "tcp"),
                        "name": (service.get("name") if service is not None else None) or "tcp",
                        "product": service.get("product") if service is not None else None,
                        "version": service.get("version") if service is not None else None,
                        "extrainfo": service.get("extrainfo") if service is not None else None,
                    })
        hosts.append({
            "ip": ip,
            "up": up,
            "ports": sorted(ports, key=lambda item: item["port"]),
            "closed": closed,
            "filtered": filtered,
            "timed_out": host.get("timedout") == "true",
        })
    return hosts


def _write_targets(hosts: list[str], workdir: Path, name: str) -> Path:
    path = workdir / f"{name}.txt"
    path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    return path


def _run_nmap(
    args: list[str], *, binary: str, workdir: Path, name: str, timeout: float,
) -> dict[str, Any]:
    xml_path = workdir / f"{name}.xml"
    argv = [binary, "-n", *args, "-oX", str(xml_path)]
    completed = run(argv, timeout=timeout)
    errors: list[str] = []
    if completed.timed_out:
        errors.append(f"nmap {name} exceeded its {timeout:.0f}s budget")
    xml_text = xml_path.read_text(encoding="utf-8", errors="replace") if xml_path.is_file() else ""
    if not xml_text.strip():
        tail = (completed.stderr or completed.stdout).strip().splitlines()
        errors.append(f"nmap {name} produced no XML: {(tail[-1] if tail else f'exit {completed.returncode}')[:200]}")
        return {"hosts": [], "xml": "", "errors": errors}
    try:
        hosts = parse_hosts_xml(xml_text)
    except ET.ParseError as exc:
        errors.append(f"nmap {name} XML was unreadable: {exc}")
        return {"hosts": [], "xml": xml_text, "errors": errors}
    for host in hosts:
        if host["timed_out"]:
            errors.append(f"nmap {name} timed out scanning host {host['ip']}; coverage is incomplete")
    if completed.returncode != 0 and not completed.timed_out:
        errors.append(f"nmap {name} exited with status {completed.returncode}")
    return {"hosts": hosts, "xml": xml_text, "errors": errors}


def _approved(guard: ScopeGuard, ips: list[str], purpose: str) -> list[str]:
    return guard.filter(ips, purpose=purpose)


def host_discovery(
    hosts: list[str], *, guard: ScopeGuard, workdir: Path, binary: str = "nmap",
    timeout: float = 240.0, max_rate: int = 2000,
) -> dict[str, Any]:
    """Ping-style discovery across the approved range using unprivileged TCP probes."""
    approved = _approved(guard, hosts, "host discovery")
    if not approved:
        return {"live": [], "xml": "", "errors": ["no approved hosts to discover"], "tool": "nmap"}
    targets = _write_targets(approved, workdir, "discovery-targets")
    result = _run_nmap(
        ["-sn", f"-PS{LIVENESS_PORTS}", "-PA80,443", "--max-retries", "1",
         "--max-rate", str(max_rate), "-iL", str(targets)],
        binary=binary, workdir=workdir, name="host-discovery", timeout=timeout,
    )
    live = [host["ip"] for host in result["hosts"] if host["up"] and host["ip"] in approved]
    return {"live": sorted(live, key=_ip_key), "xml": result["xml"], "errors": result["errors"], "tool": "nmap"}


def top_port_scan(
    hosts: list[str], *, guard: ScopeGuard, workdir: Path, binary: str = "nmap",
    top_ports: int = 1000, port_spec: str | None = None, timeout: float = 600.0,
    host_timeout: int = 240, max_rate: int = 2000, group_size: int = 12, concurrency: int = 3,
) -> dict[str, Any]:
    """Connect-scan the most common TCP ports (or an explicit list) on already-discovered hosts.

    Hosts run in groups of ``group_size`` as separate nmap processes, ``concurrency`` at a time.
    nmap only writes XML when a process finishes, so grouping means a slow group cannot
    discard the results of groups that already finished.
    """
    approved = _approved(guard, hosts, "top-port inventory")
    if not approved:
        return {"hosts": [], "xmls": [], "errors": [], "tool": "nmap"}
    selection = ["-p", port_spec] if port_spec else ["--top-ports", str(top_ports)]
    label = f"ports-{port_spec}" if port_spec else f"top-{top_ports}"
    groups = [approved[start:start + group_size] for start in range(0, len(approved), group_size)]

    def run_group(item: tuple[int, list[str]]) -> dict[str, Any]:
        index, group = item
        targets = _write_targets(group, workdir, f"inventory-{label}-g{index}")
        result = _run_nmap(
            ["-Pn", "-sT", *selection, "--max-retries", "1",
             "--host-timeout", f"{host_timeout}s", "--max-rate", str(max_rate), "-T4", "-iL", str(targets)],
            binary=binary, workdir=workdir, name=f"{label}-g{index}", timeout=timeout,
        )
        return {"hosts": _approved_hosts(guard, result["hosts"]), "xml": result["xml"], "errors": result["errors"]}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        results = list(pool.map(run_group, enumerate(groups)))
    return {
        "hosts": [host for result in results for host in result["hosts"]],
        "xmls": [result["xml"] for result in results if result["xml"]],
        "errors": [error for result in results for error in result["errors"]],
        "tool": "nmap",
    }


def range_port_scan(
    host: str, port_range: str, *, guard: ScopeGuard, workdir: Path, binary: str = "nmap",
    timeout: float = 330.0, host_timeout: int = 300, max_rate: int = 2000,
) -> dict[str, Any]:
    """One chunk of a full TCP sweep against a single suspicious host."""
    approved = _approved(guard, [host], "full-range inventory")
    if not approved:
        return {"hosts": [], "xml": "", "errors": [f"{host} is outside the authorised scope"], "tool": "nmap"}
    # The host is part of the name: chunks for different focus hosts run concurrently now.
    safe_host = host.replace(":", "_").replace(".", "_")
    name = f"range-{safe_host}-{port_range}"
    targets = _write_targets(approved, workdir, name)
    result = _run_nmap(
        ["-Pn", "-sT", "-p", port_range, "--max-retries", "1",
         "--host-timeout", f"{host_timeout}s", "--max-rate", str(max_rate), "-T4", "-iL", str(targets)],
        binary=binary, workdir=workdir, name=name, timeout=timeout,
    )
    return {"hosts": _approved_hosts(guard, result["hosts"]), "xml": result["xml"],
            "errors": result["errors"], "tool": "nmap", "range": port_range}


def service_versions(
    host: str, ports: list[int], *, guard: ScopeGuard, workdir: Path, binary: str = "nmap",
    timeout: float = 300.0, host_timeout: int = 240, max_rate: int = 2000,
) -> dict[str, Any]:
    """nmap service-version detection (light) on the already-open ports of one host."""
    approved = _approved(guard, [host], "service versions")
    if not approved or not ports:
        return {"hosts": [], "xml": "", "errors": [], "tool": "nmap"}
    targets = _write_targets(approved, workdir, f"versions-{host}")
    spec = ",".join(str(port) for port in ports)
    result = _run_nmap(
        ["-Pn", "-sT", "-sV", "--version-light", "-p", spec, "--max-retries", "1",
         "--host-timeout", f"{host_timeout}s", "--max-rate", str(max_rate), "-T4", "-iL", str(targets)],
        binary=binary, workdir=workdir, name=f"versions-{host}", timeout=timeout,
    )
    return {"hosts": _approved_hosts(guard, result["hosts"]), "xml": result["xml"],
            "errors": result["errors"], "tool": "nmap"}


def tcp_fallback(
    hosts: list[str], *, guard: ScopeGuard, ports: tuple[int, ...] = FALLBACK_PORTS,
    timeout_s: float = 0.8, budget_s: float = 12.0, workers: int = 16,
) -> dict[str, Any]:
    """Degraded discovery when nmap is absent: bounded TCP connects over a short list."""
    from ..surfaces.network import scan_host

    approved = _approved(guard, hosts, "tcp fallback discovery")

    def probe(ip: str) -> dict[str, Any]:
        try:
            guard.require(ip, purpose="tcp fallback discovery")
        except ScopeViolation:
            return {"ip": ip, "up": False, "ports": [], "closed": 0, "filtered": 0, "timed_out": False}
        result = scan_host(ip, list(ports), timeout_s=timeout_s, budget_s=budget_s)
        return {
            "ip": ip, "up": bool(result["reachable"]),
            "ports": [{"port": s["port"], "proto": "tcp", "name": s["name"], "product": None,
                       "version": None, "extrainfo": None} for s in result["services"]],
            "closed": 0, "filtered": 0, "timed_out": False,
        }

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(probe, approved))
    return {"hosts": results, "xml": "", "errors": [], "tool": "tcp-connect-fallback"}


def _approved_hosts(guard: ScopeGuard, hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """nmap reports only hosts it was given, but never trust that: re-check every address."""
    approved_ips = set(guard.filter([host["ip"] for host in hosts], purpose="nmap result address"))
    return [host for host in hosts if host["ip"] in approved_ips]


def _ip_key(ip: str) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(ip)
