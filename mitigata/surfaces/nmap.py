"""Nmap connect-scan adapter: normalized service records plus the raw XML.

Used by the local GUI (host-direct, unenforced) and by tests. Nothing here
interprets the result as a vulnerability; product/version strings are stored so
later agents can reason over them.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ..tools.runner import run

NMAP_TIMEOUT_S = 960.0
FULL_TCP_PORTS = 65_535
STATE_OPEN = "open"


def available(binary: str = "nmap") -> bool:
    return shutil.which(binary) is not None


def build_command(
    binary: str, ip: str, ports: list[int] | None, xml_path: Path, *, max_rate_pps: int = 1000,
) -> list[str]:
    return [
        binary, "-n", "-Pn", "-sT", "-sV", "--version-light",
        "--host-timeout", "900s", "--max-rate", str(max_rate_pps),
        "-p", ",".join(map(str, ports)) if ports is not None else "1-65535",
        "-oX", str(xml_path), "-oN", "/dev/null", ip,
    ]


def parse_xml(xml_text: str, fallback_ip: str = "") -> dict[str, Any]:
    """Normalize the first host element in an nmap XML document."""
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        raise ValueError("nmap XML contained no host element")
    address = next(
        (node.get("addr") for node in host.findall("address")
         if node.get("addrtype") in ("ipv4", "ipv6") and node.get("addr")),
        fallback_ip,
    )
    status = host.find("status")
    reachable = status is not None and status.get("state") == "up"
    services: list[dict[str, Any]] = []
    closed_ports = 0
    filtered_ports = 0
    ports_element = host.find("ports")
    if ports_element is not None:
        for extra in ports_element.findall("extraports"):
            try:
                count = int(extra.get("count", "0"))
            except ValueError:
                continue
            if extra.get("state") == "closed":
                closed_ports += count
            elif extra.get("state") == "filtered":
                filtered_ports += count
        for port in ports_element.findall("port"):
            state = port.find("state")
            if state is None:
                continue
            if state.get("state") == "closed":
                closed_ports += 1
                continue
            if state.get("state") == "filtered":
                filtered_ports += 1
                continue
            if state.get("state") != STATE_OPEN:
                continue
            service = port.find("service")
            services.append({
                "port": int(port.get("portid", "0")),
                "proto": port.get("protocol", "tcp"),
                "name": (service.get("name") if service is not None else None) or "tcp",
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None,
                "extrainfo": service.get("extrainfo") if service is not None else None,
            })
    scaninfo = root.find("scaninfo")
    finished = root.find("runstats/finished")
    errors = []
    if finished is not None and finished.get("exit") == "error":
        errors.append(finished.get("errormsg") or "nmap stopped before completing the scan")
    return {
        "ip": address,
        "reachable": reachable,
        "services": services,
        "closed_ports": closed_ports,
        "filtered_ports": filtered_ports,
        "ports_scanned": int(scaninfo.get("numservices", "0")) if scaninfo is not None else 0,
        "errors": errors,
    }


def scan_nmap(
    ip: str, ports: list[int] | None = None, *, binary: str = "nmap",
    timeout_s: float = NMAP_TIMEOUT_S, max_rate_pps: int = 1000,
) -> tuple[dict[str, Any], str]:
    """Run nmap against one numeric address; return ``(result, xml_text)``."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError("ip must be a numeric IPv4 or IPv6 address") from exc
    if getattr(address, "scope_id", None) is not None:
        raise ValueError("IPv6 zone identifiers are not accepted")
    if ports is not None and (
        not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
    ):
        raise ValueError("ports must be a non-empty list of integers between 1 and 65535")
    if type(max_rate_pps) is not int or max_rate_pps < 1:
        raise ValueError("max_rate_pps must be a positive integer")

    result: dict[str, Any] = {
        "ip": str(address), "scanner": "nmap", "reachable": False,
        "services": [], "closed_ports": 0, "filtered_ports": 0,
        "ports_scanned": 0, "errors": [],
    }
    if not available(binary):
        result["errors"].append(f"nmap binary not found: {binary}")
        return result, ""

    with tempfile.TemporaryDirectory(prefix="mitigata-nmap-") as tmp:
        xml_path = Path(tmp) / "scan.xml"
        completed = run(
            build_command(binary, str(address), ports, xml_path, max_rate_pps=max_rate_pps),
            timeout=timeout_s,
        )
        if completed.timed_out:
            result["errors"].append("nmap timed out")
            return result, ""
        xml_text = xml_path.read_text(encoding="utf-8", errors="replace") if xml_path.is_file() else ""
        if not xml_text:
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            tail = detail[-1] if detail else f"exit {completed.returncode}"
            result["errors"].append(f"nmap produced no XML: {tail[:200]}")
            return result, ""
    try:
        parsed = parse_xml(xml_text, str(address))
    except (ET.ParseError, ValueError) as exc:
        result["errors"].append(f"invalid nmap XML: {exc}")
        return result, xml_text
    result.update(parsed)
    if completed.returncode != 0 and not result["errors"]:
        result["errors"].append(f"nmap exited with status {completed.returncode}")
    if result["ports_scanned"] == 0:
        result["ports_scanned"] = len(ports) if ports is not None else FULL_TCP_PORTS
    result["scanner"] = "nmap"
    return result, xml_text


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Nmap connect scan for one numeric address")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--ports", required=True, help="Comma-separated TCP ports")
    parser.add_argument("--binary", default="nmap")
    args = parser.parse_args(argv)
    try:
        ports = [int(value) for value in args.ports.split(",") if value.strip()]
        result, xml_text = scan_nmap(args.ip, ports, binary=args.binary)
    except ValueError as exc:
        print(json.dumps({"errors": [str(exc)]}))
        return 2
    summary = dict(result)
    summary["xml_bytes"] = len(xml_text.encode())
    print(json.dumps(summary))
    return 0 if not result["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
