"""Bounded TCP connect checks against one explicitly supplied numeric IP address."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import math
import socket
import time


_SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    80: "http",
    139: "smb",
    443: "https",
    445: "smb",
    3000: "http",
    3306: "mysql",
    5000: "http",
    5432: "postgres",
    6379: "redis",
    8000: "http",
    8008: "http",
    8080: "http",
    8443: "https",
    8888: "http",
    9443: "https",
}
_DEFAULT_BUDGET_S = 30.0
_MAX_SECONDS = 86400.0


def _positive_seconds(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be positive and at most {_MAX_SECONDS:g} seconds")
    try:
        seconds = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be positive and at most {_MAX_SECONDS:g} seconds") from exc
    if not math.isfinite(seconds) or not 0 < seconds <= _MAX_SECONDS:
        raise ValueError(f"{name} must be positive and at most {_MAX_SECONDS:g} seconds")
    return seconds


def scan_host(
    ip: str,
    ports: list[int],
    *,
    timeout_s: float = 1.5,
    budget_s: float = _DEFAULT_BUDGET_S,
    stop_on_response: bool = False,
) -> dict:
    """Report TCP responses, optionally stopping after the first live indication.

    Each connect is capped by ``timeout_s`` and the entire host by ``budget_s``.
    No DNS lookups, protocol probes, or requests are performed. A refusal/reset
    establishes reachability but does not establish an open service.
    """
    if not isinstance(ip, str) or "%" in ip:
        raise ValueError("ip must be a numeric IPv4 or IPv6 address without a zone ID")
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError("ip must be a numeric IPv4 or IPv6 address") from exc
    if not isinstance(ports, list) or any(
        type(port) is not int or not 1 <= port <= 65535 for port in ports
    ):
        raise ValueError("ports must be a list of integers between 1 and 65535")
    timeout = _positive_seconds(timeout_s, "timeout_s")
    budget = _positive_seconds(budget_s, "budget_s")

    result: dict = {"ip": ip, "reachable": False, "services": [], "errors": []}
    deadline = time.monotonic() + budget
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    numeric_ip = str(address)
    for index, port in enumerate(ports):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result["errors"].append(f"host budget exhausted; {len(ports) - index} ports not scanned")
            break
        destination = (numeric_ip, port) if family == socket.AF_INET else (numeric_ip, port, 0, 0)
        try:
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(min(timeout, remaining))
                connection.connect(destination)
        except TimeoutError:
            result["errors"].append(f"tcp/{port}: connection timed out")
        except OSError as exc:
            # A refusal/reset proves that an IP stack answered even though the port is closed.
            if exc.errno in {errno.ECONNREFUSED, errno.ECONNRESET}:
                result["reachable"] = True
                if stop_on_response:
                    break
            else:
                result["errors"].append(f"tcp/{port}: {exc.strerror or type(exc).__name__}")
        else:
            result["reachable"] = True
            result["services"].append(
                {"port": port, "proto": "tcp", "name": _SERVICE_NAMES.get(port, "tcp")}
            )
            if stop_on_response:
                break
    return result


class _JSONArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _JSONArgumentParser(description="Check TCP ports on one numeric IP address")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--ports", required=True, help="Comma-separated TCP port numbers")
    parser.add_argument("--timeout", type=float, default=1.5, help="Per-port timeout in seconds")
    parser.add_argument("--budget", type=float, default=_DEFAULT_BUDGET_S, help="Host budget in seconds")
    args = None
    try:
        args = parser.parse_args(argv)
        raw_ports = args.ports.split(",")
        if not raw_ports or any(not value.isascii() or not value.isdecimal() for value in raw_ports):
            raise ValueError("ports must be comma-separated decimal integers between 1 and 65535")
        ports = [int(value) for value in raw_ports]
        result = scan_host(args.ip, ports, timeout_s=args.timeout, budget_s=args.budget)
    except ValueError as exc:
        print(json.dumps({"ip": args.ip if args is not None else None, "services": [], "errors": [str(exc)]}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
