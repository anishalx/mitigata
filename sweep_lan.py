#!/usr/bin/env python3
"""Print only the reachable hosts in a range, using the engine's network worker.

``--scope`` + ``--out`` additionally record a run (blackboard + report) so the
local GUI lists it; that run is stamped ``host_direct_unenforced`` because no
namespace or egress policy was installed.

Examples
--------
    .venv/bin/python sweep_lan.py --range 192.168.60.1-254
    .venv/bin/python sweep_lan.py --range 192.168.60.1-254 \
        --scope scope-lan.yaml --out runs
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mitigata import discovery  # noqa: E402
from mitigata.assessment import DEFAULT_PORTS, parse_ports  # noqa: E402
from mitigata.config import ConfigError, load_manifest, manifest_hash  # noqa: E402
from mitigata.scope import ScopeError, compile_scope  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print only the reachable hosts in a range")
    parser.add_argument("--range", default="192.168.60.1-254",
                        help="CIDR, A.B.C.N-M, or a single IP (expands to its /24)")
    parser.add_argument("--ports", default=DEFAULT_PORTS, help="TCP ports/ranges (default: curated list)")
    parser.add_argument("--workers", type=int, default=32, help="parallel host probes (1-256)")
    parser.add_argument("--timeout", type=float, default=0.35, help="per-port timeout in seconds")
    parser.add_argument("--budget", type=float, default=15.0, help="per-host budget in seconds")
    parser.add_argument("--scope", help="manifest used to authorise and record the run")
    parser.add_argument("--out", default="runs", help="run directory when --scope is given")
    args = parser.parse_args(argv)

    if not 1 <= args.workers <= 256:
        raise SystemExit("--workers must be 1-256")
    try:
        hosts = discovery.parse_range(args.range)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    manifest = scope = raw = None
    if args.scope:
        try:
            manifest, raw = load_manifest(Path(args.scope))
            scope = compile_scope(manifest)
        except (ConfigError, ScopeError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        start, end = manifest.engagement.window_bounds
        if not start <= datetime.now(UTC) <= end:
            print(f"error: engagement window {manifest.engagement.window} is closed; refusing to scan", file=sys.stderr)
            return 2
        in_scope = discovery.filter_scope(scope, hosts)
        if not in_scope:
            print("error: requested range has no addresses inside the authorised scope", file=sys.stderr)
            return 2
        if len(in_scope) != len(hosts):
            print(f"skipping {len(hosts) - len(in_scope)} addresses outside the authorised scope", file=sys.stderr)
        hosts = in_scope
    if len(hosts) > discovery.MAX_HOSTS:
        print(f"error: range has {len(hosts)} addresses; the limit is {discovery.MAX_HOSTS}", file=sys.stderr)
        return 2

    started = time.monotonic()
    results = []
    alive = 0
    for result in discovery.iterate(hosts, ports, workers=args.workers, timeout_s=args.timeout, budget_s=args.budget):
        results.append(result)
        if result["reachable"]:
            alive += 1
            ports_text = ", ".join(f"{service['port']}/{service.get('name', 'tcp')}" for service in result["services"])
            print(f"{result['ip']:<15} {ports_text or '-'}", flush=True)
    print(
        f"alive: {alive} / {len(results)} in {time.monotonic() - started:.1f}s (ports: {len(ports)}, timeout: {args.timeout}s)",
        file=sys.stderr,
    )

    if not (args.scope and manifest and scope and raw is not None):
        return 0

    store = None
    try:
        run_id, store, run_dir = discovery.create_run(Path(args.out), manifest, scope, manifest_hash(raw))
        errors: list[str] = []
        for result in results:
            info = discovery.record_result(store, run_id, result, ports)
            if result.get("errors"):
                errors.append(f"{info['ip']}: {len(result['errors'])} port checks were uncertain")
        status = discovery.finalize(
            store, run_id, run_dir, manifest, planned=len(results), scanned=len(results),
            ports=ports, errors=errors, timeout_s=args.timeout, workers=args.workers,
        )
    except (ConfigError, ScopeError, ValueError, OSError) as exc:
        print(f"error: run not recorded: {exc}", file=sys.stderr)
        return 2
    finally:
        if store is not None:
            store.close()
    print(f"recorded run {run_id} ({status}) in {run_dir}", file=sys.stderr)
    return 4 if status == "partial" else 0


if __name__ == "__main__":
    raise SystemExit(main())
