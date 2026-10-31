"""Single-command entry point (design §8.4). No prompts, no interactive input.

Exit codes: 0 success, 2 usage/manifest error, 3 preflight refused the run.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .assessment import (
    DEFAULT_PORTS, MAX_HOSTS, AssessmentError, parse_ports, run_assessment,
)
from .policy import PolicyError, remove_in_namespace
from .agents import RunContext, default_registry
from .agents.preflight import PreflightError
from .config import ConfigError, load_manifest, manifest_hash
from .dedup import task as task_dedup_key
from .models import Event, ScopeManifest, TaskRecord, utcnow
from .scheduler import Scheduler
from .scope import CompiledScope, ScopeError, compile_scope
from .store import Store

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_REFUSED = 3


def _new_run_id() -> str:
    return f"run-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"


def _event(run_id: str, type: str, payload: dict, ptes_phase: str = "pre_engagement") -> Event:
    return Event(
        id=f"ev-{secrets.token_hex(8)}",
        run_id=run_id,
        agent="orchestrator",
        type=type,
        payload=payload,
        ptes_phase=ptes_phase,  # type: ignore[arg-type]
    )


def _match_binaries(base: Path, patterns: list[str]) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for pattern in patterns:
        for path in sorted(base.glob(pattern)):
            if path.is_file():
                found.append({"path": str(path), "size": path.stat().st_size})
    return found


def _load(scope_path: str) -> tuple[ScopeManifest, bytes, CompiledScope]:
    manifest, raw = load_manifest(Path(scope_path).resolve())
    return manifest, raw, compile_scope(manifest)


def cmd_preflight(args: argparse.Namespace) -> int:
    manifest, raw, scope = _load(args.scope)
    binaries = _match_binaries(Path(args.scope).resolve().parent, manifest.scope.binaries)
    print(
        json.dumps(
            {
                "engagement": manifest.engagement.name,
                "tier": manifest.engagement.tier,
                "window": manifest.engagement.window,
                "scope_hash": scope.scope_hash,
                "manifest_sha256": manifest_hash(raw),
                "allowlist": [str(net) for net in scope.allowlist],
                "exclude": [str(net) for net in scope.exclude],
                "block_ipv6": scope.block_ipv6,
                "allow_public": scope.allow_public,
                "dns_resolver": scope.dns_resolver,
                "binaries": binaries,
                "enforcement_required": "installed (root + nft) for any target-facing worker",
            },
            indent=2,
        )
    )
    return EXIT_OK


def cmd_scope_show(args: argparse.Namespace) -> int:
    manifest, _, scope = _load(args.scope)
    print(f"engagement    {manifest.engagement.name} ({manifest.engagement.tier})")
    print(f"window        {manifest.engagement.window}")
    print(f"scope_hash    {scope.scope_hash}")
    for net in scope.allowlist:
        print(f"allow         {net}")
    for net in scope.exclude:
        print(f"exclude       {net}")
    print(f"ipv6          {'blocked' if scope.block_ipv6 else 'per range'}")
    print(f"allow_public  {scope.allow_public}")
    print(f"dns_resolver  {scope.dns_resolver or 'none'}")
    if args.classify:
        for literal in args.classify:
            print(f"classify      {literal} -> {scope.classify(literal)}")
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    """Local dashboard and API (loopback only); ``gui`` is kept as an alias."""
    import uvicorn

    from .web import create_app

    if not 1 <= args.port <= 65535:
        print("cannot start the dashboard: port must be between 1 and 65535", file=sys.stderr)
        return EXIT_USAGE
    app = create_app(
        out_dir=Path(args.out), scope_path=Path(args.scope).resolve() if args.scope else None, port=args.port,
    )
    host = getattr(args, "host", "127.0.0.1")
    if host not in ("127.0.0.1", "0.0.0.0"):
        print("cannot start the dashboard: --host must be 127.0.0.1 or 0.0.0.0", file=sys.stderr)
        return EXIT_USAGE
    print(f"MITIGATA dashboard: http://127.0.0.1:{args.port}/   (Ctrl+C to stop)", flush=True)
    if host == "0.0.0.0":
        print("warning: bound on all container interfaces; publish the port to 127.0.0.1 on the host only", flush=True)
    uvicorn.run(app, host=host, port=args.port, log_level="warning", access_log=False)
    return EXIT_OK


def cmd_hunt(args: argparse.Namespace) -> int:
    """One command: scope guard, discovery, web/network/binary agents, verification, attack path and report."""
    from .pipeline import HuntOptions, HuntRefused, run_hunt

    options = HuntOptions(
        scope_path=Path(args.scope),
        out_dir=Path(args.out),
        binaries=list(args.binaries),
        focus=list(args.focus),
        top_ports=args.top_ports,
        ports=args.ports,
        full_scan=not args.no_full_scan,
        deadline_seconds=args.deadline_seconds,
        max_pages=args.max_pages,
        workers=args.workers,
        rate_limit_pps=args.rate,
        include_flags=True if args.include_flags else None,
        auth_hosts=list(args.auth_hosts),
    )
    try:
        summary = run_hunt(options)
    except HuntRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    print(json.dumps(summary, indent=2, default=str))
    status = summary.get("status")
    if status == "complete":
        return EXIT_OK
    return 4 if status == "partial" else 1


def cmd_discover(args: argparse.Namespace) -> int:
    """Phase 1: alive hosts and their top ports. Prints the run id and the hosts to choose from."""
    from .pipeline import HuntOptions, HuntRefused
    from .pipeline.orchestrator import run_discovery

    options = HuntOptions(scope_path=Path(args.scope), out_dir=Path(args.out), top_ports=args.top_ports,
                          deadline_seconds=args.deadline_seconds, workers=args.workers)
    try:
        summary = run_discovery(options)
    except HuntRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    print(json.dumps(summary, indent=2, default=str))
    return EXIT_OK if summary.get("status") == "discovered" else 1


def cmd_target(args: argparse.Namespace) -> int:
    """Phase 2: scan one IP chosen from a discovery run (nmap, crawl, fuzz, binaries, credential tests)."""
    from .pipeline import HuntOptions, HuntRefused
    from .pipeline.orchestrator import run_target

    options = HuntOptions(
        scope_path=Path(args.scope), out_dir=Path(args.out), run_id=args.run, focus=[args.ip],
        deadline_seconds=args.deadline_seconds, max_pages=args.max_pages, fuzz=not args.no_fuzz,
        external_tools=not args.no_external, workers=args.workers, full_scan=not args.no_sweep,
        ports=args.ports, auth_hosts=list(args.auth_hosts),
        include_flags=True if args.include_flags else None,
    )
    try:
        summary = run_target(options)
    except HuntRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    print(json.dumps(summary, indent=2, default=str))
    status = summary.get("status")
    if status == "complete":
        return EXIT_OK
    return 4 if status == "partial" else 1


def cmd_tools(args: argparse.Namespace) -> int:
    """Which external tools are installed, and what runs without them."""
    from .pipeline.tools import detect

    for row in detect():
        state = "installed" if row["installed"] else "missing"
        print(f"{row['key']:<9} {state:<10} {row['path'] or '-'}")
        if not row["installed"]:
            print(f"          fallback: {row['fallback']}")
            print(f"          install:  {row['install_hint']}")
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    manifest_path = Path(args.scope).resolve()
    manifest, raw, scope = load_manifest_checked(manifest_path)
    registry = default_registry()
    ports = parse_ports(args.ports)
    if not 1 <= args.max_hosts <= MAX_HOSTS or not 1 <= args.max_pages <= 20 or not 1 <= args.workers <= 8:
        raise ValueError("--max-hosts must be 1–1024, --max-pages 1–20, and --workers 1–8")

    if args.profile == "enforce" and not args.netns:
        raise ValueError("--netns is required with --profile enforce; refusing to run target-facing workers")
    if args.profile == "no-target" and args.netns:
        raise ValueError("--netns is illegal with --profile no-target; no target traffic is permitted")

    run_id = _new_run_id()
    run_dir = Path(args.out).resolve() / run_id
    evidence_dir = run_dir / "evidence"
    run_dir.mkdir(parents=True, exist_ok=False)
    evidence_dir.mkdir()
    shutil.copy2(manifest_path, run_dir / "scope.manifest.yaml")

    store = Store(run_dir / "blackboard.db")
    enforcement = "installed_in_namespace" if args.profile == "enforce" else "not_required_no_workers"
    store.create_run(
        run_id,
        engagement=manifest.engagement.name,
        tier=manifest.engagement.tier,
        scope_hash=scope.scope_hash,
        manifest_sha256=manifest_hash(raw),
        enforcement=enforcement,
    )
    store.add_event(
        _event(
            run_id,
            "run.started",
            {
                "tier": manifest.engagement.tier,
                "profile": args.profile,
                "scope_hash": scope.scope_hash,
                "deadline_seconds": args.deadline_seconds,
            },
        )
    )

    ctx = RunContext(
        run_id=run_id,
        scope=scope,
        store=store,
        out_dir=run_dir,
        evidence_dir=evidence_dir,
        profile=args.profile,
        deadline=time.monotonic() + args.deadline_seconds,
    )
    scheduler = Scheduler(ctx, registry)

    binaries = list(args.binaries) if args.binaries else list(manifest.scope.binaries)
    store.schedule(
        TaskRecord(
            id=f"task-{secrets.token_hex(6)}",
            run_id=run_id,
            agent="preflight-agent",
            kind="preflight",
            payload={
                "manifest_path": str(manifest_path),
                "manifest_sha256": manifest_hash(raw),
                "profile": args.profile,
                "control_ips": list(args.control_ip),
                "worker_netns": args.netns,
                "binaries": binaries,
            },
            priority=100.0,
            min_seconds=1.0,
            dedup_key=task_dedup_key(run_id, "preflight"),
        )
    )

    try:
        asyncio.run(scheduler.drain())
    except PreflightError as exc:
        store.add_event(_event(run_id, "run.refused", {"reason": str(exc)[:500]}))
        store.finish_run(run_id, "refused")
        store.close()
        print(f"preflight refused the run: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    if "done" not in store.task_counts(run_id):
        store.finish_run(run_id, "failed")
        store.close()
        print("preflight did not complete; no report written", file=sys.stderr)
        return EXIT_REFUSED

    assessment = None
    if args.profile == "enforce" or args.analyze_binaries:
        try:
            assessment = run_assessment(
                store, run_id, scope, evidence_dir,
                namespace=args.netns if args.profile == "enforce" else None,
                ports=ports, max_hosts=args.max_hosts, max_pages=args.max_pages,
                max_workers=args.workers, deadline=ctx.deadline,
                analyze_binaries=True,
            )
        except (AssessmentError, PolicyError, OSError, ValueError) as exc:
            assessment = {"errors": [str(exc)[:300]], "hosts_scanned": 0}
            store.add_event(_event(run_id, "assessment.failed", assessment, "vulnerability_analysis"))
        finally:
            if args.profile == "enforce" and args.netns:
                try:
                    remove_in_namespace(scope, args.netns)
                except PolicyError as exc:
                    if assessment is None:
                        assessment = {"errors": [], "hosts_scanned": 0}
                    assessment.setdefault("errors", []).append(str(exc)[:300])
                    store.add_event(_event(
                        run_id, "policy.cleanup_failed", {"reason": str(exc)[:300]}, "post_exploitation",
                    ))

    store.add_event(_event(run_id, "run.finalizing", {"reason": "assessment_complete"}))
    finished_at = utcnow()
    incomplete = bool(assessment and (
        assessment.get("errors") or assessment.get("host_cap_reached")
        or (args.profile == "no-target" and args.analyze_binaries)
    ))
    planned_status = "partial" if incomplete or store.task_counts(run_id).get("failed") else "complete"
    store.schedule(
        TaskRecord(
            id=f"task-{secrets.token_hex(6)}",
            run_id=run_id,
            agent="reporter-agent",
            kind="report",
            payload={
                "formats": list(manifest.report.formats),
                "status": planned_status,
                "finished_at": finished_at,
            },
            priority=1.0,
            min_seconds=0.1,
            dedup_key=task_dedup_key(run_id, "report"),
            ptes_phase="reporting",
        )
    )
    asyncio.run(scheduler.drain())

    counts = store.task_counts(run_id)
    status = planned_status if counts.get("done", 0) >= 2 else "failed"
    store.finish_run(run_id, status, finished_at=finished_at)
    summary = {
        "run_id": run_id,
        "status": status,
        "scope_hash": scope.scope_hash,
        "enforcement": enforcement,
        "blackboard": str(store.path),
        "reports": sorted(str(path) for path in run_dir.glob("report.*")),
        "tasks": counts,
    }
    store.close()
    print(json.dumps(summary, indent=2))
    return EXIT_OK if status == "complete" else 4


def load_manifest_checked(path: Path) -> tuple[ScopeManifest, bytes, CompiledScope]:
    manifest, raw = load_manifest(path)
    return manifest, raw, compile_scope(manifest)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mitigata", description="scope-enforced pentest engine")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="execute a run and write the report")
    run.add_argument("--scope", required=True, help="scope manifest (YAML)")
    run.add_argument("--out", default="runs", help="run output directory (default: runs)")
    run.add_argument(
        "--profile",
        choices=("enforce", "no-target"),
        default="enforce",
        help="enforce: install nftables egress policy (root); no-target: only for builds with no target-routed worker",
    )
    run.add_argument("--binaries", action="append", default=[], help="extra binary glob(s), relative to the manifest")
    run.add_argument("--netns", help="pre-configured named network namespace; required for target-facing runs")
    run.add_argument("--ports", default=DEFAULT_PORTS, help="TCP ports/ranges (default: curated common ports)")
    run.add_argument("--max-hosts", type=int, default=256, help="hard host cap (1–1024; report untested remainder)")
    run.add_argument("--max-pages", type=int, default=20, help="pages per web origin (1–20)")
    run.add_argument("--workers", type=int, default=8, help="parallel scan workers (1–8)")
    run.add_argument("--analyze-binaries", action="store_true",
                     help="run offline static analysis with --profile no-target")
    run.add_argument("--control-ip", action="append", default=[], help="orchestrator control-channel IP allowed by policy")
    run.add_argument("--deadline-seconds", type=float, default=1200.0, help="wall-clock budget for the run")
    run.set_defaults(func=cmd_run)

    pre = sub.add_parser("preflight", help="validate scope and inventory without sending traffic")
    pre.add_argument("--scope", required=True)
    pre.set_defaults(func=cmd_preflight)

    hunt = sub.add_parser(
        "hunt",
        help="one-command pipeline: discovery, web/network/binary agents, verification, attack path and report",
    )
    hunt.add_argument("--scope", required=True, help="scope manifest (YAML); must hold an open authorisation window")
    hunt.add_argument("--out", default="runs", help="run output directory (default: runs)")
    hunt.add_argument("--binaries", action="append", default=[],
                      help="binary glob(s) relative to the manifest directory (added to scope.binaries)")
    hunt.add_argument("--focus", action="append", default=[],
                      help="suspicious host(s) to scan across all 65,535 TCP ports (repeatable)")
    hunt.add_argument("--top-ports", type=int, default=1000, help="TCP ports checked on every live host (default: 1000)")
    hunt.add_argument("--ports", help="explicit TCP ports/ranges for live hosts (overrides --top-ports)")
    hunt.add_argument("--no-full-scan", action="store_true", help="do not run the full-range scan on focus hosts")
    hunt.add_argument("--deadline-seconds", type=float, default=1200.0,
                      help="wall-clock budget for the whole run (default: 1200 = 20 minutes)")
    hunt.add_argument("--max-pages", type=int, default=20, help="GET requests per web origin (1-20)")
    hunt.add_argument("--workers", type=int, default=8, help="parallel service agents (3-16)")
    hunt.add_argument("--rate", type=int, default=None, help="probe rate cap in packets/s (default: manifest limit, max 2000)")
    hunt.add_argument("--include-flags", action="store_true", help="private copy: write captured flag values to the report")
    hunt.add_argument("--auth-hosts", action="append", default=[],
                      help="hosts that may receive credential attempts (default: the focus host(s) only)")
    hunt.set_defaults(func=cmd_hunt)

    discover = sub.add_parser("discover", help="phase 1: alive hosts on the range and their top ports")
    discover.add_argument("--scope", required=True, help="scope manifest (YAML)")
    discover.add_argument("--out", default="runs", help="run output directory (default: runs)")
    discover.add_argument("--top-ports", type=int, default=100, help="TCP ports checked on each alive host (default: 100)")
    discover.add_argument("--deadline-seconds", type=float, default=600.0, help="wall-clock budget (default: 600)")
    discover.add_argument("--workers", type=int, default=8, help="parallel workers (3-16)")
    discover.set_defaults(func=cmd_discover)

    target = sub.add_parser(
        "target", help="phase 2: nmap (all ports), crawl, fuzz, binary analysis and credential tests on one IP",
    )
    target.add_argument("--scope", required=True, help="scope manifest (YAML)")
    target.add_argument("--out", default="runs", help="run output directory (default: runs)")
    target.add_argument("--run", required=True, help="run id of a discovery run")
    target.add_argument("--ip", required=True, help="the IP to scan (must be in scope)")
    target.add_argument("--deadline-seconds", type=float, default=1500.0, help="wall-clock budget (default: 1500)")
    target.add_argument("--max-pages", type=int, default=20, help="pages per crawl pass (1-20)")
    target.add_argument("--no-fuzz", action="store_true", help="skip endpoint fuzzing")
    target.add_argument("--no-external", action="store_true", help="use the built-in crawler and fuzzer even if katana/ffuf are installed")
    target.add_argument("--no-sweep", action="store_true", help="skip the 65,535-port sweep (use ports from earlier scans)")
    target.add_argument("--ports", help="explicit TCP ports/ranges to scan on the focus host (works with --no-sweep)")
    target.add_argument("--auth-hosts", action="append", default=[],
                        help="extra hosts allowed to receive credential tests (default: the focus IP)")
    target.add_argument("--workers", type=int, default=8, help="parallel workers (3-16)")
    target.add_argument("--include-flags", action="store_true", help="private copy: write captured flag values")
    target.set_defaults(func=cmd_target)

    tools_cmd = sub.add_parser("tools", help="show which external tools are installed")
    tools_cmd.set_defaults(func=cmd_tools)

    serve = sub.add_parser("serve", help="local dashboard and API for runs and hunts (127.0.0.1 only)")
    serve.add_argument("--scope", help="scope manifest (YAML) used to start hunts from the dashboard")
    serve.add_argument("--out", default="runs", help="run output directory (default: runs)")
    serve.add_argument("--port", type=int, default=8765, help="localhost port (default: 8765)")
    serve.add_argument("--host", default="127.0.0.1",
                       help="bind address: 127.0.0.1 (default) or 0.0.0.0 inside a container whose port is published "
                            "to the host's loopback only")
    serve.set_defaults(func=cmd_serve)

    gui = sub.add_parser("gui", help="alias of 'serve' (kept for existing scripts)")
    gui.add_argument("--scope", help="scope manifest (YAML) used to start hunts from the dashboard")
    gui.add_argument("--out", default="runs", help="run output directory (default: runs)")
    gui.add_argument("--port", type=int, default=8765, help="localhost port (default: 8765)")
    gui.set_defaults(func=cmd_serve)

    scope = sub.add_parser("scope", help="inspect the compiled scope")
    scope_sub = scope.add_subparsers(dest="scope_command", required=True)
    show = scope_sub.add_parser("show", help="print the compiled allowlist and hash")
    show.add_argument("--scope", required=True)
    show.add_argument("--classify", action="append", default=[], help="classify an IP/hostname literal")
    show.set_defaults(func=cmd_scope_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ConfigError, ScopeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
