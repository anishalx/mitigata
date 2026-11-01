"""Orchestrator (diagram stage 2): one command, one run, every agent through the blackboard.

Stages, each tagged with its PTES phase:

1. scope guard   (pre_engagement)          validate window, scope and focus hosts; queue binaries
2. discovery     (intelligence_gathering)  nmap host discovery, top-port inventory, full-range chunks
3. services      (intelligence_gathering)  passive banner or single GET per port; web crawl; leads
4. binaries      (vulnerability_analysis)  static triage of supplied and downloaded ELF/PE artifacts
5. verification  (exploitation)            controlled checks: CANDIDATE -> CONFIRMED / REJECTED / INCONCLUSIVE
6. report        (threat_modeling, reporting)  attack path (NetworkX), Markdown/HTML/JSON report

Only this thread writes to the blackboard. Worker threads return plain results,
and every network call passes the scope guard first. The run deadline is
enforced here: work that cannot finish inside its budget is recorded as a gap.
"""

from __future__ import annotations

import glob
from fnmatch import fnmatchcase
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import queue
import ssl
import threading
import time
from collections import Counter, deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from concurrent.futures import TimeoutError as FuturesTimeout
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar

from ..assessment import DEFAULT_PORTS, allowed_hosts, parse_ports
from ..discovery import filter_scope
from ..config import load_manifest, manifest_hash
from ..dedup import candidate as candidate_key
from ..models import CoverageRow, Event, ScopeManifest, TaskRecord, utcnow
from ..scope import CompiledScope, compile_scope
from ..store import Store
from ..tools.runner import terminate_active
from . import binary_agent, net_agent, planner, report, scanner, solver, tools, verifier, web_agent
from .guard import ScopeGuard, ScopeViolation

ENFORCEMENT = "host_guard_in_process"
MAX_BINARIES = 4
MAX_DOWNLOADS_PER_SERVICE = 3
MAX_LITERALS_PER_BINARY = 12
SERVICE_SHARE = 0.82
VERIFY_SHARE = 0.93
DISCOVERY_SHARE = 0.35
FULL_RANGE_SHARE = 0.80
FULL_RANGE_WORKERS = 4
FULL_RANGE_CHUNK_SECONDS = 240.0
FULL_RANGE_HOST_TIMEOUT = 210
FULL_RANGE_VERSIONS_SECONDS = 300.0
FULL_RANGE_MIN_SECONDS = 30.0
HEARTBEAT_SECONDS = 30.0
TLS_PORTS = frozenset({443, 8443, 9443})
TLS_NAMES = frozenset({"https", "ssl/http", "https-alt", "ssl"})
VERIFY_ORDER = {
    "default_credentials": 0, "passkey_protocol_auth": 1, "raw_html_reflection": 2, "exposed_path": 3,
    "information_disclosure_banner": 4, "hardcoded_secret": 5, "static_unsafe_function": 6,
    "trusted_header_bypass": 7,
}
LEAD_PHASE = {
    "default_credentials": "vulnerability_analysis",
    "passkey_protocol_auth": "vulnerability_analysis",
    "raw_html_reflection": "vulnerability_analysis",
    "exposed_path": "intelligence_gathering",
    "information_disclosure_banner": "intelligence_gathering",
}


RETRY_DELAY_S = 20.0
#: Seconds kept back from the deadline for analysis and the report, so a slow tool cannot starve them.
ANALYSIS_RESERVE_S = 60.0
MIN_GHIDRA_SECONDS = 45.0
GHIDRA_TIMEOUT_S = 900.0
R2_TIMEOUT_S = 240.0
MIN_RADARE_SECONDS = 20.0
SOLVER_TIMEOUT_S = 240.0
#: Follow-up probes are bounded: total steps, chain depth, and the time kept back before the deadline.
MAX_FOLLOWUPS = 40
MAX_FOLLOWUP_DEPTH = 3
FOLLOWUP_RESERVE_S = 30.0
#: RFC 5737 documentation address: never a trusted proxy, so it is the control value of the header test.
UNTRUSTED_CONTROL_VALUE = "203.0.113.7"
#: The kind of task that a task of this kind follows, for the dashboard's discovery chain.
TASK_PARENT_KIND = {"inventory_ports": "discover_hosts", "identify_service": "inventory_ports"}
T = TypeVar("T")


def _with_retry(attempt: Callable[[], T], *, failed: Callable[[T], bool], retry: bool, delay: float) -> T:
    """Run ``attempt`` once; if it failed and ``retry`` is set, pause and try once more."""
    result = attempt()
    if retry and failed(result):
        time.sleep(delay)
        result = attempt()
    return result


class HuntRefused(RuntimeError):
    """The run must not start: the window is closed or a focus host is out of scope."""


def check_permitted(checks: Any, name: str) -> bool:
    """Apply manifest check-pack patterns; exclusions override inclusions."""
    return (not checks.include or any(fnmatchcase(name, pattern) for pattern in checks.include)) and not any(
        fnmatchcase(name, pattern) for pattern in checks.exclude
    )


@dataclass
class HuntOptions:
    scope_path: Path
    out_dir: Path
    binaries: list[str] = field(default_factory=list)
    focus: list[str] = field(default_factory=list)
    top_ports: int = 1000
    ports: str | None = None
    full_scan: bool = True
    deadline_seconds: float = 1200.0
    max_hosts: int = 256
    max_pages: int = 20
    workers: int = 8
    nmap_binary: str = "nmap"
    rate_limit_pps: int | None = None
    include_flags: bool | None = None
    on_created: Callable[[str], None] | None = None
    #: Hosts that may receive credential attempts. Defaults to the focus host(s).
    auth_hosts: list[str] = field(default_factory=list)
    #: hunt (one shot) | discover (alive hosts only) | target (one IP inside an existing run)
    mode: str = "hunt"
    run_id: str | None = None
    fuzz: bool = True
    external_tools: bool = True
    #: Addresses the user chose for discovery (already checked against the manifest). Empty means the manifest scope.
    targets: list[str] = field(default_factory=list)


def _prepare(options: HuntOptions) -> tuple[Path, ScopeManifest, bytes, CompiledScope, ScopeGuard]:
    scope_path = Path(options.scope_path).resolve()
    manifest, raw = load_manifest(scope_path)
    if not check_permitted(manifest.checks, "network.inventory"):
        raise HuntRefused("the manifest does not permit network.inventory; nothing was sent")
    scope = compile_scope(manifest)
    start, end = manifest.engagement.window_bounds
    if not start <= datetime.now(UTC) <= end:
        raise HuntRefused(f"authorisation window {manifest.engagement.window} is closed; nothing was sent")
    guard = ScopeGuard(scope, http_interval=1.0 / max(1, manifest.limits.max_http_rps_per_host))
    for focus in options.focus:
        if not guard.permits(focus):
            raise HuntRefused(f"focus host {focus} is outside the authorised scope; nothing was sent")
    for host in options.auth_hosts:
        if not guard.permits(host):
            raise HuntRefused(f"auth host {host} is outside the authorised scope; nothing was sent")
    if options.ports:
        parse_ports(options.ports)
    if not 60.0 <= options.deadline_seconds <= 7200.0:
        raise HuntRefused("deadline must be between 60 and 7200 seconds")
    return scope_path, manifest, raw, scope, guard


def run_hunt(options: HuntOptions) -> dict[str, Any]:
    """One-shot pipeline for the given focus hosts: discovery, services, binaries, verification and report."""
    options.mode = "hunt"
    scope_path, manifest, raw, scope, guard = _prepare(options)
    return _Hunt(options, scope_path, manifest, raw, scope, guard).execute()


def run_discovery(options: HuntOptions) -> dict[str, Any]:
    """Phase 1: alive hosts on the range and their top ports. The run stops as ``discovered``."""
    options.mode = "discover"
    options.focus = []
    scope_path, manifest, raw, scope, guard = _prepare(options)
    return _Hunt(options, scope_path, manifest, raw, scope, guard).execute()


def run_target(options: HuntOptions) -> dict[str, Any]:
    """Phase 2: the chosen IP gets nmap (all ports, then versions), crawl, fuzzing, binary analysis with
    radare2, literal extraction and credential tests, recorded in the same run."""
    if not options.run_id:
        raise HuntRefused("a target scan needs the run id of a discovery run")
    if len(options.focus) != 1:
        raise HuntRefused("choose exactly one target IP")
    options.mode = "target"
    options.auth_hosts = list(dict.fromkeys([*options.focus, *options.auth_hosts]))
    scope_path, manifest, raw, scope, guard = _prepare(options)
    return _Hunt(options, scope_path, manifest, raw, scope, guard).execute()


def _merge_web(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    for key in ("endpoints", "forms", "auth_challenges", "candidates", "errors", "binary_links"):
        base[key] = base[key] + [item for item in extra[key] if item not in base[key]]
    known = {item["value"] for item in base["literals"]}
    base["literals"] = base["literals"] + [item for item in extra["literals"] if item["value"] not in known]
    base["pages"] = base["pages"] + extra["pages"]
    base["server"] = base["server"] or extra["server"]
    base["cookies"] = base["cookies"] or extra["cookies"]
    return base


class _Hunt:
    def __init__(
        self, options: HuntOptions, scope_path: Path, manifest: ScopeManifest, raw: bytes,
        scope: CompiledScope, guard: ScopeGuard,
    ) -> None:
        self.opt = options
        self.scope_path = scope_path
        self.manifest = manifest
        self.scope = scope
        self.guard = guard
        self.started = time.monotonic()
        self.deadline = self.started + options.deadline_seconds
        self.started_at = utcnow()
        self.mode = options.mode
        self.resuming = bool(options.run_id)
        if self.resuming:
            self.run_id = str(options.run_id)
            self.run_dir = Path(options.out_dir).resolve() / self.run_id
            database = self.run_dir / "blackboard.db"
            if not database.is_file():
                raise HuntRefused(f"run {self.run_id} does not exist under {options.out_dir}")
            self.store = Store(database)
            try:
                row = self.store.get_run(self.run_id)
            except KeyError as exc:
                self.store.close()
                raise HuntRefused(f"run {self.run_id} has no run record") from exc
            if row["scope_hash"] != scope.scope_hash or row["manifest_sha256"] != manifest_hash(raw):
                self.store.close()
                raise HuntRefused("the manifest changed since this run was created; start a new discovery")
        else:
            self.run_id = f"run-{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"
            self.run_dir = Path(options.out_dir).resolve() / self.run_id
            self.run_dir.mkdir(parents=True, exist_ok=False)
        self.evidence_dir = self.run_dir / "evidence"
        self.scans_dir = self.run_dir / "scans"
        self.quarantine = self.evidence_dir / "binaries"
        self.downloads = self.evidence_dir / "downloads"
        for directory in (self.evidence_dir, self.scans_dir, self.quarantine, self.downloads,
                          self.evidence_dir / "nmap"):
            directory.mkdir(parents=True, exist_ok=True)
        if not self.resuming:
            shutil.copy2(scope_path, self.run_dir / "scope.manifest.yaml")
            self.store = Store(self.run_dir / "blackboard.db")
            self.store.create_run(
                self.run_id, engagement=manifest.engagement.name, tier=manifest.engagement.tier,
                scope_hash=scope.scope_hash, manifest_sha256=manifest_hash(raw), enforcement=ENFORCEMENT,
                started_at=self.started_at, pid=os.getpid(),
            )
        self.pool = ThreadPoolExecutor(max_workers=max(3, options.workers), thread_name_prefix="mitigata")
        self.secrets: dict[str, str] = {}
        self.literal_refs: list[str] = []
        self.literal_meta: dict[str, dict[str, Any]] = {}
        self.stages: list[dict[str, Any]] = []
        self.gaps: list[str] = []
        self.limitations: list[str] = []
        self.errors: list[str] = []
        self.counts: Counter[str] = Counter()
        self.open_services: dict[tuple[str, int], dict[str, Any]] = {}
        self.asset_ids: dict[str, int] = {}
        self.live: list[str] = []
        self.hosts_all: list[str] = []
        self.chunk_queue: queue.Queue = queue.Queue()
        self.chunk_pool: ThreadPoolExecutor | None = None
        self.chunk_futures: list[Future] = []
        #: Follow-up probes that earlier results name (hints, header trust), run after the service stage.
        self.followups: deque[dict[str, Any]] = deque()
        self.followups_run = 0
        self.header_probes_done: set[tuple[str, int, str]] = set()
        #: Lineage: the latest task of each kind, and the identify task of each service (for the dashboard chain).
        self.last_task_by_kind: dict[str, str] = {}
        self.service_task_ids: dict[tuple[str, int], str] = {}
        #: Optional planner (DeepSeek). None unless the manifest enables it and the key is in the environment.
        self.planner, self.planner_reason = planner.build_planner(self.manifest.llm)
        self.llm_calls = 0
        #: Probes already sent, so the same GET is never repeated for the same headers.
        self.probed: set[tuple[str, int, str, tuple[str, ...]]] = set()
        if self.manifest.llm.enabled and self.planner is None:
            self.gaps.append(f"LLM planner not started: {self.planner_reason}")
        self.versions_futures: dict[str, Future] = {}
        self.pending_chunks: dict[str, int] = {}
        self.full_open_ports: dict[str, set[int]] = {}
        self.versions_started: set[str] = set()
        self.versions_enabled = False
        self.sweep_end_at = 0.0
        self.sweep_rate = 1
        self.pending_services: dict[Future, tuple[tuple[str, int], str]] = {}
        self.full_done: list[str] = []
        self.binary_futures: list[tuple[Future, str, str]] = []
        self.nmap_ok = scanner.nmap_available(options.nmap_binary)
        self.tool = "nmap" if self.nmap_ok else "tcp-connect-fallback"
        manifest_rate = max(1, min(manifest.limits.max_rate_pps, 2000))
        self.rate = max(1, min(manifest_rate, options.rate_limit_pps)) if options.rate_limit_pps is not None else manifest_rate
        self.auth_budget = verifier.AttemptBudget(
            cap=manifest.limits.max_auth_attempts_per_account, enabled=manifest.checks.auth_tests,
        )
        self.flag_patterns = [re.compile(pattern) for pattern in manifest.flags.patterns]
        self.include_flags = manifest.report.include_flags if options.include_flags is None else options.include_flags
        self.summary: dict[str, Any] = {}
        self.flag_values_seen: set[str] = set()
        self.auth_hosts = set(options.focus) | set(options.auth_hosts)
        self.web_enabled = check_permitted(manifest.checks, "web.inventory")
        self.binary_enabled = check_permitted(manifest.checks, "binary.triage")
        self.fuzz_enabled = bool(options.fuzz) and check_permitted(manifest.checks, "web.fuzz") and self.web_enabled
        if self.mode != "discover":
            if not self.web_enabled:
                self.gaps.append("web inventory is disabled by the manifest checks (web.inventory)")
            elif self.opt.fuzz and not self.fuzz_enabled:
                self.gaps.append("endpoint fuzzing was requested but the manifest excludes web.fuzz")
            if not self.binary_enabled:
                self.gaps.append("binary triage is disabled by the manifest checks (binary.triage)")
        self.external_tools = bool(options.external_tools)
        self.http_rps = max(1, manifest.limits.max_http_rps_per_host)
        self.tools_info = tools.detect()
        self.tools_used: set[str] = set()
        if self.resuming:
            self._load_resumed_state()
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="mitigata-heartbeat", daemon=True,
        )
        self._heartbeat_thread.start()
        if options.on_created is not None:
            options.on_created(self.run_id)

    # -- plumbing -------------------------------------------------------------
    def _heartbeat_loop(self) -> None:
        """Keep the run visibly alive even while a long nmap subprocess blocks the main thread."""
        while not self._heartbeat_stop.wait(HEARTBEAT_SECONDS):
            try:
                with Store(self.store.path) as beat:
                    beat.heartbeat_run(self.run_id, pid=os.getpid())
            except Exception:  # noqa: BLE001 - a missed heartbeat must never kill the scan
                continue

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def share_end(self, share: float) -> float:
        return self.started + share * self.opt.deadline_seconds

    def _scrub(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Defence in depth: no recovered literal may ever reach the blackboard as plain text."""
        text = json.dumps(payload, sort_keys=True, default=str)
        for value in self.secrets.values():
            text = text.replace(value, "<redacted>")
        return json.loads(text)

    def _scrub_store(self) -> int:
        """Replace recovered values in every text column, including rows written before a value was known."""
        if not self.secrets:
            return 0
        changed = 0
        tables = [row[0] for row in self.store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        with self.store._tx() as conn:
            for table in tables:
                columns = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")
                           if (row[2] or "").upper() in ("TEXT", "")]
                for column in columns:
                    for value in self.secrets.values():
                        cursor = conn.execute(
                            f"UPDATE {table} SET {column} = replace({column}, ?, '<redacted>') "
                            f"WHERE instr({column}, ?) > 0", (value, value))
                        changed += cursor.rowcount
        return changed

    def _mask_flags(self, value: Any) -> Any:
        """Captured flag values never reach the blackboard unless the private copy was requested."""
        if isinstance(value, str):
            for flag in self.flag_values_seen:
                value = value.replace(flag, flag[:5] + "…")
            return value
        if isinstance(value, dict):
            return {key: self._mask_flags(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._mask_flags(item) for item in value]
        return value

    def event(self, agent: str, kind: str, payload: dict[str, Any], phase: str = "intelligence_gathering") -> None:
        self.store.add_event(Event(
            id=f"ev-{secrets.token_hex(8)}", run_id=self.run_id, agent=agent, type=kind,
            payload=self._scrub(payload), ptes_phase=phase,  # type: ignore[arg-type]
        ))

    def _task(self, agent: str, kind: str, payload: dict[str, Any], phase: str, parent: str | None = None) -> str:
        task_id = f"task-{secrets.token_hex(8)}"
        if parent is None:  # network stages chain to the stage before them without threading ids through every call
            parent = self.last_task_by_kind.get(TASK_PARENT_KIND.get(kind, ""))
        self.last_task_by_kind[kind] = task_id
        self.store.schedule(TaskRecord(
            id=task_id, run_id=self.run_id, agent=agent, kind=kind,
            payload=self._scrub(payload), priority=50.0,
            dedup_key=candidate_key(self.run_id, None, None, None, f"task:{kind}", task_id),
            ptes_phase=phase,  # type: ignore[arg-type]
            parent_task_id=parent,
        ))
        self.store.start_task(task_id)
        return task_id

    def _finish(self, task_id: str, ok: bool = True, state: str | None = None) -> None:
        self.store.complete(task_id, state or ("done" if ok else "failed"))

    def _asset(self, ip: str) -> int:
        if ip not in self.asset_ids:
            self.asset_ids[ip] = self.store.upsert_asset(self.run_id, ip, source="discovery")
        return self.asset_ids[ip]

    @contextmanager
    def stage(self, name: str, phase: str) -> Iterator[None]:
        began = time.monotonic()
        self.event("orchestrator", "stage.started", {"stage": name}, phase)
        try:
            yield
        finally:
            seconds = round(time.monotonic() - began, 1)
            self.stages.append({"name": name, "ptes_phase": phase, "seconds": seconds})
            self.event("orchestrator", "stage.finished", {"stage": name, "seconds": seconds}, phase)
            self.guard.flush(self.store, self.run_id)

    def _keep_xml(self, xml_text: str, name: str) -> None:
        if not xml_text:
            return
        path = self.evidence_dir / "nmap" / f"{name}.xml"
        path.write_text(xml_text, encoding="utf-8")
        self.store.add_evidence(
            self.run_id, type="nmap_xml", candidate_id=None, ptes_phase="intelligence_gathering",
            path=str(path), sha256=hashlib.sha256(xml_text.encode()).hexdigest(), payload={"scan": name},
        )

    # -- execution ------------------------------------------------------------
    def execute(self) -> dict[str, Any]:
        try:
            if self.mode == "discover":
                self.event("orchestrator", "run.started", {
                    "mode": "discover", "engagement": self.manifest.engagement.name,
                    "tier": self.manifest.engagement.tier, "window": self.manifest.engagement.window,
                    "scope_hash": self.scope.scope_hash, "tool": self.tool, "rate_pps": self.rate,
                    "deadline_seconds": self.opt.deadline_seconds, "tools": self.tools_info,
                    "auth_tests": self.manifest.checks.auth_tests, "enforcement": ENFORCEMENT,
                }, "pre_engagement")
                self.stage_scope()
                self.stage_discovery()
                self.finish_discovery()
            elif self.mode == "target":
                self.store.resume_run(self.run_id, pid=os.getpid())
                self.event("orchestrator", "target.started", {
                    "mode": "target", "ip": self.opt.focus[0], "tool": self.tool,
                    "rate_pps": max(1, self.rate // 2), "deadline_seconds": self.opt.deadline_seconds,
                    "fuzz": self.fuzz_enabled, "external_tools": self.external_tools, "tools": self.tools_info,
                    "auth_tests": self.manifest.checks.auth_tests, "enforcement": ENFORCEMENT,
                }, "pre_engagement")
                self._queue_binaries()
                self.stage_target()
                self.stage_services()
                self.stage_followups()
                self.stage_binaries()
                self.stage_verification(only_ips=set(self.auth_hosts))
                self.stage_report()
            else:
                self.event("orchestrator", "run.started", {
                    "mode": "hunt", "engagement": self.manifest.engagement.name,
                    "tier": self.manifest.engagement.tier, "window": self.manifest.engagement.window,
                    "scope_hash": self.scope.scope_hash, "tool": self.tool, "rate_pps": self.rate,
                    "deadline_seconds": self.opt.deadline_seconds, "tools": self.tools_info,
                    "auth_tests": self.manifest.checks.auth_tests, "enforcement": ENFORCEMENT,
                }, "pre_engagement")
                self.stage_scope()
                self.stage_discovery()
                self.stage_services()
                self.stage_followups()
                self.stage_binaries()
                self.stage_verification()
                self.stage_report()
        except KeyboardInterrupt:
            self.errors.append("the run was interrupted (SIGINT) and finalized as interrupted")
            try:
                self.event("orchestrator", "run.interrupted", {"reason": "SIGINT"}, "reporting")
            except Exception:  # noqa: BLE001 - finalization must not depend on an event write
                pass
            self.store.finish_run(self.run_id, "interrupted", finished_at=utcnow())
            self.summary = {"run_id": self.run_id, "status": "interrupted", "errors": self.errors,
                            "run_dir": str(self.run_dir)}
        except Exception as exc:  # noqa: BLE001 - the run must end with a recorded reason
            self.errors.append(f"{type(exc).__name__}: {str(exc)[:240]}")
            self.event("orchestrator", "run.failed", {"error": self.errors[-1]}, "reporting")
            self.store.finish_run(self.run_id, "failed", finished_at=utcnow())
            self.summary = {"run_id": self.run_id, "status": "failed", "errors": self.errors,
                            "run_dir": str(self.run_dir)}
        finally:
            self._heartbeat_stop.set()
            self._heartbeat_thread.join(timeout=2.0)
            terminate_active()
            if self.chunk_pool is not None:
                self.chunk_pool.shutdown(wait=False, cancel_futures=True)
            self.pool.shutdown(wait=False, cancel_futures=True)
            terminate_active()
            self.guard.flush(self.store, self.run_id)
            self.store.close()
        return self.summary

    def stage_scope(self) -> None:
        with self.stage("scope-guard", "pre_engagement"):
            if self.opt.targets:  # the user's range, checked against the manifest before the run started
                self.hosts_all = filter_scope(self.scope, self.opt.targets)
                truncated = False
            else:
                self.hosts_all, truncated = allowed_hosts(self.scope, self.opt.max_hosts)
            if truncated:
                self.gaps.append(f"host cap {self.opt.max_hosts} reached; addresses beyond it were not discovered")
            self.event("scope-guard", "scope.validated", {
                "allowlist": [str(net) for net in self.scope.allowlist],
                "exclude": [str(net) for net in self.scope.exclude],
                "hosts_in_scope": len(self.hosts_all), "focus": list(self.opt.focus),
                "window": self.manifest.engagement.window, "auth_tests": self.manifest.checks.auth_tests,
                "max_auth_attempts_per_account": self.manifest.limits.max_auth_attempts_per_account,
                "rate_pps": self.rate, "enforcement": ENFORCEMENT,
            }, "pre_engagement")
            if self.mode != "discover":
                self._queue_binaries()

    def _queue_binaries(self) -> None:
        paths = self._binary_paths() if self.binary_enabled else []
        if self.binary_enabled and not paths:
            patterns = list(self.manifest.scope.binaries) + list(self.opt.binaries)
            if patterns:
                self.gaps.append(
                    f"binary patterns {', '.join(patterns)} matched no files; static binary analysis was skipped"
                )
        self.event("binary-agent", "binary.queued", {
            "count": len(paths), "names": [path.name for path in paths[:MAX_BINARIES]],
        }, "vulnerability_analysis")
        if len(paths) > MAX_BINARIES:
            self.event("orchestrator", "binary.deferred", {"count": len(paths) - MAX_BINARIES,
                                                           "reason": "max_artifacts"}, "vulnerability_analysis")
        for path in paths[:MAX_BINARIES]:
            task_id = self._task("binary-agent", "triage_binary", {"name": path.name}, "vulnerability_analysis")
            self.binary_futures.append((self.pool.submit(self._triage_one, path), f"scope:{path.name}", task_id))

    def _binary_paths(self) -> list[Path]:
        base = self.scope_path.parent
        patterns = list(self.manifest.scope.binaries) + list(self.opt.binaries)
        found: list[Path] = []
        for pattern in patterns:
            for match in sorted(glob.glob(os.path.join(base, pattern))):
                path = Path(match)
                if path.is_file() and path not in found:
                    found.append(path)
        return found

    def _triage_one(self, path: Path) -> dict[str, Any]:
        return binary_agent.triage(path, self.quarantine)

    # 2. discovery
    def stage_discovery(self) -> None:
        if self.nmap_ok:
            self.tools_used.add("nmap")
        budget = max(30.0, self.share_end(DISCOVERY_SHARE) - time.monotonic())
        with self.stage("host-discovery", "intelligence_gathering"):
            task = self._task("discovery-agent", "discover_hosts", {"targets": len(self.hosts_all), "tool": self.tool},
                              "intelligence_gathering")
            if self.nmap_ok:
                result = scanner.host_discovery(self.hosts_all, guard=self.guard, workdir=self.scans_dir,
                                                binary=self.opt.nmap_binary, timeout=budget * 0.8, max_rate=self.rate)
                self.live = list(result["live"])
                self._keep_xml(result["xml"], "host-discovery")
            else:
                self.limitations.append("nmap is not installed: discovery degraded to TCP connect over a short port list")
                result = scanner.tcp_fallback(self.hosts_all, guard=self.guard)
                self.live = [host["ip"] for host in result["hosts"] if host["up"]]
            self.errors.extend(result["errors"])
            for ip in self.live:
                self._asset(ip)
                self.counts["hosts_live"] += 1
                self.event("discovery-agent", "host.discovered", {"ip": ip}, "intelligence_gathering")
                self.store.upsert_coverage(CoverageRow(
                    run_id=self.run_id, asset_id=self._asset(ip), attack_class="network.host_discovery",
                    state="tested", reason=f"answered {self.tool} discovery probes"))
            self._finish(task, ok=not result["errors"])

        focus = list(dict.fromkeys(self.opt.focus))
        if focus and self.opt.full_scan and self.nmap_ok:
            for ip in focus:
                self._asset(ip)
            self.event("orchestrator", "full_range.started", {
                "hosts": focus, "chunks": list(scanner.FULL_RANGE_CHUNKS), "rate_pps": max(1, self.rate // 2),
                "workers": FULL_RANGE_WORKERS,
            }, "intelligence_gathering")
            self._start_full_range(focus)
        elif focus and not self.opt.full_scan:
            self.gaps.append("full-range scan disabled for this run")
        elif focus and not self.nmap_ok:
            self.gaps.append("full-range scan skipped because nmap is not installed")

        with self.stage("port-inventory", "intelligence_gathering"):
            if not self.live:
                self.gaps.append("no live host answered discovery, so no port inventory was run")
            else:
                ports_label = self.opt.ports or f"top {self.opt.top_ports} TCP ports"
                task = self._task("network-agent", "inventory_ports", {"hosts": len(self.live), "ports": ports_label},
                                  "intelligence_gathering")
                budget = max(30.0, self.share_end(SERVICE_SHARE) - time.monotonic() - 60)
                if self.nmap_ok:
                    inventory = scanner.top_port_scan(
                        self.live, guard=self.guard, workdir=self.scans_dir, binary=self.opt.nmap_binary,
                        top_ports=self.opt.top_ports, port_spec=self.opt.ports, timeout=budget,
                        host_timeout=int(min(240, budget)), max_rate=max(1, self.rate // 6),
                    )
                    rows = inventory["hosts"]
                    for number, xml_text in enumerate(inventory["xmls"]):
                        self._keep_xml(xml_text, f"port-inventory-{number}")
                else:
                    ports = tuple(parse_ports(self.opt.ports or DEFAULT_PORTS))
                    inventory = scanner.tcp_fallback(self.live, guard=self.guard, ports=ports)
                    rows = inventory["hosts"]
                self.errors.extend(inventory["errors"])
                for host in rows:
                    self._asset(host["ip"])
                    for port in host["ports"]:
                        self._open_service(host["ip"], port, source=self.tool)
                for ip in self.live:
                    self.store.upsert_coverage(CoverageRow(
                        run_id=self.run_id, asset_id=self._asset(ip), attack_class="network.port_inventory",
                        state="tested", reason=f"{ports_label} checked from the host network; no UDP claim"))
                self._finish(task, ok=not inventory["errors"])

    def _load_resumed_state(self) -> None:
        secrets_file = self.run_dir / "secrets.json"
        if secrets_file.is_file():
            loaded = json.loads(secrets_file.read_text(encoding="utf-8"))
            self.secrets = {str(key): str(value) for key, value in loaded.items()}
            self.literal_refs = sorted(self.secrets, key=lambda ref: int(ref.split("-", 1)[1]))
        meta_file = self.run_dir / "literals.json"
        if meta_file.is_file():
            self.literal_meta = json.loads(meta_file.read_text(encoding="utf-8"))
        for row in self.store.conn.execute("SELECT id, ip FROM assets WHERE run_id=?", (self.run_id,)):
            self.asset_ids[str(row["ip"])] = int(row["id"])
        self.live = list(self.asset_ids)
        if self.mode == "target":
            # The focus host is always scanned; extra auth hosts reuse the services the
            # discovery run already found, so credentials can be tested there too.
            hosts = sorted(self.auth_hosts)
            if hosts:
                placeholders = ",".join("?" for _ in hosts)
                rows = self.store.conn.execute(
                    "SELECT a.ip, s.id, s.asset_id, s.port, s.name FROM services s"
                    " JOIN assets a ON a.id = s.asset_id"
                    f" WHERE s.run_id=? AND a.ip IN ({placeholders})",
                    (self.run_id, *hosts),
                ).fetchall()
                for row in rows:
                    ip = str(row["ip"])
                    number = int(row["port"])
                    name = str(row["name"] or "tcp")
                    self.open_services[(ip, number)] = {
                        "asset_id": int(row["asset_id"]), "service_id": int(row["id"]), "name": name,
                        "tls_hint": number in TLS_PORTS or name in TLS_NAMES, "submitted": False,
                    }

    def stage_target(self) -> None:
        ip = self.opt.focus[0]
        self._asset(ip)
        self.event("discovery-agent", "target.selected", {"ip": ip, "alive_in_discovery": ip in self.live},
                   "intelligence_gathering")
        if self.opt.ports:
            if not self.nmap_ok:
                self.gaps.append("the explicit port list needs nmap, which is not installed")
            else:
                budget = self.remaining() - 10.0
                if budget < 10.0:
                    self.gaps.append("the explicit port scan was skipped because the run deadline is too close")
                else:
                    with self.stage("explicit-port-scan", "intelligence_gathering"):
                        timeout = min(180.0, budget)
                        try:
                            result = scanner.range_port_scan(
                                ip, self.opt.ports, guard=self.guard, workdir=self.scans_dir,
                                binary=self.opt.nmap_binary, timeout=timeout,
                                host_timeout=int(min(120, timeout)), max_rate=self.rate,
                            )
                        except Exception as exc:  # noqa: BLE001 - recorded as a gap, not a failed run
                            self.gaps.append(f"explicit port scan failed: {type(exc).__name__}")
                        else:
                            self.tools_used.add("nmap")
                            self._keep_xml(result["xml"], f"explicit-{ip}")
                            self.errors.extend(result["errors"])
                            opened = 0
                            for host in result["hosts"]:
                                for port in host["ports"]:
                                    if self._open_service(host["ip"], port, source="explicit"):
                                        opened += 1
                            self.event("discovery-agent", "explicit_ports.completed", {
                                "ip": ip, "new_open_ports": opened, "errors": len(result["errors"]),
                                "ports": self.opt.ports,
                            }, "intelligence_gathering")
        if not self.opt.full_scan:
            self.gaps.append("full-range sweep skipped for this run (--no-sweep); ports known from earlier scans only")
            return
        if not self.nmap_ok:
            self.gaps.append("full-range scan skipped because nmap is not installed")
            return
        self.event("discovery-agent", "full_range.started", {
            "ip": ip, "chunks": list(scanner.FULL_RANGE_CHUNKS), "rate_pps": max(1, self.rate // 2),
            "versions": True, "workers": FULL_RANGE_WORKERS,
        }, "intelligence_gathering")
        self._start_full_range([ip], rate=max(1, self.rate // 2), versions=True)

    def finish_discovery(self) -> str:
        open_by_ip = dict(self.store.conn.execute(
            "SELECT a.ip, COUNT(s.id) FROM assets a LEFT JOIN services s"
            " ON s.asset_id = a.id AND s.run_id = a.run_id WHERE a.run_id=? GROUP BY a.ip", (self.run_id,),
        ).fetchall())
        alive = [{"ip": ip, "open_ports": int(open_by_ip.get(ip, 0))}
                 for ip in sorted(self.live, key=lambda value: tuple(int(part) for part in value.split(".")))]
        self.event("orchestrator", "discovery.completed", {
            "alive_hosts": len(alive), "open_ports": int(self.counts["open_ports"]), "hosts": alive[:300],
        }, "intelligence_gathering")
        self.store.finish_run(self.run_id, "discovered", finished_at=utcnow())
        self.summary = {"run_id": self.run_id, "status": "discovered", "alive_hosts": alive,
                        "run_dir": str(self.run_dir), "tools": self._tools_report()}
        return "discovered"

    def _tools_report(self) -> list[dict[str, Any]]:
        rows = []
        for item in self.tools_info:
            used = item["key"] in self.tools_used
            if used:
                note = "used in this run"
            elif item["installed"]:
                note = "installed, not used in this run"
            else:
                note = f"not installed; {item['fallback']}"
            rows.append({"key": item["key"], "installed": item["installed"], "used": used,
                         "wired": item["wired"], "note": note})
        return rows

    def _fuzz(self, ip: str, port: int, tls: bool, origin: str) -> list[dict[str, Any]]:
        remaining = self.share_end(SERVICE_SHARE) - time.monotonic() - 20.0
        if remaining <= 0:
            self.gaps.append(f"endpoint discovery on {ip}:{port} skipped because the service budget ended")
            return []
        if self.external_tools and tools.find("ffuf") is not None:
            try:
                self.guard.require(ip, port=port, purpose="fuzz (ffuf)")
                found = tools.ffuf_paths(origin, list(web_agent.FUZZ_WORDS), rate=self.http_rps,
                                         timeout_s=min(120.0, remaining))
                self.tools_used.add("ffuf")
                return found
            except Exception as exc:  # noqa: BLE001
                reason = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
                self.limitations.append(f"ffuf failed on {ip}:{port} ({reason}); built-in fuzzer used")
        return web_agent.fuzz(ip, port, tls=tls, guard=self.guard, words=web_agent.FUZZ_WORDS)

    def _analyze_binary(self, result: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any] | None,
                                                               dict[str, Any]]:
        """Ghidra decompilation when installed, otherwise radare2. Strings from the tool feed the literal candidates.

        Returns the literals, the analysis (or None) and an outcome record the dashboard shows: which tool ran, and
        for every failure or skip, why. Failures are recorded here rather than only in memory.
        """
        literals = list(result["literals"])
        artifact = result.get("artifact") or ""
        name = result.get("name", "a binary")
        outcome: dict[str, Any] = {"tool": None, "status": "not_run", "errors": [], "functions": 0,
                                   "decompiled_functions": 0, "strings": 0}
        if not artifact:
            outcome["status"] = "no_artifact"
            return literals, None, outcome
        analysis: dict[str, Any] | None = None
        budget = self.remaining() - ANALYSIS_RESERVE_S
        ghidra_found = tools.find("analyzeHeadless") is not None
        radare_found = tools.find("r2") is not None or tools.find("radare2") is not None
        if ghidra_found and budget < MIN_GHIDRA_SECONDS:
            outcome["errors"].append("ghidra skipped: the deadline budget is too small")
        elif ghidra_found:
            try:
                exported = tools.ghidra_analyze(Path(artifact), timeout_s=min(GHIDRA_TIMEOUT_S, budget))
                analysis = {
                    "tool": "ghidra", "decompiler": "ghidra",
                    "strings": [{"vaddr": index, "string": item["string"]}
                                for index, item in enumerate(exported["strings"])],
                    "imports": exported["imports"],
                    "functions": [item["name"] for item in exported["functions"]],
                    "main_listing": [],
                    "decompiled": "\n\n".join(f"// {item['name']}\n{item['c']}"
                                              for item in exported["decompiled"])[:12000],
                }
                outcome["decompiled_functions"] = len(exported["decompiled"])
                self.tools_used.add("ghidra")
                if radare_found:  # radare2 keeps a disassembly of main even when the Ghidra export does not
                    try:
                        analysis["main_listing"] = tools.r2_analyze(
                            Path(artifact), timeout_s=min(R2_TIMEOUT_S, max(MIN_RADARE_SECONDS, budget)))["main_listing"]
                    except Exception as exc:  # noqa: BLE001
                        outcome["errors"].append(f"radare2 listing: {type(exc).__name__}")
            except Exception as exc:  # noqa: BLE001
                outcome["errors"].append(f"ghidra: {type(exc).__name__}: {str(exc)[:160]}")
                self.limitations.append(f"Ghidra analysis failed for {name} ({type(exc).__name__}); radare2 used if installed")
        if analysis is None and radare_found:
            try:
                parsed = tools.r2_analyze(Path(artifact), timeout_s=min(R2_TIMEOUT_S, max(MIN_RADARE_SECONDS, budget)))
            except Exception as exc:  # noqa: BLE001
                outcome["errors"].append(f"radare2: {type(exc).__name__}: {str(exc)[:160]}")
                self.limitations.append(f"radare2 analysis failed for {name} ({type(exc).__name__})")
            else:
                analysis = {"tool": "radare2", "decompiler": parsed["decompiler"], "strings": parsed["strings"],
                            "imports": parsed["imports"], "functions": parsed["functions"],
                            "main_listing": parsed["main_listing"], "decompiled": parsed["decompiled"]}
                outcome["decompiled_functions"] = 1 if str(parsed["decompiled"]).strip() else 0
                self.tools_used.add("radare2")
        if analysis is None:
            if outcome["errors"]:
                outcome["status"] = "failed"
            elif not ghidra_found and not radare_found:
                outcome["status"] = "not_installed"
            else:
                outcome["status"] = "skipped_deadline"
            return literals, None, outcome
        outcome.update(tool=analysis["tool"], status="analyzed", strings=len(analysis["strings"]),
                       functions=len(analysis["functions"]))
        known = {item["value"] for item in literals}
        for literal in binary_agent.auth_literals([(int(item["vaddr"]), str(item["string"]))
                                                   for item in analysis["strings"]]):
            if literal["value"] not in known:
                known.add(literal["value"])
                literals.append(literal)
        return literals[:MAX_LITERALS_PER_BINARY], analysis, outcome

    def _solve_literal(self, result: dict[str, Any], analysis: dict[str, Any] | None) -> dict[str, Any]:
        """Offline solver for a stdout-gated input check (optional angr). A verified candidate joins the literals.

        The returned record never carries the candidate except under the "candidate" key, which the caller removes
        before anything is persisted.
        """
        if analysis is None:
            return {"status": "no_analysis"}
        length = solver.argv_length(str(analysis.get("decompiled") or ""))
        if length is None:
            length = solver.argv_length_from_listing([str(line) for line in analysis.get("main_listing") or []])
        if length is None:
            return {"status": "no_length", "reason": "no strlen equality check in the decompile or the listing"}
        success, failure = solver.stdout_markers([str(item["string"]) for item in analysis.get("strings", [])])
        if success is None or failure is None:
            return {"status": "no_markers", "reason": "no success and failure messages among the strings",
                    "length": length}
        if not solver.available():
            return {"status": "unavailable", "reason": "angr is not installed (optional solver dependency)",
                    "length": length}
        budget = min(SOLVER_TIMEOUT_S, self.remaining() - ANALYSIS_RESERVE_S)
        if budget < 30:
            return {"status": "skipped_deadline", "length": length}
        try:
            outcome = solver.solve(Path(result.get("artifact") or ""), length=length, success=success,
                                   failure=failure, timeout_s=budget)
        except Exception as exc:  # noqa: BLE001 - a solver failure is a recorded status, never a crashed run
            return {"status": "error", "reason": f"{type(exc).__name__}: {str(exc)[:120]}", "length": length}
        record = {key: value for key, value in outcome.items() if key != "candidate"}
        record["length"] = length
        if outcome.get("status") == "verified":
            record["candidate"] = outcome["candidate"]
        return record

    def _binary_details(self, result: dict[str, Any], literals: list[dict[str, Any]], outcome: dict[str, Any],
                        solver_outcome: dict[str, Any], source: str = "") -> dict[str, Any]:
        """What the dashboard shows for one binary. Literal values never appear here, only where they came from."""
        return {
            "name": result.get("name", ""),
            "source": source,
            "sources": [source],
            "protections": result.get("protections") or {},
            "unsafe_imports": list(result.get("unsafe_imports") or [])[:20],
            "literal_count": len(literals),
            "literal_sources": [{"via": item.get("via"), "keyword": item.get("keyword"),
                                 "offset": item.get("offset"), "score": item.get("score")} for item in literals],
            "analysis": outcome,
            "solver": solver_outcome,
        }

    def _open_service(self, ip: str, port: dict[str, Any], *, source: str) -> bool:
        number = int(port["port"])
        name = str(port.get("name") or "tcp")
        asset_id = self._asset(ip)
        service_id = self.store.upsert_service(
            self.run_id, asset_id, number, proto=str(port.get("proto") or "tcp"), name=name,
            product=port.get("product"), version=port.get("version"), extrainfo=port.get("extrainfo"), source=source,
        )
        key = (ip, number)
        if key in self.open_services:
            return False
        self.open_services[key] = {
            "asset_id": asset_id, "service_id": service_id, "name": name,
            "tls_hint": number in TLS_PORTS or name in TLS_NAMES, "submitted": False,
        }
        self.counts["open_ports"] += 1
        self.event("discovery-agent", "port.open", {"ip": ip, "port": number, "name": name}, "intelligence_gathering")
        return True

    # 3. services (network + web agents), run concurrently with the focus host's full-range sweep
    def _start_full_range(self, focus: list[str], *, rate: int | None = None, versions: bool = False) -> None:
        """Start the focus host(s) full TCP sweep as independent, bounded chunks.

        Chunks run on a dedicated pool so one slow nmap chunk cannot starve the
        others and the service inventory is not blocked behind a single
        65,535-port process. Workers only queue results; the orchestrator
        thread remains the only writer to the blackboard.
        """
        self.sweep_end_at = self.share_end(FULL_RANGE_SHARE)
        self.sweep_rate = rate or max(1, self.rate // 2)
        self.versions_enabled = versions
        chunks = list(scanner.FULL_RANGE_CHUNKS)
        if not chunks:
            return
        per_chunk_rate = max(1, self.sweep_rate // len(chunks))
        if self.chunk_pool is None:
            self.chunk_pool = ThreadPoolExecutor(
                max_workers=min(FULL_RANGE_WORKERS, len(chunks), max(1, self.sweep_rate)),
                thread_name_prefix="mitigata-sweep",
            )
        for ip in focus:
            self.pending_chunks[ip] = len(chunks)
            self.full_open_ports.setdefault(ip, set())
            for port_range in chunks:
                self.chunk_futures.append(
                    self.chunk_pool.submit(
                        self._run_full_chunk, ip, port_range, self.sweep_end_at, per_chunk_rate
                    )
                )

    def _run_full_chunk(self, ip: str, port_range: str, end_at: float, rate: int) -> None:
        remaining = end_at - time.monotonic()
        # Never let an orphaned nmap outlive the run's own wall-clock deadline.
        hard_remaining = self.deadline - time.monotonic() - 5.0
        if remaining < FULL_RANGE_MIN_SECONDS or hard_remaining < FULL_RANGE_MIN_SECONDS:
            self.chunk_queue.put((ip, port_range, "skipped", "the sweep budget ended before this chunk started"))
            return
        timeout = min(FULL_RANGE_CHUNK_SECONDS, remaining, hard_remaining)
        try:
            result = scanner.range_port_scan(
                ip, port_range, guard=self.guard, workdir=self.scans_dir, binary=self.opt.nmap_binary,
                timeout=timeout, host_timeout=int(min(FULL_RANGE_HOST_TIMEOUT, timeout)), max_rate=rate,
            )
        except Exception as exc:  # noqa: BLE001 - reported as a gap, never dropped silently
            self.chunk_queue.put((ip, port_range, "error", type(exc).__name__))
            return
        self.chunk_queue.put((ip, port_range, "result", result))

    def _versions_worker(self, ip: str, ports: list[int], end_at: float, rate: int) -> None:
        remaining = end_at - time.monotonic()
        hard_remaining = self.deadline - time.monotonic() - 5.0
        if remaining < FULL_RANGE_MIN_SECONDS or hard_remaining < FULL_RANGE_MIN_SECONDS:
            self.chunk_queue.put(
                (ip, "", "versions_error", "the sweep budget ended before service versions started")
            )
            return
        timeout = min(FULL_RANGE_VERSIONS_SECONDS, remaining, hard_remaining)
        try:
            found = scanner.service_versions(
                ip, ports, guard=self.guard, workdir=self.scans_dir, binary=self.opt.nmap_binary,
                timeout=timeout, host_timeout=int(min(240, timeout)), max_rate=rate,
            )
        except Exception as exc:  # noqa: BLE001
            self.chunk_queue.put((ip, "", "versions_error", f"service versions {type(exc).__name__}"))
            return
        self.chunk_queue.put((ip, "", "versions", found))

    def _maybe_start_versions(self) -> None:
        """Start one version-detection pass per host after all of that host's chunks have drained."""
        if not self.versions_enabled or self.chunk_pool is None:
            return
        for ip, remaining in list(self.pending_chunks.items()):
            if remaining > 0 or ip in self.versions_started:
                continue
            self.versions_started.add(ip)
            ports = sorted(self.full_open_ports.get(ip, set()))
            if not ports:
                continue
            self.versions_futures[ip] = self.chunk_pool.submit(
                self._versions_worker, ip, ports, self.sweep_end_at, self.sweep_rate,
            )

    def _chunk_done(self, ip: str) -> None:
        remaining = self.pending_chunks.get(ip, 0)
        if remaining > 0:
            self.pending_chunks[ip] = remaining - 1

    def _sweep_running(self) -> bool:
        if any(not future.done() for future in self.chunk_futures):
            return True
        if any(not future.done() for future in self.versions_futures.values()):
            return True
        return any(count > 0 for count in self.pending_chunks.values())

    def _drain_chunks(self, *, submit_services: bool = True) -> None:
        while True:
            try:
                ip, port_range, kind, payload = self.chunk_queue.get_nowait()
            except queue.Empty:
                return
            label = f"{ip} {port_range}".strip()
            if kind in ("skipped", "error"):
                self.gaps.append(f"full-range chunk {label} not completed: {payload}")
                if port_range:
                    self._chunk_done(ip)
                continue
            if kind == "versions_error":
                self.gaps.append(f"service versions for {ip} not completed: {payload}")
                continue
            if kind == "versions":
                self._keep_xml(payload["xml"], f"versions-{ip}")
                self.errors.extend(payload["errors"])
                for host in payload["hosts"]:
                    asset_id = self._asset(host["ip"])
                    for port in host["ports"]:
                        if port.get("product") or port.get("version"):
                            self.store.upsert_service(
                                self.run_id, asset_id, int(port["port"]), name=str(port.get("name") or "tcp"),
                                product=port.get("product"), version=port.get("version"),
                                extrainfo=port.get("extrainfo"), source="nmap-versions",
                            )
                self.tools_used.add("nmap")
                self.event("discovery-agent", "service_versions.completed", {
                    "ip": ip, "ports": sum(len(host["ports"]) for host in payload["hosts"]),
                }, "intelligence_gathering")
                continue
            self.tools_used.add("nmap")
            task_id = self._task("network-agent", "full_range_scan", {"ip": ip, "range": port_range},
                                 "intelligence_gathering")
            self._keep_xml(payload["xml"], f"range-{port_range}-{ip}")
            self.errors.extend(payload["errors"])
            opened = 0
            for host in payload["hosts"]:
                for port in host["ports"]:
                    number = int(port["port"])
                    self.full_open_ports.setdefault(ip, set()).add(number)
                    if self._open_service(host["ip"], port, source="nmap-full"):
                        opened += 1
                        if submit_services:
                            self._submit_service((host["ip"], number))
            if payload.get("xml"):
                self.full_done.append(label if not payload["errors"] else f"{label} (partial)")
            self.event("network-agent", "full_range.completed", {
                "ip": ip, "range": port_range, "new_open_ports": opened, "errors": len(payload["errors"]),
            }, "intelligence_gathering")
            self._finish(task_id, ok=not payload["errors"])
            self._chunk_done(ip)

    def _submit_service(self, key: tuple[str, int]) -> None:
        info = self.open_services.get(key)
        if info is None or info["submitted"]:
            return
        info["submitted"] = True
        task_id = self._task("network-agent", "identify_service",
                             {"ip": key[0], "port": key[1]}, "intelligence_gathering")
        self.service_task_ids[key] = task_id
        future = self.pool.submit(self._inventory_one, key[0], key[1], bool(info["tls_hint"]))
        self.pending_services[future] = (key, task_id)

    def stage_services(self) -> None:
        end_at = self.share_end(SERVICE_SHARE)
        with self.stage("service-inventory", "intelligence_gathering"):
            for key in list(self.open_services):
                self._submit_service(key)
            while True:
                self._drain_chunks()
                self._maybe_start_versions()
                if (not self.pending_services and not self._sweep_running()
                        and self.chunk_queue.empty()):
                    break
                left = end_at - time.monotonic()
                if left <= 0:
                    break
                if self.pending_services:
                    done, _ = wait(list(self.pending_services), timeout=min(1.0, left),
                                   return_when=FIRST_COMPLETED)
                else:
                    done = set()
                    time.sleep(min(1.0, left))
                for future in done:
                    key, task_id = self.pending_services.pop(future)
                    try:
                        outcome = future.result()
                    except ScopeViolation as exc:
                        self._finish(task_id, ok=False)
                        self.errors.append(f"refused {key[0]}:{key[1]}: {str(exc)[:120]}")
                        continue
                    except Exception as exc:  # noqa: BLE001
                        self._finish(task_id, ok=False)
                        self.errors.append(f"service {key[0]}:{key[1]}: {type(exc).__name__}")
                        continue
                    self._ingest_service(key, outcome)
                    self._finish(task_id, ok=True)
            self._drain_chunks(submit_services=False)
            # The deadline may have expired between the last wait() and this point: keep results
            # that are already available instead of throwing away a finished probe.
            for future in [item for item in self.pending_services if item.done()]:
                key, task_id = self.pending_services.pop(future)
                try:
                    outcome = future.result()
                except Exception as exc:  # noqa: BLE001
                    self._finish(task_id, ok=False)
                    self.errors.append(f"service {key[0]}:{key[1]}: {type(exc).__name__}")
                    continue
                self._ingest_service(key, outcome)
                self._finish(task_id, ok=True)
            for future, (key, task_id) in list(self.pending_services.items()):
                future.cancel()
                self._finish(task_id, state="skipped_deadline")
                self.gaps.append(f"service {key[0]}:{key[1]} was not inventoried inside the service budget")
            if self._sweep_running():
                self.gaps.append("the focus host's full-range sweep was still running at the service deadline; "
                                 "ports in unfinished chunks may be missing")

    def _inventory_one(self, ip: str, port: int, tls_hint: bool) -> dict[str, Any]:
        # Focus hosts get one retry: a transient failure there (for example while the sweep is running)
        # would otherwise hide a service for the whole run.
        retry = ip in self.auth_hosts
        probe = _with_retry(
            lambda: net_agent.probe_service(ip, port, guard=self.guard, tls_hint=tls_hint),
            failed=lambda found: found.kind in ("silent", "error"), retry=retry, delay=RETRY_DELAY_S,
        )
        outcome: dict[str, Any] = {"probe": probe, "web": None, "artifacts": [], "leads": [], "fuzz": []}
        if probe.kind == "http":
            if not self.web_enabled:
                return outcome
            scheme = "https" if probe.tls else "http"
            origin = f"{scheme}://{ip}:{port}"
            seeds: tuple[str, ...] = ()
            crawl_time = min(30.0, self.share_end(SERVICE_SHARE) - time.monotonic() - 20.0)
            if self.mode == "target" and self.external_tools and crawl_time > 0 and tools.find("katana") is not None:
                try:
                    self.guard.require(ip, port=port, purpose="crawl (katana)")
                    seeds = tuple(tools.katana_paths(origin + "/", origin, rate=self.http_rps,
                                                     timeout_s=crawl_time))[:60]
                    self.tools_used.add("katana")
                except Exception as exc:  # noqa: BLE001
                    reason = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
                    self.limitations.append(f"katana failed on {ip}:{port} ({reason}); built-in crawler used")
            if ip in self.auth_hosts:  # entry paths are GETs we chose, so they stay on the focus host(s)
                seeds = tuple(dict.fromkeys((*web_agent.ENTRY_PATHS, *seeds)))
            web = _with_retry(
                lambda: web_agent.inventory(
                    ip, port, tls=probe.tls, guard=self.guard, max_pages=self.opt.max_pages, seeds=seeds,
                    timeout=web_agent.CRAWL_TIMEOUT, sensitive_timeout=web_agent.DEFAULT_SENSITIVE_TIMEOUT,
                    max_sensitive_paths=web_agent.DEFAULT_MAX_SENSITIVE_PATHS,
                ),
                failed=lambda found: found["pages"] == 0, retry=retry, delay=RETRY_DELAY_S,
            )
            if self.mode == "target" and self.fuzz_enabled:
                found = self._fuzz(ip, port, probe.tls, origin)
                outcome["fuzz"] = found
                fuzz_seeds = tuple(dict.fromkeys(
                    item["path"] for item in found if item["status"] in web_agent.FUZZ_KEEP))[:25]
                if fuzz_seeds:
                    extra = web_agent.inventory(ip, port, tls=probe.tls, guard=self.guard,
                                                max_pages=len(fuzz_seeds), seeds=fuzz_seeds, include_root=False)
                    web = _merge_web(web, extra)
            outcome["web"] = web
            if self.binary_enabled:
                for link in web["binary_links"][:MAX_DOWNLOADS_PER_SERVICE]:
                    outcome["artifacts"].append((link, *self._download(ip, port, probe.tls, link)))
        elif probe.kind == "banner":
            outcome["leads"] = net_agent.banner_leads(probe)
        return outcome

    def _download(self, ip: str, port: int, tls: bool, target: str,
                  headers: dict[str, str] | None = None) -> tuple[str | None, str]:
        """Fetch a same-origin binary link under the guard; keep it only if it is ELF or PE within the cap."""
        self.guard.require(ip, port=port, purpose="artifact download")
        self.guard.pace(ip)
        connection = (
            http.client.HTTPSConnection(ip, port, timeout=8, context=ssl._create_unverified_context())
            if tls else http.client.HTTPConnection(ip, port, timeout=8)
        )
        try:
            connection.request("GET", target, headers={"User-Agent": "mitigata-hackathon/0.2", "Connection": "close",
                                                       **(headers or {})})
            response = connection.getresponse()
            if response.status != 200:
                return None, f"status {response.status}"
            declared = response.getheader("Content-Length") or ""
            if declared.isdigit() and int(declared) > binary_agent.MAX_BINARY_SIZE:
                return None, "over the 64 MiB cap"
            data = bytearray()
            while len(data) <= binary_agent.MAX_BINARY_SIZE:
                chunk = response.read(65536)
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > binary_agent.MAX_BINARY_SIZE:
                return None, "over the 64 MiB cap"
            if data[:4] != b"\x7fELF" and data[:2] != b"MZ":
                return None, "not an ELF or PE artifact"
            path = self.downloads / f"{secrets.token_hex(8)}.bin"
            path.write_bytes(bytes(data))
            return str(path), "downloaded"
        except (OSError, http.client.HTTPException, ValueError) as exc:
            return None, type(exc).__name__
        finally:
            connection.close()

    def _ingest_service(self, key: tuple[str, int], outcome: dict[str, Any]) -> None:
        ip, port = key
        info = self.open_services[key]
        probe = outcome["probe"]
        agent = "web-agent" if probe.kind == "http" else "network-agent"
        self.event(agent, "service.classified", {
            "ip": ip, "port": port, "kind": probe.kind, "status": probe.status, "tls": probe.tls,
            "detail": probe.detail,
        }, "intelligence_gathering")
        asset_id = int(info["asset_id"])
        if probe.kind in ("silent", "error"):
            self.store.upsert_coverage(CoverageRow(
                run_id=self.run_id, asset_id=asset_id, attack_class=f"network.service_probe:{port}",
                state="untested" if probe.kind == "silent" else "failed",
                reason="open port sent no banner and no HTTP response" if probe.kind == "silent"
                else f"connection error: {probe.detail}",
            ))
            return
        if probe.kind == "banner":
            self._finish(self._task("network-agent", "read_banner", {"ip": ip, "port": port}, "intelligence_gathering"))
            self.store.add_evidence(
                self.run_id, type="service_banner", candidate_id=None, ptes_phase="intelligence_gathering",
                payload={"ip": ip, "port": port, "banner_excerpt": probe.banner[:400]},
            )
            self.store.upsert_coverage(CoverageRow(
                run_id=self.run_id, asset_id=asset_id, attack_class=f"network.banner:{port}",
                state="tested", reason="passive banner read; no input was sent"))
            for lead in outcome["leads"]:
                self._add_lead(ip, port, info, lead, tls=False)
            return
        web = outcome["web"]
        self.store.upsert_coverage(CoverageRow(
            run_id=self.run_id, asset_id=asset_id, attack_class=f"network.service_probe:{port}",
            state="tested", reason=f"answered HTTP ({probe.status})"))
        if not self.web_enabled:
            self.store.upsert_coverage(CoverageRow(
                run_id=self.run_id, asset_id=asset_id, attack_class=f"web.inventory:{port}",
                state="untested", reason="web inventory is excluded by the manifest"))
            return
        crawl_task = self._task("web-agent", "crawl_origin",
                                {"ip": ip, "port": port, "pages": (web or {}).get("pages", 0)},
                                "intelligence_gathering", parent=self.service_task_ids.get(key))
        self._finish(crawl_task, ok=bool(web))
        if web and web["server"]:
            self.store.upsert_service(self.run_id, asset_id, port, name=info["name"],
                                      product=web["server"][:80], source="web-agent")
        self._ingest_web_result(ip, port, info, probe.tls, web, task_id=crawl_task, headers=None,
                                artifacts=outcome["artifacts"], depth=0, coverage_class=f"web.inventory:{port}")

    def _ingest_web_result(self, ip: str, port: int, info: dict[str, Any], tls: bool, web: dict[str, Any] | None, *,
                           task_id: str, headers: dict[str, str] | None, artifacts: list[tuple[str, str | None, str]],
                           depth: int, coverage_class: str) -> None:
        """Endpoints, leads, literals, artifacts and the next hint probes from one web result (crawl or follow-up)."""
        scheme = "https" if tls else "http"
        asset_id = int(info["asset_id"])
        for endpoint in (web or {}).get("endpoints", []):
            url = f"{scheme}://{ip}:{port}{endpoint['path']}"
            self.store.upsert_endpoint(self.run_id, int(info["service_id"]), "GET", url, url)
            self.counts["endpoints"] += 1
            self.event("web-agent", "endpoint.discovered", {
                "ip": ip, "port": port, "url": url, "status": endpoint["status"], "length": endpoint["length"],
                **({"via_header": sorted(headers)} if headers else {}),
            }, "intelligence_gathering")
        if web:
            suffix = f"; forwarded header {sorted(headers)[0]} set" if headers else ""
            self.store.upsert_coverage(CoverageRow(
                run_id=self.run_id, asset_id=asset_id, attack_class=coverage_class, state="tested",
                reason=f"{web['pages']} GET requests on {ip}:{port}; {len(web['errors'])} page errors; "
                       f"no form submitted{suffix}"))
            for lead in web["candidates"]:
                self._add_lead(ip, port, info, dict(lead), tls=tls)
            for literal in web.get("literals", []):
                self._register_web_literal(ip, port, info, literal)
        for source_link, artifact_path, reason in artifacts:
            link = source_link.split("?", 1)[0]
            if artifact_path:
                binary_task = self._task("binary-agent", "triage_binary",
                                         {"name": Path(artifact_path).name, "from": link},
                                         "vulnerability_analysis", parent=task_id)
                self.binary_futures.append((self.pool.submit(self._triage_one, Path(artifact_path)),
                                            f"web:{ip}:{port}{link}", binary_task))
                self.event("web-agent", "binary.found", {"ip": ip, "port": port, "path": link},
                           "vulnerability_analysis")
            else:
                self.event("web-agent", "binary.rejected", {"ip": ip, "port": port, "reason": reason},
                           "vulnerability_analysis")
        if web:
            selection = (self._planner_selection(ip, port, tls, web, parent=task_id)
                         if depth == 0 and headers is None else None)
            self._enqueue_hints(ip, port, tls, web, parent=task_id, depth=depth, headers=headers,
                                selection=selection)

    def _register_web_literal(self, ip: str, port: int, info: dict[str, Any], literal: dict[str, Any]) -> None:
        """A credential-like literal from readable page content: value kept privately, lead recorded."""
        source = f"web:{ip}:{port}{literal['path']}"
        ref = f"cred-{len(self.secrets) + 1}"
        self.secrets[ref] = literal["value"]
        self.literal_refs.append(ref)
        self.literal_meta[ref] = {"keyword": literal["keyword"], "score": float(literal.get("score", 0.0)),
                                  "source": "web", "user": literal.get("user")}
        self.store.add_credential(self.run_id, kind="auth_literal", secret_ref=ref, source=source,
                                  service_id=int(info["service_id"]), confidence="static")
        key = candidate_key(self.run_id, int(info["asset_id"]), int(info["service_id"]), None, "hardcoded_secret",
                            f"{source}:{literal['offset']}")
        details = {
            "class": "hardcoded_secret", "source": source, "offset": literal["offset"], "via": literal["via"],
            "keyword": literal["keyword"], "secret_ref": ref, "ip": ip, "port": port, "tls": False,
            "path": literal["path"],
        }
        candidate_id = self.store.add_candidate(
            self.run_id, dedup_key=key, vuln_class="hardcoded_secret",
            claim=(f"static authentication literal near '{literal['keyword']}' in readable content at "
                   f"{literal['path']} on {ip}:{port} (unverified)"),
            asset_id=int(info["asset_id"]), service_id=int(info["service_id"]),
            ptes_phase="vulnerability_analysis", details=self._scrub(details),
        )
        if candidate_id is not None:
            self.counts["candidates"] += 1
            self.event("web-agent", "candidate.created", {
                "candidate_id": candidate_id, "class": "hardcoded_secret",
                "target": f"{ip}:{port} {literal['path']}", "status": "candidate",
            }, "vulnerability_analysis")
        self._persist_secrets()

    def _add_lead(self, ip: str, port: int, info: dict[str, Any], lead: dict[str, Any], *, tls: bool) -> None:
        klass = str(lead["class"])
        details = dict(lead)
        details.update({"class": klass, "ip": ip, "port": port, "tls": tls, "service_id": info["service_id"]})
        discriminator = {
            "default_credentials": f"{lead.get('surface')}:{lead.get('path')}",
            "raw_html_reflection": f"{lead.get('path')}:{lead.get('parameter')}",
            "exposed_path": str(lead.get("path")),
        }.get(klass, klass)
        key = candidate_key(self.run_id, int(info["asset_id"]), int(info["service_id"]), None, klass, discriminator)
        target = str(lead.get("path") or lead.get("target") or "")
        claims = {
            "default_credentials": f"authentication surface ({lead.get('surface')}) at {target} on {ip}:{port}; default credentials not yet tested",
            "raw_html_reflection": f"parameter '{lead.get('parameter')}' appears unescaped in the HTML of {target} on {ip}:{port}; script execution not tested",
            "exposed_path": f"sensitive path {target} returned 200 on {ip}:{port}; not yet compared with a control",
            "passkey_protocol_auth": f"service on {ip}:{port} gates access behind an AUTH passkey; the passkey may be recoverable from a supplied binary",
            "information_disclosure_banner": f"pre-authentication banner on {ip}:{port} discloses the authentication protocol",
        }
        candidate_id = self.store.add_candidate(
            self.run_id, dedup_key=key, vuln_class=klass, claim=claims.get(klass, klass),
            asset_id=int(info["asset_id"]), service_id=int(info["service_id"]),
            ptes_phase=LEAD_PHASE.get(klass, "vulnerability_analysis"), details=self._scrub(details),
        )
        if candidate_id is not None:
            self.counts["candidates"] += 1
            self.event("web-agent" if klass != "passkey_protocol_auth" and klass != "information_disclosure_banner"
                       else "network-agent", "candidate.created",
                       {"candidate_id": candidate_id, "class": klass, "target": f"{ip}:{port} {target}".strip(),
                        "status": "candidate"}, LEAD_PHASE.get(klass, "vulnerability_analysis"))

    # 3b. follow-up probes: only what earlier results name, in bounded steps
    def _gateway_of(self, ip: str) -> str:
        octets = ip.split(".")
        return ".".join([*octets[:3], "1"]) if len(octets) == 4 else ip

    def _header_trust_allowed(self, ip: str) -> bool:
        section = self.manifest.checks.header_trust
        return section.enabled and ip in section.hosts and check_permitted(self.manifest.checks, "web.header_trust")

    def _planner_selection(self, ip: str, port: int, tls: bool, web: dict[str, Any], *,
                           parent: str) -> planner.Selection | None:
        """One bounded planner call per service, on the first crawl. Its picks are checked against the target's hints."""
        section = self.manifest.llm
        text = str(web.get("hint_text") or "")
        if self.planner is None or self.llm_calls >= section.max_calls or not text:
            return None
        known = {str(item["path"]) for item in web.get("endpoints", [])}
        paths = web_agent.hint_paths(text, known=known)
        names = (web_agent.hint_header_names(text) or [web_agent.KNOWN_FORWARD_HEADERS[0]])[:4]
        values = [value for value in dict.fromkeys([*web_agent.hint_ipv4(text), self._gateway_of(ip), "127.0.0.1"])
                  if value != UNTRUSTED_CONTROL_VALUE][:4]
        if not paths and not (self._header_trust_allowed(ip) and values):
            return None
        self.llm_calls += 1
        context = {"target": f"{ip}:{port}", "scheme": "https" if tls else "http",
                   "endpoints": [{"path": str(item["path"]), "status": item.get("status"),
                                  "length": item.get("length")} for item in web.get("endpoints", [])[:40]],
                   "text_excerpt": text}
        task = self._task("planner-agent", "propose_probes",
                          {"ip": ip, "port": port, "candidates": len(paths), "provider": section.provider,
                           "model": section.model}, "intelligence_gathering", parent=parent)
        try:
            selection = self.planner.select(context, candidate_paths=paths, candidate_headers=names,
                                            candidate_values=values)
        except planner.PlannerError as exc:
            self.gaps.append(f"LLM planner skipped for {ip}:{port}: {exc}")
            self._finish(task, ok=False)
            return None
        self._finish(task, ok=True)
        self.event("planner-agent", "llm.proposal", {
            "ip": ip, "port": port, "provider": section.provider, "model": section.model,
            "accepted_paths": list(selection.probe_paths),
            "accepted_header": list(selection.trusted_header) if selection.trusted_header else None,
            "rejected": list(selection.rejected), "why": selection.why,
            "sent_sha256": selection.sent_sha256, "sent_chars": selection.sent_chars,
        }, "intelligence_gathering")
        return selection

    def _enqueue_hints(self, ip: str, port: int, tls: bool, web: dict[str, Any], *, parent: str, depth: int,
                       headers: dict[str, str] | None, selection: planner.Selection | None = None) -> None:
        """Turn what the target says into bounded follow-ups: exposure paths it names, and forwarded-address tests."""
        if depth >= MAX_FOLLOWUP_DEPTH:
            return
        text = str(web.get("hint_text") or "")
        if text:
            known = {str(item["path"]) for item in web.get("endpoints", [])}
            paths = web_agent.hint_paths(text, known=known)
            if selection is not None and selection.probe_paths:  # the planner's picks go first; nothing is added
                paths = [*selection.probe_paths, *[path for path in paths if path not in selection.probe_paths]]
            if paths:
                self.followups.append({"kind": "probe_paths", "ip": ip, "port": port, "tls": tls, "paths": paths,
                                       "headers": headers, "parent": parent, "depth": depth + 1})
                self.event("web-agent", "hint.found", {"ip": ip, "port": port, "paths": paths},
                           "intelligence_gathering")
        if headers is None and self._header_trust_allowed(ip):
            names = web_agent.hint_header_names(text) or [web_agent.KNOWN_FORWARD_HEADERS[0]]
            values = [value for value in dict.fromkeys([*web_agent.hint_ipv4(text), self._gateway_of(ip), "127.0.0.1"])
                      if value != UNTRUSTED_CONTROL_VALUE]
            if selection is not None and selection.trusted_header is not None:  # the planner's header goes first
                chosen_name, chosen_value = selection.trusted_header
                names = [chosen_name, *[name for name in names if name != chosen_name]]
                values = [chosen_value, *[value for value in values if value != chosen_value]]
            self.followups.append({"kind": "header_trust", "ip": ip, "port": port, "tls": tls, "path": "/",
                                   "names": names[:4], "values": values[:4], "parent": parent, "depth": depth + 1})

    def _run_probe_paths(self, item: dict[str, Any]) -> None:
        ip, port, tls = str(item["ip"]), int(item["port"]), bool(item["tls"])
        info = self.open_services.get((ip, port))
        if info is None:
            return
        headers = dict(item["headers"]) if item.get("headers") else None
        header_key = tuple(sorted(f"{name}={value}" for name, value in (headers or {}).items()))
        paths = [str(path) for path in item["paths"] if (ip, port, str(path), header_key) not in self.probed]
        self.probed.update((ip, port, path, header_key) for path in paths)
        if not paths:
            return
        task = self._task("web-agent", "probe_paths",
                          {"ip": ip, "port": port, "paths": len(item["paths"]), "forwarded": sorted(headers or {})},
                          "intelligence_gathering", parent=str(item["parent"]))
        web = web_agent.inventory(
            ip, port, tls=tls, guard=self.guard, max_pages=len(paths) + 6, seeds=tuple(paths),
            include_root=False, headers=headers, timeout=web_agent.CRAWL_TIMEOUT,
            sensitive_timeout=web_agent.DEFAULT_SENSITIVE_TIMEOUT, max_sensitive_paths=0,
        )
        self._finish(task, ok=bool(web["pages"]))
        artifacts: list[tuple[str, str | None, str]] = []
        if self.binary_enabled:
            for link in web["binary_links"][:MAX_DOWNLOADS_PER_SERVICE]:
                artifacts.append((link, *self._download(ip, port, tls, link, headers=headers)))
        self._ingest_web_result(ip, port, info, tls, web, task_id=task, headers=headers, artifacts=artifacts,
                                depth=int(item["depth"]), coverage_class=f"web.followup:{port}")

    def _run_header_trust(self, item: dict[str, Any]) -> None:
        ip, port, tls, path = str(item["ip"]), int(item["port"]), bool(item["tls"]), str(item["path"])
        info = self.open_services.get((ip, port))
        if info is None or (ip, port, path) in self.header_probes_done:
            return
        self.header_probes_done.add((ip, port, path))
        section = self.manifest.checks.header_trust
        names = [str(name) for name in item["names"]]
        values = [str(value) for value in item["values"]]
        task = self._task("web-agent", "header_trust_probe",
                          {"ip": ip, "port": port, "path": path, "names": names, "values": len(values),
                           "max_requests": section.max_requests}, "vulnerability_analysis",
                          parent=str(item["parent"]))
        probe = web_agent.trusted_header_probe(
            ip, port, tls=tls, guard=self.guard, path=path, names=names, values=values,
            control_value=UNTRUSTED_CONTROL_VALUE, max_requests=section.max_requests, timeout=web_agent.CRAWL_TIMEOUT)
        control = probe["control"]
        self._finish(task, ok=control is not None)
        asset_id = int(info["asset_id"])
        self.store.upsert_coverage(CoverageRow(
            run_id=self.run_id, asset_id=asset_id, attack_class=f"web.header_trust:{port}",
            state="tested" if control else "failed",
            reason=(f"{probe['requests']} GET requests on {ip}:{port}{path}; control status "
                    f"{control['status'] if control else 'n/a'}; {len(probe['tried'])} candidates tried")))
        if probe["blocked"]:
            self.gaps.append(f"header trust test on {ip}:{port} stopped: the service signalled rate limiting")
        revealed = probe["revealed"]
        if revealed is None or control is None:
            return
        details = {"class": "trusted_header_bypass", "ip": ip, "port": port, "tls": tls, "path": path,
                   "header": revealed["header"], "trusted_value": revealed["value"],
                   "control_status": control["status"], "candidate_status": revealed["status"]}
        cid = self.store.add_candidate(
            self.run_id,
            dedup_key=candidate_key(self.run_id, asset_id, int(info["service_id"]), None,
                                    "trusted_header_bypass", f"{path}:{revealed['header']}"),
            vuln_class="trusted_header_bypass",
            claim=(f"{path} on {ip}:{port} answers {control['status']} to an untrusted {revealed['header']} value "
                   f"and 200 to a trusted one"),
            asset_id=asset_id, service_id=int(info["service_id"]), ptes_phase="vulnerability_analysis",
            details=details,
        )
        if cid is None:
            return
        self.event("web-agent", "candidate.created", {"candidate_id": cid, "class": "trusted_header_bypass",
                                                      "ip": ip, "port": port, "path": path, "status": "candidate"},
                   "vulnerability_analysis")
        verdict = verifier.Verdict(
            "confirmed",
            "the same path answers differently for an untrusted and a trusted forwarded-address value",
            f"untrusted {revealed['header']} value",
            f"{path} on {ip}:{port} answers {control['status']} to the untrusted value and 200 to the trusted value",
            evidence={"requests": probe["requests"], "control": control, "candidate": revealed,
                      "tried": probe["tried"][:10]},
        )
        self._record(cid, {"details_json": json.dumps(details), "vuln_class": "trusted_header_bypass"}, verdict)
        # The trusted value is the lead: inventory the same origin with that header set.
        self.followups.append({"kind": "probe_paths", "ip": ip, "port": port, "tls": tls, "paths": ["/"],
                               "headers": {str(revealed["header"]): str(revealed["value"])}, "parent": task,
                               "depth": int(item["depth"]) + 1})

    def stage_followups(self) -> None:
        """Run the queued follow-ups in FIFO order, within the step cap, the depth cap and the deadline reserve."""
        with self.stage("follow-up-probes", "intelligence_gathering"):
            while self.followups:
                if self.followups_run >= MAX_FOLLOWUPS:
                    self.gaps.append(f"follow-up probes stopped after {MAX_FOLLOWUPS} steps; "
                                     f"{len(self.followups)} not run")
                    self.followups.clear()
                    break
                if self.remaining() < FOLLOWUP_RESERVE_S:
                    self.gaps.append(f"follow-up probes stopped at the deadline; {len(self.followups)} not run")
                    self.followups.clear()
                    break
                item = self.followups.popleft()
                if int(item["depth"]) > MAX_FOLLOWUP_DEPTH:
                    continue
                self.followups_run += 1
                try:
                    if item["kind"] == "probe_paths":
                        self._run_probe_paths(item)
                    elif item["kind"] == "header_trust":
                        self._run_header_trust(item)
                except (OSError, http.client.HTTPException, ValueError, ScopeViolation) as exc:
                    self.limitations.append(f"follow-up {item['kind']} on {item.get('ip')}:{item.get('port')} "
                                            f"did not complete ({type(exc).__name__})")

    # 4. binaries
    def stage_binaries(self) -> None:
        with self.stage("binary-triage", "vulnerability_analysis"):
            for future, source, task_id in list(self.binary_futures):
                wait_for = max(5.0, min(120.0, self.remaining() - 30.0))
                try:
                    result = future.result(timeout=wait_for)
                except FuturesTimeout:
                    self.gaps.append(f"binary triage did not finish for {source}")
                    self.event("binary-agent", "binary.skipped", {
                        "source": source, "reason": "triage did not finish before the deadline"},
                        "vulnerability_analysis")
                    self._finish(task_id, state="skipped_deadline")
                    continue
                except Exception as exc:  # noqa: BLE001
                    self.errors.append(f"binary {source}: {type(exc).__name__}")
                    self._finish(task_id, ok=False)
                    continue
                self._ingest_binary(result, source)
                self._finish(task_id, ok=not result.get("rejected"))
            if not self.binary_futures:
                self.limitations.append("binary analysis is excluded by the manifest" if not self.binary_enabled else
                                        "no binary was supplied or downloaded; binary analysis did not run")

    def _ingest_binary(self, result: dict[str, Any], source: str) -> None:
        if result.get("rejected"):
            reason = (result.get("errors") or ["unsupported artifact"])[0]
            self.event("binary-agent", "binary.rejected", {"source": source, "reason": str(reason)[:160]},
                       "vulnerability_analysis")
            return
        sha = result["sha256"]
        already = self.store.conn.execute(
            "SELECT 1 FROM binaries WHERE run_id=? AND sha256=?", (self.run_id, sha)).fetchone()
        if already is not None:
            # The same bytes can arrive twice (supplied copy and web download); analyse them once.
            self.store.add_binary_source(self.run_id, sha, source)  # the web copy is kept as a source, not dropped
            self.event("binary-agent", "binary.duplicate", {"sha256": sha, "source": source}, "vulnerability_analysis")
            return
        self.store.upsert_binary(self.run_id, sha, result.get("source_path") or "", int(result["size"]),
                                 format=result["format"], state="analyzed_static")
        self.counts["binaries"] += 1
        self.event("binary-agent", "binary.ingested", {
            "sha256": sha, "name": result.get("name", ""), "format": result["format"], "size": result["size"],
            "source": source, "protections": result["protections"], "unsafe_imports": result["unsafe_imports"],
            "secret_lead_count": result["secret_lead_count"], "literal_count": len(result["literals"]),
        }, "vulnerability_analysis")
        self.store.add_evidence(
            self.run_id, type="binary_triage", candidate_id=None, ptes_phase="vulnerability_analysis",
            payload={"sha256": sha, "name": result.get("name", ""), "format": result["format"],
                     "artifact": result.get("artifact") or "", "protections": result["protections"],
                     "unsafe_imports": result["unsafe_imports"], "literal_count": len(result["literals"])},
        )
        for name in result["unsafe_imports"]:
            key = candidate_key(self.run_id, None, None, None, "static_unsafe_function", f"{sha}:{name}")
            candidate_id = self.store.add_candidate(
                self.run_id, dedup_key=key, vuln_class="static_unsafe_function",
                claim=f"static {name} reference in binary {sha[:12]} (reachability unverified)",
                ptes_phase="vulnerability_analysis",
                details={"class": "static_unsafe_function", "binary_sha256": sha, "name": name},
            )
            if candidate_id is not None:
                self.counts["candidates"] += 1
        literals, analysis, outcome = self._analyze_binary(result)
        solver_outcome = self._solve_literal(result, analysis)
        candidate = solver_outcome.pop("candidate", None)
        if candidate:
            literals = [*literals, {"value": candidate, "offset": -1, "via": "solver", "keyword": "solver",
                                    "score": 3.0, "user": None}]
        self.store.upsert_binary(self.run_id, sha, result.get("source_path") or "", int(result["size"]),
                                 format=result["format"], state="analyzed_static",
                                 details=self._binary_details(result, literals, outcome, solver_outcome, source))
        self.event("binary-agent", "binary.analysis", {
            "sha256": sha[:16], "name": result.get("name", ""), "tool": outcome.get("tool"),
            "status": outcome.get("status"), "errors": outcome.get("errors", [])[:3],
            "solver": solver_outcome.get("status"), "literal_count": len(literals),
        }, "vulnerability_analysis")
        for literal in literals:
            ref = f"cred-{len(self.secrets) + 1}"
            self.secrets[ref] = literal["value"]
            self.literal_refs.append(ref)
            self.literal_meta[ref] = {"keyword": literal["keyword"], "score": float(literal.get("score", 0.0)),
                                      "source": "binary", "user": literal.get("user")}
            self.store.add_credential(
                self.run_id, kind="auth_literal", secret_ref=ref,
                source=f"binary:{sha}:{literal['offset']}", confidence="static",
            )
            key = candidate_key(self.run_id, None, None, None, "hardcoded_secret", f"{sha}:{literal['offset']}")
            candidate_id = self.store.add_candidate(
                self.run_id, dedup_key=key, vuln_class="hardcoded_secret",
                claim=f"static authentication literal near '{literal['keyword']}' in binary {sha[:12]} at offset {literal['offset']} (unverified)",
                ptes_phase="vulnerability_analysis",
                details={"class": "hardcoded_secret", "binary_sha256": sha, "offset": literal["offset"],
                         "via": literal["via"], "keyword": literal["keyword"], "secret_ref": ref},
            )
            if candidate_id is not None:
                self.counts["candidates"] += 1
                self.event("binary-agent", "candidate.created", {
                    "candidate_id": candidate_id, "class": "hardcoded_secret", "binary": sha[:12],
                    "offset": literal["offset"], "status": "candidate",
                }, "vulnerability_analysis")
        if analysis is not None:
            self.store.add_evidence(
                self.run_id, type="decompile", candidate_id=None, ptes_phase="vulnerability_analysis",
                payload=self._scrub({
                    "sha256": sha, "tool": analysis["tool"], "decompiler": analysis["decompiler"],
                    "strings_seen": len(analysis["strings"]), "imports": analysis["imports"][:60],
                    "functions": analysis["functions"][:80], "main_listing": analysis["main_listing"][:60],
                    "decompiled": analysis["decompiled"][:6000],
                }),
            )
        self._persist_secrets()

    def _persist_secrets(self) -> None:
        """Literal values live only in this private file (mode 0600), never in the database."""
        path = self.run_dir / "secrets.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(self.secrets, handle)
        # Keyword, score and source only: no values, so this file can sit beside the reports safely.
        (self.run_dir / "literals.json").write_text(json.dumps(self.literal_meta, sort_keys=True), encoding="utf-8")

    # 5. verification
    def stage_verification(self, only_ips: set[str] | None = None) -> None:
        end_at = self.share_end(VERIFY_SHARE)
        # Attempts already made, blocked accounts and tried literals come from stored evidence, so a resumed run keeps
        # the per-account cap and tries only what is new.
        candidate_rows = self.store.candidates(self.run_id)
        details_by_id: dict[int, dict[str, Any]] = {}
        for row in candidate_rows:
            details = json.loads(row["details_json"] or "{}")
            details["class"] = row["vuln_class"]
            details_by_id[int(row["id"])] = details
        prior = verifier.prior_auth_state(self.store.evidence(self.run_id), details_by_id)
        self.auth_budget.used = dict(prior.used)
        self.auth_budget.blocked = set(prior.blocked)

        # Load engagement-wide attempt history and credential fingerprints
        from . import engagement
        eng_state = engagement.engagement_state(self.run_dir.parent)
        self.auth_budget.used.update(eng_state.attempts)
        self.auth_budget.blocked.update(eng_state.blocked)
        engagement_key = engagement.engagement_key(self.run_dir.parent)

        plans = verifier.plan_auth_tests(
            [(int(row["id"]), row["vuln_class"], row["state"], details_by_id[int(row["id"])]) for row in candidate_rows],
            prior, self.literal_refs, self.auth_hosts,
        )
        ctx = verifier.VerifyContext(
            guard=self.guard, budget=self.auth_budget, secrets=self.secrets,
            literal_refs=list(self.literal_refs), flag_patterns=self.flag_patterns, timeout=4.0,
            literal_meta=dict(self.literal_meta),
            engagement_key=engagement_key, tried_fingerprints=frozenset(eng_state.tried_fingerprints),
        )
        tried_all: dict[int, set[str]] = {cid: set(refs) for cid, refs in prior.tried.items()}
        with self.stage("verification", "exploitation"):
            rows = [row for row in candidate_rows if row["state"] == "candidate" or int(row["id"]) in plans]
            rows.sort(key=lambda row: (VERIFY_ORDER.get(row["vuln_class"], 9), row["id"]))
            accepted: dict[str, tuple[int, int]] = dict(prior.accepted)
            for row in rows:
                klass = row["vuln_class"]
                if klass in ("hardcoded_secret", "trusted_header_bypass"):  # resolved or verified where they were found
                    continue
                if klass in ("default_credentials", "raw_html_reflection", "exposed_path") and not self.web_enabled:
                    if row["state"] == "candidate":
                        self._record(int(row["id"]), row, verifier.Verdict(
                            "inconclusive", "manifest excludes web checks", "", "web checks are excluded by the manifest"))
                    continue
                details = json.loads(row["details_json"] or "{}")
                details["class"] = klass
                cid = int(row["id"])
                if only_ips is not None and str(details.get("ip")) not in only_ips and klass != "static_unsafe_function":
                    continue
                if klass in ("default_credentials", "passkey_protocol_auth") and str(details.get("ip")) not in self.auth_hosts:
                    self._record(cid, row, verifier.Verdict(
                        "inconclusive", "outside the authentication host set", "",
                        "credential checks run only against the focus or --auth-hosts host(s); no credential was submitted"))
                    continue
                if time.monotonic() >= end_at:
                    if row["state"] == "candidate":  # a retest must never overwrite an earlier verdict with a budget note
                        self._record(cid, row, verifier.Verdict(
                            "inconclusive", "verification budget", "",
                            "verification budget ended before this lead was tested"))
                    continue
                self.event("verification-agent", "verification.started", {
                    "candidate_id": cid, "class": klass, "target": f"{details.get('ip')}:{details.get('port')} "
                    f"{details.get('path') or details.get('target') or ''}".strip(),
                }, "exploitation")
                verify_task = self._task("verification-agent", "verify_candidate",
                                         {"candidate_id": cid, "class": klass}, "exploitation")
                plan = plans.get(cid)
                ctx.include_defaults = plan.include_defaults if plan else True
                ctx.only_refs = plan.only_refs if plan else None
                ctx.tried_log.clear()
                ctx.tested_fingerprints.clear()
                used_before, blocked_before = dict(self.auth_budget.used), set(self.auth_budget.blocked)
                try:
                    verdict = verifier.dispatch(details, ctx)
                except ScopeViolation as exc:
                    verdict = verifier.Verdict("inconclusive", "scope guard refused", "", str(exc)[:200])
                except Exception as exc:  # noqa: BLE001
                    verdict = verifier.Verdict("inconclusive", "check error", "", f"{type(exc).__name__}")
                verdict.tried = list(ctx.tried_log)
                verdict.accounts = {account: total - used_before.get(account, 0)
                                    for account, total in self.auth_budget.used.items()
                                    if total > used_before.get(account, 0)}
                verdict.blocked_accounts = sorted(self.auth_budget.blocked - blocked_before)
                tried_all.setdefault(cid, set()).update(verdict.tried)
                evidence_id = self._record(cid, row, verdict)
                self._finish(verify_task)
                for ref in verdict.accepted_refs:
                    accepted.setdefault(ref, (cid, evidence_id))

            tested_refs = set().union(*tried_all.values())
            auth_surface_exists = any(
                str(details.get("class")) in verifier.AUTH_CLASSES and str(details.get("ip")) in self.auth_hosts
                for details in details_by_id.values()
            )
            for row in self.store.candidates(self.run_id):
                if row["vuln_class"] != "hardcoded_secret" or row["state"] == "confirmed":
                    continue
                details = json.loads(row["details_json"] or "{}")
                cid = int(row["id"])
                ref = details.get("secret_ref")
                if ref in accepted:
                    source_cid, source_evidence = accepted[ref]
                    evidence_id = self.store.add_evidence(
                        self.run_id, type="reuse_confirmation", candidate_id=cid, ptes_phase="exploitation",
                        payload={"surface_candidate_id": source_cid, "surface_evidence_id": source_evidence,
                                 "summary": "recovered literal is accepted by a live authentication surface"},
                    )
                    self.store.add_validation(
                        self.run_id, cid, verdict="confirmed",
                        oracle="accepted by a live authentication surface",
                        control_kind="random value rejected by the same surface", evidence_id=evidence_id,
                    )
                    self.event("verification-agent", "verification.finished", {
                        "candidate_id": cid, "verdict": "confirmed", "summary": "literal authenticates",
                    }, "exploitation")
                elif ref in tested_refs:
                    self._record(cid, row, verdict_for("rejected", "not accepted by any tested authentication surface"))
                elif auth_surface_exists:
                    self._record(cid, row, verdict_for(
                        "inconclusive", "authentication surfaces did not reach this literal (attempt cap, blocked account or time budget)"))
                else:
                    self._record(cid, row, verdict_for("inconclusive", "no live authentication surface was tested"))
            for row in self.store.candidates(self.run_id):
                if row["vuln_class"] == "static_unsafe_function" and row["state"] == "candidate":
                    self._record(int(row["id"]), row, verifier.static_only(
                        "unsafe libc import is a static string; reachability needs dynamic analysis"))

    def _record(self, cid: int, row: Any, verdict: verifier.Verdict) -> int | None:
        details = json.loads(row["details_json"] or "{}")
        payload: dict[str, Any] = {
            "summary": verdict.summary, "oracle": verdict.oracle, "control": verdict.control,
            "attempts": verdict.attempts, "accepted_refs": verdict.accepted_refs,
            "tried_refs": verdict.tried, "accounts": verdict.accounts, "blocked_accounts": verdict.blocked_accounts,
            "credential_fingerprints": verdict.credential_fingerprints,
            **verdict.evidence,
        }
        if verdict.flags:
            for flag in verdict.flags:
                self.flag_values_seen.add(flag)
                self.store.add_flag(self.run_id, value_sha256=hashlib.sha256(flag.encode()).hexdigest(),
                                    source=f"{details.get('ip')}:{details.get('port')}")
                self.counts["flags"] += 1
            payload["flags_masked"] = [flag[:5] + "…" for flag in verdict.flags]
            if self.include_flags:
                payload["flag_values"] = list(verdict.flags)
        if not self.include_flags:
            payload = self._mask_flags(payload)
        evidence_id = self.store.add_evidence(
            self.run_id, type="verification", candidate_id=cid, ptes_phase="exploitation",
            payload=self._scrub(payload),
        )
        self.store.add_validation(
            self.run_id, cid, verdict=verdict.verdict, oracle=verdict.oracle or "unspecified",
            control_kind=verdict.control or "", evidence_id=evidence_id,
        )
        self.counts[verdict.verdict] += 1
        self.event("verification-agent", "verification.finished", {
            "candidate_id": cid, "class": row["vuln_class"], "verdict": verdict.verdict,
            "summary": verdict.summary, "attempts": verdict.attempts,
        }, "exploitation")
        return evidence_id

    # 6. attack path and report
    def stage_report(self) -> str:
        with self.stage("attack-path-and-report", "threat_modeling"):
            self._drain_chunks(submit_services=False)
            scrubbed = self._scrub_store()
            if scrubbed:
                self.event("orchestrator", "store.scrubbed", {"cells": scrubbed}, "reporting")
            confirmed_total = sum(1 for row in self.store.candidates(self.run_id) if row["state"] == "confirmed")
            budget_cut = bool(self.remaining() <= 0)
            incomplete = bool(self.errors or self.gaps or budget_cut)
            status = "partial" if incomplete else "complete"
            meta = self._meta(status, budget_cut)
            model = report.build_model(self.store, self.run_id, meta, include_flags=self.include_flags)
            # Attack path is confirmed only when an objective (authenticated access or flag) is actually reached
            has_objective = bool(model["attack_path"]["paths"])
            self.store.add_attack_path(
                self.run_id, json.dumps(model["attack_path"]["paths"], default=str),
                "confirmed" if has_objective else "lead",
            )
            self.event("attack-path", "attack_path.built", {
                "paths": len(model["attack_path"]["paths"]), "confirmed": confirmed_total,
            }, "threat_modeling")
            written = report.write_outputs(self.run_dir, model, list(self.manifest.report.formats))
            self.event("reporter-agent", "report.written", {"formats": sorted(written)}, "reporting")
        finished = utcnow()
        self.store.finish_run(self.run_id, status, finished_at=finished)
        self.summary = {
            "run_id": self.run_id, "status": status, "run_dir": str(self.run_dir),
            "blackboard": str(self.run_dir / "blackboard.db"), "reports": written,
            "counts": model["counts"], "stages": self.stages, "errors": self.errors,
            "tool": self.tool, "enforcement": ENFORCEMENT,
        }
        return status

    def _meta(self, status: str, budget_cut: bool) -> dict[str, Any]:
        gaps = list(self.gaps)
        if budget_cut:
            gaps.append("the run deadline ended before every stage completed")
        if self.opt.ports:
            gaps.append(f"ports checked on live hosts: explicit list {self.opt.ports}")
        elif self.mode != "target":
            gaps.append(f"ports checked on live hosts: top {self.opt.top_ports} TCP ports only")
        else:
            gaps.append("ports checked on the focus host: ports known from earlier scans (no top-port pass)")
        if self.opt.focus:
            if self.opt.full_scan:
                gaps.append(
                    f"full TCP range (1-65535) only for focus host(s) {', '.join(self.opt.focus)}; "
                    f"completed chunks: {', '.join(self.full_done) or 'none'}"
                )
            else:
                gaps.append("full TCP range (1-65535) was not scanned for this run")
        gaps.append("UDP was not scanned")
        if self.store.binaries(self.run_id):
            gaps.append("binaries were analysed statically; none was executed, debugged or fuzzed")
        if not self.manifest.checks.auth_tests:
            gaps.append("authentication checks are disabled by the manifest (checks.auth_tests)")
        limitations = list(self.limitations)
        limitations += [
            "scope is enforced in-process before every connect; no kernel egress policy was installed (enforcement: "
            f"{ENFORCEMENT})",
            "verification covers default and binary-derived credentials, reflected HTML canaries, exposed paths and "
            "banner repeatability; other leads are reported as leads, not findings",
            "after a passkey is accepted, one PIDREQ is sent only when the service advertises a flag path; other "
            "post-authentication protocols are not followed",
            "credential values are kept only in the run's private secrets.json (mode 0600) and are never written to "
            "events, reports or the API",
        ]
        if self.auth_budget.blocked:
            limitations.append("one or more surfaces rate-limited or blocked the engine; attempts stopped there and "
                               "no evasion was attempted")
        duration = round(time.monotonic() - self.started, 1)
        return {
            "started_at": self.started_at, "finished_at": utcnow(), "duration_seconds": duration,
            "deadline_seconds": self.opt.deadline_seconds, "tool": self.tool, "rate_pps": self.rate,
            "top_ports": self.opt.top_ports if not self.opt.ports else None, "ports": self.opt.ports,
            "focus": list(self.opt.focus), "auth_tests": self.manifest.checks.auth_tests,
            "max_auth_attempts_per_account": self.manifest.limits.max_auth_attempts_per_account,
            "auth_attempts_used": self.auth_budget.total, "allowed_checks": self.guard.allowed,
            "stages": self.stages, "gaps": gaps, "limitations": limitations, "errors": self.errors[:50],
            "mode": self.mode, "target_ip": self.opt.focus[0] if self.mode == "target" else None,
            "tools": self._tools_report(), "fuzz": self.fuzz_enabled, "external_tools": self.external_tools,
            "status": status, "window": self.manifest.engagement.window,
        }


def verdict_for(verdict: str, summary: str) -> verifier.Verdict:
    return verifier.Verdict(verdict, "cross-surface resolution", "", summary)
