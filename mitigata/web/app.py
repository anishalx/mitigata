"""Local FastAPI service and dashboard for the hunt pipeline (diagram stage 7: API and report).

Loopback only. Read routes serve blackboard facts for finished and running runs.
The one write route starts a hunt in a background thread, behind a per-process
token and same-origin checks. Recovered literal values, default passwords and
(unless the manifest allows it) flag values never leave the server.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field, field_validator

from ..config import ConfigError, load_manifest
from ..models import utcnow
from ..pipeline import HuntOptions, HuntRefused, run_hunt
from ..pipeline import tools as pipeline_tools
from ..pipeline.orchestrator import check_permitted, run_discovery, run_target
from ..scope import ScopeError, compile_scope
from ..store import reconcile_stale_runs

RUN_ID = re.compile(r"run-[A-Za-z0-9_-]{1,80}\Z")
REPORT_FORMATS = {
    "md": ("report.md", "text/markdown; charset=utf-8"),
    "html": ("report.html", "text/html; charset=utf-8"),
    "json": ("report.json", "application/json"),
    "attack-path": ("attack_path.json", "application/json"),
    "mermaid": ("attack_path.mmd", "text/plain; charset=utf-8"),
}
CANDIDATE_DETAIL_KEYS = ("ip", "port", "class", "surface", "path", "parameter", "realm", "binary_sha256",
                         "offset", "via", "keyword", "secret_ref", "name")
# Wheels bundle the assets inside the package; a source checkout serves the top-level frontend/.
_PACKAGE_FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
FRONTEND = _PACKAGE_FRONTEND if _PACKAGE_FRONTEND.is_dir() else Path(__file__).resolve().parents[2] / "frontend"
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    ),
}


class HuntRequest(BaseModel):
    focus: list[str] = Field(default_factory=list, max_length=8)
    deadline_seconds: float = Field(default=1200.0, ge=60.0, le=3600.0)
    full_scan: bool = True
    top_ports: int = Field(default=1000, ge=10, le=65535)
    ports: str | None = Field(default=None, max_length=200)
    binaries: list[str] = Field(default_factory=list, max_length=8)
    auth_hosts: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("focus", "auth_hosts")
    @classmethod
    def _addresses(cls, values: list[str]) -> list[str]:
        for value in values:
            ipaddress.IPv4Address(value.strip())
        return [value.strip() for value in values]

    @field_validator("binaries")
    @classmethod
    def _relative_patterns(cls, values: list[str]) -> list[str]:
        for value in values:
            if value.startswith("/") or ".." in Path(value).parts or len(value) > 200:
                raise ValueError("binary patterns must be relative to the manifest directory")
        return values


class DiscoverRequest(BaseModel):
    top_ports: int = Field(default=100, ge=10, le=1000)
    deadline_seconds: float = Field(default=600.0, ge=60.0, le=3600.0)


class TargetRequest(BaseModel):
    ip: str = Field(max_length=15)
    deadline_seconds: float = Field(default=1500.0, ge=60.0, le=7200.0)
    fuzz: bool = True
    external_tools: bool = True
    full_scan: bool = True
    ports: str | None = Field(default=None, max_length=200)
    auth_hosts: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("ip")
    @classmethod
    def _address(cls, value: str) -> str:
        return str(ipaddress.IPv4Address(value.strip()))

    @field_validator("auth_hosts")
    @classmethod
    def _auth_addresses(cls, values: list[str]) -> list[str]:
        for value in values:
            ipaddress.IPv4Address(value.strip())
        return [value.strip() for value in values]


class _Job:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.state: dict[str, Any] = {"state": "idle"}

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.state)

    def update(self, **values: Any) -> None:
        with self.lock:
            self.state.update(values)


def _open_run(out_dir: Path, run_id: str) -> sqlite3.Connection | None:
    if not RUN_ID.fullmatch(run_id):
        return None
    run_dir = out_dir / run_id
    database = run_dir / "blackboard.db"
    if run_dir.is_symlink() or not database.is_file() or database.is_symlink():
        return None
    connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True, timeout=2)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def _run_db(out_dir: Path, run_id: str) -> Iterator[sqlite3.Connection | None]:
    """Yield a read-only connection, or None when the run does not exist; always closes what it opened."""
    connection = _open_run(out_dir, run_id)
    try:
        yield connection
    finally:
        if connection is not None:
            connection.close()


def list_runs(out_dir: Path) -> list[dict[str, Any]]:
    runs = []
    if not out_dir.is_dir():
        return runs
    for entry in out_dir.iterdir():
        try:
            with _run_db(out_dir, entry.name) as conn:
                if conn is None:
                    continue
                row = conn.execute("SELECT id, engagement, tier, status, enforcement, started_at, finished_at"
                                   " FROM runs WHERE id=?", (entry.name,)).fetchone()
                if row is None:
                    continue
                counts = {
                    "hosts": conn.execute("SELECT COUNT(*) FROM assets WHERE run_id=?", (entry.name,)).fetchone()[0],
                    "candidates": conn.execute("SELECT COUNT(*) FROM candidates WHERE run_id=?", (entry.name,)).fetchone()[0],
                    "confirmed": conn.execute("SELECT COUNT(*) FROM candidates WHERE run_id=? AND state='confirmed'",
                                              (entry.name,)).fetchone()[0],
                    "flags": conn.execute("SELECT COUNT(*) FROM flags WHERE run_id=?", (entry.name,)).fetchone()[0],
                }
                runs.append({**dict(row), "counts": counts,
                             "has_report": (out_dir / entry.name / "report.json").is_file()})
        except sqlite3.Error:
            continue
    return sorted(runs, key=lambda item: (item["started_at"], item["id"]), reverse=True)


def run_view(out_dir: Path, run_id: str) -> dict[str, Any] | None:
    with _run_db(out_dir, run_id) as conn:
        if conn is None:
            return None
        run = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if run is None:
            return None
        events = [dict(row) for row in conn.execute(
            "SELECT ts, agent, type, ptes_phase, payload_json FROM events WHERE run_id=? ORDER BY rowid DESC LIMIT 200",
            (run_id,))]
        for item in events:
            item["payload"] = json.loads(item.pop("payload_json") or "{}")
        ordered = list(reversed(events))
        # Stages come from the full history, not the 200 newest events, so early stages are never shown as queued.
        stage_rows = [(row["type"], row["ptes_phase"], json.loads(row["payload_json"] or "{}")) for row in conn.execute(
            "SELECT type, ptes_phase, payload_json FROM events WHERE run_id=? AND type IN"
            " ('stage.started','stage.finished') ORDER BY rowid", (run_id,))]
        stages = [{"name": payload.get("stage"), "seconds": payload.get("seconds"), "ptes_phase": phase}
                  for kind, phase, payload in stage_rows if kind == "stage.finished"]
        current_stage = (stage_rows[-1][2].get("stage") if stage_rows and stage_rows[-1][0] == "stage.started"
                         else None)

        def latest_payload(event_type: str) -> dict[str, Any]:
            row = conn.execute("SELECT payload_json FROM events WHERE run_id=? AND type=? ORDER BY rowid DESC LIMIT 1",
                               (run_id, event_type)).fetchone()
            return json.loads(row["payload_json"] or "{}") if row else {}

        target_payload = latest_payload("target.started")
        started_payload = target_payload or latest_payload("run.started")
        validated_payload = latest_payload("scope.validated")

        agents: dict[str, dict[str, Any]] = {}
        for row in conn.execute("SELECT agent, kind, state FROM tasks WHERE run_id=?", (run_id,)):
            entry = agents.setdefault(row["agent"], {"agent": row["agent"], "states": {}, "kinds": set()})
            entry["states"][row["state"]] = entry["states"].get(row["state"], 0) + 1
            entry["kinds"].add(row["kind"])
        for entry in agents.values():
            entry["kinds"] = sorted(entry["kinds"])
        for item in ordered:
            if item["agent"] in agents:
                agents[item["agent"]]["last_event"] = item["type"]
                agents[item["agent"]]["last_ts"] = item["ts"]

        hosts = []
        services_by_asset: dict[int, list[dict[str, Any]]] = {}
        for row in conn.execute(
            "SELECT asset_id, port, proto, name, product, version, source FROM services WHERE run_id=? ORDER BY port",
            (run_id,),
        ):
            services_by_asset.setdefault(row["asset_id"], []).append(dict(row))
        for asset in conn.execute("SELECT id, ip, source FROM assets WHERE run_id=? ORDER BY id", (run_id,)):
            hosts.append({"asset_id": asset["id"], "ip": asset["ip"], "source": asset["source"],
                          "ports": services_by_asset.get(asset["id"], [])})

        endpoints = [dict(row) for row in conn.execute(
            "SELECT id, method, url FROM endpoints WHERE run_id=? ORDER BY id LIMIT 300", (run_id,))]
        candidates = _candidates(conn, run_id)
        credentials = [dict(row) for row in conn.execute(
            "SELECT id, kind, secret_ref, source, confidence FROM credentials WHERE run_id=? ORDER BY id", (run_id,))]
        flags = [{"source": row["source"], "sha256_prefix": row["value_sha256"][:12]}
                 for row in conn.execute("SELECT value_sha256, source FROM flags WHERE run_id=? ORDER BY id", (run_id,))]
        coverage = [dict(row) for row in conn.execute(
            "SELECT asset_id, attack_class, state, reason FROM coverage WHERE run_id=? ORDER BY attack_class, asset_id"
            " LIMIT 400", (run_id,))]
        binaries = [{"sha256": row["sha256"], "format": row["format"], "state": row["state"],
                     "name": Path(row["path"]).name if row["path"] else "",
                     "details": json.loads(row["details_json"] or "{}")}
                    for row in conn.execute(
                        "SELECT sha256, format, state, path, details_json FROM binaries WHERE run_id=? ORDER BY id",
                        (run_id,))]
        lineage = [dict(row) for row in conn.execute(
            "SELECT id, agent, kind, state, parent_task_id, created_at, payload_json FROM tasks WHERE run_id=?"
            " ORDER BY created_at, rowid LIMIT 400", (run_id,))]
        for item in lineage:
            item["payload"] = json.loads(item.pop("payload_json") or "{}")
        paths = _attack_paths(out_dir, run_id)
        task_counts = {row["state"]: row["n"] for row in conn.execute(
            "SELECT state, COUNT(*) AS n FROM tasks WHERE run_id=? GROUP BY state", (run_id,))}
        scope_row = conn.execute(
            "SELECT COALESCE(SUM(CASE WHEN sent_outside=0 THEN 1 ELSE 0 END), 0) AS refused,"
            " COALESCE(SUM(sent_outside), 0) AS sent FROM scope_events WHERE run_id=?", (run_id,)).fetchone()

    reports = {fmt: (out_dir / run_id / name).is_file() for fmt, (name, _) in REPORT_FORMATS.items()}
    return {
        "run": dict(run),
        "counts": {
            "hosts": len(hosts), "open_ports": sum(len(h["ports"]) for h in hosts),
            "endpoints": len(endpoints), "candidates": len(candidates),
            "confirmed": sum(1 for c in candidates if c["state"] == "confirmed"),
            "rejected": sum(1 for c in candidates if c["state"] == "rejected"),
            "inconclusive": sum(1 for c in candidates if c["state"] == "inconclusive"),
            "candidate": sum(1 for c in candidates if c["state"] == "candidate"),
            "flags": len(flags), "credentials": len(credentials), "binaries": len(binaries),
            "attack_paths": len(paths.get("paths", [])),
        },
        "mode": started_payload.get("mode") or ("target" if target_payload else "hunt"),
        "target_ip": target_payload.get("ip"),
        "config": {key: started_payload.get(key) for key in ("tool", "rate_pps", "deadline_seconds", "auth_tests",
                                                              "window", "fuzz", "external_tools")},
        "validated": {key: validated_payload.get(key) for key in ("hosts_in_scope", "focus", "rate_pps",
                                                                  "auth_tests", "max_auth_attempts_per_account")},
        "tools": started_payload.get("tools") or pipeline_tools.detect(),
        "stages": stages,
        "current_stage": current_stage,
        "agents": sorted(agents.values(), key=lambda item: item["agent"]),
        "task_counts": task_counts,
        "scope": {"refused": scope_row["refused"], "sent_outside": scope_row["sent"]},
        "hosts": hosts,
        "endpoints": endpoints,
        "candidates": candidates,
        "credentials": credentials,
        "flags": flags,
        "binaries": binaries,
        "lineage": lineage,
        "coverage": coverage,
        "attack_path": paths,
        "events": events,
        "reports": reports,
    }


def _candidates(conn: sqlite3.Connection, run_id: str, asset_id: int | None = None) -> list[dict[str, Any]]:
    query = ("SELECT c.id, c.vuln_class, c.state, c.claim, c.ptes_phase, c.asset_id, c.service_id, c.details_json,"
             " v.oracle, v.control_kind, e.payload_json AS payload FROM candidates c"
             " LEFT JOIN validations v ON v.id = (SELECT MAX(id) FROM validations WHERE candidate_id = c.id)"
             " LEFT JOIN evidence e ON e.id = v.evidence_id WHERE c.run_id=?")
    params: tuple[Any, ...] = (run_id,)
    if asset_id is not None:
        query += " AND c.asset_id=?"
        params = (run_id, asset_id)
    rows = []
    for row in conn.execute(query + " ORDER BY c.id", params):
        details = json.loads(row["details_json"] or "{}")
        payload = json.loads(row["payload"] or "{}") if row["payload"] else {}
        rows.append({
            "id": row["id"], "class": row["vuln_class"], "state": row["state"], "claim": row["claim"],
            "ptes_phase": row["ptes_phase"], "asset_id": row["asset_id"], "service_id": row["service_id"],
            "details": {key: details[key] for key in CANDIDATE_DETAIL_KEYS if key in details},
            "oracle": row["oracle"] or "", "control": row["control_kind"] or "",
            "summary": payload.get("summary", ""), "attempts": payload.get("attempts", 0),
        })
    return rows


def _attack_paths(out_dir: Path, run_id: str) -> dict[str, Any]:
    path = out_dir / run_id / "attack_path.json"
    if not path.is_file() or path.is_symlink():
        return {"paths": [], "mermaid": ""}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"paths": [], "mermaid": ""}


def create_app(
    *, out_dir: Path, scope_path: Path | None, port: int, token: str | None = None,
) -> FastAPI:
    out_dir = out_dir.resolve()
    token = token or secrets.token_urlsafe(24)
    try:
        reconciled = reconcile_stale_runs(out_dir)
    except Exception:  # noqa: BLE001 - a broken run directory must not stop the dashboard
        reconciled = []
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    job = _Job()
    app = FastAPI(title="MITIGATA", version="0.2.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.reconciled_runs = reconciled

    def scope_summary() -> dict[str, Any]:
        if scope_path is None:
            return {"state": "unconfigured", "message": "Start with --scope to enable hunts."}
        try:
            manifest, raw = load_manifest(scope_path)
            compiled = compile_scope(manifest)
            start, end = manifest.engagement.window_bounds
            return {
                "state": "valid", "name": manifest.engagement.name, "tier": manifest.engagement.tier,
                "window": manifest.engagement.window, "window_open": start <= datetime.now(UTC) <= end,
                "allowlist": [str(net) for net in compiled.allowlist],
                "exclude": [str(net) for net in compiled.exclude],
                "scope_hash": compiled.scope_hash, "auth_tests": manifest.checks.auth_tests,
                "max_auth_attempts_per_account": manifest.limits.max_auth_attempts_per_account,
                "max_rate_pps": manifest.limits.max_rate_pps,
                "flag_patterns": len(manifest.flags.patterns), "binaries_declared": manifest.scope.binaries,
                "web_inventory": check_permitted(manifest.checks, "web.inventory"),
                "fuzz_allowed": check_permitted(manifest.checks, "web.inventory") and
                                check_permitted(manifest.checks, "web.fuzz"),
                "authorised_by": manifest.engagement.authorised_by, "manifest_name": scope_path.name,
            }
        except (ConfigError, ScopeError, ValueError, TypeError) as exc:
            return {"state": "invalid", "message": str(exc)[:300]}

    @app.middleware("http")
    async def local_only(request: Request, call_next: Any) -> Response:
        host = request.headers.get("host", "").lower()
        origin = request.headers.get("origin")
        fetch_site = request.headers.get("sec-fetch-site", "").lower()
        if host not in allowed_hosts:
            return PlainTextResponse("Forbidden", status_code=403, headers=SECURITY_HEADERS)
        if origin and origin.lower() not in {f"http://{item}" for item in allowed_hosts}:
            return PlainTextResponse("Forbidden", status_code=403, headers=SECURITY_HEADERS)
        if fetch_site == "cross-site":
            return PlainTextResponse("Forbidden", status_code=403, headers=SECURITY_HEADERS)
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    @app.get("/", response_class=HTMLResponse)
    def index() -> FileResponse:
        return FileResponse(FRONTEND / "index.html", media_type="text/html; charset=utf-8")

    @app.get("/app.js")
    def app_js() -> FileResponse:
        return FileResponse(FRONTEND / "app.js", media_type="text/javascript; charset=utf-8")

    @app.get("/style.css")
    def style_css() -> FileResponse:
        return FileResponse(FRONTEND / "style.css", media_type="text/css; charset=utf-8")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "time": utcnow(), "version": app.version}

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        return {
            "scope": scope_summary(),
            "tools": pipeline_tools.detect(),
            "job": job.snapshot(),
            "action_token": token,
            "runs": len(list_runs(out_dir)),
            "reconciled_runs": getattr(app.state, "reconciled_runs", []),
            "enforcement": "host_guard_in_process",
        }

    @app.post("/api/hunt", status_code=202)
    def start_hunt(
        payload: HuntRequest,
        x_mitigata_token: str = Header(default=""),
    ) -> Response:
        if not secrets.compare_digest(x_mitigata_token, token):
            return PlainTextResponse("Forbidden", status_code=403)
        if scope_path is None:
            return JSONResponse({"error": "Start the server with --scope to enable hunts."}, status_code=400)
        summary = scope_summary()
        if summary["state"] != "valid":
            return JSONResponse({"error": "The scope manifest is invalid or unavailable."}, status_code=422)
        if not summary["window_open"]:
            return JSONResponse({"error": "The authorisation window is closed; nothing was sent."}, status_code=409)
        with job.lock:
            if job.state.get("state") == "running":
                return JSONResponse({"error": "A hunt is already running."}, status_code=409)
            job.state = {"state": "running", "run_id": "", "started_at": utcnow(), "error": "", "status": ""}

        def created(run_id: str) -> None:
            job.update(run_id=run_id)

        options = HuntOptions(
            scope_path=scope_path, out_dir=out_dir, binaries=payload.binaries, focus=payload.focus,
            top_ports=payload.top_ports, ports=payload.ports, full_scan=payload.full_scan,
            deadline_seconds=payload.deadline_seconds, auth_hosts=payload.auth_hosts, on_created=created,
        )

        def worker() -> None:
            try:
                result = run_hunt(options)
                job.update(state="done", status=result.get("status", ""), run_id=result.get("run_id", ""),
                           errors=result.get("errors", []))
            except HuntRefused as exc:
                job.update(state="refused", error=str(exc)[:300])
            except Exception as exc:  # noqa: BLE001 - the UI must always get a final state
                job.update(state="error", error=f"{type(exc).__name__}: {str(exc)[:240]}")
            finally:
                job.update(finished_at=utcnow())

        threading.Thread(target=worker, name="mitigata-hunt", daemon=True).start()
        return JSONResponse(job.snapshot(), status_code=202)

    def _start_job(kind: str, runner: Callable[[], dict[str, Any]], **fields: Any) -> Response:
        with job.lock:
            if job.state.get("state") == "running":
                return JSONResponse({"error": "A job is already running; wait for it to finish."}, status_code=409)
            job.state = {"state": "running", "kind": kind, "run_id": fields.get("run_id", ""),
                         "target": fields.get("target", ""), "started_at": utcnow(), "error": "", "status": ""}

        def worker() -> None:
            try:
                result = runner()
                job.update(state="done", status=result.get("status", ""),
                           run_id=result.get("run_id") or job.snapshot().get("run_id", ""),
                           errors=result.get("errors", []))
            except HuntRefused as exc:
                job.update(state="refused", error=str(exc)[:300])
            except Exception as exc:  # noqa: BLE001 - the UI must always get a final state
                job.update(state="error", error=f"{type(exc).__name__}: {str(exc)[:240]}")
            finally:
                job.update(finished_at=utcnow())

        threading.Thread(target=worker, name=f"mitigata-{kind}", daemon=True).start()
        return JSONResponse(job.snapshot(), status_code=202)

    def _guard_start(x_mitigata_token: str) -> Response | None:
        if not secrets.compare_digest(x_mitigata_token, token):
            return PlainTextResponse("Forbidden", status_code=403)
        if scope_path is None:
            return JSONResponse({"error": "Start the server with --scope to enable scans."}, status_code=400)
        summary = scope_summary()
        if summary["state"] != "valid":
            return JSONResponse({"error": "The scope manifest is invalid or unavailable."}, status_code=422)
        if not summary["window_open"]:
            return JSONResponse({"error": "The authorisation window is closed; nothing was sent."}, status_code=409)
        return None

    @app.post("/api/discover", status_code=202)
    def start_discovery(payload: DiscoverRequest, x_mitigata_token: str = Header(default="")) -> Response:
        refusal = _guard_start(x_mitigata_token)
        if refusal is not None:
            return refusal
        options = HuntOptions(scope_path=scope_path, out_dir=out_dir, top_ports=payload.top_ports,
                              deadline_seconds=payload.deadline_seconds,
                              on_created=lambda run_id: job.update(run_id=run_id))
        return _start_job("discover", lambda: run_discovery(options))

    @app.post("/api/runs/{run_id}/target", status_code=202)
    def start_target(run_id: str, payload: TargetRequest, x_mitigata_token: str = Header(default="")) -> Response:
        refusal = _guard_start(x_mitigata_token)
        if refusal is not None:
            return refusal
        if not RUN_ID.fullmatch(run_id):
            return PlainTextResponse("Not found", status_code=404)
        with _run_db(out_dir, run_id) as conn:
            if conn is None:
                return PlainTextResponse("Not found", status_code=404)
        options = HuntOptions(scope_path=scope_path, out_dir=out_dir, run_id=run_id, focus=[payload.ip],
                              deadline_seconds=payload.deadline_seconds, fuzz=payload.fuzz,
                              external_tools=payload.external_tools, full_scan=payload.full_scan,
                              ports=payload.ports, auth_hosts=payload.auth_hosts)
        return _start_job("target", lambda: run_target(options), run_id=run_id, target=payload.ip)

    @app.get("/api/job")
    def job_status() -> dict[str, Any]:
        return job.snapshot()

    @app.get("/api/runs")
    def runs() -> dict[str, Any]:
        return {"runs": list_runs(out_dir)}

    @app.get("/api/runs/{run_id}")
    def run_detail(run_id: str) -> Response:
        view = run_view(out_dir, run_id)
        if view is None:
            return PlainTextResponse("Not found", status_code=404)
        return JSONResponse(view)

    @app.get("/api/runs/{run_id}/report/{fmt}")
    def report(run_id: str, fmt: str) -> Response:
        if fmt not in REPORT_FORMATS or not RUN_ID.fullmatch(run_id):
            return PlainTextResponse("Not found", status_code=404)
        name, media = REPORT_FORMATS[fmt]
        path = out_dir / run_id / name
        if not path.is_file() or path.is_symlink():
            return PlainTextResponse("Not found", status_code=404)
        return FileResponse(path, media_type=media, filename=f"{run_id}-{name}")

    @app.get("/targets")
    def targets(run_id: str | None = Query(default=None)) -> Response:
        resolved = _resolve_run(out_dir, run_id)
        if resolved is None:
            return PlainTextResponse("Not found", status_code=404)
        view = run_view(out_dir, resolved)
        return JSONResponse({"run_id": resolved, "targets": view["hosts"] if view else []})

    @app.get("/targets/{asset_id}/findings")
    def target_findings(asset_id: int, run_id: str | None = Query(default=None)) -> Response:
        resolved = _resolve_run(out_dir, run_id)
        if resolved is None:
            return PlainTextResponse("Not found", status_code=404)
        with _run_db(out_dir, resolved) as conn:
            if conn is None:
                return PlainTextResponse("Not found", status_code=404)
            if conn.execute("SELECT 1 FROM assets WHERE run_id=? AND id=?", (resolved, asset_id)).fetchone() is None:
                return PlainTextResponse("Not found", status_code=404)
            findings = _candidates(conn, resolved, asset_id)
        return JSONResponse({"run_id": resolved, "asset_id": asset_id, "findings": findings})

    @app.get("/findings")
    def findings(run_id: str | None = Query(default=None)) -> Response:
        resolved = _resolve_run(out_dir, run_id)
        if resolved is None:
            return PlainTextResponse("Not found", status_code=404)
        with _run_db(out_dir, resolved) as conn:
            if conn is None:
                return PlainTextResponse("Not found", status_code=404)
            return JSONResponse({"run_id": resolved, "findings": _candidates(conn, resolved)})

    return app


def _resolve_run(out_dir: Path, run_id: str | None) -> str | None:
    """An explicit run id must exist; otherwise the newest run is used."""
    if run_id is not None:
        if not RUN_ID.fullmatch(run_id):
            return None
        with _run_db(out_dir, run_id) as conn:
            return run_id if conn is not None else None
    runs = list_runs(out_dir)
    return runs[0]["id"] if runs else None
