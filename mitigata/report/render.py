"""Report assembly: deterministic markdown/HTML/JSON (design §8.1).

Confirmed findings only. Candidates, unverified static leads and untested
classes stay in the appendix and are excluded from counts (§5.5).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import utcnow
from ..store import Store

BUILD = "phase 1 — bounded discovery, unauthenticated web inventory, static binary triage"

LIMITATIONS = (
    "Not performed: authentication, authorisation testing, exploitation or fuzzing, "
    "UDP or full-port scans beyond the configured ports, script execution for reflected "
    "markup, DNS resolution by the orchestrator, and any host outside the compiled scope."
)


def _tool_versions(out_dir: Path) -> dict[str, Any] | None:
    for candidate in (out_dir / "tools" / "versions.json", Path("tools/versions.json")):
        if candidate.is_file():
            try:
                return json.loads(candidate.read_text())
            except json.JSONDecodeError:
                return None
    return None


def _scope_payload(store: Store, run_id: str) -> dict[str, Any]:
    for row in store.events(run_id):
        if row["type"] == "scope.compiled":
            return json.loads(row["payload_json"])
    return {}


def _assessment_payload(store: Store, run_id: str) -> dict[str, Any]:
    latest: dict[str, Any] = {}
    for row in store.events(run_id):
        if row["type"] == "assessment.summary":
            try:
                latest = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                latest = {}
    return latest


def build_report(
    store: Store,
    run_id: str,
    out_dir: Path,
    *,
    status: str | None = None,
    finished_at: str | None = None,
) -> dict[str, Any]:
    aggregate = store.aggregate(run_id)
    run = dict(aggregate["run"])
    if status is not None:
        run["status"] = status
    if finished_at is not None:
        run["finished_at"] = finished_at
    candidates = [dict(row) for row in store.candidates(run_id)]
    validations = {row["candidate_id"]: dict(row) for row in store.validations(run_id)}
    evidence = {row["id"]: dict(row) for row in store.evidence(run_id)}
    confirmed: list[dict[str, Any]] = []
    appendix: list[dict[str, Any]] = []
    for candidate in candidates:
        if candidate["state"] != "confirmed":
            appendix.append(candidate)
            continue
        validation = validations.get(candidate["id"])
        record = evidence.get(validation["evidence_id"]) if validation else None
        confirmed.append({**candidate, "validation": validation, "evidence": record})
    untested = sorted({
        row["attack_class"] for row in aggregate["coverage"] if row["state"] != "tested"
    })
    return {
        "generated_at": utcnow(),
        "run": run,
        "counts": {
            "assets": aggregate["assets"],
            "services": aggregate["services"],
            "endpoints": aggregate["endpoints"],
            "binaries": aggregate["binaries"],
            "candidates": aggregate["candidates"],
            "confirmed": len(confirmed),
            "inconclusive": aggregate["inconclusive"],
            "validations": aggregate["validations"],
            "events": aggregate["events"],
            "scope_events": aggregate["scope_events"],
        },
        "scope": _scope_payload(store, run_id),
        "assessment": _assessment_payload(store, run_id),
        "coverage": aggregate["coverage"],
        "untested_classes": untested,
        "tasks": [dict(row) for row in store.tasks(run_id)],
        "task_states": aggregate["tasks"],
        "confirmed": confirmed,
        "appendix": appendix,
        "binaries": [dict(row) for row in store.binaries(run_id)],
        "tool_versions": _tool_versions(out_dir),
        "build": BUILD,
        "limitations": LIMITATIONS,
    }


def render_markdown(model: dict[str, Any]) -> str:
    run = model["run"]
    counts = model["counts"]
    scope = model["scope"]
    assessment = model["assessment"]
    lines = [
        f"# MITIGATA report — {run['engagement']}",
        "",
        f"- **Run:** `{run['id']}`",
        f"- **Tier:** {run['tier']}",
        f"- **Status:** {run['status']}",
        f"- **Started:** {run['started_at']}",
        f"- **Finished:** {run['finished_at'] or 'in progress'}",
        f"- **Scope hash:** `{run['scope_hash']}`",
        f"- **Manifest hash:** `{run['manifest_sha256']}`",
        f"- **Egress enforcement:** {run['enforcement']}",
        f"- **Build:** {model['build']}",
        "",
        "## 1. Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Confirmed findings | {counts['confirmed']} |",
        f"| Candidates (appendix, excluded from counts) | {counts['candidates']} |",
        f"| Inconclusive | {counts['inconclusive']} |",
        f"| Validations / evidence records | {counts['validations']} |",
        f"| Assets / services / endpoints | {counts['assets']} / {counts['services']} / {counts['endpoints']} |",
        f"| Binaries inventoried | {counts['binaries']} |",
        f"| Blackboard events | {counts['events']} |",
        f"| Scope events (strays sent) | {counts['scope_events']} sent outside scope |",
        "",
        "Confirmed findings require a class-appropriate oracle, a control comparison and",
        "retained evidence (§5.4). Nothing in this report is inferred from a tool banner.",
        "",
        "## 2. Scope",
        "",
    ]
    if scope:
        lines += [
            f"- **Allowed ranges:** {', '.join(scope.get('allowlist', [])) or 'none'}",
            f"- **Excluded:** {', '.join(scope.get('exclude', [])) or 'none'}",
            f"- **IPv6:** {'blocked' if scope.get('block_ipv6') else 'allowed per range'}",
            f"- **Public ranges authorised:** {scope.get('allow_public')}",
            f"- **Pinned DNS resolver:** {scope.get('dns_resolver') or 'none (offline pinning)'}",
            f"- **Enforcement profile:** {scope.get('profile')} ({scope.get('enforcement')})",
        ]
    else:
        lines.append("- No compiled scope event was recorded; treat this run as refused.")
    if assessment:
        cap = " (host cap reached)" if assessment.get("host_cap_reached") else ""
        lines += [
            "",
            "### Assessment budget",
            "",
            f"- Hosts: {assessment.get('hosts_scanned', 0)} scanned of "
            f"{assessment.get('hosts_planned', 0)} planned{cap}",
            f"- Ports per host: {assessment.get('ports_per_host', 0)}; "
            f"web origins: {assessment.get('web_services', 0)}",
            f"- Binary artifacts analysed: {assessment.get('binaries_analyzed', 0)}",
        ]
    lines += ["", "## 3. Coverage", ""]
    if model["coverage"]:
        lines += ["| Attack class | Asset | State | Reason |", "|---|---|---|---|"]
        for row in model["coverage"]:
            lines.append(f"| {row['attack_class']} | {row['asset_id']} | {row['state']} | {row['reason']} |")
    else:
        lines.append("No asset x attack-class checks were scheduled or completed.")
    if model["untested_classes"]:
        rows = ", ".join(model["untested_classes"])
        lines += [
            "",
            f"**Untested rows:** {rows}. These rows did not complete and make no coverage claim.",
        ]
    lines += [
        "",
        "**Out-of-model classes:** authentication, authorisation/IDOR, injection, SSRF,",
        "deserialisation, business logic and exploitation are not implemented. Their absence",
        "from this report is not a clean result.",
        "",
        "## 4. Confirmed findings",
        "",
    ]
    if model["confirmed"]:
        for finding in model["confirmed"]:
            validation = finding.get("validation") or {}
            record = finding.get("evidence") or {}
            oracle = validation.get("oracle") or "unrecorded"
            control = validation.get("control_kind") or "unrecorded"
            retained = record.get("path") or "not retained"
            digest = record.get("sha256") or "unrecorded"
            lines += [
                f"### {finding['vuln_class']} — {finding['claim'] or 'unlabelled'}",
                "",
                f"- State: {finding['state']}",
                f"- Oracle: {oracle} (control: {control})",
                f"- Evidence: `{retained}` sha256 `{digest}`",
                f"- Limits: {finding['vuln_class'].replace('_', ' ')} confirmed only as stated in the claim; escalation was not attempted.",
                "",
            ]
    else:
        lines.append("None. No candidate reached `validation.passed` in this run.")
    lines += ["", "## Appendix A — candidates and unverified leads", ""]
    if model["appendix"]:
        lines += ["| Vuln class | State | Claim |", "|---|---|---|"]
        for row in model["appendix"]:
            lines.append(f"| {row['vuln_class']} | {row['state']} | {row['claim']} |")
    else:
        lines.append("No unconfirmed candidates were created.")
    lines += ["", "## Appendix B — binary inventory", ""]
    if model["binaries"]:
        lines += ["| Path | SHA-256 | Size (bytes) | Format | State |", "|---|---|---|---|---|"]
        for row in model["binaries"]:
            lines.append(
                f"| `{row['path']}` | `{row['sha256']}` | {row['size']} | {row['format']} | {row['state']} |"
            )
    else:
        lines.append("No binaries were supplied to this run.")
    lines += [
        "",
        "## Appendix C — reproducibility and limitations",
        "",
        f"- Tool versions: {'recorded' if model['tool_versions'] else 'unavailable (no tools/versions.json)'}",
        f"- Tasks: {model['task_states']}",
        f"- {model['limitations']}",
        "- Workers: preflight and reporter (orchestrator); network TCP connect and web GET",
        "  inventory (namespace-isolated, unprivileged); binary static strings (offline).",
        "- Binary results are printable-string heuristics: unsafe imports and secret",
        "  indicators are unverified and never reported as credentials.",
        "",
    ]
    return "\n".join(lines)


def render_html(model: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template("report.html.j2").render(**model)


def write_report(model: dict[str, Any], out_dir: Path, formats: list[str]) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    if "md" in formats:
        path = out_dir / "report.md"
        path.write_text(render_markdown(model), encoding="utf-8")
        written["md"] = path
    if "html" in formats:
        path = out_dir / "report.html"
        path.write_text(render_html(model), encoding="utf-8")
        written["html"] = path
    if "json" in formats:
        path = out_dir / "report.json"
        path.write_text(json.dumps(model, indent=2, sort_keys=True, default=str), encoding="utf-8")
        written["json"] = path
    return written
