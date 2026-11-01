"""Reporter (diagram stage 7): one report with the attack path, PTES tags and evidence.

Structure: executive summary, attack path, confirmed findings (main body),
rejected and inconclusive leads (appendix), hosts and services, web surface,
binary analysis, coverage and gaps, limitations. Secret values, default
passwords and (unless the manifest allows it) flag values are never written.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from ..store import Store
from . import attack_path
from .remediation import remedy_for

PHASE_ORDER = (
    "pre_engagement", "intelligence_gathering", "threat_modeling", "vulnerability_analysis",
    "exploitation", "post_exploitation", "reporting",
)


def _mask(value: str) -> str:
    return value[:5] + "…" if len(value) > 5 else "…"


def _target_label(details: dict[str, Any]) -> str:
    """Network targets show host:port and path; binary-derived leads show the artifact and offset."""
    if details.get("ip") is not None:
        where = f"{details['ip']}:{details.get('port', '')}"
        return f"{where} {details.get('path') or details.get('target') or ''}".strip()
    sha = str(details.get("binary_sha256", ""))[:12]
    offset = details.get("offset")
    return f"binary {sha}" + (f" offset {offset}" if offset is not None else "")


def _public_payload(payload: dict[str, Any], include_flags: bool) -> dict[str, Any]:
    """Drop default passwords; flag values only appear in the private copy (include_flags)."""
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if key == "default_password":
            cleaned[key] = "<built-in default: not reproduced in reports>"
        elif key == "flag_values":
            if include_flags:
                cleaned["flag_values"] = value
            else:
                cleaned["flags_masked"] = [_mask(str(item)) for item in value]
        else:
            cleaned[key] = value
    return cleaned


def build_model(store: Store, run_id: str, meta: dict[str, Any], *, include_flags: bool) -> dict[str, Any]:
    snapshot = attack_path.facts(store, run_id)
    graph = attack_path.build(snapshot)
    run_row = dict(store.get_run(run_id))

    findings = []
    for candidate in snapshot["candidates"]:
        verdict = (candidate["verdict"] or {}).get("verdict") or "candidate"
        details = candidate["details"]
        remedy = remedy_for(candidate["class"])
        findings.append({
            "id": candidate["id"],
            "class": candidate["class"],
            "state": verdict,
            "ptes_phase": candidate["ptes_phase"],
            "target": _target_label(details),
            "claim": candidate["claim"],
            "oracle": (candidate["verdict"] or {}).get("oracle", ""),
            "control": (candidate["verdict"] or {}).get("control_kind", ""),
            "summary": candidate["payload"].get("summary", ""),
            "evidence": _public_payload(candidate["payload"], include_flags),
            "fix": remedy.fix,
            "fix_check": remedy.check,
        })

    services = [{"ip": s["ip"], "port": s["port"], "name": s["name"], "product": s["product"],
                 "version": s["version"]} for s in snapshot["services"]]
    endpoints = [dict(row) for row in store.conn.execute(
        "SELECT url, method FROM endpoints WHERE run_id=? ORDER BY id LIMIT 200", (run_id,))]
    binaries = [dict(row) for row in store.binaries(run_id)]
    scope_refusals = store.conn.execute(
        "SELECT COUNT(*) FROM scope_events WHERE run_id=? AND sent_outside=0", (run_id,)).fetchone()[0]
    scope_sent = store.conn.execute(
        "SELECT COALESCE(SUM(sent_outside),0) FROM scope_events WHERE run_id=?", (run_id,)).fetchone()[0]
    coverage = [dict(row) for row in store.coverage(run_id)]

    flags = [{"source": row["source"], "sha256_prefix": row["value_sha256"][:12]} for row in snapshot["flags"]]

    confirmed = [item for item in findings if item["state"] == "confirmed"]
    leads = [item for item in findings if item["state"] != "confirmed"]
    counts = {
        "hosts_live": sum(1 for asset in snapshot["assets"]),
        "services": len(snapshot["services"]),
        "endpoints": len(endpoints),
        "candidates": len(findings),
        "confirmed": len(confirmed),
        "rejected": sum(1 for item in findings if item["state"] == "rejected"),
        "inconclusive": sum(1 for item in findings if item["state"] == "inconclusive"),
        "flags": len(flags),
        "attack_paths": len(graph["paths"]),
        "secrets_recovered": len(snapshot["credentials"]),
        "scope_refused": scope_refusals,
        "scope_sent_outside": int(scope_sent),
    }
    return {
        "run": {
            "id": run_id, "status": run_row["status"], "engagement": run_row["engagement"],
            "tier": run_row["tier"], "scope_hash": run_row["scope_hash"],
            "manifest_sha256": run_row["manifest_sha256"], "enforcement": run_row["enforcement"],
            "started_at": run_row["started_at"], "finished_at": run_row["finished_at"],
            **meta,
        },
        "counts": counts,
        "stages": meta.get("stages", []),
        "attack_path": {"paths": graph["paths"], "mermaid": graph["mermaid"], "edges": graph["edges"]},
        "findings": findings,
        "confirmed": confirmed,
        "leads": leads,
        "hosts": [{"ip": a["ip"]} for a in snapshot["assets"]],
        "services": services,
        "endpoints": endpoints,
        "binaries": [{"name": b.get("path", "").rsplit("/", 1)[-1], "sha256": b["sha256"], "format": b["format"],
                      "size": b["size"], "state": b["state"]} for b in binaries],
        "coverage": coverage,
        "flags": flags,
        "scope": {"allowed_checks": meta.get("allowed_checks", 0), "refused": scope_refusals,
                  "sent_outside": int(scope_sent)},
        "gaps": meta.get("gaps", []),
        "limitations": meta.get("limitations", []),
    }


def render_markdown(model: dict[str, Any]) -> str:
    run, counts = model["run"], model["counts"]
    lines = [
        f"# MITIGATA hunt report — {run['id']}",
        "",
        f"- **Status:** {run['status']}  ·  **Engagement:** {run['engagement']} ({run['tier']})",
        f"- **Scope hash:** `{run['scope_hash'][:16]}…`  ·  **Enforcement:** {run['enforcement']}",
        f"- **Window:** {run.get('window', '')}  ·  **Runtime:** {run.get('duration_seconds', 0):.0f}s",
        "",
        "## Executive summary",
        "",
        "| Live hosts | Open services | Endpoints | Leads | Confirmed | Rejected | Inconclusive | Attack paths | Flags |",
        "|---|---|---|---|---|---|---|---|---|",
        f"| {counts['hosts_live']} | {counts['services']} | {counts['endpoints']} | {counts['candidates']} | "
        f"{counts['confirmed']} | {counts['rejected']} | {counts['inconclusive']} | {counts['attack_paths']} | {counts['flags']} |",
        "",
        f"Scope guard: {counts['scope_refused']} out-of-scope target(s) refused, {counts['scope_sent_outside']} sent outside scope.",
        "",
        "## Attack path",
        "",
        "Chains from the scoped operator to an objective that was actually reached (authenticated access or a "
        "captured flag). Each step is tagged with its PTES phase.",
        "",
    ]
    if not model["attack_path"]["paths"]:
        lines.append("No objective was reached in this run. Confirmed findings are listed below.")
    for number, path in enumerate(model["attack_path"]["paths"], start=1):
        lines.append(f"### Path {number}: {path['objective']}")
        lines.append("")
        lines.append("| Step | PTES phase | From | To | Action |")
        lines.append("|---|---|---|---|---|")
        for step in path["steps"]:
            lines.append(f"| {step['step']} | {step['ptes_phase']} | {_cell(step['from'])} | {_cell(step['to'])} | {_cell(step['action'])} |")
        lines.append("")
    lines += ["## Confirmed findings", ""]
    if not model["confirmed"]:
        lines.append("None confirmed in this run.")
    for item in model["confirmed"]:
        lines += _finding_block(item)
    lines += ["## Appendix: rejected and inconclusive leads", ""]
    if not model["leads"]:
        lines.append("None.")
    literal_leads = [item for item in model["leads"] if item["class"] == "hardcoded_secret"]
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for item in model["leads"]:
        if item["class"] == "hardcoded_secret":
            continue
        groups.setdefault((item["class"], item["state"], item["summary"] or item["claim"]), []).append(item)
    for (klass, state, text), items in groups.items():
        fix = _lead_fix(klass, state)
        if len(items) == 1:
            lines.append(f"- **{klass}** on `{items[0]['target']}` — {state}: {text} ({items[0]['ptes_phase']}){fix}")
        else:
            examples = ", ".join(f"`{entry['target']}`" for entry in items[:3])
            more = " …" if len(items) > 3 else ""
            lines.append(f"- **{klass}** × {len(items)} — {state}: {text}. Examples: {examples}{more} ({items[0]['ptes_phase']}){fix}")
    if literal_leads:
        n_accepted = sum(1 for item in literal_leads if item["state"] == "confirmed")
        n_rejected = sum(1 for item in literal_leads if item["state"] == "rejected")
        n_open = len(literal_leads) - n_accepted - n_rejected
        fix = _lead_fix("hardcoded_secret", "inconclusive", " ") if n_open else ""
        lines.append(
            f"- **hardcoded_secret** — {len(literal_leads)} static literal(s) recovered from target binaries or readable "
            f"content: {n_accepted} accepted by a live authentication surface, {n_rejected} not accepted by any surface "
            f"that was tested, {n_open} not tested. Values are withheld from reports.{fix}"
        )
    lines += ["", "## Hosts and services", "", "| Host | Port | Service | Product / version |", "|---|---|---|---|"]
    for service in model["services"]:
        product = " ".join(part for part in [service.get("product") or "", service.get("version") or ""] if part)
        lines.append(f"| {service['ip']} | {service['port']} | {service['name'] or 'tcp'} | {_cell(product)} |")
    if model["endpoints"]:
        lines += ["", "## Web surface (sampled)", ""]
        for endpoint in model["endpoints"][:40]:
            lines.append(f"- `{endpoint['method']} {endpoint['url']}`")
    if model["binaries"]:
        lines += ["", "## Binary triage (static only)", ""]
        for binary in model["binaries"]:
            lines.append(f"- `{binary['name']}` · {binary['format']} · sha256 `{binary['sha256'][:16]}…` · state {binary['state']}")
    lines += ["", "## Coverage and gaps", ""]
    for gap in model["gaps"]:
        lines.append(f"- {gap}")
    lines += ["", "## Limitations", ""]
    for note in model["limitations"]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _lead_fix(finding_class: str, state: str, separator: str = " — ") -> str:
    """The fix sentence for a lead that is still open. A rejected lead needs no fix."""
    if state == "rejected":
        return ""
    return f"{separator}Fix: {remedy_for(finding_class).fix}"


_EVIDENCE_SKIP = frozenset({"probe_reply_excerpt", "summary", "oracle", "control", "accepted_refs",
                            "control_reply_sha256", "probe_reply_sha256"})


def _evidence_lines(evidence: dict[str, Any]) -> list[str]:
    """Show the facts a reviewer needs as short key: value bullets, not a JSON dump."""
    lines = []
    for key in sorted(evidence):
        if key in _EVIDENCE_SKIP or evidence[key] in (None, "", [], {}):
            continue
        value = evidence[key]
        text = json.dumps(value, sort_keys=True, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
        lines.append(f"  - {key.replace('_', ' ')}: {text[:200]}")
    return lines


def _finding_block(item: dict[str, Any]) -> list[str]:
    return [
        f"### {item['class']} — `{item['target']}`",
        "",
        f"- **Verdict:** confirmed · **PTES phase:** {item['ptes_phase']}",
        f"- **Oracle:** {item['oracle']}",
        f"- **Control:** {item['control']}",
        f"- **Summary:** {item['summary']}",
        "- **Evidence:**",
        *_evidence_lines(item["evidence"]),
        f"- **Fix:** {item['fix']}",
        f"- **How to check the fix:** {item['fix_check']}",
        "",
    ]


def render_html(model: dict[str, Any]) -> str:
    body: list[str] = []
    table: list[list[str]] = []

    def flush_table() -> None:
        if not table:
            return
        header, *rows = table
        html_rows = ["<table><tr>" + "".join(f"<th>{cell}</th>" for cell in header) + "</tr>"]
        for row in rows:
            html_rows.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
        body.append("".join(html_rows) + "</table>")
        table.clear()

    for line in render_markdown(model).splitlines():
        if line.startswith("|"):
            if set(line.replace("|", "").strip()) <= {"-", " "}:
                continue
            table.append([html.escape(cell.strip()) for cell in line.strip().strip("|").split("|")])
            continue
        flush_table()
        if line.startswith("### "):
            body.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("## "):
            body.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("- "):
            body.append(f"<p class=\"item\">{html.escape(line[2:])}</p>")
        elif line.strip():
            body.append(f"<p>{html.escape(line)}</p>")
    flush_table()
    content = "\n".join(body)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>MITIGATA report {html.escape(model['run']['id'])}</title>"
        "<style>body{font:15px/1.5 system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#0f172a}"
        "h1,h2,h3{color:#0b2545}table{border-collapse:collapse;width:100%;margin:.5rem 0}"
        "td,th{border:1px solid #cbd5e1;padding:.35rem .5rem;text-align:left;font-size:13px}"
        "p.item{margin:.2rem 0;font-size:14px}</style></head><body>"
        f"{content}</body></html>\n"
    )


def write_outputs(run_dir: Path, model: dict[str, Any], formats: list[str]) -> dict[str, str]:
    written: dict[str, str] = {}
    if "md" in formats:
        path = run_dir / "report.md"
        path.write_text(render_markdown(model), encoding="utf-8")
        written["md"] = str(path)
    if "html" in formats:
        path = run_dir / "report.html"
        path.write_text(render_html(model), encoding="utf-8")
        written["html"] = str(path)
    if "json" in formats:
        path = run_dir / "report.json"
        path.write_text(json.dumps(model, indent=2, sort_keys=True, default=str), encoding="utf-8")
        written["json"] = str(path)
    (run_dir / "attack_path.json").write_text(json.dumps(model["attack_path"], indent=2, default=str), encoding="utf-8")
    (run_dir / "attack_path.mmd").write_text(model["attack_path"]["mermaid"], encoding="utf-8")
    return written
