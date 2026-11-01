"""Attack path engine (diagram stage 7): a NetworkX graph of verified facts, mapped to PTES phases.

The graph is built only from blackboard facts. A *path* is a chain from the
scoped operator to an objective that was actually reached: a confirmed
authentication (``access``) or a captured flag. Confirmed findings that do not
grant access (reflection, exposed paths, banners) are listed as findings, not
paths. Secret values never enter the graph: credentials appear by reference id.
Credential edges carry a lower weight so that the recovered-secret route is
reported when it reaches the same objective as a plain host route.
"""

from __future__ import annotations

import json
import re
from typing import Any

import networkx as nx

from ..store import Store

ATTACKER = "attacker"
ACCESS_CLASSES = frozenset({"default_credentials", "passkey_protocol_auth"})
CREDENTIAL_WEIGHT = 0.5


_WEB_SOURCE = re.compile(r"^web:([^:]+):(\d+)")


def _binary_sources(details_json: str | None) -> list[str]:
    """Every place a binary was found: the first source plus each duplicate's source, in order."""
    details = json.loads(details_json or "{}")
    return list(dict.fromkeys(str(source) for source in [details.get("source", ""), *details.get("sources", [])]
                              if source))


def _web_origin(source: str) -> tuple[str, int] | None:
    """(ip, port) of a binary that was downloaded from a web origin, from its recorded source."""
    match = _WEB_SOURCE.match(source)
    return (match.group(1), int(match.group(2))) if match else None


def _node_id(*parts: Any) -> str:
    return ":".join(str(part) for part in parts)


def facts(store: Store, run_id: str) -> dict[str, Any]:
    """Read-only snapshot of everything the graph needs."""
    assets = [dict(row) for row in store.conn.execute(
        "SELECT id, ip FROM assets WHERE run_id=? ORDER BY id", (run_id,))]
    services = [dict(row) for row in store.conn.execute(
        "SELECT s.id, s.asset_id, s.port, s.name, s.product, s.version, a.ip FROM services s"
        " JOIN assets a ON a.id = s.asset_id WHERE s.run_id=? ORDER BY s.id", (run_id,))]
    candidates = []
    for row in store.candidates(run_id):
        details = json.loads(row["details_json"] or "{}")
        verdict = store.conn.execute(
            "SELECT v.verdict, v.oracle, v.control_kind, v.evidence_id, e.payload_json AS payload"
            " FROM validations v LEFT JOIN evidence e ON e.id = v.evidence_id"
            " WHERE v.candidate_id=? AND v.run_id=? ORDER BY v.id DESC LIMIT 1",
            (row["id"], run_id),
        ).fetchone()
        candidates.append({
            "id": row["id"], "class": row["vuln_class"], "state": row["state"], "claim": row["claim"],
            "ptes_phase": row["ptes_phase"], "details": details,
            "verdict": dict(verdict) if verdict else None,
            "payload": json.loads(verdict["payload"]) if verdict and verdict["payload"] else {},
        })
    credentials = [dict(row) for row in store.credentials(run_id)]
    flags = [dict(row) for row in store.flags(run_id)]
    binaries = [dict(row) for row in store.binaries(run_id)]
    return {"assets": assets, "services": services, "candidates": candidates,
            "credentials": credentials, "flags": flags, "binaries": binaries}


def _verdict_of(candidate: dict[str, Any]) -> str:
    return (candidate["verdict"] or {}).get("verdict") or candidate["state"]


def _finding_label(candidate: dict[str, Any]) -> str:
    details = candidate["details"]
    if details.get("ip") is not None:
        where = f"{details['ip']}:{details.get('port')}"
        suffix = details.get("path") or details.get("target") or details.get("parameter") or ""
        return f"{candidate['class']} @ {where} {suffix}".strip()
    return f"{candidate['class']} (binary {str(details.get('binary_sha256', ''))[:12]})"


def build(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Return nodes, edges, objective paths, confirmed findings and a Mermaid rendering."""
    graph = nx.DiGraph()
    graph.add_node(ATTACKER, label="Scoped operator", kind="attacker", ptes_phase="pre_engagement", state="confirmed")

    service_by_key: dict[tuple[str, int], str] = {}
    for asset in snapshot["assets"]:
        node = _node_id("host", asset["ip"])
        graph.add_node(node, label=asset["ip"], kind="host", ptes_phase="intelligence_gathering", state="confirmed")
        graph.add_edge(ATTACKER, node, label="discovered in range", ptes_phase="intelligence_gathering", w=1.0)
    for service in snapshot["services"]:
        node = _node_id("service", service["ip"], service["port"])
        service_by_key[(service["ip"], int(service["port"]))] = node
        graph.add_node(node, label=f"{service['ip']}:{service['port']}/{service['name'] or 'tcp'}", kind="service",
                       ptes_phase="intelligence_gathering", state="confirmed")
        graph.add_edge(_node_id("host", service["ip"]), node, label="open TCP port",
                       ptes_phase="intelligence_gathering", w=1.0)

    # A confirmed trusted-address bypass opens a content node on its service; web-downloaded binaries hang off it.
    bypass_services: set[tuple[str, int]] = set()
    for candidate in snapshot["candidates"]:
        if candidate["class"] == "trusted_header_bypass" and _verdict_of(candidate) == "confirmed":
            key = (str(candidate["details"].get("ip")), int(candidate["details"].get("port", -1)))
            if key in service_by_key:
                bypass_services.add(key)
                content = _node_id("content", key[0], key[1])
                if not graph.has_node(content):
                    graph.add_node(content, label=f"content served to a trusted forwarded address on {key[0]}:{key[1]}",
                                   kind="content", ptes_phase="exploitation", state="confirmed")
    binary_sources = {str(item["sha256"]): _binary_sources(item.get("details_json")) for item in snapshot["binaries"]}
    binary_names = {str(item["sha256"]): str(item.get("path", "")).rsplit("/", 1)[-1] for item in snapshot["binaries"]}
    for credential in snapshot["credentials"]:
        cred_node = _node_id("credential", credential["secret_ref"])
        graph.add_node(cred_node, label=f"recovered {credential['kind'].replace('_', ' ')} [redacted]", kind="credential",
                       ptes_phase="vulnerability_analysis", state="lead", secret_ref=credential["secret_ref"])
        source = str(credential.get("source", ""))
        if source.startswith("web:"):
            page_node = _node_id("page", source)
            if not graph.has_node(page_node):
                graph.add_node(page_node, label=f"readable content {source[4:][:90]}", kind="webpage",
                               ptes_phase="intelligence_gathering", state="confirmed")
                graph.add_edge(ATTACKER, page_node, label="fetched by web agent",
                               ptes_phase="intelligence_gathering", w=1.0)
            graph.add_edge(page_node, cred_node, label="literal in page content",
                           ptes_phase="vulnerability_analysis", w=CREDENTIAL_WEIGHT)
            continue
        parts = source.split(":")
        binary_sha = parts[1] if source.startswith("binary:") and len(parts) >= 2 else "unknown"
        binary_node = _node_id("binary", binary_sha[:12])
        if not graph.has_node(binary_node):
            name = binary_names.get(binary_sha, "")
            graph.add_node(binary_node, label=f"binary {name or binary_sha[:12]} (static)", kind="binary",
                           ptes_phase="vulnerability_analysis", state="confirmed")
            origins = [origin for origin in (_web_origin(source) for source in binary_sources.get(binary_sha, []))
                       if origin is not None]
            bypass_origin = next((origin for origin in origins if origin in bypass_services), None)
            if bypass_origin is not None:
                graph.add_edge(_node_id("content", bypass_origin[0], bypass_origin[1]), binary_node,
                               label="downloaded behind the trusted address", ptes_phase="vulnerability_analysis", w=1.0)
            else:
                graph.add_edge(ATTACKER, binary_node, label="downloaded from web" if origins else "supplied artifact",
                               ptes_phase="intelligence_gathering", w=1.0)
        graph.add_edge(binary_node, cred_node, label="string literal in binary",
                       ptes_phase="vulnerability_analysis", w=CREDENTIAL_WEIGHT)

    findings: list[dict[str, Any]] = []
    for candidate in snapshot["candidates"]:
        details = candidate["details"]
        verdict = _verdict_of(candidate)
        if verdict == "confirmed":
            findings.append({"id": candidate["id"], "class": candidate["class"], "label": _finding_label(candidate),
                             "ptes_phase": candidate["ptes_phase"]})
        ip, port = details.get("ip"), details.get("port")
        if ip is None or port is None:
            continue
        service = service_by_key.get((ip, int(port)))
        if service is None:
            continue
        node = _node_id("finding", candidate["id"])
        graph.add_node(node, label=_finding_label(candidate)[:140], kind="finding", ptes_phase=candidate["ptes_phase"],
                       state=verdict, class_name=candidate["class"], candidate_id=candidate["id"])
        graph.add_edge(service, node, label=f"lead ({verdict})", ptes_phase=candidate["ptes_phase"], w=1.0)
        content = _node_id("content", ip, int(port))
        if candidate["class"] == "trusted_header_bypass" and verdict == "confirmed" and graph.has_node(content):
            graph.add_edge(node, content, label=f"trusted {details.get('header', 'forwarded header')} accepted",
                           ptes_phase="exploitation", w=1.0)

        accepted = candidate["payload"].get("accepted_refs") or []
        if verdict == "confirmed" and candidate["class"] in ACCESS_CLASSES:
            access = _node_id("access", ip, port, candidate["id"])
            graph.add_node(access, label=f"authenticated access on {ip}:{port}", kind="access",
                           ptes_phase="exploitation", state="confirmed", service_key=f"{ip}:{port}")
            linked = [ref for ref in accepted if graph.has_node(_node_id("credential", ref))]
            if not linked:  # no recovered credential is known to be accepted: the surface result is the only route
                graph.add_edge(node, access, label="authentication accepted", ptes_phase="exploitation", w=1.0)
            for ref in linked:  # with a known credential, access is reachable only through that credential
                cred_node = _node_id("credential", ref)
                graph.add_edge(cred_node, access, label="accepted by this surface",
                               ptes_phase="exploitation", w=CREDENTIAL_WEIGHT)
                graph.nodes[cred_node]["state"] = "confirmed"

    for flag in snapshot["flags"]:
        flag_node = _node_id("flag", flag["value_sha256"][:12])
        graph.add_node(flag_node, label="flag captured (value withheld)", kind="flag",
                       ptes_phase="post_exploitation", state="confirmed")
        for node, data in list(graph.nodes(data=True)):
            if data.get("kind") == "access" and data.get("service_key") == flag["source"]:
                graph.add_edge(node, flag_node, label="flag observed after authentication",
                               ptes_phase="post_exploitation", w=1.0)

    paths = []
    for node, data in graph.nodes(data=True):
        if data.get("kind") not in ("access", "flag"):
            continue
        try:
            route = nx.shortest_path(graph, ATTACKER, node, weight="w")
        except nx.NetworkXNoPath:
            continue
        steps = []
        for position, (source, target) in enumerate(zip(route, route[1:]), start=1):
            edge = graph.edges[source, target]
            steps.append({
                "step": position,
                "ptes_phase": edge.get("ptes_phase", "pre_engagement"),
                "from": graph.nodes[source].get("label", source),
                "to": graph.nodes[target].get("label", target),
                "action": edge.get("label", ""),
            })
        paths.append({"objective": data.get("label", node), "kind": data.get("kind"), "steps": steps,
                      "length": len(steps)})
    paths.sort(key=lambda item: (item["kind"] != "flag", item["length"], item["objective"]))

    return {
        "nodes": [{"id": node, **data} for node, data in graph.nodes(data=True)],
        "edges": [{"source": u, "target": v, **data} for u, v, data in graph.edges(data=True)],
        "paths": paths,
        "findings": findings,
        "mermaid": mermaid(graph),
    }


def _mermaid_id(node: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9]", "_", node)


def mermaid(graph: nx.DiGraph) -> str:
    lines = ["flowchart LR"]
    for node, data in graph.nodes(data=True):
        label = str(data.get("label", node)).replace('"', "'")
        lines.append(f'    {_mermaid_id(node)}["{label}"]')
    for source, target, data in graph.edges(data=True):
        label = str(data.get("label", "")).replace('"', "'")
        lines.append(f'    {_mermaid_id(source)} -- "{label}" --> {_mermaid_id(target)}')
    return "\n".join(lines) + "\n"
