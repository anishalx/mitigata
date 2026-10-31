from __future__ import annotations

import hashlib
import html
import http.server
import socket
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from mitigata.assessment import allowed_hosts
from mitigata.scope import compile_scope
from mitigata.surfaces.network import scan_host
from mitigata.surfaces.web import inspect_site

from .conftest import make_manifest


class _ReflectingHandler(http.server.BaseHTTPRequestHandler):
    escaped = False

    def do_GET(self) -> None:
        value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        rendered = html.escape(value) if self.escaped else value
        body = (
            f'<html><body><p>echo: {rendered}</p><a href="/page?q=hello">more</a></body></html>'
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture
def reflector():
    servers: list[http.server.ThreadingHTTPServer] = []

    def start(*, escaped: bool = False) -> int:
        handler = type("Handler", (_ReflectingHandler,), {"escaped": escaped})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server.server_address[1]

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def test_raw_reflection_is_confirmed_with_paired_canaries(reflector):
    port = reflector()
    result = inspect_site("127.0.0.1", port, max_pages=2, timeout_s=2)
    candidates = [lead for lead in result["candidates"] if lead["type"] == "raw_html_reflection"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["parameter"] == "q"
    assert candidate["verified"] is True
    evidence = candidate["evidence"]
    assert evidence["probe_sha256"] != evidence["control_sha256"]
    assert evidence["probe_status"] == evidence["control_status"] == 200


def test_escaped_reflection_is_not_reported(reflector):
    port = reflector(escaped=True)
    result = inspect_site("127.0.0.1", port, max_pages=2, timeout_s=2)
    assert result["candidates"] == []
    assert result["endpoints"], "the page itself should still be inventoried"


def test_scan_host_reports_refusal_as_reachable():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        open_port = listener.getsockname()[1]
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        result = scan_host("127.0.0.1", [open_port, closed_port], timeout_s=1, budget_s=5)
    assert result["reachable"] is True
    assert [service["port"] for service in result["services"]] == [open_port]


def test_scan_host_marks_unanswered_ports_unreachable():
    result = scan_host("127.0.0.1", [], timeout_s=1, budget_s=1)
    assert result["reachable"] is False


def test_allowed_hosts_excludes_and_keeps_unicast_only():
    hosts, truncated = allowed_hosts(compile_scope(make_manifest()), 400)
    assert truncated is False
    assert hosts[0] == "10.10.5.2" and hosts[-1] == "10.10.5.254"
    assert "10.10.5.0" not in hosts
    assert "10.10.5.1" not in hosts
    assert "10.10.5.255" not in hosts
    assert len(hosts) == 253


def test_allowed_hosts_reports_the_cap():
    hosts, truncated = allowed_hosts(compile_scope(make_manifest()), 3)
    assert truncated is True and hosts == ["10.10.5.2", "10.10.5.3", "10.10.5.4"]


def test_web_ingestion_redacts_queries_and_retains_confirmation_evidence(tmp_path):
    from mitigata.assessment import _ingest_web_result
    from mitigata.report.render import build_report, render_markdown
    from mitigata.store import Store

    store = Store(tmp_path / "blackboard.db")
    store.create_run(
        "run-1", engagement="unit", tier="recon", scope_hash="a" * 64,
        manifest_sha256="b" * 64, enforcement="installed",
    )
    try:
        asset_id = store.upsert_asset("run-1", "10.10.5.5")
        service_id = store.upsert_service("run-1", asset_id, 80, name="http")
        result = {
            "ip": "10.10.5.5", "port": 80,
            "endpoints": [{"url": "http://10.10.5.5:80/search?q=secretvalue&x=1", "status": 200}],
            "candidates": [{
                "type": "raw_html_reflection", "parameter": "q", "verified": True,
                "evidence": {
                    "path": "/search", "probe_status": 200, "control_status": 200,
                    "probe_sha256": "c" * 64, "control_sha256": "d" * 64,
                    "oracle": "distinct raw HTML canaries reflected by paired GET requests",
                },
            }],
            "errors": [],
        }
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        counts = _ingest_web_result(store, "run-1", evidence_dir, "10.10.5.5", 80, asset_id, service_id, result, 20)
        assert counts == {"endpoints": 1, "candidates": 1, "confirmed": 1}
        aggregate = store.aggregate("run-1")
        assert aggregate["confirmed"] == 1 and aggregate["validations"] == 1

        endpoints = store.conn.execute("SELECT url FROM endpoints").fetchall()
        assert "secretvalue" not in endpoints[0]["url"]
        assert "q=%3Credacted%3E" in endpoints[0]["url"]

        report = build_report(store, "run-1", tmp_path)
        finding = report["confirmed"][0]
        assert finding["vuln_class"] == "raw_html_reflection"
        evidence_path = tmp_path / "evidence" / "reflections" / f"{finding['id']}.json"
        assert evidence_path.is_file()
        assert finding["evidence"]["sha256"] == hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        rendered = render_markdown(report)
        assert "Oracle: paired_canary_get (control: distinct_marker)" in rendered
        assert str(evidence_path) in rendered
        assert "secretvalue" not in rendered
    finally:
        store.close()
