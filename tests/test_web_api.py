"""Local API and dashboard: loopback guards, token-protected hunt start, flow data without secret values."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mitigata.web import create_app

from .lab_sim import FLAG, PASSKEY

PORT = 8765
LOCAL = {"Host": f"127.0.0.1:{PORT}"}
TOKEN = "test-token-123"
FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


@pytest.fixture
def client(lab_run):
    app = create_app(out_dir=lab_run["out"], scope_path=lab_run["manifest"], port=PORT, token=TOKEN)
    return TestClient(app)


@pytest.fixture
def run_id(lab_run):
    return lab_run["summary"]["run_id"]


def test_dashboard_is_served_to_the_local_host_with_a_strict_csp(client):
    response = client.get("/", headers=LOCAL)
    assert response.status_code == 200
    assert "MITIGATA" in response.text
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "default-src 'none'" in csp
    assert response.headers["x-frame-options"] == "DENY"
    assert client.get("/app.js", headers=LOCAL).status_code == 200
    assert client.get("/style.css", headers=LOCAL).status_code == 200


def test_requests_from_other_hosts_origins_or_sites_are_refused(client):
    assert client.get("/api/status", headers={"Host": "evil.example"}).status_code == 403
    assert client.get("/api/status", headers={**LOCAL, "Origin": "http://evil.example"}).status_code == 403
    assert client.get("/api/status", headers={**LOCAL, "Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.get("/api/status", headers={**LOCAL, "Origin": f"http://localhost:{PORT}"}).status_code == 200


def test_status_reports_scope_and_hands_the_token_only_to_the_local_dashboard(client):
    body = client.get("/api/status", headers=LOCAL).json()
    assert body["scope"]["state"] == "valid"
    assert body["scope"]["allowlist"] == ["127.0.0.1/32"]
    assert body["action_token"] == TOKEN
    assert body["enforcement"] == "host_guard_in_process"
    tools = {row["key"]: row["installed"] for row in body["tools"]}
    assert set(tools) == {"nmap", "katana", "ffuf", "radare2", "ghidra"}
    assert isinstance(tools["nmap"], bool)


def test_status_exposes_scope_limits_for_target_controls(tmp_path):
    from .lab_sim import write_lab_manifest

    manifest = write_lab_manifest(tmp_path / "scope.yaml", auth_tests=False)
    manifest.write_text(manifest.read_text().replace(
        "checks:\n", 'checks:\n  include: ["network.*"]\n  exclude: ["*.fuzz"]\n'))
    app = create_app(out_dir=tmp_path / "runs", scope_path=manifest, port=PORT, token=TOKEN)
    scope = TestClient(app).get("/api/status", headers=LOCAL).json()["scope"]
    assert scope["auth_tests"] is False
    assert scope["web_inventory"] is False
    assert scope["fuzz_allowed"] is False


def test_hunt_start_requires_the_token(client):
    assert client.post("/api/hunt", headers=LOCAL, json={}).status_code == 403
    assert client.post("/api/hunt", headers={**LOCAL, "X-Mitigata-Token": "wrong"}, json={}).status_code == 403


def test_target_request_carries_explicit_ports_and_auth_hosts():
    from mitigata.web.app import TargetRequest

    request = TargetRequest(ip="127.0.0.1", ports="80,1111", auth_hosts=["127.0.0.1"], full_scan=False)
    assert request.ports == "80,1111"
    assert request.auth_hosts == ["127.0.0.1"]
    assert request.full_scan is False
    with pytest.raises(ValueError):
        TargetRequest(ip="127.0.0.1", auth_hosts=["not-an-ip"])


def test_hunt_start_validates_focus_addresses_before_anything_runs(client):
    response = client.post("/api/hunt", headers={**LOCAL, "X-Mitigata-Token": TOKEN},
                           json={"focus": ["not-an-address"]})
    assert response.status_code == 422


def test_hunt_outside_scope_is_refused_by_the_job_and_creates_no_run(lab_run):
    app = create_app(out_dir=lab_run["out"], scope_path=lab_run["manifest"], port=PORT, token=TOKEN)
    client = TestClient(app)
    before = {item["id"] for item in client.get("/api/runs", headers=LOCAL).json()["runs"]}
    response = client.post("/api/hunt", headers={**LOCAL, "X-Mitigata-Token": TOKEN},
                           json={"focus": ["10.10.5.7"], "deadline_seconds": 300})
    assert response.status_code == 202
    state = {}
    for _ in range(100):
        state = client.get("/api/job", headers=LOCAL).json()
        if state.get("state") in ("refused", "error", "done"):
            break
        time.sleep(0.05)
    assert state["state"] == "refused" and "outside the authorised scope" in state["error"]
    after = {item["id"] for item in client.get("/api/runs", headers=LOCAL).json()["runs"]}
    assert after == before


def test_hunt_without_a_scope_manifest_is_unavailable(lab_run):
    app = create_app(out_dir=lab_run["out"], scope_path=None, port=PORT, token=TOKEN)
    response = TestClient(app).post("/api/hunt", headers={**LOCAL, "X-Mitigata-Token": TOKEN}, json={})
    assert response.status_code == 400


def test_run_listing_and_detail_expose_the_flow_but_never_secret_values(client, run_id):
    runs = client.get("/api/runs", headers=LOCAL).json()["runs"]
    assert any(item["id"] == run_id and item["status"] == "complete" for item in runs)
    response = client.get(f"/api/runs/{run_id}", headers=LOCAL)
    assert response.status_code == 200
    body = response.json()
    for key in ("run", "counts", "stages", "agents", "hosts", "candidates", "credentials", "flags",
                "attack_path", "events", "reports", "scope", "coverage"):
        assert key in body, key
    assert body["counts"]["confirmed"] >= 6 and body["counts"]["flags"] == 1
    assert {"discovery-agent", "web-agent", "network-agent", "binary-agent"} <= {a["agent"] for a in body["agents"]}
    assert all(item["secret_ref"].startswith("cred-") for item in body["credentials"])
    raw = response.text
    assert PASSKEY not in raw and FLAG not in raw and "flag{lab_passkey_capt" not in raw


def test_report_downloads_are_limited_to_known_formats(client, run_id):
    assert client.get(f"/api/runs/{run_id}/report/md", headers=LOCAL).status_code == 200
    assert client.get(f"/api/runs/{run_id}/report/json", headers=LOCAL).headers["content-type"].startswith("application/json")
    assert client.get(f"/api/runs/{run_id}/report/exe", headers=LOCAL).status_code == 404
    assert client.get(f"/api/runs/{run_id}/report/md", headers=LOCAL).text.startswith("# MITIGATA hunt report")
    assert client.get("/api/runs/..%2F..%2Fetc/report/md", headers=LOCAL).status_code == 404
    assert client.get("/api/runs/run-does-not-exist", headers=LOCAL).status_code == 404
    assert client.get("/api/runs/bad$id", headers=LOCAL).status_code == 404


def test_attack_path_is_available_as_json_and_mermaid(client, run_id):
    path = client.get(f"/api/runs/{run_id}/report/attack-path", headers=LOCAL).json()
    assert any(item["kind"] == "flag" for item in path["paths"])
    mermaid = client.get(f"/api/runs/{run_id}/report/mermaid", headers=LOCAL)
    assert mermaid.status_code == 200 and mermaid.text.startswith("flowchart LR")


def test_targets_and_per_target_findings_follow_the_prd_route(client, run_id):
    targets = client.get("/targets", headers=LOCAL, params={"run_id": run_id}).json()
    assert targets["run_id"] == run_id and targets["targets"]
    asset_id = targets["targets"][0]["asset_id"]
    findings = client.get(f"/targets/{asset_id}/findings", headers=LOCAL, params={"run_id": run_id}).json()
    assert findings["asset_id"] == asset_id
    assert findings["findings"] and all("class" in item and "state" in item for item in findings["findings"])
    assert client.get("/targets/999999/findings", headers=LOCAL, params={"run_id": run_id}).status_code == 404


def test_findings_default_to_the_newest_run(client, run_id):
    body = client.get("/findings", headers=LOCAL).json()
    assert body["run_id"] == run_id
    assert any(item["state"] == "confirmed" for item in body["findings"])


def test_frontend_has_no_inline_script_or_style_so_the_csp_holds():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert "style=" not in html
    assert not re.search(r"\son[a-z]+=", html)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_dashboard_script_parses():
    result = subprocess.run(["node", "--check", str(FRONTEND / "app.js")], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


def test_discover_and_target_need_the_token_and_a_valid_address(client, run_id):
    headers = {**LOCAL, "X-Mitigata-Token": TOKEN}
    assert client.post("/api/discover", headers=LOCAL, json={}).status_code == 403
    assert client.post(f"/api/runs/{run_id}/target", headers=LOCAL, json={"ip": "127.0.0.1"}).status_code == 403
    assert client.post(f"/api/runs/{run_id}/target", headers=headers, json={"ip": "999.1.1.1"}).status_code == 422
    assert client.post("/api/runs/run-missing-1/target", headers=headers, json={"ip": "127.0.0.1"}).status_code == 404


def test_run_detail_carries_mode_tools_and_the_full_stage_history(client, run_id):
    body = client.get(f"/api/runs/{run_id}", headers=LOCAL).json()
    assert body["mode"] in ("hunt", "target", "discover")
    assert {row["key"] for row in body["tools"]} == {"nmap", "katana", "ffuf", "radare2", "ghidra"}
    assert len(body["stages"]) >= 5  # read from the whole history, not from the 200 newest events
    assert body["current_stage"] is None


def test_discover_range_is_checked_against_the_manifest_before_anything_runs(client):
    headers = {**LOCAL, "X-Mitigata-Token": TOKEN}
    refused = client.post("/api/discover", headers=headers, json={"range": "10.9.9.0/30"})
    assert refused.status_code == 422 and "outside the manifest scope" in refused.json()["error"]
    malformed = client.post("/api/discover", headers=headers, json={"range": "not-a-range"})
    assert malformed.status_code == 422
