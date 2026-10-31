"""End-to-end hunt against the loopback lab simulator: proof, attack path, secrecy, scope and authorisation gates."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from mitigata.pipeline import HuntOptions, HuntRefused, run_hunt

from .lab_sim import BASIC_PASSWORD, FLAG, PASSKEY, LabSim, write_lab_manifest


def _report(run_dir: Path) -> dict:
    return json.loads((run_dir / "report.json").read_text(encoding="utf-8"))


def _run_dir(lab_run: dict) -> Path:
    return Path(lab_run["summary"]["run_dir"])


def test_hunt_completes_and_proves_every_lead_class(lab_run):
    summary = lab_run["summary"]
    assert summary["status"] == "complete", summary.get("errors")
    assert summary["enforcement"] == "host_guard_in_process"
    report = _report(_run_dir(lab_run))
    classes = {item["class"] for item in report["confirmed"]}
    assert {"default_credentials", "raw_html_reflection", "exposed_path", "passkey_protocol_auth",
            "information_disclosure_banner", "hardcoded_secret"} <= classes, sorted(classes)
    login = [item for item in report["confirmed"]
             if item["class"] == "default_credentials" and item["evidence"].get("surface") == "login_form"]
    assert login and login[0]["evidence"]["credential_source"] == "built-in default"
    basic = [item for item in report["confirmed"]
             if item["class"] == "default_credentials" and item["evidence"].get("surface") == "basic_auth"]
    assert basic and basic[0]["evidence"]["credential_source"] == "recovered literal"
    assert report["counts"]["scope_sent_outside"] == 0
    assert report["counts"]["flags"] == 1


def test_attack_path_chains_binary_to_secret_to_access_to_flag(lab_run):
    report = _report(_run_dir(lab_run))
    flag_paths = [path for path in report["attack_path"]["paths"] if path["kind"] == "flag"]
    assert flag_paths, report["attack_path"]["paths"]
    steps = flag_paths[0]["steps"]
    phases = [step["ptes_phase"] for step in steps]
    assert steps[0]["from"] == "Scoped operator" and "binary" in steps[0]["to"]
    assert "intelligence_gathering" == phases[0]
    assert phases[-1] == "post_exploitation"
    assert "exploitation" in phases and "vulnerability_analysis" in phases
    assert "recovered auth literal" in " ".join(step["to"] for step in steps)
    assert report["attack_path"]["mermaid"].startswith("flowchart LR")


def test_no_secret_value_or_flag_appears_outside_the_private_secret_file(lab_run):
    run_dir = _run_dir(lab_run)
    secret_values = [PASSKEY.encode(), BASIC_PASSWORD.encode(), FLAG.encode()]
    checked = []
    for path in run_dir.rglob("*"):
        if not path.is_file() or path.name == "secrets.json":
            continue
        if path.relative_to(run_dir).parts[:2] in {("evidence", "binaries"), ("evidence", "downloads")}:
            continue  # the supplied binary legitimately contains the passkey string; it is evidence input
        data = path.read_bytes()
        checked.append(path.name)
        for value in secret_values:
            assert value not in data, f"{value!r} leaked into {path.relative_to(run_dir)}"
    assert "report.json" in checked and "blackboard.db" in checked


def test_recovered_secrets_are_stored_privately_and_referenced_by_id(lab_run):
    run_dir = _run_dir(lab_run)
    secrets_file = run_dir / "secrets.json"
    assert stat.S_IMODE(os.stat(secrets_file).st_mode) == 0o600
    values = json.loads(secrets_file.read_text(encoding="utf-8"))
    assert PASSKEY in values.values()
    import sqlite3

    connection = sqlite3.connect(run_dir / "blackboard.db")
    refs = [row[0] for row in connection.execute("SELECT secret_ref FROM credentials")]
    connection.close()
    assert refs and all(ref in values for ref in refs)


def test_flag_value_is_masked_unless_the_private_copy_is_requested(lab_run):
    report = _report(_run_dir(lab_run))
    rendered = json.dumps(report)
    assert FLAG not in rendered
    assert "flag{lab_passkey_capt" not in rendered
    assert any(item["evidence"].get("flags_masked") for item in report["confirmed"])


def test_auth_tests_disabled_means_no_credential_is_submitted(tmp_path):
    with LabSim(tmp_path) as lab:
        manifest = write_lab_manifest(tmp_path / "scope.yaml", auth_tests=False)
        summary = run_hunt(HuntOptions(scope_path=manifest, out_dir=tmp_path / "runs",
                                       ports=",".join(str(p) for p in lab.ports.values()),
                                       full_scan=False, deadline_seconds=300,
                                       auth_hosts=["127.0.0.1"]))
    report = _report(Path(summary["run_dir"]))
    auth = [item for item in report["findings"] if item["class"] in ("default_credentials", "passkey_protocol_auth")]
    assert auth and all(item["state"] == "inconclusive" for item in auth)
    assert all("checks.auth_tests" in item["summary"] for item in auth)
    assert report["counts"]["flags"] == 0
    assert report["counts"]["confirmed"] >= 2  # reflection, exposure and banner still need no credentials


def test_attempt_cap_is_respected_per_account(tmp_path):
    with LabSim(tmp_path) as lab:
        manifest = write_lab_manifest(tmp_path / "scope.yaml", max_auth_attempts=1)
        summary = run_hunt(HuntOptions(scope_path=manifest, out_dir=tmp_path / "runs",
                                       ports=",".join(str(p) for p in lab.ports.values()),
                                       full_scan=False, deadline_seconds=300,
                                       auth_hosts=["127.0.0.1"]))
    report = _report(Path(summary["run_dir"]))
    auth = [item for item in report["findings"] if item["class"] == "default_credentials"]
    assert auth and all(item["state"] != "confirmed" for item in auth)
    # One attempt per account: the control consumes the only admin attempt, so admin:admin is never tried.
    assert all("default_password" not in item["evidence"] for item in auth)
    assert report["run"]["max_auth_attempts_per_account"] == 1
    assert report["counts"]["flags"] == 0


def test_closed_window_refuses_before_any_traffic_or_run_directory(tmp_path):
    manifest = write_lab_manifest(tmp_path / "scope.yaml", window="2020-01-01T00:00:00Z/2020-01-02T00:00:00Z")
    out = tmp_path / "runs"
    with pytest.raises(HuntRefused, match="window"):
        run_hunt(HuntOptions(scope_path=manifest, out_dir=out, ports="80", full_scan=False))
    assert not out.exists() or not any(out.iterdir())


def test_focus_host_outside_scope_is_refused_before_any_traffic(tmp_path):
    manifest = write_lab_manifest(tmp_path / "scope.yaml")
    out = tmp_path / "runs"
    with pytest.raises(HuntRefused, match="outside the authorised scope"):
        run_hunt(HuntOptions(scope_path=manifest, out_dir=out, focus=["10.10.5.7"], ports="80"))
    assert not out.exists() or not any(out.iterdir())


def test_credentials_are_only_tried_on_the_focus_or_named_auth_hosts(tmp_path):
    with LabSim(tmp_path) as lab:
        manifest = write_lab_manifest(tmp_path / "scope.yaml")
        # No focus and no --auth-hosts: the engine still discovers and reads the surfaces, but submits nothing.
        summary = run_hunt(HuntOptions(scope_path=manifest, out_dir=tmp_path / "runs",
                                       ports=",".join(str(p) for p in lab.ports.values()),
                                       full_scan=False, deadline_seconds=300))
    report = _report(Path(summary["run_dir"]))
    auth = [item for item in report["findings"] if item["class"] in ("default_credentials", "passkey_protocol_auth")]
    assert auth and all(item["state"] == "inconclusive" for item in auth)
    assert all(item["oracle"] == "outside the authentication host set" for item in auth)
    assert all("credential checks run only" in item["summary"] for item in auth)
    assert report["counts"]["flags"] == 0


def test_deadline_outside_the_supported_range_is_refused(tmp_path):
    manifest = write_lab_manifest(tmp_path / "scope.yaml")
    with pytest.raises(HuntRefused, match="deadline"):
        run_hunt(HuntOptions(scope_path=manifest, out_dir=tmp_path / "runs", ports="80", deadline_seconds=5))


def test_passkey_constant_matches_the_simulator_contract():
    # The e2e assertions rely on the simulator's banner advertising AUTH <passkey>.
    from .lab_sim import BANNER

    assert "AUTH <passkey>" in BANNER and PASSKEY and BASIC_PASSWORD != PASSKEY


def test_discovery_then_target_analyses_supplied_binary(tmp_path, monkeypatch):
    from mitigata.pipeline import orchestrator
    from mitigata.web.app import run_view
    from .lab_sim import build_binary

    build_binary(tmp_path / "binaries")
    manifest = write_lab_manifest(tmp_path / "scope.yaml")
    monkeypatch.setattr(orchestrator._Hunt, "stage_discovery", lambda self: None)
    monkeypatch.setattr(orchestrator._Hunt, "_analyze_binary",
                        lambda self, result: (result["literals"], None, {"tool": None, "status": "stubbed", "errors": []}))
    out = tmp_path / "runs"
    discovery = orchestrator.run_discovery(HuntOptions(scope_path=manifest, out_dir=out, deadline_seconds=300))
    observed = []
    original_queue = orchestrator._Hunt._queue_binaries
    def inspect_target(hunt):
        view = run_view(out, hunt.run_id)
        observed.append((view["mode"], view["run"]["status"]))
        original_queue(hunt)
    monkeypatch.setattr(orchestrator._Hunt, "_queue_binaries", inspect_target)
    result = orchestrator.run_target(HuntOptions(scope_path=manifest, out_dir=out, run_id=discovery["run_id"],
                                                  focus=["127.0.0.1"], full_scan=False, deadline_seconds=300))
    report = _report(Path(result["run_dir"]))
    assert report["binaries"]
    assert report["counts"]["secrets_recovered"] > 0
    assert observed == [("target", "running")]


def test_target_refuses_a_changed_manifest_even_if_ip_range_is_unchanged(tmp_path, monkeypatch):
    from mitigata.pipeline import orchestrator

    manifest = write_lab_manifest(tmp_path / "scope.yaml")
    monkeypatch.setattr(orchestrator._Hunt, "stage_discovery", lambda self: None)
    out = tmp_path / "runs"
    discovery = orchestrator.run_discovery(HuntOptions(scope_path=manifest, out_dir=out, deadline_seconds=300))
    manifest.write_text(manifest.read_text() + "\n# changed\n")
    with pytest.raises(HuntRefused, match="manifest changed"):
        orchestrator.run_target(HuntOptions(scope_path=manifest, out_dir=out, run_id=discovery["run_id"],
                                            focus=["127.0.0.1"], full_scan=False, deadline_seconds=300))


def test_credentials_from_readable_page_content_are_verified_like_any_literal(lab_run):
    report = _report(_run_dir(lab_run))
    notes = [item for item in report["findings"]
             if item["class"] == "hardcoded_secret" and "/notes.html" in item["target"]]
    assert notes, [item["target"] for item in report["findings"]]
    assert notes[0]["state"] == "confirmed"
    basic = [item for item in report["confirmed"]
             if item["class"] == "default_credentials" and item["evidence"].get("surface") == "basic_auth"]
    assert basic and basic[0]["evidence"]["credential_source"] == "recovered literal"


def test_full_range_sweep_finds_a_service_outside_the_top_ports(tmp_path):
    import sqlite3

    with LabSim(tmp_path) as lab:
        manifest = write_lab_manifest(tmp_path / "scope.yaml", auth_tests=False)
        passkey_port = lab.ports["passkey"]
        summary = run_hunt(HuntOptions(scope_path=manifest, out_dir=tmp_path / "runs", focus=["127.0.0.1"],
                                       top_ports=100, full_scan=True, deadline_seconds=600))
    run_dir = Path(summary["run_dir"])
    connection = sqlite3.connect(run_dir / "blackboard.db")
    services = {(row[0], row[1]) for row in connection.execute("SELECT port, source FROM services")}
    chunks_done = connection.execute("SELECT COUNT(*) FROM events WHERE type='full_range.completed'").fetchone()[0]
    connection.close()
    assert (passkey_port, "nmap-full") in services, sorted(services)
    assert chunks_done == 4
    report = _report(run_dir)
    assert any(item["class"] == "passkey_protocol_auth" for item in report["findings"])
    assert report["counts"]["flags"] == 0  # auth tests were off, so no passkey was submitted


def test_discovery_then_target_scan_runs_the_whole_flow(tmp_path):
    import sqlite3

    from mitigata.pipeline import tools
    from mitigata.pipeline.orchestrator import run_discovery, run_target

    with LabSim(tmp_path) as lab:
        passkey_port = lab.ports["passkey"]
        manifest = write_lab_manifest(tmp_path / "scope.yaml")
        out = tmp_path / "runs"
        discovery = run_discovery(HuntOptions(scope_path=manifest, out_dir=out, top_ports=100, deadline_seconds=300))
        assert discovery["status"] == "discovered"
        assert discovery["alive_hosts"] and discovery["alive_hosts"][0]["ip"] == "127.0.0.1"
        target = run_target(HuntOptions(scope_path=manifest, out_dir=out, run_id=discovery["run_id"],
                                        focus=["127.0.0.1"], deadline_seconds=900))
    assert target["run_id"] == discovery["run_id"]
    assert target["status"] in ("complete", "partial"), target.get("errors")
    run_dir = Path(target["run_dir"])
    report = _report(run_dir)
    assert report["run"]["mode"] == "target"
    tools_used = {row["key"]: row["used"] for row in report["run"]["tools"]}
    assert tools_used["nmap"] is True
    if tools.find("katana") is not None:
        assert tools_used["katana"] is True
    decompiler = "ghidra" if tools.find("analyzeHeadless") is not None else ("radare2" if tools.find("r2") else None)
    if decompiler is not None:
        assert tools_used[decompiler] is True
        connection = sqlite3.connect(run_dir / "blackboard.db")
        tool_rows = connection.execute("SELECT payload_json FROM evidence WHERE type='decompile'").fetchall()
        connection.close()
        assert tool_rows and all(json.loads(row[0])["tool"] == decompiler for row in tool_rows)
    # Other simulators can still be listening on this machine during the suite, and each passkey service presents
    # the same flag, so assert on this test's own passkey port rather than on a global count.
    assert report["counts"]["flags"] >= 1
    confirmed = [item for item in report["findings"] if item["class"] == "passkey_protocol_auth" and item["state"] == "confirmed"]
    assert any(f":{passkey_port}" in item["target"] for item in confirmed), [item["target"] for item in confirmed]
    connection = sqlite3.connect(run_dir / "blackboard.db")
    status = connection.execute("SELECT status FROM runs WHERE id=?", (discovery["run_id"],)).fetchone()[0]
    sources = {row[0] for row in connection.execute("SELECT source FROM services")}
    connection.close()
    assert status == target["status"]
    assert "nmap-full" in sources


def test_target_explicit_ports_skips_the_full_sweep(tmp_path):
    import sqlite3

    from mitigata.pipeline.orchestrator import run_discovery, run_target

    with LabSim(tmp_path) as lab:
        manifest = write_lab_manifest(tmp_path / "scope.yaml")
        out = tmp_path / "runs"
        discovery = run_discovery(HuntOptions(scope_path=manifest, out_dir=out, top_ports=10,
                                              deadline_seconds=300))
        ports = ",".join(str(port) for port in (lab.ports["basic"], lab.ports["passkey"]))
        result = run_target(HuntOptions(
            scope_path=manifest, out_dir=out, run_id=discovery["run_id"], focus=["127.0.0.1"],
            ports=ports, full_scan=False, deadline_seconds=300,
        ))

    assert result["status"] in ("complete", "partial"), result.get("errors")
    run_dir = Path(result["run_dir"])
    connection = sqlite3.connect(run_dir / "blackboard.db")
    found = {row[0] for row in connection.execute("SELECT port FROM services")}
    connection.close()
    assert {lab.ports["basic"], lab.ports["passkey"]} <= found, sorted(found)
    report = _report(run_dir)
    passkey = [item for item in report["confirmed"] if item["class"] == "passkey_protocol_auth"]
    assert any(f":{lab.ports['passkey']}" in item["target"] for item in passkey), passkey


def test_passkey_zone_pidreq_captures_the_flag(tmp_path):
    with LabSim(tmp_path, zone_mode=True) as lab:
        manifest = write_lab_manifest(tmp_path / "scope.yaml")
        summary = run_hunt(HuntOptions(
            scope_path=manifest, out_dir=tmp_path / "runs", focus=["127.0.0.1"],
            ports=str(lab.ports["passkey"]), full_scan=False, deadline_seconds=300,
        ))

    assert summary["status"] in ("complete", "partial"), summary.get("errors")
    report = _report(Path(summary["run_dir"]))
    assert report["counts"]["flags"] == 1
    passkey = [item for item in report["confirmed"] if item["class"] == "passkey_protocol_auth"]
    assert passkey and "PIDREQ" in passkey[0]["summary"], passkey


def test_target_refuses_an_ip_outside_scope_and_an_unknown_run(tmp_path):
    from mitigata.pipeline.orchestrator import run_discovery, run_target

    with LabSim(tmp_path) as lab:
        manifest = write_lab_manifest(tmp_path / "scope.yaml")
        discovery = run_discovery(HuntOptions(scope_path=manifest, out_dir=tmp_path / "runs", top_ports=10,
                                              deadline_seconds=120))
        with pytest.raises(HuntRefused, match="outside the authorised scope"):
            run_target(HuntOptions(scope_path=manifest, out_dir=tmp_path / "runs", run_id=discovery["run_id"],
                                   focus=["10.10.5.7"]))
        with pytest.raises(HuntRefused, match="does not exist"):
            run_target(HuntOptions(scope_path=manifest, out_dir=tmp_path / "runs", run_id="run-missing-1",
                                   focus=["127.0.0.1"]))
        assert lab.ports  # the simulator stayed up for the whole test
