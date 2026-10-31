from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def manifest_doc(**overrides) -> dict:
    doc = {
        "engagement": {
            "name": "e2e-lab",
            "tier": "recon",
            "authorised_by": "test harness",
            "window": "2020-01-01T00:00:00Z/2035-01-01T00:00:00Z",
            "description": "cli e2e",
        },
        "scope": {
            "ipv4": ["10.10.5.0/24"],
            "ipv6": [],
            "domains": [],
            "exclude": ["10.10.5.1", "10.10.5.255"],
            "binaries": ["binaries/*"],
            "allow_public": False,
            "dns_resolver": "10.10.5.53",
        },
        "limits": {"max_rate_pps": 500},
        "checks": {"include": ["binary.*"], "exclude": ["*.fuzz"]},
        "flags": {"patterns": [r"flag\{[^}]+\}"]},
        "crown_jewel": {"hosts": [], "services": []},
        "report": {"formats": ["md", "html", "json"], "redact_secrets": True, "include_flags": False},
    }
    doc.update(overrides)
    return doc


def write_scope(tmp_path: Path, *, window: str | None = None, ipv4: list[str] | None = None) -> Path:
    doc = manifest_doc()
    if window:
        doc["engagement"]["window"] = window
    if ipv4:
        doc["scope"]["ipv4"] = ipv4
    (tmp_path / "binaries").mkdir(exist_ok=True)
    (tmp_path / "binaries" / "vulnbin").write_bytes(b"\x7fELF" + b"\x00" * 96)
    path = tmp_path / "scope.yaml"
    import yaml

    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "mitigata", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_run_produces_all_reports_and_a_valid_blackboard(tmp_path):
    scope = write_scope(tmp_path)
    out = tmp_path / "runs"
    result = cli("run", "--scope", str(scope), "--out", str(out), "--profile", "no-target")
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["status"] == "complete"
    assert summary["enforcement"] == "not_required_no_workers"
    assert len(summary["reports"]) == 3

    run_dir = out / summary["run_id"]
    markdown = (run_dir / "report.md").read_text(encoding="utf-8")
    assert summary["scope_hash"] in markdown
    assert "- **Status:** complete" in markdown
    assert "10.10.5.0/24" in markdown
    assert "None. No candidate reached" in markdown
    assert "0 sent outside scope" in markdown
    assert "<html" in (run_dir / "report.html").read_text(encoding="utf-8")
    report_json = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report_json["counts"]["confirmed"] == 0
    assert report_json["scope"]["scope_hash"] == summary["scope_hash"]

    # The orchestrator snapshot and the blackboard are both present.
    assert (run_dir / "scope.manifest.yaml").is_file()
    conn = sqlite3.connect(run_dir / "blackboard.db")
    try:
        types = {row[0] for row in conn.execute("SELECT type FROM events")}
        assert {"run.started", "scope.compiled", "scope.audit", "run.finalizing", "report.ready"} <= types
        assert conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] == 0
        # The preflight worker must never create network-facing rows.
        assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    finally:
        conn.close()


def test_preflight_command_reports_the_scope_hash(tmp_path):
    scope = write_scope(tmp_path)
    result = cli("preflight", "--scope", str(scope))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert len(payload["scope_hash"]) == 64
    assert payload["allowlist"] == ["10.10.5.0/24"]
    assert payload["exclude"] == ["10.10.5.1/32", "10.10.5.255/32"]
    assert payload["block_ipv6"] is True
    assert payload["binaries"][0]["path"].endswith("vulnbin")


def test_scope_show_classifies_literals(tmp_path):
    scope = write_scope(tmp_path)
    result = cli(
        "scope",
        "show",
        "--scope",
        str(scope),
        "--classify",
        "10.10.5.42",
        "--classify",
        "10.10.5.1",
        "--classify",
        "8.8.8.8",
    )
    assert result.returncode == 0, result.stderr
    assert "10.10.5.42 -> in_scope" in result.stdout
    assert "10.10.5.1 -> excluded" in result.stdout
    assert "8.8.8.8 -> out_of_scope" in result.stdout


def test_expired_window_is_refused_without_a_report(tmp_path):
    scope = write_scope(tmp_path, window="2020-01-01T00:00:00Z/2020-02-01T00:00:00Z")
    out = tmp_path / "runs"
    result = cli("run", "--scope", str(scope), "--out", str(out), "--profile", "no-target")
    assert result.returncode == 3
    assert "engagement window" in result.stderr
    run_dirs = list(out.iterdir())
    assert len(run_dirs) == 1
    assert not list(run_dirs[0].glob("report.*"))
    conn = sqlite3.connect(run_dirs[0] / "blackboard.db")
    try:
        status = conn.execute("SELECT status FROM runs").fetchone()[0]
        assert status == "refused"
    finally:
        conn.close()


def test_unsafe_scope_is_rejected_before_any_run(tmp_path):
    scope = write_scope(tmp_path, ipv4=["93.184.216.0/24"])
    result = cli("run", "--scope", str(scope), "--out", str(tmp_path / "runs"), "--profile", "no-target")
    assert result.returncode == 2
    assert "allow_public" in result.stderr
    assert not (tmp_path / "runs").exists()


def test_enforce_profile_requires_a_worker_namespace(tmp_path):
    scope = write_scope(tmp_path)
    result = cli("run", "--scope", str(scope), "--out", str(tmp_path / "runs"), "--profile", "enforce")
    assert result.returncode == 2
    assert "--netns is required" in result.stderr
    assert not (tmp_path / "runs").exists()


def test_no_target_profile_refuses_a_worker_namespace(tmp_path):
    scope = write_scope(tmp_path)
    result = cli(
        "run", "--scope", str(scope), "--out", str(tmp_path / "runs"),
        "--profile", "no-target", "--netns", "mitigata0",
    )
    assert result.returncode == 2
    assert "--netns is illegal" in result.stderr
    assert not (tmp_path / "runs").exists()
