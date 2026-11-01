"""The private view: recovered literal values are returned only when the server runs with --reveal-recovered."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from mitigata.web import create_app

from .lab_sim import PASSKEY

LOCAL = {"Host": "127.0.0.1:8765"}
FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


def _client(lab_run, reveal):
    app = create_app(out_dir=lab_run["out"], scope_path=lab_run["manifest"], port=8765, token="view-token",
                     reveal_recovered=reveal)
    return TestClient(app)


def test_recovered_values_are_not_returned_by_default(lab_run):
    run_id = lab_run["summary"]["run_id"]
    client = _client(lab_run, reveal=False)
    detail = client.get(f"/api/runs/{run_id}", headers=LOCAL)
    assert detail.status_code == 200
    assert PASSKEY not in detail.text
    assert "recovered" not in detail.json()
    assert client.get("/api/status", headers=LOCAL).json()["reveal_recovered"] is False


def test_the_private_view_returns_the_values_and_reports_still_do_not(lab_run):
    run_id = lab_run["summary"]["run_id"]
    client = _client(lab_run, reveal=True)
    recovered = client.get(f"/api/runs/{run_id}", headers=LOCAL).json()["recovered"]
    assert PASSKEY in [entry["value"] for entry in recovered]
    assert client.get("/api/status", headers=LOCAL).json()["reveal_recovered"] is True
    assert PASSKEY not in client.get(f"/api/runs/{run_id}/report/json", headers=LOCAL).text
    assert PASSKEY not in client.get(f"/api/runs/{run_id}/report/md", headers=LOCAL).text


def test_the_binary_panel_keeps_the_values_behind_a_click():
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")
    assert "Recovered value (private view, click to show)" in script
    assert 'class="private"' in script
    assert "private view: recovered values shown" in script
