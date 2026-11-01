"""Deleting a past run: token-protected, identifier-checked, and its attempt counts stay in the engagement ledger."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mitigata.pipeline import HuntOptions, engagement, run_hunt
from mitigata.web import create_app

from .lab_sim import LabSim, write_lab_manifest

PORT = 8765
LOCAL = {"Host": f"127.0.0.1:{PORT}"}
TOKEN = "delete-test-token"


@pytest.fixture(scope="module")
def own_run(tmp_path_factory):
    """A dedicated lab hunt: deleting it must not disturb the runs other API tests share."""
    work = tmp_path_factory.mktemp("delete-lab")
    out = tmp_path_factory.mktemp("delete-runs")
    with LabSim(work) as lab:
        manifest = write_lab_manifest(work / "scope.yaml")
        ports = ",".join(str(port) for port in lab.ports.values())
        summary = run_hunt(HuntOptions(scope_path=manifest, out_dir=out, ports=ports, full_scan=False,
                                       deadline_seconds=300, auth_hosts=["127.0.0.1"]))
    yield {"run_id": summary["run_id"], "out": out, "manifest": manifest}


@pytest.fixture
def client(own_run):
    return TestClient(create_app(out_dir=own_run["out"], scope_path=own_run["manifest"], port=PORT, token=TOKEN))


def test_delete_needs_the_token(client, own_run):
    response = client.delete(f"/api/runs/{own_run['run_id']}", headers=LOCAL)
    assert response.status_code == 403
    assert (own_run["out"] / own_run["run_id"]).is_dir()


def test_delete_refuses_anything_that_is_not_a_run_identifier(client):
    response = client.delete("/api/runs/..%2Fetc", headers={**LOCAL, "X-Mitigata-Token": TOKEN})
    assert response.status_code in (404, 422)


def test_deleting_a_finished_run_removes_its_files_and_keeps_its_attempts(client, own_run):
    out, run_id = own_run["out"], own_run["run_id"]
    before = engagement.engagement_state(out).attempts
    assert before, "the lab hunt should have recorded credential attempts for the ledger to keep"
    response = client.delete(f"/api/runs/{run_id}", headers={**LOCAL, "X-Mitigata-Token": TOKEN})
    assert response.status_code == 200 and response.json()["deleted"] == run_id
    assert not (out / run_id).exists()
    assert client.get(f"/api/runs/{run_id}", headers=LOCAL).status_code == 404
    assert engagement.engagement_state(out).attempts == before  # the cap cannot be reset by deleting
    assert (out / engagement.LEDGER_NAME).is_file()
    again = client.delete(f"/api/runs/{run_id}", headers={**LOCAL, "X-Mitigata-Token": TOKEN})
    assert again.status_code == 404
