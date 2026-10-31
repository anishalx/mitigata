"""Forwarded-header chain on the loopback simulator, plus unit checks for the hint and header helpers.

Everything here targets 127.0.0.1 only. The real passkey and flag never appear in these tests.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from mitigata.pipeline import solver, tools, web_agent

from .chain_lab import CORE_ROUTER, TRUST_HEADER, UNTRUSTED_VALUE, ChainLab, build_computed, write_chain_manifest
from .lab_sim import FLAG, write_lab_manifest

HAS_GCC = shutil.which("gcc") is not None
HAS_ANGR = solver.available()


def test_hint_paths_turn_vocabulary_words_and_path_tokens_into_origin_relative_probes():
    text = "Staged artifacts live in the artifact vault. Notes are under /ops/notes/ and and/or stays put."
    paths = web_agent.hint_paths(text, known=set(), limit=10)
    assert "/vault/" in paths
    assert "/notes/" in paths  # "notes" is in the vendored list, so it is a hint word
    assert "/ops/notes/" in paths  # a path token printed by the target
    # "artifact" is not in the vendored list, so it is not a hint word: every hint word must be a real list entry
    assert "/artifact/" not in paths and "/artifacts/" not in paths
    assert not any(path.startswith("/or") for path in paths)  # "and/or" is not a path token
    assert len(web_agent.hint_paths(text, known=set(), limit=2)) == 2


def test_hint_paths_skip_known_paths_and_state_changing_names():
    paths = web_agent.hint_paths("the vault and /vault/ and /logout/", known={"/vault/"}, limit=10)
    assert "/vault/" not in paths
    assert "/logout/" not in paths


def test_hint_ipv4_keeps_addresses_and_drops_unspecified_and_broadcast():
    text = "forwarded only from the core router 10.44.0.1; also 0.0.0.0, 255.255.255.255 and 300.1.1.1"
    assert web_agent.hint_ipv4(text) == ["10.44.0.1"]


def test_hint_header_names_match_case_insensitively_in_canonical_form():
    assert web_agent.hint_header_names("it checks the x-forwarded-for header") == ["X-Forwarded-For"]
    assert web_agent.hint_header_names("nothing relevant here") == []


def test_vocabulary_is_the_vendored_seclists_subset_and_contains_vault():
    words = web_agent.vocabulary()
    assert "vault" in words
    assert words <= web_agent.HINT_WORDS
    vendored = Path(web_agent.WORDLIST_PATH)
    assert vendored.is_file()
    assert "vault" in {line.strip() for line in vendored.read_text(encoding="utf-8").splitlines()}


@pytest.mark.skipif(not HAS_GCC, reason="needs gcc to build the lab binary")
def test_trusted_header_probe_reveals_the_trusted_value_and_stops_there(tmp_path):
    with ChainLab(tmp_path) as lab:
        port = lab.ports["web"]
        result = web_agent.trusted_header_probe(
            "127.0.0.1", port, tls=False, guard=None, path="/", names=[TRUST_HEADER, "X-Real-IP"],
            values=["127.0.0.1", CORE_ROUTER], control_value=UNTRUSTED_VALUE, max_requests=30,
        )
    assert result["control"]["status"] == 502
    assert result["revealed"]["header"] == TRUST_HEADER
    assert result["revealed"]["value"] == CORE_ROUTER
    assert result["revealed"]["status"] == 200
    assert result["requests"] == 3  # control, the loopback guess (502), the trusted value (200)


@pytest.mark.skipif(not HAS_GCC, reason="needs gcc to build the lab binary")
def test_header_probe_respects_the_request_cap(tmp_path):
    with ChainLab(tmp_path) as lab:
        result = web_agent.trusted_header_probe(
            "127.0.0.1", lab.ports["web"], tls=False, guard=None, path="/", names=[TRUST_HEADER],
            values=["127.0.0.1", "10.0.0.1"], control_value=UNTRUSTED_VALUE, max_requests=2,
        )
    assert result["requests"] <= 2
    assert result["revealed"] is None


@pytest.mark.skipif(not HAS_GCC, reason="needs gcc to build the lab binary")
def test_binary_analysis_outcome_is_visible_when_the_analysers_are_missing(tmp_path, monkeypatch):
    from mitigata.pipeline import orchestrator
    from mitigata.web.app import run_view

    build_computed(tmp_path / "binaries")
    manifest = write_lab_manifest(tmp_path / "scope.yaml")
    real_find = tools.find
    monkeypatch.setattr(tools, "find", lambda name: None if name in {"analyzeHeadless", "r2", "radare2"} else real_find(name))
    monkeypatch.setattr(orchestrator._Hunt, "stage_discovery", lambda self: None)
    out = tmp_path / "runs"
    discovery = orchestrator.run_discovery(orchestrator.HuntOptions(scope_path=manifest, out_dir=out, deadline_seconds=120))
    orchestrator.run_target(orchestrator.HuntOptions(scope_path=manifest, out_dir=out, run_id=discovery["run_id"],
                                                     focus=["127.0.0.1"], ports="1", full_scan=False,
                                                     deadline_seconds=120))
    view = run_view(out, discovery["run_id"])
    assert len(view["binaries"]) == 1
    details = view["binaries"][0]["details"]
    assert details["analysis"]["status"] == "not_installed"
    assert details["analysis"]["tool"] is None
    assert details["protections"]["class"] == "ELF64"
    assert details["literal_count"] == 0


@pytest.mark.skipif(not (HAS_GCC and HAS_ANGR), reason="needs gcc and angr (optional solver dependency)")
def test_forwarded_header_chain_is_discovered_end_to_end(tmp_path, monkeypatch):
    from mitigata.pipeline import orchestrator
    from mitigata.web.app import run_view

    out = tmp_path / "runs"
    with ChainLab(tmp_path / "lab") as lab:
        manifest = write_chain_manifest(tmp_path / "lab" / "scope.yaml")
        ports = lab.ports
        monkeypatch.setattr(orchestrator._Hunt, "stage_discovery", lambda self: None)
        discovery = orchestrator.run_discovery(orchestrator.HuntOptions(scope_path=manifest, out_dir=out,
                                                                        deadline_seconds=300))
        result = orchestrator.run_target(orchestrator.HuntOptions(
            scope_path=manifest, out_dir=out, run_id=discovery["run_id"], focus=["127.0.0.1"],
            ports=f"{ports['web']},{ports['passkey']}", full_scan=False, deadline_seconds=900))
    view = run_view(out, discovery["run_id"])
    bypass = [item for item in view["candidates"] if item["class"] == "trusted_header_bypass"]
    assert bypass and bypass[0]["state"] == "confirmed"
    assert any(item["details"]["analysis"]["status"] == "analyzed" for item in view["binaries"])
    kinds = {row["kind"]: row for row in view["lineage"]}
    assert "header_trust_probe" in kinds and kinds["header_trust_probe"]["parent_task_id"]
    assert any(row["kind"] == "triage_binary" and row["parent_task_id"] for row in view["lineage"])
    assert view["counts"]["flags"] >= 1
    report = Path(result["run_dir"], "report.md").read_text(encoding="utf-8")
    assert FLAG not in report
