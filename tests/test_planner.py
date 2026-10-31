"""Planner tests: DeepSeek request shape, validation, redaction and key handling. No network: transports are fakes."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from mitigata.models import LLMSection
from mitigata.pipeline import planner

from .chain_lab import CORE_ROUTER, ChainLab, write_chain_manifest

FAKE_KEY = "sk-test-not-a-real-key-0001"
HAS_GCC = shutil.which("gcc") is not None


def _reply(content: dict) -> bytes:
    return json.dumps({"choices": [{"message": {"content": json.dumps(content)}}]}).encode("utf-8")


def test_redact_masks_flags_and_credential_pairs():
    text = "password: hunter2 and token=abc123 and MITIGATA{x_y_z} plus flag{lab}"
    out = planner.redact(text)
    for secret in ("hunter2", "abc123", "MITIGATA{", "flag{lab}"):
        assert secret not in out
    assert "[redacted-flag]" in out


def test_planner_is_off_by_default_and_needs_the_environment_key():
    assert planner.build_planner(LLMSection(), {})[0] is None
    enabled = LLMSection(enabled=True)
    missing, reason = planner.build_planner(enabled, {})
    assert missing is None and "DEEPSEEK_API_KEY" in reason
    ready, reason = planner.build_planner(enabled, {"DEEPSEEK_API_KEY": FAKE_KEY})
    assert isinstance(ready, planner.DeepSeekPlanner) and reason == "ready"


def test_planner_endpoint_must_be_https():
    with pytest.raises(ValueError):
        LLMSection(base_url="http://api.deepseek.com")


def test_deepseek_request_has_the_documented_shape_and_keeps_the_key_in_the_header_only():
    captured = {}

    def transport(url, headers, payload, timeout):
        captured.update(url=url, headers=headers, body=json.loads(payload), timeout=timeout)
        return _reply({"probe_paths": [], "trusted_header": None, "why": "nothing to add"})

    client = planner.DeepSeekPlanner(LLMSection(enabled=True), api_key=FAKE_KEY, transport=transport)
    selection = client.select({"target": "127.0.0.1:80", "text_excerpt": "x"}, candidate_paths=["/vault/"],
                              candidate_headers=["X-Forwarded-For"], candidate_values=[CORE_ROUTER])
    assert captured["url"] == "https://api.deepseek.com/chat/completions"
    assert captured["headers"]["Authorization"] == f"Bearer {FAKE_KEY}"
    body = captured["body"]
    assert body["model"] == "deepseek-flash"
    assert body["response_format"] == {"type": "json_object"}
    assert body["thinking"] == {"type": "disabled"} and body["temperature"] == 0 and body["stream"] is False
    assert FAKE_KEY not in json.dumps(body)
    assert selection.probe_paths == () and selection.trusted_header is None and selection.why == "nothing to add"


def test_selections_are_limited_to_the_target_candidates():
    def transport(url, headers, payload, timeout):
        return _reply({"probe_paths": ["/vault/", "/invented/"],
                       "trusted_header": {"name": "X-Forwarded-For", "value": CORE_ROUTER},
                       "why": "the handover names the core router"})

    client = planner.DeepSeekPlanner(LLMSection(enabled=True), api_key=FAKE_KEY, transport=transport)
    selection = client.select({"target": "x"}, candidate_paths=["/vault/"], candidate_headers=["X-Forwarded-For"],
                              candidate_values=[CORE_ROUTER])
    assert selection.probe_paths == ("/vault/",)
    assert selection.trusted_header == ("X-Forwarded-For", CORE_ROUTER)
    assert any("/invented/" in item for item in selection.rejected)

    def invented_address(url, headers, payload, timeout):
        return _reply({"probe_paths": [], "trusted_header": {"name": "X-Forwarded-For", "value": "10.9.9.9"},
                       "why": "guess"})

    guessed = planner.DeepSeekPlanner(LLMSection(enabled=True), api_key=FAKE_KEY, transport=invented_address)
    rejected = guessed.select({"target": "x"}, candidate_paths=["/vault/"], candidate_headers=["X-Forwarded-For"],
                              candidate_values=[CORE_ROUTER])
    assert rejected.trusted_header is None and rejected.rejected


def test_excerpt_is_redacted_and_bounded_before_it_is_sent():
    captured = {}

    def transport(url, headers, payload, timeout):
        captured["context"] = json.loads(json.loads(payload)["messages"][1]["content"])
        return _reply({"probe_paths": [], "trusted_header": None, "why": ""})

    section = LLMSection(enabled=True, max_excerpt_chars=500)
    client = planner.DeepSeekPlanner(section, api_key=FAKE_KEY, transport=transport)
    client.select({"target": "x", "text_excerpt": "password: hunter2 " + "a" * 2000 + " MITIGATA{abc}"},
                  candidate_paths=[], candidate_headers=[], candidate_values=[])
    excerpt = captured["context"]["text_excerpt"]
    assert len(excerpt) <= 500
    assert "hunter2" not in excerpt and "MITIGATA{abc}" not in excerpt


def test_unexpected_replies_become_planner_errors_that_never_echo_the_key():
    def transport(url, headers, payload, timeout):
        return b'{"choices": []}'

    client = planner.DeepSeekPlanner(LLMSection(enabled=True), api_key=FAKE_KEY, transport=transport)
    with pytest.raises(planner.PlannerError) as caught:
        client.select({"target": "x"}, candidate_paths=[], candidate_headers=[], candidate_values=[])
    assert FAKE_KEY not in str(caught.value)


@pytest.mark.skipif(not HAS_GCC, reason="needs gcc to build the lab binary")
def test_deepseek_selections_are_used_and_the_key_never_reaches_the_run_record(tmp_path, monkeypatch):
    from mitigata.pipeline import orchestrator
    from mitigata.web.app import run_view

    consulted = []

    def fake_deepseek(url, headers, payload, timeout):
        context = json.loads(json.loads(payload)["messages"][1]["content"])
        consulted.append(context["target"])
        header = None
        if "X-Forwarded-For" in context["candidate_headers"] and CORE_ROUTER in context["candidate_values"]:
            header = {"name": "X-Forwarded-For", "value": CORE_ROUTER}
        return _reply({"probe_paths": [path for path in context["candidate_paths"] if path == "/vault/"],
                       "trusted_header": header, "why": "the handover names the core router"})

    monkeypatch.setattr(planner, "build_planner", lambda section, environ=None: (
        planner.DeepSeekPlanner(section, api_key=FAKE_KEY, transport=fake_deepseek), "ready"))
    out = tmp_path / "runs"
    with ChainLab(tmp_path / "lab") as lab:
        manifest = write_chain_manifest(tmp_path / "lab" / "scope.yaml")
        manifest.write_text(manifest.read_text(encoding="utf-8") + "llm:\n  enabled: true\n  max_calls: 4\n",
                            encoding="utf-8")
        ports = lab.ports
        monkeypatch.setattr(orchestrator._Hunt, "stage_discovery", lambda self: None)
        discovery = orchestrator.run_discovery(orchestrator.HuntOptions(scope_path=manifest, out_dir=out,
                                                                        deadline_seconds=300))
        result = orchestrator.run_target(orchestrator.HuntOptions(
            scope_path=manifest, out_dir=out, run_id=discovery["run_id"], focus=["127.0.0.1"],
            ports=f"{ports['web']},{ports['passkey']}", full_scan=False, deadline_seconds=900))
    view = run_view(out, discovery["run_id"])
    assert consulted, "the planner should be consulted on the first crawl"
    assert "propose_probes" in {row["kind"] for row in view["lineage"]}
    assert any(item["class"] == "trusted_header_bypass" and item["state"] == "confirmed"
               for item in view["candidates"])
    run_dir = Path(result["run_dir"])
    for path in run_dir.rglob("*"):
        if path.is_file():
            assert FAKE_KEY.encode() not in path.read_bytes(), path.name
