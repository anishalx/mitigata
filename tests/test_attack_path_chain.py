"""The attack-path graph shows a trusted-address bypass feeding the binary it served, and the access it leads to."""

from __future__ import annotations

import json

from mitigata.pipeline import attack_path


def _snapshot(*, bypass: bool) -> dict:
    candidates = [{
        "id": 2, "class": "passkey_protocol_auth", "state": "confirmed", "claim": "passkey", "ptes_phase": "exploitation",
        "details": {"ip": "127.0.0.1", "port": 8833}, "verdict": {"verdict": "confirmed"},
        "payload": {"accepted_refs": ["cred-1"]},
    }]
    if bypass:
        candidates.insert(0, {
            "id": 1, "class": "trusted_header_bypass", "state": "confirmed", "claim": "bypass",
            "ptes_phase": "vulnerability_analysis",
            "details": {"ip": "127.0.0.1", "port": 80, "header": "X-Forwarded-For", "trusted_value": "10.44.0.1"},
            "verdict": {"verdict": "confirmed"}, "payload": {},
        })
    return {
        "assets": [{"id": 1, "ip": "127.0.0.1"}],
        "services": [
            {"id": 1, "asset_id": 1, "port": 80, "name": "http", "product": "", "version": "", "ip": "127.0.0.1"},
            {"id": 2, "asset_id": 1, "port": 8833, "name": "unknown", "product": "", "version": "", "ip": "127.0.0.1"},
        ],
        "candidates": candidates,
        "credentials": [{"secret_ref": "cred-1", "kind": "auth_literal", "source": "binary:abc123:-1"}],
        "binaries": [{"sha256": "abc123", "path": "/evidence/keykeeper",
                      "details_json": json.dumps({"source": "web:127.0.0.1:80/vault/keykeeper"})}],
        "flags": [],
    }


def _actions(graph: dict) -> set[str]:
    return {step["action"] for path in graph["paths"] for step in path["steps"]}


def test_a_confirmed_bypass_leads_through_the_content_it_served_to_the_access_it_enables():
    graph = attack_path.build(_snapshot(bypass=True))
    actions = _actions(graph)
    assert "trusted X-Forwarded-For accepted" in actions
    assert "downloaded behind the trusted address" in actions
    assert any(node["kind"] == "content" for node in graph["nodes"])
    access_paths = [path for path in graph["paths"] if path["kind"] == "access"]
    assert access_paths and any("downloaded behind the trusted address" in
                                {step["action"] for step in path["steps"]} for path in access_paths)


def test_without_a_bypass_a_web_download_is_shown_as_a_download_not_as_a_supplied_artifact():
    graph = attack_path.build(_snapshot(bypass=False))
    actions = _actions(graph)
    assert "downloaded from web" in actions
    assert "supplied artifact" not in actions
    assert not any(node["kind"] == "content" for node in graph["nodes"])


def test_a_web_copy_kept_as_a_duplicate_source_still_links_through_the_bypass():
    snapshot = _snapshot(bypass=True)
    # The supplied copy is the first source; the web copy (same bytes) is kept as a later source.
    snapshot["binaries"] = [{"sha256": "abc123", "path": "/evidence/keykeeper",
                             "details_json": json.dumps({"source": "scope:keykeeper",
                                                         "sources": ["scope:keykeeper",
                                                                     "web:127.0.0.1:80/vault/keykeeper"]})}]
    graph = attack_path.build(snapshot)
    assert "downloaded behind the trusted address" in _actions(graph)
