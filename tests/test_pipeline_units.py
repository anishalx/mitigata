"""Unit tests for the pipeline building blocks: scanner parsing, scope guard, binary triage, redaction, budgets."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from mitigata import pipeline  # noqa: F401  (import check: package wiring)
from mitigata.models import ScopeManifest
from mitigata.pipeline import attack_path, binary_agent, net_agent, report, verifier, web_agent
from mitigata.pipeline.guard import ScopeGuard, ScopeViolation
from mitigata.pipeline.scanner import parse_hosts_xml
from mitigata.scope import compile_scope
from mitigata.store import Store

from .lab_sim import PASSKEY, build_binary

FIXTURES = Path(__file__).parent / "fixtures"


def _scope(ipv4: list[str], exclude: list[str] | None = None):
    manifest = ScopeManifest.model_validate({
        "engagement": {"name": "unit", "tier": "recon", "authorised_by": "unit test",
                       "window": "2020-01-01T00:00:00Z/2035-01-01T00:00:00Z"},
        "scope": {"ipv4": ipv4, "exclude": exclude or []},
    })
    return compile_scope(manifest)


# -- scanner ----------------------------------------------------------------------

def test_nmap_full_range_xml_from_the_suspicious_host_is_parsed():
    hosts = parse_hosts_xml((FIXTURES / "nmap_139_full_range.xml").read_text())
    assert len(hosts) == 1
    host = hosts[0]
    assert host["ip"] == "192.168.60.139" and host["up"] is True
    assert [(port["port"], port["name"]) for port in host["ports"]] == [(80, "http"), (1111, "lmsocialserver"), (8833, "unknown")]
    assert host["filtered"] == 65530
    assert host["closed"] == 2


def test_empty_or_host_less_xml_yields_no_hosts():
    assert parse_hosts_xml("") == []
    assert parse_hosts_xml('<?xml version="1.0"?><nmaprun></nmaprun>') == []


def test_nmap_host_timeout_is_reported_as_incomplete(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from mitigata.pipeline import scanner

    def fake_run(argv, *, timeout):
        Path(argv[-1]).write_text(
            '<nmaprun><host timedout="true"><status state="up"/>'
            '<address addr="127.0.0.1" addrtype="ipv4"/></host></nmaprun>'
        )
        return SimpleNamespace(timed_out=False, returncode=0, stderr="", stdout="")

    monkeypatch.setattr(scanner, "run", fake_run)
    result = scanner._run_nmap([], binary="nmap", workdir=tmp_path, name="unit", timeout=10)
    assert result["hosts"][0]["timed_out"]
    assert any("127.0.0.1" in error and "incomplete" in error for error in result["errors"])


# -- scope guard --------------------------------------------------------------------

def test_guard_permits_in_scope_and_refuses_excluded_and_outside_addresses(tmp_path):
    scope = _scope(["192.168.60.0/24"], exclude=["192.168.60.1"])
    guard = ScopeGuard(scope)
    assert guard.permits("192.168.60.139")
    assert not guard.permits("192.168.60.1")  # excluded
    assert not guard.permits("10.10.5.7")  # outside
    assert not guard.permits("192.168.60.0")  # network address is not a usable host
    guard.require("192.168.60.139", port=80, purpose="unit")
    with pytest.raises(ScopeViolation):
        guard.require("8.8.8.8", purpose="unit")
    assert guard.filter(["192.168.60.2", "10.0.0.1"], purpose="unit") == ["192.168.60.2"]


def test_guard_refusals_are_queued_then_recorded_without_sending(tmp_path):
    scope = _scope(["127.0.0.1/32"])
    guard = ScopeGuard(scope)
    with pytest.raises(ScopeViolation):
        guard.require("10.9.9.9", purpose="probe")
    store = Store(tmp_path / "blackboard.db")
    store.create_run("run-unit-1", engagement="e", tier="recon", scope_hash="h", manifest_sha256="m",
                     enforcement="host_guard_in_process")
    assert guard.flush(store, "run-unit-1") == 1
    row = store.conn.execute("SELECT kind, detail, sent_outside FROM scope_events").fetchone()
    assert row["kind"] == "refused" and row["sent_outside"] == 0 and "10.9.9.9" in row["detail"]
    assert guard.flush(store, "run-unit-1") == 0
    store.close()


# -- binary triage ------------------------------------------------------------------

def _obfuscated_xor_checker(value: str) -> bytes:
    """Minimal ELF64 payload containing the static loop recognised by triage."""
    assert len(value) == 16
    data = bytearray(0x2200)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x02\x01"  # ELF64, little endian
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64,
                     1, 5, 0, 0x400000, 0x400000, len(data), len(data), 0x1000)
    encoded_va, mask_va = 0x4020B0, 0x4020A0
    seed, step, mask = 13, 7, b"\x11\x22\x33\x44\x55\x66\x77\x08"
    encoded = bytes(ord(char) ^ ((seed + index * step) & 0xFF) ^ mask[index & 7]
                    for index, char in enumerate(value))
    data[0x20A0:0x20A8] = mask
    data[0x20B0:0x20C0] = encoded
    data[0x2040:0x2048] = b"passkey\x00"
    code = (
        b"\xb9" + struct.pack("<I", seed) + b"\x31\xc0"
        + b"\x0f\xb6\x90" + struct.pack("<I", encoded_va)
        + b"\x48\x89\xc6\x83\xe6\x07\x31\xca\x32\x96" + struct.pack("<I", mask_va)
        + b"\x3a\x14\x03\x75\x01\x48\x83\xc0\x01\x83\xc1" + bytes([step])
        + b"\x48\x83\xf8\x10\x75\x01"
    )
    data[0x1000:0x1000 + len(code)] = code
    return bytes(data)


def test_auth_literal_is_ranked_from_strings_next_to_the_keyword():
    strings = [(100, "passkey"), (112, PASSKEY), (140, "hello world")]
    literals = binary_agent.auth_literals(strings)
    assert literals and literals[0]["value"] == PASSKEY
    assert literals[0]["via"] == "adjacent" and literals[0]["keyword"] == "passkey"


def test_inline_key_value_literal_is_recognised_with_its_offset():
    strings = [(0, "password=Hunter2!x")]
    literals = binary_agent.auth_literals(strings)
    assert literals[0]["value"] == "Hunter2!x" and literals[0]["via"] == "inline"
    assert literals[0]["offset"] == len("password=")


def test_static_xor_compare_passkey_is_recovered_without_execution():
    expected = "Decode-Key-12345"
    literals = binary_agent.recover_auth_literals(_obfuscated_xor_checker(expected))
    found = next(item for item in literals if item["value"] == expected)
    assert found["via"] == "x86_xor_compare" and found["keyword"] == "passkey"


@pytest.mark.parametrize("value", ["hello world", 'quo"ted1!', "back\\slash1", "AUTH", "<passkey>", "x"])
def test_unsafe_or_placeholder_strings_are_not_secret_candidates(value):
    assert not binary_agent.looks_like_secret(value)


def test_elf_protections_are_read_from_the_compiled_lab_binary(tmp_path):
    binary = build_binary(tmp_path / "bin")
    protections = binary_agent.elf_protections(binary.read_bytes())
    assert protections["class"] == "ELF64"
    assert protections["nx"] is True
    assert protections["relro"] in {"partial", "full", "none"}


def test_elf_protections_reject_truncated_program_headers():
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # ELF64
    header[5] = 1  # little-endian
    struct.pack_into("<Q", header, 32, 0xFFFF)  # e_phoff points past the end of the file
    struct.pack_into("<HH", header, 54, 56, 1)  # e_phentsize, e_phnum
    assert binary_agent.elf_protections(bytes(header)) == {"error": "truncated program header table"}


def test_triage_quarantines_a_valid_artifact_read_only(tmp_path):
    binary = build_binary(tmp_path / "bin")
    result = binary_agent.triage(binary, tmp_path / "quarantine")
    assert result["format"] == "elf" and result["sha256"]
    artifact = Path(result["artifact"])
    assert artifact.is_file() and oct(artifact.stat().st_mode & 0o777) == "0o400"
    assert any(item["value"] == PASSKEY for item in result["literals"])


def test_triage_rejects_scripts(tmp_path):
    script = tmp_path / "run.sh"
    script.write_text("#!/bin/sh\necho passkey=abcd1234\n")
    result = binary_agent.triage(script, tmp_path / "q")
    assert result.get("rejected") is True and result["format"] == ""


# -- web agent helpers ----------------------------------------------------------------

def test_public_path_keeps_parameter_names_and_hides_values():
    assert web_agent.public_path("/index.php?p=/etc&x=1") == "/index.php?p=<redacted>&x=<redacted>"
    assert "/etc" not in web_agent.public_path("/index.php?p=/etc")
    assert web_agent.public_path("/") == "/"


def test_crawled_sensitive_path_is_kept_for_verification(monkeypatch):
    def fake_request(ip, port, *, target, **kwargs):
        if target == "/":
            return web_agent.Response(200, {"content-type": "text/html"}, b'<a href="/backup">backup</a>', "")
        if target == "/backup":
            return web_agent.Response(200, {"content-type": "text/plain"}, b"database backup", "")
        return web_agent.Response(404, {}, b"not found", "")

    monkeypatch.setattr(web_agent, "request", fake_request)
    result = web_agent.inventory("127.0.0.1", 80)
    candidates = [c for c in result["candidates"] if c["class"] == "exposed_path"]
    assert [c["target"] for c in candidates] == ["/backup"]


def test_manifest_check_exclusions_override_inclusions():
    from mitigata.pipeline.orchestrator import check_permitted
    from mitigata.models import Checks

    checks = Checks(include=["network.*", "web.*"], exclude=["*.fuzz"])
    assert check_permitted(checks, "web.inventory")
    assert not check_permitted(checks, "web.fuzz")
    assert not check_permitted(checks, "binary.triage")
    assert check_permitted(Checks(), "web.inventory")


def test_network_only_scope_skips_web_inventory(monkeypatch):
    from types import SimpleNamespace
    from mitigata.pipeline import orchestrator

    monkeypatch.setattr(net_agent, "probe_service", lambda *args, **kwargs: SimpleNamespace(kind="http", tls=False))
    monkeypatch.setattr(web_agent, "inventory", lambda *args, **kwargs: pytest.fail("web inventory must be skipped"))
    hunt = SimpleNamespace(auth_hosts=set(), guard=None, web_enabled=False)
    result = orchestrator._Hunt._inventory_one(hunt, "127.0.0.1", 80, False)
    assert result["web"] is None


def test_same_origin_target_rejects_other_hosts_and_schemes():
    assert web_agent.same_origin_target("/login.php", "/", "10.0.0.5", 80, "http") == "/login.php"
    assert web_agent.same_origin_target("http://10.0.0.6/x", "/", "10.0.0.5", 80, "http") is None
    assert web_agent.same_origin_target("javascript:alert(1)", "/", "10.0.0.5", 80, "http") is None
    assert web_agent.same_origin_target("http://10.0.0.5:8080/x", "/", "10.0.0.5", 80, "http") is None


def test_banner_leads_only_for_passkey_protocol_banners():
    probe = net_agent.Probe(kind="banner", banner="AUTH <passkey> to begin; HELP; EXIT")
    classes = [lead["class"] for lead in net_agent.banner_leads(probe)]
    assert classes == ["passkey_protocol_auth", "information_disclosure_banner"]
    assert net_agent.banner_leads(net_agent.Probe(kind="banner", banner="SSH-2.0-OpenSSH")) == []


# -- verifier budget and rate-limit handling --------------------------------------------

def test_attempt_budget_is_capped_per_account_and_off_when_disabled():
    budget = verifier.AttemptBudget(cap=2, enabled=True)
    assert budget.take("admin") and budget.take("admin")
    assert not budget.take("admin")  # cap reached for this account
    assert budget.take("root")  # other accounts have their own cap
    off = verifier.AttemptBudget(cap=5, enabled=False)
    assert not off.take("admin")


def test_blocked_account_is_never_retried():
    budget = verifier.AttemptBudget(cap=5, enabled=True)
    budget.blocked.add("admin")
    assert not budget.take("admin")


def test_rate_limit_is_detected_from_status_or_body_and_banner_words_are_ignored():
    limited = web_agent.Response(429, {}, b"", "")
    assert verifier._is_rate_limited(limited)
    body_limited = web_agent.Response(200, {}, b"Too many attempts, slow down", "")
    assert verifier._is_rate_limited(body_limited)
    # The protocol banner says "rate limited and blocked" in its own text; only the reply counts.
    assert not verifier._protocol_rate_limited(banner="abusive source addresses are rate limited", reply="AUTH denied")
    assert verifier._protocol_rate_limited(banner="", reply="you are blocked")


def test_login_success_needs_a_difference_and_no_password_field():
    control = web_agent.Response(200, {}, b"<form><input type='password'></form>", "")
    redirect = web_agent.Response(302, {"location": "/dashboard.php"}, b"", "")
    still_login = web_agent.Response(200, {}, b"Invalid credentials <input type='password'>", "")
    assert verifier._looks_logged_in(redirect, control)
    assert not verifier._looks_logged_in(still_login, control)
    assert not verifier._looks_logged_in(web_agent.Response(302, {"location": "/login.php"}, b"", ""), control)


def test_default_pairs_run_before_binary_literals():
    ctx = verifier.VerifyContext(
        guard=ScopeGuard(_scope(["127.0.0.1/32"])), budget=verifier.AttemptBudget(cap=8, enabled=True),
        secrets={"cred-1": "Tr4pK3y!x9"}, literal_refs=["cred-1"], flag_patterns=[],
    )
    pairs = verifier._pairs(ctx)
    assert pairs[0][2] is None  # a built-in default comes first
    assert pairs[-1] == ("admin", "Tr4pK3y!x9", "cred-1")


# -- attack path and report -------------------------------------------------------------

def test_attack_path_has_no_objective_without_confirmed_access():
    snapshot = {"assets": [{"id": 1, "ip": "10.0.0.5"}],
                "services": [{"id": 1, "asset_id": 1, "port": 80, "name": "http", "product": None,
                              "version": None, "ip": "10.0.0.5"}],
                "candidates": [], "credentials": [], "flags": [], "binaries": []}
    graph = attack_path.build(snapshot)
    assert graph["paths"] == []
    assert graph["mermaid"].startswith("flowchart LR")


def test_report_masks_flag_values_and_drops_default_passwords():
    payload = report._public_payload({"default_password": "password", "flag_values": ["flag{secret_value}"]},
                                     include_flags=False)
    rendered = json.dumps(payload)
    assert "secret_value" not in rendered
    assert payload["default_password"] == "<built-in default: not reproduced in reports>"
    assert payload["flags_masked"] == ["flag{…"]
    kept = report._public_payload({"flag_values": ["flag{secret_value}"]}, include_flags=True)
    assert kept["flag_values"] == ["flag{secret_value}"]


def test_report_target_label_for_binary_leads_has_no_ip():
    assert report._target_label({"binary_sha256": "abcdef1234567890", "offset": 42}) == "binary abcdef123456 offset 42"


# -- pacing, action filter and readable-content literals ----------------------------------

def test_pacing_spaces_operations_per_host_but_not_across_hosts():
    import time as _time

    guard = ScopeGuard(_scope(["127.0.0.1/32"]), http_interval=0.05)
    started = _time.monotonic()
    for _ in range(3):
        guard.pace("127.0.0.1")
    assert _time.monotonic() - started >= 0.09
    other = _time.monotonic()
    guard.pace("10.0.0.9")  # a different host has its own slot and is not delayed
    assert _time.monotonic() - other < 0.02


def test_action_segments_and_state_changing_names_are_never_followed():
    assert web_agent._state_changing("/UI/ascan/")
    assert web_agent._state_changing("/api/scan/start")
    assert web_agent._state_changing("/index.php?p=/&del=file.txt")
    assert not web_agent._state_changing("/ops/netops-handover.txt")
    assert not web_agent._state_changing("/index.php?p=ops&view=netops-handover.txt")


def test_readable_page_text_yields_literals_but_script_and_style_are_ignored():
    html = ("<html><script>var hint='password=Zz9!script';</script><style>p{color:red}</style>"
            "<p>Log monitor password: Mon1tor-Pass! (rotate)</p></html>")
    collector = web_agent._TextCollector()
    collector.feed(html)
    collector.close()
    result: dict = {"literals": []}
    web_agent._collect_literals(result, collector.text(), "/notes.html")
    values = [item["value"] for item in result["literals"]]
    assert "Mon1tor-Pass!" in values
    assert "Zz9!script" not in values


def test_focus_host_failures_get_one_retry_and_others_do_not():
    from mitigata.pipeline.orchestrator import _with_retry

    calls = {"n": 0}

    def flaky() -> str:
        calls["n"] += 1
        return "silent" if calls["n"] == 1 else "http"

    assert _with_retry(flaky, failed=lambda kind: kind == "silent", retry=True, delay=0.0) == "http"
    assert calls["n"] == 2

    calls["n"] = 0
    assert _with_retry(flaky, failed=lambda kind: kind == "silent", retry=False, delay=0.0) == "silent"
    assert calls["n"] == 1

    always_empty = {"pages": 0}
    seen = []
    result = _with_retry(lambda: (seen.append(1), always_empty)[1], failed=lambda w: w["pages"] == 0,
                         retry=True, delay=0.0)
    assert result is always_empty and len(seen) == 2  # only one retry, never a loop

