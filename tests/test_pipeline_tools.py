"""External-tool parsers, honest fallbacks, and literal ranking (no network, no tool required)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mitigata.pipeline import binary_agent, tools, web_agent
from mitigata.pipeline.verifier import PASSKEY_KEYWORDS, PASSWORD_KEYWORDS, VerifyContext, _ordered_refs

FIXTURE = Path(__file__).parent / "fixtures" / "r2_sample_output.txt"


def test_radare2_output_yields_strings_imports_functions_and_listing():
    parsed = tools.parse_r2_output(FIXTURE.read_text(encoding="utf-8"))
    assert any(item["string"] == "Tr4pK3y!x9" for item in parsed["strings"])
    assert {"strcmp", "puts"} <= set(parsed["imports"])
    assert parsed["main_listing"] and parsed["decompiler"] == "disassembly"


def test_radare2_plugin_missing_message_is_never_taken_as_decompiled_code():
    text = "---MAIN\n push rbp\n---DEC\nYou need to install the plugin with r2pm -ci r2ghidra\n"
    parsed = tools.parse_r2_output(text)
    assert parsed["decompiled"] == "" and parsed["decompiler"] == "disassembly"


def test_terminate_active_kills_a_child_process_group():
    import threading
    import time

    from mitigata.tools.runner import run, terminate_active

    box: list = []
    thread = threading.Thread(target=lambda: box.append(run(["sleep", "30"], timeout=60)))
    thread.start()
    time.sleep(0.3)
    assert terminate_active() >= 1
    thread.join(5)
    assert not thread.is_alive()
    assert box and box[0].returncode < 0


def test_ffuf_results_keep_single_segment_words_only():
    text = ('{"results":[{"input":{"FUZZ":"backup"},"status":200,"length":33},'
            '{"input":{"FUZZ":"a/b"},"status":200,"length":1}]}')
    assert tools.parse_ffuf_json(text) == [{"path": "/backup", "status": 200, "length": 33, "source": "ffuf"}]
    assert tools.parse_ffuf_json("not json") == []


def test_katana_output_keeps_same_origin_paths_once():
    origin = "http://192.168.60.139:80"
    text = "\n".join([
        '{"request":{"method":"GET","endpoint":"http://192.168.60.139:80/ops/"}}',
        '{"request":{"method":"GET","endpoint":"http://192.168.60.139:80/ops/"}}',
        '{"request":{"method":"GET","endpoint":"http://evil.example/x"}}',
        "garbage",
    ])
    assert tools.parse_katana_jsonl(text, origin) == ["/ops/"]


def test_missing_tools_fall_back_and_say_so(monkeypatch):
    monkeypatch.setattr(tools, "find", lambda name: None)
    rows = {row["key"]: row for row in tools.detect()}
    assert rows["katana"]["installed"] is False and "crawler" in rows["katana"]["fallback"]
    assert rows["ghidra"]["wired"] is True and "radare2" in rows["ghidra"]["fallback"]
    with pytest.raises(RuntimeError, match="ffuf is not installed"):
        tools.ffuf_paths("http://127.0.0.1:1", ["a"], rate=1)


def test_literals_are_tried_by_keyword_fit_then_score_then_binary_source():
    ctx = VerifyContext(
        guard=None, budget=None,  # type: ignore[arg-type]
        secrets={"cred-1": "a1!bcd", "cred-2": "x9!yzw", "cred-3": "q7!mnp"},
        literal_refs=["cred-1", "cred-2", "cred-3"], flag_patterns=[],
        literal_meta={
            "cred-1": {"keyword": "token", "score": 3.0, "source": "binary"},
            "cred-2": {"keyword": "passkey", "score": 2.0, "source": "web"},
            "cred-3": {"keyword": "passkey", "score": 2.0, "source": "binary"},
        },
    )
    assert _ordered_refs(ctx, PASSKEY_KEYWORDS) == ["cred-3", "cred-2", "cred-1"]
    assert _ordered_refs(ctx, PASSWORD_KEYWORDS) == ["cred-1", "cred-3", "cred-2"]


def test_katana_timeout_is_reported_for_builtin_fallback(monkeypatch):
    from types import SimpleNamespace
    from mitigata.pipeline import tools as tools_module

    monkeypatch.setattr(tools_module, "find", lambda name: "/fake/katana")
    monkeypatch.setattr(tools_module, "run", lambda *args, **kwargs: SimpleNamespace(
        timed_out=True, returncode=-9, stdout=""))
    with pytest.raises(RuntimeError, match="timed out"):
        tools_module.katana_paths("http://127.0.0.1/", "http://127.0.0.1", rate=1, timeout_s=1)


def test_ffuf_timeout_is_reported_for_builtin_fallback(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(tools, "find", lambda name: "/fake/ffuf")
    monkeypatch.setattr(tools, "run", lambda *args, **kwargs: SimpleNamespace(
        timed_out=True, returncode=-9))
    with pytest.raises(RuntimeError, match="timed out"):
        tools.ffuf_paths("http://127.0.0.1", ["backup"], rate=1, timeout_s=1)


def test_target_inventory_falls_back_after_crawler_timeout(monkeypatch):
    import time
    from types import SimpleNamespace
    from mitigata.pipeline import orchestrator

    calls = []
    inventory_options = []
    def timed_out(*args, **kwargs):
        calls.append(kwargs["timeout_s"])
        raise RuntimeError("katana timed out")

    monkeypatch.setattr(tools, "find", lambda name: "/fake/katana")
    monkeypatch.setattr(tools, "katana_paths", timed_out)
    monkeypatch.setattr(orchestrator.net_agent, "probe_service", lambda *args, **kwargs:
                        SimpleNamespace(kind="http", tls=False))
    def builtin_inventory(*args, **kwargs):
        inventory_options.append(kwargs)
        return {"pages": 1, "binary_links": []}
    monkeypatch.setattr(orchestrator.web_agent, "inventory", builtin_inventory)
    hunt = SimpleNamespace(
        auth_hosts=set(), guard=SimpleNamespace(require=lambda *args, **kwargs: None),
        mode="target", external_tools=True, fuzz_enabled=False, web_enabled=True, binary_enabled=True, http_rps=5,
        share_end=lambda share: time.monotonic() + 300, tools_used=set(), limitations=[],
        opt=SimpleNamespace(max_pages=20),
    )
    result = orchestrator._Hunt._inventory_one(hunt, "127.0.0.1", 80, False)
    assert result["web"]["pages"] == 1
    assert calls and 0 < calls[0] <= 30
    # Off the focus host there are no entry-path GETs: the seeds are whatever katana produced, here nothing.
    assert inventory_options == [{"tls": False, "guard": hunt.guard, "max_pages": 20,
                                  "seeds": (),
                                  "timeout": 8.0, "sensitive_timeout": 2.0, "max_sensitive_paths": 12}]
    assert "katana timed out" in hunt.limitations[0]


def test_entry_paths_are_requested_only_on_the_focus_host(monkeypatch):
    import time
    from types import SimpleNamespace
    from mitigata.pipeline import orchestrator

    seen = []
    monkeypatch.setattr(orchestrator.net_agent, "probe_service", lambda *args, **kwargs:
                        SimpleNamespace(kind="http", tls=False))
    monkeypatch.setattr(orchestrator.web_agent, "inventory",
                        lambda *args, **kwargs: seen.append(kwargs["seeds"]) or {"pages": 1, "binary_links": []})
    base = dict(guard=SimpleNamespace(require=lambda *args, **kwargs: None), mode="target", external_tools=False,
                fuzz_enabled=False, web_enabled=True, binary_enabled=False, http_rps=5,
                share_end=lambda share: time.monotonic() + 300, tools_used=set(), limitations=[],
                opt=SimpleNamespace(max_pages=20))
    orchestrator._Hunt._inventory_one(SimpleNamespace(auth_hosts={"127.0.0.1"}, **base), "127.0.0.1", 80, False)
    orchestrator._Hunt._inventory_one(SimpleNamespace(auth_hosts={"127.0.0.1"}, **base), "10.0.0.5", 80, False)
    assert seen[0] == web_agent.ENTRY_PATHS
    assert seen[1] == ()


@pytest.mark.parametrize("value, expected", [
    ("tool.c", False), ("backup.zip", False), ("config.php", False),
    ("Tr4pK3y!x9", True), ("Mon1tor-Pass!", True), ("Hunter2!x", True),
])
def test_secret_shape_rejects_file_names_and_accepts_credentials(value, expected):
    assert binary_agent.looks_like_secret(value) is expected


def test_user_password_pairs_in_auth_context_keep_their_user_name():
    from mitigata.pipeline.binary_agent import auth_literals

    found = {item["value"]: item for item in auth_literals([
        (0, "python gen.py --basic-auth elastic:changeme --output http"),
        (40, "log monitor login: ops:Mon1tor-Pass!"),
        (80, "url http://host:8080/x"),
    ])}
    assert found["changeme"]["user"] == "elastic" and found["changeme"]["via"] == "pair"
    assert found["Mon1tor-Pass!"]["user"] == "ops"
    assert all(item["value"] != "8080" for item in found.values())


def test_a_pair_is_tried_with_its_own_user_name_not_admin():
    from mitigata.pipeline.verifier import AttemptBudget, VerifyContext, _pairs

    ctx = VerifyContext(
        guard=None, budget=AttemptBudget(cap=8, enabled=True),  # type: ignore[arg-type]
        secrets={"cred-1": "changeme"}, literal_refs=["cred-1"], flag_patterns=[],
        literal_meta={"cred-1": {"keyword": "basic-auth", "score": 2.5, "source": "web", "user": "elastic"}},
    )
    pairs = _pairs(ctx)
    assert ("elastic", "changeme", "cred-1") in pairs
    assert ("admin", "changeme", "cred-1") not in pairs


def test_ghidra_export_parses_functions_decompiled_c_and_strings_without_log_decoration():
    from mitigata.pipeline import tools as tools_module

    text = (Path(__file__).parent / "fixtures" / "ghidra_export_output.txt").read_text(encoding="utf-8")
    parsed = tools_module.parse_ghidra_output(text)
    assert parsed["complete"] is True and parsed["program"] == "sample.bin"
    assert any(item["string"] == "Tr4pK3y!x9" for item in parsed["strings"])  # no quotes, no log suffix
    main = next(item for item in parsed["decompiled"] if item["name"] == "main")
    assert "strcmp" in main["c"] and "Tr4pK3y!x9" in main["c"]


def test_ghidra_parser_strips_log_suffix_and_c_string_quotes():
    from mitigata.pipeline import tools as tools_module

    line = 'INFO  X.java> MITIGATA_STR|00102010|%22Tr4pK3y%21x9%22  (GhidraScript)  \n'
    parsed = tools_module.parse_ghidra_output(line + "INFO  X.java> MITIGATA_END|0|1 (GhidraScript)\n")
    assert parsed["strings"] == [{"address": "00102010", "string": "Tr4pK3y!x9"}]
    assert parsed["complete"] is True
