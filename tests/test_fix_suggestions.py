"""Requirement B-3: every finding carries a plain-English fix and a way to check it, in the report and the dashboard."""

from __future__ import annotations

import html
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mitigata.pipeline import report
from mitigata.pipeline.remediation import REMEDIES, remedy_for
from mitigata.web import create_app

ROOT = Path(__file__).resolve().parents[1]
LOCAL = {"Host": "127.0.0.1:8765"}
# The classes the live runs produced on the focus host.
LIVE_CLASSES = ["trusted_header_bypass", "passkey_protocol_auth", "information_disclosure_banner",
                "hardcoded_secret", "default_credentials"]


def _item(finding_class, state, summary="summary text", target="192.168.60.139:80 /"):
    remedy = remedy_for(finding_class)
    return {
        "id": 1, "class": finding_class, "state": state, "ptes_phase": "exploitation", "target": target,
        "claim": "claim text", "oracle": "oracle text", "control": "control text", "summary": summary,
        "evidence": {"status": 302}, "fix": remedy.fix, "fix_check": remedy.check,
    }


def _model(confirmed, leads):
    return {
        "run": {"id": "run-test", "status": "partial", "engagement": "lab", "tier": "lab", "scope_hash": "a" * 64,
                "enforcement": "host_guard_in_process", "window": "", "duration_seconds": 0},
        "counts": {"hosts_live": 1, "services": 3, "endpoints": 0, "candidates": len(confirmed) + len(leads),
                   "confirmed": len(confirmed), "rejected": 0, "inconclusive": 0, "flags": 0, "attack_paths": 0,
                   "secrets_recovered": 0, "scope_refused": 0, "scope_sent_outside": 0},
        "attack_path": {"paths": [], "mermaid": "flowchart LR", "edges": []},
        "confirmed": confirmed, "leads": leads, "findings": confirmed + leads,
        "services": [], "endpoints": [], "binaries": [], "gaps": [], "limitations": [],
    }


@pytest.fixture
def api(lab_run):
    app = create_app(out_dir=lab_run["out"], scope_path=lab_run["manifest"], port=8765, token="fix-token")
    return TestClient(app)


# -- the fixes themselves -------------------------------------------------------------------------

@pytest.mark.parametrize("finding_class", sorted(REMEDIES))
def test_each_fix_and_check_is_a_plain_sentence_with_no_values(finding_class):
    remedy = REMEDIES[finding_class]
    for text in (remedy.fix, remedy.check):
        assert 40 <= len(text) <= 360, finding_class
        assert text.endswith("."), finding_class
        assert "\n" not in text, finding_class
        assert not re.search(r"flag\{|CVE-\d", text), finding_class


def test_the_classes_the_live_runs_produced_each_have_a_written_fix():
    for finding_class in LIVE_CLASSES:
        assert finding_class in REMEDIES, finding_class


def test_a_class_without_a_written_fix_gets_the_generic_pair():
    remedy = remedy_for("some_new_class")
    assert remedy.fix.startswith("No standard fix")
    assert "no longer be CONFIRMED" in remedy.check


# -- the report: Markdown, HTML and the appendix ---------------------------------------------------

def test_confirmed_findings_show_the_fix_and_how_to_check_it():
    text = report.render_markdown(_model([_item("trusted_header_bypass", "confirmed")], []))
    remedy = remedy_for("trusted_header_bypass")
    assert f"- **Fix:** {remedy.fix}" in text
    assert f"- **How to check the fix:** {remedy.check}" in text


def test_open_leads_show_their_fix_and_rejected_leads_do_not():
    leads = [_item("default_credentials", "inconclusive"),
             _item("default_credentials", "rejected", summary="none accepted")]
    lines = report.render_markdown(_model([], leads)).splitlines()
    open_line = next(line for line in lines if "**default_credentials**" in line and "— inconclusive:" in line)
    rejected_line = next(line for line in lines if "**default_credentials**" in line and "— rejected:" in line)
    assert remedy_for("default_credentials").fix in open_line
    assert "Fix:" not in rejected_line


def test_the_static_literal_summary_carries_the_fix_while_literals_are_open():
    leads = [_item("hardcoded_secret", "inconclusive", target="binary abcdef123456 offset 8368")]
    text = report.render_markdown(_model([], leads))
    line = next(line for line in text.splitlines() if "static literal(s) recovered" in line)
    assert remedy_for("hardcoded_secret").fix in line


def test_html_report_carries_the_same_fix_text():
    page = report.render_html(_model([_item("passkey_protocol_auth", "confirmed")], []))
    assert html.escape(remedy_for("passkey_protocol_auth").fix) in page
    assert "How to check the fix" in page


# -- the dashboard and the JSON report, from a real hunt on the loopback lab -----------------------

def test_dashboard_candidates_and_the_json_report_carry_the_fix(api, lab_run):
    run_id = lab_run["summary"]["run_id"]
    view = api.get(f"/api/runs/{run_id}", headers=LOCAL).json()
    assert view["candidates"], "the lab run should produce leads"
    for candidate in view["candidates"]:
        assert candidate["fix"] and candidate["fix_check"], candidate["class"]
    body = api.get(f"/api/runs/{run_id}/report/json", headers=LOCAL).json()
    assert body["findings"], "the report should list the findings"
    for item in body["findings"]:
        assert item["fix"] and item["fix_check"], item["class"]


def test_the_verification_panel_shows_the_fix_for_open_leads_only():
    script = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
    assert "How to check:" in script and "item.fix_check" in script
    assert 'item.state !== "rejected"' in script
