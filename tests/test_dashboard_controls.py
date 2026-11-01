"""The dashboard's run controls: Run and Clear in the top bar, and one Open and Delete for each previous run.

These are static checks on the served files. The behaviour (what the screen shows during a scan, Clear, reload,
per-run Delete) was exercised in a headless browser against a loopback lab during development.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_top_bar_has_run_and_clear_and_the_old_single_delete_is_gone():
    html = _read(FRONTEND / "index.html")
    run_button = re.search(r"<button\b[^>]*>Run</button>", html)
    clear_button = re.search(r"<button\b[^>]*>Clear</button>", html)
    assert run_button and 'id="discover-btn"' in run_button.group(0)
    assert run_button and 'form="discover-form"' in run_button.group(0)  # submits the range form from the top bar
    assert clear_button and 'id="clear-btn"' in clear_button.group(0)
    assert "delete-run-btn" not in html
    assert "run-select" not in html


def test_each_previous_run_has_its_own_open_and_delete_controls():
    html = _read(FRONTEND / "index.html")
    js = _read(FRONTEND / "app.js")
    assert 'id="runs-list"' in html
    assert 'data-open="${esc(run.id)}"' in js
    assert 'data-delete="${esc(run.id)}"' in js
    assert ">Delete</button>" in js
    assert 'run.status === "running"' in js  # a run in progress is never offered for deletion


def test_the_run_on_screen_is_kept_per_browser_under_one_key():
    js = _read(FRONTEND / "app.js")
    assert 'const VIEW_KEY = "mitigata.view";' in js
    assert "localStorage.setItem(VIEW_KEY" in js


def test_no_stale_or_misspelled_delete_labels_in_the_dashboard_or_its_docs():
    for path in (FRONTEND / "index.html", FRONTEND / "app.js", FRONTEND / "style.css",
                 FRONTEND / "README.md", ROOT / "README.md"):
        text = _read(path)
        assert not re.search(r"\bdelet\b", text), f"misspelled 'delet' in {path.name}"
        assert "Delete run</" not in text and "**Delete run**" not in text, f"stale 'Delete run' control in {path.name}"
