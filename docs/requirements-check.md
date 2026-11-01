# Requirements check

Status key: **Met** = implemented and shown working (test, code path, or a live run); **Partly** = implemented
with a stated gap; **Not yet** = not implemented.

Live evidence refers to runs in `runs/`: `run-20261031T230237Z-395261` (chain, earlier build) and
`run-20261031T235407Z-e49db3` (focus host, credential tests off, current build).

## Must have

| ID | Requirement | Status | Evidence | Gap / next step |
|---|---|---|---|---|
| FR-1 | Network discovery: find live hosts, open ports and services in scope | **Met** | Dashboard step 1 takes an IP range (CIDR, `A.B.C.N-M`, or one address), checked against the manifest (`discovery.resolve_range`, `tests/test_range_input.py`). nmap host discovery and port inventory (`pipeline/scanner.py`). Live: a one-host range returned the focus host with its open port (`POST /api/discover`). | UDP is not scanned. |
| FR-2 | Web surface: crawl, list endpoints, flag common issues (find `/login`, `/admin`, a form that echoes input) | **Partly** | GET-only crawl, endpoints list (40 on the focus host), login-form detection, raw-HTML reflection check (`web_agent.py`, `tests/test_pipeline_e2e.py`, `tests/test_surfaces.py`). Entry paths `/index.php`, `/share/`, `/files/` on the focus host. | `/admin` is not probed: fuzzing is excluded by the manifest (`*.fuzz`), and hint probes only follow words the target prints. Closing this needs a manifest decision on a short admin-path list. |
| FR-3 | Binary analysis: a hard-coded password or an unsafe function | **Met** | Static triage and literal recovery (`binary_agent.py`); unsafe imports (`surfaces/binary.py`, `_UNSAFE_IMPORTS`); offline solver for computed checks (`pipeline/solver.py`, verified on the supplied keykeeper, `tests/test_solver.py`). Binary output is shown per binary in the dashboard (sources, analysis, solver, decompile, disassembly). | The solver needs angr (in the image by default). The stripped keykeeper has no unsafe imports in the Ghidra export. |
| FR-4 | Multi-agent coordination: agents share findings so work is not repeated | **Met** | One SQLite blackboard with tasks, events, candidates and evidence; discovery hands each service to the web agent; each step records its parent task (`tasks.parent_task_id`). Live: discover → inventory → identify → crawl → header test → binary → verification, shown as the discovery chain. | — |
| FR-5 | Map each step to a PTES phase | **Met** | Every event, task and candidate carries a PTES phase (`ptes_phase`); the report shows PTES tags and the dashboard timeline shows phases. | — |
| FR-6 | Verify a finding, do not just flag it | **Met** | Verifier verdicts CONFIRMED / REJECTED / INCONCLUSIVE with oracle and control (`pipeline/verifier.py`). Live: `trusted_header_bypass` CONFIRMED (control 502, trusted value 200); `information_disclosure_banner` CONFIRMED (banner repeatable). Default-credential checks use a control and per-account caps. | The passkey candidate could not be tested live: the account's engagement cap is used up (see B-1). |
| FR-7 | One report with the attack path, a simple API or page, and a README; e.g. `GET /targets/5/findings` | **Met** | Reports in Markdown, HTML and JSON per run (`runs/<id>/report.*`); attack path as JSON and Mermaid; `GET /targets/{asset_id}/findings` (`web/app.py`, `tests/test_web_api.py`); dashboard; `README.md`, `cmd.md`. | — |

## Bonus

| ID | Feature | Status | Evidence | Gap / next step |
|---|---|---|---|---|
| B-1 | Capture the planted flags on the lab network | **Partly** | Flag capture is demonstrated on the loopback chain (`tests/test_chain.py`, flag masked in the report). On the focus host the passkey step did not run: the account's cap (8 per engagement) was used by earlier runs, so the verified candidate was never sent. | A decision on the cap for that account (manifest `limits.max_auth_attempts_per_account`), then a new run. |
| B-2 | Chain findings into a full path to a protected "crown jewel" host | **Partly** | Attack-path graph chains attacker → host → service → trusted-address bypass → content → binary → credential → access → flag (`tests/test_attack_path_chain.py`). | The manifest's `crown_jewel` section is not yet used as the path objective. |
| B-3 | Suggest a fix for each finding in plain English | **Met** | A fix text per finding class in `pipeline/report.py` (eight classes, including the trusted-address bypass). | — |
| B-4 | Add a new agent or check by editing a config file, not code | **Partly** | Checks are switched and bounded by the manifest: include and exclude patterns, `header_trust`, `llm`, `limits`, and the auth caps. | A new check class still needs code. A registry that loads checks from config is the next step. |
| B-5 | Live dashboard showing each agent working and what it found | **Met** | Dashboard polls the run: agent cards with task states, a live timeline, the discovery chain, the binary agent output, candidates and verdicts, attack path. Step 1 takes a range, step 2 picks the target, step 3 scans it. | Checked through the API, the served page and a syntax check; not exercised in a browser. |

## Changes that closed the binary question

- The web copy of a binary is kept as a **source** of the same bytes, not dropped as a duplicate
  (`store.add_binary_source`). The live run shows both sources for the keykeeper.
- The binary panel shows where each binary was found, the protections, unsafe imports, the literal count, the
  solver result, and expandable functions, decompiled code and disassembly. Literal values are never shown.
- The run view returns the decompile output (`web/app.py`), so the UI no longer depends on the table alone.
