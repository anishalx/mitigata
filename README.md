# MITIGATA

**Scope-enforced, multi-agent penetration-testing engine for authorised lab work.** One command discovers the
authorised range, inventories services, follows what the target itself names, analyses binaries, verifies each lead
with a control, maps every step to a PTES phase, and writes one report with the attack path. A local dashboard shows
the run, including the discovery chain (which step caused which).

The deterministic core decides. An optional LLM planner (DeepSeek) may only choose among candidates the target named.
Nothing is sent outside the manifest's ranges, and credential checks run only against the focus host(s).

Scope of this build: authorised lab testing only. See **Safety model** below.

## Quick start

### Local (Python 3.12, nmap, radare2 on PATH)

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e . pytest httpx   # once
.venv/bin/mitigata tools                                  # what is installed and what each agent falls back to
cp scope.example.yaml scope.yaml                          # then set the window, ranges and authorised_by
.venv/bin/mitigata serve --scope scope.yaml --out runs    # dashboard on http://127.0.0.1:8765/
```

The dashboard starts hunts itself: discover alive hosts, choose an IP, scan it. The CLI has the same steps:
`discover`, `target --ip ... --run <id>`, and the one-shot `hunt --focus <ip>`. `cmd.md` is the runbook.

`discover` exits `0` when the run is discovered. `target` exits `0` when complete, `4` when partial (gaps are listed in
the report), `3` when it refused before sending anything (closed window, out-of-scope IP), and `1` on failure.

### Docker

```bash
cp .env.example .env            # optional: DEEPSEEK_API_KEY, host uid/gid, scope file, solver on/off
mkdir -p runs binaries          # the container writes runs/ and reads binaries/
docker compose up --build       # dashboard on http://127.0.0.1:8765/ (host network, loopback only)
```

The image is Debian-slim with Python 3.12, nmap, and radare2 6.2.4 (the upstream `.deb`, pinned and SHA-256 checked).
`WITH_SOLVER=1` (the default) adds the optional angr solver; `WITH_SOLVER=0` gives a smaller image. Ghidra is not in the
image; the engine uses radare2 when Ghidra is absent. No secret is baked into the image; the key is passed at run time.

Host networking is Linux-only. On Docker Desktop, publish the port to the host's loopback and bind the container's
interfaces instead: `docker run -p 127.0.0.1:8765:8765 ... mitigata serve --host 0.0.0.0 ...`. The port stays on the
host's loopback, and the dashboard's Host check still applies.

## How the pipeline maps to the design

| Stage | Module | What it does |
|---|---|---|
| Scope guard | `pipeline/guard.py`, `scope.py` | Fail-closed allowlist and exclusions. Every connect asks the guard first; refusals are recorded. |
| Orchestrator | `pipeline/orchestrator.py` | Stages with deadline budgets, task dedup, PTES tags, lineage, and the only SQLite writer. |
| Discovery | `pipeline/scanner.py` | nmap host discovery (TCP connect), top ports, and a bounded full-range sweep of the focus host. |
| Network | `pipeline/net_agent.py` | Passive banner read before any input; passkey-protocol banners become leads. |
| Web | `pipeline/web_agent.py` | GET-only same-origin crawl; entry paths on the focus host; names the target prints (hints); forwarded-address trust test; binary links. |
| Follow-ups | `orchestrator.stage_followups` | Bounded probes derived from what earlier results said, each linked to the step that caused it. |
| Planner (optional) | `pipeline/planner.py` | DeepSeek selection among the target's own candidates. Off by default. |
| Binary | `pipeline/binary_agent.py`, `tools.py` | Static triage; Ghidra decompile or radare2 listings; literal recovery; the optional solver. |
| Solver (optional) | `pipeline/solver.py` | angr emulation of a stdout-gated check. A candidate counts only after a concrete emulated run prints success. |
| Verification | `pipeline/verifier.py` | Each lead has a control. Verdicts: CONFIRMED, REJECTED, INCONCLUSIVE, with the oracle recorded. |
| Attack path & report | `pipeline/attack_path.py`, `report.py` | Graph of the chain; Markdown, HTML and JSON reports with PTES tags and fixes. |
| Dashboard | `web/app.py`, `frontend/` | FastAPI on loopback. Panels: stepper, board, binaries with analysis status, discovery chain, verification, paths. |

## The discovery chain

Every step records the task that caused it (`tasks.parent_task_id`). The dashboard's **Discovery chain** panel draws
the tree, so you can see, for example: discover → inventory → identify → crawl → header test → content behind the
trusted address → binary → analysis → verification.

- **Hint probes.** Readable text from the target may name exposure words and paths (for example `/vault/`). Each name
  is requested once, at most 8 per service, and only when the word is also in the vendored SecLists list
  (`mitigata/wordlists/`, MIT). State-changing names are excluded.
- **Forwarded-address trust test (manifest-gated).** Some edge proxies trust a client-supplied address header. The test
  sends a control value from an address that is never trusted (an RFC 5737 documentation address), then candidates the
  target itself mentioned, plus the subnet gateway and loopback. A result counts only when the control gets a non-200
  and a candidate gets a 200 with a body. It stops at the first revealing candidate, at the request cap, or on HTTP 429.
  It runs only for the hosts listed under `checks.header_trust`.
- **Binary outcome.** Every binary records which tool ran, its status, the reason for any failure or skip, function
  counts, the literal count, and where each literal came from. The dashboard and the event log show it.

## Binary analysis and the solver

Static triage reads ELF/PE protections, unsafe imports and printable literals. When Ghidra is installed it decompiles the
binary; radare2 supplies disassembly listings either way. A stripped binary's check is often not a plain string, so
literal search misses it.

The optional solver handles that case. It reads the argument length from the decompile or the listing, takes the
success and failure messages from the strings, and asks angr for an input that makes the emulated program print
success. A candidate is kept only after a concrete emulated run confirms it. The live authentication check is still a
separate, bounded step: one control attempt plus one candidate.

The solver never runs the binary natively. To enable it, install angr into the project venv:
`uv pip install --python .venv/bin/python "angr==9.2.*"`. The 9.2 line pins claripy to a matching release; angr 10 does
not match the claripy 9.3 that the resolver picks in this environment.

## Optional LLM planner (DeepSeek official API)

- **Off by default.** Enable it with `llm: {enabled: true}` in the manifest and `DEEPSEEK_API_KEY` in the environment.
  The key is read from the environment only. It is never written to a manifest, event, report, database, or image.
- **What it sees.** One request per service on the first crawl: the target and scheme, up to 40 endpoint paths with
  status and length, the candidate paths, the header names and addresses the target mentioned, and a redacted text
  excerpt (flags and credential-looking pairs masked, length capped by `max_excerpt_chars`). The record keeps a SHA-256
  and a size of what was sent, not its content.
- **What it can do.** Choose among the candidates it was given. Its picks go first in the probe order, and its header
  choice is tested first. It cannot add a path, header or address, cannot confirm a finding, and every probe it reorders
  still passes the same gates.
- **Model and endpoint.** `deepseek-flash` (default) or `deepseek-v4-pro`, at `https://api.deepseek.com`, with JSON output,
  thinking disabled and temperature 0. The endpoint must be HTTPS.
- **Failure.** Any error (no key, HTTP error, unreadable reply) is recorded as a gap, and the run continues without it.

## Safety model

- **Scope:** every target-facing call passes the in-process guard before a socket opens. Refusals are logged.
- **Authentication tests:** only the focus host or hosts named with `--auth-hosts`. Each account is capped at
  `limits.max_auth_attempts_per_account`, control attempts included. A rate-limit or block signal stops that surface.
- **Forwarded-address test:** only on hosts listed under `checks.header_trust`, GET only, at most `max_requests`, and it
  stops on HTTP 429. It does not try to evade rate limits.
- **Hint probes and entry paths:** hint probes are paths the target names, at most 8 per service. Entry paths
  (`/index.php`, `/index.html`, `/share/`, `/files/`) are requested on the focus host only.
- **No fuzzing by default:** a manifest that excludes `*.fuzz` keeps `web.fuzz` off. Enabling fuzzing is a manifest
  decision, not a code default.
- **Destruction:** no writes, uploads, deletions or form submissions. No denial of service, no persistence.
- **Secrets:** recovered literal values live only in `secrets.json` (mode 0600). They never appear in events, the
  blackboard, reports, the API, or the planner's requests.
- **Flags:** captured flag values are masked everywhere unless `--include-flags` is passed for a private copy.
- **Dashboard:** bound to 127.0.0.1 by default. `--host 0.0.0.0` is for containers whose port is published to the host's
  loopback only. Host and Origin checks, a per-process token for the single write route, and a strict CSP
  (`default-src 'none'`, no inline script or style).

## Repository layout

```
scope.example.yaml             manifest template (copy to scope.yaml; local manifests stay out of git)
mitigata/
  cli.py                       serve | hunt | discover | target | run | preflight | tools | scope
  pipeline/                    guard, scanner, net/web/binary agents, follow-ups, planner, solver, verifier,
                               attack_path, report, orchestrator
  wordlists/                   vendored SecLists common list (MIT) and its licence
  web/app.py                   FastAPI dashboard and API (loopback by default)
  store.py, models.py, scope.py, config.py   blackboard (SQLite WAL), schemas, scope compiler, manifest loader
frontend/                      dashboard: index.html, style.css, app.js (no build step)
tests/                         unit, end-to-end, API and loopback chain tests (chain_lab.py, lab_sim.py)
Dockerfile, docker-compose.yml, .dockerignore, .env.example
docs/research-and-design.md    design of record
cmd.md                         runbook
```

## Tests

```bash
.venv/bin/python -m pytest -q
```

Everything runs on loopback. The chain and binary tests need `gcc`; the solver tests need angr and are skipped without it.
The planner tests use a fake transport, so no test calls the DeepSeek API. The full suite takes several minutes because
the full-range test scans all 65,535 loopback TCP ports.

## What is built and what is not

Built and tested: every stage above, the forwarded-address trust test, the discovery chain with lineage, the binary
outcome record, the optional angr solver (verified on a loopback computed-check binary and offline on the supplied
binary), the DeepSeek planner, the attack-path step for a trusted-address bypass, the dashboard API and panels, and the
container image.

Not built, or not verified:

- A live run against a current lab host was not part of this release.
- The dashboard panels were checked through the API and by a syntax check; they were not exercised in a browser.
- The DeepSeek planner's selection quality has not been measured against a live model.
- Ghidra is not in the image. Dynamic execution of binaries is not performed.
- UDP scanning, authenticated crawling beyond the verifier's single-form login, and attack classes beyond the verifier's
  table are not implemented.
