# MITIGATA hunt console (frontend)

A single vanilla-JS page (`index.html`, `style.css`, `app.js`) that follows the architecture diagram from
top to bottom: kickoff command → scope guard & firewall → orchestrator → Discovery / Network / Web / Binary
agents → shared blackboard → verification agent → attack path & report engine. There is no build step.

Start it with the API:

```bash
.venv/bin/mitigata serve --scope scope-hackathon.yaml --out runs --port 8765
# open http://127.0.0.1:8765/
```

The server binds to `127.0.0.1` only and rejects requests whose `Host` header is not `127.0.0.1:<port>` or
`localhost:<port>`, whose `Origin` differs, or that come from a cross-site context. Starting a hunt from the page
needs the per-process token that the page receives from `/api/status`; the token is never printed to logs.

## What each panel shows

| Panel | Source | Notes |
|---|---|---|
| Kickoff | `/api/status` | Scope, focus host, deadline and the equivalent CLI command. **Start hunt** is enabled only when the manifest is valid and its window is open. |
| Scope guard | run events and `scope_events` | In-scope hosts, refused and sent-outside counts, auth-test state. |
| Orchestrator | `stage.started` / `stage.finished` events | PTES phase of the current stage and a deadline bar. |
| Agents | `tasks` table | Per-agent states (`done`, `running`, `pending`, `failed`) and the last event. |
| Shared blackboard | `/api/runs/{id}` | Hosts and ports, endpoints (parameter values redacted), credential references (never values), findings marked `[CANDIDATE]`. |
| Verification | candidates with validations | CONFIRMED / REJECTED / INCONCLUSIVE, the oracle, the control and the attempt count. |
| Attack path & report | `attack_path.json`, `report.*` | Chains to an objective (authenticated access or a captured flag), each step tagged with its PTES phase; downloads for Markdown, HTML, JSON and Mermaid. |
| Timeline, coverage, gaps | events, `coverage`, `report.json` | What was checked, what was not, and the limitations stated in the report. |

## Security properties (enforced server-side, tested in `tests/test_web_api.py`)

- Recovered literal values, default passwords and captured flag values are never returned by any route.
- Only the run's report files and the known report formats can be downloaded; run ids are validated.
- `script-src 'self'` and `style-src 'self'`: the page has no inline scripts, inline styles or inline handlers.
- Every server-supplied string is escaped before it reaches the DOM.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/status` | Scope summary, tool availability, job state, action token (local only) |
| POST | `/api/hunt` | Start a hunt (`X-Mitigata-Token` required); body: `focus`, `deadline_seconds`, `full_scan`, `top_ports`, `ports`, `binaries` |
| POST | `/api/discover` | Phase 1: alive hosts and top ports (`X-Mitigata-Token` required); body: `top_ports`, `deadline_seconds` |
| POST | `/api/runs/{id}/target` | Phase 2: scan one IP from a discovery run (`X-Mitigata-Token` required); body: `ip`, `deadline_seconds`, `fuzz`, `external_tools` |
| GET | `/api/job` | State of the most recent hunt started from the server |
| GET | `/api/runs` | Run list with counts |
| GET | `/api/runs/{id}` | Full run view for the dashboard |
| GET | `/api/runs/{id}/report/{md\|html\|json\|attack-path\|mermaid}` | Report downloads |
| GET | `/targets?run_id=` | Live hosts and their ports |
| GET | `/targets/{asset_id}/findings?run_id=` | Findings for one target (PRD FR-7 route) |
| GET | `/findings?run_id=` | All findings for a run |

The API is documented in code (`mitigata/web/app.py`); the OpenAPI schema is intentionally disabled for the local UI.
