# Runbook — MITIGATA hackathon lab (192.168.60.0/24)

All commands run from the repository root (`/home/anish/mitigata`). Set the authorisation window and
`authorised_by` in `scope-hackathon.yaml` before any run.

## 0. Tools

```bash
.venv/bin/mitigata tools
```

- **nmap** (required for discovery and port scans), **katana**, **ffuf**, **radare2** and **Ghidra** are installed.
  The unpacked tools live in `~/.local/share/mitigata-tools` (override with `MITIGATA_TOOLS_DIR`); Ghidra uses the
  JDK in `~/.local/share/jdk-25-temurin`.
- If a tool is missing, the engine falls back: the built-in same-origin crawler instead of katana, the built-in
  wordlist fuzzer instead of ffuf, and static ELF triage instead of radare2/Ghidra.
- **Ghidra** is wired: when `analyzeHeadless` is found it provides decompiled C; radare2 is the fallback.

## 1. Discover the alive hosts (phase 1)

```bash
.venv/bin/mitigata discover --scope scope-hackathon.yaml --out runs
```

Prints the run id and the alive hosts with their open ports. The run stops with status `discovered`.

## 2. Scan the IP you choose (phase 2)

```bash
.venv/bin/mitigata target --scope scope-hackathon.yaml --run <RUN-ID> --ip 192.168.60.139 --out runs
```

For that IP, in order: nmap across all 65,535 TCP ports, then service versions; web crawl (katana when installed,
otherwise the built-in crawler); endpoint fuzzing (ffuf when installed, otherwise the built-in wordlist); any binary
found on the endpoints is downloaded and analysed with radare2; the credential-like literals found in the binary or
in page text are tried against that IP's endpoints (controls first, attempts capped per account); then the report.

Options: `--no-fuzz`, `--no-external` (ignore katana and ffuf), `--no-sweep` (skip the 65,535-port sweep),
`--ports 80,1111,8833` (explicit ports; works with `--no-sweep`), `--auth-hosts` (extra hosts that may receive
credential tests; the focus IP is always included), `--deadline-seconds 1500` (default), `--include-flags`
(private copy only).

One-shot alternative (discovery plus the focus host in one run): `.venv/bin/mitigata hunt --scope scope-hackathon.yaml --focus 192.168.60.139`.

## 3. Dashboard

```bash
.venv/bin/mitigata serve --scope scope-hackathon.yaml --out runs --port 8765
```

Open http://127.0.0.1:8765/: enter the range in **1 · Discover alive hosts** and press **Run** in the top bar. Then
pick a host in **2 · Choose a target IP** and press **Scan this IP**. **Clear** empties the screen without deleting
anything; **Previous runs** opens or deletes a run one at a time.
The form accepts an explicit port list, extra authentication hosts, and can disable the full 65,535-port sweep
(useful for a fast check). The tools panel shows what is installed and what each agent falls back to.

## 4. Results

`runs/<run-id>/report.md` (also `.html`, `.json`), `attack_path.mmd`, and `evidence/decompile` rows in the blackboard
(radare2 output, scrubbed of recovered values). `secrets.json` holds the recovered values (mode `0600`); do not copy it
into reports.

## 5. Authorisation checklist

- The window in `scope-hackathon.yaml` is open for the current lab week.
- `checks.auth_tests: true` permits credential tests; set it to `false` for discovery and passive checks only.
- Credential tests run only against the IP you scan (plus any `--auth-hosts` you add). Each account is capped at
  `limits.max_auth_attempts_per_account`, control attempts included.
- Add the gateway or any organiser-excluded host to `scope.exclude`.

---

## Optional features

- **Forwarded-address trust test.** Add to the manifest's `checks` section, for the focus host only:
  `header_trust: {enabled: true, hosts: ["<focus-ip>"], max_requests: 30}`. It sends GETs with forwarded-address headers
  and never fuzzes. Leave it out to skip the test.
- **DeepSeek planner.** Add `llm: {enabled: true}` to the manifest and export `DEEPSEEK_API_KEY` in the shell that
  starts the run. Each service gets at most one planner call (`llm.max_calls`, default 4). The planner chooses only
  among the target's own candidates; a missing or failing key is recorded as a gap and the run continues.
- **angr solver.** `uv pip install --python .venv/bin/python "angr==9.2.*"`. Without it, the binary agent records the
  solver as unavailable. The solver never runs the binary natively.

## Docker

```bash
cp .env.example .env          # set DEEPSEEK_API_KEY only if you use the planner; keep .env out of git
mkdir -p runs binaries        # binaries/ holds organiser-supplied files; runs/ receives every run
docker compose up --build     # dashboard on http://127.0.0.1:8765/ (host network, loopback only)
docker compose run --rm mitigata tools     # check what is installed inside the image
```

Set `SCOPE_FILE` in `.env` to point at your manifest. Set `WITH_SOLVER=0` before building for a smaller image.

## Legacy commands

The single-host network worker and the namespace-enforced `run` command still work; see `README.md`.
