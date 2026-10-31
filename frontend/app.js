"use strict";
// MITIGATA hunt console. Vanilla JS, no build step. Server-supplied strings are escaped before they reach the DOM,
// and the page has no inline scripts or styles (see the Content-Security-Policy).
(() => {
  const DISCOVER_STAGES = [
    { id: "scope-guard", label: "Scope guard", phase: "pre_engagement" },
    { id: "host-discovery", label: "Host discovery", phase: "intelligence_gathering" },
    { id: "port-inventory", label: "Top ports", phase: "intelligence_gathering" },
  ];
  const TARGET_STAGES = [
    { id: "service-inventory", label: "nmap · crawl · fuzz", phase: "intelligence_gathering" },
    { id: "follow-up-probes", label: "Hints · forwarded headers", phase: "intelligence_gathering" },
    { id: "binary-triage", label: "Binaries · Ghidra / radare2 · solver", phase: "vulnerability_analysis" },
    { id: "verification", label: "Credential tests", phase: "exploitation" },
    { id: "attack-path-and-report", label: "Attack path & report", phase: "threat_modeling" },
  ];
  const AGENTS = ["discovery-agent", "network-agent", "web-agent", "binary-agent"];
  const state = {
    token: "",
    status: null,
    runs: [],
    runId: "",
    view: null,
    report: null,
    reportKey: "",
    job: { state: "idle" },
    pollTimer: null,
  };
  const $ = (selector) => document.querySelector(selector);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
  const short = (text, limit = 110) => {
    const value = String(text ?? "");
    return value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
  };
  const when = (iso) => (iso ? iso.replace("T", " ").replace("Z", " UTC") : "");
  const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

  async function api(path, options = {}) {
    const headers = { Accept: "application/json" };
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    if (options.token) headers["X-Mitigata-Token"] = state.token;
    const response = await fetch(path, {
      method: options.method || "GET",
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      cache: "no-store",
      credentials: "same-origin",
    });
    const type = response.headers.get("content-type") || "";
    const data = type.includes("application/json") ? await response.json() : await response.text();
    if (!response.ok) {
      const message = typeof data === "string" ? data : data.error || data.detail || `HTTP ${response.status}`;
      throw new Error(message);
    }
    return data;
  }

  function notice(message, kind = "info") {
    const box = $("#notice");
    box.hidden = !message;
    box.className = `notice${kind === "error" ? " error" : ""}`;
    box.textContent = message || "";
  }

  // -- status, tools, runs -----------------------------------------------------------
  async function loadStatus() {
    state.status = await api("/api/status");
    state.token = state.status.action_token || state.token;
    renderChips();
    renderTools();
    renderControls();
  }

  function renderChips() {
    const scope = state.status.scope;
    const chips = [];
    if (scope.state === "valid") {
      chips.push(`<span class="chip">${esc(scope.name)} · ${esc((scope.allowlist || []).join(", "))}</span>`);
      chips.push(scope.window_open ? '<span class="chip ok">window open</span>' : '<span class="chip bad">window closed</span>');
      chips.push(scope.auth_tests
        ? `<span class="chip warn">credential tests on · cap ${esc(scope.max_auth_attempts_per_account)}/account</span>`
        : '<span class="chip">credential tests off</span>');
    } else {
      chips.push(`<span class="chip bad">${esc(scope.message || "no scope")}</span>`);
    }
    chips.push(`<span class="chip">enforcement: ${esc(state.status.enforcement)}</span>`);
    $("#chips").innerHTML = chips.join("");
  }

  function renderTools() {
    const rows = state.status.tools || [];
    const installed = rows.filter((row) => row.installed).length;
    $("#tools-summary").textContent = `${installed} of ${rows.length} installed`;
    $("#tools-list").innerHTML = rows.length ? `<table><tr><th>Tool</th><th>Status</th><th>Used for</th><th>If missing</th></tr>${rows.map((row) => `
      <tr>
        <td><b>${esc(row.key)}</b></td>
        <td>${row.installed ? '<span class="badge confirmed">installed</span>' : '<span class="badge rejected">missing</span>'}</td>
        <td class="wrap">${esc(row.purpose)}</td>
        <td class="wrap">${row.installed ? "" : `${esc(row.fallback)}<br><span class="muted">${esc(row.install_hint)}</span>`}</td>
      </tr>`).join("")}</table>` : '<p class="empty">Tool detection unavailable.</p>';
  }

  async function loadRuns() {
    const data = await api("/api/runs");
    state.runs = data.runs;
    const select = $("#run-select");
    const current = state.runId;
    select.innerHTML = state.runs.length
      ? state.runs.map((run) => `<option value="${esc(run.id)}">${esc(run.id)} · ${esc(run.status)}</option>`).join("")
      : '<option value="">no runs yet</option>';
    if (!state.runs.length) {
      state.runId = "";
      return;
    }
    state.runId = state.runs.some((run) => run.id === current) ? current : state.runs[0].id;
    select.value = state.runId;
  }

  async function loadRun() {
    if (!state.runId) {
      state.view = null;
      renderEmpty();
      return;
    }
    state.view = await api(`/api/runs/${encodeURIComponent(state.runId)}`);
    const key = `${state.runId}:${state.view.run.status}`;
    if (state.view.reports.json && state.reportKey !== key) {
      state.report = await api(`/api/runs/${encodeURIComponent(state.runId)}/report/json`);
      state.reportKey = key;
    }
    renderAll();
  }

  async function pollJob() {
    state.job = await api("/api/job");
    if (state.job.run_id && state.job.run_id !== state.runId) {
      state.runId = state.job.run_id;
      await loadRuns();
    }
  }

  function jobRunning() {
    return state.job.state === "running";
  }

  function scheduleNext() {
    clearTimeout(state.pollTimer);
    const busy = jobRunning() || (state.view && state.view.run.status === "running");
    state.pollTimer = setTimeout(tick, busy ? 1500 : 8000);
  }

  async function tick() {
    try {
      await pollJob();
      await loadStatus();
      await loadRuns();
      await loadRun();
      if (state.job.state === "error" || state.job.state === "refused") {
        notice(state.job.error || "The job did not start.", "error");
      } else if (state.job.state === "done") {
        notice(`${state.job.kind || "Job"} finished: ${state.job.status || "done"}.`);
      }
    } catch (error) {
      notice(`Dashboard could not refresh: ${error.message}`, "error");
    } finally {
      scheduleNext();
    }
  }

  // -- actions -----------------------------------------------------------------------------
  async function startDiscovery(event) {
    event.preventDefault();
    $("#discover-btn").disabled = true;
    try {
      state.job = await api("/api/discover", {
        method: "POST", token: true,
        body: { top_ports: Number($("#top-ports-input").value), deadline_seconds: Number($("#discover-deadline-input").value) },
      });
      notice("Discovery started. Alive hosts appear in step 2 when it finishes.");
      await loadRuns();
      if (state.job.run_id) state.runId = state.job.run_id;
      await loadRun();
    } catch (error) {
      notice(error.message, "error");
    } finally {
      await loadStatus().catch(() => {});
      scheduleNext();
    }
  }

  async function startTarget(event) {
    event.preventDefault();
    const ip = $("#target-ip").value.trim();
    if (!IPV4.test(ip)) {
      notice("Enter an IPv4 address from the alive list.", "error");
      return;
    }
    if (!state.runId) {
      notice("Run discovery first.", "error");
      return;
    }
    $("#target-btn").disabled = true;
    try {
      state.job = await api(`/api/runs/${encodeURIComponent(state.runId)}/target`, {
        method: "POST", token: true,
        body: {
          ip,
          deadline_seconds: Number($("#target-deadline-input").value),
          fuzz: $("#fuzz-input").checked,
          external_tools: $("#external-input").checked,
          full_scan: $("#full-scan-input").checked,
          ports: $("#target-ports-input").value.trim() || null,
          auth_hosts: $("#target-auth-input").value
            .split(",").map((item) => item.trim()).filter(Boolean),
        },
      });
      notice(`Scan of ${ip} started using ${state.status.scope.manifest_name}.`);
      await loadRun();
    } catch (error) {
      notice(error.message, "error");
    } finally {
      await loadStatus().catch(() => {});
      scheduleNext();
    }
  }

  function renderControls() {
    const scope = state.status.scope;
    const ready = scope.state === "valid" && scope.window_open;
    const busy = jobRunning();
    $("#discover-btn").disabled = !ready || busy;
    let discoverHint = "";
    if (scope.state !== "valid") discoverHint = "Start the server with --scope to enable scans.";
    else if (!scope.window_open) discoverHint = "The authorisation window is closed.";
    else if (busy) discoverHint = "A job is running.";
    $("#discover-hint").textContent = discoverHint;

    const ip = $("#target-ip").value.trim();
    const hasRun = Boolean(state.view);
    $("#fuzz-input").disabled = !scope.fuzz_allowed || busy;
    if (!scope.fuzz_allowed) $("#fuzz-input").checked = false;
    $("#target-btn").disabled = !ready || busy || !hasRun || !IPV4.test(ip);
    let targetHint = "";
    if (!hasRun) targetHint = "Run discovery first.";
    else if (!IPV4.test(ip)) targetHint = "Pick or type an IPv4 address.";
    else if (busy) targetHint = "A job is running.";
    else if (!scope.web_inventory || !scope.auth_tests || !scope.flag_patterns) {
      const limits = [];
      if (!scope.web_inventory) limits.push("web inventory off");
      if (!scope.auth_tests) limits.push("credential tests off");
      if (!scope.flag_patterns) limits.push("no flag patterns");
      targetHint = `Current scope (${scope.manifest_name}): ${limits.join(", ")}.`;
    } else if (!scope.fuzz_allowed) targetHint = "Endpoint fuzzing is excluded by the current scope.";
    $("#target-hint").textContent = targetHint;
  }

  // -- rendering -----------------------------------------------------------------------------
  function renderEmpty() {
    $("#stepper").innerHTML = DISCOVER_STAGES.map((stage) => `<li class="pending"><b>${esc(stage.label)}</b>waiting</li>`).join("");
    $("#phase-tag").textContent = "no run yet";
    ["#alive-list", "#board-hosts", "#board-endpoints", "#board-binaries", "#board-lineage", "#board-creds", "#board-findings",
      "#verify-list", "#path-list", "#timeline", "#coverage", "#gaps", "#limitations"].forEach((id) => {
      $(id).innerHTML = '<p class="empty">Nothing to show yet.</p>';
    });
    $("#guard-kv").innerHTML = "";
    $("#downloads").innerHTML = "";
    $("#mermaid").textContent = "";
    renderAgents(null);
    renderControls();
  }

  function renderAll() {
    renderControls();
    renderGuard(state.view);
    renderStepper(state.view);
    renderDeadline(state.view);
    renderAgents(state.view);
    renderAlive(state.view);
    renderBoard(state.view);
    renderLineage(state.view);
    renderVerify(state.view);
    renderPaths(state.view);
    renderDownloads(state.view);
    renderTimeline(state.view);
    renderCoverage(state.view);
    renderGaps();
    document.querySelectorAll(".agent").forEach((card) => {
      const active = state.view && state.view.run.status === "running" && state.view.agents.some(
        (agent) => agent.agent === card.dataset.agent && (agent.states.running || 0) > 0);
      card.classList.toggle("active", Boolean(active));
    });
  }

  function latestPayload(view, type) {
    const event = view.events.find((item) => item.type === type);
    return event ? event.payload : null;
  }

  function renderGuard(view) {
    const cfg = view.config || {};
    const validated = view.validated || {};
    const cells = [
      [validated.hosts_in_scope ?? "–", "hosts in scope"],
      [cfg.rate_pps ?? validated.rate_pps ?? "–", "probe cap (pps)"],
      [cfg.auth_tests ?? validated.auth_tests ? "on" : "off", "credential tests"],
      [view.target_ip || "none yet", "target IP"],
      [view.scope.refused, "out-of-scope refused"],
      [view.scope.sent_outside, "sent outside scope"],
      [view.counts.hosts, "alive hosts"],
      [view.counts.open_ports, "open ports"],
    ];
    $("#guard-kv").innerHTML = cells.map(([value, label]) =>
      `<div><b>${esc(value)}</b><span>${esc(label)}</span></div>`).join("");
  }

  function stageSet(view) {
    if (view.mode === "discover") return DISCOVER_STAGES;
    if (view.mode === "target") return TARGET_STAGES;
    return [...DISCOVER_STAGES, ...TARGET_STAGES];
  }

  function renderStepper(view) {
    const stages = stageSet(view);
    const finished = new Map(view.stages.map((stage) => [stage.name, stage]));
    const running = view.current_stage;
    $("#stepper").innerHTML = stages.map((stage) => {
      let klass = "pending";
      let detail = "queued";
      if (finished.has(stage.id)) {
        klass = "done";
        detail = `${finished.get(stage.id).seconds ?? 0}s`;
      } else if (running === stage.id) {
        klass = "running";
        detail = "running";
      }
      return `<li class="${klass}"><b>${esc(stage.label)}</b>${esc(detail)} · ${esc(stage.phase.replace(/_/g, " "))}</li>`;
    }).join("");
    const active = stages.find((stage) => stage.id === running);
    const modeLabel = view.mode === "discover" ? "discovery" : view.mode === "target" ? `target ${view.target_ip || ""}` : "hunt";
    $("#phase-tag").textContent = view.run.status === "running"
      ? `${modeLabel} · ${active ? active.phase.replace(/_/g, " ") : "running"}`
      : `${modeLabel} · ${view.run.status}`;
  }

  function renderDeadline(view) {
    const started = Date.parse(view.run.started_at);
    const budget = ((view.config && view.config.deadline_seconds) || 1200) * 1000;
    const end = view.run.finished_at ? Date.parse(view.run.finished_at) : Date.now();
    const used = Number.isFinite(started) ? Math.min(1, Math.max(0, (end - started) / budget)) : 0;
    $("#deadline-fill").style.width = `${(used * 100).toFixed(1)}%`;
    const elapsed = Number.isFinite(started) ? Math.round((end - started) / 1000) : 0;
    const tool = view.config && view.config.tool ? view.config.tool : "–";
    $("#deadline-text").textContent = `${elapsed}s of ${Math.round(budget / 1000)}s budget · tool ${tool}`;
  }

  function renderAgents(view) {
    AGENTS.forEach((id) => {
      const body = document.querySelector(`.agent[data-agent="${id}"] .agent-body`);
      if (!body) return;
      const entry = view ? view.agents.find((agent) => agent.agent === id) : null;
      if (!entry) {
        body.innerHTML = '<div class="last">idle</div>';
        return;
      }
      const pills = Object.entries(entry.states).map(([name, count]) =>
        `<span class="pill">${esc(name)} ${esc(count)}</span>`).join("");
      body.innerHTML = `<div class="state">${pills}</div>
        <div class="last">${esc(entry.kinds.join(", "))}</div>
        <div class="last">last: ${esc(entry.last_event || "–")} ${esc(when(entry.last_ts))}</div>`;
    });
  }

  function renderAlive(view) {
    const hosts = view.hosts || [];
    const rows = hosts.filter((host) => host.ports.length || host.source);
    $("#alive-list").innerHTML = rows.length
      ? rows.map((host) => `<button type="button" class="alive" data-ip="${esc(host.ip)}">
          <b>${esc(host.ip)}</b><span>${esc(host.ports.length)} open</span></button>`).join("")
      : '<p class="empty">No alive hosts yet. Run discovery first.</p>';
    document.querySelectorAll(".alive").forEach((button) => {
      button.addEventListener("click", () => {
        $("#target-ip").value = button.dataset.ip;
        renderControls();
      });
    });
  }

  function renderBoard(view) {
    const hosts = view.hosts.filter((host) => host.ports.length || host.source);
    $("#board-hosts").innerHTML = hosts.length
      ? `<div class="scroll"><table><tr><th>Host</th><th>Open ports</th></tr>${hosts.map((host) =>
        `<tr><td class="wrap">${esc(host.ip)}</td><td>${host.ports.map((port) =>
          `${esc(port.port)}/${esc(port.name || "tcp")}${port.product ? ` (${esc(short(port.product, 30))})` : ""}`)
          .join("<br>") || '<span class="muted">none</span>'}</td></tr>`).join("")}</table></div>`
      : '<p class="empty">No live hosts yet.</p>';

    $("#board-endpoints").innerHTML = view.endpoints.length
      ? `<div class="scroll"><table><tr><th>Method</th><th>URL (parameter values redacted)</th></tr>${view.endpoints.map(
        (item) => `<tr><td>${esc(item.method)}</td><td class="wrap">${esc(short(item.url, 120))}</td></tr>`).join("")}</table></div>`
      : '<p class="empty">No endpoints yet.</p>';

    $("#board-binaries").innerHTML = view.binaries.length
      ? `<div class="scroll"><table><tr><th>Binary</th><th>Format</th><th>Protections</th><th>Analysis</th>
          <th>Literals</th><th>State</th></tr>${view.binaries.map((item) => binaryRow(item)).join("")}</table></div>`
      : '<p class="empty">No binary found on this target yet.</p>';

    $("#board-creds").innerHTML = view.credentials.length
      ? `<div class="scroll"><table><tr><th>Ref</th><th>Kind</th><th>Source</th></tr>${view.credentials.map(
        (item) => `<tr><td>${esc(item.secret_ref)}</td><td>${esc(item.kind)}</td><td class="wrap">${esc(short(item.source, 60))}</td></tr>`).join("")}</table></div>`
      : '<p class="empty">No credential-like literal recovered yet.</p>';

    $("#board-findings").innerHTML = view.candidates.length
      ? `<div class="scroll"><table><tr><th>#</th><th>Class</th><th>State</th><th>Target</th></tr>${view.candidates.map(
        (item) => `<tr><td>${esc(item.id)}</td><td class="wrap">${esc(item.class)}</td>
          <td><span class="badge ${esc(item.state)}">${esc(item.state)}</span></td>
          <td class="wrap">${esc(targetOf(item))}</td></tr>`).join("")}</table></div>`
      : '<p class="empty">No leads yet.</p>';
  }

  function binaryRow(item) {
    const d = item.details || {};
    const p = d.protections || {};
    const a = d.analysis || {};
    const s = d.solver || {};
    const protections = [p.nx ? "NX" : "no NX", p.pie ? "PIE" : "no PIE",
      p.relro ? `RELRO ${p.relro}` : "no RELRO"].join(" · ");
    const analysis = a.tool ? `${a.tool} · ${a.status}` : (a.status || "not run");
    const errors = (a.errors || []).map((message) => `<div class="muted">${esc(short(message, 140))}</div>`).join("");
    const solver = s.status ? `solver: ${esc(s.status)}${s.reason ? ` (${esc(short(s.reason, 90))})` : ""}` : "";
    return `<tr><td class="wrap">${esc(item.name || item.sha256.slice(0, 12))}</td><td>${esc(item.format)}</td>
      <td class="wrap">${esc(protections)}</td>
      <td class="wrap">${esc(analysis)}${errors}<div class="muted">${esc(a.functions ?? 0)} functions ·
        ${esc(a.decompiled_functions ?? 0)} decompiled</div></td>
      <td>${esc(d.literal_count ?? 0)}</td>
      <td class="wrap">${esc(item.state)}${solver ? `<div class="muted">${solver}</div>` : ""}</td></tr>`;
  }

  function renderLineage(view) {
    const rows = view.lineage || [];
    const ids = new Set(rows.map((row) => row.id));
    const children = new Map();
    rows.forEach((row) => {
      const parent = row.parent_task_id && ids.has(row.parent_task_id) ? row.parent_task_id : "";
      children.set(parent, [...(children.get(parent) || []), row]);
    });
    const describe = (row) => {
      const p = row.payload || {};
      const extras = [];
      if (Array.isArray(p.forwarded) && p.forwarded.length) extras.push(`forwarded ${p.forwarded.join(", ")}`);
      if (Array.isArray(p.names) && p.names.length) extras.push(`headers ${p.names.join(", ")}`);
      if (typeof p.paths === "number") extras.push(`${p.paths} path(s)`);
      if (p.path) extras.push(String(p.path));
      if (p.name) extras.push(String(p.name));
      return `<span class="badge ${esc(row.state)}">${esc(row.state)}</span> ${esc(row.agent)} · ${esc(row.kind)}${
        extras.map((text) => ` · ${esc(short(text, 80))}`).join("")}`;
    };
    const render = (parent) => (children.get(parent) || []).map((row) =>
      `<li>${describe(row)}${children.get(row.id) ? `<ul>${render(row.id)}</ul>` : ""}</li>`).join("");
    const html = render("");
    $("#board-lineage").innerHTML = html ? `<ol class="lineage">${html}</ol>` : '<p class="empty">No discovery steps yet.</p>';
  }

  function targetOf(item) {
    const d = item.details || {};
    if (d.ip) return `${d.ip}:${d.port ?? ""} ${d.path || d.parameter || ""}`.trim();
    return `binary ${String(d.binary_sha256 || "").slice(0, 12)}${d.offset !== undefined ? ` @${d.offset}` : ""}`;
  }

  function renderVerify(view) {
    const items = view.candidates;
    if (!items.length) {
      $("#verify-list").innerHTML = '<p class="empty">Waiting for leads from the agents.</p>';
      return;
    }
    const order = { confirmed: 0, inconclusive: 1, rejected: 2, candidate: 3 };
    const rows = [...items].sort((a, b) => (order[a.state] - order[b.state]) || (a.id - b.id));
    $("#verify-list").innerHTML = rows.map((item) => `
      <div class="vrow">
        <div class="head">
          <span class="badge ${esc(item.state)}">${esc(item.state === "candidate" ? "CANDIDATE" : item.state.toUpperCase())}</span>
          <b>${esc(item.class)}</b>
          <span class="muted small">${esc(item.attempts ? `${item.attempts} attempt(s)` : "")}</span>
        </div>
        <div class="small wrap">${esc(targetOf(item))}</div>
        <p>${esc(item.summary || item.claim)}</p>
        ${item.oracle ? `<p><b>oracle:</b> ${esc(item.oracle)} · <b>control:</b> ${esc(item.control || "–")}</p>` : ""}
      </div>`).join("");
  }

  function renderPaths(view) {
    const paths = view.attack_path.paths || [];
    if (!paths.length) {
      $("#path-list").innerHTML = `<p class="empty">No objective reached yet (${esc(view.counts.confirmed)} confirmed finding(s)).</p>`;
      return;
    }
    $("#path-list").innerHTML = paths.map((path, index) => `
      <div class="path">
        <div class="objective">Path ${index + 1}: ${esc(path.objective)}</div>
        <ol>${path.steps.map((step) => `<li><span class="phase">${esc(step.ptes_phase.replace(/_/g, " "))}</span>
          ${esc(short(step.from, 60))} → ${esc(short(step.to, 60))} <span class="muted">(${esc(step.action)})</span></li>`).join("")}</ol>
      </div>`).join("");
  }

  function renderDownloads(view) {
    const formats = [["md", "Markdown"], ["html", "HTML"], ["json", "JSON"], ["attack-path", "Attack path JSON"], ["mermaid", "Mermaid"]];
    $("#downloads").innerHTML = formats.map(([key, label]) => {
      const enabled = Boolean(view.reports[key]);
      return `<a href="/api/runs/${encodeURIComponent(view.run.id)}/report/${esc(key)}" aria-disabled="${!enabled}">${esc(label)}</a>`;
    }).join("");
    $("#mermaid").textContent = view.attack_path.mermaid || "(no attack path yet)";
  }

  function renderTimeline(view) {
    $("#timeline").innerHTML = view.events.slice(0, 80).map((event) => {
      const verdict = event.payload.verdict === "confirmed";
      const kind = verdict ? "verdict" : /stage|report|run\.|target|discovery\.completed/.test(event.type) ? "stage"
        : /failed|refused|rejected/.test(event.type) ? "alert" : "";
      const detail = event.payload.summary || event.payload.url || event.payload.ip || event.payload.class || event.payload.stage || "";
      return `<li class="${kind}"><b>${esc(event.type)}</b> <span class="meta">${esc(event.agent)} · ${esc(event.ptes_phase.replace(/_/g, " "))}</span>
        ${detail ? `<div class="meta wrap">${esc(short(detail, 110))}</div>` : ""}
        <div class="meta">${esc(when(event.ts))}</div></li>`;
    }).join("") || '<li class="meta">no events yet</li>';
  }

  function renderCoverage(view) {
    $("#coverage").innerHTML = view.coverage.length
      ? `<div class="scroll"><table class="coverage-table"><tr><th>Check</th><th>State</th></tr>${view.coverage.slice(0, 120).map(
        (item) => `<tr><td class="wrap">${esc(item.attack_class)}</td><td>${esc(item.state)}</td></tr>`).join("")}</table></div>`
      : '<p class="empty">No coverage rows yet.</p>';
  }

  function renderGaps() {
    const report = state.report;
    const gaps = report ? report.gaps || [] : [];
    const limitations = report ? report.limitations || [] : [];
    $("#gaps").innerHTML = gaps.length ? gaps.map((item) => `<li>${esc(item)}</li>`).join("")
      : '<li class="muted">Gaps appear here when a scan completes.</li>';
    $("#limitations").innerHTML = limitations.length ? limitations.map((item) => `<li>${esc(item)}</li>`).join("")
      : '<li class="muted">Limitations appear here when a scan completes.</li>';
  }

  // -- wiring -----------------------------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", async () => {
    $("#discover-form").addEventListener("submit", startDiscovery);
    $("#target-form").addEventListener("submit", startTarget);
    $("#target-ip").addEventListener("input", renderControls);
    $("#run-select").addEventListener("change", async (event) => {
      state.runId = event.target.value;
      await loadRun();
    });
    try {
      await loadStatus();
      await pollJob();
      await loadRuns();
      await loadRun();
    } catch (error) {
      notice(`Could not reach the MITIGATA server: ${error.message}`, "error");
    } finally {
      scheduleNext();
    }
  });
})();
