// ---------------- Shell: rail navigation (hash-based) ----------------
const SECTIONS = ["agent", "intel", "shield", "metrics"];

function showSection(id, focus) {
  if (!SECTIONS.includes(id)) id = "agent";
  SECTIONS.forEach(s => { document.getElementById(s).hidden = s !== id; });
  document.querySelectorAll("#rail-nav a").forEach(a => {
    if (a.dataset.section === id) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  if (id === "intel") loadThreatIntel();
  if (id === "shield") { loadTrending(); loadBlockedDomains(); startInboxFeed(); }
  else { stopInboxFeed(); }
  if (id === "metrics") loadMetrics();
  if (focus) document.getElementById("main").focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

window.addEventListener("hashchange", () => showSection(location.hash.slice(1), true));

// Feed status in the rail: live, local cache, or never synced. Real values only.
async function loadFeedStatus() {
  const el = document.getElementById("feed-status");
  try {
    const [kev, phish] = await Promise.all([
      fetch("/api/threat-intel/meta").then(r => r.json()),
      fetch("/api/blocked-domains/meta").then(r => r.json()),
    ]);
    el.innerHTML = feedStatusRow("CISA KEV", kev) + feedStatusRow("OpenPhish", phish);
  } catch (e) {
    el.innerHTML = "<dt>Feeds</dt><dd>Status unavailable</dd>";
  }
}

function feedStatusRow(name, meta) {
  let state;
  if (!meta || !meta.last_synced_at) state = "Not synced yet";
  else if (meta.source === "live") state = "Live · " + meta.last_synced_at;
  else state = "Local cache · " + (meta.source || "").replace(/^cached \(fetched /, "").replace(/\)$/, "");
  return `<dt>${name}</dt><dd>${escapeHtml(state)}</dd>`;
}


// ---------------- Shared helpers ----------------
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function escapeHtml(str) {
  return String(str == null ? "" : str).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function sevTag(sev) {
  const s = SEV_ORDER[sev] === undefined ? "low" : sev;
  return `<span class="sev sev-${s}">${escapeHtml(sev || "n/a")}</span>`;
}

function statusTag(status) {
  return `<span class="tag tag-${escapeHtml(status)}">${escapeHtml(status)}</span>`;
}

function setBusy(btn, busy, label) {
  btn.disabled = busy;
  if (busy) btn.setAttribute("aria-busy", "true"); else btn.removeAttribute("aria-busy");
  if (label) btn.textContent = label;
}

async function getJson(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(url + " returned " + res.status);
  return res.json();
}

function notice(text, isError) {
  const el = document.getElementById("decision-notice");
  el.textContent = text;
  el.classList.toggle("is-error", !!isError);
}

// "Path Traversal - precedent: Fortinet ..." -> ["Path Traversal", "Fortinet ..."]
function splitRuleName(name) {
  const i = (name || "").indexOf(" - precedent: ");
  return i === -1 ? [name, ""] : [name.slice(0, i), name.slice(i + 14)];
}

// ---------------- Rules: queue + enforced (shared by Agent and Threat Intel) ----------------
let intelCache = { patterns: [], domains: [] };
const justApproved = new Set();

async function loadThreatIntel() {
  const queue = document.getElementById("queue");
  let patterns, domains;
  try {
    [patterns, domains] = await Promise.all([getJson("/api/threat-intel"), getJson("/api/blocked-domains/all")]);
  } catch (e) {
    queue.removeAttribute("aria-busy");
    queue.innerHTML = '<li class="panel state state-error"><strong>Could not load drafted rules.</strong> The server did not respond. Reload the page to try again.</li>';
    document.getElementById("enforced-body").innerHTML = '<tr><td colspan="5" class="state state-error">Could not load enforced rules.</td></tr>';
    return;
  }
  intelCache = { patterns, domains };
  renderQueue();
  renderEnforced();
  if (typeof renderIntelTable === "function") renderIntelTable();
}

function queueItems() {
  const { patterns, domains } = intelCache;
  const code = patterns.filter(p => p.status === "pending").map(p => ({ kind: "code", key: p.id, rec: p }));
  const dom = domains.filter(d => d.status === "pending").map(d => ({ kind: "domain", key: d.domain, rec: d }));
  return code.concat(dom).sort((a, b) => (SEV_ORDER[a.rec.severity] - SEV_ORDER[b.rec.severity]) || String(b.rec.date_added).localeCompare(String(a.rec.date_added)));
}

function renderQueue() {
  const items = queueItems();
  const queue = document.getElementById("queue");
  queue.removeAttribute("aria-busy");
  document.getElementById("queue-count").textContent = items.length ? `(${items.length})` : "";
  document.getElementById("rail-pending").textContent = items.length ? items.length : "";
  if (!items.length) {
    queue.innerHTML = '<li class="panel state"><strong>No rules are waiting for approval.</strong> Sync the feeds in <a href="#intel">Threat Intel</a> to draft rules for newly reported attacks.</li>';
    return;
  }
  const code = items.filter(it => it.kind === "code");
  const dom = items.filter(it => it.kind === "domain");
  const group = (title, list, render) => list.length
    ? `<li class="queue-group label" role="presentation">${title} (${list.length})</li>` + list.map(it => render(it.rec)).join("")
    : "";
  queue.innerHTML = group("Code rules drafted from CISA KEV", code, codeRuleItem)
    + group("Domain rules drafted from OpenPhish", dom, domainRuleItem);
}

function decisionColumn(kind, key, where) {
  return `
    <div class="rule-decide">
      <span class="label">Analyst decision</span>
      <button type="button" class="btn btn-approve" data-decide="approve" data-kind="${kind}" data-key="${escapeHtml(key)}" data-where="${escapeHtml(where)}">Approve</button>
      <button type="button" class="btn btn-reject" data-decide="reject" data-kind="${kind}" data-key="${escapeHtml(key)}">Reject</button>
      <span class="hint" aria-live="polite"></span>
    </div>`;
}

function codeRuleItem(p) {
  const [category, precedent] = splitRuleName(p.name);
  const patternCell = p.regex
    ? `<code class="pattern">${escapeHtml(p.regex)}</code>`
    : '<span class="muted">No automatic signature. This attack class depends on business logic a static scanner cannot infer, so approving it adds manual-review guidance only.</span>';
  const cve = p.source_cve
    ? (p.source_url ? `<a class="data" href="${escapeHtml(p.source_url)}" target="_blank" rel="noopener">${escapeHtml(p.source_cve)}</a>` : `<span class="data">${escapeHtml(p.source_cve)}</span>`)
    : "";
  const examples = p.example_vulnerable ? `
      <div class="examples">
        <div><div class="label">Would flag</div><code class="pattern">${escapeHtml(p.example_vulnerable)}</code></div>
        <div><div class="label">Suggested fix</div><code class="pattern">${escapeHtml(p.example_fixed)}</code></div>
      </div>` : "";
  return `
    <li class="rule" id="rule-${cssId(p.id)}">
      <div class="rule-body">
        <div class="rule-title">${statusTag(p.status)} ${sevTag(p.severity)} <h3>${escapeHtml(category)}</h3></div>
        <dl class="rule-fields">
          <dt>Rule pattern</dt><dd>${patternCell}</dd>
          <dt>Source entry</dt><dd>CISA KEV ${cve}${precedent ? " &middot; " + escapeHtml(precedent) : ""}<span class="cell-sub">${escapeHtml(p.description)}</span></dd>
          <dt>Protects against</dt><dd><span class="data">${escapeHtml(p.cwe || "")}</span> ${escapeHtml(category)} in application code.${examples}</dd>
          <dt>Enforced in</dt><dd><span class="tag tag-where">Dev/CI scanner</span></dd>
          <dt>Rule ID</dt><dd class="data">${escapeHtml(p.id)} &middot; drafted ${escapeHtml(p.date_added)}</dd>
        </dl>
      </div>
      ${decisionColumn("code", p.id, "the Dev/CI scanner")}
    </li>`;
}

function domainRuleItem(d) {
  const reported = d.reported_url ? `<code class="pattern break">${escapeHtml(d.reported_url)}</code>` : "";
  return `
    <li class="rule" id="rule-${cssId(d.domain)}">
      <div class="rule-body">
        <div class="rule-title">${statusTag(d.status)} ${sevTag(d.severity)} <h3 class="data">${escapeHtml(d.domain)}</h3></div>
        <dl class="rule-fields">
          <dt>Rule pattern</dt><dd><code class="pattern">host == ${escapeHtml(d.domain)}  OR  host ends with .${escapeHtml(d.domain)}</code></dd>
          <dt>Source entry</dt><dd>${escapeHtml(d.source)}${reported ? '<span class="cell-sub">Reported URL</span>' + reported : ""}</dd>
          <dt>Protects against</dt><dd>${escapeHtml(d.category)}. Any link to this domain or its subdomains in a customer message is blocked. Only the destination is checked; message content is not read.</dd>
          <dt>Enforced in</dt><dd><span class="tag tag-where">Customer Shield link firewall</span></dd>
          <dt>Drafted</dt><dd class="data">${escapeHtml(d.date_added)}</dd>
        </dl>
      </div>
      ${decisionColumn("domain", d.domain, "the Customer Shield link firewall")}
    </li>`;
}

const ENFORCED_PREVIEW = 8;
let enforcedExpanded = false;
document.getElementById("enforced-more").addEventListener("click", () => { enforcedExpanded = !enforcedExpanded; renderEnforced(); });

function renderEnforced() {
  const { patterns, domains } = intelCache;
  const rows = patterns.filter(p => p.status === "approved").map(p => ({
    key: p.id, date: p.date_added, sev: p.severity,
    rule: `${escapeHtml(splitRuleName(p.name)[0])}<span class="cell-sub data">${escapeHtml(p.id)}${p.cwe ? " &middot; " + escapeHtml(p.cwe) : ""}${p.category === "dependency" ? " &middot; dependency version check" : (p.regex ? "" : " &middot; manual review only")}</span>`,
    where: "Dev/CI scanner", source: p.source,
  })).concat(domains.filter(d => d.status === "approved").map(d => ({
    key: d.domain, date: d.date_added, sev: d.severity,
    rule: `<span class="data break">${escapeHtml(d.domain)}</span><span class="cell-sub">${escapeHtml(d.category)}</span>`,
    where: "Customer Shield link firewall", source: d.source,
  })));
  rows.sort((a, b) => (justApproved.has(b.key) - justApproved.has(a.key)) || String(b.date).localeCompare(String(a.date)) || (SEV_ORDER[a.sev] - SEV_ORDER[b.sev]));
  document.getElementById("enforced-count").textContent = `(${rows.length})`;
  const body = document.getElementById("enforced-body");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="5" class="state">No rules are enforced yet. Approve a drafted rule above to start enforcing it.</td></tr>';
    return;
  }
  const limit = enforcedExpanded ? rows.length : ENFORCED_PREVIEW;
  const more = document.getElementById("enforced-more");
  more.hidden = rows.length <= ENFORCED_PREVIEW;
  more.textContent = enforcedExpanded ? "Show newest " + ENFORCED_PREVIEW + " only" : `Show all ${rows.length} enforced rules`;
  more.setAttribute("aria-expanded", String(enforcedExpanded));
  body.innerHTML = rows.slice(0, limit).map(r => `
    <tr class="${justApproved.has(r.key) ? "is-new" : ""}">
      <td class="top wrap">${justApproved.has(r.key) ? '<span class="tag tag-approved">just approved</span> ' : ""}${r.rule}</td>
      <td>${sevTag(r.sev)}</td>
      <td class="nowrap"><span class="tag tag-where">${r.where}</span></td>
      <td class="top wrap"><span class="cell-sub">${escapeHtml(r.source)}</span></td>
      <td class="data nowrap">${escapeHtml(r.date)}</td>
    </tr>`).join("");
}

// Two-step decision: first click arms the button, second click within 6s commits.
document.getElementById("queue").addEventListener("click", async e => {
  const btn = e.target.closest("button[data-decide]");
  if (!btn || btn.disabled) return;
  const item = btn.closest(".rule");
  const hint = item.querySelector(".hint");
  const action = btn.dataset.decide;

  if (!btn.classList.contains("is-confirming")) {
    item.querySelectorAll("button[data-decide]").forEach(b => disarm(b));
    btn.classList.add("is-confirming");
    btn.dataset.label = btn.textContent;
    btn.textContent = action === "approve" ? "Confirm approval" : "Confirm rejection";
    hint.textContent = action === "approve"
      ? `Click again to enforce this rule in ${btn.dataset.where}.`
      : "Click again to reject. Rejected rules are not enforced.";
    clearTimeout(btn._t);
    btn._t = setTimeout(() => { disarm(btn); hint.textContent = ""; }, 6000);
    return;
  }

  clearTimeout(btn._t);
  item.querySelectorAll("button[data-decide]").forEach(b => { b.disabled = true; });
  setBusy(btn, true, action === "approve" ? "Approving" : "Rejecting");
  hint.textContent = "";
  const { kind, key } = btn.dataset;
  const url = kind === "code"
    ? `/api/threat-intel/${encodeURIComponent(key)}/${action}`
    : `/api/blocked-domains/${encodeURIComponent(key)}/${action}`;
  try {
    const res = await fetch(url, { method: "POST" });
    if (!res.ok) throw new Error(res.status);
    if (action === "approve") {
      justApproved.add(key);
      notice(kind === "code"
        ? `Approved ${key}. The Dev/CI scanner checks for it from the next scan onward.`
        : `Approved ${key}. The Customer Shield now blocks links to this domain.`);
    } else {
      notice(`Rejected ${key}. It will not be enforced.`);
    }
    await loadThreatIntel();
    loadFeedStatus();
    if (action === "approve") document.getElementById("enforced-h").scrollIntoView({ block: "start", behavior: "smooth" });
  } catch (err) {
    notice(`Could not ${action} ${key}: the server did not accept the request. Nothing was changed.`, true);
    item.querySelectorAll("button[data-decide]").forEach(b => { b.disabled = false; disarm(b); });
    setBusy(btn, false);
    btn.textContent = action === "approve" ? "Approve" : "Reject";
  }
});

function disarm(btn) {
  if (!btn.classList.contains("is-confirming")) return;
  btn.classList.remove("is-confirming");
  btn.textContent = btn.dataset.label || (btn.dataset.decide === "approve" ? "Approve" : "Reject");
}

// ---------------- Dev/CI scan ----------------
let currentFindings = [];
let activeSevFilter = "all";
let scanStale = false;
let polling = false;
let eventsSeen = 0;

async function loadRepos() {
  const sel = document.getElementById("repo-select");
  try {
    const repos = await getJson("/api/repos");
    sel.innerHTML = repos.map(r => `<option value="${escapeHtml(r.id)}">${escapeHtml(r.name)} (${r.file_count} files)</option>`).join("");
    sel.disabled = false;
  } catch (e) {
    sel.innerHTML = "<option>Could not load repositories</option>";
    document.getElementById("run-scan-btn").disabled = true;
  }
}

const LOG_LABEL = { info: "info", checking: "check", clear: "clear", found: "found", done: "done", error: "error" };

function logLine(ev) {
  const k = LOG_LABEL[ev.kind] || ev.kind;
  return `<li class="${escapeHtml(ev.kind)}"><span class="k k-${escapeHtml(ev.kind)}">${escapeHtml(k)}</span><span>${escapeHtml(ev.text)}</span></li>`;
}

document.getElementById("run-scan-btn").addEventListener("click", startScan);

async function startScan() {
  const btn = document.getElementById("run-scan-btn");
  const repoId = document.getElementById("repo-select").value;
  setBusy(btn, true, "Scanning");
  document.getElementById("repo-select").disabled = true;
  eventsSeen = 0;
  currentFindings = [];
  scanStale = false;
  document.getElementById("stale-banner").hidden = true;
  document.getElementById("scan-summary").innerHTML = '<span class="muted">Scan running&hellip;</span>';
  document.getElementById("agent-feed").innerHTML = "";
  document.getElementById("findings-list").innerHTML = '<tr><td colspan="5" class="state">Scan in progress. Findings appear when it finishes.</td></tr>';
  document.getElementById("findings-count").textContent = "";

  try {
    const { job_id } = await getJson("/api/scan/start", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repo_id: repoId })
    });
    polling = true;
    pollJob(job_id, btn, Date.now());
  } catch (e) {
    scanFailed(btn, "Could not start the scan: the server did not respond.");
  }
}

function scanFailed(btn, msg) {
  polling = false;
  setBusy(btn, false, "Run scan");
  document.getElementById("repo-select").disabled = false;
  document.getElementById("scan-summary").innerHTML = `<span class="state-error">${escapeHtml(msg)}</span>`;
  document.getElementById("findings-list").innerHTML = '<tr><td colspan="5" class="state state-error">No findings: the scan did not complete.</td></tr>';
}

async function pollJob(jobId, btn, startTime) {
  if (!polling) return;
  let job;
  try {
    job = await getJson(`/api/scan/${jobId}/status?since=${eventsSeen}`);
  } catch (e) {
    scanFailed(btn, "Lost contact with the server during the scan.");
    return;
  }
  const feed = document.getElementById("agent-feed");
  if (job.events && job.events.length) {
    job.events.forEach(ev => feed.insertAdjacentHTML("beforeend", logLine(ev)));
    feed.scrollTop = feed.scrollHeight;
    eventsSeen = job.event_count;
  }
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  if (job.status === "running") {
    document.getElementById("scan-summary").innerHTML = `<span>${escapeHtml(job.status_line)}</span><span class="muted num">${elapsed}s</span>`;
  }

  if (job.status === "done") {
    polling = false;
    renderResults(job);
    setBusy(btn, false, "Run scan");
    document.getElementById("repo-select").disabled = false;
  } else if (job.status === "error") {
    scanFailed(btn, "Scan failed: " + (job.error || "unknown error"));
  } else {
    setTimeout(() => pollJob(jobId, btn, startTime), 300);
  }
}

function renderResults(job) {
  currentFindings = job.findings;
  const c = job.counts || {};
  let verdict = "PASS: no critical or high findings";
  if (c.critical > 0) verdict = "BLOCK: critical findings must be fixed before this ships";
  else if (c.high > 0) verdict = "WARN: high-severity findings";
  const sevCounts = ["critical", "high", "medium", "low"].map(s => `<span>${sevTag(s)} <span class="num">${c[s] || 0}</span></span>`).join("");
  document.getElementById("scan-summary").innerHTML = `
    <span class="verdict">${verdict}</span>
    ${sevCounts}
    <span class="muted">${escapeHtml(job.repo)} &middot; ${job.files_scanned} files &middot; ${job.patterns_checked} enforced rules &middot; <span class="data">${escapeHtml(job.scanned_at)}</span></span>`;
  activeSevFilter = "all";
  syncFilterButtons();
  renderFindingsList();
}

function syncFilterButtons() {
  document.querySelectorAll("#sev-filter button").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.sev === activeSevFilter)));
}

document.getElementById("sev-filter").addEventListener("click", e => {
  const b = e.target.closest("button");
  if (!b) return;
  activeSevFilter = b.dataset.sev;
  syncFilterButtons();
  renderFindingsList();
});

function renderFindingsList() {
  const list = document.getElementById("findings-list");
  const filtered = activeSevFilter === "all" ? currentFindings : currentFindings.filter(f => f.severity === activeSevFilter);
  document.getElementById("findings-count").textContent = currentFindings.length
    ? `(${filtered.length}${activeSevFilter !== "all" ? " of " + currentFindings.length : ""})` : "";
  if (currentFindings.length === 0) {
    list.innerHTML = '<tr><td colspan="5" class="state">No findings. None of the enforced code rules matched this repository.</td></tr>';
    return;
  }
  if (filtered.length === 0) {
    list.innerHTML = `<tr><td colspan="5" class="state">No ${escapeHtml(activeSevFilter)} findings in this scan.</td></tr>`;
    return;
  }
  list.innerHTML = filtered.map(f => {
    const id = cssId(f.finding_id);
    return `
    <tr>
      <td>${sevTag(f.severity)}</td>
      <td class="top wrap">${escapeHtml(f.name)}<span class="cell-sub data">${escapeHtml(f.pattern_id)}${f.cwe ? " &middot; " + escapeHtml(f.cwe) : ""}</span></td>
      <td class="data nowrap">${escapeHtml(f.file)}:${f.line}</td>
      <td class="data break wrap">${escapeHtml(f.snippet)}</td>
      <td class="nowrap"><button type="button" class="btn btn-sm" aria-expanded="false" aria-controls="d-${id}" data-toggle="d-${id}" data-label="${f.has_code_fix ? "View fix" : "Details"}">${f.has_code_fix ? "View fix" : "Details"}</button></td>
    </tr>
    <tr class="detail" id="d-${id}" hidden>
      <td colspan="5">
        <div class="detail-grid">
          <div>
            <p>${escapeHtml(f.description)}</p>
            <p><span class="label">Suggested fix</span><br>${escapeHtml(f.suggested_fix)}</p>
            <p class="cell-sub">Rule source: ${escapeHtml(f.source)} &middot; added <span class="data">${escapeHtml(f.date_added)}</span></p>
          </div>
          <div>${f.has_code_fix ? fixBoxHtml(f) : '<p>No verified one-click fix exists for this finding. Apply the suggested fix by hand.</p>'}</div>
        </div>
      </td>
    </tr>`;
  }).join("");
  if (scanStale) disableUnappliedFixes();
}

function fixBoxHtml(f) {
  const del = f.fix_original.split("\n").map(l => `<div class="del">${escapeHtml(l)}</div>`).join("");
  const add = f.fix_fixed.split("\n").map(l => `<div class="add">${escapeHtml(l)}</div>`).join("");
  return `
    <div class="label">Verified fix for <span class="data">${escapeHtml(f.file)}:${f.line}</span></div>
    <div class="diff" role="group" aria-label="Code change">${del}${add}</div>
    <div class="fix-actions">
      <button type="button" class="btn btn-primary btn-sm apply-fix-btn" data-repo="${escapeHtml(f.repo_id)}" data-file="${escapeHtml(f.file)}" data-line="${f.line}">Apply this fix</button>
      <span class="fix-msg" aria-live="polite"></span>
    </div>`;
}

function cssId(str) {
  return String(str).replace(/[^a-zA-Z0-9]/g, "_");
}

document.getElementById("findings-list").addEventListener("click", e => {
  const t = e.target.closest("button[data-toggle]");
  if (t) {
    const row = document.getElementById(t.dataset.toggle);
    row.hidden = !row.hidden;
    t.setAttribute("aria-expanded", String(!row.hidden));
    t.textContent = row.hidden ? t.dataset.label : "Hide";
    return;
  }
  const a = e.target.closest(".apply-fix-btn");
  if (a) applyFix(a);
});

async function applyFix(btn) {
  if (scanStale || btn.disabled) return;
  const msg = btn.parentElement.querySelector(".fix-msg");
  setBusy(btn, true, "Applying");
  try {
    const res = await fetch("/api/fix/apply", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_id: btn.dataset.repo, file: btn.dataset.file, line: parseInt(btn.dataset.line, 10) })
    });
    const result = await res.json();
    if (result.ok) {
      setBusy(btn, false, "Applied");
      btn.disabled = true;
      btn.dataset.applied = "1";
      msg.textContent = "Written to the file. Re-run the scan to confirm.";
      markScanStale();
    } else {
      setBusy(btn, false, "Apply this fix");
      msg.textContent = result.error || "Could not apply this fix.";
    }
  } catch (e) {
    setBusy(btn, false, "Apply this fix");
    msg.textContent = "Could not reach the server. Nothing was changed.";
  }
}

function markScanStale() {
  scanStale = true;
  document.getElementById("stale-banner").hidden = false;
  disableUnappliedFixes();
}

function disableUnappliedFixes() {
  document.querySelectorAll(".apply-fix-btn").forEach(b => { if (!b.dataset.applied) { b.disabled = true; b.title = "Re-run the scan first"; } });
}

loadRepos();
loadThreatIntel();
loadFeedStatus();

// ---------------- Threat Intel: sync both feeds ----------------
let lastSync = { code: [], domains: [] };
document.getElementById("sync-btn").addEventListener("click", async () => {
  const btn = document.getElementById("sync-btn");
  const statusEl = document.getElementById("sync-status");
  setBusy(btn, true, "Syncing feeds");
  statusEl.textContent = "Fetching the CISA KEV catalog and the OpenPhish feed. Falls back to the local cache if offline.";
  statusEl.classList.remove("state-error");
  try {
    const [codeRes, domainRes] = await Promise.all([
      getJson("/api/threat-intel/sync", { method: "POST" }),
      getJson("/api/blocked-domains/sync", { method: "POST" }),
    ]);
    const parts = [];
    parts.push(codeRes.ok
      ? `CISA KEV (${codeRes.source}): ${codeRes.total_seen} CVEs read, ${codeRes.new_patterns.length} new rule(s) drafted`
      : `CISA KEV sync failed: ${codeRes.error}`);
    parts.push(domainRes.ok
      ? `OpenPhish (${domainRes.source}): ${domainRes.total_seen} URLs read, ${domainRes.new_domains.length} new domain(s) drafted`
      : `OpenPhish sync failed: ${domainRes.error}`);
    statusEl.textContent = parts.join(". ") + ".";
    statusEl.classList.toggle("state-error", !(codeRes.ok && domainRes.ok));
    lastSync = { code: codeRes.ok ? codeRes.new_patterns.map(p => p.id) : [], domains: domainRes.ok ? domainRes.new_domains.map(d => d.domain) : [] };
  } catch (e) {
    statusEl.textContent = "Sync failed: the server did not respond. Existing rules are unchanged.";
    statusEl.classList.add("state-error");
  }
  setBusy(btn, false, "Sync feeds now");
  await loadThreatIntel();
  loadFeedStatus();
});


// ---------------- Scam Shield tab ----------------
async function loadTrending() {
  const res = await fetch("/api/scam-patterns");
  const patterns = await res.json();
  document.getElementById("trending-list").innerHTML = patterns.map(p => `
    <div class="trend-card">
      <div class="t-name">${p.status === "pending" ? "🆕 " : ""}${escapeHtml(p.name)}</div>
      <div class="t-desc">${escapeHtml(p.description)}</div>
      <div class="t-source">${escapeHtml(p.source)}</div>
    </div>`).join("");
}

async function loadBlockedDomains() {
  const res = await fetch("/api/blocked-domains");
  const domains = await res.json();
  document.getElementById("blocked-domains-list").innerHTML = domains.map(d => `
    <div class="trend-card">
      <div class="t-name">🚫 ${escapeHtml(d.domain)}</div>
      <div class="t-desc">${escapeHtml(d.category)}</div>
      <div class="t-source">${escapeHtml(d.source)}</div>
    </div>`).join("");
}

// ---------------- Live inbox feed (automatic, no paste needed) ----------------
let inboxTimer = null;
const MAX_INBOX_MESSAGES = 6;

function startInboxFeed() {
  if (inboxTimer) return;
  addIncomingMessage();
  inboxTimer = setInterval(addIncomingMessage, 4500);
}

function stopInboxFeed() {
  clearInterval(inboxTimer);
  inboxTimer = null;
}

async function addIncomingMessage() {
  const feed = document.getElementById("inbox-feed");
  if (!feed) return;
  const res = await fetch("/api/inbox/next");
  const msg = await res.json();

  const el = document.createElement("div");
  el.className = "inbox-msg";
  el.dataset.id = msg.id;
  el.innerHTML = `
    <div class="inbox-msg-top">
      <span class="inbox-sender">${escapeHtml(msg.sender)}</span>
      <span class="inbox-time">${msg.arrived_at}</span>
    </div>
    <div class="inbox-text">${escapeHtml(msg.text)}</div>
    <div class="inbox-badge scanning"><span class="dot">◐</span> Scanning…</div>
  `;
  feed.insertBefore(el, feed.firstChild);
  while (feed.children.length > MAX_INBOX_MESSAGES) {
    feed.removeChild(feed.lastChild);
  }

  setTimeout(() => revealVerdict(el, msg), 700);
}

function revealVerdict(el, msg) {
  const badge = el.querySelector(".inbox-badge");
  if (msg.risk === "high") {
    el.classList.add("flagged");
    badge.className = "inbox-badge flagged";
    badge.textContent = `⚠ Flagged — ${msg.score}% likely scam`;
    el.appendChild(buildInboxExpand(msg));
    el.addEventListener("click", () => el.classList.toggle("open"));
  } else if (msg.risk === "medium") {
    el.classList.add("caution");
    badge.className = "inbox-badge caution";
    badge.textContent = `⚠ Caution — ${msg.score}%`;
    el.appendChild(buildInboxExpand(msg));
    el.addEventListener("click", () => el.classList.toggle("open"));
  } else {
    badge.remove();
  }
}

function buildInboxExpand(msg) {
  const wrap = document.createElement("div");
  wrap.className = "inbox-expand";
  const linkRows = (msg.links_checked || []).map(l => `
    <div class="link-row ${l.verdict}">
      <span class="host">🔗 ${escapeHtml(l.host)}</span>
      <span class="verdict-tag">${{ blocked: "🚫 Blocked", warning: "⚠ Caution", allowed: "✓ Clean" }[l.verdict]}</span>
    </div>`).join("");
  wrap.innerHTML = `
    <ul class="reasons-list">${msg.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
    ${linkRows}
  `;
  return wrap;
}

document.getElementById("manual-toggle-btn").addEventListener("click", () => {
  const panel = document.getElementById("manual-panel");
  panel.classList.toggle("hidden");
  document.getElementById("manual-toggle-btn").textContent = panel.classList.contains("hidden")
    ? "✍️ Test a message by hand ▾" : "✍️ Test a message by hand ▴";
});

document.getElementById("scam-check-btn").addEventListener("click", async () => {
  const text = document.getElementById("scam-input").value.trim();
  if (!text) return;
  const res = await fetch("/api/scam-check", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text })
  });
  const result = await res.json();
  showScamResult(result);
});

function showScamResult(result) {
  const box = document.getElementById("scam-result");
  box.classList.remove("hidden");
  document.getElementById("recovery-box").classList.add("hidden");

  const colors = { high: "var(--critical)", medium: "var(--high)", low: "var(--green)" };
  const color = colors[result.risk];
  const ring = document.getElementById("risk-ring");
  ring.style.background = `conic-gradient(${color} ${result.score * 3.6}deg, var(--panel-border) 0deg)`;
  document.getElementById("risk-score").textContent = result.score + "%";
  document.getElementById("risk-score").style.color = color;

  const label = document.getElementById("risk-label");
  label.textContent = result.risk === "high" ? "High risk — likely a scam"
    : result.risk === "medium" ? "Medium risk — be cautious" : "Low risk — looks legitimate";
  label.style.color = color;

  document.getElementById("scam-reasons").innerHTML = result.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("");

  const linksBox = document.getElementById("links-checked-box");
  if (result.links_checked && result.links_checked.length) {
    const tags = { blocked: "🚫 Blocked", warning: "⚠ Caution", allowed: "✓ Clean" };
    linksBox.innerHTML = result.links_checked.map(l => `
      <div class="link-row ${l.verdict}">
        <span class="host">🔗 ${escapeHtml(l.host)}</span>
        <span class="verdict-tag">${tags[l.verdict]}</span>
      </div>`).join("");
    linksBox.classList.remove("hidden");
  } else {
    linksBox.classList.add("hidden");
  }
}

document.getElementById("btn-already-clicked").addEventListener("click", async () => {
  const res = await fetch("/api/recovery");
  const steps = await res.json();
  const box = document.getElementById("recovery-box");
  box.classList.remove("hidden");
  box.innerHTML = "<h4>Recovery checklist</h4>" + steps.map(s => `
    <div class="recovery-step">${escapeHtml(s.step)}<span class="detail">${escapeHtml(s.detail)}</span></div>`).join("");
});

document.getElementById("btn-block-report").addEventListener("click", () => {
  const btn = document.getElementById("btn-block-report");
  btn.textContent = "✓ Reported";
  btn.disabled = true;
});

// ---------------- Metrics tab ----------------
async function loadMetrics() {
  const res = await fetch("/api/metrics");
  if (!res.ok) return;
  const m = await res.json();
  document.getElementById("metrics-grid").innerHTML = `
    <div class="metric-tile"><div class="val">${(m.precision * 100).toFixed(1)}%</div><div class="lab">Precision</div></div>
    <div class="metric-tile"><div class="val">${(m.recall * 100).toFixed(1)}%</div><div class="lab">Recall</div></div>
    <div class="metric-tile"><div class="val">${(m.f1 * 100).toFixed(1)}%</div><div class="lab">F1 Score</div></div>
    <div class="metric-tile"><div class="val">${m.dataset_size}</div><div class="lab">Messages tested</div></div>
  `;
  document.getElementById("confusion-table").innerHTML = `
    <tr><th></th><th>Predicted Scam</th><th>Predicted Legit</th></tr>
    <tr><th>Actual Scam</th><td>${m.true_positive}</td><td>${m.false_negative}</td></tr>
    <tr><th>Actual Legit</th><td>${m.false_positive}</td><td>${m.true_negative}</td></tr>
  `;
}

// ---------------- Boot: show the section named in the URL ----------------
showSection(location.hash.slice(1), false);
