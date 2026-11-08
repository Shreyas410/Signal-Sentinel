// ---------------- Shell: rail navigation (hash-based) ----------------
const SECTIONS = ["agent", "scan", "intel", "shield"];

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
    if (typeof loadFeedMetaTable === "function") loadFeedMetaTable();
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
    queue.innerHTML = '<li class="panel state"><strong>No rules are waiting for approval.</strong> Click “Check for new vulnerabilities” above to draft rules for newly reported attacks.</li>';
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
      ? `Press Confirm approval to enforce this rule in ${btn.dataset.where}. Esc cancels.`
      : "Press Confirm rejection to reject. Rejected rules are not enforced. Esc cancels.";
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
    if (action === "approve") {
      const calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      document.getElementById("enforced-h").scrollIntoView({ block: "start", behavior: calm ? "auto" : "smooth" });
    }
  } catch (err) {
    notice(`Could not ${action} ${key}: the server did not accept the request. Nothing was changed.`, true);
    item.querySelectorAll("button[data-decide]").forEach(b => { b.disabled = false; disarm(b); });
    setBusy(btn, false);
    btn.textContent = action === "approve" ? "Approve" : "Reject";
  }
});

// Escape cancels an armed Approve/Reject.
document.getElementById("queue").addEventListener("keydown", e => {
  if (e.key !== "Escape") return;
  const armed = e.target.closest(".rule") && e.target.closest(".rule").querySelector(".is-confirming");
  if (armed) { clearTimeout(armed._t); disarm(armed); armed.closest(".rule").querySelector(".hint").textContent = "Cancelled."; }
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
  setBusy(btn, false, "Check for new vulnerabilities");
  await loadThreatIntel();
  loadFeedStatus();
});


// ---------------- Threat Intel: feed status table + entries table ----------------
function feedMetaRow(name, meta, unit) {
  if (!meta || !meta.last_synced_at) {
    return `<tr><th scope="row">${name}</th><td><span class="tag tag-pending">not synced</span></td><td colspan="3" class="muted">No sync has run yet. Click Check for new vulnerabilities.</td></tr>`;
  }
  const live = meta.source === "live";
  const status = live
    ? '<span class="tag tag-approved">live</span>'
    : `<span class="tag tag-suspicious">local cache</span><span class="cell-sub">Feed unreachable; used ${escapeHtml(meta.source)}</span>`;
  return `<tr>
    <th scope="row">${name}</th>
    <td class="top wrap">${status}</td>
    <td class="data nowrap">${escapeHtml(meta.last_synced_at)}</td>
    <td class="num">${escapeHtml(meta.total_seen)} ${unit}</td>
    <td class="num">${meta.new_count == null ? "n/a" : escapeHtml(meta.new_count)}</td>
  </tr>`;
}

async function loadFeedMetaTable() {
  const body = document.getElementById("feed-meta-body");
  try {
    const [kev, phish] = await Promise.all([getJson("/api/threat-intel/meta"), getJson("/api/blocked-domains/meta")]);
    body.innerHTML = feedMetaRow("CISA KEV", kev, "CVEs") + feedMetaRow("OpenPhish", phish, "URLs");
  } catch (e) {
    body.innerHTML = '<tr><td colspan="5" class="state state-error">Could not load feed status from the server.</td></tr>';
  }
}

let intelSort = { key: "date", dir: -1 };
let intelFeed = "all";
const STATUS_ORDER = { pending: 0, approved: 1, rejected: 2 };

function intelRows() {
  const { patterns, domains } = intelCache;
  const rows = patterns.map(p => ({
    key: p.id, kind: "code",
    feed: p.source_cve ? "CISA KEV" : "Seed list",
    entry: p.source_cve
      ? (p.source_url ? `<a class="data" href="${escapeHtml(p.source_url)}" target="_blank" rel="noopener">${escapeHtml(p.source_cve)}</a>` : `<span class="data">${escapeHtml(p.source_cve)}</span>`)
      : `<span class="data">${escapeHtml(p.id)}</span>`,
    entryText: p.source_cve || p.id,
    detail: `${escapeHtml(splitRuleName(p.name)[0])}<span class="cell-sub">${escapeHtml(p.cwe || "")}${p.cwe ? " &middot; " : ""}${escapeHtml(p.source)}</span>`,
    sev: p.severity, status: p.status, date: p.date_added || "",
  })).concat(domains.map(d => ({
    key: d.domain, kind: "domain",
    feed: d.source === "OpenPhish Community Feed" ? "OpenPhish" : "Seed list",
    entry: `<span class="data break">${escapeHtml(d.domain)}</span>`,
    entryText: d.domain,
    detail: `${escapeHtml(d.category)}<span class="cell-sub">${escapeHtml(d.source)}</span>`,
    sev: d.severity, status: d.status || "approved", date: d.date_added || "",
  })));
  return rows;
}

function renderIntelTable() {
  const body = document.getElementById("intel-body");
  if (!body) return;
  let rows = intelRows();
  const total = rows.length;
  if (intelFeed !== "all") rows = rows.filter(r => r.feed === intelFeed);
  const k = intelSort.key, dir = intelSort.dir;
  const val = r => k === "sev" ? (SEV_ORDER[r.sev] ?? 9) : k === "status" ? (STATUS_ORDER[r.status] ?? 9) : k === "entry" ? r.entryText.toLowerCase() : k === "feed" ? r.feed : r.date;
  rows.sort((a, b) => { const x = val(a), y = val(b); return (x < y ? -1 : x > y ? 1 : 0) * dir || a.entryText.localeCompare(b.entryText); });
  document.getElementById("entries-count").textContent = intelFeed === "all" ? `(${total})` : `(${rows.length} of ${total})`;
  if (!total) {
    body.innerHTML = '<tr><td colspan="6" class="state">No intel entries yet. Click Check for new vulnerabilities in <a href="#agent">New Vulnerabilities</a> to read the public feeds.</td></tr>';
    return;
  }
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="6" class="state">No entries from ${escapeHtml(intelFeed)} yet. Sync the feeds to draft some.</td></tr>`;
    return;
  }
  const fresh = new Set(lastSync.code.concat(lastSync.domains));
  body.innerHTML = rows.map(r => `
    <tr class="${fresh.has(r.key) ? "is-new" : ""}">
      <td class="nowrap">${r.entry}${fresh.has(r.key) ? ' <span class="tag tag-where">new</span>' : ""}</td>
      <td class="nowrap">${r.feed}</td>
      <td>${sevTag(r.sev)}</td>
      <td class="top wrap">${r.detail}</td>
      <td>${r.status === "pending" ? '<a href="#agent">' + statusTag(r.status) + '</a>' : statusTag(r.status)}</td>
      <td class="data nowrap">${escapeHtml(r.date)}</td>
    </tr>`).join("");
}

document.querySelector("#intel-table thead").addEventListener("click", e => {
  const th = e.target.closest("th[data-sort]");
  if (!th) return;
  const key = th.dataset.sort;
  intelSort = { key, dir: intelSort.key === key ? -intelSort.dir : (key === "date" ? -1 : 1) };
  document.querySelectorAll("#intel-table th[data-sort]").forEach(h => {
    const btn = h.querySelector("button");
    const arrow = btn.querySelector("span");
    if (arrow) arrow.remove();
    if (h === th) {
      h.setAttribute("aria-sort", intelSort.dir === 1 ? "ascending" : "descending");
      btn.insertAdjacentHTML("beforeend", `<span aria-hidden="true">${intelSort.dir === 1 ? "&uarr;" : "&darr;"}</span>`);
    } else {
      h.removeAttribute("aria-sort");
    }
  });
  renderIntelTable();
});

document.getElementById("feed-filter").addEventListener("click", e => {
  const b = e.target.closest("button");
  if (!b) return;
  intelFeed = b.dataset.feed;
  document.querySelectorAll("#feed-filter button").forEach(x => x.setAttribute("aria-pressed", String(x === b)));
  renderIntelTable();
});

// ---------------- Customer Shield ----------------
const RISK_VERDICT = { high: "blocked", medium: "suspicious", low: "allowed" };
const LINK_VERDICT = { blocked: "blocked", warning: "suspicious", allowed: "allowed" };

function verdictTag(v) {
  return `<span class="tag tag-${v}">${v}</span>`;
}

function linksCell(links) {
  if (!links || !links.length) return '<span class="muted">No links</span>';
  return links.map(l => `<span class="nowrap">${verdictTag(LINK_VERDICT[l.verdict] || "allowed")} <span class="data">${escapeHtml(l.host)}</span></span>`).join("<br>");
}

async function loadTrending() {
  const body = document.getElementById("trending-list");
  try {
    const patterns = await getJson("/api/scam-patterns");
    document.getElementById("trending-count").textContent = `(${patterns.length})`;
    body.innerHTML = patterns.length ? patterns.map(p => `
      <tr>
        <td class="top wrap">${escapeHtml(p.name)}<span class="cell-sub">${escapeHtml(p.source)}</span></td>
        <td>${sevTag(p.severity)}</td>
        <td>${statusTag(p.status)}</td>
      </tr>`).join("") : '<tr><td colspan="3" class="state">No scam patterns loaded.</td></tr>';
  } catch (e) {
    body.innerHTML = '<tr><td colspan="3" class="state state-error">Could not load scam patterns.</td></tr>';
  }
}

async function loadBlockedDomains() {
  const body = document.getElementById("blocked-domains-list");
  try {
    const domains = await getJson("/api/blocked-domains");
    domains.sort((a, b) => String(b.date_added).localeCompare(String(a.date_added)));
    document.getElementById("blocked-count").textContent = `(${domains.length})`;
    body.innerHTML = domains.length ? domains.map(d => `
      <tr>
        <td class="data break">${escapeHtml(d.domain)}</td>
        <td>${sevTag(d.severity)}</td>
        <td class="wrap">${escapeHtml(d.category)}</td>
        <td class="wrap"><span class="cell-sub">${escapeHtml(d.source)}</span></td>
        <td class="data nowrap">${escapeHtml(d.date_added)}</td>
      </tr>`).join("") : '<tr><td colspan="5" class="state">No domains are blocked yet. Approve a domain rule in New Vulnerabilities.</td></tr>';
  } catch (e) {
    body.innerHTML = '<tr><td colspan="5" class="state state-error">Could not load the blocklist.</td></tr>';
  }
}

// Simulated arrivals, scored by the real engine. Polls only while the section is open.
let inboxTimer = null;
let inboxPaused = false;
let inboxFailures = 0;
const MAX_INBOX_MESSAGES = 8;

function startInboxFeed() {
  if (inboxTimer || inboxPaused) return;
  addIncomingMessage();
  inboxTimer = setInterval(addIncomingMessage, 4500);
}

function stopInboxFeed() {
  clearInterval(inboxTimer);
  inboxTimer = null;
}

document.getElementById("feed-toggle").addEventListener("click", () => {
  const btn = document.getElementById("feed-toggle");
  inboxPaused = !inboxPaused;
  btn.setAttribute("aria-pressed", String(inboxPaused));
  btn.textContent = inboxPaused ? "Resume feed" : "Pause feed";
  if (inboxPaused) stopInboxFeed(); else startInboxFeed();
});

async function addIncomingMessage() {
  const feed = document.getElementById("inbox-feed");
  let msg;
  try {
    msg = await getJson("/api/inbox/next");
    inboxFailures = 0;
  } catch (e) {
    inboxFailures += 1;
    if (inboxFailures >= 2 || !feed.querySelector("tr[data-id]")) {
      feed.querySelectorAll("tr:not([data-id])").forEach(r => r.remove());
      feed.insertAdjacentHTML("afterbegin", '<tr><td colspan="7" class="state state-error">Could not reach the server for new messages. Retrying.</td></tr>');
    }
    return;
  }
  feed.querySelectorAll("tr:not([data-id])").forEach(r => r.remove());
  const v = RISK_VERDICT[msg.risk] || "allowed";
  const row = document.createElement("tr");
  row.dataset.id = msg.id;
  row.innerHTML = `
    <td class="data nowrap">${escapeHtml(msg.arrived_at)}</td>
    <td class="nowrap">${escapeHtml(msg.sender)}</td>
    <td class="top wrap">${escapeHtml(msg.text)}</td>
    <td class="num">${escapeHtml(msg.score)}</td>
    <td>${verdictTag(v)}</td>
    <td class="top">${linksCell(msg.links_checked)}</td>
    <td class="top wrap"><span class="cell-sub">${escapeHtml((msg.reasons || [])[0] || "")}</span></td>`;
  feed.insertBefore(row, feed.firstChild);
  while (feed.children.length > MAX_INBOX_MESSAGES) feed.removeChild(feed.lastChild);
}

document.getElementById("scam-form").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = document.getElementById("scam-check-btn");
  const box = document.getElementById("scam-result");
  const text = document.getElementById("scam-input").value.trim();
  if (!text) {
    box.hidden = false;
    box.innerHTML = '<p class="state-error">Paste a message or link first.</p>';
    return;
  }
  setBusy(btn, true, "Checking");
  try {
    const result = await getJson("/api/scam-check", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text })
    });
    showScamResult(result);
  } catch (err) {
    box.hidden = false;
    box.innerHTML = '<p class="state-error">Could not check the message: the server did not respond.</p>';
  }
  setBusy(btn, false, "Check message");
});

function showScamResult(r) {
  const box = document.getElementById("scam-result");
  const v = RISK_VERDICT[r.risk] || "allowed";
  const meaning = { blocked: "Likely a scam.", suspicious: "Be cautious.", allowed: "No strong scam signals." }[v];
  const links = (r.links_checked || []).length ? `
    <div class="table-wrap fit block">
      <table>
        <thead><tr><th scope="col">Domain</th><th scope="col">Verdict</th><th scope="col">Score</th></tr></thead>
        <tbody>${r.links_checked.map(l => `<tr><td class="data break">${escapeHtml(l.host)}</td><td>${verdictTag(LINK_VERDICT[l.verdict] || "allowed")}</td><td class="num">${escapeHtml(l.score)}</td></tr>`).join("")}</tbody>
      </table>
    </div>` : '<p class="muted block">No links found in this message.</p>';
  box.hidden = false;
  box.innerHTML = `
    <div class="result-head">${verdictTag(v)} <span class="result-score">${escapeHtml(r.score)}</span><span class="muted">risk score out of 99. ${meaning}</span></div>
    <ul class="reasons">${(r.reasons || []).map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>
    ${links}
    <div class="block"><button type="button" class="btn" id="btn-already-clicked">The customer already clicked</button></div>
    <div id="recovery-box" aria-live="polite"></div>`;
  document.getElementById("btn-already-clicked").addEventListener("click", loadRecovery);
}

async function loadRecovery() {
  const btn = document.getElementById("btn-already-clicked");
  const box = document.getElementById("recovery-box");
  setBusy(btn, true, "Loading checklist");
  try {
    const steps = await getJson("/api/recovery");
    box.innerHTML = '<h3 class="block">Recovery checklist</h3><ol class="recovery">' +
      steps.map(s => `<li>${escapeHtml(s.step)}<span>${escapeHtml(s.detail)}</span></li>`).join("") + "</ol>";
    btn.hidden = true;
  } catch (e) {
    box.innerHTML = '<p class="state-error">Could not load the recovery checklist.</p>';
    setBusy(btn, false, "The customer already clicked");
  }
}

// In-page jump links (buttons, so they don't fight the section hash).
document.querySelector(".jump").addEventListener("click", e => {
  const b = e.target.closest("button[data-jump]");
  if (!b) return;
  const target = document.getElementById(b.dataset.jump);
  target.setAttribute("tabindex", "-1");
  target.scrollIntoView({ block: "start" });
  target.focus({ preventScroll: true });
});

// ---------------- Boot: show the section named in the URL ----------------
showSection(location.hash.slice(1), false);
