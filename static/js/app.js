// ---------------- Tabs ----------------
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("panel-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "intel") loadThreatIntel();
    if (btn.dataset.tab === "scam") { loadTrending(); loadBlockedDomains(); startInboxFeed(); }
    else { stopInboxFeed(); }
    if (btn.dataset.tab === "metrics") loadMetrics();
  });
});

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
let currentFindings = [];
let activeSevFilter = "all";

// ---------------- Repo selector ----------------
async function loadRepos() {
  const res = await fetch("/api/repos");
  const repos = await res.json();
  const sel = document.getElementById("repo-select");
  sel.innerHTML = repos.map(r => `<option value="${r.id}">${escapeHtml(r.name)} (${r.file_count} files)</option>`).join("");
}
loadRepos();
loadThreatIntel();

// ---------------- AI Agent feed ----------------
const ICONS = { info: "ℹ", checking: "◐", clear: "·", found: "⚠", done: "✓", error: "✕" };

function feedLine(ev) {
  const icon = ICONS[ev.kind] || "·";
  const sevClass = ev.kind === "found" && ev.severity ? " " + ev.severity : "";
  return `<div class="feed-line ${ev.kind}${sevClass}"><span class="icon">${icon}</span><span>${escapeHtml(ev.text)}</span></div>`;
}

let polling = false;
let eventsSeen = 0;

document.getElementById("run-scan-btn").addEventListener("click", startScan);

async function startScan() {
  const btn = document.getElementById("run-scan-btn");
  const repoId = document.getElementById("repo-select").value;
  btn.disabled = true;
  btn.textContent = "⏳ Scanning...";
  eventsSeen = 0;
  currentFindings = [];
  scanStale = false;
  document.getElementById("stale-banner").classList.remove("show");

  const orb = document.getElementById("agent-orb");
  orb.className = "agent-orb working";
  document.getElementById("agent-status").textContent = "Starting up...";
  document.getElementById("agent-meta").textContent = "";
  document.getElementById("agent-feed").innerHTML = "";
  document.getElementById("findings-list").innerHTML = '<div class="empty-state muted">Scanning in progress...</div>';
  document.getElementById("findings-count").textContent = "";

  const res = await fetch("/api/scan/start", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repo_id: repoId })
  });
  const { job_id } = await res.json();

  const startTime = Date.now();
  polling = true;
  pollJob(job_id, btn, startTime);
}

async function pollJob(jobId, btn, startTime) {
  if (!polling) return;
  const res = await fetch(`/api/scan/${jobId}/status?since=${eventsSeen}`);
  const job = await res.json();

  if (job.events && job.events.length) {
    const feed = document.getElementById("agent-feed");
    job.events.forEach(ev => { feed.insertAdjacentHTML("beforeend", feedLine(ev)); });
    feed.scrollTop = feed.scrollHeight;
    eventsSeen = job.event_count;
    document.getElementById("agent-status").textContent = job.status_line;
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  const checks = Array.from(document.querySelectorAll(".feed-line.found, .feed-line.clear")).length;
  document.getElementById("agent-meta").textContent = `${checks} pattern(s) checked so far · ${elapsed}s elapsed`;

  if (job.status === "done") {
    polling = false;
    document.getElementById("agent-orb").className = "agent-orb done";
    renderResults(job);
    btn.disabled = false;
    btn.textContent = "▶ Run AI Scan";
  } else if (job.status === "error") {
    polling = false;
    document.getElementById("agent-orb").className = "agent-orb idle";
    btn.disabled = false;
    btn.textContent = "▶ Run AI Scan";
  } else {
    setTimeout(() => pollJob(jobId, btn, startTime), 300);
  }
}

function renderResults(job) {
  currentFindings = job.findings;
  const counts = job.counts || {};
  document.getElementById("stat-critical").textContent = counts.critical || 0;
  document.getElementById("stat-high").textContent = counts.high || 0;
  document.getElementById("stat-medium").textContent = counts.medium || 0;
  document.getElementById("stat-low").textContent = counts.low || 0;

  const total = job.findings.length;
  const ring = document.getElementById("badge-ring");
  const ringText = document.getElementById("badge-ring-text");
  const headline = document.getElementById("badge-headline");
  const sub = document.getElementById("badge-sub");

  let color = "var(--green)", word = "PASS";
  if (counts.critical > 0) { color = "var(--critical)"; word = "BLOCK"; }
  else if (counts.high > 0) { color = "var(--high)"; word = "WARN"; }

  ring.style.background = `conic-gradient(${color} 360deg, var(--panel-border) 0deg)`;
  ringText.textContent = word;
  ringText.style.color = color;
  headline.textContent = total === 0
    ? "Tested against " + job.patterns_checked + " known attacks"
    : `${total} vulnerabilities found`;
  sub.textContent = `${job.repo} · Tested against ${job.patterns_checked} active patterns · Updated ${job.scanned_at}`;

  activeSevFilter = "all";
  document.querySelectorAll("#sev-filter .chip").forEach(c => c.classList.toggle("active", c.dataset.sev === "all"));
  renderFindingsList();
}

document.getElementById("sev-filter").addEventListener("click", e => {
  const chip = e.target.closest(".chip");
  if (!chip) return;
  document.querySelectorAll("#sev-filter .chip").forEach(c => c.classList.remove("active"));
  chip.classList.add("active");
  activeSevFilter = chip.dataset.sev;
  renderFindingsList();
});

function renderFindingsList() {
  const filtered = activeSevFilter === "all" ? currentFindings : currentFindings.filter(f => f.severity === activeSevFilter);
  document.getElementById("findings-count").textContent = `(${filtered.length}${activeSevFilter !== "all" ? " of " + currentFindings.length : ""})`;
  const list = document.getElementById("findings-list");
  if (currentFindings.length === 0) {
    list.innerHTML = '<div class="empty-state muted">No vulnerabilities found. Ship it. ✅</div>';
    return;
  }
  if (filtered.length === 0) {
    list.innerHTML = '<div class="empty-state muted">No findings at this severity.</div>';
    return;
  }
  list.innerHTML = filtered.map(f => `
    <div class="finding ${f.severity}" data-finding-id="${f.finding_id}">
      <div class="finding-top">
        <div class="finding-title">${escapeHtml(f.name)}</div>
        <span class="sev-chip ${f.severity}">${f.severity}</span>
      </div>
      <div class="finding-loc">${escapeHtml(f.file)}:${f.line} ${f.cwe ? "· " + f.cwe : ""}</div>
      <div class="finding-snippet">${escapeHtml(f.snippet)}</div>
      <div class="finding-desc">${escapeHtml(f.description)}</div>
      <div class="finding-fix">💡 Suggested fix: ${escapeHtml(f.suggested_fix)}</div>
      <div class="finding-meta">
        <span>Pattern ${f.pattern_id}</span>
        <span>Source: ${escapeHtml(f.source)}</span>
        <span>Added ${f.date_added}</span>
      </div>
      ${f.has_code_fix ? fixBoxHtml(f) : ""}
    </div>`).join("");

  wireFixButtons();
}

function fixBoxHtml(f) {
  const origLines = f.fix_original.split("\n").map(l => `<div class="diff-line removed">${escapeHtml(l)}</div>`).join("");
  const fixedLines = f.fix_fixed.split("\n").map(l => `<div class="diff-line added">${escapeHtml(l)}</div>`).join("");
  return `
    <div class="fix-box">
      <button class="btn btn-ghost small fix-toggle" data-target="diff-${cssId(f.finding_id)}">👀 View code fix</button>
      <div class="fix-diff hidden" id="diff-${cssId(f.finding_id)}">
        ${origLines}
        ${fixedLines}
        <div class="fix-diff-actions">
          <button class="btn btn-primary small apply-fix-btn" data-repo="${f.repo_id}" data-file="${escapeHtml(f.file)}" data-line="${f.line}" data-finding-id="${f.finding_id}">✓ Apply this fix</button>
          <span class="fix-applied-chip hidden" data-chip-for="${f.finding_id}">✓ Applied — re-run scan to confirm</span>
        </div>
      </div>
    </div>`;
}

function cssId(str) {
  return str.replace(/[^a-zA-Z0-9]/g, "_");
}

function wireFixButtons() {
  document.querySelectorAll(".fix-toggle").forEach(btn => {
    btn.addEventListener("click", () => {
      const target = document.getElementById(btn.dataset.target);
      target.classList.toggle("hidden");
      btn.textContent = target.classList.contains("hidden") ? "👀 View code fix" : "🔼 Hide code fix";
    });
  });
  document.querySelectorAll(".apply-fix-btn").forEach(btn => {
    btn.addEventListener("click", () => applyFix(btn));
  });
}

let scanStale = false;

async function applyFix(btn) {
  if (scanStale) return;
  btn.disabled = true;
  btn.textContent = "Applying...";
  try {
    const res = await fetch("/api/fix/apply", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_id: btn.dataset.repo, file: btn.dataset.file, line: parseInt(btn.dataset.line, 10) })
    });
    const result = await res.json();
    if (result.ok) {
      btn.textContent = "✓ Applied";
      const chip = document.querySelector(`.fix-applied-chip[data-chip-for="${btn.dataset.findingId}"]`);
      if (chip) chip.classList.remove("hidden");
      markScanStale();
    } else {
      btn.disabled = false;
      btn.textContent = "✓ Apply this fix";
      alert(result.error || "Could not apply fix.");
    }
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "✓ Apply this fix";
    alert("Could not reach the server.");
  }
}

function markScanStale() {
  scanStale = true;
  document.getElementById("stale-banner").classList.add("show");
  document.querySelectorAll(".apply-fix-btn").forEach(b => { if (b.textContent !== "✓ Applied") { b.disabled = true; } });
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------------- Threat Intel tab ----------------
async function loadThreatIntel() {
  const [patterns, domains] = await Promise.all([
    fetch("/api/threat-intel").then(r => r.json()),
    fetch("/api/blocked-domains/all").then(r => r.json()),
  ]);
  const pending = patterns.filter(p => p.status === "pending");
  const approved = patterns.filter(p => p.status === "approved").sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const pendingDomains = domains.filter(d => d.status === "pending");

  const badge = document.getElementById("intel-badge");
  const totalPending = pending.length + pendingDomains.length;
  if (totalPending) {
    badge.textContent = totalPending;
    badge.classList.remove("hidden");
  } else {
    badge.classList.add("hidden");
  }
  document.getElementById("pending-count-label").textContent = pending.length
    ? `— ${pending.length} awaiting review`
    : "— none right now";
  document.getElementById("pending-domains-count-label").textContent = pendingDomains.length
    ? `— ${pendingDomains.length} awaiting review`
    : "— none right now";

  document.getElementById("pending-list").innerHTML = pending.length
    ? pending.map(p => reportCard(p)).join("")
    : '<div class="empty-state muted">No new vulnerabilities pending review. Click "Sync Threat Intel from Web" to check for new ones.</div>';

  document.getElementById("pending-domains-list").innerHTML = pendingDomains.length
    ? pendingDomains.map(d => domainReportCard(d)).join("")
    : '<div class="empty-state muted">No new scam domains pending review. Click "Sync Threat Intel from Web" to check OpenPhish for new ones.</div>';

  document.getElementById("approved-list").innerHTML = approved.length
    ? approved.map(p => intelItem(p)).join("")
    : '<div class="empty-state muted">Nothing approved yet.</div>';

  document.querySelectorAll("[data-approve]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const name = btn.dataset.name;
      btn.disabled = true;
      btn.textContent = "Adding to memory...";
      await fetch(`/api/threat-intel/${btn.dataset.approve}/approve`, { method: "POST" });
      showApproveToast(`✓ "${name}" added to the AI's memory — every future scan now checks for this.`);
      loadThreatIntel();
    });
  });
  document.querySelectorAll("[data-reject]").forEach(btn => {
    btn.addEventListener("click", async () => {
      await fetch(`/api/threat-intel/${btn.dataset.reject}/reject`, { method: "POST" });
      loadThreatIntel();
    });
  });
  document.querySelectorAll("[data-approve-domain]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const domain = btn.dataset.approveDomain;
      btn.disabled = true;
      btn.textContent = "Adding to firewall...";
      await fetch(`/api/blocked-domains/${encodeURIComponent(domain)}/approve`, { method: "POST" });
      showApproveToast(`✓ "${domain}" added to the network firewall — blocked for every customer from now on.`);
      loadThreatIntel();
    });
  });
  document.querySelectorAll("[data-reject-domain]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const domain = btn.dataset.rejectDomain;
      await fetch(`/api/blocked-domains/${encodeURIComponent(domain)}/reject`, { method: "POST" });
      loadThreatIntel();
    });
  });

  const meta = await (await fetch("/api/threat-intel/meta")).json();
  const domainMeta = await (await fetch("/api/blocked-domains/meta")).json();
  const statusEl = document.getElementById("sync-status");
  if (meta.last_synced_at || domainMeta.last_synced_at) {
    const bits = [];
    if (meta.last_synced_at) bits.push(`Code: synced ${meta.last_synced_at}, ${meta.total_seen} CVEs scanned, ${meta.new_count} new`);
    if (domainMeta.last_synced_at) bits.push(`Domains: synced ${domainMeta.last_synced_at}, ${domainMeta.total_seen} sites scanned, ${domainMeta.new_count} new`);
    statusEl.textContent = bits.join(" · ");
    statusEl.className = "sync-status muted";
  }
}

function domainReportCard(d) {
  return `
    <div class="report-card">
      <div class="report-top">
        <div class="report-title">🚫 ${escapeHtml(d.domain)}</div>
        <span class="sev-chip ${d.severity}">${d.severity}</span>
      </div>
      <div class="report-meta-row">
        <span>${escapeHtml(d.category)}</span>
        <span>${escapeHtml(d.source)}</span>
        <span>Discovered ${d.date_added}</span>
      </div>
      <div class="report-actions">
        <button class="btn btn-primary small" data-approve-domain="${escapeHtml(d.domain)}">🧠 Approve — add to firewall</button>
        <button class="btn btn-ghost small" data-reject-domain="${escapeHtml(d.domain)}">✕ Reject</button>
      </div>
    </div>`;
}

function showApproveToast(text) {
  const toast = document.getElementById("approve-toast");
  toast.textContent = text;
  toast.classList.add("show");
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => toast.classList.remove("show"), 5000);
}

function reportCard(p) {
  const sourceLink = p.source_url ? ` · <a href="${p.source_url}" target="_blank" rel="noopener">${escapeHtml(p.source_cve || "source")}</a>` : "";
  const examples = p.example_vulnerable ? `
    <div class="report-examples">
      <div class="example-box vuln">
        <div class="example-label">⚠ Vulnerable example</div>
        <pre class="example-code">${escapeHtml(p.example_vulnerable)}</pre>
      </div>
      <div class="example-box fixed">
        <div class="example-label">✓ Fixed example</div>
        <pre class="example-code">${escapeHtml(p.example_fixed)}</pre>
      </div>
    </div>` : "";
  const manualNote = p.auto_detectable === false
    ? '<div class="no-signature-note">ℹ No automated signature could be drafted for this one — it depends on business logic a static scanner can\'t infer. Approving it adds the report to memory for manual review guidance; it won\'t auto-flag code.</div>'
    : "";
  return `
    <div class="report-card">
      <div class="report-top">
        <div class="report-title">${escapeHtml(p.name)}</div>
        <span class="sev-chip ${p.severity}">${p.severity}</span>
      </div>
      <div class="report-meta-row">
        <span>${p.cwe || ""}</span>
        <span>${escapeHtml(p.source)}${sourceLink}</span>
        <span>Discovered ${p.date_added}</span>
      </div>
      <div class="report-desc">${escapeHtml(p.description)}</div>
      ${examples}
      ${manualNote}
      <div class="report-actions">
        <button class="btn btn-primary small" data-approve="${p.id}" data-name="${escapeHtml(p.name)}">🧠 Approve — add to AI memory</button>
        <button class="btn btn-ghost small" data-reject="${p.id}">✕ Reject</button>
      </div>
    </div>`;
}

function intelItem(p) {
  const manualTag = p.auto_detectable === false ? '<span class="pill manual">Manual review</span>' : '<span class="pill memory">🧠 in memory</span>';
  const sourceLink = p.source_url ? ` · <a href="${p.source_url}" target="_blank" rel="noopener">${escapeHtml(p.source_cve || "source")}</a>` : "";
  return `
    <div class="intel-item">
      <div>
        <span class="pill ${p.status}">${p.status}</span>${manualTag}
        <div class="name">${escapeHtml(p.name)}</div>
        <div class="desc">${escapeHtml(p.description)}</div>
        <div class="meta">${escapeHtml(p.source)}${sourceLink} · Added ${p.date_added} · Severity: ${p.severity}</div>
      </div>
    </div>`;
}

document.getElementById("sync-btn").addEventListener("click", async () => {
  const btn = document.getElementById("sync-btn");
  const statusEl = document.getElementById("sync-status");
  btn.disabled = true;
  btn.textContent = "🌐 Syncing...";
  statusEl.textContent = "Fetching the CISA KEV catalog and the OpenPhish domain feed...";
  statusEl.className = "sync-status muted";
  try {
    const [codeRes, domainRes] = await Promise.all([
      fetch("/api/threat-intel/sync", { method: "POST" }).then(r => r.json()),
      fetch("/api/blocked-domains/sync", { method: "POST" }).then(r => r.json()),
    ]);
    const parts = [];
    if (codeRes.ok) {
      parts.push(`code: scanned ${codeRes.total_seen} CVEs, ${codeRes.new_patterns.length} new pattern(s)`);
    } else {
      parts.push("code sync failed: " + codeRes.error);
    }
    if (domainRes.ok) {
      parts.push(`domains: scanned ${domainRes.total_seen} reported sites, ${domainRes.new_domains.length} new domain(s)`);
    } else {
      parts.push("domain sync failed: " + domainRes.error);
    }
    statusEl.textContent = parts.join(" · ");
    statusEl.className = "sync-status " + (codeRes.ok && domainRes.ok ? "ok" : "err");
  } catch (e) {
    statusEl.textContent = "Sync failed: could not reach the internet.";
    statusEl.className = "sync-status err";
  }
  btn.disabled = false;
  btn.textContent = "🌐 Sync Threat Intel from Web";
  loadThreatIntel();
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
