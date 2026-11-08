// Landing page: one line of real, current numbers from the app's own API.
(async function () {
  const el = document.getElementById("live-line");
  try {
    const get = u => fetch(u).then(r => { if (!r.ok) throw new Error(u); return r.json(); });
    const [patterns, domains, kev] = await Promise.all([
      get("/api/threat-intel"), get("/api/blocked-domains/all"), get("/api/threat-intel/meta"),
    ]);
    const code = patterns.filter(p => p.status === "approved").length;
    const blocked = domains.filter(d => d.status === "approved").length;
    const pending = patterns.filter(p => p.status === "pending").length + domains.filter(d => d.status === "pending").length;
    let feed = "CISA KEV not synced yet";
    if (kev.last_synced_at) {
      feed = "CISA KEV " + (kev.source === "live" ? "synced " : "from local cache, synced ") + kev.last_synced_at;
    }
    el.textContent = `Right now: ${code} code rules and ${blocked} domains enforced, ${pending} drafts awaiting approval. ${feed}.`;
  } catch (e) {
    el.textContent = "Current rule counts are unavailable. Open the console to see them.";
  }
})();
