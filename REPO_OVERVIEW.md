# Signal Sentinel — Repository Overview

Signal Sentinel is an AI security agent that keeps its own knowledge current by pulling **real, live, public threat-intelligence feeds**, drafts detection rules for new attacks, and — once a human analyst approves them — enforces those rules in two places at once:

1. **Layer 1 — the dev/CI pipeline**: scans a codebase against known attack patterns before it ships, and can apply hand-verified fixes directly to the file.
2. **Layer 2 — the customer-facing app**: automatically scores incoming messages and the links inside them, blocking known-malicious domains at a network-firewall level before the user ever interacts with them.

Both layers share the same live-updating "brain": approve a new pattern once, and both the code scanner and the customer shield start checking for it immediately.

This document explains what every file in the repo does and how the pieces fit together, so a new contributor (or a judge reading the code) can orient quickly.

---

## Quick start

```bash
cd /path/to/repo
python app.py
```
Then open:
- **http://127.0.0.1:5057/** — the marketing/landing page
- **http://127.0.0.1:5057/app** — the actual working dashboard (4 tabs)

No API keys are required. Two features make live internet calls (CISA KEV sync, OpenPhish sync) and fall back to a local cache if offline.

---

## High-level architecture

```
Flask app (app.py)
 ├─ templates/landing.html   → marketing page at "/"
 ├─ templates/index.html     → dashboard app at "/app" (4 tabs, single-page style)
 ├─ static/css, static/js    → two independent visual themes (landing vs dashboard)
 ├─ scanner.py                → Layer 1: static code scanner + repo registry
 ├─ threat_intel_agent.py     → Layer 1's live feed: CISA KEV → new code-vuln patterns
 ├─ fixes.py                  → hand-verified code fixes, keyed by (repo, file, line)
 ├─ scam_shield.py             → Layer 2: message/link scam-risk scoring engine
 ├─ domain_intel_agent.py      → Layer 2's live feed: OpenPhish → new blocked domains
 ├─ generate_dataset.py        → builds the synthetic test set + precision/recall metrics
 └─ data/*.json                → all persisted state (patterns, domains, sample repos, metrics)
```

Nothing here uses a database — every piece of mutable state (approved/pending patterns, blocked domains, metrics) is a JSON file under `data/`, read and rewritten directly. This keeps the whole thing inspectable and easy to reset between demo runs.

---

## Backend — Python files

### `app.py`
The Flask application and every HTTP route. Organized into three groups:

**Pages**
- `GET /` — renders `landing.html`
- `GET /app` — renders `index.html` (the dashboard)

**Layer 1 — AI Security Agent (dev/CI pipeline)**
- `GET /api/repos` — lists the two sample repos available to scan (`core-api`, `payments-service`)
- `GET /api/pipeline/repo-files` — returns the raw source of a repo's files (used for display)
- `POST /api/scan/start` — starts a scan job in a background thread; returns a `job_id`
- `GET /api/scan/<job_id>/status?since=N` — polled every ~300ms by the frontend; returns new narrated events (`"Checking for SQL Injection..."`, `"1 match(es) found..."`) plus final findings once done. This is what drives the live, narrated "AI agent" feed instead of a static progress bar.
- `POST /api/fix/apply` — looks up a hand-verified fix from `fixes.py`, re-reads the target file, verifies the original text still matches exactly (so it refuses if the file already changed), then writes the fix in place.

**Threat Intel (shared by both layers)**
- `GET /api/threat-intel` — all code-vulnerability patterns (pending + approved)
- `GET /api/threat-intel/meta` — last sync time/source for the code-side feed
- `POST /api/threat-intel/sync` — triggers `threat_intel_agent.sync_from_web()` (CISA KEV)
- `POST /api/threat-intel/<id>/approve` / `/reject` — analyst review actions

**Layer 2 — Customer Shield**
- `POST /api/scam-check` — scores a pasted message (and any links inside it) via `scam_shield.analyze_message`
- `POST /api/link-check` — scores a single URL via `scam_shield.analyze_link` (the "domain firewall")
- `GET /api/blocked-domains` — **approved-only** blocklist (used by the public "Recently blocked" list)
- `GET /api/blocked-domains/all` — full blocklist including pending (used by the analyst review UI)
- `GET /api/blocked-domains/meta` — last sync time/source for the domain-side feed
- `POST /api/blocked-domains/sync` — triggers `domain_intel_agent.sync_from_web()` (OpenPhish)
- `POST /api/blocked-domains/<domain>/approve` / `/reject` — analyst review actions
- `GET /api/inbox/next` — picks a random message from `data/simulated_inbox.json`, scores it, and returns it with a sender/timestamp — this is what feeds the "Live Message Shield" auto-flagging feed (simulates a message arriving and being checked automatically, no paste required)
- `GET /api/scam-patterns` / `POST /api/scam-patterns/<id>/approve` — the "Trending this week" scam-pattern list (keyword-based, separate from the domain blocklist)
- `GET /api/recovery` — the post-click recovery checklist steps

**Metrics**
- `GET /api/metrics` — precision/recall/F1 computed by `generate_dataset.py`, served to the Metrics tab

---

### `scanner.py`
Layer 1's static analysis engine.
- `REPOS` — registry of the two demo repos (`core-api` → `data/sample_repo/`, `payments-service` → `data/sample_repo_payments/`) with id/name/description/path.
- `load_patterns()` / `save_patterns()` — read/write `data/threat_intel_patterns.json`.
- `scan_code(repo_dir, patterns)` — runs each pattern's regex against every `.py`/`.js`/`.ts` file in the repo, returns one finding per match with file/line/snippet/severity/etc.
- `scan_dependencies(repo_dir, patterns)` — checks `requirements.txt` pins against patterns with a `max_safe_below` version, flags outdated/vulnerable pins.
- `run_full_scan()` — convenience wrapper combining both, sorted by severity.

### `threat_intel_agent.py`
Layer 1's self-updating feed. Fetches the **CISA Known Exploited Vulnerabilities (KEV)** catalog (a real, public, actively-maintained US government feed — no API key needed), caches it locally for offline fallback, and for each new CVE whose CWE maps to a pattern we know how to auto-detect (`CWE_TEMPLATES`: path traversal, XSS, open redirect, insecure comparison, missing auth), drafts a new pending pattern citing the real CVE ID and a plain-language example. Dedupes by CVE ID and by CWE (won't re-propose a category that's already approved or already pending).

### `fixes.py`
A static lookup table: `(repo_id, file, line) → {"original": ..., "fixed": ...}`. These are **hand-verified**, not generated — each `original` string was checked to exactly match the real file content, so the "Apply fix" button in the dashboard can safely do a literal find-and-replace. Covers all 25 findings across both demo repos.

### `scam_shield.py`
Layer 2's scoring engine, with three responsibilities:
1. **`analyze_message(text)`** — the main entry point. Scores wording (urgency/payment/brand-impersonation keywords + scam-pattern keyword match), then for every URL found in the text, calls `analyze_link()` and folds the result in — a confirmed-malicious link dominates the score even if the wording alone looked mild. URLs are stripped out before the wording checks run, so a bare link's domain text (e.g. "usps" inside a URL) can't falsely trigger "claims to be from USPS."
2. **`analyze_link(url)`** — the "domain firewall." Checks only the destination host: exact/suffix match against `data/blocked_domains.json`, lookalike-brand detection, risky TLDs (.top/.xyz/.click/etc.), and a synthetic domain-age check. Never looks at message content — this is what makes it channel-agnostic (works the same for a link from SMS, email, or an encrypted app like WhatsApp).
3. Data loaders for `scam_patterns.json`, `blocked_domains.json`, and `simulated_inbox.json`, plus the static `RECOVERY_STEPS` checklist.

### `domain_intel_agent.py`
Layer 2's self-updating feed, mirroring `threat_intel_agent.py`'s pattern exactly but for domains. Fetches the **OpenPhish community feed** (a real, public, continuously-updated list of currently-active phishing URLs — no API key needed), extracts each domain, and for any domain not already known, drafts a pending blocklist entry. Caches locally for offline fallback.

### `generate_dataset.py`
A standalone script (not imported by the app at runtime) that builds `data/synthetic_messages.json` — 260 synthetic scam/legitimate messages from 24 hand-written templates — and scores them all through `scam_shield.analyze_message` to compute precision/recall/F1/accuracy, written to `data/metrics.json`. Re-run this manually (`python generate_dataset.py`) if the scoring logic changes and the Metrics tab should reflect it.

---

## Frontend

### `templates/landing.html` + `static/css/landing.css` + `static/js/landing.js`
The marketing page. Distinct visual identity from the dashboard (Fraunces serif + IBM Plex Mono, acid-green/magenta/amber palette, grain texture, a live-scrolling ticker of real CWE/pattern names, scroll-reveal animations, mouse-parallax hero). Scoped entirely under a `.landing-body` class so it never leaks into the dashboard's styling. `landing.js` also pulls real numbers (CVE count, precision) from the API for the animated stat counters.

### `templates/index.html` + `static/css/style.css` + `static/js/app.js`
The actual product — four tabs:
1. **AI Security Agent** — repo picker, "Run AI Scan" button, live narrated agent feed, findings list with severity filter and per-finding "View code fix" diff + "Apply this fix" button.
2. **Threat Intel** — one "Sync Threat Intel from Web" button triggers both live feeds at once; two pending-review sections (code vulnerabilities / scam domains), each rendered as a detailed report card with a real/fixed code example and an approve/reject action; an "In AI memory" list of everything currently active.
3. **Customer Shield** — the "Live Message Shield" auto-flagging feed (polls `/api/inbox/next` every ~4.5s, only shows a badge on messages that are actually risky), a collapsed "Test a message by hand" manual fallback, a "Trending this week" scam-pattern card, and a "Recently blocked across the network" domain list.
4. **Metrics** — precision/recall/F1/dataset-size tiles and a confusion matrix, from `data/metrics.json`.

`app.js` is organized by tab (tabs switcher at the top, then one section per tab) and uses simple polling (not WebSockets) for anything "live," matching the rest of the project's keep-it-inspectable philosophy.

---

## Data files (`data/`)

| File | What it holds | Who writes it |
|---|---|---|
| `threat_intel_patterns.json` | Code-vulnerability detection patterns (regex + metadata), pending and approved | seeded by hand, extended by `threat_intel_agent.py` |
| `blocked_domains.json` | Domain firewall blocklist, pending and approved | seeded by hand, extended by `domain_intel_agent.py` |
| `scam_patterns.json` | Keyword-based scam message patterns ("Trending this week") | hand-seeded only |
| `simulated_inbox.json` | Sender/text pairs the Live Message Shield feed draws from | hand-written, static |
| `synthetic_messages.json` | 260-message labeled test set | generated by `generate_dataset.py` |
| `metrics.json` | Precision/recall/F1/confusion matrix | generated by `generate_dataset.py` |
| `threat_intel_meta.json` / `domain_intel_meta.json` | Last-sync bookkeeping for each live feed | written by the respective agent |
| `kev_cache.json` / `openphish_cache.json` | Offline fallback cache of the last successful fetch | written by the respective agent |
| `sample_repo/`, `sample_repo_payments/` | Two intentionally-vulnerable demo codebases the scanner runs against | hand-written fixtures |

---

## Things worth knowing before presenting

- **What's real vs. simulated**: the CISA KEV sync, OpenPhish sync, and all scoring/firewall logic are real and run live. The "Live Message Shield" feed is a **simulation** — it draws from a local example pool to demonstrate automatic, no-paste-required flagging, since this prototype isn't wired into actual SMS delivery.
- **Privacy architecture**: `analyze_link()` never reads message content — only the destination domain. `analyze_message()` processes text in memory for one scoring pass; nothing is persisted beyond the verdict shown back to the user.
- **No real customer data anywhere** — all messages, repos, and scam scenarios are synthetic, per the challenge rules.
- **Known gap**: the `btn-block-report` button in Customer Shield currently only changes its own label — it isn't wired to a backend action yet.
