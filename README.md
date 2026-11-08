# Signal Sentinel

An AI security agent that keeps its own knowledge current by pulling **real, live, public threat-intelligence feeds**, drafts detection rules for new attacks, and — once a human analyst approves them — enforces those rules in two places at once:

- **Layer 1 — the dev/CI pipeline**: scans a codebase against known attack patterns before it ships, with live narrated scanning and one-click verified code fixes.
- **Layer 2 — the customer-facing app**: automatically scores incoming messages and the links inside them, blocking known-malicious domains before the user ever interacts with them.

Both layers share the same self-updating "brain": approve a new pattern once, and both the code scanner and the customer shield start checking for it immediately.

## What makes it real, not mocked

- Pulls live CVEs from the **CISA Known Exploited Vulnerabilities catalog** to draft new code-vulnerability detection rules.
- Pulls live phishing domains from the **OpenPhish community feed** to draft new domain-firewall entries.
- A real "domain firewall" that blocks malicious links by destination only — it never reads message content, which is also why it works the same for SMS, email, or encrypted apps like WhatsApp.
- A synthetic (no real customer data) test set with measured precision/recall/F1 shown live in the dashboard.

## Quick start

```bash
pip install flask requests
python app.py
```

Then open:
- `http://127.0.0.1:5057/` — the overview / landing page
- `http://127.0.0.1:5057/app` — the working dashboard (AI Security Agent, Threat Intel, Customer Shield, Metrics)

No API keys required. The two live-sync features fall back to a local cache if run offline.

## Full documentation

See **[REPO_OVERVIEW.md](REPO_OVERVIEW.md)** for a complete file-by-file breakdown: every backend module, every API route, every data file, and what's genuinely live versus simulated for demo purposes.
