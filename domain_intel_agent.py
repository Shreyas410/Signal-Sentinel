"""Live domain threat-intelligence agent for the customer-side firewall.

Mirrors threat_intel_agent.py's pattern exactly, but for the scam/domain
side instead of the code side: fetches a real, public, continuously
updated feed of currently-active phishing sites (OpenPhish's community
feed), drafts candidate blocklist entries for domains we haven't seen
before, and queues them as "pending" for an analyst to approve before
they go live in the domain firewall. Before this agent existed, the
domain blocklist was a static, hand-seeded list — this is what makes
it self-updating the same way the code-vulnerability side already is.
"""
import json
import os
import re
from datetime import datetime, timezone

import requests

import scam_shield

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_PATH = os.path.join(BASE_DIR, "data", "openphish_cache.json")
META_PATH = os.path.join(BASE_DIR, "data", "domain_intel_meta.json")
OPENPHISH_URL = "https://openphish.com/feed.txt"


def _utcnow_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _domain_from_url(url):
    host = re.sub(r"^https?://", "", url.strip())
    host = host.split("/")[0].split("?")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _save_cache(lines):
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump({"fetched_at": _utcnow_str(), "lines": lines}, f)


def _load_cache():
    if not os.path.exists(CACHE_PATH):
        return None
    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_meta(meta):
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def load_meta():
    if not os.path.exists(META_PATH):
        return {"last_synced_at": None, "source": None, "total_seen": 0}
    with open(META_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def fetch_openphish(timeout=8):
    resp = requests.get(OPENPHISH_URL, timeout=timeout)
    resp.raise_for_status()
    lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
    _save_cache(lines)
    return lines, "live"


def sync_from_web(max_new=6):
    """Pull the current OpenPhish community feed, draft blocklist
    entries for domains not already known, and queue them as pending
    for analyst review."""
    try:
        lines, source = fetch_openphish()
    except Exception as exc:
        cached = _load_cache()
        if cached is None:
            return {"ok": False, "error": str(exc), "new_domains": [], "source": "none"}
        lines, source = cached["lines"], "cached (fetched " + cached["fetched_at"] + ")"

    domains = scam_shield.load_blocked_domains(approved_only=False)
    known = {d["domain"] for d in domains}

    new_domains = []
    seen_this_run = set()
    for url in lines:
        if len(new_domains) >= max_new:
            break
        host = _domain_from_url(url)
        if not host or host in known or host in seen_this_run:
            continue
        seen_this_run.add(host)
        entry = {
            "domain": host,
            "category": "Live-reported phishing site",
            "severity": "high",
            "source": "OpenPhish Community Feed",
            "date_added": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "status": "pending",
            "reported_url": url,
        }
        domains.append(entry)
        new_domains.append(entry)

    if new_domains:
        scam_shield.save_blocked_domains(domains)

    meta = {
        "last_synced_at": _utcnow_str(),
        "source": source,
        "total_seen": len(lines),
        "new_count": len(new_domains),
    }
    save_meta(meta)

    return {
        "ok": True,
        "source": source,
        "total_seen": len(lines),
        "new_domains": new_domains,
        "synced_at": meta["last_synced_at"],
    }
