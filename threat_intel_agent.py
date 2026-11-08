"""Live threat-intelligence agent.

Fetches real, currently-exploited vulnerabilities from the CISA Known
Exploited Vulnerabilities (KEV) catalog  -  a public, actively maintained
feed of real-world attacks. For each new CVE whose CWE maps to a
detectable code pattern we don't already check for, it drafts a new
scanner rule and queues it as "pending" for an analyst to approve
before it goes live. This is what keeps the pipeline current without
anyone hand-writing new regexes every time a new attack class appears.
"""
import json
import os
from datetime import datetime, timezone

import requests

import scanner

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_PATH = os.path.join(BASE_DIR, "data", "kev_cache.json")
META_PATH = os.path.join(BASE_DIR, "data", "threat_intel_meta.json")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# CWE -> an auto-draftable detection rule. We only auto-generate a rule
# for CWEs we can reliably express as a static regex signature; anything
# else (e.g. missing-authorization, business-logic flaws) is still
# logged as a pending item for a human to review, just with no regex.
CWE_TEMPLATES = {
    "CWE-22": {
        "category_name": "Path Traversal",
        "regex": r"request\.(?:args|form|json|values)\.get\([^)]*\)\s*\n[^\n]*(?:os\.path\.join\(|open\(|send_file\()",
        "flags": "IGNORECASE",
        "severity": "high",
        "suggested_fix": "Resolve the requested path against a fixed base directory with os.path.realpath() and reject any path that escapes it, or map requests to an allow-list of known file IDs instead of raw paths.",
        "example_vulnerable": 'path = os.path.join(UPLOAD_DIR, request.args.get("file"))\nreturn send_file(path)',
        "example_fixed": 'safe_name = os.path.basename(request.args.get("file"))\npath = os.path.realpath(os.path.join(UPLOAD_DIR, safe_name))\nif not path.startswith(os.path.realpath(UPLOAD_DIR)):\n    abort(403)\nreturn send_file(path)',
    },
    "CWE-79": {
        "category_name": "Cross-Site Scripting (XSS)",
        "regex": r"[\"'][^\"'\n]*[\"']\s*\+\s*\w+\s*\+\s*[\"'][^\"'\n]*[\"']\s*\n[^\n]*render_template_string\(",
        "flags": "IGNORECASE",
        "severity": "high",
        "suggested_fix": "Never build HTML by string-concatenating user input. Use render_template with Jinja autoescaping, or escape manually with markupsafe.escape().",
        "example_vulnerable": 'html = "<h1>Hello " + username + "</h1>"\nreturn render_template_string(html)',
        "example_fixed": 'return render_template_string("<h1>Hello {{ name }}</h1>", name=username)',
    },
    "CWE-601": {
        "category_name": "Open Redirect",
        "regex": r"request\.(?:args|form|values)\.get\([^)]*\)\s*\n[^\n]*redirect\(",
        "flags": "IGNORECASE",
        "severity": "medium",
        "suggested_fix": "Validate the redirect target against an allow-list of known internal paths before calling redirect(), or only allow relative paths.",
        "example_vulnerable": 'next_url = request.args.get("next")\nreturn redirect(next_url)',
        "example_fixed": 'next_url = request.args.get("next", "/")\nif not next_url.startswith("/"):\n    next_url = "/"\nreturn redirect(next_url)',
    },
    "CWE-287": {
        "category_name": "Improper Authentication (insecure secret comparison)",
        "regex": r"\w*(?:token|secret|password|key|signature)\w*\s*==\s*[A-Za-z][A-Za-z0-9_]{3,}\b",
        "flags": "IGNORECASE",
        "severity": "high",
        "suggested_fix": "Use hmac.compare_digest() instead of == to compare secrets, tokens or signatures  -  a plain == leaks timing information an attacker can use to guess the value byte by byte.",
        "example_vulnerable": 'if token == ADMIN_TOKEN:\n    grant_access()',
        "example_fixed": 'if hmac.compare_digest(token, ADMIN_TOKEN):\n    grant_access()',
    },
    "CWE-306": {
        "category_name": "Missing Authentication for Critical Function",
        "regex": None,
        "flags": "",
        "severity": "medium",
        "suggested_fix": "Add an explicit authentication/authorization check to this endpoint. This class of bug depends on business logic our static scanner can't infer automatically  -  flagged for manual review.",
        "example_vulnerable": '@app.route("/admin/export")\ndef export_data():\n    return get_all_records()  # no auth check',
        "example_fixed": '@app.route("/admin/export")\n@require_admin\ndef export_data():\n    return get_all_records()',
    },
}


def _utcnow_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _save_cache(data):
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump({"fetched_at": _utcnow_str(), "data": data}, f)


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


def fetch_kev(timeout=8):
    resp = requests.get(KEV_URL, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    _save_cache(data)
    return data, "live"


def sync_from_web(max_new=6):
    """Pull the latest KEV catalog, draft rules for net-new detectable
    CWE categories, and queue them as pending patterns for review."""
    try:
        data, source = fetch_kev()
    except Exception as exc:
        cached = _load_cache()
        if cached is None:
            return {"ok": False, "error": str(exc), "new_patterns": [], "source": "none"}
        data, source = cached["data"], "cached (fetched " + cached["fetched_at"] + ")"

    vulns = data.get("vulnerabilities", [])
    vulns_sorted = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)

    patterns = scanner.load_patterns(approved_only=False)
    existing_cves = {p["source_cve"] for p in patterns if p.get("source_cve")}
    taken_cwes = {p["cwe"] for p in patterns if p.get("status") in ("approved", "pending") and p.get("cwe")}

    new_patterns = []
    for v in vulns_sorted:
        if len(new_patterns) >= max_new:
            break
        cve_id = v.get("cveID")
        if not cve_id or cve_id in existing_cves:
            continue
        for cwe in (v.get("cwes") or []):
            if cwe not in CWE_TEMPLATES or cwe in taken_cwes:
                continue
            tmpl = CWE_TEMPLATES[cwe]
            pattern = {
                "id": "TI-WEB-" + cve_id,
                "name": tmpl["category_name"] + " - precedent: " + v.get("vulnerabilityName", cve_id),
                "category": "code",
                "severity": tmpl["severity"],
                "cwe": cwe,
                "regex": tmpl["regex"],
                "flags": tmpl["flags"],
                "description": (v.get("shortDescription") or "")[:300],
                "suggested_fix": tmpl["suggested_fix"],
                "source": "CISA KEV Catalog  -  " + cve_id + " (" + v.get("vendorProject", "") + " " + v.get("product", "") + "), added " + v.get("dateAdded", ""),
                "source_cve": cve_id,
                "source_url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
                "date_added": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "status": "pending",
                "auto_detectable": tmpl["regex"] is not None,
                "example_vulnerable": tmpl.get("example_vulnerable", ""),
                "example_fixed": tmpl.get("example_fixed", ""),
            }
            patterns.append(pattern)
            new_patterns.append(pattern)
            taken_cwes.add(cwe)
            break

    if new_patterns:
        scanner.save_patterns(patterns)

    meta = {
        "last_synced_at": _utcnow_str(),
        "source": source,
        "total_seen": len(vulns),
        "new_count": len(new_patterns),
    }
    save_meta(meta)

    return {
        "ok": True,
        "source": source,
        "total_seen": len(vulns),
        "new_patterns": new_patterns,
        "synced_at": meta["last_synced_at"],
    }
