"""Phase 2 — heuristic scam/phishing message & link risk scorer."""
import json
import os
import re
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCAM_PATTERNS_PATH = os.path.join(BASE_DIR, "data", "scam_patterns.json")
BLOCKED_DOMAINS_PATH = os.path.join(BASE_DIR, "data", "blocked_domains.json")
SIMULATED_INBOX_PATH = os.path.join(BASE_DIR, "data", "simulated_inbox.json")

URGENCY_WORDS = ["within 24 hours", "act now", "immediately", "urgent", "final notice",
                 "expire", "suspended", "act fast", "limited time", "right away"]
PAYMENT_WORDS = ["gift card", "crypto", "bitcoin", "zelle", "wire transfer", "small fee",
                 "processing fee", "redelivery fee", "pay now"]
IMPERSONATION_BRANDS = ["usps", "fedex", "ups", "irs", "carrier", "bank of america",
                        "amazon", "apple", "paypal", "social security"]
RISKY_TLDS = [".top", ".xyz", ".click", ".click", ".work", ".info", ".tk", ".loan"]

LOOKALIKE_BRANDS = {
    "usps": "usps.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "paypal": "paypal.com",
}


def load_scam_patterns(approved_only=True):
    with open(SCAM_PATTERNS_PATH, "r", encoding="utf-8") as f:
        patterns = json.load(f)
    if approved_only:
        patterns = [p for p in patterns if p.get("status") == "approved"]
    return patterns


def save_scam_patterns(patterns):
    with open(SCAM_PATTERNS_PATH, "w", encoding="utf-8") as f:
        json.dump(patterns, f, indent=2)


def _extract_urls(text):
    return re.findall(r"https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9\-]+\.(?:com|net|org|top|xyz|click|work|info|tk|loan)[^\s]*", text)


def _is_lookalike(url_host, brand):
    real = LOOKALIKE_BRANDS.get(brand)
    if not real:
        return False
    host = url_host.lower()
    if host == real:
        return False
    # crude leetspeak / char-swap lookalike check
    normalized = host.replace("1", "i").replace("0", "o").replace("rn", "m")
    brand_core = real.split(".")[0]
    return brand_core in normalized and host != real


def _synthetic_domain_age_days(url):
    # deterministic pseudo-"WHOIS" lookup for demo purposes, seeded by domain text
    h = abs(hash(url)) % 400
    return h


def analyze_message(text, patterns=None):
    if patterns is None:
        patterns = load_scam_patterns(approved_only=True)

    urls = _extract_urls(text)
    # Wording heuristics look only at the message text, not the link
    # itself — otherwise a bare link containing "usps" in its domain
    # would falsely look like it "claims to be from USPS" in the text.
    wording_only = text
    for u in urls:
        wording_only = wording_only.replace(u, " ")
    text_lower = wording_only.lower()

    score = 0
    reasons = []
    matched_pattern = None

    # Layer 3: wording heuristics
    hits_urgency = [w for w in URGENCY_WORDS if w in text_lower]
    if hits_urgency:
        score += 20
        reasons.append(f"Uses urgency language ({', '.join(hits_urgency[:2])})")

    hits_payment = [w for w in PAYMENT_WORDS if w in text_lower]
    if hits_payment:
        score += 25
        reasons.append(f"Requests payment via {hits_payment[0]}")

    brand_hit = next((b for b in IMPERSONATION_BRANDS if b in text_lower), None)
    sender_looks_personal = bool(re.search(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", text)) or "unknown number" in text_lower
    if brand_hit:
        score += 15
        reasons.append(f"Claims to be from {brand_hit.upper()}")
        if sender_looks_personal:
            score += 15
            reasons.append("Message claims to be a brand but came from a personal-looking number")

    # Pattern-library match (self-updating threat intel)
    for p in patterns:
        kw_hits = [k for k in p["keywords"] if k in text_lower]
        if len(kw_hits) >= 2:
            score += 25
            matched_pattern = p
            reasons.append(f"Matches known pattern '{p['name']}' ({p['source']})")
            break

    # Layer 1 + 2: every link in the message is run through the same
    # domain-firewall check used by the network pipeline. A single
    # malicious link is often the strongest signal in the whole message,
    # so its verdict carries real weight here rather than being a
    # separate step the user has to run themselves.
    blocked_domains = load_blocked_domains()
    links_checked = []
    link_score = 0
    for url in urls:
        link_result = analyze_link(url, blocked_domains=blocked_domains)
        links_checked.append({
            "url": url,
            "host": link_result["host"],
            "verdict": link_result["verdict"],
            "score": link_result["score"],
        })
        link_score = max(link_score, link_result["score"])
        if link_result["verdict"] == "blocked":
            reasons.append(f"Link to {link_result['host']} is blocked by the network firewall: {link_result['reasons'][0]}")
        elif link_result["verdict"] == "warning":
            reasons.append(f"Link to {link_result['host']}: {link_result['reasons'][0]}")

    # A confirmed-malicious link dominates the verdict even if the
    # wording alone looked mild; a borderline link just adds weight.
    score = max(score, link_score) + min(score, link_score) * 0.3
    score = min(round(score), 99)
    if score >= 70:
        risk = "high"
    elif score >= 40:
        risk = "medium"
    else:
        risk = "low"

    if not reasons:
        reasons.append("No known scam indicators detected in wording or links")

    return {
        "score": score,
        "risk": risk,
        "reasons": reasons[:4],
        "matched_pattern": matched_pattern["name"] if matched_pattern else None,
        "urls_found": urls,
        "links_checked": links_checked,
    }


def load_simulated_inbox():
    with open(SIMULATED_INBOX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_blocked_domains(approved_only=True):
    with open(BLOCKED_DOMAINS_PATH, "r", encoding="utf-8") as f:
        domains = json.load(f)
    if approved_only:
        domains = [d for d in domains if d.get("status", "approved") == "approved"]
    return domains


def save_blocked_domains(domains):
    with open(BLOCKED_DOMAINS_PATH, "w", encoding="utf-8") as f:
        json.dump(domains, f, indent=2)


def _host_from_url(url):
    host = re.sub(r"^https?://", "", url.strip())
    host = host.split("/")[0].split("?")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def analyze_link(url, blocked_domains=None):
    """Network-firewall-style check: looks only at the destination domain,
    never at the message or page content. Mirrors the dev pipeline's
    'match against known-bad patterns, block before it ships' logic —
    here applied to a connection instead of a commit."""
    if blocked_domains is None:
        blocked_domains = load_blocked_domains()

    host = _host_from_url(url)
    reasons = []
    score = 0
    matched_entry = None

    for entry in blocked_domains:
        if host == entry["domain"] or host.endswith("." + entry["domain"]):
            matched_entry = entry
            break

    if matched_entry:
        score = 99
        reasons.append(f"On the network's known-scam blocklist - {matched_entry['category']}")
        reasons.append(f"Source: {matched_entry['source']} (added {matched_entry['date_added']})")
    else:
        if any(host.endswith(tld) for tld in RISKY_TLDS):
            score += 35
            reasons.append(f"Uses a high-risk domain ending (.{host.split('.')[-1]})")

        matched_brand = None
        for brand in LOOKALIKE_BRANDS:
            if _is_lookalike(host, brand):
                matched_brand = brand
                break
        if matched_brand:
            score += 40
            reasons.append(f"Looks like a lookalike of {LOOKALIKE_BRANDS[matched_brand]}")

        age_days = _synthetic_domain_age_days(url)
        if age_days < 14:
            score += 35
            reasons.append(f"Domain was registered only {age_days} day(s) ago")
        elif age_days < 60:
            score += 15
            reasons.append(f"Domain was registered recently ({age_days} days ago)")

    score = min(score, 99)
    if score >= 70:
        verdict = "blocked"
    elif score >= 35:
        verdict = "warning"
    else:
        verdict = "allowed"

    if not reasons:
        reasons.append("No known threat indicators found for this domain")

    return {
        "host": host,
        "score": score,
        "verdict": verdict,
        "reasons": reasons[:4],
        "checked_against": len(blocked_domains),
    }


RECOVERY_STEPS = [
    {"step": "Freeze the card or account used", "detail": "Call your bank's fraud line or freeze the card in its app immediately."},
    {"step": "Change your passwords", "detail": "Update the password for any account whose login info may have been entered on the fake page."},
    {"step": "Report the message", "detail": "Forward the text to 7726 (SPAM) and report the number in the app so other customers are protected."},
    {"step": "Lock your SIM", "detail": "Enable a SIM lock / port-out PIN in your carrier app to stop SIM-swap attempts."},
    {"step": "Set a 48-hour check-in reminder", "detail": "We'll remind you to review recent statements for any unauthorized charges."},
]


def recovery_checklist():
    return RECOVERY_STEPS
