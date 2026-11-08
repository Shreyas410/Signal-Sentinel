"""Regex-based static scanner that matches source files against the
approved threat-intel pattern library, plus a dependency-version checker
for requirements.txt."""
import os
import re
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PATTERNS_PATH = os.path.join(BASE_DIR, "data", "threat_intel_patterns.json")
SAMPLE_REPO = os.path.join(BASE_DIR, "data", "sample_repo")

REPOS = {
    "core-api": {
        "id": "core-api",
        "name": "core-customer-api",
        "description": "Core customer API — auth, profile, admin and session endpoints.",
        "path": os.path.join(BASE_DIR, "data", "sample_repo"),
    },
    "payments-service": {
        "id": "payments-service",
        "name": "payments-service",
        "description": "Payments & receipts microservice — downloads, refunds and webhook handling.",
        "path": os.path.join(BASE_DIR, "data", "sample_repo_payments"),
    },
}


def get_repo(repo_id):
    return REPOS.get(repo_id, REPOS["core-api"])


def list_repos():
    out = []
    for r in REPOS.values():
        file_count = len(list_repo_files(r["path"]))
        out.append({**r, "file_count": file_count})
    return out


def load_patterns(category=None, approved_only=True):
    with open(PATTERNS_PATH, "r", encoding="utf-8") as f:
        patterns = json.load(f)
    if approved_only:
        patterns = [p for p in patterns if p.get("status") == "approved"]
    if category:
        patterns = [p for p in patterns if p.get("category") == category]
    return patterns


def save_patterns(patterns):
    with open(PATTERNS_PATH, "w", encoding="utf-8") as f:
        json.dump(patterns, f, indent=2)


def _flags_from_str(flag_str):
    flags = 0
    if not flag_str:
        return flags
    for name in flag_str.split("|"):
        flags |= getattr(re, name.strip(), 0)
    return flags


def _line_number_for_offset(text, offset):
    return text.count("\n", 0, offset) + 1


def list_repo_files(repo_dir=SAMPLE_REPO):
    out = []
    for root, _dirs, files in os.walk(repo_dir):
        for fname in files:
            out.append(os.path.relpath(os.path.join(root, fname), repo_dir))
    return sorted(out)


def scan_code(repo_dir=SAMPLE_REPO, patterns=None):
    """Scan every source file in repo_dir against the regex patterns.
    Returns a list of findings: file, line, snippet, pattern info."""
    if patterns is None:
        patterns = load_patterns(category="code", approved_only=True)

    findings = []
    for root, _dirs, files in os.walk(repo_dir):
        for fname in files:
            if not fname.endswith((".py", ".js", ".ts")):
                continue
            path = os.path.join(root, fname)
            rel = os.path.relpath(path, repo_dir)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            lines = content.splitlines()

            for pattern in patterns:
                regex = pattern.get("regex")
                if not regex:
                    continue
                flags = _flags_from_str(pattern.get("flags", ""))
                for m in re.finditer(regex, content, flags):
                    line_no = _line_number_for_offset(content, m.start())
                    snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else m.group(0).strip()
                    findings.append({
                        "file": rel,
                        "line": line_no,
                        "snippet": snippet,
                        "pattern_id": pattern["id"],
                        "name": pattern["name"],
                        "severity": pattern["severity"],
                        "cwe": pattern.get("cwe", ""),
                        "description": pattern["description"],
                        "suggested_fix": pattern["suggested_fix"],
                        "source": pattern["source"],
                        "date_added": pattern.get("date_added", ""),
                    })
    return findings


_VERSION_RE = re.compile(r"^([A-Za-z0-9_\-\.]+)\s*==\s*([0-9][0-9A-Za-z\.\-]*)")


def _version_tuple(v):
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def scan_dependencies(repo_dir=SAMPLE_REPO, patterns=None):
    if patterns is None:
        patterns = load_patterns(category="dependency", approved_only=True)
    by_package = {p["package"].lower(): p for p in patterns}

    findings = []
    req_path = os.path.join(repo_dir, "requirements.txt")
    if not os.path.exists(req_path):
        return findings

    with open(req_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for i, raw_line in enumerate(lines, start=1):
        m = _VERSION_RE.match(raw_line.strip())
        if not m:
            continue
        pkg, version = m.group(1).lower(), m.group(2)
        pattern = by_package.get(pkg)
        if not pattern:
            continue
        max_safe = pattern.get("max_safe_below")
        if max_safe and _version_tuple(version) < _version_tuple(max_safe):
            findings.append({
                "file": "requirements.txt",
                "line": i,
                "snippet": raw_line.strip(),
                "pattern_id": pattern["id"],
                "name": pattern["name"],
                "severity": pattern["severity"],
                "cwe": pattern.get("cwe", ""),
                "description": pattern["description"],
                "suggested_fix": pattern["suggested_fix"],
                "source": pattern["source"],
                "date_added": pattern.get("date_added", ""),
            })
    return findings


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_full_scan(repo_dir=SAMPLE_REPO):
    code_findings = scan_code(repo_dir)
    dep_findings = scan_dependencies(repo_dir)
    all_findings = code_findings + dep_findings
    all_findings.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 9), x["file"], x["line"]))
    return all_findings
