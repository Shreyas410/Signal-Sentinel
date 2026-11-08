"""Signal Sentinel — Flask backend.

Phase 1: an AI security agent that keeps its own knowledge current by
pulling real, currently-exploited vulnerabilities from the CISA KEV
feed, drafts detection rules for them, and (once an analyst approves
them) runs those checks against a codebase in a live, narrated scan.
Phase 2: customer-facing scam/phishing message & link shield.
"""
import json
import os
import random
import threading
import time
import uuid
from datetime import datetime

from flask import Flask, jsonify, render_template, request

import scanner
import scam_shield
import threat_intel_agent
import domain_intel_agent
import fixes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

JOBS = {}
JOBS_LOCK = threading.Lock()


def _emit(job, text, kind="info", **extra):
    event = {"t": time.time(), "kind": kind, "text": text}
    event.update(extra)
    job["events"].append(event)
    job["status_line"] = text


def _run_pipeline(job_id, repo_id):
    job = JOBS[job_id]
    try:
        repo = scanner.get_repo(repo_id)
        job["repo"] = repo["name"]

        _emit(job, "Connecting to repository \"" + repo["name"] + "\"...", "info")
        time.sleep(0.7)

        files = scanner.list_repo_files(repo["path"])
        job["files"] = files
        _emit(job, "Found " + str(len(files)) + " files to analyze: " + ", ".join(files), "info")
        time.sleep(0.5)

        all_patterns = scanner.load_patterns(approved_only=True)
        code_patterns = [p for p in all_patterns if p.get("category") == "code" and p.get("regex")]
        dep_patterns = [p for p in all_patterns if p.get("category") == "dependency"]

        meta = threat_intel_agent.load_meta()
        last_sync = meta.get("last_synced_at") or "never (using seed patterns)"
        _emit(job, "Loaded " + str(len(code_patterns) + len(dep_patterns)) + " active attack patterns from the threat-intel feed (last synced " + last_sync + ")", "info")
        time.sleep(0.6)

        findings = []
        total_checks = len(code_patterns) + (1 if dep_patterns else 0)
        per_check_delay = max(0.12, min(0.4, 3.5 / max(total_checks, 1)))

        for pattern in code_patterns:
            _emit(job, "Checking for " + pattern["name"] + " (" + pattern.get("cwe", "") + ")...",
                  "checking", pattern_id=pattern["id"], severity=pattern["severity"])
            time.sleep(per_check_delay)
            matches = scanner.scan_code(repo["path"], patterns=[pattern])
            findings.extend(matches)
            if matches:
                locs = ", ".join(m["file"] + ":" + str(m["line"]) for m in matches[:3])
                _emit(job, str(len(matches)) + " match(es) found -> " + locs, "found",
                      pattern_id=pattern["id"], severity=pattern["severity"], count=len(matches))
            else:
                _emit(job, "Clear", "clear", pattern_id=pattern["id"])

        if dep_patterns:
            _emit(job, "Auditing requirements.txt against " + str(len(dep_patterns)) + " known-vulnerable dependency versions...", "checking")
            time.sleep(per_check_delay * 2)
            dep_findings = scanner.scan_dependencies(repo["path"], patterns=dep_patterns)
            findings.extend(dep_findings)
            if dep_findings:
                names = ", ".join(f["name"] for f in dep_findings)
                _emit(job, str(len(dep_findings)) + " vulnerable dependency pin(s) found -> " + names, "found", severity="high")
            else:
                _emit(job, "All dependencies clear", "clear")

        findings.sort(key=lambda x: (scanner.SEVERITY_ORDER.get(x["severity"], 9), x["file"], x["line"]))

        for f in findings:
            f["repo_id"] = repo_id
            f["finding_id"] = f["file"] + ":" + str(f["line"]) + ":" + f["pattern_id"]
            code_fix = fixes.get_fix(repo_id, f["file"], f["line"])
            f["has_code_fix"] = code_fix is not None
            if code_fix:
                f["fix_original"] = code_fix["original"]
                f["fix_fixed"] = code_fix["fixed"]

        _emit(job, "Drafting fix suggestions for " + str(len(findings)) + " finding(s)...", "info")
        time.sleep(0.9)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        with JOBS_LOCK:
            job["findings"] = findings
            job["counts"] = counts
            job["patterns_checked"] = len(code_patterns) + len(dep_patterns)
            job["scanned_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            job["files_scanned"] = len(files)

        _emit(job, "Scan complete - " + str(len(findings)) + " finding(s) across " + str(len(files)) + " files, checked against " + str(job["patterns_checked"]) + " active patterns.", "done")

        with JOBS_LOCK:
            job["status"] = "done"
    except Exception as exc:  # pragma: no cover
        with JOBS_LOCK:
            job["status"] = "error"
            job["error"] = str(exc)
        _emit(job, "Scan failed: " + str(exc), "error")


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/app")
def dashboard():
    return render_template("index.html")


# ---------- Phase 1: Developer / CI shield ----------

@app.route("/api/repos")
def repos():
    return jsonify(scanner.list_repos())


@app.route("/api/pipeline/repo-files")
def repo_files():
    repo_id = request.args.get("repo_id", "core-api")
    repo = scanner.get_repo(repo_id)
    files = {}
    for rel in scanner.list_repo_files(repo["path"]):
        with open(os.path.join(repo["path"], rel), "r", encoding="utf-8") as f:
            files[rel] = f.read()
    return jsonify(files)


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    body = request.get_json(silent=True) or {}
    repo_id = body.get("repo_id", "core-api")
    job_id = uuid.uuid4().hex[:10]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "running",
            "events": [],
            "status_line": "Starting...",
            "findings": [],
            "counts": {},
        }
    thread = threading.Thread(target=_run_pipeline, args=(job_id, repo_id), daemon=True)
    thread.start()
    return jsonify({"job_id": job_id})


@app.route("/api/scan/<job_id>/status")
def scan_status(job_id):
    since = int(request.args.get("since", 0))
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "not found"}), 404
        new_events = job["events"][since:]
        return jsonify({
            "status": job["status"],
            "status_line": job["status_line"],
            "events": new_events,
            "event_count": len(job["events"]),
            "findings": job["findings"] if job["status"] in ("done", "error") else [],
            "counts": job["counts"],
            "patterns_checked": job.get("patterns_checked"),
            "files_scanned": job.get("files_scanned"),
            "scanned_at": job.get("scanned_at"),
            "repo": job.get("repo"),
            "error": job.get("error"),
        })


@app.route("/api/fix/apply", methods=["POST"])
def apply_fix():
    body = request.get_json(force=True) or {}
    repo_id = body.get("repo_id")
    file = body.get("file")
    line = body.get("line")
    if not (repo_id and file and line):
        return jsonify({"ok": False, "error": "missing repo_id/file/line"}), 400

    fix = fixes.get_fix(repo_id, file, line)
    if not fix:
        return jsonify({"ok": False, "error": "no fix available for this finding"}), 404

    repo = scanner.get_repo(repo_id)
    path = os.path.join(repo["path"], file)
    if not os.path.exists(path):
        return jsonify({"ok": False, "error": "file not found"}), 404

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    file_lines = content.split("\n")

    original_lines = fix["original"].split("\n")
    start = line - 1
    end = start + len(original_lines)
    current_slice = "\n".join(file_lines[start:end])

    if current_slice.strip() != fix["original"].strip():
        return jsonify({
            "ok": False,
            "error": "the file has changed since this was scanned — re-run the scan and try again",
        }), 409

    new_lines = file_lines[:start] + fix["fixed"].split("\n") + file_lines[end:]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(new_lines))

    return jsonify({"ok": True, "file": file, "line": line, "fixed": fix["fixed"]})


@app.route("/api/threat-intel")
def threat_intel_list():
    patterns = scanner.load_patterns(approved_only=False)
    return jsonify(patterns)


@app.route("/api/threat-intel/meta")
def threat_intel_meta():
    return jsonify(threat_intel_agent.load_meta())


@app.route("/api/threat-intel/sync", methods=["POST"])
def threat_intel_sync():
    result = threat_intel_agent.sync_from_web()
    return jsonify(result)


@app.route("/api/threat-intel/<pattern_id>/approve", methods=["POST"])
def approve_pattern(pattern_id):
    patterns = scanner.load_patterns(approved_only=False)
    found = None
    for p in patterns:
        if p["id"] == pattern_id:
            p["status"] = "approved"
            found = p
            break
    if not found:
        return jsonify({"error": "not found"}), 404
    scanner.save_patterns(patterns)
    return jsonify(found)


@app.route("/api/threat-intel/<pattern_id>/reject", methods=["POST"])
def reject_pattern(pattern_id):
    patterns = scanner.load_patterns(approved_only=False)
    found = None
    for p in patterns:
        if p["id"] == pattern_id:
            p["status"] = "rejected"
            found = p
            break
    if not found:
        return jsonify({"error": "not found"}), 404
    scanner.save_patterns(patterns)
    return jsonify(found)


# ---------- Phase 2: Customer scam shield ----------

@app.route("/api/scam-check", methods=["POST"])
def scam_check():
    body = request.get_json(force=True) or {}
    text = body.get("text", "")
    result = scam_shield.analyze_message(text)
    return jsonify(result)


@app.route("/api/link-check", methods=["POST"])
def link_check():
    body = request.get_json(force=True) or {}
    url = body.get("url", "").strip()
    if not url:
        return jsonify({"error": "missing url"}), 400
    result = scam_shield.analyze_link(url)
    return jsonify(result)


@app.route("/api/blocked-domains")
def blocked_domains():
    return jsonify(scam_shield.load_blocked_domains())


@app.route("/api/blocked-domains/all")
def blocked_domains_all():
    return jsonify(scam_shield.load_blocked_domains(approved_only=False))


@app.route("/api/blocked-domains/meta")
def blocked_domains_meta():
    return jsonify(domain_intel_agent.load_meta())


@app.route("/api/blocked-domains/sync", methods=["POST"])
def blocked_domains_sync():
    result = domain_intel_agent.sync_from_web()
    return jsonify(result)


@app.route("/api/blocked-domains/<path:domain>/approve", methods=["POST"])
def approve_domain(domain):
    domains = scam_shield.load_blocked_domains(approved_only=False)
    found = None
    for d in domains:
        if d["domain"] == domain:
            d["status"] = "approved"
            found = d
            break
    if not found:
        return jsonify({"error": "not found"}), 404
    scam_shield.save_blocked_domains(domains)
    return jsonify(found)


@app.route("/api/blocked-domains/<path:domain>/reject", methods=["POST"])
def reject_domain(domain):
    domains = scam_shield.load_blocked_domains(approved_only=False)
    found = None
    for d in domains:
        if d["domain"] == domain:
            d["status"] = "rejected"
            found = d
            break
    if not found:
        return jsonify({"error": "not found"}), 404
    scam_shield.save_blocked_domains(domains)
    return jsonify(found)


@app.route("/api/inbox/next")
def inbox_next():
    """Simulates a message arriving and being scored automatically,
    the moment it arrives — the same check a carrier-integrated
    version would run on-device, before the user ever opens it.
    Nothing here is read or stored after scoring; the demo pool just
    stands in for a real incoming message."""
    inbox = scam_shield.load_simulated_inbox()
    entry = random.choice(inbox)
    result = scam_shield.analyze_message(entry["text"])
    return jsonify({
        "id": uuid.uuid4().hex[:8],
        "sender": entry["sender"],
        "text": entry["text"],
        "arrived_at": datetime.utcnow().strftime("%H:%M:%S"),
        **result,
    })


@app.route("/api/scam-patterns")
def scam_patterns():
    return jsonify(scam_shield.load_scam_patterns(approved_only=False))


@app.route("/api/scam-patterns/<pattern_id>/approve", methods=["POST"])
def approve_scam_pattern(pattern_id):
    patterns = scam_shield.load_scam_patterns(approved_only=False)
    found = None
    for p in patterns:
        if p["id"] == pattern_id:
            p["status"] = "approved"
            found = p
            break
    if not found:
        return jsonify({"error": "not found"}), 404
    scam_shield.save_scam_patterns(patterns)
    return jsonify(found)


@app.route("/api/recovery")
def recovery():
    return jsonify(scam_shield.recovery_checklist())


@app.route("/api/metrics")
def metrics():
    path = os.path.join(BASE_DIR, "data", "metrics.json")
    if not os.path.exists(path):
        return jsonify({"error": "metrics not generated yet"}), 404
    with open(path, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5057, debug=True, use_reloader=False)
