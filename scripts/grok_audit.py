#!/usr/bin/env python3
"""
grok_audit.py — Forensic audit of Grok Build CLI data uploads.

Reads ~/.grok (read-only), determines what the CLI uploaded to xAI,
checks whether local secrets leaked into uploadable artifacts, and
writes an evidence package with SHA-256 checksums.

SECRET SAFETY: secret VALUES are never printed, never written to any
output file, and never leave this process. Only key names, lengths,
masked prefixes (first 6 chars of non-secrets only) and hit counts
are reported.

Usage:
    python3 grok_audit.py [--grok-dir ~/.grok] [--output-dir DIR] [--no-log-copy]

Output:
    <output-dir>/audit_summary.json   machine-readable findings
    <output-dir>/evidence/*.jsonl     extracted raw log records
    <output-dir>/evidence/gcs_objects.txt
    <output-dir>/evidence/SHA256SUMS.txt
Exit codes: 0 ok, 1 grok not installed, 2 unexpected error.
"""

import argparse, gzip, hashlib, json, os, re, subprocess, sys, urllib.parse
from collections import defaultdict
from datetime import datetime, timezone

HOME = os.path.expanduser("~")

# Grok's own shipped content — excluded from user-secret matching (perf)
# but INCLUDED in the key-prefix scan, classified as vendor docs.
VENDOR_DIRS = {"docs", "marketplace-cache", "bundled", "downloads", "vendor",
               "bin", "completions", "installed-plugins", "skills"}

# Fields in auth.json safe to surface (identity, not credentials).
AUTH_SAFE_FIELDS = {"user_id", "email", "first_name", "last_name", "team_id",
                    "principal_id", "auth_mode", "coding_data_retention_opt_out",
                    "oidc_issuer", "oidc_client_id", "create_time"}

KEY_PREFIXES = ["sk-ant-", "sk-proj-", "sk-svcacct", "ghp_", "github_pat_",
                "gsk_", "AKIA", "xoxb-", "xoxp-"]
# Minimum matched-token length for a prefix hit to look like a real credential.
PREFIX_REAL_MIN = {"ghp_": 40, "github_pat_": 50, "AKIA": 20}
PREFIX_REAL_DEFAULT = 30

MIN_SECRET_LEN = 12   # env values shorter than this are skipped: empty/short
                      # values cause massive false positives (an empty value
                      # substring-matches every line of every file).

# Key-name heuristic for sensitivity. Not every long .env value is a secret —
# base URLs, mode flags, model names and enum values are config, and flagging
# them as "leaked secrets" buries the credentials that actually matter. A
# credential is identified by its KEY name, then confirmed by value match.
SECRET_KEY_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|_KEY$|APIKEY|API_KEY|PRIVATE|CREDENTIAL|"
    r"_DSN|CONN|DATABASE_URL|ACCESS_KEY|_PWD|SIGNING|SALT|CERT|PEM)", re.I)


def is_secret_key(name):
    return bool(SECRET_KEY_RE.search(name))


def log(msg):
    print(f"[audit] {msg}", file=sys.stderr, flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path, limit=200 * 1024 * 1024):
    try:
        if os.path.getsize(path) > limit:
            return ""
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


# ---------------------------------------------------------------- install
def detect_install(grok):
    info = {"grok_dir": grok, "installed": os.path.isdir(grok)}
    if not info["installed"]:
        return info
    v = os.path.join(grok, "version.json")
    if os.path.isfile(v):
        try:
            info["version"] = json.load(open(v)).get("version")
        except Exception:
            pass
    a = os.path.join(grok, "agent_id")
    if os.path.isfile(a):
        info["agent_id"] = read_text(a).strip()
    cfg = read_text(os.path.join(grok, "config.toml"))
    info["mitigation_config"] = {
        "harness.disable_codebase_upload": "disable_codebase_upload" in cfg and "true" in
            cfg.split("disable_codebase_upload", 1)[1].splitlines()[0],
        "telemetry.trace_upload_false": bool(re.search(
            r"\[telemetry\][^\[]*trace_upload\s*=\s*false", cfg, re.S)),
        "features.telemetry_false": bool(re.search(
            r"\[features\][^\[]*telemetry\s*=\s*false", cfg, re.S)),
        "auto_update": bool(re.search(r"auto_update\s*=\s*true", cfg)),
    }
    return info


def read_identity(grok):
    """Non-secret account identity from auth.json (values of token-ish
    fields are replaced by their length)."""
    path = os.path.join(grok, "auth.json")
    out = {}
    if not os.path.isfile(path):
        return out
    try:
        data = json.load(open(path))
    except Exception:
        return out
    # shape: { "<issuer>::<client>": {fields} }  — tolerate variants
    entries = list(data.values()) if isinstance(data, dict) else []
    for e in entries:
        if not isinstance(e, dict):
            continue
        for k, v in e.items():
            if k in AUTH_SAFE_FIELDS:
                out[k] = v
    return out


# ---------------------------------------------------------------- log parse
def parse_unified_log(grok):
    """Stream unified.jsonl; collect upload evidence."""
    path = os.path.join(grok, "logs", "unified.jsonl")
    r = {"log_found": os.path.isfile(path), "log_path": path,
         "first_ts": None, "last_ts": None, "versions": set(),
         "decisions": [], "decision_count": 0, "consent": None,
         "uploads_start": [], "enqueued": [], "failures": [],
         "sid_repos": defaultdict(set), "endpoints": set(),
         "artifact_refs": defaultdict(int)}
    if not r["log_found"]:
        return r
    art_re = re.compile(r"turn_\d+/(?:before_|after_)?([a-z_]+?)(?:\.tar\.gz|\.json)")
    with open(path, "r", errors="ignore") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            ts, msg, ctx = rec.get("ts"), rec.get("msg", ""), rec.get("ctx") or {}
            if ts:
                r["first_ts"] = r["first_ts"] or ts
                r["last_ts"] = ts
            if rec.get("ver"):
                r["versions"].add(rec["ver"])
            if msg == "trace.upload.decision":
                r["decision_count"] += 1
                if r["consent"] is None:
                    r["consent"] = {k: ctx.get(k) for k in (
                        "trace_upload", "trace_upload_source", "telemetry_mode",
                        "telemetry_source", "in_env_trace_upload",
                        "in_cfg_telemetry_trace_upload", "in_cfg_features_telemetry",
                        "in_remote_trace_upload_enabled")}
                if len(r["decisions"]) < 3:
                    r["decisions"].append(rec)
            elif msg == "repo_state.upload.start":
                r["uploads_start"].append(rec)
                if rec.get("sid") and ctx.get("repo_path"):
                    r["sid_repos"][rec["sid"]].add(ctx["repo_path"])
            elif msg == "repo_state.upload.enqueued":
                r["enqueued"].append(rec)
                m = art_re.search(ctx.get("gcs_path", ""))
                if m:
                    r["artifact_refs"][m.group(1)] += 1
            elif msg.startswith("upload failed"):
                r["failures"].append(rec)
                for u in re.findall(r"https://[\w./-]+", json.dumps(ctx)):
                    # keep only real upload destinations; failure strings also
                    # embed cloudflare 5xx error-page URLs that are just noise.
                    if re.search(r"grok\.com|x\.ai|googleapis|storage", u):
                        r["endpoints"].add(u)
                m = art_re.search(json.dumps(ctx))
                if m:
                    r["artifact_refs"][m.group(1)] += 1
    r["versions"] = sorted(r["versions"])
    r["endpoints"] = sorted(r["endpoints"])
    return r


def summarize_sessions(parsed):
    """Per-session upload totals."""
    sess = defaultdict(lambda: {"snapshots": 0, "bytes": 0,
                                "first_ts": None, "last_ts": None, "objects": []})
    for rec in parsed["enqueued"]:
        sid, ctx = rec.get("sid", "?"), rec.get("ctx") or {}
        s = sess[sid]
        s["snapshots"] += 1
        s["bytes"] += ctx.get("size_bytes", 0)
        s["first_ts"] = s["first_ts"] or rec.get("ts")
        s["last_ts"] = rec.get("ts")
        s["objects"].append(ctx.get("gcs_path", ""))
    out = []
    for sid, s in sorted(sess.items(), key=lambda kv: kv[1]["first_ts"] or ""):
        out.append({"session_id": sid,
                    "repos": sorted(parsed["sid_repos"].get(sid, [])),
                    "snapshots": s["snapshots"], "bytes": s["bytes"],
                    "first_ts": s["first_ts"], "last_ts": s["last_ts"],
                    "objects": s["objects"]})
    return out


def session_cwds(grok):
    """All working directories Grok ever ran in (sessions/ dir names are
    URL-encoded cwds)."""
    d = os.path.join(grok, "sessions")
    cwds = []
    if os.path.isdir(d):
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if os.path.isdir(p) and name.startswith("%2F"):
                cwds.append(urllib.parse.unquote(name))
    return cwds


# ---------------------------------------------------------------- secrets
def find_env_files(repos):
    """Real .env files (not *.example) in the affected repos, bounded."""
    prune = {"node_modules", ".git", ".venv", "venv", "dist", "build", "target"}
    found = []
    for repo in repos:
        if not os.path.isdir(repo) or os.path.realpath(repo) == HOME:
            continue  # never sweep the home directory
        base_depth = repo.rstrip("/").count("/")
        for root, dirs, files in os.walk(repo):
            dirs[:] = [x for x in dirs if x not in prune]
            if root.count("/") - base_depth >= 4:
                dirs[:] = []
            for fn in files:
                if fn.startswith(".env") and ".example" not in fn:
                    found.append({"file": os.path.join(root, fn), "repo": repo})
    return found


def env_candidates(env_files):
    """(label, key_name, value) triples; values stay in memory only."""
    cands = []
    for ef in env_files:
        tracked = None
        try:
            tracked = subprocess.run(
                ["git", "-C", ef["repo"], "ls-files", "--error-unmatch",
                 os.path.relpath(ef["file"], ef["repo"])],
                capture_output=True, timeout=10).returncode == 0
        except Exception:
            pass
        ef["git_tracked"] = tracked
        for line in read_text(ef["file"]).splitlines():
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.+)$", line.strip())
            if not m:
                continue
            val = m.group(2).strip().strip("'\"")
            if len(val) >= MIN_SECRET_LEN:
                cands.append((ef["file"], m.group(1), val))
    return cands


def crosstool_candidates():
    """Long string values from other AI-tool credential files."""
    cands = []

    def from_json(path, label, min_len=25, key_filter=None):
        if not os.path.isfile(path):
            return
        try:
            data = json.load(open(path))
        except Exception:
            return

        def walk(o, keypath=""):
            if isinstance(o, dict):
                for k, v in o.items():
                    walk(v, k)
            elif isinstance(o, list):
                for v in o:
                    walk(v, keypath)
            elif isinstance(o, str) and len(o) >= min_len:
                if key_filter and not re.search(key_filter, keypath, re.I):
                    return
                cands.append((label, keypath or "?", o))
        walk(data)

    from_json(os.path.join(HOME, ".codex", "auth.json"), "~/.codex/auth.json")
    from_json(os.path.join(HOME, ".claude", ".credentials.json"),
              "~/.claude/.credentials.json")
    # Big mixed-content configs: only fields whose NAME suggests a credential.
    from_json(os.path.join(HOME, ".claude.json"), "~/.claude.json",
              min_len=20, key_filter=r"key|token|secret|password|credential")
    from_json(os.path.join(HOME, ".claude", "settings.json"),
              "~/.claude/settings.json",
              min_len=20, key_filter=r"key|token|secret|password|credential")
    return cands


def search_values(grok, candidates, own_output):
    """One pass over user-generated files in ~/.grok; count hits per value.
    Values are compared in-memory only."""
    results = {i: 0 for i in range(len(candidates))}
    files_hit = defaultdict(set)
    for root, dirs, files in os.walk(grok):
        rel_top = os.path.relpath(root, grok).split(os.sep)[0]
        if rel_top in VENDOR_DIRS:
            dirs[:] = []
            continue
        if own_output and os.path.commonpath([root, own_output]) == own_output:
            dirs[:] = []
            continue
        for fn in files:
            p = os.path.join(root, fn)
            try:
                if os.path.getsize(p) > 100 * 1024 * 1024:
                    continue
            except OSError:
                continue
            content = read_text(p)
            if not content:
                continue
            for i, (_src, _key, val) in enumerate(candidates):
                n = content.count(val)
                if n:
                    results[i] += n
                    files_hit[i].add(os.path.relpath(p, grok))
    return results, files_hit


def path_reference_counts(grok):
    """How often sessions reference other AI tools' config paths."""
    targets = {
        "claude_dir_abs": os.path.join(HOME, ".claude"),
        "claude_json": os.path.join(HOME, ".claude.json"),
        "codex_dir_abs": os.path.join(HOME, ".codex"),
        "codex_auth": ".codex/auth.json",
        "credentials_json": "credentials.json",
        "claude_md": "CLAUDE.md",
    }
    counts = {k: 0 for k in targets}
    sess_dir = os.path.join(grok, "sessions")
    if not os.path.isdir(sess_dir):
        return counts
    for root, _dirs, files in os.walk(sess_dir):
        for fn in files:
            content = read_text(os.path.join(root, fn))
            for k, t in targets.items():
                counts[k] += content.count(t)
    return counts


def prefix_scan(grok):
    """Scan ALL of ~/.grok for credential-shaped prefixes; classify."""
    hits = []
    tok_re = {p: re.compile(re.escape(p) + r"[A-Za-z0-9_\-]*") for p in KEY_PREFIXES}
    for root, dirs, files in os.walk(grok):
        for fn in files:
            p = os.path.join(root, fn)
            try:
                if os.path.getsize(p) > 100 * 1024 * 1024:
                    continue
            except OSError:
                continue
            content = None
            for pref in KEY_PREFIXES:
                if content is None:
                    content = read_text(p)
                    if not content:
                        break
                if pref not in content:
                    continue
                rel = os.path.relpath(p, grok)
                vendor = rel.split(os.sep)[0] in VENDOR_DIRS or rel == "README.md"
                for tok in set(tok_re[pref].findall(content)):
                    real_min = PREFIX_REAL_MIN.get(pref, PREFIX_REAL_DEFAULT)
                    hits.append({"prefix": pref, "file": rel,
                                 "token_len": len(tok),
                                 "masked": tok[:len(pref) + 4] + "...",
                                 "in_vendor_docs": vendor,
                                 "looks_real": len(tok) >= real_min and not vendor})
    return hits


# ---------------------------------------------------------------- evidence
def write_evidence(grok, parsed, sessions, outdir, copy_log=True):
    ev = os.path.join(outdir, "evidence")
    os.makedirs(ev, exist_ok=True)

    def dump(name, records):
        with open(os.path.join(ev, name), "w") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    log_path = parsed["log_path"]
    if parsed["log_found"]:
        # re-extract full record sets (parse kept only samples of decisions)
        keep = {"repo_state.upload.start": [], "repo_state.upload.enqueued": [],
                "trace.upload.decision": []}
        fails = []
        with open(log_path, "r", errors="ignore") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                msg = rec.get("msg", "")
                if msg in keep:
                    keep[msg].append(rec)
                elif msg.startswith("upload failed"):
                    fails.append(rec)
        dump("upload_start.jsonl", keep["repo_state.upload.start"])
        dump("upload_enqueued.jsonl", keep["repo_state.upload.enqueued"])
        dump("trace_upload_decisions.jsonl", keep["trace.upload.decision"])
        dump("upload_failures.jsonl", fails)
        with open(os.path.join(ev, "gcs_objects.txt"), "w") as f:
            for s in sessions:
                for o in s["objects"]:
                    f.write(o + "\n")
        if copy_log:
            with open(log_path, "rb") as src, \
                 gzip.open(os.path.join(ev, "unified.jsonl.gz"), "wb") as dst:
                while chunk := src.read(1 << 20):
                    dst.write(chunk)
    with open(os.path.join(ev, "SHA256SUMS.txt"), "w") as f:
        for fn in sorted(os.listdir(ev)):
            if fn != "SHA256SUMS.txt":
                f.write(f"{sha256_file(os.path.join(ev, fn))}  {fn}\n")
    return ev


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--grok-dir", default=os.path.join(HOME, ".grok"))
    ap.add_argument("--output-dir", default=None)
    ap.add_argument("--no-log-copy", action="store_true",
                    help="skip gzipping the full raw log into evidence/")
    args = ap.parse_args()

    grok = os.path.abspath(os.path.expanduser(args.grok_dir))
    outdir = args.output_dir or os.path.join(
        HOME, "Documents",
        f"grok-upload-audit-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}")
    outdir = os.path.abspath(os.path.expanduser(outdir))

    install = detect_install(grok)
    if not install["installed"]:
        print(json.dumps({"installed": False, "grok_dir": grok}))
        log("Grok CLI not found — nothing to audit.")
        return 1
    os.makedirs(outdir, exist_ok=True)

    log("reading account identity (non-secret fields only)")
    identity = read_identity(grok)

    log("parsing unified.jsonl")
    parsed = parse_unified_log(grok)
    sessions = summarize_sessions(parsed)
    cwds = session_cwds(grok)
    uploaded_repos = sorted({r for s in sessions for r in s["repos"]})
    attempted_repos = sorted({rec["ctx"]["repo_path"]
                              for rec in parsed["uploads_start"]
                              if rec.get("ctx", {}).get("repo_path")})

    log("writing evidence package")
    ev_dir = write_evidence(grok, parsed, sessions, outdir,
                            copy_log=not args.no_log_copy)

    log("scanning .env files in affected repos (values stay in memory)")
    env_files = find_env_files(sorted(set(attempted_repos) | set(cwds)))
    cands = env_candidates(env_files)
    log(f"  {len(env_files)} env file(s), {len(cands)} candidate value(s)")

    log("collecting cross-tool credential values (codex/claude)")
    ct = crosstool_candidates()

    log("matching all candidate values against ~/.grok user data (single pass)")
    all_cands = [(src, key, val) for src, key, val in cands] + ct
    counts, files_hit = search_values(grok, all_cands, outdir)

    secret_findings = []
    for i, (src, key, val) in enumerate(all_cands):
        # cross-tool candidates carry a label like "~/.codex/auth.json" as src
        # and are inherently credential material regardless of key name.
        crosstool = src.startswith("~") or src.startswith("/") is False
        secret_findings.append({
            "source_file": src.replace(HOME, "~"), "key": key,
            "value_len": len(val), "hits_in_grok": counts[i],
            "likely_secret": is_secret_key(key) or crosstool,
            "hit_files_sample": sorted(files_hit[i])[:5]})
    # credentials first (leaked ones on top), then config values
    secret_findings.sort(key=lambda s: (not s["likely_secret"],
                                        s["hits_in_grok"] == 0, -s["hits_in_grok"]))

    log("counting cross-tool config path references in sessions")
    path_refs = path_reference_counts(grok)

    log("scanning ~/.grok for credential-shaped prefixes")
    prefixes = prefix_scan(grok)

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "install": install,
        "identity": identity,
        "log_window": {"found": parsed["log_found"],
                       "first_ts": parsed["first_ts"],
                       "last_ts": parsed["last_ts"],
                       "cli_versions_seen": parsed["versions"]},
        "consent_evidence": {"decision_count": parsed["decision_count"],
                             "first_decision_fields": parsed["consent"]},
        "upload_summary": {
            "snapshots_enqueued": sum(s["snapshots"] for s in sessions),
            "total_bytes": sum(s["bytes"] for s in sessions),
            "upload_start_events": len(parsed["uploads_start"]),
            "failures": len(parsed["failures"]),
            "artifact_types": dict(parsed["artifact_refs"]),
            "endpoints_seen": parsed["endpoints"],
            "repos_uploaded": uploaded_repos,
            "repos_attempted_only": sorted(set(attempted_repos) - set(uploaded_repos)),
            "all_session_cwds": cwds,
            "cwds_without_upload_evidence": sorted(
                set(cwds) - set(attempted_repos)),
        },
        "sessions": [{k: v for k, v in s.items() if k != "objects"}
                     for s in sessions],
        "env_files": [{**ef, "file": ef["file"].replace(HOME, "~"),
                       "repo": ef["repo"].replace(HOME, "~")}
                      for ef in env_files],
        "secret_findings": secret_findings,
        "crosstool_path_refs": path_refs,
        "prefix_scan": prefixes,
        "evidence_dir": ev_dir,
        "notes": [
            "Log coverage begins at log_window.first_ts; sessions before that "
            "cannot be confirmed or denied locally.",
            "hits_in_grok > 0 for a secret means its VALUE is present in local "
            "Grok session/log data; whether it reached xAI depends on whether "
            "that session's state/repo was uploaded (compare with sessions[]).",
            "Values were compared in memory only and are not stored anywhere.",
        ],
    }
    out_json = os.path.join(outdir, "audit_summary.json")
    with open(out_json, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    # human-readable one-screen digest
    up = summary["upload_summary"]
    print(json.dumps({
        "audit_summary": out_json,
        "uploaded": up["snapshots_enqueued"] > 0,
        "snapshots": up["snapshots_enqueued"],
        "megabytes": round(up["total_bytes"] / 1048576, 1),
        "repos_uploaded": up["repos_uploaded"],
        "remote_enabled": (parsed["consent"] or {}).get("trace_upload_source") == "remote",
        "secrets_leaked_ROTATE": [f"{s['key']} ({s['hits_in_grok']} hits)"
                                  for s in secret_findings
                                  if s["hits_in_grok"] and s["likely_secret"]],
        "other_env_values_present": [f"{s['key']} ({s['hits_in_grok']} hits)"
                                     for s in secret_findings
                                     if s["hits_in_grok"] and not s["likely_secret"]],
        "prefix_hits_needing_review": [h for h in prefixes if h["looks_real"]],
        "mitigation_config": install.get("mitigation_config"),
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
    except Exception as e:
        log(f"ERROR: {e}")
        raise
