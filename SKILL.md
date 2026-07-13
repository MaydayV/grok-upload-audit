---
name: grok-upload-audit
description: >-
  Forensically audit what the Grok Build CLI (xAI, ~/.grok) has uploaded from a
  user's machine, check whether local secrets or other AI tools' credentials
  leaked into uploaded artifacts, block further uploads, and generate an
  evidence package plus a ready-to-send privacy deletion request letter. Use
  this whenever a user is worried that Grok / Grok Build / Grok CLI has uploaded
  their source code, repositories, .env secrets, API keys, or Claude/Codex
  config to xAI — including phrasings like "did Grok upload my code", "is Grok
  sending my repo to xAI", "Grok data exfiltration", "Grok stole my keys",
  "check if my code leaked to xAI", or reactions to news/tweets about Grok
  uploading project code. Also use to produce a GDPR/CCPA data-deletion request
  against xAI for coding-session data. Trigger even if the user only names the
  symptom (leaked keys, uploaded repo) without saying "audit".
---

# Grok Build CLI Upload Audit

## What this does and why

The Grok Build CLI (xAI) stores everything under `~/.grok`. In affected
versions it packages the working repository into `tar.gz` archives and uploads
them — plus session state and plugin manifests — to an xAI Google Cloud Storage
bucket via `https://cli-chat-proxy.grok.com/v1/storage`, and the upload switch
can be flipped on **remotely by xAI** with no local opt-in. Files the agent
reads (including `.env`) are sent verbatim.

The user's fear is concrete and answerable, because `~/.grok` keeps the
receipts: `logs/unified.jsonl` records every `repo_state.upload.start`,
`repo_state.upload.enqueued` (with GCS object path + byte size), and
`trace.upload.decision` (showing whether the switch was local or remote). Your
job is to turn those receipts into a clear, evidence-backed answer and, if the
user wants it, a deletion demand.

**Golden rule — never exfiltrate while investigating an exfiltration.** Secret
*values* must never be printed to the transcript, written into any report, or
sent anywhere. You verify a secret leaked by matching its value and reporting a
**count and its key name** — never the value. The bundled script enforces this;
keep the same discipline in anything you do by hand.

## Workflow

Run these in order. Steps 1–2 are read-only investigation; do them before
suggesting any change. Do not modify `~/.grok` until Step 4, and only with the
user's understanding.

### Step 1 — Run the audit script

```bash
python3 <skill-dir>/scripts/grok_audit.py
```

It reads `~/.grok` read-only, writes an evidence package to
`~/Documents/grok-upload-audit-<timestamp>/`, and prints a JSON digest plus the
path to a full `audit_summary.json`. Read `audit_summary.json` — it is the
source of truth for everything below. Key sections: `install` (version,
mitigation config already present), `consent_evidence`, `upload_summary`
(snapshots, bytes, `repos_uploaded`, `repos_attempted_only`,
`cwds_without_upload_evidence`), `sessions[]`, `secret_findings`,
`crosstool_path_refs`, `prefix_scan`.

Useful flags: `--grok-dir PATH` (non-default location), `--output-dir PATH`,
`--no-log-copy` (skip gzipping the full raw log if disk/size is a concern).

If `installed:false` comes back, Grok isn't on this machine — tell the user
there's nothing to audit and stop.

For the detailed meaning of every field, artifact type, and how to read the
consent flags, see `references/log-format.md`.

### Step 2 — Interpret and report to the user

Lead with the verdict a worried user actually wants: **was code uploaded, yes or
no, and were any live secrets in it.** Then support it. Cover:

- **Upload scope.** Snapshot count, total MB, and the exact `repos_uploaded`.
  Distinguish three tiers the script separates: confirmed uploaded, *attempted
  only* (`repos_attempted_only` — start events but nothing enqueued), and
  *touched but no upload evidence* (`cwds_without_upload_evidence`, e.g. the
  home directory or non-git folders). This precision is what makes the report
  credible.
- **Consent.** If `consent_evidence.first_decision_fields.trace_upload_source`
  is `"remote"` while the `in_cfg_*` / `in_env_*` inputs are `null`, state
  plainly that xAI enabled the upload remotely with no local opt-in. That is the
  crux of the story.
- **Secret leakage.** For each entry in `secret_findings` with `hits_in_grok >
  0`, name the key (e.g. `DATABASE_URL`) and where it was found, and cross-
  reference `sessions[]` to say whether that session's data was actually
  uploaded. Treat any real secret with hits as **compromised → must rotate**.
  Report `value_len` and hit counts, never values.
- **Cross-tool credentials.** Report `crosstool_path_refs` (how often
  `~/.claude`, `CLAUDE.md`, `~/.codex` paths appear in sessions) and any
  `secret_findings` sourced from `~/.codex/auth.json` etc. Enumerating a config
  directory (paths appearing) is different from stealing a credential (a token
  *value* getting hits) — say which one you actually found. Absence of value
  hits is the reassuring, defensible finding.
- **Prefix scan caveat.** `prefix_scan` flags credential-shaped strings
  (`sk-ant-`, `ghp_`, …) anywhere in `~/.grok`. Most are placeholders in Grok's
  own bundled docs — the script marks these `in_vendor_docs:true`,
  `looks_real:false`. Only surface `looks_real:true` hits as real concerns;
  mention the rest only to show you checked.
- **Log coverage limit.** Findings are bounded by `log_window.first_ts`.
  Sessions before the log starts can't be confirmed or denied locally — say so,
  and fold them into the deletion request by account ID rather than pretending
  certainty.

Write it as prose a non-expert can act on, secrets-to-rotate first. This is
usually the deliverable — don't jump to writing files or changing config unless
the user wants the letter (Step 3) or the block (Step 4).

### Step 3 — Generate the deletion request (when the user wants it)

Use `references/deletion-letter-template.md`. Fill every `{{PLACEHOLDER}}` from
`audit_summary.json` — account IDs from `identity`, the session/upload table
from `sessions[]`, byte totals, endpoints, the remote-consent finding, and the
cross-tool section only if you actually found references. Write it next to the
evidence package (same output dir) as `xAI-Data-Deletion-Request.md`. Keep the
evidence-backed tone: specific object counts and session IDs, not vague outrage.
Never put a secret value in the letter — refer to leaked credentials by key name
and state they are being rotated.

### Step 4 — Offer to block further uploads

Only after the user has seen the findings. Show them the additions first, then
edit `~/.grok/config.toml` (preserve existing content; append):

```toml
[harness]
disable_codebase_upload = true

[telemetry]
trace_upload = false

[features]
telemetry = false
```

Explain the caveats honestly: local config is understood to take precedence over
the remote switch, but this isn't a guarantee from xAI; and if
`install.mitigation_config.auto_update` is true, an update could change behavior,
so the block is worth re-checking after upgrades. Uninstalling Grok is the only
complete stop — offer that framing, let the user choose.

### Step 5 — Wrap up

Give the user the checklist that still needs their hands: rotate the specific
compromised keys (name them), send the letter to `privacy@x.ai`, and turn on
`coding_data_retention_opt_out` in their account if `identity` shows it false.
Point them at the evidence directory. If a memory system is available, this is
worth recording as a project fact (incident date, what was blocked, what's still
pending).

## Guardrails

- **Read-only until Step 4.** Investigation must not alter `~/.grok`.
- **Never reveal secret values** anywhere — transcript, files, or network.
- **Don't overclaim.** "Present in local session data" ≠ "confirmed received by
  xAI." Tie every leakage claim to whether that session actually uploaded, and
  respect the log-coverage window. A precise, bounded finding is more useful to
  the user than a dramatic one.
- **Home-directory safety.** The script refuses to sweep `$HOME` as a repo; keep
  that boundary if you investigate by hand.
