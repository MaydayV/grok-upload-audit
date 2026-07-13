# Data deletion request template

Fill every `{{PLACEHOLDER}}` from `audit_summary.json`. Delete any section whose
finding didn't occur (e.g. drop the cross-tool section if no references were
found, drop the secrets paragraph if `secret_findings` is all zero). Keep the
evidence-backed tone — specific counts and session IDs, never vague accusation.
**Never insert a secret value; refer to leaked credentials by key name only.**

Placeholder sources:
- `{{EMAIL}}`, `{{USER_ID}}`, `{{TEAM_ID}}` → `identity`
- `{{AGENT_ID}}` → `install.agent_id`
- `{{VERSIONS}}` → `log_window.cli_versions_seen`
- `{{WINDOW_START}}`/`{{WINDOW_END}}` → `log_window.first_ts`/`last_ts`
- `{{SNAPSHOTS}}`, `{{BYTES}}`, `{{MB}}`, `{{FAILURES}}` → `upload_summary`
- `{{ENDPOINTS}}` → `upload_summary.endpoints_seen`
- `{{SESSION_TABLE}}` → one row per `sessions[]` entry
- `{{DECISION_COUNT}}` → `consent_evidence.decision_count`
- `{{LEAKED_KEYS}}` → `secret_findings` where `hits_in_grok>0` (key names only)
- `{{PREUNDER_REPOS}}` → repos in `cwds` whose sessions predate `WINDOW_START`

---

# Formal Data Deletion Request — Unauthorized Codebase Upload by Grok Build CLI

**Date:** {{DATE}}
**To:** xAI Privacy Team (privacy@x.ai), xAI Support
**From:** {{EMAIL}}

**Account identifiers:**

| Field | Value |
|---|---|
| xAI user_id | `{{USER_ID}}` |
| xAI team_id | `{{TEAM_ID}}` |
| Grok CLI agent_id | `{{AGENT_ID}}` |
| CLI versions involved | {{VERSIONS}} |

## 1. Summary

Between **{{WINDOW_START}} and {{WINDOW_END}} (UTC)**, the Grok Build CLI
installed on my machine uploaded snapshots of my private source-code
repositories — including proprietary code and files containing live credentials
— to xAI-controlled storage, without my informed consent. My local CLI logs
(`~/.grok/logs/unified.jsonl`, preserved and attached) establish the following.

1. **Activation without local consent.** Across {{DECISION_COUNT}}
   `trace.upload.decision` records, the upload was enabled with
   `trace_upload_source: "remote"` while every local consent input
   (`in_cfg_telemetry_trace_upload`, `in_env_trace_upload`, `in_requirement_pin`)
   was `null`. I never opted in; the switch was set server-side by xAI.
2. **Full-repository upload.** The CLI packaged my repositories into `tar.gz`
   archives and uploaded them through the storage proxy
   ({{ENDPOINTS}}). Upload-failure records identify the backend as Google Cloud
   Storage (`reason: "gcs_upload_failed"`); public wire-level analysis of the
   same CLI version identifies the destination bucket as
   `grok-code-session-traces`.
3. **Scale.** In the logged window alone, **{{SNAPSHOTS}} repository snapshots
   totaling {{BYTES}} bytes ({{MB}} MB compressed)** were enqueued and flushed
   (only {{FAILURES}} failures logged). Session-state archives — which contain
   the verbatim contents of `.env` files read during sessions — were uploaded
   through the same channel.

This contradicts xAI's public "local-first" positioning for Grok Build.

## 2. Inventory of uploaded data (from local logs)

### 2.1 Sessions and repositories

| Session ID | Repository | Snapshots | MB | First upload (UTC) |
|---|---|---|---|---|
{{SESSION_TABLE}}

The complete list of every uploaded object path
(`{session_id}/turn_{N}/{phase}.tar.gz`) is attached as
`evidence/gcs_objects.txt`. My local logs begin {{WINDOW_START}}; any sessions
predating that ({{PREUNDER_REPOS}}) cannot be reconstructed locally and must be
located by account ID and included in the deletion scope.

### 2.2 Sensitive content included

- Proprietary, unpublished source code and git history of the repositories above.
- **Live credentials.** Session traces contain the verbatim contents of `.env`
  files, including: {{LEAKED_KEYS}}. These credentials are being rotated; every
  copy xAI holds remains a breach liability until deleted.

### 2.3 Personal configuration of other tools *(include only if found)*

Session records show the CLI enumerated my Claude Code configuration
(`~/.claude/CLAUDE.md` and `~/.claude/skills/*` paths, referenced
{{CLAUDE_REF_COUNT}} times) and referenced private documents outside any
repository. Whether this material is contained in the uploaded `session_state`
archives cannot be verified locally and must be covered by the inventory in §3.

### 2.4 Consent state

My account shows `coding_data_retention_opt_out = {{OPT_OUT}}` — a default I was
never asked about. Combined with remote activation, this collection occurred
without informed consent.

## 3. Demands

Pursuant to applicable data-protection law — including, to the extent
applicable, GDPR Articles 15 and 17, and CCPA/CPRA §1798.105 and §1798.110 — and
xAI's own Privacy Policy, I demand that xAI:

1. **Permanently delete** all objects under the session-ID prefixes in §2.1 (see
   `evidence/gcs_objects.txt`) and **all other coding-session data associated
   with user_id `{{USER_ID}}`** — `codebase`, `session_state`, `plugins`, trace,
   and telemetry artifacts — from the `grok-code-session-traces` bucket and every
   replica, backup, cache, and downstream store.
2. **Confirm in writing** whether any of this data was used for model training,
   evaluation, or fine-tuning; if so, identify the affected datasets/models and
   the remediation applied.
3. **Provide a complete inventory** of all data collected from this account via
   Grok CLI, including sessions predating my local log coverage.
4. **Set `coding_data_retention_opt_out = true`** server-side immediately and
   disable the remote `trace_upload` flag for my account.
5. **Disclose the legal basis** for enabling full-repository upload by default
   via a remote flag without consent, and the retention period applied.
6. Provide **written confirmation of completed deletion within 30 days**,
   including the deletion date and scope.

Because the uploaded material contains live production credentials, please treat
item 1 with the urgency of a **security incident**.

## 4. Attached evidence

Extracts of `~/.grok/logs/unified.jsonl`; SHA-256 checksums in
`evidence/SHA256SUMS.txt`.

| File | Contents |
|---|---|
| `evidence/upload_enqueued.jsonl` | Every upload-enqueued record: timestamp, session, GCS object path, size |
| `evidence/upload_start.jsonl` | Every packaging-start record: repository, phase, turn |
| `evidence/trace_upload_decisions.jsonl` | Consent-decision records proving remote activation |
| `evidence/upload_failures.jsonl` | Failure records naming the storage endpoint and GCS backend |
| `evidence/gcs_objects.txt` | Complete list of uploaded object paths |
| `evidence/unified.jsonl.gz` | Full unmodified CLI log for the window |

I reserve all rights, including to lodge complaints with competent supervisory
and consumer-protection authorities.

Sincerely,
{{EMAIL}}
