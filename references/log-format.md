# Grok `~/.grok` layout & log format reference

Read this when you need to interpret `audit_summary.json` precisely, verify a
finding by hand, or the log schema looks different from what the script expected
(Grok updates may rename fields). Everything here is observed from real
installs; treat field names as *likely* not guaranteed, and degrade gracefully.

## Directory layout (`~/.grok`)

| Path | What it holds | Audit relevance |
|---|---|---|
| `logs/unified.jsonl` | Append-only JSONL event log | **Primary evidence.** Upload records live here. |
| `auth.json` | OAuth tokens + account identity | Identity (user_id/email/team_id) for the letter; **contains live tokens — never dump values.** |
| `agent_id` | Stable install UUID | Identifier for the deletion request. |
| `config.toml` | User config | Where the upload-block goes; read to report current mitigation state. |
| `version.json` | Installed version | Correlate with known-affected versions. |
| `sessions/<url-encoded-cwd>/<sid>/` | Per-session chat history, updates, terminal logs | Dir names are `%2F`-encoded working directories → the full list of every folder Grok ran in. Session files may contain secret values pulled into context. |
| `projects/` | Per-project metadata | Secondary. |
| `upload_queue/` | Pending upload spool | Empty usually means uploads already flushed (sent), not that nothing happened. |

## `unified.jsonl` record shape

Each line: `{"ts","src","pid","ver","lvl","sid","msg","ctx":{...}}`.
`sid` = session id, `msg` = event type, `ctx` = event payload. The audit keys
off `msg`.

### Upload evidence events

- **`repo_state.upload.start`** — a packaging pass began.
  `ctx`: `phase` (`before_codebase`/`after_codebase`/`before_session_state`/…),
  `turn_number`, `repo_path`, `max_file_bytes`. Presence proves Grok *attempted*
  to package that `repo_path`.
- **`repo_state.upload.enqueued`** — an artifact was built and queued for
  upload. `ctx`: `turn_number`, `size_bytes`, `gcs_path`
  (`<sid>/turn_<n>/<phase>_<artifact>.tar.gz`), `blobs`. This is the strongest
  "it was uploaded" signal — enqueued artifacts are flushed to the storage
  proxy. Sum `size_bytes` for total volume; `gcs_path` values are the exact
  objects to demand deleted.
- **`upload failed: <artifact> (<reason>)`** — `ctx` includes the failing
  `method` (`proxy`) and an `error` string that often contains the endpoint
  (`https://cli-chat-proxy.grok.com/v1`) and confirms the GCS backend
  (`reason:"gcs_upload_failed"`).

**Artifact types** seen in `gcs_path` / errors: `codebase` (repo tarball),
`session_state` (conversation state — this is where `.env` contents read during
the session end up), `plugins` (plugin manifest). The script tallies these in
`upload_summary.artifact_types`.

### Consent events — the crux

- **`trace.upload.decision`** — logged each time Grok decides whether to upload.
  `ctx` fields the audit captures:
  - `trace_upload` (bool) — was uploading on?
  - `trace_upload_source` — `"remote"` means xAI's server flag decided it;
    `"config"`/`"env"` would mean the user did.
  - `in_cfg_telemetry_trace_upload`, `in_env_trace_upload`,
    `in_requirement_pin`, `in_cfg_features_telemetry` — the *local* inputs. All
    `null` + `trace_upload:true` + `source:"remote"` = **uploaded with no local
    opt-in**, the central finding.
  - `in_remote_trace_upload_enabled` — the remote switch state.

The script stores the first such record's fields in
`consent_evidence.first_decision_fields` and the total count in
`decision_count`.

## Reading `audit_summary.json`

- `upload_summary.repos_uploaded` — repos with ≥1 enqueued artifact. **Confirmed
  uploaded.**
- `upload_summary.repos_attempted_only` — start events but nothing enqueued
  (e.g. upload disabled/failed for that repo). Report as *attempted*.
- `upload_summary.cwds_without_upload_evidence` — Grok ran there but no upload
  events at all (often the home dir, or non-git folders). Report as *touched, no
  upload evidence*. Uploads appear tied to git repos.
- `sessions[]` — per session: `session_id`, `repos`, `snapshots`, `bytes`,
  `first_ts`/`last_ts`. This is the table for the deletion letter.
- `secret_findings[]` — per candidate secret: `source_file`, `key`, `value_len`,
  `hits_in_grok`, `hit_files_sample`. **No values.** `hits_in_grok>0` = the
  value exists somewhere in local Grok data. To decide if it reached xAI, check
  whether the sessions containing it (`hit_files_sample` dir names decode to
  cwds) are in `repos_uploaded`.
- `crosstool_path_refs` — counts of `~/.claude`, `claude_md`, `~/.codex`,
  `codex_auth`, `credentials_json` path strings in session files. High
  `claude_md`/`claude_dir_abs` with zero `codex_auth` value hits = "it enumerated
  my Claude config but did not read my Codex credentials."
- `prefix_scan[]` — credential-shaped strings found anywhere in `~/.grok`.
  `in_vendor_docs:true` = inside Grok's own shipped docs/marketplace cache
  (placeholders, ignore). `looks_real:true` = long enough to be a real token and
  not in vendor docs — **investigate these**.

## Verifying by hand (spot checks)

The script is the source of truth, but to confirm a specific claim:

```bash
# repos with confirmed uploads + their snapshot counts
grep '"repo_state.upload.enqueued"' ~/.grok/logs/unified.jsonl | wc -l
grep -oE '"repo_path":"[^"]*"' ~/.grok/logs/unified.jsonl | sort | uniq -c

# consent source (should show "remote" in affected versions)
grep '"trace.upload.decision"' ~/.grok/logs/unified.jsonl | head -1
```

To check a secret leaked **without exposing it**, compare by count only:
```bash
val=$(grep -m1 '^KEYNAME=' /path/.env | cut -d= -f2-)   # value stays in shell var
[ ${#val} -ge 12 ] && grep -rcF -- "$val" ~/.grok/ | awk -F: '{n+=$NF} END{print n}'
```
Never echo `$val`. Skip values shorter than ~12 chars: empty/short values
substring-match everything and produce false positives (a real pitfall — an
empty `OPENAI_API_KEY=` will appear to "match" thousands of lines).
