# grok-upload-audit

A [Claude Code](https://claude.com/claude-code) skill that forensically audits
what the **xAI Grok Build CLI** uploaded from your machine — and helps you do
something about it.

Grok Build stores everything it does under `~/.grok`. In affected versions it
packages your working repository into `tar.gz` archives and uploads them — along
with session state and plugin manifests — to an xAI Google Cloud Storage bucket
via `https://cli-chat-proxy.grok.com/v1/storage`. The upload switch can be turned
on **remotely by xAI with no local opt-in**, and files the agent reads
(including `.env`) are sent verbatim. This behavior contradicts Grok Build's
public "local-first" positioning.

The good news: `~/.grok` keeps the receipts. This skill reads them and turns them
into a clear answer to the question every affected user is asking — *did my code
get uploaded, and were any live secrets in it?* — plus a tamper-evident evidence
package and a ready-to-send data-deletion request.

> **Background:** [What xAI Grok Build CLI actually sends to xAI — a wire-level analysis](https://gist.github.com/cereblab/dc9a40bc26120f4540e4e09b75ffb547)
> · [Hacker News discussion](https://news.ycombinator.com/item?id=48877371)

---

## What it does

Given a machine with Grok Build installed, the skill:

1. **Parses `~/.grok/logs/unified.jsonl`** to reconstruct every upload event —
   which repositories were packaged, how many snapshots, total bytes, the exact
   GCS object paths, and the storage endpoints hit.
2. **Proves (or disproves) consent** by reading the `trace.upload.decision`
   records. If the upload was enabled with `trace_upload_source: "remote"` while
   every local opt-in field is `null`, that's the smoking gun: xAI turned it on
   server-side.
3. **Checks for secret leakage** by matching the *values* of your `.env` files
   (and other AI tools' credential files) against local Grok data — reporting
   only **key names and hit counts, never the values themselves**.
4. **Classifies the blast radius** into three honest tiers: repositories
   *confirmed uploaded*, *attempted only*, and *touched but with no upload
   evidence* (e.g. your home directory or non-git folders).
5. **Writes an evidence package** — extracted log records with SHA-256
   checksums — suitable for attaching to a complaint.
6. **Generates a data-deletion request letter** (GDPR Art. 15/17, CCPA/CPRA
   §1798.105/.110) pre-filled with your account IDs, the per-session upload
   table, and the consent finding.
7. **Blocks further uploads** by adding the known mitigation config to
   `~/.grok/config.toml` — only after you've seen the findings.

## Safety by design

Auditing a data-exfiltration problem must not itself exfiltrate data. This skill
is built around that principle:

- **Secret values never leave the process.** They are compared in memory only and
  are never printed to the transcript, written to any output file, or sent
  anywhere. Findings identify a leaked credential by its key name and a hit
  count — e.g. `DATABASE_URL (27 hits)` — so you learn *what* leaked without
  re-exposing it.
- **Read-only until you decide.** All investigation is read-only; nothing under
  `~/.grok` is modified unless you explicitly opt to apply the upload block.
- **No overclaiming.** "Present in local session data" is reported distinctly
  from "confirmed uploaded to xAI," and every finding is bounded by the log's
  time coverage. A precise, defensible result is the goal — not a dramatic one.
- **Home-directory guard.** The scanner refuses to treat `$HOME` as a repository,
  so it won't sweep your entire home folder.

## Requirements

- [Claude Code](https://claude.com/claude-code) (the skill triggers within it).
- Python 3.8+ (standard library only — no third-party packages).
- macOS or Linux. Grok Build installed at `~/.grok` (or pass `--grok-dir`).

## Installation

Clone directly into your Claude Code skills directory:

```bash
git clone https://github.com/MaydayV/grok-upload-audit \
  ~/.claude/skills/grok-upload-audit
```

Claude Code discovers it automatically. That's it.

To update later: `git -C ~/.claude/skills/grok-upload-audit pull`.

## Usage

### Via Claude Code (recommended)

Just describe the concern in plain language and the skill triggers:

- *"Did Grok upload my code to xAI? Check my machine."*
- *"There's news that Grok CLI uploads project code — audit mine and draft a deletion request."*
- *"Did Grok leak any of my API keys?"*

Claude runs the audit, explains the findings, and — if you want — writes the
deletion letter and applies the upload block, walking you through each step.

### Standalone (just the report)

You can also run the auditor directly, without Claude:

```bash
python3 ~/.claude/skills/grok-upload-audit/scripts/grok_audit.py
```

Options:

| Flag | Purpose |
|------|---------|
| `--grok-dir PATH` | Audit a non-default Grok location (default `~/.grok`). |
| `--output-dir PATH` | Where to write the report/evidence (default `~/Documents/grok-upload-audit-<timestamp>/`). |
| `--no-log-copy` | Skip gzipping the full raw log into the evidence package. |

It prints a JSON digest to stdout and writes the full findings to
`audit_summary.json`. Exit code `1` means Grok isn't installed.

## What you get

```
grok-upload-audit-<timestamp>/
├── audit_summary.json                 # machine-readable findings (source of truth)
├── xAI-Data-Deletion-Request.md       # pre-filled deletion letter (when generated)
└── evidence/
    ├── upload_enqueued.jsonl          # every upload: timestamp, session, GCS path, size
    ├── upload_start.jsonl             # every packaging pass: repo, phase, turn
    ├── trace_upload_decisions.jsonl   # consent records proving remote activation
    ├── upload_failures.jsonl          # failures naming the storage endpoint + GCS backend
    ├── gcs_objects.txt                # complete list of uploaded object paths
    ├── unified.jsonl.gz               # full unmodified raw log for the window
    └── SHA256SUMS.txt                 # checksums for evidence integrity
```

The digest at a glance:

```json
{
  "uploaded": true,
  "snapshots": 197,
  "megabytes": 33.4,
  "repos_uploaded": ["~/Dev/project-a", "~/Dev/project-b"],
  "remote_enabled": true,
  "secrets_leaked_ROTATE": ["DATABASE_URL (27 hits)", "JWT_SECRET (9 hits)"],
  "other_env_values_present": ["API_BASE_URL (140 hits)"],
  "prefix_hits_needing_review": []
}
```

## How it works

Everything lives in `scripts/grok_audit.py` (single file, standard library only).
It streams the append-only `unified.jsonl` event log and keys off the message
types Grok writes:

- `repo_state.upload.start` — a packaging pass began (proves *attempt*).
- `repo_state.upload.enqueued` — an artifact was built and queued (proves
  *upload*; carries the GCS path and byte size).
- `trace.upload.decision` — the consent decision, including whether the switch
  was `local` or `remote`.
- `upload failed: …` — failures whose error text confirms the storage proxy
  endpoint and the GCS backend.

Secret detection classifies `.env` keys by name (a value tied to a key like
`*_SECRET`, `*_TOKEN`, `*_KEY`, `*_DSN`, `PASSWORD` is treated as a credential;
a base URL or mode flag is treated as config) and confirms leakage by matching
the value — reported by count only. A credential-prefix scan (`sk-ant-`, `ghp_`,
`AKIA`, …) flags anything credential-shaped anywhere in `~/.grok`, while marking
placeholders inside Grok's own bundled docs so they don't raise false alarms.

For the full log schema and field-by-field meaning, see
[`references/log-format.md`](references/log-format.md). The deletion-letter
structure and placeholder mapping is in
[`references/deletion-letter-template.md`](references/deletion-letter-template.md).

## Limitations

- **Local evidence only.** The audit reflects what your machine recorded. It can
  prove an upload happened and name the objects; it cannot see xAI's servers. Any
  sessions predating your log's coverage window can't be reconstructed locally —
  the deletion letter folds those in by account ID instead.
- **Mitigation is best-effort.** Local config is understood to take precedence
  over xAI's remote switch, but that isn't a guarantee from xAI, and
  `auto_update = true` means a future update could change behavior. Re-run the
  audit after upgrades. Uninstalling Grok is the only complete stop.
- **Field names may drift.** Grok updates can rename log fields; the script
  degrades gracefully and the reference doc explains how to verify by hand.

## Disclaimer

This tool is provided for personal data-protection and security-hygiene
purposes. It reads only your own local files and makes no network connections.
The generated letter is a template, not legal advice — consult a qualified
professional for your jurisdiction. Not affiliated with, endorsed by, or
associated with xAI.

## License

[MIT](LICENSE)
