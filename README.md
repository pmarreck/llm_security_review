# llm_security_review

A pattern and a tool for running per-file security reviews against a source
tree by shelling out to a local LLM CLI (Claude Code, Codex, Gemini).

The pattern is simple: each source file is sent to the LLM with a prompt that
encodes a senior application-security engineer's review methodology — an
inventory of sinks first, then a per-sink trace / boundary / validate /
impact pass, with an OWASP Top 10 sweep at the end. Findings get spliced into
a master Markdown doc, one section per file, with HTML-comment markers
carrying the review timestamp and the source file's mtime so reruns only
re-review files that have changed since.

This repo contains two things:

- `elixir_reviewer.ex` — the original Elixir module that this pattern grew
  from. Useful as a reference if you want to embed the same prompts inside a
  larger Elixir/BEAM agent pipeline.
- `secreview` — a single-file Bash script that orchestrates the same idea
  from the shell. Walks a path, filters by extension, picks the right prompt
  variant per language, shells out to claude / codex / gemini, and manages
  the master findings doc.

## Supported languages

Currently:

| Extension | Prompt variant | Focus |
|-----------|----------------|-------|
| `.ex`, `.exs` | Elixir / Erlang | BEAM sinks: `binary_to_term`, dynamic dispatch, ETS, NIF FFI, metaprogramming gadgets, etc. |
| `.zig` | Zig | Memory + error discipline, integer / UB / casting, `@enumFromInt` / `@ptrCast` on untrusted input, FFI boundary, `catch unreachable`, comptime sinks, etc. |
| anything else | Generic, OWASP-aware | Language-agnostic sinks tagged with OWASP Top 10 categories. Placeholder for richer per-language prompts (JS, Python, Go, Rust, …). |

Each variant carries its own sink-class inventory and "always-flag" list
(things dangerous enough on sight that no trace/boundary check is needed —
e.g. `:erlang.binary_to_term/1` without `:safe`, `catch unreachable` on
attacker-supplied input, `eval`/`exec` of computed strings).

**Adding a new language** is mostly a matter of writing two more heredocs in
`secreview` (sink classes + always-flag list) and adding one branch to
`language_for()`. The shared methodology / output sections are reused.

## Quick start

```bash
# Detect a CLI on PATH (claude > codex > gemini); review every .zig/.ex/.exs
# file under ./src into SECURITY_FINDINGS.md.
./secreview ./src

# Preview what would be reviewed (post-filter, one path per line on stdout):
./secreview --list ./src

# Cap the run; useful for dipping a toe in or budgeting credits:
./secreview --max-files 5 ./src

# Skip insubstantial files (default: <10 non-blank lines):
./secreview --min-loc 30 ./src

# Override CLI selection:
SECREVIEW_LLM_CLI=codex ./secreview ./src
# or: ./secreview --cli codex ./src

# Strip "No findings" / ruled-out-only sections for a clean deliverable:
./secreview --extract-actionable --actionable-out review.md
```

Run `./secreview --help` for the full flag list.

## How resume works

Each reviewed file gets a section in the findings doc bounded by:

```html
<!-- secreview:begin file="REL/PATH" reviewed_at="ISO8601" file_mtime="ISO8601" -->
## REL/PATH

_Reviewed … · file mtime at review … · CLI claude · style deep_

…findings…

<!-- secreview:end file="REL/PATH" -->
```

On rerun:

- File has no entry → review it.
- Source mtime > recorded → re-review (replace section).
- Source mtime == recorded → skip (override with `--force`).

Large trees are resumable: kill the run, restart, and only the unreviewed
and modified files are re-processed.

## Defaults

| Flag | Default |
|------|---------|
| `--out` | `SECURITY_FINDINGS.md` |
| `--style` | `deep` (the full inventory + per-sink methodology). `--style simple` skims with the sink list in mind. |
| `--ext` | `zig,ex,exs` |
| `--min-loc` | `10` non-blank lines |
| `--max-files` | `0` (no cap) |
| Default excluded dirs | `.git`, `.jj`, `.hg`, `.svn`, `.claude`, `.serena`, `.codescan`, `.cursor`, `.idea`, `.vscode`, `.worktrees`, `.zig-cache`, `zig-out`, `_build`, `.elixir_ls`, `.lexical`, `node_modules`, `dist`, `target`, `vendor`, `deps`, `__pycache__`, `.pytest_cache`, `.tox`, `.next`, `.nuxt`, `cover`, `coverage`. Disable with `--no-default-excludes`; add more with `--exclude NAME` (repeatable). |

## CLI invocation details

`secreview` shells out, capturing the LLM's stdout response and splicing it
into the findings doc. Per CLI:

- **claude** — `claude -p` reading the prompt from stdin (Claude Code's
  non-interactive "print" mode).
- **codex** — `codex exec --skip-git-repo-check --ephemeral --color never
  -o <tmpfile> -` reading the prompt from stdin. `-o` writes only the
  agent's final message to a tempfile so the captured output isn't polluted
  by status events.
- **gemini** — `gemini -p -` (best-guess; verify the exact flags for your
  install).

The selected CLI is reported in the startup banner and recorded in each
section's header line.

## License

MIT — see [LICENSE](LICENSE).
