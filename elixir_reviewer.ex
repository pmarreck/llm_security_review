defmodule MyApp.Prompts.Audit do
  @moduledoc """
  Prompts for the audit pipeline. Two entry points:

    * `audit_file/4` — embeds a single source file in the prompt and
      runs `MyApp.CodingAgent` against it. Style is `:simple` or
      `:deep`; the executor picks based on `audit.strategy`.
    * `audit_directory/2` — whole-package audit. Spawns the agent with
      `:cwd` set to the source dir so it can use Read/Grep/Bash.
  """

  alias MyApp.CodingAgent

  @per_file_timeout to_timeout(minute: 10)
  @whole_timeout to_timeout(hour: 1)
  @default_effort "max"

  @sink_classes """
  Sink classes — every place dangerous logic could live, regardless of whether
  the input currently looks hostile. Enumerate first, judge second.

    * Code execution — eval, dynamic dispatch on a computed name (`apply`,
      `Code.eval_*`, `:erlang.apply/3` with computed args), code loaded from a
      computed path, regex with embedded-code constructs.
    * Command execution — `System.cmd`, `:os.cmd`, `Port.open({:spawn, …})`,
      shelling out where args are built by concatenation rather than passed as
      a list.
    * File operations — `File.read/write/rm/cp/ln/chmod` where the path is
      computed; `Code.require_file` / `Code.eval_file` with dynamic paths.
    * Path handling — `Path.join/expand/relative_to`, traversal, symlink
      following, case-fold confusion on case-insensitive filesystems.
    * Archive extraction — `:erl_tar`, `:zip`, any unpack where entry names
      become filesystem paths (zip-slip).
    * Deserialisation — `:erlang.binary_to_term/1` (no `:safe`),
      `Plug.Crypto.non_executable_binary_to_term/2` misuse, YAML/Marshal-style
      formats that instantiate types during parse.
    * Template / interpolation — values reaching another interpreted context
      without escaping for it: HTML, SQL via raw fragments, EEx/Phoenix
      `raw/1`, shell, regex, format strings, log lines.
    * Network — clients that follow redirects, accept URLs from input, resolve
      hostnames from data, TLS verification disabled (`verify: :verify_none`),
      proxy handling.
    * Validation — predicates whose contract is "this is safe": the sink is
      the return value, the danger is returning the wrong answer.
    * Cryptography — KDF parameters, IV reuse, mode/padding, MAC verification,
      `==` on secrets instead of `Plug.Crypto.secure_compare/2`.
    * Memory safety — Rust `unsafe`, raw pointers, unchecked indexing, FFI,
      transmute. For NIFs: lifetime/aliasing across the BEAM boundary.
    * Shared mutable state — `Application.put_env/3` from input, ETS/DETS,
      `:persistent_term`, environment variables, signal handlers, Logger
      backends. One input poisoning what another sees.
    * Concurrency — check-then-act sequences a racer can interleave: file
      existence before open, permission before access, GenServer state read
      then written without serialisation.
    * Resource consumption — atom leaks (`String.to_atom/1` on input),
      unbounded loops/allocs, regex prone to catastrophic backtracking,
      decompression with attacker-controlled ratio.
    * Reflection / metaprogramming gadgets the library installs into the
      caller — `__using__` macros, `@before_compile`, telemetry handler
      attaches, Logger backends, monkeypatched callbacks. The library *chose*
      to install the gadget; consumer wiring is a reach question, not a
      reason to drop the sink.
    * Round-trip integrity — pairs meant to be inverses: `encode`/`decode`,
      `parse`/`serialize`, `marshal`/`unmarshal`. The sink is the pair. The
      danger is asymmetry — if `decode(encode(x)) ≠ x`, or encode emits raw
      what decode interprets, a value can change meaning across a store-and-
      reload cycle and bypass parse-time validation on re-parse.
  """

  @per_file_deep_methodology """
  ## Methodology

  Two phases. Don't skip phase 1 — skipping it is what makes audits miss bugs.

  Phase 1 — inventory. List every sink in this file using the sink classes
  below. Don't judge any of them yet — a sink is dangerous-if-input-is-hostile,
  regardless of whether you currently think the input is hostile. Grep
  exhaustively for the language's primitives in each class.

  Phase 2 — for each sink in your inventory, in order:

    1. Trace — where does the value come from? If it's a hardcoded constant
       or internal data only, write "internal" and stop.
    2. Boundary — does it originate from a function parameter exposed
       publicly, or some other source crossing a trust boundary? The
       library's caller is *not* the attacker — but data the caller
       forwards from the network, from disk, or from deserialisation is.
    3. Validate — sketch a one-paragraph reproduction (input → effect).
       If a guard in the file rules it out, name the guard and stop.
    4. Impact - what is the real-world impact? What can an attacker that
       exploits this actually do? Explain this in simple terms and plain language.
    4. Rate — Critical / High / Medium / Low.

  Every sink ends up either as a finding or in `## Ruled out` with the
  step that disqualified it.
  """

  @whole_methodology """
  ## Methodology

  Two phases. Phase 1 is an inventory — write it down before judging anything.
  Two runs against the same source should produce the same inventory.

  ### Phase 1: Boundaries + inventory

  Before listing sinks, name the trust boundaries. For a small library this
  is one or two lines: who calls it, what they pass, where external data
  enters. Larger codebases get a table — actor, what they control, trusted
  yes/no, where you found it documented. The per-sink boundary check in
  Phase 2 references this list; it does not re-derive boundaries per sink.

  Then enumerate every sink. For each: file, line, sink class, what it
  consumes. Don't judge any of them yet — a sink is dangerous-if-input-is-
  hostile, regardless of whether you currently think the input is hostile.
  Grep exhaustively for the language's primitives in each class.

  ### Phase 2: Per-sink — six steps in order

  Stop when a step rules the sink out and record which step did. Every
  inventory sink ends up either in `findings` or in `ruled_out`.

    1. Trace — backwards from sink to a boundary. Name each hop. If the
       value never crosses a boundary, write "internal" and stop.
    2. Boundary — which boundary from Phase 1 does it cross? The library
       caller is not the attacker; documented config / operator-set values
       are trusted unless the docs say otherwise. Cite the doc. Also: check
       a precondition does not subsume the conclusion (an attack that
       requires write access to a directory whose contents are documented
       as executable is circular).
    3. Validate — write a reproduction script. For Elixir, a short `.exs`
       under `scripts/{package_name}/{short_description}.exs` runnable via
       `Mix.install` is ideal. DO NOT execute it; the human will. Paste the
       script in the `validation` field. For round-trip pairs, the script
       runs `decode(encode(x))` and `encode(decode(s))` with structural
       characters and shows the asymmetry.
    4. Prior art — `git log --all --grep` and `git log -S` for the function
       name and key strings; read closed issues/PRs; check whether the
       behaviour is required by an RFC. If a maintainer already declined,
       quote the comment.
    5. Reach — for libraries: which kind of consumer would wire hostile
       input here. You don't have dependents data; reason about plausible
       call patterns. "No plausible exposed caller" is data, not a verdict.
    6. Rate — severity + confidence. Critical = works on a fresh install,
       no preconditions. High = realistic preconditions a normal deployment
       satisfies. Medium = significant attacker positioning, unusual config,
       or a chain. Low = unrealistic preconditions or narrow impact.
  """

  @per_file_deep_output """
  ## Output

  Use plain, easy-to-understand, and concise language. Focus on the real-world
  impact of the findings.

  If the file has no sinks at all (truly nothing dangerous-looking to even
  consider), output exactly:

      No findings.

  Otherwise, for each finding output one block in this format:

      ### <Short title>
      **Severity:** Critical | High | Medium | Low
      **Location:** <relative/path>:<line> | <relative/path>:<line_start>-<line_end>
      **Class:** <sink class>

      **Trace:** <one short paragraph backwards from sink to where the
      value enters this file>

      **Boundary:** <which trust boundary the input crosses, or "internal">

      **Impact:** <a short paragraph on the impact of the finding>

      **Validation:** <one short paragraph reproduction sketch — input that
      would trigger the sink and what dangerous behaviour follows. If a
      guard in the file blocks it, name the guard.>

      **Suggested fix:** <one or two sentences>

  Then, if any sinks were considered and dropped, append:

      ## Ruled out

      - `<file>:<line>` (<sink class>, step N) — <one-sentence reason>

  Listing ruled-out sinks is required when phase 1 found any — it's how the
  audit demonstrates it considered them. No preamble, no overall summary.
  """

  @whole_output """
  ## Output

  Always output the full report — boundaries and inventory must be present
  even when nothing rises to a finding. Format:

      ## Trust boundaries

      | Actor | Trusted | Controls | Source |
      |-------|---------|----------|--------|
      | <name> | yes/no/conditional | <what they control> | <doc citation> |

      ## Inventory

      | ID | Location | Class | Consumes |
      |----|----------|-------|----------|
      | S1 | <rel/path>:<line> or <rel/path>:<line_start>-<line_end> | <sink class> | <what it consumes> |

      ## Findings

      ### F1 — <short title>
      **Severity:** Critical | High | Medium | Low
      **CWE:** CWE-NNN
      **Location:** <rel/path>:<line> | <rel/path>:<line_start>-<line_end>
      **Sinks:** S1[, S2…]

      **Trace:** <markdown>

      **Boundary:** <markdown>

      **Validation:** <markdown — include the reproduction script verbatim
      under a fenced code block. Do NOT execute it; the human will.>

      **Prior art:** <markdown — git log / issues / RFC citations>

      **Reach:** <markdown — plausible exposed callers>

      **Rating:** <markdown — severity + confidence rationale>

      **Suggested fix:** <one or two sentences>

      ## Ruled out

      - **S2, S3** (step N) — <one or two sentences>

  Use `## Findings\\n\\n_None._` for a clean report — never omit the section.
  Every inventory sink ID must appear in either `Findings → Sinks:` or in
  the `Ruled out` list. No preamble, no overall summary, no closing notes.
  """

  @always_flag """
  ## Always-flag

  Some sinks are dangerous enough on sight that the trace/boundary check is
  skipped — flag every occurrence as a finding even if you can't trace where
  the input comes from.

    * **`:erlang.binary_to_term/1`, or `:erlang.binary_to_term/2` without
      `:safe` in the options list.** Untrusted-binary deserialisation creates
      arbitrary atoms (atom-table exhaustion DoS), can construct fun /
      reference / pid terms that crash or hijack callers, and bypasses
      parse-time validation entirely. The safe alternatives are
      `:erlang.binary_to_term(bin, [:safe])` and
      `Plug.Crypto.non_executable_binary_to_term/2`. Severity: **Critical**.
      Report once per call site. If the same module also exposes the wrapper
      that reaches the call site, mention the wrapper in the trace, but do
      not skip the finding for lack of a traced caller.

    * **`:erlang.binary_to_term/2` with `:safe`.** `:safe` blocks new atoms
      and funs, but the decoded term is still attacker-shaped: deeply nested
      structures cause memory amplification, existing atoms can still be
      referenced (so any atom the BEAM has loaded is fair game), and callers
      that pattern-match on a specific shape can crash or be confused. Worth
      a note so reviewers can confirm the caller validates the result.
      Severity: **Low**.
  """

  @simple_prompt """
  You are a senior application security engineer auditing one source file from
  an open-source Elixir/Erlang or Rust library. Find real, exploitable
  vulnerabilities only — no style, no speculation.

  You see this one file in isolation. Flag only bugs you can argue from this
  file alone. Skim the file with the vector list below in mind and report
  what's actually dangerous; don't write up an inventory or methodology.

  #{@always_flag}

  #{@sink_classes}

  ## Output

  If the file has no real vulnerabilities, output exactly:

      No findings.

  Otherwise, for each finding output one block in this format:

      ### <Short title>
      **Severity:** Critical | High | Medium | Low
      **Location:** <relative/path>:<line> | <relative/path>:<line_start>-<line_end>

      **Description:** <one short paragraph: what's vulnerable and how it
      could be exploited. If a guard in the file blocks the obvious attack,
      name the guard.>

      **Suggested fix:** <one or two sentences>

  No preamble, no overall summary, no ruled-out section.
  """

  @deep_prompt """
  You are a senior application security engineer auditing one source file from
  an open-source Elixir/Erlang or Rust library. Find real, exploitable bugs
  only — no style, no speculation.

  You see this one file in isolation. You cannot trace inputs across modules
  or check reach. Flag only bugs you can argue from this file alone.

  #{@per_file_deep_methodology}

  #{@always_flag}

  #{@sink_classes}

  #{@per_file_deep_output}
  """

  @whole_prompt """
  You are a senior application security engineer. Audit the open-source
  Elixir/Erlang or Rust library in the current working directory for real,
  exploitable vulnerabilities.

  Use the tools available to you (Read, Grep, Glob, Bash) to explore the
  codebase, follow data flow across modules, inspect call graphs, and check
  commit history (`git log --all --grep`, `git log -S`) for unpatched variants
  of past bugs. Spend effort proportional to the package's risk surface.

  #{@whole_methodology}

  #{@always_flag}

  #{@sink_classes}

  #{@whole_output}
  """

  @doc """
  Audit a single file. `style` is `:simple` or `:deep`; `opts` may
  override `:effort` and `:timeout_ms`.
  """
  def audit_file(rel_path, content, style, opts \\ [])
      when is_binary(rel_path) and is_binary(content) and style in [:simple, :deep] do
    CodingAgent.run(build_for_file(style, rel_path, content),
      effort: Keyword.get(opts, :effort, @default_effort),
      timeout_ms: Keyword.get(opts, :timeout_ms, @per_file_timeout),
      agent: Keyword.get(opts, :agent)
    )
  end

  @doc """
  Audit a whole package. `cwd` is the source directory the agent runs
  in. `opts` may override `:effort` and `:timeout_ms`.
  """
  def audit_directory(cwd, opts \\ []) when is_binary(cwd) do
    CodingAgent.run(@whole_prompt,
      cwd: cwd,
      effort: Keyword.get(opts, :effort, @default_effort),
      timeout_ms: Keyword.get(opts, :timeout_ms, @whole_timeout),
      agent: Keyword.get(opts, :agent)
    )
  end

  defp build_for_file(style, rel_path, content) do
    Enum.join(
      [base_for(style), "", "File path: #{rel_path}", "```", content, "```"],
      "\n"
    )
  end

  defp base_for(:simple), do: @simple_prompt
  defp base_for(:deep), do: @deep_prompt
end

