# Changelog

Each release, with its binaries, is on
https://github.com/memprove/memprove/releases.

## Unreleased

### Added

- The memprove plugin for coding agents (`plugins/memprove`), with one
  skill, `memprove-setup`: asked to set memprove up, the agent installs it
  when it is missing and runs `memprove init`, `memprove eval init`,
  `memprove policy init` (when the release has it) and `memprove doctor`,
  then reports what changed. This repository is its marketplace for Claude
  Code (`/plugin install memprove --marketplace memprove/memprove`) and
  Codex (`codex plugin marketplace add memprove/memprove`), and
  `.cursor-plugin/marketplace.json` lists it for Cursor. No change to the
  binaries.
- `memprove verify` (crate `memprove-verify`): checks that work an agent
  says is done is done. A contract (`.memprove/verify.json`, schema
  `memprove.verify.contract.v1`) names the checks, commands that must
  exit 0, and the protected paths. `verify run` writes the work (the
  working tree without what Git ignores, or `--commit`) to a clean copy,
  runs the checks there and judges by exit codes; when the work changes a
  protected path it runs them again with those paths as at the base
  commit. Verdicts: `pass` (exit 0), `fail` (1), `needs_human` (4: the
  checks pass only with the work's own changes to protected paths, or
  the work adds a skip marker). The contract is read from the base
  commit. Every run writes a receipt (`memprove.verify.receipt.v1`)
  under `<git common dir>/memprove-verify/runs/`. `verify init` writes
  the contract and, with `--hook`, the Claude Code `SessionStart` and
  `Stop` handlers; `verify hook` keeps an agent working while a check
  fails, at most 3 times in a session. `verify show` prints a run again.
  See `docs/verify.md`. The ledger format, the control API and the Pack
  are unchanged.
- `memprove init` writes the session-start hook for Codex
  (`.codex/hooks.json`, the same `hook session-start` as Claude Code's,
  run once you approve it in Codex's `/hooks`) and for Cursor
  (`.cursor/hooks.json`, `hook session-start --client cursor`, which reads
  Cursor's `sessionStart` input and answers with `additional_context`), so
  that the Pack is injected at the start of a session in all three
  clients; both files go into `.git/info/exclude`. The Claude Code
  handler prints nothing when Cursor runs it, so Cursor gets the Pack
  once.
- `memprove import` lists the statements (one per list item or paragraph)
  of `CLAUDE.md`, `CLAUDE.local.md`, `.claude/CLAUDE.md`, `AGENTS.md`,
  `GEMINI.md`, `.github/copilot-instructions.md`, `.cursorrules`,
  `.cursor/rules/` and Claude Code's auto-memory of the repository, or of
  the `--file`s given, without sending anything; `--select` records the
  chosen ones as open items `<text> (imported from <source>:<line>; not
  verified)` in one Checkpoint of the current Session, keeping the next
  action in force, and leaves out those already in force, so a second
  import records nothing twice.
- `memprove doctor` has a `client-hooks` line when `.codex/hooks.json`
  or `.cursor/hooks.json` exists: the handler `init` writes is there, its
  `memprove` exists, Cursor's has `--client cursor`, and its
  `--config-dir` is the configuration directory doctor uses. Whether Codex
  trusts the project and approved the hook in `/hooks` is not checked.
- `memprove init --client trae` enables TRAE and TRAE CN (detected from
  `~/.trae-cn` or `~/.trae`): the session-start hook in `.trae/hooks.json`
  (the same `hook session-start` as Codex's, as one shell command line;
  TRAE sends Claude Code's members and adds plain output to the context),
  `mcpServers.memprove` in `.trae/mcp.json`, and the note as the
  always-applied rule `.trae/rules/memprove.md`; all three go into
  `.git/info/exclude`, and doctor's `client-hooks` line checks the hook.
  TRAE runs it once you trust the folder and enable the hook; `init` says
  so and turns nothing on itself.
- `memprove policy` (crate `memprove-policy`): one set of tool rules for
  Claude Code, Codex and Cursor in `.memprove/policy.rules`
  (`<deny|ask|allow> <Bash|Read|Edit|Mcp>(<pattern>) [-- reason]`, the
  first matching rule deciding, a command line getting the strictest
  decision of its commands, and `expect` lines as tests). `policy hook
  --client <c>` reads each client's tool-call hook input and answers in
  its JSON; shell command lines are read without running them (separators,
  quotes, heredocs, substitutions, wrappers such as `sudo` and `xargs`,
  `bash -c`, `find -exec`, `cd`), and their reads and writes are checked
  against `Read` and `Edit` rules. `ask` refuses where the client cannot
  ask from a hook (Codex; Cursor's file reads and writes). Changes to the
  policy file and the clients' hook settings always need a person; a
  policy that does not parse makes every call need one. `policy init`
  writes a starter policy and the hooks (`.claude/settings.local.json`,
  `.codex/hooks.json`, `.cursor/hooks.json`, kept out of Git), `policy
  check` decides one call and names the deciding line, `policy test` runs
  the `expect` lines, and `policy log` shows the refusals and approvals
  asked for, logged in `<git common dir>/memprove-policy/log.jsonl`.

### Fixed

- `memprove eval run` and `ab` passed their whole environment to the
  agent under test, but for a list of session variables; run from a
  Claude Code session, the agent got that session's messaging socket and
  token, its ingress token file and the user's email, account and
  organization. The agent now inherits only a list of variables (the
  shell's, the network's, the model providers' login, the toolchains';
  `docs/eval.md` names them) and those named with the new `--pass-env
  NAME`, which `run.json` records; `--pass-env` refuses the session
  variables. Setup and check commands are unchanged.
- `docs/guide.md` said that `.cursor/rules/memprove.mdc` is committed;
  `init` puts it into `.git/info/exclude` with Cursor's other files, as
  it always has.

## 0.2.1 · 2026-11-16

A patch release: help text only, no change in behaviour.

### Fixed

- `memprove eval init --help` and `memprove eval mine --help` now say
  that `--dry-run` lists the files that would be written; it never
  printed their contents.

## 0.2.0 · 2026-11-15

Adds `memprove eval`: run a coding agent on the repository's own tasks,
and measure whether memprove's memory helps it.

### Added

- `memprove eval` (crate `memprove-eval`): runs a coding agent on the
  repository's own tasks (`evals/*.json`, schema
  `memprove.eval.task.v1`), each trial in a new Git repository whose one
  commit holds the files of the task's base commit without the run's
  task files and check patches (no history, no other branch), and judges
  it by the check command's exit code alone, with an optional check patch
  applied after the agent. Writes
  `run.json` and every log under `<git common dir>/memprove-eval/runs/`;
  its last line is a cargo-style summary, so `memprove run --test-format
  cargo` records a run as test Evidence.
- `memprove eval run --memory pack` gives every trial's agent the Context
  Pack the SessionStart hook would give a new session (without the
  takeover hint and the `Can:` lines, since the agent is not to run
  memprove), ahead of its prompt, kept as `pack.md` and recorded as
  `run.json` `memory_given`;
  `memprove eval ab` runs the tasks without memory and with that Pack and
  reports the second against the first. `--baseline` also takes a run
  directory. The agent's `MEMPROVE_CONFIG_DIR` is an empty directory in
  every run.
- `.github/workflows/release.yml`: for a tag `v*` (or by hand for an
  existing tag) it builds the release binaries for Linux x86_64 (on
  Ubuntu 22.04) and macOS arm64, installs each archive once and runs
  `doctor`, and attaches the archives with their SHA-256 to the tag's
  GitHub Release. Linux arm64 is left out until memproved starts there.

## 0.1.0 · 2026-11-14

The first release: the work that made the repository publishable.

### Added

- `memprove init`: enables a repository in one command for Claude Code,
  Codex and Cursor (registers the Project, keeps memprove's files out of
  Evidence through `.git/info/exclude`, writes the SessionStart hook, the
  MCP server entries and a short note for clients without a hook, then runs
  `doctor`).
- `memprove init --allow-tools`: `init` writes Claude Code's
  `permissions.allow` rules only when asked, and otherwise prints them;
  it also replaces what it wrote under the previous name (the `AGENTS.md`
  note, the Codex table, an unedited `.cursor/rules/continuity.mdc`).
- `memprove init` records the Project it registers, so the first
  `memprove begin --new-task` after it needs no `--project` (before, it
  stopped with a usage error); `doctor` says so before that first `begin`.
- `scripts/install.sh`, when it builds and crates are missing, runs
  `cargo fetch --locked` and builds again; the README, the guide and
  CONTRIBUTING fetch the crates before their offline builds.
- `scripts/install.sh` gives an upgrade within the same second as the one
  before it a free backup directory and free names for the old binaries
  (`-2`, `-3`, ...) instead of failing on a backup directory that exists.
- `TAKEOVER_EVAL_PROTECT` for the takeover evaluation: more directories
  (such as a second installation) that its safety checks guard, besides
  `~/.memprove` and `~/.config/memprove`.
- `scripts/install.sh --write-profile` / `--no-write-profile`; a default
  prefix (`~/.memprove`) needs no environment variable, because the CLI,
  the hook and the MCP server find `~/.memprove/config` on their own.
- `LICENSE` (Apache-2.0), `CONTRIBUTING.md`, a CI workflow for macOS and
  Ubuntu, `README.md`, `docs/guide.md` and `docs/architecture.md`.

### Changed

- The product is named memprove: the crates are `memprove-*`, the binaries
  `memprove` and `memproved`, the MCP server `memprove` (allow rules
  `mcp__memprove`, `Bash(memprove run:*)`), the default installation prefix
  `~/.memprove` with its configuration in `~/.memprove/config`, the daemon's
  socket and lock `memproved.sock` and `memproved.lock`, the environment
  variables `MEMPROVE_*` (`MEMPROVE_CONFIG_DIR`, `MEMPROVE_DATA_DIR`,
  `MEMPROVE_TOKEN_FILE`, `MEMPROVE_TOKEN`, `MEMPROVE_CLIENT_SESSION`,
  `MEMPROVE_AGENT_NAME`, `MEMPROVE_AGENT_ROLE`, `MEMPROVE_PARENT_SESSION`),
  and the Pack's format label `memprove-pack v1`. The ledger's own
  identifiers are unchanged, so an existing ledger reads as before: the
  daemon still writes its Events as the producer `continuityd` and its
  repository probes as the collector `continuityd-git` (a migration's trigger
  enforces the former), the ontology version is
  `continuity.work-state-ontology.v4`, the backup marker is
  `continuity-backup.txt`, and the migrations and the published schemas are as
  they were. `scripts/install.sh` renames an installation of the previous name
  in place: it stops the old `continuityd`, keeps the data and the tokens,
  writes `ct` and `ensure-daemon.sh` again, and leaves `memproved` running
  when `continuityd` was. In a repository enabled under the
  previous name, `memprove hook install` replaces that installation's
  SessionStart handler, `env.CONTINUITY_CONFIG_DIR` and
  `mcpServers.continuity` (with `--allow-tools` also its rules
  `mcp__continuity`, `Bash(continuity run:*)` and `Bash(<path> run:*)`)
  instead of adding its own beside them, and `memprove hook uninstall`
  removes them.
- Every fixed text is English: the Context Pack lines, the hook's
  statements, the MCP tool descriptions and failure sentences, the help
  pages, `resume`, `preview`, `doctor`, the run hints and the daemon's
  error details. The Pack's line structure, omission levels, budget and
  digest algorithm are unchanged; only the digest values moved.
- The last sentence of the hook's and the MCP `pack` tool's opening, and the
  takeover rule in the MCP `begin` and `end` descriptions, name the session
  that records the open item for a Session it leaves open, and when: in its
  first checkpoint (before, the item "is recorded", with no one named).
- The query Pack keeps the ASCII matching path only (terms of three or more
  characters through the trigram index, shorter ones as whole words).
- The takeover evaluation's prompt, seeds and scorer are English.

### Removed

- The semantic projection and its MCP tool, the ontology manifest, the
  client and query profiles, the ContextManifest and the static HTML export,
  with their tests and documentation (the budgets and omission levels they
  carried are plain constants of the Pack now).
