# memprove

memprove is a memory and task-state layer for coding agents. Every fact an
agent records is bound to a commit, a repository state and a test run, and a
deterministic rule, not a model, decides whether it is still `verified`,
`stale`, or `unconfirmed`. The record is a hash-chained ledger kept by a
local daemon; a new session (the same agent later, another agent, a person)
reads a compact Context Pack of what holds, what is open and what to do
next, and takes the work over under a rule that says when a Session left
open may be ended.

It is a Rust workspace: `memproved` (the daemon), `memprove` (the
command-line client, the Claude Code SessionStart hook and an MCP server
with ten tools), and the crates they share. Everything runs on your machine
over a Unix socket; nothing leaves it.

## Why not just notes?

Agent memory goes stale silently: a sentence in `CLAUDE.md` or a memory
store says the parser handles empty input, and three commits later it does
not. Tools that audit memory files (stalebrain, true-memory-fragments and
their kin) check sentences against paths, symbol hashes or the commit that
contradicts them; Claude Code's auto-memory and the hosted memory layers
merge and expire entries by timestamps and wording. memprove does not
judge text: a fact is `verified` only while a test run that `memprove
run` recorded passed in the repository state the daemon can still observe.
When HEAD, the index or the worktree moves, the fact is `stale` and the Pack
says which command to run again. When the ledger itself is changed behind
the daemon's back, every verdict of that Task is `tampered` and the word
`verified` appears nowhere. What was superseded or withdrawn stays in the
record, and every statement names the Session, hence the agent, that wrote
it.

## Install in two steps

1. Install. Release binaries for macOS on Apple silicon and Linux x86_64
   (glibc 2.35 or later) are on the
   [releases page](https://github.com/memprove/memprove/releases), with
   the commands that verify and install them; https://memprove.dev/docs/
   has them too. To build from source instead (macOS with Homebrew LLVM;
   on Ubuntu install `libclang-dev` and skip the two exports):

   ```bash
   export LIBCLANG_PATH=/opt/homebrew/opt/llvm/lib
   export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/opt/llvm/lib
   cargo fetch --locked        # downloads the crates once; the rest is offline
   cargo build --offline --release -p memprove-cli -p memprove-daemon
   scripts/install.sh --from-binaries target/release
   ```

   The default prefix is `~/.memprove`: binaries in `bin/`, the daemon's
   data in `data/`, the agent's token and the data directory's path in
   `config/`, the operator's token in `operator-token`, the guide in
   `share/`. The daemon is started for you, and the binaries find their
   configuration without any environment variable. Put `~/.memprove/bin`
   on `PATH` (`--write-profile` writes the line into your shell profile).

2. Enable a repository, from inside its Git worktree:

   ```bash
   memprove init
   ```

   It registers the Project (and records it, so the first `memprove begin`
   there needs no `--project`), keeps memprove's own files out of your
   Evidence through `.git/info/exclude`, writes the Claude Code hook and MCP
   entry (`.claude/settings.local.json`, `.mcp.json`), the Codex server
   entry (`~/.codex/config.toml`) and hook (`.codex/hooks.json`) with a
   short note in `AGENTS.md`, the Cursor entry and hook (`.cursor/mcp.json`,
   `.cursor/hooks.json`) with a rule, the TRAE and TRAE CN hook, entry and
   rule (`.trae/hooks.json`, `.trae/mcp.json`, `.trae/rules/memprove.md`),
   for whichever clients it detects (`--client` names them), and ends with
   `memprove doctor`. Codex runs its hook once you approve it in `/hooks`;
   TRAE once you trust the folder and enable the hook in its settings.
   Running it again changes nothing. No token is shown or written into the
   repository.

   Rules your agents already have in `CLAUDE.md`, `AGENTS.md`, Cursor's
   rules or Claude Code's auto-memory come along with `memprove import`
   (it lists them) and `memprove import --select all` (after the first
   `begin` and `run`): each becomes an open item marked as imported and not
   verified.

Or let your coding agent do both steps, and set up `memprove eval` and
`memprove policy` too: add the memprove plugin
(`/plugin install memprove --marketplace memprove/memprove` in Claude Code;
`codex plugin marketplace add memprove/memprove`, then
`codex plugin add memprove@memprove` in Codex) and say "Set up memprove in
this repository." `plugins/memprove/README.md` has Cursor and other agents.

## One session, five commands

```bash
memprove begin --new-task "parser: handle empty input"     # or a plain `begin` to continue the Task
# ... edit, commit ...
memprove run --test-format cargo -- cargo test              # the run is the Evidence; its label is r1
memprove checkpoint create \
  --fact "the parser accepts empty input and reports it as an empty document" --evidence r1 \
  --open "the error path for a truncated header is untested" \
  --next "write the truncated-header test and run cargo test"
memprove resume --pack                                     # what the next session will read
memprove end --reason "empty input handled"
```

`begin` starts a Session on a Task (and creates the Task with `--new-task`).
`run` runs the command in your shell and records its result together with
the repository state. `checkpoint create` records facts (each citing runs),
open items, decisions and the next action; a fact needs a passed test run,
and stays `verified` only while the tree matches that run (commit or ignore
a file the test run creates, such as a first `Cargo.lock`).
`resume --pack` prints the Context Pack: the Task's verdict, the Sessions,
the last passed run, what can be done next, every active statement with its
verdict and the commit it is bound to, and what to run again. `end` ends
the Session. In Claude Code, Codex, Cursor and TRAE the hook injects the Pack at
the start of every session, and the MCP tools do what the commands do,
except running commands: tests are always recorded with `memprove run`.

`memprove --help` lists every command; `docs/guide.md` is the agent's
manual, from install to takeover.

## Taking over

A Pack lists every Session that has not ended. A session that finds one
left by another agent ends it as abandoned only when all three hold: its
agent is not you; it looks gone, because its last write is more than 15
minutes old or the Session that dispatched it has ended; and it is not your
own parent. Otherwise the Session stays open, `begin` as usual, and the
session's first checkpoint records an open item that another Session may
still be working. The hook's opening gives you your name, the current UTC
time and your parent, so the rule needs no read of your environment.
`memproved` records who ended whom, and a Session that declared the
`sub_agent` role cannot record a Decision, complete the Task, or overrule
another agent's facts; the orchestrating session or a person does that. The
takeover evaluation (`docs/takeover-eval.md`) runs a real client through
six scenarios and scores the archive.

## Evaluating your agent

`memprove eval` gives a coding agent (Claude Code, Codex, or any
program) this repository's own tasks, each in a fresh Git repository
holding the files of a base commit, and judges each only by the exit
code of its check command, with hidden tests applied after the agent.
Runs are compared with a baseline committed under `evals/`, and
`memprove eval gate` fails CI when a change of model, prompt or memory
makes the agent worse. `memprove eval ab` runs the tasks without memory
and then with memprove's Context Pack, and shows which tasks the memory
fixed or broke. `memprove eval init` sets a repository up and
`memprove eval mine` writes tasks from its history; `docs/eval.md` has
the rest.

## Verifying that work is done

`memprove verify` checks an agent's "done": the repository's contract
(`.memprove/verify.json`) names the commands that must exit 0 and the
protected paths, its tests. `memprove verify run` runs the commands on a
clean copy of the work (no ignored file, no build output), and exit
codes alone judge. Work that passes only with its own changes to the
protected paths, or that adds a skip marker, is left to a person; the
contract is read from the base commit, so the work cannot weaken it.
Every run writes a receipt. `memprove verify init --hook` adds Claude
Code hooks that verify each time the agent finishes and keep it working
while a check fails; `docs/verify.md` has the rest.

## One set of tool rules for every agent

`memprove policy` puts the rules for an agent's tool calls in one committed
file, `.memprove/policy.rules`, and has Claude Code, Codex and Cursor check
each call against it before it runs, on the developer's machine:

```text
deny  Bash(git push *--force*)  -- push a new branch instead
ask   Bash(git push *)
deny  Read(.env*)
deny  Edit(db/migrations/**)
expect deny Bash(cd app && git push origin main --force)
```

The hook reads a command line as a shell would (`&&`, pipes, `bash -c`,
`$(...)`, `sudo`, `xargs`, `cat .env`), the first matching rule decides,
and `memprove policy test` runs the `expect` lines in CI.
`memprove policy init` writes a starter file and each client's hook;
`docs/policy.md` has the rest.

`memprove policy scan` finds the secrets agents have already left in
their own files: the password inside a command you allowed once
(`Bash(PGPASSWORD=… psql …)` in `.claude/settings.local.json`), the API key
in an MCP entry's `env`, the token quoted in `CLAUDE.md`. It names the
file, the line and the kind, never the value, and says whether Git tracks
the file. It runs locally, needs no policy file and exits 1 when it finds
one, so it fits CI. The rule `ask Secret(*)`, in the starter file, has a
person approve a call that writes a new one: the agent is told to pass the
secret through the environment instead.

Against prompt injection, `taint` lines mark a session once it has read
content from outside (`taint Web(*)`, `taint Mcp(*)`), and `tainted` rules
apply only to marked sessions (`tainted ask Bash(curl *)`): after the
agent has read a web page, what could send data out needs a person. No
model judges the page; the same calls get the same answers. The starter
file holds this gate as comments.

## What a session cost, did and read

`memprove report` reads one Claude Code or Codex session of this
repository from the client's own transcript on this machine and says
what it cost (tokens per model, estimated at list prices), which tools
it called and how many failed, which calls `memprove policy` refused or
sent to a person, and which memprove statements the agent read, with the
facts that were not verified when it read them. `memprove report --list`
shows the last sessions, and `--json` gives the same for scripts. It
writes nothing and sends nothing anywhere; `docs/report.md` has the rest.

## Status

memprove 0.3.1 came out on 2026-11-27
([release notes and binaries](https://github.com/memprove/memprove/releases/tag/v0.3.1));
it fixes TRAE's MCP server, which found no Workspace in TRAE itself.
0.3.0, which added `memprove verify`, `memprove policy`, `memprove
report` and `memprove import`, the session-start hook for Codex and
Cursor, and TRAE, came out on 2026-11-21; 0.2.1, a correction of help
text, on 2026-11-16, 0.2.0, which added `memprove eval`, on 2026-11-15,
and 0.1.0, the first release, on 2026-11-14.
It is under active development. The ledger format, the control API
(`openapi/control-api-v1.yaml`) and the Pack's line set are stable; the
daemon has no network access by design. Linux on arm64 is not supported
yet. `docs/architecture.md` says how it is built.

## Licence

Apache License, Version 2.0 (`LICENSE`).
