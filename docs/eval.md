# memprove eval

`memprove eval` answers one question: after a change to how a coding agent works in this repository (a new model, a
new prompt, an edited `CLAUDE.md` or `AGENTS.md`, different memory), does the agent still do this repository's real
work? It gives the repository's own tasks to the agent, each in a fresh Git repository holding the files of the task's
base commit, and judges each by the exit code of the task's check command alone. Runs are kept as `run.json`, compared
with a baseline committed to the repository, and gated in CI.

```bash
memprove eval init                      # evals/, a CI workflow, five lines in AGENTS.md / CLAUDE.md
memprove eval mine --verify             # tasks from the history: parent commit, message, the commit's tests
memprove eval run evals/ --agent claude-code
memprove eval report latest
memprove eval baseline latest --write evals/baseline.json
memprove eval gate latest --baseline evals/baseline.json
```

A developer can hand the first two commands to their own coding agent: `init` writes `evals/README.md`, a guide
addressed to that agent, and the agent then adds and checks tasks by itself.

## Why only the exit code

A model that grades another model's work is a second thing to evaluate, costs a second bill, and gives a different
answer the next day. A check command does not: `cargo test -p parser` exits 0 or it does not, today and in a year, on
a laptop and in CI. So a task is judged by its check command and nothing else; an agent's own account of what it did
is recorded but never counted. The price is that a task needs a check that can tell good work from bad, which is what
hidden test patches (below) are for.

## Install and set up

`memprove eval` is part of the `memprove` binary (see the README for installing it); it needs Git and, to run a real
agent, that agent's CLI (`claude` for Claude Code, `codex` for Codex). It does not need the memprove daemon unless
the run reads memory (see "Memory").

```
memprove eval init [--agent claude-code|codex] [--no-workflow] [--dry-run]
```

`init` writes, in the repository root:

- `evals/README.md`: how to write and check task files, addressed to a coding agent.
- `evals/smoke.json`: a first task, with a check guessed from the repository's files (first match wins):
  `Cargo.toml` gives `cargo test`; `package.json` with a `test` script gives `npm test` after `npm ci` (`pnpm` or
  `yarn` when their lock file is there); `pyproject.toml`, `pytest.ini` or `setup.cfg` give `python3 -m pytest`;
  `go.mod` gives `go test ./...`; a `Makefile` with a `test` target gives `make test`. With no match, no smoke task
  is written and init says so.
- `.github/workflows/memprove-eval.yml` (not with `--no-workflow`), see "CI".
- A block of at most five lines between `<!-- memprove-eval:begin -->` and `<!-- memprove-eval:end -->` in
  `AGENTS.md` and/or `CLAUDE.md`, whichever exist (`AGENTS.md` when neither does), telling the agent where the evals
  are and what to run after changing prompts or memory.

Running `init` again changes nothing. It replaces its block in place, and it never overwrites `evals/README.md`,
`evals/smoke.json` or the workflow once they hold something else: it reports them as kept, so edits are safe.
`--dry-run` lists the files that would be written and writes nothing; it does not print their contents.

## Tasks

A task is a file `evals/<id>.json`:

```json
{
  "schema": "memprove.eval.task.v1",
  "id": "empty-input",
  "title": "parser accepts empty input",
  "base": "a1b2c3d",
  "prompt": "Make `parse` accept empty input and return an empty document.",
  "setup": [{"argv": ["npm", "ci"], "timeout_secs": 600}],
  "check": {"argv": ["cargo", "test", "-p", "parser"], "timeout_secs": 900},
  "check_patch": "evals/empty-input.check.patch",
  "agent_timeout_secs": 1800,
  "tags": ["parser"]
}
```

| Member | |
|---|---|
| `id` | 1 to 64 of `a-z`, `0-9`, `-`, `_`; the file name when left out |
| `base` | the commit the agent starts from; HEAD at the start of the run when left out |
| `prompt` | what the agent is asked to do |
| `setup` | commands run in the fresh worktree before the agent (installing packages); a failure is `setup_failed` |
| `check` | the acceptance command: exit code 0 is `passed` |
| `check_patch` | a patch, relative to the root, applied after the agent and before the check; the files it touches are first put back as they are at `base`, so its version of them replaces the agent's |
| `agent_timeout_secs` | the agent's limit; past it the agent is killed and the check runs all the same |
| `tags` | free labels |

Commands run without a shell; write `["sh", "-c", "..."]` for one. A member not in the table is an error.

A good task is real work from this repository (a fixed bug, a small feature), takes an agent less than 15 minutes,
and has a narrow check (one package, one test file) that fails before the work and passes after it. The tests that
judge it go in the check patch, so that the agent can neither read nor weaken them: make the change and its tests on
a branch from `base`, then `git diff <base> HEAD -- <test files> > evals/<id>.check.patch`.

Check a new task file with an agent that does nothing:

```bash
memprove eval run evals/<id>.json --agent command -- true
```

The smoke task should come out `passed`, a task for new work `failed`; if a task for new work passes, its check does
not test the work. `patch_failed`, `setup_failed` and `error` mean the file needs fixing.

## Mining tasks from the history

```
memprove eval mine [--limit N] [--range <git-range>] [--out evals] [--verify] [--dry-run]
```

`mine` looks at the non-merge commits of `--range` (the history of HEAD by default), newest first, and turns a commit
into a task when it changed at least one test file and at least one file that is neither a test nor documentation,
and no more than 20 files and 600 lines. A test file is one under a `test`, `tests`, `spec`, `specs` or `__tests__`
directory, or one whose name starts with `test_` or holds `_test.`, `.test.`, `_spec.` or `.spec.`; documentation is
under `docs/` or `doc/`, or a `.md`, `.markdown`, `.rst` or `.adoc` file. The task `evals/mined-<7 hex>.json` has:

- `base`: the commit's parent;
- `prompt`: the commit's subject and body, without trailers such as `Co-Authored-By:`;
- `check_patch`: `evals/mined-<7 hex>.check.patch`, the binary diff of the commit's test files against the parent;
- `check`: the guessed test command, narrowed when the rules allow: for Rust, `cargo test -p <package>` for the
  packages that hold the test files, plus `--test <name>` when they are all integration tests of one package; for
  Go, `go test` with the test files' package directories; for Python, `python3 -m pytest` with the test files;
  `setup` comes from the same guess.

A task file that exists is never overwritten, and counts towards `--limit` (10 by default), so running `mine` again
changes nothing. With `--verify`, each candidate is tried in two worktrees before it is written: setup and check must
fail on the parent with the check patch applied, and pass on the commit. Candidates that do not are reported with the
reason and the directory of their logs (under `.git/memprove-eval/mine/`) and are not written. A Rust repository
builds from scratch in each worktree; setting `CARGO_TARGET_DIR` to one directory for the whole run saves most of it.
In a Rust repository that builds `memprove` itself, run `memprove eval` from an installed binary then, not from that
directory: the checks rebuild it there at older commits.

Mined tasks are a start, not a finished suite: read each prompt (a commit message says what changed, not always what
was asked), and add the setup the check needs that the guess cannot know (a service, a binary another package builds).

## Running, reporting, gating

```
memprove eval run      [<task file or dir>...] [--agent claude-code|codex|command] [--model M]
                       [--agent-arg A]... [--pass-env NAME]... [--trials N] [--jobs N] [--out-root DIR]
                       [--keep-worktrees] [--memory none|pack] [--no-memory] [-- <program> <args>...]
memprove eval ab       [<task file or dir>...] [the options of run but --memory and --no-memory]
memprove eval report   [<run dir>|latest] [--baseline FILE|RUN_DIR] [--format markdown|json]
memprove eval baseline [<run dir>|latest] [--write FILE]
memprove eval gate     [<run dir>|latest] --baseline FILE|RUN_DIR [--max-drop <percentage points>]
                       [--allow-regressions]
```

`run` reads the tasks (`evals/` by default; `baseline.json` is not a task) and runs every trial in a working copy of
its own at the task's base (see "What the agent sees"): setup, the agent with the prompt, then the check patch and the
check. Each trial ends as one of `passed`, `failed`, `check_timeout`, `setup_failed`, `patch_failed`, or `error` (the
trial could not be run: not the agent's fault, counted as not passed and reported apart). The run directory
`<git common dir>/memprove-eval/runs/<run id>/` holds `run.json` and each trial's agent and check output and the
agent's diff; it is inside `.git`, so it is never an untracked file. `latest` is the run directory with the greatest
name. See "Agents" for what each agent is started with.

`report` prints a run as Markdown (for a pull request comment or the job summary) or as JSON: the pass rate, cost and
tokens as the agent reported them, one row per task with each trial's outcome and, against a baseline, its change
(`regressed`, `worse`, `fixed`, `better`, `same`, `new`, `missing`), and every trial that did not pass with its reason
and logs. `baseline --write` keeps a run's per-task results (passed out of trials) as `evals/baseline.json`, to
commit; `--baseline` also takes a run directory, whose results are then the baseline. `ab` is two runs and a report:
see "Does memory help?". `gate` exits 1 when the pass rate is more than `--max-drop` points below the baseline's, when
a task that passed every trial in the baseline now passes none (unless `--allow-regressions`), or when a baseline task
did not run.

Exit codes of every `eval` command: 0 done (all trials passed, the gate passed), 1 some trial did not pass or the gate
failed, 2 usage error, 3 the command could not be done (a file, `git`, the agent would not start).

## Agents

Each agent runs in the trial's working copy with the prompt; its output goes to `agent.out` and `agent.err`, the
prompt to `prompt.md`, in the trial's directory. `--model` and each `--agent-arg` are passed on.

- `claude-code`: `claude -p --output-format json [--model M] --permission-mode bypassPermissions
  --no-session-persistence <agent args> -- <prompt>`. Tokens, turns and `total_cost_usd` are read from its JSON
  result. As root, Claude Code refuses `bypassPermissions` unless `IS_SANDBOX=1` is set; `memprove eval` does not set
  it for you.
- `codex`: `codex exec --json [--model M] --sandbox workspace-write --ephemeral -C <worktree> <agent args> --
  <prompt>`. Tokens are summed over its `turn.completed` events; Codex reports no cost. Its `workspace-write` sandbox
  has no network by default; `--agent-arg --dangerously-bypass-approvals-and-sandbox` lifts it. Whether the agent
  commits does not change the outcome: the diff holds its commits and its uncommitted changes alike.
- `command`: `--agent command -- <program> <args>...` runs any program, with `{prompt_file}` and `{workdir}` replaced
  in its arguments and `MEMPROVE_EVAL_PROMPT_FILE`, `MEMPROVE_EVAL_WORKDIR`, `MEMPROVE_EVAL_USAGE_FILE` (and
  `MEMPROVE_EVAL_MODEL` with `--model`) in its environment. A program that writes the usage file (members of
  `run.json`'s `usage`: `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_write_tokens`, `cost_microusd`,
  `turns`) has its usage recorded.

`MEMPROVE_EVAL_CLAUDE` and `MEMPROVE_EVAL_CODEX` name the programs when they are not `claude` and `codex` on `PATH`.

The agent inherits only a list of this environment's variables, and those named with `--pass-env NAME` (repeatable):

- the shell's: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TERM`, `COLORTERM`, `LANG`, `LANGUAGE`, `TZ`, `TMPDIR`,
  `TMP`, `TEMP`, and every `LC_*` and `XDG_*`;
- the network's: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (and their lower-case forms), `SSL_CERT_FILE`,
  `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`;
- the model providers' login and settings: every `ANTHROPIC_*`, `OPENAI_*`, `AWS_*` and `VERTEX_REGION_*`,
  `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_OAUTH_TOKEN`, `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_VERTEX`, `CODEX_HOME`,
  `GOOGLE_APPLICATION_CREDENTIALS`, `CLOUD_ML_REGION`, `IS_SANDBOX`;
- the toolchains': every `CARGO_*`, `RUSTUP_*` and `npm_config_*`, `LIBCLANG_PATH`, `DYLD_FALLBACK_LIBRARY_PATH`,
  `LD_LIBRARY_PATH`, `PKG_CONFIG_PATH`, `CC`, `CXX`, `JAVA_HOME`, `GOPATH`, `GOROOT`, `GOCACHE`, `GOMODCACHE`, `GOFLAGS`,
  `GOPROXY`, `NVM_DIR`, `PNPM_HOME`, `BUN_INSTALL`, `VIRTUAL_ENV`, `CONDA_PREFIX`, `PYENV_ROOT`, `HOMEBREW_PREFIX`,
  `HOMEBREW_CELLAR`, `HOMEBREW_REPOSITORY`, and Git's `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`.

Nothing else reaches it: not a calling Claude Code session's socket, tokens or identity (`CLAUDE_CODE_MESSAGING_*`,
`CLAUDE_SESSION_INGRESS_TOKEN_FILE`, `CLAUDE_CODE_USER_EMAIL`, `CLAUDE_CODE_ACCOUNT_UUID`, `CLAUDE_CODE_REMOTE*`), not
`SSH_AUTH_SOCK`, `GITHUB_TOKEN` or memprove's `MEMPROVE_DATA_DIR`. `run.json` records the `--pass-env` names (never
values) as the agent's `pass_env`. The variables that would tie a command to the session running the evaluation are
never passed, `--pass-env` refuses them, and the setup and check commands, which otherwise get this environment, start
without them too: memprove's `MEMPROVE_CLIENT_SESSION`, `MEMPROVE_AGENT_NAME`, `MEMPROVE_AGENT_ROLE`,
`MEMPROVE_PARENT_SESSION` (and their `CONTINUITY_` forms), Claude Code's session variables (`CLAUDECODE`,
`CLAUDE_CODE_SESSION_ID`, `CLAUDE_CODE_REMOTE_SESSION_ID` and the like) and Codex's `CODEX_THREAD_ID`. The agent's
`MEMPROVE_CONFIG_DIR` is an empty directory of the run (`agent-config/`), so a memprove command, hook or MCP server
that finds its installation through that variable finds none. One given `--config-dir` (as `memprove init` writes the
hook into `.claude/settings.local.json`) still finds the installation, but a trial's working copy is not a Workspace
with a memprove context, so the hook injects no Pack there and a command cannot record to a Session; the agent gets no
Pack but the one `--memory pack` gives.

## What the agent sees

A trial's working copy is a new Git repository under the system's temporary directory with one commit on `main`, whose
subject is `the files of commit <base>`: the files of the task's base commit, without the task file and check patch of
any task in the run (a directory they leave empty goes too). It has no history, no other branch or tag, and no link
back to the repository under evaluation, so neither its files nor `git log --all`, `git show` or `git branch --all`
show a check, a task file, or a later commit such as the one a mined task was made from. The trial's `base` in
`run.json` is still the task's base commit, and `agent.diff` is the agent's change against the working copy's one
commit. The repository under evaluation is read and not changed: its index, worktrees and refs stay as they were.

Without history, `git log` and `git blame` show nothing older than the trial, and a setup or check that needs history
or tags (`git describe`) does not work there. This hides the answer from a look at the working copy and its
repository; it is not a sandbox (see "Limits of v0").

## CI

The workflow `init` writes runs by hand (`workflow_dispatch`) or on a pull request labelled `eval`, not on every push,
since a real agent costs money. It checks out the whole history (tasks start from earlier commits), downloads the
memprove release it names from GitHub, installs the agent's CLI with npm, runs `memprove eval run evals/ --agent <agent>
--no-memory`, adds `memprove eval report` to the job summary, gates against `evals/baseline.json` when that file
exists, and uploads the run directory as an artifact. It needs the repository secret `ANTHROPIC_API_KEY` (Claude Code)
or `OPENAI_API_KEY` (Codex). Add to it what the checks need, such as a toolchain or a service; `init` leaves an edited
workflow alone.

## Memory

memprove records what an agent learned as facts bound to Evidence; an evaluation is Evidence too. Run it under
`memprove run`:

```bash
memprove run --test-format cargo -- memprove eval run evals/
```

`eval run` ends with a line in libtest's format (`test result: ok. 5 passed; 0 failed; ...`, one case per trial), so
memprove records the run as test Evidence that a fact can cite ("the agent passes 5 of 5 evals with this CLAUDE.md"),
and the fact goes stale when HEAD moves, like any other.

Without `--no-memory`, `eval run` also reads the statements memprove holds for the repository when the run starts
(the Pack's facts, open items, decisions and next action, each with its verdict) and keeps them in `run.json`. When a
trial fails, the report lists those memprove no longer judges verified: a fact that is not `verified`, and any
statement whose Evidence is `stale` or `tampered`. When memprove's statements cannot be read (no daemon, no Task in
progress), the run goes on, `run.json` keeps the reason as `memory_unread`, and a report with failures says so.

By default the agent does not get these statements: a trial worktree has no memprove context of its own, so the agent
starts without a Pack.

### Does memory help?

`--memory pack` gives every trial's agent the Context Pack memprove would inject into a new session in the repository
now: the SessionStart hook's rules for choosing the Task and its budget, read once when the run starts (read only:
`getTaskCapsule` and `listTasks`). What the Pack says a reader can do with memprove is left out, since the agent is not
to run memprove: the hint at the end of the line of a Session that has not ended (how to end it before taking over)
and the `Can:` lines; the `Digest:` line is written again for the lines kept. The agent's prompt is a short note (this
is memprove's Context Pack for the repository, read-only here, do not run memprove commands; the commits it names are
not in the working copy, which holds the files of the base commit as one new commit), the Pack in a `text` block, then
`Task:` and the task's own prompt; every agent gets it this way, not through its own hook. The run directory keeps the
Pack as `pack.md`, and `run.json` records it as `memory_given` (`sha256`, `bytes`; `null` without it). When the Pack
cannot be read, the run stops before any trial with exit code 3 and says why. `--memory pack` and `--no-memory` cannot
be used together.

`eval ab` answers "does this repository's memory make the agent better at its own tasks?" in one command:

```bash
memprove eval ab evals/ --agent claude-code --trials 3
```

It reads memprove's memory once, runs the tasks without memory, runs them again with that Pack, and prints the report
of the second run against the first as its baseline: the pass rate without and with the Pack, and each task's change
(`fixed` is a task that passed no trial without memory and every trial with it, `regressed` the reverse). Each run has
its own directory, so `eval report <with> --baseline <without>` prints the comparison again. It costs two runs. A task
that measures memory needs something only memory says: a fact recorded earlier that the prompt leaves out, like a
port, a name, or a decision. Trials of a real agent vary; use `--trials` so that one lucky trial is not the result.

## Limits of v0

- Claude Code (`claude -p`), Codex (`codex exec`) and any program as `command`; not Cursor, which has no
  non-interactive CLI yet.
- Cost and tokens are what the agent reports about itself; there is no price table. An agent killed at its limit
  reports nothing, so a run's cost leaves out its timed-out trials.
- The agent gets memprove's Pack only with `--memory pack`, as text ahead of its prompt, read once when the run
  starts; it reads no other memory and records none during a trial (see "Does memory help?").
- The agent runs as you: it can read any file you can, so one that searches the disk beyond its working copy can
  still find the repository under evaluation, its check patches and its later commits; and your own configuration
  under your home directory (`~/.claude`, `~/.codex`) applies to it. Tasks measure an agent setup against itself over
  time; they are not a sealed benchmark.
- No model grades the work, no hosted service, no web page.
