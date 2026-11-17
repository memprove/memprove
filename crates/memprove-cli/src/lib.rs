//! Thin Local Control API client behind the `memprove` binary.
//!
//! The CLI never opens the store; every command is one HTTP/1.1 request over
//! the daemon's Unix socket, and every response is checked against the frozen
//! `memprove-protocol` validators before it is printed.

#![forbid(unsafe_code)]

use std::{
    ffi::OsString,
    fmt::{self, Write as _},
    fs::File,
    io::{self, Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    time::Duration,
};

use memprove_protocol::{
    phase1::{OperationId, binding_for, validate_response, validate_www_authenticate},
    strict_json::{JsonValue, parse_strict_bytes},
};

pub mod backup;
pub mod claims;
pub mod context;
pub mod display;
pub mod doctor;
pub mod eval_memory;
pub mod flow;
pub mod help;
pub mod hook;
pub mod import;
pub mod init;
pub mod mcp;
pub mod preview;
pub mod resume;
pub mod run;

use context::ContextLookup;
use run::{RunSpec, TestFormat, TestSpec};

/// Writes `line` and a line break on standard error, and ignores a failure.
///
/// U1 (C3): `eprintln!` panics when standard error cannot be written, a
/// broken pipe included, and a log line or a warning is not worth the
/// process; `mcp serve` keeps serving whatever reads its standard error.
pub(crate) fn log_line(line: fmt::Arguments<'_>) {
    let _ = writeln!(io::stderr().lock(), "{line}");
}

/// U1 (E1): the build identity `build.rs` compiled in: the first 12
/// characters of the commit, with `-dirty` when the worktree had changes,
/// or `unknown` (see `crates/shared/build_id.rs`).
pub const BUILD_ID: &str = env!("MEMPROVE_BUILD_ID");

/// U10 N4 (U9 VN12; Owner O6): the hint that a refused `operation` adds
/// when `memproved` is older than this `memprove`: the member
/// `session_id` the completion sends (U9 SF1-A) is "an unknown member" to a
/// daemon built before it, which answers `400 invalid_request` with that
/// `detail`. Only the daemon's own phrase for an unknown member counts, so
/// the `400`s of a daemon that knows `session_id` (`$.session_id must name a
/// Session of the Task` and the like) get no hint. The build is this
/// `memprove`'s.
#[must_use]
pub fn older_daemon_hint(
    operation: OperationId,
    status: u16,
    detail: Option<&str>,
) -> Option<String> {
    (operation == OperationId::TransitionTask
        && status == 400
        && detail.is_some_and(|detail| detail.contains("has an unknown member session_id")))
    .then(|| {
        format!(
            "the daemon is older than this build (it does not know session_id); memproved {BUILD_ID} \
             knows it"
        )
    })
}

/// U1 (E1): what `memprove --version` prints, without the line break.
pub const VERSION_LINE: &str = concat!(
    "memprove ",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("MEMPROVE_BUILD_ID"),
    ")"
);

#[cfg(test)]
#[path = "../../shared/build_id.rs"]
mod build_id;

/// Environment variable naming the daemon data directory.
pub const DATA_DIR_ENV: &str = "MEMPROVE_DATA_DIR";
/// Environment variable carrying a bearer token for protected operations.
pub const TOKEN_ENV: &str = "MEMPROVE_TOKEN";
/// Environment variable naming a 0600 file that holds the bearer token.
pub const TOKEN_FILE_ENV: &str = "MEMPROVE_TOKEN_FILE";
/// Socket file name inside the data directory.
pub const SOCKET_FILE_NAME: &str = "memproved.sock";

/// Upper bound for a single response.
const MAX_RESPONSE_BYTES: u64 = 1 << 20;
/// Upper bound for a Task Capsule response (P3-C2, T12 S-5): it grows with
/// the Task's ledger, about 1.2 KB per claim.
pub const MAX_CAPSULE_RESPONSE_BYTES: u64 = 16 << 20;

/// The most bytes the CLI reads as one response of `operation`.
#[must_use]
pub fn response_limit(operation: OperationId) -> u64 {
    match operation {
        OperationId::GetTaskCapsule => MAX_CAPSULE_RESPONSE_BYTES,
        _ => MAX_RESPONSE_BYTES,
    }
}
/// Upper bound for an Event envelope read by `event ingest`.
const MAX_ENVELOPE_BYTES: u64 = 1 << 20;
/// Upper bound for a token file.
const MAX_TOKEN_FILE_BYTES: u64 = 4096;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// `Idempotency-Key` length bounds from the contract.
const KEY_CHARS: std::ops::RangeInclusive<usize> = 16..=200;

/// Usage text.
pub const USAGE: &str = "\
Usage: memprove [--data-dir <PATH> | --socket <PATH>] [--token-file <PATH>] <COMMAND>

Commands:
  health live    healthLive         GET  /health/live
  health ready   healthReady        GET  /health/ready
  status         getStatus          GET  /v1/status   (control scope)
  version        getVersion         GET  /v1/version  (any token)
  token create --label <LABEL> --scope <SCOPE> [--scope <SCOPE>...] [--idempotency-key <KEY>]
                 createClientToken  POST /v1/auth/tokens  (control scope)
  token list [--limit <N>] [--cursor <CURSOR>]
                 listClientTokens   GET  /v1/auth/tokens  (control scope)
  token revoke <TOKEN_ID> [--idempotency-key <KEY>]
                 revokeClientToken  POST /v1/auth/tokens/<TOKEN_ID>/revoke  (control scope)
  project register <ROOT> [--idempotency-key <KEY>]
                 registerProject    POST /v1/projects/register  (control scope)
  project get <PROJECT_ID>
                 getProject         GET  /v1/projects/<PROJECT_ID>  (control or mcp-read)
  workspace resolve --project <PROJECT_ID> <PATH>
                 resolveWorkspace   POST /v1/workspaces/resolve  (control or mcp-write)
  session create --workspace <WORKSPACE_ID> --agent <AGENT_ID> [--task <TASK_ID>]
                 [--agent-name <NAME> --agent-role <ROLE> [--parent-session <SESSION_ID>]]
                 [--idempotency-key <KEY>]
                 createSession      POST /v1/sessions  (control or mcp-write)
  session list --workspace <WORKSPACE_ID> [--limit <N>] [--cursor <CURSOR>]
                 listSessions       GET  /v1/sessions  (control or mcp-read)
  session end [<SESSION_ID>] [--revision <N>] [--reason <TEXT>] [--abandoned]
              [--workspace <WORKSPACE_ID>] [--idempotency-key <KEY>]
                 endSession         POST /v1/sessions/<SESSION_ID>/end  (control or mcp-write)
  task create --project <PROJECT_ID> --title <TITLE> [--workspace <WORKSPACE_ID>]
              [--description <TEXT>] [--idempotency-key <KEY>]
                 createTask         POST /v1/tasks  (control or mcp-write)
  task list --project <PROJECT_ID> [--limit <N>] [--cursor <CURSOR>]
                 listTasks          GET  /v1/tasks  (control or mcp-read)
  task transition [<TASK_ID>] --to <STATE> [--revision <N>] [--evidence <EVIDENCE_ID>...]
                  [--workspace <WORKSPACE_ID>] [--idempotency-key <KEY>]
                 transitionTask     POST /v1/tasks/<TASK_ID>/transition  (control or mcp-write)
  task complete [--evidence <EVIDENCE_ID | last | rN>...] [--revision <N>] [--idempotency-key <KEY>]
                 transitionTask to completed for the context's Task  (control or mcp-write)
  event ingest <ENVELOPE_FILE | -> [--idempotency-key <KEY>]
                 ingestEvent        POST /v1/events  (control or mcp-write)
  event list --project <PROJECT_ID> [--limit <N>] [--cursor <CURSOR>]
                 listEvents         GET  /v1/events  (control scope)
  event get <EVENT_ID>
                 getEvent           GET  /v1/events/<EVENT_ID>  (control scope)
  run [--session <SESSION_ID>] [--workspace <WORKSPACE_ID>] [--task <TASK_ID>]
      [--test [--test-cases <N>] [--test-name <NAME>]] [--test-format cargo|pytest]
      [--digest-only] [--idempotency-key <KEY>] -- <PROGRAM> [<ARG>...]
                 captureEvidence    POST /v1/evidence/capture  (control or mcp-write)
  evidence get <EVIDENCE_ID>
                 getEvidence        GET  /v1/evidence/<EVIDENCE_ID>  (control scope)
  checkpoint create <REQUEST_FILE | -> [--idempotency-key <KEY>]
  checkpoint create [--fact <TEXT> [--evidence <EVIDENCE_ID | last | rN>...] [--supersedes <CLAIM>...]]...
                    [--open <TEXT> [--evidence <EVIDENCE_ID | last | rN>...] [--supersedes <CLAIM>...]]...
                    [--reaffirm <CLAIM> [--evidence <EVIDENCE_ID | last | rN>...]]...
                    [--reaffirm-all [--evidence <EVIDENCE_ID | last | rN>...]]
                    --next <TEXT> [--supersedes <CLAIM>...] [--withdraw <CLAIM>...]
                    [--withdraw-session <K>] [--withdraw-reason <TEXT>]
                    [--objective <TEXT>] [--snapshot <SNAPSHOT_ID>] [--session <SESSION_ID>]
                    [--workspace <WORKSPACE_ID>] [--task <TASK_ID>] [--idempotency-key <KEY>]
                 createCheckpoint   POST /v1/checkpoints  (control or mcp-write)
  checkpoint get <CHECKPOINT_ID>
                 getCheckpoint      GET  /v1/checkpoints/<CHECKPOINT_ID>  (control or mcp-read)
  decide <TEXT> [--rationale <TEXT>] [--evidence <EVIDENCE_ID | last | rN>...]
         [--supersedes <CLAIM>...] [--task <TASK_ID>] [--session <SESSION_ID>]
         [--idempotency-key <KEY>]
                 proposeDecision    POST /v1/decisions  (control or mcp-write)
  recover preview [--task <TASK_ID>] [--workspace <WORKSPACE_ID>] [--text]
                 getRecoveryPreview GET  /v1/tasks/<TASK_ID>/recovery-preview  (control or mcp-read)
  resume [--task <TASK_ID>] [--workspace <WORKSPACE_ID>] [--text [--all | --claims <NUMBERS>]]
  resume [--task <TASK_ID>] [--workspace <WORKSPACE_ID>] --text [--all] --session <K>
  resume [--task <TASK_ID>] [--workspace <WORKSPACE_ID>] --pack [--budget <N> | --claims <NUMBERS>]
         [--query <TEXT>]
                 getTaskCapsule     GET  /v1/tasks/<TASK_ID>/recovery-capsule  (control or mcp-read)
  ledger verify [--project <PROJECT_ID>] [--idempotency-key <KEY>]
                 verifyLedger       POST /v1/verification/ledger  (control or mcp-read)

Current context:
  begin [--project <PROJECT_ID>] [--task <TASK_ID> | --new-task <TITLE> [--description <TEXT>]]
        [--agent <AGENT_ID>] [--agent-name <NAME> --agent-role <ROLE> [--parent-session <SESSION_ID>]]
                 resolveWorkspace, then createTask (--new-task), then createSession;
                 records the current context of this Workspace
  end [--reason <TEXT>] [--revision <N>] [--abandoned]
                 endSession of the current Session; clears it from the context;
                 --abandoned ends a Session someone else left (session.crashed),
                 naming this client's own Session and declared agent as its ender
  context show   prints the current context; no daemon call, no token

Session-start hook (Claude Code, Codex, Cursor):
  hook session-start [--client cursor] [--config-dir <DIR>]
                 reads the SessionStart JSON on standard input; prints one statement
                 and the Context Pack in a fence (for Cursor, as its JSON); read
                 requests only; always exits 0
  hook print-config
                 prints the settings fragment for .claude/settings.local.json
  hook install [--allow-tools]
                 adds that entry to <Workspace root>/.claude/settings.local.json,
                 with env.MEMPROVE_CONFIG_DIR (and with --allow-tools the suggested
                 permissions.allow rules), and mcpServers.memprove to .mcp.json
  hook uninstall removes that entry again; every other value stays, not the file's bytes

Agent evaluation (memprove eval --help):
  eval init | mine | run | ab | report | baseline | gate
                 gives a coding agent (Claude Code, Codex, or any program) this
                 repository's own tasks, each in a Git worktree of its own, and
                 judges each by its check command's exit code alone; compares
                 runs with a committed baseline and fails CI below it; `ab`
                 compares the agent without memory and with memprove's Pack

Completion check (memprove verify --help):
  verify init | run | show | hook
                 runs the checks of this repository's contract
                 (.memprove/verify.json) on a clean copy of the work and judges
                 by their exit codes; work that passes only with its own changes
                 to the protected paths (the tests) is left to a person; the
                 contract is read from the base commit; `hook` is the Claude Code
                 Stop hook that keeps an agent working while a check fails

Install and maintenance:
  init [--client <claude-code|codex|cursor|trae>]... [--operator-token <FILE>] [--allow-tools] [--dry-run]
                 enables memprove in this repository: registers the Project with
                 the operator's token, keeps memprove's files out of Evidence,
                 writes the detected clients' configuration (Claude Code: the hook,
                 .mcp.json, and with --allow-tools the allow rules; Codex:
                 ~/.codex/config.toml and a note in AGENTS.md; Cursor:
                 .cursor/mcp.json and a rule), and runs doctor
  doctor [--json]
                 checks the setup, read-only: one PASS, WARN, or FAIL line per check
                 (builds, daemon, modes, token, configuration directory, context,
                 hook, ledger); exits 1 when a check fails
  import [--file <PATH>]... [--select <NUMBERS | all> [--next <TEXT>] [--dry-run]]
                 lists the statements of CLAUDE.md, AGENTS.md, Cursor's rules, and
                 Claude Code's auto-memory; with --select records them as open items
                 of the current Session, each marked imported and not verified
  backup [--data-dir <PATH>] --out <DIR>
                 offline: copies the data directory, while the daemon is stopped,
                 into a new or empty directory, with SHA256SUMS; no socket, lock,
                 or tmp/; no token
  restore --from <DIR> --data-dir <PATH>
                 offline: checks a backup against its SHA256SUMS, then restores it
                 into a new or empty data directory with the modes it recorded

MCP server (Claude Code):
  mcp serve [--config-dir <DIR>]
                 serves the Model Context Protocol on standard input and output:
                 ten tools, read tools (mcp-read) apart from write tools (mcp-write);
                 no tool runs a command; exits 0 at the end of standard input
  mcp print-config
                 prints the .claude/settings.local.json part (hook, env, the
                 suggested permissions) and the .mcp.json part (the server) that
                 enable memprove; writes nothing

Scopes: control, ingest-only, mcp-read, mcp-write, proxy-client.

Options:
  --data-dir <PATH>    Daemon data directory (default: $MEMPROVE_DATA_DIR, else
                       the one line of <configuration directory>/data-dir)
  --socket <PATH>      Socket path, overriding <data-dir>/memproved.sock
  --token-file <PATH>  File holding the bearer token; it must not be readable
                       by group or others (chmod 600); without it,
                       $MEMPROVE_TOKEN, else the file $MEMPROVE_TOKEN_FILE
                       names, else <configuration directory>/token
  -h, --help           Print this help
  -V, --version        Print the version and the build: the first 12
                       characters of the commit it was built from, with
                       -dirty when the worktree had changes, or unknown

`memprove begin` resolves the Workspace containing the current directory,
creates a Session continuing the Task (--task, or a new Task titled
--new-task, else the context's Task), moves a proposed or ready Task to
in_progress, and records the Project, Workspace, agent, Task, and Session
identities as the current context of that Workspace. It refuses (exit 1)
while the context's Session is still active (end it with `memprove end
--reason <TEXT>`; it is never ended for you) and for a completed or
cancelled Task (use --new-task). --project is needed the first time; later
it comes from the context. --agent defaults to the context's agent, else a
new identity. --agent-name, --agent-role (orchestrator, sub_agent, or human),
and --parent-session declare the Session's agent; each defaults to
$MEMPROVE_AGENT_NAME, $MEMPROVE_AGENT_ROLE, or $MEMPROVE_PARENT_SESSION
(an empty one is unset), and when none of the three is given, begin reuses
the context's agent, whole. The context lives under $MEMPROVE_CONFIG_DIR (default
~/.memprove/config when it exists, else $XDG_CONFIG_HOME/memprove, else
~/.config/memprove), one 0600 file per
Workspace root, never inside the Workspace, and holds no token. `run`,
`checkpoint create`, `recover preview`, `resume`, `task transition`, `task
complete`, `session end`, and `end` take omitted IDs (and the --revision of
the context's Task or Session) from the context of the Workspace containing
the current directory; an option given explicitly wins. `run` records its
Snapshot, Evidence, and result as the context's latest; `end` and `session
end` of the context's Session clear the Session. `context show` prints the
context: Project, Workspace, agent, Task (title, state, revision), Session,
latest Snapshot and Evidence. With $MEMPROVE_CLIENT_SESSION set to 1 to 128
characters of A-Z, a-z, 0-9, _, and -, each client session (a Claude Code
session) of a Workspace root has its own context file and its own record of
the last Pack, under contexts/<sha256(root)>/; another value is ignored, with
a warning, and the directory's context is used. A client session with no
context of its own yet `begin`s the Task of the last Pack it was given.

The bearer token comes from --token-file, else $MEMPROVE_TOKEN, else the
file named by $MEMPROVE_TOKEN_FILE. Tokens are never accepted as
command-line arguments. `token create` prints the new secret once; it cannot
be shown again. A random Idempotency-Key is used when none is given.
Relative <ROOT> and <PATH> arguments are made absolute against the current
directory before they are sent. `event ingest` sends the Event envelope JSON
read from <ENVELOPE_FILE>, or from standard input for `-`, unchanged.
--revision is the expected_revision last read; <STATE> is one of proposed,
ready, in_progress, blocked, completed, cancelled. `--to completed` needs
one --evidence per completion Evidence: each must be a PASS command or test
of the Task that still holds against the Workspace (--workspace, else the
context's, else the one the Recovery Preview would probe); otherwise 409
evidence_stale. --workspace applies only to `--to completed`. `task
complete` is `--to completed` for the context's Task, revision, and
Workspace, citing every citable passed run of the current state (the runs
`run` lists as PASS) unless --evidence is given, and the latest run when
none passed; it says on standard error which labels it cited. Without
--evidence it is refused with exit 2 and no request while the latest run of
some command (same argv) in this state did not pass: it names those runs;
rerun the command until it passes, or cite runs with --evidence.
`--evidence last` names the latest run anywhere --evidence is accepted by
`task complete` and `checkpoint create`. Obtain the first control token with
`memproved bootstrap`.

`run` executes <PROGRAM> here, in this environment minus MEMPROVE_TOKEN
(every other variable, MEMPROVE_* included, is inherited), with this
standard input; memproved never runs it. Its argv is recorded: never put
a secret in it. Its exit code, start and end times, the SHA-256 of
its complete output, and the last 4096 characters of each stream are
submitted as Evidence, and memproved seals them into a new snapshot of the
Workspace's repository. The command's own output goes to standard error;
standard output carries the recorded Evidence. With --test the result is a
test run; it passes only when the exit code is 0 and --test-cases is above 0.
With --digest-only only the SHA-256 of each stream is recorded, not its
text. A program that cannot be started is recorded as UNAVAILABLE, with the
launch error and exit code -1; it never counts as passed. With
--test-format cargo the run is a test run whose case count is the passed
plus failed tests of every line that starts with `test result:`, outside
the captured output libtest prints for tests; output it cannot read
records no count, which never passes. With --test-format pytest the case
count is the passed plus failed plus error cases of pytest's summary on the
last line of its output (`=== 1 failed, 4 passed, 2 skipped in 0.3s ===`;
skipped, xfailed, xpassed and deselected are not cases); when pytest
printed no summary (`-qq`, or `-q` with another `-q` in addopts) and the
last line is only progress marks (`..... [100%]`), the dots and the F and E
marks are counted (F and E are failures; s, x, and X are not cases) and the
run says counted from the progress line; the run passes only
when failed and errors are 0 and the exit code is 0; any other last line
records no count, which never passes; --test-cases given with it wins over
the count. `run` exits with the
command's exit code (128 + N for signal N); it exits 125 when the command
could not be started or its result could not be recorded, and says why on
standard error. When the result was recorded, the last line of standard
error sums it up: the status, the case count of a test run, and the
evidence_id.

`checkpoint create` sends the CreateCheckpointRequest JSON read from
<REQUEST_FILE>, or from standard input for `-`, unchanged; its statements
cite Evidence IDs of the snapshot. Without a file it builds the request:
each --fact is a verified_fact in verified_completed_work and needs at
least one --evidence of a passed test run; each --open is an unknown entry
in open_items (record a failing test this way, citing its run with
--evidence); --next is the recommendation in next_action. Each --evidence
belongs to the closest --fact or --open before it; a --fact without one
cites the context's latest run, an --open without one cites no Evidence.
The snapshot defaults to the context's latest, so a
Checkpoint cites Evidence of the latest run and of the earlier runs of the
same repository state that `run` carried into it (same Task and Workspace,
same commit, index, worktree, and branch, and no untracked file); cite
those by the label `run` printed (--evidence r2). The objective defaults to
the context's Task title. Earlier claims stay listed by `resume`, so a new
Checkpoint records only what is new: --supersedes <CLAIM> after a --fact,
--open, or --next says that statement is the new version of <CLAIM> (a fact
that completes an open item, too); --withdraw <CLAIM> says <CLAIM> no longer
holds and nothing replaces it, and --withdraw-reason <TEXT> says why (needed
when a withdrawn claim is a fact); --reaffirm <CLAIM> records the active fact
<CLAIM> again with the same text on this Checkpoint's Evidence (the latest
run, or the --evidence after it) and supersedes it. --reaffirm-all
reaffirms every active fact that is not verified and that the command
names nowhere else: with --evidence after it, on that Evidence; without,
only on the latest run in the current repository state of each command
its Evidence ran, of the same kind (a test run for a test run), when
every such run passed (otherwise the fact is skipped, and standard error
says why); standard error then gives each reaffirmation's actual verdict. <CLAIM> is a claim number from
`resume --text` (3 or #3) or a claim ID. Numbers and --reaffirm are
resolved through the Task Capsule read just before sending; when the
Capsule is tampered, or does not list a number, nothing is sent (exit 1).

`decide <TEXT>` records a Decision of the Task (the context's Task and
Session unless --task and --session are given): --rationale says why,
--evidence cites Evidence of the Task it rests on (none by default), and
--supersedes names earlier claims it replaces, an earlier Decision too.
There is no accept step; a Decision is in force until superseded or
withdrawn, and its verdict only says whether its Evidence still holds.

`recover preview` prints the Recovery Preview JSON of the Task's latest
Checkpoint exactly as received: whether its Evidence still holds against the
Workspace --workspace names, by default the Workspace of the Checkpoint's
snapshot. With --text it prints one human-readable sentence instead, plus
one sentence for each run that is still fresh but did not pass
(evidence_not_passed); the sentences are display only and the JSON is the
judgement.

`resume` prints the Task Capsule JSON exactly as received: every statement
of every Checkpoint of the Task and every Decision, numbered #1, #2, … in
ledger order, each judged against the Workspace --workspace names (by
default the latest Checkpoint's snapshot Workspace), with what superseded
it, the reruns, the changed files since each commit the Evidence is bound
to, and the continuation items in a fixed order. With --text it prints one
line per continuation item from fixed templates, showing the numbers;
everything an agent wrote (statement text, argv, file names, reasons) is
quoted in 「」, and \"verified\" outside 「」 appears only on the Task line
or a fact whose verdict is verified; an open item, a next action, and a
Decision show no verdict, only \"no evidence cited\" or each cited Evidence's own
result and whether its commit is still the current state; the first line
counts the withdrawn facts,
and a withdrawn statement shows its reason; a line after the Task line
counts the Sessions (\"Sessions:\": all, ended normally, ended abandoned,
not ended); a Session the ledger records no end for reads \"not ended\" with
the time the ledger last recorded one of its Events, and the Session the
context file of this directory names is labelled
\"the Session this directory's context file records\" (it need not be yours). Superseded and
withdrawn statements are not listed one by one: one line after the other
statements counts each kind and names their numbers; --text --all lists
them too, one line each. The lines are display only; the JSON is the
judgement. Run it first when taking over a
Task; `recover preview` answers only for the latest Checkpoint.
--text --claims 3,5-7 prints only the lines of the claims named, in full,
superseded and withdrawn ones too. --pack prints the Context Pack instead:
the Capsule as numbered lines within --budget UTF-16 code units (default
9000, from 1000 through 1000000), leaving out file lists and bodies first
when it must, with a last line holding its SHA-256 (pack_digest);
--pack --claims 3,5-7 prints the full Pack lines of the claims named;
--pack --query <TEXT> lists only the claims the query matches, best first
(--query-profile search.v2, the default, or search.v1).

`ledger verify` recomputes the Project's Event chain and every Evidence,
snapshot, and Checkpoint digest, and prints how many records it checked,
the chain-head digest, and the first record that does not hold. It writes
nothing; its Idempotency-Key is required by the contract but not recorded.
Without --project it verifies the Project of the current context (inside a
Workspace with one); an explicit --project wins; with neither it is a usage
error.

Exit status: 0 success, 1 Problem response, `begin` refusal, or a claim
             number that cannot be resolved, 2 usage error,
             3 daemon unreachable, 4 response violates the contract,
             5 `ledger verify` found a record that does not hold,
             6 response larger than the CLI accepts (16 MiB for
             `resume`, 1 MiB otherwise);
             `run`: the command's own exit code, or 125 (see above).";

/// What `resume` prints besides the JSON and the `--text` lines (P4-C).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CapsuleView {
    /// The JSON, or the `--text` lines.
    #[default]
    Plain,
    /// `--pack [--budget N]`: the Context Pack within `budget` UTF-16 code
    /// units (ADR 0014 E1, E2).
    Pack {
        /// The budget.
        budget: usize,
    },
    /// `--text --claims <NUMBERS>`: the `--text --all` line of each claim
    /// whose number one of these inclusive ranges holds.
    Claims(Vec<(u64, u64)>),
    /// `--pack --claims <NUMBERS>` (P4-C2 revision 5): the full Pack line of
    /// each claim whose number one of these inclusive ranges holds, after
    /// the base lines they name, with no budget.
    PackClaims(Vec<(u64, u64)>),
    /// `--pack --query <TEXT> [--budget N]` (U3 G4, Owner O8): the query
    /// Pack of `query` within `budget`.
    PackQuery {
        /// The budget.
        budget: usize,
        /// The query text, checked by `check_pack_query`.
        query: String,
    },
    /// `--text [--all] --session <k>` (U8 A5, Owner O4): the `--text` lines
    /// of `Session k`'s statements only.
    SessionText(u64),
}

/// One Local Control API request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Operation being called.
    pub operation: OperationId,
    /// Request target: path plus optional query.
    pub target: String,
    /// JSON body, if the operation has one.
    pub body: Option<String>,
    /// Caller-chosen `Idempotency-Key`; mutating calls get a random one when
    /// absent.
    pub idempotency_key: Option<String>,
    /// Print a one-sentence summary of a successful response instead of its
    /// JSON (`recover preview --text`, `resume --text`).
    pub summary: bool,
    /// With [`Request::summary`], list every continuation item, the
    /// superseded and withdrawn claims too (`resume --text --all`, P4-A).
    pub all_items: bool,
    /// What `resume` prints instead of the JSON or the `--text` lines: the
    /// Context Pack (`--pack`), or the lines of given claim numbers
    /// (`--text --claims`, P4-C).
    pub capsule_view: CapsuleView,
    /// A body still to be built from claim numbers or `--reaffirm`, which
    /// resolve through the current Task Capsule before the request is sent
    /// (P3-C); `body` is `None` until then.
    pub pending: Option<claims::Draft>,
}

impl Request {
    /// A request of `operation` to `target` with no body, no key, and no
    /// flags; the callers fill in what the operation takes. U17 (M1 O4):
    /// public for `init`'s `registerProject`.
    #[must_use]
    pub fn bare(operation: OperationId, target: String) -> Self {
        Self {
            operation,
            target,
            body: None,
            idempotency_key: None,
            summary: false,
            all_items: false,
            capsule_view: CapsuleView::Plain,
            pending: None,
        }
    }

    /// Whether the operation requires an `Idempotency-Key`.
    #[must_use]
    pub fn needs_idempotency_key(&self) -> bool {
        matches!(
            self.operation,
            OperationId::CreateClientToken
                | OperationId::RevokeClientToken
                | OperationId::RegisterProject
                | OperationId::CreateSession
                | OperationId::EndSession
                | OperationId::CreateTask
                | OperationId::TransitionTask
                | OperationId::IngestEvent
                | OperationId::CaptureEvidence
                | OperationId::CreateCheckpoint
                | OperationId::VerifyLedger
                | OperationId::ProposeDecision
        )
    }
}

/// A parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// Print the general usage.
    Help,
    /// U1 (E1): print [`VERSION_LINE`] (`--version` or `-V`, alone).
    Version,
    /// Print the help of these commands (`<command> --help`, P3-A): one
    /// command, or every command of a group such as `token`.
    CommandHelp(Vec<&'static help::CommandHelp>),
    /// Call one operation over `socket`.
    Call {
        /// Socket path.
        socket: PathBuf,
        /// Request to send.
        request: Request,
        /// `--token-file`, if given.
        token_file: Option<PathBuf>,
        /// What a successful or refused reply changes in the context.
        follow: Follow,
    },
    /// Start a Session here and record the current context (`begin`).
    Begin {
        /// Socket path.
        socket: PathBuf,
        /// What to begin.
        spec: BeginSpec,
        /// `--token-file`, if given.
        token_file: Option<PathBuf>,
    },
    /// Print the current context (`context show`, P2-H); no daemon call.
    ShowContext(context::Context),
    /// P4-E: `hook print-config`, `hook install`, or `hook uninstall`; no
    /// daemon call, no token. (`hook session-start` never reaches the
    /// parser: see [`hook_session_start_requested`].)
    Hook(HookCommand),
    /// P4-G: `mcp serve`, the MCP server on standard input and output (ADR
    /// 0014 E7), or `mcp print-config`; no option, no token or path on the
    /// command line.
    Mcp(McpCommand),
    /// U1 (E3): `doctor`, a read-only self-check.
    Doctor(doctor::DoctorSpec),
    /// U17 (M1 O4): `init`, which enables memprove in the repository of
    /// the current directory; one daemon call (`registerProject`), then
    /// `doctor`'s.
    Init(init::InitSpec),
    /// U1 (E4): `backup`, offline; no daemon call, no token.
    Backup {
        /// The data directory to copy.
        data_dir: PathBuf,
        /// The new or empty backup directory.
        out: PathBuf,
    },
    /// U1 (E4): `restore`, offline; no daemon call, no token.
    Restore {
        /// The backup directory.
        from: PathBuf,
        /// The new or empty data directory.
        data_dir: PathBuf,
    },
    /// Run a command here and submit its result (`captureEvidence`).
    Run {
        /// Socket path.
        socket: PathBuf,
        /// What to run and where to record it.
        spec: RunSpec,
        /// `--token-file`, if given.
        token_file: Option<PathBuf>,
    },
}

/// P4-E: the `hook` commands that manage the settings entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookCommand {
    /// Print the settings fragment.
    PrintConfig,
    /// Add the entry to `<Workspace root>/.claude/settings.local.json`; U5
    /// P3: with `env.MEMPROVE_CONFIG_DIR`, and with `allow_tools`
    /// (`--allow-tools`) the suggested `permissions.allow` rules; U5 Z-F
    /// round 1 (S1): `mcpServers.memprove` goes into `<Workspace
    /// root>/.mcp.json`, not the settings file.
    Install {
        /// `--allow-tools`.
        allow_tools: bool,
    },
    /// Remove it again.
    Uninstall,
}

/// P4-G: the `mcp` commands (ADR 0014 E7.3, E7.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpCommand {
    /// Serve the protocol on standard input and output.
    Serve,
    /// Print the `.mcp.json` fragment; write nothing.
    PrintConfig,
}

/// P4-G: the `mcp` commands: no option (the global ones included: the
/// server takes its paths and token from its environment), no argument.
fn mcp_command(
    words: &[&str],
    options: &[(&'static str, OsString)],
    trailing: Option<&Vec<OsString>>,
) -> Result<Invocation, UsageError> {
    let command = match words {
        ["mcp", "serve"] => McpCommand::Serve,
        ["mcp", "print-config"] => McpCommand::PrintConfig,
        ["mcp", "serve", ..] => return Err(usage("mcp serve takes no argument")),
        ["mcp", "print-config", ..] => return Err(usage("mcp print-config takes no argument")),
        _ => return Err(usage("mcp takes serve or print-config")),
    };
    if trailing.is_some() {
        return Err(usage("`--` applies only to `run`"));
    }
    if let Some((name, _)) = options.first() {
        return Err(usage(format!("{name} does not apply to this command")));
    }
    Ok(Invocation::Mcp(command))
}

/// The commands that call no daemon operation of their own: `context
/// show`, the `hook` commands, and (P4-G) the `mcp` commands; `None` for
/// every other command.
fn local_command(
    words: &[&str],
    options: &[(&'static str, OsString)],
    trailing: Option<&Vec<OsString>>,
    lookup: &ContextLookup,
    env_data_dir: Option<&OsString>,
) -> Option<Result<Invocation, UsageError>> {
    match words.first() {
        Some(&"context") if words == ["context", "show"] => {
            Some(show_context(options, trailing, lookup))
        }
        Some(&"hook") => Some(hook_command(words, options, trailing)),
        Some(&"mcp") => Some(mcp_command(words, options, trailing)),
        Some(&("backup" | "restore")) => {
            Some(offline_command(words, options, trailing, env_data_dir))
        }
        Some(&"doctor") => Some(doctor_command(words, options, trailing, env_data_dir)),
        Some(&"init") => Some(init_command(words, options, trailing)),
        _ => None,
    }
}

/// U17 (M1 O4): `init [--client <NAME>]... [--operator-token <FILE>]
/// [--allow-tools] [--dry-run]` (U22: `--allow-tools`); no global option (the daemon's location and the agent's
/// token come from the configuration directory alone).
fn init_command(
    words: &[&str],
    options: &[(&'static str, OsString)],
    trailing: Option<&Vec<OsString>>,
) -> Result<Invocation, UsageError> {
    if trailing.is_some() {
        return Err(usage("`--` applies only to `run`"));
    }
    if words.len() > 1 {
        return Err(usage("init takes no argument"));
    }
    if let Some((name, _)) = options
        .iter()
        .find(|(name, _)| GLOBAL_OPTIONS.contains(name))
    {
        return Err(usage(format!(
            "{name} does not apply to init, which reads the daemon location and the token \
             from the installed configuration"
        )));
    }
    check_allowed(
        options,
        &[
            OPTION_CLIENT,
            OPTION_OPERATOR_TOKEN,
            FLAG_ALLOW_TOOLS,
            FLAG_DRY_RUN,
        ],
    )?;
    let mut clients = Vec::new();
    for (name, value) in options {
        if *name == OPTION_CLIENT {
            let text = value.to_string_lossy();
            let client = init::Client::parse(&text).ok_or_else(|| {
                usage(format!(
                    "--client takes {}",
                    init::Client::ALL.map(init::Client::name).join(", ")
                ))
            })?;
            if !clients.contains(&client) {
                clients.push(client);
            }
        }
    }
    let operator_token = options
        .iter()
        .find(|(name, _)| *name == OPTION_OPERATOR_TOKEN)
        .map(|(_, value)| PathBuf::from(value))
        .filter(|path| !path.as_os_str().is_empty());
    Ok(Invocation::Init(init::InitSpec {
        clients,
        operator_token,
        dry_run: options.iter().any(|(name, _)| *name == FLAG_DRY_RUN),
        allow_tools: options.iter().any(|(name, _)| *name == FLAG_ALLOW_TOOLS),
    }))
}

/// U1 (E3): `doctor [--json]` with the global options.
fn doctor_command(
    words: &[&str],
    options: &[(&'static str, OsString)],
    trailing: Option<&Vec<OsString>>,
    env_data_dir: Option<&OsString>,
) -> Result<Invocation, UsageError> {
    if trailing.is_some() {
        return Err(usage("`--` applies only to `run`"));
    }
    if words.len() > 1 {
        return Err(usage("doctor takes no argument"));
    }
    check_allowed(options, &[FLAG_JSON])?;
    let path = |name: &str| {
        options
            .iter()
            .find(|(seen, _)| *seen == name)
            .map(|(_, value)| PathBuf::from(value))
            .filter(|path| !path.as_os_str().is_empty())
    };
    Ok(Invocation::Doctor(doctor::DoctorSpec {
        data_dir: path("--data-dir").or_else(|| {
            env_data_dir
                .filter(|dir| !dir.is_empty())
                .map(PathBuf::from)
        }),
        socket: path("--socket"),
        token_file: path("--token-file"),
        json: options.iter().any(|(name, _)| *name == FLAG_JSON),
    }))
}

/// U1 (E4): `backup` and `restore`, which take only their own options and
/// `--data-dir`: `backup` the data directory to copy (else
/// `$MEMPROVE_DATA_DIR`), `restore` the one to restore into, given
/// explicitly.
fn offline_command(
    words: &[&str],
    options: &[(&'static str, OsString)],
    trailing: Option<&Vec<OsString>>,
    env_data_dir: Option<&OsString>,
) -> Result<Invocation, UsageError> {
    if trailing.is_some() {
        return Err(usage("`--` applies only to `run`"));
    }
    let allowed: &[&str] = match words {
        ["backup"] => &["--data-dir", "--out"],
        ["restore"] => &["--data-dir", "--from"],
        [command, ..] => return Err(usage(format!("{command} takes no argument"))),
        [] => unreachable!("called for a command word"),
    };
    if let Some((name, _)) = options.iter().find(|(name, _)| !allowed.contains(name)) {
        return Err(usage(format!("{name} does not apply to {}", words[0])));
    }
    let path = |name: &str| {
        options
            .iter()
            .find(|(seen, _)| *seen == name)
            .map(|(_, value)| PathBuf::from(value))
            .filter(|path| !path.as_os_str().is_empty())
    };
    if words == ["backup"] {
        let out = path("--out").ok_or_else(|| usage("backup requires --out <DIR>"))?;
        let data_dir = path("--data-dir")
            .or_else(|| {
                env_data_dir
                    .filter(|dir| !dir.is_empty())
                    .map(PathBuf::from)
            })
            .ok_or_else(|| {
                usage(format!(
                    "backup requires a data directory: --data-dir <PATH> or {DATA_DIR_ENV}"
                ))
            })?;
        return Ok(Invocation::Backup { data_dir, out });
    }
    let from = path("--from").ok_or_else(|| usage("restore requires --from <DIR>"))?;
    let data_dir = path("--data-dir").ok_or_else(|| {
        usage("restore requires --data-dir <PATH>, the new or empty directory to restore into")
    })?;
    Ok(Invocation::Restore { from, data_dir })
}

/// P4-E (Owner condition o): what the arguments of `hook session-start`
/// ask for; it always exits 0 and so never goes through the parser's usage
/// errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookStart {
    /// Exactly `hook session-start`, or (U7 P2, Owner O4) `hook
    /// session-start --config-dir <DIR>` with the directory.
    Run(Option<OsString>),
    /// U24 (H2): `hook session-start --client cursor`, with or without
    /// `--config-dir <DIR>` after it: Cursor's `sessionStart` input, and the
    /// answer as Cursor's JSON.
    Cursor(Option<OsString>),
    /// `hook session-start` with anything else, and why (U8 K1).
    Refused(ConfigDirRefusal),
}

/// U8 K1 (U7 V-N1): why the arguments of `hook session-start` or `mcp serve`
/// are not the accepted `<command>` or `<command> --config-dir <DIR>`; the
/// texts that refuse them say so instead of blaming `--config-dir` itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDirRefusal {
    /// A global option (`--data-dir`, `--socket`, `--token-file`) is among
    /// the arguments; neither command takes one.
    GlobalOption(&'static str),
    /// `--config-dir` is the last argument.
    MissingDirectory,
    /// `--config-dir` is followed by an empty directory.
    EmptyDirectory,
    /// U9 K3 (U8 V-N10): the directory is spelled `--config-dir=<DIR>`, one
    /// argument; the commands take it as two.
    EqualsForm,
    /// Anything else.
    Other,
}

/// The options every command that reaches the daemon takes, and which
/// `hook session-start` and `mcp serve` do not.
const GLOBAL_OPTIONS: [&str; 3] = ["--data-dir", "--socket", "--token-file"];

/// P4-E (Owner condition o): whether the arguments ask for `hook
/// session-start`: [`HookStart::Run`] when they are exactly `hook
/// session-start` (U7 P2: or that and `--config-dir <DIR>`, a non-empty
/// directory), [`HookStart::Refused`] when they name it with anything else,
/// and `None` when they do not name it or ask for help.
#[must_use]
pub fn hook_session_start_requested(args: &[OsString]) -> Option<HookStart> {
    if help_for(args).is_some() {
        return None;
    }
    let words = command_words(args);
    (words.len() >= 2 && words[0] == "hook" && words[1] == "session-start").then(|| match args {
        [first, second, option, client, rest @ ..]
            if *option == hook::CURSOR_CLIENT_ARGUMENTS[0]
                && *client == hook::CURSOR_CLIENT_ARGUMENTS[1] =>
        {
            let without: Vec<OsString> = [first.clone(), second.clone()]
                .into_iter()
                .chain(rest.iter().cloned())
                .collect();
            match config_dir_argument(&without, "hook", "session-start") {
                HookStart::Run(dir) => HookStart::Cursor(dir),
                refused => refused,
            }
        }
        _ => config_dir_argument(args, "hook", "session-start"),
    })
}

/// U7 P2 (D2 F13, Owner O4): the option a hook or MCP server entry passes
/// its configuration directory with; it wins over `MEMPROVE_CONFIG_DIR`.
pub const CONFIG_DIR_OPTION: &str = "--config-dir";

/// U7 P2: [`HookStart::Run`] without a directory when `args` are exactly
/// `<first> <second>`, with `DIR` when they are `<first> <second>
/// --config-dir <DIR>` with a non-empty `DIR`, and [`HookStart::Refused`]
/// for anything else.
fn config_dir_argument(args: &[OsString], first: &str, second: &str) -> HookStart {
    match args {
        [a, b] if a == first && b == second => HookStart::Run(None),
        [a, b, option, dir]
            if a == first && b == second && option == CONFIG_DIR_OPTION && !dir.is_empty() =>
        {
            HookStart::Run(Some(dir.clone()))
        }
        _ => HookStart::Refused(config_dir_refusal(args, first, second)),
    }
}

/// U8 K1 (U7 V-N1): the real reason `args` are not the accepted form of
/// `<first> <second>`, the global option first, then a missing or an empty
/// directory after `--config-dir`.
fn config_dir_refusal(args: &[OsString], first: &str, second: &str) -> ConfigDirRefusal {
    if let Some(name) = GLOBAL_OPTIONS
        .into_iter()
        .find(|name| args.iter().any(|argument| argument == name))
    {
        return ConfigDirRefusal::GlobalOption(name);
    }
    match args {
        [a, b, option] if a == first && b == second && option == CONFIG_DIR_OPTION => {
            ConfigDirRefusal::MissingDirectory
        }
        [a, b, option, dir]
            if a == first && b == second && option == CONFIG_DIR_OPTION && dir.is_empty() =>
        {
            ConfigDirRefusal::EmptyDirectory
        }
        [a, b, option] if a == first && b == second && is_equals_form(option) => {
            ConfigDirRefusal::EqualsForm
        }
        _ => ConfigDirRefusal::Other,
    }
}

/// U9 K3 (U8 V-N10): whether `argument` is `--config-dir=<anything>`.
fn is_equals_form(argument: &OsString) -> bool {
    argument
        .to_str()
        .and_then(|argument| argument.strip_prefix(CONFIG_DIR_OPTION))
        .is_some_and(|rest| rest.starts_with('='))
}

/// U8 K1 (U7 V-N1): the usage error of `mcp serve` given `--config-dir` in a
/// form `mcp serve --config-dir <DIR>` is not (a global option, no or an
/// empty directory, another argument); `None` when the arguments are not
/// `mcp serve`, do not name `--config-dir`, or are that form.
fn mcp_serve_config_dir_error(args: &[OsString]) -> Option<String> {
    let words = command_words(args);
    if words.len() < 2 || words[0] != "mcp" || words[1] != "serve" {
        return None;
    }
    if !args
        .iter()
        .any(|argument| argument == CONFIG_DIR_OPTION || is_equals_form(argument))
    {
        return None;
    }
    match config_dir_argument(args, "mcp", "serve") {
        HookStart::Run(_) | HookStart::Cursor(_) => None,
        HookStart::Refused(ConfigDirRefusal::GlobalOption(name)) => Some(format!(
            "{name} does not apply to mcp serve; {CONFIG_DIR_OPTION} <DIR> goes right after \
             mcp serve, with no global option"
        )),
        HookStart::Refused(ConfigDirRefusal::MissingDirectory) => {
            Some(format!("{CONFIG_DIR_OPTION} requires a value"))
        }
        HookStart::Refused(ConfigDirRefusal::EmptyDirectory) => Some(format!(
            "{CONFIG_DIR_OPTION} requires a non-empty directory"
        )),
        HookStart::Refused(ConfigDirRefusal::EqualsForm) => Some(format!(
            "{CONFIG_DIR_OPTION}=<DIR> is not accepted; write {CONFIG_DIR_OPTION} <DIR> as two \
             arguments"
        )),
        HookStart::Refused(ConfigDirRefusal::Other) => Some(format!(
            "mcp serve takes no argument besides {CONFIG_DIR_OPTION} <DIR>"
        )),
    }
}

/// U7 P2 (Owner O4): the directory of `mcp serve --config-dir <DIR>`, when
/// the arguments are exactly that; plain `mcp serve` and every other form
/// go through the parser.
#[must_use]
pub fn mcp_serve_config_dir(args: &[OsString]) -> Option<OsString> {
    match config_dir_argument(args, "mcp", "serve") {
        HookStart::Run(dir) => dir,
        HookStart::Cursor(_) | HookStart::Refused(_) => None,
    }
}

/// P4-G (ADR 0014 E7.3): whether the arguments name an `mcp` command, its
/// help included. Such a command reads no context and prints no warning
/// before it runs: the parser takes nothing from the context for it, and
/// `mcp serve` resolves everything per tool call.
#[must_use]
pub fn mcp_requested(args: &[OsString]) -> bool {
    command_words(args)
        .first()
        .is_some_and(|word| word == "mcp")
}

/// The `hook` commands other than `session-start`: no option, no argument.
fn hook_command(
    words: &[&str],
    options: &[(&'static str, OsString)],
    trailing: Option<&Vec<OsString>>,
) -> Result<Invocation, UsageError> {
    let command = match words {
        ["hook", "print-config"] => HookCommand::PrintConfig,
        ["hook", "install"] => HookCommand::Install {
            allow_tools: options.iter().any(|(name, _)| *name == FLAG_ALLOW_TOOLS),
        },
        ["hook", "uninstall"] => HookCommand::Uninstall,
        ["hook", "session-start", ..] => {
            return Err(usage("hook session-start takes no argument and no option"));
        }
        _ => {
            return Err(usage(
                "hook takes session-start, print-config, install, or uninstall",
            ));
        }
    };
    if trailing.is_some() {
        return Err(usage("`--` applies only to `run`"));
    }
    if let Some((name, _)) = options.iter().find(|(name, _)| {
        !(*name == FLAG_ALLOW_TOOLS && matches!(command, HookCommand::Install { .. }))
    }) {
        return Err(usage(format!("{name} does not apply to this command")));
    }
    Ok(Invocation::Hook(command))
}

/// What the CLI does with the context after a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Follow {
    /// Nothing.
    Nothing,
    /// The Session ended; clear it when it is the context's.
    SessionEnded {
        /// The Session ended.
        session_id: String,
        /// U10 T7 (Owner O4): `session end <ID> --abandoned` without
        /// `--revision`; the request has no body yet, and `send` makes it
        /// once it has read the Session's current revision.
        unread: Option<Box<EndLater>>,
    },
    /// The Task moved; keep its new revision when it is the context's.
    TaskTransitioned {
        /// The Task transitioned.
        task_id: String,
    },
    /// `task complete` (P2-H): as [`Follow::TaskTransitioned`], and explain
    /// an `evidence_stale` refusal.
    TaskCompleted {
        /// The Task completed.
        task_id: String,
        /// P3-L L11: the labels of the runs cited by default, when
        /// `--evidence` was not given and the context lists passed runs.
        cited: Vec<String>,
        /// U4 Y1: a usage error in the Evidence, kept for after the
        /// Session check (see [`parse_args_deferring`]); `None` otherwise.
        refusal: Option<String>,
    },
    /// A built Checkpoint with `--fact` statements: explain an
    /// `invalid_request` refusal.
    CheckpointFacts,
}

/// U10 T7 (Owner O4; D3 F24): what the body of `session end <ID>
/// --abandoned` needs besides the Session's current revision, which `send`
/// reads first (`listSessions` of the Workspace) when `--revision` was not
/// given and the context does not name that Session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndLater {
    /// `--reason`.
    pub reason: Option<String>,
    /// Who ends it (U9 A7).
    pub ended_by: Option<memprove_domain::SessionEndedBy>,
    /// The Workspace of `--workspace` (U11 N2), else of the current context,
    /// when there is one; else the one every context of this Workspace root
    /// records.
    pub workspace_id: Option<String>,
}

/// The Task a `begin` Session continues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginTask {
    /// An existing Task.
    Existing(String),
    /// A new Task with this title and optional description.
    New {
        /// Title.
        title: String,
        /// Description.
        description: Option<String>,
    },
}

/// What `memprove begin` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginSpec {
    /// Project of the Workspace.
    pub project_id: String,
    /// Task to continue.
    pub task: BeginTask,
    /// Agent identity; a new one when `None`.
    pub agent_id: Option<String>,
    /// U8 A3 (Owner O4): the agent the Session declares; none when no
    /// option, environment variable, or context names one.
    pub agent: Option<memprove_domain::SessionAgent>,
}

/// U8 A3 (Owner O4): the environment variable of the default of
/// `--agent-name`.
pub const AGENT_NAME_ENV: &str = "MEMPROVE_AGENT_NAME";
/// U8 A3: the environment variable of the default of `--agent-role`.
pub const AGENT_ROLE_ENV: &str = "MEMPROVE_AGENT_ROLE";
/// U8 A3: the environment variable of the default of `--parent-session`.
pub const PARENT_SESSION_ENV: &str = "MEMPROVE_PARENT_SESSION";

/// U8 A3 (Owner O4): the values of [`AGENT_NAME_ENV`], [`AGENT_ROLE_ENV`],
/// and [`PARENT_SESSION_ENV`]; an empty value is none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentEnv {
    /// `MEMPROVE_AGENT_NAME`.
    pub name: Option<String>,
    /// `MEMPROVE_AGENT_ROLE`.
    pub role: Option<String>,
    /// `MEMPROVE_PARENT_SESSION`.
    pub parent_session: Option<String>,
}

impl AgentEnv {
    /// The three variables as the environment holds them.
    #[must_use]
    pub fn of(
        name: Option<OsString>,
        role: Option<OsString>,
        parent_session: Option<OsString>,
    ) -> Self {
        let text = |value: Option<OsString>| {
            value
                .map(|value| value.to_string_lossy().into_owned())
                .filter(|value| !value.is_empty())
        };
        Self {
            name: text(name),
            role: text(role),
            parent_session: text(parent_session),
        }
    }
}

/// U8 A3 (Owner O4): the agent a new Session declares: each of its name,
/// role, and parent Session from its option, else its environment variable
/// (an empty one is unset). The declaration is taken as a whole (U8 S-F
/// round 1, B1): only when no option and no variable gives any of the three
/// does `begin` reuse the agent the context file remembers, all three
/// members of it, so nothing of an earlier agent is mixed into a new one. A
/// name needs a role and a role a name; a parent needs both. Each value is
/// checked here, so a mistake is a usage error and no request is sent; the
/// error never repeats a value.
fn agent_of(
    options: &[(&'static str, OsString)],
    env: &AgentEnv,
    context: Option<&context::Context>,
) -> Result<Option<memprove_domain::SessionAgent>, UsageError> {
    let given =
        |option: &str, env: &Option<String>| text_option(options, option).or_else(|| env.clone());
    let mut name = given("--agent-name", &env.name);
    let mut role = given("--agent-role", &env.role);
    let mut parent = given("--parent-session", &env.parent_session);
    if let Some(context) = context.filter(|_| name.is_none() && role.is_none() && parent.is_none())
    {
        name.clone_from(&context.agent_name);
        role.clone_from(&context.agent_role);
        parent.clone_from(&context.parent_session_id);
    }
    let (name, role) = match (name, role) {
        (None, None) if parent.is_none() => return Ok(None),
        (None, None) => {
            return Err(usage(format!(
                "--parent-session needs --agent-name and --agent-role (or ${AGENT_NAME_ENV} and \
                 ${AGENT_ROLE_ENV})"
            )));
        }
        (Some(_), None) => {
            return Err(usage(format!(
                "--agent-name needs --agent-role orchestrator, sub_agent, or human (or \
                 ${AGENT_ROLE_ENV})"
            )));
        }
        (None, Some(_)) => {
            return Err(usage(format!(
                "--agent-role needs --agent-name <NAME> (or ${AGENT_NAME_ENV})"
            )));
        }
        (Some(name), Some(role)) => (name, role),
    };
    if !memprove_domain::SessionAgent::is_name(&name) {
        return Err(usage(format!(
            "--agent-name (or ${AGENT_NAME_ENV}) {}",
            memprove_domain::AGENT_NAME_RULE
        )));
    }
    if memprove_domain::AgentRole::parse(&role).is_none() {
        return Err(usage(format!(
            "--agent-role (or ${AGENT_ROLE_ENV}) must be orchestrator, sub_agent, or human"
        )));
    }
    memprove_domain::SessionAgent::new(&name, &role, parent.as_deref())
        .map(Some)
        .map_err(|_| {
            usage(format!(
                "--parent-session (or ${PARENT_SESSION_ENV}) must be a Session ID, a lowercase \
                 UUIDv7"
            ))
        })
}

/// The `agent` member of a `createSession` body, with its leading comma;
/// empty without an agent.
#[must_use]
pub fn agent_member(agent: Option<&memprove_domain::SessionAgent>) -> String {
    agent.map_or_else(String::new, |agent| format!(r#","agent":{}"#, agent.wire()))
}

/// Command-line error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

impl fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

fn usage(message: impl Into<String>) -> UsageError {
    UsageError(message.into())
}

/// U2 (S1, N-3, Owner O4): whether a command-line word may be repeated in
/// a usage error: a word of the command vocabulary (`[a-z][a-z0-9-]*`, at
/// most 32 characters), or an option name (the same after `-` or `--`). A
/// statement body or any other value is never repeated.
fn echoable_word(word: &str) -> bool {
    let name = word
        .strip_prefix("--")
        .or_else(|| word.strip_prefix('-'))
        .unwrap_or(word);
    (1..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// U2 (S1): the usage error of an argument that starts with `-` and names
/// no option; it is repeated only when it has the shape of an option name.
fn unknown_option(text: &str) -> String {
    if echoable_word(text) {
        format!("unknown option {text:?}")
    } else {
        "unknown option: an argument starts with - and names no option".to_owned()
    }
}

/// U2 (S1): the usage error of words that name no command; a word outside
/// the command vocabulary is shown as `<ARG>`.
fn unknown_command(words: &[&str]) -> String {
    let shown = words
        .iter()
        .map(|word| if echoable_word(word) { *word } else { "<ARG>" })
        .collect::<Vec<_>>()
        .join(" ");
    format!("unknown command {shown:?}")
}

/// P3-L L11 patch: why `task complete` without `--evidence` is refused
/// locally: the latest run of a command in the context's repository state
/// did not pass. Names those runs and the runs of the state, and says to
/// cite runs explicitly.
fn failing_runs_refusal(context: &context::Context) -> UsageError {
    let describe = |runs: &[&context::RunLabel]| {
        runs.iter()
            .map(|run| {
                format!(
                    "{} ({})",
                    run.label,
                    run.status.as_deref().unwrap_or("unknown")
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let passed = context
        .completion_runs()
        .iter()
        .map(|run| run.label.as_str())
        .collect::<Vec<_>>();
    let cite = if passed.is_empty() {
        "no run of this state passed".to_owned()
    } else {
        format!("the passed runs here are {}", passed.join(", "))
    };
    usage(format!(
        "task complete cites the passed runs of this repository state, but the latest run of a \
         command did not pass: {}. The runs of this state are {}. Rerun the failing command \
         with `memprove run` until it passes, or name the runs to cite with `--evidence \
         <LABEL>` ({cite})",
        describe(&context.failing_runs()),
        context.citable_runs(),
    ))
}

/// P3-L L11 (Owner O3) and its patch: the runs `task complete` cites
/// without `--evidence`, every citable passed run of the context's
/// repository state that no later run of the same argv overrules (P4-G:
/// shared with the MCP `complete` tool, ADR 0014 E7.5.6).
///
/// # Errors
///
/// The runs that stand as the latest run of their command without passing:
/// then nothing is cited by default (the local refusal).
pub fn default_completion(
    context: &context::Context,
) -> Result<Vec<&context::RunLabel>, Vec<&context::RunLabel>> {
    let failing = context.failing_runs();
    if failing.is_empty() {
        Ok(context.completion_runs())
    } else {
        Err(failing)
    }
}

/// The `transitionTask` body of `task complete` (P2-H): to `completed` at
/// `revision`, citing `evidence` (Evidence IDs), judged in `workspace`, and
/// (U9 SF1-A, the Owner's O8 exception to R1) asked by `session`, the
/// context's Session, by whose declared role the daemon judges it.
#[must_use]
pub fn completion_body(
    revision: u64,
    evidence: &[String],
    workspace: &str,
    session: Option<&str>,
) -> String {
    let ids = evidence
        .iter()
        .map(|id| json_string(id))
        .collect::<Vec<_>>()
        .join(",");
    let session = session.map_or_else(String::new, |session| {
        format!(r#","session_id":{}"#, json_string(session))
    });
    format!(
        r#"{{"schema_version":1,"expected_revision":{revision},"target_state":"completed","completion_evidence_ids":[{ids}],"workspace_id":{}{session}}}"#,
        json_string(workspace)
    )
}

/// The `endSession` body of `end` at `revision`, with the reason when given
/// and (ADR 0013 D6) the outcome `abandoned` when asked.
#[must_use]
pub fn end_body(revision: u64, reason: Option<&str>, abandoned: bool) -> String {
    end_body_by(revision, reason, abandoned, None)
}

/// [`end_body`] with (U9 A7, Owner O3) who ends the Session, when it is
/// ended as abandoned and an ender is known ([`ender_of`]).
#[must_use]
pub fn end_body_by(
    revision: u64,
    reason: Option<&str>,
    abandoned: bool,
    ended_by: Option<&memprove_domain::SessionEndedBy>,
) -> String {
    let mut body = format!(r#"{{"schema_version":1,"expected_revision":{revision}"#);
    if let Some(reason) = reason {
        write!(body, r#","reason":{}"#, json_string(reason))
            .expect("writing to a String cannot fail");
    }
    if abandoned {
        body.push_str(r#","outcome":"abandoned""#);
        if let Some(ended_by) = ended_by {
            write!(body, r#","ended_by":{}"#, ended_by.recorded())
                .expect("writing to a String cannot fail");
        }
    }
    body.push('}');
    body
}

/// U9 A7 (Owner O3): who `end --abandoned` (and the MCP `end` with
/// `abandoned`) reports as the ender of `target`, filled in, never typed:
/// the Session the ender's own context names, when it names one that is
/// not `target`; and the agent the ender declares, as `begin` takes it
/// (A3: its environment variables, else the context file's agent, whole),
/// except that the context file's agent is not used when that context
/// names `target` itself (it is then `target`'s agent, not the ender's).
/// `None` when neither is known: the request is as before.
///
/// # Errors
///
/// The usage error of [`agent_of`] for an environment that does not
/// declare a whole agent.
pub fn ender_of(
    target: &str,
    context: Option<&context::Context>,
    env: &AgentEnv,
) -> Result<Option<memprove_domain::SessionEndedBy>, UsageError> {
    let own = context.and_then(|context| context.session_id.as_deref());
    let session_id = own
        .filter(|own| *own != target)
        .and_then(|own| memprove_domain::SessionId::parse(own).ok());
    let agent = agent_of(&[], env, context.filter(|_| own != Some(target)))?;
    Ok((session_id.is_some() || agent.is_some())
        .then_some(memprove_domain::SessionEndedBy { session_id, agent }))
}

/// Options that take a value, and whether they may repeat.
const VALUE_OPTIONS: [(&str, bool); 44] = [
    // U17 (M1 O4): `init`.
    (OPTION_CLIENT, true),
    (OPTION_OPERATOR_TOKEN, false),
    // U8 A5 (Owner O4): withdraw one Session's statements.
    ("--withdraw-session", false),
    // U8 A3 (Owner O4): the agent a Session declares.
    ("--agent-name", false),
    ("--agent-role", false),
    ("--parent-session", false),
    ("--data-dir", false),
    ("--socket", false),
    ("--token-file", false),
    ("--label", false),
    ("--scope", true),
    ("--idempotency-key", false),
    ("--limit", false),
    ("--cursor", false),
    ("--project", false),
    ("--workspace", false),
    ("--agent", false),
    ("--task", false),
    ("--session", false),
    ("--test-cases", false),
    ("--test-name", false),
    ("--title", false),
    ("--description", false),
    ("--revision", false),
    ("--reason", false),
    ("--to", false),
    ("--evidence", true),
    ("--new-task", false),
    ("--fact", true),
    ("--open", true),
    ("--next", false),
    ("--objective", false),
    ("--snapshot", false),
    ("--test-format", false),
    ("--supersedes", true),
    ("--withdraw", true),
    ("--withdraw-reason", false),
    ("--reaffirm", true),
    ("--rationale", false),
    ("--budget", false),
    ("--claims", false),
    ("--query", false),
    ("--out", false),
    ("--from", false),
];

/// Parses arguments (without the program name) and the data-directory
/// environment value.
///
/// # Errors
///
/// Returns [`UsageError`] for unknown commands or options, a token passed as
/// an argument, or when no socket can be located.
pub fn parse_args<I>(args: I, env_data_dir: Option<OsString>) -> Result<Invocation, UsageError>
where
    I: IntoIterator<Item = OsString>,
{
    parse_args_in(args, env_data_dir, &ContextLookup::Unavailable)
}

/// [`parse_args`] with the current context of the working directory, from
/// which omitted IDs are taken (P2-D1).
///
/// # Errors
///
/// As [`parse_args`]; an ID that is neither given nor in the context is a
/// usage error that says why the context could not supply it.
pub fn parse_args_in<I>(
    args: I,
    env_data_dir: Option<OsString>,
    lookup: &ContextLookup,
) -> Result<Invocation, UsageError>
where
    I: IntoIterator<Item = OsString>,
{
    parse_args_with(args, env_data_dir, lookup, &|| None)
}

/// [`parse_args_in`] with (U2, H1, Owner O5) the Project of this client
/// session's last-Pack record, which only `begin` reads, and only when no
/// context file of this client session covers the directory: the record of
/// a Pack or of no Pack (ADR 0014, "Amendment (U2)"). It is asked for only
/// when `begin` needs it.
///
/// # Errors
///
/// As [`parse_args_in`].
pub fn parse_args_with<I>(
    args: I,
    env_data_dir: Option<OsString>,
    lookup: &ContextLookup,
    recorded_project: &dyn Fn() -> Option<String>,
) -> Result<Invocation, UsageError>
where
    I: IntoIterator<Item = OsString>,
{
    parse_args_core(
        args,
        env_data_dir,
        lookup,
        recorded_project,
        None,
        &AgentEnv::default(),
        &|| None,
    )
}

/// [`parse_args_with`] for the binary (U4, Y1, N-3): a mistake in the
/// Evidence of `task complete` (a run label that names no run, no run to
/// cite, a latest run that failed) does not end the parse; it is carried in
/// [`Follow::TaskCompleted`]'s `refusal`, so that the caller can read the
/// state of the context's Session first and let that refusal win.
///
/// U5 Z-F round 1 (S2, the Owner's S2 decision): `configured` is the
/// fallback for the daemon's location when neither `--socket`, nor
/// `--data-dir`, nor a non-empty `env_data_dir` names it: the data
/// directory of `<config>/data-dir`, or the clause the usage error adds
/// ([`hook::configured_location`]). It is asked only then.
///
/// U11 N4 (U10 VN14; Owner O6): `root_project` is the Project every context
/// of the Workspace root records (the directory's and each client session's),
/// when they agree; `task list` without `--project` takes it when the
/// current context names none. It is asked for only then.
///
/// # Errors
///
/// As [`parse_args_with`], except for the Evidence of `task complete`.
pub fn parse_args_deferring<I>(
    args: I,
    env_data_dir: Option<OsString>,
    lookup: &ContextLookup,
    recorded_project: &dyn Fn() -> Option<String>,
    configured: &dyn Fn() -> Result<PathBuf, String>,
    agent_env: &AgentEnv,
    root_project: &dyn Fn() -> Option<String>,
) -> Result<Invocation, UsageError>
where
    I: IntoIterator<Item = OsString>,
{
    parse_args_core(
        args,
        env_data_dir,
        lookup,
        recorded_project,
        Some(configured),
        agent_env,
        root_project,
    )
}

/// [`parse_args_with`] with (U8 A3) the agent's environment variables.
///
/// # Errors
///
/// As [`parse_args_with`].
pub fn parse_args_with_agent<I>(
    args: I,
    env_data_dir: Option<OsString>,
    lookup: &ContextLookup,
    agent_env: &AgentEnv,
) -> Result<Invocation, UsageError>
where
    I: IntoIterator<Item = OsString>,
{
    parse_args_core(
        args,
        env_data_dir,
        lookup,
        &|| None,
        None,
        agent_env,
        &|| None,
    )
}

fn parse_args_core<I>(
    args: I,
    env_data_dir: Option<OsString>,
    lookup: &ContextLookup,
    recorded_project: &dyn Fn() -> Option<String>,
    configured: Option<&dyn Fn() -> Result<PathBuf, String>>,
    agent_env: &AgentEnv,
    root_project: &dyn Fn() -> Option<String>,
) -> Result<Invocation, UsageError>
where
    I: IntoIterator<Item = OsString>,
{
    // The Evidence of `task complete` is carried to the caller, not refused
    // here, exactly when the caller asked for the deferred parse.
    let defer = configured.is_some();
    let mut options: Vec<(&'static str, OsString)> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut trailing: Option<Vec<OsString>> = None;
    let args: Vec<OsString> = args.into_iter().collect();
    if let Some(early) = help_or_version(&args) {
        return early;
    }
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        let text = argument.to_string_lossy().into_owned();
        if text == "--" {
            trailing = Some(args.by_ref().collect());
            break;
        }
        if text == "-" {
            // Standard input, for `event ingest -` and `checkpoint create -`.
            words.push(text);
            continue;
        }
        if let Some(flag) = BOOLEAN_FLAGS.into_iter().find(|flag| *flag == text) {
            if options.iter().any(|(seen, _)| *seen == flag) {
                return Err(usage(format!("{flag} was given more than once")));
            }
            options.push((flag, OsString::new()));
            continue;
        }
        if text == "--token" || text.starts_with("--token=") {
            return Err(usage(format!(
                "tokens are not accepted on the command line; set {TOKEN_ENV} or use --token-file"
            )));
        }
        if let Some((name, repeatable)) = VALUE_OPTIONS.iter().find(|(name, _)| *name == text) {
            let value = args
                .next()
                .ok_or_else(|| usage(format!("{name} requires a value")))?;
            if !repeatable && options.iter().any(|(seen, _)| seen == name) {
                return Err(usage(format!("{name} was given more than once")));
            }
            options.push((name, value));
        } else if text.starts_with('-') {
            return Err(usage(unknown_option(&text)));
        } else {
            words.push(text);
        }
    }
    let take = |name: &str| -> Option<OsString> {
        options
            .iter()
            .find(|(seen, _)| *seen == name)
            .map(|(_, value)| value.clone())
    };
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    if let Some(local) = local_command(
        &words,
        &options,
        trailing.as_ref(),
        lookup,
        env_data_dir.as_ref(),
    ) {
        return local;
    }
    let run = if words == ["run"] {
        Some(run_spec(&options, trailing, lookup)?)
    } else if trailing.is_some() {
        return Err(usage("`--` applies only to `run`"));
    } else {
        None
    };
    let begin = if run.is_none() && words == ["begin"] {
        Some(begin_spec(&options, lookup, recorded_project, agent_env)?)
    } else {
        None
    };
    let request = match (&run, &begin) {
        (None, None) => Some(command_request(
            &words,
            &options,
            lookup,
            defer,
            agent_env,
            root_project,
        )?),
        _ => None,
    };
    let socket = socket_of(&options, env_data_dir, configured)?;
    let token_file = take("--token-file").map(PathBuf::from);
    Ok(invocation_of(socket, token_file, (run, begin, request)))
}

/// The invocation of what `parse_args_core` built: a `run`, a `begin`, or a
/// request, in that order.
fn invocation_of(
    socket: PathBuf,
    token_file: Option<PathBuf>,
    built: (
        Option<RunSpec>,
        Option<BeginSpec>,
        Option<(Request, Follow)>,
    ),
) -> Invocation {
    match built {
        (Some(spec), _, _) => Invocation::Run {
            socket,
            spec,
            token_file,
        },
        (None, Some(spec), _) => Invocation::Begin {
            socket,
            spec,
            token_file,
        },
        (None, None, Some((request, follow))) => Invocation::Call {
            socket,
            request,
            token_file,
            follow,
        },
        (None, None, None) => unreachable!("every command builds a request, a run, or a begin"),
    }
}

/// A help request (it wins over every other mistake), else (U1, E1) a
/// version request, else (U8 K1) the refusal of `mcp serve` given
/// `--config-dir` in a form it does not take; `None` for none of them.
fn help_or_version(args: &[OsString]) -> Option<Result<Invocation, UsageError>> {
    if let Some(entries) = help_for(args) {
        return Some(Ok(if entries.is_empty() {
            Invocation::Help
        } else {
            Invocation::CommandHelp(entries)
        }));
    }
    version_requested(args)
        .or_else(|| mcp_serve_config_dir_error(args).map(|error| Err(usage(error))))
}

/// U1 (E1): `--version` or `-V` before any `--`, outside an option's
/// value: alone, [`Invocation::Version`]; with anything else, a usage error.
fn version_requested(args: &[OsString]) -> Option<Result<Invocation, UsageError>> {
    let mut rest = args.iter();
    while let Some(argument) = rest.next() {
        let text = argument.to_string_lossy();
        if text == "--" {
            break;
        }
        if text == "--version" || text == "-V" {
            return Some(if args.len() == 1 {
                Ok(Invocation::Version)
            } else {
                Err(usage(format!("{text} takes no other argument")))
            });
        }
        if VALUE_OPTIONS.iter().any(|(name, _)| *name == text) {
            rest.next();
        }
    }
    None
}

/// The command words of `args`: what is neither an option nor an option's
/// value, up to a `--`.
fn command_words(args: &[OsString]) -> Vec<String> {
    let mut words = Vec::new();
    let mut rest = args.iter();
    while let Some(argument) = rest.next() {
        let text = argument.to_string_lossy();
        if text == "--" {
            break;
        }
        if VALUE_OPTIONS.iter().any(|(name, _)| *name == text) {
            rest.next();
        } else if !text.starts_with('-') || text == "-" {
            words.push(text.into_owned());
        }
    }
    words
}

/// The help a `-h` or `--help` asks for, when the arguments hold one before
/// any `--`: the commands their words name, or none for the general help.
/// Help wins over every other mistake, wherever the flag stands; the value
/// of an option such as `--reason --help` is not a flag.
fn help_for(args: &[OsString]) -> Option<Vec<&'static help::CommandHelp>> {
    let mut requested = false;
    let mut rest = args.iter();
    while let Some(argument) = rest.next() {
        let text = argument.to_string_lossy();
        if text == "--" {
            break;
        }
        if text == "-h" || text == "--help" {
            requested = true;
        } else if VALUE_OPTIONS.iter().any(|(name, _)| *name == text) {
            rest.next();
        }
    }
    requested.then(|| {
        let words = command_words(args);
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        help::lookup(&words)
    })
}

/// The last line of a usage error (P3-L L9): which `--help` to read. The
/// command the arguments name, or its group when only the group is known,
/// else the general help. The error itself is printed before it.
#[must_use]
pub fn usage_hint(args: &[OsString]) -> String {
    let words = command_words(args);
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let entries = help::lookup(&words);
    let command = match entries.as_slice() {
        [] => None,
        [only] => Some(only.name),
        [first, ..] => first.name.split(' ').next(),
    };
    match command {
        Some(name) => {
            format!("memprove: for the usage of this command, run `memprove {name} --help`")
        }
        None => "memprove: for the list of commands, run `memprove --help`".to_owned(),
    }
}

/// The daemon socket: `--socket` of `options`, else `memproved.sock` in
/// the data directory (`--data-dir`, else `env_data_dir`). U5 Z-F round 1 (S2):
/// when neither option is given and `env_data_dir` is unset or empty (as
/// the hook and `mcp serve` take it), the data directory of `configured`
/// ([`hook::configured_location`]), whose clause, when it names none, ends
/// the usage error; with no `configured` (the library's other parsers) or
/// an option given, the error is the one before.
fn socket_of(
    options: &[(&'static str, OsString)],
    env_data_dir: Option<OsString>,
    configured: Option<&dyn Fn() -> Result<PathBuf, String>>,
) -> Result<PathBuf, UsageError> {
    let take = |name: &str| {
        options
            .iter()
            .find(|(seen, _)| *seen == name)
            .map(|(_, value)| value.clone())
    };
    let (socket, data_dir) = (take("--socket"), take("--data-dir"));
    let no_location = format!(
        "no daemon location; pass --data-dir <PATH>, --socket <PATH>, or set {DATA_DIR_ENV}"
    );
    let unnamed = data_dir.is_none() && env_data_dir.as_ref().is_none_or(|dir| dir.is_empty());
    match (socket, data_dir.or(env_data_dir)) {
        (Some(socket), _) => Ok(PathBuf::from(socket)),
        (None, Some(data_dir)) if !data_dir.is_empty() => {
            Ok(PathBuf::from(data_dir).join(SOCKET_FILE_NAME))
        }
        _ => match configured.filter(|_| unnamed) {
            Some(configured) => configured()
                .map(|data_dir| data_dir.join(SOCKET_FILE_NAME))
                .map_err(|clause| usage(format!("{no_location}; {clause}"))),
            None => Err(usage(no_location)),
        },
    }
}

/// The `context show` command (P2-H): local only, no daemon and no token.
fn show_context(
    options: &[(&'static str, OsString)],
    trailing: Option<&Vec<OsString>>,
    lookup: &ContextLookup,
) -> Result<Invocation, UsageError> {
    if trailing.is_some() {
        return Err(usage("`--` applies only to `run`"));
    }
    check_allowed(options, &[])?;
    lookup
        .context()
        .cloned()
        .map(Invocation::ShowContext)
        .ok_or_else(|| {
            usage(format!(
                "context show: {}; run `memprove begin` in this Workspace first",
                lookup.reason()
            ))
        })
}

/// The `begin` command: the Project from `--project`, the context, or (U2,
/// H1) this client session's last-Pack record, and the Task from `--task`,
/// `--new-task`, or the context.
fn begin_spec(
    options: &[(&'static str, OsString)],
    lookup: &ContextLookup,
    recorded_project: &dyn Fn() -> Option<String>,
    agent_env: &AgentEnv,
) -> Result<BeginSpec, UsageError> {
    let text_of = |name: &str| text_option(options, name);
    let allowed = [
        "--project",
        "--task",
        "--new-task",
        "--description",
        "--agent",
        "--agent-name",
        "--agent-role",
        "--parent-session",
    ];
    check_allowed(options, &allowed)?;
    let context = lookup.context();
    // P4-E: a client session with no context here yet continues the Task
    // of the Pack it was given, in the Project that Pack's file names.
    let unbegun = lookup.unbegun();
    let project_id = text_of("--project")
        .or_else(|| context.map(|context| context.project_id.clone()))
        .or_else(|| unbegun.and_then(|pack| pack.project_id.clone()))
        // U2 (H1, Owner O5): with no context file of its own here, the
        // Project of this client session's last-Pack record, also of the
        // hook's record of no Pack, which the lookup reads as no context.
        .or_else(|| {
            matches!(
                lookup,
                ContextLookup::Absent { .. } | ContextLookup::Unbegun { .. }
            )
            .then(recorded_project)
            .flatten()
        })
        .ok_or_else(|| {
            usage(format!(
                "begin requires --project <PROJECT_ID> the first time in a Workspace: {}. \
                 `memprove context show` in a Workspace that already has a context prints \
                 the Project ID, as does `memprove project register` for the operator",
                lookup.reason()
            ))
        })?;
    path_segment(&project_id, "project id")?;
    let task = match (text_of("--task"), text_of("--new-task")) {
        (Some(_), Some(_)) => return Err(usage("begin takes --task or --new-task, not both")),
        (Some(task), None) => {
            path_segment(&task, "task id")?;
            BeginTask::Existing(task)
        }
        (None, Some(title)) => {
            if title.is_empty() {
                return Err(usage("--new-task must not be empty"));
            }
            BeginTask::New {
                title,
                description: text_of("--description"),
            }
        }
        // P2-H: without either, continue the context's Task.
        (None, None) => BeginTask::Existing(
            context
                .and_then(|context| context.task_id.clone())
                .or_else(|| unbegun.map(|pack| pack.task_id.clone()))
                .ok_or_else(|| {
                    // U3 (K4): a --project given is not repeated; a Project
                    // the context or a record names is shown.
                    let shown = if text_of("--project").is_some() {
                        "<PROJECT_ID>"
                    } else {
                        project_id.as_str()
                    };
                    usage(format!(
                        "begin has no Task to continue: the current context names none. Pass \
                         --new-task <TITLE> to start one, or --task <TASK_ID> to continue one \
                         (`memprove context show` in its earlier Workspace prints it; \
                         `memprove task list --project {shown}` lists the Project's Tasks)"
                    ))
                })?,
        ),
    };
    if text_of("--description").is_some() && !matches!(task, BeginTask::New { .. }) {
        return Err(usage("--description requires --new-task"));
    }
    let agent_id = text_of("--agent").or_else(|| context.map(|context| context.agent_id.clone()));
    if let Some(agent) = &agent_id {
        path_segment(agent, "agent id")?;
    }
    let agent = agent_of(options, agent_env, context)?;
    Ok(BeginSpec {
        project_id,
        task,
        agent_id,
        agent,
    })
}

/// Whether `begin` may start a Session while the context still names
/// `session_id`, given what `listSessions` said of it: its state, not
/// listed, or why it could not be read (P2-H). `Err` is the refusal, with
/// the hint; the Session is never ended for the caller. A Session its
/// Workspace does not list is not active, and `end` could not end it, so it
/// does not block.
///
/// # Errors
///
/// When the Session is listed as anything but `ended`, or the list cannot
/// be read.
pub fn previous_session_check(
    session_id: &str,
    listed: Result<Option<&str>, String>,
) -> Result<(), String> {
    let why = match listed {
        Ok(Some("ended") | None) => return Ok(()),
        Ok(Some(_)) => format!("Session {session_id} of the current context is still active"),
        Err(why) => format!(
            "cannot confirm that Session {session_id} of the current context has ended ({why})"
        ),
    };
    // U7 P1 (D2 F15, Owner O3): a Session someone else left is not ended
    // as one's own.
    Err(format!(
        "{why}; end it first with `memprove end --reason <TEXT>` (the reason is recorded), \
         then run `memprove begin` again; a Session someone else left open is ended with \
         `memprove end --abandoned --reason <why>`"
    ))
}

/// The transitions `begin` makes after creating the Session so that a Task
/// in `state` is `in_progress` (P2-H): one edge at a time, since the domain
/// graph has no direct `proposed` → `in_progress` edge. Any other state is
/// left alone; an unknown state takes no step.
///
/// # Errors
///
/// A `completed` or `cancelled` Task takes no new Session: the refusal says
/// to start the next piece of work with `--new-task`.
pub fn begin_steps(task_id: &str, state: Option<&str>) -> Result<&'static [&'static str], String> {
    match state {
        Some("proposed") => Ok(&["ready", "in_progress"]),
        Some("ready") => Ok(&["in_progress"]),
        Some(finished @ ("completed" | "cancelled")) => Err(format!(
            "Task {task_id} is {finished}; start the next piece of work with \
             `memprove begin --new-task <TITLE>`"
        )),
        _ => Ok(&[]),
    }
}

/// The last value of the option `name`, as text.
fn text_option(options: &[(&'static str, OsString)], name: &str) -> Option<String> {
    options
        .iter()
        .find(|(seen, _)| *seen == name)
        .map(|(_, value)| value.to_string_lossy().into_owned())
}

/// Refuses command-specific options outside `allowed`.
fn check_allowed(options: &[(&'static str, OsString)], allowed: &[&str]) -> Result<(), UsageError> {
    for (name, _) in options {
        let global = matches!(*name, "--data-dir" | "--socket" | "--token-file");
        if !global && !allowed.contains(name) {
            return Err(usage(format!("{name} does not apply to this command")));
        }
    }
    Ok(())
}

/// P4-C: what `resume` prints, from `--pack`, `--budget`, and `--claims`
/// (`request` already holds `--text` and `--all`). `--pack` goes without
/// `--text` and `--all`; `--claims` goes with `--text` (not `--all`) or,
/// P4-C2 revision 5, with `--pack` (not `--budget`); U3 G4: `--query`
/// goes with `--pack` only, without `--claims`.
fn capsule_view(
    pack: bool,
    budget: Option<&str>,
    claims: Option<&str>,
    query: Option<&OsString>,
    request: &Request,
) -> Result<CapsuleView, UsageError> {
    use memprove_domain::{PACK_DEFAULT_BUDGET, PACK_MAX_BUDGET, PACK_MIN_BUDGET};
    if pack && (request.summary || request.all_items) {
        return Err(usage(
            "--pack prints the Context Pack; it is used without --text and --all",
        ));
    }
    // U3 G4 (Owner O8): the query is checked here and never repeated.
    let query = match query {
        None => None,
        Some(_) if !pack || claims.is_some() => {
            return Err(usage(
                "--query selects the claims of a whole Pack; it is used only with --pack, \
                 without --claims",
            ));
        }
        Some(value) => Some(query_text(value)?),
    };
    if let Some(numbers) = claims {
        if pack {
            if budget.is_some() {
                return Err(usage(
                    "--pack --claims prints the full lines of the claims it names, with no budget; it \
                     is used without --budget",
                ));
            }
            return Ok(CapsuleView::PackClaims(claim_ranges(numbers)?));
        }
        if !request.summary || request.all_items {
            return Err(usage(
                "--claims prints the lines of the claims it names, superseded and withdrawn \
                 ones too; it is used with --pack, or with --text and not with --all",
            ));
        }
        return Ok(CapsuleView::Claims(claim_ranges(numbers)?));
    }
    match (pack, budget) {
        (false, None) => Ok(CapsuleView::Plain),
        (false, Some(_)) => Err(usage("--budget is used only with --pack")),
        (true, budget) => {
            let budget = match budget {
                None => PACK_DEFAULT_BUDGET,
                Some(text) => text
                    .parse::<usize>()
                    .ok()
                    .filter(|budget| {
                        text.bytes().all(|byte| byte.is_ascii_digit())
                            && (PACK_MIN_BUDGET..=PACK_MAX_BUDGET).contains(budget)
                    })
                    .ok_or_else(|| {
                        usage(format!(
                            "--budget must be a whole number of UTF-16 code units from \
                             {PACK_MIN_BUDGET} through {PACK_MAX_BUDGET}"
                        ))
                    })?,
            };
            Ok(match query {
                Some(query) => CapsuleView::PackQuery { budget, query },
                None => CapsuleView::Pack { budget },
            })
        }
    }
}

/// U3 G4 (Owner O8): the text of `--query`, checked as the domain checks a
/// query; a refusal names the rule, never the text.
fn query_text(value: &OsString) -> Result<String, UsageError> {
    let text = value.to_str().ok_or_else(|| {
        usage("--query is not valid UTF-8; the query is not repeated and nothing was sent")
    })?;
    memprove_domain::check_pack_query(text)
        .map_err(|refusal| usage(query_refusal_sentence(refusal)))?;
    Ok(text.to_owned())
}

/// The sentence for a refused `--query`: the rule, never the text.
const fn query_refusal_sentence(refusal: memprove_domain::QueryRefusal) -> &'static str {
    use memprove_domain::QueryRefusal;
    match refusal {
        QueryRefusal::Length => {
            "--query takes 1 through 256 characters (Unicode scalar values); the query is \
             not repeated and nothing was sent"
        }
        QueryRefusal::Control => {
            "--query refuses a query with a control character (Unicode category Cc); the \
             query is not repeated and nothing was sent"
        }
        QueryRefusal::TokenFormat => {
            "--query refuses a query with a string in the format of a memprove token (43 \
             characters of A-Z, a-z, 0-9, '-', and '_', with at least one upper-case letter, \
             one lower-case letter, and one digit); the query is not repeated and nothing was \
             sent"
        }
    }
}

/// U6 K3 (U5 N4): the refusal of a `--query` that holds the whole `token`
/// this process holds, which may not be in the token format of C4: the
/// refusal of a query in that format, the same words, and neither the query
/// nor the token is repeated. `None` when the query does not hold it.
#[must_use]
pub fn query_holding_token(query: &str, token: &str) -> Option<UsageError> {
    (!token.is_empty() && query.contains(token)).then(|| {
        usage(query_refusal_sentence(
            memprove_domain::QueryRefusal::TokenFormat,
        ))
    })
}

/// P4-C: the claim numbers of `--claims`: numbers and ranges separated by
/// commas (`3,5-7`), each number optionally written `#3`, a range with `-`
/// or `–` (as the Pack writes `#5–#7`).
fn claim_ranges(value: &str) -> Result<Vec<(u64, u64)>, UsageError> {
    let invalid = || {
        usage(
            "--claims takes claim numbers and ranges separated by commas, such as 3,5-7 or \
             #3,#5-#7",
        )
    };
    let number = |text: &str| {
        let digits = text.strip_prefix('#').unwrap_or(text);
        if digits.is_empty()
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
            || digits.starts_with('0')
        {
            return None;
        }
        digits.parse::<u64>().ok()
    };
    value
        .split(',')
        .map(|part| {
            let (first, last) = part.split_once(['-', '–']).unwrap_or((part, part));
            match (number(first), number(last)) {
                (Some(first), Some(last)) if first <= last => Ok((first, last)),
                _ => Err(invalid()),
            }
        })
        .collect()
}

/// `explicit`, else the context's value, else a usage error naming why.
fn id_or_context(
    explicit: Option<String>,
    from_context: Option<&String>,
    lookup: &ContextLookup,
    command: &str,
    flag: &str,
) -> Result<String, UsageError> {
    let value = explicit
        .or_else(|| from_context.cloned())
        .ok_or_else(|| usage(lookup.missing(command, flag)))?;
    path_segment(&value, flag.trim_start_matches('-'))?;
    Ok(value)
}

/// The `--evidence` value naming the latest run of the current context.
pub const LAST_EVIDENCE: &str = "last";

/// An `--evidence` value: an Evidence ID, `last` for the Evidence of the
/// latest `memprove run` the context records (P2-H), or the label of a
/// run the latest Snapshot seals (`r2`, P3-D). A value that only looks
/// like a label (`r0`, `r01`, `R1`) is a usage error; nothing is sent.
/// U3 (K4, V-N-3): an error names the value by its `ordinal` among the
/// command's `--evidence` options (`--evidence #2`), never by the value.
fn evidence_ref(
    value: &str,
    ordinal: usize,
    lookup: &ContextLookup,
    command: &str,
) -> Result<String, UsageError> {
    if context::is_run_label(value) {
        let context = lookup.context();
        return match context.and_then(|context| context.run(value)) {
            Some(run) => Ok(path_segment(&run.evidence_id, "evidence id")?.to_owned()),
            None => Err(usage(format!(
                "{command}: --evidence #{ordinal} names no run the latest Snapshot of the \
                 current context seals; {}",
                match context {
                    Some(context) if !context.runs.is_empty() => format!(
                        "the runs you can cite now are {}; a run of another repository state \
                         cannot be cited (run the command again)",
                        context.citable_runs()
                    ),
                    Some(_) =>
                        "it records no run; record one with `memprove run -- <COMMAND>`".to_owned(),
                    None => lookup.reason(),
                }
            ))),
        };
    }
    if context::looks_like_run_label(value) {
        return Err(usage(format!(
            "{command}: --evidence #{ordinal} is not a run label; a label is `r` and a \
             positive number without leading zeros (r1, r2, ...)"
        )));
    }
    if value != LAST_EVIDENCE {
        return Ok(path_segment(value, "evidence id")?.to_owned());
    }
    let latest = lookup
        .context()
        .and_then(|context| context.evidence_id.as_ref())
        .ok_or_else(|| {
            usage(format!(
                "{command}: --evidence {LAST_EVIDENCE} names the latest run of the current \
                 context, but {}; record one first with `memprove run -- <COMMAND>`",
                match lookup {
                    ContextLookup::Found(_) => "it records no run".to_owned(),
                    other => other.reason(),
                }
            ))
        })?;
    Ok(path_segment(latest, "evidence id")?.to_owned())
}

/// The boolean option marking `run` as a test run.
const FLAG_TEST: &str = "--test";
/// The boolean option asking `recover preview` for a one-sentence summary
/// and `resume` for one line per continuation item.
const FLAG_TEXT: &str = "--text";
/// The boolean option asking `resume --text` to list every statement one
/// by one, superseded and withdrawn ones too (P4-A).
const FLAG_ALL: &str = "--all";
/// The boolean option of `checkpoint create` reaffirming every fact that
/// awaits reaffirmation (P4-A); `--evidence` after it applies to each.
const FLAG_REAFFIRM_ALL: &str = "--reaffirm-all";
/// The boolean option asking `resume` for the Context Pack (P4-C).
const FLAG_PACK: &str = "--pack";
/// The boolean option asking `doctor` for its report as JSON (U1, E3).
const FLAG_JSON: &str = "--json";
/// U5 P3 (Owner O5): the boolean option of `hook install` that also writes
/// the suggested `permissions.allow` rules.
const FLAG_ALLOW_TOOLS: &str = "--allow-tools";
/// U17 (M1 O4): `init --dry-run`: say what would be written, write nothing,
/// send nothing.
const FLAG_DRY_RUN: &str = "--dry-run";
/// U17 (M1 O4): `init --client <NAME>`, repeatable.
const OPTION_CLIENT: &str = "--client";
/// U17 (M1 O4): `init --operator-token <FILE>`.
const OPTION_OPERATOR_TOKEN: &str = "--operator-token";
/// Every option that takes no value.
const BOOLEAN_FLAGS: [&str; 10] = [
    FLAG_DRY_RUN,
    FLAG_TEST,
    FLAG_TEXT,
    FLAG_DIGEST_ONLY,
    FLAG_ABANDONED,
    FLAG_ALL,
    FLAG_REAFFIRM_ALL,
    FLAG_PACK,
    FLAG_JSON,
    FLAG_ALLOW_TOOLS,
];
/// The boolean option asking `run` to keep only the digests of the
/// command's output, not its text (P2-C).
const FLAG_DIGEST_ONLY: &str = "--digest-only";
/// The boolean option ending a Session as abandoned: `session.crashed`
/// instead of `session.ended` (ADR 0013 D6, P3-D).
const FLAG_ABANDONED: &str = "--abandoned";

/// The `run` command: its options and the command after `--`.
fn run_spec(
    options: &[(&'static str, OsString)],
    trailing: Option<Vec<OsString>>,
    lookup: &ContextLookup,
) -> Result<RunSpec, UsageError> {
    let text_of = |name: &str| {
        options
            .iter()
            .find(|(seen, _)| *seen == name)
            .map(|(_, value)| value.to_string_lossy().into_owned())
    };
    let allowed = [
        "--session",
        "--workspace",
        "--task",
        FLAG_TEST,
        "--test-cases",
        "--test-name",
        "--idempotency-key",
        FLAG_DIGEST_ONLY,
        "--test-format",
    ];
    check_allowed(options, &allowed)?;
    let trailing =
        trailing.ok_or_else(|| usage("run requires `--` followed by the command to run"))?;
    // U3 (K4): the argument is named by its place, not repeated.
    if let Some(place) = trailing
        .iter()
        .position(|argument| argument.to_str().is_none())
    {
        return Err(usage(format!(
            "argument {} of the command after `--` is not valid UTF-8",
            place + 1
        )));
    }
    let argv = run::utf8_argv(trailing).map_err(|_| usage("the command is not valid UTF-8"))?;
    if argv.is_empty() || argv.iter().any(String::is_empty) {
        return Err(usage(
            "run requires a non-empty command with non-empty arguments after `--`",
        ));
    }
    refuse_unrecordable_argv(&argv)?;
    let context = lookup.context();
    let id = |name: &str, from_context: Option<&String>| {
        id_or_context(text_of(name), from_context, lookup, "run", name)
    };
    let format = text_of("--test-format")
        .map(|name| {
            TestFormat::parse(&name).ok_or_else(|| usage("--test-format must be cargo or pytest"))
        })
        .transpose()?;
    let tested = format.is_some() || options.iter().any(|(name, _)| *name == FLAG_TEST);
    let case_count = text_of("--test-cases")
        .map(|count| {
            count
                .parse::<u64>()
                .ok()
                .filter(|count| *count <= 9_007_199_254_740_991)
                .ok_or_else(|| usage("--test-cases must be a non-negative integer"))
        })
        .transpose()?;
    let name = text_of("--test-name");
    if !tested && (case_count.is_some() || name.is_some()) {
        return Err(usage("--test-cases and --test-name require --test"));
    }
    // U5 (H4): with pytest the cases a caller gives win over the summary.
    if format == Some(TestFormat::Cargo) && case_count.is_some() {
        return Err(usage(
            "--test-format counts the cases from the output; do not also give --test-cases",
        ));
    }
    if name.as_deref() == Some("") {
        return Err(usage("--test-name must not be empty"));
    }
    let idempotency_key = text_of("--idempotency-key");
    if idempotency_key
        .as_deref()
        .is_some_and(|key| !valid_idempotency_key(key))
    {
        return Err(usage(
            "--idempotency-key must be 16 to 200 visible ASCII characters",
        ));
    }
    Ok(RunSpec {
        session_id: id("--session", context.and_then(|c| c.session_id.as_ref()))?,
        workspace_id: id("--workspace", context.map(|c| &c.workspace_id))?,
        task_id: id("--task", context.and_then(|c| c.task_id.as_ref()))?,
        test: tested.then_some(TestSpec {
            name,
            case_count,
            format,
        }),
        argv,
        idempotency_key,
        digest_only: options.iter().any(|(name, _)| *name == FLAG_DIGEST_ONLY),
    })
}

/// Builds the request for the command `words`, checking that every
/// command-specific option applies to it.
#[allow(clippy::too_many_lines)] // One command table keeps the CLI surface reviewable.
fn command_request(
    words: &[&str],
    options: &[(&'static str, OsString)],
    lookup: &ContextLookup,
    defer: bool,
    agent_env: &AgentEnv,
    root_project: &dyn Fn() -> Option<String>,
) -> Result<(Request, Follow), UsageError> {
    let text_of = |name: &str| text_option(options, name);
    let context = lookup.context();
    let mut follow = Follow::Nothing;
    let (request, allowed): (Request, &[&str]) = match *words {
        ["health", "live"] => (
            Request::bare(OperationId::HealthLive, "/health/live".into()),
            &[],
        ),
        ["health", "ready"] => (
            Request::bare(OperationId::HealthReady, "/health/ready".into()),
            &[],
        ),
        ["status"] => (
            Request::bare(OperationId::GetStatus, "/v1/status".into()),
            &[],
        ),
        ["version"] => (
            Request::bare(OperationId::GetVersion, "/v1/version".into()),
            &[],
        ),
        ["token", "create"] => {
            let mut request =
                Request::bare(OperationId::CreateClientToken, "/v1/auth/tokens".into());
            request.body = Some(create_body(options)?);
            (request, &["--label", "--scope", "--idempotency-key"])
        }
        ["token", "list"] => (
            Request::bare(
                OperationId::ListClientTokens,
                list_target(
                    "/v1/auth/tokens",
                    None,
                    text_of("--limit"),
                    text_of("--cursor"),
                )?,
            ),
            &["--limit", "--cursor"],
        ),
        ["token", "revoke", token_id] => {
            if !is_url_safe(token_id) {
                return Err(usage("the token id contains unexpected characters"));
            }
            (
                Request::bare(
                    OperationId::RevokeClientToken,
                    format!("/v1/auth/tokens/{token_id}/revoke"),
                ),
                &["--idempotency-key"],
            )
        }
        ["token", "revoke"] => return Err(usage("token revoke requires a <TOKEN_ID>")),
        ["project", "register", root] => {
            let mut request =
                Request::bare(OperationId::RegisterProject, "/v1/projects/register".into());
            request.body = Some(format!(
                r#"{{"schema_version":1,"root":{}}}"#,
                json_string(&absolute_path(root)?)
            ));
            (request, &["--idempotency-key"])
        }
        ["project", "register"] => return Err(usage("project register requires a <ROOT>")),
        ["project", "get", project_id] => (
            Request::bare(
                OperationId::GetProject,
                format!("/v1/projects/{}", path_segment(project_id, "project id")?),
            ),
            &[],
        ),
        ["project", "get"] => return Err(usage("project get requires a <PROJECT_ID>")),
        ["workspace", "resolve", path] => {
            let project = required(&text_of, "--project", "workspace resolve")?;
            let mut request = Request::bare(
                OperationId::ResolveWorkspace,
                "/v1/workspaces/resolve".into(),
            );
            request.body = Some(format!(
                r#"{{"schema_version":1,"project_id":{},"path":{}}}"#,
                json_string(&project),
                json_string(&absolute_path(path)?)
            ));
            (request, &["--project"])
        }
        ["workspace", "resolve"] => return Err(usage("workspace resolve requires a <PATH>")),
        ["session", "create"] => {
            let workspace = required(&text_of, "--workspace", "session create")?;
            let agent = required(&text_of, "--agent", "session create")?;
            let mut body = format!(
                r#"{{"schema_version":1,"workspace_id":{},"agent_id":{}"#,
                json_string(&workspace),
                json_string(&agent)
            );
            if let Some(task) = text_of("--task") {
                write!(body, r#","task_id":{}"#, json_string(&task))
                    .expect("writing to a String cannot fail");
            }
            // U8 A3 (Owner O4): the options and the environment; no
            // context.
            body.push_str(&agent_member(agent_of(options, agent_env, None)?.as_ref()));
            body.push('}');
            let mut request = Request::bare(OperationId::CreateSession, "/v1/sessions".into());
            request.body = Some(body);
            (
                request,
                &[
                    "--workspace",
                    "--agent",
                    "--task",
                    "--idempotency-key",
                    "--agent-name",
                    "--agent-role",
                    "--parent-session",
                ],
            )
        }
        ["session", "list"] => {
            let workspace = required(&text_of, "--workspace", "session list")?;
            (
                Request::bare(
                    OperationId::ListSessions,
                    list_target(
                        "/v1/sessions",
                        Some(("workspace_id", workspace)),
                        text_of("--limit"),
                        text_of("--cursor"),
                    )?,
                ),
                &["--workspace", "--limit", "--cursor"],
            )
        }
        ["session", "end", _] | ["session", "end"] | ["end"] => {
            let command = if words == ["end"] {
                "end"
            } else {
                "session end"
            };
            let explicit = words.get(2).map(|id| (*id).to_owned());
            let context_session = context.and_then(|c| c.session_id.as_ref());
            let from_context = explicit.is_none() || explicit.as_ref() == context_session;
            let abandoned = options.iter().any(|(name, _)| *name == FLAG_ABANDONED);
            let session_id = match explicit {
                Some(id) => id,
                // U10 T7 (Owner O4; D3 F24): `end` ends the context's
                // Session only; a Session a Pack names is ended by its ID.
                None => context_session.cloned().ok_or_else(|| {
                    usage(if command == "end" {
                        format!(
                            "end ends the Session of the current context, but {}; to end a \
                             Session someone else left open (the one a Pack's `Session k` line \
                             names), run `memprove session end <SESSION_ID> --abandoned \
                             --reason <why>`",
                            lookup.reason()
                        )
                    } else {
                        lookup.missing(command, "<SESSION_ID>")
                    })
                })?,
            };
            path_segment(&session_id, "session id")?;
            let revision = match text_of("--revision") {
                Some(_) => Some(revision_of(&text_of, command)?),
                None => match context
                    .filter(|_| from_context)
                    .and_then(|c| c.session_revision)
                {
                    Some(revision) => Some(revision),
                    // U10 T7: an abandoned end of another Session reads its
                    // current revision before it is sent.
                    None if abandoned => None,
                    None => return Err(usage(lookup.missing(command, "--revision"))),
                },
            };
            let mut request = Request::bare(
                OperationId::EndSession,
                format!("/v1/sessions/{session_id}/end"),
            );
            // U9 A7 (Owner O3): who ends it, filled in from this client's
            // own context and declared agent; there is no option for it.
            let ended_by = if abandoned {
                ender_of(&session_id, context, agent_env)?
            } else {
                None
            };
            let unread = match revision {
                Some(revision) => {
                    request.body = Some(end_body_by(
                        revision,
                        text_of("--reason").as_deref(),
                        abandoned,
                        ended_by.as_ref(),
                    ));
                    None
                }
                None => Some(Box::new(EndLater {
                    reason: text_of("--reason"),
                    ended_by,
                    // U11 N2 (U10 VN10; Owner O6): an explicit --workspace
                    // wins over the context's, as for `session list`.
                    workspace_id: match text_of("--workspace") {
                        Some(workspace) => {
                            path_segment(&workspace, "--workspace")?;
                            Some(workspace)
                        }
                        None => context.map(|c| c.workspace_id.clone()),
                    },
                })),
            };
            follow = Follow::SessionEnded { session_id, unread };
            (
                request,
                &[
                    "--revision",
                    "--reason",
                    FLAG_ABANDONED,
                    "--workspace",
                    "--idempotency-key",
                ],
            )
        }
        ["task", "create"] => {
            let project = required(&text_of, "--project", "task create")?;
            let title = required(&text_of, "--title", "task create")?;
            let mut body = format!(
                r#"{{"schema_version":1,"project_id":{},"title":{}"#,
                json_string(&project),
                json_string(&title)
            );
            if let Some(workspace) = text_of("--workspace") {
                write!(body, r#","workspace_id":{}"#, json_string(&workspace))
                    .expect("writing to a String cannot fail");
            }
            if let Some(description) = text_of("--description") {
                write!(body, r#","description":{}"#, json_string(&description))
                    .expect("writing to a String cannot fail");
            }
            body.push('}');
            let mut request = Request::bare(OperationId::CreateTask, "/v1/tasks".into());
            request.body = Some(body);
            (
                request,
                &[
                    "--project",
                    "--title",
                    "--workspace",
                    "--description",
                    "--idempotency-key",
                ],
            )
        }
        ["task", "list"] => {
            // U10 N10 (D3 F29): without --project, the Project of the
            // current context, as `session list` takes its Workspace's and
            // `run` its Session's; an explicit --project wins. U11 N4 (U10
            // VN14; Owner O6): the context is the client session's when
            // MEMPROVE_CLIENT_SESSION names one that covers the
            // directory, else the directory's (the lookup); when it names
            // none, the Project every context of this Workspace root
            // records, when they agree.
            let project = text_of("--project")
                .or_else(|| context.map(|c| c.project_id.clone()))
                .or_else(root_project)
                .ok_or_else(|| usage(lookup.missing("task list", "--project")))?;
            (
                Request::bare(
                    OperationId::ListTasks,
                    list_target(
                        "/v1/tasks",
                        Some(("project_id", project)),
                        text_of("--limit"),
                        text_of("--cursor"),
                    )?,
                ),
                &["--project", "--limit", "--cursor"],
            )
        }
        ["task", "complete"] => {
            // P2-H: the context's Task, revision, and Workspace; the
            // Evidence defaults to the latest run's.
            let needs = |what: &str| {
                usage(format!(
                    "task complete completes the Task of the current context and needs its \
                     {what}, but {}; run `memprove begin` in this Workspace first",
                    lookup.reason()
                ))
            };
            let task_id = context
                .and_then(|c| c.task_id.clone())
                .ok_or_else(|| needs("Task"))?;
            path_segment(&task_id, "task id")?;
            let revision = match text_of("--revision") {
                Some(_) => revision_of(&text_of, "task complete")?,
                None => context
                    .and_then(|c| c.task_revision)
                    .ok_or_else(|| needs("Task revision (or pass --revision)"))?,
            };
            let workspace = context
                .map(|c| c.workspace_id.clone())
                .ok_or_else(|| needs("Workspace"))?;
            path_segment(&workspace, "workspace id")?;
            // U3 (K1, W-B-1, Owner O3): a Task is completed in an active
            // Session of the context; `send` reads its state before the
            // request goes, and a context that names none is refused here.
            if context.and_then(|c| c.session_id.as_ref()).is_none() {
                return Err(usage(
                    "task complete needs the active Session of the current context, and the \
                     context names no Session; run `memprove begin` to start one, then \
                     `memprove run`, then `memprove task complete`"
                        .to_owned(),
                ));
            }
            // U4 (Y1): a value that is neither a run label nor `last` is
            // judged by its spelling alone (an ID, or a mistake that no
            // state of the Session changes): refused at once, as before.
            for (ordinal, (_, value)) in options
                .iter()
                .filter(|(name, _)| *name == "--evidence")
                .enumerate()
            {
                let value = value.to_string_lossy();
                if !context::is_run_label(&value) && value != LAST_EVIDENCE {
                    evidence_ref(&value, ordinal + 1, lookup, "task complete")?;
                }
            }
            let chosen = (|| -> Result<(Vec<String>, Vec<String>), UsageError> {
                let mut evidence = Vec::new();
                for (ordinal, (_, value)) in options
                    .iter()
                    .filter(|(name, _)| *name == "--evidence")
                    .enumerate()
                {
                    let id = evidence_ref(
                        &value.to_string_lossy(),
                        ordinal + 1,
                        lookup,
                        "task complete",
                    )?;
                    if !evidence.contains(&id) {
                        evidence.push(id);
                    }
                }
                // P3-L L11 (O3): without --evidence, every citable passed run of
                // the current state; none: the latest run, as before. L11 patch:
                // not while the latest run of some command did not pass.
                let mut cited = Vec::new();
                if evidence.is_empty()
                    && let Some(context) = context
                {
                    let Ok(runs) = default_completion(context) else {
                        return Err(failing_runs_refusal(context));
                    };
                    for run in runs {
                        evidence.push(path_segment(&run.evidence_id, "evidence id")?.to_owned());
                        cited.push(run.label.clone());
                    }
                }
                if evidence.is_empty() {
                    evidence.push(evidence_ref(LAST_EVIDENCE, 0, lookup, "task complete")?);
                }
                Ok((evidence, cited))
            })();
            let (evidence, cited, refusal) = match chosen {
                Ok((evidence, cited)) => (evidence, cited, None),
                Err(error) if defer => (Vec::new(), Vec::new(), Some(error.0)),
                Err(error) => return Err(error),
            };
            let mut request = Request::bare(
                OperationId::TransitionTask,
                format!("/v1/tasks/{task_id}/transition"),
            );
            if refusal.is_none() {
                // U9 SF1-A: the context's Session asks (checked above).
                let session = context.and_then(|c| c.session_id.as_deref());
                request.body = Some(completion_body(revision, &evidence, &workspace, session));
            }
            follow = Follow::TaskCompleted {
                task_id,
                cited,
                refusal,
            };
            (request, &["--evidence", "--revision", "--idempotency-key"])
        }
        ["task", "transition", _] | ["task", "transition"] => {
            let explicit = words.get(2).map(|id| (*id).to_owned());
            let context_task = context.and_then(|c| c.task_id.as_ref());
            let from_context = explicit.is_none() || explicit.as_ref() == context_task;
            let task_id = match explicit {
                Some(id) => id,
                None => context_task
                    .cloned()
                    .ok_or_else(|| usage(lookup.missing("task transition", "<TASK_ID>")))?,
            };
            path_segment(&task_id, "task id")?;
            let revision = match text_of("--revision") {
                Some(_) => revision_of(&text_of, "task transition")?,
                None => context
                    .filter(|_| from_context)
                    .and_then(|c| c.task_revision)
                    .ok_or_else(|| usage(lookup.missing("task transition", "--revision")))?,
            };
            let target = required(&text_of, "--to", "task transition")?;
            let mut request = Request::bare(
                OperationId::TransitionTask,
                format!("/v1/tasks/{task_id}/transition"),
            );
            follow = Follow::TaskTransitioned { task_id };
            let mut body = format!(
                r#"{{"schema_version":1,"expected_revision":{revision},"target_state":{}"#,
                json_string(&target)
            );
            // P2-C: the completion Evidence, in order, and the Workspace
            // whose probe judges it.
            let evidence = options
                .iter()
                .filter(|(name, _)| *name == "--evidence")
                .map(|(_, value)| {
                    let id = value.to_string_lossy();
                    path_segment(&id, "evidence id").map(json_string)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if !evidence.is_empty() {
                write!(
                    body,
                    r#","completion_evidence_ids":[{}]"#,
                    evidence.join(",")
                )
                .expect("writing to a String cannot fail");
            }
            // The daemon takes a Workspace only with `completed`, whose
            // Evidence it judges there (P2-H: any other target with one is
            // `400 invalid_request`).
            let explicit_workspace = text_of("--workspace");
            if target != "completed" && explicit_workspace.is_some() {
                return Err(usage(
                    "--workspace applies only to --to completed (the Workspace whose probe \
                     judges the completion Evidence)",
                ));
            }
            if let Some(workspace) = explicit_workspace
                .or_else(|| context.map(|c| c.workspace_id.clone()))
                .filter(|_| target == "completed")
            {
                write!(
                    body,
                    r#","workspace_id":{}"#,
                    json_string(path_segment(&workspace, "workspace id")?)
                )
                .expect("writing to a String cannot fail");
            }
            // U9 SF1-A (the Owner's O8 exception to R1): a completion of the
            // context's Task is asked by the context's Session, by whose
            // declared role the daemon judges it; none when the context
            // names none or another Task is named.
            if let Some(session) = context
                .filter(|_| from_context && target == "completed")
                .and_then(|c| c.session_id.as_deref())
            {
                write!(
                    body,
                    r#","session_id":{}"#,
                    json_string(path_segment(session, "session id")?)
                )
                .expect("writing to a String cannot fail");
            }
            body.push('}');
            request.body = Some(body);
            (
                request,
                &[
                    "--to",
                    "--revision",
                    "--evidence",
                    "--workspace",
                    "--idempotency-key",
                ],
            )
        }
        ["event", "ingest", source] => {
            let mut request = Request::bare(OperationId::IngestEvent, "/v1/events".into());
            request.body = Some(read_envelope(source)?);
            (request, &["--idempotency-key"])
        }
        ["event", "ingest"] => {
            return Err(usage("event ingest requires an <ENVELOPE_FILE> or -"));
        }
        ["event", "list"] => {
            let project = required(&text_of, "--project", "event list")?;
            (
                Request::bare(
                    OperationId::ListEvents,
                    list_target(
                        "/v1/events",
                        Some(("project_id", project)),
                        text_of("--limit"),
                        text_of("--cursor"),
                    )?,
                ),
                &["--project", "--limit", "--cursor"],
            )
        }
        ["event", "get", event_id] => (
            Request::bare(
                OperationId::GetEvent,
                format!("/v1/events/{}", path_segment(event_id, "event id")?),
            ),
            &[],
        ),
        ["event", "get"] => return Err(usage("event get requires an <EVENT_ID>")),
        ["evidence", "get", evidence_id] => (
            Request::bare(
                OperationId::GetEvidence,
                format!("/v1/evidence/{}", path_segment(evidence_id, "evidence id")?),
            ),
            &[],
        ),
        ["evidence", "get"] => return Err(usage("evidence get requires an <EVIDENCE_ID>")),
        ["checkpoint", "create", source] => {
            let mut request =
                Request::bare(OperationId::CreateCheckpoint, "/v1/checkpoints".into());
            request.body = Some(read_envelope(source)?);
            (request, &["--idempotency-key"])
        }
        ["checkpoint", "create"] => {
            let mut request =
                Request::bare(OperationId::CreateCheckpoint, "/v1/checkpoints".into());
            let draft = checkpoint_draft(options, lookup)?;
            if draft.statements.iter().any(claims::StatementDraft::is_fact) {
                follow = Follow::CheckpointFacts;
            }
            drafted(&mut request, claims::Draft::Checkpoint(draft))?;
            (
                request,
                &[
                    "--fact",
                    "--open",
                    "--reaffirm",
                    FLAG_REAFFIRM_ALL,
                    "--evidence",
                    "--supersedes",
                    "--withdraw",
                    "--withdraw-reason",
                    "--withdraw-session",
                    "--next",
                    "--objective",
                    "--snapshot",
                    "--session",
                    "--workspace",
                    "--task",
                    "--idempotency-key",
                ],
            )
        }
        ["decide", decision] => {
            let mut request = Request::bare(OperationId::ProposeDecision, "/v1/decisions".into());
            drafted(
                &mut request,
                claims::Draft::Decision(decision_draft(decision, options, lookup)?),
            )?;
            (
                request,
                &[
                    "--rationale",
                    "--evidence",
                    "--supersedes",
                    "--task",
                    "--session",
                    "--idempotency-key",
                ],
            )
        }
        ["decide", ..] => {
            return Err(usage(
                "decide requires the decision as one argument: decide \"<TEXT>\"",
            ));
        }
        ["checkpoint", "get", checkpoint_id] => (
            Request::bare(
                OperationId::GetCheckpoint,
                format!(
                    "/v1/checkpoints/{}",
                    path_segment(checkpoint_id, "checkpoint id")?
                ),
            ),
            &[],
        ),
        ["checkpoint", "get"] => return Err(usage("checkpoint get requires a <CHECKPOINT_ID>")),
        ["recover", "preview"] => {
            let task = id_or_context(
                text_of("--task"),
                context.and_then(|c| c.task_id.as_ref()),
                lookup,
                "recover preview",
                "--task",
            )?;
            let mut target = format!("/v1/tasks/{task}/recovery-preview");
            if let Some(workspace) =
                text_of("--workspace").or_else(|| context.map(|c| c.workspace_id.clone()))
            {
                write!(
                    target,
                    "?workspace_id={}",
                    path_segment(&workspace, "workspace id")?
                )
                .expect("writing to a String cannot fail");
            }
            let mut request = Request::bare(OperationId::GetRecoveryPreview, target);
            request.summary = options.iter().any(|(name, _)| *name == FLAG_TEXT);
            (request, &["--task", "--workspace", FLAG_TEXT])
        }
        ["resume"] => {
            let task = id_or_context(
                text_of("--task"),
                context.and_then(|c| c.task_id.as_ref()),
                lookup,
                "resume",
                "--task",
            )?;
            let mut target = format!("/v1/tasks/{task}/recovery-capsule");
            if let Some(workspace) =
                text_of("--workspace").or_else(|| context.map(|c| c.workspace_id.clone()))
            {
                write!(
                    target,
                    "?workspace_id={}",
                    path_segment(&workspace, "workspace id")?
                )
                .expect("writing to a String cannot fail");
            }
            let mut request = Request::bare(OperationId::GetTaskCapsule, target);
            request.summary = options.iter().any(|(name, _)| *name == FLAG_TEXT);
            // P4-A: --all lists every claim one by one; it shapes only the
            // text, so it needs --text.
            request.all_items = options.iter().any(|(name, _)| *name == FLAG_ALL);
            if request.all_items && !request.summary {
                return Err(usage(
                    "--all lists every statement of `resume --text`, superseded and withdrawn \
                     ones too; it is used only with --text (the JSON always holds every claim)",
                ));
            }
            request.capsule_view = capsule_view(
                options.iter().any(|(name, _)| *name == FLAG_PACK),
                text_of("--budget").as_deref(),
                text_of("--claims").as_deref(),
                options
                    .iter()
                    .find(|(name, _)| *name == "--query")
                    .map(|(_, value)| value),
                &request,
            )?;
            // U8 A5 (Owner O4): one Session's statements, by its number.
            if let Some(number) = text_of("--session") {
                if !request.summary || request.capsule_view != CapsuleView::Plain {
                    return Err(usage(
                        "--session lists the statements of one Session in `resume --text`; it \
                         is used with --text (and --all), without --pack and --claims",
                    ));
                }
                let number = number
                    .parse::<u64>()
                    .ok()
                    .filter(|number| *number >= 1)
                    .ok_or_else(|| {
                        usage(
                            "--session takes a Session number k from 1, as the `Session k` lines \
                             number the Task's Sessions",
                        )
                    })?;
                request.capsule_view = CapsuleView::SessionText(number);
            }
            (
                request,
                &[
                    "--task",
                    "--workspace",
                    "--session",
                    FLAG_TEXT,
                    FLAG_ALL,
                    FLAG_PACK,
                    "--budget",
                    "--claims",
                    "--query",
                ],
            )
        }
        ["ledger", "verify"] => {
            // P3-L L10: `--project`, else the current context's Project.
            let project = text_of("--project")
                .or_else(|| context.map(|context| context.project_id.clone()))
                .ok_or_else(|| {
                    usage(format!(
                        "ledger verify needs a Project: pass --project <PROJECT_ID>, or run it \
                         inside a Workspace with a current context (`memprove begin` creates \
                         one); {}",
                        lookup.reason()
                    ))
                })?;
            path_segment(&project, "project id")?;
            let mut request =
                Request::bare(OperationId::VerifyLedger, "/v1/verification/ledger".into());
            request.body = Some(format!(
                r#"{{"schema_version":1,"project_id":{}}}"#,
                json_string(&project)
            ));
            (request, &["--project", "--idempotency-key"])
        }
        [] => return Err(usage("no command given")),
        _ => return Err(usage(unknown_command(words))),
    };
    let mut request = request;
    check_allowed(options, allowed)?;
    if let Some(key) = text_of("--idempotency-key") {
        if !valid_idempotency_key(&key) {
            return Err(usage(
                "--idempotency-key must be 16 to 200 visible ASCII characters",
            ));
        }
        request.idempotency_key = Some(key);
    }
    Ok((request, follow))
}

/// Builds `request`'s body from `draft` now, or leaves it to be built after
/// the current Task Capsule resolves its claim numbers (P3-C).
fn drafted(request: &mut Request, draft: claims::Draft) -> Result<(), UsageError> {
    if draft.needs_capsule() {
        request.pending = Some(draft);
    } else {
        request.body = Some(
            draft
                .render(None)
                .map_err(|error| usage(error.to_string()))?,
        );
    }
    Ok(())
}

/// One claim reference option.
fn claim_ref(name: &str, value: &str) -> Result<claims::ClaimRef, UsageError> {
    claims::ClaimRef::parse(value, name).map_err(usage)
}

/// The `CreateCheckpointRequest` of `checkpoint create` without a file,
/// before its claim references are resolved. Each `--evidence` belongs to
/// the closest `--fact`, `--open`, or `--reaffirm` before it; each
/// `--supersedes` to the closest `--fact`, `--open`, `--reaffirm`, or
/// `--next` before it (P3-C).
#[allow(clippy::too_many_lines)] // One pass over the flags in command-line order.
fn checkpoint_draft(
    options: &[(&'static str, OsString)],
    lookup: &ContextLookup,
) -> Result<claims::CheckpointDraft, UsageError> {
    use claims::{StatementDraft, StatementKind};
    let text_of = |name: &str| text_option(options, name);
    let context = lookup.context();
    let id = |name: &str, from_context: Option<&String>| {
        id_or_context(
            text_of(name),
            from_context,
            lookup,
            "checkpoint create",
            name,
        )
    };
    let mut statements: Vec<StatementDraft> = Vec::new();
    let mut next_supersedes = Vec::new();
    let mut withdrawals = Vec::new();
    // Where the latest --supersedes goes: a statement, or --next.
    let mut owner: Option<Option<usize>> = None;
    // U3 (K4): the place of each --evidence, for its errors.
    let mut evidence_seen = 0;
    for (name, value) in options {
        let value = value.to_string_lossy().into_owned();
        match *name {
            "--fact" | "--open" => {
                if value.is_empty() {
                    return Err(usage(format!("{name} must not be empty")));
                }
                statements.push(StatementDraft {
                    kind: if *name == "--fact" {
                        StatementKind::Fact(value)
                    } else {
                        StatementKind::Open(value)
                    },
                    evidence: Vec::new(),
                    supersedes: Vec::new(),
                });
                owner = Some(Some(statements.len() - 1));
            }
            "--reaffirm" => {
                statements.push(StatementDraft {
                    kind: StatementKind::Reaffirm(claim_ref(name, &value)?),
                    evidence: Vec::new(),
                    supersedes: Vec::new(),
                });
                owner = Some(Some(statements.len() - 1));
            }
            // P4-A: a placeholder, expanded through the Task Capsule; the
            // --evidence after it applies to every fact it reaffirms. A
            // --supersedes after it belongs to nothing.
            FLAG_REAFFIRM_ALL => {
                statements.push(StatementDraft {
                    kind: StatementKind::ReaffirmAll,
                    evidence: Vec::new(),
                    supersedes: Vec::new(),
                });
                owner = None;
            }
            "--next" => owner = Some(None),
            "--evidence" => {
                let statement = statements.last_mut().ok_or_else(|| {
                    usage(
                        "each --evidence must follow the --fact, --open, --reaffirm, or \
                         --reaffirm-all it supports",
                    )
                })?;
                evidence_seen += 1;
                let value = evidence_ref(&value, evidence_seen, lookup, "checkpoint create")?;
                if !statement.evidence.contains(&value) {
                    statement.evidence.push(value);
                }
            }
            "--supersedes" => {
                let reference = claim_ref(name, &value)?;
                let target = match owner {
                    Some(Some(index)) => &mut statements[index].supersedes,
                    Some(None) => &mut next_supersedes,
                    None => {
                        return Err(usage(
                            "each --supersedes must follow the --fact, --open, --reaffirm, or \
                             --next that replaces the claim; use --withdraw for a claim that \
                             nothing replaces",
                        ));
                    }
                };
                target.push(reference);
            }
            "--withdraw" => withdrawals.push(claim_ref(name, &value)?),
            _ => {}
        }
    }
    // P2-H: a fact (or a reaffirmation) without --evidence cites the latest
    // run, when the context records one. P3-L L5 (Owner O1): an --open
    // without --evidence cites nothing.
    if let Some(latest) = context.and_then(|c| c.evidence_id.as_ref()) {
        for statement in &mut statements {
            if statement.is_fact()
                && statement.evidence.is_empty()
                && statement.kind != StatementKind::ReaffirmAll
            {
                statement
                    .evidence
                    .push(path_segment(latest, "evidence id")?.to_owned());
            }
        }
    }
    // U8 K5 (Owner O5): a fact whose every citation is a run this context
    // recorded as a command run is held back with the one reason, before any
    // request.
    if let Some(sentence) = context.and_then(|context| {
        statements
            .iter()
            .filter(|statement| matches!(statement.kind, StatementKind::Fact(_)))
            .find_map(|statement| context.only_command_runs(&statement.evidence))
            .map(|(run, argv)| run::command_run_cannot_support_fact(&run.label, argv))
    }) {
        return Err(usage(sentence));
    }
    if let Some(index) = statements.iter().position(|statement| {
        statement.is_fact()
            && statement.evidence.is_empty()
            && statement.kind != StatementKind::ReaffirmAll
    }) {
        // U2 (S1, N-3, Owner O4): a body is named by its option and its
        // ordinal among that option's occurrences, never by its text.
        let flag = match &statements[index].kind {
            StatementKind::Fact(_) => {
                let ordinal = statements[..=index]
                    .iter()
                    .filter(|statement| matches!(statement.kind, StatementKind::Fact(_)))
                    .count();
                format!("--fact #{ordinal}")
            }
            _ => "--reaffirm".to_owned(),
        };
        return Err(usage(format!(
            "{flag} needs at least one --evidence of a passed test run, and the \
             current context records no run to default to; run the tests with \
             `memprove run`, or record an unverified or failing result with --open instead"
        )));
    }
    let next = text_of("--next")
        .filter(|next| !next.is_empty())
        .ok_or_else(|| usage("checkpoint create requires --next <TEXT> (or a <REQUEST_FILE>)"))?;
    // P3-D2: why the withdrawn claims no longer hold (a withdrawn fact
    // needs it; the daemon checks which claims are facts).
    let withdrawal_reason = text_of("--withdraw-reason");
    if withdrawal_reason.as_deref() == Some("") {
        return Err(usage("--withdraw-reason must not be empty"));
    }
    // U8 A5 (Owner O4): every statement in force of one Session, by its
    // number; it needs a reason, as a withdrawn fact does.
    let withdraw_session = match text_of("--withdraw-session") {
        None => None,
        Some(number) => Some(
            number
                .parse::<u64>()
                .ok()
                .filter(|number| *number >= 1)
                .ok_or_else(|| {
                    usage(
                        "--withdraw-session takes a Session number k from 1, as the `Session k` lines \
                         number the Task's Sessions",
                    )
                })?,
        ),
    };
    if withdraw_session.is_some() && withdrawal_reason.is_none() {
        return Err(usage(
            "--withdraw-session needs --withdraw-reason <TEXT>, which says why that Session's \
             statements no longer hold",
        ));
    }
    if withdrawal_reason.is_some() && withdrawals.is_empty() && withdraw_session.is_none() {
        return Err(usage(
            "--withdraw-reason says why the --withdraw claims no longer hold; give --withdraw too",
        ));
    }
    let objective = text_of("--objective")
        .or_else(|| context.and_then(|c| c.task_title.clone()))
        .filter(|objective| !objective.is_empty())
        .ok_or_else(|| usage(lookup.missing("checkpoint create", "--objective")))?;
    // U9 K1 (U8 V-N3): with `--withdraw-session k`, a missing Snapshot is
    // told after the Task Capsule has checked `k`.
    let snapshot_given = text_of("--snapshot").is_some()
        || context.is_some_and(|context| context.snapshot_id.is_some());
    let snapshot_id = if withdraw_session.is_some() && !snapshot_given {
        Err(lookup
            .missing("checkpoint create", "--snapshot")
            .into_boxed_str())
    } else {
        Ok(id(
            "--snapshot",
            context.and_then(|c| c.snapshot_id.as_ref()),
        )?)
    };
    Ok(claims::CheckpointDraft {
        workspace_id: id("--workspace", context.map(|c| &c.workspace_id))?,
        task_id: id("--task", context.and_then(|c| c.task_id.as_ref()))?,
        session_id: id("--session", context.and_then(|c| c.session_id.as_ref()))?,
        objective,
        statements,
        next,
        next_supersedes,
        withdrawals,
        withdrawal_reason,
        withdraw_session,
        state_runs: context.map(|c| c.runs.clone()).unwrap_or_default(),
        // P4-A: the state of those runs, when the Checkpoint is sealed on
        // the Snapshot they belong to.
        state_manifest: context
            .filter(|c| {
                snapshot_id
                    .as_ref()
                    .is_ok_and(|snapshot_id| c.snapshot_id.as_ref() == Some(snapshot_id))
            })
            .and_then(|c| c.snapshot_manifest.clone()),
        // P4-B (T18 N-c): the Workspace those runs are of.
        state_workspace: context.map(|c| c.workspace_id.clone()),
        snapshot_id,
    })
}

/// The `DecisionProposal` of `decide "<TEXT>"` (ADR 0013 D2, P3-C), before
/// its claim references are resolved. The Task and Session come from the
/// context unless given; Evidence is cited only with --evidence.
fn decision_draft(
    decision: &str,
    options: &[(&'static str, OsString)],
    lookup: &ContextLookup,
) -> Result<claims::DecisionDraft, UsageError> {
    let text_of = |name: &str| text_option(options, name);
    let context = lookup.context();
    if decision.is_empty() {
        return Err(usage("decide: the decision must not be empty"));
    }
    let rationale = text_of("--rationale");
    if rationale.as_deref() == Some("") {
        return Err(usage("--rationale must not be empty"));
    }
    let mut evidence = Vec::new();
    let mut supersedes = Vec::new();
    let mut evidence_seen = 0;
    for (name, value) in options {
        let value = value.to_string_lossy();
        match *name {
            "--evidence" => {
                evidence_seen += 1;
                let value = evidence_ref(&value, evidence_seen, lookup, "decide")?;
                if !evidence.contains(&value) {
                    evidence.push(value);
                }
            }
            "--supersedes" => supersedes.push(claim_ref(name, &value)?),
            _ => {}
        }
    }
    Ok(claims::DecisionDraft {
        task_id: id_or_context(
            text_of("--task"),
            context.and_then(|c| c.task_id.as_ref()),
            lookup,
            "decide",
            "--task",
        )?,
        session_id: id_or_context(
            text_of("--session"),
            context.and_then(|c| c.session_id.as_ref()),
            lookup,
            "decide",
            "--session",
        )?,
        content: decision.to_owned(),
        rationale,
        evidence,
        supersedes,
    })
}

/// The positive `--revision` of a lifecycle command.
fn revision_of(
    text_of: &impl Fn(&str) -> Option<String>,
    command: &str,
) -> Result<u64, UsageError> {
    required(text_of, "--revision", command)?
        .parse::<u64>()
        .ok()
        .filter(|revision| *revision >= 1)
        .ok_or_else(|| usage("--revision must be a positive integer"))
}

/// The JSON body of `event ingest` or `checkpoint create`, from a file or `-`
/// for stdin.
fn read_envelope(source: &str) -> Result<String, UsageError> {
    let mut text = String::new();
    let read = if source == "-" {
        io::stdin()
            .take(MAX_ENVELOPE_BYTES + 1)
            .read_to_string(&mut text)
    } else {
        File::open(source)
            .and_then(|file| file.take(MAX_ENVELOPE_BYTES + 1).read_to_string(&mut text))
    };
    // U3 (K4): the file is not named; the error of reading it is.
    read.map_err(|error| {
        usage(if source == "-" {
            format!("cannot read the request from standard input: {error}")
        } else {
            format!("cannot read the request from the file given: {error}")
        })
    })?;
    if text.len() as u64 > MAX_ENVELOPE_BYTES {
        return Err(usage("the request exceeds 1 MiB"));
    }
    Ok(text)
}

/// `CreateClientTokenRequest` JSON from `--label` and every `--scope`.
fn create_body(options: &[(&'static str, OsString)]) -> Result<String, UsageError> {
    let values = |wanted: &str| -> Vec<String> {
        options
            .iter()
            .filter(|(name, _)| *name == wanted)
            .map(|(_, value)| json_string(&value.to_string_lossy()))
            .collect()
    };
    let label = values("--label")
        .pop()
        .ok_or_else(|| usage("token create requires --label"))?;
    let scopes = values("--scope");
    if scopes.is_empty() {
        return Err(usage("token create requires at least one --scope"));
    }
    Ok(format!(
        r#"{{"schema_version":1,"client_label":{label},"scopes":[{}]}}"#,
        scopes.join(",")
    ))
}

/// The value of a required command option.
fn required(
    text_of: &impl Fn(&str) -> Option<String>,
    name: &str,
    command: &str,
) -> Result<String, UsageError> {
    text_of(name).ok_or_else(|| usage(format!("{command} requires {name}")))
}

/// What the Evidence of a `run` cannot hold, refused before the command
/// runs; the text of the argument is not repeated.
fn refuse_unrecordable_argv(argv: &[String]) -> Result<(), UsageError> {
    // U1 (C2): a control character in any element.
    if argv
        .iter()
        .any(|argument| argument.chars().any(char::is_control))
    {
        return Err(usage(
            "run refuses a command with a control character (Unicode category Cc) in the \
             program or in any argument; the command was not run and nothing was sent",
        ));
    }
    // U3 (K5, Owner O4): memproved refuses an argv that holds a string in
    // the format of a memprove token (C4's rule), so a command that has
    // one is refused before it runs, as C2 refuses a control character.
    if argv.iter().any(|argument| holds_token_shape(argument)) {
        return Err(usage(
            "run refuses a command with a string in the format of a memprove token (43 \
             characters of A-Z, a-z, 0-9, '-', and '_', with at least one upper-case letter, one \
             lower-case letter, and one digit) in the program or in any argument; the command \
             was not run and nothing was sent",
        ));
    }
    Ok(())
}

/// U3 (K5, Owner O4): whether `text` holds a string in the format of a
/// memprove token, by memproved's C4 rule; U5 P2 (Owner O4 a, c): a
/// maximal run of exactly 43 characters of `A-Z`, `a-z`, `0-9`, `-`, and
/// `_` with an upper-case letter, a lower-case letter, and a digit, the
/// one rule of [`memprove_domain::holds_token_shape`]. memproved also
/// refuses a token it issued whatever its characters, which the CLI cannot
/// know: such an argv is refused when the run is recorded, after it ran.
fn holds_token_shape(text: &str) -> bool {
    memprove_domain::holds_token_shape(text)
}

/// `value` as one URL path segment or query value.
fn path_segment<'a>(value: &'a str, what: &str) -> Result<&'a str, UsageError> {
    if is_url_safe(value) {
        Ok(value)
    } else {
        Err(usage(format!("the {what} contains unexpected characters")))
    }
}

/// `path` made absolute against the current directory, as UTF-8.
fn absolute_path(path: &str) -> Result<String, UsageError> {
    // U3 (K4): the path is not repeated.
    let absolute = std::path::absolute(path)
        .map_err(|error| usage(format!("cannot make the path given absolute: {error}")))?;
    absolute
        .into_os_string()
        .into_string()
        .map_err(|_| usage("the path given is not valid UTF-8"))
}

/// List request target with an optional required subject parameter, `limit`,
/// and `cursor`.
fn list_target(
    base: &str,
    subject: Option<(&str, String)>,
    limit: Option<String>,
    cursor: Option<String>,
) -> Result<String, UsageError> {
    let mut query = Vec::new();
    if let Some((name, value)) = subject {
        query.push(format!("{name}={}", path_segment(&value, name)?));
    }
    if let Some(limit) = limit {
        if limit.is_empty() || !limit.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(usage("--limit must be a positive integer"));
        }
        query.push(format!("limit={limit}"));
    }
    if let Some(cursor) = cursor {
        if !is_url_safe(&cursor) {
            return Err(usage("--cursor contains unexpected characters"));
        }
        query.push(format!("cursor={cursor}"));
    }
    Ok(if query.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", query.join("&"))
    })
}

fn is_url_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_idempotency_key(key: &str) -> bool {
    KEY_CHARS.contains(&key.len()) && key.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Encodes `value` as a JSON string literal.
#[must_use]
pub fn json_string(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            control if u32::from(control) < 0x20 => {
                write!(encoded, "\\u{:04x}", u32::from(control))
                    .expect("writing to a String cannot fail");
            }
            other => encoded.push(other),
        }
    }
    encoded.push('"');
    encoded
}

/// Generates a random `Idempotency-Key` from `/dev/urandom`.
///
/// # Errors
///
/// Returns the I/O error when the random device cannot be read.
pub fn generate_idempotency_key() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().fold(String::from("cli-"), |mut key, byte| {
        write!(key, "{byte:02x}").expect("writing to a String cannot fail");
        key
    }))
}

/// Why no usable bearer token could be loaded. Messages never include the
/// token itself.
#[derive(Debug)]
pub enum TokenSourceError {
    /// The token file could not be opened or read.
    Unreadable {
        /// Token file path.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
    /// The token file is not a regular file.
    NotAFile(PathBuf),
    /// The token file grants group or other access.
    InsecurePermissions {
        /// Token file path.
        path: PathBuf,
        /// Observed permission bits.
        mode: u32,
    },
    /// The token file or variable is empty, multi-line, or not UTF-8.
    Malformed(String),
}

impl fmt::Display for TokenSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, source } => {
                write!(
                    formatter,
                    "cannot read token file {}: {source}",
                    path.display()
                )
            }
            Self::NotAFile(path) => {
                write!(
                    formatter,
                    "token file {} is not a regular file",
                    path.display()
                )
            }
            Self::InsecurePermissions { path, mode } => write!(
                formatter,
                "token file {} has mode {mode:04o}; it must not be accessible by group or \
                 others (chmod 600)",
                path.display()
            ),
            Self::Malformed(source) => write!(
                formatter,
                "{source} must hold exactly one token on a single line"
            ),
        }
    }
}

impl std::error::Error for TokenSourceError {}

/// Resolves the bearer token: `--token-file`, else `MEMPROVE_TOKEN`, else
/// the file named by `MEMPROVE_TOKEN_FILE`. Empty variables are ignored.
///
/// # Errors
///
/// Returns [`TokenSourceError`] when the chosen source is unusable.
pub fn resolve_token(
    token_file: Option<&Path>,
    env_token: Option<OsString>,
    env_token_file: Option<OsString>,
) -> Result<Option<String>, TokenSourceError> {
    if let Some(path) = token_file {
        return read_token_file(path).map(Some);
    }
    if let Some(token) = env_token.filter(|token| !token.is_empty()) {
        let token = token
            .into_string()
            .map_err(|_| TokenSourceError::Malformed(TOKEN_ENV.to_owned()))?;
        return single_token(&token, TOKEN_ENV).map(Some);
    }
    match env_token_file.filter(|path| !path.is_empty()) {
        Some(path) => read_token_file(Path::new(&path)).map(Some),
        None => Ok(None),
    }
}

/// Reads a token file that only its owner can access.
///
/// # Errors
///
/// Returns [`TokenSourceError`] when the file is unreadable, not a regular
/// file, accessible by group or others, or malformed.
pub fn read_token_file(path: &Path) -> Result<String, TokenSourceError> {
    let unreadable = |source| TokenSourceError::Unreadable {
        path: path.to_path_buf(),
        source,
    };
    let file = File::open(path).map_err(unreadable)?;
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(TokenSourceError::NotAFile(path.to_path_buf()));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(TokenSourceError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    let mut contents = String::new();
    file.take(MAX_TOKEN_FILE_BYTES)
        .read_to_string(&mut contents)
        .map_err(|_| TokenSourceError::Malformed(format!("token file {}", path.display())))?;
    single_token(&contents, &format!("token file {}", path.display()))
}

fn single_token(raw: &str, source: &str) -> Result<String, TokenSourceError> {
    let token = raw.strip_suffix('\n').unwrap_or(raw);
    let token = token.strip_suffix('\r').unwrap_or(token);
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(TokenSourceError::Malformed(source.to_owned()));
    }
    Ok(token.to_owned())
}

/// A received and contract-checked response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// Media type without parameters.
    pub media_type: String,
    /// Raw body text.
    pub body: String,
}

impl Reply {
    /// Whether the status is a success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Problem `detail`, when the body is a Problem that carries one.
    #[must_use]
    pub fn problem_detail(&self) -> Option<String> {
        let body = parse_strict_bytes(self.body.as_bytes()).ok()?;
        body.get("detail")
            .and_then(JsonValue::as_str)
            .filter(|detail| !detail.is_empty())
            .map(str::to_owned)
    }

    /// The standard-error line for a refused `operation`: status, Problem
    /// code, and the Problem `detail` when there is one (P2-H).
    #[must_use]
    pub fn failure_line(&self, operation: OperationId) -> String {
        let mut line = format!(
            "memprove: {operation} failed: {} {}",
            self.status,
            self.problem_code().unwrap_or_default()
        );
        let detail = self.problem_detail();
        if let Some(detail) = &detail {
            write!(line, ": {detail}").expect("writing to a String cannot fail");
        }
        // U10 N4: a completion refused by a daemon that does not know
        // `session_id` says which build to upgrade to.
        if let Some(hint) = older_daemon_hint(operation, self.status, detail.as_deref()) {
            write!(line, "\nmemprove: {hint}").expect("writing to a String cannot fail");
        }
        line
    }

    /// Problem `code`, when the body is a Problem.
    #[must_use]
    pub fn problem_code(&self) -> Option<String> {
        let body = parse_strict_bytes(self.body.as_bytes()).ok()?;
        body.get("code")
            .and_then(JsonValue::as_str)
            .map(str::to_owned)
    }
}

/// Failure to obtain a contract-valid response.
#[derive(Debug)]
pub enum CallError {
    /// The daemon could not be reached or the exchange failed.
    Transport {
        /// Socket path.
        socket: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
    /// The response could not be parsed or violates the frozen contract.
    Contract(String),
    /// The bearer token cannot be sent in an HTTP header.
    InvalidToken,
    /// The response is larger than the CLI reads for the operation
    /// ([`response_limit`]); nothing of it was used (P3-C2, T12 S-5).
    ResponseTooLarge {
        /// The operation.
        operation: OperationId,
        /// The limit in bytes.
        limit: u64,
    },
}

impl fmt::Display for CallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { socket, source } => write!(
                formatter,
                "cannot reach memproved at {}: {source} (is the daemon running?)",
                socket.display()
            ),
            Self::Contract(detail) => write!(formatter, "response violates the contract: {detail}"),
            Self::InvalidToken => write!(formatter, "{TOKEN_ENV} must not contain line breaks"),
            Self::ResponseTooLarge { operation, limit } => write!(
                formatter,
                "the {operation} response exceeds the CLI's limit of {limit} bytes ({} MiB); \
                 nothing of it was used",
                limit >> 20
            ),
        }
    }
}

impl std::error::Error for CallError {}

/// Sends `request` over `socket`, with `token` as a bearer credential when
/// present, and validates the response against the operation binding.
///
/// # Errors
///
/// Returns [`CallError::Transport`] when the exchange fails or the connection
/// closes before any response byte, [`CallError::ResponseTooLarge`] when the
/// response is longer than [`response_limit`], [`CallError::Contract`] when
/// the response is malformed or not allowed by the
/// contract, and [`CallError::InvalidToken`] when `token` contains a line break.
///
/// # Panics
///
/// Panics only if the frozen registry lacks a binding for the operation, which
/// the protocol crate's own tests rule out.
pub fn call(socket: &Path, request: &Request, token: Option<&str>) -> Result<Reply, CallError> {
    let transport = |source| CallError::Transport {
        socket: socket.to_path_buf(),
        source,
    };
    let binding = binding_for(request.operation.as_str()).expect("every OperationId has a binding");
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: continuity.local\r\nAccept: application/json, application/problem+json\r\nConnection: close\r\n",
        binding.method, request.target
    );
    if let Some(token) = token {
        if token.contains(['\r', '\n']) {
            return Err(CallError::InvalidToken);
        }
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    if let Some(key) = &request.idempotency_key {
        write!(head, "Idempotency-Key: {key}\r\n").expect("writing to a String cannot fail");
    }
    let body = request.body.as_deref().unwrap_or_default();
    if request.body.is_some() {
        head.push_str("Content-Type: application/json\r\n");
    }
    if request.body.is_some() || binding.method == "POST" {
        write!(head, "Content-Length: {}\r\n", body.len())
            .expect("writing to a String cannot fail");
    }
    head.push_str("\r\n");
    head.push_str(body);

    let mut stream = UnixStream::connect(socket).map_err(transport)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(transport)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(transport)?;
    stream.write_all(head.as_bytes()).map_err(transport)?;
    let mut raw = Vec::new();
    let limit = response_limit(request.operation);
    stream
        .take(limit.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(transport)?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > limit {
        return Err(CallError::ResponseTooLarge {
            operation: request.operation,
            limit,
        });
    }
    if raw.is_empty() {
        // The daemon closed the connection without answering (for example it
        // was killed mid-request): the outcome is unknown, as for any other
        // transport failure, so the caller should retry with the same key.
        return Err(transport(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the connection closed before any response",
        )));
    }
    let reply = parse_http_response(&raw)?;
    check_contract(request.operation, &reply)?;
    Ok(reply.reply)
}

/// A parsed HTTP response with the challenge header kept for validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedResponse {
    /// Status, media type, and body.
    pub reply: Reply,
    /// `WWW-Authenticate` value, if any.
    pub www_authenticate: Option<String>,
}

/// Parses a complete `Connection: close` HTTP/1.1 response.
///
/// # Errors
///
/// Returns [`CallError::Contract`] for a malformed status line, headers,
/// framing, or a non-UTF-8 body.
pub fn parse_http_response(raw: &[u8]) -> Result<ParsedResponse, CallError> {
    let malformed =
        |detail: &str| CallError::Contract(format!("malformed HTTP response: {detail}"));
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| malformed("no header terminator"))?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| malformed("non-UTF-8 header"))?;
    let mut body = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(malformed("unexpected protocol version"));
    }
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| malformed("bad status code"))?;

    let mut media_type = None;
    let mut content_length = None;
    let mut www_authenticate = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| malformed("header without colon"))?;
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-type" => {
                let essence = value.split(';').next().unwrap_or_default().trim();
                media_type = Some(essence.to_ascii_lowercase());
            }
            "content-length" => {
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| malformed("bad Content-Length"))?,
                );
            }
            "transfer-encoding" => return Err(malformed("unsupported Transfer-Encoding")),
            "www-authenticate" => www_authenticate = Some(value.to_owned()),
            _ => {}
        }
    }
    if let Some(length) = content_length {
        body = body
            .get(..length)
            .ok_or_else(|| malformed("body shorter than Content-Length"))?;
    }
    let body = String::from_utf8(body.to_vec()).map_err(|_| malformed("non-UTF-8 body"))?;
    Ok(ParsedResponse {
        reply: Reply {
            status,
            media_type: media_type.unwrap_or_default(),
            body,
        },
        www_authenticate,
    })
}

/// Validates a parsed response against `operation`'s frozen binding.
///
/// # Errors
///
/// Returns [`CallError::Contract`] with the validator diagnostic.
pub fn check_contract(operation: OperationId, response: &ParsedResponse) -> Result<(), CallError> {
    let reply = &response.reply;
    let body = parse_strict_bytes(reply.body.as_bytes())
        .map_err(|error| CallError::Contract(format!("body is not strict JSON: {error}")))?;
    validate_response(operation, reply.status, &reply.media_type, &body)
        .map_err(|error| CallError::Contract(error.to_string()))?;
    if reply.status == 401 {
        let challenge = response.www_authenticate.clone().unwrap_or_default();
        validate_www_authenticate(&JsonValue::String(challenge))
            .map_err(|error| CallError::Contract(format!("401 challenge: {error}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn call_of(invocation: Invocation) -> (PathBuf, Request) {
        match invocation {
            Invocation::Call {
                socket, request, ..
            } => (socket, request),
            Invocation::Help
            | Invocation::Version
            | Invocation::Doctor(_)
            | Invocation::Backup { .. }
            | Invocation::Restore { .. }
            | Invocation::CommandHelp(_)
            | Invocation::Run { .. }
            | Invocation::Begin { .. }
            | Invocation::ShowContext(_)
            | Invocation::Hook(_)
            | Invocation::Init(_)
            | Invocation::Mcp(_) => {
                panic!("expected a call")
            }
        }
    }

    #[test]
    fn run_takes_the_command_after_the_separator() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let parse = |words: &[&str]| {
            let mut argv = args(&["--data-dir", "/d"]);
            argv.extend(args(words));
            parse_args(argv, None)
        };
        let base = ["run", "--session", id, "--workspace", id, "--task", id];
        let with = |extra: &[&str]| {
            let mut words = base.to_vec();
            words.extend_from_slice(extra);
            parse(&words)
        };
        let Ok(Invocation::Run { spec, .. }) = with(&[
            "--test",
            "--test-cases",
            "4",
            "--",
            "cargo",
            "test",
            "--",
            "--nocapture",
        ]) else {
            panic!("expected a run");
        };
        assert_eq!(spec.argv, ["cargo", "test", "--", "--nocapture"]);
        assert_eq!(
            spec.test,
            Some(TestSpec {
                name: None,
                case_count: Some(4),
                format: None,
            })
        );
        let Ok(Invocation::Run { spec, .. }) = with(&["--", "make"]) else {
            panic!("expected a run");
        };
        assert_eq!((spec.argv.len(), spec.test), (1, None));
        assert!(!spec.digest_only);
        let Ok(Invocation::Run { spec, .. }) = with(&["--digest-only", "--", "make"]) else {
            panic!("expected a run");
        };
        assert!(spec.digest_only);
        for invalid in [
            with(&["--digest-only", "--digest-only", "--", "make"]),
            parse(&["status", "--digest-only"]),
            with(&[]),
            with(&["--"]),
            with(&["--test-cases", "1", "--", "make"]),
            with(&["--test", "--test-cases", "-1", "--", "make"]),
            with(&["--test", "--test", "--", "make"]),
            with(&["--title", "x", "--", "make"]),
            parse(&["run", "--session", id, "--task", id, "--", "make"]),
            parse(&["status", "--", "make"]),
            parse(&["status", "--test"]),
        ] {
            assert!(invalid.is_err(), "{invalid:?}");
        }
    }

    const P: &str = "018f47a0-0000-7000-8000-0000000000a1";
    const W: &str = "018f47a0-0000-7000-8000-0000000000a2";
    const T: &str = "018f47a0-0000-7000-8000-0000000000a3";
    const S: &str = "018f47a0-0000-7000-8000-0000000000a4";
    const N: &str = "018f47a0-0000-7000-8000-0000000000a5";
    const X: &str = "018f47a0-0000-7000-8000-0000000000ff";

    fn found() -> ContextLookup {
        ContextLookup::Found(context::Context {
            workspace_root: PathBuf::from("/work"),
            project_id: P.to_owned(),
            workspace_id: W.to_owned(),
            agent_id: "018f47a0-0000-7000-8000-0000000000a6".to_owned(),
            task_id: Some(T.to_owned()),
            task_title: Some("Make it pass".to_owned()),
            task_revision: Some(3),
            task_state: Some("in_progress".to_owned()),
            session_id: Some(S.to_owned()),
            session_revision: Some(1),
            snapshot_id: Some(N.to_owned()),
            snapshot_manifest: None,
            evidence_id: None,
            evidence_status: None,
            runs: Vec::new(),
            next_run: 1,
            agent_name: None,
            agent_role: None,
            parent_session_id: None,
        })
    }

    /// The latest run's Evidence, as `memprove run` records it (P2-H).
    const E: &str = "018f47a0-0000-7000-8000-0000000000e9";

    fn found_with_run() -> ContextLookup {
        let ContextLookup::Found(mut context) = found() else {
            unreachable!()
        };
        context.evidence_id = Some(E.to_owned());
        context.evidence_status = Some("PASS".to_owned());
        ContextLookup::Found(context)
    }

    fn evidence_ids(statement: &JsonValue) -> Vec<String> {
        statement
            .get("evidence_ids")
            .or_else(|| statement.get("completion_evidence_ids"))
            .and_then(JsonValue::as_array)
            .map(|ids| {
                ids.iter()
                    .map(|id| id.as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// P2-H item 3: `task complete` moves the context's Task to `completed`
    /// with its revision and Workspace, citing the latest run by default.
    #[test]
    fn task_complete_uses_the_context_and_the_latest_run() {
        let lookup = found_with_run();
        let (request, follow) = call_in(&["task", "complete"], &lookup);
        assert_eq!(request.operation, OperationId::TransitionTask);
        assert_eq!(request.target, format!("/v1/tasks/{T}/transition"));
        assert!(request.needs_idempotency_key());
        let body = body_of(&request);
        assert_eq!(str_at(&body, "target_state"), Some("completed"));
        assert_eq!(str_at(&body, "workspace_id"), Some(W));
        assert_eq!(
            body.get("expected_revision").and_then(JsonValue::as_i64),
            Some(3)
        );
        assert_eq!(evidence_ids(&body), [E]);
        assert_eq!(
            follow,
            Follow::TaskCompleted {
                task_id: T.to_owned(),
                cited: Vec::new(),
                refusal: None
            }
        );
        let (request, _) = call_in(&["task", "complete", "--evidence", "last"], &lookup);
        assert_eq!(evidence_ids(&body_of(&request)), [E]);
        let (request, _) = call_in(
            &[
                "task",
                "complete",
                "--evidence",
                X,
                "--evidence",
                "last",
                "--revision",
                "9",
            ],
            &lookup,
        );
        let body = body_of(&request);
        assert_eq!(evidence_ids(&body), [X, E]);
        assert_eq!(
            body.get("expected_revision").and_then(JsonValue::as_i64),
            Some(9)
        );

        // No run recorded yet: say how to record one.
        let error = parse_in(&["task", "complete"], &found()).unwrap_err().0;
        assert!(error.contains("memprove run"), "{error}");
        let absent = ContextLookup::Absent {
            cwd: PathBuf::from("/elsewhere"),
        };
        let error = parse_in(&["task", "complete"], &absent).unwrap_err().0;
        assert!(error.contains("memprove begin"), "{error}");
        for invalid in [
            &["task", "complete", "--to", "ready"][..],
            &["task", "complete", "--workspace", W][..],
            &["task", "complete", "--evidence", "a/b"][..],
            &["task", "complete", T][..],
        ] {
            assert!(parse_in(invalid, &lookup).is_err(), "{invalid:?}");
        }
    }

    /// P3-L L11 (O3): `task complete` without `--evidence` cites every
    /// citable passed run of the current state, in label order, not only the
    /// latest; runs without a recorded result and runs that did not pass are
    /// left out; with no passed run it cites the latest run as before. A
    /// later pass of a command restores an earlier pass of it. An explicit
    /// `--evidence` is untouched. The labels cited are in the `Follow`. (The
    /// L11 patch refuses the default while the latest run of a command did
    /// not pass: `l11_task_complete_is_refused_while_the_latest_run_of_a_command_fails`.)
    #[test]
    fn l11_task_complete_cites_all_citable_passed_runs() {
        let cited = |lookup: &ContextLookup, extra: &[&str]| {
            let mut words = vec!["task", "complete"];
            words.extend_from_slice(extra);
            let (request, follow) = call_in(&words, lookup);
            let Follow::TaskCompleted { cited, .. } = follow else {
                panic!("not a completion: {follow:?}");
            };
            (evidence_ids(&body_of(&request)), cited)
        };

        // Three passed runs of three commands: all three, in label order.
        let three = lookup_with_runs(vec![
            run_label("r1", RA, Some("PASS"), Some("a")),
            run_label("r2", RB, Some("PASS"), Some("b")),
            run_label("r3", RC, Some("PASS"), Some("c")),
        ]);
        assert_eq!(
            cited(&three, &[]),
            (
                [RA, RB, RC].map(str::to_owned).to_vec(),
                ["r1", "r2", "r3"].map(str::to_owned).to_vec()
            )
        );

        // r1 passed, then the same argv failed (r2), then passed (r3): r1
        // is restored, r2 did not pass and is not cited.
        let restored = lookup_with_runs(vec![
            run_label("r1", RA, Some("PASS"), Some("a")),
            run_label("r2", RB, Some("FAIL"), Some("a")),
            run_label("r3", RC, Some("PASS"), Some("a")),
        ]);
        assert_eq!(cited(&restored, &[]).1, ["r1", "r3"]);
        // A run carried over from elsewhere has no result recorded here.
        let carried = lookup_with_runs(vec![
            run_label("r1", RA, None, None),
            run_label("r2", RB, Some("PASS"), Some("b")),
        ]);
        assert_eq!(cited(&carried, &[]).0, [RB]);

        // No passed run: the latest run, as before, and no label.
        let only_carried = lookup_with_runs(vec![run_label("r1", RA, None, None)]);
        assert_eq!(cited(&only_carried, &[]), (vec![E.to_owned()], Vec::new()));
        assert_eq!(
            cited(&found_with_run(), &[]),
            (vec![E.to_owned()], Vec::new())
        );

        // An explicit --evidence is not widened.
        assert_eq!(
            cited(&three, &["--evidence", "r2"]),
            (vec![RB.to_owned()], Vec::new())
        );
        assert_eq!(cited(&three, &["--evidence", "last"]).0, [E]);
    }

    const RA: &str = "018f47a0-0000-7000-8000-0000000000d1";
    const RB: &str = "018f47a0-0000-7000-8000-0000000000d2";
    const RC: &str = "018f47a0-0000-7000-8000-0000000000d3";
    const RD: &str = "018f47a0-0000-7000-8000-0000000000d4";

    /// A run the context labelled: its result, when recorded, and the name
    /// of its argv (a stand-in for the digest).
    fn run_label(
        label: &str,
        id: &str,
        status: Option<&str>,
        argv: Option<&str>,
    ) -> context::RunLabel {
        context::RunLabel {
            label: label.to_owned(),
            evidence_id: id.to_owned(),
            status: status.map(str::to_owned),
            argv_sha256: argv.map(str::to_owned),
            kind: None,
            argv: None,
        }
    }

    /// The context of `found_with_run` listing exactly `runs`.
    fn lookup_with_runs(runs: Vec<context::RunLabel>) -> ContextLookup {
        let ContextLookup::Found(mut context) = found_with_run() else {
            unreachable!()
        };
        context.next_run = u64::try_from(runs.len()).unwrap() + 1;
        context.runs = runs;
        ContextLookup::Found(context)
    }

    /// P3-L L11 patch: `task complete` without `--evidence` is refused
    /// locally, as a usage error and before any request, while the latest
    /// run of some command in this repository state did not pass; it names
    /// those runs and says to cite runs with `--evidence`. When the latest
    /// run of every command passed, the default is L11's. An explicit
    /// `--evidence` is cited as given whatever the runs say.
    #[test]
    fn l11_task_complete_is_refused_while_the_latest_run_of_a_command_fails() {
        let message =
            |lookup: &ContextLookup| parse_in(&["task", "complete"], lookup).unwrap_err().0;
        // The runs the message names as failing, before the list of the state.
        let refusal = |lookup: &ContextLookup| {
            let message = message(lookup);
            let (_, named) = message.split_once("did not pass: ").unwrap();
            let (named, _) = named.split_once(". The runs of this state").unwrap();
            named.to_owned()
        };
        let cited_by_default = |lookup: &ContextLookup| {
            let (request, follow) = call_in(&["task", "complete"], lookup);
            let Follow::TaskCompleted { cited, .. } = follow else {
                panic!("not a completion: {follow:?}");
            };
            (evidence_ids(&body_of(&request)), cited)
        };

        // r1 a test that passed, r2 another command that failed: refused,
        // naming r2 and the way out; r1 is offered as the run to cite.
        let failed = lookup_with_runs(vec![
            run_label("r1", RA, Some("PASS"), Some("a")),
            run_label("r2", RB, Some("FAIL"), Some("b")),
        ]);
        assert_eq!(refusal(&failed), "r2 (FAIL)");
        let error = message(&failed);
        assert!(error.contains("`--evidence <LABEL>`"), "{error}");
        // The runs of the state are listed, so the labels can be chosen, and
        // the passed ones are named.
        assert!(
            error.contains("The runs of this state are r1 (PASS), r2 (FAIL)."),
            "{error}"
        );
        assert!(error.contains("the passed runs here are r1)"), "{error}");

        // r1 passed, r2 failed, r3 is the same command as r2 and passed:
        // the latest run of each command passed; r2 is not cited.
        let rerun = lookup_with_runs(vec![
            run_label("r1", RA, Some("PASS"), Some("a")),
            run_label("r2", RB, Some("FAIL"), Some("b")),
            run_label("r3", RC, Some("PASS"), Some("b")),
        ]);
        assert_eq!(
            cited_by_default(&rerun),
            (
                [RA, RC].map(str::to_owned).to_vec(),
                ["r1", "r3"].map(str::to_owned).to_vec()
            )
        );

        // r1 passed, r2 failed: an explicit --evidence r1 is as before.
        let (request, follow) = call_in(&["task", "complete", "--evidence", "r1"], &failed);
        assert_eq!(evidence_ids(&body_of(&request)), [RA]);
        assert_eq!(
            follow,
            Follow::TaskCompleted {
                task_id: T.to_owned(),
                cited: Vec::new(),
                refusal: None
            }
        );
        // So is citing the failing run itself, or the latest run.
        let (request, _) = call_in(&["task", "complete", "--evidence", "r2"], &failed);
        assert_eq!(evidence_ids(&body_of(&request)), [RB]);
        let (request, _) = call_in(&["task", "complete", "--evidence", "last"], &failed);
        assert_eq!(evidence_ids(&body_of(&request)), [E]);

        // The same command: a pass overruled by its own later failure is
        // refused, and so is a command whose only run failed.
        let overruled = lookup_with_runs(vec![
            run_label("r1", RA, Some("PASS"), Some("a")),
            run_label("r2", RB, Some("FAIL"), Some("a")),
            run_label("r3", RC, Some("PASS"), Some("c")),
        ]);
        assert_eq!(refusal(&overruled), "r2 (FAIL)");
        let alone = lookup_with_runs(vec![run_label("r1", RA, Some("FAIL"), Some("a"))]);
        assert_eq!(refusal(&alone), "r1 (FAIL)");
        assert!(
            message(&alone).contains("no run of this state passed"),
            "{}",
            message(&alone)
        );

        // A result that is not PASS is a failure, and every command that
        // ends on one is named, in label order.
        let several = lookup_with_runs(vec![
            run_label("r1", RA, Some("NOT_RUN"), Some("a")),
            run_label("r2", RB, Some("PASS"), Some("b")),
            run_label("r3", RC, Some("FAIL"), Some("c")),
            run_label("r4", RD, Some("PASS"), Some("a")),
        ]);
        // r1 is restored by r4, so only r3 stands.
        assert_eq!(refusal(&several), "r3 (FAIL)");
        let two = lookup_with_runs(vec![
            run_label("r1", RA, Some("NOT_RUN"), Some("a")),
            run_label("r2", RB, Some("PASS"), Some("b")),
            run_label("r3", RC, Some("FAIL"), Some("c")),
        ]);
        assert_eq!(refusal(&two), "r1 (NOT_RUN), r3 (FAIL)");

        // A failed run whose argv this context never saw is a command of
        // its own: it is not restored by a pass of another command.
        let unknown = lookup_with_runs(vec![
            run_label("r1", RA, Some("FAIL"), None),
            run_label("r2", RB, Some("PASS"), Some("b")),
        ]);
        assert_eq!(refusal(&unknown), "r1 (FAIL)");

        // A run carried over from elsewhere has no result recorded here and
        // is no failure; with nothing recorded as passed the default is the
        // latest run, as before.
        let carried = lookup_with_runs(vec![run_label("r1", RA, None, None)]);
        assert_eq!(cited_by_default(&carried), (vec![E.to_owned()], Vec::new()));
        assert_eq!(
            cited_by_default(&found_with_run()),
            (vec![E.to_owned()], Vec::new())
        );
    }

    /// P3-D: `--evidence r<N>` names a run the latest Snapshot seals, by the
    /// label `run` recorded in the context; any other label sends nothing.
    #[test]
    fn run_labels_resolve_through_the_context() {
        let ContextLookup::Found(mut context) = found_with_run() else {
            unreachable!()
        };
        context.label_runs(
            &[X.to_owned(), E.to_owned()],
            E,
            Some("PASS".to_owned()),
            None,
        );
        assert_eq!(context.citable_runs(), "r1 (earlier run), r2 (PASS)");
        let lookup = ContextLookup::Found(context);
        let (request, _) = call_in(
            &[
                "checkpoint",
                "create",
                "--fact",
                "both pass",
                "--evidence",
                "r1",
                "--evidence",
                "r2",
                "--next",
                "n",
            ],
            &lookup,
        );
        let body = body_of(&request);
        let work = body
            .get("verified_completed_work")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(evidence_ids(&work[0]), [X, E]);
        let (request, _) = call_in(&["task", "complete", "--evidence", "r1"], &lookup);
        assert_eq!(evidence_ids(&body_of(&request)), [X]);
        for (label, expected) in [
            (
                "r3",
                "the runs you can cite now are r1 (earlier run), r2 (PASS)",
            ),
            ("r9", "a run of another repository state cannot be cited"),
        ] {
            let error = parse_in(
                &[
                    "checkpoint",
                    "create",
                    "--fact",
                    "x",
                    "--evidence",
                    label,
                    "--next",
                    "n",
                ],
                &lookup,
            )
            .unwrap_err()
            .0;
            assert!(error.contains(expected), "{error}");
        }
        // Not labels; see `label_like_evidence_is_a_usage_error`.
        for spelled in ["r0", "r01", "R1", "r", "r1x"] {
            assert!(!context::is_run_label(spelled), "{spelled}");
        }
        let error = parse_in(&["decide", "d", "--evidence", "r1"], &found())
            .unwrap_err()
            .0;
        assert!(error.contains("it records no run"), "{error}");
    }

    /// An `--evidence` value that looks like a run label but is not one
    /// (`r0`, `r01`, `R1`) is refused locally by every command that takes
    /// `--evidence`, with or without a context; nothing is sent. Values that
    /// do not look like a label still go to the daemon as Evidence IDs.
    #[test]
    fn label_like_evidence_is_a_usage_error() {
        for spelled in ["r0", "r00", "r01", "R1", "R01", "R0"] {
            assert!(context::looks_like_run_label(spelled), "{spelled}");
            assert!(!context::is_run_label(spelled), "{spelled}");
            for lookup in [found_with_run(), found()] {
                for words in [
                    &[
                        "checkpoint",
                        "create",
                        "--fact",
                        "x",
                        "--evidence",
                        spelled,
                        "--next",
                        "n",
                    ][..],
                    &["task", "complete", "--evidence", spelled][..],
                    &["decide", "d", "--evidence", spelled][..],
                ] {
                    let error = parse_in(words, &lookup).unwrap_err().0;
                    // U3 (K4): named by its place, not repeated.
                    assert!(
                        error.contains("--evidence #1 is not a run label"),
                        "{words:?}: {error}"
                    );
                    assert!(!error.contains(spelled), "{words:?}: {error}");
                }
            }
        }
        for spelled in ["r1", "r10"] {
            assert!(context::looks_like_run_label(spelled), "{spelled}");
            assert!(context::is_run_label(spelled), "{spelled}");
        }
        let lookup = found_with_run();
        for spelled in ["r", "r1x", "run1", "1", "R", "rr1"] {
            assert!(!context::looks_like_run_label(spelled), "{spelled}");
            // Sent as given; the daemon refuses what is not an Evidence ID.
            let (request, _) = call_in(&["task", "complete", "--evidence", spelled], &lookup);
            let body = parse_strict_bytes(request.body.as_deref().unwrap().as_bytes()).unwrap();
            assert_eq!(evidence_ids(&body), [spelled]);
        }
    }

    /// P2-H item 4: `--fact` without `--evidence` cites the latest run;
    /// `--evidence last` names it explicitly. P3-L L5: a bare `--open`
    /// cites nothing.
    #[test]
    fn checkpoint_statements_default_to_the_latest_run() {
        let lookup = found_with_run();
        let (request, follow) = call_in(
            &[
                "checkpoint",
                "create",
                "--fact",
                "tests pass",
                "--open",
                "docs unknown",
                "--open",
                "flaky",
                "--evidence",
                X,
                "--fact",
                "named",
                "--evidence",
                "last",
                "--next",
                "n",
            ],
            &lookup,
        );
        assert_eq!(follow, Follow::CheckpointFacts);
        let body = body_of(&request);
        let section = |name: &str| {
            body.get(name)
                .and_then(JsonValue::as_array)
                .unwrap()
                .iter()
                .map(evidence_ids)
                .collect::<Vec<_>>()
        };
        assert_eq!(section("verified_completed_work"), [[E], [E]]);
        assert_eq!(section("open_items"), [vec![], vec![X.to_owned()]]);
        assert_eq!(str_at(&body, "snapshot_id"), Some(N));

        // Without a recorded run, a bare --fact still needs --evidence, and
        // `last` says there is none.
        let error = parse_in(
            &["checkpoint", "create", "--fact", "x", "--next", "n"],
            &found(),
        )
        .unwrap_err()
        .0;
        assert!(error.contains("memprove run"), "{error}");
        let error = parse_in(
            &[
                "checkpoint",
                "create",
                "--open",
                "x",
                "--evidence",
                "last",
                "--next",
                "n",
            ],
            &found(),
        )
        .unwrap_err()
        .0;
        assert!(error.contains("records no run"), "{error}");
    }

    /// U2 (S1, N-3, Owner O4): a local usage error names a body by its
    /// option and ordinal and never repeats it; a word outside the command
    /// vocabulary is not repeated either.
    #[test]
    fn u2_s1_a_usage_error_never_repeats_a_body() {
        let body = "the key is u2S1-tokenShaped_0123456789abcdefghijklmnop, rotate it";
        let error = |words: &[&str]| parse_in(words, &found()).unwrap_err().0;
        for (words, expected) in [
            (
                &["checkpoint", "create", "--fact", body, "--next", "n"][..],
                "--fact #1 needs at least one --evidence",
            ),
            (
                &[
                    "checkpoint",
                    "create",
                    "--open",
                    "o",
                    "--fact",
                    "a",
                    "--evidence",
                    X,
                    "--fact",
                    body,
                    "--next",
                    "n",
                ][..],
                "--fact #2 needs at least one --evidence",
            ),
            (
                &["decide", "plan", body][..],
                "decide requires the decision as one argument",
            ),
            (
                &["checkpoint", body][..],
                "unknown command \"checkpoint <ARG>\"",
            ),
            (&["decide", "-x", body][..], "unknown option \"-x\""),
            (
                &["decide", &format!("-{body}")][..],
                "unknown option: an argument starts with - and names no option",
            ),
        ] {
            let error = error(words);
            assert!(error.contains(expected), "{words:?}: {error}");
            assert!(!error.contains("u2S1"), "{error}");
        }
        // Command words and option names are still repeated.
        assert!(error(&["nonsense", "words"]).contains("unknown command \"nonsense words\""));
        assert!(error(&["task", "--bogus"]).contains("unknown option \"--bogus\""));
    }

    /// U3 (K4, V-N-3, original #65): no usage error repeats an argument
    /// value; it names the option, or the argument's place, instead. Every
    /// command of the help, with each value option and as a positional
    /// argument, given a plain value and a token-shaped one (and twice, and
    /// on a context with runs, with no runs, and with none at all): the
    /// errors never hold either value. A value that is not UTF-8 is not
    /// repeated either.
    #[test]
    fn u3_k4_no_usage_error_repeats_an_argument_value() {
        use std::os::unix::ffi::OsStringExt;
        let token = "u3K4_tokenShaped-0123456789abcdefghijklmnop";
        assert_eq!(token.len(), 43);
        let values = [
            "u3K4plain".to_owned(),
            token.to_owned(),
            format!("#u3K4{token}"),
            "u3K4,5-7".to_owned(),
            "r0u3K4".to_owned(),
        ];
        let lookups = [
            found_with_run(),
            found(),
            ContextLookup::Absent {
                cwd: PathBuf::from("/elsewhere"),
            },
        ];
        let mut refused = 0;
        let mut check = |argv: &[OsString], lookup: &ContextLookup| {
            let mut all = args(&["--data-dir", "/d"]);
            all.extend(argv.iter().cloned());
            if let Err(UsageError(error)) = parse_args_in(all, None, lookup) {
                refused += 1;
                assert!(!error.contains("u3K4"), "{argv:?}: {error}");
                assert!(!error.contains(token), "{argv:?}: {error}");
            }
        };
        let commands = help::COMMANDS
            .iter()
            .chain(help::HOOK_COMMANDS)
            .chain(help::MCP_COMMANDS)
            .chain(help::MAINTENANCE_COMMANDS);
        for command in commands {
            let words = args(&command.name.split(' ').collect::<Vec<_>>());
            for lookup in &lookups {
                for value in &values {
                    let value = OsString::from(value);
                    for (option, _) in VALUE_OPTIONS {
                        let option = OsString::from(option);
                        let once = [&words[..], &[option.clone(), value.clone()]].concat();
                        check(&once, lookup);
                        check(&[&once[..], &[option, value.clone()]].concat(), lookup);
                    }
                    check(&[&words[..], std::slice::from_ref(&value)].concat(), lookup);
                    check(
                        &[&words[..], &[OsString::from("--"), value.clone()]].concat(),
                        lookup,
                    );
                }
            }
        }
        // A value that is not UTF-8: as a run argument, an option's value,
        // and a positional argument.
        let raw = || OsString::from_vec(b"u3K4\xff".to_vec());
        for argv in [
            vec![OsString::from("run"), OsString::from("--"), raw()],
            vec![OsString::from("resume"), OsString::from("--budget"), raw()],
            vec![OsString::from("project"), OsString::from("get"), raw()],
        ] {
            for lookup in &lookups {
                check(&argv, lookup);
            }
        }
        assert!(refused > 1000, "{refused}");
        // A label no run of the context has, and a label-like value: named
        // by their place among the --evidence options.
        for (words, expected) in [
            (
                &[
                    "checkpoint",
                    "create",
                    "--fact",
                    "x",
                    "--evidence",
                    "r1",
                    "--evidence",
                    "r97",
                    "--next",
                    "n",
                ][..],
                "--evidence #2 names no run",
            ),
            (
                &["decide", "d", "--evidence", "r98"][..],
                "--evidence #1 names no run",
            ),
            (
                &["task", "complete", "--evidence", "r1", "--evidence", "r099"][..],
                "--evidence #2 is not a run label",
            ),
        ] {
            let lookup = lookup_with_runs(vec![run_label("r1", RA, Some("PASS"), Some("a"))]);
            let error = parse_in(words, &lookup).unwrap_err().0;
            assert!(error.contains(expected), "{words:?}: {error}");
            for value in ["r97", "r98", "r099"] {
                assert!(!error.contains(value), "{words:?}: {error}");
            }
        }
    }

    /// P3-L L5 (Owner O1): an `--open` without an `--evidence` of its own
    /// cites no Evidence, even when the context records a run; `--fact` and
    /// `--reaffirm` still default to the latest run, and an `--open` with
    /// `--evidence` cites exactly what it names.
    #[test]
    fn l5_open_without_evidence_cites_no_evidence() {
        let lookup = found_with_run();
        let (request, _) = call_in(
            &[
                "checkpoint",
                "create",
                "--open",
                "docs unknown",
                "--next",
                "n",
            ],
            &lookup,
        );
        let body = body_of(&request);
        let open = body
            .get("open_items")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].get("evidence_ids"), None, "{body:?}");
        let (request, _) = call_in(
            &[
                "checkpoint",
                "create",
                "--open",
                "bare",
                "--fact",
                "tests pass",
                "--open",
                "cited",
                "--evidence",
                "last",
                "--open",
                "named",
                "--evidence",
                X,
                "--next",
                "n",
            ],
            &lookup,
        );
        let body = body_of(&request);
        let section = |name: &str| {
            body.get(name)
                .and_then(JsonValue::as_array)
                .unwrap()
                .iter()
                .map(evidence_ids)
                .collect::<Vec<_>>()
        };
        assert_eq!(section("verified_completed_work"), [[E]]);
        assert_eq!(
            section("open_items"),
            [vec![], vec![E.to_owned()], vec![X.to_owned()]]
        );
        // Without any run in the context a bare --open is still accepted.
        let (request, _) = call_in(
            &["checkpoint", "create", "--open", "x", "--next", "n"],
            &found(),
        );
        assert_eq!(
            body_of(&request)
                .get("open_items")
                .and_then(JsonValue::as_array)
                .unwrap()[0]
                .get("evidence_ids"),
            None
        );
    }

    /// P2-H item 5: `context show` needs a context but no daemon location.
    #[test]
    fn context_show_reads_the_context_without_a_daemon() {
        let ContextLookup::Found(context) = found() else {
            unreachable!()
        };
        assert_eq!(
            parse_args_in(args(&["context", "show"]), None, &found()),
            Ok(Invocation::ShowContext(context))
        );
        let absent = ContextLookup::Absent {
            cwd: PathBuf::from("/elsewhere"),
        };
        let error = parse_args_in(args(&["context", "show"]), None, &absent)
            .unwrap_err()
            .0;
        assert!(
            error.contains("/elsewhere is not inside a Workspace"),
            "{error}"
        );
        assert!(error.contains("memprove begin"), "{error}");
        for invalid in [
            &["context", "show", "--task", T][..],
            &["context", "show", "--", "true"][..],
            &["context"][..],
        ] {
            assert!(
                parse_args_in(args(invalid), Some("/d".into()), &found()).is_err(),
                "{invalid:?}"
            );
        }
    }

    /// P2-H item 2: what `begin` does with the previous Session and the
    /// Task's state.
    #[test]
    fn begin_refuses_an_active_session_and_a_finished_task() {
        assert_eq!(previous_session_check(S, Ok(Some("ended"))), Ok(()));
        // Not listed: not active, and `end` could not end it.
        assert_eq!(previous_session_check(S, Ok(None)), Ok(()));
        for listed in [
            Ok(Some("active")),
            Err("listSessions answered 403 policy_denied".to_owned()),
        ] {
            let refusal = previous_session_check(S, listed.clone()).unwrap_err();
            assert!(refusal.contains(S), "{refusal}");
            assert!(
                refusal.contains("memprove end --reason"),
                "{listed:?}: {refusal}"
            );
            // U7 P1 (D2 F15): and how a Session someone else left is ended.
            assert!(
                refusal.contains("memprove end --abandoned --reason <why>"),
                "{listed:?}: {refusal}"
            );
        }
        assert!(
            previous_session_check(S, Ok(Some("active")))
                .unwrap_err()
                .contains("still active")
        );

        assert_eq!(
            begin_steps(T, Some("proposed")),
            Ok(&["ready", "in_progress"][..])
        );
        assert_eq!(begin_steps(T, Some("ready")), Ok(&["in_progress"][..]));
        for unchanged in [Some("in_progress"), Some("blocked"), None] {
            assert_eq!(begin_steps(T, unchanged), Ok(&[][..]), "{unchanged:?}");
        }
        for finished in ["completed", "cancelled"] {
            let refusal = begin_steps(T, Some(finished)).unwrap_err();
            assert!(refusal.contains("--new-task"), "{refusal}");
            assert!(refusal.contains(finished), "{refusal}");
        }
    }

    /// P2-H item 2: without --task and --new-task, `begin` continues the
    /// context's Task, and says how to name one when there is none.
    #[test]
    fn begin_without_a_task_continues_the_context_task_or_says_how() {
        let spec = match parse_in(&["begin"], &found()) {
            Ok(Invocation::Begin { spec, .. }) => spec,
            other => panic!("expected a begin, got {other:?}"),
        };
        assert_eq!(spec.task, BeginTask::Existing(T.to_owned()));
        let ContextLookup::Found(mut context) = found() else {
            unreachable!()
        };
        context.task_id = None;
        let error = parse_in(&["begin"], &ContextLookup::Found(context))
            .unwrap_err()
            .0;
        for expected in [
            "--new-task <TITLE>",
            "--task <TASK_ID>",
            "task list --project",
        ] {
            assert!(error.contains(expected), "{expected}: {error}");
        }
        assert!(!error.contains("  "), "{error}");
        let absent = ContextLookup::Absent {
            cwd: PathBuf::from("/w"),
        };
        let error = parse_in(&["begin", "--new-task", "x"], &absent)
            .unwrap_err()
            .0;
        assert_eq!(
            error,
            "begin requires --project <PROJECT_ID> the first time in a Workspace: /w is not \
             inside a Workspace with a current context. `memprove context show` in a \
             Workspace that already has a context prints the Project ID, as does `memprove \
             project register` for the operator"
        );
    }

    /// P2-H item 9: a Problem `detail` is shown on the failure line.
    #[test]
    fn a_problem_detail_is_shown() {
        let problem = |detail: &str| Reply {
            status: 409,
            media_type: "application/problem+json".to_owned(),
            body: format!(
                r#"{{"type":"about:blank","title":"Conflict","status":409,"code":"evidence_stale"{detail},"request_id":"r","retryable":false}}"#
            ),
        };
        assert_eq!(
            problem(r#","detail":"Evidence E is stale""#).failure_line(OperationId::TransitionTask),
            "memprove: transitionTask failed: 409 evidence_stale: Evidence E is stale"
        );
        assert_eq!(
            problem("").failure_line(OperationId::TransitionTask),
            "memprove: transitionTask failed: 409 evidence_stale"
        );
    }

    /// U10 N4 (U9 VN12): only a `400` of `transitionTask` whose `detail` is the
    /// daemon's unknown-member phrase for `session_id` gets the upgrade hint,
    /// with this build; the `400`s of a daemon that knows the member, other
    /// members, other operations, and other statuses get none.
    #[test]
    fn u10_n4_only_an_unknown_session_id_gets_the_upgrade_hint() {
        let unknown = "the request body has an unknown member session_id";
        let reply = |status: u16, detail: &str| Reply {
            status,
            media_type: "application/problem+json".to_owned(),
            body: format!(
                r#"{{"type":"about:blank","title":"T","status":{status},"code":"invalid_request","detail":"{detail}","request_id":"r","retryable":false}}"#
            ),
        };
        let hint = format!(
            "the daemon is older than this build (it does not know session_id); memproved {BUILD_ID} \
             knows it"
        );
        assert_eq!(
            reply(400, unknown).failure_line(OperationId::TransitionTask),
            format!(
                "memprove: transitionTask failed: 400 invalid_request: {unknown}\n\
                 memprove: {hint}"
            )
        );
        for (operation, status, detail) in [
            (
                OperationId::TransitionTask,
                400,
                "$.session_id must name a Session of the Task",
            ),
            (
                OperationId::TransitionTask,
                400,
                "$.session_id applies only to target_state completed",
            ),
            (
                OperationId::TransitionTask,
                400,
                "the request body has an unknown member other_id",
            ),
            (OperationId::CreateSession, 400, unknown),
            (OperationId::TransitionTask, 409, unknown),
        ] {
            let line = reply(status, detail).failure_line(operation);
            assert!(!line.contains("the daemon is older"), "{line}");
            assert_eq!(older_daemon_hint(operation, status, Some(detail)), None);
        }
        assert_eq!(
            older_daemon_hint(OperationId::TransitionTask, 400, None),
            None
        );
    }

    fn parse_in(words: &[&str], lookup: &ContextLookup) -> Result<Invocation, UsageError> {
        let mut argv = args(&["--data-dir", "/d"]);
        argv.extend(args(words));
        parse_args_in(argv, None, lookup)
    }

    fn call_in(words: &[&str], lookup: &ContextLookup) -> (Request, Follow) {
        match parse_in(words, lookup).unwrap() {
            Invocation::Call {
                request, follow, ..
            } => (request, follow),
            other => panic!("expected a call, got {other:?}"),
        }
    }

    fn body_of(request: &Request) -> JsonValue {
        let body = parse_strict_bytes(request.body.as_deref().unwrap().as_bytes()).unwrap();
        memprove_protocol::phase1::validate_request(request.operation, Some(&body)).unwrap();
        body
    }

    fn str_at<'a>(value: &'a JsonValue, name: &str) -> Option<&'a str> {
        value.get(name).and_then(JsonValue::as_str)
    }

    /// U11 N4 (U10 VN14; Owner O6): `task list` without `--project` takes the
    /// Project of the current context (the client session's, else the
    /// directory's, as the lookup gives it) and, when that names none, the
    /// Project every context of the Workspace root records; an explicit
    /// `--project` wins over both; with neither it is the usage error. The
    /// root's Project is asked for only when it is needed.
    #[test]
    fn u11_n4_task_list_takes_the_roots_project_when_the_context_names_none() {
        let asked = std::cell::Cell::new(0_u32);
        let counter = &asked;
        let root = move |project: Option<&'static str>| {
            move || {
                counter.set(counter.get() + 1);
                project.map(str::to_owned)
            }
        };
        let target =
            |words: &[&str], lookup: &ContextLookup, root_project: &dyn Fn() -> Option<String>| {
                let mut argv = args(&["--data-dir", "/d"]);
                argv.extend(args(words));
                parse_args_deferring(
                    argv,
                    None,
                    lookup,
                    &|| None,
                    &|| Ok(PathBuf::from("/d")),
                    &AgentEnv::default(),
                    root_project,
                )
                .map(|invocation| match invocation {
                    Invocation::Call { request, .. } => request.target,
                    other => panic!("expected a call, got {other:?}"),
                })
                .map_err(|error| error.0)
            };
        let absent = ContextLookup::Absent {
            cwd: PathBuf::from("/w"),
        };
        // No context: the root's Project.
        assert_eq!(
            target(&["task", "list"], &absent, &root(Some(X))),
            Ok(format!("/v1/tasks?project_id={X}"))
        );
        assert_eq!(
            target(&["task", "list", "--limit", "5"], &absent, &root(Some(X))),
            Ok(format!("/v1/tasks?project_id={X}&limit=5"))
        );
        // A client session with no context of its own here is `Absent` too.
        let after = asked.get();
        // The current context wins, and the root is not asked.
        assert_eq!(
            target(&["task", "list"], &found(), &root(Some(X))),
            Ok(format!("/v1/tasks?project_id={P}"))
        );
        assert_eq!(asked.get(), after);
        // An explicit --project wins, and the root is not asked.
        assert_eq!(
            target(&["task", "list", "--project", T], &absent, &root(Some(X))),
            Ok(format!("/v1/tasks?project_id={T}"))
        );
        assert_eq!(asked.get(), after);
        // Neither: the usage error of before.
        let error = target(&["task", "list"], &absent, &root(None)).unwrap_err();
        assert!(
            error.starts_with("task list requires --project: /w is not inside a Workspace"),
            "{error}"
        );
    }

    /// U10 N10 (D3 F29): `task list` without `--project` lists the Project of
    /// the directory's context; an explicit `--project` wins; with no context
    /// it is the usage error it was.
    #[test]
    fn u10_n10_task_list_takes_the_project_of_the_context() {
        let target = |words: &[&str], lookup: &ContextLookup| {
            let (request, _) = call_in(words, lookup);
            assert_eq!(request.operation, OperationId::ListTasks);
            request.target
        };
        let lookup = found();
        assert_eq!(
            target(&["task", "list"], &lookup),
            format!("/v1/tasks?project_id={P}")
        );
        assert_eq!(
            target(&["task", "list", "--limit", "5"], &lookup),
            format!("/v1/tasks?project_id={P}&limit=5")
        );
        assert_eq!(
            target(&["task", "list", "--project", X], &lookup),
            format!("/v1/tasks?project_id={X}")
        );
        // No context: the usage error of before, in the same words.
        let error = parse_in(&["task", "list"], &ContextLookup::Unavailable).unwrap_err();
        assert_eq!(error.0, "task list requires --project");
        let absent = ContextLookup::Absent {
            cwd: PathBuf::from("/w"),
        };
        let error = parse_in(&["task", "list"], &absent).unwrap_err();
        assert!(
            error
                .0
                .starts_with("task list requires --project: /w is not inside a Workspace"),
            "{}",
            error.0
        );
    }

    #[test]
    fn omitted_ids_come_from_the_context_and_explicit_ones_win() {
        let lookup = found();
        let Ok(Invocation::Run { spec, .. }) = parse_in(&["run", "--", "true"], &lookup) else {
            panic!("expected a run");
        };
        assert_eq!(
            (
                spec.session_id.as_str(),
                spec.workspace_id.as_str(),
                spec.task_id.as_str()
            ),
            (S, W, T)
        );
        let Ok(Invocation::Run { spec, .. }) =
            parse_in(&["run", "--session", X, "--task", X, "--", "true"], &lookup)
        else {
            panic!("expected a run");
        };
        assert_eq!((spec.session_id.as_str(), spec.task_id.as_str()), (X, X));
        assert_eq!(spec.workspace_id, W);

        let (preview, _) = call_in(&["recover", "preview"], &lookup);
        assert_eq!(
            preview.target,
            format!("/v1/tasks/{T}/recovery-preview?workspace_id={W}")
        );
        let (preview, _) = call_in(
            &["recover", "preview", "--task", X, "--workspace", X],
            &lookup,
        );
        assert_eq!(
            preview.target,
            format!("/v1/tasks/{X}/recovery-preview?workspace_id={X}")
        );

        let (resume, _) = call_in(&["resume"], &lookup);
        assert_eq!(
            resume.target,
            format!("/v1/tasks/{T}/recovery-capsule?workspace_id={W}")
        );

        let (transition, follow) = call_in(&["task", "transition", "--to", "in_progress"], &lookup);
        assert_eq!(transition.target, format!("/v1/tasks/{T}/transition"));
        let body = body_of(&transition);
        assert_eq!(
            body.get("expected_revision").and_then(JsonValue::as_i64),
            Some(3)
        );
        // P2-H: not `completed`, so no Workspace (it was a 400).
        assert_eq!(str_at(&body, "workspace_id"), None);
        assert_eq!(
            follow,
            Follow::TaskTransitioned {
                task_id: T.to_owned()
            }
        );
        // Another Task: the context's revision does not apply to it.
        assert!(parse_in(&["task", "transition", X, "--to", "ready"], &lookup).is_err());
        let (other, _) = call_in(
            &["task", "transition", X, "--to", "ready", "--revision", "7"],
            &lookup,
        );
        assert_eq!(other.target, format!("/v1/tasks/{X}/transition"));
        assert_eq!(
            body_of(&other)
                .get("expected_revision")
                .and_then(JsonValue::as_i64),
            Some(7)
        );

        for words in [&["end"][..], &["session", "end"][..]] {
            let (end, follow) = call_in(words, &lookup);
            assert_eq!(end.operation, OperationId::EndSession);
            assert_eq!(end.target, format!("/v1/sessions/{S}/end"));
            assert_eq!(
                body_of(&end)
                    .get("expected_revision")
                    .and_then(JsonValue::as_i64),
                Some(1)
            );
            assert_eq!(
                follow,
                Follow::SessionEnded {
                    session_id: S.to_owned(),
                    unread: None
                }
            );
        }
        let (end, _) = call_in(&["end", "--revision", "2", "--reason", "done"], &lookup);
        let body = body_of(&end);
        assert_eq!(
            body.get("expected_revision").and_then(JsonValue::as_i64),
            Some(2)
        );
        assert_eq!(str_at(&body, "reason"), Some("done"));
        assert_eq!(str_at(&body, "outcome"), None);
        assert!(parse_in(&["session", "end", X], &lookup).is_err());
    }

    /// P3-D: `end --abandoned` and `session end --abandoned` end the Session
    /// as abandoned, which the daemon records as `session.crashed`.
    #[test]
    fn end_abandoned_sends_the_abandoned_outcome() {
        let lookup = found();
        for words in [
            &["end", "--abandoned"][..],
            &["session", "end", "--abandoned"][..],
        ] {
            let (end, _) = call_in(words, &lookup);
            let body = body_of(&end);
            assert_eq!(str_at(&body, "outcome"), Some("abandoned"), "{words:?}");
            memprove_protocol::phase1::validate_request(OperationId::EndSession, Some(&body))
                .unwrap();
        }
        assert!(parse_in(&["end", "--abandoned", "--abandoned"], &lookup).is_err());
        assert!(parse_in(&["run", "--abandoned", "--", "true"], &lookup).is_err());
    }

    /// P2-H item 1: the daemon refuses `workspace_id` on any target but
    /// `completed` (`400 invalid_request`), so the context's Workspace is
    /// sent only with `--to completed`, and an explicit `--workspace` with
    /// another target is a usage error.
    #[test]
    fn task_transition_sends_the_workspace_only_for_completed() {
        let lookup = found();
        for target in ["ready", "in_progress", "blocked", "cancelled"] {
            let (request, _) = call_in(&["task", "transition", "--to", target], &lookup);
            let body = body_of(&request);
            assert_eq!(str_at(&body, "workspace_id"), None, "{target}");
            assert_eq!(str_at(&body, "target_state"), Some(target));
        }
        let (complete, _) = call_in(
            &["task", "transition", "--to", "completed", "--evidence", X],
            &lookup,
        );
        assert_eq!(str_at(&body_of(&complete), "workspace_id"), Some(W));
        let error = parse_in(
            &["task", "transition", "--to", "ready", "--workspace", W],
            &lookup,
        )
        .unwrap_err()
        .0;
        assert!(error.contains("--to completed"), "{error}");
    }

    #[test]
    fn without_a_context_omitted_ids_are_usage_errors_that_say_why() {
        let absent = ContextLookup::Absent {
            cwd: PathBuf::from("/elsewhere"),
        };
        for words in [
            &["run", "--", "true"][..],
            &["recover", "preview"][..],
            &["task", "transition", "--to", "ready"][..],
            &["end"][..],
            &["session", "end"][..],
            &["checkpoint", "create", "--next", "x", "--objective", "y"][..],
            &["begin"][..],
        ] {
            let error = parse_in(words, &absent).unwrap_err().0;
            assert!(
                error.contains("/elsewhere is not inside a Workspace"),
                "{words:?}: {error}"
            );
        }
        let broken = ContextLookup::Broken("context file /c/x.json is malformed".to_owned());
        let error = parse_in(&["run", "--", "true"], &broken).unwrap_err().0;
        assert!(error.contains("malformed"), "{error}");
        // A Session cleared by `end` is not reused.
        let ContextLookup::Found(mut context) = found() else {
            unreachable!()
        };
        context.session_id = None;
        let error = parse_in(&["end"], &ContextLookup::Found(context))
            .unwrap_err()
            .0;
        assert!(error.contains("has none"), "{error}");
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One request built from flags, checked member by member.
    fn checkpoint_flags_build_the_request_with_evidence_after_each_statement() {
        let lookup = found();
        let e1 = "018f47a0-0000-7000-8000-0000000000e1";
        let e2 = "018f47a0-0000-7000-8000-0000000000e2";
        let (request, follow) = call_in(
            &[
                "checkpoint",
                "create",
                "--fact",
                "tests pass",
                "--evidence",
                e1,
                "--open",
                "flaky test fails",
                "--evidence",
                e2,
                "--open",
                "docs unknown",
                "--next",
                "fix the flaky test",
            ],
            &lookup,
        );
        assert_eq!(request.operation, OperationId::CreateCheckpoint);
        assert_eq!(follow, Follow::CheckpointFacts);
        let body = body_of(&request);
        for (name, value) in [
            ("workspace_id", W),
            ("task_id", T),
            ("session_id", S),
            ("snapshot_id", N),
            ("objective", "Make it pass"),
        ] {
            assert_eq!(str_at(&body, name), Some(value), "{name}");
        }
        let work = body
            .get("verified_completed_work")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(work.len(), 1);
        assert_eq!(str_at(&work[0], "classification"), Some("verified_fact"));
        assert_eq!(str_at(&work[0], "text"), Some("tests pass"));
        let ids = |statement: &JsonValue| -> Vec<String> {
            statement
                .get("evidence_ids")
                .and_then(JsonValue::as_array)
                .map(|ids| {
                    ids.iter()
                        .map(|id| id.as_str().unwrap().to_owned())
                        .collect()
                })
                .unwrap_or_default()
        };
        assert_eq!(ids(&work[0]), [e1]);
        let open = body
            .get("open_items")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(open.len(), 2);
        assert_eq!(str_at(&open[0], "classification"), Some("unknown"));
        assert_eq!(ids(&open[0]), [e2]);
        assert!(ids(&open[1]).is_empty());
        let next = body.get("next_action").unwrap();
        assert_eq!(str_at(next, "classification"), Some("recommendation"));
        assert_eq!(str_at(next, "text"), Some("fix the flaky test"));

        // Explicit IDs win; only --open: no fact hint.
        let (request, follow) = call_in(
            &[
                "checkpoint",
                "create",
                "--open",
                "fails",
                "--evidence",
                e2,
                "--next",
                "n",
                "--objective",
                "o",
                "--snapshot",
                X,
                "--session",
                X,
            ],
            &lookup,
        );
        assert_eq!(follow, Follow::Nothing);
        let body = body_of(&request);
        assert_eq!(str_at(&body, "snapshot_id"), Some(X));
        assert_eq!(str_at(&body, "session_id"), Some(X));
        assert_eq!(str_at(&body, "objective"), Some("o"));

        for invalid in [
            &[
                "checkpoint",
                "create",
                "--fact",
                "tests pass",
                "--next",
                "n",
            ][..],
            &[
                "checkpoint",
                "create",
                "--evidence",
                e1,
                "--fact",
                "x",
                "--next",
                "n",
            ][..],
            &["checkpoint", "create", "--fact", "x", "--evidence", e1][..],
            &["checkpoint", "create", "--open", "", "--next", "n"][..],
            &[
                "checkpoint",
                "create",
                "--open",
                "x",
                "--evidence",
                "a/b",
                "--next",
                "n",
            ][..],
            &["checkpoint", "create", "--next", "n", "--limit", "1"][..],
        ] {
            assert!(parse_in(invalid, &lookup).is_err(), "{invalid:?}");
        }
        let error = parse_in(
            &["checkpoint", "create", "--fact", "x", "--next", "n"],
            &lookup,
        )
        .unwrap_err()
        .0;
        assert!(error.contains("--open"), "{error}");
    }

    #[test]
    fn begin_takes_the_project_and_task_from_options_or_the_context() {
        let begin = |words: &[&str], lookup: &ContextLookup| match parse_in(words, lookup) {
            Ok(Invocation::Begin { spec, .. }) => Ok(spec),
            Ok(other) => panic!("expected a begin, got {other:?}"),
            Err(error) => Err(error),
        };
        let absent = ContextLookup::Absent {
            cwd: PathBuf::from("/w"),
        };
        let spec = begin(&["begin", "--project", P, "--new-task", "Do it"], &absent).unwrap();
        assert_eq!(spec.project_id, P);
        assert_eq!(
            spec.task,
            BeginTask::New {
                title: "Do it".to_owned(),
                description: None
            }
        );
        assert_eq!(spec.agent_id, None);
        let spec = begin(&["begin"], &found()).unwrap();
        assert_eq!(
            (spec.project_id.as_str(), &spec.task),
            (P, &BeginTask::Existing(T.to_owned()))
        );
        assert!(spec.agent_id.is_some());
        let spec = begin(&["begin", "--project", X, "--task", X], &found()).unwrap();
        assert_eq!(
            (spec.project_id.as_str(), spec.task),
            (X, BeginTask::Existing(X.to_owned()))
        );
        for invalid in [
            &["begin", "--new-task", "x"][..],
            &["begin", "--project", P][..],
            &["begin", "--project", P, "--task", T, "--new-task", "x"][..],
            &["begin", "--project", P, "--task", T, "--description", "d"][..],
            &["begin", "--project", P, "--new-task", ""][..],
            &["begin", "--project", P, "--task", T, "--to", "ready"][..],
        ] {
            assert!(begin(invalid, &absent).is_err(), "{invalid:?}");
        }
    }

    /// U2 (H1, Owner O5): `--project`, else the context's Project, else the
    /// Project of this client session's last-Pack record, else the usage
    /// error; the record is asked for only when no context file applies.
    #[test]
    fn begin_takes_the_project_of_the_record_after_the_context() {
        let begin = |words: &[&str], lookup: &ContextLookup, recorded: Option<&str>| {
            let mut argv = args(&["--data-dir", "/d"]);
            argv.extend(args(words));
            let asked = std::cell::Cell::new(false);
            let parsed = parse_args_with(argv, None, lookup, &|| {
                asked.set(true);
                recorded.map(str::to_owned)
            });
            match parsed {
                Ok(Invocation::Begin { spec, .. }) => (Ok(spec.project_id), asked.get()),
                Ok(other) => panic!("expected a begin, got {other:?}"),
                Err(error) => (Err(error.0), asked.get()),
            }
        };
        let absent = ContextLookup::Absent {
            cwd: PathBuf::from("/w"),
        };
        let new_task = ["begin", "--new-task", "Do it"];
        assert_eq!(begin(&new_task, &absent, Some(X)), (Ok(X.to_owned()), true));
        assert_eq!(
            begin(
                &["begin", "--project", P, "--new-task", "Do it"],
                &absent,
                Some(X)
            ),
            (Ok(P.to_owned()), false)
        );
        assert_eq!(
            begin(&new_task, &found(), Some(X)),
            (Ok(P.to_owned()), false)
        );
        let broken = ContextLookup::Broken("context file /c is malformed".to_owned());
        let (refused, asked) = begin(&new_task, &broken, Some(X));
        assert!(!asked);
        assert!(refused.unwrap_err().contains("is malformed"));
        let (refused, asked) = begin(&new_task, &absent, None);
        assert!(asked);
        assert!(
            refused
                .unwrap_err()
                .starts_with("begin requires --project <PROJECT_ID> the first time in a Workspace")
        );
        let asked = std::cell::Cell::new(false);
        let mut argv = args(&["--data-dir", "/d"]);
        argv.extend(args(&["task", "list", "--project", P]));
        let listed = parse_args_with(argv, None, &absent, &|| {
            asked.set(true);
            Some(X.to_owned())
        });
        assert!(matches!(listed, Ok(Invocation::Call { .. })));
        assert!(!asked.get(), "only begin asks for the record");
    }

    #[test]
    fn run_test_format_cargo_is_a_test_run_without_declared_cases() {
        let lookup = found();
        let Ok(Invocation::Run { spec, .. }) = parse_in(
            &["run", "--test-format", "cargo", "--", "cargo", "test"],
            &lookup,
        ) else {
            panic!("expected a run");
        };
        assert_eq!(
            spec.test,
            Some(TestSpec {
                name: None,
                case_count: None,
                format: Some(TestFormat::Cargo),
            })
        );
        for invalid in [
            &["run", "--test-format", "junit", "--", "pytest"][..],
            &[
                "run",
                "--test-format",
                "cargo",
                "--test-cases",
                "3",
                "--",
                "cargo",
                "test",
            ][..],
        ] {
            assert!(parse_in(invalid, &lookup).is_err(), "{invalid:?}");
        }
    }

    /// U5 H4 (O6): `--test-format pytest` is a test run like `cargo`, and
    /// `--test-cases` may be given with it (it wins); with `cargo` the two
    /// stay exclusive.
    #[test]
    fn run_test_format_pytest_is_a_test_run_and_takes_explicit_cases() {
        let lookup = found();
        for (words, cases) in [
            (
                &["run", "--test-format", "pytest", "--", "pytest"][..],
                None,
            ),
            (
                &[
                    "run",
                    "--test-format",
                    "pytest",
                    "--test-cases",
                    "7",
                    "--",
                    "pytest",
                ][..],
                Some(7),
            ),
        ] {
            let Ok(Invocation::Run { spec, .. }) = parse_in(words, &lookup) else {
                panic!("expected a run: {words:?}");
            };
            assert_eq!(
                spec.test,
                Some(TestSpec {
                    name: None,
                    case_count: cases,
                    format: Some(TestFormat::Pytest),
                })
            );
        }
        let cargo_with_cases = [
            "run",
            "--test-format",
            "cargo",
            "--test-cases",
            "3",
            "--",
            "cargo",
            "test",
        ];
        assert!(parse_in(&cargo_with_cases, &lookup).is_err());
    }

    #[test]
    fn evidence_and_checkpoint_reads_and_checkpoint_create_parse() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let evidence = request_of(&["evidence", "get", id]);
        assert_eq!(evidence.operation, OperationId::GetEvidence);
        assert_eq!(evidence.target, format!("/v1/evidence/{id}"));
        let checkpoint = request_of(&["checkpoint", "get", id]);
        assert_eq!(checkpoint.operation, OperationId::GetCheckpoint);
        assert_eq!(checkpoint.target, format!("/v1/checkpoints/{id}"));
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("checkpoint.json");
        std::fs::write(&file, "{}").unwrap();
        let create = request_of(&["checkpoint", "create", file.to_str().unwrap()]);
        assert_eq!(create.operation, OperationId::CreateCheckpoint);
        assert!(create.needs_idempotency_key());
        assert_eq!(create.body.as_deref(), Some("{}"));
    }

    #[test]
    fn recover_preview_parses_its_task_workspace_and_text_options() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let other = "018f47a0-0000-7000-8000-000000000002";
        let plain = request_of(&["recover", "preview", "--task", id]);
        assert_eq!(plain.operation, OperationId::GetRecoveryPreview);
        assert_eq!(plain.target, format!("/v1/tasks/{id}/recovery-preview"));
        assert!(!plain.summary && !plain.needs_idempotency_key() && plain.body.is_none());
        let asked = request_of(&[
            "recover",
            "preview",
            "--task",
            id,
            "--workspace",
            other,
            "--text",
        ]);
        assert_eq!(
            asked.target,
            format!("/v1/tasks/{id}/recovery-preview?workspace_id={other}")
        );
        assert!(asked.summary);
        let parse = |words: &[&str]| {
            let mut argv = args(&["--data-dir", "/d"]);
            argv.extend(args(words));
            parse_args(argv, None)
        };
        for invalid in [
            parse(&["recover", "preview"]),
            parse(&["recover", "preview", "--task", "a/b"]),
            parse(&["recover", "preview", "--task", id, "--text", "--text"]),
            parse(&["recover", "preview", "--task", id, "--limit", "1"]),
            parse(&["status", "--text"]),
            parse(&["run", "--text", "--", "true"]),
        ] {
            assert!(invalid.is_err(), "{invalid:?}");
        }
    }

    /// ADR 0013 D4: `resume` reads the Task Capsule like `recover preview`
    /// reads the Preview.
    #[test]
    fn resume_parses_its_task_workspace_and_text_options() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let other = "018f47a0-0000-7000-8000-000000000002";
        let plain = request_of(&["resume", "--task", id]);
        assert_eq!(plain.operation, OperationId::GetTaskCapsule);
        assert_eq!(plain.target, format!("/v1/tasks/{id}/recovery-capsule"));
        assert!(!plain.summary && !plain.needs_idempotency_key() && plain.body.is_none());
        let asked = request_of(&["resume", "--task", id, "--workspace", other, "--text"]);
        assert_eq!(
            asked.target,
            format!("/v1/tasks/{id}/recovery-capsule?workspace_id={other}")
        );
        assert!(asked.summary);
        let parse = |words: &[&str]| {
            let mut argv = args(&["--data-dir", "/d"]);
            argv.extend(args(words));
            parse_args(argv, None)
        };
        for invalid in [
            parse(&["resume"]),
            parse(&["resume", "--task", "a/b"]),
            parse(&["resume", "--task", id, "--text", "--text"]),
            parse(&["resume", "--task", id, "--limit", "1"]),
            parse(&["resume", "now"]),
        ] {
            assert!(invalid.is_err(), "{invalid:?}");
        }
    }

    /// P4-A: `--all` asks `resume --text` for every statement one by one;
    /// it goes only with `--text`, and only on `resume`.
    #[test]
    fn resume_takes_all_only_with_text() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let folded = request_of(&["resume", "--task", id, "--text"]);
        assert!(folded.summary && !folded.all_items);
        for words in [
            &["resume", "--task", id, "--text", "--all"][..],
            &["resume", "--all", "--task", id, "--text"][..],
        ] {
            let every = request_of(words);
            assert!(every.summary && every.all_items, "{words:?}");
            assert_eq!(every.target, folded.target);
        }
        let parse = |words: &[&str]| {
            let mut argv = args(&["--data-dir", "/d"]);
            argv.extend(args(words));
            parse_args(argv, None)
        };
        let alone = parse(&["resume", "--task", id, "--all"]).unwrap_err();
        assert!(alone.to_string().contains("only with --text"), "{alone}");
        for invalid in [
            parse(&["resume", "--task", id, "--text", "--all", "--all"]),
            parse(&["recover", "preview", "--task", id, "--text", "--all"]),
            parse(&["task", "list", "--project", id, "--all"]),
        ] {
            assert!(invalid.is_err(), "{invalid:?}");
        }
    }

    /// P4-C: `--pack [--budget N]` and `--text --claims <NUMBERS>`; each
    /// out-of-range budget, bad list, or combination is a usage error.
    #[test]
    fn resume_takes_pack_budget_and_claims() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let plain = request_of(&["resume", "--task", id]);
        assert_eq!(plain.capsule_view, CapsuleView::Plain);
        let pack = request_of(&["resume", "--task", id, "--pack"]);
        assert_eq!(pack.capsule_view, CapsuleView::Pack { budget: 9_000 });
        assert_eq!(pack.target, plain.target);
        assert!(!pack.summary);
        for (budget, expected) in [("1000", 1_000), ("1000000", 1_000_000), ("2500", 2_500)] {
            let request = request_of(&["resume", "--task", id, "--pack", "--budget", budget]);
            assert_eq!(request.capsule_view, CapsuleView::Pack { budget: expected });
        }
        for (numbers, expected) in [
            ("3", vec![(3, 3)]),
            ("3,5-7", vec![(3, 3), (5, 7)]),
            ("#3,#5-#7", vec![(3, 3), (5, 7)]),
            ("#5–#7,1", vec![(5, 7), (1, 1)]),
            ("2-2", vec![(2, 2)]),
        ] {
            let request = request_of(&["resume", "--task", id, "--text", "--claims", numbers]);
            assert_eq!(
                request.capsule_view,
                CapsuleView::Claims(expected.clone()),
                "{numbers}"
            );
            assert!(request.summary);
            // P4-C2 revision 5: the same numbers with --pack.
            let request = request_of(&["resume", "--task", id, "--pack", "--claims", numbers]);
            assert_eq!(
                request.capsule_view,
                CapsuleView::PackClaims(expected),
                "{numbers}"
            );
            assert!(!request.summary);
        }
        let parse = |words: &[&str]| {
            let mut argv = args(&["--data-dir", "/d"]);
            argv.extend(args(words));
            parse_args(argv, None).map(|_| ()).unwrap_err().to_string()
        };
        for budget in [
            "999", "1000001", "0", "-5", "9k", "", "+1000", " 1000", "01000x",
        ] {
            let error = parse(&["resume", "--task", id, "--pack", "--budget", budget]);
            assert!(
                error.contains("from 1000 through 1000000"),
                "{budget:?}: {error}"
            );
        }
        for numbers in [
            "", "0", "3,", "a", "5-3", "1-", "-2", "03", "3 ,4", "1.5", "#",
        ] {
            let error = parse(&["resume", "--task", id, "--text", "--claims", numbers]);
            assert!(error.contains("--claims takes"), "{numbers:?}: {error}");
        }
        for (words, said) in [
            (
                &["resume", "--task", id, "--budget", "2000"][..],
                "only with --pack",
            ),
            (
                &["resume", "--task", id, "--pack", "--text"][..],
                "without --text",
            ),
            (
                &[
                    "resume", "--task", id, "--pack", "--claims", "1", "--budget", "2000",
                ][..],
                "used without --budget",
            ),
            (
                &["resume", "--task", id, "--pack", "--text", "--claims", "1"][..],
                "without --text",
            ),
            (
                &["resume", "--task", id, "--claims", "1"][..],
                "with --pack, or with --text",
            ),
            (
                &["resume", "--task", id, "--text", "--all", "--claims", "1"][..],
                "not with --all",
            ),
            (
                &["resume", "--task", id, "--pack", "--pack"][..],
                "more than once",
            ),
            (
                &["recover", "preview", "--task", id, "--pack"][..],
                "does not apply",
            ),
        ] {
            let error = parse(words);
            assert!(error.contains(said), "{words:?}: {error}");
        }
    }

    /// U3 G4 (Owner O8): `--query <TEXT>` asks for a query Pack; it goes
    /// with `--pack` and `--budget`, not with `--claims` or without
    /// `--pack`; a query of no or more than 256 characters, with a control
    /// character, or with a string in the format of a memprove token is a
    /// usage error that never repeats it.
    #[test]
    #[allow(clippy::too_many_lines)] // One option, case by case.
    fn resume_takes_a_query_with_a_whole_pack_only() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let request = request_of(&["resume", "--task", id, "--pack", "--query", "pack budget"]);
        assert_eq!(
            request.capsule_view,
            CapsuleView::PackQuery {
                budget: 9_000,
                query: "pack budget".to_owned(),
            }
        );
        let request = request_of(&[
            "resume", "--task", id, "--pack", "--query", "x", "--budget", "1500",
        ]);
        assert_eq!(
            request.capsule_view,
            CapsuleView::PackQuery {
                budget: 1_500,
                query: "x".to_owned(),
            }
        );
        let parse = |words: &[String]| {
            let mut argv = args(&["--data-dir", "/d"]);
            argv.extend(words.iter().map(OsString::from));
            parse_args(argv, None).map(|_| ()).unwrap_err().to_string()
        };
        let words = |rest: &[&str]| {
            ["resume", "--task", id]
                .iter()
                .chain(rest)
                .map(|word| (*word).to_owned())
                .collect::<Vec<_>>()
        };
        for rest in [
            &["--query", "x"][..],
            &["--text", "--query", "x"],
            &["--pack", "--claims", "1", "--query", "x"],
        ] {
            let error = parse(&words(rest));
            assert!(
                error.contains("--query selects the claims of a whole Pack"),
                "{rest:?}: {error}"
            );
        }
        assert!(
            parse(&words(&["--pack", "--query", "a", "--query", "b"])).contains("more than once")
        );
        // U5 P2 (Owner O4 a, c): a run of the three classes; `Q` × 43, the
        // token here before U5, is a query now (below).
        let token = "Ab3_cDe-4fGh5iJk6lMn7oPq8rSt9uVw0xYz1AbCd2E".to_owned();
        for (query, said) in [
            (String::new(), "1 through 256 characters"),
            ("secret".repeat(50), "1 through 256 characters"),
            ("secret\u{7}text".to_owned(), "control character"),
            ("secret\ntext".to_owned(), "control character"),
            (format!("secret {token}"), "format of a memprove token"),
        ] {
            let mut all = words(&["--pack", "--query"]);
            all.push(query.clone());
            let error = parse(&all);
            assert!(error.contains(said), "{query:?}: {error}");
            assert!(error.contains("--query"), "{error}");
            assert!(
                !error.contains("secret") && !error.contains(&token),
                "{error}"
            );
        }
        for query in [
            "é".repeat(256),
            "a".repeat(42),
            "a".repeat(44),
            " ".to_owned(),
            "Q".repeat(43),
            "test_calculate_metrics_rejects_empty_series".to_owned(),
        ] {
            let mut all = words(&["--pack", "--query"]);
            all.push(query.clone());
            let mut argv = args(&["--data-dir", "/d"]);
            argv.extend(all.iter().map(OsString::from));
            assert!(parse_args(argv, None).is_ok(), "{query:?}");
        }
    }

    /// P4-A: `--reaffirm-all` is a placeholder resolved through the
    /// Capsule; the --evidence after it is its own, and it takes neither a
    /// --supersedes nor a second --reaffirm-all.
    #[test]
    fn checkpoint_create_takes_reaffirm_all() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let ids = [
            "--workspace",
            id,
            "--task",
            id,
            "--session",
            id,
            "--snapshot",
            id,
            "--objective",
            "o",
        ];
        let parse = |words: &[&str]| {
            let mut argv = args(&["--data-dir", "/d", "checkpoint", "create"]);
            argv.extend(args(&ids));
            argv.extend(args(words));
            parse_args(argv, None)
        };
        let pending = |words: &[&str]| call_of(parse(words).unwrap()).1.pending.unwrap();
        let claims::Draft::Checkpoint(draft) = pending(&["--reaffirm-all", "--next", "n"]) else {
            panic!("not a checkpoint draft");
        };
        assert_eq!(draft.statements.len(), 1);
        assert_eq!(draft.statements[0].kind, claims::StatementKind::ReaffirmAll);
        assert!(draft.statements[0].evidence.is_empty());
        let claims::Draft::Checkpoint(draft) =
            pending(&["--reaffirm-all", "--evidence", id, "--next", "n"])
        else {
            panic!("not a checkpoint draft");
        };
        assert_eq!(draft.statements[0].evidence, [id]);
        for invalid in [
            parse(&["--reaffirm-all", "--reaffirm-all", "--next", "n"]),
            parse(&["--reaffirm-all", "--supersedes", "1", "--next", "n"]),
            parse(&["--reaffirm-all"]),
        ] {
            assert!(invalid.is_err(), "{invalid:?}");
        }
        let mut argv = args(&["--data-dir", "/d", "checkpoint", "create", "request.json"]);
        argv.extend(args(&["--reaffirm-all"]));
        assert!(parse_args(argv, None).is_err());
    }

    fn request_of(words: &[&str]) -> Request {
        let mut argv = args(&["--data-dir", "/d"]);
        argv.extend(args(words));
        call_of(parse_args(argv, None).unwrap()).1
    }

    #[test]
    fn commands_map_one_to_one_to_operations() {
        for (words, operation, target) in [
            (
                &["health", "live"][..],
                OperationId::HealthLive,
                "/health/live",
            ),
            (
                &["health", "ready"][..],
                OperationId::HealthReady,
                "/health/ready",
            ),
            (&["status"][..], OperationId::GetStatus, "/v1/status"),
            (&["version"][..], OperationId::GetVersion, "/v1/version"),
            (
                &["token", "list"][..],
                OperationId::ListClientTokens,
                "/v1/auth/tokens",
            ),
            (
                &["token", "revoke", "018f47a0-0000-7000-8000-000000000001"][..],
                OperationId::RevokeClientToken,
                "/v1/auth/tokens/018f47a0-0000-7000-8000-000000000001/revoke",
            ),
            (
                &["event", "get", "018f47a0-0000-7000-8000-000000000001"][..],
                OperationId::GetEvent,
                "/v1/events/018f47a0-0000-7000-8000-000000000001",
            ),
            (
                &[
                    "event",
                    "list",
                    "--project",
                    "018f47a0-0000-7000-8000-000000000001",
                ][..],
                OperationId::ListEvents,
                "/v1/events?project_id=018f47a0-0000-7000-8000-000000000001",
            ),
        ] {
            let mut argv = args(&["--data-dir", "/d"]);
            argv.extend(args(words));
            let (socket, request) = call_of(parse_args(argv, None).unwrap());
            assert_eq!(socket, PathBuf::from("/d/memproved.sock"));
            assert_eq!(request.operation, operation);
            assert_eq!(request.target, target);
            assert_eq!(request.body, None);
        }
    }

    #[test]
    fn ledger_verify_builds_a_project_command() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let request = request_of(&["ledger", "verify", "--project", id]);
        assert_eq!(request.operation, OperationId::VerifyLedger);
        assert_eq!(request.target, "/v1/verification/ledger");
        assert!(request.needs_idempotency_key());
        let body =
            memprove_protocol::strict_json::parse_strict(request.body.as_deref().unwrap()).unwrap();
        memprove_protocol::phase1::validate_request(OperationId::VerifyLedger, Some(&body))
            .unwrap();
        for invalid in [
            &["ledger", "verify"][..],
            &["ledger", "verify", "--project", "a/b"][..],
            &["ledger", "verify", "--project", id, "--limit", "1"][..],
        ] {
            let mut argv = args(&["--data-dir", "/d"]);
            argv.extend(args(invalid));
            assert!(parse_args(argv, None).is_err(), "{invalid:?}");
        }
    }

    /// P3-L L10: without `--project`, `ledger verify` takes the Project of
    /// the current context; an explicit `--project` wins; with neither, the
    /// usage error names both ways to give it.
    #[test]
    fn l10_ledger_verify_takes_the_project_from_the_context() {
        let other = "018f47a0-0000-7000-8000-0000000000b2";
        let project_of =
            |request: &Request| str_at(&body_of(request), "project_id").map(str::to_owned);
        let (from_context, _) = call_in(&["ledger", "verify"], &found());
        assert_eq!(from_context.operation, OperationId::VerifyLedger);
        assert_eq!(from_context.target, "/v1/verification/ledger");
        assert!(from_context.needs_idempotency_key());
        assert_eq!(project_of(&from_context).as_deref(), Some(P));
        let (explicit, _) = call_in(&["ledger", "verify", "--project", other], &found());
        assert_eq!(project_of(&explicit).as_deref(), Some(other));
        // An unsafe explicit value is still refused, whatever the context says.
        assert!(parse_in(&["ledger", "verify", "--project", "a/b"], &found()).is_err());
        for lookup in [
            ContextLookup::Unavailable,
            ContextLookup::Absent {
                cwd: PathBuf::from("/elsewhere"),
            },
        ] {
            let error = parse_in(&["ledger", "verify"], &lookup).unwrap_err().0;
            assert!(error.contains("--project <PROJECT_ID>"), "{error}");
            assert!(error.contains("current context"), "{error}");
            assert!(error.contains("`memprove begin`"), "{error}");
        }
    }

    #[test]
    fn token_create_builds_a_json_body() {
        let request = request_of(&[
            "token",
            "create",
            "--label",
            "ci \"bot\"\\",
            "--scope",
            "mcp-read",
            "--scope",
            "ingest-only",
        ]);
        assert_eq!(request.operation, OperationId::CreateClientToken);
        let body = request.body.clone().unwrap();
        let parsed = parse_strict_bytes(body.as_bytes()).unwrap();
        memprove_protocol::phase1::validate_request(OperationId::CreateClientToken, Some(&parsed))
            .unwrap();
        assert_eq!(
            parsed.get("client_label").and_then(JsonValue::as_str),
            Some("ci \"bot\"\\")
        );
        assert!(request.needs_idempotency_key());
        assert_eq!(request.idempotency_key, None);

        let keyed = request_of(&[
            "token",
            "create",
            "--label",
            "x",
            "--scope",
            "control",
            "--idempotency-key",
            "0123456789abcdef",
        ]);
        assert_eq!(keyed.idempotency_key.as_deref(), Some("0123456789abcdef"));
    }

    #[test]
    fn event_ingest_sends_the_envelope_file_verbatim() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("event.json");
        let envelope = "{\"envelope_version\":\"1.0\",\n \"payload\":{\"n\":1.50}}";
        std::fs::write(&path, envelope).unwrap();
        let request = request_of(&[
            "event",
            "ingest",
            path.to_str().unwrap(),
            "--idempotency-key",
            "0123456789abcdef",
        ]);
        assert_eq!(request.operation, OperationId::IngestEvent);
        assert_eq!(request.target, "/v1/events");
        assert_eq!(request.body.as_deref(), Some(envelope));
        assert!(request.needs_idempotency_key());
        let mut argv = args(&["--data-dir", "/d", "event", "ingest"]);
        argv.push(directory.path().join("missing.json").into_os_string());
        assert!(parse_args(argv, None).is_err());
        assert!(parse_args(args(&["--data-dir", "/d", "event", "ingest"]), None).is_err());
        assert!(
            parse_args(
                args(&["--data-dir", "/d", "event", "list", "--project", "a&b"]),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn token_list_builds_a_query() {
        let request = request_of(&["token", "list", "--limit", "5", "--cursor", "abc-1"]);
        assert_eq!(request.target, "/v1/auth/tokens?limit=5&cursor=abc-1");
    }

    #[test]
    fn lifecycle_commands_build_contract_requests() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let check = |request: &Request| {
            let parsed = parse_strict_bytes(request.body.as_deref().unwrap().as_bytes()).unwrap();
            memprove_protocol::phase1::validate_request(request.operation, Some(&parsed)).unwrap();
        };
        let end = request_of(&["session", "end", id, "--revision", "1", "--reason", "done"]);
        assert_eq!(end.operation, OperationId::EndSession);
        assert_eq!(end.target, format!("/v1/sessions/{id}/end"));
        assert_eq!(
            end.body.as_deref(),
            Some(r#"{"schema_version":1,"expected_revision":1,"reason":"done"}"#)
        );
        assert!(end.needs_idempotency_key());
        check(&end);

        let step = request_of(&["task", "transition", id, "--to", "ready", "--revision", "2"]);
        assert_eq!(step.operation, OperationId::TransitionTask);
        assert_eq!(step.target, format!("/v1/tasks/{id}/transition"));
        assert_eq!(
            step.body.as_deref(),
            Some(r#"{"schema_version":1,"expected_revision":2,"target_state":"ready"}"#)
        );
        assert!(step.needs_idempotency_key());
        check(&step);
        // P2-C: completion Evidence, in order, and the probed Workspace.
        let other = "018f47a0-0000-7000-8000-000000000002";
        let complete = request_of(&[
            "task",
            "transition",
            id,
            "--to",
            "completed",
            "--revision",
            "3",
            "--evidence",
            other,
            "--evidence",
            id,
            "--workspace",
            id,
        ]);
        assert_eq!(
            complete.body.as_deref(),
            Some(&*format!(
                r#"{{"schema_version":1,"expected_revision":3,"target_state":"completed","completion_evidence_ids":["{other}","{id}"],"workspace_id":"{id}"}}"#
            ))
        );
        check(&complete);

        for argv in [
            &[
                "task",
                "transition",
                id,
                "--to",
                "completed",
                "--revision",
                "3",
                "--evidence",
                "a/b",
            ][..],
            &["session", "end", id][..],
            &["session", "end", id, "--revision", "0"][..],
            &["session", "end", id, "--revision", "x"][..],
            &["session", "end", "--revision", "1"][..],
            &["session", "end", id, "--revision", "1", "--to", "ready"][..],
            &["task", "transition", id, "--revision", "1"][..],
            &["task", "transition", id, "--to", "ready"][..],
            &[
                "task",
                "transition",
                "../x",
                "--to",
                "ready",
                "--revision",
                "1",
            ][..],
            &[
                "task",
                "transition",
                id,
                "--to",
                "ready",
                "--revision",
                "1",
                "--reason",
                "x",
            ][..],
            &["project", "get", id, "--title", "x"][..],
        ] {
            let mut full = args(&["--data-dir", "/d"]);
            full.extend(args(argv));
            assert!(parse_args(full, None).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn catalog_commands_build_contract_requests() {
        let id = "018f47a0-0000-7000-8000-000000000001";
        let check = |request: &Request| {
            if let Some(body) = &request.body {
                let parsed = parse_strict_bytes(body.as_bytes()).unwrap();
                memprove_protocol::phase1::validate_request(request.operation, Some(&parsed))
                    .unwrap();
            }
        };

        let register = request_of(&["project", "register", "/repo"]);
        assert_eq!(register.operation, OperationId::RegisterProject);
        assert_eq!(register.target, "/v1/projects/register");
        assert_eq!(
            register.body.as_deref(),
            Some(r#"{"schema_version":1,"root":"/repo"}"#)
        );
        assert!(register.needs_idempotency_key());
        check(&register);

        let get = request_of(&["project", "get", id]);
        assert_eq!(get.operation, OperationId::GetProject);
        assert_eq!(get.target, format!("/v1/projects/{id}"));

        let resolve = request_of(&["workspace", "resolve", "--project", id, "/repo/src"]);
        assert_eq!(resolve.operation, OperationId::ResolveWorkspace);
        assert!(!resolve.needs_idempotency_key());
        check(&resolve);

        let session = request_of(&["session", "create", "--workspace", id, "--agent", id]);
        assert_eq!(session.operation, OperationId::CreateSession);
        assert!(session.needs_idempotency_key());
        check(&session);
        let linked = request_of(&[
            "session",
            "create",
            "--workspace",
            id,
            "--agent",
            id,
            "--task",
            id,
        ]);
        check(&linked);
        let parsed = parse_strict_bytes(linked.body.as_deref().unwrap().as_bytes()).unwrap();
        assert_eq!(parsed.get("task_id").and_then(JsonValue::as_str), Some(id));

        let sessions = request_of(&["session", "list", "--workspace", id, "--limit", "5"]);
        assert_eq!(
            sessions.target,
            format!("/v1/sessions?workspace_id={id}&limit=5")
        );

        let task = request_of(&[
            "task",
            "create",
            "--project",
            id,
            "--title",
            "Fix \"it\"",
            "--workspace",
            id,
            "--description",
            "",
        ]);
        assert_eq!(task.operation, OperationId::CreateTask);
        check(&task);
        let parsed = parse_strict_bytes(task.body.as_deref().unwrap().as_bytes()).unwrap();
        assert_eq!(
            parsed.get("title").and_then(JsonValue::as_str),
            Some("Fix \"it\"")
        );

        let tasks = request_of(&["task", "list", "--project", id, "--cursor", id]);
        assert_eq!(
            tasks.target,
            format!("/v1/tasks?project_id={id}&cursor={id}")
        );

        let relative = request_of(&["project", "register", "."]);
        let body = parse_strict_bytes(relative.body.as_deref().unwrap().as_bytes()).unwrap();
        let root = body.get("root").and_then(JsonValue::as_str).unwrap();
        assert!(Path::new(root).is_absolute(), "{root}");

        for argv in [
            &["project", "register"][..],
            &["project", "get"][..],
            &["project", "get", "../x"][..],
            &["workspace", "resolve", "/repo"][..],
            &["session", "create", "--workspace", id][..],
            &["session", "list"][..],
            &["task", "create", "--project", id][..],
            &["task", "list"][..],
            &["task", "list", "--project", "a&b=c"][..],
        ] {
            let mut full = args(&["--data-dir", "/d"]);
            full.extend(args(argv));
            assert!(parse_args(full, None).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn json_string_escapes() {
        assert_eq!(json_string("a\"b\\c\n"), r#""a\"b\\c\u000a""#);
    }

    #[test]
    fn socket_resolution_precedence() {
        let env = Some(OsString::from("/env"));
        assert_eq!(
            call_of(parse_args(args(&["status"]), env.clone()).unwrap()).0,
            PathBuf::from("/env/memproved.sock")
        );
        assert_eq!(
            call_of(parse_args(args(&["--socket", "/s.sock", "status"]), env).unwrap()).0,
            PathBuf::from("/s.sock")
        );
        assert!(parse_args(args(&["status"]), None).is_err());
    }

    #[test]
    fn bad_invocations_are_usage_errors() {
        for argv in [
            &["--data-dir", "/d"][..],
            &["--data-dir", "/d", "health"][..],
            &["--data-dir", "/d", "events"][..],
            &["--tcp", "status"][..],
            &["--data-dir", "/d", "token", "create", "--scope", "control"][..],
            &["--data-dir", "/d", "token", "create", "--label", "x"][..],
            &["--data-dir", "/d", "token", "revoke"][..],
            &["--data-dir", "/d", "token", "revoke", "../x"][..],
            &["--data-dir", "/d", "token", "list", "--limit", "a"][..],
            &["--data-dir", "/d", "status", "--label", "x"][..],
            &[
                "--data-dir",
                "/d",
                "token",
                "revoke",
                "id",
                "--idempotency-key",
                "short",
            ][..],
        ] {
            assert!(parse_args(args(argv), None).is_err(), "{argv:?}");
        }
        assert_eq!(parse_args(args(&["-h"]), None), Ok(Invocation::Help));
    }

    #[test]
    fn help_names_the_command_and_an_option_value_is_not_a_flag() {
        let help_of = |argv: &[&str]| match parse_args(args(argv), None) {
            Ok(Invocation::CommandHelp(entries)) => {
                entries.iter().map(|entry| entry.name).collect::<Vec<_>>()
            }
            other => panic!("{argv:?}: {other:?}"),
        };
        assert_eq!(help_of(&["ledger", "verify", "--help"]), ["ledger verify"]);
        assert_eq!(help_of(&["-h", "run"]), ["run"]);
        assert_eq!(
            help_of(&["task", "create", "--bogus", "-h"]),
            ["task create"]
        );
        assert_eq!(
            help_of(&["--data-dir", "/d", "token", "--help"]),
            ["token create", "token list", "token revoke"]
        );
        // `--reason --help` records the text "--help"; it asks for no help.
        let call = parse_args(
            args(&[
                "--data-dir",
                "/d",
                "session",
                "end",
                "018f47a0-0000-7000-8000-000000000001",
                "--revision",
                "2",
                "--reason",
                "--help",
            ]),
            None,
        );
        assert!(matches!(call, Ok(Invocation::Call { .. })), "{call:?}");
        // Nothing after `--` is read for help.
        assert!(parse_args(args(&["run", "--", "echo", "--help"]), None).is_err());
    }

    #[test]
    fn tokens_are_refused_as_arguments() {
        for argv in [
            &["--data-dir", "/d", "--token", "secret", "status"][..],
            &["--data-dir", "/d", "status", "--token=secret"][..],
        ] {
            let error = parse_args(args(argv), None).unwrap_err();
            assert!(error.0.contains("not accepted on the command line"));
            assert!(!error.0.contains("secret"));
        }
    }

    #[test]
    fn token_sources_and_file_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, "file-token\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = resolve_token(Some(&file), None, None).unwrap_err();
        assert!(matches!(
            error,
            TokenSourceError::InsecurePermissions { mode: 0o644, .. }
        ));
        assert!(!error.to_string().contains("file-token"));

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            resolve_token(Some(&file), Some("env-token".into()), None).unwrap(),
            Some("file-token".to_owned())
        );
        assert_eq!(
            resolve_token(None, Some("env-token".into()), Some(file.clone().into())).unwrap(),
            Some("env-token".to_owned())
        );
        assert_eq!(
            resolve_token(None, Some(OsString::new()), Some(file.clone().into())).unwrap(),
            Some("file-token".to_owned())
        );
        assert_eq!(resolve_token(None, None, None).unwrap(), None);

        std::fs::write(&file, "two\nlines\n").unwrap();
        assert!(matches!(
            resolve_token(Some(&file), None, None),
            Err(TokenSourceError::Malformed(_))
        ));
        assert!(matches!(
            resolve_token(Some(dir.path()), None, None),
            Err(TokenSourceError::NotAFile(_))
        ));
    }

    #[test]
    fn generated_idempotency_keys_are_valid_and_distinct() {
        let first = generate_idempotency_key().unwrap();
        let second = generate_idempotency_key().unwrap();
        assert!(valid_idempotency_key(&first));
        assert_ne!(first, second);
    }

    #[test]
    fn parses_and_validates_a_success_response() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 15\r\n\r\n{\"status\":\"ok\"}";
        let parsed = parse_http_response(raw).unwrap();
        assert_eq!(parsed.reply.status, 200);
        check_contract(OperationId::HealthLive, &parsed).unwrap();
    }

    #[test]
    fn rejects_contract_violations() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"status\":\"bad\"}";
        let parsed = parse_http_response(raw).unwrap();
        assert!(check_contract(OperationId::HealthLive, &parsed).is_err());

        let problem = br#"{"type":"https://continuity.local/problems/authentication-required","title":"Authentication required","status":401,"code":"authentication_required","request_id":"018f47a0-0000-7000-8000-000000000001","retryable":false}"#;
        let mut raw =
            b"HTTP/1.1 401 Unauthorized\r\ncontent-type: application/problem+json\r\n\r\n".to_vec();
        raw.extend_from_slice(problem);
        let without_challenge = parse_http_response(&raw).unwrap();
        assert!(check_contract(OperationId::GetVersion, &without_challenge).is_err());

        let mut raw = b"HTTP/1.1 401 Unauthorized\r\ncontent-type: application/problem+json\r\nwww-authenticate: Bearer\r\n\r\n".to_vec();
        raw.extend_from_slice(problem);
        let with_challenge = parse_http_response(&raw).unwrap();
        check_contract(OperationId::GetVersion, &with_challenge).unwrap();
        assert_eq!(
            with_challenge.reply.problem_code().as_deref(),
            Some("authentication_required")
        );
    }

    #[test]
    fn a_connection_closed_without_a_response_is_a_transport_failure() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("closing.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 64];
            let _ = stream.read(&mut request).unwrap();
        });
        let mut request = request_of(&["status"]);
        request.idempotency_key = None;
        let error = call(&socket, &request, None).unwrap_err();
        server.join().unwrap();
        assert!(matches!(error, CallError::Transport { .. }), "{error}");
    }

    /// P3-C2 (T12 S-5): a Task Capsule may be up to 16 MiB; a response
    /// over an operation's limit is its own error, naming the limit, not a
    /// contract violation (exit 4).
    #[test]
    fn a_response_over_the_limit_names_the_limit() {
        fn serve(body_bytes: usize) -> (tempfile::TempDir, PathBuf, std::thread::JoinHandle<()>) {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("large.sock");
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).unwrap();
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {body_bytes}\r\n\r\n"
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&vec![b' '; body_bytes]);
            });
            (directory, socket, server)
        }
        assert_eq!(response_limit(OperationId::GetTaskCapsule), 16 << 20);
        assert_eq!(response_limit(OperationId::GetStatus), 1 << 20);
        let capsule = Request::bare(
            OperationId::GetTaskCapsule,
            "/v1/tasks/018f47a0-0000-7000-8000-000000000001/recovery-capsule".to_owned(),
        );
        // 2 MiB: read whole for a Capsule (then judged by the contract).
        let (_directory, socket, server) = serve(2 << 20);
        let error = call(&socket, &capsule, None).unwrap_err();
        server.join().unwrap();
        assert!(matches!(error, CallError::Contract(_)), "{error}");
        // Over 16 MiB: too large, the limit named.
        let (_directory, socket, server) = serve((16 << 20) + 1);
        let error = call(&socket, &capsule, None).unwrap_err();
        server.join().unwrap();
        assert!(
            matches!(
                error,
                CallError::ResponseTooLarge {
                    operation: OperationId::GetTaskCapsule,
                    limit: 16_777_216
                }
            ),
            "{error}"
        );
        assert_eq!(
            error.to_string(),
            "the getTaskCapsule response exceeds the CLI's limit of 16777216 bytes (16 MiB); \
             nothing of it was used"
        );
        // Any other operation keeps 1 MiB.
        let mut status = request_of(&["status"]);
        status.idempotency_key = None;
        let (_directory, socket, server) = serve(2 << 20);
        let error = call(&socket, &status, None).unwrap_err();
        server.join().unwrap();
        assert!(
            matches!(
                error,
                CallError::ResponseTooLarge {
                    limit: 1_048_576,
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn rejects_malformed_framing() {
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(parse_http_response(b"HTTP/1.0 200 OK\r\n\r\n{}").is_err());
        assert!(
            parse_http_response(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n").is_err()
        );
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\n{}").is_err());
    }

    /// P3-C: --supersedes belongs to the closest --fact, --open,
    /// --reaffirm, or --next before it; --withdraw to the Checkpoint. Claim
    /// IDs build the body now; a number or --reaffirm leaves it to the Task
    /// Capsule, read just before sending.
    #[test]
    #[allow(clippy::too_many_lines)] // Every claim flag, built now or later.
    fn checkpoint_claim_flags_attach_to_their_statement() {
        let lookup = found_with_run();
        let c = "018f47a0-0000-7000-8000-0000000000c1";
        let o1 = format!("{c}/open_items/0");
        let n1 = format!("{c}/next_action/0");
        let d1 = "decision/018f47a0-0000-7000-8000-0000000000d1";
        let (request, follow) = call_in(
            &[
                "checkpoint",
                "create",
                "--fact",
                "F2",
                "--supersedes",
                &o1,
                "--open",
                "O2",
                "--next",
                "go",
                "--supersedes",
                &n1,
                "--withdraw",
                d1,
            ],
            &lookup,
        );
        assert_eq!(follow, Follow::CheckpointFacts);
        assert_eq!(request.pending, None);
        let body = body_of(&request);
        let strings = |value: Option<&JsonValue>| -> Vec<String> {
            value
                .and_then(JsonValue::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().unwrap().to_owned())
                        .collect()
                })
                .unwrap_or_default()
        };
        let work = body
            .get("verified_completed_work")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(
            strings(work[0].get("supersedes")),
            std::slice::from_ref(&o1)
        );
        assert_eq!(strings(work[0].get("evidence_ids")), [E]);
        let open = body
            .get("open_items")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert!(open[0].get("supersedes").is_none());
        assert_eq!(
            strings(
                body.get("next_action")
                    .and_then(|next| next.get("supersedes"))
            ),
            [n1]
        );
        assert_eq!(strings(body.get("withdrawals")), [d1]);
        assert!(body.get("withdrawal_reason").is_none());
        // P3-D2: --withdraw-reason goes into the body as withdrawal_reason.
        let (request, _) = call_in(
            &[
                "checkpoint",
                "create",
                "--withdraw",
                d1,
                "--withdraw-reason",
                "superseded by the \"nom\" decision",
                "--next",
                "go",
            ],
            &lookup,
        );
        assert_eq!(
            body_of(&request)
                .get("withdrawal_reason")
                .and_then(JsonValue::as_str),
            Some("superseded by the \"nom\" decision")
        );

        // A number or --reaffirm: the body waits for the Capsule.
        for words in [
            &[
                "checkpoint",
                "create",
                "--open",
                "O",
                "--supersedes",
                "2",
                "--next",
                "n",
            ][..],
            &["checkpoint", "create", "--withdraw", "#3", "--next", "n"][..],
            &["checkpoint", "create", "--reaffirm", "1", "--next", "n"][..],
        ] {
            let (request, _) = call_in(words, &lookup);
            assert_eq!(request.body, None, "{words:?}");
            let Some(claims::Draft::Checkpoint(draft)) = &request.pending else {
                panic!("{words:?}");
            };
            assert_eq!(draft.task_id, T);
        }
        // --reaffirm without a run to cite, a --supersedes with nothing
        // before it, and a value that is neither a number nor a claim ID.
        for (words, expected) in [
            (
                &["checkpoint", "create", "--supersedes", "1", "--next", "n"][..],
                "each --supersedes must follow",
            ),
            (
                &["checkpoint", "create", "--withdraw", "first", "--next", "n"][..],
                "--withdraw takes a claim number",
            ),
            (
                &["checkpoint", "create", "--withdraw", "0", "--next", "n"][..],
                "claim numbers start at 1",
            ),
            // P3-D2: a withdrawal reason needs a withdrawal, and text.
            (
                &[
                    "checkpoint",
                    "create",
                    "--withdraw-reason",
                    "why",
                    "--next",
                    "n",
                ][..],
                "--withdraw-reason says why the --withdraw claims no longer hold",
            ),
            (
                &[
                    "checkpoint",
                    "create",
                    "--withdraw",
                    d1,
                    "--withdraw-reason",
                    "",
                    "--next",
                    "n",
                ][..],
                "--withdraw-reason must not be empty",
            ),
        ] {
            let error = parse_in(words, &lookup).unwrap_err().to_string();
            assert!(error.contains(expected), "{words:?}: {error}");
        }
        let error = parse_in(
            &["checkpoint", "create", "--reaffirm", "1", "--next", "n"],
            &found(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("--reaffirm needs at least one --evidence"),
            "{error}"
        );
    }

    /// P3-C: `decide "<TEXT>"` is proposeDecision for the context's Task and
    /// Session; Evidence only with --evidence.
    #[test]
    fn decide_builds_the_decision_proposal() {
        let lookup = found_with_run();
        let d1 = "decision/018f47a0-0000-7000-8000-0000000000d1";
        let (request, follow) = call_in(
            &[
                "decide",
                "use JCS",
                "--rationale",
                "stable bytes",
                "--supersedes",
                d1,
            ],
            &lookup,
        );
        assert_eq!(follow, Follow::Nothing);
        assert_eq!(request.operation, OperationId::ProposeDecision);
        assert_eq!(request.target, "/v1/decisions");
        assert!(request.needs_idempotency_key());
        let body = body_of(&request);
        assert_eq!(str_at(&body, "task_id"), Some(T));
        assert_eq!(str_at(&body, "session_id"), Some(S));
        assert_eq!(str_at(&body, "content"), Some("use JCS"));
        assert_eq!(str_at(&body, "rationale"), Some("stable bytes"));
        assert!(body.get("evidence_ids").is_none());
        let (request, _) = call_in(&["decide", "x", "--evidence", "last"], &lookup);
        let body = body_of(&request);
        assert_eq!(
            body.get("evidence_ids")
                .and_then(JsonValue::as_array)
                .unwrap()[0]
                .as_str(),
            Some(E)
        );
        let (request, _) = call_in(&["decide", "x", "--supersedes", "4"], &lookup);
        assert!(request.body.is_none() && request.pending.is_some());
        for (words, expected) in [
            (&["decide"][..], "decide requires the decision"),
            (
                &["decide", "x", "--withdraw", "1"][..],
                "--withdraw does not apply",
            ),
            (
                &["decide", "x", "--rationale", ""][..],
                "--rationale must not be empty",
            ),
        ] {
            let error = parse_in(words, &lookup).unwrap_err().to_string();
            assert!(error.contains(expected), "{words:?}: {error}");
        }
        let error = parse_in(&["decide", "x"], &ContextLookup::Unavailable)
            .unwrap_err()
            .to_string();
        assert!(error.contains("--task"), "{error}");
    }

    /// P4-G (ADR 0014 E7.3): `main` reads no context for the arguments
    /// `mcp_requested` names, so the parser must take nothing from the
    /// context for them: the same answer with or without one.
    #[test]
    fn mcp_commands_are_named_and_parse_without_a_context() {
        let absent = ContextLookup::Absent {
            cwd: PathBuf::from("/w"),
        };
        let broken = ContextLookup::Broken("unreadable".to_owned());
        for words in [
            &["mcp", "serve"][..],
            &["mcp"][..],
            &["mcp", "bogus"][..],
            &["mcp", "serve", "extra"][..],
            &["mcp", "--help"][..],
            &["mcp", "serve", "--help"][..],
            &["--data-dir", "x", "mcp", "serve"][..],
            &["mcp", "serve", "--token-file", "x"][..],
            &["mcp", "serve", "--", "x"][..],
            &["mcp", "serve", "--token", "x"][..],
            &["mcp", "print-config"][..],
            &["mcp", "print-config", "extra"][..],
            &["mcp", "print-config", "--help"][..],
            &["mcp", "print-config", "--socket", "x"][..],
        ] {
            assert!(mcp_requested(&args(words)), "{words:?}");
            let without = parse_args_in(args(words), None, &ContextLookup::Unavailable);
            for lookup in [&absent, &broken] {
                assert_eq!(
                    parse_args_in(args(words), Some(OsString::from("/d")), lookup),
                    without,
                    "{words:?}"
                );
            }
        }
        for words in [
            &["context", "show"][..],
            &["hook", "print-config"][..],
            &["task", "create", "--title", "mcp"][..],
            &["--data-dir", "mcp", "context", "show"][..],
            &["run", "--", "mcp", "serve"][..],
            &["--help"][..],
            &[][..],
        ] {
            assert!(!mcp_requested(&args(words)), "{words:?}");
        }
        let parsed = |words: &[&str]| parse_args_in(args(words), None, &ContextLookup::Unavailable);
        assert_eq!(
            parsed(&["mcp", "serve"]),
            Ok(Invocation::Mcp(McpCommand::Serve))
        );
        assert_eq!(
            parsed(&["mcp", "print-config"]),
            Ok(Invocation::Mcp(McpCommand::PrintConfig))
        );
        for words in [
            &["mcp", "print-config", "extra"][..],
            &["mcp", "print-config", "--data-dir", "x"][..],
            &["mcp", "print-config", "--", "x"][..],
            &["mcp"][..],
        ] {
            assert!(parsed(words).is_err(), "{words:?}");
        }
    }

    /// U5 Z-F round 1 (S2): the configuration directory's data directory is
    /// asked for only when neither `--socket`, `--data-dir`, nor a non-empty
    /// `MEMPROVE_DATA_DIR` names one; its clause ends the usage error; a
    /// given option or variable gives what it gave before.
    #[test]
    fn u5_zf1_s2_the_daemon_location_falls_back_to_the_configuration_directory() {
        use std::cell::Cell;
        let asked = Cell::new(0);
        let found = || {
            asked.set(asked.get() + 1);
            Ok(PathBuf::from("/cfg-data"))
        };
        let missing = || {
            Err("/c/data-dir does not exist (the configuration directory is /c, from MEMPROVE_CONFIG_DIR)".to_owned())
        };
        let socket = |invocation: Result<Invocation, UsageError>| match invocation {
            Ok(Invocation::Call { socket, .. }) => Ok(socket),
            Ok(other) => panic!("{other:?}"),
            Err(UsageError(error)) => Err(error),
        };
        let deferring = |words: &[&str],
                         env: Option<&str>,
                         configured: &dyn Fn() -> Result<PathBuf, String>| {
            socket(parse_args_deferring(
                args(words),
                env.map(OsString::from),
                &ContextLookup::Unavailable,
                &|| None,
                configured,
                &AgentEnv::default(),
                &|| None,
            ))
        };
        let plain = |words: &[&str], env: Option<&str>| {
            socket(parse_args_in(
                args(words),
                env.map(OsString::from),
                &ContextLookup::Unavailable,
            ))
        };
        let old =
            "no daemon location; pass --data-dir <PATH>, --socket <PATH>, or set MEMPROVE_DATA_DIR"
                .to_owned();

        assert_eq!(
            deferring(&["status"], None, &found),
            Ok(PathBuf::from("/cfg-data/memproved.sock"))
        );
        assert_eq!(
            deferring(&["status"], Some(""), &found),
            Ok(PathBuf::from("/cfg-data/memproved.sock"))
        );
        assert_eq!(asked.get(), 2);
        for (words, env, expected) in [
            (
                &["--data-dir", "/d", "status"][..],
                None,
                "/d/memproved.sock",
            ),
            (&["--socket", "/s.sock", "status"][..], None, "/s.sock"),
            (&["status"][..], Some("/e"), "/e/memproved.sock"),
            (
                &["--data-dir", "/d", "status"][..],
                Some("/e"),
                "/d/memproved.sock",
            ),
        ] {
            assert_eq!(
                deferring(words, env, &found),
                Ok(PathBuf::from(expected)),
                "{words:?}"
            );
            assert_eq!(
                deferring(words, env, &found),
                plain(words, env),
                "{words:?}"
            );
        }
        assert_eq!(
            asked.get(),
            2,
            "asked although an option or variable was given"
        );
        assert_eq!(
            deferring(&["status"], None, &missing),
            Err(format!(
                "{old}; /c/data-dir does not exist (the configuration directory is /c, from MEMPROVE_CONFIG_DIR)"
            ))
        );
        // An empty --data-dir is given: the error of before, not asked.
        assert_eq!(
            deferring(&["--data-dir", "", "status"], None, &found),
            Err(old.clone())
        );
        assert_eq!(asked.get(), 2);
        // The library's other parsers have no fallback.
        assert_eq!(plain(&["status"], None), Err(old));
    }

    /// U8 S-F round 1, B1 (ADR 0014, "Amendment (U8, S-A)", A3): a
    /// declaration is taken as a whole. When an option or a variable gives
    /// any of the name, role, and parent, the context's remembered agent is
    /// not read, so nothing of an earlier agent is mixed in, and the pairing
    /// rules are usage errors; only when none is given is the remembered
    /// agent reused, whole. An empty variable counts as unset.
    #[test]
    fn u8_f1_b1_a_declaration_is_taken_as_a_whole() {
        let ContextLookup::Found(mut context) = found() else {
            unreachable!()
        };
        context.agent_name = Some("child".to_owned());
        context.agent_role = Some("sub_agent".to_owned());
        context.parent_session_id = Some(S.to_owned());
        let options = |pairs: &[(&'static str, &str)]| {
            pairs
                .iter()
                .map(|(name, value)| (*name, OsString::from(value)))
                .collect::<Vec<_>>()
        };
        let env = |name: Option<&str>, role: Option<&str>, parent: Option<&str>| {
            AgentEnv::of(
                name.map(OsString::from),
                role.map(OsString::from),
                parent.map(OsString::from),
            )
        };
        let declared = |pairs: &[(&'static str, &str)], env: &AgentEnv| {
            agent_of(&options(pairs), env, Some(&context))
                .map(|agent| {
                    agent.map(|agent| {
                        (
                            agent.name,
                            agent.role.as_str(),
                            agent.parent_session_id.map(|parent| parent.to_string()),
                        )
                    })
                })
                .map_err(|UsageError(error)| error)
        };
        let none = AgentEnv::default();
        // A new name and role by option: the remembered parent is not theirs.
        assert_eq!(
            declared(
                &[("--agent-name", "lead"), ("--agent-role", "orchestrator")],
                &none
            ),
            Ok(Some(("lead".to_owned(), "orchestrator", None)))
        );
        // The same by variable, with an empty MEMPROVE_PARENT_SESSION.
        assert_eq!(
            declared(&[], &env(Some("other"), Some("human"), Some(""))),
            Ok(Some(("other".to_owned(), "human", None)))
        );
        // A name alone, by option or variable, is a usage error.
        let no_role = "--agent-name needs --agent-role orchestrator, sub_agent, or human (or \
                       $MEMPROVE_AGENT_ROLE)"
            .to_owned();
        assert_eq!(
            declared(&[("--agent-name", "x")], &none),
            Err(no_role.clone())
        );
        assert_eq!(
            declared(&[], &env(Some("envonly"), None, None)),
            Err(no_role)
        );
        // A role alone, and a parent alone, are usage errors too.
        assert_eq!(
            declared(&[], &env(None, Some("human"), None)),
            Err("--agent-role needs --agent-name <NAME> (or $MEMPROVE_AGENT_NAME)".to_owned())
        );
        assert_eq!(
            declared(&[("--parent-session", S)], &none),
            Err("--parent-session needs --agent-name and --agent-role (or \
                 $MEMPROVE_AGENT_NAME and $MEMPROVE_AGENT_ROLE)"
                .to_owned())
        );
        // Nothing given (empty variables are unset): the remembered agent,
        // whole.
        let remembered = Ok(Some(("child".to_owned(), "sub_agent", Some(S.to_owned()))));
        assert_eq!(declared(&[], &none), remembered);
        assert_eq!(
            declared(&[], &env(Some(""), Some(""), Some(""))),
            remembered
        );
        // Without a context, nothing given declares no agent.
        assert_eq!(agent_of(&[], &none, None), Ok(None));
    }
}
