//! Per-command help (P3-A): `memprove <command> --help` prints that
//! command's own usage, arguments, and exit codes, not the general help.

use std::fmt::Write as _;

/// How a command can end, for its `Exit status` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exits {
    /// One daemon call: exit codes 0 through 4, and 6 (P3-C2).
    Call,
    /// `ledger verify`: as [`Exits::Call`], plus 5 when a record does not
    /// hold.
    LedgerVerify,
    /// `run`: the command's own exit code, or 125.
    Run,
    /// `begin`: as [`Exits::Call`]; 1 also covers a refusal.
    Begin,
    /// `checkpoint create` and `decide` (P3-C): as [`Exits::Call`]; 1 also
    /// covers a claim number that cannot be resolved (nothing is sent).
    Claims,
    /// `context show`: local only.
    Local,
    /// `resume` (P4-C): as [`Exits::Call`]; 1 also covers a Pack that does
    /// not fit its budget, 2 a `--claims` number the Capsule does not list.
    Resume,
    /// `hook session-start` (P4-E): always 0.
    Hook,
    /// `hook print-config`, `install`, `uninstall` (P4-E): local only; 1
    /// when the settings file is refused or cannot be written.
    HookConfig,
    /// `mcp serve` (P4-G): 0 at the end of standard input.
    McpServe,
    /// `mcp print-config` (P4-G): local only; 1 when this executable or the
    /// current directory cannot be resolved.
    McpConfig,
    /// `backup` and `restore` (U1, E4): offline, no daemon call; 1 when
    /// refused or failed.
    Offline,
    /// `doctor` (U1, E3): 1 when a check failed.
    Doctor,
    /// `init` (U17, M1 O4): 1 when a step failed or `doctor` reports a FAIL.
    Init,
}

/// The help of one command.
#[derive(Debug, PartialEq, Eq)]
pub struct CommandHelp {
    /// The words that name the command, for example `token create`.
    pub name: &'static str,
    /// One line saying what the command does.
    pub summary: &'static str,
    /// The command line, without the leading `memprove [OPTIONS]`.
    pub usage: &'static [&'static str],
    /// The operation it calls and its scope, when it calls one.
    pub calls: Option<&'static str>,
    /// Its arguments and options, each with a description.
    pub options: &'static [(&'static str, &'static str)],
    /// Further explanation; empty when there is none.
    pub notes: &'static str,
    /// How it ends.
    pub exits: Exits,
}

const IDEM: (&str, &str) = (
    "--idempotency-key <KEY>",
    "Idempotency-Key to send, 16 through 200 characters; a random one is used when omitted",
);
// U8 A3 (Owner O4): the agent a Session declares.
const AGENT_NAME: (&str, &str) = (
    "--agent-name <NAME>",
    "the agent's name, 1 to 64 of A-Z, a-z, 0-9, _ and -; needs --agent-role",
);
const AGENT_ROLE: (&str, &str) = (
    "--agent-role <ROLE>",
    "orchestrator, sub_agent, or human; U9: a sub_agent may not decide, complete, or overrule another agent",
);
const PARENT_SESSION: (&str, &str) = (
    "--parent-session <SESSION_ID>",
    "the Session that dispatched this agent, a Session of the same Project",
);
const AGENT_NOTE: &str = "--agent-name, --agent-role, and --parent-session default to\n\
                          $MEMPROVE_AGENT_NAME, $MEMPROVE_AGENT_ROLE, and\n\
                          $MEMPROVE_PARENT_SESSION; the daemon records the agent in\n\
                          session.started@3 and the Session's row.";
const LIMIT: (&str, &str) = ("--limit <N>", "page size, 1 through 500 (default 100)");
const CURSOR: (&str, &str) = (
    "--cursor <CURSOR>",
    "id of the last item of the previous page (lowercase UUIDv7)",
);
const EVIDENCE_LAST: (&str, &str) = (
    "--evidence <EVIDENCE_ID | last | rN>",
    "an Evidence id, `last` for the context's latest run, or a run label (r2) that `run` printed; \
     a value that only looks like a label (r0, r01, R1) is a usage error (exit 2), nothing sent; repeatable",
);

/// Every command with help, in the order of the general usage.
pub const COMMANDS: &[CommandHelp] = &[
    CommandHelp {
        name: "health live",
        summary: "check that the daemon process is up",
        usage: &["health live"],
        calls: Some("healthLive  GET /health/live  (no token)"),
        options: &[],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "health ready",
        summary: "check that the daemon is ready for protected operations",
        usage: &["health ready"],
        calls: Some("healthReady  GET /health/ready  (no token)"),
        options: &[],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "status",
        summary: "show the daemon's readiness, writer queue depth, and Project count",
        usage: &["status"],
        calls: Some("getStatus  GET /v1/status  (control scope)"),
        options: &[],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "version",
        summary: "show the daemon's version, API major version, and capabilities",
        usage: &["version"],
        calls: Some("getVersion  GET /v1/version  (any token)"),
        options: &[],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "token create",
        summary: "create a client token",
        usage: &[
            "token create --label <LABEL> --scope <SCOPE> [--scope <SCOPE>...]",
            "              [--idempotency-key <KEY>]",
        ],
        calls: Some("createClientToken  POST /v1/auth/tokens  (control scope)"),
        options: &[
            (
                "--label <LABEL>",
                "what the token is for, 1 through 128 characters",
            ),
            (
                "--scope <SCOPE>",
                "control, ingest-only, mcp-read, mcp-write, or proxy-client; repeatable",
            ),
            IDEM,
        ],
        notes: "The new secret is printed once and cannot be shown again.",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "token list",
        summary: "list client tokens, without their secrets",
        usage: &["token list [--limit <N>] [--cursor <CURSOR>]"],
        calls: Some("listClientTokens  GET /v1/auth/tokens  (control scope)"),
        options: &[LIMIT, CURSOR],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "token revoke",
        summary: "revoke a client token",
        usage: &["token revoke <TOKEN_ID> [--idempotency-key <KEY>]"],
        calls: Some("revokeClientToken  POST /v1/auth/tokens/<TOKEN_ID>/revoke  (control scope)"),
        options: &[
            ("<TOKEN_ID>", "the token to revoke (lowercase UUIDv7)"),
            IDEM,
        ],
        notes: "The last active control token cannot be revoked (409 last_control_token).",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "project register",
        summary: "register the Git repository containing <ROOT> as a Project",
        usage: &["project register <ROOT> [--idempotency-key <KEY>]"],
        calls: Some("registerProject  POST /v1/projects/register  (control scope)"),
        options: &[
            (
                "<ROOT>",
                "a path inside a Git worktree; a relative path is made absolute against the current directory",
            ),
            IDEM,
        ],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "project get",
        summary: "show a Project",
        usage: &["project get <PROJECT_ID>"],
        calls: Some("getProject  GET /v1/projects/<PROJECT_ID>  (control or mcp-read)"),
        options: &[("<PROJECT_ID>", "the Project (lowercase UUIDv7)")],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "workspace resolve",
        summary: "find the Workspace of a path in a Project; a linked worktree of the repository is registered",
        usage: &["workspace resolve --project <PROJECT_ID> <PATH>"],
        calls: Some("resolveWorkspace  POST /v1/workspaces/resolve  (control or mcp-write)"),
        options: &[
            ("--project <PROJECT_ID>", "the Project (lowercase UUIDv7)"),
            (
                "<PATH>",
                "a path in the worktree; a relative path is made absolute against the current directory",
            ),
        ],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "session create",
        summary: "start a Session in a Workspace",
        usage: &[
            "session create --workspace <WORKSPACE_ID> --agent <AGENT_ID> [--task <TASK_ID>]",
            "               [--agent-name <NAME> --agent-role <ROLE> [--parent-session <SESSION_ID>]]",
            "               [--idempotency-key <KEY>]",
        ],
        calls: Some("createSession  POST /v1/sessions  (control or mcp-write)"),
        options: &[
            (
                "--workspace <WORKSPACE_ID>",
                "the Workspace (lowercase UUIDv7)",
            ),
            (
                "--agent <AGENT_ID>",
                "the agent identity (lowercase UUIDv7)",
            ),
            ("--task <TASK_ID>", "the Task this Session continues"),
            AGENT_NAME,
            AGENT_ROLE,
            PARENT_SESSION,
            IDEM,
        ],
        notes: AGENT_NOTE,
        exits: Exits::Call,
    },
    CommandHelp {
        name: "session list",
        summary: "list the Sessions of a Workspace",
        usage: &["session list --workspace <WORKSPACE_ID> [--limit <N>] [--cursor <CURSOR>]"],
        calls: Some("listSessions  GET /v1/sessions  (control or mcp-read)"),
        options: &[
            (
                "--workspace <WORKSPACE_ID>",
                "the Workspace (lowercase UUIDv7)",
            ),
            LIMIT,
            CURSOR,
        ],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "session end",
        summary: "end a Session",
        usage: &[
            "session end [<SESSION_ID>] [--revision <N>] [--reason <TEXT>] [--abandoned]",
            "            [--workspace <WORKSPACE_ID>] [--idempotency-key <KEY>]",
        ],
        calls: Some("endSession  POST /v1/sessions/<SESSION_ID>/end  (control or mcp-write)"),
        options: &[
            (
                "<SESSION_ID>",
                "the Session; the current context's when omitted",
            ),
            (
                "--revision <N>",
                "the revision last read; the context's when omitted, and with --abandoned for another Session its current revision, read first (U10)",
            ),
            (
                "--reason <TEXT>",
                "why it ended; recorded in the session.ended Event",
            ),
            (
                "--abandoned",
                "end it as abandoned: recorded as session.crashed instead of session.ended",
            ),
            (
                "--workspace <WORKSPACE_ID>",
                "the Workspace whose Sessions are read for the revision of another Session, when --revision is omitted: the current context's, else the one every context of this Workspace root records; needed in a configuration directory that holds no context of this Workspace root (U11)",
            ),
            IDEM,
        ],
        notes: "Ending the context's Session clears it from the context. With --abandoned the\n\
                request also names who ends it (U9): the Session this client's context names, when\n\
                it is not the one ended, and the agent this client declares ($MEMPROVE_AGENT_NAME\n\
                and $MEMPROVE_AGENT_ROLE, else the context's); there is no option for it.\n\
                Taking over (U10): the Session line of a Pack for a Session someone else left open ends\n\
                with this command, its ID filled in, to copy as it stands:\n\
                `memprove session end <SESSION_ID> --abandoned --reason <why>`. Without --revision\n\
                it reads that Session's current revision (listSessions of this Workspace) first. In\n\
                a configuration directory that holds no context of this Workspace root (a reader\n\
                with only the daemon's location and a token) the Workspace is not known: add\n\
                --workspace, `memprove session end <SESSION_ID> --abandoned --reason <why>\n\
                --workspace <WORKSPACE_ID>`, or run the command in the Workspace's directory where\n\
                the configuration directory has a context, or pass --revision. With none of them\n\
                nothing is sent (exit 2).",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "task create",
        summary: "create a Task in a Project",
        usage: &[
            "task create --project <PROJECT_ID> --title <TITLE> [--workspace <WORKSPACE_ID>]",
            "            [--description <TEXT>] [--idempotency-key <KEY>]",
        ],
        calls: Some("createTask  POST /v1/tasks  (control or mcp-write)"),
        options: &[
            ("--project <PROJECT_ID>", "the Project (lowercase UUIDv7)"),
            ("--title <TITLE>", "the Task's title"),
            (
                "--workspace <WORKSPACE_ID>",
                "scope the Task to one Workspace of the Project",
            ),
            ("--description <TEXT>", "a longer description"),
            IDEM,
        ],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "task list",
        summary: "list the Tasks of a Project",
        usage: &["task list [--project <PROJECT_ID>] [--limit <N>] [--cursor <CURSOR>]"],
        calls: Some("listTasks  GET /v1/tasks  (control or mcp-read)"),
        options: &[
            (
                "--project <PROJECT_ID>",
                "the Project (lowercase UUIDv7); the current context's Project when omitted",
            ),
            LIMIT,
            CURSOR,
        ],
        notes: "Without --project the Project is the current context's: this client session's when\n\
                $MEMPROVE_CLIENT_SESSION names one that covers the directory, else the directory's\n\
                (U11); and when neither names one, the Project every context of this Workspace root\n\
                records, if they agree. With none of them it is a usage error and nothing is sent.",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "task transition",
        summary: "move a Task to another state",
        usage: &[
            "task transition [<TASK_ID>] --to <STATE> [--revision <N>] [--evidence <EVIDENCE_ID>...]",
            "                [--workspace <WORKSPACE_ID>] [--idempotency-key <KEY>]",
        ],
        calls: Some("transitionTask  POST /v1/tasks/<TASK_ID>/transition  (control or mcp-write)"),
        options: &[
            ("<TASK_ID>", "the Task; the current context's when omitted"),
            (
                "--to <STATE>",
                "proposed, ready, in_progress, blocked, completed, or cancelled",
            ),
            (
                "--revision <N>",
                "the revision last read; the context's when omitted",
            ),
            (
                "--evidence <EVIDENCE_ID>",
                "completion Evidence, one per option; only for --to completed",
            ),
            (
                "--workspace <WORKSPACE_ID>",
                "the Workspace the Evidence is judged against; only for --to completed",
            ),
            IDEM,
        ],
        notes: "`--to completed` needs one --evidence per completion Evidence: each must be a PASS\n\
                command or test of the Task that still holds against the Workspace; otherwise\n\
                409 evidence_stale. U9: it sends the context's Session only with --to completed of\n\
                the context's Task while the context has a Session, as `task complete` does, and a\n\
                sub_agent's is 403 role_forbidden; with no Session in the context (after `end`) or\n\
                another Task named, it sends none, and the daemon does not judge that completion\n\
                by role (the context's Session is no Session of another Task: 400).",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "task complete",
        summary: "complete the context's Task, citing its passed runs",
        usage: &[
            "task complete [--evidence <EVIDENCE_ID | last | rN>...] [--revision <N>]",
            "              [--idempotency-key <KEY>]",
        ],
        calls: Some("transitionTask to completed  (control or mcp-write)"),
        options: &[
            EVIDENCE_LAST,
            (
                "--revision <N>",
                "the revision last read; the context's when omitted",
            ),
            IDEM,
        ],
        notes: "Uses the context's Task, revision, and Workspace. Without --evidence it cites every\n\
                citable passed run of the current state: the runs `memprove run` lists as PASS;\n\
                when none passed it cites the latest run. On success standard error names the\n\
                labels it cited. Without --evidence it is refused, exit 2 and no request, while the\n\
                latest run of some command (same argv) in this state did not pass: standard error\n\
                names those runs. Rerun the command with `memprove run` until it passes, or\n\
                cite runs yourself with --evidence <LABEL>. With --evidence it cites exactly\n\
                those, whatever the other runs say. 409 evidence_stale when an Evidence no\n\
                longer holds or the Task does not verify: commit, rerun with `memprove run`,\n\
                and try again. When a record of the Task does not hold (`resume` reads tampered)\n\
                it is 409 evidence_stale whatever you cite, and its detail says the integrity\n\
                check failed: a rerun does not help; run `memprove ledger verify` to see\n\
                which record. The Workspace it sends is where the Evidence is judged; the\n\
                response's workspace_id is the Task's own Workspace (null for a Task `begin\n\
                --new-task` created). It sends the context's Session, and the daemon judges\n\
                the completion by that Session's role (U9): when it declared --agent-role\n\
                sub_agent, it is 403 role_forbidden, exit 1, and nothing changes, whatever\n\
                runs it cites; the orchestrator or a person completes the Task, citing any\n\
                Session's runs.",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "event ingest",
        summary: "send one Event envelope",
        usage: &["event ingest <ENVELOPE_FILE | -> [--idempotency-key <KEY>]"],
        calls: Some("ingestEvent  POST /v1/events  (control or mcp-write)"),
        options: &[
            (
                "<ENVELOPE_FILE | ->",
                "the envelope JSON, from the file or from standard input for `-`; sent unchanged",
            ),
            IDEM,
        ],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "event list",
        summary: "list the Events of a Project",
        usage: &["event list --project <PROJECT_ID> [--limit <N>] [--cursor <CURSOR>]"],
        calls: Some("listEvents  GET /v1/events  (control scope)"),
        options: &[
            ("--project <PROJECT_ID>", "the Project (lowercase UUIDv7)"),
            LIMIT,
            CURSOR,
        ],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "event get",
        summary: "show one Event",
        usage: &["event get <EVENT_ID>"],
        calls: Some("getEvent  GET /v1/events/<EVENT_ID>  (control scope)"),
        options: &[("<EVENT_ID>", "the Event (lowercase UUIDv7)")],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "run",
        summary: "run a command here and record its result as Evidence",
        usage: &[
            "run [--session <SESSION_ID>] [--workspace <WORKSPACE_ID>] [--task <TASK_ID>]",
            "    [--test [--test-cases <N>] [--test-name <NAME>]] [--test-format cargo|pytest]",
            "    [--digest-only] [--idempotency-key <KEY>] -- <PROGRAM> [<ARG>...]",
        ],
        calls: Some("captureEvidence  POST /v1/evidence/capture  (control or mcp-write)"),
        options: &[
            (
                "--session <SESSION_ID>",
                "the Session; the context's when omitted",
            ),
            (
                "--workspace <WORKSPACE_ID>",
                "the Workspace; the context's when omitted",
            ),
            ("--task <TASK_ID>", "the Task; the context's when omitted"),
            (
                "--test",
                "record the result as a test run; it passes only with exit code 0 and --test-cases above 0",
            ),
            ("--test-cases <N>", "the number of test cases; needs --test"),
            ("--test-name <NAME>", "the test target's name; needs --test"),
            (
                "--test-format cargo",
                "a test run whose case count is read from the `test result:` lines of cargo test",
            ),
            (
                "--test-format pytest",
                "a test run whose case count (passed + failed + errors) is read from pytest's summary on the last line of its output; when pytest printed no summary (-qq, or -q with another -q in addopts) and the last line is only progress marks, the dots and the F and E marks are counted (s, x, and X are not cases, as in a summary; a line of only those is 0 cases and does not pass) and the run says counted from the progress line; any other last line records no count; --test-cases given with it wins",
            ),
            (
                "--digest-only",
                "record only the SHA-256 of each output stream, not its text",
            ),
            IDEM,
            (
                "-- <PROGRAM> [<ARG>...]",
                "the command to run, here, in this environment",
            ),
        ],
        notes: "The command runs in this process's environment minus MEMPROVE_TOKEN; memproved\n\
                never runs it. Its argv is recorded: never put a secret in it. A control character\n\
                (a line break or a tab, say) in the program or an argument is refused with exit 2\n\
                before the command runs, and so is a string in the format of a memprove token\n\
                (43 characters of A-Z, a-z, 0-9, - and _ with at least one upper-case letter, one\n\
                lower-case letter, and one digit; a test name such as\n\
                test_calculate_metrics_rejects_empty_series is not one). Its own output goes\n\
                to standard error; standard output carries the recorded Evidence. The last line of\n\
                standard error sums up what was recorded, with the run's label (r2). The line\n\
                before it lists every run of this repository state that `checkpoint create` can\n\
                cite: memproved seals the earlier runs of the same Task and Workspace into the\n\
                new Snapshot when the commit, index, worktree, and branch are unchanged and no\n\
                untracked file exists. A passed run whose argv ran again later in this state\n\
                without passing is listed as `r1 (PASS, overruled by r2)`, with a line saying why:\n\
                it cannot back a --fact. Ignored files, permission bits other than the executable\n\
                bit, and environment variables are not part of the repository state.\n\
                Standard output is large (the Evidence with the tails of both streams and its\n\
                Snapshot): redirect it to a file outside the repository, for example\n\
                `memprove run ... > ../run.json`, since a file inside it is an untracked file\n\
                that keeps the run from being carried; read the result and the label on the\n\
                last line of standard error. A run without --test and --test-format whose argv is\n\
                the one of the Task's last passed test run (the Pack's Last passed line) says, on the\n\
                line before the summary, which arguments to add; it is recorded as a command run\n\
                all the same, and no fact can cite a command run.\n\
                A test run records the format it was made with in the ledger as its test_format:\n\
                cargo or pytest from --test-format, and cases for a --test-cases count without\n\
                one. The Pack's Last passed line reads it to give the arguments that record the same\n\
                run again, and so does the hint above that a command run which repeats it gets;\n\
                a run recorded without a format is read from its argv.",
        exits: Exits::Run,
    },
    CommandHelp {
        name: "evidence get",
        summary: "show one Evidence",
        usage: &["evidence get <EVIDENCE_ID>"],
        calls: Some("getEvidence  GET /v1/evidence/<EVIDENCE_ID>  (control scope)"),
        options: &[("<EVIDENCE_ID>", "the Evidence (lowercase UUIDv7)")],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "checkpoint create",
        summary: "record a Checkpoint for the context's Task",
        usage: &[
            "checkpoint create <REQUEST_FILE | -> [--idempotency-key <KEY>]",
            "checkpoint create [--fact <TEXT> [--evidence <EVIDENCE_ID | last | rN>...] [--supersedes <CLAIM>...]]...",
            "                  [--open <TEXT> [--evidence <EVIDENCE_ID | last | rN>...] [--supersedes <CLAIM>...]]...",
            "                  [--reaffirm <CLAIM> [--evidence <EVIDENCE_ID | last | rN>...]]...",
            "                  [--reaffirm-all [--evidence <EVIDENCE_ID | last | rN>...]]",
            "                  --next <TEXT> [--supersedes <CLAIM>...] [--withdraw <CLAIM>...]",
            "                  [--withdraw-session <K>] [--withdraw-reason <TEXT>]",
            "                  [--objective <TEXT>] [--snapshot <SNAPSHOT_ID>] [--session <SESSION_ID>]",
            "                  [--workspace <WORKSPACE_ID>] [--task <TASK_ID>] [--idempotency-key <KEY>]",
        ],
        calls: Some("createCheckpoint  POST /v1/checkpoints  (control or mcp-write)"),
        options: &[
            (
                "<REQUEST_FILE | ->",
                "a CreateCheckpointRequest JSON, from the file or from standard input for `-`; sent unchanged",
            ),
            (
                "--fact <TEXT>",
                "a verified_fact; needs --evidence of a passed test run",
            ),
            (
                "--open <TEXT>",
                "an open item; cites no Evidence unless --evidence follows it (cite a failing run this way)",
            ),
            (
                "--reaffirm <CLAIM>",
                "the active fact <CLAIM> again, same text, on this Checkpoint's Evidence; supersedes it",
            ),
            (
                "--reaffirm-all",
                "reaffirm every active fact that is not verified and that this command names nowhere \
                 else; see below",
            ),
            EVIDENCE_LAST,
            (
                "--supersedes <CLAIM>",
                "the statement before it (or --next) is the new version of <CLAIM>; repeatable",
            ),
            (
                "--withdraw <CLAIM>",
                "<CLAIM> no longer holds and nothing replaces it; repeatable",
            ),
            (
                "--withdraw-reason <TEXT>",
                "why the withdrawn claims no longer hold; required when one of them is a fact",
            ),
            (
                "--withdraw-session <K>",
                "withdraw every statement in force that `Session K` (the Pack's and resume --text's Session number) wrote, as that many --withdraw; needs --withdraw-reason; at most 500, and none in force is a usage error",
            ),
            ("--next <TEXT>", "the recommendation for the next agent"),
            ("--objective <TEXT>", "default: the context's Task title"),
            ("--snapshot <SNAPSHOT_ID>", "default: the context's latest"),
            ("--session <SESSION_ID>", "default: the context's"),
            ("--workspace <WORKSPACE_ID>", "default: the context's"),
            ("--task <TASK_ID>", "default: the context's"),
            IDEM,
        ],
        notes: "Each --evidence belongs to the closest --fact, --open, or --reaffirm before it. A\n\
                --fact or --reaffirm without --evidence cites the context's latest run; an --open\n\
                without --evidence cites no Evidence. A Checkpoint can cite only\n\
                Evidence of its Snapshot: the latest run and the earlier runs of the same\n\
                repository state that `memprove run` carried into it, each cited by the label\n\
                `run` printed (--evidence r2). A --fact all of whose citations (also by `last`, or by\n\
                default) are runs this context recorded as command runs (a `run` without --test\n\
                or --test-format) sends nothing and says so: `r2 is a command run and cannot support a\n\
                fact; a rerun with memprove run <rerun arguments> -- <argv> can be cited` (exit 2; a fact that cites a\n\
                test run too, and an --open, are not held back). Each --supersedes belongs to\n\
                the closest --fact, --open, --reaffirm, or --next before it. <CLAIM> is a claim\n\
                number from `memprove resume --text` (3 or #3) or a claim ID; numbers and\n\
                --reaffirm are resolved through the Task Capsule just before sending, and nothing\n\
                is sent when the Capsule is tampered or does not list the number. Write only what\n\
                is new: earlier claims stay listed; supersede, withdraw, or reaffirm them instead\n\
                of repeating them. After the Checkpoint is recorded, standard error names each new\n\
                statement's number and kind and the numbers superseded (the replaced next action\n\
                too), withdrawn, and reaffirmed, read from the Task Capsule; standard output is\n\
                the Checkpoint JSON. A statement's text says what holds, not which commit (the\n\
                system shows the commit its Evidence is bound to) and not how many test cases\n\
                (the count is in the Evidence). --reaffirm reuses the original text unchanged;\n\
                when that text is no longer accurate, record a new --fact with --supersedes\n\
                <CLAIM> instead. A new --next replaces the previous next action as a whole:\n\
                there is no partial edit, so restate all of it.\n\
                --reaffirm-all reaffirms every fact that awaits it: active, not verified, and not\n\
                named by a --supersedes, --withdraw, or --reaffirm of the same command. With\n\
                --evidence after it, every such fact cites that Evidence, as one --reaffirm <N>\n\
                with the same --evidence per fact would. Without --evidence, a fact is reaffirmed\n\
                only when, for each command its Evidence ran, the latest run of that same command\n\
                (same argv) in the current repository state passed; it then cites those runs and\n\
                never a run of another command. A run answers only for Evidence of its own kind:\n\
                a test run for a test run, a command run (without --test or --test-format) for a\n\
                command run; a fact whose Evidence holds no test run is skipped. The runs are\n\
                those `run` lists, of this context's Workspace, and they count\n\
                only while the Workspace is still in their repository state: after a commit or an\n\
                edit with no run since, every fact is skipped. So is a fact one of whose commands\n\
                did not run, or did not run as a test when its Evidence is a test run, or whose\n\
                latest run did not pass; the reason says how to rerun it. Standard error names the\n\
                facts reaffirmed, each with the claim that reaffirms it and its actual verdict read\n\
                back after the write (reaffirm-all reaffirmed: #1 (r5) as #7: verified), and\n\
                skipped, each with the reason (reaffirm-all skipped:), and ends with\n\
                reaffirmed N (verified K), skipped M. With --evidence, a fact whose cited\n\
                runs are not runs of the commands its Evidence ran is named in a warning before\n\
                sending, and sent as given. When no fact is reaffirmed and the command records\n\
                nothing else, nothing is sent and the exit code is 0, unless --next differs from\n\
                the next action in force: then the Checkpoint is recorded. The daemon checks each\n\
                reaffirmation as for --reaffirm; when it refuses the request, standard error then\n\
                says nothing was written, names the facts it would have reaffirmed and skipped,\n\
                and which fact each $.verified_completed_work[i] of the detail reaffirms. Nothing\n\
                is retried. U9: a Session that declared --agent-role sub_agent may supersede\n\
                (--reaffirm and --reaffirm-all supersede) only open items and the claims of\n\
                Sessions of its own --agent-name, and withdraw (--withdraw, --withdraw-session)\n\
                only the latter, open items of another agent not included; any other target is\n\
                403 role_forbidden, exit 1, and nothing is written: the orchestrator or a person\n\
                writes it. The next action that --next replaces is not such a target.",
        exits: Exits::Claims,
    },
    CommandHelp {
        name: "checkpoint get",
        summary: "show one Checkpoint",
        usage: &["checkpoint get <CHECKPOINT_ID>"],
        calls: Some("getCheckpoint  GET /v1/checkpoints/<CHECKPOINT_ID>  (control or mcp-read)"),
        options: &[("<CHECKPOINT_ID>", "the Checkpoint (lowercase UUIDv7)")],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "decide",
        summary: "record a Decision of the context's Task",
        usage: &[
            "decide <TEXT> [--rationale <TEXT>] [--evidence <EVIDENCE_ID | last | rN>...]",
            "       [--supersedes <CLAIM>...] [--task <TASK_ID>] [--session <SESSION_ID>]",
            "       [--idempotency-key <KEY>]",
        ],
        calls: Some("proposeDecision  POST /v1/decisions  (control or mcp-write)"),
        options: &[
            ("<TEXT>", "the decision, as one argument"),
            ("--rationale <TEXT>", "why"),
            (
                "--evidence <EVIDENCE_ID | last | rN>",
                "Evidence of the Task it rests on, as for checkpoint create (a value that only looks \
                 like a label, r0, r01, R1, is a usage error, exit 2, nothing sent); repeatable; none by default",
            ),
            (
                "--supersedes <CLAIM>",
                "an earlier claim this Decision replaces (an earlier Decision, too); repeatable",
            ),
            ("--task <TASK_ID>", "default: the context's"),
            (
                "--session <SESSION_ID>",
                "default: the context's; it must be active",
            ),
            IDEM,
        ],
        notes: "A Decision needs no run and has no accept step: it is in force until a later claim\n\
                supersedes it or a Checkpoint withdraws it. Its verdict says whether the Evidence it\n\
                cites still holds; without Evidence it cannot be confirmed. <CLAIM> is a claim\n\
                number from `memprove resume --text` (3 or #3) or a claim ID; numbers are\n\
                resolved through the Task Capsule just before sending, and nothing is sent when\n\
                the Capsule is tampered or does not list the number. U9: a Session that declared\n\
                --agent-role sub_agent records no Decision: 403 role_forbidden, exit 1; the\n\
                orchestrator or a person records it.",
        exits: Exits::Claims,
    },
    CommandHelp {
        name: "recover preview",
        summary: "show whether the Task's latest Checkpoint still holds",
        usage: &["recover preview [--task <TASK_ID>] [--workspace <WORKSPACE_ID>] [--text]"],
        calls: Some(
            "getRecoveryPreview  GET /v1/tasks/<TASK_ID>/recovery-preview  (control or mcp-read)",
        ),
        options: &[
            ("--task <TASK_ID>", "the Task; the context's when omitted"),
            (
                "--workspace <WORKSPACE_ID>",
                "the Workspace to judge against; default: the Checkpoint's Snapshot's",
            ),
            (
                "--text",
                "print sentences instead of JSON; display only, the JSON is the judgement",
            ),
        ],
        notes: "",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "resume",
        summary: "show every claim of the Task and what to do next, to take it over",
        usage: &[
            "resume [--task <TASK_ID>] [--workspace <WORKSPACE_ID>] [--text [--all | --claims <NUMBERS>]]",
            "resume [--task <TASK_ID>] [--workspace <WORKSPACE_ID>] --text [--all] --session <K>",
            "resume [--task <TASK_ID>] [--workspace <WORKSPACE_ID>] --pack [--budget <N> | --claims <NUMBERS>]",
            "       [--query <TEXT>]",
        ],
        calls: Some(
            "getTaskCapsule  GET /v1/tasks/<TASK_ID>/recovery-capsule  (control or mcp-read)",
        ),
        options: &[
            ("--task <TASK_ID>", "the Task; the context's when omitted"),
            (
                "--workspace <WORKSPACE_ID>",
                "the Workspace to judge against; default: the latest Checkpoint's Snapshot's",
            ),
            (
                "--text",
                "print one line per continuation item; display only, the JSON is the judgement",
            ),
            (
                "--all",
                "with --text only: also list each superseded and withdrawn statement on its own line",
            ),
            (
                "--session <K>",
                "with --text only: list only the statements `Session K` wrote, and its Session line; a K that names no Session, or one that wrote nothing, is a usage error",
            ),
            (
                "--claims <NUMBERS>",
                "with --text (not --all) or --pack (not --budget): print only the lines of these claims, in full, superseded and withdrawn ones too; numbers and ranges separated by commas, such as 3,5-7 or #3,#5-#7",
            ),
            (
                "--pack",
                "print the Context Pack instead: the Capsule as numbered lines within a length budget (P4-C, P4-C2); the line of a Session that is not ended and not your own ends with `; end it before taking over: memprove session end <SESSION_ID> --abandoned --reason <why> (MCP: end {session:<k>, abandoned:true})`, its ID and number filled in, with the absolute path of this executable in place of memprove when memprove is not on PATH (U10)",
            ),
            (
                "--budget <N>",
                "with --pack only: the budget in UTF-16 code units, from 1000 through 1000000; default 9000",
            ),
            (
                "--query <TEXT>",
                "with --pack only (not --claims): list only the claims the query matches, best first, each followed by the claims that supersede it, then the active next action; 1 through 256 characters, with no control character and no string in the format of a memprove token; nothing is recorded for `memprove begin`",
            ),
        ],
        notes: "Lists the statements of every Checkpoint of the Task and every Decision,\n\
                numbered #1, #2, ... in ledger order, with their verdicts, what superseded them,\n\
                the reruns, and the files changed since each commit their Evidence is bound to.\n\
                With --text a line after the Task line counts the Sessions (Sessions: all,\n\
                ended normally, ended abandoned, not ended); a Session the ledger records no end\n\
                for reads not ended with the time the ledger last recorded one of\n\
                its Events (last wrote to the ledger at, UTC), and the Session the context file of this\n\
                directory names is labelled the Session this directory's context file records: only that, not\n\
                necessarily your own.\n\
                With --text each item is one line: everything an agent wrote (text, argv, each\n\
                changed file, a withdrawal reason) is quoted in 「」, with line breaks, control\n\
                characters, and invisible format characters shown escaped, so verified outside 「」\n\
                appears only on the Task line or a verified fact that stands. An open item, a\n\
                next action, a Decision, and a superseded or withdrawn statement (a fact too)\n\
                show no verdict: no evidence cited, or each cited Evidence's own\n\
                result and whether its commit is still the current state. The first line\n\
                counts the withdrawn facts. The\n\
                files changed since each commit are listed once (at most 20, with the total).\n\
                By default --text does not list superseded and withdrawn statements one by one:\n\
                one line after the other statements counts each kind and names their numbers,\n\
                consecutive numbers as a range (superseded 2: #1–#2; withdrawn 1: #4). --text --all\n\
                lists every one of them, as before; --all without --text is a usage error.\n\
                The CLI reads a Task Capsule of up to 16 MiB; a larger one exits 6.\n\
                To restore what the reruns list (Rerun), copy the argv of each line exactly as listed,\n\
                the `env NAME=value` prefix included, into `memprove run -- <argv>` (elements are\n\
                joined by spaces; quote one that holds spaces): a run with a different argv is a\n\
                different command and does not restore the fact.\n\
                Reading a Session line: not ended with a recent last write may still be\n\
                running; an old time means it was probably left behind, and the line labelled\n\
                the Session this directory's context file records is only the one that file\n\
                names. End a Session someone else left with the command its Session line ends with,\n\
                `memprove session end <SESSION_ID> --abandoned --reason <why>` (U10).\n\
                --text --claims 3,5-7 prints only the lines of claims #3, #5, #6, and #7, each in\n\
                full as --text --all prints it, superseded and withdrawn ones too; a number the\n\
                Task Capsule does not list is a usage error (exit 2).\n\
                --pack prints the Context Pack (ADR 0014 E1, E2): the same Capsule as numbered\n\
                lines, each starting with a fixed prefix (Pack:, Ontology:, Task「, Integrity:,\n\
                Sessions:, Session, Last passed:, Can:, Cannot:, Base:, #<number>, Rerun:,\n\
                No rerun needed:, Folded:, Not listed:, Superseded and withdrawn:, Gaps:, Omitted:,\n\
                Digest:), agent text quoted\n\
                in 「」 with 「, 」, and line breaks escaped. With no Rerun line, a Last passed line\n\
                after the Session lines names the test run that last passed, its argv, the first 12\n\
                digits of its commit, and after a ; the memprove run arguments that record it as\n\
                a test run (--test --test-format cargo, --test --test-format pytest, or --test\n\
                --test-cases <N> for any other command): run the tests with that argv and those\n\
                arguments. A claim line names a commit by its first 12 digits; each\n\
                base commit has one Base line with its full name and the files changed since,\n\
                and the current HEAD is on the first line only. The Pack is at most --budget\n\
                UTF-16 code units long, its last line included (default 9000, from 1000 through\n\
                1000000; out of range is a usage error). When the whole Pack is longer, it\n\
                leaves out in steps that stop as soon as it fits: level 1 writes only the number\n\
                of changed files on each Base line, level 2 shortens bodies to their first 120\n\
                characters (verified facts first, then the other facts, the Decisions, the open\n\
                items; lower numbers first), level 3 omits whole bodies in the same order, level\n\
                4 folds the verified facts into one line, level 5 stops listing claims one by one\n\
                (facts first, then Decisions, then open items) and counts them on one Not listed line,\n\
                facts by verdict, the others by kind, with their numbers. The next action, every\n\
                count on the Task line, the integrity lines, the Session lines, the Last passed line,\n\
                and the reruns are never left out; the Omitted line counts what was left out, and names the command for\n\
                the full lines of given numbers. The last line is Digest: sha256:<pack_digest>, the\n\
                SHA-256 of the lines before it; the same ledger, probe, and budget give the same\n\
                bytes. When even level 5 does not fit, it prints nothing and exits 1 with the\n\
                length it needs. In a tampered Pack the first Integrity line adds that the numbers\n\
                may differ from before (claim numbers may differ from before).\n\
                --pack --claims 3,5-7 prints the full Pack lines of claims #3, #5, #6, and #7,\n\
                superseded and withdrawn ones too, after the Base lines they name, with no budget;\n\
                it takes no --budget, and a number the Task Capsule does not list is a usage\n\
                error (exit 2).\n\
                The Can and Cannot lines (ADR 0014 E3) say, for completing the Task, starting a\n\
                Session on it, and citing its latest run in a fact, whether the daemon would\n\
                accept the write now, and if not the Problem codes it would refuse it with;\n\
                they are never left out. The Session lines list every Session that has not ended,\n\
                the latest Session that ended, and the latest three that ended abandoned\n\
                (ended abandoned); the other Sessions are only counted on the Sessions line, which\n\
                also counts the Sessions that declared the Pack they resumed from. A Session line of\n\
                such a Session ends continues from the Pack at ledger sequence N (self-reported,\n\
                digest sha256:<first 12 digits of its pack_digest>).\n\
                --pack --query <TEXT> prints a query Pack (U3, U4): the\n\
                Task line, the integrity, Session, and action lines as --pack prints them, a\n\
                Query line after the Ontology line with the query in 「」, how many claims it matched,\n\
                and their numbers best first, then only those claims, superseded and withdrawn\n\
                ones too, best first, each followed by the claims that supersede it, and the\n\
                active next action when anything matched; no Rerun or Superseded and withdrawn line. The\n\
                claims are ranked by an SQLite FTS5 index built in memory for this command and\n\
                dropped (tokenizer trigram, ranking bm25, ties by number): the query is split at\n\
                spaces, and a word of three or more characters matches where it appears in a\n\
                claim's text or rationale, case folded; a Latin or digit word of one or two\n\
                characters matches only as a whole word (ID does not match valid), a word that\n\
                is a kind's label (fact, open_item, decision, next_action) also\n\
                matches the claims of that kind, the claims every word matches come before\n\
                those only some match, and within that the active claims before the\n\
                superseded and withdrawn ones.\n\
                With no match the Pack has no claim line. The same levels cut it to --budget,\n\
                the superseded and withdrawn claims first. The query is not persisted or sent;\n\
                one of more than 256 characters, with a control character, or with a string in\n\
                the format of a memprove token is a usage error (exit 2) that does not repeat\n\
                it.\n\
                Run it first when taking over a Task. It writes nothing to the ledger; after a\n\
                whole --pack (not --claims) it records the Pack's Task, capsule_digest, ledger\n\
                sequence, pack_digest, and budget next to this Workspace's context file, for\n\
                `memprove begin` to declare (a failure is a warning only).\n\
                With MEMPROVE_CLIENT_SESSION set, the context file and that record are this\n\
                client session's own, and --text labels the Session its context file names\n\
                the Session this client session's context file records instead.",
        exits: Exits::Resume,
    },
    CommandHelp {
        name: "ledger verify",
        summary: "recompute the Project's Event chain and every record digest",
        usage: &["ledger verify [--project <PROJECT_ID>] [--idempotency-key <KEY>]"],
        calls: Some("verifyLedger  POST /v1/verification/ledger  (control or mcp-read)"),
        options: &[
            (
                "--project <PROJECT_ID>",
                "the Project (lowercase UUIDv7); by default the Project of the current context, \
                 so inside a Workspace with a context it is not needed; an explicit --project wins; \
                 with neither it is a usage error",
            ),
            (
                "--idempotency-key <KEY>",
                "required by the contract but not recorded; a random one is used when omitted",
            ),
        ],
        notes: "Prints how many records it checked, the chain-head digest, and the first record\n\
                that does not hold. It writes nothing. Exit 5, not 1, means the check ran and a\n\
                record does not hold; the report is on standard output.\n\
                Any read that answers 409 capsule_tampered (retryable false) needs a stored record\n\
                that is missing, does not decode, or does not recompute, or the Project's state\n\
                database is not bound to it: a retry does not help; run `memprove ledger verify`\n\
                to see which record. Only 503 service_not_ready is worth a retry.",
        exits: Exits::LedgerVerify,
    },
    CommandHelp {
        name: "begin",
        summary: "start a Session here and record the current context",
        usage: &[
            "begin [--project <PROJECT_ID>] [--task <TASK_ID> | --new-task <TITLE> [--description <TEXT>]]",
            "      [--agent <AGENT_ID>]",
            "      [--agent-name <NAME> --agent-role <ROLE> [--parent-session <SESSION_ID>]]",
        ],
        calls: Some("resolveWorkspace, then createTask (--new-task), then createSession"),
        options: &[
            (
                "--project <PROJECT_ID>",
                "needed the first time in a Workspace that `memprove init` did not register; later the context's",
            ),
            ("--task <TASK_ID>", "continue this Task"),
            (
                "--new-task <TITLE>",
                "create a Task with this title and continue it",
            ),
            (
                "--description <TEXT>",
                "the new Task's description; needs --new-task",
            ),
            (
                "--agent <AGENT_ID>",
                "default: the context's agent, else a new identity",
            ),
            AGENT_NAME,
            AGENT_ROLE,
            PARENT_SESSION,
        ],
        notes: "Resolves the Workspace containing the current directory, moves a proposed or ready\n\
                Task to in_progress, and records the Project, Workspace, agent, Task, and Session as\n\
                the context of that Workspace. It refuses (exit 1) while the context's Session is\n\
                still active (end it with `memprove end`) and for a completed or cancelled Task\n\
                (use --new-task). When `memprove resume --pack` last printed a whole Pack of the\n\
                same Task here, the Session declares it as resumed_from (the daemon records\n\
                capsule.recovered) and the record is removed; a record of another Task is left,\n\
                and one that cannot be read is not declared, with a warning.\n\
                With MEMPROVE_CLIENT_SESSION set, the context is this client session's own\n\
                file; when it has none yet, begin continues the Task of the last Pack this\n\
                client session was given (by `memprove hook session-start` or `resume --pack`),\n\
                in the Project that record names. A client session with neither a context of its\n\
                own nor such a record does not fall back to this directory's context, its Project\n\
                or its Task: begin then needs --project and --task (or --new-task).\n\
                --agent-name, --agent-role, and --parent-session each default to\n\
                $MEMPROVE_AGENT_NAME, $MEMPROVE_AGENT_ROLE, and $MEMPROVE_PARENT_SESSION\n\
                (an empty one is unset). The agent is declared whole: only when none of the\n\
                three is given does begin reuse the agent the context file recorded at the last\n\
                begin, all of it; the context file and `context show` record the agent declared.",
        exits: Exits::Begin,
    },
    CommandHelp {
        name: "end",
        summary: "end the current Session and clear it from the context",
        usage: &["end [--reason <TEXT>] [--revision <N>] [--abandoned]"],
        calls: Some("endSession of the context's Session  (control or mcp-write)"),
        options: &[
            (
                "--reason <TEXT>",
                "why it ended; recorded in the session.ended Event",
            ),
            (
                "--revision <N>",
                "the revision last read; the context's when omitted",
            ),
            (
                "--abandoned",
                "end it as abandoned: recorded as session.crashed instead of session.ended",
            ),
        ],
        notes: "`end` ends the Session of the current context only. Taking over a Session another\n\
                agent left unfinished (U10): read the Pack (`memprove resume --pack`), end that\n\
                Session with the command its Session line ends with,\n\
                `memprove session end <SESSION_ID> --abandoned --reason <why>`, then `memprove\n\
                begin`; `end --abandoned` ends it when the current context names it. `resume` then\n\
                shows that Session as ended abandoned. Use --abandoned only for a\n\
                Session someone else left; end your own Session with a plain `end`.\n\
                The end names who ended it (U9): the Session this client's context names, when it\n\
                is not the one ended, and the agent this client declares ($MEMPROVE_AGENT_NAME and\n\
                $MEMPROVE_AGENT_ROLE, else the context's); its line in the Pack then ends with\n\
                ; ended by Session <j> (or ; ended by unlisted Session <id>, or ; ended by agent「<name>」(<role>)).",
        exits: Exits::Call,
    },
    CommandHelp {
        name: "context show",
        summary: "print the current context of this Workspace",
        usage: &["context show"],
        calls: None,
        options: &[],
        notes: "Reads only the local context file: no daemon call and no token. The Task state it\n\
                shows is the one this CLI last saw, not a fresh read.",
        exits: Exits::Local,
    },
];

/// P4-E: the `hook` commands (ADR 0014 E4), in the order of the general
/// usage. They take no global option: the hook never takes a token or a
/// data directory on its command line.
pub const HOOK_COMMANDS: &[CommandHelp] = &[
    CommandHelp {
        name: "hook session-start",
        summary: "the session-start hook of Claude Code, Codex, and Cursor: print the Context Pack of this directory's Task",
        usage: &["hook session-start [--client cursor] [--config-dir <DIR>]"],
        calls: Some(
            "getTaskCapsule, and listTasks unless this client session's context names the Task  \
             (control or mcp-read); read requests only",
        ),
        options: &[
            (
                "--client cursor",
                "read Cursor's sessionStart JSON (session_id, else conversation_id; the first of workspace_roots, else $CURSOR_PROJECT_DIR, else the current directory; source startup) and print the same text as {\"additional_context\": <text>}; `memprove init --client cursor` writes it into .cursor/hooks.json",
            ),
            (
                "--config-dir <DIR>",
                "the configuration directory; wins over $MEMPROVE_CONFIG_DIR (`memprove hook install` writes it into the hook's args)",
            ),
        ],
        notes: "Configured as a command hook (see `memprove hook print-config`; `memprove init`\n\
                also writes it into Codex's .codex/hooks.json, as a shell command, and with\n\
                --client cursor into .cursor/hooks.json). Reads the SessionStart JSON on\n\
                standard input (session_id, cwd, source; Codex sends the same members) as\n\
                untrusted input; without --client cursor, an input that names cursor_version\n\
                (Cursor running the hooks of .claude/settings.local.json) gets no output, so\n\
                that Cursor's own handler answers it once.\n\
                It chooses the Task from this client session's context, else this directory's\n\
                context, else the only Task in progress in this Workspace, and prints one\n\
                statement and the Context Pack (budget 9000) in a ```text fence; otherwise one\n\
                statement alone. A completed or cancelled Task gets no Pack: when this client\n\
                session's context names it, one statement names the Task and its state; when this\n\
                directory's context names it, the only Task in progress in this Workspace is\n\
                chosen instead, and the statement names the finished Task and its state. Its\n\
                whole output is at most 10,000 UTF-16 code units and, without --client cursor,\n\
                never starts with {. It\n\
                never writes the ledger. It appends\n\
                export MEMPROVE_CLIENT_SESSION='<session_id>' to $CLAUDE_ENV_FILE once (only a\n\
                session_id of 1 to 128 characters of A-Z, a-z, 0-9, _, and -), and records the\n\
                injected Pack, with its Project, for that client session's `memprove begin`;\n\
                a client session it exported with no record yet is first recorded with no Pack\n\
                (and the Project), for `memprove mcp serve`.\n\
                The token comes from $MEMPROVE_TOKEN, else the file named by\n\
                $MEMPROVE_TOKEN_FILE, else <configuration directory>/token (mode 0600); the data\n\
                directory from $MEMPROVE_DATA_DIR, else the one line of <configuration\n\
                directory>/data-dir. Never on its command line, and it never prints a token.\n\
                It gives up after 8 seconds with a statement. Given a global option (--data-dir,\n\
                --socket, --token-file), a --config-dir with no directory or an empty one, or\n\
                any other argument (--config-dir=<DIR> in one argument included: write it as two), it\n\
                prints one statement that says which, and exits 0.",
        exits: Exits::Hook,
    },
    CommandHelp {
        name: "hook print-config",
        summary: "print the settings fragment that configures the SessionStart hook",
        usage: &["hook print-config"],
        calls: None,
        options: &[],
        notes: "Prints JSON for .claude/settings.local.json: one SessionStart command handler in\n\
                exec form, this executable's absolute path with the arguments hook session-start,\n\
                timeout 10 seconds, no matcher (every source). The arguments end with --config-dir\n\
                <this command's configuration directory>, as `hook install` and `mcp print-config`\n\
                give them, and the fragment also holds env.MEMPROVE_CONFIG_DIR (that directory),\n\
                the entry `hook install` writes beside the handler: into a new settings file\n\
                `install` writes exactly this text. With no configuration directory to name it\n\
                fails (exit 1). Standard error says where it goes. It writes nothing.",
        exits: Exits::HookConfig,
    },
    CommandHelp {
        name: "hook install",
        summary: "add the SessionStart hook to <Workspace root>/.claude/settings.local.json",
        usage: &["hook install [--allow-tools]"],
        calls: None,
        options: &[(
            "--allow-tools",
            "also add mcp__memprove, Bash(memprove run:*), and Bash(<this executable's absolute path> run:*) to permissions.allow",
        )],
        notes: "Writes only <Workspace root>/.claude/settings.local.json and <Workspace\n\
                root>/.mcp.json (the Workspace root of the current directory), as `memprove mcp\n\
                print-config` prints their parts (U7 P2: both entries pass this command's\n\
                configuration directory as --config-dir, which wins over the environment, and a\n\
                handler or server an earlier install wrote without it is rewritten). Into the\n\
                settings file: the handler print-config\n\
                prints, once, and env.MEMPROVE_CONFIG_DIR (this command's configuration\n\
                directory); with --allow-tools also the rules of permissions.allow that are not\n\
                there yet, without it it only names them; an mcpServers.memprove that an earlier\n\
                install wrote there is taken out (Claude Code does not read mcpServers from a\n\
                settings file). Into .mcp.json: mcpServers.memprove with the same env. In each\n\
                file it keeps every other value, the spelling of numbers, and the order of members,\n\
                but not the file's bytes: it rewrites the file indented by two spaces. Run again, it\n\
                changes nothing. The handler, env.CONTINUITY_CONFIG_DIR and mcpServers.continuity that\n\
                an installation under the previous name continuity wrote are replaced, not kept beside\n\
                the new ones; with --allow-tools so are its rules mcp__continuity, Bash(continuity\n\
                run:*) and Bash(<its path> run:*). A file that is not valid JSON, or whose hooks are not shaped as settings,\n\
                is refused (exit 1), and neither file is changed. Run it only when the project's\n\
                owner asks for it.",
        exits: Exits::HookConfig,
    },
    CommandHelp {
        name: "hook uninstall",
        summary: "remove the SessionStart hook from <Workspace root>/.claude/settings.local.json",
        usage: &["hook uninstall"],
        calls: None,
        options: &[],
        notes: "Removes only the handler install wrote (a command memprove with the arguments\n\
                hook session-start, with or without --config-dir <DIR>), env.MEMPROVE_CONFIG_DIR, and an mcpServers.memprove that\n\
                runs memprove mcp serve, from the settings file and from <Workspace\n\
                root>/.mcp.json (and the handler, env.CONTINUITY_CONFIG_DIR and mcpServers.continuity\n\
                of the previous name continuity), and a group, list, or object that only they filled; a file that\n\
                only they filled is left holding {}, and a file that does not exist is not made;\n\
                permissions.allow stays as it is; in each file every other value stays, but not the\n\
                file's bytes: it rewrites the file as install does. A file that is not valid JSON is refused\n\
                (exit 1), and neither file is changed.",
        exits: Exits::HookConfig,
    },
];

/// P4-G: the `mcp` commands (ADR 0014 E7), in the order of the general
/// usage. They take no global option: the server reads its token and data
/// directory from its environment.
pub const MCP_COMMANDS: &[CommandHelp] = &[
    CommandHelp {
        name: "mcp serve",
        summary: "serve the Model Context Protocol on standard input and output (Claude Code)",
        usage: &["mcp serve [--config-dir <DIR>]"],
        calls: Some(
            "per tool: for the read tools getTaskCapsule, listTasks, verifyLedger (mcp-read); for \
         the write tools their writes (mcp-write) and the reads listSessions, listTasks, \
         getTaskCapsule (mcp-read); never a control-only operation",
        ),
        options: &[(
            "--config-dir <DIR>",
            "the configuration directory; wins over $MEMPROVE_CONFIG_DIR (`memprove hook install` writes it into the entry's args)",
        )],
        notes: "Reads one JSON-RPC 2.0 message per line of standard input and writes each answer as\n\
            one line of standard output; nothing else goes to standard output. Standard error\n\
            carries one log line per message, never a token or an argument value. Both protocol\n\
            eras are served, decided per request: 2026-07-28 (server/discover, the protocol\n\
            version in each request's _meta) and the initialize handshake of 2025-11-25 and\n\
            2025-06-18. Ten tools are listed: pack, claims, context, tasks, ledger_verify\n\
            (read, mcp-read) and begin, checkpoint, decide, end, complete (write,\n\
            mcp-write). No tool runs a command; tests are recorded with `memprove run` in a\n\
            shell. The pack tool's\n\
            default budget is 6000 UTF-16 code units. Every tool call reads the token\n\
            ($MEMPROVE_TOKEN, else the file named by $MEMPROVE_TOKEN_FILE, else\n\
            <configuration directory>/token), the data directory ($MEMPROVE_DATA_DIR, else the\n\
            one line of <configuration directory>/data-dir), and the context files anew; the\n\
            client session is $MEMPROVE_CLIENT_SESSION, else $CLAUDE_CODE_SESSION_ID (which\n\
            Claude Code sets) once that client session has a context or last-Pack file, which\n\
            the SessionStart hook writes, else none; the Workspace is $CLAUDE_PROJECT_DIR's,\n\
            else the working directory's. Its only option is --config-dir <DIR>, the\n\
            configuration directory, which wins over $MEMPROVE_CONFIG_DIR; never a token on\n\
            its command line. `--config-dir <DIR>` goes right after `mcp serve`, as two\n\
            arguments: with a global option, no directory, an empty one, the `--config-dir=<DIR>`\n\
            spelling, or another argument, the usage error (exit 2) says which. `memprove mcp print-config` prints the client's entry.",
        exits: Exits::McpServe,
    },
    CommandHelp {
        name: "mcp print-config",
        summary: "print the .claude/settings.local.json and .mcp.json parts that enable memprove (Claude Code)",
        usage: &["mcp print-config"],
        calls: None,
        options: &[],
        notes: "Prints two parts, each one JSON value under a line ==> <file> <== that names the\n\
                file of the Workspace root it belongs in, apart by one empty line. The part of\n\
                .claude/settings.local.json: the SessionStart hook (as hook print-config prints\n\
                it, with --config-dir <this command's configuration directory> after hook\n\
                session-start), env.MEMPROVE_CONFIG_DIR set to that directory, and\n\
                the suggested permissions.allow (mcp__memprove, Bash(memprove run:*), and\n\
                Bash(<this executable's absolute path> run:*), for an agent that runs it by its\n\
                path when memprove is not on PATH). The\n\
                part of .mcp.json, the file Claude Code reads the project's MCP servers from (it\n\
                does not read mcpServers from a settings file): one stdio server named memprove\n\
                in mcpServers whose command is this executable's absolute path, with the arguments\n\
                mcp serve --config-dir <the same directory> (exec form, no shell) and the same env;\n\
                that entry belongs in <Workspace\n\
                root>/.mcp.json (project scope) or ~/.claude.json (local or user scope). No timeout\n\
                for the server, no data directory, and never a token: the hook and the server find\n\
                the data directory and the token through the configuration directory. Standard\n\
                error says where each part goes, gives the same entry as a claude mcp add command\n\
                line, and names the configuration directory. It writes nothing and adds the entry\n\
                nowhere; `memprove hook install` writes both parts (permissions.allow only with\n\
                --allow-tools).",
        exits: Exits::McpConfig,
    },
];

/// U1 (E4, ADR 0015): the install and maintenance commands, in the order
/// of the general usage. They call no daemon operation and take no token.
pub const MAINTENANCE_COMMANDS: &[CommandHelp] = &[
    CommandHelp {
        name: "init",
        summary: "enable memprove in this repository: register the Project, write the clients' configuration, run doctor",
        usage: &[
            "init [--client <claude-code|codex|cursor>]... [--operator-token <FILE>] [--allow-tools] [--dry-run]",
        ],
        calls: Some(
            "registerProject (control), with the operator's token; then the read-only calls of \
             `memprove doctor`",
        ),
        options: &[
            (
                "--client <NAME>",
                "a client to write for, repeatable: claude-code, codex, or cursor; without it the clients are detected (Claude Code from ~/.claude or claude on PATH, Codex from ~/.codex or codex on PATH, Cursor from ~/.cursor, cursor on PATH, or /Applications/Cursor.app)",
            ),
            (
                "--operator-token <FILE>",
                "the operator's control token file; default: <prefix>/operator-token of the installation whose configuration directory is in use (the file scripts/install.sh writes beside its config/)",
            ),
            (
                "--allow-tools",
                "also write mcp__memprove, Bash(memprove run:*), and Bash(<this executable's absolute path> run:*) into permissions.allow of .claude/settings.local.json; without it they are only printed",
            ),
            (
                "--dry-run",
                "print what would be registered and written; register nothing, write nothing",
            ),
        ],
        notes: "The second of the two steps that put memprove to work (the first is\n\
                scripts/install.sh). In the Git worktree of the current directory it: registers\n\
                the Project (registerProject with the operator's token; a repository already\n\
                registered gets its Project back); adds .claude/settings.local.json and .mcp.json\n\
                (and Codex's .codex/hooks.json; Cursor's .cursor/mcp.json,\n\
                .cursor/rules/memprove.mdc and .cursor/hooks.json) to\n\
                .git/info/exclude, so that they never become untracked files that keep a run's\n\
                Evidence from being verified; for Claude Code runs `hook install` (the\n\
                SessionStart hook and env.MEMPROVE_CONFIG_DIR in .claude/settings.local.json,\n\
                mcpServers.memprove in .mcp.json; with --allow-tools also the permissions.allow\n\
                rules, which it otherwise only prints); for Codex\n\
                writes [mcp_servers.memprove] into ~/.codex/config.toml ($CODEX_HOME/config.toml\n\
                when CODEX_HOME is set, as Codex reads it) and a note of under\n\
                five lines into AGENTS.md (between <!-- memprove:begin --> and\n\
                <!-- memprove:end -->, replaced on a second run) telling the agent to read the\n\
                Context Pack through the MCP tool pack first, and the SessionStart hook into\n\
                .codex/hooks.json (Codex runs it once you trust the project and approve the hook\n\
                in /hooks; init trusts nothing for you); for Cursor writes mcpServers.memprove\n\
                into .cursor/mcp.json, the sessionStart hook (hook session-start --client\n\
                cursor) into .cursor/hooks.json, and the same note as an always-applied rule in\n\
                .cursor/rules/memprove.mdc; then runs doctor and prints its report. Every\n\
                file it edits keeps its other content; run again, it changes nothing. What init\n\
                wrote under the previous name continuity is replaced: the AGENTS.md note between\n\
                <!-- continuity:begin --> and <!-- continuity:end -->, the Codex table\n\
                [mcp_servers.continuity] of a program named continuity, and the entries of\n\
                .claude/settings.local.json and .mcp.json; .cursor/rules/continuity.mdc is\n\
                removed when it holds exactly the rule init wrote. The agent's\n\
                token is the one scripts/install.sh wrote into <configuration directory>/token,\n\
                which begin, the hook, and the MCP server read; neither token is printed. The\n\
                configuration directory is $MEMPROVE_CONFIG_DIR, else ~/.memprove/config when\n\
                it exists (the default installation), else $XDG_CONFIG_HOME/memprove, else\n\
                ~/.config/memprove. The daemon location and the token come from that directory\n\
                too: --data-dir, --socket, and --token-file do not apply to init.",
        exits: Exits::Init,
    },
    CommandHelp {
        name: "doctor",
        summary: "check the setup, read-only: one PASS, WARN, or FAIL line per check",
        usage: &["doctor [--json]"],
        calls: Some(
            "healthLive, healthReady (no token); getVersion, getProject, getStatus, verifyLedger, \
             and resolveWorkspace with an empty body, which the daemon refuses before it reads \
             anything (400 when the token may write, 403 when it may not); nothing is written",
        ),
        options: &[(
            "--json",
            "print the report as one JSON document instead of lines",
        )],
        notes: "Checks, in order: data-dir (exists, mode 0700 or stricter); projects-dir\n\
                (<data-dir>/projects and each Project directory in it, and <data-dir>/tmp when it\n\
                exists, mode 0700 or stricter);\n\
                socket (<data-dir>/memproved.sock or --socket, mode 0600); daemon (answers healthLive\n\
                and healthReady); token-file (the token source the other commands use, a file of\n\
                mode 0600 holding one token); token (the daemon accepts it and it reaches the\n\
                mcp-read and mcp-write operations; WARN for a control token); build (memprove\n\
                and memproved report the same version and build, see `memprove --version`);\n\
                config-dir (the configuration directory is outside every Git worktree); path (the\n\
                directory of this executable is on PATH, so `memprove run` and the rule\n\
                Bash(memprove run:*) find it; WARN with the export PATH=... line otherwise);\n\
                workspace\n\
                (inside a Git worktree: its context and whether the daemon has that Project;\n\
                outside one it passes and the last three checks are left out); hook (a SessionStart\n\
                handler in .claude/settings.json or .claude/settings.local.json runs\n\
                `<path> hook session-start`, and <path> exists; its --config-dir argument, else\n\
                their env.MEMPROVE_CONFIG_DIR, is the configuration directory doctor uses: WARN\n\
                when neither is there, FAIL when another); mcp-entry (mcpServers.memprove of\n\
                <Workspace root>/.mcp.json, the file Claude Code reads it from, with the same\n\
                --config-dir argument, else env.MEMPROVE_CONFIG_DIR: WARN when there is no entry\n\
                or it has neither, FAIL when another; one in .claude/settings.local.json or\n\
                .claude/settings.json counts for nothing (Claude Code does not read it), and the\n\
                line says so); ledger (verifyLedger of the\n\
                context's Project: counts and chain head, or the first record that does not\n\
                hold). A check that cannot be made (no daemon, no token) is a WARN that says why.\n\
                Each line is `<STATUS> <check>: <detail>`, and the last line counts them; --json\n\
                gives {\"schema_version\":1,\"cli\":...,\"checks\":[{\"check\",\"status\",\"detail\"}...],\n\
                \"pass\":N,\"warn\":N,\"fail\":N}. No output holds a token's text.",
        exits: Exits::Doctor,
    },
    CommandHelp {
        name: "import",
        summary: "list the statements of CLAUDE.md, AGENTS.md, Cursor's rules, and Claude Code's auto-memory; with --select, record them as open items, each marked imported and not verified",
        usage: &[
            "import [--file <PATH>]... [--select <NUMBERS | all> [--next <TEXT>] [--dry-run]]",
        ],
        calls: Some(
            "none without --select; with it getTaskCapsule, then createCheckpoint as \
             `checkpoint create --open ... --next ...` of the current context",
        ),
        options: &[
            (
                "--file <PATH>",
                "a file to read, repeatable; without it: CLAUDE.md, CLAUDE.local.md, .claude/CLAUDE.md, AGENTS.md, GEMINI.md, .github/copilot-instructions.md, .cursorrules, and .cursor/rules/*.mdc and *.md of the Workspace root (not memprove's own rule), then Claude Code's auto-memory of this repository ($CLAUDE_CONFIG_DIR or ~/.claude, projects/<root with every character other than A-Z, a-z, 0-9 as ->/memory/*.md)",
            ),
            (
                "--select <NUMBERS | all>",
                "the statements to record, by the numbers the listing gives them with the same --file options: `all`, or numbers and ranges such as 1,3,5-7",
            ),
            (
                "--next <TEXT>",
                "the next action the Checkpoint records; default: the next action in force",
            ),
            (
                "--dry-run",
                "print the open items that would be recorded (after reading the Task Capsule); send nothing",
            ),
        ],
        notes: "A statement is one list item (with its continuation lines) or one paragraph;\n\
                front matter, headings, fenced code, HTML comments and tags, tables, rules,\n\
                Claude Code's @path imports, and memprove's own note in AGENTS.md are passed\n\
                over, and so is a statement seen earlier in the same listing. Without --select\n\
                nothing is sent: each statement is listed as `<N>  <source>:<line>  <text>`. With\n\
                it, each selected statement becomes the open item `<text> (imported from\n\
                <source>:<line>; not verified)` of one Checkpoint of the current Session (so\n\
                `memprove begin` and a `memprove run` come first, as for `checkpoint create`); a\n\
                statement that is in force already as an imported open item, from any line, is\n\
                left out, so a second import records nothing twice. A statement in the format of\n\
                a memprove token, or longer than a statement may be, is named and not imported.\n\
                Imported open items are not facts: none is verified until a test run supports it.",
        exits: Exits::Claims,
    },
    CommandHelp {
        name: "backup",
        summary: "copy the data directory while the daemon is stopped, with SHA256SUMS",
        usage: &["backup [--data-dir <PATH>] --out <DIR>"],
        calls: None,
        options: &[
            (
                "--data-dir <PATH>",
                "the data directory to copy (default: $MEMPROVE_DATA_DIR)",
            ),
            (
                "--out <DIR>",
                "a new or empty directory outside the data directory; created with mode 0700",
            ),
        ],
        notes: "Offline: it takes the daemon's instance lock for as long as it reads, and refuses\n\
                (exit 1, nothing written) while a daemon holds it; stop the daemon first. It\n\
                copies every file and directory of the data directory (registry.sqlite, each\n\
                Project's projects/<PROJECT_ID>/state.sqlite, and anything else there) with its\n\
                mode, except memproved.sock, memproved.lock, and tmp/. It writes\n\
                continuity-backup.txt (the mode of each entry, the source, the time, this build)\n\
                and SHA256SUMS, one `<sha256>  <path>` line per other file, which\n\
                `shasum -a 256 -c SHA256SUMS` checks. Standard output gives the counts.",
        exits: Exits::Offline,
    },
    CommandHelp {
        name: "restore",
        summary: "check a backup's SHA256SUMS, then restore it into a new or empty data directory",
        usage: &["restore --from <DIR> --data-dir <PATH>"],
        calls: None,
        options: &[
            ("--from <DIR>", "a directory `memprove backup` wrote"),
            (
                "--data-dir <PATH>",
                "the data directory to restore into: new or empty, given explicitly",
            ),
        ],
        notes: "Offline. It first checks every file of the backup against SHA256SUMS and\n\
                continuity-backup.txt (a changed, missing, or unlisted file refuses the restore,\n\
                exit 1, nothing written), then refuses a target that is not empty (a daemon\n\
                running there included), then takes the target's instance lock and holds it until\n\
                it ends (a daemon that holds it refuses the restore), then copies each entry and\n\
                gives it the mode the backup recorded, the data directory's own included. A\n\
                failure part way removes only what it wrote. Start memproved on the restored directory afterwards and run\n\
                `memprove ledger verify` for each Project.",
        exits: Exits::Offline,
    },
];

/// The help entries a `--help` request names: the command itself, or, for a
/// group such as `token`, every command in the group. `words` are the
/// positional arguments seen; extra words after the command are ignored.
/// Empty when `words` name no command.
#[must_use]
pub fn lookup(words: &[&str]) -> Vec<&'static CommandHelp> {
    let every = || {
        COMMANDS
            .iter()
            .chain(HOOK_COMMANDS)
            .chain(MCP_COMMANDS)
            .chain(MAINTENANCE_COMMANDS)
    };
    if let [first, second, ..] = words {
        let name = format!("{first} {second}");
        if let Some(entry) = every().find(|entry| entry.name == name) {
            return vec![entry];
        }
    }
    let Some(first) = words.first() else {
        return Vec::new();
    };
    every()
        .filter(|entry| entry.name.split(' ').next() == Some(*first))
        .collect()
}

/// The text printed for `entries`, one command after another.
#[must_use]
pub fn render(entries: &[&CommandHelp]) -> String {
    let mut out = String::new();
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        render_one(entry, &mut out);
    }
    out
}

/// What every usage line starts with; a continuation line lines up after it.
const COMMAND_LINE: &str = "  memprove [GLOBAL OPTIONS] ";

fn render_one(entry: &CommandHelp, out: &mut String) {
    let w = |out: &mut String, line: &str| {
        writeln!(out, "{line}").expect("writing to a String cannot fail");
    };
    w(out, &format!("memprove {}: {}", entry.name, entry.summary));
    w(out, "");
    w(out, "Usage:");
    for (index, line) in entry.usage.iter().enumerate() {
        if index == 0 {
            w(out, &format!("{COMMAND_LINE}{line}"));
        } else {
            // A continuation line lines up under the command's own words.
            let indent = " ".repeat(COMMAND_LINE.len());
            w(out, &format!("{indent}{}", line.trim_start()));
        }
    }
    if let Some(calls) = entry.calls {
        w(out, "");
        w(out, &format!("Calls: {calls}"));
    }
    if !entry.options.is_empty() {
        w(out, "");
        w(out, "Arguments and options:");
        let width = entry
            .options
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(0);
        for (name, description) in entry.options {
            w(out, &format!("  {name:<width$}  {description}"));
        }
    }
    if !entry.notes.is_empty() {
        w(out, "");
        for line in entry.notes.lines() {
            w(out, line);
        }
    }
    if !matches!(
        entry.exits,
        Exits::Local
            | Exits::Hook
            | Exits::HookConfig
            | Exits::McpServe
            | Exits::McpConfig
            | Exits::Offline
    ) {
        w(out, "");
        w(out, "Global options:");
        w(
            out,
            "  --data-dir <PATH>    Daemon data directory (default: $MEMPROVE_DATA_DIR, else the",
        );
        w(
            out,
            "                       one line of <configuration directory>/data-dir)",
        );
        w(
            out,
            "  --socket <PATH>      Socket path, overriding <data-dir>/memproved.sock",
        );
        w(
            out,
            "  --token-file <PATH>  File holding the bearer token (mode 0600); else $MEMPROVE_TOKEN,",
        );
        w(
            out,
            "                       else the file named by $MEMPROVE_TOKEN_FILE, else",
        );
        w(
            out,
            "                       <configuration directory>/token; never a command-line token",
        );
    }
    w(out, "");
    w(out, "Exit status:");
    for (code, meaning) in exit_lines(entry.exits) {
        w(out, &format!("  {code:<4} {meaning}"));
    }
}

/// U7 K7 (U6 K1): what exit 1 also covers for a command that needs a token:
/// none of the sources (`--token-file`, `MEMPROVE_TOKEN`,
/// `MEMPROVE_TOKEN_FILE`, `<configuration directory>/token`) gave one. The
/// request is not sent; `run` exits 125 then, as it does not run its command.
macro_rules! no_token {
    () => {
        "a command that needs a token found none (standard error names the places looked at; nothing was sent)"
    };
}

/// The meaning of exit 2 of a command that sends a token: only a token that
/// cannot be put in a request header is exit 2; a missing token is exit 1
/// (U6 K1).
macro_rules! usage_exit {
    () => {
        "usage error, or a token that cannot be sent because it contains a line break; nothing was sent"
    };
}

/// What exit 1 covers for the commands that make one daemon call: a Problem
/// response, or no token.
macro_rules! call_exit {
    () => {
        concat!(
            "the daemon answered with a Problem (its code and detail, when it has one, are on standard error), or ",
            no_token!()
        )
    };
}

/// P3-C2 (T12 S-5): a response over the CLI's limit is not a contract
/// violation.
const TOO_LARGE: (&str, &str) = (
    "6",
    "the response is larger than the CLI accepts (16 MiB for getTaskCapsule, 1 MiB for any other operation); standard error names the limit, and nothing of the response was used",
);

/// The exit lines of a command that calls the daemon: they differ in what 1
/// covers, in `resume`'s 2 and 4, and in `ledger verify`'s 5.
fn daemon_exit_lines(
    one: &'static str,
    two: &'static str,
    four: &'static str,
    five: Option<&'static str>,
) -> Vec<(&'static str, &'static str)> {
    let mut lines = vec![
        ("0", "success"),
        ("1", one),
        ("2", two),
        ("3", "the daemon is unreachable"),
        ("4", four),
    ];
    if let Some(five) = five {
        lines.push(("5", five));
    }
    lines.push(TOO_LARGE);
    lines
}

fn exit_lines(exits: Exits) -> Vec<(&'static str, &'static str)> {
    let contract = "the response violates the contract";
    match exits {
        Exits::Call => daemon_exit_lines(call_exit!(), usage_exit!(), contract, None),
        Exits::LedgerVerify => daemon_exit_lines(
            call_exit!(),
            usage_exit!(),
            contract,
            Some(
                "the ledger was checked and a record does not hold (see first_failure in the report)",
            ),
        ),
        Exits::Claims => daemon_exit_lines(
            concat!(
                "a Problem response, ",
                no_token!(),
                ", or a claim number or --reaffirm that cannot be resolved (the Task Capsule is tampered, does not list the number, or names no active fact); nothing was sent then"
            ),
            usage_exit!(),
            contract,
            None,
        ),
        Exits::Begin => daemon_exit_lines(
            concat!(
                "a Problem response, ",
                no_token!(),
                ", or a refusal (the context's Session is still active; the Task is completed or cancelled)"
            ),
            usage_exit!(),
            contract,
            None,
        ),
        Exits::Resume => daemon_exit_lines(
            concat!(
                "a Problem response, ",
                no_token!(),
                ", or --pack: the Pack does not fit the budget even at level 5 (standard error says the length it needs; nothing is printed)"
            ),
            concat!(
                usage_exit!(),
                ". Also --claims naming a number the Task Capsule does not list"
            ),
            "the response violates the contract, or --pack: the Capsule holds a string the Pack cannot show",
            None,
        ),
        Exits::Run => vec![
            ("0", "the command exited 0 and its result was recorded"),
            (
                "N",
                "any other exit code of the command (128 + N for signal N): it ran and its result was recorded",
            ),
            (
                "125",
                "the command could not be started (recorded as UNAVAILABLE), its result could not be recorded, or no token was found (standard error names the places looked at; nothing ran); standard error says which",
            ),
            (
                "2",
                "usage error, or an ID that is neither given nor in the context; nothing ran",
            ),
        ],
        Exits::Local => vec![
            ("0", "success"),
            ("2", "usage error, or no context for this directory"),
        ],
        Exits::Offline => offline_exit_lines(),
        Exits::Hook | Exits::HookConfig => hook_exit_lines(exits),
        Exits::McpServe | Exits::McpConfig => mcp_exit_lines(exits),
        Exits::Doctor => doctor_exit_lines(),
        Exits::Init => init_exit_lines(),
    }
}

/// The exit codes of `init` (U17, M1 O4).
fn init_exit_lines() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "0",
            "every step was done (or, with --dry-run, described) and doctor reported no FAIL",
        ),
        (
            "1",
            "a step failed (the current directory is not a Git worktree, no configuration \
             directory or operator token, memproved refused or is unreachable, a file could \
             not be written) or doctor reported a FAIL; the steps before the failure stay done",
        ),
        ("2", "usage error; nothing was done"),
    ]
}

/// The exit codes of `doctor` (U1, E3).
fn doctor_exit_lines() -> Vec<(&'static str, &'static str)> {
    vec![
        ("0", "every check passed or warned"),
        ("1", "at least one check failed (a FAIL line)"),
        ("2", "usage error; nothing was checked"),
    ]
}

/// U1 (E4): the exit codes of `backup` and `restore`.
fn offline_exit_lines() -> Vec<(&'static str, &'static str)> {
    vec![
        ("0", "success"),
        (
            "1",
            "refused or failed (a daemon runs, the target is not new or empty, the backup does not match SHA256SUMS, a file cannot be read or written); standard error says why",
        ),
        ("2", "usage error; nothing was read or written"),
    ]
}

/// P4-G: the exit codes of the `mcp` commands.
fn mcp_exit_lines(exits: Exits) -> Vec<(&'static str, &'static str)> {
    if exits == Exits::McpServe {
        return vec![
            (
                "0",
                "standard input ended (every message was answered, every open subscription completed), or standard output closed",
            ),
            ("2", "usage error; nothing was read"),
        ];
    }
    vec![
        ("0", "success: the fragment is on standard output"),
        (
            "1",
            "this executable or the current directory cannot be resolved; nothing is printed on standard output",
        ),
        ("2", "usage error; nothing is printed on standard output"),
    ]
}

/// P4-E: the exit codes of the `hook` commands.
fn hook_exit_lines(exits: Exits) -> Vec<(&'static str, &'static str)> {
    if exits == Exits::Hook {
        return vec![(
            "0",
            "always, whatever happened: standard output says it in one statement",
        )];
    }
    vec![
        ("0", "success"),
        (
            "1",
            "the settings file (for install and uninstall, or .mcp.json) is not valid JSON or not shaped as settings (it is left unchanged, and so is the other file), or it cannot be written",
        ),
        ("2", "usage error; nothing was written"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::USAGE;

    #[test]
    fn every_command_of_the_general_usage_has_help_under_its_own_name() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in COMMANDS {
            assert!(seen.insert(entry.name), "{} is listed twice", entry.name);
            assert!(
                USAGE.contains(&format!("\n  {}", entry.name)),
                "{} is not a command of the general usage",
                entry.name
            );
            assert!(
                entry.usage[0].starts_with(entry.name),
                "{}: the first usage line must start with the command's name",
                entry.name
            );
            let text = render(&[entry]);
            assert!(text.starts_with(&format!("memprove {}:", entry.name)));
            assert!(text.contains("\nUsage:\n"), "{}", entry.name);
            assert!(text.contains("\nExit status:\n"), "{}", entry.name);
        }
    }

    #[test]
    fn every_hook_command_has_help_and_is_in_the_general_usage() {
        for entry in HOOK_COMMANDS {
            assert!(
                USAGE.contains(&format!("\n  {}", entry.name)),
                "{}",
                entry.name
            );
            assert!(!COMMANDS.iter().any(|other| other.name == entry.name));
            let text = render(&[entry]);
            assert!(text.starts_with(&format!("memprove {}:", entry.name)));
            assert!(!text.contains("Global options:"), "{}", entry.name);
        }
        let names: Vec<&str> = lookup(&["hook"]).iter().map(|entry| entry.name).collect();
        assert_eq!(
            names,
            [
                "hook session-start",
                "hook print-config",
                "hook install",
                "hook uninstall"
            ]
        );
    }

    #[test]
    fn every_maintenance_command_has_help_and_is_in_the_general_usage() {
        for entry in MAINTENANCE_COMMANDS {
            assert!(
                USAGE.contains(&format!("\n  {}", entry.name)),
                "{} is missing from the general usage",
                entry.name
            );
            assert_eq!(lookup(&[entry.name]), [entry]);
            assert!(!COMMANDS.iter().any(|other| other.name == entry.name));
        }
    }

    #[test]
    fn every_mcp_command_has_help_and_is_in_the_general_usage() {
        for entry in MCP_COMMANDS {
            assert!(
                USAGE.contains(&format!("\n  {}", entry.name)),
                "{}",
                entry.name
            );
            assert!(!COMMANDS.iter().any(|other| other.name == entry.name));
            let text = render(&[entry]);
            assert!(text.starts_with(&format!("memprove {}:", entry.name)));
            assert!(!text.contains("Global options:"), "{}", entry.name);
            assert!(!text.contains(['?', '!']), "{}", entry.name);
        }
        let names: Vec<&str> = lookup(&["mcp"]).iter().map(|entry| entry.name).collect();
        assert_eq!(names, ["mcp serve", "mcp print-config"]);
    }

    #[test]
    fn lookup_takes_the_command_or_the_whole_group() {
        let names = |words: &[&str]| -> Vec<&str> {
            lookup(words).iter().map(|entry| entry.name).collect()
        };
        assert_eq!(names(&["token", "create"]), ["token create"]);
        assert_eq!(names(&["token", "revoke", "an-id"]), ["token revoke"]);
        assert_eq!(names(&["run"]), ["run"]);
        assert_eq!(names(&["end"]), ["end"]);
        assert_eq!(
            names(&["token"]),
            ["token create", "token list", "token revoke"]
        );
        assert_eq!(names(&["task", "bogus"]), names(&["task"]));
        assert!(names(&[]).is_empty());
        assert!(names(&["bogus"]).is_empty());
    }

    #[test]
    fn only_ledger_verify_documents_exit_five() {
        for entry in COMMANDS {
            let text = render(&[entry]);
            let five = text.contains("\n  5    ");
            assert_eq!(five, entry.name == "ledger verify", "{}", entry.name);
        }
    }
}
