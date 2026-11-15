//! P4-E (ADR 0014 E4, Owner conditions l to p): `memprove hook
//! session-start`, the Claude Code `SessionStart` command hook, and `hook
//! print-config`, `hook install`, `hook uninstall`, which manage its entry
//! in `<project>/.claude/settings.local.json` (U5 Z-F round 1: and the MCP
//! server's entry in `<project>/.mcp.json`).
//!
//! `session-start` reads the hook's JSON on standard input as untrusted
//! input, sends only read requests to `memproved` (`listTasks`,
//! `getTaskCapsule`), and prints one statement, followed by the Context
//! Pack in a fence when there is one to inject. It writes nothing to the
//! ledger; its only local writes are one `export` line in `CLAUDE_ENV_FILE`
//! and the last-Pack file of the client session (Owner condition i), or
//! (U2, H3) of the directory when the client session was not exported. It
//! always exits 0; `main` enforces its time limit.

use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use memprove_domain::{PACK_DEFAULT_BUDGET, PACK_HOOK_OUTPUT_LIMIT, PACK_MAX_BUDGET, PackError};
use memprove_protocol::{
    phase1::OperationId,
    strict_json::{JsonValue, parse_strict},
};

use crate::{
    CallError, Reply, Request, SOCKET_FILE_NAME, call,
    claims::is_uuid_v7,
    context::{
        CLIENT_SESSION_ENV, Context, ContextStore, LastPack, is_client_session, workspace_root,
    },
    json_string, read_token_file, resolve_token, resume,
};

/// The hook's own time limit (Owner condition o): 8 seconds since U15 T1
/// (Owner O2; U14-N1; ADR 0014 "Amendment (U15)"), 5 until then. Under
/// load the 5 ran out while the 10 seconds of the handler's `timeout`
/// ([`HANDLER_TIMEOUT_SECONDS`]) had room; 2 seconds stay for printing and
/// exiting.
pub const TIME_LIMIT: Duration = Duration::from_secs(8);
/// The most bytes of standard input the hook reads; a longer input is
/// refused.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
/// The most UTF-16 code units the hook prints (Owner condition n), 10,000.
pub const MAX_OUTPUT_UNITS: usize = PACK_HOOK_OUTPUT_LIMIT;
/// The budget of the Pack the hook prints, 9,000 as before.
pub const HOOK_PACK_BUDGET: usize = PACK_DEFAULT_BUDGET;
/// U12 T4 (Owner O5; U11-VN1; ADR 0014 "Amendment (U11, S-T)", Length): the
/// most UTF-16 code units the opening's time sentence and identity sentence
/// take together. The longest declaration the server takes (a name of 64
/// characters, `orchestrator`, a parent Session ID) gives 290 in English
/// (224 in the Chinese text before U17), which a test computes; the bound
/// of a whole response stays [`MAX_OUTPUT_UNITS`], whose path is unchanged,
/// and nothing at run time reads this one. U14 T1 (Owner O2; ADR 0014
/// "Amendment (U14)"): with [`OPEN_ITEM_SENTENCE`] after them, 290 for that
/// declaration in Chinese, so the bound was 320; U17 (M1 O3): the English
/// sentences are longer, so the bound is 480.
pub const OPENING_SENTENCES_MAX_UNITS: usize = 480;
/// U14 T1 (Owner O2; U13-F1, U13-VN1; ADR 0014 E4 condition n, "Amendment
/// (U14)"): the last sentence of the opening, the hook's and the MCP `pack`
/// tool's, after the time sentence and the identity sentence. It states the
/// last sentence of the unattended takeover rule (ADR 0021), which the rule
/// itself keeps unchanged: a Session the rule leaves open is recorded as an
/// open item of this session. U21 (Owner, 2026-11-10): the sentence names
/// who records the item and when, this session in its first checkpoint; the
/// passive form left that unsaid, and in the U20 baseline the clients of E
/// recorded the item in 1 of 4 runs.
pub const OPEN_ITEM_SENTENCE: &str = "Under the unattended takeover rule, this session records each \
                                      Session it leaves open as an open item 「another Session \
                                      (Session k) may still be working, not ended」 in its first \
                                      checkpoint.";
/// U7 P1 (Owner O3): the sentence of a `fork` opening: a forked session has
/// no context of its own, so every open Session's line carries the takeover
/// hint; one may be the parent's, which is still working.
pub const FORK_SENTENCE: &str = "This session was forked from another session; none of the Sessions \
                                 the Pack lists was started by this session, and an unended one may \
                                 belong to the parent session; while the parent session is still \
                                 running, the guidance at the end of that line does not apply to it.";
/// The `SessionStart` sources the hook accepts.
pub const SOURCES: [&str; 5] = ["startup", "resume", "clear", "compact", "fork"];
/// The settings file `install` writes, relative to the Workspace root
/// (Owner condition p).
pub const SETTINGS_FILE: &str = ".claude/settings.local.json";
/// The `timeout` of the handler `install` writes, in seconds.
pub const HANDLER_TIMEOUT_SECONDS: u64 = 10;
/// The default token file in the configuration directory, read after
/// `MEMPROVE_TOKEN` and `MEMPROVE_TOKEN_FILE` (ADR 0014 E4).
pub const TOKEN_FILE_NAME: &str = "token";
/// The file in the configuration directory naming the data directory,
/// read when `MEMPROVE_DATA_DIR` is not set (ADR 0014 E4).
pub const DATA_DIR_FILE_NAME: &str = "data-dir";
/// The most in-progress Tasks the hook looks at to find the one of this
/// Workspace.
const MAX_CANDIDATES: usize = 20;
/// The most bytes of `CLAUDE_ENV_FILE` read to avoid a repeated line.
const MAX_ENV_FILE_BYTES: u64 = 1 << 20;
/// The most bytes of a settings file `install` and `uninstall` read.
const MAX_SETTINGS_BYTES: u64 = 4 << 20;
/// The most bytes of the data-directory file.
const MAX_DATA_DIR_FILE_BYTES: u64 = 4096;
/// U2 (H2): the line on standard error when the hook replaces a damaged
/// last-Pack record of the client session it exported.
const REPLACED: &str = "memprove: warning: the last-Pack record of this client session could \
     not be read or is malformed; the record of this SessionStart replaces it";
/// The clause that ends every statement that injects nothing.
const NOT_INJECTED: &str = "no Context Pack was injected into this session";
/// U15 T1 (Owner O2): the clause after it in the time-limit statement, how
/// the client fetches the Pack itself; a statement, like the rest. Without
/// `--task`, `resume` chooses the Task as it always does here.
const SELF_FETCH: &str = "running memprove resume --pack in this session fetches it";

/// U5 P3 (D1 F5, Owner O5): the variable the enabling fragment sets in
/// `env`, for the hook and the MCP server.
pub const CONFIG_DIR_VARIABLE: &str = crate::context::CONFIG_DIR_ENV;

/// U5 P3 (Owner O5): the rules the fragment suggests for `permissions.allow`
/// (Claude Code's rule syntax): every tool of the MCP server named
/// `memprove`, and a Bash command that starts with `memprove run`.
pub const ALLOW_RULES: [&str; 2] = ["mcp__memprove", "Bash(memprove run:*)"];

/// U20 T1 (U19-O2): the product's previous name. An installation under it
/// wrote a handler whose program is named `continuity`, the variable
/// [`PREVIOUS_CONFIG_DIR_VARIABLE`] in `env`, an `mcpServers.continuity`
/// entry and, with `--allow-tools`, the rules of [`is_previous_rule`].
/// `install` replaces them with its own and `uninstall` removes them as it
/// removes its own, so that a renamed installation does not leave a handler
/// whose program no longer exists beside the new one.
pub const PREVIOUS_NAME: &str = "continuity";

/// U20 T1 (U19-O2): the variable an installation of the previous name set
/// in `env`.
pub const PREVIOUS_CONFIG_DIR_VARIABLE: &str = "CONTINUITY_CONFIG_DIR";

/// U7 P3 (D2 F11, Owner O5): the rules `--allow-tools` writes and the
/// fragment suggests: [`ALLOW_RULES`], and a Bash command that starts with
/// `executable` (this executable's canonical absolute path) and `run`, which
/// an agent types when `memprove` is not on `PATH` and which the rule
/// `Bash(memprove run:*)` does not match.
#[must_use]
pub fn allow_rules(executable: &str) -> [String; 3] {
    [
        ALLOW_RULES[0].to_owned(),
        ALLOW_RULES[1].to_owned(),
        format!("Bash({executable} run:*)"),
    ]
}

/// U5 P3 (D1 F5): the configuration directory a command of this process
/// uses, as [`ContextStore::from_env`] resolves it, made absolute against
/// `cwd`, and the variable it came from (`MEMPROVE_CONFIG_DIR`,
/// `XDG_CONFIG_HOME`, or `HOME`); `None` when all three are unset.
#[must_use]
pub fn configuration_dir(
    config_dir: Option<&OsStr>,
    xdg_config_home: Option<&OsStr>,
    home: Option<&OsStr>,
    cwd: Option<&Path>,
) -> Option<(PathBuf, &'static str)> {
    let set = |value: Option<&OsStr>| value.is_some_and(|value| !value.is_empty());
    let source = if set(config_dir) {
        CONFIG_DIR_VARIABLE
    } else if crate::context::installed_config_dir(home).is_some() {
        // U17 (M1 O4): the default installation, found by its place.
        INSTALL_SOURCE
    } else if set(xdg_config_home) {
        "XDG_CONFIG_HOME"
    } else if set(home) {
        "HOME"
    } else {
        return None;
    };
    let store = ContextStore::from_env(
        config_dir.map(OsStr::to_os_string),
        xdg_config_home.map(OsStr::to_os_string),
        home.map(OsStr::to_os_string),
    )?;
    let dir = match cwd {
        Some(cwd) if store.config_dir.is_relative() => cwd.join(&store.config_dir),
        _ => store.config_dir,
    };
    Some((dir, source))
}

/// U17 (M1 O4): the source [`configuration_dir`] names for the default
/// installation's `$HOME/.memprove/config`.
pub const INSTALL_SOURCE: &str = "HOME/.memprove/config";

/// A path as one line of a statement: as it is, unless it holds a control
/// character, which is written as `\u{..}`.
pub(crate) fn shown_path(path: &Path) -> String {
    use std::fmt::Write as _;
    let mut shown = String::new();
    for character in path.to_string_lossy().chars() {
        if character.is_control() {
            write!(shown, "\\u{{{:02x}}}", u32::from(character))
                .expect("writing to a String cannot fail");
        } else {
            shown.push(character);
        }
    }
    shown
}

/// U5 P3 (D1 F5, Owner O5): the statement when no context of this
/// Workspace root is in the configuration directory the hook used: it names
/// that directory and where it came from, so a hook that fell back to the
/// default directory says so.
fn no_context_clause(environment: &Environment, start: &Start) -> String {
    let resolved = configuration_dir(
        environment.config_dir.as_deref(),
        environment.xdg_config_home.as_deref(),
        environment.home.as_deref(),
        Some(&start.cwd),
    );
    let used = match resolved {
        // U7 P2 (Owner O4): the argument of the hook's entry.
        Some((dir, CONFIG_DIR_VARIABLE)) if environment.config_dir_argument => format!(
            "the hook's configuration directory is {} (from {})",
            shown_path(&dir),
            crate::CONFIG_DIR_OPTION
        ),
        Some((dir, CONFIG_DIR_VARIABLE)) => {
            format!(
                "the hook's configuration directory is {} (from {CONFIG_DIR_VARIABLE})",
                shown_path(&dir)
            )
        }
        Some((dir, source)) => format!(
            "the hook's configuration directory is {} (from {source}; {CONFIG_DIR_VARIABLE} is not set)",
            shown_path(&dir)
        ),
        None => "the hook has no configuration directory".to_owned(),
    };
    // U7 P2 (Owner O4): where the directory comes from, in order, and
    // where the installation's directory belongs.
    format!(
        "this directory has no memprove context ({used}; the hook takes, in order, --config-dir, \
         {CONFIG_DIR_VARIABLE}, HOME/.memprove/config when it exists, XDG_CONFIG_HOME, HOME; the \
         installation's configuration directory belongs in the hook's args in \
         .claude/settings.local.json as --config-dir, which memprove hook install writes); the \
         hook sends only read-only requests and cannot resolve the Workspace here"
    )
}

/// What the hook reads from its process environment.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    /// `MEMPROVE_CONFIG_DIR`.
    pub config_dir: Option<OsString>,
    /// `XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<OsString>,
    /// `HOME`.
    pub home: Option<OsString>,
    /// `MEMPROVE_DATA_DIR`.
    pub data_dir: Option<OsString>,
    /// `MEMPROVE_TOKEN`.
    pub token: Option<OsString>,
    /// `MEMPROVE_TOKEN_FILE`.
    pub token_file: Option<OsString>,
    /// `CLAUDE_ENV_FILE`.
    pub env_file: Option<OsString>,
    /// U7 P2 (Owner O4): whether `config_dir` came from `--config-dir`,
    /// not from `MEMPROVE_CONFIG_DIR`.
    pub config_dir_argument: bool,
    /// U11 T1 (Owner O3): `MEMPROVE_AGENT_NAME`, the agent `begin` and
    /// `end` declare without agent inputs, which the opening names.
    pub agent_name: Option<OsString>,
    /// U11 T1: `MEMPROVE_AGENT_ROLE`.
    pub agent_role: Option<OsString>,
    /// U11 T1: `MEMPROVE_PARENT_SESSION`.
    pub parent_session: Option<OsString>,
    /// U11 T2 (Owner O4): the Unix time, in seconds, the opening states as
    /// `The current UTC time is <time>.`; `None` (as [`Environment::from_process`] leaves it)
    /// reads the system clock when the opening is written. A test sets it.
    pub now: Option<u64>,
}

impl Environment {
    /// The environment of this process.
    #[must_use]
    pub fn from_process() -> Self {
        let var = std::env::var_os;
        Self {
            config_dir: var(crate::context::CONFIG_DIR_ENV),
            xdg_config_home: var("XDG_CONFIG_HOME"),
            home: var("HOME"),
            data_dir: var(crate::DATA_DIR_ENV),
            token: var(crate::TOKEN_ENV),
            token_file: var(crate::TOKEN_FILE_ENV),
            env_file: var("CLAUDE_ENV_FILE"),
            config_dir_argument: false,
            agent_name: var(crate::AGENT_NAME_ENV),
            agent_role: var(crate::AGENT_ROLE_ENV),
            parent_session: var(crate::PARENT_SESSION_ENV),
            now: None,
        }
    }

    /// U7 P2 (D2 F13, Owner O4): with `--config-dir <DIR>` given, `DIR` is
    /// the configuration directory, whatever `MEMPROVE_CONFIG_DIR` says;
    /// `None` leaves the environment as it is.
    #[must_use]
    pub fn with_config_dir(mut self, config_dir: Option<OsString>) -> Self {
        if let Some(config_dir) = config_dir {
            self.config_dir = Some(config_dir);
            self.config_dir_argument = true;
        }
        self
    }
}

/// What one run of `hook session-start` decided: the text to print, and
/// the last-Pack file to write when a Pack is injected.
#[derive(Debug)]
pub struct Outcome {
    text: String,
    record: Option<Record>,
}

/// The last-Pack file of a client session (Owner condition i).
#[derive(Debug)]
struct Record {
    store: ContextStore,
    root: PathBuf,
    pack: LastPack,
}

impl Outcome {
    fn statement(text: String) -> Self {
        Self { text, record: None }
    }

    /// An outcome that prints `text` and records nothing.
    #[must_use]
    pub fn from_statement(text: String) -> Self {
        Self::statement(text)
    }

    /// Writes the last-Pack file of an injected Pack (a failure is a note on
    /// standard error only), then returns the text to print. Called once the
    /// text is sure to be printed, so a Pack is recorded only when injected.
    #[must_use]
    pub fn finish(self) -> String {
        // U3 (K3, V-N-2): a record location that is a directory is left
        // alone, and nothing is said about it.
        if let Some(record) = self.record
            && !record.store.record_is_directory(&record.root)
            && let Err(error) = record.store.save_last_pack(&record.root, &record.pack)
        {
            eprintln!(
                "memprove: warning: the injected Pack was not recorded for `memprove begin` \
                 ({error})"
            );
        }
        self.text
    }
}

/// The statement printed when the hook did not finish within
/// [`TIME_LIMIT`]; since U15 T1 it also says how to fetch the Pack
/// ([`SELF_FETCH`]).
#[must_use]
pub fn timeout_statement() -> String {
    format!(
        "memprove: the Context Pack was not read within {} seconds; {NOT_INJECTED}; {SELF_FETCH}.\n",
        TIME_LIMIT.as_secs()
    )
}

/// The statement printed when the hook failed inside.
#[must_use]
pub fn internal_error_statement() -> String {
    format!("memprove: the hook failed internally; {NOT_INJECTED}.\n")
}

/// The statement printed when `hook session-start` was given arguments.
#[must_use]
pub fn arguments_statement() -> String {
    format!(
        "memprove: hook session-start takes one option only, --config-dir <DIR>; {NOT_INJECTED}.\n"
    )
}

/// U8 K1 (U7 V-N1): the statement printed when `hook session-start` was
/// refused for the reason `refusal` names: a global option does not apply, or
/// `--config-dir` has no directory or an empty one, or (U9 K3) is spelled
/// `--config-dir=<DIR>`; anything else is [`arguments_statement`].
#[must_use]
pub fn refusal_statement(refusal: crate::ConfigDirRefusal) -> String {
    use crate::ConfigDirRefusal::{
        EmptyDirectory, EqualsForm, GlobalOption, MissingDirectory, Other,
    };
    match refusal {
        EqualsForm => format!(
            "memprove: hook session-start takes --config-dir <DIR> as two arguments, not the \
             --config-dir=<DIR> spelling; {NOT_INJECTED}.\n"
        ),
        GlobalOption(name) => format!(
            "memprove: the global option {name} does not apply to hook session-start; --config-dir \
             <DIR> goes right after hook session-start; {NOT_INJECTED}.\n"
        ),
        MissingDirectory => {
            format!(
                "memprove: hook session-start's --config-dir lacks a directory; {NOT_INJECTED}.\n"
            )
        }
        EmptyDirectory => {
            format!(
                "memprove: hook session-start's --config-dir directory is empty; {NOT_INJECTED}.\n"
            )
        }
        Other => arguments_statement(),
    }
}

fn failed(why: &str) -> String {
    format!("memprove: {why}; {NOT_INJECTED}.\n")
}

/// The `SessionStart` input the hook acts on.
struct Start {
    session_id: String,
    cwd: PathBuf,
    source: &'static str,
}

/// Reads the hook's standard input as one JSON object; `Err` is the clause
/// that says what is wrong with it, never a part of it.
fn read_input(input: &mut dyn Read) -> Result<JsonValue, &'static str> {
    let mut bytes = Vec::new();
    input
        .take(u64::try_from(MAX_INPUT_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| " cannot be read")?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(" exceeds 65536 bytes");
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| " is not UTF-8 text")?;
    let value = parse_strict(text).map_err(|_| " is not well-formed JSON")?;
    if value.as_object().is_none() {
        return Err(" is not a JSON object");
    }
    Ok(value)
}

/// Reads and checks the hook's standard input; `Err` is the clause that
/// says what is wrong with it, never a part of it.
#[cfg(test)]
fn read_start(input: &mut dyn Read) -> Result<Start, &'static str> {
    start_of(&read_input(input)?)
}

/// U24 (H2): whether `value` is the input of a Cursor hook (it names
/// `cursor_version`, which Cursor gives every hook). Cursor also runs the
/// hooks of `.claude/settings.local.json`; the Claude Code handler then
/// prints nothing and leaves the answer to Cursor's own handler
/// (`hook session-start --client cursor`), so that a Pack is injected once.
fn is_cursor_input(value: &JsonValue) -> bool {
    value.get("cursor_version").is_some()
}

/// Checks a Claude Code (or Codex, which sends the same members)
/// `SessionStart` input; `Err` as [`read_input`].
fn start_of(value: &JsonValue) -> Result<Start, &'static str> {
    if let Some(name) = value.get("hook_event_name")
        && name.as_str() != Some("SessionStart")
    {
        return Err("'s hook_event_name is not SessionStart");
    }
    let session_id = value
        .get("session_id")
        .and_then(JsonValue::as_str)
        .filter(|id| is_client_session(id))
        .ok_or("'s session_id is not 1 to 128 characters of A-Z, a-z, 0-9, _, -")?
        .to_owned();
    let source = value
        .get("source")
        .and_then(JsonValue::as_str)
        .and_then(|source| SOURCES.into_iter().find(|known| *known == source))
        .ok_or("'s source is not one of startup, resume, clear, compact, fork")?;
    let cwd = value
        .get("cwd")
        .and_then(JsonValue::as_str)
        .map(Path::new)
        .filter(|cwd| cwd.is_absolute())
        .and_then(|cwd| fs::canonicalize(cwd).ok())
        .filter(|cwd| cwd.is_dir())
        .ok_or("'s cwd is not the absolute path of an existing directory")?;
    Ok(Start {
        session_id,
        cwd,
        source,
    })
}

/// `hook session-start` after its arguments were checked: reads standard
/// input, then decides what to print. Never fails: every problem is a
/// statement.
pub fn session_start(input: &mut dyn Read, environment: &Environment) -> Outcome {
    let start = match read_input(input) {
        Ok(value) if is_cursor_input(&value) => return Outcome::statement(String::new()),
        Ok(value) => start_of(&value),
        Err(why) => Err(why),
    };
    let start = match start {
        Ok(start) => start,
        Err(why) => return Outcome::statement(failed(&format!("the SessionStart input{why}"))),
    };
    started(&start, environment)
}

/// U24 (H2): `hook session-start --client cursor`: Cursor's `sessionStart`
/// input, checked as the hook checks Claude Code's: its `session_id` (else
/// `conversation_id`) is the client session; the Workspace is the first of
/// `workspace_roots`, else `project_dir` (`CURSOR_PROJECT_DIR`), else the
/// current directory, where Cursor runs a project's hooks; the source is
/// `startup`, since Cursor names none. What it prints is the same text;
/// [`cursor_output`] wraps it in the JSON Cursor reads.
pub fn cursor_session_start(
    input: &mut dyn Read,
    environment: &Environment,
    project_dir: Option<&OsStr>,
) -> Outcome {
    let start = read_input(input).and_then(|value| cursor_start_of(&value, project_dir));
    match start {
        Ok(start) => started(&start, environment),
        Err(why) => Outcome::statement(failed(&format!("the sessionStart input{why}"))),
    }
}

/// U24 (H2): what [`cursor_session_start`] reads from Cursor's input.
fn cursor_start_of(value: &JsonValue, project_dir: Option<&OsStr>) -> Result<Start, &'static str> {
    if let Some(name) = value.get("hook_event_name")
        && name.as_str() != Some("sessionStart")
    {
        return Err("'s hook_event_name is not sessionStart");
    }
    let session_id = ["session_id", "conversation_id"]
        .into_iter()
        .find_map(|name| value.get(name).and_then(JsonValue::as_str))
        .filter(|id| is_client_session(id))
        .ok_or("'s session_id is not 1 to 128 characters of A-Z, a-z, 0-9, _, -")?
        .to_owned();
    let directory = |path: &Path| {
        path.is_absolute()
            .then(|| fs::canonicalize(path).ok())
            .flatten()
            .filter(|path| path.is_dir())
    };
    let root = value
        .get("workspace_roots")
        .and_then(JsonValue::as_array)
        .and_then(|roots| roots.first())
        .and_then(JsonValue::as_str)
        .map(Path::new);
    let cwd = match root {
        Some(root) => directory(root),
        None => project_dir
            .filter(|dir| !dir.is_empty())
            .map(Path::new)
            .map_or_else(
                || std::env::current_dir().ok().and_then(|dir| directory(&dir)),
                directory,
            ),
    }
    .ok_or("'s workspace_roots does not begin with the absolute path of an existing directory")?;
    Ok(Start {
        session_id,
        cwd,
        source: "startup",
    })
}

/// U24 (H2): `text`, what `hook session-start` prints, as Cursor's
/// `sessionStart` output: `{"additional_context": <text>}` and a line end;
/// nothing when `text` is empty.
#[must_use]
pub fn cursor_output(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    format!("{{\"additional_context\":{}}}\n", json_string(text))
}

/// What the hook does with a checked input: exports the client session,
/// records it, and injects the Pack.
fn started(start: &Start, environment: &Environment) -> Outcome {
    let exported = export_client_session(environment.env_file.as_deref(), &start.session_id)
        .unwrap_or_else(|why| {
            eprintln!(
                "memprove: warning: {CLIENT_SESSION_ENV} was not written to CLAUDE_ENV_FILE: \
                 {why}"
            );
            false
        });
    let Some(store) = ContextStore::from_env(
        environment.config_dir.clone(),
        environment.xdg_config_home.clone(),
        environment.home.clone(),
    ) else {
        return Outcome::statement(failed(
            "no configuration directory (none of MEMPROVE_CONFIG_DIR, XDG_CONFIG_HOME, HOME is set)",
        ));
    };
    if exported {
        record_client_session(start, &store);
    }
    // U11 T1 (Owner O3): half a declaration, or one the server refuses, is
    // one line on standard error; the opening then names no agent.
    if let Err(warning) = declared_agent(environment) {
        eprintln!("{warning}");
    }
    inject(start, &store, environment, exported)
        .unwrap_or_else(|why| Outcome::statement(failed(&why)))
}

/// U1 (U-F, SF-1R): gives the client session the hook exported to the
/// shell a record, before the Task is chosen, so that `memprove mcp
/// serve` with the same `CLAUDE_CODE_SESSION_ID` uses that client
/// session's files as the shell does, also when no Pack is injected (or
/// the hook does not finish in time). Only when the client session has no
/// context file and no last-Pack file at or above the directory yet (a
/// record given earlier is kept), and only at a Workspace root: the
/// last-Pack file of the root, written as a record of no Pack, with the
/// Project every context of the root names when they name one. It declares
/// no Pack: an injected Pack replaces it ([`Outcome::finish`]). A failure
/// is a note on standard error only.
///
/// U2 (H2, N-12): a last-Pack file of the client session at the root that
/// cannot be used (unreadable, insecure, a symbolic link, or malformed) is
/// not a record that is kept: it is replaced by this run's record (of no
/// Pack here, of the Pack once one is injected), with [`REPLACED`] on
/// standard error. A readable record is kept, as before. U3 (K3, V-N-2):
/// a directory there is not replaced and counts as a record; no line is
/// written about it.
fn record_client_session(start: &Start, store: &ContextStore) {
    let client = store.for_client(Some(&start.session_id));
    let Ok(root) = workspace_root(&start.cwd) else {
        return;
    };
    if client.has_damaged_record(&root) {
        eprintln!("{REPLACED}");
    } else if client.has_records(&start.cwd) {
        return;
    }
    let project = workspace_of(store, &root)
        .ok()
        .map(|(project, _)| project)
        .filter(|project| is_uuid_v7(project));
    if let Err(error) = client.save_no_pack(&root, project.as_deref()) {
        eprintln!(
            "memprove: warning: the client session was not recorded for `memprove mcp \
             serve` ({error})"
        );
    }
}

/// Appends `export MEMPROVE_CLIENT_SESSION='<client>'` to the file
/// `CLAUDE_ENV_FILE` names, unless the last such line there already says
/// it. `client` is a value [`is_client_session`] accepts, so the line
/// assigns a quoted literal and runs nothing when a shell reads it.
/// `Ok(true)` when the file ends up with the line, `Ok(false)` when
/// `CLAUDE_ENV_FILE` is not set.
fn export_client_session(path: Option<&OsStr>, client: &str) -> Result<bool, String> {
    let Some(path) = path.filter(|path| !path.is_empty()) else {
        return Ok(false);
    };
    if !is_client_session(client) {
        return Err("the client session is not a valid identifier".to_owned());
    }
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err("CLAUDE_ENV_FILE is not an absolute path".to_owned());
    }
    let prefix = format!("export {CLIENT_SESSION_ENV}=");
    let line = format!("{prefix}'{client}'");
    let mut existing = Vec::new();
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            File::open(path)
                .and_then(|file| file.take(MAX_ENV_FILE_BYTES).read_to_end(&mut existing))
                .map_err(|error| error.to_string())?;
        }
        Ok(_) => return Err("CLAUDE_ENV_FILE is not a regular file".to_owned()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let existing = String::from_utf8_lossy(&existing);
    let last = existing
        .lines()
        .rev()
        .map(|line| line.trim_end_matches('\r'))
        .find(|line| line.starts_with(&prefix));
    if last == Some(line.as_str()) {
        return Ok(true);
    }
    let mut text = String::new();
    if !existing.is_empty() && !existing.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&line);
    text.push('\n');
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .map(|()| true)
        .map_err(|error| error.to_string())
}

/// Why the Task of the Pack was chosen (Owner condition m).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Basis {
    /// The client session's own context names it.
    Client,
    /// The directory's context names it.
    Directory,
    /// It is the only Task in progress in the Workspace. P4-H1: with the
    /// finished Task the directory's context names, when it gave way.
    OnlyInProgress(Option<Finished>),
}

/// P4-H1: a Task that is completed or cancelled, as its Capsule says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finished {
    /// The Task.
    pub(crate) task_id: String,
    /// `completed` or `cancelled`.
    pub(crate) state: &'static str,
}

impl Finished {
    /// The clause that names the directory context's finished Task.
    fn clause(&self) -> String {
        format!(
            "the Task {} recorded by this directory's context is {}",
            self.task_id, self.state
        )
    }
}

/// P4-H1: the states of a finished Task, whose Pack the hook never injects.
const FINISHED_STATES: [&str; 2] = ["completed", "cancelled"];

/// P4-H1: the state of the Task of `capsule` when it is finished: its
/// `task.status` is completed or cancelled. `None` for any other state, and
/// for a Capsule judged tampered: the row's state is not trusted then, and
/// the Pack says why.
fn finished_state(capsule: &JsonValue) -> Option<&'static str> {
    if capsule.get("status").and_then(JsonValue::as_str) == Some("tampered") {
        return None;
    }
    let state = capsule.get("task")?.get("status")?.as_str()?;
    FINISHED_STATES
        .into_iter()
        .find(|finished| *finished == state)
}

/// U11 T1 (Owner O3): the line on standard error when the hook's process
/// sets only a part of the agent declaration: `MEMPROVE_AGENT_NAME`
/// without `MEMPROVE_AGENT_ROLE`, the role without the name, or
/// `MEMPROVE_PARENT_SESSION` alone. `begin` and `end` without agent inputs
/// refuse such a declaration (`invalid_arguments`, or a usage error in the
/// shell), so the opening names no agent. It never repeats a value.
pub const AGENT_PART_WARNING: &str = "memprove: warning: MEMPROVE_AGENT_NAME and \
     MEMPROVE_AGENT_ROLE are one declaration (with MEMPROVE_PARENT_SESSION), and only part of \
     it is set: the opening names no agent, and begin and end without agent inputs refuse it \
     (invalid_arguments)";

/// U11 T1 (Owner O3): the line on standard error when the agent variables
/// are all there but one does not hold its rule (a name of 1 to 64 ASCII
/// letters, digits, `_` or `-`; a role `orchestrator`, `sub_agent`, or
/// `human`; a parent that is a Session ID), which `begin` and `end` refuse
/// as well: the opening names no agent the server would refuse.
pub const AGENT_INVALID_WARNING: &str = "memprove: warning: MEMPROVE_AGENT_NAME, \
     MEMPROVE_AGENT_ROLE, or MEMPROVE_PARENT_SESSION does not hold its rule (a name of 1 to 64 \
     ASCII letters, digits, _ or -; a role orchestrator, sub_agent, or human; a parent that is a \
     lowercase UUIDv7): the opening names no agent, and begin and end without agent inputs refuse \
     it (invalid_arguments)";

/// U11 T1 (Owner O3): the agent the hook's process declares in
/// `MEMPROVE_AGENT_NAME`, `MEMPROVE_AGENT_ROLE`, and
/// `MEMPROVE_PARENT_SESSION` (an empty one is unset), the agent the MCP
/// `begin` and `end` and the shell's `memprove begin` use when given no
/// agent input (U10 T6): `Ok(None)` when none of the three is set; `Err`
/// with the warning when only part of the declaration is set or a value
/// does not hold its rule, so that the opening never names an agent the
/// server would refuse.
pub(crate) fn declared_agent(
    environment: &Environment,
) -> Result<Option<memprove_domain::SessionAgent>, &'static str> {
    let env = crate::AgentEnv::of(
        environment.agent_name.clone(),
        environment.agent_role.clone(),
        environment.parent_session.clone(),
    );
    match (&env.name, &env.role) {
        (None, None) if env.parent_session.is_none() => Ok(None),
        (Some(name), Some(role)) => {
            memprove_domain::SessionAgent::new(name, role, env.parent_session.as_deref())
                .map(Some)
                .map_err(|_| AGENT_INVALID_WARNING)
        }
        _ => Err(AGENT_PART_WARNING),
    }
}

/// U11 T1 (Owner O3): the sentence of the opening that names the agent
/// `begin` and `end` will use, and that they then need no agent input.
/// U12 T3 (Owner O5): a statement of what the server does (ADR 0014 E4
/// condition n), no longer an imperative.
#[must_use]
pub(crate) fn identity_sentence(agent: &memprove_domain::SessionAgent) -> String {
    let parent = agent
        .parent_session_id
        .as_ref()
        .map_or_else(String::new, |parent| {
            format!(", parent Session {}", parent.as_str())
        });
    format!(
        "You are agent「{}」({}{parent}); when begin and end get no agent_name, agent_role, or \
         parent_session, the server uses these three.",
        agent.name,
        agent.role.as_str()
    )
}

/// U11 T2 (Owner O4): Unix seconds as the opening writes them: an RFC 3339
/// UTC timestamp in the canonical form of the ledger's times, the form of
/// the Pack's `last wrote to the ledger at <time>` (`YYYY-MM-DDTHH:MM:SSZ`, whole
/// seconds, so no fraction is written).
#[must_use]
pub(crate) fn utc_seconds(seconds: u64) -> String {
    // `format_utc` writes milliseconds, which are zero here.
    let written = crate::run::format_utc(seconds, 0);
    let whole = written.get(..19).unwrap_or(&written);
    format!("{whole}Z")
}

/// U11 T2 (Owner O4): the sentence of the opening that states the current
/// UTC time, from `now` (seconds), else the system clock.
#[must_use]
pub(crate) fn time_sentence(now: Option<u64>) -> String {
    let seconds = now.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    });
    format!("The current UTC time is {}.", utc_seconds(seconds))
}

/// Why the Task was chosen, as the opening writes it after `Context Pack`
/// (Owner condition m; U12 T2: the MCP `pack` tool's opening too).
#[must_use]
pub(crate) fn basis_clause(basis: &Basis) -> String {
    match basis {
        Basis::Client => ", chosen from this client session's context".to_owned(),
        Basis::Directory => ", chosen from this directory's context".to_owned(),
        Basis::OnlyInProgress(None) => {
            "; it is the only in-progress Task of this Workspace".to_owned()
        }
        Basis::OnlyInProgress(Some(finished)) => format!(
            "; it is the only in-progress Task of this Workspace ({})",
            finished.clause()
        ),
    }
}

/// The statement before the fenced Pack. U11 T2 (Owner O4): it ends with
/// `time`, the current UTC time, and U11 T1 (Owner O3), when the hook's
/// process declares an agent, with `identity`, the sentence that names it.
fn opening(
    task_id: &str,
    source: &str,
    basis: &Basis,
    time: &str,
    identity: Option<&str>,
) -> String {
    statement_opening(task_id, Some(source), &basis_clause(basis), time, identity)
}

/// The opening of a Pack, in one function for the `SessionStart` hook and
/// (U12 T2, Owner O4) the MCP `pack` tool: `source` is the hook's
/// `SessionStart` source, `None` for the tool, whose opening has no
/// `at SessionStart (<source>)` and no fork sentence; `why` is the
/// [`basis_clause`] (or the tool's own for a Task named by number). U14 T1
/// (Owner O2): both end with [`OPEN_ITEM_SENTENCE`].
#[must_use]
pub(crate) fn statement_opening(
    task_id: &str,
    source: Option<&str>,
    why: &str,
    time: &str,
    identity: Option<&str>,
) -> String {
    let identity = identity.map_or_else(String::new, |identity| format!("{identity} "));
    let Some(source) = source else {
        return format!(
            "memprove: below is the Context Pack of Task {task_id}{why}. {time} {identity}\
             {OPEN_ITEM_SENTENCE}"
        );
    };
    // U7 P1 (Owner O3): a forked session has no context of its own, so
    // every open Session's line carries the takeover hint; one may be the
    // parent's, which is still working.
    let fork = if source == "fork" {
        format!("{FORK_SENTENCE} ")
    } else {
        String::new()
    };
    format!(
        "memprove: below is the Context Pack of Task {task_id} at SessionStart ({source}){why}. \
         {fork}{time} {identity}{OPEN_ITEM_SENTENCE}"
    )
}

/// U11 T1 (Owner O3); U12 T2 (Owner O4) for the MCP `pack` tool too: the
/// identity sentence of `environment`'s whole agent declaration, `None`
/// when it declares none or only part of one (the warning is written where
/// the process starts, not here).
#[must_use]
pub(crate) fn opening_identity(environment: &Environment) -> Option<String> {
    declared_agent(environment)
        .ok()
        .flatten()
        .map(|agent| identity_sentence(&agent))
}

/// Why the daemon cannot be asked (P4-G: shared with `mcp serve`, ADR 0014
/// E7.8): the data directory, its socket, or the token is missing or
/// unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachError {
    /// Neither `MEMPROVE_DATA_DIR` nor the `data-dir` file names one.
    NoDataDir,
    /// The `data-dir` file cannot be read.
    DataDirUnreadable,
    /// The `data-dir` file is not one absolute path on one line.
    DataDirMalformed,
    /// The data directory has no socket.
    DaemonNotRunning,
    /// No token source is set and the `token` file does not exist.
    NoToken,
    /// The token source is unusable.
    TokenUnusable,
}

impl ReachError {
    /// The hook's clause.
    pub(crate) const fn clause(self) -> &'static str {
        match self {
            Self::NoDataDir => {
                "no data directory of memproved (MEMPROVE_DATA_DIR is not set, and the configuration directory has no data-dir file)"
            }
            Self::DataDirUnreadable => {
                "the data-dir file in the configuration directory cannot be read"
            }
            Self::DataDirMalformed => {
                "the data-dir file in the configuration directory is not one absolute path on one line"
            }
            Self::DaemonNotRunning => "memproved is not running (the data directory has no socket)",
            Self::NoToken => {
                "no usable token (none of MEMPROVE_TOKEN, MEMPROVE_TOKEN_FILE, and the token file in the configuration directory)"
            }
            Self::TokenUnusable => {
                "the token is unusable (the token file cannot be read, is readable by other users, or is not one token on one line)"
            }
        }
    }
}

/// How one request to the daemon failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadFailure {
    /// The exchange failed (the daemon is unreachable, or closed early).
    Unreachable,
    /// The token cannot be put in a request header.
    InvalidToken,
    /// The response violates the contract or is too large.
    BadResponse,
    /// The daemon refused: the status, the Problem code when it is a
    /// plain identifier, and the Problem's `detail`.
    Refused {
        /// HTTP status.
        status: u16,
        /// Problem code.
        code: Option<String>,
        /// The Problem's `detail`, when it has one (P4-G: an
        /// `evidence_stale` with one is a tampered Task). The hook never
        /// shows it; U2 (S1, N-3, Owner O4): the MCP server relays it for a
        /// `400` of a write (`mcp::failure`).
        detail: Option<String>,
    },
    /// P4-G: the operation is outside the closed set of the caller (ADR
    /// 0014 E7.5.1); nothing was sent.
    NotAllowed,
}

/// One failed request: its operation and how it failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadError {
    /// The operation.
    pub(crate) operation: OperationId,
    /// How it failed.
    pub(crate) failure: ReadFailure,
}

impl ReadError {
    /// The hook's clause.
    fn clause(&self) -> String {
        match &self.failure {
            ReadFailure::Unreachable => "cannot connect to memproved".to_owned(),
            ReadFailure::InvalidToken => "the token cannot be put in a request header".to_owned(),
            ReadFailure::BadResponse => "memproved's response is malformed or too large".to_owned(),
            ReadFailure::Refused { status, code, .. } => {
                let code = code
                    .as_deref()
                    .map(|code| format!(" {code}"))
                    .unwrap_or_default();
                match status {
                    401 => format!("memproved did not accept this token (401{code})"),
                    403 => format!(
                        "this token has no read permission (403{code}; control or mcp-read is needed)"
                    ),
                    404 => {
                        format!("memproved cannot find the object the context records (404{code})")
                    }
                    status => format!("memproved refused the read-only request ({status}{code})"),
                }
            }
            ReadFailure::NotAllowed => "the request is not among the allowed operations".to_owned(),
        }
    }
}

/// P4-G: the hook's clause, which the shared write flows show when a quiet
/// read fails ([`crate::flow::Daemon::Unread`]).
impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.clause())
    }
}

/// Why Owner condition m chose no Task (P4-G: shared with `mcp serve`).
/// [`ChoiceError::clause`] is what the hook prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChoiceError {
    /// No context of the Workspace root records a Workspace.
    NoContext,
    /// The context files of the Workspace root record more than one
    /// Workspace.
    SeveralWorkspaces,
    /// A context file records an ID that is not a `UUIDv7`.
    NotUuid,
    /// The daemon cannot be asked.
    Reach(ReachError),
    /// A read request failed.
    Read(ReadError),
    /// P4-H1: the client session's own context names a finished Task.
    ClientTaskFinished(Finished),
    /// No Task in progress in the Workspace; with the directory context's
    /// finished Task when it gave way (P4-H1).
    NoneInProgress(Option<Finished>),
    /// Several Tasks in progress in the Workspace, by ID.
    Several(Option<Finished>, Vec<String>),
    /// More Tasks in progress in the Project than the hook looks at.
    TooMany(Option<Finished>, usize),
}

impl ChoiceError {
    /// The hook's clause: the statement printed instead of a Pack.
    pub(crate) fn clause(&self) -> String {
        let prefix = |replaced: &Option<Finished>| {
            replaced
                .as_ref()
                .map(|finished| format!("{}; ", finished.clause()))
                .unwrap_or_default()
        };
        match self {
            Self::NoContext => {
                "this directory has no memprove context; the hook sends only read-only requests \
                 and cannot resolve the Workspace here"
                    .to_owned()
            }
            Self::SeveralWorkspaces => {
                "this directory's context file records more than one Workspace".to_owned()
            }
            Self::NotUuid => "the ID the context file records is not a UUIDv7".to_owned(),
            Self::Reach(error) => error.clause().to_owned(),
            Self::Read(error) => error.clause(),
            Self::ClientTaskFinished(finished) => format!(
                "the Task {} recorded by this client session's context is {}",
                finished.task_id, finished.state
            ),
            Self::NoneInProgress(None) => {
                "this directory's context names no Task, and this Workspace has no in-progress Task"
                    .to_owned()
            }
            Self::NoneInProgress(replaced) => {
                format!("{}this Workspace has no in-progress Task", prefix(replaced))
            }
            Self::Several(replaced, tasks) => format!(
                "{}this Workspace has {} in-progress Tasks ({}), and neither this client session's \
                 context nor this directory's names one of them",
                prefix(replaced),
                tasks.len(),
                tasks.join(", ")
            ),
            Self::TooMany(replaced, count) => format!(
                "{}this Project has {count} in-progress Tasks, and neither this client session's \
                 context nor this directory's names one of them",
                prefix(replaced)
            ),
        }
    }
}

/// The read requests choosing the Task sends; [`Reader`] sends them to
/// `memproved`. T21 (V3-F-1, fix round 2): `Sync`, so that the Capsules
/// of several Tasks are read at once ([`capsules`]).
pub(crate) trait Reads: Sync {
    /// The Task Capsule of `task`, judged against `workspace`.
    ///
    /// # Errors
    ///
    /// How the request failed.
    fn capsule(&self, task: &str, workspace: &str) -> Result<String, ReadError>;
    /// The Tasks of `project` as `listTasks` lists them: those in progress,
    /// each with whether its own Workspace is `workspace`, and those whose
    /// row is completed or cancelled.
    ///
    /// # Errors
    ///
    /// How a request failed.
    fn listing(&self, project: &str, workspace: &str) -> Result<Listing, ReadError>;
}

/// The Tasks of a Project as `listTasks` lists them, for Owner condition m.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Listing {
    /// The Tasks in progress, each with whether its own Workspace is the one
    /// asked about.
    pub(crate) in_progress: Vec<(String, bool)>,
    /// The Tasks whose row says completed or cancelled. Only a hint of what
    /// to read at once: whether a Task is finished is read from its Capsule.
    pub(crate) finished: Vec<String>,
}

/// T21 (V3-F-1, fix round 2): the Capsules of `tasks` judged against
/// `workspace`, in the order of `tasks`, each read on its own thread.
/// `memproved` serves each request on its blocking pool, so the reads,
/// each with its own probe of the Workspace, overlap: choosing waits about
/// as long as the slowest read, not their sum. Each result is what the read
/// alone would give; a read that panics panics here.
fn capsules(
    reads: &dyn Reads,
    tasks: &[String],
    workspace: &str,
) -> Vec<Result<String, ReadError>> {
    if tasks.len() < 2 {
        return tasks
            .iter()
            .map(|task| reads.capsule(task, workspace))
            .collect();
    }
    std::thread::scope(|scope| {
        let handles = tasks
            .iter()
            .map(|task| scope.spawn(move || reads.capsule(task, workspace)))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    })
}

/// What the last rule of Owner condition m found in the Workspace.
enum InProgress {
    /// Exactly one Task in progress: its ID and Capsule.
    One(String, String),
    /// No Task in progress.
    None,
    /// Several Tasks in progress, by ID.
    Several(Vec<String>),
    /// More Tasks in progress in the Project than the hook looks at.
    TooMany(usize),
}

/// The Tasks in progress of a listing and their Capsules, read before the
/// last rule needed them (T21, V3-F-1 fix round 2).
struct ReadAhead {
    in_progress: Vec<(String, bool)>,
    capsules: Vec<Result<String, ReadError>>,
}

/// The only Task of `in_progress` in progress in `workspace` (Owner
/// condition m): the Task's own Workspace, or a Session of it in the
/// Workspace, read from its Capsule. P4-H1: a Task whose Capsule says it is
/// finished (it finished after it was listed) is not in progress. The
/// Capsules are `read` when already read (as many as `in_progress`), else
/// read here, at once ([`capsules`]); the first failed read, in the order
/// of `in_progress`, is the error, as when they were read one by one.
fn only_task_in_progress(
    reads: &dyn Reads,
    workspace: &str,
    in_progress: Vec<(String, bool)>,
    read: Option<Vec<Result<String, ReadError>>>,
) -> Result<InProgress, ReadError> {
    if in_progress.len() > MAX_CANDIDATES {
        return Ok(InProgress::TooMany(in_progress.len()));
    }
    let bodies = read.unwrap_or_else(|| {
        let tasks = in_progress
            .iter()
            .map(|(task, _)| task.clone())
            .collect::<Vec<_>>();
        capsules(reads, &tasks, workspace)
    });
    let mut here = Vec::new();
    for ((task, own_workspace), body) in in_progress.into_iter().zip(bodies) {
        let body = body?;
        let capsule = parse_strict(&body).ok();
        let session_here = capsule.as_ref().is_some_and(|capsule| {
            capsule
                .get("sessions")
                .and_then(JsonValue::as_array)
                .unwrap_or_default()
                .iter()
                .any(|session| {
                    session.get("workspace_id").and_then(JsonValue::as_str) == Some(workspace)
                })
        });
        let finished = capsule.as_ref().and_then(finished_state).is_some();
        if (own_workspace || session_here) && !finished {
            here.push((task, body));
        }
    }
    Ok(match here.len() {
        0 => InProgress::None,
        1 => {
            let (task, body) = here.remove(0);
            InProgress::One(task, body)
        }
        _ => InProgress::Several(here.into_iter().map(|(task, _)| task).collect()),
    })
}

/// The Capsule of `task_id`, which the directory's context names. T21
/// (V3-F-1, fix round 2): its read runs on its own thread while `listTasks`
/// lists the Project's Tasks; when the list gives that Task's row as
/// completed or cancelled, the Task is likely to give way to the last rule,
/// so the Capsules of the Tasks in progress are read at once, alongside its
/// own, and kept for that rule. Otherwise (its row is not finished, it is
/// not listed, `listTasks` fails, or more Tasks are in progress than the
/// hook looks at) only its own Capsule is read, as before, and the last
/// rule lists and reads afresh if it is needed. A daemon that does not
/// answer therefore costs one wait, not two, and the error is that of its
/// own read, as before.
fn directory_capsule(
    reads: &dyn Reads,
    project: &str,
    workspace: &str,
    task_id: &str,
) -> (Result<String, ReadError>, Option<ReadAhead>) {
    std::thread::scope(|scope| {
        let own = scope.spawn(|| reads.capsule(task_id, workspace));
        let ahead = match reads.listing(project, workspace) {
            Ok(listing)
                if listing.finished.iter().any(|task| task == task_id)
                    && listing.in_progress.len() <= MAX_CANDIDATES =>
            {
                let tasks = listing
                    .in_progress
                    .iter()
                    .map(|(task, _)| task.clone())
                    .collect::<Vec<_>>();
                Some(ReadAhead {
                    capsules: capsules(reads, &tasks, workspace),
                    in_progress: listing.in_progress,
                })
            }
            _ => None,
        };
        let own = own
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        (own, ahead)
    })
}

/// Chooses the Task whose Pack is injected (Owner condition m) and reads
/// its Capsule: its ID, why it was chosen, and the Capsule. P4-H1: a
/// finished Task (completed or cancelled) gets no Pack. When the client
/// session's context names it, the error names it and its state; when the
/// directory's context names it, the last rule chooses, and what it gives
/// names the finished Task and its state.
fn choose(
    reads: &dyn Reads,
    project: &str,
    workspace: &str,
    named: Option<(String, Basis)>,
) -> Result<(String, Basis, String), ChoiceError> {
    let mut replaced = None;
    let mut ahead = None;
    if let Some((task_id, basis)) = named {
        let body = if matches!(basis, Basis::Directory) {
            let (body, read) = directory_capsule(reads, project, workspace, &task_id);
            ahead = read;
            body
        } else {
            reads.capsule(&task_id, workspace)
        }
        .map_err(ChoiceError::Read)?;
        let Some(state) = parse_strict(&body).ok().as_ref().and_then(finished_state) else {
            return Ok((task_id, basis, body));
        };
        let finished = Finished { task_id, state };
        if matches!(basis, Basis::Client) {
            return Err(ChoiceError::ClientTaskFinished(finished));
        }
        replaced = Some(finished);
    }
    let (in_progress, read) = match ahead {
        Some(ahead) => (ahead.in_progress, Some(ahead.capsules)),
        None => (
            reads
                .listing(project, workspace)
                .map_err(ChoiceError::Read)?
                .in_progress,
            None,
        ),
    };
    match only_task_in_progress(reads, workspace, in_progress, read).map_err(ChoiceError::Read)? {
        InProgress::One(task_id, body) => Ok((task_id, Basis::OnlyInProgress(replaced), body)),
        InProgress::None => Err(ChoiceError::NoneInProgress(replaced)),
        InProgress::Several(tasks) => Err(ChoiceError::Several(replaced, tasks)),
        InProgress::TooMany(count) => Err(ChoiceError::TooMany(replaced, count)),
    }
}

/// The Task Owner condition m chose, with what it was chosen from.
#[derive(Debug)]
pub(crate) struct Chosen {
    /// The Project of the Workspace.
    pub(crate) project_id: String,
    /// The Task.
    pub(crate) task_id: String,
    /// Why it was chosen.
    pub(crate) basis: Basis,
    /// Its Task Capsule, as received.
    pub(crate) body: String,
    /// The Workspace root of the directory asked about.
    pub(crate) root: PathBuf,
    /// The context that named the Workspace (and the Task, unless the last
    /// rule chose it), when one did.
    pub(crate) context: Option<Context>,
}

/// Owner condition m, in one function for the `SessionStart` hook and (P4-G,
/// ADR 0014 E7.5.2) the MCP server's `pack` and `claims`: the context of the
/// client session (`client`, when there is one), else the directory's
/// context, else the only Task in progress in the Workspace of the Workspace
/// root of `cwd`. `connect` opens the reader once the contexts named a
/// Workspace; a context file that cannot be used is left out, with a warning
/// on standard error.
pub(crate) fn choose_task<R: Reads>(
    client: Option<&ContextStore>,
    directory: &ContextStore,
    cwd: &Path,
    connect: impl FnOnce() -> Result<R, ReachError>,
) -> Result<Chosen, ChoiceError> {
    let root = workspace_root(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let chosen = client
        .map(|store| (store, Basis::Client))
        .into_iter()
        .chain([(directory, Basis::Directory)])
        .find_map(|(store, basis)| match store.find(cwd) {
            Ok(found) => found.map(|context| (context, basis)),
            Err(error) => {
                crate::log_line(format_args!("memprove: warning: {error}; it is not used"));
                None
            }
        });
    let (project_id, workspace_id, named, context) = if let Some((context, basis)) = chosen {
        (
            context.project_id.clone(),
            context.workspace_id.clone(),
            context.task_id.clone().map(|task| (task, basis)),
            Some(context),
        )
    } else {
        let (project, workspace) = workspace_of(directory, &root)?;
        (project, workspace, None, None)
    };
    let task_is_uuid = named.as_ref().is_none_or(|(task, _)| is_uuid_v7(task));
    if !is_uuid_v7(&project_id) || !is_uuid_v7(&workspace_id) || !task_is_uuid {
        return Err(ChoiceError::NotUuid);
    }
    let reads = connect().map_err(ChoiceError::Reach)?;
    let (task_id, basis, body) = choose(&reads, &project_id, &workspace_id, named)?;
    Ok(Chosen {
        project_id,
        task_id,
        basis,
        body,
        root,
        context,
    })
}

/// Chooses the Task (Owner condition m), reads its Capsule, and renders the
/// Pack; `Err` is the clause of the statement that says why not.
///
/// U2 (H3, N-14): the Pack is recorded as the client session's last Pack
/// only when the client session was `exported` to the shell; otherwise (no
/// `CLAUDE_ENV_FILE`, or the `export` line was not written) as the
/// directory's last Pack, the file of the context the shell then uses (and
/// `memprove mcp serve`, which finds no record of the client session),
/// so that no file of a client session the shell does not have is written.
///
/// U3 (K2, V-N-1, original #63): a client session that already has a
/// record or a context at or above `cwd` (from an earlier `SessionStart`
/// whose export worked) keeps its Pack recorded in its own file when this
/// export fails: the shell still has the earlier export, and the server
/// with `CLAUDE_CODE_SESSION_ID` finds those records, so both use the
/// client session's files.
fn inject(
    start: &Start,
    store: &ContextStore,
    environment: &Environment,
    exported: bool,
) -> Result<Outcome, String> {
    let client = store.for_client(Some(&start.session_id));
    let directory = store.for_client(None);
    let own_records = exported || client.has_records(&start.cwd);
    let Chosen {
        project_id,
        task_id,
        basis,
        body,
        root,
        context,
    } = choose_task(Some(&client), &directory, &start.cwd, || {
        Reader::new(environment, store)
    })
    .map_err(|error| match error {
        // U5 P3 (D1 F5): which configuration directory had no context.
        ChoiceError::NoContext => no_context_clause(environment, start),
        error => error.clause(),
    })?;
    // U7 P1 (Owner O3): the client session's own Sessions are the one its
    // own context names (a `resume` or `compact` of a client session that
    // began one) and one that declared the Pack its last-Pack record names;
    // the directory's context belongs to whoever used it.
    let recorded = resume::recorded_pack(Some(&client), Some(&start.cwd));
    let own = resume::Own::of(
        context
            .as_ref()
            .filter(|_| matches!(basis, Basis::Client))
            .and_then(|context| context.session_id.as_deref()),
        recorded.as_ref(),
    );
    let pack = match resume::pack(&body, HOOK_PACK_BUDGET, own) {
        Ok(pack) => pack,
        Err(PackError::OverBudget { needed, .. }) => {
            let needed = working_budget(&body, needed, own);
            let command = if needed <= PACK_MAX_BUDGET {
                format!("memprove resume --task {task_id} --pack --budget {needed}")
            } else {
                format!("memprove resume --task {task_id} --text")
            };
            return Err(format!(
                "the Context Pack of Task {task_id} does not fit the budget of {HOOK_PACK_BUDGET} UTF-16 \
                 code units (it needs {needed}); {command} prints the full text"
            ));
        }
        Err(_) => {
            return Err(format!(
                "the Capsule of Task {task_id} cannot be written as a Context Pack"
            ));
        }
    };
    // U11 T1, T2 (Owner O3, O4): the time and the agent are sentences of
    // the opening, outside the Pack, whose bytes and record do not change.
    let identity = opening_identity(environment);
    let text = format!(
        "{}\n```text\n{pack}```\n",
        opening(
            &task_id,
            start.source,
            &basis,
            &time_sentence(environment.now),
            identity.as_deref()
        )
    );
    if text.encode_utf16().count() > MAX_OUTPUT_UNITS {
        return Err(format!(
            "the Context Pack of Task {task_id} with its opening exceeds {MAX_OUTPUT_UNITS} UTF-16 code units"
        ));
    }
    let record = match resume::last_pack(&body, &pack, HOOK_PACK_BUDGET) {
        Ok(mut last) => {
            last.project_id = Some(project_id);
            Some(Record {
                store: if own_records { client } else { directory },
                root,
                pack: last,
            })
        }
        Err(error) => {
            eprintln!("memprove: warning: the injected Pack was not recorded ({error})");
            None
        }
    };
    Ok(Outcome { text, record })
}

/// The Project and Workspace every context of the Workspace root `root`
/// records (the directory's and each client session's), when they agree:
/// the Workspace of Owner condition m's last rule, found without a write.
/// P4-G: also the Project of the MCP server's `tasks` and `ledger_verify`.
pub(crate) fn workspace_of(
    store: &ContextStore,
    root: &Path,
) -> Result<(String, String), ChoiceError> {
    let mut known = store
        .contexts_of(root)
        .into_iter()
        .map(|context| (context.project_id, context.workspace_id))
        .collect::<Vec<_>>();
    known.sort();
    known.dedup();
    match known.as_slice() {
        [] => Err(ChoiceError::NoContext),
        [(project, workspace)] => Ok((project.clone(), workspace.clone())),
        _ => Err(ChoiceError::SeveralWorkspaces),
    }
}

/// The smallest budget, from `needed` up, at which the Pack of `body` for
/// the reader whose own Session is `own` fits: the first line names the
/// budget, so a budget with more digits than the one `needed` was measured
/// at needs as many more code units.
pub(crate) fn working_budget(body: &str, mut needed: usize, own: resume::Own<'_>) -> usize {
    for _ in 0..4 {
        match resume::pack(body, needed, own) {
            Err(PackError::OverBudget { needed: more, .. }) if more > needed => needed = more,
            _ => break,
        }
    }
    needed
}

/// Requests to `memproved`, with the token found for the hook (P4-G:
/// and for `mcp serve`, ADR 0014 E7.8).
pub(crate) struct Reader {
    socket: PathBuf,
    token: String,
    /// P4-G: the only operations this reader sends, when restricted.
    allowed: Option<&'static [OperationId]>,
}

impl Reader {
    /// The data directory (`MEMPROVE_DATA_DIR`, else the `data-dir` file
    /// of the configuration directory), its socket, and the token
    /// (`MEMPROVE_TOKEN`, `MEMPROVE_TOKEN_FILE`, else the `token` file
    /// of the configuration directory).
    ///
    /// # Errors
    ///
    /// Which of them is missing or unusable.
    pub(crate) fn new(environment: &Environment, store: &ContextStore) -> Result<Self, ReachError> {
        let data_dir = match environment.data_dir.as_ref().filter(|dir| !dir.is_empty()) {
            Some(dir) => PathBuf::from(dir),
            None => configured_data_dir(&store.config_dir)?,
        };
        let socket = data_dir.join(SOCKET_FILE_NAME);
        if fs::symlink_metadata(&socket).is_err() {
            return Err(ReachError::DaemonNotRunning);
        }
        let token = match resolve_token(
            None,
            environment.token.clone(),
            environment.token_file.clone(),
        ) {
            Ok(Some(token)) => token,
            Ok(None) => match configured_token(&store.config_dir) {
                Ok(Some(token)) => token,
                Ok(None) => return Err(ReachError::NoToken),
                Err(_) => return Err(ReachError::TokenUnusable),
            },
            Err(_) => return Err(ReachError::TokenUnusable),
        };
        Ok(Self {
            socket,
            token,
            allowed: None,
        })
    }

    /// U6 K3 (U5 N4): whether `text` holds the whole token this reader
    /// holds, in whatever format; nothing is sent.
    pub(crate) fn token_in(&self, text: &str) -> bool {
        !self.token.is_empty() && text.contains(&self.token)
    }

    /// P4-G: the same reader, refusing every operation outside `allowed`
    /// before anything is sent (ADR 0014 E7.5.1).
    #[must_use]
    pub(crate) const fn only(mut self, allowed: &'static [OperationId]) -> Self {
        self.allowed = Some(allowed);
        self
    }

    /// Sends one request.
    ///
    /// # Errors
    ///
    /// How it failed, a Problem response included.
    pub(crate) fn send(&self, request: &Request) -> Result<Reply, ReadError> {
        let fail = |failure| ReadError {
            operation: request.operation,
            failure,
        };
        if self
            .allowed
            .is_some_and(|allowed| !allowed.contains(&request.operation))
        {
            return Err(fail(ReadFailure::NotAllowed));
        }
        match call(&self.socket, request, Some(&self.token)) {
            Ok(reply) if reply.is_success() => Ok(reply),
            Ok(reply) => Err(fail(ReadFailure::Refused {
                status: reply.status,
                code: plain_code(&reply),
                detail: reply.problem_detail(),
            })),
            Err(CallError::Transport { .. }) => Err(fail(ReadFailure::Unreachable)),
            Err(CallError::InvalidToken) => Err(fail(ReadFailure::InvalidToken)),
            Err(CallError::Contract(_) | CallError::ResponseTooLarge { .. }) => {
                Err(fail(ReadFailure::BadResponse))
            }
        }
    }

    /// One read request.
    fn get(&self, operation: OperationId, target: String) -> Result<Reply, ReadError> {
        self.send(&Request::bare(operation, target))
    }

    /// P4-G: every Task of `project` as `listTasks` lists it, page by page
    /// (at most 100 pages of 500).
    ///
    /// # Errors
    ///
    /// How a request failed.
    pub(crate) fn tasks(&self, project: &str) -> Result<Vec<JsonValue>, ReadError> {
        let mut tasks = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..100 {
            let mut target = format!("/v1/tasks?project_id={project}&limit=500");
            if let Some(cursor) = &cursor {
                target.push_str("&cursor=");
                target.push_str(cursor);
            }
            let page =
                parse_strict(&self.get(OperationId::ListTasks, target)?.body).map_err(|_| {
                    ReadError {
                        operation: OperationId::ListTasks,
                        failure: ReadFailure::BadResponse,
                    }
                })?;
            tasks.extend(
                page.get("items")
                    .and_then(JsonValue::as_array)
                    .unwrap_or_default()
                    .iter()
                    .cloned(),
            );
            match page.get("next_cursor").and_then(JsonValue::as_str) {
                Some(next) if is_uuid_v7(next) => cursor = Some(next.to_owned()),
                _ => break,
            }
        }
        Ok(tasks)
    }
}

impl Reads for Reader {
    fn capsule(&self, task: &str, workspace: &str) -> Result<String, ReadError> {
        self.get(
            OperationId::GetTaskCapsule,
            format!("/v1/tasks/{task}/recovery-capsule?workspace_id={workspace}"),
        )
        .map(|reply| reply.body)
    }

    fn listing(&self, project: &str, workspace: &str) -> Result<Listing, ReadError> {
        let mut listing = Listing::default();
        for item in self.tasks(project)? {
            let text = |name: &str| item.get(name).and_then(JsonValue::as_str);
            let Some(task) = text("task_id").filter(|task| is_uuid_v7(task)) else {
                continue;
            };
            match text("state") {
                Some("in_progress") => listing
                    .in_progress
                    .push((task.to_owned(), text("workspace_id") == Some(workspace))),
                Some(state) if FINISHED_STATES.contains(&state) => {
                    listing.finished.push(task.to_owned());
                }
                _ => {}
            }
        }
        Ok(listing)
    }
}

/// The Problem code of a refused reply when it is a plain identifier
/// (never the detail).
fn plain_code(reply: &Reply) -> Option<String> {
    reply.problem_code().filter(|code| {
        !code.is_empty()
            && code.len() <= 64
            && code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    })
}

/// U5 Z-F round 1 (S2, the Owner's S2 decision): the data directory
/// `<config_dir>/data-dir` names, one absolute path on one line (ADR 0014
/// E4). The one rule of the hook and `mcp serve` ([`Reader::new`]), the CLI
/// ([`configured_location`]), and `doctor`, for when `MEMPROVE_DATA_DIR`
/// (or an option) names none.
///
/// # Errors
///
/// [`ReachError::NoDataDir`] when the file does not exist,
/// [`ReachError::DataDirUnreadable`] or [`ReachError::DataDirMalformed`].
pub fn configured_data_dir(config_dir: &Path) -> Result<PathBuf, ReachError> {
    data_dir_file(&config_dir.join(DATA_DIR_FILE_NAME))
}

/// U5 Z-F round 1 (S2): the token of `<config_dir>/token` (mode 0600, one
/// token on one line), `Ok(None)` when that file does not exist; the
/// fallback of the hook, `mcp serve`, the CLI, and `doctor` when no
/// `--token-file`, `MEMPROVE_TOKEN`, or `MEMPROVE_TOKEN_FILE` names one.
///
/// # Errors
///
/// When the file exists and is unusable ([`read_token_file`]).
pub fn configured_token(config_dir: &Path) -> Result<Option<String>, crate::TokenSourceError> {
    let file = config_dir.join(TOKEN_FILE_NAME);
    if fs::symlink_metadata(&file).is_err() {
        return Ok(None);
    }
    read_token_file(&file).map(Some)
}

/// U6 K1 (U5 ZR1): what the CLI says when no token source gave a token, for
/// a command that needs one: every place it looked, by variable name and
/// file path, never a file's contents; `config` being the configuration
/// directory and the variable it came from ([`configuration_dir`]). Nothing
/// was sent.
#[must_use]
pub fn missing_token(config: Option<(&Path, &str)>) -> String {
    const LOOKED: &str = "no token: --token-file was not given; MEMPROVE_TOKEN is not set or \
                          is empty; MEMPROVE_TOKEN_FILE is not set or is empty";
    const GIVE: &str = "Give one with --token-file <PATH>, MEMPROVE_TOKEN, or \
                        MEMPROVE_TOKEN_FILE";
    match config {
        Some((dir, source)) => {
            let file = shown_path(&dir.join(TOKEN_FILE_NAME));
            format!(
                "{LOOKED}; {file} does not exist {}; nothing was sent. {GIVE}, or put it in \
                 {file} (mode 0600)",
                configured_from(dir, source)
            )
        }
        None => format!(
            "{LOOKED}; there is no configuration directory to read a {TOKEN_FILE_NAME} file \
             from ({CONFIG_DIR_VARIABLE}, XDG_CONFIG_HOME, and HOME are all unset); nothing was \
             sent. {GIVE}"
        ),
    }
}

/// U5 Z-F round 1 (S2): `(the configuration directory is <dir>, from
/// <source>)`, with `; MEMPROVE_CONFIG_DIR is not set` for a default
/// directory: where a statement about one of its files says the directory
/// came from.
#[must_use]
pub fn configured_from(dir: &Path, source: &str) -> String {
    if source == CONFIG_DIR_VARIABLE {
        format!(
            "(the configuration directory is {}, from {source})",
            shown_path(dir)
        )
    } else {
        format!(
            "(the configuration directory is {}, from {source}; {CONFIG_DIR_VARIABLE} is not set)",
            shown_path(dir)
        )
    }
}

/// U5 Z-F round 1 (S2): the CLI's fallback for the daemon's location when
/// no `--data-dir`, `--socket`, or `MEMPROVE_DATA_DIR` names one: the data
/// directory `<config>/data-dir` names ([`configured_data_dir`]), `config`
/// being the configuration directory and the variable it came from
/// ([`configuration_dir`]). Else the clause the usage error adds: which file
/// was read and why it named none, or that there is no configuration
/// directory. It never holds a token.
///
/// # Errors
///
/// That clause.
pub fn configured_location(config: Option<(&Path, &str)>) -> Result<PathBuf, String> {
    let Some((dir, source)) = config else {
        return Err(format!(
            "there is no configuration directory to read a {DATA_DIR_FILE_NAME} file from \
             ({CONFIG_DIR_VARIABLE}, XDG_CONFIG_HOME, and HOME are all unset)"
        ));
    };
    configured_data_dir(dir).map_err(|error| {
        let why = match error {
            ReachError::NoDataDir => "does not exist",
            ReachError::DataDirMalformed => "is not one absolute path on one line",
            _ => "cannot be read",
        };
        format!(
            "{} {why} {}",
            shown_path(&dir.join(DATA_DIR_FILE_NAME)),
            configured_from(dir, source)
        )
    })
}

/// The data directory the file `path` names: one absolute path on one line.
fn data_dir_file(path: &Path) -> Result<PathBuf, ReachError> {
    let mut text = String::new();
    match File::open(path) {
        Ok(file) => file
            .take(MAX_DATA_DIR_FILE_BYTES)
            .read_to_string(&mut text)
            .map_err(|_| ReachError::DataDirUnreadable)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ReachError::NoDataDir);
        }
        Err(_) => return Err(ReachError::DataDirUnreadable),
    };
    let line = text.strip_suffix('\n').unwrap_or(&text);
    if line.is_empty() || line.contains(['\n', '\r']) || !Path::new(line).is_absolute() {
        return Err(ReachError::DataDirMalformed);
    }
    Ok(PathBuf::from(line))
}

/// What `install` or `uninstall` did to the settings file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The file was written.
    Written(PathBuf),
    /// The file already said what was asked; it was not touched.
    Unchanged(PathBuf),
}

/// The absolute, canonical path of this executable, as text.
///
/// # Errors
///
/// When it cannot be found or is not UTF-8.
pub fn executable() -> Result<String, String> {
    let path = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("cannot find this executable: {error}"))?;
    path.into_os_string()
        .into_string()
        .map_err(|_| "the path of this executable is not UTF-8".to_owned())
}

/// The settings file of the Workspace root of `cwd`.
///
/// # Errors
///
/// When `cwd` cannot be resolved.
pub fn settings_path(cwd: &Path) -> Result<PathBuf, String> {
    workspace_root(cwd)
        .map(|root| root.join(SETTINGS_FILE))
        .map_err(|error| format!("cannot resolve the current directory: {error}"))
}

/// The handler of `hook session-start`: the exec form, `executable` with
/// the arguments `hook session-start`, followed (U7 P2, Owner O4) by
/// `--config-dir <config_dir>` when given.
fn own_group(executable: &str, config_dir: Option<&str>) -> JsonValue {
    let text = |value: &str| JsonValue::String(value.to_owned());
    let member = |name: &str, value: JsonValue| (name.to_owned(), value);
    JsonValue::Object(vec![member(
        "hooks",
        JsonValue::Array(vec![JsonValue::Object(vec![
            member("type", text("command")),
            member("command", text(executable)),
            member(
                "args",
                JsonValue::Array(
                    ["hook", "session-start"]
                        .into_iter()
                        .chain(
                            config_dir
                                .map(|dir| [crate::CONFIG_DIR_OPTION, dir])
                                .into_iter()
                                .flatten(),
                        )
                        .map(text)
                        .collect(),
                ),
            ),
            member(
                "timeout",
                JsonValue::Number(HANDLER_TIMEOUT_SECONDS.to_string()),
            ),
        ])]),
    )])
}

/// What `hook print-config` prints: the settings fragment, as indented JSON.
/// U8 K2 (U7 V-N2): the handler passes `--config-dir <config_dir>` after
/// `hook session-start`, as `hook install` writes it and `mcp print-config`
/// prints it. U9 K3 (U8 V-N9): and `env.MEMPROVE_CONFIG_DIR`, the entry
/// `hook install` writes beside the handler ([`with_enabling`]).
#[must_use]
pub fn config_fragment(executable: &str, config_dir: &str) -> String {
    let fragment = JsonValue::Object(vec![
        (
            "hooks".to_owned(),
            JsonValue::Object(vec![(
                "SessionStart".to_owned(),
                JsonValue::Array(vec![own_group(executable, Some(config_dir))]),
            )]),
        ),
        ("env".to_owned(), config_env(config_dir)),
    ]);
    let mut text = String::new();
    pretty(&fragment, 0, &mut text);
    text.push('\n');
    text
}

/// U5 P3 (Owner O5): `mcpServers.memprove` of the fragment: the stdio
/// server `executable mcp serve` with `env.MEMPROVE_CONFIG_DIR` set to
/// `config_dir`.
fn server_entry(executable: &str, config_dir: &str) -> JsonValue {
    let text = |value: &str| JsonValue::String(value.to_owned());
    JsonValue::Object(vec![
        ("type".to_owned(), text("stdio")),
        ("command".to_owned(), text(executable)),
        // U7 P2 (Owner O4): the directory as an argument, which wins over
        // the environment Claude Code starts the server in; `env` stays.
        (
            "args".to_owned(),
            JsonValue::Array(
                ["mcp", "serve", crate::CONFIG_DIR_OPTION, config_dir]
                    .into_iter()
                    .map(text)
                    .collect(),
            ),
        ),
        ("env".to_owned(), config_env(config_dir)),
    ])
}

/// `{"MEMPROVE_CONFIG_DIR": config_dir}`.
fn config_env(config_dir: &str) -> JsonValue {
    JsonValue::Object(vec![(
        CONFIG_DIR_VARIABLE.to_owned(),
        JsonValue::String(config_dir.to_owned()),
    )])
}

/// U5 P3 (D1 F1, F5, Owner O5; U5 Z-F round 1, S1): the enabling part of
/// `.claude/settings.local.json`, in this order: `hooks.SessionStart` (the
/// handler of [`config_fragment`]), `env.MEMPROVE_CONFIG_DIR`, and the
/// suggested `permissions.allow` ([`allow_rules`], U7 P3: with the rule of
/// `executable`'s absolute path); no `mcpServers`, which
/// Claude Code does not read from a settings file (the server's entry is
/// [`mcp_json_fragment`]). `mcp print-config` prints it; `install` writes
/// the first two, and the third with `--allow-tools`.
#[must_use]
pub fn settings_fragment(executable: &str, config_dir: &str) -> String {
    let fragment = JsonValue::Object(vec![
        (
            "hooks".to_owned(),
            JsonValue::Object(vec![(
                "SessionStart".to_owned(),
                JsonValue::Array(vec![own_group(executable, Some(config_dir))]),
            )]),
        ),
        ("env".to_owned(), config_env(config_dir)),
        (
            "permissions".to_owned(),
            JsonValue::Object(vec![(
                "allow".to_owned(),
                JsonValue::Array(
                    allow_rules(executable)
                        .into_iter()
                        .map(JsonValue::String)
                        .collect(),
                ),
            )]),
        ),
    ]);
    let mut text = String::new();
    pretty(&fragment, 0, &mut text);
    text.push('\n');
    text
}

/// U5 Z-F round 1 (S1, Owner's O5 revision): the enabling part of
/// `<Workspace root>/.mcp.json`, the file Claude Code reads project-scoped
/// MCP servers from: `mcpServers.memprove`, the stdio server `executable
/// mcp serve` with `env.MEMPROVE_CONFIG_DIR` set to `config_dir`.
/// `mcp print-config` prints it; `install` writes it.
#[must_use]
pub fn mcp_json_fragment(executable: &str, config_dir: &str) -> String {
    let fragment = JsonValue::Object(vec![(
        "mcpServers".to_owned(),
        JsonValue::Object(vec![(
            "memprove".to_owned(),
            server_entry(executable, config_dir),
        )]),
    )]);
    let mut text = String::new();
    pretty(&fragment, 0, &mut text);
    text.push('\n');
    text
}

/// U7 P2 (Owner O4): whether `args` are `<first> <second>`, or that and
/// `--config-dir <DIR>` (an entry an earlier install wrote, and one of now).
fn own_args(args: Option<&[JsonValue]>, first: &str, second: &str) -> bool {
    args.is_some_and(|args| {
        let words = args.iter().map(JsonValue::as_str).collect::<Vec<_>>();
        match words.as_slice() {
            [Some(a), Some(b)] => *a == first && *b == second,
            [Some(a), Some(b), Some(option), Some(_)] => {
                *a == first && *b == second && *option == crate::CONFIG_DIR_OPTION
            }
            _ => false,
        }
    })
}

/// Whether `command` names a program called `memprove` or (U20 T1) by
/// [`PREVIOUS_NAME`], wherever it lives.
fn is_own_program(command: &str) -> bool {
    Path::new(command)
        .file_name()
        .is_some_and(|name| name == "memprove" || name == PREVIOUS_NAME)
}

/// Whether `entry` is an MCP server entry `install` wrote: the program
/// `memprove` (U20 T1: or of the previous name), wherever it lives, with
/// the arguments `mcp serve` (U7 P2: and `--config-dir <DIR>` or not).
fn is_own_server(entry: &JsonValue) -> bool {
    own_args(
        entry.get("args").and_then(JsonValue::as_array),
        "mcp",
        "serve",
    ) && entry
        .get("command")
        .and_then(JsonValue::as_str)
        .is_some_and(is_own_program)
}

/// U20 T1 (U19-O2): whether `rule` is one that `--allow-tools` wrote under
/// the previous name: `mcp__continuity`, `Bash(continuity run:*)`, or
/// `Bash(<absolute path of a program named continuity> run:*)`.
fn is_previous_rule(rule: &str) -> bool {
    rule.strip_prefix("mcp__") == Some(PREVIOUS_NAME)
        || rule
            .strip_prefix("Bash(")
            .and_then(|rest| rest.strip_suffix(" run:*)"))
            .is_some_and(|program| {
                let path = Path::new(program);
                program == PREVIOUS_NAME
                    || (path.is_absolute()
                        && path.file_name().is_some_and(|name| name == PREVIOUS_NAME))
            })
}

/// The members of the object `name` of `members`: empty when absent, an
/// error when it is not an object.
fn object_of(
    members: &[(String, JsonValue)],
    name: &str,
) -> Result<Vec<(String, JsonValue)>, String> {
    match members.iter().find(|(seen, _)| seen == name) {
        None => Ok(Vec::new()),
        Some((_, JsonValue::Object(inner))) => Ok(inner.clone()),
        Some(_) => Err(format!("its \"{name}\" is not a JSON object")),
    }
}

/// Sets `name` to `value` in `members`, in its place when it is there, else
/// last.
fn set(members: &mut Vec<(String, JsonValue)>, name: &str, value: JsonValue) {
    match members.iter_mut().find(|(seen, _)| seen == name) {
        Some((_, old)) => *old = value,
        None => members.push((name.to_owned(), value)),
    }
}

/// U5 P3: `settings` with `env.MEMPROVE_CONFIG_DIR` set as
/// [`settings_fragment`] has it, and, when `allow_tools`, each rule of
/// [`allow_rules`] of `executable` (U7 P3) that `permissions.allow` does
/// not hold yet added after the ones it holds. U5 Z-F round 1 (S1): without an
/// `mcpServers.memprove` that `install` wrote there before
/// ([`is_own_server`]); the server's entry belongs in `.mcp.json`
/// ([`with_server`]). U20 T1 (U19-O2): without
/// [`PREVIOUS_CONFIG_DIR_VARIABLE`] in `env`, and, when `allow_tools`,
/// without the rules of the previous name ([`is_previous_rule`]).
fn with_enabling(
    settings: &JsonValue,
    executable: &str,
    config_dir: &str,
    allow_tools: bool,
) -> Result<JsonValue, String> {
    let JsonValue::Object(members) = settings else {
        return Err("its top level is not a JSON object".to_owned());
    };
    let mut members = members.clone();
    let mut env = object_of(&members, "env")?;
    env.retain(|(name, _)| name != PREVIOUS_CONFIG_DIR_VARIABLE);
    set(
        &mut env,
        CONFIG_DIR_VARIABLE,
        JsonValue::String(config_dir.to_owned()),
    );
    set(&mut members, "env", JsonValue::Object(env));
    drop_from(&mut members, "mcpServers", is_own_server_member)?;
    if allow_tools {
        let mut permissions = object_of(&members, "permissions")?;
        let mut allow = match permissions.iter().find(|(name, _)| name == "allow") {
            None => Vec::new(),
            Some((_, JsonValue::Array(rules))) => rules.clone(),
            Some(_) => return Err("its \"permissions\".\"allow\" is not a JSON array".to_owned()),
        };
        allow.retain(|rule| !rule.as_str().is_some_and(is_previous_rule));
        for rule in allow_rules(executable) {
            if !allow
                .iter()
                .any(|seen| seen.as_str() == Some(rule.as_str()))
            {
                allow.push(JsonValue::String(rule));
            }
        }
        set(&mut permissions, "allow", JsonValue::Array(allow));
        set(&mut members, "permissions", JsonValue::Object(permissions));
    }
    Ok(JsonValue::Object(members))
}

/// U5 P3: `settings` without `env.MEMPROVE_CONFIG_DIR` and without an
/// `mcpServers.memprove` that `install` wrote ([`is_own_server`]; U5 Z-F
/// round 1: an earlier build wrote it there); an `env` or `mcpServers`
/// object that only this emptied goes with it. `permissions` is left as it
/// is: the rules are the operator's. U20 T1 (U19-O2): the variable and the
/// entry of the previous name go too.
fn without_enabling(settings: &JsonValue) -> Result<JsonValue, String> {
    let JsonValue::Object(members) = settings else {
        return Err("its top level is not a JSON object".to_owned());
    };
    let mut members = members.clone();
    drop_from(&mut members, "env", |(name, _)| {
        name == CONFIG_DIR_VARIABLE || name == PREVIOUS_CONFIG_DIR_VARIABLE
    })?;
    drop_from(&mut members, "mcpServers", is_own_server_member)?;
    Ok(JsonValue::Object(members))
}

/// Whether a member of `mcpServers` is the `memprove` entry `install`
/// wrote, or (U20 T1) the `continuity` entry an installation of the
/// previous name wrote.
fn is_own_server_member(member: &(String, JsonValue)) -> bool {
    (member.0 == "memprove" && is_own_server(&member.1)) || is_previous_server_member(member)
}

/// U20 T1 (U19-O2): whether a member of `mcpServers` is the entry an
/// installation of the previous name wrote: `continuity`, running a program
/// of that name or `memprove` with `mcp serve`.
fn is_previous_server_member((name, entry): &(String, JsonValue)) -> bool {
    name == PREVIOUS_NAME && is_own_server(entry)
}

/// U5 Z-F round 1 (S1): `mcp_json` (the value of `.mcp.json`) with
/// `mcpServers.memprove` set as [`mcp_json_fragment`] has it, in its
/// place when it is there, else last; everything else is kept. U20 T1
/// (U19-O2): without the entry of the previous name
/// ([`is_previous_server_member`]).
fn with_server(
    mcp_json: &JsonValue,
    executable: &str,
    config_dir: &str,
) -> Result<JsonValue, String> {
    let JsonValue::Object(members) = mcp_json else {
        return Err("its top level is not a JSON object".to_owned());
    };
    let mut members = members.clone();
    let mut servers = object_of(&members, "mcpServers")?;
    servers.retain(|member| !is_previous_server_member(member));
    set(
        &mut servers,
        "memprove",
        server_entry(executable, config_dir),
    );
    set(&mut members, "mcpServers", JsonValue::Object(servers));
    Ok(JsonValue::Object(members))
}

/// U5 Z-F round 1 (S1): `mcp_json` without an `mcpServers.memprove` that
/// `install` wrote; an `mcpServers` object that only this emptied goes
/// with it.
fn without_server(mcp_json: &JsonValue) -> Result<JsonValue, String> {
    let JsonValue::Object(members) = mcp_json else {
        return Err("its top level is not a JSON object".to_owned());
    };
    let mut members = members.clone();
    drop_from(&mut members, "mcpServers", is_own_server_member)?;
    Ok(JsonValue::Object(members))
}

/// Removes the members of the object `name` of `members` that `remove`
/// takes; the object goes too when that empties it.
fn drop_from(
    members: &mut Vec<(String, JsonValue)>,
    name: &str,
    remove: impl Fn(&(String, JsonValue)) -> bool,
) -> Result<(), String> {
    let inner = object_of(members, name)?;
    if !inner.iter().any(&remove) {
        return Ok(());
    }
    let kept = inner
        .into_iter()
        .filter(|member| !remove(member))
        .collect::<Vec<_>>();
    if kept.is_empty() {
        members.retain(|(seen, _)| seen != name);
    } else {
        set(members, name, JsonValue::Object(kept));
    }
    Ok(())
}

/// Whether `handler` is a handler `install` wrote: a command handler whose
/// arguments are exactly `hook session-start` (U7 P2: with or without
/// `--config-dir <DIR>`) and whose program is named `memprove` (U20 T1:
/// or [`PREVIOUS_NAME`]), wherever it lives.
fn is_own(handler: &JsonValue) -> bool {
    let args = handler.get("args").and_then(JsonValue::as_array);
    handler.get("type").and_then(JsonValue::as_str) == Some("command")
        && own_args(args, "hook", "session-start")
        && handler
            .get("command")
            .and_then(JsonValue::as_str)
            .is_some_and(is_own_program)
}

/// `settings` without the handlers `install` wrote, and with `add` as the
/// last `SessionStart` group when given. A group, a `SessionStart` list, or
/// a `hooks` object that only the removal emptied is removed with it;
/// everything else is kept as it was, in its order.
fn edit(settings: &JsonValue, add: Option<JsonValue>) -> Result<JsonValue, String> {
    edit_event(settings, "SessionStart", add, is_own)
}

/// U24 (H1): [`edit`] for the groups of `event`, with `own` saying which
/// handlers `install` wrote: Claude Code's `SessionStart` and its exec-form
/// handler, or Codex's `SessionStart` and its shell-form handler
/// ([`is_own_shell_handler`]).
fn edit_event(
    settings: &JsonValue,
    event: &str,
    add: Option<JsonValue>,
    own: fn(&JsonValue) -> bool,
) -> Result<JsonValue, String> {
    let JsonValue::Object(members) = settings else {
        return Err("its top level is not a JSON object".to_owned());
    };
    let mut members = members.clone();
    let hooks_at = members.iter().position(|(name, _)| name == "hooks");
    let mut hooks = match hooks_at.map(|index| &members[index].1) {
        None => Vec::new(),
        Some(JsonValue::Object(hooks)) => hooks.clone(),
        Some(_) => return Err("its \"hooks\" is not a JSON object".to_owned()),
    };
    let start_at = hooks.iter().position(|(name, _)| name == event);
    let groups = match start_at.map(|index| &hooks[index].1) {
        None => Vec::new(),
        Some(JsonValue::Array(groups)) => groups.clone(),
        Some(_) => return Err(format!("its \"hooks\".\"{event}\" is not a JSON array")),
    };
    let had_groups = !groups.is_empty();
    let mut kept = Vec::new();
    for group in groups {
        let JsonValue::Object(fields) = &group else {
            kept.push(group);
            continue;
        };
        let Some((index, JsonValue::Array(handlers))) = fields
            .iter()
            .enumerate()
            .find(|(_, (name, _))| name == "hooks")
            .map(|(index, (_, value))| (index, value))
        else {
            kept.push(group);
            continue;
        };
        let remaining = handlers
            .iter()
            .filter(|handler| !own(handler))
            .cloned()
            .collect::<Vec<_>>();
        if remaining.len() == handlers.len() {
            kept.push(group);
        } else if !remaining.is_empty() {
            let mut fields = fields.clone();
            fields[index].1 = JsonValue::Array(remaining);
            kept.push(JsonValue::Object(fields));
        }
    }
    if let Some(group) = add {
        kept.push(group);
    }
    let emptied = had_groups && kept.is_empty();
    match start_at {
        Some(index) if emptied => {
            hooks.remove(index);
        }
        Some(index) => hooks[index].1 = JsonValue::Array(kept),
        None if kept.is_empty() => {}
        None => hooks.push((event.to_owned(), JsonValue::Array(kept))),
    }
    match hooks_at {
        Some(index) if emptied && hooks.is_empty() => {
            members.remove(index);
        }
        Some(index) => members[index].1 = JsonValue::Object(hooks),
        None if hooks.is_empty() => {}
        None => members.push(("hooks".to_owned(), JsonValue::Object(hooks))),
    }
    Ok(JsonValue::Object(members))
}

/// Reads the settings file (U5 Z-F round 1: or `.mcp.json`): `None` when
/// it does not exist.
fn read_settings(path: &Path) -> Result<Option<JsonValue>, String> {
    let refuse = |why: String| format!("{} is refused and left unchanged: {why}", path.display());
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(file) => {
            file.take(MAX_SETTINGS_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| refuse(error.to_string()))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(refuse(error.to_string())),
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SETTINGS_BYTES {
        return Err(refuse("it is larger than 4 MiB".to_owned()));
    }
    let text = String::from_utf8(bytes).map_err(|_| refuse("it is not UTF-8".to_owned()))?;
    parse_strict(&text)
        .map(Some)
        .map_err(|error| refuse(format!("it is not valid JSON ({error})")))
}

/// Writes `value` to `path` atomically, keeping the file's mode (0600 for a
/// new file); creates its directory when missing. The temporary file is
/// `.<file name>.tmp-<pid>` next to it.
fn write_settings(path: &Path, value: &JsonValue) -> Result<(), String> {
    let fail = |error: io::Error| format!("{} was not written: {error}", path.display());
    let directory = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(directory).map_err(fail)?;
    let mode = fs::metadata(path).map_or(0o600, |metadata| metadata.permissions().mode() & 0o777);
    let mut text = String::new();
    pretty(value, 0, &mut text);
    text.push('\n');
    let name = path
        .file_name()
        .map_or_else(|| "settings".into(), |name| name.to_string_lossy());
    let temporary = directory.join(format!(".{name}.tmp-{}", std::process::id()));
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&temporary, path));
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(fail(error));
    }
    Ok(())
}

/// One file `install` or `uninstall` edits: its path, the value read
/// (`None` when it does not exist), and the value to write.
struct Edit {
    path: PathBuf,
    existing: Option<JsonValue>,
    edited: JsonValue,
}

impl Edit {
    /// Reads `path` and applies `change` to its value (`{}` when it does
    /// not exist); refused, with nothing written, when either fails.
    fn of(
        path: &Path,
        change: impl FnOnce(&JsonValue) -> Result<JsonValue, String>,
    ) -> Result<Self, String> {
        let existing = read_settings(path)?;
        let original = existing
            .clone()
            .unwrap_or_else(|| JsonValue::Object(Vec::new()));
        let edited = change(&original)
            .map_err(|why| format!("{} is refused and left unchanged: {why}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            existing,
            edited,
        })
    }

    /// Writes the file unless it already holds the value; `uninstall` does
    /// not create a file that does not exist (`create`).
    fn apply(self, create: bool) -> Result<Change, String> {
        match &self.existing {
            Some(existing) if *existing == self.edited => return Ok(Change::Unchanged(self.path)),
            None if !create => return Ok(Change::Unchanged(self.path)),
            _ => {}
        }
        write_settings(&self.path, &self.edited)?;
        Ok(Change::Written(self.path))
    }
}

/// `hook install`: adds the handler of `executable` to the settings file
/// `settings` once, keeping everything else (Owner condition p). U5 P3
/// (Owner O5): also `env.MEMPROVE_CONFIG_DIR` (`config_dir`), and with
/// `allow_tools` the rules of [`allow_rules`] in `permissions.allow`
/// ([`with_enabling`]). U5 Z-F round 1 (S1, Owner's O5 revision):
/// `mcpServers.memprove` goes into `mcp_json` (`<Workspace root>/.mcp.json`,
/// [`with_server`]), keeping everything else there too, and one an
/// earlier build wrote into the settings file is taken out of it. Both
/// files are read and edited before either is written.
///
/// # Errors
///
/// When a file is not valid JSON or not shaped as settings (both are left
/// unchanged), or cannot be written.
pub fn install(
    settings: &Path,
    mcp_json: &Path,
    executable: &str,
    config_dir: &str,
    allow_tools: bool,
) -> Result<[Change; 2], String> {
    let settings = Edit::of(settings, |original| {
        edit(original, Some(own_group(executable, Some(config_dir))))
            .and_then(|edited| with_enabling(&edited, executable, config_dir, allow_tools))
    })?;
    let mcp_json = Edit::of(mcp_json, |original| {
        with_server(original, executable, config_dir)
    })?;
    Ok([settings.apply(true)?, mcp_json.apply(true)?])
}

/// U17 (M1 O4): `mcp_json` (a client's `mcp.json`, such as Cursor's
/// `.cursor/mcp.json`) with `mcpServers.memprove` as [`with_server`] sets
/// it, everything else kept; the file is created when it does not exist.
///
/// # Errors
///
/// As [`install`].
pub fn install_mcp_json(
    mcp_json: &Path,
    executable: &str,
    config_dir: &str,
) -> Result<Change, String> {
    Edit::of(mcp_json, |original| {
        with_server(original, executable, config_dir)
    })?
    .apply(true)
}

/// U24 (H1): the file Codex reads a project's hooks from, relative to the
/// Workspace root. Codex loads it only for a project it trusts, and runs a
/// handler only after the user trusted it (`/hooks` in Codex).
pub const CODEX_HOOKS_FILE: &str = ".codex/hooks.json";

/// U24 (H2): the file Cursor reads a project's hooks from, relative to the
/// Workspace root.
pub const CURSOR_HOOKS_FILE: &str = ".cursor/hooks.json";

/// U24 (H2): the option and value of `hook session-start` in the handler
/// `init` writes for Cursor: Cursor's `sessionStart` input, and its answer
/// as JSON.
pub const CURSOR_CLIENT_ARGUMENTS: [&str; 2] = ["--client", "cursor"];

/// `text` as one word of a POSIX shell command line: in single quotes, a
/// single quote as `'\''`.
fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// U24 (H1, H2): the command line of the handler for a client that runs a
/// hook's command through a shell (Codex, Cursor): `'<executable>' hook
/// session-start`, then `--client cursor` for Cursor, then `--config-dir
/// '<config_dir>'`.
#[must_use]
pub fn shell_command(executable: &str, config_dir: &str, cursor: bool) -> String {
    let mut command = format!("{} hook session-start", shell_word(executable));
    if cursor {
        command.push(' ');
        command.push_str(&CURSOR_CLIENT_ARGUMENTS.join(" "));
    }
    command.push(' ');
    command.push_str(crate::CONFIG_DIR_OPTION);
    command.push(' ');
    command.push_str(&shell_word(config_dir));
    command
}

/// The first word of the shell command line `command` as a POSIX shell
/// reads it (quotes and backslashes taken out), and the text after it;
/// `None` when a quote is left open.
fn first_shell_word(command: &str) -> Option<(String, &str)> {
    let command = command.trim_start();
    let mut word = String::new();
    let mut quote = None;
    let mut chars = command.char_indices();
    while let Some((index, character)) = chars.next() {
        match (quote, character) {
            (None, '\'' | '"') => quote = Some(character),
            (Some(open), character) if character == open => quote = None,
            (None | Some('"'), '\\') => word.push(chars.next()?.1),
            (None, character) if character.is_whitespace() => {
                return Some((word, &command[index..]));
            }
            (_, character) => word.push(character),
        }
    }
    quote.is_none().then_some((word, ""))
}

/// U24 (H1, H2): whether `handler` is a shell-form handler `init` wrote: a
/// command (Cursor's `type` may be left out) whose program is `memprove`
/// (or of [`PREVIOUS_NAME`]), wherever it lives, with the words `hook
/// session-start` after it.
fn is_own_shell_handler(handler: &JsonValue) -> bool {
    handler
        .get("type")
        .is_none_or(|kind| kind.as_str() == Some("command"))
        && handler
            .get("command")
            .and_then(JsonValue::as_str)
            .and_then(first_shell_word)
            .is_some_and(|(program, rest)| {
                is_own_program(&program)
                    && rest
                        .split_whitespace()
                        .take(2)
                        .eq(["hook", "session-start"])
            })
}

/// U24 (H1): the `SessionStart` group of `.codex/hooks.json`: no matcher
/// (every source, as Claude Code's group), one command handler with the
/// [`HANDLER_TIMEOUT_SECONDS`] timeout, and `additionalContextLimit` 0, so
/// that Codex gives the model the whole output (at most
/// [`MAX_OUTPUT_UNITS`]) instead of spilling it to a file past its default
/// of about 2,500 tokens.
fn codex_group(executable: &str, config_dir: &str) -> JsonValue {
    let member = |name: &str, value: JsonValue| (name.to_owned(), value);
    JsonValue::Object(vec![member(
        "hooks",
        JsonValue::Array(vec![JsonValue::Object(vec![
            member("type", JsonValue::String("command".to_owned())),
            member(
                "command",
                JsonValue::String(shell_command(executable, config_dir, false)),
            ),
            member(
                "timeout",
                JsonValue::Number(HANDLER_TIMEOUT_SECONDS.to_string()),
            ),
            member("additionalContextLimit", JsonValue::Number("0".to_owned())),
        ])]),
    )])
}

/// U24 (H2): the `sessionStart` handler of `.cursor/hooks.json`: the shell
/// command with `--client cursor` and the [`HANDLER_TIMEOUT_SECONDS`]
/// timeout.
fn cursor_handler(executable: &str, config_dir: &str) -> JsonValue {
    JsonValue::Object(vec![
        (
            "command".to_owned(),
            JsonValue::String(shell_command(executable, config_dir, true)),
        ),
        (
            "timeout".to_owned(),
            JsonValue::Number(HANDLER_TIMEOUT_SECONDS.to_string()),
        ),
    ])
}

/// U24 (H2): `hooks` (Cursor's `hooks.json`, `{}` when new) with `version`
/// (1 when there is none), and the handler of [`cursor_handler`] as the
/// last of `hooks.sessionStart`, in place of every handler `init` wrote
/// there before; everything else is kept, in its order.
fn with_cursor_handler(
    hooks_file: &JsonValue,
    executable: &str,
    config_dir: &str,
) -> Result<JsonValue, String> {
    let JsonValue::Object(members) = hooks_file else {
        return Err("its top level is not a JSON object".to_owned());
    };
    let mut members = members.clone();
    if !members.iter().any(|(name, _)| name == "version") {
        members.insert(0, ("version".to_owned(), JsonValue::Number("1".to_owned())));
    }
    let mut hooks = match members.iter().find(|(name, _)| name == "hooks") {
        None => Vec::new(),
        Some((_, JsonValue::Object(hooks))) => hooks.clone(),
        Some(_) => return Err("its \"hooks\" is not a JSON object".to_owned()),
    };
    let mut handlers = match hooks.iter().find(|(name, _)| name == "sessionStart") {
        None => Vec::new(),
        Some((_, JsonValue::Array(handlers))) => handlers.clone(),
        Some(_) => return Err("its \"hooks\".\"sessionStart\" is not a JSON array".to_owned()),
    };
    handlers.retain(|handler| !is_own_shell_handler(handler));
    handlers.push(cursor_handler(executable, config_dir));
    set(&mut hooks, "sessionStart", JsonValue::Array(handlers));
    set(&mut members, "hooks", JsonValue::Object(hooks));
    Ok(JsonValue::Object(members))
}

/// U24 (H1): `init` for Codex: the `SessionStart` group of [`codex_group`]
/// in `hooks_file` (`<Workspace root>/.codex/hooks.json`), in place of
/// every handler `init` wrote there before; everything else is kept, and
/// the file is created when it does not exist.
///
/// # Errors
///
/// As [`install`].
pub fn install_codex_hooks(
    hooks_file: &Path,
    executable: &str,
    config_dir: &str,
) -> Result<Change, String> {
    Edit::of(hooks_file, |original| {
        edit_event(
            original,
            "SessionStart",
            Some(codex_group(executable, config_dir)),
            is_own_shell_handler,
        )
    })?
    .apply(true)
}

/// U24 (H2): `init` for Cursor: the handler of [`cursor_handler`] in
/// `hooks_file` (`<Workspace root>/.cursor/hooks.json`), as
/// [`with_cursor_handler`] puts it; the file is created when it does not
/// exist.
///
/// # Errors
///
/// As [`install`].
pub fn install_cursor_hooks(
    hooks_file: &Path,
    executable: &str,
    config_dir: &str,
) -> Result<Change, String> {
    Edit::of(hooks_file, |original| {
        with_cursor_handler(original, executable, config_dir)
    })?
    .apply(true)
}

/// `hook uninstall`: removes the handlers `install` wrote from the settings
/// file `settings`, and nothing else; U5 P3: with them
/// `env.MEMPROVE_CONFIG_DIR` and an `mcpServers.memprove` it wrote
/// ([`without_enabling`]), not the rules of `permissions.allow`. U5 Z-F
/// round 1 (S1): and the `mcpServers.memprove` it wrote into `mcp_json`
/// ([`without_server`]). A file that does not exist is not created; one
/// that only these filled is left holding `{}`.
///
/// # Errors
///
/// As [`install`].
pub fn uninstall(settings: &Path, mcp_json: &Path) -> Result<[Change; 2], String> {
    let settings = Edit::of(settings, |original| {
        edit(original, None).and_then(|edited| without_enabling(&edited))
    })?;
    let mcp_json = Edit::of(mcp_json, without_server)?;
    Ok([settings.apply(false)?, mcp_json.apply(false)?])
}

/// `value` as JSON indented by two spaces per level.
pub(crate) fn pretty(value: &JsonValue, indent: usize, out: &mut String) {
    let pad = |out: &mut String, depth: usize| out.push_str(&" ".repeat(depth));
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        JsonValue::Number(number) => out.push_str(number),
        JsonValue::String(text) => out.push_str(&json_string(text)),
        JsonValue::Array(items) if items.is_empty() => out.push_str("[]"),
        JsonValue::Object(members) if members.is_empty() => out.push_str("{}"),
        JsonValue::Array(items) => {
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                pad(out, indent + 2);
                pretty(item, indent + 2, out);
                out.push_str(if index + 1 < items.len() { ",\n" } else { "\n" });
            }
            pad(out, indent);
            out.push(']');
        }
        JsonValue::Object(members) => {
            out.push_str("{\n");
            for (index, (name, member)) in members.iter().enumerate() {
                pad(out, indent + 2);
                out.push_str(&json_string(name));
                out.push_str(": ");
                pretty(member, indent + 2, out);
                out.push_str(if index + 1 < members.len() {
                    ",\n"
                } else {
                    "\n"
                });
            }
            pad(out, indent);
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hook_input_is_checked_field_by_field() {
        let read = |text: &str| read_start(&mut text.as_bytes()).map(|start| start.source);
        let cwd = std::env::temp_dir();
        let cwd = cwd.to_str().unwrap();
        let good = format!(
            r#"{{"session_id":"abc-DEF_1","cwd":{},"source":"compact","hook_event_name":"SessionStart","extra":[1]}}"#,
            json_string(cwd)
        );
        assert_eq!(read(&good), Ok("compact"));
        for bad in [
            good.replace("abc-DEF_1", "a b"),
            good.replace("abc-DEF_1", "a'b"),
            good.replace("abc-DEF_1", ""),
            good.replace("abc-DEF_1", &"x".repeat(129)),
            good.replace("compact", "boot"),
            good.replace("\"SessionStart\"", "\"Stop\""),
            good.replace(&json_string(cwd), "\"relative\""),
            good.replace("\"abc-DEF_1\"", "7"),
            "[]".to_owned(),
            "{".to_owned(),
        ] {
            assert!(read(&bad).is_err(), "{bad}");
        }
        assert_eq!(
            read(&"x".repeat(MAX_INPUT_BYTES + 1)),
            Err(" exceeds 65536 bytes")
        );
    }

    /// U24 (H1): Codex sends the members Claude Code sends, and more
    /// (`model`, `permission_mode`, a `transcript_path` that may be null);
    /// the hook takes them as it takes Claude Code's.
    #[test]
    fn u24_codex_input_is_read_as_claude_codes() {
        let cwd = std::env::temp_dir();
        let text = format!(
            r#"{{"session_id":"019a2b3c-4d5e-7f60-8a9b-0c1d2e3f4a5b","transcript_path":null,"cwd":{},"hook_event_name":"SessionStart","model":"gpt-5.5-codex","permission_mode":"default","source":"resume"}}"#,
            json_string(cwd.to_str().unwrap())
        );
        let value = read_input(&mut text.as_bytes()).unwrap();
        assert!(!is_cursor_input(&value));
        let start = start_of(&value).unwrap();
        assert_eq!(start.source, "resume");
        assert_eq!(start.session_id, "019a2b3c-4d5e-7f60-8a9b-0c1d2e3f4a5b");
    }

    /// U24 (H2): Cursor's `sessionStart` input: the session from
    /// `session_id` (else `conversation_id`), the Workspace from the first of
    /// `workspace_roots` (else `CURSOR_PROJECT_DIR`), the source `startup`.
    /// The Claude Code handler, which Cursor also runs, prints nothing for
    /// it.
    #[test]
    fn u24_cursor_input_is_read_from_its_own_members() {
        let base = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(base.path()).unwrap();
        let root_text = root.to_str().unwrap();
        let good = format!(
            r#"{{"conversation_id":"c-1","generation_id":"g-1","model":"auto","hook_event_name":"sessionStart","cursor_version":"3.25.6","workspace_roots":[{}],"user_email":null,"transcript_path":null,"session_id":"0b6f2c1e-1111-4a2b-9c3d-123456789abc","is_background_agent":false,"composer_mode":"agent"}}"#,
            json_string(root_text)
        );
        let value = parse_strict(&good).unwrap();
        assert!(is_cursor_input(&value));
        let start = cursor_start_of(&value, None).unwrap();
        assert_eq!(start.session_id, "0b6f2c1e-1111-4a2b-9c3d-123456789abc");
        assert_eq!(start.cwd, root);
        assert_eq!(start.source, "startup");

        let without_session = good.replace(
            r#""session_id":"0b6f2c1e-1111-4a2b-9c3d-123456789abc","#,
            "",
        );
        let start = cursor_start_of(&parse_strict(&without_session).unwrap(), None).unwrap();
        assert_eq!(start.session_id, "c-1");

        let without_roots = good.replace(
            &format!(r#""workspace_roots":[{}],"#, json_string(root_text)),
            "",
        );
        let start = cursor_start_of(
            &parse_strict(&without_roots).unwrap(),
            Some(root.as_os_str()),
        )
        .unwrap();
        assert_eq!(start.cwd, root);

        for bad in [
            good.replace("\"sessionStart\"", "\"SessionStart\""),
            good.replace("0b6f2c1e-1111-4a2b-9c3d-123456789abc", "a b"),
            good.replace(&json_string(root_text), "\"relative\""),
            good.replace(
                &json_string(root_text),
                &json_string(&format!("{root_text}/missing")),
            ),
        ] {
            assert!(
                cursor_start_of(&parse_strict(&bad).unwrap(), None).is_err(),
                "{bad}"
            );
        }

        // The Claude Code handler answers Cursor's input with nothing.
        let environment = Environment::from_process();
        let outcome = session_start(&mut good.as_bytes(), &environment);
        assert_eq!(outcome.finish(), "");
    }

    /// U24 (H2): Cursor reads `{"additional_context": …}`; the text is the
    /// hook's, escaped as a JSON string; nothing stays nothing.
    #[test]
    fn u24_cursor_output_wraps_the_text_in_cursors_json() {
        let text = "memprove: a \"quoted\" word\n```text\nPack\n```\n";
        let output = cursor_output(text);
        assert!(output.ends_with("}\n"), "{output}");
        let value = parse_strict(output.trim_end()).unwrap();
        assert_eq!(
            value.get("additional_context").and_then(JsonValue::as_str),
            Some(text)
        );
        assert_eq!(cursor_output(""), "");
    }

    /// U24 (H1, H2): the shell command line of the Codex and Cursor handlers
    /// quotes both paths, and the handler is recognised again whatever its
    /// path, so that `init` replaces it instead of adding a second.
    #[test]
    fn u24_shell_handlers_quote_their_paths_and_are_recognised() {
        let command = shell_command(
            "/opt/it's here/memprove",
            "/home/me/.memprove/config",
            false,
        );
        assert_eq!(
            command,
            r"'/opt/it'\''s here/memprove' hook session-start --config-dir '/home/me/.memprove/config'"
        );
        assert_eq!(
            first_shell_word(&command),
            Some((
                "/opt/it's here/memprove".to_owned(),
                " hook session-start --config-dir '/home/me/.memprove/config'"
            ))
        );
        assert_eq!(
            shell_command("/bin/memprove", "/c", true),
            "'/bin/memprove' hook session-start --client cursor --config-dir '/c'"
        );
        let handler = |command: &str| {
            JsonValue::Object(vec![(
                "command".to_owned(),
                JsonValue::String(command.to_owned()),
            )])
        };
        for own in [
            command.as_str(),
            "/usr/local/bin/memprove hook session-start",
            "\"/a b/continuity\" hook session-start --config-dir /c",
        ] {
            assert!(is_own_shell_handler(&handler(own)), "{own}");
        }
        for other in [
            "'/bin/memprove' mcp serve",
            "'/bin/memproved' hook session-start",
            "echo memprove hook session-start",
            "'/bin/memprove hook session-start",
        ] {
            assert!(!is_own_shell_handler(&handler(other)), "{other}");
        }
    }

    /// U24 (H1): `.codex/hooks.json` gets one `SessionStart` group with the
    /// handler; a second install changes nothing, and one with another path
    /// replaces the handler; another hook of the file stays.
    #[test]
    fn u24_codex_hooks_file_holds_one_handler_and_keeps_the_rest() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join(".codex").join("hooks.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            r#"{"description":"mine","hooks":{"Stop":[{"hooks":[{"type":"command","command":"say done"}]}]}}"#,
        )
        .unwrap();
        assert!(matches!(
            install_codex_hooks(&path, "/a/memprove", "/a/config").unwrap(),
            Change::Written(_)
        ));
        assert!(matches!(
            install_codex_hooks(&path, "/a/memprove", "/a/config").unwrap(),
            Change::Unchanged(_)
        ));
        assert!(matches!(
            install_codex_hooks(&path, "/b/memprove", "/b/config").unwrap(),
            Change::Written(_)
        ));
        let value = parse_strict(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            value.get("description").and_then(JsonValue::as_str),
            Some("mine")
        );
        let hooks = value.get("hooks").unwrap();
        assert!(hooks.get("Stop").is_some());
        let groups = hooks
            .get("SessionStart")
            .and_then(JsonValue::as_array)
            .unwrap();
        assert_eq!(groups.len(), 1, "{groups:?}");
        let handler = &groups[0]
            .get("hooks")
            .and_then(JsonValue::as_array)
            .unwrap()[0];
        assert_eq!(
            handler.get("command").and_then(JsonValue::as_str),
            Some("'/b/memprove' hook session-start --config-dir '/b/config'")
        );
        assert_eq!(
            handler.get("type").and_then(JsonValue::as_str),
            Some("command")
        );
        assert_eq!(
            handler.get("timeout"),
            Some(&JsonValue::Number("10".to_owned()))
        );
        assert_eq!(
            handler.get("additionalContextLimit"),
            Some(&JsonValue::Number("0".to_owned()))
        );
        assert!(groups[0].get("matcher").is_none());
    }

    /// U24 (H2): `.cursor/hooks.json` gets `version` 1 and the handler in
    /// `hooks.sessionStart`; a handler of someone else stays before it, a
    /// second install changes nothing, a `version` that is there is kept.
    #[test]
    fn u24_cursor_hooks_file_holds_one_handler_and_keeps_the_rest() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join(".cursor").join("hooks.json");
        assert!(matches!(
            install_cursor_hooks(&path, "/a/memprove", "/a/config").unwrap(),
            Change::Written(_)
        ));
        let first = parse_strict(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            first.get("version"),
            Some(&JsonValue::Number("1".to_owned()))
        );
        fs::write(
            &path,
            r#"{"version":2,"hooks":{"sessionStart":[{"command":"./mine.sh"},{"command":"'/old/memprove' hook session-start --client cursor"}],"stop":[{"command":"./stop.sh"}]}}"#,
        )
        .unwrap();
        install_cursor_hooks(&path, "/a/memprove", "/a/config").unwrap();
        assert!(matches!(
            install_cursor_hooks(&path, "/a/memprove", "/a/config").unwrap(),
            Change::Unchanged(_)
        ));
        let value = parse_strict(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            value.get("version"),
            Some(&JsonValue::Number("2".to_owned()))
        );
        let hooks = value.get("hooks").unwrap();
        assert!(hooks.get("stop").is_some());
        let handlers = hooks
            .get("sessionStart")
            .and_then(JsonValue::as_array)
            .unwrap();
        let commands: Vec<&str> = handlers
            .iter()
            .filter_map(|handler| handler.get("command").and_then(JsonValue::as_str))
            .collect();
        assert_eq!(
            commands,
            [
                "./mine.sh",
                "'/a/memprove' hook session-start --client cursor --config-dir '/a/config'"
            ]
        );
    }

    #[test]
    fn the_export_line_is_written_once_and_never_for_a_bad_value() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("env.sh");
        fs::write(&path, "export OTHER=1").unwrap();
        assert_eq!(
            export_client_session(Some(path.as_os_str()), "s-1"),
            Ok(true)
        );
        assert_eq!(
            export_client_session(Some(path.as_os_str()), "s-1"),
            Ok(true)
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "export OTHER=1\nexport MEMPROVE_CLIENT_SESSION='s-1'\n"
        );
        export_client_session(Some(path.as_os_str()), "s-2").unwrap();
        export_client_session(Some(path.as_os_str()), "s-1").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 4);
        let before = fs::read_to_string(&path).unwrap();
        assert!(export_client_session(Some(path.as_os_str()), "$(x)").is_err());
        assert!(export_client_session(Some(OsStr::new("relative")), "s").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
        assert_eq!(export_client_session(None, "s"), Ok(false));
    }

    /// P4-H1: read requests answered from memory. `capsules` are by Task;
    /// `in_progress` lists the Tasks in progress, each with whether its own
    /// Workspace is the one asked about; `finished` the Tasks whose row is
    /// completed or cancelled.
    struct Ledger {
        capsules: Vec<(String, String)>,
        in_progress: Vec<(String, bool)>,
        finished: Vec<String>,
    }

    impl Reads for Ledger {
        fn capsule(&self, task: &str, _workspace: &str) -> Result<String, ReadError> {
            self.capsules
                .iter()
                .find(|(id, _)| id == task)
                .map(|(_, body)| body.clone())
                .ok_or(ReadError {
                    operation: OperationId::GetTaskCapsule,
                    failure: ReadFailure::Refused {
                        status: 404,
                        code: None,
                        detail: None,
                    },
                })
        }

        fn listing(&self, _project: &str, _workspace: &str) -> Result<Listing, ReadError> {
            Ok(Listing {
                in_progress: self.in_progress.clone(),
                finished: self.finished.clone(),
            })
        }
    }

    /// A Capsule with the verdict `verdict` of a Task in state `state`.
    fn capsule(verdict: &str, state: &str) -> String {
        format!(r#"{{"status":"{verdict}","task":{{"status":"{state}"}},"sessions":[]}}"#)
    }

    /// U11 T2: a time sentence, as [`time_sentence`] writes it.
    const NOW: &str = "The current UTC time is 2026-11-03T18:40:00Z.";
    const FINISHED_TASK: &str = "01a116c0-0000-7000-8000-00000000000d";
    const ONE: &str = "01a116c0-0000-7000-8000-000000000001";
    const TWO: &str = "01a116c0-0000-7000-8000-000000000002";
    const ELSEWHERE: &str = "01a116c0-0000-7000-8000-000000000003";

    /// A ledger where `named` is in `state`, and `in_progress` are in
    /// progress in this Workspace (plus one Task in progress elsewhere).
    fn ledger(named: (&str, &str, &str), in_progress: &[&str]) -> Ledger {
        let mut capsules = vec![(named.0.to_owned(), capsule(named.1, named.2))];
        let mut listed = vec![(ELSEWHERE.to_owned(), false)];
        capsules.push((ELSEWHERE.to_owned(), capsule("partial", "in_progress")));
        for task in in_progress {
            capsules.push(((*task).to_owned(), capsule("partial", "in_progress")));
            listed.push(((*task).to_owned(), true));
        }
        Ledger {
            capsules,
            in_progress: listed,
            finished: FINISHED_STATES
                .contains(&named.2)
                .then(|| named.0.to_owned())
                .into_iter()
                .collect(),
        }
    }

    fn choice(
        ledger: &Ledger,
        named: Option<(&str, Basis)>,
    ) -> Result<(String, Basis, String), String> {
        let named = named.map(|(task, basis)| (task.to_owned(), basis));
        choose(ledger, "project", "workspace", named).map_err(|error| error.clause())
    }

    /// The statement a clause prints, checked against Owner conditions n
    /// and o: one line, a statement first (never `{`), the closing clause
    /// of every statement without a Pack, at most 10,000 UTF-16 code units.
    fn statement(clause: &str) -> String {
        let text = failed(clause);
        assert!(text.starts_with("memprove: "), "{text}");
        assert!(
            text.ends_with("; no Context Pack was injected into this session.\n"),
            "{text}"
        );
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.encode_utf16().count() <= MAX_OUTPUT_UNITS, "{text}");
        text
    }

    #[test]
    fn a_finished_task_is_read_from_its_capsule() {
        let state = |body: &str| parse_strict(body).ok().as_ref().and_then(finished_state);
        for verdict in ["verified", "partial", "stale"] {
            assert_eq!(state(&capsule(verdict, "completed")), Some("completed"));
            assert_eq!(state(&capsule(verdict, "cancelled")), Some("cancelled"));
            for open in ["proposed", "ready", "in_progress", "blocked", "other"] {
                assert_eq!(state(&capsule(verdict, open)), None, "{open}");
            }
        }
        // A tampered Capsule's row state is not trusted: its Pack says why.
        assert_eq!(state(&capsule("tampered", "completed")), None);
        assert_eq!(state(&capsule("tampered", "cancelled")), None);
        assert_eq!(state("{\"status\":\"partial\"}"), None);
        assert_eq!(state("not json"), None);
    }

    #[test]
    fn a_finished_task_of_the_client_context_is_one_statement() {
        for state in FINISHED_STATES {
            for in_progress in [&[][..], &[ONE][..], &[ONE, TWO][..]] {
                let ledger = ledger((FINISHED_TASK, "partial", state), in_progress);
                let clause = choice(&ledger, Some((FINISHED_TASK, Basis::Client))).unwrap_err();
                assert_eq!(
                    statement(&clause),
                    format!(
                        "memprove: the Task {FINISHED_TASK} recorded by this client session's context \
                         is {state}; no Context Pack was injected into this session.\n"
                    )
                );
            }
        }
    }

    #[test]
    fn a_finished_task_of_the_directory_context_gives_way() {
        for state in FINISHED_STATES {
            let named =
                format!("the Task {FINISHED_TASK} recorded by this directory's context is {state}");
            let of = |in_progress: &[&str]| {
                let ledger = ledger((FINISHED_TASK, "verified", state), in_progress);
                choice(&ledger, Some((FINISHED_TASK, Basis::Directory)))
            };

            let clause = of(&[]).unwrap_err();
            assert_eq!(
                statement(&clause),
                format!(
                    "memprove: {named}; this Workspace has no in-progress Task; no Context Pack was \
                     injected into this session.\n"
                )
            );

            let (task, basis, body) = of(&[ONE]).unwrap();
            assert_eq!(task, ONE);
            assert_eq!(body, capsule("partial", "in_progress"));
            // U11 T2 (Owner O4): the time sentence; U14 T1 (Owner O2): then
            // the open-item sentence.
            assert_eq!(
                opening(&task, "startup", &basis, NOW, None),
                format!(
                    "memprove: below is the Context Pack of Task {ONE} at SessionStart (startup); it \
                     is the only in-progress Task of this Workspace ({named}). {NOW} {OPEN_ITEM_SENTENCE}"
                )
            );

            let clause = of(&[ONE, TWO]).unwrap_err();
            assert_eq!(
                statement(&clause),
                format!(
                    "memprove: {named}; this Workspace has 2 in-progress Tasks ({ONE}, {TWO}), and \
                     neither this client session's context nor this directory's names one of them; no \
                     Context Pack was injected into this session.\n"
                )
            );

            let crowded = Ledger {
                in_progress: vec![(ONE.to_owned(), true); MAX_CANDIDATES + 1],
                ..ledger((FINISHED_TASK, "verified", state), &[])
            };
            let clause = choice(&crowded, Some((FINISHED_TASK, Basis::Directory))).unwrap_err();
            assert!(
                statement(&clause).starts_with(&format!(
                    "memprove: {named}; this Project has 21 in-progress Tasks, "
                )),
                "{clause}"
            );

            // The most IDs a statement lists still fit the limit.
            let many = (0..MAX_CANDIDATES)
                .map(|index| format!("01a116c0-0000-7000-8000-{index:012}"))
                .collect::<Vec<_>>();
            let full = Ledger {
                finished: vec![FINISHED_TASK.to_owned()],
                in_progress: many.iter().map(|task| (task.clone(), true)).collect(),
                capsules: many
                    .iter()
                    .map(|task| (task.clone(), capsule("partial", "in_progress")))
                    .chain([(FINISHED_TASK.to_owned(), capsule("partial", state))])
                    .collect(),
            };
            let clause = choice(&full, Some((FINISHED_TASK, Basis::Directory))).unwrap_err();
            assert!(
                statement(&clause).contains("20 in-progress Tasks"),
                "{clause}"
            );
        }
    }

    /// The reads of [`Ledger`], each held until `together` reads are in
    /// flight at once (at most one second), recording the most in flight.
    struct Overlapping {
        ledger: Ledger,
        together: usize,
        flight: std::sync::Mutex<(usize, usize)>,
        changed: std::sync::Condvar,
    }

    impl Overlapping {
        fn new(ledger: Ledger, together: usize) -> Self {
            Self {
                ledger,
                together,
                flight: std::sync::Mutex::new((0, 0)),
                changed: std::sync::Condvar::new(),
            }
        }

        fn most(&self) -> usize {
            self.flight.lock().unwrap().1
        }
    }

    impl Reads for Overlapping {
        fn capsule(&self, task: &str, workspace: &str) -> Result<String, ReadError> {
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            let mut flight = self.flight.lock().unwrap();
            flight.0 += 1;
            flight.1 = flight.1.max(flight.0);
            self.changed.notify_all();
            while flight.1 < self.together {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                flight = self.changed.wait_timeout(flight, left).unwrap().0;
            }
            flight.0 -= 1;
            drop(flight);
            self.ledger.capsule(task, workspace)
        }

        fn listing(&self, project: &str, workspace: &str) -> Result<Listing, ReadError> {
            self.ledger.listing(project, workspace)
        }
    }

    /// Six Tasks in progress in this Workspace, besides the Task elsewhere.
    fn six() -> Vec<String> {
        (1..=6)
            .map(|index| format!("01a116c0-0000-7000-8000-0000000001{index:02}"))
            .collect()
    }

    /// T21 (V3-F-1, fix round 2): the last rule reads the Capsules of the
    /// Tasks in progress at once, and, when the directory's context names a
    /// Task whose row is finished, reads them with that Task's own, so the
    /// hook waits about one read, not one per Task (before: one after
    /// another, at most one in flight). What it chooses is unchanged.
    #[test]
    fn the_capsules_of_the_last_rule_are_read_at_once() {
        let tasks = six();
        let named: Vec<&str> = tasks.iter().map(String::as_str).collect();
        // The named Task, the Task elsewhere, and the six: eight at once.
        for state in FINISHED_STATES {
            let reads = Overlapping::new(ledger((FINISHED_TASK, "partial", state), &named), 8);
            let clause = choose(
                &reads,
                "project",
                "workspace",
                Some((FINISHED_TASK.to_owned(), Basis::Directory)),
            )
            .unwrap_err()
            .clause();
            assert!(clause.contains("6 in-progress Tasks"), "{clause}");
            assert_eq!(reads.most(), 8, "{state}");
        }

        // No context names a Task: the six and the Task elsewhere at once.
        let reads = Overlapping::new(ledger((ELSEWHERE, "partial", "in_progress"), &named), 7);
        let clause = choose(&reads, "project", "workspace", None)
            .unwrap_err()
            .clause();
        assert!(clause.contains("6 in-progress Tasks"), "{clause}");
        assert_eq!(reads.most(), 7);

        // The directory's Task is in progress: its Capsule alone is read.
        let reads = Overlapping::new(ledger((ONE, "partial", "in_progress"), &named), 1);
        let (task, basis, _) = choose(
            &reads,
            "project",
            "workspace",
            Some((ONE.to_owned(), Basis::Directory)),
        )
        .unwrap();
        assert_eq!((task.as_str(), basis), (ONE, Basis::Directory));
        assert_eq!(reads.most(), 1);
    }

    /// The reads of [`Ledger`], recording whether a Capsule read was in
    /// flight while the Tasks were listed: each waits for the other (at most
    /// one second).
    struct Listed {
        ledger: Ledger,
        flight: std::sync::Mutex<(usize, Option<usize>)>,
        changed: std::sync::Condvar,
    }

    impl Reads for Listed {
        fn capsule(&self, task: &str, workspace: &str) -> Result<String, ReadError> {
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            let mut flight = self.flight.lock().unwrap();
            flight.0 += 1;
            self.changed.notify_all();
            while flight.1.is_none() {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                flight = self.changed.wait_timeout(flight, left).unwrap().0;
            }
            flight.0 -= 1;
            drop(flight);
            self.ledger.capsule(task, workspace)
        }

        fn listing(&self, project: &str, workspace: &str) -> Result<Listing, ReadError> {
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            let mut flight = self.flight.lock().unwrap();
            while flight.0 == 0 {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                flight = self.changed.wait_timeout(flight, left).unwrap().0;
            }
            flight.1 = Some(flight.0);
            self.changed.notify_all();
            drop(flight);
            self.ledger.listing(project, workspace)
        }
    }

    /// T21 (V3-F-1, fix round 2): the Capsule of the Task the directory's
    /// context names is read while the Tasks are listed, never after the
    /// list, so a daemon that does not answer costs one wait, not two.
    #[test]
    fn the_directory_task_is_read_while_the_tasks_are_listed() {
        for (verdict, state) in [("partial", "completed"), ("partial", "in_progress")] {
            let reads = Listed {
                ledger: ledger((FINISHED_TASK, verdict, state), &[ONE]),
                flight: std::sync::Mutex::new((0, None)),
                changed: std::sync::Condvar::new(),
            };
            let chosen = choose(
                &reads,
                "project",
                "workspace",
                Some((FINISHED_TASK.to_owned(), Basis::Directory)),
            );
            assert!(chosen.is_ok(), "{state}: {chosen:?}");
            assert_eq!(reads.flight.lock().unwrap().1, Some(1), "{state}");
        }
    }

    /// The reads of [`Ledger`], the Capsule reads of `failing` refused with
    /// the given status.
    struct Failing {
        ledger: Ledger,
        failing: Vec<(&'static str, u16)>,
    }

    impl Reads for Failing {
        fn capsule(&self, task: &str, workspace: &str) -> Result<String, ReadError> {
            match self.failing.iter().find(|(failing, _)| *failing == task) {
                Some((_, status)) => Err(ReadError {
                    operation: OperationId::GetTaskCapsule,
                    failure: ReadFailure::Refused {
                        status: *status,
                        code: None,
                        detail: None,
                    },
                }),
                None => self.ledger.capsule(task, workspace),
            }
        }

        fn listing(&self, project: &str, workspace: &str) -> Result<Listing, ReadError> {
            self.ledger.listing(project, workspace)
        }
    }

    /// T21 (V3-F-1, fix round 2): read at once, a failed read fails the
    /// choice as it did one read after another: the named Task's own first,
    /// then the first Task of the listing whose read failed.
    #[test]
    fn a_failed_read_of_the_last_rule_is_the_first_in_order() {
        let status = |failing: Vec<(&'static str, u16)>| {
            let reads = Failing {
                ledger: ledger((FINISHED_TASK, "partial", "completed"), &[ONE, TWO]),
                failing,
            };
            match choose(
                &reads,
                "project",
                "workspace",
                Some((FINISHED_TASK.to_owned(), Basis::Directory)),
            ) {
                Err(ChoiceError::Read(ReadError {
                    operation: OperationId::GetTaskCapsule,
                    failure: ReadFailure::Refused { status, .. },
                })) => status,
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(status(vec![(TWO, 500), (ONE, 503)]), 503);
        assert_eq!(status(vec![(TWO, 500), (ELSEWHERE, 502), (ONE, 503)]), 502);
        assert_eq!(status(vec![(TWO, 500), (FINISHED_TASK, 504)]), 504);
    }

    #[test]
    fn a_task_finished_after_it_was_listed_is_not_in_progress() {
        let mut ledger = ledger((ONE, "partial", "completed"), &[]);
        ledger.in_progress.push((ONE.to_owned(), true));
        assert_eq!(
            choice(&ledger, None).unwrap_err(),
            "this directory's context names no Task, and this Workspace has no in-progress Task"
        );
    }

    #[test]
    fn a_task_that_is_not_known_to_be_finished_keeps_its_pack() {
        for basis in [Basis::Client, Basis::Directory] {
            for (verdict, state) in [
                ("partial", "in_progress"),
                ("verified", "blocked"),
                ("stale", "ready"),
                ("tampered", "completed"),
                ("tampered", "cancelled"),
            ] {
                let ledger = ledger((FINISHED_TASK, verdict, state), &[ONE]);
                let (task, chosen, body) =
                    choice(&ledger, Some((FINISHED_TASK, basis.clone()))).unwrap();
                assert_eq!(
                    (task.as_str(), &chosen, body),
                    (FINISHED_TASK, &basis, capsule(verdict, state))
                );
            }
        }
        // No context names a Task: the last rule, as before.
        let (task, basis, _) =
            choice(&ledger((ELSEWHERE, "partial", "in_progress"), &[ONE]), None).unwrap();
        assert_eq!((task.as_str(), basis), (ONE, Basis::OnlyInProgress(None)));
        // U11 T2 (Owner O4): the time sentence; U14 T1 (Owner O2): then the
        // open-item sentence.
        assert_eq!(
            opening(ONE, "startup", &Basis::OnlyInProgress(None), NOW, None),
            format!(
                "memprove: below is the Context Pack of Task {ONE} at SessionStart (startup); it is \
                 the only in-progress Task of this Workspace. {NOW} {OPEN_ITEM_SENTENCE}"
            )
        );
        assert_eq!(
            choice(&ledger((ELSEWHERE, "partial", "in_progress"), &[]), None).unwrap_err(),
            "this directory's context names no Task, and this Workspace has no in-progress Task"
        );
        assert_eq!(
            choice(
                &ledger((ELSEWHERE, "partial", "in_progress"), &[ONE, TWO]),
                None
            )
            .unwrap_err(),
            format!(
                "this Workspace has 2 in-progress Tasks ({ONE}, {TWO}), and neither this client \
                 session's context nor this directory's names one of them"
            )
        );
    }

    /// U11 T2 (Owner O4): the time sentence states the given Unix seconds in
    /// the canonical form of the ledger's times (whole seconds, `Z`), and
    /// the system clock without them.
    #[test]
    fn u11_t2_the_time_sentence_states_utc_in_the_ledgers_form() {
        assert_eq!(utc_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_seconds(1_793_664_000), "2026-11-03T00:00:00Z");
        assert_eq!(time_sentence(Some(1_793_731_200)), NOW);
        let now = time_sentence(None);
        let time = now
            .strip_prefix("The current UTC time is ")
            .and_then(|rest| rest.strip_suffix('.'))
            .unwrap();
        assert_eq!(
            memprove_domain::UtcTimestamp::parse(time).unwrap().as_str(),
            time
        );
    }

    /// U11 T1 (Owner O3): the agent the opening names is the whole
    /// declaration of the three variables (an empty one unset), only when
    /// the server would take it; part of it, or a value the server refuses,
    /// is a warning; none of the three is no agent.
    #[test]
    fn u11_t1_the_opening_names_only_a_whole_declaration_the_server_takes() {
        let parent = "01a1a2af-4151-7aa3-aaa1-e59698e77720";
        let with = |name: Option<&str>, role: Option<&str>, parent: Option<&str>| {
            let environment = Environment {
                agent_name: name.map(OsString::from),
                agent_role: role.map(OsString::from),
                parent_session: parent.map(OsString::from),
                ..Environment::default()
            };
            declared_agent(&environment)
        };
        assert_eq!(with(None, None, None), Ok(None));
        assert_eq!(with(Some(""), Some(""), Some("")), Ok(None));
        let agent = with(Some("takeover-eval-other"), Some("sub_agent"), None)
            .unwrap()
            .unwrap();
        assert_eq!(
            identity_sentence(&agent),
            "You are agent「takeover-eval-other」(sub_agent); when begin and end get no agent_name, \
             agent_role, or parent_session, the server uses these three."
        );
        let agent = with(Some("u11-s-t"), Some("sub_agent"), Some(parent))
            .unwrap()
            .unwrap();
        assert_eq!(
            identity_sentence(&agent),
            format!(
                "You are agent「u11-s-t」(sub_agent, parent Session {parent}); when begin and end get \
                 no agent_name, agent_role, or parent_session, the server uses these three."
            )
        );
        for (name, role, parent) in [
            (Some("a"), None, None),
            (None, Some("human"), None),
            (None, None, Some(parent)),
            (Some("a"), None, Some(parent)),
            (Some("a"), Some(""), None),
        ] {
            assert_eq!(
                with(name, role, parent),
                Err(AGENT_PART_WARNING),
                "{name:?} {role:?} {parent:?}"
            );
        }
        for (name, role, parent) in [
            ("a b", "human", None),
            (&"a".repeat(65)[..], "human", None),
            ("a", "boss", None),
            ("a", "human", Some("not-a-session")),
        ] {
            assert_eq!(
                with(Some(name), Some(role), parent),
                Err(AGENT_INVALID_WARNING),
                "{name:?} {role:?} {parent:?}"
            );
        }
        for warning in [AGENT_PART_WARNING, AGENT_INVALID_WARNING] {
            assert!(!warning.contains('\n') && warning.starts_with("memprove: warning: "));
        }
        // The opening: the time sentence, then the agent's (U14 T1: then the
        // open-item sentence).
        let identity = identity_sentence(
            &with(Some("takeover-eval-other"), Some("sub_agent"), None)
                .unwrap()
                .unwrap(),
        );
        assert_eq!(
            opening(ONE, "fork", &Basis::Client, NOW, Some(&identity)),
            format!(
                "memprove: below is the Context Pack of Task {ONE} at SessionStart (fork), chosen \
                 from this client session's context. This session was forked from another session; \
                 none of the Sessions the Pack lists was started by this session, and an unended one \
                 may belong to the parent session; while the parent session is still running, the \
                 guidance at the end of that line does not apply to it. {NOW} {identity} \
                 {OPEN_ITEM_SENTENCE}"
            )
        );
    }

    /// U13 T1 (Owner O5; U12-VN3): every sentence of the opening is a
    /// statement (ADR 0014 E4 condition n): the `memprove: ` sentence, the
    /// fork sentence, the time sentence, and the identity sentence say what
    /// is so and give the client no instruction.
    #[test]
    fn u13_t1_the_opening_has_no_imperative_sentence() {
        let parent = "01a1a2af-4151-7aa3-aaa1-e59698e77720";
        let named =
            memprove_domain::SessionAgent::new("takeover-eval-other", "sub_agent", None).unwrap();
        let dispatched =
            memprove_domain::SessionAgent::new("takeover-eval-other", "sub_agent", Some(parent))
                .unwrap();
        let identities = [
            None,
            Some(identity_sentence(&named)),
            Some(identity_sentence(&dispatched)),
        ];
        for source in ["startup", "resume", "clear", "compact", "fork"] {
            for identity in &identities {
                for basis in [Basis::Client, Basis::OnlyInProgress(None)] {
                    let text = opening(ONE, source, &basis, NOW, identity.as_deref());
                    for word in ["do not", "please", "give no"] {
                        assert!(!text.contains(word), "{source}: {word} in {text}");
                    }
                    assert_eq!(
                        text.contains("This session was forked from another session"),
                        source == "fork"
                    );
                }
            }
        }
        let fork = opening(ONE, "fork", &Basis::Client, NOW, None);
        assert!(
            fork.contains(
                "while the parent session is still running, the guidance at the end of that line \
                 does not apply to it."
            ),
            "{fork}"
        );
        assert!(!fork.contains("do not end"), "{fork}");
    }

    /// U12 T3 (Owner O5; U11-VN3): the identity sentence is a statement
    /// (ADR 0014 E4 condition n): it says what the server does when `begin`
    /// and `end` get no agent input, and tells the client nothing to do.
    #[test]
    fn u12_t3_the_identity_sentence_is_a_statement() {
        let parent = "01a1a2af-4151-7aa3-aaa1-e59698e77720";
        for agent in [
            memprove_domain::SessionAgent::new("takeover-eval-other", "sub_agent", None),
            memprove_domain::SessionAgent::new("u12-s-t", "sub_agent", Some(parent)),
        ] {
            let sentence = identity_sentence(&agent.unwrap());
            assert!(!sentence.contains("do not"), "{sentence}");
            assert!(
                sentence.ends_with(
                    "; when begin and end get no agent_name, agent_role, or parent_session, the \
                     server uses these three."
                ),
                "{sentence}"
            );
        }
    }

    /// U12 T4 (Owner O5; U11-VN1): the time sentence and the identity
    /// sentence of the longest declaration the server takes (a name of 64
    /// characters, the role `orchestrator`, a parent Session ID of 36) are
    /// 290 UTF-16 code units together (U17: in English); U14 T1 (Owner O2):
    /// with the open-item sentence after them, within
    /// [`OPENING_SENTENCES_MAX_UNITS`] (480); every shorter declaration is
    /// shorter.
    #[test]
    fn u12_t4_u14_t1_the_opening_sentences_are_within_the_bound() {
        let parent = "01a1aa76-d767-7d43-89aa-eda39635321f";
        let longest =
            memprove_domain::SessionAgent::new(&"w".repeat(64), "orchestrator", Some(parent))
                .unwrap();
        let units = |agent: &memprove_domain::SessionAgent| {
            format!(
                "{}{}",
                time_sentence(Some(1_793_731_200)),
                identity_sentence(agent)
            )
            .encode_utf16()
            .count()
        };
        let worst = units(&longest);
        println!("the longest time and identity sentences: {worst} UTF-16 code units");
        assert_eq!(worst, 290);
        // U14 T1 (Owner O2): with the open-item sentence after them (and
        // the two spaces between the three), the longest declaration's
        // sentences are within the bound, 480 since U17.
        let three = worst
            + "Under the unattended takeover rule, this session records each Session it leaves \
               open as an open item 「another Session (Session k) may still be working, not \
               ended」 in its first checkpoint."
                .encode_utf16()
                .count()
            + 2;
        println!("with the open-item sentence: {three} UTF-16 code units");
        assert!(three <= OPENING_SENTENCES_MAX_UNITS, "{three}");
        assert_eq!(OPENING_SENTENCES_MAX_UNITS, 480);
        // The time sentence has one length up to the year 9999.
        assert_eq!(
            time_sentence(Some(253_402_300_799)).encode_utf16().count(),
            time_sentence(Some(1_793_731_200)).encode_utf16().count()
        );
        // A shorter name, another role, or no parent is shorter.
        for (name, role, parent) in [
            ("w".repeat(63), "orchestrator", Some(parent)),
            ("w".repeat(64), "sub_agent", Some(parent)),
            ("w".repeat(64), "orchestrator", None),
        ] {
            let agent = memprove_domain::SessionAgent::new(&name, role, parent).unwrap();
            assert!(units(&agent) < worst, "{name} {role} {parent:?}");
        }
    }

    /// U14 T1 (Owner O2; U13-F1, U13-VN1): the opening, the hook's for every
    /// source and the MCP `pack` tool's, ends with the statement of the open
    /// item a Session left open under the unattended takeover rule is
    /// recorded as, once, after the time sentence and the identity sentence;
    /// it gives the client no instruction (U13 T1's guard).
    #[test]
    fn u14_t1_the_opening_states_the_open_item_of_a_session_left_open() {
        let sentence = "Under the unattended takeover rule, this session records each Session it \
                        leaves open as an open item 「another Session (Session k) may still be \
                        working, not ended」 in its first checkpoint.";
        let parent = "01a1a2af-4151-7aa3-aaa1-e59698e77720";
        let identities = [
            None,
            Some(identity_sentence(
                &memprove_domain::SessionAgent::new("takeover-eval-other", "sub_agent", None)
                    .unwrap(),
            )),
            Some(identity_sentence(
                &memprove_domain::SessionAgent::new(
                    "takeover-eval-other",
                    "sub_agent",
                    Some(parent),
                )
                .unwrap(),
            )),
        ];
        for identity in &identities {
            let tail = format!(
                "{NOW} {}{sentence}",
                identity
                    .as_deref()
                    .map_or_else(String::new, |identity| format!("{identity} "))
            );
            for source in SOURCES {
                for basis in [Basis::Client, Basis::Directory, Basis::OnlyInProgress(None)] {
                    let text = opening(ONE, source, &basis, NOW, identity.as_deref());
                    assert!(text.ends_with(&tail), "{source}: {text}");
                    assert_eq!(text.matches(sentence).count(), 1, "{text}");
                }
            }
            let pack = statement_opening(
                ONE,
                None,
                &basis_clause(&Basis::Client),
                NOW,
                identity.as_deref(),
            );
            assert!(pack.ends_with(&tail), "{pack}");
            assert_eq!(pack.matches(sentence).count(), 1, "{pack}");
        }
        for word in ["do not", "please", "give no"] {
            assert!(!sentence.contains(word), "{word}");
        }
    }

    /// U12 T2 (Owner O4): the MCP `pack` tool's opening is the hook's, from
    /// the same function, without `at SessionStart (<source>)` and without
    /// the fork sentence; the basis, the time, and the identity are the same.
    #[test]
    fn u12_t2_the_pack_opening_is_the_hooks_without_its_sessionstart_words() {
        let identity = identity_sentence(
            &memprove_domain::SessionAgent::new("takeover-eval-other", "sub_agent", None).unwrap(),
        );
        for basis in [Basis::Client, Basis::Directory, Basis::OnlyInProgress(None)] {
            let hook = opening(ONE, "startup", &basis, NOW, Some(&identity));
            let pack = statement_opening(ONE, None, &basis_clause(&basis), NOW, Some(&identity));
            assert_eq!(
                pack,
                hook.replacen(" at SessionStart (startup)", "", 1),
                "{basis:?}"
            );
            assert!(
                !pack.contains("SessionStart") && !pack.contains("forked from"),
                "{pack}"
            );
        }
        assert_eq!(
            statement_opening(
                ONE,
                None,
                ", chosen by the call's task argument (Task number 2)",
                NOW,
                None
            ),
            format!(
                "memprove: below is the Context Pack of Task {ONE}, chosen by the call's task argument \
                 (Task number 2). {NOW} {OPEN_ITEM_SENTENCE}"
            )
        );
        let environment = Environment {
            agent_name: Some("takeover-eval-other".into()),
            agent_role: Some("sub_agent".into()),
            ..Environment::default()
        };
        assert_eq!(opening_identity(&environment), Some(identity));
        assert_eq!(opening_identity(&Environment::default()), None);
        let part = Environment {
            agent_name: Some("takeover-eval-other".into()),
            ..Environment::default()
        };
        assert_eq!(opening_identity(&part), None);
    }

    #[test]
    fn edit_adds_once_and_removes_only_its_own_handler() {
        let settings = parse_strict(
            r#"{"a":1.50,"hooks":{"SessionStart":[{"matcher":"x","hooks":[{"type":"command","command":"/bin/true"}]}],"Stop":[]}}"#,
        )
        .unwrap();
        let added = edit(&settings, Some(own_group("/opt/bin/memprove", None))).unwrap();
        assert_eq!(
            edit(&added, Some(own_group("/opt/bin/memprove", None))).unwrap(),
            added
        );
        // A moved binary replaces the handler, it does not add a second.
        let moved = edit(&added, Some(own_group("/usr/bin/memprove", None))).unwrap();
        assert_eq!(
            moved
                .get("hooks")
                .unwrap()
                .get("SessionStart")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(edit(&added, None).unwrap(), settings);
        let empty = JsonValue::Object(Vec::new());
        let only = edit(&empty, Some(own_group("/c/memprove", None))).unwrap();
        assert_eq!(edit(&only, None).unwrap(), empty);
        let mut text = String::new();
        pretty(&added, 0, &mut text);
        assert_eq!(parse_strict(&text).unwrap(), added);
        assert!(text.contains("\"a\": 1.50"));
        for bad in ["[]", r#"{"hooks":[]}"#, r#"{"hooks":{"SessionStart":{}}}"#] {
            assert!(edit(&parse_strict(bad).unwrap(), None).is_err(), "{bad}");
        }
    }

    /// U20 T1 (U19-O2): `install` takes the handler, the `env` variable, the
    /// MCP entry and the rules of the previous name as its own, and nothing
    /// that only looks like them: a `continuity` handler or server with
    /// other arguments, another program under the name `continuity`, a rule
    /// that is not one `--allow-tools` wrote.
    #[test]
    fn u20_t1_the_previous_name_is_replaced_and_its_look_alikes_are_kept() {
        let handler = |command: &str, args: &str| {
            parse_strict(&format!(
                r#"{{"type":"command","command":"{command}","args":{args}}}"#
            ))
            .unwrap()
        };
        assert!(is_own(&handler(
            "/t/bin/continuity",
            r#"["hook","session-start"]"#
        )));
        assert!(is_own(&handler(
            "/t/bin/continuity",
            r#"["hook","session-start","--config-dir","/t/c"]"#
        )));
        assert!(!is_own(&handler("/t/bin/continuity", r#"["hook","stop"]"#)));
        assert!(!is_own(&handler(
            "/t/bin/continuity2",
            r#"["hook","session-start"]"#
        )));
        for rule in [
            "mcp__continuity",
            "Bash(continuity run:*)",
            "Bash(/t/a b/continuity run:*)",
        ] {
            assert!(is_previous_rule(rule), "{rule}");
        }
        for rule in [
            "mcp__continuity_x",
            "mcp__memprove",
            "Bash(continuity:*)",
            "Bash(bin/continuity run:*)",
            "Bash(/t/bin/memprove run:*)",
            "Bash(/t/bin/continuityd run:*)",
        ] {
            assert!(!is_previous_rule(rule), "{rule}");
        }
        let mcp_json = parse_strict(
            r#"{"mcpServers":{"continuity":{"command":"/t/bin/continuity","args":["mcp","serve"]},"x":{"command":"/x"}}}"#,
        )
        .unwrap();
        let written = with_server(&mcp_json, "/t/bin/memprove", "/t/c").unwrap();
        let names = |value: &JsonValue| {
            let Some(JsonValue::Object(servers)) = value.get("mcpServers") else {
                return Vec::new();
            };
            servers
                .iter()
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&written), ["x", "memprove"]);
        assert_eq!(names(&without_server(&mcp_json).unwrap()), ["x"]);
        // Another server under the name continuity is not the previous name's.
        let other = parse_strict(
            r#"{"mcpServers":{"continuity":{"command":"/x/other","args":["mcp","serve"]}}}"#,
        )
        .unwrap();
        assert_eq!(
            names(&with_server(&other, "/t/bin/memprove", "/t/c").unwrap()),
            ["continuity", "memprove"]
        );
        assert_eq!(without_server(&other).unwrap(), other);
        let settings = parse_strict(
            r#"{"env":{"CONTINUITY_CONFIG_DIR":"/t/c","A":"1"},"permissions":{"allow":["mcp__continuity","B"]}}"#,
        )
        .unwrap();
        let kept = with_enabling(&settings, "/t/bin/memprove", "/t/c", false).unwrap();
        assert_eq!(
            kept,
            parse_strict(
                r#"{"env":{"A":"1","MEMPROVE_CONFIG_DIR":"/t/c"},"permissions":{"allow":["mcp__continuity","B"]}}"#
            )
            .unwrap(),
            "without --allow-tools the rules are not touched"
        );
        assert_eq!(
            without_enabling(&settings).unwrap(),
            parse_strict(r#"{"env":{"A":"1"},"permissions":{"allow":["mcp__continuity","B"]}}"#)
                .unwrap()
        );
    }

    /// U5 Z-F round 1 (S2): the CLI's fallback reads `<config>/data-dir`
    /// as the hook does, and says which file it read when it names none.
    #[test]
    fn u5_zf1_s2_the_configured_location_is_the_data_dir_file() {
        let base = tempfile::tempdir().unwrap();
        let config = base.path().join("cfg");
        fs::create_dir_all(&config).unwrap();
        let shown = config.display().to_string();
        let at = |source| configured_location(Some((config.as_path(), source)));
        assert_eq!(
            at(CONFIG_DIR_VARIABLE),
            Err(format!(
                "{shown}/data-dir does not exist (the configuration directory is {shown}, from \
                 MEMPROVE_CONFIG_DIR)"
            ))
        );
        assert_eq!(
            at("HOME"),
            Err(format!(
                "{shown}/data-dir does not exist (the configuration directory is {shown}, from \
                 HOME; MEMPROVE_CONFIG_DIR is not set)"
            ))
        );
        fs::write(config.join("data-dir"), "/a\n/b\n").unwrap();
        assert!(
            at(CONFIG_DIR_VARIABLE)
                .unwrap_err()
                .contains("data-dir is not one absolute path on one line"),
        );
        fs::write(config.join("data-dir"), "/data/dir\n").unwrap();
        assert_eq!(at(CONFIG_DIR_VARIABLE), Ok(PathBuf::from("/data/dir")));
        assert_eq!(
            configured_location(None),
            Err(
                "there is no configuration directory to read a data-dir file from \
                 (MEMPROVE_CONFIG_DIR, XDG_CONFIG_HOME, and HOME are all unset)"
                    .to_owned()
            )
        );
        assert_eq!(
            configured_token(&config).map_err(|error| error.to_string()),
            Ok(None)
        );
    }

    /// U15 T1 (Owner O2; U14-N1; ADR 0014 "Amendment (U15)"): the hook's own
    /// limit (E4 condition o) is 8 seconds, 2 within the 10 of the handler's
    /// `timeout` that `install` writes, and the statement a timeout prints
    /// names the limit, says that no Pack was injected, and says how the
    /// client fetches one itself. It is one line and a statement, like the
    /// hook's other statements (U13 T1's rule).
    #[test]
    fn u15_t1_the_limit_is_eight_seconds_and_the_statement_says_how_to_fetch_the_pack() {
        assert_eq!(TIME_LIMIT, Duration::from_secs(8));
        assert!(
            TIME_LIMIT + Duration::from_secs(2) <= Duration::from_secs(HANDLER_TIMEOUT_SECONDS)
        );
        let statement = timeout_statement();
        assert_eq!(
            statement,
            "memprove: the Context Pack was not read within 8 seconds; no Context Pack was injected \
             into this session; running memprove resume --pack in this session fetches it.\n"
        );
        assert_eq!(statement.lines().count(), 1);
        assert!(!statement.starts_with('{'));
        assert!(statement.contains(NOT_INJECTED));
        assert!(statement.encode_utf16().count() <= MAX_OUTPUT_UNITS);
        for text in [statement, internal_error_statement(), arguments_statement()] {
            assert!(text.starts_with("memprove: "), "{text}");
            assert!(text.ends_with(".\n"), "{text}");
            for word in ["do not", "please", "give no"] {
                assert!(!text.contains(word), "{word} in {text}");
            }
        }
    }
}
