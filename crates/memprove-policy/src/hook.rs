//! `memprove policy hook --client <client>`: the hook every client runs
//! before a tool call. It reads the client's JSON on standard input, finds
//! the policy of the repository, decides the call, and answers in the
//! client's own form:
//!
//! | client | deny | ask | no objection |
//! |---|---|---|---|
//! | Claude Code (`PreToolUse`) | `permissionDecision: deny` | `permissionDecision: ask` | nothing |
//! | Codex (`PreToolUse`) | `permissionDecision: deny` | deny, saying a person must approve: Codex's hooks cannot ask | nothing |
//! | Cursor (`beforeShellExecution`, `beforeMCPExecution`) | `permission: deny` | `permission: ask` | `permission: allow` |
//! | Cursor (`beforeReadFile`, `preToolUse`) | `permission: deny` | deny, as for Codex | `permission: allow` |
//!
//! Cursor also runs Claude Code's hooks: given Cursor's input, the Claude
//! Code hook leaves the call to Cursor's own hooks when the repository has
//! them, and decides it as Cursor's `preToolUse` would otherwise. The hook
//! exits 0; what it cannot read it lets through with a warning on standard
//! error, since the client's own permissions still apply.
//!
//! A call that matches a `taint` line of the policy marks its session
//! ([`crate::taint`]), by the id the client gives (`session_id`, or
//! Cursor's `conversation_id`), unless the call is refused; from the next
//! call on, the `tainted` rules apply to that session.

use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use memprove_protocol::strict_json::{JsonLimits, parse_strict_with_limits};

use crate::{
    engine::{self, Call, Extra, POLICY_FILE, Site, Verdict, Written},
    json::{self, JsonValue},
    log::{self, Record},
    rules::{self, Decision, Policy, Tool},
    taint::{self, Mark},
};

/// The largest input read, in bytes (a `Write` call holds the whole file).
pub const MAX_INPUT_BYTES: usize = 64 << 20;

/// A client the hook answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Client {
    /// Claude Code.
    ClaudeCode,
    /// Codex.
    Codex,
    /// Cursor.
    Cursor,
}

impl Client {
    /// Every client.
    pub const ALL: [Self; 3] = [Self::ClaudeCode, Self::Codex, Self::Cursor];

    /// The name `--client` takes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    /// The name a person reads.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
        }
    }

    /// The client named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|client| client.name() == name)
    }
}

/// What the hook knows beside its input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookEnv {
    /// The project directory the client names (`CLAUDE_PROJECT_DIR`,
    /// `CURSOR_PROJECT_DIR`).
    pub project_dir: Option<PathBuf>,
    /// The hook's working directory.
    pub cwd: PathBuf,
    /// The home directory.
    pub home: Option<PathBuf>,
    /// The time of the call, as the log writes it.
    pub time: String,
}

/// What the hook answers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answer {
    /// Its standard output.
    pub stdout: String,
    /// A warning for standard error.
    pub warning: Option<String>,
    /// The record for the audit log, with the root whose log takes it.
    pub record: Option<(PathBuf, Record)>,
    /// The mark the call puts on its session: the root, the session, and
    /// the call that matched a `taint` line.
    pub mark: Option<(PathBuf, String, Mark)>,
}

/// How a client is answered for one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// Claude Code's and Codex's `hookSpecificOutput`; `ask` only when the
    /// client can ask.
    Nested { can_ask: bool, silent: bool },
    /// Cursor's `permission`; `ask` only when the event can ask.
    Permission { can_ask: bool },
}

/// The call of an event, how to answer it, and where it runs.
struct Event {
    call: Option<Call>,
    /// The text the call writes into files, where the client gives it.
    written: Vec<Written>,
    /// The session the client says the call belongs to.
    session: Option<String>,
    form: Form,
    cwd: Option<PathBuf>,
    /// The directory the repository is looked for from.
    start: Option<PathBuf>,
    /// Cursor's input to the Claude Code hook.
    cursor_through_claude: bool,
}

fn path_of(input: &JsonValue) -> Option<String> {
    json::first_str(
        input,
        &[
            "file_path",
            "path",
            "target_file",
            "filePath",
            "notebook_path",
            "target_notebook",
        ],
    )
    .map(str::to_owned)
}

/// The text a file tool's input writes: a whole file (`content`), what an
/// edit puts in (`new_string`, each of `edits`), or a notebook cell
/// (`new_source`).
fn written_of(input: &JsonValue) -> Vec<Written> {
    let Some(path) = path_of(input) else {
        return Vec::new();
    };
    let mut texts: Vec<&str> = ["content", "contents", "new_string", "new_source"]
        .iter()
        .filter_map(|name| json::str_at(input, name))
        .collect();
    if let Some(edits) = input.get("edits").and_then(JsonValue::as_array) {
        texts.extend(
            edits
                .iter()
                .filter_map(|edit| json::str_at(edit, "new_string")),
        );
    }
    if texts.is_empty() {
        return Vec::new();
    }
    vec![Written {
        path,
        text: texts.join("\n"),
    }]
}

/// The lines an `apply_patch` patch adds, file by file.
#[must_use]
pub fn patch_written(patch: &str) -> Vec<Written> {
    let mut written: Vec<Written> = Vec::new();
    for line in patch.lines() {
        let file = ["*** Add File: ", "*** Update File: ", "*** Move to: "]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix));
        if let Some(path) = file {
            written.push(Written {
                path: path.trim().to_owned(),
                text: String::new(),
            });
        } else if line.starts_with("*** ") {
            // A deleted file, or the patch's own first and last lines.
        } else if let Some(added) = line.strip_prefix('+')
            && let Some(current) = written.last_mut()
        {
            current.text.push_str(added);
            current.text.push('\n');
        }
    }
    written.retain(|file| !file.path.is_empty() && !file.text.is_empty());
    written
}

fn mcp_call(name: &str) -> Option<Call> {
    let rest = name.strip_prefix("mcp__")?;
    let (server, tool) = rest.split_once("__")?;
    Some(Call::Mcp {
        server: Some(server.to_owned()),
        tool: tool.to_owned(),
    })
}

/// A shell command given as a list of words: the script of `bash -c`, or
/// the words joined by spaces.
fn command_of_words(words: &[JsonValue]) -> Option<String> {
    let words: Vec<&str> = words.iter().map(JsonValue::as_str).collect::<Option<_>>()?;
    if words.len() >= 3
        && ["sh", "bash", "zsh"].contains(&crate::commands::basename(words[0]))
        && words[1].starts_with('-')
        && words[1].contains('c')
    {
        return Some(words[2].to_owned());
    }
    Some(words.join(" "))
}

/// The files an `apply_patch` patch adds, updates, deletes, or moves to.
#[must_use]
pub fn patch_paths(patch: &str) -> Vec<String> {
    patch
        .lines()
        .filter_map(|line| {
            [
                "*** Add File: ",
                "*** Update File: ",
                "*** Delete File: ",
                "*** Move to: ",
            ]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
        })
        .map(|path| path.trim().to_owned())
        .filter(|path| !path.is_empty())
        .collect()
}

/// A client's own web tool: a fetch by its URL, a search as
/// `search:<query>`. An input that names neither is still a web call, with
/// nothing to match but `*`, so that it marks a session all the same.
fn web_call(tool: &str, input: &JsonValue) -> Option<Call> {
    match tool {
        "WebFetch" => Some(Call::Web(
            json::str_at(input, "url").unwrap_or_default().to_owned(),
        )),
        "WebSearch" => Some(Call::Web(format!(
            "search:{}",
            json::str_at(input, "query").unwrap_or_default()
        ))),
        _ => None,
    }
}

fn claude_call(tool: &str, input: &JsonValue) -> Option<Call> {
    match tool {
        "Bash" => json::str_at(input, "command").map(|command| Call::Bash(command.to_owned())),
        "WebFetch" | "WebSearch" => web_call(tool, input),
        "Read" | "NotebookRead" => path_of(input).map(|path| Call::Read(vec![path])),
        "Grep" => json::str_at(input, "path").map(|path| Call::Read(vec![path.to_owned()])),
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
            path_of(input).map(|path| Call::Edit(vec![path]))
        }
        _ => mcp_call(tool),
    }
}

fn codex_call(tool: &str, input: &JsonValue) -> Option<Call> {
    if tool == "apply_patch" {
        let patch = json::first_str(input, &["command", "input", "patch"])?;
        return Some(Call::Edit(patch_paths(patch)));
    }
    if tool.starts_with("mcp__") {
        return mcp_call(tool);
    }
    match input.get("command").or_else(|| input.get("cmd")) {
        Some(JsonValue::String(command)) => Some(Call::Bash(command.clone())),
        Some(JsonValue::Array(words)) => command_of_words(words).map(Call::Bash),
        _ => None,
    }
}

fn cursor_tool_call(tool: &str, input: &JsonValue) -> Option<Call> {
    match tool {
        "Shell" | "Bash" => {
            json::str_at(input, "command").map(|command| Call::Bash(command.to_owned()))
        }
        "Read" => path_of(input).map(|path| Call::Read(vec![path])),
        "Write" | "Delete" | "Edit" | "MultiEdit" => {
            path_of(input).map(|path| Call::Edit(vec![path]))
        }
        "WebFetch" | "WebSearch" => web_call(tool, input),
        _ => tool
            .strip_prefix("MCP:")
            .map(|name| Call::Mcp {
                server: None,
                tool: name.to_owned(),
            })
            .or_else(|| mcp_call(tool)),
    }
}

fn cwd_of(value: &JsonValue) -> Option<PathBuf> {
    json::str_at(value, "cwd")
        .filter(|cwd| !cwd.is_empty())
        .map(PathBuf::from)
}

fn first_workspace_root(value: &JsonValue) -> Option<PathBuf> {
    value
        .get("workspace_roots")?
        .as_array()?
        .first()?
        .as_str()
        .map(PathBuf::from)
}

fn event_of(client: Client, value: &JsonValue, env: &HookEnv) -> Event {
    let tool = json::str_at(value, "tool_name").unwrap_or_default();
    let empty = JsonValue::Object(Vec::new());
    let tool_input = value.get("tool_input").unwrap_or(&empty);
    let cursor_shaped = value.get("cursor_version").is_some();
    let project = env.project_dir.clone();
    let session = json::first_str(value, &["session_id", "conversation_id"])
        .filter(|id| !id.is_empty())
        .map(str::to_owned);
    match client {
        Client::ClaudeCode if cursor_shaped => Event {
            call: cursor_tool_call(tool, tool_input),
            written: written_of(tool_input),
            session,
            form: Form::Nested {
                can_ask: false,
                silent: false,
            },
            cwd: cwd_of(value).or_else(|| first_workspace_root(value)),
            start: project
                .or_else(|| first_workspace_root(value))
                .or_else(|| cwd_of(value)),
            cursor_through_claude: true,
        },
        Client::ClaudeCode => Event {
            call: claude_call(tool, tool_input),
            written: written_of(tool_input),
            session,
            form: Form::Nested {
                can_ask: true,
                silent: true,
            },
            cwd: cwd_of(value),
            start: project.or_else(|| cwd_of(value)),
            cursor_through_claude: false,
        },
        Client::Codex => Event {
            call: codex_call(tool, tool_input),
            written: if tool == "apply_patch" {
                json::first_str(tool_input, &["command", "input", "patch"])
                    .map(patch_written)
                    .unwrap_or_default()
            } else {
                Vec::new()
            },
            session,
            form: Form::Nested {
                can_ask: false,
                silent: true,
            },
            cwd: cwd_of(value),
            start: cwd_of(value),
            cursor_through_claude: false,
        },
        Client::Cursor => {
            let event = json::str_at(value, "hook_event_name").unwrap_or_default();
            let (call, can_ask) = match event {
                "beforeShellExecution" => (
                    json::str_at(value, "command").map(|command| Call::Bash(command.to_owned())),
                    true,
                ),
                "beforeMCPExecution" => (
                    json::str_at(value, "tool_name").map(|name| Call::Mcp {
                        server: json::first_str(
                            value,
                            &["mcp_server_name", "server_name", "server"],
                        )
                        .map(str::to_owned),
                        tool: name.to_owned(),
                    }),
                    true,
                ),
                "beforeReadFile" => (path_of(value).map(|path| Call::Read(vec![path])), false),
                "preToolUse" => (cursor_tool_call(tool, tool_input), false),
                _ => (None, false),
            };
            Event {
                call,
                written: if event == "preToolUse" {
                    written_of(tool_input)
                } else {
                    Vec::new()
                },
                session,
                form: Form::Permission { can_ask },
                cwd: cwd_of(value).or_else(|| first_workspace_root(value)),
                start: project
                    .or_else(|| first_workspace_root(value))
                    .or_else(|| cwd_of(value)),
                cursor_through_claude: false,
            }
        }
    }
}

/// What the client is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    Deny,
    Ask,
}

fn no_objection(form: Form) -> String {
    match form {
        Form::Nested { silent: true, .. } => String::new(),
        Form::Nested { silent: false, .. } => nested("allow", None),
        Form::Permission { .. } => json::object(&[("permission", json::string("allow"))]),
    }
}

fn nested(decision: &str, reason: Option<&str>) -> String {
    let mut members = vec![
        ("hookEventName", json::string("PreToolUse")),
        ("permissionDecision", json::string(decision)),
    ];
    if let Some(reason) = reason {
        members.push(("permissionDecisionReason", json::string(reason)));
    }
    json::object(&[("hookSpecificOutput", json::object(&members))])
}

fn answer_text(form: Form, sent: Sent, reason: &str) -> String {
    let word = match sent {
        Sent::Deny => "deny",
        Sent::Ask => "ask",
    };
    match form {
        Form::Nested { .. } => nested(word, Some(reason)),
        Form::Permission { .. } => json::object(&[
            ("permission", json::string(word)),
            ("user_message", json::string(reason)),
            ("agent_message", json::string(reason)),
        ]),
    }
}

fn can_ask(form: Form) -> bool {
    match form {
        Form::Nested { can_ask, .. } | Form::Permission { can_ask } => can_ask,
    }
}

/// Whether `client` can have a person approve a call of `tool` from its
/// hook: Claude Code always; Cursor for shell commands and MCP tools; Codex
/// never.
#[must_use]
pub fn can_ask_for(client: Client, tool: Tool) -> bool {
    match client {
        Client::ClaudeCode => true,
        Client::Cursor => matches!(tool, Tool::Bash | Tool::Mcp),
        Client::Codex => false,
    }
}

/// What a check is about, in words.
fn subject_words(tool: Tool, subject: &str) -> String {
    match tool {
        Tool::Bash => format!("the command `{subject}`"),
        Tool::Read => format!("reading `{subject}`"),
        Tool::Edit => format!("changing `{subject}`"),
        Tool::Mcp => format!("the MCP tool `{subject}`"),
        Tool::Web => match subject.strip_prefix("search:") {
            Some(query) => format!("the web search `{query}`"),
            None => format!("fetching `{subject}`"),
        },
        Tool::Secret => format!("a secret in this call ({subject})"),
    }
}

/// The reason the client is given for `verdict`; `mark` is the mark of the
/// call's session, which a `tainted` rule's answer names.
#[must_use]
pub fn reason(verdict: &Verdict, cannot_ask: Option<&str>, mark: Option<&Mark>) -> String {
    let decision = verdict.decision.unwrap_or(Decision::Ask);
    let deciding = verdict
        .deciding_check()
        .and_then(|check| check.rule.as_ref().map(|rule| (check, rule)));
    let mut text = match deciding {
        Some((check, rule)) => {
            let source = if rule.line == 0 {
                format!("memprove's built-in rule `{}`", rule.text())
            } else {
                format!("{POLICY_FILE}:{} `{}`", rule.line, rule.text())
            };
            let subject = subject_words(check.tool, &check.subject);
            let mut text = if decision == Decision::Deny {
                format!("memprove policy denies {subject} ({source})")
            } else {
                format!("memprove policy: {subject} needs a person's approval ({source})")
            };
            if let Some(why) = &rule.reason {
                text.push_str(": ");
                text.push_str(why);
            }
            if rule.tainted {
                match mark {
                    Some(mark) => {
                        let _ = write!(
                            text,
                            "; the rule applies because this session read content from outside \
                             ({} `{}`, {POLICY_FILE}:{} `{}`)",
                            mark.tool, mark.subject, mark.line, mark.rule
                        );
                    }
                    None => text
                        .push_str("; the rule applies in a session that a `taint` line has marked"),
                }
            }
            text
        }
        None => format!(
            "memprove policy: this command cannot be read in full ({}), so it needs a person's approval",
            verdict.problem.as_deref().unwrap_or("it could not be read")
        ),
    };
    if decision == Decision::Ask
        && let Some(client) = cannot_ask
    {
        let _ = write!(
            text,
            "; {client} cannot ask from a hook, so the call is refused: ask the user to run it, or \
             to change {POLICY_FILE}"
        );
    }
    text.push('.');
    text
}

/// Reads the policy file of `root`.
///
/// # Errors
///
/// Why it cannot be read or what is wrong with it, in one line.
pub fn load_policy(root: &Path) -> Result<Policy, String> {
    let path = root.join(POLICY_FILE);
    let bytes =
        fs::read(&path).map_err(|error| format!("{POLICY_FILE} cannot be read: {error}"))?;
    if bytes.len() > rules::MAX_POLICY_BYTES {
        return Err(format!("{POLICY_FILE} is larger than 1 MiB"));
    }
    let text = String::from_utf8(bytes).map_err(|_| format!("{POLICY_FILE} is not UTF-8"))?;
    rules::parse(&text).map_err(|errors| {
        let more = if errors.len() > 1 {
            format!(" (and {} more)", errors.len() - 1)
        } else {
            String::new()
        };
        format!("{POLICY_FILE} {}{more}", errors[0])
    })
}

/// Whether the repository's Cursor hooks run this policy's own Cursor hook.
fn cursor_hooks_installed(root: &Path) -> bool {
    fs::read_to_string(root.join(".cursor/hooks.json"))
        .is_ok_and(|text| text.contains("policy hook --client cursor"))
}

/// The hook: `input` from `client`.
#[must_use]
#[allow(clippy::too_many_lines)] // Reading, deciding and answering one call.
pub fn answer(client: Client, input: &[u8], env: &HookEnv) -> Answer {
    let unreadable = |why: String, form: Form| Answer {
        stdout: no_objection(form),
        warning: Some(format!(
            "memprove policy: the hook's input was not read ({why}); the call is left to {}",
            client.title()
        )),
        record: None,
        mark: None,
    };
    let fallback_form = match client {
        Client::Cursor => Form::Permission { can_ask: false },
        _ => Form::Nested {
            can_ask: false,
            silent: true,
        },
    };
    if input.len() > MAX_INPUT_BYTES {
        return unreadable("it is larger than 64 MiB".to_owned(), fallback_form);
    }
    let Ok(text) = std::str::from_utf8(input) else {
        return unreadable("it is not UTF-8".to_owned(), fallback_form);
    };
    let value = match parse_strict_with_limits(text, JsonLimits::default()) {
        Ok(value) => value,
        Err(error) => return unreadable(format!("it is not valid JSON: {error}"), fallback_form),
    };
    let event = event_of(client, &value, env);
    let form = event.form;
    let quiet = Answer {
        stdout: no_objection(form),
        warning: None,
        record: None,
        mark: None,
    };
    let Some(call) = event.call else {
        return quiet;
    };
    let start = event.start.unwrap_or_else(|| env.cwd.clone());
    let Some(root) = engine::find_root(&start) else {
        return quiet;
    };
    if event.cursor_through_claude && cursor_hooks_installed(&root) {
        return quiet;
    }
    let site = Site {
        root: root.clone(),
        cwd: event.cwd.unwrap_or(start),
        home: env.home.clone(),
    };
    // Cursor running the Claude Code hook is Cursor to the person.
    let client = if event.cursor_through_claude {
        Client::Cursor
    } else {
        client
    };
    let cannot_ask = (!can_ask(form)).then(|| client.title());
    let session = event.session.as_deref().and_then(taint::session_name);
    let mut mark = None;
    let (verdict, broken) = match load_policy(&root) {
        Ok(policy) => {
            // Only a call that changes files writes text into them.
            let written: &[Written] = match &call {
                Call::Edit(_) => &event.written,
                _ => &[],
            };
            if policy.follows_sessions()
                && let Some(session) = &session
            {
                mark = taint::read(&root, session);
            }
            let extra = Extra {
                written,
                tainted: mark.is_some(),
            };
            (engine::evaluate_with(&policy, &call, extra, &site), None)
        }
        Err(why) => (
            Verdict {
                decision: Some(Decision::Ask),
                deciding: None,
                checks: Vec::new(),
                problem: None,
                taint: None,
            },
            Some(why),
        ),
    };
    let sent = match verdict.decision {
        Some(Decision::Ask) if can_ask(form) => Some(Sent::Ask),
        Some(Decision::Deny | Decision::Ask) => Some(Sent::Deny),
        Some(Decision::Allow) | None => None,
    };
    // A call that matches a `taint` line marks its session, unless it is
    // refused here: it goes ahead, or does once a person approves it.
    let new_mark = match (&verdict.taint, &session) {
        (Some(marked), Some(session)) if mark.is_none() && sent != Some(Sent::Deny) => Some((
            root.clone(),
            session.clone(),
            Mark {
                time: env.time.clone(),
                client: client.name().to_owned(),
                tool: marked.tool.name().to_owned(),
                subject: log::redacted(&marked.subject),
                line: marked.taint.line,
                rule: marked.taint.text(),
            },
        )),
        _ => None,
    };
    let (Some(sent), Some(decision)) = (sent, verdict.decision) else {
        return Answer {
            mark: new_mark,
            ..quiet
        };
    };
    let text = match &broken {
        Some(why) => {
            let mut text = format!(
                "memprove policy: {why}, so every call needs a person's approval until a person fixes it"
            );
            if let Some(client) = cannot_ask {
                let _ = write!(
                    text,
                    "; {client} cannot ask from a hook, so the call is refused"
                );
            }
            text.push('.');
            text
        }
        None => reason(&verdict, cannot_ask, mark.as_ref()),
    };
    let check = verdict.deciding_check();
    let record = Record {
        time: env.time.clone(),
        client: client.name().to_owned(),
        tool: check.map_or_else(|| "-".to_owned(), |check| check.tool.name().to_owned()),
        subject: log::redacted(&match (check, &call) {
            (Some(check), _) => check.subject.clone(),
            (None, Call::Bash(command)) => command.clone(),
            (None, _) => "-".to_owned(),
        }),
        decision: decision.word().to_owned(),
        sent: match sent {
            Sent::Deny => "deny",
            Sent::Ask => "ask",
        }
        .to_owned(),
        line: check
            .and_then(|check| check.rule.as_ref())
            .map(|rule| rule.line),
        rule: check
            .and_then(|check| check.rule.as_ref())
            .map(rules::Rule::text),
    };
    Answer {
        stdout: answer_text(form, sent, &text),
        warning: None,
        record: Some((root, record)),
        mark: new_mark,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Repo {
        dir: tempfile::TempDir,
    }

    impl Repo {
        fn new(policy: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir_all(dir.path().join(".git")).unwrap();
            fs::create_dir_all(dir.path().join(".memprove")).unwrap();
            fs::write(dir.path().join(POLICY_FILE), policy).unwrap();
            Self { dir }
        }

        fn root(&self) -> &Path {
            self.dir.path()
        }

        fn env(&self) -> HookEnv {
            HookEnv {
                project_dir: None,
                cwd: self.root().to_path_buf(),
                home: Some(PathBuf::from("/home/me")),
                time: "2026-11-15T20:00:00Z".to_owned(),
            }
        }

        fn ask(&self, client: Client, input: &str) -> Answer {
            answer(
                client,
                input
                    .replace("ROOT", &self.root().display().to_string())
                    .as_bytes(),
                &self.env(),
            )
        }
    }

    const POLICY: &str = "deny Bash(git push *--force*) -- push a new branch\n\
                          ask Bash(git push *)\n\
                          deny Read(.env*)\n\
                          deny Edit(db/**)\n\
                          deny Mcp(github.merge_*)\n";

    #[test]
    fn claude_code_gets_deny_ask_or_nothing() {
        let repo = Repo::new(POLICY);
        let deny = repo.ask(
            Client::ClaudeCode,
            r#"{"hook_event_name":"PreToolUse","cwd":"ROOT","tool_name":"Bash","tool_input":{"command":"cd sub && git push --force"}}"#,
        );
        assert_eq!(
            deny.stdout,
            nested(
                "deny",
                Some(
                    "memprove policy denies the command `git push --force` (.memprove/policy.rules:1 `deny Bash(git push *--force*)`): push a new branch."
                )
            )
        );
        let (root, record) = deny.record.unwrap();
        assert_eq!(root, repo.root());
        assert_eq!(
            (record.decision.as_str(), record.sent.as_str(), record.line),
            ("deny", "deny", Some(1))
        );
        let ask = repo.ask(
            Client::ClaudeCode,
            r#"{"cwd":"ROOT","tool_name":"Bash","tool_input":{"command":"git push origin x"}}"#,
        );
        assert!(ask.stdout.contains("\"permissionDecision\":\"ask\""));
        let none = repo.ask(
            Client::ClaudeCode,
            r#"{"cwd":"ROOT","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
        );
        assert_eq!(none, Answer::default());
        let read = repo.ask(
            Client::ClaudeCode,
            r#"{"cwd":"ROOT","tool_name":"Read","tool_input":{"file_path":"ROOT/.env"}}"#,
        );
        assert!(read.stdout.contains("denies reading `.env`"));
        let edit = repo.ask(Client::ClaudeCode, r#"{"cwd":"ROOT","tool_name":"Write","tool_input":{"file_path":"ROOT/db/x.sql","content":"x"}}"#);
        assert!(edit.stdout.contains("denies changing `db/x.sql`"));
        let mcp = repo.ask(
            Client::ClaudeCode,
            r#"{"cwd":"ROOT","tool_name":"mcp__github__merge_pull_request","tool_input":{}}"#,
        );
        assert!(
            mcp.stdout
                .contains("the MCP tool `github.merge_pull_request`")
        );
    }

    #[test]
    fn codex_cannot_ask_so_ask_is_refused() {
        let repo = Repo::new(POLICY);
        let ask = repo.ask(
            Client::Codex,
            r#"{"cwd":"ROOT","tool_name":"Bash","tool_input":{"command":"git push origin x"}}"#,
        );
        assert!(ask.stdout.contains("\"permissionDecision\":\"deny\""));
        assert!(ask.stdout.contains("Codex cannot ask from a hook"));
        assert_eq!(ask.record.unwrap().1.sent, "deny");
        let patch = repo.ask(
            Client::Codex,
            r#"{"cwd":"ROOT","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: src/a.rs\n*** Add File: db/m.sql\n+x\n*** End Patch\n"}}"#,
        );
        assert!(patch.stdout.contains("changing `db/m.sql`"));
        let words = repo.ask(Client::Codex, r#"{"cwd":"ROOT","tool_name":"Bash","tool_input":{"command":["bash","-lc","cat .env"]}}"#);
        assert!(words.stdout.contains("reading `.env`"));
        let quiet = repo.ask(
            Client::Codex,
            r#"{"cwd":"ROOT","tool_name":"update_plan","tool_input":{}}"#,
        );
        assert_eq!(quiet.stdout, "");
    }

    #[test]
    fn cursor_gets_its_permission_form() {
        let repo = Repo::new(POLICY);
        let shell = repo.ask(Client::Cursor, r#"{"hook_event_name":"beforeShellExecution","cursor_version":"2","command":"git push origin x","cwd":"ROOT","workspace_roots":["ROOT"]}"#);
        assert!(
            shell
                .stdout
                .starts_with("{\"permission\":\"ask\",\"user_message\":")
        );
        let read = repo.ask(Client::Cursor, r#"{"hook_event_name":"beforeReadFile","cursor_version":"2","file_path":"ROOT/.env","content":"K=1","workspace_roots":["ROOT"]}"#);
        assert!(read.stdout.starts_with("{\"permission\":\"deny\""));
        let mcp = repo.ask(Client::Cursor, r#"{"hook_event_name":"beforeMCPExecution","cursor_version":"2","tool_name":"merge_pull_request","mcp_server_name":"github","tool_input":"{}","workspace_roots":["ROOT"]}"#);
        assert!(mcp.stdout.starts_with("{\"permission\":\"deny\""));
        let write = repo.ask(Client::Cursor, r#"{"hook_event_name":"preToolUse","cursor_version":"2","tool_name":"Write","tool_input":{"file_path":"ROOT/README.md"},"workspace_roots":["ROOT"]}"#);
        assert_eq!(write.stdout, "{\"permission\":\"allow\"}");
        let other = repo.ask(
            Client::Cursor,
            r#"{"hook_event_name":"sessionStart","cursor_version":"2"}"#,
        );
        assert_eq!(other.stdout, "{\"permission\":\"allow\"}");
    }

    #[test]
    fn cursor_running_the_claude_hook_defers_to_its_own_hooks() {
        let repo = Repo::new(POLICY);
        let input = r#"{"hook_event_name":"preToolUse","cursor_version":"2","tool_name":"Shell","tool_input":{"command":"git push origin x"},"workspace_roots":["ROOT"]}"#;
        let alone = repo.ask(Client::ClaudeCode, input);
        assert!(alone.stdout.contains("\"permissionDecision\":\"deny\""));
        assert!(alone.stdout.contains("Cursor cannot ask from a hook"));
        fs::create_dir_all(repo.root().join(".cursor")).unwrap();
        fs::write(repo.root().join(".cursor/hooks.json"), "{\"hooks\":{\"beforeShellExecution\":[{\"command\":\"'m' policy hook --client cursor\"}]}}").unwrap();
        let deferred = repo.ask(Client::ClaudeCode, input);
        assert_eq!(deferred.stdout, nested("allow", None));
    }

    #[test]
    fn a_broken_policy_sends_every_call_to_a_person() {
        let repo = Repo::new("deny Bash(x\n");
        let answer = repo.ask(
            Client::ClaudeCode,
            r#"{"cwd":"ROOT","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
        );
        assert!(answer.stdout.contains("\"permissionDecision\":\"ask\""));
        assert!(
            answer
                .stdout
                .contains(".memprove/policy.rules line 1: the pattern is not closed")
        );
    }

    #[test]
    fn unreadable_input_and_no_policy_leave_the_call_to_the_client() {
        let repo = Repo::new(POLICY);
        let bad = repo.ask(Client::ClaudeCode, "not json");
        assert_eq!(bad.stdout, "");
        assert!(bad.warning.unwrap().contains("not valid JSON"));
        let bad_cursor = repo.ask(Client::Cursor, "{");
        assert_eq!(bad_cursor.stdout, "{\"permission\":\"allow\"}");
        let elsewhere = tempfile::tempdir().unwrap();
        fs::create_dir(elsewhere.path().join(".git")).unwrap();
        let input = format!(
            r#"{{"cwd":"{}","tool_name":"Bash","tool_input":{{"command":"git push --force"}}}}"#,
            elsewhere.path().display()
        );
        assert_eq!(
            answer(Client::ClaudeCode, input.as_bytes(), &repo.env()),
            Answer::default()
        );
    }

    /// A token of GitHub's format that GitHub never issued.
    fn made_token() -> String {
        let body: String = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"
            .chars()
            .cycle()
            .take(36)
            .collect();
        format!("ghp_{body}")
    }

    #[test]
    fn a_secret_in_a_command_is_asked_about_and_never_repeated() {
        let repo =
            Repo::new("ask Secret(*) -- use an environment variable\ndeny Bash(sshpass *)\n");
        let asked = repo.ask(
            Client::ClaudeCode,
            r#"{"cwd":"ROOT","tool_name":"Bash","tool_input":{"command":"PGPASSWORD=hunter2 psql -h db"}}"#,
        );
        assert!(asked.stdout.contains("\"permissionDecision\":\"ask\""));
        assert!(
            asked
                .stdout
                .contains("a secret in this call (password in PGPASSWORD: h"),
            "{}",
            asked.stdout
        );
        assert!(
            asked
                .stdout
                .contains("`ask Secret(*)`): use an environment variable.")
        );
        assert!(!asked.stdout.contains("hunter2"));
        let record = asked.record.unwrap().1;
        assert_eq!(
            (record.tool.as_str(), record.subject.as_str(), record.line),
            (
                "Secret",
                "password in PGPASSWORD: h…(7 characters)",
                Some(1)
            )
        );
        // Codex cannot ask, so the call is refused.
        let codex = repo.ask(
            Client::Codex,
            r#"{"cwd":"ROOT","tool_name":"Bash","tool_input":{"command":["bash","-lc","curl -u deploy:tr0ub4dor https://x.internal"]}}"#,
        );
        assert!(codex.stdout.contains("\"permissionDecision\":\"deny\""));
        assert!(codex.stdout.contains("Codex cannot ask from a hook"));
        // A command another rule refuses is logged without its password.
        let denied = repo.ask(
            Client::ClaudeCode,
            r#"{"cwd":"ROOT","tool_name":"Bash","tool_input":{"command":"sshpass -p tr0ub4dor ssh host"}}"#,
        );
        let record = denied.record.unwrap().1;
        assert_eq!(
            (record.tool.as_str(), record.subject.as_str()),
            ("Bash", "sshpass -p tr…(9 characters) ssh host")
        );
        let none = repo.ask(
            Client::ClaudeCode,
            r#"{"cwd":"ROOT","tool_name":"Bash","tool_input":{"command":"PGPASSWORD=\"$DB_PASSWORD\" psql -h db"}}"#,
        );
        assert_eq!(none, Answer::default());
    }

    #[test]
    fn a_secret_in_the_text_a_call_writes_is_asked_about() {
        let repo = Repo::new("deny Secret(private-key)\nask Secret(*)\n");
        let token = made_token();
        let write = repo.ask(
            Client::ClaudeCode,
            &format!(
                r#"{{"cwd":"ROOT","tool_name":"Write","tool_input":{{"file_path":"ROOT/src/config.ts","content":"export const token = \"{token}\";\n"}}}}"#
            ),
        );
        assert!(write.stdout.contains("\"permissionDecision\":\"ask\""));
        assert!(!write.stdout.contains(&token));
        let record = write.record.unwrap().1;
        assert_eq!(
            (record.tool.as_str(), record.subject.as_str()),
            ("Secret", "github-token: ghp_…(40 characters)")
        );
        let edit = repo.ask(
            Client::ClaudeCode,
            r#"{"cwd":"ROOT","tool_name":"Edit","tool_input":{"file_path":"ROOT/deploy/key","old_string":"x","new_string":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n"}}"#,
        );
        assert!(edit.stdout.contains("\"permissionDecision\":\"deny\""));
        let multi = repo.ask(
            Client::ClaudeCode,
            &format!(
                r#"{{"cwd":"ROOT","tool_name":"MultiEdit","tool_input":{{"file_path":"ROOT/a.py","edits":[{{"old_string":"a","new_string":"b"}},{{"old_string":"c","new_string":"T = '{token}'"}}]}}}}"#
            ),
        );
        assert!(multi.stdout.contains("\"permissionDecision\":\"ask\""));
        // What an edit takes out is not written.
        let removes = repo.ask(
            Client::ClaudeCode,
            &format!(
                r#"{{"cwd":"ROOT","tool_name":"Edit","tool_input":{{"file_path":"ROOT/a.py","old_string":"T = '{token}'","new_string":"T = os.environ['TOKEN']"}}}}"#
            ),
        );
        assert_eq!(removes, Answer::default());
        // Codex's patch: the lines it adds, not the ones it removes.
        let patch = |sign: char| {
            repo.ask(
                Client::Codex,
                &format!(
                    r#"{{"cwd":"ROOT","tool_name":"apply_patch","tool_input":{{"command":"*** Begin Patch\n*** Update File: a.py\n@@\n{sign}T = '{token}'\n*** End Patch\n"}}}}"#
                ),
            )
        };
        let added = patch('+');
        assert!(added.stdout.contains("\"permissionDecision\":\"deny\""));
        assert!(added.stdout.contains("Codex cannot ask from a hook"));
        assert_eq!(patch('-').stdout, "");
        // Cursor's file writes cannot ask either.
        let cursor = repo.ask(
            Client::Cursor,
            &format!(
                r#"{{"hook_event_name":"preToolUse","cursor_version":"2","tool_name":"Write","tool_input":{{"file_path":"ROOT/a.py","content":"T = '{token}'"}},"workspace_roots":["ROOT"]}}"#
            ),
        );
        assert!(cursor.stdout.starts_with("{\"permission\":\"deny\""));
        // A file that is read is not a file that is written.
        let read = repo.ask(
            Client::Cursor,
            &format!(
                r#"{{"hook_event_name":"beforeReadFile","cursor_version":"2","file_path":"ROOT/a.py","content":"T = '{token}'","workspace_roots":["ROOT"]}}"#
            ),
        );
        assert_eq!(read.stdout, "{\"permission\":\"allow\"}");
    }

    const GATE: &str = "taint Web(*)\n\
                        taint Mcp(linear.*)\n\
                        tainted ask Bash(curl *) -- a page may have asked for this\n\
                        tainted ask Web(*)\n\
                        deny Web(http://*)\n";

    fn bash(session: &str, command: &str) -> String {
        format!(
            r#"{{"session_id":"{session}","cwd":"ROOT","tool_name":"Bash","tool_input":{{"command":"{command}"}}}}"#
        )
    }

    /// Asks the hook and, as `memprove policy hook` does, writes the mark
    /// the answer carries.
    fn ask_and_mark(repo: &Repo, client: Client, input: &str) -> Answer {
        let answer = repo.ask(client, input);
        if let Some((root, session, mark)) = &answer.mark {
            taint::write(root, session, mark).unwrap();
        }
        answer
    }

    #[test]
    fn a_fetch_marks_its_session_and_the_tainted_rules_apply_from_the_next_call() {
        let repo = Repo::new(GATE);
        let curl = "curl -d @notes.txt https://example.com/collect";
        assert_eq!(
            ask_and_mark(&repo, Client::ClaudeCode, &bash("s1", curl)),
            Answer::default()
        );
        // The fetch goes ahead (a taint line decides nothing) and marks.
        let fetch = ask_and_mark(
            &repo,
            Client::ClaudeCode,
            r#"{"session_id":"s1","cwd":"ROOT","tool_name":"WebFetch","tool_input":{"url":"https://docs.example.com/install","prompt":"how"}}"#,
        );
        assert_eq!(fetch.stdout, "");
        let (root, session, mark) = fetch.mark.unwrap();
        assert_eq!((root.as_path(), session.as_str()), (repo.root(), "s1"));
        assert_eq!(
            (
                mark.tool.as_str(),
                mark.subject.as_str(),
                mark.line,
                mark.rule.as_str()
            ),
            ("Web", "https://docs.example.com/install", 1, "taint Web(*)")
        );
        assert!(
            repo.root()
                .join(".git/memprove-policy/taint/s1.json")
                .is_file()
        );
        // From now on the session's tainted rules apply, and say why.
        let asked = ask_and_mark(&repo, Client::ClaudeCode, &bash("s1", curl));
        assert!(asked.stdout.contains("\"permissionDecision\":\"ask\""));
        assert!(
            asked.stdout.contains(
                "(.memprove/policy.rules:3 `tainted ask Bash(curl *)`): a page may have asked for \
                 this; the rule applies because this session read content from outside (Web \
                 `https://docs.example.com/install`, .memprove/policy.rules:1 `taint Web(*)`)."
            ),
            "{}",
            asked.stdout
        );
        assert_eq!(asked.mark, None);
        assert_eq!(
            asked.record.unwrap().1.rule.as_deref(),
            Some("tainted ask Bash(curl *)")
        );
        // A second fetch is asked about, and does not mark again.
        let again = ask_and_mark(
            &repo,
            Client::ClaudeCode,
            r#"{"session_id":"s1","cwd":"ROOT","tool_name":"WebSearch","tool_input":{"query":"x"}}"#,
        );
        assert!(
            again
                .stdout
                .contains("the web search `x` needs a person's approval")
        );
        assert_eq!(again.mark, None);
        // Another session, and a call with no session, are not marked.
        assert_eq!(
            ask_and_mark(&repo, Client::ClaudeCode, &bash("s2", curl)),
            Answer::default()
        );
        let nameless =
            format!(r#"{{"cwd":"ROOT","tool_name":"Bash","tool_input":{{"command":"{curl}"}}}}"#);
        assert_eq!(
            ask_and_mark(&repo, Client::ClaudeCode, &nameless),
            Answer::default()
        );
    }

    #[test]
    fn a_refused_call_does_not_mark_and_other_clients_sessions_are_marked_too() {
        let repo = Repo::new(GATE);
        // Refused by a rule: the page is not read, the session not marked.
        let refused = ask_and_mark(
            &repo,
            Client::ClaudeCode,
            r#"{"session_id":"s1","cwd":"ROOT","tool_name":"WebFetch","tool_input":{"url":"http://docs.example.com/"}}"#,
        );
        assert!(
            refused
                .stdout
                .contains("denies fetching `http://docs.example.com/`")
        );
        assert_eq!(refused.mark, None);
        // Codex: an MCP tool marks, by the session id Codex gives.
        let codex = ask_and_mark(
            &repo,
            Client::Codex,
            r#"{"session_id":"thr_1","cwd":"ROOT","tool_name":"mcp__linear__get_issue","tool_input":{"id":"X-1"}}"#,
        );
        assert_eq!(codex.stdout, "");
        assert_eq!(codex.mark.unwrap().2.subject, "linear.get_issue");
        let curl = ask_and_mark(
            &repo,
            Client::Codex,
            &bash("thr_1", "curl https://example.com"),
        );
        assert!(curl.stdout.contains("\"permissionDecision\":\"deny\""));
        assert!(curl.stdout.contains("Codex cannot ask from a hook"));
        // Cursor: by its conversation id.
        let cursor_mcp = ask_and_mark(
            &repo,
            Client::Cursor,
            r#"{"hook_event_name":"beforeMCPExecution","cursor_version":"2","conversation_id":"c-1","tool_name":"get_issue","mcp_server_name":"linear","tool_input":"{}","workspace_roots":["ROOT"]}"#,
        );
        assert_eq!(cursor_mcp.stdout, "{\"permission\":\"allow\"}");
        assert!(cursor_mcp.mark.is_some());
        let cursor_shell = ask_and_mark(
            &repo,
            Client::Cursor,
            r#"{"hook_event_name":"beforeShellExecution","cursor_version":"2","conversation_id":"c-1","command":"curl https://example.com","cwd":"ROOT","workspace_roots":["ROOT"]}"#,
        );
        assert!(cursor_shell.stdout.starts_with("{\"permission\":\"ask\""));
        // A policy with no taint line and no tainted rule reads no mark.
        let plain = Repo::new("ask Bash(git push *)\n");
        assert_eq!(
            ask_and_mark(
                &plain,
                Client::ClaudeCode,
                r#"{"session_id":"s1","cwd":"ROOT","tool_name":"WebFetch","tool_input":{"url":"https://docs.example.com/"}}"#,
            ),
            Answer::default()
        );
        assert!(!plain.root().join(".git/memprove-policy").exists());
    }

    #[test]
    fn patches_name_their_files() {
        assert_eq!(
            patch_written(
                "*** Begin Patch\n*** Update File: a.rs\n@@ fn main\n-old\n+new one\n context\n*** Add File: b.txt\n+x\n+y\n*** Delete File: c.rs\n*** Update File: d.rs\n*** Move to: e.rs\n-z\n*** End Patch"
            ),
            vec![
                Written {
                    path: "a.rs".to_owned(),
                    text: "new one\n".to_owned()
                },
                Written {
                    path: "b.txt".to_owned(),
                    text: "x\ny\n".to_owned()
                },
            ]
        );
        assert_eq!(
            patch_paths(
                "*** Begin Patch\n*** Update File: a.rs\n*** Move to: b.rs\n*** Delete File: c.rs\n*** End Patch"
            ),
            vec!["a.rs", "b.rs", "c.rs"]
        );
    }
}
