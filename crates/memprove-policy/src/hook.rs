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

use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use memprove_protocol::strict_json::{JsonLimits, parse_strict_with_limits};

use crate::{
    engine::{self, Call, POLICY_FILE, Site, Verdict},
    json::{self, JsonValue},
    log::{self, Record},
    rules::{self, Decision, Policy, Tool},
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

fn claude_call(tool: &str, input: &JsonValue) -> Option<Call> {
    match tool {
        "Bash" => json::str_at(input, "command").map(|command| Call::Bash(command.to_owned())),
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
    match client {
        Client::ClaudeCode if cursor_shaped => Event {
            call: cursor_tool_call(tool, tool_input),
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
    }
}

/// The reason the client is given for `verdict`.
#[must_use]
pub fn reason(verdict: &Verdict, cannot_ask: Option<&str>) -> String {
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
    let (verdict, broken) = match load_policy(&root) {
        Ok(policy) => (engine::evaluate(&policy, &call, &site), None),
        Err(why) => (
            Verdict {
                decision: Some(Decision::Ask),
                deciding: None,
                checks: Vec::new(),
                problem: None,
            },
            Some(why),
        ),
    };
    let Some(decision @ (Decision::Deny | Decision::Ask)) = verdict.decision else {
        return quiet;
    };
    let sent = if decision == Decision::Deny || !can_ask(form) {
        Sent::Deny
    } else {
        Sent::Ask
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
        None => reason(&verdict, cannot_ask),
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

    #[test]
    fn patches_name_their_files() {
        assert_eq!(
            patch_paths(
                "*** Begin Patch\n*** Update File: a.rs\n*** Move to: b.rs\n*** Delete File: c.rs\n*** End Patch"
            ),
            vec!["a.rs", "b.rs", "c.rs"]
        );
    }
}
