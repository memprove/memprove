//! `memprove policy scan`: credentials in the files coding agents write and
//! read in a repository. An "always allow" click stores the whole command
//! in a settings file, password and all; an MCP entry keeps an API key in
//! its `env`; an instruction file quotes the command that worked. This
//! reads those files and names each credential by file, line and kind,
//! without ever printing one ([`crate::secrets::redacted`]).
//!
//! A JSON file is read as JSON: a `command` (with its `args`) and a
//! `Bash(…)` rule as a shell reads them, a member by its name, every string
//! for credentials of a known format. Any other file is read line by line:
//! `name = value` lines, `NAME=value` words, code spans and code blocks as
//! commands, and the same formats.
//!
//! The scan asks Git which of the files it tracks, the one command this
//! crate runs; without Git the answer is "unknown". Nothing is sent
//! anywhere and no secret is checked against a service.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use memprove_protocol::strict_json::parse_strict;

use crate::{
    json::{self, JsonValue},
    secrets::{self, Finding},
};

/// The schema of `memprove policy scan --json`.
pub const SCAN_SCHEMA: &str = "memprove.policy.scan.v1";
/// The largest file read.
pub const MAX_FILE_BYTES: u64 = 4 << 20;
/// The most files read in one scan.
pub const MAX_FILES: usize = 5000;
/// The deepest directory below a scanned one.
const MAX_DEPTH: usize = 8;

/// Where coding agents keep settings, instructions and saved sessions in a
/// repository: what a scan reads when no path is given.
pub const AGENT_PATHS: &[&str] = &[
    ".claude",
    ".mcp.json",
    ".codex",
    ".cursor",
    ".cursorrules",
    ".trae",
    ".gemini",
    ".specstory",
    ".memprove",
    ".vscode/mcp.json",
    ".windsurfrules",
    ".clinerules",
    ".github/copilot-instructions.md",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "GEMINI.md",
];

/// Whether `relative`, a path below the repository root, is one of the
/// files a scan reads when no path is given, or is below one.
#[must_use]
pub fn is_agent_path(relative: &Path) -> bool {
    AGENT_PATHS.iter().any(|agent| relative.starts_with(agent))
}

/// Directories never entered.
const SKIPPED_DIRS: &[&str] = &[".git", "node_modules", "target"];

/// One credential in a file's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The line, from 1; 0 when it could not be told.
    pub line: usize,
    /// Where in a JSON file: `permissions.allow[3]`.
    pub place: Option<String>,
    /// The credential.
    pub finding: Finding,
}

/// What Git does with a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitState {
    /// In the index: committed, or about to be.
    Tracked,
    /// Ignored.
    Ignored,
    /// Neither: the next `git add .` takes it.
    Untracked,
    /// Not asked, or Git did not answer.
    Unknown,
}

impl GitState {
    /// The word of `--json`.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Tracked => "tracked",
            Self::Ignored => "ignored",
            Self::Untracked => "untracked",
            Self::Unknown => "unknown",
        }
    }

    const fn phrase(self) -> Option<&'static str> {
        match self {
            Self::Tracked => Some("file tracked by Git"),
            Self::Ignored => Some("file ignored by Git"),
            Self::Untracked => Some("file not tracked and not ignored"),
            Self::Unknown => None,
        }
    }
}

/// One credential of a scan, as it is reported: without its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The file, relative to the repository root when it is inside it.
    pub path: String,
    /// The line, from 1; 0 when it could not be told.
    pub line: usize,
    /// `password`, or the name of the format.
    pub kind: &'static str,
    /// The variable, option, header or URL that holds it.
    pub name: Option<String>,
    /// Where in a JSON file.
    pub place: Option<String>,
    /// The value, redacted.
    pub shown: String,
    /// The value's length in characters.
    pub length: usize,
    /// What Git does with the file.
    pub git: GitState,
}

/// The result of a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The files read.
    pub files: usize,
    /// The files not read, and why.
    pub skipped: Vec<(String, String)>,
    /// The credentials, in the order of the files.
    pub findings: Vec<Found>,
}

fn merge(out: &mut Vec<Finding>, found: Vec<Finding>) {
    for finding in found {
        secrets::merge(out, finding);
    }
}

/// The command of a tool rule: `Bash(psql -h db:*)` gives `psql -h db`.
fn rule_command(text: &str) -> Option<&str> {
    let inner = ["Bash(", "Shell("]
        .iter()
        .find_map(|tool| text.strip_prefix(tool))?
        .strip_suffix(')')?;
    Some(inner.strip_suffix(":*").unwrap_or(inner))
}

/// The credentials of one JSON string, held by the member `name` (empty
/// for an array's item).
fn in_string(name: &str, text: &str) -> Vec<Finding> {
    let mut found = Vec::new();
    if let Some(finding) = (!name.is_empty())
        .then(|| secrets::in_member(name, text))
        .flatten()
    {
        found.push(finding);
    }
    if let Some(command) = rule_command(text) {
        merge(&mut found, secrets::in_command(command));
    }
    merge(&mut found, secrets::in_text(text));
    if text.contains("://") {
        merge(&mut found, secrets::in_pairs(text));
    }
    found
}

fn strings_of(items: &[JsonValue]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// A credential of a JSON document before its line is known: where it
/// stands, and the string that holds it.
struct Raw {
    place: String,
    source: String,
    finding: Finding,
}

/// The credentials of a JSON value.
fn walk(value: &JsonValue, place: &str, out: &mut Vec<Raw>) {
    let at = |name: &str| {
        if place.is_empty() {
            name.to_owned()
        } else {
            format!("{place}.{name}")
        }
    };
    let push = |out: &mut Vec<Raw>, place: String, source: &str, found: Vec<Finding>| {
        out.extend(found.into_iter().map(|finding| Raw {
            place: place.clone(),
            source: source.to_owned(),
            finding,
        }));
    };
    match value {
        JsonValue::Object(members) => {
            let command = json::str_at(value, "command");
            match value.get("args").and_then(JsonValue::as_array) {
                Some(args) => {
                    // The command and its arguments are one command's words;
                    // each credential stands in the word that holds it.
                    let args = strings_of(args);
                    let mut words: Vec<String> = command.iter().map(|&c| c.to_owned()).collect();
                    words.extend(args.iter().cloned());
                    for finding in secrets::in_words(&words) {
                        let held_by = args.iter().position(|word| word.contains(&finding.value));
                        let (place, source) = match (held_by, command) {
                            (Some(index), _) => {
                                (format!("{}[{index}]", at("args")), args[index].as_str())
                            }
                            (None, Some(command)) => (at("command"), command),
                            (None, None) => continue,
                        };
                        push(out, place, source, vec![finding]);
                    }
                }
                None => {
                    if let Some(command) = command {
                        push(out, at("command"), command, secrets::in_command(command));
                    }
                }
            }
            for (name, member) in members {
                match member {
                    JsonValue::String(text) => push(out, at(name), text, in_string(name, text)),
                    JsonValue::Array(_) | JsonValue::Object(_) => walk(member, &at(name), out),
                    _ => {}
                }
            }
        }
        JsonValue::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let here = format!("{place}[{index}]");
                match item {
                    JsonValue::String(text) => push(out, here, text, in_string("", text)),
                    other => walk(other, &here, out),
                }
            }
        }
        _ => {}
    }
}

/// The hits of a JSON document, each on the line of `text` where the
/// string that holds it stands (the next such string for the next hit of
/// the same value in the same string).
fn located(value: &JsonValue, text: &str, first_line: usize) -> Vec<Hit> {
    let mut found = Vec::new();
    walk(value, "", &mut found);
    let line_at = |offset: usize| first_line + text[..offset].matches('\n').count();
    // Where the search for a string and value goes on from.
    let mut after: Vec<((String, String), usize)> = Vec::new();
    let mut done: Vec<(String, String)> = Vec::new();
    let mut hits: Vec<Hit> = Vec::new();
    for raw in found {
        // Two detectors may find one credential in one string.
        let once = (raw.place.clone(), raw.finding.value.clone());
        if done.contains(&once) {
            continue;
        }
        done.push(once);
        let source = json::string(&raw.source);
        let encoded = json::string(&raw.finding.value);
        let needle = &encoded[1..encoded.len() - 1];
        let key = (source.clone(), raw.finding.value.clone());
        let known = after.iter().position(|(seen, _)| *seen == key);
        let from = known.map_or(0, |index| after[index].1);
        let line = match text[from..].find(&source) {
            Some(offset) => {
                let start = from + offset;
                let end = start + source.len();
                match known {
                    Some(index) => after[index].1 = end,
                    None => after.push((key, end)),
                }
                line_at(start + source.find(needle).unwrap_or(0))
            }
            // Written with other escapes than this crate writes: the value
            // alone, where it first stands.
            None => text.find(needle).map_or(0, line_at),
        };
        hits.push(Hit {
            line,
            place: Some(raw.place),
            finding: raw.finding,
        });
    }
    hits
}

/// The quoted strings of a line. A `'` after a letter is an apostrophe.
fn quoted(line: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let mut before: Option<char> = None;
    let mut chars = line.chars();
    while let Some(character) = chars.next() {
        let opens = match character {
            '"' => true,
            '\'' => !before.is_some_and(char::is_alphanumeric),
            _ => false,
        };
        if opens {
            let mut inner = String::new();
            let mut closed = false;
            while let Some(next) = chars.next() {
                if next == '\\' && character == '"' {
                    inner.extend(chars.next());
                } else if next == character {
                    closed = true;
                    break;
                } else {
                    inner.push(next);
                }
            }
            if closed {
                strings.push(inner);
            }
            before = Some(character);
        } else {
            before = Some(character);
        }
    }
    strings
}

/// Bare values of a `name: value` line that are a type or nothing, not a
/// secret.
const NOT_VALUES: &[&str] = &[
    "string",
    "str",
    "&str",
    "bool",
    "boolean",
    "number",
    "int",
    "integer",
    "bytes",
    "undefined",
];

/// The name and value of a `name = value` or `name: value` line (a dotenv,
/// TOML, YAML or JSON-like line); a bare value is one word.
fn key_value(line: &str) -> Option<(String, String)> {
    let mut rest = line.trim_start();
    for prefix in ["export ", "- ", "set "] {
        rest = rest.strip_prefix(prefix).unwrap_or(rest).trim_start();
    }
    let (name, after) = if let Some(quote @ ('"' | '\'')) = rest.chars().next() {
        rest[1..].split_once(quote)?
    } else {
        let end = rest
            .find(|character: char| {
                !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
            })
            .unwrap_or(rest.len());
        rest.split_at(end)
    };
    let after = after.trim_start();
    let value = after
        .strip_prefix('=')
        .or_else(|| after.strip_prefix(':'))?
        .trim();
    if name.is_empty() || value.starts_with(['=', '>', '/']) {
        return None;
    }
    if let Some(quote @ ('"' | '\'')) = value.chars().next() {
        let (inner, _) = value[1..].split_once(quote)?;
        return Some((name.to_owned(), inner.to_owned()));
    }
    let mut words = value.split_whitespace();
    let word = words.next()?.trim_end_matches([',', ';']);
    if words
        .next()
        .is_some_and(|next| !next.starts_with(['#', '/']))
        || word.contains(['(', ')', '<', '>', '{', '}', '[', ']'])
        || NOT_VALUES.contains(&word.to_ascii_lowercase().as_str())
    {
        return None;
    }
    Some((name.to_owned(), word.to_owned()))
}

/// Whether a file is a shell script, by its name or its first line.
fn is_shell(name: &str, text: &str) -> bool {
    let extension = name.rsplit('.').next().unwrap_or_default();
    matches!(extension, "sh" | "bash" | "zsh")
        || text
            .lines()
            .next()
            .is_some_and(|first| first.starts_with("#!") && first.contains("sh"))
}

/// The credentials of a text that is not JSON, line by line.
fn in_lines(name: &str, text: &str) -> Vec<Hit> {
    let shell = is_shell(name, text);
    let policy_file = Path::new(name)
        .file_name()
        .is_some_and(|file| file == "policy.rules");
    let mut fenced = false;
    let mut hits = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        let mut found = Vec::new();
        if policy_file {
            // In a policy file an `expect` line is a test, its secret made
            // up, and a `Bash(…)` rule is read as the command it matches.
            if trimmed.split_whitespace().next() == Some("expect") {
                continue;
            }
            if let Ok(policy) = crate::rules::parse(trimmed) {
                for rule in &policy.rules {
                    if rule.tool == crate::rules::Tool::Bash {
                        merge(&mut found, secrets::in_command(&rule.pattern));
                    }
                }
            }
        }
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fenced = !fenced;
        } else if shell || fenced {
            let command = trimmed.strip_prefix("$ ").unwrap_or(trimmed);
            merge(&mut found, secrets::in_command(command));
        } else {
            if let Some(command) = trimmed.strip_prefix("$ ") {
                merge(&mut found, secrets::in_command(command));
            }
            for span in line.split('`').skip(1).step_by(2) {
                merge(&mut found, secrets::in_command(span));
            }
            let strings = quoted(line);
            for string in &strings {
                if string.contains(char::is_whitespace) {
                    merge(&mut found, secrets::in_command(string));
                }
            }
            if strings.len() >= 2 {
                merge(&mut found, secrets::in_words(&strings));
            }
            // `NAME=value` written into a sentence.
            for word in line.split_whitespace() {
                let word = word
                    .trim_start_matches(['`', '"', '\'', '('])
                    .trim_end_matches(['`', '"', '\'', ')', ',', ';', '.']);
                if let Some((name, value)) = word.split_once('=')
                    && !name.is_empty()
                    && name
                        .chars()
                        .all(|character| character == '_' || character.is_ascii_alphanumeric())
                    && let Some(finding) = secrets::in_member(name, value)
                {
                    secrets::merge(&mut found, finding);
                }
            }
        }
        if let Some(finding) =
            key_value(line).and_then(|(name, value)| secrets::in_member(&name, &value))
        {
            secrets::merge(&mut found, finding);
        }
        merge(&mut found, secrets::in_text(line));
        hits.extend(found.into_iter().map(|finding| Hit {
            line: index + 1,
            place: None,
            finding,
        }));
    }
    hits
}

/// The credentials in the text of the file `name`.
#[must_use]
pub fn in_file(name: &str, text: &str) -> Vec<Hit> {
    let extension = name.rsplit('.').next().unwrap_or_default();
    if matches!(extension, "jsonl" | "ndjson") {
        let mut hits = Vec::new();
        for (index, line) in text.lines().enumerate() {
            match parse_strict(line) {
                Ok(value) => hits.extend(located(&value, line, index + 1)),
                Err(_) => hits.extend(in_lines(name, line).into_iter().map(|hit| Hit {
                    line: index + 1,
                    ..hit
                })),
            }
        }
        return hits;
    }
    if (extension == "json" || text.trim_start().starts_with('{'))
        && let Ok(value) = parse_strict(text)
    {
        return located(&value, text, 1);
    }
    in_lines(name, text)
}

/// The files at and below `path`, in name order; symbolic links and
/// [`SKIPPED_DIRS`] are left out.
fn files_below(path: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.is_file() {
        out.push(path.to_path_buf());
    } else if metadata.is_dir() && depth <= MAX_DEPTH {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        let mut children: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|child| {
                !child
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| SKIPPED_DIRS.contains(&name))
            })
            .collect();
        children.sort();
        for child in children {
            files_below(&child, depth + 1, out);
        }
    }
}

/// `path` as a scan shows it: relative to `root` when inside it.
fn shown(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// The files among `paths` (relative to `root`) that `git ls-files` with
/// `options` lists; `None` when Git does not answer.
fn git_lists(root: &Path, options: &[&str], paths: &[&str]) -> Option<BTreeSet<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .args(options)
        .arg("--")
        .args(paths)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output.status.success().then(|| {
        String::from_utf8_lossy(&output.stdout)
            .split('\0')
            .filter(|path| !path.is_empty())
            .map(str::to_owned)
            .collect()
    })
}

/// Reads `targets` (files, or directories with everything below them) and
/// reports their credentials. With `targets` empty, reads the
/// [`AGENT_PATHS`] of `root` that exist.
///
/// # Errors
///
/// When a given target does not exist.
pub fn scan(root: &Path, targets: &[PathBuf]) -> Result<Report, String> {
    let mut files = Vec::new();
    if targets.is_empty() {
        for path in AGENT_PATHS {
            files_below(&root.join(path), 0, &mut files);
        }
    } else {
        for target in targets {
            if fs::symlink_metadata(target).is_err() {
                return Err(format!("{} does not exist", target.display()));
            }
            files_below(target, 0, &mut files);
        }
    }
    let mut report = Report::default();
    for path in files {
        let name = shown(&path, root);
        if report.files >= MAX_FILES {
            report
                .skipped
                .push((name, format!("more than {MAX_FILES} files")));
            continue;
        }
        if fs::metadata(&path).is_ok_and(|metadata| metadata.len() > MAX_FILE_BYTES) {
            report.skipped.push((name, "larger than 4 MiB".to_owned()));
            continue;
        }
        let text = match fs::read(&path).map(String::from_utf8) {
            Ok(Ok(text)) => text,
            Ok(Err(_)) => {
                report.skipped.push((name, "not UTF-8 text".to_owned()));
                continue;
            }
            Err(error) => {
                report.skipped.push((name, format!("not read: {error}")));
                continue;
            }
        };
        report.files += 1;
        for hit in in_file(&name, &text) {
            report.findings.push(Found {
                path: name.clone(),
                line: hit.line,
                kind: hit.finding.kind,
                name: hit.finding.name.clone(),
                place: hit.place,
                shown: secrets::redacted(&hit.finding.value),
                length: hit.finding.value.chars().count(),
                git: GitState::Unknown,
            });
        }
    }
    let inside: Vec<&str> = report
        .findings
        .iter()
        .map(|found| found.path.as_str())
        .filter(|path| Path::new(path).is_relative())
        .collect::<BTreeSet<&str>>()
        .into_iter()
        .collect();
    if !inside.is_empty()
        && let Some(tracked) = git_lists(root, &["--cached"], &inside)
        && let Some(ignored) = git_lists(
            root,
            &["--others", "--ignored", "--exclude-standard"],
            &inside,
        )
    {
        for found in &mut report.findings {
            if Path::new(&found.path).is_relative() {
                found.git = if tracked.contains(&found.path) {
                    GitState::Tracked
                } else if ignored.contains(&found.path) {
                    GitState::Ignored
                } else {
                    GitState::Untracked
                };
            }
        }
    }
    Ok(report)
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

impl Report {
    /// What `memprove policy scan` prints.
    #[must_use]
    pub fn text(&self) -> String {
        let mut lines = Vec::new();
        for found in &self.findings {
            let line = if found.line == 0 {
                String::new()
            } else {
                format!(":{}", found.line)
            };
            let name = found
                .name
                .as_ref()
                .map_or_else(String::new, |name| format!(" in {name}"));
            let git = found
                .git
                .phrase()
                .map_or_else(String::new, |phrase| format!(" ({phrase})"));
            lines.push(format!(
                "{}{line}: {}{name}: {}{git}",
                found.path, found.kind, found.shown
            ));
            if let Some(place) = &found.place {
                lines.push(format!("    at {place}"));
            }
        }
        for (path, why) in &self.skipped {
            lines.push(format!("skipped {path}: {why}"));
        }
        let read = plural(self.files, "file", "files");
        if self.findings.is_empty() {
            lines.push(format!("no secret found in {read} read"));
        } else {
            let in_files = self
                .findings
                .iter()
                .map(|found| found.path.as_str())
                .collect::<BTreeSet<&str>>()
                .len();
            let tracked = self
                .findings
                .iter()
                .filter(|found| found.git == GitState::Tracked)
                .count();
            let in_git = if tracked == 0 {
                String::new()
            } else {
                format!(
                    "; {tracked} in files Git tracks: those are in the repository's history or \
                     will be with the next commit"
                )
            };
            lines.push(format!(
                "{} in {in_files} of {read} read{in_git}",
                plural(self.findings.len(), "secret", "secrets")
            ));
            lines.push(
                "next: revoke and reissue each one (every agent and tool that reads the file \
                 has seen it), then give it through the environment: a variable such as \
                 $PGPASSWORD, or an env file Git ignores"
                    .to_owned(),
            );
        }
        lines.push(String::new());
        lines.join("\n")
    }

    /// What `memprove policy scan --json` prints.
    #[must_use]
    pub fn json(&self, root: &Path) -> String {
        let text = |value: &str| JsonValue::String(value.to_owned());
        let number = |value: usize| JsonValue::Number(value.to_string());
        let optional = |value: Option<&String>| value.map_or(JsonValue::Null, |value| text(value));
        let member = |name: &str, value: JsonValue| (name.to_owned(), value);
        let findings = self
            .findings
            .iter()
            .map(|found| {
                JsonValue::Object(vec![
                    member("path", text(&found.path)),
                    member(
                        "line",
                        if found.line == 0 {
                            JsonValue::Null
                        } else {
                            number(found.line)
                        },
                    ),
                    member("kind", text(found.kind)),
                    member("name", optional(found.name.as_ref())),
                    member("place", optional(found.place.as_ref())),
                    member("redacted", text(&found.shown)),
                    member("length", number(found.length)),
                    member("git", text(found.git.word())),
                ])
            })
            .collect();
        let skipped = self
            .skipped
            .iter()
            .map(|(path, why)| {
                JsonValue::Object(vec![member("path", text(path)), member("why", text(why))])
            })
            .collect();
        let value = JsonValue::Object(vec![
            member("schema", text(SCAN_SCHEMA)),
            member("root", text(&root.to_string_lossy())),
            member("files_read", number(self.files)),
            member("skipped", JsonValue::Array(skipped)),
            member("findings", JsonValue::Array(findings)),
        ]);
        let mut out = String::new();
        json::pretty(&value, 0, &mut out);
        out.push('\n');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Line, place, kind, name, value.
    type Seen<'a> = (usize, Option<&'a str>, &'a str, Option<&'a str>, &'a str);

    fn seen(hits: &[Hit]) -> Vec<Seen<'_>> {
        hits.iter()
            .map(|hit| {
                (
                    hit.line,
                    hit.place.as_deref(),
                    hit.finding.kind,
                    hit.finding.name.as_deref(),
                    hit.finding.value.as_str(),
                )
            })
            .collect()
    }

    #[test]
    fn a_policy_files_rules_are_read_as_commands_and_its_expect_lines_are_not() {
        let text = "ask Secret(*) -- use an environment variable\n\
                    allow Bash(PGPASSWORD=tr0ub4dor psql:*) -- the staging database\n\
                    expect ask Bash(PGPASSWORD=hunter2 psql -h db.internal)\n";
        assert_eq!(
            seen(&in_file(".memprove/policy.rules", text)),
            [(2, None, "password", Some("PGPASSWORD"), "tr0ub4dor")]
        );
        assert_eq!(
            in_file(".memprove/policy.rules", crate::starter::STARTER),
            []
        );
        assert!(is_agent_path(Path::new(".claude/settings.local.json")));
        assert!(is_agent_path(Path::new("CLAUDE.md")));
        assert!(!is_agent_path(Path::new("src/CLAUDE.md")));
        assert!(!is_agent_path(Path::new(".claudeignore")));
    }

    /// A value no service ever issued.
    fn made(prefix: &str, length: usize) -> String {
        let body: String = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"
            .chars()
            .cycle()
            .take(length)
            .collect();
        format!("{prefix}{body}")
    }

    #[test]
    fn a_settings_file_gives_up_the_passwords_of_its_allowed_commands() {
        let text = r#"{
  "permissions": {
    "allow": [
      "Bash(git status)",
      "Bash(PGPASSWORD=hunter2 psql -h db.internal -U app:*)",
      "Bash(sshpass -p 'tr0ub4dor' ssh deploy@host uptime)",
      "Read(.env.example)"
    ],
    "deny": ["Bash(PGPASSWORD=$PGPASSWORD psql:*)"]
  }
}
"#;
        assert_eq!(
            seen(&in_file(".claude/settings.local.json", text)),
            [
                (
                    5,
                    Some("permissions.allow[1]"),
                    "password",
                    Some("PGPASSWORD"),
                    "hunter2"
                ),
                (
                    6,
                    Some("permissions.allow[2]"),
                    "password",
                    Some("sshpass -p"),
                    "tr0ub4dor"
                ),
            ]
        );
    }

    #[test]
    fn an_mcp_entry_gives_up_its_env_its_headers_and_its_arguments() {
        let token = made("ghp_", 36);
        let text = format!(
            r#"{{
  "mcpServers": {{
    "github": {{
      "command": "npx",
      "args": ["-y", "server-github", "--api-key", "s3cr3tKey"],
      "env": {{
        "GITHUB_TOKEN": "{token}",
        "LOG_LEVEL": "debug",
        "DB_PASSWORD": "${{DB_PASSWORD}}"
      }}
    }},
    "remote": {{
      "url": "https://mcp.example.net/sse?api_key=q7w8e9r0",
      "headers": {{"Authorization": "Bearer t0k3n-Value-123"}}
    }}
  }}
}}
"#
        );
        assert_eq!(
            seen(&in_file(".mcp.json", &text)),
            [
                (
                    5,
                    Some("mcpServers.github.args[3]"),
                    "password",
                    Some("--api-key"),
                    "s3cr3tKey"
                ),
                (
                    7,
                    Some("mcpServers.github.env.GITHUB_TOKEN"),
                    "github-token",
                    Some("GITHUB_TOKEN"),
                    token.as_str()
                ),
                (
                    13,
                    Some("mcpServers.remote.url"),
                    "password",
                    Some("api_key"),
                    "q7w8e9r0"
                ),
                (
                    14,
                    Some("mcpServers.remote.headers.Authorization"),
                    "password",
                    Some("Authorization"),
                    "t0k3n-Value-123"
                ),
            ]
        );
    }

    #[test]
    fn a_hook_command_and_a_repeated_value_are_placed_line_by_line() {
        let text = r#"{
  "hooks": {
    "Stop": [
      {"hooks": [{"type": "command", "command": "curl -u ci:s3cr3tPw https://ci/notify"}]},
      {"hooks": [{"type": "command", "command": "curl -u ci:s3cr3tPw https://ci/done"}]}
    ]
  }
}
"#;
        assert_eq!(
            seen(&in_file("settings.json", text)),
            [
                (
                    4,
                    Some("hooks.Stop[0].hooks[0].command"),
                    "password",
                    Some("curl -u"),
                    "s3cr3tPw"
                ),
                (
                    5,
                    Some("hooks.Stop[1].hooks[0].command"),
                    "password",
                    Some("curl -u"),
                    "s3cr3tPw"
                ),
            ]
        );
    }

    #[test]
    fn a_short_value_is_placed_by_the_string_that_holds_it() {
        // `app` stands on every line; the password `app1` only in the last
        // command, and the same command twice gives two lines.
        let text = r#"{
  "permissions": {
    "allow": [
      "Bash(psql -h app1.internal -U app app)",
      "Bash(PGPASSWORD=app1 psql -U app app)",
      "Bash(pg_dump app > app1.sql)",
      "Bash(PGPASSWORD=app1 psql -U app app)"
    ]
  }
}
"#;
        assert_eq!(
            seen(&in_file("settings.json", text)),
            [
                (
                    5,
                    Some("permissions.allow[1]"),
                    "password",
                    Some("PGPASSWORD"),
                    "app1"
                ),
                (
                    7,
                    Some("permissions.allow[3]"),
                    "password",
                    Some("PGPASSWORD"),
                    "app1"
                ),
            ]
        );
    }

    #[test]
    fn an_instruction_file_gives_up_what_its_code_and_its_settings_lines_hold() {
        let key = made("sk-ant-api03-", 40);
        let text = format!(
            "# Project notes\n\
             \n\
             Connect with `PGPASSWORD=hunter2 psql -h db.internal` when the tunnel is up.\n\
             The --password option takes the value from the vault, never write it here.\n\
             \n\
             ```sh\n\
             $ sshpass -p tr0ub4dor ssh deploy@host\n\
             export API_TOKEN=\"$API_TOKEN\"\n\
             ```\n\
             \n\
             Key for the staging model: {key}\n\
             db_password: Zx81-spectrum\n\
             password: String,\n\
             token: the API token of the service\n"
        );
        assert_eq!(
            seen(&in_file("CLAUDE.md", &text)),
            [
                (3, None, "password", Some("PGPASSWORD"), "hunter2"),
                (7, None, "password", Some("sshpass -p"), "tr0ub4dor"),
                (11, None, "anthropic-key", None, key.as_str()),
                (12, None, "password", Some("db_password"), "Zx81-spectrum"),
            ]
        );
    }

    #[test]
    fn a_toml_file_and_a_rules_file_are_read_by_their_lines() {
        let toml = "[mcp_servers.search]\n\
                    command = \"npx\"\n\
                    args = [\"-y\", \"search-server\", \"--token\", \"s3cr3tTok\"]\n\
                    \n\
                    [mcp_servers.search.env]\n\
                    SEARCH_API_KEY = \"k3y-Value-99\"\n\
                    TIMEOUT = \"30\"\n";
        assert_eq!(
            seen(&in_file(".codex/config.toml", toml)),
            [
                (3, None, "password", Some("--token"), "s3cr3tTok"),
                (6, None, "password", Some("SEARCH_API_KEY"), "k3y-Value-99"),
            ]
        );
        let rules = "prefix_rule(pattern=[\"env\", \"PGPASSWORD=hunter2\", \"psql\"], decision=\"allow\")\n";
        assert_eq!(
            seen(&in_file(".codex/rules/default.rules", rules)),
            [(1, None, "password", Some("PGPASSWORD"), "hunter2")]
        );
    }

    #[test]
    fn a_session_log_is_read_one_json_line_at_a_time() {
        let text = "{\"type\":\"user\",\"text\":\"run the migration\"}\n\
                    {\"type\":\"tool_use\",\"input\":{\"command\":\"PGPASSWORD=hunter2 psql -f m.sql\"}}\n\
                    not json: MYSQL_PWD=tr0ub4dor\n";
        assert_eq!(
            seen(&in_file("session.jsonl", text)),
            [
                (
                    2,
                    Some("input.command"),
                    "password",
                    Some("PGPASSWORD"),
                    "hunter2"
                ),
                (3, None, "password", Some("MYSQL_PWD"), "tr0ub4dor"),
            ]
        );
    }

    #[test]
    fn a_clean_file_has_no_hit() {
        let settings = r#"{
  "permissions": {"allow": ["Bash(cargo test:*)", "Bash(git push origin main)", "mcp__memprove"]},
  "env": {"MEMPROVE_CONFIG_DIR": "/home/me/.config/memprove", "MAX_THINKING_TOKENS": "8000"},
  "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "memprove", "args": ["hook", "session-start"]}]}]}
}"#;
        assert_eq!(in_file(".claude/settings.json", settings), []);
        let notes = "# Rules\n\n- Never commit a token: use `$GITHUB_TOKEN`.\n\
                     - Run `cargo test --workspace` before you finish.\n\
                     - The password: ask the owner.\n\
                     - See https://docs.example.com/auth?page=2 for the flow.\n";
        assert_eq!(in_file("AGENTS.md", notes), []);
    }

    #[test]
    fn the_report_never_shows_a_value() {
        let report = Report {
            files: 3,
            skipped: vec![("big.json".to_owned(), "larger than 4 MiB".to_owned())],
            findings: vec![Found {
                path: ".claude/settings.local.json".to_owned(),
                line: 5,
                kind: "password",
                name: Some("PGPASSWORD".to_owned()),
                place: Some("permissions.allow[1]".to_owned()),
                shown: secrets::redacted("hunter2"),
                length: 7,
                git: GitState::Tracked,
            }],
        };
        let text = report.text();
        assert!(
            text.starts_with(
                ".claude/settings.local.json:5: password in PGPASSWORD: h…(7 characters) (file \
                 tracked by Git)\n    at permissions.allow[1]\nskipped big.json: larger than 4 \
                 MiB\n1 secret in 1 of 3 files read; 1 in files Git tracks"
            ),
            "{text}"
        );
        let json = report.json(Path::new("/repo"));
        let value = parse_strict(&json).unwrap();
        assert_eq!(json::str_at(&value, "schema"), Some(SCAN_SCHEMA));
        let finding = &value.get("findings").unwrap().as_array().unwrap()[0];
        assert_eq!(json::str_at(finding, "redacted"), Some("h…(7 characters)"));
        assert_eq!(json::str_at(finding, "git"), Some("tracked"));
        assert_eq!(finding.get("line").unwrap().as_i64(), Some(5));
        assert!(!text.contains("hunter2") && !json.contains("hunter2"));
    }
}
