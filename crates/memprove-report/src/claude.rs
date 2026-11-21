//! Claude Code transcripts: `<config dir>/projects/<dir>/<session>.jsonl`,
//! one JSON record per line, and the sub-agents' transcripts in
//! `<session>/subagents/*.jsonl` next to it.
//!
//! Claude Code writes one line per content block of an assistant message,
//! each with the message's whole `usage`; a message is counted once, by its
//! `message.id`, with the usage of its last line.

use std::{
    collections::{HashMap, HashSet},
    fs,
    hash::{DefaultHasher, Hash as _, Hasher as _},
    path::{Path, PathBuf},
};

use memprove_protocol::strict_json::{JsonValue, parse_strict};

use crate::{
    model::{Bucket, Client, Session, Usage},
    prices::LONG_PROMPT_TOKENS,
    read::{command_of, count_at, reads_memprove, str_at, text_of, transcript_text},
    time,
};

/// The model Claude Code names on messages it wrote itself (API errors,
/// interruptions); they are no model requests.
const SYNTHETIC_MODEL: &str = "<synthetic>";

/// The session in the transcript at `path`, with its sub-agents'
/// transcripts.
///
/// # Errors
///
/// One sentence saying why the transcript cannot be read.
pub fn read(path: &Path) -> Result<Session, String> {
    let id = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut session = Session::new(Client::ClaudeCode, &id);
    session.failures_recorded = true;
    session.files.push(path.to_owned());
    read_lines(&transcript_text(path)?, &mut session, true);
    for file in subagent_files(path) {
        if let Ok(text) = transcript_text(&file) {
            read_lines(&text, &mut session, false);
            session.files.push(file);
            session.subagents += 1;
        }
    }
    Ok(session)
}

/// The sub-agents' transcripts of the session at `path`, in name order.
#[must_use]
pub fn subagent_files(path: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(path.with_extension("").join("subagents")) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|file| {
            file.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect();
    files.sort();
    files
}

/// The working directory the transcript `text` records first.
#[must_use]
pub fn first_cwd(text: &str) -> Option<String> {
    text.lines()
        .take(200)
        .filter_map(|line| parse_strict(line).ok())
        .find_map(|record| str_at(&record, "cwd").map(str::to_owned))
}

/// A tool call waiting for its result.
struct Call {
    name: String,
    memprove: bool,
}

/// The state of reading one transcript.
#[derive(Default)]
struct Reading {
    /// Each message's bucket and usage, in first-seen order.
    messages: Vec<(Bucket, Usage)>,
    /// Where each message id is in `messages`.
    message_index: HashMap<String, usize>,
    /// Tool calls by block id.
    calls: HashMap<String, Call>,
    /// Tool-use block ids already counted.
    seen_blocks: HashSet<String>,
    /// The hook outputs read, by their text's hash, and the line each was
    /// last read at.
    hook_texts: HashMap<u64, usize>,
}

/// How many lines apart two records of one hook's output can be: Claude
/// Code writes what a hook printed (`hook_success`) and the context it
/// added (`hook_additional_context`) as records of their own. The same
/// output further apart is another run of the hook (a resumed session).
const SAME_HOOK_RUN_LINES: usize = 50;

/// The hook events whose plain output Claude Code gives the agent as
/// context; other events' output reaches it only as `additionalContext`.
const CONTEXT_EVENTS: [&str; 2] = ["SessionStart", "UserPromptSubmit"];

/// What hooks gave the agent, from a `hook_success` or
/// `hook_additional_context` attachment, one text per hook: the context
/// (`content`, and the `heldContent` Claude Code kept back), else what the
/// hook printed (`stdout`: the `additionalContext` of the JSON it printed,
/// or the plain output of an event in [`CONTEXT_EVENTS`]).
fn hook_texts(attachment: &JsonValue) -> Vec<String> {
    if !matches!(
        str_at(attachment, "type"),
        Some("hook_success" | "hook_additional_context")
    ) {
        return Vec::new();
    }
    let mut texts = Vec::new();
    for name in ["content", "heldContent"] {
        match attachment.get(name) {
            Some(JsonValue::Array(parts)) => {
                texts.extend(parts.iter().map(text_of));
            }
            Some(part) => texts.push(text_of(part)),
            None => {}
        }
    }
    texts.retain(|text| !text.trim().is_empty());
    if texts.is_empty()
        && let Some(stdout) = str_at(attachment, "stdout")
    {
        let printed = parse_strict(stdout).ok();
        let added = printed.as_ref().and_then(|printed| {
            printed
                .get("hookSpecificOutput")
                .and_then(|output| str_at(output, "additionalContext"))
        });
        let event = str_at(attachment, "hookEvent").unwrap_or_default();
        if let Some(added) = added {
            texts.push(added.to_owned());
        } else if printed.is_none() && CONTEXT_EVENTS.contains(&event) {
            texts.push(stdout.to_owned());
        }
        texts.retain(|text| !text.trim().is_empty());
    }
    texts
}

/// Reads the records of one transcript into `session`; `main` is the
/// session's own transcript (not a sub-agent's).
pub fn read_lines(text: &str, session: &mut Session, main: bool) {
    let mut reading = Reading::default();
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(record) = parse_strict(line) else {
            session.unreadable_lines += 1;
            continue;
        };
        if let Some(ms) = str_at(&record, "timestamp").and_then(time::unix_ms) {
            session.saw_time(ms);
        }
        if main {
            header(&record, session);
        }
        match str_at(&record, "type") {
            Some("assistant") => {
                if let Some(message) = record.get("message") {
                    reading.assistant(message, &record, number, session);
                }
            }
            Some("user") => {
                if let Some(content) = record
                    .get("message")
                    .and_then(|message| message.get("content"))
                {
                    reading.results(content, session);
                }
            }
            Some("attachment") => {
                for text in record.get("attachment").map(hook_texts).unwrap_or_default() {
                    reading.hook(&text, number, session);
                }
            }
            _ => {}
        }
    }
    for (bucket, usage) in reading.messages {
        session.spent(bucket, &usage);
    }
}

/// The session's directory, client version and branch, from any record.
fn header(record: &JsonValue, session: &mut Session) {
    if session.cwd.is_none() {
        session.cwd = str_at(record, "cwd").map(str::to_owned);
    }
    if session.version.is_none() {
        session.version = str_at(record, "version").map(str::to_owned);
    }
    if let Some(branch) = str_at(record, "gitBranch") {
        session.branch = Some(branch.to_owned());
    }
}

impl Reading {
    /// What a hook gave the agent at line `number`, once per run of the
    /// hook.
    fn hook(&mut self, text: &str, number: usize, session: &mut Session) {
        let mut hasher = DefaultHasher::new();
        text.trim().hash(&mut hasher);
        let earlier = self.hook_texts.insert(hasher.finish(), number);
        if earlier.is_none_or(|line| number - line > SAME_HOOK_RUN_LINES) {
            session.memory.feed("hook", text);
        }
    }

    /// One assistant record: its message's usage (replacing an earlier line
    /// of the same message) and its tool calls.
    fn assistant(
        &mut self,
        message: &JsonValue,
        record: &JsonValue,
        number: usize,
        session: &mut Session,
    ) {
        let model = str_at(message, "model").unwrap_or("unknown");
        if model != SYNTHETIC_MODEL
            && let Some(usage) = message.get("usage")
        {
            let (usage, fast, us_only) = usage_of(usage);
            let bucket = Bucket {
                model: model.to_owned(),
                fast,
                us_only,
                long_prompt: usage.prompt() > LONG_PROMPT_TOKENS,
            };
            let key = str_at(message, "id")
                .or_else(|| str_at(record, "requestId"))
                .map_or_else(|| format!("line {number}"), str::to_owned);
            if let Some(&index) = self.message_index.get(&key) {
                self.messages[index] = (bucket, usage);
            } else {
                self.message_index.insert(key, self.messages.len());
                self.messages.push((bucket, usage));
            }
        }
        for block in message
            .get("content")
            .and_then(JsonValue::as_array)
            .unwrap_or_default()
        {
            if !matches!(str_at(block, "type"), Some("tool_use" | "server_tool_use")) {
                continue;
            }
            let Some(name) = str_at(block, "name") else {
                continue;
            };
            let id =
                str_at(block, "id").map_or_else(|| format!("line {number} {name}"), str::to_owned);
            if !self.seen_blocks.insert(id.clone()) {
                continue;
            }
            session.called(name);
            let command = block.get("input").map(command_of).unwrap_or_default();
            self.calls.insert(
                id,
                Call {
                    name: name.to_owned(),
                    memprove: reads_memprove(name, &command),
                },
            );
        }
    }

    /// The tool results of a user record: failures, and what memprove
    /// told the agent.
    fn results(&self, content: &JsonValue, session: &mut Session) {
        for block in content.as_array().unwrap_or_default() {
            if str_at(block, "type") != Some("tool_result") {
                continue;
            }
            let Some(call) = str_at(block, "tool_use_id").and_then(|id| self.calls.get(id)) else {
                continue;
            };
            if block.get("is_error").and_then(JsonValue::as_bool) == Some(true) {
                session.failed(&call.name);
            }
            if call.memprove
                && let Some(result) = block.get("content")
            {
                session.memory.feed(&call.name, &text_of(result));
            }
        }
    }
}

/// A message's `usage` as tokens, whether it ran in fast mode, and whether
/// it ran in the United States only. Cache writes without a duration count
/// as five-minute writes.
#[must_use]
pub fn usage_of(usage: &JsonValue) -> (Usage, bool, bool) {
    let written = count_at(usage, "cache_creation_input_tokens");
    let (mut five, hour) = usage.get("cache_creation").map_or((0, 0), |split| {
        (
            count_at(split, "ephemeral_5m_input_tokens"),
            count_at(split, "ephemeral_1h_input_tokens"),
        )
    });
    if five + hour < written {
        five = written - hour;
    }
    (
        Usage {
            input: count_at(usage, "input_tokens"),
            cache_write: five,
            cache_write_1h: hour,
            cache_read: count_at(usage, "cache_read_input_tokens"),
            output: count_at(usage, "output_tokens"),
        },
        str_at(usage, "speed") == Some("fast"),
        str_at(usage, "inference_geo") == Some("us"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(attachment: &str) -> Vec<String> {
        hook_texts(&parse_strict(attachment).unwrap())
    }

    #[test]
    fn a_hooks_output_is_read_where_claude_code_records_it() {
        // What a SessionStart hook printed, as plain text and as JSON.
        assert_eq!(
            texts(
                r#"{"type":"hook_success","hookEvent":"SessionStart","content":"","stdout":"a Pack\n"}"#
            ),
            ["a Pack\n"]
        );
        assert_eq!(
            texts(
                r#"{"type":"hook_success","hookEvent":"PostToolUse","content":"","stdout":"{\"hookSpecificOutput\":{\"additionalContext\":\"a note\"}}"}"#
            ),
            ["a note"]
        );
        // The context Claude Code made of it, one text per hook.
        assert_eq!(
            texts(
                r#"{"type":"hook_additional_context","content":"[]","heldContent":["first","second"]}"#
            ),
            ["[]", "first", "second"]
        );
        assert_eq!(
            texts(r#"{"type":"hook_additional_context","content":["a Pack"]}"#),
            ["a Pack"]
        );
        // Not given to the agent: another event's plain output, a hook's
        // JSON without context, another attachment.
        for attachment in [
            r#"{"type":"hook_success","hookEvent":"PostToolUse","content":"","stdout":"done\n"}"#,
            r#"{"type":"hook_success","hookEvent":"SessionStart","content":"","stdout":"{\"continue\":true}"}"#,
            r#"{"type":"file","content":"a Pack"}"#,
        ] {
            assert!(texts(attachment).is_empty(), "{attachment}");
        }
    }

    #[test]
    fn one_run_of_a_hook_recorded_twice_is_one_read() {
        let pack = "Pack: memprove-pack v1; HEAD 1234567\\nTask「T」 (in_progress)\\n#1 verified: 「a」 (from Session 1)\\nDigest: sha256:bb\\n";
        let line = |kind: &str, field: &str| {
            format!(
                r#"{{"type":"attachment","timestamp":"2026-11-16T10:00:00.000Z","attachment":{{"type":"{kind}","hookEvent":"SessionStart","content":"","{field}":"{pack}"}}}}"#
            )
        };
        let other = r#"{"type":"user","message":{"role":"user","content":"hi"}}"#;
        let run = [
            line("hook_success", "stdout"),
            line("hook_additional_context", "heldContent"),
        ]
        .join("\n");
        // The same hook output again, later in the file: a resumed session.
        let gap = vec![other; SAME_HOOK_RUN_LINES + 1].join("\n");
        let mut session = Session::new(Client::ClaudeCode, "s");
        read_lines(&format!("{run}\n{gap}\n{run}\n"), &mut session, true);
        assert_eq!(session.memory.reads, 2);
        assert_eq!(session.memory.packs.len(), 2);
        assert_eq!(session.memory.statements.len(), 1);
    }
}
