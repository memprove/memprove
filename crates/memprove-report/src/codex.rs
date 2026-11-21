//! Codex transcripts ("rollouts"): `<codex home>/sessions/YYYY/MM/DD/
//! rollout-<time>-<thread id>.jsonl` (older ones compressed to `.zst`), one
//! `{timestamp, type, payload}` record per line.
//!
//! Tokens come from the thread's running totals (`event_msg` `token_count`
//! `info.total_token_usage`, or `token_usage_record`
//! `thread_token_usage`): each increase is one request, of the model the
//! last `turn_context` named. As in `OpenAI`'s usage, `input_tokens` holds
//! the cached ones. A rollout does not record which tool calls failed.

use std::{collections::HashMap, path::Path};

use memprove_protocol::strict_json::{JsonValue, parse_strict};

use crate::{
    memory::holds_pack,
    model::{Bucket, Client, Session, Usage},
    prices::LONG_PROMPT_TOKENS,
    read::{command_of, count_at, reads_memprove, str_at, text_of, transcript_text},
    time,
};

/// The session in the rollout at `path`.
///
/// # Errors
///
/// One sentence saying why the rollout cannot be read.
pub fn read(path: &Path) -> Result<Session, String> {
    let mut session = Session::new(Client::Codex, &id_of(path).unwrap_or_default());
    session.files.push(path.to_owned());
    read_lines(&transcript_text(path)?, &mut session);
    Ok(session)
}

/// The thread id in a rollout's file name, `rollout-YYYY-MM-DDTHH-MM-SS-<id>`
/// with `.jsonl` or `.jsonl.zst` (a reverted thread adds `_<rollout id>`).
#[must_use]
pub fn id_of(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let name = name.strip_suffix(".zst").unwrap_or(name);
    let core = name.strip_prefix("rollout-")?.strip_suffix(".jsonl")?;
    let ids = core.get(20..)?;
    let id = ids.split_once('_').map_or(ids, |(thread, _)| thread);
    (!id.is_empty()).then(|| id.to_owned())
}

/// The working directory of a rollout's first record (`session_meta`).
#[must_use]
pub fn first_cwd(text: &str) -> Option<String> {
    text.lines()
        .take(20)
        .filter_map(|line| parse_strict(line).ok())
        .find_map(|record| {
            record
                .get("payload")
                .and_then(|payload| str_at(payload, "cwd"))
                .map(str::to_owned)
        })
}

/// A thread's running token totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Totals {
    input: u64,
    cached: u64,
    cache_write: u64,
    output: u64,
    total: u64,
}

impl Totals {
    fn of(usage: &JsonValue) -> Self {
        Self {
            input: count_at(usage, "input_tokens"),
            cached: count_at(usage, "cached_input_tokens"),
            cache_write: count_at(usage, "cache_write_input_tokens"),
            output: count_at(usage, "output_tokens"),
            total: count_at(usage, "total_tokens"),
        }
    }

    fn since(self, earlier: Self) -> Usage {
        let input = self.input.saturating_sub(earlier.input);
        let cached = self.cached.saturating_sub(earlier.cached);
        let cache_write = self.cache_write.saturating_sub(earlier.cache_write);
        Usage {
            input: input.saturating_sub(cached).saturating_sub(cache_write),
            cache_write,
            cache_write_1h: 0,
            cache_read: cached,
            output: self.output.saturating_sub(earlier.output),
        }
    }
}

/// The state of reading one rollout.
#[derive(Default)]
struct Reading {
    model: Option<String>,
    totals: Option<Totals>,
    /// Calls by id: the tool's name and whether it reads memprove.
    calls: HashMap<String, (String, bool)>,
}

/// Reads the records of one rollout into `session`.
pub fn read_lines(text: &str, session: &mut Session) {
    let mut reading = Reading::default();
    for line in text.lines() {
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
        let Some(payload) = record.get("payload") else {
            continue;
        };
        match str_at(&record, "type") {
            Some("session_meta") => meta(payload, session),
            Some("turn_context") => {
                if let Some(model) = str_at(payload, "model") {
                    reading.model = Some(model.to_owned());
                }
                if session.cwd.is_none() {
                    session.cwd = str_at(payload, "cwd").map(str::to_owned);
                }
            }
            Some("response_item") => reading.item(payload, session),
            Some("event_msg") if str_at(payload, "type") == Some("token_count") => {
                if let Some(usage) = payload
                    .get("info")
                    .and_then(|info| info.get("total_token_usage"))
                {
                    reading.tokens(Totals::of(usage), session);
                }
            }
            Some("token_usage_record") => {
                if let Some(usage) = payload.get("thread_token_usage") {
                    reading.tokens(Totals::of(usage), session);
                }
            }
            _ => {}
        }
    }
}

/// The `session_meta` record: id, directory, version, branch.
fn meta(payload: &JsonValue, session: &mut Session) {
    if session.id.is_empty()
        && let Some(id) = str_at(payload, "id")
    {
        id.clone_into(&mut session.id);
    }
    if session.cwd.is_none() {
        session.cwd = str_at(payload, "cwd").map(str::to_owned);
    }
    if session.version.is_none() {
        session.version = str_at(payload, "cli_version").map(str::to_owned);
    }
    if let Some(branch) = payload.get("git").and_then(|git| str_at(git, "branch")) {
        session.branch = Some(branch.to_owned());
    }
}

impl Reading {
    /// A new running total: the increase since the last one is a request.
    /// A total below the last one starts a new count.
    fn tokens(&mut self, totals: Totals, session: &mut Session) {
        let earlier = match self.totals {
            Some(earlier) if totals.total == earlier.total => return,
            Some(earlier) if totals.total > earlier.total => earlier,
            _ => Totals::default(),
        };
        self.totals = Some(totals);
        let usage = totals.since(earlier);
        let bucket = Bucket {
            model: self.model.clone().unwrap_or_else(|| "unknown".to_owned()),
            fast: false,
            us_only: false,
            long_prompt: usage.prompt() > LONG_PROMPT_TOKENS,
        };
        session.spent(bucket, &usage);
    }

    /// One `response_item`: a tool call, a tool's output, or a message.
    fn item(&mut self, payload: &JsonValue, session: &mut Session) {
        let call_id = str_at(payload, "call_id").map(str::to_owned);
        let (name, command) = match str_at(payload, "type") {
            Some("function_call") => {
                let name = str_at(payload, "name").unwrap_or("function");
                let name = match str_at(payload, "namespace") {
                    Some(namespace) if !name.starts_with(namespace) => {
                        let joint = if namespace.ends_with("__") { "" } else { "__" };
                        format!("{namespace}{joint}{name}")
                    }
                    _ => name.to_owned(),
                };
                let command = str_at(payload, "arguments")
                    .and_then(|arguments| parse_strict(arguments).ok())
                    .map(|arguments| command_of(&arguments))
                    .unwrap_or_default();
                (name, command)
            }
            Some("custom_tool_call") => (
                str_at(payload, "name").unwrap_or("custom_tool").to_owned(),
                str_at(payload, "input").unwrap_or_default().to_owned(),
            ),
            Some("local_shell_call") => (
                "local_shell".to_owned(),
                payload.get("action").map(command_of).unwrap_or_default(),
            ),
            Some("web_search_call") => ("web_search".to_owned(), String::new()),
            Some("tool_search_call") => ("tool_search".to_owned(), String::new()),
            Some("function_call_output" | "custom_tool_call_output") => {
                if let Some((name, true)) = call_id.as_ref().and_then(|id| self.calls.get(id))
                    && let Some(output) = payload.get("output")
                {
                    session.memory.feed(name, &text_of(output));
                }
                return;
            }
            Some("message") => {
                if matches!(str_at(payload, "role"), Some("user" | "developer"))
                    && let Some(content) = payload.get("content")
                {
                    let text = text_of(content);
                    if holds_pack(&text) {
                        session.memory.feed("message", &text);
                    }
                }
                return;
            }
            _ => return,
        };
        session.called(&name);
        let memprove = reads_memprove(&name, &command);
        if let Some(id) = call_id {
            self.calls.insert(id, (name, memprove));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn rollout_names_give_thread_ids() {
        let id = |name: &str| id_of(&PathBuf::from(name));
        assert_eq!(
            id("rollout-2026-11-16T00-02-11-019a1b2c-3d4e-7f00-8a9b-0c1d2e3f4a5b.jsonl").as_deref(),
            Some("019a1b2c-3d4e-7f00-8a9b-0c1d2e3f4a5b")
        );
        assert_eq!(
            id("rollout-2026-11-16T00-02-11-019a_019b.jsonl.zst").as_deref(),
            Some("019a")
        );
        assert_eq!(id("notes.jsonl"), None);
    }
}
