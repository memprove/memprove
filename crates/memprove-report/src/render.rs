//! A report for a person (text) and for a program (JSON,
//! `memprove.report.session.v1`), and the one-line rows of `--list`
//! (`memprove.report.list.v1`).

use std::{collections::BTreeMap, fmt::Write as _};

use memprove_policy::json::{self, JsonValue};

use crate::{
    memory::{MemorySeen, PACK_FORMAT, Statement},
    model::{Client, Session, Usage},
    prices::{BUILT_IN_SOURCE, Priced, Prices, dollars, micro},
    report::{Now, Report},
    time,
};

/// The schema of `memprove report --json`.
pub const SESSION_SCHEMA: &str = "memprove.report.session.v1";
/// The schema of `memprove report --list --json`.
pub const LIST_SCHEMA: &str = "memprove.report.list.v1";

/// The characters of a statement's text a report shows.
const TEXT_SHOWN: usize = 100;
/// The tools a text report names one by one.
const TOOLS_SHOWN: usize = 12;

/// One model's requests, tokens and cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRow {
    /// The model.
    pub model: String,
    /// Its requests.
    pub requests: u64,
    /// Their tokens.
    pub usage: Usage,
    /// Their cost in billionths of a dollar; `None` when the model has no
    /// price.
    pub cost_nano: Option<u128>,
    /// Where the price came from.
    pub price_source: Option<&'static str>,
}

/// The rows of `session`, one per model, in name order.
#[must_use]
pub fn model_rows(session: &Session, prices: &Prices) -> Vec<ModelRow> {
    let mut rows: BTreeMap<&str, ModelRow> = BTreeMap::new();
    for (bucket, spend) in &session.spend {
        let row = rows
            .entry(bucket.model.as_str())
            .or_insert_with(|| ModelRow {
                model: bucket.model.clone(),
                requests: 0,
                usage: Usage::default(),
                cost_nano: Some(0),
                price_source: None,
            });
        row.requests += spend.requests;
        row.usage.add(&spend.usage);
        match prices.cost(bucket, &spend.usage) {
            Priced::Cost(nano, source) => {
                row.cost_nano = row.cost_nano.map(|sum| sum + nano);
                row.price_source = Some(source);
            }
            Priced::Unknown => row.cost_nano = None,
        }
    }
    rows.into_values().collect()
}

/// The total cost of `rows` and whether every model had a price.
#[must_use]
pub fn total_cost(rows: &[ModelRow]) -> (u128, bool) {
    (
        rows.iter().filter_map(|row| row.cost_nano).sum(),
        rows.iter().all(|row| row.cost_nano.is_some()),
    )
}

/// A token count for a person: `812`, `1.2k`, `5.1M`, `2.0B`.
#[must_use]
pub fn tokens(count: u64) -> String {
    let scaled =
        |unit: u64, suffix: &str| format!("{}.{}{suffix}", count / unit, count % unit * 10 / unit);
    match count {
        0..1_000 => count.to_string(),
        1_000..1_000_000 => scaled(1_000, "k"),
        1_000_000..1_000_000_000 => scaled(1_000_000, "M"),
        _ => scaled(1_000_000_000, "B"),
    }
}

fn shorten(text: &str) -> String {
    if text.chars().count() > TEXT_SHOWN {
        let mut short: String = text.chars().take(TEXT_SHOWN).collect();
        // Not half of an escape (`\」`).
        if short.chars().rev().take_while(|last| *last == '\\').count() % 2 == 1 {
            short.pop();
        }
        short.push('…');
        short
    } else {
        text.to_owned()
    }
}

fn plural<T: Copy + std::fmt::Display + PartialEq + From<u8>>(
    count: T,
    one: &str,
    many: &str,
) -> String {
    format!("{count} {}", if count == T::from(1) { one } else { many })
}

/// The report as text for a person.
#[must_use]
pub fn text(report: &Report, prices: &Prices) -> String {
    let session = &report.session;
    let mut out = String::new();
    header(&mut out, report);
    let rows = model_rows(session, prices);
    cost_section(&mut out, &rows);
    tools_section(&mut out, session);
    policy_section(&mut out, report);
    memory_section(&mut out, report);
    notes_section(&mut out, session, &rows);
    out
}

/// A session's first and last record for a person:
/// `2026-11-16 10:00 to 10:05 UTC (5 min)`, the end with its date when it
/// is another day (a session resumed later spans the time it was idle).
fn period(start: i64, end: i64) -> String {
    let (from, to) = (time::minute(start), time::minute(end));
    let same_day =
        from.split_once(' ').map(|(day, _)| day) == to.split_once(' ').map(|(day, _)| day);
    let to = match to.split_once(' ') {
        Some((_, clock)) if same_day => clock,
        _ => to.as_str(),
    };
    format!("{from} to {to} UTC ({})", time::duration(end - start))
}

fn header(out: &mut String, report: &Report) {
    let session = &report.session;
    let client = session.client.name();
    let _ = writeln!(out, "memprove report: {client} session {}", session.id);
    let mut line = String::from(" ");
    if let (Some(start), Some(end)) = (session.started_ms, session.ended_ms) {
        let _ = write!(line, " {} ·", period(start, end));
    }
    if let Some(version) = &session.version {
        let _ = write!(line, " {client} {version} ·");
    }
    if let Some(branch) = &session.branch {
        let _ = write!(line, " branch {branch} ·");
    }
    let _ = writeln!(out, "{}", line.trim_end_matches(" ·"));
    let _ = writeln!(out, "  repository {}", report.root.display());
    if let Some(cwd) = &session.cwd
        && std::path::Path::new(cwd) != report.root
    {
        let _ = writeln!(out, "  started in {cwd}");
    }
    if let Some(first) = session.files.first() {
        let more = if session.subagents == 0 {
            String::new()
        } else {
            format!(
                " (+{})",
                plural(
                    session.subagents,
                    "sub-agent transcript",
                    "sub-agent transcripts"
                )
            )
        };
        let _ = writeln!(out, "  transcript {}{more}", first.display());
    }
}

fn cost_section(out: &mut String, rows: &[ModelRow]) {
    out.push('\n');
    if rows.is_empty() {
        out.push_str("Cost: no model requests recorded\n");
        return;
    }
    let (total, complete) = total_cost(rows);
    if !complete && total == 0 {
        out.push_str("Cost: unknown (no price for these models; see the note below)\n");
    } else {
        let total = if complete {
            dollars(total)
        } else {
            format!("at least {}", dollars(total))
        };
        let _ = writeln!(
            out,
            "Cost: {total} (estimated at list prices; a subscription is not billed per token)"
        );
    }
    let width = rows
        .iter()
        .map(|row| row.model.len())
        .max()
        .unwrap_or(5)
        .max(5);
    let _ = writeln!(
        out,
        "  {:<width$}  {:>8}  {:>7}  {:>11}  {:>10}  {:>7}  {:>9}",
        "model", "requests", "input", "cache write", "cache read", "output", "cost"
    );
    for row in rows {
        let usage = &row.usage;
        let _ = writeln!(
            out,
            "  {:<width$}  {:>8}  {:>7}  {:>11}  {:>10}  {:>7}  {:>9}",
            row.model,
            row.requests,
            tokens(usage.input),
            tokens(usage.cache_write + usage.cache_write_1h),
            tokens(usage.cache_read),
            tokens(usage.output),
            row.cost_nano.map_or_else(|| "unknown".to_owned(), dollars)
        );
    }
    if rows.iter().any(|row| row.price_source == Some("built-in")) {
        let _ = writeln!(out, "  prices: {BUILT_IN_SOURCE}");
    }
}

fn tools_section(out: &mut String, session: &Session) {
    out.push('\n');
    let calls = session.tool_calls();
    let failed = if session.failures_recorded {
        format!(", {} failed", session.tool_failures())
    } else {
        String::new()
    };
    let _ = writeln!(out, "Tool calls: {calls}{failed}");
    let mut tools: Vec<(&String, &crate::model::ToolUse)> = session.tools.iter().collect();
    tools.sort_by(|a, b| b.1.calls.cmp(&a.1.calls).then_with(|| a.0.cmp(b.0)));
    if tools.is_empty() {
        return;
    }
    let mut named: Vec<String> = tools
        .iter()
        .take(TOOLS_SHOWN)
        .map(|(name, tool)| {
            if tool.failed > 0 {
                format!("{name} {} ({} failed)", tool.calls, tool.failed)
            } else {
                format!("{name} {}", tool.calls)
            }
        })
        .collect();
    if tools.len() > TOOLS_SHOWN {
        named.push(format!("{} more", tools.len() - TOOLS_SHOWN));
    }
    let _ = writeln!(out, "  {}", named.join(", "));
}

fn policy_section(out: &mut String, report: &Report) {
    out.push('\n');
    let policy = &report.policy;
    let Some(log) = &policy.log else {
        out.push_str("Policy: not checked (the repository has no Git directory)\n");
        return;
    };
    if let Some(error) = &policy.error {
        let _ = writeln!(out, "Policy: the log cannot be read: {error}");
        return;
    }
    if !policy.exists {
        out.push_str(
            "Policy: no log (memprove policy is not set up here, or has refused nothing)\n",
        );
        return;
    }
    if policy.records.is_empty() {
        let _ = writeln!(
            out,
            "Policy: nothing refused or sent to a person during the session ({})",
            log.display()
        );
        return;
    }
    let _ = writeln!(
        out,
        "Policy: {} refused, {} sent to a person ({})",
        policy.refused(),
        policy.asked(),
        log.display()
    );
    for record in &policy.records {
        let at = time::unix_ms(&record.time).map_or_else(|| record.time.clone(), time::clock);
        let sent = if record.sent == "deny" {
            "refused"
        } else {
            "asked"
        };
        let rule = match (record.line, &record.rule) {
            (Some(0), Some(rule)) => format!(" (built-in: {rule})"),
            (Some(line), Some(rule)) => format!(" (line {line}: {rule})"),
            _ => String::new(),
        };
        let _ = writeln!(
            out,
            "  {at}  {sent:<7}  {}  {}{rule}",
            record.tool, record.subject
        );
    }
}

fn memory_section(out: &mut String, report: &Report) {
    out.push('\n');
    let memory = &report.session.memory;
    if memory.is_empty() {
        out.push_str("Memory: the agent read nothing from memprove\n");
        return;
    }
    if memory.packs.is_empty() && memory.statements.is_empty() {
        let _ = writeln!(
            out,
            "Memory: the agent read no statement this version can read ({PACK_FORMAT})"
        );
        other_packs(out, memory);
        return;
    }
    let mut sources: Vec<&str> = memory
        .packs
        .iter()
        .map(|pack| pack.source.as_str())
        .collect();
    sources.dedup();
    let packs = if memory.packs.is_empty() {
        "no Pack".to_owned()
    } else {
        format!(
            "{} ({})",
            plural(memory.packs.len(), "Pack", "Packs"),
            sources.join(", ")
        )
    };
    let unverified: Vec<&Statement> = memory.unverified_facts().collect();
    let _ = writeln!(
        out,
        "Memory: read {packs}, {}; {} not verified when read",
        plural(memory.statements.len(), "statement", "statements"),
        plural(unverified.len(), "fact", "facts")
    );
    for statement in unverified {
        let _ = writeln!(out, "  {}", statement_words(statement));
    }
    other_packs(out, memory);
    match &report.now {
        None => {}
        Some(Now::Unread(why)) => {
            let _ = writeln!(out, "  now: not read ({why})");
        }
        Some(Now::Read(stale)) if stale.is_empty() => {
            out.push_str("  now: every fact read as verified is still verified\n");
        }
        Some(Now::Read(stale)) => {
            let _ = writeln!(
                out,
                "  now: {} read as verified {} not verified any more",
                plural(stale.len(), "fact", "facts"),
                if stale.len() == 1 { "is" } else { "are" }
            );
            for (statement, verdict) in stale {
                let _ = writeln!(
                    out,
                    "    #{} now {verdict}: 「{}」",
                    statement.number,
                    shorten(&statement.text)
                );
            }
        }
    }
}

/// The Packs of another format the agent was given.
fn other_packs(out: &mut String, memory: &MemorySeen) {
    for (format, count) in &memory.other_packs {
        let _ = writeln!(
            out,
            "  not read: {} of the format {format}",
            plural(*count, "Pack", "Packs")
        );
    }
}

fn statement_words(statement: &Statement) -> String {
    let verdict = statement.verdict.as_deref().unwrap_or("unknown");
    let reasons = if statement.reasons.is_empty() {
        String::new()
    } else {
        format!(" ({})", statement.reasons.join(", "))
    };
    format!(
        "#{} {verdict}{reasons}: 「{}」",
        statement.number,
        shorten(&statement.text)
    )
}

fn notes_section(out: &mut String, session: &Session, rows: &[ModelRow]) {
    let mut notes = Vec::new();
    let unpriced: Vec<&str> = rows
        .iter()
        .filter(|row| row.cost_nano.is_none())
        .map(|row| row.model.as_str())
        .collect();
    if !unpriced.is_empty() {
        notes.push(format!(
            "no price for {}; give one with --prices <FILE>",
            unpriced.join(", ")
        ));
    }
    if !session.failures_recorded {
        notes.push(format!(
            "a {} transcript does not record which tool calls failed",
            session.client.name()
        ));
    }
    if session.unreadable_lines > 0 {
        notes.push(format!(
            "{} of the transcript could not be read",
            plural(
                usize::try_from(session.unreadable_lines).unwrap_or(usize::MAX),
                "line",
                "lines"
            )
        ));
    }
    if notes.is_empty() {
        return;
    }
    out.push('\n');
    for note in notes {
        let _ = writeln!(out, "Note: {note}");
    }
}

fn string(text: &str) -> JsonValue {
    JsonValue::String(text.to_owned())
}

fn number<T: Copy + std::fmt::Display>(value: T) -> JsonValue {
    JsonValue::Number(value.to_string())
}

fn optional(value: Option<JsonValue>) -> JsonValue {
    value.unwrap_or(JsonValue::Null)
}

fn object(members: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        members
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn usage_members(usage: &Usage) -> Vec<(&'static str, JsonValue)> {
    vec![
        ("input_tokens", number(usage.input)),
        ("cache_write_tokens", number(usage.cache_write)),
        ("cache_write_1h_tokens", number(usage.cache_write_1h)),
        ("cache_read_tokens", number(usage.cache_read)),
        ("output_tokens", number(usage.output)),
    ]
}

fn statement_json(statement: &Statement) -> JsonValue {
    object(vec![
        ("number", number(statement.number)),
        ("kind", string(statement.kind.name())),
        (
            "verdict",
            optional(statement.verdict.as_deref().map(string)),
        ),
        ("standing", string(statement.standing.name())),
        (
            "reasons",
            JsonValue::Array(
                statement
                    .reasons
                    .iter()
                    .map(|reason| string(reason))
                    .collect(),
            ),
        ),
        ("text", string(&statement.text)),
        ("source", string(&statement.source)),
    ])
}

/// The report as a JSON value (`memprove.report.session.v1`).
#[must_use]
pub fn json_value(report: &Report, prices: &Prices) -> JsonValue {
    let session = &report.session;
    let rows = model_rows(session, prices);
    let (total, complete) = total_cost(&rows);
    let models = rows
        .iter()
        .map(|row| {
            let mut members = vec![
                ("model", string(&row.model)),
                ("requests", number(row.requests)),
            ];
            members.extend(usage_members(&row.usage));
            members.push((
                "cost_microusd",
                optional(row.cost_nano.map(|nano| number(micro(nano)))),
            ));
            members.push(("price_source", optional(row.price_source.map(string))));
            object(members)
        })
        .collect();
    let mut totals = vec![("requests", number(session.requests()))];
    totals.extend(usage_members(&session.usage()));
    totals.push((
        "cost_microusd",
        if rows.is_empty() || total > 0 || complete {
            number(micro(total))
        } else {
            JsonValue::Null
        },
    ));
    totals.push(("cost_complete", JsonValue::Bool(complete)));
    let tools = session
        .tools
        .iter()
        .map(|(name, tool)| {
            object(vec![
                ("name", string(name)),
                ("calls", number(tool.calls)),
                (
                    "failed",
                    if session.failures_recorded {
                        number(tool.failed)
                    } else {
                        JsonValue::Null
                    },
                ),
            ])
        })
        .collect();
    object(vec![
        ("schema", string(SESSION_SCHEMA)),
        ("client", string(session.client.name())),
        ("session_id", string(&session.id)),
        ("repository", string(&report.root.to_string_lossy())),
        ("cwd", optional(session.cwd.as_deref().map(string))),
        (
            "client_version",
            optional(session.version.as_deref().map(string)),
        ),
        ("branch", optional(session.branch.as_deref().map(string))),
        (
            "started_at",
            optional(session.started_ms.map(|ms| string(&time::iso(ms)))),
        ),
        (
            "ended_at",
            optional(session.ended_ms.map(|ms| string(&time::iso(ms)))),
        ),
        (
            "transcripts",
            JsonValue::Array(
                session
                    .files
                    .iter()
                    .map(|file| string(&file.to_string_lossy()))
                    .collect(),
            ),
        ),
        ("subagent_transcripts", number(session.subagents)),
        ("models", JsonValue::Array(models)),
        ("total", object(totals)),
        ("built_in_prices", string(BUILT_IN_SOURCE)),
        ("tool_calls", number(session.tool_calls())),
        (
            "tool_failures",
            if session.failures_recorded {
                number(session.tool_failures())
            } else {
                JsonValue::Null
            },
        ),
        ("tools", JsonValue::Array(tools)),
        ("policy", policy_json(report)),
        ("memory", memory_json(report)),
        ("unreadable_lines", number(session.unreadable_lines)),
    ])
}

fn policy_json(report: &Report) -> JsonValue {
    let policy = &report.policy;
    let records = policy
        .records
        .iter()
        .map(|record| {
            object(vec![
                ("time", string(&record.time)),
                ("tool", string(&record.tool)),
                ("subject", string(&record.subject)),
                ("decision", string(&record.decision)),
                ("sent", string(&record.sent)),
                ("line", optional(record.line.map(number))),
                ("rule", optional(record.rule.as_deref().map(string))),
            ])
        })
        .collect();
    object(vec![
        (
            "log",
            optional(
                policy
                    .log
                    .as_ref()
                    .map(|log| string(&log.to_string_lossy())),
            ),
        ),
        ("log_exists", JsonValue::Bool(policy.exists)),
        ("error", optional(policy.error.as_deref().map(string))),
        ("refused", number(policy.refused())),
        ("asked", number(policy.asked())),
        ("records", JsonValue::Array(records)),
    ])
}

fn memory_json(report: &Report) -> JsonValue {
    let memory = &report.session.memory;
    let packs = memory
        .packs
        .iter()
        .map(|pack| {
            object(vec![
                ("source", string(&pack.source)),
                ("task", optional(pack.task.as_deref().map(string))),
                ("digest", optional(pack.digest.as_deref().map(string))),
            ])
        })
        .collect();
    let now = match &report.now {
        None => JsonValue::Null,
        Some(Now::Unread(why)) => object(vec![("error", string(why))]),
        Some(Now::Read(stale)) => object(vec![(
            "not_verified_now",
            JsonValue::Array(
                stale
                    .iter()
                    .map(|(statement, verdict)| {
                        object(vec![
                            ("number", number(statement.number)),
                            ("verdict_now", string(verdict)),
                            ("text", string(&statement.text)),
                        ])
                    })
                    .collect(),
            ),
        )]),
    };
    let unread_packs = memory
        .other_packs
        .iter()
        .map(|(format, count)| object(vec![("format", string(format)), ("packs", number(*count))]))
        .collect();
    object(vec![
        ("packs", JsonValue::Array(packs)),
        ("unread_packs", JsonValue::Array(unread_packs)),
        ("reads", number(memory.reads)),
        (
            "statements",
            JsonValue::Array(memory.statements.values().map(statement_json).collect()),
        ),
        (
            "unverified_facts",
            JsonValue::Array(memory.unverified_facts().map(statement_json).collect()),
        ),
        ("now", now),
    ])
}

/// `value` as indented JSON with a final newline.
#[must_use]
pub fn json_text(value: &JsonValue) -> String {
    let mut out = String::new();
    json::pretty(value, 0, &mut out);
    out.push('\n');
    out
}

/// The titles of the `--list` rows' columns.
pub const LIST_TITLES: &str = "last record UTC         span  client       session   \
                               models  requests  cost  tool calls  policy  memory";

/// One `--list` row of `report` for a person: when the session's last
/// record was written, the time from its first record to it, and its
/// counts.
#[must_use]
pub fn list_line(report: &Report, prices: &Prices) -> String {
    let session = &report.session;
    let rows = model_rows(session, prices);
    let (total, complete) = total_cost(&rows);
    let cost = match (rows.is_empty(), complete) {
        (true, _) => "-".to_owned(),
        (false, true) => dollars(total),
        (false, false) if total == 0 => "unknown".to_owned(),
        (false, false) => format!("≥{}", dollars(total)),
    };
    let when = session
        .ended_ms
        .map_or_else(|| "unknown time".to_owned(), time::minute);
    let span = match (session.started_ms, session.ended_ms) {
        (Some(start), Some(end)) => time::duration(end - start),
        _ => "-".to_owned(),
    };
    let id: String = session.id.chars().take(8).collect();
    let models = session.models().join(",");
    format!(
        "{when}  {span:>10}  {:<11}  {id:<8}  {models}  {}  {cost}  {}  {} refused  {}",
        session.client.name(),
        plural(session.requests(), "request", "requests"),
        plural(session.tool_calls(), "tool call", "tool calls"),
        report.policy.refused(),
        memory_words(&session.memory)
    )
}

/// What a `--list` row says of the memory the agent was given: nothing, the
/// facts it read that were not verified, the Packs this version does not
/// read.
fn memory_words(memory: &MemorySeen) -> String {
    if memory.is_empty() {
        return "nothing read".to_owned();
    }
    let mut parts = Vec::new();
    if !(memory.packs.is_empty() && memory.statements.is_empty()) {
        parts.push(format!(
            "{} read",
            plural(
                memory.unverified_facts().count(),
                "unverified fact",
                "unverified facts"
            )
        ));
    }
    let unread: u64 = memory.other_packs.values().sum();
    if unread > 0 {
        let formats: Vec<&str> = memory.other_packs.keys().map(String::as_str).collect();
        parts.push(format!(
            "{} not read ({})",
            plural(unread, "Pack", "Packs"),
            formats.join(", ")
        ));
    }
    parts.join(", ")
}

/// The `--list` reports as JSON (`memprove.report.list.v1`).
#[must_use]
pub fn list_json(reports: &[Report], prices: &Prices) -> JsonValue {
    let sessions = reports
        .iter()
        .map(|report| {
            let session = &report.session;
            let rows = model_rows(session, prices);
            let (total, complete) = total_cost(&rows);
            object(vec![
                ("client", string(session.client.name())),
                ("session_id", string(&session.id)),
                (
                    "started_at",
                    optional(session.started_ms.map(|ms| string(&time::iso(ms)))),
                ),
                (
                    "ended_at",
                    optional(session.ended_ms.map(|ms| string(&time::iso(ms)))),
                ),
                (
                    "models",
                    JsonValue::Array(session.models().into_iter().map(string).collect()),
                ),
                ("requests", number(session.requests())),
                ("cost_microusd", number(micro(total))),
                ("cost_complete", JsonValue::Bool(complete)),
                ("tool_calls", number(session.tool_calls())),
                ("refused", number(report.policy.refused())),
                ("asked", number(report.policy.asked())),
                ("packs", number(session.memory.packs.len())),
                (
                    "unread_packs",
                    number(session.memory.other_packs.values().sum::<u64>()),
                ),
                (
                    "unverified_facts",
                    number(session.memory.unverified_facts().count()),
                ),
                (
                    "transcript",
                    optional(
                        session
                            .files
                            .first()
                            .map(|file| string(&file.to_string_lossy())),
                    ),
                ),
            ])
        })
        .collect();
    object(vec![
        ("schema", string(LIST_SCHEMA)),
        ("sessions", JsonValue::Array(sessions)),
    ])
}

/// The clients a listing shows, by name.
#[must_use]
pub fn client_names(clients: &[Client]) -> String {
    clients
        .iter()
        .map(|client| client.name())
        .collect::<Vec<_>>()
        .join(" or ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_counts_read_short() {
        assert_eq!(tokens(812), "812");
        assert_eq!(tokens(1_234), "1.2k");
        assert_eq!(tokens(310_200), "310.2k");
        assert_eq!(tokens(5_100_000), "5.1M");
        assert_eq!(tokens(2_000_000_000), "2.0B");
    }

    #[test]
    fn a_list_row_tells_nothing_read_from_a_pack_not_read() {
        let mut memory = MemorySeen::default();
        assert_eq!(memory_words(&memory), "nothing read");
        memory.feed("hook", "Pack：continuity-pack v1；账本序号 12\n");
        assert_eq!(
            memory_words(&memory),
            "1 Pack not read (continuity-pack v1)"
        );
        memory.feed(
            "hook",
            "Pack: memprove-pack v1; HEAD 1234567\n#1 verified: 「a」 (from Session 1)\nDigest: sha256:bb\n",
        );
        assert_eq!(
            memory_words(&memory),
            "0 unverified facts read, 1 Pack not read (continuity-pack v1)"
        );
        let mut read = MemorySeen::default();
        read.feed(
            "Bash",
            "#2 fact stale: 「b」 (reasons: head_changed; from Session 1)\n",
        );
        assert_eq!(memory_words(&read), "1 unverified fact read");
        // A cut text does not end in half an escape.
        let long = format!("{}\\」", "x".repeat(TEXT_SHOWN - 1));
        assert_eq!(shorten(&long), format!("{}…", "x".repeat(TEXT_SHOWN - 1)));
    }
}
