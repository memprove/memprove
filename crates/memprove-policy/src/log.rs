//! The audit log: one JSON line for every call the policy refused or sent
//! to a person, in `<git common dir>/memprove-policy/log.jsonl`, which is
//! never committed. A command is kept to its first 200 characters, and a
//! run of 32 or more token-like characters is replaced by `[redacted]`.

use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::json;

/// The log's directory under the Git common directory.
pub const LOG_DIR: &str = "memprove-policy";
/// The log file in [`LOG_DIR`].
pub const LOG_FILE: &str = "log.jsonl";
/// The characters of a subject the log keeps.
pub const SUBJECT_CHARS: usize = 200;

/// One logged decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// When, as `YYYY-MM-DDTHH:MM:SSZ`.
    pub time: String,
    /// The client: `claude-code`, `codex` or `cursor`.
    pub client: String,
    /// The tool of the deciding check: `Bash`, `Read`, `Edit` or `Mcp`
    /// (or `-` when none decided).
    pub tool: String,
    /// What was checked, shortened and redacted.
    pub subject: String,
    /// The policy's decision: `deny` or `ask`.
    pub decision: String,
    /// What the client was told: `deny` or `ask`.
    pub sent: String,
    /// The rule's line (0 for a built-in rule), if a rule decided.
    pub line: Option<usize>,
    /// The rule, if one decided.
    pub rule: Option<String>,
}

impl Record {
    /// The record as one JSON line.
    #[must_use]
    pub fn to_json(&self) -> String {
        json::object(&[
            ("time", json::string(&self.time)),
            ("client", json::string(&self.client)),
            ("tool", json::string(&self.tool)),
            ("subject", json::string(&self.subject)),
            ("decision", json::string(&self.decision)),
            ("sent", json::string(&self.sent)),
            (
                "line",
                self.line
                    .map_or_else(|| "null".to_owned(), |line| line.to_string()),
            ),
            (
                "rule",
                self.rule
                    .as_deref()
                    .map_or_else(|| "null".to_owned(), json::string),
            ),
        ])
    }

    /// The record of a JSON line, if it is one.
    #[must_use]
    pub fn from_json(line: &str) -> Option<Self> {
        let value = memprove_protocol::strict_json::parse_strict(line).ok()?;
        let text = |name: &str| json::str_at(&value, name).map(str::to_owned);
        Some(Self {
            time: text("time")?,
            client: text("client")?,
            tool: text("tool")?,
            subject: text("subject")?,
            decision: text("decision")?,
            sent: text("sent")?,
            line: value
                .get("line")
                .and_then(memprove_protocol::strict_json::JsonValue::as_i64)
                .and_then(|line| usize::try_from(line).ok()),
            rule: text("rule"),
        })
    }
}

/// `subject` as the log keeps it: token-like runs redacted, then at most
/// [`SUBJECT_CHARS`] characters.
#[must_use]
pub fn redacted(subject: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.chars().count() >= 32 {
            out.push_str("[redacted]");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for character in subject.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '+' | '=') {
            run.push(character);
        } else {
            flush(&mut run, &mut out);
            out.push(character);
        }
    }
    flush(&mut run, &mut out);
    if out.chars().count() > SUBJECT_CHARS {
        let mut short: String = out.chars().take(SUBJECT_CHARS).collect();
        short.push('…');
        short
    } else {
        out
    }
}

/// The Git common directory of the repository at `root`: `.git` itself, or
/// for a linked worktree the directory its `commondir` names.
#[must_use]
pub fn git_common_dir(root: &Path) -> Option<PathBuf> {
    let dot_git = root.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    let text = fs::read_to_string(&dot_git).ok()?;
    let git_dir = text
        .lines()
        .find_map(|line| line.strip_prefix("gitdir:"))?
        .trim();
    let git_dir = root.join(git_dir);
    match fs::read_to_string(git_dir.join("commondir")) {
        Ok(common) => Some(crate::commands::clean(&git_dir.join(common.trim()))),
        Err(_) => Some(git_dir),
    }
}

/// The log file of the repository at `root`.
#[must_use]
pub fn log_path(root: &Path) -> Option<PathBuf> {
    git_common_dir(root).map(|dir| dir.join(LOG_DIR).join(LOG_FILE))
}

/// Appends `record` to the log of `root`.
///
/// # Errors
///
/// When the repository has no Git directory or the log cannot be written.
pub fn append(root: &Path, record: &Record) -> Result<(), String> {
    let path = log_path(root).ok_or("the repository has no Git directory")?;
    let fail = |error: std::io::Error| format!("{} was not written: {error}", path.display());
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(fail)?;
    }
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)
        .map_err(fail)?;
    file.write_all(format!("{}\n", record.to_json()).as_bytes())
        .map_err(fail)
}

/// The last `count` records of the log of `root` (the log's last 4 MiB at
/// most), oldest first; lines that are not records are skipped.
///
/// # Errors
///
/// When the log exists but cannot be read.
pub fn last(root: &Path, count: usize) -> Result<Vec<Record>, String> {
    let Some(path) = log_path(root) else {
        return Ok(Vec::new());
    };
    let mut file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{} cannot be read: {error}", path.display())),
    };
    let fail = |error: std::io::Error| format!("{} cannot be read: {error}", path.display());
    let length = file.metadata().map_err(fail)?.len();
    let window = 4 << 20;
    if length > window {
        file.seek(SeekFrom::Start(length - window)).map_err(fail)?;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(fail)?;
    let text = String::from_utf8_lossy(&bytes);
    let records: Vec<Record> = text.lines().filter_map(Record::from_json).collect();
    let skip = records.len().saturating_sub(count);
    Ok(records.into_iter().skip(skip).collect())
}

/// `now` as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn rfc3339(now: SystemTime) -> String {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = i64::try_from(since / 86_400).unwrap_or(i64::MAX);
    let seconds = since % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a
/// proleptic Gregorian date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn record(subject: &str) -> Record {
        Record {
            time: "2026-11-15T20:00:00Z".to_owned(),
            client: "codex".to_owned(),
            tool: "Bash".to_owned(),
            subject: subject.to_owned(),
            decision: "ask".to_owned(),
            sent: "deny".to_owned(),
            line: Some(3),
            rule: Some("ask Bash(git push *)".to_owned()),
        }
    }

    #[test]
    fn records_round_trip_and_come_back_last_first() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        assert_eq!(last(dir.path(), 5).unwrap(), Vec::new());
        for index in 0..4 {
            append(dir.path(), &record(&format!("git push {index}"))).unwrap();
        }
        let records = last(dir.path(), 2).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1], record("git push 3"));
        assert!(dir.path().join(".git/memprove-policy/log.jsonl").is_file());
    }

    #[test]
    fn a_worktree_logs_into_the_common_directory() {
        let dir = tempfile::tempdir().unwrap();
        let common = dir.path().join("main/.git");
        fs::create_dir_all(common.join("worktrees/w")).unwrap();
        fs::write(common.join("worktrees/w/commondir"), "../..\n").unwrap();
        fs::create_dir_all(dir.path().join("w")).unwrap();
        fs::write(
            dir.path().join("w/.git"),
            format!("gitdir: {}\n", common.join("worktrees/w").display()),
        )
        .unwrap();
        assert_eq!(git_common_dir(&dir.path().join("w")), Some(common));
    }

    #[test]
    fn subjects_are_redacted_and_shortened() {
        let token = "A".repeat(40);
        assert_eq!(
            redacted(&format!("curl -H 'x: {token}' u")),
            "curl -H 'x: [redacted]' u"
        );
        assert_eq!(
            redacted(&"a ".repeat(150)).chars().count(),
            SUBJECT_CHARS + 1
        );
    }

    #[test]
    fn formats_utc_times() {
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(1_794_694_403)),
            "2026-11-14T22:13:23Z"
        );
    }
}
