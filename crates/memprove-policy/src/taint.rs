//! Marked sessions: once a call of a session matches a `taint` line of the
//! policy, the session has read content nobody here wrote (a web page, the
//! result of an MCP tool), and the `tainted` rules apply to the rest of it.
//!
//! A mark is one small JSON file per session in `<git common dir>/
//! memprove-policy/taint/`, never committed. It holds the call that marked
//! the session, redacted as the audit log's subjects are. A mark is never
//! taken back: a new session starts unmarked. Marks older than
//! [`KEEP_DAYS`] days are removed when a new one is written.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use memprove_protocol::strict_json::parse_strict;

use crate::{
    json::{self, JsonValue},
    log,
};

/// The marks' directory under [`log::LOG_DIR`].
pub const TAINT_DIR: &str = "taint";
/// How long a mark is kept, in days.
pub const KEEP_DAYS: u64 = 30;
/// The longest session name used as it is.
const MAX_NAME: usize = 128;

/// Why a session is marked: the call that matched a `taint` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    /// When, as `YYYY-MM-DDTHH:MM:SSZ`.
    pub time: String,
    /// The client: `claude-code`, `codex` or `cursor`.
    pub client: String,
    /// The tool of the call's check that matched: `Web`, `Mcp`, …
    pub tool: String,
    /// What matched, shortened and redacted as the log does.
    pub subject: String,
    /// The line of the `taint` line.
    pub line: usize,
    /// The `taint` line.
    pub rule: String,
}

impl Mark {
    fn to_json(&self) -> String {
        json::object(&[
            ("time", json::string(&self.time)),
            ("client", json::string(&self.client)),
            ("tool", json::string(&self.tool)),
            ("subject", json::string(&self.subject)),
            ("line", self.line.to_string()),
            ("rule", json::string(&self.rule)),
        ])
    }

    fn from_json(text: &str) -> Option<Self> {
        let value = parse_strict(text.trim()).ok()?;
        let string = |name: &str| json::str_at(&value, name).map(str::to_owned);
        Some(Self {
            time: string("time")?,
            client: string("client")?,
            tool: string("tool")?,
            subject: string("subject")?,
            line: value
                .get("line")
                .and_then(JsonValue::as_i64)
                .and_then(|line| usize::try_from(line).ok())?,
            rule: string("rule")?,
        })
    }
}

/// The file name of the session a client calls `id`: `id` itself when it is
/// made of letters, digits, `-`, `_` and `.` (as the clients' ids are), a
/// hash of it otherwise; none for an empty id, which names no session.
#[must_use]
pub fn session_name(id: &str) -> Option<String> {
    if id.is_empty() {
        return None;
    }
    let plain = id.len() <= MAX_NAME
        && !id.starts_with('.')
        && id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        });
    if plain {
        return Some(id.to_owned());
    }
    // FNV-1a, 64 bits: a file name for an id that cannot be one.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Some(format!("id-{hash:016x}"))
}

/// The marks' directory of the repository at `root`.
#[must_use]
pub fn dir(root: &Path) -> Option<PathBuf> {
    log::git_common_dir(root).map(|dir| dir.join(log::LOG_DIR).join(TAINT_DIR))
}

fn mark_path(root: &Path, session: &str) -> Option<PathBuf> {
    Some(dir(root)?.join(format!("{}.json", session_name(session)?)))
}

/// The mark of `session` in the repository at `root`, if it is marked. A
/// mark that cannot be read still marks: the session stays marked.
#[must_use]
pub fn read(root: &Path, session: &str) -> Option<Mark> {
    let path = mark_path(root, session)?;
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => String::new(),
    };
    Some(Mark::from_json(&text).unwrap_or_else(|| Mark {
        time: "an unknown time".to_owned(),
        client: "-".to_owned(),
        tool: "-".to_owned(),
        subject: "a call this file no longer names".to_owned(),
        line: 0,
        rule: "taint".to_owned(),
    }))
}

/// Marks `session` with `mark`, unless it is marked already: the first mark
/// stays. Says whether this call wrote it.
///
/// # Errors
///
/// When the repository has no Git directory or the mark cannot be written.
pub fn write(root: &Path, session: &str, mark: &Mark) -> Result<bool, String> {
    let path = mark_path(root, session).ok_or("the repository has no Git directory")?;
    let fail = |error: std::io::Error| format!("{} was not written: {error}", path.display());
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(fail)?;
        remove_old(dir);
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path);
    match file {
        Ok(mut file) => file
            .write_all(format!("{}\n", mark.to_json()).as_bytes())
            .map(|()| true)
            .map_err(fail),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(fail(error)),
    }
}

/// Removes the marks of `dir` last written more than [`KEEP_DAYS`] days ago.
fn remove_old(dir: &Path) {
    let Some(limit) = SystemTime::now().checked_sub(Duration::from_secs(KEEP_DAYS * 86_400)) else {
        return;
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let old = path
            .extension()
            .is_some_and(|extension| extension == "json")
            && entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .is_ok_and(|modified| modified < limit);
        if old {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark(subject: &str) -> Mark {
        Mark {
            time: "2026-11-21T08:00:00Z".to_owned(),
            client: "claude-code".to_owned(),
            tool: "Web".to_owned(),
            subject: subject.to_owned(),
            line: 12,
            rule: "taint Web(*)".to_owned(),
        }
    }

    #[test]
    fn a_session_is_marked_once_and_stays_marked() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let root = dir.path();
        assert_eq!(read(root, "s-1"), None);
        assert_eq!(write(root, "s-1", &mark("https://a.example/x")), Ok(true));
        assert_eq!(write(root, "s-1", &mark("https://b.example/y")), Ok(false));
        assert_eq!(read(root, "s-1"), Some(mark("https://a.example/x")));
        assert_eq!(read(root, "s-2"), None);
        let file = root.join(".git/memprove-policy/taint/s-1.json");
        assert!(file.is_file());
        // A mark that no longer reads is still a mark.
        fs::write(&file, "{").unwrap();
        assert_eq!(read(root, "s-1").unwrap().line, 0);
    }

    #[test]
    fn a_session_id_becomes_a_file_name_inside_the_directory() {
        assert_eq!(
            session_name("0b9c7f2e-1d3a-4e5f-8a6b-7c8d9e0f1a2b").as_deref(),
            Some("0b9c7f2e-1d3a-4e5f-8a6b-7c8d9e0f1a2b")
        );
        assert_eq!(session_name("thr_123").as_deref(), Some("thr_123"));
        assert_eq!(session_name(""), None);
        for odd in ["../../x", ".hidden", "a/b", "a b", &"x".repeat(200)] {
            let name = session_name(odd).unwrap();
            assert!(name.starts_with("id-") && name.len() == 19, "{name}");
        }
        assert_ne!(session_name("a/b"), session_name("a/c"));
    }

    #[test]
    fn old_marks_are_removed_when_a_new_one_is_written() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let root = dir.path();
        write(root, "old", &mark("https://a.example")).unwrap();
        write(root, "recent", &mark("https://a.example")).unwrap();
        let marks = root.join(".git/memprove-policy/taint");
        let long_ago = SystemTime::now() - Duration::from_secs((KEEP_DAYS + 1) * 86_400);
        fs::File::options()
            .write(true)
            .open(marks.join("old.json"))
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        write(root, "new", &mark("https://a.example")).unwrap();
        assert_eq!(read(root, "old"), None);
        assert!(read(root, "recent").is_some() && read(root, "new").is_some());
    }
}
