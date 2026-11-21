//! The calls `memprove policy` refused or sent to a person during a
//! session: the records of the repository's audit log
//! (`<git common dir>/memprove-policy/log.jsonl`) of the session's client
//! between its first and last timestamp. The log names no session, so two
//! sessions of one client in one repository at the same time share them.

use std::{
    fs,
    io::{Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
};

use memprove_policy::log::{Record, log_path};

use crate::{model::Session, time};

/// The most bytes of the log read (its end).
const LOG_WINDOW: u64 = 16 << 20;

/// How long after a session's last timestamp a record still counts as the
/// session's: the hook runs before the call it decides is written.
pub const AFTER_MS: i64 = 5_000;

/// What the policy log says of one session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySeen {
    /// The log file, when the repository has a Git directory.
    pub log: Option<PathBuf>,
    /// Whether the log exists.
    pub exists: bool,
    /// The session's records, oldest first.
    pub records: Vec<Record>,
    /// Why the log could not be read, when it could not.
    pub error: Option<String>,
}

impl PolicySeen {
    /// How many calls the policy refused (the client was told `deny`).
    #[must_use]
    pub fn refused(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.sent == "deny")
            .count()
    }

    /// How many calls it sent to a person (the client was told `ask`).
    #[must_use]
    pub fn asked(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.sent == "ask")
            .count()
    }
}

/// The records of `session` in the policy log of the repository at `root`.
#[must_use]
pub fn for_session(root: &Path, session: &Session) -> PolicySeen {
    let Some(path) = log_path(root) else {
        return PolicySeen::default();
    };
    let mut seen = PolicySeen {
        log: Some(path.clone()),
        ..PolicySeen::default()
    };
    let text = match read_tail(&path) {
        Ok(Some(text)) => text,
        Ok(None) => return seen,
        Err(error) => {
            seen.error = Some(error);
            return seen;
        }
    };
    seen.exists = true;
    let (Some(start), Some(end)) = (session.started_ms, session.ended_ms) else {
        return seen;
    };
    // The log keeps whole seconds.
    let start = start - start.rem_euclid(1000);
    seen.records = text
        .lines()
        .filter_map(Record::from_json)
        .filter(|record| record.client == session.client.name())
        .filter(|record| {
            time::unix_ms(&record.time).is_some_and(|at| at >= start && at <= end + AFTER_MS)
        })
        .collect();
    seen
}

/// The log's last [`LOG_WINDOW`] bytes; `None` when there is no log.
fn read_tail(path: &Path) -> Result<Option<String>, String> {
    let fail = |error: std::io::Error| format!("{} cannot be read: {error}", path.display());
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(fail(error)),
    };
    let length = file.metadata().map_err(fail)?.len();
    if length > LOG_WINDOW {
        file.seek(SeekFrom::Start(length - LOG_WINDOW))
            .map_err(fail)?;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(fail)?;
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

#[cfg(test)]
mod tests {
    use crate::model::Client;

    use super::*;

    fn record(time: &str, client: &str, sent: &str) -> String {
        Record {
            time: time.to_owned(),
            client: client.to_owned(),
            tool: "Bash".to_owned(),
            subject: "git push -f".to_owned(),
            decision: sent.to_owned(),
            sent: sent.to_owned(),
            line: Some(3),
            rule: Some("deny Bash(git push *-f*)".to_owned()),
        }
        .to_json()
    }

    #[test]
    fn records_of_the_client_within_the_session_count() {
        let repo = tempfile::tempdir().unwrap();
        let mut session = Session::new(Client::ClaudeCode, "s");
        assert_eq!(for_session(repo.path(), &session), PolicySeen::default());
        fs::create_dir_all(repo.path().join(".git/memprove-policy")).unwrap();
        let none = for_session(repo.path(), &session);
        assert!(!none.exists && none.log.is_some());
        let log = [
            record("2026-11-17T02:36:59Z", "claude-code", "deny"),
            record("2026-11-17T02:37:00Z", "claude-code", "deny"),
            record("2026-11-17T02:40:00Z", "codex", "deny"),
            record("2026-11-17T02:41:00Z", "claude-code", "ask"),
            record("2026-11-17T02:45:04Z", "claude-code", "deny"),
            record("2026-11-17T02:45:06Z", "claude-code", "deny"),
            "not a record".to_owned(),
        ]
        .join("\n");
        fs::write(repo.path().join(".git/memprove-policy/log.jsonl"), log).unwrap();
        session.saw_time(time::unix_ms("2026-11-17T02:37:00.400Z").unwrap());
        session.saw_time(time::unix_ms("2026-11-17T02:45:00.000Z").unwrap());
        let seen = for_session(repo.path(), &session);
        assert!(seen.exists);
        assert_eq!(
            seen.records
                .iter()
                .map(|record| record.time.as_str())
                .collect::<Vec<_>>(),
            vec![
                "2026-11-17T02:37:00Z",
                "2026-11-17T02:41:00Z",
                "2026-11-17T02:45:04Z"
            ]
        );
        assert_eq!((seen.refused(), seen.asked()), (2, 1));
    }
}
