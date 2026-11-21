//! One report: a session, the repository it ran in, the policy log's
//! records of it, and (with `--now`) the statements memprove holds now.

use std::path::{Path, PathBuf};

use crate::{
    memory::Statement,
    model::Session,
    policy::{self, PolicySeen},
};

/// A statement as memprove holds it now, for `--now`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentStatement {
    /// Its label, such as `#4`.
    pub label: String,
    /// `fact`, `open`, `decision`, or `next`.
    pub kind: String,
    /// `verified`, `stale`, `unconfirmed`, or `tampered`.
    pub verdict: String,
    /// Its text.
    pub text: String,
}

/// Reads the statements memprove would give a new session in a repository
/// now, without writing anything; the CLI reads them from the daemon.
pub trait Present {
    /// The statements, in the Pack's order.
    ///
    /// # Errors
    ///
    /// One sentence saying why they could not be read.
    fn statements(&self, repo_root: &Path) -> Result<Vec<CurrentStatement>, String>;
}

/// What `--now` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Now {
    /// The facts the agent read as verified that are not verified now,
    /// each with its verdict now.
    Read(Vec<(Statement, String)>),
    /// Why memprove's statements could not be read.
    Unread(String),
}

/// One session's report.
#[derive(Debug, Clone)]
pub struct Report {
    /// The session.
    pub session: Session,
    /// The repository it is reported for.
    pub root: PathBuf,
    /// The policy log's records of it.
    pub policy: PolicySeen,
    /// What `--now` found, when it was asked for.
    pub now: Option<Now>,
}

impl Report {
    /// The report of `session` in the repository at `root`; with `present`,
    /// also what memprove holds now.
    #[must_use]
    pub fn new(session: Session, root: &Path, present: Option<&dyn Present>) -> Self {
        let policy = policy::for_session(root, &session);
        let now = present.map(|present| match present.statements(root) {
            Ok(current) => Now::Read(gone_stale(&session, &current)),
            Err(why) => Now::Unread(why),
        });
        Self {
            session,
            root: root.to_owned(),
            policy,
            now,
        }
    }
}

/// The characters of a statement's text compared with its text now (a Pack
/// may have shortened the one the agent read).
const TEXT_COMPARED: usize = 40;

/// The facts of `session` read as verified whose statement of the same
/// number and text is not verified in `current`.
fn gone_stale(session: &Session, current: &[CurrentStatement]) -> Vec<(Statement, String)> {
    session
        .memory
        .statements
        .values()
        .filter(|statement| {
            statement.standing == crate::memory::Standing::Active
                && statement.verdict.as_deref() == Some("verified")
        })
        .filter_map(|statement| {
            let label = format!("#{}", statement.number);
            let head: String = statement.text.chars().take(TEXT_COMPARED).collect();
            current
                .iter()
                .find(|now| now.label == label && now.text.starts_with(&head))
                .filter(|now| now.verdict != "verified")
                .map(|now| (statement.clone(), now.verdict.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::model::Client;

    use super::*;

    struct Fixed(Result<Vec<CurrentStatement>, String>);

    impl Present for Fixed {
        fn statements(&self, _: &Path) -> Result<Vec<CurrentStatement>, String> {
            self.0.clone()
        }
    }

    fn current(label: &str, verdict: &str, text: &str) -> CurrentStatement {
        CurrentStatement {
            label: label.to_owned(),
            kind: "fact".to_owned(),
            verdict: verdict.to_owned(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn now_names_facts_read_as_verified_that_are_not_any_more() {
        let repo = tempfile::tempdir().unwrap();
        let mut session = Session::new(Client::Codex, "t");
        session.memory.feed(
            "hook",
            "#1 verified: 「A holds」 (x)\n#2 verified: 「B holds」 (x)\n#3 fact stale: 「C」 (x)\n#4 verified: 「D」 (x)\n",
        );
        let present = Fixed(Ok(vec![
            current("#1", "stale", "A holds"),
            current("#2", "verified", "B holds"),
            current("#3", "stale", "C"),
            current("#4", "stale", "something else"),
        ]));
        let report = Report::new(session.clone(), repo.path(), Some(&present));
        let Some(Now::Read(stale)) = &report.now else {
            panic!("{:?}", report.now);
        };
        assert_eq!(
            stale
                .iter()
                .map(|(statement, now)| (statement.number, now.as_str()))
                .collect::<Vec<_>>(),
            vec![(1, "stale")]
        );
        let unread = Report::new(
            session,
            repo.path(),
            Some(&Fixed(Err("no daemon".to_owned()))),
        );
        assert_eq!(unread.now, Some(Now::Unread("no daemon".to_owned())));
    }
}
