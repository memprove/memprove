//! `memprove report --now`: the [`memprove_report::Present`] the CLI gives
//! the report crate. It reads the statements memprove would give a new
//! session in the repository with `memprove eval`'s read-only probe
//! ([`crate::eval_memory::notes_with`]: only `getTaskCapsule` and
//! `listTasks`, nothing written).

use std::path::Path;

use memprove_report::{CurrentStatement, Present};

use crate::{eval_memory, hook::Environment};

/// Reads the statements from the daemon of the configuration in use.
#[derive(Debug, Default, Clone, Copy)]
pub struct DaemonStatements;

impl Present for DaemonStatements {
    fn statements(&self, repo_root: &Path) -> Result<Vec<CurrentStatement>, String> {
        eval_memory::notes_with(&Environment::from_process(), repo_root).map(|notes| {
            notes
                .into_iter()
                .map(|note| CurrentStatement {
                    label: note.label,
                    kind: note.kind,
                    verdict: note.verdict,
                    text: note.text,
                })
                .collect()
        })
    }
}
