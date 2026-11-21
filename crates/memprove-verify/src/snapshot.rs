//! What a verification compares: the tree being verified, the base commit,
//! and what differs between them, read with `git` plumbing that touches
//! neither the repository's index nor its refs.

use std::{
    fs,
    path::{Path, PathBuf},
};

use memprove_eval::git::{self, git, git_with_env};

use crate::{VerifyError, markers};

/// How the base commit was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseSource {
    /// `--base`.
    Option,
    /// The commit the client session started at, recorded by the hook.
    Session,
    /// The merge base with the current branch's upstream.
    Upstream,
    /// The first parent of the commit being verified (`--commit`, when its
    /// branch has no upstream).
    Parent,
    /// `HEAD`: only changes that are not committed are compared.
    Head,
}

impl BaseSource {
    /// The name in a receipt.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Option => "option",
            Self::Session => "session",
            Self::Upstream => "upstream",
            Self::Parent => "parent",
            Self::Head => "head",
        }
    }

    /// What a summary says after the commit.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            Self::Option => "from --base",
            Self::Session => "where the client session started",
            Self::Upstream => "the merge base with the upstream branch",
            Self::Parent => "the first parent of the commit",
            Self::Head => "HEAD: only changes that are not committed are compared",
        }
    }
}

/// The commit the work is compared with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    /// The full commit name.
    pub commit: String,
    /// How it was chosen.
    pub chosen_by: BaseSource,
}

/// The tree of `rev` (a commit or a tree) in `repo_root`.
///
/// # Errors
/// When `rev` names no tree.
pub fn tree_of(repo_root: &Path, rev: &str) -> Result<String, VerifyError> {
    let spec = format!("{rev}^{{tree}}");
    Ok(
        git(repo_root, &["rev-parse", "--verify", "--quiet", &spec])?
            .trim()
            .to_owned(),
    )
}

/// The tree of the worktree as it stands: every tracked file as it is on
/// disk and every untracked file Git does not ignore. It is written through
/// an index file of its own in `scratch`, so the repository's index is not
/// touched.
///
/// # Errors
/// When `git` fails.
pub fn worktree_tree(repo_root: &Path, scratch: &Path) -> Result<String, VerifyError> {
    let index = scratch.join("worktree.index");
    let env = [("GIT_INDEX_FILE", index.as_os_str())];
    let written = git_with_env(repo_root, &env, &["read-tree", "HEAD"])
        .and_then(|_| git_with_env(repo_root, &env, &["add", "--all"]))
        .and_then(|_| git_with_env(repo_root, &env, &["write-tree"]));
    let _ = fs::remove_file(&index);
    Ok(written?.trim().to_owned())
}

/// Chooses the base: `option` (`--base`), else `recorded` (the commit the
/// hook recorded when the client session started) when it still names a
/// commit, else the merge base of `tip` with the current branch's upstream,
/// else `fallback`.
///
/// # Errors
/// [`VerifyError::Usage`] when `option` names no commit; when `fallback`
/// names none.
pub fn resolve_base(
    repo_root: &Path,
    option: Option<&str>,
    recorded: Option<&str>,
    tip: &str,
    fallback: (&str, BaseSource),
) -> Result<Base, VerifyError> {
    if let Some(rev) = option {
        let commit = git::commit(repo_root, rev)
            .map_err(|_| VerifyError::Usage(format!("--base names no commit: {rev}")))?;
        return Ok(Base {
            commit,
            chosen_by: BaseSource::Option,
        });
    }
    if let Some(commit) = recorded.and_then(|rev| git::commit(repo_root, rev).ok()) {
        return Ok(Base {
            commit,
            chosen_by: BaseSource::Session,
        });
    }
    if let Ok(merge_base) = git(repo_root, &["merge-base", tip, "@{upstream}"])
        && !merge_base.trim().is_empty()
    {
        return Ok(Base {
            commit: merge_base.trim().to_owned(),
            chosen_by: BaseSource::Upstream,
        });
    }
    Ok(Base {
        commit: git::commit(repo_root, fallback.0)?,
        chosen_by: fallback.1,
    })
}

/// The text of `path` in `tree`, or `None` when the tree has no such file.
///
/// # Errors
/// When `git` cannot be run.
pub fn file_at(repo_root: &Path, tree: &str, path: &str) -> Result<Option<String>, VerifyError> {
    let spec = format!("{tree}:{path}");
    if git(repo_root, &["cat-file", "-e", &spec]).is_err() {
        return Ok(None);
    }
    git(repo_root, &["cat-file", "blob", &spec]).map(Some)
}

/// How a path differs from the base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// The base does not have it.
    Added,
    /// The base has it with other content or another mode.
    Modified,
    /// Only the base has it.
    Deleted,
}

/// One path that differs between the base and the tree being verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// How it differs.
    pub kind: ChangeKind,
    /// The path, relative to the repository root.
    pub path: String,
    /// Its mode at the base (`000000` when added).
    base_mode: String,
    /// Its object at the base (zeros when added).
    base_object: String,
}

fn pathspecs(patterns: &[String]) -> Vec<String> {
    patterns
        .iter()
        .map(|pattern| format!(":(glob){pattern}"))
        .collect()
}

/// The paths matching `patterns` (Git glob patterns) that differ between
/// the trees `base` and `tree`; none when there is no pattern.
///
/// # Errors
/// When `git` fails.
pub fn changes(
    repo_root: &Path,
    base: &str,
    tree: &str,
    patterns: &[String],
) -> Result<Vec<Change>, VerifyError> {
    if patterns.is_empty() {
        return Ok(Vec::new());
    }
    let specs = pathspecs(patterns);
    let mut args = vec![
        "diff-tree",
        "-r",
        "--no-renames",
        "--raw",
        "--no-abbrev",
        "-z",
        base,
        tree,
        "--",
    ];
    args.extend(specs.iter().map(String::as_str));
    Ok(parse_raw(&git(repo_root, &args)?))
}

/// The entries of `git diff-tree --raw -z` output:
/// `:<old mode> <new mode> <old object> <new object> <status>\0<path>\0`.
fn parse_raw(listing: &str) -> Vec<Change> {
    let mut changes = Vec::new();
    let mut fields = listing.split('\0');
    while let (Some(meta), Some(path)) = (fields.next(), fields.next()) {
        let mut meta = meta.trim_start_matches(':').split(' ');
        let (Some(base_mode), Some(_), Some(base_object), Some(_), Some(status)) = (
            meta.next(),
            meta.next(),
            meta.next(),
            meta.next(),
            meta.next(),
        ) else {
            continue;
        };
        let kind = match status.chars().next() {
            Some('A') => ChangeKind::Added,
            Some('D') => ChangeKind::Deleted,
            _ => ChangeKind::Modified,
        };
        changes.push(Change {
            kind,
            path: path.to_owned(),
            base_mode: base_mode.to_owned(),
            base_object: base_object.to_owned(),
        });
    }
    changes
}

/// The tree `tree` becomes when every path of `changes` is put back as it
/// is at the base: an added path is removed, a modified or deleted one gets
/// the base's content and mode. Written through an index file of its own in
/// `scratch`.
///
/// # Errors
/// When `git` fails.
pub fn restored_tree(
    repo_root: &Path,
    scratch: &Path,
    tree: &str,
    changes: &[Change],
) -> Result<String, VerifyError> {
    let index = scratch.join("restored.index");
    let env = [("GIT_INDEX_FILE", index.as_os_str())];
    let build = || -> Result<String, VerifyError> {
        git_with_env(repo_root, &env, &["read-tree", tree])?;
        // Removals first: a file the base has may stand where the work
        // made a directory.
        for change in changes
            .iter()
            .filter(|change| change.kind == ChangeKind::Added)
        {
            git_with_env(
                repo_root,
                &env,
                &["update-index", "--force-remove", "--", &change.path],
            )?;
        }
        for change in changes
            .iter()
            .filter(|change| change.kind != ChangeKind::Added)
        {
            let entry = format!(
                "{},{},{}",
                change.base_mode, change.base_object, change.path
            );
            git_with_env(
                repo_root,
                &env,
                &["update-index", "--add", "--cacheinfo", &entry],
            )?;
        }
        git_with_env(repo_root, &env, &["write-tree"])
    };
    let written = build();
    let _ = fs::remove_file(&index);
    Ok(written?.trim().to_owned())
}

/// How much differs between the trees `base` and `tree`: files, lines
/// added, lines removed.
///
/// # Errors
/// When `git` fails.
pub fn diff_stat(repo_root: &Path, base: &str, tree: &str) -> Result<(u64, u64, u64), VerifyError> {
    let numstat = git(
        repo_root,
        &["diff-tree", "-r", "--no-renames", "--numstat", base, tree],
    )?;
    let mut stat = (0, 0, 0);
    for line in numstat.lines() {
        let mut fields = line.split('\t');
        let mut count = || {
            fields
                .next()
                .and_then(|field| field.parse::<u64>().ok())
                .unwrap_or(0)
        };
        stat.0 += 1;
        stat.1 += count();
        stat.2 += count();
    }
    Ok(stat)
}

/// Writes the differences in the paths matching `patterns` between the
/// trees `base` and `tree` to `out`, as a patch for a person to read.
///
/// # Errors
/// When `git` fails or `out` cannot be written.
pub fn write_patch(
    repo_root: &Path,
    base: &str,
    tree: &str,
    patterns: &[String],
    out: &Path,
) -> Result<(), VerifyError> {
    let specs = pathspecs(patterns);
    let mut args = vec![
        "diff-tree",
        "-r",
        "-p",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        base,
        tree,
        "--",
    ];
    args.extend(specs.iter().map(String::as_str));
    let patch = git(repo_root, &args)?;
    fs::write(out, patch).map_err(|error| VerifyError::io(out, error))
}

/// A skip marker the work adds: the file, the line in it, the marker.
pub type AddedMarker = (String, u64, &'static str);

/// The skip markers in the lines added between the trees `base` and
/// `tree`.
///
/// # Errors
/// When `git` fails.
pub fn added_markers(
    repo_root: &Path,
    base: &str,
    tree: &str,
) -> Result<Vec<AddedMarker>, VerifyError> {
    let patch = git(
        repo_root,
        &[
            "diff-tree",
            "-r",
            "-p",
            "-U0",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            base,
            tree,
        ],
    )?;
    Ok(markers::added_in(&patch)
        .into_iter()
        .map(|added| (added.path, added.line, added.marker))
        .collect())
}

/// A new directory for one verification's index files and working copies,
/// under the system's temporary directory. It is made anew: a directory of
/// that name that is already there is another run's, and is never shared.
///
/// # Errors
/// When it cannot be created; with the kind `AlreadyExists` when a run of
/// that name has one.
pub fn scratch_dir(run_id: &str) -> Result<PathBuf, VerifyError> {
    let parent = std::env::temp_dir();
    fs::create_dir_all(&parent).map_err(|error| VerifyError::io(&parent, error))?;
    let dir = parent.join(format!("memprove-verify-{run_id}"));
    fs::create_dir(&dir).map_err(|error| VerifyError::io(&dir, error))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scratch_directory_is_made_anew_and_never_shared() {
        let run_id = format!("test-{}-a-name-taken-twice", std::process::id());
        let dir = scratch_dir(&run_id).expect("the first run gets the directory");
        let second = scratch_dir(&run_id);
        fs::remove_dir_all(&dir).expect("removed");
        match second {
            Err(VerifyError::Io { path, source }) => {
                assert_eq!(path, dir);
                assert_eq!(source.kind(), std::io::ErrorKind::AlreadyExists);
            }
            other => panic!("a second run was given the first run's directory: {other:?}"),
        }
    }

    #[test]
    fn reads_raw_entries() {
        let zeros = "0".repeat(40);
        let object = "a".repeat(40);
        let listing = format!(
            ":100644 100644 {object} {zeros} M\0tests/a.rs\0:000000 100644 {zeros} {object} A\0tests/new file.rs\0:100755 000000 {object} {zeros} D\0tests/run.sh\0"
        );
        let changes = parse_raw(&listing);
        assert_eq!(
            changes
                .iter()
                .map(|change| (change.kind, change.path.as_str()))
                .collect::<Vec<_>>(),
            [
                (ChangeKind::Modified, "tests/a.rs"),
                (ChangeKind::Added, "tests/new file.rs"),
                (ChangeKind::Deleted, "tests/run.sh"),
            ]
        );
        assert_eq!(changes[2].base_mode, "100755");
        assert_eq!(changes[2].base_object, object);
    }
}
