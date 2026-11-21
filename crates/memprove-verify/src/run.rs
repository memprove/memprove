//! One verification: what to compare ([`plan`]), then the commands on
//! clean copies and the receipt ([`execute`]).

use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use memprove_eval::{
    CommandSpec, git,
    process::{self, Invocation},
    runner::SCRUBBED_ENV,
    time,
    workspace::Worktree,
};
use sha2::{Digest, Sha256};

use crate::{
    CONTRACT_PATH, Contract, VerifyError,
    receipt::{CommandResult, ContractSource, Finding, FindingKind, Receipt, Stage, Verdict},
    snapshot::{self, Base, BaseSource, Change, ChangeKind},
    state_dir,
};

/// Given to every setup and check command: the run's name.
pub const RUN_ENV: &str = "MEMPROVE_VERIFY_RUN";
/// Given to every setup and check command: `candidate` for the work as it
/// is, `restored` for the work with every protected path as at the base.
pub const STAGE_ENV: &str = "MEMPROVE_VERIFY_STAGE";
/// Given to every setup and check command: a directory that outlives the
/// run (`<git common dir>/memprove-verify/cache`), where a contract's
/// commands may keep what is slow to rebuild.
pub const CACHE_ENV: &str = "MEMPROVE_VERIFY_CACHE";

/// The files of a run directory beside each stage's logs.
pub const RECEIPT_FILE: &str = "receipt.json";
/// What a person reads, as `memprove verify run` prints it.
pub const SUMMARY_FILE: &str = "summary.txt";
/// The end of the first failing command's output; written when the
/// verdict is `fail`.
pub const FAILURE_FILE: &str = "failure.txt";
/// The work's changes to the protected paths, as a patch; written when
/// there are any.
pub const PROTECTED_PATCH_FILE: &str = "protected.diff";

/// The most bytes of a failing command's output kept in
/// [`FAILURE_FILE`], from the end of each stream.
const TAIL_BYTES: usize = 2_000;

/// What to verify and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The worktree root.
    pub repo_root: PathBuf,
    /// `--base`: the commit the work is compared with.
    pub base: Option<String>,
    /// The commit the client session started at, when the hook recorded
    /// one; used when `base` is `None`.
    pub recorded_base: Option<String>,
    /// `--commit`: verify this commit's files, not the worktree's.
    pub commit: Option<String>,
    /// `--contract`: read the contract from this file, not the base.
    pub contract_file: Option<PathBuf>,
    /// Where run directories go; each run gets `<out_root>/<run id>/`.
    pub out_root: PathBuf,
    /// Keep each stage's working copy.
    pub keep_worktrees: bool,
    /// The client session the hook runs in, for the receipt.
    pub session: Option<String>,
}

impl Options {
    /// The options of a plain `memprove verify run` in `repo_root`.
    ///
    /// # Errors
    /// When `repo_root` is not in a Git worktree.
    pub fn new(repo_root: &Path) -> Result<Self, VerifyError> {
        Ok(Self {
            repo_root: repo_root.to_path_buf(),
            base: None,
            recorded_base: None,
            commit: None,
            contract_file: None,
            out_root: state_dir(repo_root)?.join("runs"),
            keep_worktrees: false,
            session: None,
        })
    }
}

/// What one verification compares, before any command runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The run's name.
    pub run_id: String,
    started: SystemTime,
    /// The run's directory for index files and working copies, removed
    /// when the run ends.
    scratch: PathBuf,
    /// `HEAD`.
    pub head: String,
    /// The commit the work is compared with.
    pub base: Base,
    /// Its tree.
    pub base_tree: String,
    /// The tree being verified.
    pub tree: String,
    /// The commit being verified (`--commit`).
    pub commit: Option<String>,
    /// The contract.
    pub contract: Contract,
    /// Where it was read.
    pub contract_source: ContractSource,
    /// Its file, for messages and the receipt.
    pub contract_path: String,
    /// SHA-256 of its text, hex.
    pub contract_sha256: String,
    /// Whether the work changes or deletes the contract the base has.
    pub contract_changed: bool,
}

impl Plan {
    /// Names what the verdict depends on (the tree, the base, the
    /// contract): two plans with the same key verify the same thing.
    #[must_use]
    pub fn key(&self) -> String {
        let input = format!(
            "v1\n{}\n{}\n{}\n",
            self.tree, self.base.commit, self.contract_sha256
        );
        crate::hex(&Sha256::digest(input.as_bytes()))
    }

    /// Whether the tree being verified is the base's: nothing to verify.
    #[must_use]
    pub fn unchanged(&self) -> bool {
        self.tree == self.base_tree
    }

    /// Drops a plan that will not be executed.
    pub fn discard(self) {
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

/// What [`plan`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Planned {
    /// Neither the base nor the work has a contract.
    NoContract,
    /// Ready to run.
    Ready(Box<Plan>),
}

/// Reads what a verification compares: the tree, the base and the
/// contract. Nothing of the repository is changed and no command of the
/// contract runs.
///
/// # Errors
/// [`VerifyError::Usage`] when `--base` or `--commit` names no commit;
/// [`VerifyError::Invalid`] when the repository has no commit or the
/// contract is not valid; [`VerifyError::Git`] or [`VerifyError::Io`]
/// otherwise.
pub fn plan(options: &Options) -> Result<Planned, VerifyError> {
    let started = SystemTime::now();
    let head = git::commit(&options.repo_root, "HEAD").map_err(|_| {
        VerifyError::invalid(
            None,
            "this repository has no commit yet; a verification compares the work with one",
        )
    })?;
    // The milliseconds keep two runs of the same second in order by name,
    // which is how `latest` is found.
    let millis = started
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis();
    // Two runs can start at the same instant, in one process too (a clock
    // that counts in microseconds gives two threads the same one): each
    // takes a name of its own, and a name whose directory is already there
    // is another run's.
    let mut taken = 0;
    let (run_id, scratch) = loop {
        let run_id = format!("{}-{millis:03}-{}", time::compact(started), nonce(started));
        match snapshot::scratch_dir(&run_id) {
            Ok(scratch) => break (run_id, scratch),
            Err(VerifyError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists
                    && taken < MAX_TAKEN_NAMES =>
            {
                taken += 1;
            }
            Err(error) => return Err(error),
        }
    };
    let planned = plan_in(options, started, head, run_id, &scratch);
    if !matches!(planned, Ok(Planned::Ready(_))) {
        let _ = fs::remove_dir_all(&scratch);
    }
    planned
}

fn plan_in(
    options: &Options,
    started: SystemTime,
    head: String,
    run_id: String,
    scratch: &Path,
) -> Result<Planned, VerifyError> {
    let root = &options.repo_root;
    let (tree, commit, base) = if let Some(rev) = &options.commit {
        let commit = git::commit(root, rev)
            .map_err(|_| VerifyError::Usage(format!("--commit names no commit: {rev}")))?;
        let parent = format!("{commit}~1");
        let fallback = if git::commit(root, &parent).is_ok() {
            parent
        } else {
            commit.clone()
        };
        let base = snapshot::resolve_base(
            root,
            options.base.as_deref(),
            options.recorded_base.as_deref(),
            &commit,
            (&fallback, BaseSource::Parent),
        )?;
        (snapshot::tree_of(root, &commit)?, Some(commit), base)
    } else {
        let base = snapshot::resolve_base(
            root,
            options.base.as_deref(),
            options.recorded_base.as_deref(),
            "HEAD",
            ("HEAD", BaseSource::Head),
        )?;
        (snapshot::worktree_tree(root, scratch)?, None, base)
    };
    let base_tree = snapshot::tree_of(root, &base.commit)?;
    let in_work = snapshot::file_at(root, &tree, CONTRACT_PATH)?;
    let (text, contract_source, contract_path) = if let Some(file) = &options.contract_file {
        let text = fs::read_to_string(file).map_err(|error| VerifyError::io(file, error))?;
        (
            text,
            ContractSource::File,
            file.to_string_lossy().into_owned(),
        )
    } else if let Some(text) = snapshot::file_at(root, &base_tree, CONTRACT_PATH)? {
        (text, ContractSource::Base, CONTRACT_PATH.to_owned())
    } else if let Some(text) = in_work.clone() {
        (text, ContractSource::Candidate, CONTRACT_PATH.to_owned())
    } else {
        return Ok(Planned::NoContract);
    };
    let contract = Contract::parse(&text, Some(Path::new(&contract_path)))?;
    Ok(Planned::Ready(Box::new(Plan {
        run_id,
        started,
        scratch: scratch.to_path_buf(),
        head,
        base,
        base_tree,
        tree,
        commit,
        contract,
        contract_changed: contract_source == ContractSource::Base
            && in_work.as_deref() != Some(text.as_str()),
        contract_source,
        contract_path,
        contract_sha256: crate::hex(&Sha256::digest(text.as_bytes())),
    })))
}

/// Verifies the work in `options.repo_root`: [`plan`], then [`execute`].
///
/// # Errors
/// As [`plan`] and [`execute`]; [`VerifyError::Invalid`] when there is no
/// contract.
pub fn verify(options: &Options) -> Result<(Receipt, PathBuf), VerifyError> {
    match plan(options)? {
        Planned::Ready(plan) => execute(options, &plan),
        Planned::NoContract => Err(VerifyError::invalid(
            None,
            format!(
                "no contract: neither the base commit nor the work has {CONTRACT_PATH}; \
                 `memprove verify init` writes one"
            ),
        )),
    }
}

/// Runs the contract's commands on a clean copy of the planned tree (and,
/// when the work changes a protected path, on that tree with every
/// protected path as at the base), and writes the run directory:
/// `receipt.json`, `summary.txt` and each command's output.
///
/// # Errors
/// When the run directory or a working copy cannot be written or `git`
/// fails; a command that fails is part of the verdict, not an error.
pub fn execute(options: &Options, plan: &Plan) -> Result<(Receipt, PathBuf), VerifyError> {
    let done = execute_in(options, plan);
    if !options.keep_worktrees {
        let _ = fs::remove_dir_all(&plan.scratch);
    }
    done
}

fn execute_in(options: &Options, plan: &Plan) -> Result<(Receipt, PathBuf), VerifyError> {
    let root = &options.repo_root;
    let out_root = std::path::absolute(&options.out_root)
        .map_err(|error| VerifyError::io(&options.out_root, error))?;
    let run_dir = out_root.join(&plan.run_id);
    fs::create_dir_all(&run_dir).map_err(|error| VerifyError::io(&run_dir, error))?;
    let state = state_dir(root)?;
    let cache = state.join("cache");
    fs::create_dir_all(&cache).map_err(|error| VerifyError::io(&cache, error))?;
    let run = Run {
        options,
        plan,
        dir: &run_dir,
        cache: &cache,
    };

    let protected = snapshot::changes(root, &plan.base_tree, &plan.tree, &plan.contract.protected)?;
    let mut findings: Vec<Finding> = protected.iter().map(protected_finding).collect();
    if plan.contract_changed {
        findings.push(Finding {
            kind: FindingKind::ContractChanged,
            path: plan.contract_path.clone(),
            line: None,
            detail: String::new(),
        });
    }
    if !protected.is_empty() {
        snapshot::write_patch(
            root,
            &plan.base_tree,
            &plan.tree,
            &plan.contract.protected,
            &run_dir.join(PROTECTED_PATCH_FILE),
        )?;
    }
    if plan.contract.skip_markers {
        let markers = snapshot::added_markers(root, &plan.base_tree, &plan.tree)?;
        findings.extend(
            markers
                .into_iter()
                .filter(|(path, _, _)| protected.iter().all(|change| change.path != *path))
                .map(|(path, line, marker)| Finding {
                    kind: FindingKind::SkipMarker,
                    path,
                    line: Some(line),
                    detail: marker.to_owned(),
                }),
        );
    }

    let candidate = run.stage("candidate", &plan.tree)?;
    let restored = if candidate.passed() && !protected.is_empty() {
        let tree = snapshot::restored_tree(root, &plan.scratch, &plan.tree, &protected)?;
        Some(run.stage("restored", &tree)?)
    } else {
        None
    };

    let (verdict, reasons) = judge(&candidate, restored.as_ref(), &findings);
    let receipt = Receipt {
        run_id: plan.run_id.clone(),
        started_at: time::rfc3339(plan.started),
        finished_at: time::rfc3339(SystemTime::now()),
        verdict,
        reasons,
        notes: notes(plan, restored.as_ref()),
        root: root.to_string_lossy().into_owned(),
        head: plan.head.clone(),
        session: options.session.clone(),
        contract_source: plan.contract_source,
        contract_path: plan.contract_path.clone(),
        contract_sha256: plan.contract_sha256.clone(),
        base: plan.base.clone(),
        commit: plan.commit.clone(),
        diff: snapshot::diff_stat(root, &plan.base_tree, &plan.tree)?,
        candidate,
        restored,
        findings,
    };
    let write = |name: &str, text: &str| {
        let path = run_dir.join(name);
        fs::write(&path, text).map_err(|error| VerifyError::io(&path, error))
    };
    write(RECEIPT_FILE, &receipt.to_json())?;
    write(SUMMARY_FILE, &receipt.summary(&run_dir))?;
    if let Some(failed) = receipt.candidate.first_failure() {
        write(FAILURE_FILE, &failure_tail(&run_dir, failed))?;
    }
    let index = state.join("index");
    fs::create_dir_all(&index).map_err(|error| VerifyError::io(&index, error))?;
    let entry = index.join(plan.key());
    fs::write(&entry, run_dir.to_string_lossy().as_bytes())
        .map_err(|error| VerifyError::io(&entry, error))?;
    Ok((receipt, run_dir))
}

/// The verdict and why it is not `pass`.
fn judge(
    candidate: &Stage,
    restored: Option<&Stage>,
    findings: &[Finding],
) -> (Verdict, Vec<String>) {
    if !candidate.passed() {
        return (Verdict::Fail, candidate.failures());
    }
    let mut reasons = Vec::new();
    if let Some(restored) = restored.filter(|stage| !stage.passed()) {
        reasons.push(format!(
            "the checks pass only with the work's changes to the protected paths; \
             with those paths as at the base, {}",
            restored.failures().join("; ")
        ));
    }
    let markers = findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::SkipMarker)
        .count();
    if markers > 0 {
        reasons.push(format!(
            "the work adds {markers} skip marker{} outside the protected paths",
            if markers == 1 { "" } else { "s" }
        ));
    }
    if reasons.is_empty() {
        (Verdict::Pass, reasons)
    } else {
        (Verdict::NeedsHuman, reasons)
    }
}

fn notes(plan: &Plan, restored: Option<&Stage>) -> Vec<String> {
    let mut notes = Vec::new();
    if restored.is_some_and(Stage::passed) {
        notes.push(
            "the work changes protected paths, and the checks also pass with those paths as \
             at the base"
                .to_owned(),
        );
    }
    if plan.contract_changed {
        notes.push(
            "the work changes the contract; the checks are the base commit's, and the changed \
             contract counts once it is in the base"
                .to_owned(),
        );
    }
    if plan.contract_source == ContractSource::Candidate {
        notes.push(
            "the base commit has no contract, so the contract was read from the work \
             verified; commit it to have later work verified against it"
                .to_owned(),
        );
    }
    if plan.base.chosen_by == BaseSource::Head {
        notes.push(
            "the base is HEAD, so commits already made are not compared; --base <REV> names \
             an earlier commit"
                .to_owned(),
        );
    }
    notes
}

fn protected_finding(change: &Change) -> Finding {
    Finding {
        kind: match change.kind {
            ChangeKind::Added => FindingKind::ProtectedAdded,
            ChangeKind::Modified => FindingKind::ProtectedModified,
            ChangeKind::Deleted => FindingKind::ProtectedDeleted,
        },
        path: change.path.clone(),
        line: None,
        detail: String::new(),
    }
}

/// What every stage of a run shares.
struct Run<'a> {
    options: &'a Options,
    plan: &'a Plan,
    /// The run directory.
    dir: &'a Path,
    cache: &'a Path,
}

impl Run<'_> {
    /// Writes the files of `tree` to a new repository of its own and runs
    /// the contract's setup commands and checks there; a setup command
    /// that fails ends the stage before any check.
    fn stage(&self, name: &str, tree: &str) -> Result<Stage, VerifyError> {
        let work = Worktree::isolated(
            &self.options.repo_root,
            &self.plan.scratch.join("work"),
            name,
            tree,
            &[],
        )?;
        let logs = self.dir.join(name);
        fs::create_dir_all(&logs).map_err(|error| VerifyError::io(&logs, error))?;
        let env = vec![
            (RUN_ENV.to_owned(), self.plan.run_id.clone()),
            (STAGE_ENV.to_owned(), name.to_owned()),
            (
                CACHE_ENV.to_owned(),
                self.cache.to_string_lossy().into_owned(),
            ),
        ];
        let command = |spec: &CommandSpec, result_name: String, stem: String| {
            let finished = process::run(&Invocation {
                argv: &spec.argv,
                cwd: work.path(),
                env: &env,
                env_remove: &SCRUBBED_ENV
                    .iter()
                    .map(|variable| (*variable).to_owned())
                    .collect::<Vec<_>>(),
                clear_env: false,
                stdout: logs.join(format!("{stem}.out")),
                stderr: logs.join(format!("{stem}.err")),
                timeout: spec.timeout,
            });
            CommandResult {
                name: result_name,
                argv: spec.argv.clone(),
                exit: finished.as_ref().ok().map(|finished| finished.exit),
                error: finished.as_ref().err().map(ToString::to_string),
                duration_ms: finished
                    .as_ref()
                    .map_or(0, |finished| time::millis(finished.duration)),
                timeout_secs: spec.timeout.as_secs(),
                log: format!("{name}/{stem}"),
            }
        };
        let mut stage = Stage {
            tree: tree.to_owned(),
            setup: Vec::new(),
            checks: Vec::new(),
        };
        for (index, spec) in self.plan.contract.setup.iter().enumerate() {
            let stem = format!("setup-{}", index + 1);
            let result = command(spec, stem.clone(), stem);
            let passed = result.passed();
            stage.setup.push(result);
            if !passed {
                break;
            }
        }
        if stage.setup.iter().all(CommandResult::passed) {
            for check in &self.plan.contract.checks {
                stage.checks.push(command(
                    &check.command,
                    check.name.clone(),
                    format!("check-{}", check.name),
                ));
            }
        }
        if !self.options.keep_worktrees {
            let _ = work.remove();
        }
        Ok(stage)
    }
}

/// The end of what `failed` printed, for the agent that has to fix it.
fn failure_tail(run_dir: &Path, failed: &CommandResult) -> String {
    let mut text = format!(
        "`{}` ({}) {}.\n",
        failed.name,
        failed.argv.join(" "),
        failed.ended()
    );
    for (stream, extension) in [("standard output", "out"), ("standard error", "err")] {
        let path = run_dir.join(format!("{}.{extension}", failed.log));
        let output = fs::read(&path).unwrap_or_default();
        let output = String::from_utf8_lossy(&output);
        let output = output.trim_end();
        if output.is_empty() {
            continue;
        }
        let mut start = output.len().saturating_sub(TAIL_BYTES);
        while !output.is_char_boundary(start) {
            start += 1;
        }
        writeln!(
            text,
            "The end of its {stream} ({}):\n{}",
            path.display(),
            &output[start..]
        )
        .expect("writing to a String cannot fail");
    }
    text
}

/// A verification already made of the same tree, base and contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Earlier {
    /// Its verdict.
    pub verdict: Verdict,
    /// Its summary, as `memprove verify run` printed it.
    pub summary: String,
    /// The end of its first failing command's output, when it failed.
    pub failure: Option<String>,
    /// Its run directory.
    pub run_dir: PathBuf,
}

/// The latest verification with `key` ([`Plan::key`]) in the repository of
/// `repo_root`, when its run directory still holds a receipt.
#[must_use]
pub fn earlier(repo_root: &Path, key: &str) -> Option<Earlier> {
    let entry = state_dir(repo_root).ok()?.join("index").join(key);
    let run_dir = PathBuf::from(fs::read_to_string(entry).ok()?);
    read_run(&run_dir)
}

/// The verification whose run directory is `run_dir`.
#[must_use]
pub fn read_run(run_dir: &Path) -> Option<Earlier> {
    let receipt = fs::read_to_string(run_dir.join(RECEIPT_FILE)).ok()?;
    let receipt = memprove_eval::json::parse(&receipt, None).ok()?;
    let verdict = Verdict::parse(receipt.get("verdict")?.as_str()?)?;
    Some(Earlier {
        verdict,
        summary: fs::read_to_string(run_dir.join(SUMMARY_FILE)).ok()?,
        failure: fs::read_to_string(run_dir.join(FAILURE_FILE)).ok(),
        run_dir: run_dir.to_path_buf(),
    })
}

/// The run directory `name` names under `out_root`: `latest` (or `None`)
/// is the one with the greatest name that holds a receipt; anything else
/// is a path.
///
/// # Errors
/// [`VerifyError::Invalid`] when there is no run yet.
pub fn resolve_run_dir(out_root: &Path, name: Option<&str>) -> Result<PathBuf, VerifyError> {
    let none = || {
        VerifyError::invalid(
            None,
            format!(
                "no run under {}; `memprove verify run` makes one",
                out_root.display()
            ),
        )
    };
    match name {
        Some(name) if name != "latest" => Ok(PathBuf::from(name)),
        _ => {
            let mut runs: Vec<PathBuf> = fs::read_dir(out_root)
                .map_err(|_| none())?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|dir| dir.join(RECEIPT_FILE).is_file())
                .collect();
            runs.sort();
            runs.pop().ok_or_else(none)
        }
    }
}

/// How many names that are already taken a run passes over before it gives
/// up.
const MAX_TAKEN_NAMES: u32 = 16;

/// How many names this process has made: two runs it starts at the same
/// instant still get different ones.
static NAMES_MADE: AtomicU64 = AtomicU64::new(0);

/// Six hex digits that make two runs started in the same second differ.
fn nonce(now: SystemTime) -> String {
    let nanos = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    nonce_of(
        nanos,
        std::process::id(),
        NAMES_MADE.fetch_add(1, Ordering::Relaxed),
    )
}

/// The digits for an instant, a process and the count of names it has made.
fn nonce_of(nanos: u128, process: u32, made: u64) -> String {
    let digest = Sha256::digest(format!("{nanos}-{process}-{made}").as_bytes());
    crate::hex(&digest[..3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_runs_of_one_instant_in_one_process_get_different_names() {
        // What the macOS CI showed: its clock counts in microseconds, two
        // tests started a run in the same one, and both were given the
        // same name and so the same scratch directory.
        let instant = 1_795_277_770_123_456_000;
        assert_ne!(nonce_of(instant, 685, 0), nonce_of(instant, 685, 1));
        assert_ne!(nonce_of(instant, 685, 0), nonce_of(instant, 686, 0));
        let before = NAMES_MADE.load(Ordering::Relaxed);
        let now = SystemTime::now();
        let (_first, _second) = (nonce(now), nonce(now));
        assert!(NAMES_MADE.load(Ordering::Relaxed) >= before + 2);
    }
}
