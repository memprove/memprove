//! U23-F1: a task that only an agent that read memprove's Pack can pass,
//! run without memory and with the Pack: what the agent reads, its
//! `MEMPROVE_CONFIG_DIR`, `pack.md`, `memory_given`, the comparison, and
//! the runs `--memory pack` refuses.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use memprove_eval::{
    AgentKind, AgentSpec, Baseline, Memory, MemoryNote, MemoryProbe, Outcome, RunRecord,
    agent::agent_for,
    git::git,
    report::{Format, render},
    runner::{self, AGENT_CONFIG_DIR, PACK_FILE, RunOptions, pack_preamble},
    task,
};
use sha2::{Digest as _, Sha256};

const PACK: &str =
    "Task #3: keep the answer file right\n\nFacts:\n- #4 [verified] the answer is 42\n";
const PROMPT: &str = "Write the answer to answer.txt.";

/// Reads a fixed Pack, or fails with a fixed sentence.
struct Probe(Option<&'static str>);

impl MemoryProbe for Probe {
    fn read(&self, _repo_root: &Path) -> Result<Memory, String> {
        match self.0 {
            Some(pack) => Ok(Memory {
                notes: vec![MemoryNote {
                    label: "#4".to_owned(),
                    kind: "fact".to_owned(),
                    verdict: "verified".to_owned(),
                    text: "the answer is 42".to_owned(),
                    commit: None,
                }],
                pack: pack.to_owned(),
            }),
            None => Err("no memprove context for this repository".to_owned()),
        }
    }
}

fn repository() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    for args in [
        &["init", "--quiet", "-b", "main"][..],
        &["config", "user.email", "eval@example.invalid"],
        &["config", "user.name", "eval"],
    ] {
        git(root, args).expect("git");
    }
    fs::create_dir_all(root.join("evals")).expect("evals");
    fs::write(
        root.join("evals/answer.json"),
        format!(
            r#"{{"schema": "memprove.eval.task.v1", "prompt": "{PROMPT}",
                "check": {{"argv": ["sh", "-c", "test \"$(cat answer.txt)\" = 42"]}}}}"#
        ),
    )
    .expect("task");
    git(root, &["add", "."]).expect("add");
    git(root, &["commit", "--quiet", "-m", "start"]).expect("commit");
    dir
}

/// A `command` agent that answers 42 only when its prompt says so, and
/// keeps its `MEMPROVE_CONFIG_DIR` next to its prompt.
fn options(root: &Path, out: &Path, give_pack: bool) -> RunOptions {
    let script = "if grep -q 'the answer is 42' \"$MEMPROVE_EVAL_PROMPT_FILE\"; \
                  then echo 42 > answer.txt; else echo unknown > answer.txt; fi; \
                  printf '%s' \"${MEMPROVE_CONFIG_DIR-unset}\" \
                  > \"$(dirname \"$MEMPROVE_EVAL_PROMPT_FILE\")/config-dir\"";
    RunOptions {
        repo_root: root.to_path_buf(),
        agent: AgentSpec {
            kind: AgentKind::Command,
            model: None,
            command: vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()],
            extra_args: Vec::new(),
            pass_env: Vec::new(),
        },
        trials: 1,
        jobs: 1,
        out_root: out.to_path_buf(),
        keep_worktrees: false,
        progress: false,
        give_pack,
    }
}

fn run(root: &Path, out: &Path, give_pack: bool, probe: &dyn MemoryProbe) -> (RunRecord, PathBuf) {
    let options = options(root, out, give_pack);
    let suite = task::load_suite(root, &[PathBuf::from("evals")]).expect("suite");
    let agent = agent_for(&options.agent).expect("agent");
    runner::run_suite(&options, &suite, agent.as_ref(), Some(probe)).expect("runs")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

fn trial_file(run_dir: &Path, run: &RunRecord, name: &str) -> String {
    fs::read_to_string(run_dir.join(&run.results[0].logs).join(name)).expect(name)
}

#[test]
fn u23_f1_the_pack_fixes_a_task_only_memory_can_pass() {
    let repo = repository();
    let root = repo.path();
    let out = tempfile::tempdir().expect("out");
    let probe = Probe(Some(PACK));

    let (without, without_dir) = run(root, out.path(), false, &probe);
    let (with, with_dir) = run(root, out.path(), true, &probe);
    assert_eq!(without.results[0].outcome, Outcome::Failed);
    assert_eq!(with.results[0].outcome, Outcome::Passed);

    // Without memory the agent reads the task's prompt alone; with the
    // Pack, the framed Pack, which says which commit's files the working
    // copy holds, and then the prompt.
    let base = git(root, &["rev-parse", "HEAD"]).expect("head");
    assert_eq!(with.results[0].base, base.trim());
    assert_eq!(trial_file(&without_dir, &without, "prompt.md"), PROMPT);
    assert_eq!(
        trial_file(&with_dir, &with, "prompt.md"),
        format!("{}{PROMPT}", pack_preamble(PACK, base.trim()))
    );
    assert!(
        trial_file(&with_dir, &with, "prompt.md")
            .contains(&format!("holds the files of commit {}", base.trim()))
    );
    assert!(trial_file(&with_dir, &with, "prompt.md").contains("```text\nTask #3"));

    // Both arms point the agent's memprove at an empty directory of their
    // own run, readable by its owner only.
    for (record, dir) in [(&without, &without_dir), (&with, &with_dir)] {
        let config = dir.join(AGENT_CONFIG_DIR);
        assert_eq!(
            trial_file(dir, record, "config-dir"),
            config.to_string_lossy()
        );
        assert_eq!(fs::read_dir(&config).expect("config").count(), 0);
        assert_eq!(
            fs::metadata(&config).expect("config").permissions().mode() & 0o777,
            0o700
        );
    }

    // The Pack given is kept, and run.json says which.
    assert!(!without_dir.join(PACK_FILE).exists());
    assert_eq!(without.memory_given, None);
    assert_eq!(
        fs::read_to_string(with_dir.join(PACK_FILE)).expect("pack.md"),
        PACK
    );
    let given = with.memory_given.as_ref().expect("memory_given");
    assert_eq!(given.bytes, PACK.len() as u64);
    assert_eq!(given.sha256, hex(&Sha256::digest(PACK.as_bytes())));
    assert_eq!(&runner::read_run(&with_dir).expect("reads"), &with);
    // Both arms record the statements read.
    assert_eq!(without.memory, with.memory);
    assert_eq!(with.memory.len(), 1);

    // The run with the Pack against the run without: 0% → 100%, fixed.
    let report = render(&with, Some(&Baseline::from_run(&without)), Format::Markdown);
    assert!(
        report.contains(
            "**0.0% → 100.0% (+100.0 pp)** on the 1 task in both · 0 regressed · 1 fixed"
        ),
        "{report}"
    );
    assert!(report.contains(&format!("memprove's Pack `{}`", &given.sha256[..7])));
    assert!(report.contains("| fixed |"), "{report}");
}

#[test]
fn u23_f1_memory_pack_refuses_a_run_without_a_pack() {
    let repo = repository();
    let root = repo.path();
    let out = tempfile::tempdir().expect("out");
    let options = options(root, out.path(), true);
    let suite = task::load_suite(root, &[PathBuf::from("evals")]).expect("suite");
    let agent = agent_for(&options.agent).expect("agent");

    let unread = runner::run_suite(&options, &suite, agent.as_ref(), Some(&Probe(None)))
        .expect_err("no Pack");
    assert_eq!(
        unread.to_string(),
        "--memory pack: memprove's memory was not read: no memprove context for this repository"
    );
    let none = runner::run_suite(&options, &suite, agent.as_ref(), None).expect_err("no probe");
    assert_eq!(
        none.to_string(),
        "--memory pack needs memprove's memory, and this build reads none"
    );
    // No trial ran: no run directory is left.
    assert_eq!(fs::read_dir(out.path()).expect("out").count(), 0);
    assert!(!root.join("answer.txt").exists());

    // Without --memory pack the same unread memory is a note, not an error.
    let options = RunOptions {
        give_pack: false,
        ..options
    };
    let (record, _) =
        runner::run_suite(&options, &suite, agent.as_ref(), Some(&Probe(None))).expect("runs");
    assert_eq!(
        record.memory_unread.as_deref(),
        Some("no memprove context for this repository")
    );
    assert_eq!(record.memory_given, None);
}
