//! U23 W1: `memprove eval` is served by the memprove-eval crate before the
//! CLI's parser, and its summary line is what `memprove run --test-format
//! cargo` counts.

use std::process::{Command, Output};

use memprove_cli::run::cargo_case_count;
use memprove_eval::{
    AgentKind, AgentSpec, DiffStat, Outcome, RepositoryInfo, RunRecord, TaskRef, TrialResult,
    runner::libtest_summary,
};

fn memprove(directory: &std::path::Path, words: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_memprove"))
        .args(words)
        .current_dir(directory)
        .env_remove("MEMPROVE_CONFIG_DIR")
        .output()
        .expect("memprove starts")
}

#[test]
fn u23_w1_eval_help_and_usage_errors() {
    let empty = tempfile::tempdir().expect("tempdir");
    let help = memprove(empty.path(), &["eval", "--help"]);
    assert_eq!(help.status.code(), Some(0));
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.starts_with("memprove eval: "), "{text}");
    for command in ["init", "mine", "run", "ab", "report", "baseline", "gate"] {
        let output = memprove(empty.path(), &["eval", command, "--help"]);
        assert_eq!(output.status.code(), Some(0), "{command}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.starts_with(&format!("memprove eval {command}: ")),
            "{text}"
        );
        assert!(text.contains("\nExit status:\n"), "{command}");
    }
    let output = memprove(empty.path(), &["eval", "run", "--agent", "command"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "memprove eval run: error: --agent command needs the program after --\n\
         Run `memprove eval run --help` for its options.\n"
    );
    // U23-F1: --memory takes none or pack, and pack reads memory.
    for (words, error) in [
        (
            &["eval", "run", "--memory", "all"][..],
            "--memory must be none or pack, not \"all\"",
        ),
        (
            &["eval", "run", "--memory", "pack", "--no-memory"],
            "--memory pack gives the agent memprove's memory, and --no-memory reads none",
        ),
        (
            &["eval", "ab", "--memory", "pack"],
            "unknown option --memory",
        ),
        // U23-F3: a session variable cannot be passed to the agent.
        (
            &["eval", "run", "--pass-env", "CLAUDECODE"],
            "--pass-env CLAUDECODE",
        ),
        (&["eval", "ab", "--pass-env", "A=B"], "--pass-env \"A=B\""),
    ] {
        let output = memprove(empty.path(), words);
        assert_eq!(output.status.code(), Some(2), "{words:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(error), "{words:?}: {stderr}");
    }
    let general = memprove(empty.path(), &["--help"]);
    assert!(
        String::from_utf8_lossy(&general.stdout)
            .contains("\nAgent evaluation (memprove eval --help):\n")
    );
}

fn trial(task: &str, outcome: Outcome) -> TrialResult {
    TrialResult {
        task: task.to_owned(),
        trial: 1,
        base: "0".repeat(40),
        outcome,
        reason: None,
        agent: None,
        check_exit: Some(i32::from(outcome != Outcome::Passed)),
        check_ms: 1_500,
        diff: DiffStat::default(),
        logs: format!("trials/{task}/1"),
    }
}

#[test]
fn u23_w1_the_summary_line_counts_one_case_per_trial() {
    let run = RunRecord {
        run_id: "20261114T221323Z-a1b2c3".to_owned(),
        started_at: "2026-11-14T22:13:23Z".to_owned(),
        finished_at: "2026-11-14T22:20:01Z".to_owned(),
        repository: RepositoryInfo {
            root: "/work/repo".to_owned(),
            head: "0".repeat(40),
        },
        agent: AgentSpec {
            kind: AgentKind::Command,
            model: None,
            command: vec!["sh".to_owned()],
            extra_args: Vec::new(),
            pass_env: Vec::new(),
        },
        agent_version: None,
        trials_per_task: 1,
        tasks: ["a", "b", "c"]
            .iter()
            .map(|id| TaskRef {
                id: (*id).to_owned(),
                title: None,
                source: format!("evals/{id}.json"),
                sha256: "0".repeat(64),
            })
            .collect(),
        results: vec![
            trial("a", Outcome::Passed),
            trial("b", Outcome::Failed),
            trial("c", Outcome::Passed),
        ],
        memory: Vec::new(),
        memory_unread: None,
        memory_given: None,
    };
    let line = format!("{}\n", libtest_summary(&run));
    assert_eq!(cargo_case_count(line.as_bytes(), b"", 1), Some(3));
    // A summary with failures never counts as a pass under exit code 0.
    assert_eq!(cargo_case_count(line.as_bytes(), b"", 0), None);
    let all_passed = RunRecord {
        results: vec![trial("a", Outcome::Passed)],
        ..run
    };
    let line = format!("{}\n", libtest_summary(&all_passed));
    assert_eq!(cargo_case_count(line.as_bytes(), b"", 0), Some(1));
}
