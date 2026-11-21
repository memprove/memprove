//! `memprove report`, through the real `memprove`: it is served by the
//! memprove-report crate before the CLI's parser, finds the latest session
//! of the repository under `$HOME/.claude`, and with `--now` asks memprove
//! (here: none is set up, which it says without failing).

#[path = "u1e_support/mod.rs"]
mod support;

use std::{fs, path::Path, process::Output};

use support::{cli_binary, git, isolated, short_tempdir, text};

fn memprove(directory: &Path, home: &Path, words: &[&str]) -> Output {
    isolated(cli_binary())
        .current_dir(directory)
        .env("HOME", home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .args(words)
        .output()
        .unwrap()
}

#[test]
fn report_reads_the_latest_session_of_the_repository() {
    let (_guard, root) = short_tempdir();
    git(&root, &["init", "-q", "repo"]);
    let repo = root.join("repo");
    let home = root.join("home");
    let slug: String = repo
        .to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let dir = home.join(".claude/projects").join(slug);
    fs::create_dir_all(&dir).unwrap();
    let cwd = repo.to_string_lossy();
    fs::write(
        dir.join("0b1c2d3e-0000-4000-8000-000000000001.jsonl"),
        format!(
            "{{\"type\":\"user\",\"cwd\":\"{cwd}\",\"version\":\"2.1.326\",\"timestamp\":\"2026-11-16T10:00:00.000Z\",\"message\":{{\"role\":\"user\",\"content\":\"hi\"}}}}\n\
             {{\"type\":\"assistant\",\"cwd\":\"{cwd}\",\"timestamp\":\"2026-11-16T10:00:03.000Z\",\"message\":{{\"model\":\"claude-sonnet-4-6\",\"id\":\"msg_1\",\"role\":\"assistant\",\"content\":[{{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"Bash\",\"input\":{{\"command\":\"ls\"}}}}],\"usage\":{{\"input_tokens\":1000000,\"output_tokens\":0}}}}}}\n"
        ),
    )
    .unwrap();

    let help = memprove(&repo, &home, &["report", "--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(text(&help.stdout).starts_with("memprove report: "));
    let general = memprove(&repo, &home, &["--help"]);
    assert!(
        text(&general.stdout).contains("\nAgent session report (memprove report --help):\n"),
        "{}",
        text(&general.stdout)
    );

    let output = memprove(&repo, &home, &["report"]);
    let out = text(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(
        out.starts_with("memprove report: claude-code session 0b1c2d3e-"),
        "{out}"
    );
    // 1M input tokens of Claude Sonnet 4.6 at $3 per million.
    assert!(out.contains("Cost: $3.00 "), "{out}");
    assert!(out.contains("Tool calls: 1, 0 failed"), "{out}");
    assert!(out.contains("Policy: no log"), "{out}");

    let now = memprove(&repo, &home, &["report", "--now"]);
    assert_eq!(now.status.code(), Some(0), "{}", text(&now.stderr));
    let out = text(&now.stdout);
    assert!(
        out.contains("Memory: the agent read nothing from memprove"),
        "{out}"
    );

    let usage = memprove(&repo, &home, &["report", "--bogus"]);
    assert_eq!(usage.status.code(), Some(2));
    assert!(text(&usage.stderr).contains("unknown option --bogus"));
}
