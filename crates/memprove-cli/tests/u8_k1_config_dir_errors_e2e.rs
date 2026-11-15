//! U8 K1 (U7 V-N1, V-N3; ADR 0014 "Amendment (U8, S-K)"), through the real
//! `memprove`: when `hook session-start` or `mcp serve` is refused for its
//! `--config-dir`, the text names the real reason (a global option does not
//! apply, the directory is missing, the directory is empty) instead of
//! blaming the option itself; the exit codes do not change (the hook always
//! exits 0, `mcp serve` exits 2 on a usage error). The general `--help`
//! shows `[--config-dir <DIR>]` on both commands, and `resume --help` says
//! what `--pack` does about a Session someone else left open.

#[path = "u1e_support/mod.rs"]
mod support;

use std::{
    io::Write as _,
    process::{Output, Stdio},
};

use support::{cli_binary, isolated, short_tempdir, text};

/// `memprove <words>` in an empty directory with `input` on standard input.
fn run(words: &[&str], input: &str) -> Output {
    let (_guard, root) = short_tempdir();
    let mut child = isolated(cli_binary())
        .current_dir(&root)
        .env("HOME", &root)
        .args(words)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    println!(
        "$ memprove {words:?}\n{}{}[exit {:?}]",
        text(&output.stdout),
        text(&output.stderr),
        output.status.code()
    );
    output
}

const NOT_INJECTED: &str = "no Context Pack was injected into this session";

#[test]
fn u8_k1_the_hook_statement_names_the_real_reason() {
    let input =
        r#"{"hook_event_name":"SessionStart","session_id":"k1","source":"startup","cwd":"/tmp"}"#;
    for (words, says) in [
        (
            &[
                "--data-dir",
                "/x",
                "hook",
                "session-start",
                "--config-dir",
                "/c",
            ][..],
            "memprove: the global option --data-dir does not apply to hook session-start; --config-dir <DIR> goes right after hook session-start; ",
        ),
        (
            &["--token-file", "/x", "hook", "session-start"][..],
            "memprove: the global option --token-file does not apply to hook session-start; --config-dir <DIR> goes right after hook session-start; ",
        ),
        (
            &["hook", "session-start", "--config-dir"][..],
            "memprove: hook session-start's --config-dir lacks a directory; ",
        ),
        (
            &["hook", "session-start", "--config-dir", ""][..],
            "memprove: hook session-start's --config-dir directory is empty; ",
        ),
        // Anything else is as before.
        (
            &["hook", "session-start", "--bogus"][..],
            "memprove: hook session-start takes one option only, --config-dir <DIR>; ",
        ),
        (
            &["hook", "session-start", "--config-dir", "/c", "extra"][..],
            "memprove: hook session-start takes one option only, --config-dir <DIR>; ",
        ),
    ] {
        let output = run(words, input);
        assert_eq!(output.status.code(), Some(0), "{words:?}");
        let stdout = text(&output.stdout);
        assert_eq!(
            stdout,
            format!("{says}{NOT_INJECTED}.\n"),
            "{words:?}: {stdout}"
        );
        assert!(output.stderr.is_empty(), "{words:?}");
    }
}

#[test]
fn u8_k1_mcp_serve_names_the_real_reason() {
    for (words, says) in [
        (
            &["--data-dir", "/x", "mcp", "serve", "--config-dir", "/c"][..],
            "--data-dir does not apply to mcp serve; --config-dir <DIR> goes right after mcp serve, with no global option",
        ),
        (
            &["mcp", "serve", "--socket", "/x", "--config-dir", "/c"][..],
            "--socket does not apply to mcp serve; --config-dir <DIR> goes right after mcp serve, with no global option",
        ),
        (
            &["mcp", "serve", "--config-dir"][..],
            "--config-dir requires a value",
        ),
        (
            &["mcp", "serve", "--config-dir", ""][..],
            "--config-dir requires a non-empty directory",
        ),
        (
            &["mcp", "serve", "--config-dir", "/c", "extra"][..],
            "mcp serve takes no argument besides --config-dir <DIR>",
        ),
    ] {
        let output = run(words, "");
        assert_eq!(output.status.code(), Some(2), "{words:?}");
        let stderr = text(&output.stderr);
        assert!(
            stderr.starts_with(&format!("memprove: error: {says}\n")),
            "{words:?}: {stderr}"
        );
        assert!(!stderr.contains("unknown option"), "{words:?}: {stderr}");
        assert!(
            stderr.contains("run `memprove mcp serve --help`"),
            "{words:?}: {stderr}"
        );
        assert!(output.stdout.is_empty(), "{words:?}");
    }
    // Other mistakes are as before.
    for (words, says) in [
        (
            &["mcp", "serve", "--bogus"][..],
            "unknown option \"--bogus\"",
        ),
        (
            &["--data-dir", "/x", "mcp", "serve"][..],
            "--data-dir does not apply to this command",
        ),
    ] {
        let output = run(words, "");
        assert_eq!(output.status.code(), Some(2), "{words:?}");
        assert!(text(&output.stderr).contains(says), "{words:?}");
    }
}

#[test]
fn u8_k1_the_helps_match_the_commands() {
    let general = text(&run(&["--help"], "").stdout);
    for line in [
        "\n  hook session-start [--client cursor] [--config-dir <DIR>]\n",
        "\n  mcp serve [--config-dir <DIR>]\n",
    ] {
        assert!(general.contains(line), "{line:?} is not in:\n{general}");
    }
    let resume = text(&run(&["resume", "--help"], "").stdout);
    let pack = resume
        .lines()
        .skip_while(|line| !line.starts_with("  --pack "))
        .take_while(|line| line.starts_with("  --pack ") || line.starts_with("          "))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        pack.contains("end it before taking over")
            && pack.contains("memprove session end <SESSION_ID> --abandoned"),
        "the --pack description does not mention the takeover hint: {pack}"
    );
}
