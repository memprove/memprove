//! U24 (H1, H2), through the real `memprove` and `memproved`: the
//! session-start hooks `init` writes for Codex and Cursor inject the same
//! Pack the Claude Code hook injects.
//!
//! - H1: Codex runs `'<memprove>' hook session-start --config-dir '<dir>'`
//!   through a shell, with its `SessionStart` input (Claude Code's members
//!   and `model`, `permission_mode`, a null `transcript_path`); the output is
//!   plain text, which Codex adds to the model's context: the same opening
//!   and the same Pack as for Claude Code.
//! - H2: Cursor runs the same with `--client cursor`, with its
//!   `sessionStart` input (`session_id`, `workspace_roots`,
//!   `cursor_version`, no `cwd`, no `source`); the output is one line of
//!   JSON whose `additional_context` holds that text. Cursor also runs the
//!   Claude Code handler of `.claude/settings.local.json`: for Cursor's
//!   input it prints nothing, so the Pack is injected once.

#[path = "u6_ui_support/mod.rs"]
mod support;

use std::{
    io::Write as _,
    path::Path,
    process::{Command, Output, Stdio},
};

use memprove_cli::hook::shell_command;
use memprove_protocol::strict_json::{JsonValue, parse_strict};
use support::{Fixture, cli_binary, isolated, text};

const FENCE: &str = "\n```text\n";

/// Runs `command` in the repository with `input` on standard input and the
/// fixture's data directory; it exits 0.
fn feed(fixture: &Fixture, mut command: Command, input: &str) -> Output {
    command
        .current_dir(&fixture.repo)
        .env("HOME", &fixture.root)
        .env("MEMPROVE_DATA_DIR", &fixture.data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    output
}

/// The handler's command line as Codex and Cursor run it: `sh -c`.
fn through_shell(line: &str) -> Command {
    let mut command = isolated("/bin/sh");
    command.arg("-c").arg(line);
    command
}

/// The Pack of a response that injects one, and the opening without its
/// time sentence.
fn pack_of(stdout: &str) -> (String, String) {
    let (opening, rest) = stdout
        .split_once(FENCE)
        .unwrap_or_else(|| panic!("no Pack: {stdout}"));
    let pack = rest
        .strip_suffix("```\n")
        .unwrap_or_else(|| panic!("no closing fence: {stdout}"));
    let start = opening.find("The current UTC time is ").unwrap();
    let end = opening[start..].find(". ").unwrap() + start + 2;
    let without_time = format!("{}{}", &opening[..start], &opening[end..]);
    (without_time, pack.to_owned())
}

fn claude_input(repo: &Path) -> String {
    format!(
        r#"{{"hook_event_name":"SessionStart","session_id":"u24-claude","source":"startup","cwd":"{}"}}"#,
        repo.display()
    )
}

fn codex_input(repo: &Path) -> String {
    format!(
        r#"{{"session_id":"019a2b3c-4d5e-7f60-8a9b-0c1d2e3f4a5b","transcript_path":null,"cwd":"{}","hook_event_name":"SessionStart","model":"gpt-5.5-codex","permission_mode":"default","source":"startup"}}"#,
        repo.display()
    )
}

fn cursor_input(repo: &Path) -> String {
    format!(
        r#"{{"conversation_id":"u24-conversation","generation_id":"u24-generation","model":"auto","hook_event_name":"sessionStart","cursor_version":"3.25.6","workspace_roots":["{}"],"user_email":null,"transcript_path":null,"session_id":"0b6f2c1e-1111-4a2b-9c3d-123456789abc","is_background_agent":false,"composer_mode":"agent"}}"#,
        repo.display()
    )
}

#[test]
fn u24_codex_and_cursor_hooks_inject_the_pack_claude_code_gets() {
    let fixture = Fixture::new();
    fixture.task_with_fact("u24 hooks", "the check script passes");
    fixture.end();
    let executable = cli_binary();
    let executable = executable.to_str().unwrap();
    let config = fixture.config.to_str().unwrap();

    // Claude Code's exec form, the reference.
    let mut claude = isolated(cli_binary());
    claude
        .args(["hook", "session-start", "--config-dir"])
        .arg(&fixture.config);
    let claude = text(&feed(&fixture, claude, &claude_input(&fixture.repo)).stdout);
    let (claude_opening, claude_pack) = pack_of(&claude);
    assert!(claude_pack.contains("the check script passes"), "{claude}");

    // H1: Codex, through a shell, with its own input.
    let codex_line = shell_command(executable, config, false);
    let codex = feed(
        &fixture,
        through_shell(&codex_line),
        &codex_input(&fixture.repo),
    );
    let codex = text(&codex.stdout);
    println!("Codex:\n{codex}");
    assert!(!codex.trim_start().starts_with('{'), "{codex}");
    let (codex_opening, codex_pack) = pack_of(&codex);
    assert_eq!(codex_pack, claude_pack);
    assert_eq!(codex_opening, claude_opening);

    // H2: Cursor, through a shell, with --client cursor: one JSON line.
    let cursor_line = shell_command(executable, config, true);
    let cursor = feed(
        &fixture,
        through_shell(&cursor_line),
        &cursor_input(&fixture.repo),
    );
    let cursor = text(&cursor.stdout);
    println!("Cursor:\n{cursor}");
    assert_eq!(cursor.lines().count(), 1, "{cursor}");
    let answer = parse_strict(cursor.trim_end()).unwrap();
    let JsonValue::Object(members) = &answer else {
        panic!("{cursor}");
    };
    assert_eq!(members.len(), 1, "{cursor}");
    let context = answer
        .get("additional_context")
        .and_then(JsonValue::as_str)
        .unwrap();
    let (cursor_opening, cursor_pack) = pack_of(context);
    assert_eq!(cursor_pack, claude_pack);
    assert_eq!(cursor_opening, claude_opening);

    // Cursor running the Claude Code handler: nothing, so once in all.
    let mut twice = isolated(cli_binary());
    twice
        .args(["hook", "session-start", "--config-dir"])
        .arg(&fixture.config);
    let twice = feed(&fixture, twice, &cursor_input(&fixture.repo));
    assert!(twice.stdout.is_empty(), "{}", text(&twice.stdout));

    // A bad input under --client cursor is still Cursor's JSON, a statement.
    let bad = feed(&fixture, through_shell(&cursor_line), "{}");
    let bad = text(&bad.stdout);
    let statement = parse_strict(bad.trim_end())
        .ok()
        .and_then(|value| {
            value
                .get("additional_context")
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| panic!("{bad}"));
    assert!(
        statement.starts_with("memprove: the sessionStart input's session_id")
            && statement.contains("no Context Pack was injected"),
        "{statement}"
    );

    // Another client name is refused as any other argument is: a statement.
    let mut other = isolated(cli_binary());
    other.args(["hook", "session-start", "--client", "vim"]);
    let other = text(&feed(&fixture, other, &claude_input(&fixture.repo)).stdout);
    assert!(other.starts_with("memprove: "), "{other}");
    assert!(!other.contains(FENCE), "{other}");
    fixture.stop();
}
