//! TRAE, through the real `memprove` and `memproved`: `memprove init
//! --client trae` writes `.trae/hooks.json` (the `SessionStart` hook as one
//! shell command line), `.trae/mcp.json` and the rule
//! `.trae/rules/memprove.md`, keeps them out of Evidence, and says what the
//! user still turns on in TRAE; run again it changes nothing. The hook it
//! wrote, run as TRAE runs it (`sh -c`, from the project root) with TRAE's
//! `SessionStart` input (Claude Code's members, a UUID `session_id`, and
//! `workspace_roots`), prints the same Pack the Claude Code hook prints,
//! as plain text, which TRAE adds to the model's context. Detection takes
//! TRAE from `~/.trae-cn` or `~/.trae`.

#[path = "u6_ui_support/mod.rs"]
mod support;

use std::{
    fs,
    io::Write as _,
    path::Path,
    process::{Command, Output, Stdio},
};

use memprove_protocol::strict_json::{JsonValue, parse_strict};
use support::{Fixture, cli_binary, isolated, text};

const FENCE: &str = "\n```text\n";

/// `memprove init <words>` in the repository, with the fixture's
/// configuration directory, the operator's token, a home with no client
/// directory, and a `PATH` with no client.
fn init(fixture: &Fixture, home: &Path, words: &[&str]) -> Output {
    let output = isolated(cli_binary())
        .current_dir(&fixture.repo)
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("MEMPROVE_CONFIG_DIR", &fixture.config)
        .arg("init")
        .arg("--operator-token")
        .arg(&fixture.control)
        .args(words)
        .output()
        .unwrap();
    println!(
        "$ memprove init {}\n{}{}[exit {:?}]",
        words.join(" "),
        text(&output.stdout),
        text(&output.stderr),
        output.status.code()
    );
    output
}

/// Runs `command` in the repository with `input` on standard input and the
/// fixture's data directory; it exits 0.
fn feed(fixture: &Fixture, mut command: Command, input: &str) -> String {
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
    text(&output.stdout)
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

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
#[allow(clippy::too_many_lines)] // One scenario, step by step.
fn trae_init_writes_the_trae_files_and_its_hook_injects_the_pack() {
    let fixture = Fixture::new();
    fixture.task_with_fact("trae hooks", "the check script passes");
    fixture.end();
    fs::write(
        fixture.config.join("data-dir"),
        format!("{}\n", fixture.data.display()),
    )
    .unwrap();
    let home = fixture.root.join("home");
    fs::create_dir_all(&home).unwrap();
    let repo = &fixture.repo;

    // Detection: TRAE CN's ~/.trae-cn (a dry run writes nothing).
    let none = init(&fixture, &home, &["--dry-run"]);
    assert!(text(&none.stdout).contains("or --client trae names one"));
    fs::create_dir(home.join(".trae-cn")).unwrap();
    let detected = init(&fixture, &home, &["--dry-run"]);
    assert_eq!(detected.status.code(), Some(0));
    let detected = text(&detected.stdout);
    assert!(detected.contains("clients: trae\n"), "{detected}");
    for file in [
        ".trae/hooks.json",
        ".trae/mcp.json",
        ".trae/rules/memprove.md",
    ] {
        assert!(
            detected.contains(&format!("{} would be written", repo.join(file).display())),
            "{file}: {detected}"
        );
    }
    assert!(!repo.join(".trae").exists());

    // The files, the exclude entries, the note, and doctor's line.
    let first = init(&fixture, &home, &["--client", "trae"]);
    let first_out = text(&first.stdout);
    assert!(first_out.contains("clients: trae\n"), "{first_out}");
    assert!(
        first_out.contains("note: TRAE runs this hook only after you allow it"),
        "{first_out}"
    );
    let exclude = read(&repo.join(".git/info/exclude"));
    for entry in [
        ".trae/hooks.json",
        ".trae/mcp.json",
        ".trae/rules/memprove.md",
    ] {
        assert!(exclude.lines().any(|line| line == entry), "{exclude}");
    }
    let hooks = parse_strict(&read(&repo.join(".trae/hooks.json"))).unwrap();
    assert_eq!(
        hooks.get("version"),
        Some(&JsonValue::Number("1".to_owned()))
    );
    let groups = hooks
        .get("hooks")
        .and_then(|hooks| hooks.get("SessionStart"))
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(groups.len(), 1);
    let handler = &groups[0]
        .get("hooks")
        .and_then(JsonValue::as_array)
        .unwrap()[0];
    assert!(handler.get("args").is_none(), "{handler:?}");
    let command = handler
        .get("command")
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_owned();
    assert!(
        command.ends_with(&format!(
            "/memprove' hook session-start --config-dir '{}'",
            fixture.config.display()
        )),
        "{command}"
    );
    let mcp = parse_strict(&read(&repo.join(".trae/mcp.json"))).unwrap();
    let server = mcp
        .get("mcpServers")
        .and_then(|servers| servers.get("memprove"))
        .unwrap();
    assert_eq!(
        server
            .get("args")
            .and_then(JsonValue::as_array)
            .map(|args| {
                args.iter()
                    .filter_map(JsonValue::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            }),
        Some(vec![
            "mcp".to_owned(),
            "serve".to_owned(),
            "--config-dir".to_owned(),
            fixture.config.display().to_string()
        ])
    );
    let rule = read(&repo.join(".trae/rules/memprove.md"));
    assert!(rule.starts_with("---\nalwaysApply: true\n---\n"), "{rule}");
    assert!(rule.contains("call the MCP tool `pack`"), "{rule}");
    let client_hooks = first_out
        .lines()
        .find(|line| line.contains("client-hooks"))
        .unwrap_or_else(|| panic!("{first_out}"));
    assert!(client_hooks.contains("PASS"), "{client_hooks}");
    assert!(
        client_hooks.contains("Settings > Hooks (not checked here)"),
        "{client_hooks}"
    );
    assert!(!client_hooks.contains("/hooks (not"), "{client_hooks}");
    // Claude Code was not asked for: none of its files.
    assert!(!repo.join(".claude").exists());

    // Run again: nothing changes, and no note.
    let second = init(&fixture, &home, &["--client", "trae"]);
    let second_out = text(&second.stdout);
    for file in [
        ".trae/hooks.json",
        ".trae/mcp.json",
        ".trae/rules/memprove.md",
    ] {
        assert!(
            second_out.contains(&format!("{} already as asked", repo.join(file).display())),
            "{file}: {second_out}"
        );
    }
    assert!(!second_out.contains("note: TRAE"), "{second_out}");

    // The hook as TRAE runs it, with TRAE's input: the Claude Code Pack.
    let mut claude = isolated(cli_binary());
    claude
        .args(["hook", "session-start", "--config-dir"])
        .arg(&fixture.config);
    let claude = feed(
        &fixture,
        claude,
        &format!(
            r#"{{"hook_event_name":"SessionStart","session_id":"trae-claude","source":"startup","cwd":"{}"}}"#,
            repo.display()
        ),
    );
    let (claude_opening, claude_pack) = pack_of(&claude);
    assert!(claude_pack.contains("the check script passes"), "{claude}");
    let env_file = fixture.root.join("trae-env");
    let mut trae = isolated("/bin/sh");
    trae.arg("-c")
        .arg(&command)
        .env("TRAE_PROJECT_DIR", repo)
        .env("CLAUDE_PROJECT_DIR", repo)
        .env("TRAE_ENV_FILE", &env_file)
        .env("CLAUDE_ENV_FILE", &env_file);
    let trae = feed(
        &fixture,
        trae,
        &format!(
            r#"{{"session_id":"6f1c2a9e-1b2d-4c3e-9f00-1234567890ab","cwd":"{0}","hook_event_name":"SessionStart","workspace_roots":["{0}"],"source":"startup"}}"#,
            repo.display()
        ),
    );
    println!("TRAE:\n{trae}");
    assert!(!trae.trim_start().starts_with('{'), "{trae}");
    let (trae_opening, trae_pack) = pack_of(&trae);
    assert_eq!(trae_pack, claude_pack);
    assert_eq!(trae_opening, claude_opening);
    assert_eq!(
        read(&env_file),
        "export MEMPROVE_CLIENT_SESSION='6f1c2a9e-1b2d-4c3e-9f00-1234567890ab'\n"
    );
    fixture.stop();
}
