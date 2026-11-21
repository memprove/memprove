//! Three commands write Claude Code hooks into the same
//! `.claude/settings.local.json`: `memprove hook install` (the session-start
//! hook), `memprove policy init` (the tool policy hook) and `memprove verify
//! init --hook` (the completion check). In every order each keeps the
//! handlers of the other two, running all three again changes nothing, and
//! `hook uninstall` takes back only the session-start handler.

#[path = "u1e_support/mod.rs"]
mod support;

use std::{
    fs,
    path::{Path, PathBuf},
    process::Output,
};

use memprove_protocol::strict_json::{JsonValue, parse_strict};
use support::{cli_binary, isolated, repository, short_tempdir, text};

const SETTINGS: &str = ".claude/settings.local.json";

const CONTRACT: &str = r#"{"schema": "memprove.verify.contract.v1", "checks": [{"name": "tests", "argv": ["sh", "tests/check.sh"]}], "protected": ["tests/**"]}
"#;

const COMMANDS: [&[&str]; 3] = [
    &["hook", "install"],
    &["policy", "init", "--client", "claude-code"],
    &["verify", "init", "--hook"],
];

struct Place {
    _guard: tempfile::TempDir,
    home: PathBuf,
    config: PathBuf,
    repo: PathBuf,
}

impl Place {
    fn new() -> Self {
        let (guard, root) = short_tempdir();
        let home = root.join("h");
        let config = root.join("cfg");
        let repo = root.join("repo");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&config).unwrap();
        repository(&repo);
        fs::create_dir_all(repo.join(".memprove")).unwrap();
        fs::write(repo.join(".memprove/verify.json"), CONTRACT).unwrap();
        Self {
            _guard: guard,
            home,
            config,
            repo,
        }
    }

    fn run(&self, words: &[&str]) -> Output {
        let output = isolated(cli_binary())
            .current_dir(&self.repo)
            .env("HOME", &self.home)
            .env("MEMPROVE_CONFIG_DIR", &self.config)
            .args(words)
            .output()
            .unwrap();
        println!(
            "$ memprove {}\n{}{}[exit {:?}]",
            words.join(" "),
            text(&output.stdout),
            text(&output.stderr),
            output.status.code()
        );
        output
    }

    fn settings_text(&self) -> String {
        fs::read_to_string(self.repo.join(SETTINGS)).unwrap()
    }
}

/// What each handler of `event` runs: the program's file name, then its
/// arguments (the `args` of an exec-form handler, or the rest of a shell
/// command line; the test's paths have no spaces).
fn handlers(settings: &JsonValue, event: &str) -> Vec<String> {
    let mut found = Vec::new();
    for group in settings
        .get("hooks")
        .and_then(|hooks| hooks.get(event))
        .and_then(JsonValue::as_array)
        .unwrap_or_default()
    {
        for handler in group
            .get("hooks")
            .and_then(JsonValue::as_array)
            .unwrap_or_default()
        {
            let command = handler.get("command").and_then(JsonValue::as_str).unwrap();
            let (program, rest) = command.split_once(' ').unwrap_or((command, ""));
            // A shell-form handler quotes its program.
            let program = program.trim_matches(['\'', '"']);
            let mut words = vec![
                Path::new(program)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            ];
            words.extend(rest.split_whitespace().map(str::to_owned));
            for word in handler
                .get("args")
                .and_then(JsonValue::as_array)
                .unwrap_or_default()
            {
                words.push(word.as_str().unwrap().to_owned());
            }
            found.push(words.join(" "));
        }
    }
    found
}

fn count(handlers: &[String], start: &str) -> usize {
    handlers
        .iter()
        .filter(|handler| handler.starts_with(start))
        .count()
}

/// The hooks of all three commands, each once.
fn assert_all_three(settings: &JsonValue, order: &[usize]) {
    let starts = handlers(settings, "SessionStart");
    let stops = handlers(settings, "Stop");
    let tools = handlers(settings, "PreToolUse");
    assert_eq!(
        (
            count(&starts, "memprove hook session-start"),
            count(&starts, "memprove verify hook"),
            starts.len()
        ),
        (1, 1, 2),
        "order {order:?}: SessionStart {starts:?}"
    );
    assert_eq!(
        stops,
        ["memprove verify hook"],
        "order {order:?}: Stop {stops:?}"
    );
    assert_eq!(
        tools,
        ["memprove policy hook --client claude-code"],
        "order {order:?}: PreToolUse {tools:?}"
    );
}

#[test]
fn the_three_claude_code_hooks_keep_each_other_in_every_order() {
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let place = Place::new();
        for index in order {
            let done = place.run(COMMANDS[index]);
            assert_eq!(done.status.code(), Some(0), "order {order:?}, {index}");
        }
        let first = place.settings_text();
        assert_all_three(&parse_strict(&first).unwrap(), &order);

        // Again, in the same order: nothing changes.
        for index in order {
            let done = place.run(COMMANDS[index]);
            assert_eq!(
                done.status.code(),
                Some(0),
                "order {order:?}, {index} again"
            );
        }
        assert_eq!(
            place.settings_text(),
            first,
            "order {order:?}: not idempotent"
        );

        // `hook uninstall` takes back the session-start handler only.
        let removed = place.run(&["hook", "uninstall"]);
        assert_eq!(removed.status.code(), Some(0), "order {order:?}");
        let settings = parse_strict(&place.settings_text()).unwrap();
        assert_eq!(
            handlers(&settings, "SessionStart"),
            ["memprove verify hook"],
            "order {order:?}"
        );
        assert_eq!(
            handlers(&settings, "Stop"),
            ["memprove verify hook"],
            "order {order:?}"
        );
        assert_eq!(
            handlers(&settings, "PreToolUse"),
            ["memprove policy hook --client claude-code"],
            "order {order:?}"
        );
    }
}
