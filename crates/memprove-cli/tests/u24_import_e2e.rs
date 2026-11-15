//! U24 (I1), through the real `memprove` and `memproved`: `memprove import`
//! lists the statements of CLAUDE.md, AGENTS.md, a Cursor rule, and Claude
//! Code's auto-memory of the repository without sending anything; with
//! `--select` it records them as open items of the current Session, each
//! marked imported and not verified, keeps the next action in force, and a
//! second import records nothing twice.

#[path = "u6_ui_support/mod.rs"]
mod support;

use std::{fs, process::Output};

use memprove_protocol::strict_json::JsonValue;
use support::{Fixture, cli_binary, git, isolated, json, text};

/// `memprove import ...` as the agent, in the repository, with
/// `HOME` the fixture's root and no `CLAUDE_CONFIG_DIR`.
fn import(fixture: &Fixture, words: &[&str]) -> Output {
    isolated(cli_binary())
        .current_dir(&fixture.repo)
        .env("HOME", &fixture.root)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env("MEMPROVE_CONFIG_DIR", &fixture.config)
        .arg("--data-dir")
        .arg(&fixture.data)
        .arg("--token-file")
        .arg(&fixture.agent)
        .arg("import")
        .args(words)
        .output()
        .unwrap()
}

fn ok(output: Output) -> Output {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}{}",
        text(&output.stdout),
        text(&output.stderr)
    );
    output
}

/// The texts of the claims of `kind` in force in the Task Capsule.
fn in_force(fixture: &Fixture, kind: &str) -> Vec<String> {
    let capsule = json(&fixture.agent(&["resume"]));
    capsule
        .get("claims")
        .and_then(JsonValue::as_array)
        .unwrap()
        .iter()
        .filter(|claim| {
            claim.get("kind").and_then(JsonValue::as_str) == Some(kind)
                && claim.get("standing").and_then(JsonValue::as_str) == Some("active")
        })
        .map(|claim| {
            claim
                .get("text")
                .and_then(JsonValue::as_str)
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// The agent instructions of the scenario, committed, and an auto-memory
/// file of the repository under `HOME`; the token-shaped string one holds.
fn instructions(fixture: &Fixture) -> String {
    let repo = &fixture.repo;
    fs::write(
        repo.join("CLAUDE.md"),
        "# Rules\n\n- Run `sh tests/check.sh` before every commit.\n- Never push to main.\n",
    )
    .unwrap();
    fs::write(
        repo.join("AGENTS.md"),
        "Never push to main.\n\nThe fixture has one test script.\n\n\
         <!-- memprove:begin -->\nmemprove's own note.\n<!-- memprove:end -->\n",
    )
    .unwrap();
    let token = format!("{}x", "aB3".repeat(14));
    fs::write(repo.join("GEMINI.md"), format!("Key {token}\n")).unwrap();
    fs::create_dir_all(repo.join(".cursor/rules")).unwrap();
    fs::write(
        repo.join(".cursor/rules/style.mdc"),
        "---\nalwaysApply: true\n---\nKeep lines short.\n",
    )
    .unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "--quiet", "-m", "agent instructions"]);
    let canonical = fs::canonicalize(repo).unwrap();
    let project: String = canonical
        .to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let memory = fixture
        .root
        .join(".claude/projects")
        .join(project)
        .join("memory");
    fs::create_dir_all(&memory).unwrap();
    fs::write(
        memory.join("MEMORY.md"),
        "- The daemon listens on a Unix socket.\n",
    )
    .unwrap();

    token
}

#[test]
fn u24_import_lists_then_records_each_statement_once() {
    let fixture = Fixture::new();
    let token = instructions(&fixture);

    // The listing: no Session yet, nothing sent.
    let listed = ok(import(&fixture, &[]));
    let listing = text(&listed.stdout);
    let notes = text(&listed.stderr);
    println!("{listing}{notes}");
    assert_eq!(
        listing.lines().collect::<Vec<_>>(),
        [
            "  1  CLAUDE.md:3  Run `sh tests/check.sh` before every commit.",
            "  2  CLAUDE.md:4  Never push to main.",
            "  3  AGENTS.md:3  The fixture has one test script.",
            "  4  .cursor/rules/style.mdc:4  Keep lines short.",
            "  5  auto-memory/MEMORY.md:1  The daemon listens on a Unix socket.",
        ]
    );
    assert!(
        notes.contains(
            "GEMINI.md:1 is not imported: it holds a string in the format of a memprove token"
        ),
        "{notes}"
    );
    assert!(!notes.contains(&token) && !listing.contains(&token));
    assert!(notes.contains("nothing was recorded"), "{notes}");

    // Without a current Session, --select is refused; nothing is sent.
    let refused = import(&fixture, &["--select", "all", "--next", "n"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert!(
        text(&refused.stderr).contains("run `memprove begin` and `memprove run` first"),
        "{}",
        text(&refused.stderr)
    );

    // A Session with a run: --dry-run, then the import of three.
    fixture.task_with_fact("u24 import", "the check script passes");
    let dry = ok(import(&fixture, &["--select", "1,4-5", "--dry-run"]));
    let recorded = [
        "Run `sh tests/check.sh` before every commit. (imported from CLAUDE.md:3; not verified)",
        "Keep lines short. (imported from .cursor/rules/style.mdc:4; not verified)",
        "The daemon listens on a Unix socket. (imported from auto-memory/MEMORY.md:1; not verified)",
    ];
    assert_eq!(text(&dry.stdout).lines().collect::<Vec<_>>(), recorded);
    assert!(
        text(&dry.stderr).contains("\"carry on\""),
        "{}",
        text(&dry.stderr)
    );
    assert!(in_force(&fixture, "open_item").is_empty());

    let first = ok(import(&fixture, &["--select", "1,4-5"]));
    println!("{}", text(&first.stderr));
    assert_eq!(in_force(&fixture, "open_item"), recorded);
    assert_eq!(in_force(&fixture, "next_action"), ["carry on"]);
    assert_eq!(in_force(&fixture, "fact"), ["the check script passes"]);

    // A second import of all: the three in force are left out.
    let second = ok(import(
        &fixture,
        &["--select", "all", "--next", "review the rules"],
    ));
    let second_notes = text(&second.stderr);
    assert_eq!(
        second_notes
            .matches("is in force already as an imported open item")
            .count(),
        3,
        "{second_notes}"
    );
    let open = in_force(&fixture, "open_item");
    assert_eq!(open.len(), 5, "{open:?}");
    assert!(
        open.contains(&"Never push to main. (imported from CLAUDE.md:4; not verified)".to_owned())
    );
    assert_eq!(in_force(&fixture, "next_action"), ["review the rules"]);

    // A third: nothing left, nothing sent.
    let third = ok(import(&fixture, &["--select", "all"]));
    assert!(
        text(&third.stderr)
            .contains("nothing to import: every selected statement is in force already"),
        "{}",
        text(&third.stderr)
    );

    // The Pack carries the imported open items.
    let pack = text(&fixture.agent_ok(&["resume", "--pack"]).stdout);
    assert!(
        pack.contains("Keep lines short. (imported from .cursor/rules/style.mdc:4; not verified)"),
        "{pack}"
    );

    // A number outside the listing is a usage error.
    let outside = import(&fixture, &["--select", "9"]);
    assert_eq!(outside.status.code(), Some(2));
    fixture.stop();
}
