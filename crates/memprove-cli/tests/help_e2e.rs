//! P3-A: every `memprove` subcommand answers `--help` with its own usage,
//! arguments, and exit codes, and exits 0 without a daemon or a token. The
//! real binary is run, from an empty directory, with no `MEMPROVE_*`
//! variable.

use std::process::{Command, Output};

use memprove_cli::help::COMMANDS;

/// Every command of the general usage, in its order.
const EXPECTED: [&str; 31] = [
    "health live",
    "health ready",
    "status",
    "version",
    "token create",
    "token list",
    "token revoke",
    "project register",
    "project get",
    "workspace resolve",
    "session create",
    "session list",
    "session end",
    "task create",
    "task list",
    "task transition",
    "task complete",
    "event ingest",
    "event list",
    "event get",
    "run",
    "evidence get",
    "checkpoint create",
    "checkpoint get",
    "decide",
    "recover preview",
    "resume",
    "ledger verify",
    "begin",
    "end",
    "context show",
];

fn cli(directory: &std::path::Path, words: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_memprove"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("MEMPROVE_") {
            command.env_remove(name);
        }
    }
    command
        .current_dir(directory)
        .env("HOME", directory)
        .env("XDG_CONFIG_HOME", directory)
        .args(words)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

/// Text only the general help prints.
const GENERAL_ONLY: [&str; 3] = ["\nCommands:\n", "\nCurrent context:\n", "Scopes: control,"];

#[test]
fn the_table_covers_exactly_the_commands_of_the_general_usage() {
    let names: Vec<&str> = COMMANDS.iter().map(|entry| entry.name).collect();
    assert_eq!(names, EXPECTED);
}

#[test]
fn every_subcommand_prints_its_own_help_and_exits_zero() {
    let empty = tempfile::tempdir().unwrap();
    for name in EXPECTED {
        let words: Vec<&str> = name.split(' ').collect();
        for flag in ["--help", "-h"] {
            let mut argv = words.clone();
            argv.push(flag);
            let output = cli(empty.path(), &argv);
            let text = stdout(&output);
            assert_eq!(output.status.code(), Some(0), "{argv:?}: {text}");
            assert!(output.stderr.is_empty(), "{argv:?}");
            assert!(
                text.starts_with(&format!("memprove {name}:")),
                "{argv:?}: {text}"
            );
            assert!(text.contains("\nUsage:\n"), "{argv:?}");
            assert!(text.contains("\nExit status:\n"), "{argv:?}");
            assert!(text.contains("\n  0 "), "{argv:?}: {text}");
            for general in GENERAL_ONLY {
                assert!(!text.contains(general), "{argv:?} printed the general help");
            }
            // It describes this command only: no other command's heading.
            assert_eq!(text.matches("\nUsage:\n").count(), 1, "{argv:?}");
        }
    }
}

#[test]
fn help_wins_over_other_arguments_and_their_order() {
    let empty = tempfile::tempdir().unwrap();
    for argv in [
        &["--help", "token", "create"][..],
        &["token", "--help", "create"][..],
        &["token", "create", "--bogus", "--help"][..],
        &["--data-dir", "/nowhere", "token", "create", "--help"][..],
        &["token", "revoke", "an-id", "--help"][..],
        &["--help", "--data-dir", "/nowhere", "token", "create"][..],
    ] {
        let output = cli(empty.path(), argv);
        let text = stdout(&output);
        assert_eq!(output.status.code(), Some(0), "{argv:?}: {text}");
        assert!(text.starts_with("memprove token "), "{argv:?}: {text}");
        assert_eq!(text.matches("\nUsage:\n").count(), 1, "{argv:?}");
    }
}

#[test]
fn a_group_prints_the_help_of_each_of_its_commands() {
    let empty = tempfile::tempdir().unwrap();
    let output = cli(empty.path(), &["token", "--help"]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0));
    for name in ["token create", "token list", "token revoke"] {
        assert!(text.contains(&format!("memprove {name}:")), "{text}");
    }
    assert!(!text.contains("memprove status:"));
}

#[test]
fn the_general_help_and_unknown_commands_still_print_the_general_usage() {
    let empty = tempfile::tempdir().unwrap();
    for argv in [&["--help"][..], &["-h"][..], &["bogus", "--help"][..]] {
        let output = cli(empty.path(), argv);
        let text = stdout(&output);
        assert_eq!(output.status.code(), Some(0), "{argv:?}");
        assert!(text.starts_with("Usage: memprove "), "{argv:?}: {text}");
    }
}

#[test]
fn run_help_ends_before_the_command_it_would_run() {
    let empty = tempfile::tempdir().unwrap();
    // `--help` after `--` belongs to the command, not to `memprove`: the
    // run is refused for want of a context, and no help is printed.
    let output = cli(empty.path(), &["run", "--", "echo", "--help"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.contains("run requires --session"), "{text}");
}

#[test]
fn ledger_verify_help_documents_exit_five() {
    let empty = tempfile::tempdir().unwrap();
    let output = cli(empty.path(), &["ledger", "verify", "--help"]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0));
    let five = text
        .lines()
        .find(|line| line.trim_start().starts_with("5 "))
        .unwrap_or_else(|| panic!("no exit 5 line in:\n{text}"));
    assert!(five.contains("does not hold"), "{five}");
    assert!(text.contains("Exit 5, not 1"), "{text}");
}

#[test]
fn the_agent_guide_documents_ledger_verify_exit_five() {
    let guide = include_str!("../../../docs/guide.md");
    assert!(
        guide.contains("| `5` | `memprove ledger verify` only:"),
        "the exit-code table lacks exit 5"
    );
    assert!(guide.contains("### `memprove ledger verify`"));
    assert!(guide.contains("It exits `5`, not `1`"));
}

/// P3-L L9: a usage error (exit 2) prints the error, then one last line that
/// says which `--help` to read; it no longer appends the general usage (the
/// command list), and `--help` itself prints what it printed before.
#[test]
fn usage_errors_end_with_a_help_hint_not_the_general_usage() {
    let empty = tempfile::tempdir().unwrap();
    for (argv, hint) in [
        // A required argument missing.
        (
            &["token", "create", "--scope", "control"][..],
            "memprove token create --help",
        ),
        (&["project", "get"][..], "memprove project get --help"),
        // An unknown subcommand of a group: the group's help.
        (&["token", "bogus"][..], "memprove token --help"),
        // An unknown command: the general help.
        (&["events"][..], "memprove --help"),
        // An unknown option, before and after the command words.
        (&["status", "--bogus"][..], "memprove status --help"),
        (&["--bogus", "status"][..], "memprove status --help"),
        // An option that does not belong to the command.
        (&["status", "--label", "x"][..], "memprove status --help"),
        // A label-like --evidence (the context is missing here, which is
        // also a usage error; the real label check is in cli_e2e).
        (
            &["task", "complete", "--evidence", "r0"][..],
            "memprove task complete --help",
        ),
        (
            &["decide", "d", "--evidence", "R1"][..],
            "memprove decide --help",
        ),
        (&["run", "--", "echo", "x"][..], "memprove run --help"),
        // No command at all.
        (&[][..], "memprove --help"),
    ] {
        let output = cli(empty.path(), argv);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(2), "{argv:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{argv:?}");
        let lines: Vec<&str> = stderr.lines().collect();
        assert!(
            lines
                .first()
                .is_some_and(|line| line.starts_with("memprove: error: ")),
            "{argv:?}: {stderr}"
        );
        let last = lines.last().copied().unwrap_or_default();
        assert!(
            last.contains(&format!("`{hint}`")),
            "{argv:?}: last line {last:?}"
        );
        // Nothing of the general usage: not its header, not its command list.
        for generic in [
            "Usage: memprove",
            "Commands:",
            "health live",
            "Scopes:",
            "Exit status:",
        ] {
            assert!(
                !stderr.contains(generic),
                "{argv:?} printed {generic:?}:\n{stderr}"
            );
        }
        assert!(lines.len() <= 4, "{argv:?}: {stderr}");
    }
}

/// U7 K7 (U6 report, section 14): a command that needs a token and finds none
/// exits 1 (125 for `run`), since U6 K1; exit 2 is a usage error or a token
/// that cannot be sent. Every help text that documents the global options
/// says so, none still says "no usable token", and the guide's table of exit
/// codes agrees.
#[test]
fn u7_k7_no_token_is_exit_one_in_the_help_and_in_the_guide() {
    let empty = tempfile::tempdir().unwrap();
    // The behaviour the words describe.
    let data = empty.path().join("d");
    let output = cli(
        empty.path(),
        &["--data-dir", data.to_str().unwrap(), "status"],
    );
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("no token"), "{stderr}");
    assert!(output.stdout.is_empty());

    let mut documented = 0;
    for entry in COMMANDS {
        let mut argv: Vec<&str> = entry.name.split(' ').collect();
        argv.push("--help");
        let text = stdout(&cli(empty.path(), &argv));
        assert!(!text.contains("no usable token"), "{}", entry.name);
        if !text.contains("Global options:") {
            continue;
        }
        documented += 1;
        let exits = text.split("\nExit status:\n").nth(1).unwrap();
        let line = |code: &str| {
            exits
                .lines()
                .find(|line| line.starts_with(&format!("  {code:<4} ")))
                .map(str::to_owned)
        };
        if entry.name == "run" {
            let line = line("125").unwrap();
            assert!(line.contains("no token was found"), "run: {line}");
            continue;
        }
        let one = line("1").unwrap_or_else(|| panic!("{}: no exit 1 line", entry.name));
        assert!(
            one.contains(
                "found none (standard error names the places looked at; nothing was sent)"
            ) || one.contains("no token found (standard error names the places looked at"),
            "{}: {one}",
            entry.name
        );
        let two = line("2").unwrap_or_else(|| panic!("{}: no exit 2 line", entry.name));
        assert!(
            two.contains("a token that cannot be sent because it contains a line break"),
            "{}: {two}",
            entry.name
        );
        assert!(!two.contains("no token"), "{}: {two}", entry.name);
    }
    assert!(documented >= 20, "{documented} commands documented");

    let guide = include_str!("../../../docs/guide.md");
    let section = |heading: &str| -> String {
        let start = guide.find(&format!("\n{heading}\n")).unwrap();
        let rest = &guide[start + 1..];
        let end = rest[heading.len()..]
            .find("\n## ")
            .map_or(rest.len(), |at| at + heading.len());
        rest[..end].split_whitespace().collect::<Vec<_>>().join(" ")
    };
    let others = section("## Exit codes of the other commands");
    assert!(!others.contains("no usable token"), "{others}");
    assert!(
        others.contains("found none (standard error names the places looked at"),
        "{others}"
    );
    assert!(
        others.contains("or a token that cannot be sent because it contains a line break"),
        "{others}"
    );
    let run = section("## `memprove run` exit codes");
    assert!(run.contains("or no token was found"), "{run}");
}

/// U7 K8 (D2 section 4): the guide covers the gaps D2 found, and `run`'s
/// words match what `--test-format pytest` does since U7 P4. The texts the
/// guide quotes are the ones the code prints.
#[test]
fn u7_k8_the_guide_and_run_help_cover_the_d2_gaps() {
    let guide = include_str!("../../../docs/guide.md");
    let section = |heading: &str| -> String {
        let start = guide
            .find(&format!("\n{heading}\n"))
            .unwrap_or_else(|| panic!("the guide lacks the section {heading:?}"));
        let rest = &guide[start + 1..];
        let end = rest[heading.len()..]
            .find("\n## ")
            .map_or(rest.len(), |at| at + heading.len());
        rest[..end].split_whitespace().collect::<Vec<_>>().join(" ")
    };
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");

    // Enabling, steps 7 and 10.
    let enabling = section("## Enabling memprove in a project");
    assert!(
        enabling.contains("Whether the agent may `Edit` files or run `git add` and `git commit`")
            && enabling.contains("\"Unattended takeover\" (\"What to allow\")"),
        "step 7 does not say that Edit and git are allowed separately"
    );
    assert!(
        enabling.contains("`workspace`")
            && enabling.contains("`ledger` (`not checked: no context names a Project here`)")
            && enabling.contains("exits 0"),
        "step 10 does not say that doctor warns before the first begin"
    );

    // Several runs: pytest -q, -qq, and addopts; the words of the code.
    let runs = section("## Several runs in one state");
    for words in [
        "addopts",
        "-qq",
        "counted from the progress line",
        "`--test-cases <N>` still wins",
    ] {
        assert!(runs.contains(words), "Several runs in one state: {words}");
    }
    let empty = tempfile::tempdir().unwrap();
    let run_help = flat(&stdout(&cli(empty.path(), &["run", "--help"])));
    let general = flat(&stdout(&cli(empty.path(), &["--help"])));
    for (name, text) in [("run --help", &run_help), ("--help", &general)] {
        assert!(
            text.contains("counted from the progress line"),
            "{name} lacks the progress-line note"
        );
        assert!(
            !text.contains("a last line that is not a summary records no count"),
            "{name} still has the sentence P4 made untrue"
        );
    }
    assert!(!section("## `memprove run` exit codes").contains("under the same rule for output"));

    // A Session that was not ended: the sentence of the Pack and of `begin`.
    let ended = section("## A Session that was not ended");
    // U10 T7: the sentence with the command to copy, its placeholders as
    // the domain writes them.
    assert!(
        ended.contains(&flat(
            &memprove_domain::pack_takeover_hint("memprove", 0, "<SESSION_ID>")
                .replace("session:0", "session:<k>")
        )),
        "the guide does not quote the Pack's takeover sentence"
    );
    assert!(
        ended.contains(
            "a Session someone else left open is ended with `memprove end --abandoned --reason <why>`"
        ),
        "the guide does not quote begin's refusal"
    );

    // One context per client session: the sub-agents.
    let contexts = flat(
        guide
            .split("### One context per client session")
            .nth(1)
            .unwrap()
            .split("\n## The MCP server")
            .next()
            .unwrap(),
    );
    for words in [
        "Sub-agents, one client session each",
        "memprove context show",
        "export MEMPROVE_CLIENT_SESSION=<name>",
        "memprove begin --project <PROJECT_ID> --task <TASK_ID>",
        "`from Session k`",
        "`--supersedes`",
        "`--reaffirm`",
    ] {
        assert!(
            contexts.contains(words),
            "One context per client session: {words}"
        );
    }
}

/// `--help` keeps printing the general usage on standard output, exit 0.
#[test]
fn help_output_is_unchanged_by_the_short_usage_error() {
    let empty = tempfile::tempdir().unwrap();
    let output = cli(empty.path(), &["--help"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = stdout(&output);
    assert!(text.starts_with("Usage: memprove "), "{text}");
    assert!(text.contains("Commands:"));
}

/// P3-L L13: what the agent guide teaches is also in the `--help` of the
/// command it concerns. Each entry is the guide's phrase, the command whose
/// `--help` carries `help_phrase`, and that phrase; both sides are compared
/// with whitespace folded, so line wrapping does not matter.
#[test]
#[allow(clippy::too_many_lines)] // One table of statements.
fn l13_the_guide_and_the_help_cover_the_same_advice() {
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let guide = flat(include_str!("../../../docs/guide.md"));
    let empty = tempfile::tempdir().unwrap();
    let help_of = |words: &[&str]| {
        let mut argv = words.to_vec();
        argv.push("--help");
        let output = cli(empty.path(), &argv);
        assert_eq!(output.status.code(), Some(0), "{argv:?}");
        flat(&stdout(&output))
    };
    for (guide_phrase, words, help_phrase) in [
        // `run` standard output is large: redirect it outside the repository.
        (
            "redirect it to a file outside the repository",
            &["run"][..],
            "redirect it to a file outside the repository",
        ),
        (
            "read the result and the label on the last line of standard error",
            &["run"][..],
            "read the result and the label on the last line of standard error",
        ),
        // Fact wording: no commit, no case count.
        (
            "Word a fact by what holds, not by the commit or the number of test cases",
            &["checkpoint", "create"][..],
            "A statement's text says what holds, not which commit",
        ),
        (
            "the case count is in the Evidence",
            &["checkpoint", "create"][..],
            "not how many test cases (the count is in the Evidence)",
        ),
        // --reaffirm reuses the text; otherwise a new fact with --supersedes.
        (
            "It reuses the original text as it is",
            &["checkpoint", "create"][..],
            "--reaffirm reuses the original text unchanged",
        ),
        (
            "record a new `--fact` with `--supersedes <CLAIM>` instead",
            &["checkpoint", "create"][..],
            "record a new --fact with --supersedes <CLAIM> instead",
        ),
        // --next replaces the previous one as a whole.
        (
            "replaces the previous one as a whole",
            &["checkpoint", "create"][..],
            "replaces the previous next action as a whole",
        ),
        // Session lines and `end --abandoned`.
        (
            "may still be running",
            &["resume"][..],
            "may still be running",
        ),
        (
            "A Session someone else left is ended with `memprove session end <SESSION_ID> --abandoned --reason <why>`",
            &["end"][..],
            "Use --abandoned only for a Session someone else left",
        ),
        // Reruns: the listed argv, `env` prefix included.
        (
            "the `env NAME=value` prefix included",
            &["resume"][..],
            "the `env NAME=value` prefix included",
        ),
        (
            "A run with a different argv is a different command",
            &["resume"][..],
            "a run with a different argv is a different command",
        ),
        // Completion evidence (L11), the Project from the context (L10),
        // and a bare --open (L5).
        (
            "Without `--evidence` it cites every citable passed run of the current state",
            &["task", "complete"][..],
            "Without --evidence it cites every citable passed run of the current state",
        ),
        // A tampered Task (P3-L3, T16 S-2): no rerun advice.
        (
            "Run `memprove ledger verify` to see which record; a rerun does not help",
            &["task", "complete"][..],
            "a rerun does not help; run `memprove ledger verify` to see which record",
        ),
        (
            "Inside a Workspace with a current context no `--project` is needed",
            &["ledger", "verify"][..],
            "inside a Workspace with a context it is not needed",
        ),
        (
            "An `--open` without `--evidence` cites no Evidence",
            &["checkpoint", "create"][..],
            "an --open without --evidence cites no Evidence",
        ),
    ] {
        assert!(
            guide.contains(guide_phrase),
            "the guide lacks {guide_phrase:?}"
        );
        let help = help_of(words);
        assert!(
            help.contains(help_phrase),
            "`memprove {} --help` lacks {help_phrase:?}:\n{help}",
            words.join(" ")
        );
    }
    // The general usage carries the completion, context, and --open rules.
    let general = flat(&stdout(&cli(empty.path(), &["--help"])));
    for phrase in [
        "citing every citable passed run",
        "Without --project it verifies the Project of the current context",
        "an --open without one cites no Evidence",
    ] {
        assert!(
            general.contains(phrase),
            "the general usage lacks {phrase:?}"
        );
    }
}

/// P4-A: the guide, `--help`, and the general usage say the same about
/// what `resume --text` folds and what `--all` lists.
#[test]
fn p4a_the_guide_and_the_help_cover_the_same_new_options() {
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let guide = flat(include_str!("../../../docs/guide.md"));
    let empty = tempfile::tempdir().unwrap();
    let help_of = |words: &[&str]| {
        let mut argv = words.to_vec();
        argv.push("--help");
        let output = cli(empty.path(), &argv);
        assert_eq!(output.status.code(), Some(0), "{argv:?}");
        flat(&stdout(&output))
    };
    let general = flat(&stdout(&cli(empty.path(), &["--help"])));
    for (guide_phrase, words, help_phrase, general_phrase) in [
        (
            "That line counts each kind and names their numbers",
            &["resume"][..],
            "one line after the other statements counts each kind and names their numbers",
            "one line after the other statements counts each kind and names their numbers",
        ),
        (
            "`resume --text --all` lists each of those statements on its own line",
            &["resume"][..],
            "--text --all lists every one of them, as before; --all without --text is a usage error",
            "--text --all lists them too, one line each",
        ),
        (
            "With `--evidence` after it, every such fact cites that Evidence, as one `--reaffirm <N> --evidence ...` per fact would",
            &["checkpoint", "create"][..],
            "With --evidence after it, every such fact cites that Evidence, as one --reaffirm <N> with the same --evidence per fact would",
            "--reaffirm-all reaffirms every active fact that is not verified and that the command names nowhere else",
        ),
        (
            "after a commit or an edit with no run since, every fact is skipped",
            &["checkpoint", "create"][..],
            "after a commit or an edit with no run since, every fact is skipped",
            "only on the latest run in the current repository state of each command its Evidence ran",
        ),
    ] {
        assert!(
            guide.contains(guide_phrase),
            "the guide lacks {guide_phrase:?}"
        );
        let help = help_of(words);
        assert!(
            help.contains(help_phrase),
            "`memprove {} --help` lacks {help_phrase:?}:\n{help}",
            words.join(" ")
        );
        assert!(
            general.contains(general_phrase),
            "the general usage lacks {general_phrase:?}"
        );
    }
}

/// P4-B (T18): the guide, `checkpoint create --help`, and (where it speaks
/// of it) the general usage say the same about the corrected
/// `--reaffirm-all`.
#[test]
fn p4b_the_guide_and_the_help_cover_the_reaffirm_all_corrections() {
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let guide = flat(include_str!("../../../docs/guide.md"));
    let empty = tempfile::tempdir().unwrap();
    let help = flat(&stdout(&cli(
        empty.path(),
        &["checkpoint", "create", "--help"],
    )));
    let general = flat(&stdout(&cli(empty.path(), &["--help"])));
    for (guide_phrase, help_phrase, general_phrase) in [
        (
            "A run answers only for Evidence of its own kind",
            "A run answers only for Evidence of its own kind",
            Some("of the same kind (a test run for a test run)"),
        ),
        (
            "read from the Task Capsule after the write",
            "its actual verdict read back after the write",
            Some("standard error then gives each reaffirmation's actual verdict"),
        ),
        (
            "is named in a warning on standard error before the request is sent",
            "is named in a warning before sending",
            None,
        ),
        (
            "unless `--next` differs from the next action in force",
            "unless --next differs from the next action in force",
            None,
        ),
        (
            "names the facts the request would have reaffirmed and skipped",
            "names the facts it would have reaffirmed and skipped",
            None,
        ),
        (
            "the reason says they are of another Workspace",
            "of this context's Workspace",
            None,
        ),
    ] {
        assert!(
            guide.contains(guide_phrase),
            "the guide lacks {guide_phrase:?}"
        );
        assert!(
            help.contains(help_phrase),
            "`memprove checkpoint create --help` lacks {help_phrase:?}:\n{help}"
        );
        if let Some(general_phrase) = general_phrase {
            assert!(
                general.contains(general_phrase),
                "the general usage lacks {general_phrase:?}"
            );
        }
    }
}

/// P4-C: the guide, `resume --help`, and the general usage say the same
/// about `resume --pack`, its budget, and `--text --claims`; P4-C2: its
/// five levels, `--pack --claims`, and the tampered note.
#[test]
fn p4c_the_guide_and_the_help_cover_the_pack() {
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let guide = flat(include_str!("../../../docs/guide.md"));
    let empty = tempfile::tempdir().unwrap();
    let help = flat(&stdout(&cli(empty.path(), &["resume", "--help"])));
    let general = flat(&stdout(&cli(empty.path(), &["--help"])));
    for (guide_phrase, help_phrase, general_phrase) in [
        (
            "The default is 9000; `--budget` takes a whole number from 1000 through 1000000",
            "default 9000, from 1000 through 1000000",
            Some("(default 9000, from 1000 through 1000000)"),
        ),
        (
            "level 1 writes only the number of changed files on each base line",
            "level 1 writes only the number of changed files on each Base line",
            None,
        ),
        (
            "level 2 shortens each body longer than 120 characters to its first 120",
            "level 2 shortens bodies to their first 120 characters",
            None,
        ),
        (
            "level 5 stops listing claims one by one, facts first, then Decisions, then open items",
            "level 5 stops listing claims one by one (facts first, then Decisions, then open items)",
            None,
        ),
        (
            "When even level 5 does not fit, nothing is printed and the command exits 1",
            "When even level 5 does not fit, it prints nothing and exits 1",
            None,
        ),
        (
            "The last line is `Digest: sha256:<pack_digest>`",
            "The last line is Digest: sha256:<pack_digest>",
            Some("with a last line holding its SHA-256 (pack_digest)"),
        ),
        (
            "`--text --claims <NUMBERS>` prints only the `resume --text --all` lines of the claims named, in full, superseded and withdrawn ones too",
            "--text --claims 3,5-7 prints only the lines of claims #3, #5, #6, and #7",
            Some("--text --claims 3,5-7 prints only the lines of the claims named"),
        ),
        (
            "`--pack --claims <NUMBERS>` prints the full Pack lines of the claims named, superseded and withdrawn ones too",
            "--pack --claims 3,5-7 prints the full Pack lines of claims #3, #5, #6, and #7",
            Some("--pack --claims 3,5-7 prints the full Pack lines of the claims named"),
        ),
        (
            "In a `tampered` Pack the first `Integrity:` line adds `claim numbers may differ from before`",
            "In a tampered Pack the first Integrity line adds that the numbers may differ from before",
            None,
        ),
        (
            "Put the conclusion in the first sentence of a statement's text: the Pack may keep only its first 120 characters.",
            "level 2 shortens bodies to their first 120 characters",
            None,
        ),
    ] {
        assert!(
            guide.contains(guide_phrase),
            "the guide lacks {guide_phrase:?}"
        );
        assert!(
            help.contains(help_phrase),
            "`memprove resume --help` lacks {help_phrase:?}:\n{help}"
        );
        if let Some(general_phrase) = general_phrase {
            assert!(
                general.contains(general_phrase),
                "the general usage lacks {general_phrase:?}"
            );
        }
    }
}

/// U10 N3 (U9 VN9; ADR 0014 "Amendment (U10, S-K)"): `run --help` says what
/// `--test-format` and `--test-cases` do beyond counting: the run records the
/// format (`cargo`, `pytest`, or `cases` for a `--test-cases` count) in the
/// ledger as its `test_format`; the Pack's `Last passed:` line and the hint of
/// a command run that repeats the last passed test run read it to name the
/// arguments that record the run again, and a run recorded without one is
/// read from its argv. The guide says it too. Line breaks are folded.
#[test]
fn u10_n3_run_help_says_the_test_format_is_recorded_and_where_it_is_used() {
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let empty = tempfile::tempdir().unwrap();
    let help = flat(&stdout(&cli(empty.path(), &["run", "--help"])));
    let said = [
        "A test run records the format it was made with in the ledger as its test_format: \
         cargo or pytest from --test-format, and cases for a --test-cases count without one",
        "The Pack's Last passed line reads it to give the arguments that record the same run \
         again, and so does the hint above that a command run which repeats it gets",
        "a run recorded without a format is read from its argv",
    ];
    for sentence in said {
        let sentence = flat(sentence);
        assert!(
            help.contains(&sentence),
            "`run --help` lacks {sentence:?}: {help}"
        );
    }
    let guide = flat(include_str!("../../../docs/guide.md"));
    assert!(
        guide.contains(&flat(said[0])),
        "the guide does not say what `run --help` says of test_format"
    );
}

/// U9 SF2-A (S-F round 1 review, SF-1; ADR 0020, "What it does not do"):
/// `task transition --help` says when `--to completed` sends the context's
/// Session and when it sends none (no Session in the context after `end`,
/// or another Task named), and that a completion sent without one is not
/// judged by role. The guide's row of `task complete` in "What the daemon
/// refuses a `sub_agent`" and ADR 0020 say it in the same words, and the row
/// no longer says the refusal is "always". Line breaks are folded.
#[test]
fn u9_sf2_a_task_transition_help_says_when_it_sends_the_session() {
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let empty = tempfile::tempdir().unwrap();
    let output = cli(empty.path(), &["task", "transition", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let help = flat(&stdout(&output));
    let shared = [
        "with no Session in the context (after `end`) or another Task named, it sends none",
        "the daemon does not judge that completion by role",
    ];
    for sentence in [
        "it sends the context's Session only with --to completed of the context's Task while \
         the context has a Session",
        shared[0],
        shared[1],
    ] {
        assert!(
            help.contains(sentence),
            "`task transition --help` lacks {sentence:?}: {help}"
        );
    }
    assert!(
        !help.contains("For the context's Task it sends the context's Session, as"),
        "`task transition --help` still says the old sentence: {help}"
    );
    let guide = include_str!("../../../docs/guide.md");
    let row = guide
        .lines()
        .find(|line| line.starts_with("| `task complete`"))
        .expect("the guide has the row of task complete");
    assert!(
        !row.contains("always"),
        "the guide's row of task complete still says always: {row}"
    );
    for sentence in shared {
        assert!(
            row.contains(sentence),
            "the guide's row lacks {sentence:?}: {row}"
        );
    }
}

/// Line breaks and runs of spaces folded to one space.
fn folded(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The text from `from` up to, not including, the next `to`, folded.
fn folded_between(text: &str, from: &str, to: &str) -> String {
    let start = text
        .find(from)
        .unwrap_or_else(|| panic!("no section starting {from:?}"));
    let rest = &text[start..];
    let end = rest[from.len()..]
        .find(to)
        .unwrap_or_else(|| panic!("no end {to:?} after {from:?}"));
    folded(&rest[..from.len() + end])
}

/// U10 N6: none of the `gone` sentences is in `text`, and each of the
/// `stands` sentences is.
fn guard_wording(name: &str, text: &str, gone: &[&str], stands: &[&str]) {
    for sentence in gone {
        let sentence = folded(sentence);
        assert!(
            !text.contains(&sentence),
            "{name} says again what S-F replaced: {sentence:?}"
        );
    }
    for sentence in stands {
        let sentence = folded(sentence);
        assert!(
            text.contains(&sentence),
            "{name} lacks {sentence:?}: {text}"
        );
    }
}

/// U10 N6 (U9 VN17): the same for the end of the guide's paragraph "What
/// the daemon refuses a `sub_agent`".
#[test]
fn u10_n6_the_completion_wording_is_guarded_in_the_guide_and_the_contract() {
    let guide_text = include_str!("../../../docs/guide.md");
    let paragraph = folded_between(
        guide_text,
        "**What the daemon refuses a sub_agent.**",
        "**Ending a sub-agent's Session.**",
    );
    guard_wording(
        "the guide's paragraph \"What the daemon refuses a sub_agent\"",
        &paragraph,
        &[
            "A completion sent without a Session (an older client, or a direct call of the API \
             without `session_id`) is not checked by role.",
            "| `task complete` (and `task transition --to completed` of the context's Task) | \
             always, whatever runs it cites",
        ],
        &[
            "A completion sent without a Session (an older client, `task transition --to \
             completed` after `end` or of another Task, or a direct call of the API without \
             `session_id`) is not checked by role: the CLI sends only the Session its context \
             holds.",
            "the request names a `sub_agent` Session, whatever runs it cites",
        ],
    );
}

/// U10 N8 (D3 F25; U9 ledger decision #48 (1)): ADR 0020 ("Not limited")
/// and the guide ("What the daemon refuses a `sub_agent`") say that a
/// `sub_agent`'s `--next` replaces the next action in force whoever wrote
/// it, because that replacement is a rule (ADR 0013 D1), not an edge the
/// writer records, so R1 (iii) does not check it, and that the fixed text of
/// the `403` speaks of an explicit `--supersedes` of a next action. The
/// `detail` itself is unchanged.
#[test]
fn u10_n8_the_docs_say_next_replaces_another_agents_next_action() {
    let guide = folded(include_str!("../../../docs/guide.md"));
    let said = [
        "A `sub_agent`'s `--next` therefore replaces the next action in force even when another \
         agent wrote it",
        "that replacement is a rule, not an edge the writer records, so the role check does not see it",
        "the fixed text of the `403` speaks of an explicit `--supersedes` of a next action",
    ];
    for sentence in said {
        let sentence = folded(sentence);
        assert!(guide.contains(&sentence), "the guide lacks {sentence:?}");
    }
}

/// P4-G (ADR 0014 E7.3, E7.9): `mcp serve` and `mcp print-config` answer
/// `--help` and `-h` with their own usage and exit 0 without a daemon; `mcp
/// --help` prints both, in the general usage's order; the general usage has
/// the MCP group next to the hook group.
#[test]
fn p4g_the_mcp_commands_have_their_own_help() {
    let empty = tempfile::tempdir().unwrap();
    for name in ["mcp serve", "mcp print-config"] {
        for flag in ["--help", "-h"] {
            let mut argv: Vec<&str> = name.split(' ').collect();
            argv.push(flag);
            let output = cli(empty.path(), &argv);
            let text = stdout(&output);
            assert_eq!(output.status.code(), Some(0), "{argv:?}: {text}");
            assert!(output.stderr.is_empty(), "{argv:?}");
            assert!(
                text.starts_with(&format!("memprove {name}:")),
                "{argv:?}: {text}"
            );
            assert_eq!(text.matches("\nUsage:\n").count(), 1, "{argv:?}");
            assert!(text.contains("\nExit status:\n"), "{argv:?}");
            assert!(text.contains("\n  0 "), "{argv:?}: {text}");
            assert!(!text.contains("Global options:"), "{argv:?}: {text}");
            for general in GENERAL_ONLY {
                assert!(!text.contains(general), "{argv:?} printed the general help");
            }
        }
    }
    let group = stdout(&cli(empty.path(), &["mcp", "--help"]));
    let headings: Vec<&str> = group
        .lines()
        .filter(|line| line.starts_with("memprove mcp "))
        .collect();
    assert_eq!(headings.len(), 2, "{group}");
    assert!(headings[0].starts_with("memprove mcp serve:"), "{group}");
    assert!(
        headings[1].starts_with("memprove mcp print-config:"),
        "{group}"
    );
    let general = stdout(&cli(empty.path(), &["--help"]));
    let hook = general
        .find("\nSession-start hook (Claude Code, Codex, Cursor):\n")
        .unwrap();
    let mcp = general.find("\nMCP server (Claude Code):\n").unwrap();
    let scopes = general.find("\nScopes: ").unwrap();
    assert!(hook < mcp && mcp < scopes, "{general}");
    let group = &general[mcp..scopes];
    let serve = group.find("\n  mcp serve ").unwrap();
    let print = group.find("\n  mcp print-config\n").unwrap();
    assert!(serve < print, "{group}");
}

/// P4-G: each phrase of the guide's MCP section, the command whose `--help`
/// states it, that phrase, and the general usage's phrase when it states it
/// too.
const MCP_GUIDE_AND_HELP: [(&str, &[&str], &str, Option<&str>); 12] = [
    (
        "No tool runs a command; tests are recorded with `memprove run` in a shell",
        &["mcp", "serve"],
        "No tool runs a command; tests are recorded with `memprove run` in a shell",
        Some("no tool runs a command"),
    ),
    (
        "Both protocol eras are served, decided per request",
        &["mcp", "serve"],
        "Both protocol eras are served, decided per request",
        None,
    ),
    (
        "The `pack` tool's default budget is 6000 UTF-16 code units",
        &["mcp", "serve"],
        "The pack tool's default budget is 6000 UTF-16 code units",
        None,
    ),
    (
        "`pack`, `claims`, `context`, `tasks`, and `ledger_verify` read; `begin`, `checkpoint`, `decide`, `end`, and `complete` write",
        &["mcp", "serve"],
        "pack, claims, context, tasks, ledger_verify (read, mcp-read) and begin, checkpoint, decide, end, complete (write, mcp-write)",
        Some("read tools (mcp-read) apart from write tools (mcp-write)"),
    ),
    (
        "Every tool call reads the token and the data directory anew",
        &["mcp", "serve"],
        "Every tool call reads the token",
        None,
    ),
    (
        "the token from `MEMPROVE_TOKEN`, else the file named by `MEMPROVE_TOKEN_FILE`, else `<configuration directory>/token`",
        &["mcp", "serve"],
        "($MEMPROVE_TOKEN, else the file named by $MEMPROVE_TOKEN_FILE, else <configuration directory>/token)",
        None,
    ),
    (
        "the data directory from `MEMPROVE_DATA_DIR`, else the one line of `<configuration directory>/data-dir`",
        &["mcp", "serve"],
        "the data directory ($MEMPROVE_DATA_DIR, else the one line of <configuration directory>/data-dir)",
        None,
    ),
    (
        "The Workspace is the one of `CLAUDE_PROJECT_DIR`, else of the server's working directory",
        &["mcp", "serve"],
        "the Workspace is $CLAUDE_PROJECT_DIR's, else the working directory's",
        None,
    ),
    (
        "The write tools also send reads, which need `mcp-read`",
        &["mcp", "serve"],
        "the write tools their writes (mcp-write) and the reads listSessions, listTasks, getTaskCapsule (mcp-read)",
        None,
    ),
    (
        "`memprove mcp print-config` prints it and writes nothing",
        &["mcp", "print-config"],
        "It writes nothing and adds the entry nowhere",
        // U5 P3: the whole settings fragment (before: "prints the .mcp.json
        // fragment that starts `memprove mcp serve`; writes nothing"). U5
        // Z-F round 1 (S1): two parts (before: "prints the
        // .claude/settings.local.json fragment that enables memprove").
        Some(
            "prints the .claude/settings.local.json part (hook, env, the suggested permissions) \
             and the .mcp.json part (the server) that enable memprove",
        ),
    ),
    (
        "`<Workspace root>/.mcp.json` (project scope) or in `~/.claude.json` (local or user scope)",
        &["mcp", "print-config"],
        "<Workspace root>/.mcp.json (project scope) or ~/.claude.json (local or user scope)",
        None,
    ),
    (
        "A token never goes into `.mcp.json`",
        &["mcp", "print-config"],
        // U5 P3: the entry has env now (before: "No env, no timeout, and
        // never a token").
        "no data directory, and never a token",
        None,
    ),
];

/// P4-H2: each phrase of the guide, the command whose `--help` states it
/// too (no words: the general usage), and that phrase: the Pack's Session
/// lines (P4-H1), the hook and a finished Task (P4-H1), a client session
/// without a context (T20 N-7), `409 capsule_tampered` (P4-H1), exit 5, and
/// the guide's "Enabling memprove in a project" with the hook and the MCP
/// server.
const P4H2_GUIDE_AND_HELP: [(&str, &[&str], &str); 22] = [
    // The Pack's Session lines (P4-H1).
    (
        "Then a `Session ` line for every Session that has not ended",
        &["resume"],
        "The Session lines list every Session that has not ended, the latest Session that ended",
    ),
    (
        "the latest three that ended abandoned (`ended abandoned`)",
        &["resume"],
        "and the latest three that ended abandoned (ended abandoned)",
    ),
    (
        "Every other Session is only counted on the summary line",
        &["resume"],
        "the other Sessions are only counted on the Sessions line",
    ),
    (
        "the last part counting the Sessions that declared the Pack they continue from",
        &["resume"],
        "also counts the Sessions that declared the Pack they resumed from",
    ),
    (
        "`continues from the Pack at ledger sequence N (self-reported, digest sha256:<first 12",
        &["resume"],
        "continues from the Pack at ledger sequence N (self-reported,",
    ),
    // The hook and a finished Task (P4-H1).
    (
        "A `completed` or `cancelled` Task gets no Pack",
        &["hook", "session-start"],
        "A completed or cancelled Task gets no Pack",
    ),
    (
        "When this client session's context names one, the hook prints only",
        &["hook", "session-start"],
        "when this client session's context names it, one statement names the Task and its state",
    ),
    (
        "When this directory's context names one, the hook goes on to the only Task in progress in this Workspace",
        &["hook", "session-start"],
        "when this directory's context names it, the only Task in progress in this Workspace is chosen instead",
    ),
    // A client session with neither a context nor a last Pack (T20 N-7).
    (
        "does not fall back to this directory's context, its Project or its Task",
        &["begin"],
        "does not fall back to this directory's context, its Project or its Task",
    ),
    // 409 capsule_tampered on a read (P4-H1).
    (
        "a stored record the read needs is missing, does not decode, or does not recompute, or the Project's state database is not bound to it",
        &["ledger", "verify"],
        "a stored record that is missing, does not decode, or does not recompute, or the Project's state database is not bound to it",
    ),
    (
        "Do not retry it: run `memprove ledger verify`",
        &["ledger", "verify"],
        "a retry does not help; run `memprove ledger verify` to see which record",
    ),
    (
        "Only `503 service_not_ready` is worth a retry",
        &["ledger", "verify"],
        "Only 503 service_not_ready is worth a retry",
    ),
    // Exit 5.
    (
        "(the command exits 0; 5 means a record does not hold)",
        &["ledger", "verify"],
        "Exit 5, not 1, means the check ran and a record does not hold",
    ),
    // Enabling memprove in a project.
    (
        "`memproved bootstrap` is offline",
        &[],
        "Obtain the first control token with `memproved bootstrap`",
    ),
    // U5 Z-F round 1 (S2): the CLI falls back to the two files (before: the
    // guide "take the data directory from `MEMPROVE_DATA_DIR` and the
    // token from `MEMPROVE_TOKEN` or the file `MEMPROVE_TOKEN_FILE`
    // names; they do not read `<config>/data-dir` or `<config>/token`", the
    // help "else $MEMPROVE_TOKEN, else the file named by
    // $MEMPROVE_TOKEN_FILE; never a command-line token").
    (
        "else the one line of `<config>/data-dir`, and the token from `--token-file`, else `MEMPROVE_TOKEN`, else the file `MEMPROVE_TOKEN_FILE` names, else `<config>/token`",
        &["begin"],
        "else the file named by $MEMPROVE_TOKEN_FILE, else <configuration directory>/token; never a command-line token",
    ),
    (
        "The SessionStart hook and the MCP server read the same variables first and fall back to those two files",
        &["hook", "session-start"],
        "else <configuration directory>/token (mode 0600); the data directory from $MEMPROVE_DATA_DIR, else the one line of <configuration directory>/data-dir",
    ),
    (
        "The SessionStart hook and the MCP server read the same variables first and fall back to those two files",
        &["mcp", "serve"],
        "the data directory ($MEMPROVE_DATA_DIR, else the one line of <configuration directory>/data-dir)",
    ),
    (
        "The entry runs this `memprove` by its absolute path with the arguments `hook session-start` (exec form, no shell, timeout 10 seconds, every source)",
        &["hook", "print-config"],
        "exec form, this executable's absolute path with the arguments hook session-start, timeout 10 seconds, no matcher (every source)",
    ),
    (
        "Running `install` again changes nothing",
        &["hook", "install"],
        "Run again, it changes nothing",
    ),
    (
        "Run the `claude mcp add` line that `mcp print-config` gives on standard error",
        &["mcp", "print-config"],
        "gives the same entry as a claude mcp add command line",
    ),
    (
        "the MCP server works in the Workspace of `CLAUDE_PROJECT_DIR`, which Claude Code sets to the project root, else of its working directory",
        &["mcp", "serve"],
        "the Workspace is $CLAUDE_PROJECT_DIR's, else the working directory's",
    ),
    (
        "`begin` refuses a configuration directory inside the Workspace",
        &[],
        "one 0600 file per Workspace root, never inside the Workspace",
    ),
];

/// P4-H2: what the guide says that a `--help` (or the general usage) also
/// states, they state alike (whitespace folded); the guide has the section
/// that enables memprove in a project.
#[test]
fn p4h2_the_guide_and_the_help_cover_sessions_setup_and_refusals() {
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let guide = flat(include_str!("../../../docs/guide.md"));
    assert!(guide.contains("## Enabling memprove in a project"));
    let empty = tempfile::tempdir().unwrap();
    for (guide_phrase, words, help_phrase) in P4H2_GUIDE_AND_HELP {
        assert!(
            guide.contains(guide_phrase),
            "the guide lacks {guide_phrase:?}"
        );
        let mut argv = words.to_vec();
        argv.push("--help");
        let output = cli(empty.path(), &argv);
        assert_eq!(output.status.code(), Some(0), "{argv:?}");
        let help = flat(&stdout(&output));
        assert!(
            help.contains(help_phrase),
            "`memprove {}` lacks {help_phrase:?}:\n{help}",
            argv.join(" ")
        );
    }
}

/// P4-G: what the guide's MCP section says that `mcp serve --help`, `mcp
/// print-config --help`, or the general usage also states, they state
/// alike (whitespace folded).
#[test]
fn p4g_the_guide_and_the_help_cover_the_mcp_server() {
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let guide = flat(include_str!("../../../docs/guide.md"));
    assert!(guide.contains("## The MCP server (`memprove mcp`)"));
    let empty = tempfile::tempdir().unwrap();
    let help_of = |words: &[&str]| {
        let mut argv = words.to_vec();
        argv.push("--help");
        let output = cli(empty.path(), &argv);
        assert_eq!(output.status.code(), Some(0), "{argv:?}");
        flat(&stdout(&output))
    };
    let general = flat(&stdout(&cli(empty.path(), &["--help"])));
    for (guide_phrase, words, help_phrase, general_phrase) in MCP_GUIDE_AND_HELP {
        assert!(
            guide.contains(guide_phrase),
            "the guide lacks {guide_phrase:?}"
        );
        let help = help_of(words);
        assert!(
            help.contains(help_phrase),
            "`memprove {} --help` lacks {help_phrase:?}:\n{help}",
            words.join(" ")
        );
        if let Some(general_phrase) = general_phrase {
            assert!(
                general.contains(general_phrase),
                "the general usage lacks {general_phrase:?}"
            );
        }
    }
}

/// U5 Z-Z: since Z-F round 1 (S1) `doctor`'s `mcp-entry` line goes by
/// `mcpServers.memprove` of `<Workspace root>/.mcp.json` only; its help
/// says so and no longer names a settings file as a place the entry is
/// read from.
#[test]
fn u5_zz_doctor_help_says_mcp_entry_reads_mcp_json_only() {
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let empty = tempfile::tempdir().unwrap();
    let output = cli(empty.path(), &["doctor", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let help = flat(&stdout(&output));
    assert!(
        help.contains("mcp-entry (mcpServers.memprove of <Workspace root>/.mcp.json,"),
        "`memprove doctor --help` does not say mcp-entry reads .mcp.json:\n{help}"
    );
    assert!(
        help.contains(
            "one in .claude/settings.local.json or .claude/settings.json counts for nothing \
             (Claude Code does not read it), and the line says so"
        ),
        "{help}"
    );
    for stale in [
        "mcp-entry (mcpServers.memprove in .claude/settings.local.json",
        "settings.json, or .mcp.json",
    ] {
        assert!(!help.contains(stale), "still says {stale:?}:\n{help}");
    }
}

/// The `--option` words of a block of usage text, in a set.
fn option_words(text: &str) -> std::collections::BTreeSet<String> {
    text.split(|c: char| !(c == '-' || c.is_ascii_alphanumeric()))
        .filter(|word| word.starts_with("--") && word.len() > 2)
        .map(str::to_owned)
        .collect()
}

/// U12 N1 (U11-VN4): `session end` in the general usage lists the options
/// its own `--help` Usage lists. It once lacked `--workspace` (U11 added it
/// to `session end --help` only). The general entry is the lines from the
/// command's name down to the line that names the call.
#[test]
fn u12_n1_the_general_usage_of_session_end_lists_the_options_of_its_help() {
    let empty = tempfile::tempdir().unwrap();
    let general = stdout(&cli(empty.path(), &["--help"]));
    let lines: Vec<&str> = general.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.starts_with("  session end "))
        .unwrap_or_else(|| panic!("the general usage has no session end entry: {general}"));
    // The entry runs down to its call line (`                 endSession ...`).
    let offset = lines[start..]
        .iter()
        .position(|line| line.starts_with("                 ") && line.contains("  ("))
        .expect("a call line after session end");
    let entry = lines[start..=start + offset].join("\n");

    let help = stdout(&cli(empty.path(), &["session", "end", "--help"]));
    let usage = help
        .split("\nUsage:\n")
        .nth(1)
        .and_then(|rest| rest.split("\n\nCalls:").next())
        .unwrap_or_else(|| panic!("session end --help has no Usage block: {help}"));
    assert_eq!(
        option_words(&entry),
        option_words(usage),
        "the general usage and `session end --help` list different options\ngeneral: {entry}\nhelp: {usage}"
    );
}
