//! `memprove policy <command>`: parsing and dispatch, shared by the
//! `memprove` CLI and a future standalone binary.

use std::{
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{
    engine::{self, Call, POLICY_FILE, Site},
    hook::{self, Client, HookEnv},
    log,
    rules::{self, Decision, Tool},
    scan,
    starter::STARTER,
};

/// Exit code: done; for `check`, no rule refuses the call or asks; for
/// `test`, every expectation holds; for `scan`, no secret is found.
pub const EXIT_OK: u8 = 0;
/// Exit code: for `check`, the call is refused or needs a person; for
/// `test`, an expectation does not hold; for `scan`, a secret is found.
pub const EXIT_FAILED: u8 = 1;
/// Exit code: a usage error.
pub const EXIT_USAGE: u8 = 2;
/// Exit code: the policy file is missing or cannot be read, a file cannot
/// be written, or a path given to `scan` does not exist.
pub const EXIT_ERROR: u8 = 3;

/// `memprove policy --help`.
pub const USAGE: &str =
    "memprove policy: one set of tool rules for every coding agent in this repository

Usage:
  memprove policy init  [--client claude-code|codex|cursor]... [--dry-run]
  memprove policy check '<Tool>(<subject>)' [--client claude-code|codex|cursor]
  memprove policy test
  memprove policy log   [--last <N>]
  memprove policy scan  [--json] [<PATH>...]
  memprove policy hook  --client claude-code|codex|cursor

The rules live in .memprove/policy.rules at the repository root, committed:

  deny  Bash(git push *--force*)  -- push a new branch instead
  ask   Bash(git push *)
  deny  Read(.env*)
  deny  Edit(db/migrations/**)
  deny  Mcp(github.merge_pull_request)
  expect deny Bash(cd app && git push -f)

Before each tool call, Claude Code, Codex and Cursor run `memprove policy hook`,
which decides the call by the first rule that matches, and refuses it or has a
person approve it. Nothing is sent anywhere; refusals and approvals asked for
are logged in <git common dir>/memprove-policy/log.jsonl.

  init   writes a starter .memprove/policy.rules when there is none, and the
         hook of each client (detected, or named with --client)
  check  decides one call and shows which line decides it, as in
         check 'Bash(cd app && git push -f)', check 'Read(.env)',
         check 'Edit(db/migrations/001.sql)', check 'Mcp(github.merge_pull_request)'
  test   checks every `expect` line of the policy file (for CI)
  log    shows the last refusals and approvals asked for (20 unless --last)
  scan   looks for secrets in the files agents write and read here: their
         settings (.claude/, .mcp.json, .codex/, .cursor/, .trae/, …) and
         instruction files (CLAUDE.md, AGENTS.md, …), or the paths given.
         It finds passwords written into command lines (PGPASSWORD=… psql,
         sshpass -p …, curl -u me:…, --token …), keys kept in `env` and
         `headers`, and credentials of a known format; it names the file,
         the line and the kind, never the value, and says whether Git
         tracks the file. It needs no policy file and sends nothing
  hook   the hook a client runs: reads its JSON on standard input

Exit status:
  0  done; for check, no rule refuses the call or asks; for test, every expectation holds;
     for scan, no secret is found
  1  for check, the call is refused or needs a person; for test, one does not hold;
     for scan, a secret is found
  2  usage error
  3  the policy file is missing or cannot be read, a file cannot be written, or a path
     given to scan does not exist
";

/// What `memprove policy init` asks of the CLI: writing the hook of each
/// client into the repository's client settings, which the CLI owns.
pub trait Installer {
    /// Writes (or with `dry_run` names) the hooks of `clients` in the
    /// repository at `root`; an empty `clients` means the clients found on
    /// this machine. Returns the lines to print.
    ///
    /// # Errors
    ///
    /// When a client's settings file cannot be read or written.
    fn install(
        &self,
        root: &Path,
        clients: &[Client],
        dry_run: bool,
    ) -> Result<Vec<String>, String>;
}

fn usage_error(message: &str) -> u8 {
    eprintln!("memprove: error: {message}\nmemprove: see `memprove policy --help`");
    EXIT_USAGE
}

fn current_dir() -> Result<PathBuf, u8> {
    std::env::current_dir().map_err(|error| {
        eprintln!("memprove: error: the current directory cannot be read: {error}");
        EXIT_ERROR
    })
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// Runs `memprove policy <words>` and returns its exit code.
#[must_use]
pub fn main(words: &[String], installer: Option<&dyn Installer>) -> u8 {
    let Some((command, rest)) = words.split_first() else {
        print!("{USAGE}");
        return EXIT_OK;
    };
    if rest.iter().any(|word| word == "--help" || word == "-h")
        || matches!(command.as_str(), "--help" | "-h" | "help")
    {
        print!("{USAGE}");
        return EXIT_OK;
    }
    match command.as_str() {
        "init" => init(rest, installer),
        "check" => check(rest),
        "test" => test(rest),
        "log" => show_log(rest),
        "scan" => run_scan(rest),
        "hook" => run_hook(rest),
        other => usage_error(&format!("`{other}` is not a policy command")),
    }
}

/// `--client <name>` values of `words`, and the other words.
fn take_clients(words: &[String]) -> Result<(Vec<Client>, Vec<&String>), String> {
    let mut clients = Vec::new();
    let mut other = Vec::new();
    let mut words = words.iter();
    while let Some(word) = words.next() {
        let value = if word == "--client" {
            Some(
                words
                    .next()
                    .ok_or("--client takes claude-code, codex or cursor")?
                    .as_str(),
            )
        } else {
            word.strip_prefix("--client=")
        };
        match value {
            Some(name) => {
                let client = Client::parse(name).ok_or_else(|| {
                    format!("--client takes claude-code, codex or cursor, not `{name}`")
                })?;
                if !clients.contains(&client) {
                    clients.push(client);
                }
            }
            None => other.push(word),
        }
    }
    Ok((clients, other))
}

fn init(words: &[String], installer: Option<&dyn Installer>) -> u8 {
    let (clients, other) = match take_clients(words) {
        Ok(taken) => taken,
        Err(error) => return usage_error(&error),
    };
    let mut dry_run = false;
    for word in other {
        if word == "--dry-run" {
            dry_run = true;
        } else {
            return usage_error(&format!("init takes --client and --dry-run, not `{word}`"));
        }
    }
    let cwd = match current_dir() {
        Ok(cwd) => cwd,
        Err(code) => return code,
    };
    let root = engine::repository_root(&cwd);
    let dry = if dry_run { " (dry run)" } else { "" };
    println!("memprove policy init{dry}: {}", root.display());
    let path = root.join(POLICY_FILE);
    if path.exists() {
        println!("kept {POLICY_FILE}: it exists");
    } else if dry_run {
        println!("would write {POLICY_FILE} (starter rules)");
    } else {
        let written =
            fs::create_dir_all(root.join(".memprove")).and_then(|()| fs::write(&path, STARTER));
        if let Err(error) = written {
            eprintln!("memprove: error: {POLICY_FILE} was not written: {error}");
            return EXIT_ERROR;
        }
        println!("wrote {POLICY_FILE} (starter rules): commit it");
    }
    match installer {
        Some(installer) => match installer.install(&root, &clients, dry_run) {
            Ok(lines) => {
                for line in lines {
                    println!("{line}");
                }
            }
            Err(error) => {
                eprintln!("memprove: error: {error}");
                return EXIT_ERROR;
            }
        },
        None => println!(
            "hooks: not written (this build of memprove policy cannot edit client settings)"
        ),
    }
    println!(
        "next: `memprove policy test` checks the expect lines; `memprove policy check 'Bash(git push -f)'` decides one call"
    );
    EXIT_OK
}

/// The root and policy of the repository around the current directory.
fn policy_here() -> Result<(PathBuf, PathBuf, rules::Policy), u8> {
    let cwd = current_dir()?;
    let Some(root) = engine::find_root(&cwd) else {
        eprintln!(
            "memprove: error: no {POLICY_FILE} in this directory or above it (up to the repository \
             root); `memprove policy init` writes one"
        );
        return Err(EXIT_ERROR);
    };
    let text = fs::read(root.join(POLICY_FILE))
        .map_err(|error| error.to_string())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "it is not UTF-8".to_owned()));
    let text = match text {
        Ok(text) => text,
        Err(error) => {
            eprintln!("memprove: error: {POLICY_FILE} cannot be read: {error}");
            return Err(EXIT_ERROR);
        }
    };
    match rules::parse(&text) {
        Ok(policy) => Ok((root, cwd, policy)),
        Err(errors) => {
            for error in errors {
                eprintln!("memprove: error: {POLICY_FILE} {error}");
            }
            Err(EXIT_ERROR)
        }
    }
}

fn call_of(tool: Tool, subject: &str) -> Call {
    match tool {
        Tool::Bash => Call::Bash(subject.to_owned()),
        Tool::Read => Call::Read(vec![subject.to_owned()]),
        Tool::Edit => Call::Edit(vec![subject.to_owned()]),
        Tool::Mcp => {
            let (server, name) = subject.split_once('.').unwrap_or(("*", subject));
            Call::Mcp {
                server: Some(server.to_owned()),
                tool: name.to_owned(),
            }
        }
    }
}

fn rule_source(rule: &rules::Rule) -> String {
    if rule.line == 0 {
        "built-in".to_owned()
    } else {
        format!("{POLICY_FILE}:{}", rule.line)
    }
}

fn check(words: &[String]) -> u8 {
    let (clients, other) = match take_clients(words) {
        Ok(taken) => taken,
        Err(error) => return usage_error(&error),
    };
    let [call] = other.as_slice() else {
        return usage_error("check takes one call, as in check 'Bash(git push -f)'");
    };
    let (tool, subject) = match rules::parse_call(call) {
        Ok(parsed) => parsed,
        Err(error) => return usage_error(&error),
    };
    let (root, cwd, policy) = match policy_here() {
        Ok(found) => found,
        Err(code) => return code,
    };
    let site = Site {
        root,
        cwd,
        home: home(),
    };
    let verdict = engine::evaluate(&policy, &call_of(tool, &subject), &site);
    let word = verdict.decision.map_or("no rule", Decision::word);
    println!("{word}: {}({subject})", tool.name());
    for check in &verdict.checks {
        match &check.rule {
            Some(rule) => println!(
                "  {:<5} {}  ->  {} by {} `{}`",
                check.tool.name(),
                check.subject,
                rule.decision,
                rule_source(rule),
                rule.text()
            ),
            None => println!("  {:<5} {}  ->  no rule", check.tool.name(), check.subject),
        }
    }
    if let Some(problem) = &verdict.problem {
        println!("  not read in full: {problem}; a command not read in full needs a person");
    }
    let client = clients.first().copied().unwrap_or(Client::ClaudeCode);
    match verdict.decision {
        Some(Decision::Deny | Decision::Ask) => {
            let cannot_ask = (!hook::can_ask_for(client, tool)).then(|| client.title());
            println!(
                "{} is told: {}",
                client.title(),
                hook::reason(&verdict, cannot_ask)
            );
            EXIT_FAILED
        }
        _ => EXIT_OK,
    }
}

fn test(words: &[String]) -> u8 {
    if let Some(word) = words.first() {
        return usage_error(&format!("test takes no argument, not `{word}`"));
    }
    let (root, _, policy) = match policy_here() {
        Ok(found) => found,
        Err(code) => return code,
    };
    if policy.expectations.is_empty() {
        println!("{POLICY_FILE} has no `expect` lines to check");
        return EXIT_OK;
    }
    let site = Site {
        root: root.clone(),
        cwd: root,
        home: home(),
    };
    let mut failed = 0usize;
    for expectation in &policy.expectations {
        let verdict = engine::evaluate(
            &policy,
            &call_of(expectation.tool, &expectation.subject),
            &site,
        );
        let holds = match expectation.decision {
            Decision::Allow => verdict
                .decision
                .is_none_or(|decision| decision == Decision::Allow),
            expected => verdict.decision == Some(expected),
        };
        let line = format!(
            "line {}: expect {} {}({})",
            expectation.line,
            expectation.decision,
            expectation.tool.name(),
            expectation.subject
        );
        if holds {
            println!("PASS  {line}");
        } else {
            failed += 1;
            let got = match (
                verdict.decision,
                verdict
                    .deciding_check()
                    .and_then(|check| check.rule.as_ref()),
            ) {
                (None, _) => "no rule matches".to_owned(),
                (Some(decision), Some(rule)) => {
                    format!("got {decision} by {} `{}`", rule_source(rule), rule.text())
                }
                (Some(decision), None) => format!(
                    "got {decision}: {}",
                    verdict.problem.as_deref().unwrap_or("not read in full")
                ),
            };
            println!("FAIL  {line}: {got}");
        }
    }
    let passed = policy.expectations.len() - failed;
    println!("{passed} passed, {failed} failed");
    if failed == 0 { EXIT_OK } else { EXIT_FAILED }
}

fn show_log(words: &[String]) -> u8 {
    let mut count = 20usize;
    let mut words = words.iter();
    while let Some(word) = words.next() {
        let value = if word == "--last" {
            words.next().map(String::as_str)
        } else if let Some(value) = word.strip_prefix("--last=") {
            Some(value)
        } else {
            return usage_error(&format!("log takes --last <N>, not `{word}`"));
        };
        match value
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|count| *count > 0)
        {
            Some(value) => count = value,
            None => return usage_error("--last takes a number above 0"),
        }
    }
    let cwd = match current_dir() {
        Ok(cwd) => cwd,
        Err(code) => return code,
    };
    let root = engine::find_root(&cwd).unwrap_or_else(|| engine::repository_root(&cwd));
    match log::last(&root, count) {
        Ok(records) if records.is_empty() => {
            println!("no refusals or approvals asked for are logged in this repository");
            EXIT_OK
        }
        Ok(records) => {
            for record in records {
                let told = if record.decision == record.sent {
                    record.sent.clone()
                } else {
                    format!("{} (asked as {})", record.sent, record.decision)
                };
                let rule = match (record.line, &record.rule) {
                    (Some(0), Some(rule)) => format!("built-in `{rule}`"),
                    (Some(line), Some(rule)) => format!("line {line} `{rule}`"),
                    _ => "no rule".to_owned(),
                };
                println!(
                    "{}  {told}  {}  {} {}  ({rule})",
                    record.time, record.client, record.tool, record.subject
                );
            }
            EXIT_OK
        }
        Err(error) => {
            eprintln!("memprove: error: {error}");
            EXIT_ERROR
        }
    }
}

fn run_scan(words: &[String]) -> u8 {
    let mut as_json = false;
    let mut targets = Vec::new();
    let mut only_paths = false;
    for word in words {
        if only_paths || !word.starts_with('-') {
            targets.push(PathBuf::from(word));
        } else if word == "--" {
            only_paths = true;
        } else if word == "--json" {
            as_json = true;
        } else {
            return usage_error(&format!("scan takes --json and paths, not `{word}`"));
        }
    }
    let cwd = match current_dir() {
        Ok(cwd) => cwd,
        Err(code) => return code,
    };
    let root = engine::repository_root(&cwd);
    let targets: Vec<PathBuf> = targets
        .iter()
        .map(|target| crate::commands::clean(&cwd.join(target)))
        .collect();
    let report = match scan::scan(&root, &targets) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("memprove: error: {error}");
            return EXIT_ERROR;
        }
    };
    if as_json {
        print!("{}", report.json(&root));
    } else {
        println!("memprove policy scan: {}", root.display());
        if report.files == 0 && report.skipped.is_empty() {
            println!("no agent settings or instruction file found here");
        } else {
            print!("{}", report.text());
        }
    }
    if report.findings.is_empty() {
        EXIT_OK
    } else {
        EXIT_FAILED
    }
}

fn run_hook(words: &[String]) -> u8 {
    let (clients, other) = match take_clients(words) {
        Ok(taken) => taken,
        Err(error) => return usage_error(&error),
    };
    if let Some(word) = other.first() {
        return usage_error(&format!("hook takes --client, not `{word}`"));
    }
    let [client] = clients.as_slice() else {
        return usage_error("hook takes one --client: claude-code, codex or cursor");
    };
    let mut input = Vec::new();
    let read = std::io::stdin()
        .lock()
        .take(u64::try_from(hook::MAX_INPUT_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut input);
    if let Err(error) = read {
        eprintln!("memprove policy: the hook's input was not read: {error}");
        input.clear();
    }
    let variable = match client {
        Client::ClaudeCode => Some("CLAUDE_PROJECT_DIR"),
        Client::Cursor => Some("CURSOR_PROJECT_DIR"),
        Client::Codex => None,
    };
    let env = HookEnv {
        project_dir: variable
            .and_then(std::env::var_os)
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from),
        cwd: std::env::current_dir().unwrap_or_default(),
        home: home(),
        time: log::rfc3339(SystemTime::now()),
    };
    let answer = hook::answer(*client, &input, &env);
    if let Some(warning) = &answer.warning {
        eprintln!("{warning}");
    }
    if let Some((root, record)) = &answer.record
        && let Err(error) = log::append(root, record)
    {
        eprintln!("memprove policy: warning: the decision was not logged: {error}");
    }
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(answer.stdout.as_bytes());
    if !answer.stdout.is_empty() {
        let _ = stdout.write_all(b"\n");
    }
    let _ = stdout.flush();
    EXIT_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_starter_policy_reads_and_its_expectations_hold() {
        let policy = rules::parse(STARTER).unwrap();
        assert!(policy.rules.len() >= 8);
        let site = Site {
            root: PathBuf::from("/repo"),
            cwd: PathBuf::from("/repo"),
            home: Some(PathBuf::from("/home/me")),
        };
        for expectation in &policy.expectations {
            let verdict = engine::evaluate(
                &policy,
                &call_of(expectation.tool, &expectation.subject),
                &site,
            );
            let holds = match expectation.decision {
                Decision::Allow => verdict
                    .decision
                    .is_none_or(|decision| decision == Decision::Allow),
                expected => verdict.decision == Some(expected),
            };
            assert!(holds, "line {}: {:?}", expectation.line, verdict);
        }
    }

    #[test]
    fn clients_are_taken_from_the_words() {
        let words: Vec<String> = [
            "--client",
            "codex",
            "--dry-run",
            "--client=cursor",
            "--client",
            "codex",
        ]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
        let (clients, other) = take_clients(&words).unwrap();
        assert_eq!(clients, vec![Client::Codex, Client::Cursor]);
        assert_eq!(other, vec!["--dry-run"]);
        assert!(take_clients(&["--client".to_owned(), "vim".to_owned()]).is_err());
    }
}
