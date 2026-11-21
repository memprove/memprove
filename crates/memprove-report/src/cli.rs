//! `memprove report`: parsing and dispatch, shared by the `memprove` CLI
//! and a future standalone binary.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use crate::{
    claude, codex,
    find::{self, Found, Homes},
    model::{Client, Session},
    prices::Prices,
    render,
    report::{Present, Report},
};

/// Exit code: the report or listing was printed.
pub const EXIT_OK: u8 = 0;
/// Exit code: no session was found, or its transcript cannot be read.
pub const EXIT_NOT_FOUND: u8 = 1;
/// Exit code: a usage error, or a price file that cannot be read.
pub const EXIT_USAGE: u8 = 2;

/// How many sessions `--list` shows unless `--last` says otherwise.
pub const DEFAULT_LIST: usize = 10;

/// `memprove report --help`.
pub const USAGE: &str = "memprove report: what one coding-agent session cost, did, was refused and read

Usage:
  memprove report [<SESSION>] [--client claude-code|codex] [--json] [--prices <FILE>] [--now]
  memprove report --list [--last <N>] [--client claude-code|codex] [--json] [--prices <FILE>]
  memprove report --transcript <FILE> [--client claude-code|codex] [--json] [--prices <FILE>] [--now]

Reads, on this machine, the transcript of a Claude Code or Codex session that
ran in this repository (the most recently active one, or the one whose id
starts with <SESSION>), and the repository's memprove policy log, and reports:

  cost      model requests and tokens per model, and their cost estimated at
            list prices (built in for Anthropic's models; --prices adds others)
  tools     tool calls per tool, and how many failed (Claude Code only)
  policy    the calls memprove policy refused or sent to a person while the
            session ran (<git common dir>/memprove-policy/log.jsonl)
  memory    the memprove statements the agent read (the SessionStart hook's
            Pack, the MCP tools, memprove commands it ran), and the facts that
            were not verified when it read them

Nothing is written and nothing is sent anywhere. Transcripts are found under
$CLAUDE_CONFIG_DIR or ~/.claude (projects/) and $CODEX_HOME or ~/.codex
(sessions/; compressed ones are read with zstd). Cursor is not supported.

  --list             one line per session of this repository, the most recently
                     active first
  --last <N>         with --list, how many sessions (default 10)
  --transcript <F>   report the transcript file F
  --client <C>       only sessions of client C
  --json             JSON: memprove.report.session.v1 (--list: memprove.report.list.v1)
  --prices <FILE>    prices per million tokens, one model per line:
                       <model or pattern with *> input=<$> output=<$> [cache_read=<$>]
                       [cache_write=<$>] [cache_write_1h=<$>]
                     cache_read and cache_write default to input
  --now              also ask the memprove daemon (read requests only) which
                     facts the agent read as verified are not verified now

Exit status:
  0  printed
  1  no session found, or its transcript cannot be read
  2  usage error, or the price file cannot be read
";

/// What `memprove report` was asked for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // One field per flag of the command line.
pub struct Args {
    /// The session id (or its start) to report.
    pub session: Option<String>,
    /// `--list`.
    pub list: bool,
    /// `--last <N>`.
    pub last: Option<usize>,
    /// `--transcript <FILE>`.
    pub transcript: Option<PathBuf>,
    /// `--client <C>`.
    pub client: Option<Client>,
    /// `--json`.
    pub json: bool,
    /// `--prices <FILE>`.
    pub prices: Option<PathBuf>,
    /// `--now`.
    pub now: bool,
    /// `--help`.
    pub help: bool,
}

/// The arguments after `memprove report`.
///
/// # Errors
///
/// One sentence naming the argument that is wrong.
pub fn parse(words: &[String]) -> Result<Args, String> {
    let mut args = Args::default();
    let mut words = words.iter();
    while let Some(word) = words.next() {
        let mut value = |name: &str| {
            words
                .next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match word.as_str() {
            "-h" | "--help" => args.help = true,
            "--list" => args.list = true,
            "--json" => args.json = true,
            "--now" => args.now = true,
            "--last" => {
                let text = value("--last")?;
                let last: usize = text
                    .parse()
                    .ok()
                    .filter(|last| (1..=1000).contains(last))
                    .ok_or_else(|| {
                        format!("--last takes a whole number from 1 through 1000, not {text}")
                    })?;
                args.last = Some(last);
            }
            "--client" => {
                let text = value("--client")?;
                args.client =
                    Some(Client::parse(&text).ok_or_else(|| {
                        format!("--client takes claude-code or codex, not {text}")
                    })?);
            }
            "--transcript" => args.transcript = Some(PathBuf::from(value("--transcript")?)),
            "--prices" => args.prices = Some(PathBuf::from(value("--prices")?)),
            option if option.starts_with('-') => return Err(format!("unknown option {option}")),
            session => {
                if args.session.replace(session.to_owned()).is_some() {
                    return Err("only one session can be named".to_owned());
                }
            }
        }
    }
    if args.list && (args.session.is_some() || args.transcript.is_some() || args.now) {
        return Err("--list takes no session, --transcript or --now".to_owned());
    }
    if args.last.is_some() && !args.list {
        return Err("--last goes with --list".to_owned());
    }
    if args.transcript.is_some() && args.session.is_some() {
        return Err("name a session or a --transcript, not both".to_owned());
    }
    Ok(args)
}

/// Where `memprove report` runs.
#[derive(Debug, Clone)]
pub struct Env {
    /// The current directory.
    pub cwd: PathBuf,
    /// Where the clients keep their transcripts.
    pub homes: Homes,
}

impl Env {
    /// The process's current directory and environment.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            homes: Homes::from_vars(&|name: &str| std::env::var_os(name)),
        }
    }
}

/// Runs `memprove report <words>` in this process's directory and
/// environment; `present` answers `--now`.
#[must_use]
pub fn main(words: &[String], present: Option<&dyn Present>) -> u8 {
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    run(words, &Env::from_process(), present, &mut out, &mut err)
}

/// Runs `memprove report <words>` in `env`, writing to `out` and `err`.
pub fn run(
    words: &[String],
    env: &Env,
    present: Option<&dyn Present>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let args = match parse(words) {
        Ok(args) if args.help => {
            let _ = out.write_all(USAGE.as_bytes());
            return EXIT_OK;
        }
        Ok(args) => args,
        Err(error) => {
            let _ = writeln!(
                err,
                "memprove report: {error}\nmemprove report: see `memprove report --help`"
            );
            return EXIT_USAGE;
        }
    };
    let prices = match &args.prices {
        Some(path) => match Prices::with_file(path) {
            Ok(prices) => prices,
            Err(error) => {
                let _ = writeln!(err, "memprove report: {error}");
                return EXIT_USAGE;
            }
        },
        None => Prices::default(),
    };
    let present = if args.now { present } else { None };
    let fail = |err: &mut dyn Write, error: &str| {
        let _ = writeln!(err, "memprove report: {error}");
        EXIT_NOT_FOUND
    };
    if let Some(path) = &args.transcript {
        let path = env.cwd.join(path);
        let client = args.client.unwrap_or_else(|| guess_client(&path));
        let session = match read(client, &path) {
            Ok(session) => session,
            Err(error) => return fail(err, &error),
        };
        let root = session
            .cwd
            .as_deref()
            .map(Path::new)
            .filter(|cwd| cwd.is_dir())
            .map_or_else(|| find::repository_root(&env.cwd), find::repository_root);
        let report = Report::new(session, &root, present);
        return print(out, &report, &prices, args.json);
    }
    let root = find::repository_root(&env.cwd);
    let clients: Vec<Client> = args
        .client
        .map_or_else(|| Client::ALL.to_vec(), |client| vec![client]);
    let found = find::sessions(&env.homes, &root, &clients);
    if found.is_empty() {
        return fail(
            err,
            &format!(
                "no {} session found for {} (searched {})",
                render::client_names(&clients),
                root.display(),
                searched(&env.homes, &clients)
            ),
        );
    }
    if args.list {
        return list(out, err, &found, &root, &prices, &args);
    }
    let chosen: &Found = match &args.session {
        Some(wanted) => match find::select(&found, wanted) {
            Ok(found) => found,
            Err(error) => return fail(err, &error),
        },
        None => &found[0],
    };
    match read(chosen.client, &chosen.path) {
        Ok(session) => print(
            out,
            &Report::new(session, &root, present),
            &prices,
            args.json,
        ),
        Err(error) => fail(err, &error),
    }
}

fn list(
    out: &mut dyn Write,
    err: &mut dyn Write,
    found: &[Found],
    root: &Path,
    prices: &Prices,
    args: &Args,
) -> u8 {
    let count = args.last.unwrap_or(DEFAULT_LIST);
    let mut reports = Vec::new();
    for session in found.iter().take(count) {
        match read(session.client, &session.path) {
            Ok(read) => reports.push(Report::new(read, root, None)),
            Err(error) => {
                let _ = writeln!(err, "memprove report: {error}");
            }
        }
    }
    let text = if args.json {
        render::json_text(&render::list_json(&reports, prices))
    } else {
        let mut text = format!(
            "Sessions of {} ({} of {}, the most recently active first):\n  {}\n",
            root.display(),
            reports.len(),
            found.len(),
            render::LIST_TITLES
        );
        for report in &reports {
            text.push_str("  ");
            text.push_str(&render::list_line(report, prices));
            text.push('\n');
        }
        text
    };
    let _ = out.write_all(text.as_bytes());
    EXIT_OK
}

fn print(out: &mut dyn Write, report: &Report, prices: &Prices, json: bool) -> u8 {
    let text = if json {
        render::json_text(&render::json_value(report, prices))
    } else {
        render::text(report, prices)
    };
    let _ = out.write_all(text.as_bytes());
    EXIT_OK
}

/// The session in the transcript of `client` at `path`.
///
/// # Errors
///
/// One sentence saying why it cannot be read.
pub fn read(client: Client, path: &Path) -> Result<Session, String> {
    match client {
        Client::ClaudeCode => claude::read(path),
        Client::Codex => codex::read(path),
    }
}

/// The client whose transcript `path` looks like: a Codex rollout by its
/// name or place, else Claude Code.
#[must_use]
pub fn guess_client(path: &Path) -> Client {
    let rollout = path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with("rollout-"));
    if rollout || path.components().any(|part| part.as_os_str() == ".codex") {
        Client::Codex
    } else {
        Client::ClaudeCode
    }
}

fn searched(homes: &Homes, clients: &[Client]) -> String {
    let mut places = Vec::new();
    if clients.contains(&Client::ClaudeCode)
        && let Some(dir) = &homes.claude
    {
        places.push(dir.join("projects").display().to_string());
    }
    if clients.contains(&Client::Codex)
        && let Some(dir) = &homes.codex
    {
        places.push(dir.join("sessions").display().to_string());
    }
    if places.is_empty() {
        "nowhere: HOME is not set".to_owned()
    } else {
        places.join(" and ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn arguments_parse_and_conflicts_are_usage_errors() {
        let args = parse(&words("abc --client codex --json --prices p.txt --now")).unwrap();
        assert_eq!(args.session.as_deref(), Some("abc"));
        assert_eq!(args.client, Some(Client::Codex));
        assert!(args.json && args.now);
        assert_eq!(args.prices, Some(PathBuf::from("p.txt")));
        assert_eq!(parse(&words("--list --last 3")).unwrap().last, Some(3));
        for bad in [
            "--list abc",
            "--last 3",
            "--list --last 0",
            "--client cursor",
            "--transcript f abc",
            "a b",
            "--frobnicate",
            "--prices",
            "--list --now",
        ] {
            assert!(parse(&words(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn transcripts_are_told_apart_by_name_and_place() {
        assert_eq!(
            guess_client(Path::new("/x/rollout-2026.jsonl")),
            Client::Codex
        );
        assert_eq!(
            guess_client(Path::new("/h/.codex/sessions/a.jsonl")),
            Client::Codex
        );
        assert_eq!(
            guess_client(Path::new("/h/.claude/projects/p/s.jsonl")),
            Client::ClaudeCode
        );
    }
}
