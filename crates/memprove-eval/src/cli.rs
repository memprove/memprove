//! `memprove eval <command>`: parsing and dispatch, shared by the
//! `memprove` CLI and a future standalone binary.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    AgentKind, AgentSpec, Baseline, EvalError, Memory, MemoryProbe, RunRecord, agent_for, git,
    init::{self, InitSpec},
    mine::{self, MineSpec, MineStatus},
    report::{self, Format, GatePolicy},
    runner::{self, RunOptions},
    task,
};

/// Exit code: done, every trial passed, the gate passed.
pub const EXIT_OK: u8 = 0;
/// Exit code: some trial did not pass, or the gate failed.
pub const EXIT_FAILED: u8 = 1;
/// Exit code: a usage error.
pub const EXIT_USAGE: u8 = 2;
/// Exit code: the command could not be done (a file, `git`, the agent).
pub const EXIT_ERROR: u8 = 3;

/// The task directory and baseline file when none is named.
pub const DEFAULT_TASKS: &str = "evals";
/// The baseline file when none is named.
pub const DEFAULT_BASELINE: &str = "evals/baseline.json";

const EXITS: &str = "Exit status:
  0  done; for run, every trial passed; for gate, the run may pass
  1  for run, some trial did not pass; for gate, the run fails the baseline
  2  usage error
  3  the command could not be done (a file, git, the agent)
";

/// `memprove eval --help`.
pub const USAGE: &str = "memprove eval: run a coding agent on this repository's own tasks and judge it by tests

Usage:
  memprove eval init     [--agent claude-code|codex] [--no-workflow] [--dry-run]
  memprove eval mine     [--limit <N>] [--range <GIT_RANGE>] [--out <DIR>] [--verify] [--dry-run]
  memprove eval run      [<TASK_FILE | DIR>...] [--agent claude-code|codex|command] [--model <MODEL>]
                         [--agent-arg <ARG>]... [--pass-env <NAME>]... [--trials <N>] [--jobs <N>]
                         [--out-root <DIR>]
                         [--keep-worktrees] [--memory none|pack] [--no-memory]
                         [-- <PROGRAM> [<ARG>...]]
  memprove eval ab       [<TASK_FILE | DIR>...] [the options of run but --memory, --no-memory]
  memprove eval report   [<RUN_DIR> | latest] [--baseline <FILE | RUN_DIR>] [--format markdown|json]
  memprove eval baseline [<RUN_DIR> | latest] [--write <FILE>]
  memprove eval gate     [<RUN_DIR> | latest] [--baseline <FILE | RUN_DIR>] [--max-drop <POINTS>]
                         [--allow-regressions]

A task file (evals/<id>.json, schema memprove.eval.task.v1) names a base commit, a
prompt, an optional setup, a check command, and an optional check patch: tests applied
after the agent, so it never sees them. `run` gives every task to the agent in a Git
repository of its own with one commit, the base commit's files without the run's task
files and check patches, then runs the check there; exit code 0 is `passed`, and
nothing else judges. The run is written to run.json under
<git common dir>/memprove-eval/runs/<run id>/, with every log and the agent's diff.
`ab` runs the tasks twice, without memory and with memprove's Context Pack, and
compares the two.

`memprove eval <command> --help` describes one command.

";

struct Help {
    name: &'static str,
    summary: &'static str,
    usage: &'static str,
    options: &'static [(&'static str, &'static str)],
    notes: &'static str,
}

const HELP: &[Help] = &[
    Help {
        name: "init",
        summary: "set this repository up for memprove eval",
        usage: "memprove eval init [--agent claude-code|codex] [--no-workflow] [--dry-run]",
        options: &[
            (
                "--agent <NAME>",
                "the agent the workflow is written for; default claude-code",
            ),
            (
                "--no-workflow",
                "do not write .github/workflows/memprove-eval.yml",
            ),
            (
                "--dry-run",
                "list the files that would be written; write nothing",
            ),
        ],
        notes: "Writes evals/README.md (how to write a task, addressed to the coding agent), a\n\
                first task when the test command can be guessed, the CI workflow, and a note of\n\
                under five lines in AGENTS.md or CLAUDE.md. Running it again changes nothing.",
    },
    Help {
        name: "mine",
        summary: "write tasks from this repository's history",
        usage: "memprove eval mine [--limit <N>] [--range <GIT_RANGE>] [--out <DIR>] [--verify] [--dry-run]",
        options: &[
            ("--limit <N>", "at most N tasks; default 10"),
            (
                "--range <GIT_RANGE>",
                "the commits to look at, in git log syntax; default the history of HEAD",
            ),
            (
                "--out <DIR>",
                "where task files and check patches go; default evals",
            ),
            (
                "--verify",
                "keep only tasks whose check fails at the base with the patch and passes at the commit",
            ),
            (
                "--dry-run",
                "list the files that would be written; write nothing",
            ),
        ],
        notes: "A commit that changed tests and code becomes a task: its parent is the base, its\n\
                message the prompt, and its test changes the check patch. A task file that exists\n\
                is left as it is and counts towards --limit; a task --verify refuses does not.",
    },
    Help {
        name: "run",
        summary: "run the tasks with an agent and judge each by its check",
        usage: "memprove eval run [<TASK_FILE | DIR>...] [--agent claude-code|codex|command] [--model <MODEL>]\n\
                \x20                 [--agent-arg <ARG>]... [--pass-env <NAME>]... [--trials <N>] [--jobs <N>]\n\
                \x20                 [--out-root <DIR>] [--keep-worktrees] [--memory none|pack] [--no-memory]\n\
                \x20                 [-- <PROGRAM> [<ARG>...]]",
        options: &[
            (
                "<TASK_FILE | DIR>",
                "task files, or directories of them (every *.json but baseline.json); default evals",
            ),
            (
                "--agent <NAME>",
                "claude-code (claude -p), codex (codex exec), or command (the program after --); default claude-code",
            ),
            (
                "--model <MODEL>",
                "the model to ask the agent for; default the agent's own",
            ),
            (
                "--agent-arg <ARG>",
                "an argument passed to the agent as it is, repeatable",
            ),
            (
                "--pass-env <NAME>",
                "a variable of this environment the agent inherits besides the default list, repeatable",
            ),
            ("--trials <N>", "trials of each task, 1 to 100; default 1"),
            (
                "--jobs <N>",
                "trials run at the same time, 1 to 16; default 1",
            ),
            (
                "--out-root <DIR>",
                "where the run directory goes; default <git common dir>/memprove-eval/runs",
            ),
            (
                "--keep-worktrees",
                "keep each trial's working copy (under the system's temporary directory)",
            ),
            (
                "--memory <MODE>",
                "none (default): the agent gets no memory, run.json records memprove's statements; pack: every trial's agent gets the Context Pack memprove would inject into a new session, ahead of the prompt",
            ),
            ("--no-memory", "do not read memprove's memory at all"),
            (
                "-- <PROGRAM> [<ARG>...]",
                "the command agent: {prompt_file} and {workdir} in its arguments are replaced",
            ),
        ],
        notes: "The agent runs without asking for permissions, in a working copy of its own; run it\n\
                where that is acceptable, such as CI. The last line is in the format of cargo\n\
                test's summary, one case per trial, so `memprove run --test-format cargo --\n\
                memprove eval run` records the run as test Evidence. The agent's\n\
                MEMPROVE_CONFIG_DIR is an empty directory, and its worktree has no memprove\n\
                context, so it gets no Pack but the one --memory pack gives. The agent inherits\n\
                only a list of variables (the shell's, the toolchains', the proxies' and the\n\
                model providers' login ones; docs/eval.md names them) and those of --pass-env:\n\
                no session socket, token or identity of the caller reaches it.",
    },
    Help {
        name: "ab",
        summary: "run the tasks without memory and with memprove's Pack, and compare",
        usage: "memprove eval ab [<TASK_FILE | DIR>...] [--agent claude-code|codex|command] [--model <MODEL>]\n\
                \x20                [--agent-arg <ARG>]... [--pass-env <NAME>]... [--trials <N>] [--jobs <N>]\n\
                \x20                [--out-root <DIR>] [--keep-worktrees] [-- <PROGRAM> [<ARG>...]]",
        options: &[("<TASK_FILE | DIR> and the rest", "as for run")],
        notes: "memprove's memory is read once, before any trial; when it cannot be read, nothing\n\
                runs. The first run gives the agent no memory, the second gives every trial that\n\
                Context Pack (as run --memory pack); both record the same statements, and the\n\
                report compares the second with the first. It costs two runs. Exit status 0 means\n\
                both runs were done, whatever they passed.",
    },
    Help {
        name: "report",
        summary: "print a run's report, compared with a baseline",
        usage: "memprove eval report [<RUN_DIR> | latest] [--baseline <FILE | RUN_DIR>] [--format markdown|json]",
        options: &[
            (
                "<RUN_DIR> | latest",
                "the run directory; default the latest run",
            ),
            (
                "--baseline <FILE | RUN_DIR>",
                "the baseline to compare with, or a run directory to compare with as one; default evals/baseline.json when it exists",
            ),
            ("--format <FORMAT>", "markdown (default) or json"),
        ],
        notes: "",
    },
    Help {
        name: "baseline",
        summary: "write a run's pass counts as the baseline",
        usage: "memprove eval baseline [<RUN_DIR> | latest] [--write <FILE>]",
        options: &[
            (
                "<RUN_DIR> | latest",
                "the run directory; default the latest run",
            ),
            (
                "--write <FILE>",
                "the baseline file; default evals/baseline.json",
            ),
        ],
        notes: "Commit the baseline file: later runs and CI compare with it.",
    },
    Help {
        name: "gate",
        summary: "fail when a run falls below the baseline",
        usage: "memprove eval gate [<RUN_DIR> | latest] [--baseline <FILE | RUN_DIR>] [--max-drop <POINTS>] [--allow-regressions]",
        options: &[
            (
                "<RUN_DIR> | latest",
                "the run directory; default the latest run",
            ),
            (
                "--baseline <FILE | RUN_DIR>",
                "the baseline, or a run directory; default evals/baseline.json",
            ),
            (
                "--max-drop <POINTS>",
                "the largest drop of the pass rate allowed, in percentage points (one decimal); default 0",
            ),
            (
                "--allow-regressions",
                "do not fail for a task that passed every baseline trial and passes none now",
            ),
        ],
        notes: "A task of the baseline that the run did not run fails the gate.",
    },
];

fn help_of(entry: &Help) -> String {
    let mut text = format!(
        "memprove eval {}: {}\n\nUsage:\n  {}\n",
        entry.name, entry.summary, entry.usage
    );
    if !entry.options.is_empty() {
        text.push_str("\nOptions:\n");
        for (option, description) in entry.options {
            text.push_str("  ");
            text.push_str(option);
            text.push('\n');
            text.push_str("      ");
            text.push_str(description);
            text.push('\n');
        }
    }
    if !entry.notes.is_empty() {
        text.push('\n');
        text.push_str(entry.notes);
        text.push('\n');
    }
    text.push('\n');
    text.push_str(EXITS);
    text
}

/// Runs `memprove eval` with `args` (the words after `eval`) and returns
/// its exit code; `memory` is the embedding program's memory probe.
#[must_use]
pub fn main(args: &[String], memory: Option<&dyn MemoryProbe>) -> u8 {
    let Some((command, rest)) = args.split_first() else {
        print!("{USAGE}{EXITS}");
        return EXIT_OK;
    };
    if matches!(command.as_str(), "--help" | "-h" | "help") {
        print!("{USAGE}{EXITS}");
        return EXIT_OK;
    }
    let Some(entry) = HELP.iter().find(|entry| entry.name == command) else {
        eprintln!(
            "memprove eval: error: no command {command:?}\nRun `memprove eval --help` for the commands."
        );
        return EXIT_USAGE;
    };
    let before_dashes = rest.iter().take_while(|arg| *arg != "--");
    if before_dashes
        .clone()
        .any(|arg| arg == "--help" || arg == "-h")
    {
        print!("{}", help_of(entry));
        return EXIT_OK;
    }
    let outcome = Args::parse(rest).and_then(|parsed| dispatch(entry.name, &parsed, memory));
    match outcome {
        Ok(code) => code,
        Err(EvalError::Usage(detail)) => {
            eprintln!(
                "memprove eval {command}: error: {detail}\nRun `memprove eval {command} --help` for its options."
            );
            EXIT_USAGE
        }
        Err(error) => {
            eprintln!("memprove eval {command}: error: {error}");
            EXIT_ERROR
        }
    }
}

/// The words of one command: positionals, options with values, flags, and
/// what follows `--`.
#[derive(Debug, Default)]
struct Args {
    positionals: Vec<String>,
    options: Vec<(String, String)>,
    flags: Vec<String>,
    trailing: Vec<String>,
}

const FLAGS: &[&str] = &[
    "--no-workflow",
    "--dry-run",
    "--verify",
    "--keep-worktrees",
    "--no-memory",
    "--allow-regressions",
];

impl Args {
    fn parse(words: &[String]) -> Result<Self, EvalError> {
        let mut args = Self::default();
        let mut words = words.iter();
        while let Some(word) = words.next() {
            if word == "--" {
                args.trailing = words.cloned().collect();
                break;
            }
            if FLAGS.contains(&word.as_str()) {
                args.flags.push(word.clone());
            } else if let Some(name) = word.strip_prefix("--") {
                let (name, value) = match name.split_once('=') {
                    Some((name, value)) => (name.to_owned(), value.to_owned()),
                    None => (
                        name.to_owned(),
                        words
                            .next()
                            .cloned()
                            .ok_or_else(|| EvalError::Usage(format!("--{name} needs a value")))?,
                    ),
                };
                args.options.push((format!("--{name}"), value));
            } else {
                args.positionals.push(word.clone());
            }
        }
        Ok(args)
    }

    fn allow(
        &self,
        options: &[&str],
        flags: &[&str],
        positionals: usize,
        trailing: bool,
    ) -> Result<(), EvalError> {
        if let Some((name, _)) = self
            .options
            .iter()
            .find(|(name, _)| !options.contains(&name.as_str()))
        {
            return Err(EvalError::Usage(format!("unknown option {name}")));
        }
        if let Some(flag) = self
            .flags
            .iter()
            .find(|flag| !flags.contains(&flag.as_str()))
        {
            return Err(EvalError::Usage(format!("unknown option {flag}")));
        }
        if self.positionals.len() > positionals {
            return Err(EvalError::Usage(format!(
                "unexpected argument {:?}",
                self.positionals[positionals]
            )));
        }
        if !trailing && !self.trailing.is_empty() {
            return Err(EvalError::Usage("nothing may follow --".to_owned()));
        }
        Ok(())
    }

    fn one(&self, name: &str) -> Result<Option<&str>, EvalError> {
        let mut values = self.options.iter().filter(|(option, _)| option == name);
        let first = values.next().map(|(_, value)| value.as_str());
        if values.next().is_some() {
            return Err(EvalError::Usage(format!("{name} is given twice")));
        }
        Ok(first)
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.options
            .iter()
            .filter(|(option, _)| option == name)
            .map(|(_, value)| value.clone())
            .collect()
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|flag| flag == name)
    }

    fn number(
        &self,
        name: &str,
        range: std::ops::RangeInclusive<u32>,
        default: u32,
    ) -> Result<u32, EvalError> {
        match self.one(name)? {
            None => Ok(default),
            Some(text) => text
                .parse::<u32>()
                .ok()
                .filter(|number| range.contains(number))
                .ok_or_else(|| {
                    EvalError::Usage(format!(
                        "{name} must be a whole number from {} to {}, not {text:?}",
                        range.start(),
                        range.end()
                    ))
                }),
        }
    }
}

fn dispatch(name: &str, args: &Args, memory: Option<&dyn MemoryProbe>) -> Result<u8, EvalError> {
    let cwd = std::env::current_dir().map_err(|error| EvalError::io(Path::new("."), error))?;
    match name {
        "init" => init_command(args, &cwd),
        "mine" => mine_command(args, &cwd),
        "run" => run_command(args, &cwd, memory),
        "ab" => ab_command(args, &cwd, memory),
        "report" => report_command(args, &cwd),
        "baseline" => baseline_command(args, &cwd),
        "gate" => gate_command(args, &cwd),
        _ => unreachable!("the help table names every command"),
    }
}

fn agent_kind(args: &Args, allowed: &[AgentKind]) -> Result<AgentKind, EvalError> {
    let Some(name) = args.one("--agent")? else {
        return Ok(AgentKind::ClaudeCode);
    };
    AgentKind::parse(name)
        .filter(|kind| allowed.contains(kind))
        .ok_or_else(|| {
            let names: Vec<&str> = allowed.iter().map(|kind| kind.name()).collect();
            EvalError::Usage(format!(
                "--agent must be {}, not {name:?}",
                names.join(", ")
            ))
        })
}

fn init_command(args: &Args, cwd: &Path) -> Result<u8, EvalError> {
    args.allow(&["--agent"], &["--no-workflow", "--dry-run"], 0, false)?;
    let spec = InitSpec {
        repo_root: git::toplevel(cwd)?,
        agent: agent_kind(args, &[AgentKind::ClaudeCode, AgentKind::Codex])?,
        workflow: !args.flag("--no-workflow"),
        dry_run: args.flag("--dry-run"),
    };
    let report = init::init(&spec)?;
    let verb = if spec.dry_run { "would write" } else { "wrote" };
    for path in &report.written {
        println!("{verb} {}", path.display());
    }
    for path in &report.unchanged {
        println!("unchanged {}", path.display());
    }
    for path in &report.kept {
        println!(
            "kept {} (it holds other text; delete it to have init write it)",
            path.display()
        );
    }
    for note in &report.notes {
        println!("note: {note}");
    }
    Ok(EXIT_OK)
}

fn mine_command(args: &Args, cwd: &Path) -> Result<u8, EvalError> {
    args.allow(
        &["--limit", "--range", "--out"],
        &["--verify", "--dry-run"],
        0,
        false,
    )?;
    let mut spec = MineSpec::new(git::toplevel(cwd)?);
    spec.limit = usize::try_from(args.number("--limit", 1..=100, 10)?).unwrap_or(10);
    spec.range = args.one("--range")?.map(str::to_owned);
    if let Some(out) = args.one("--out")? {
        spec.out_dir = PathBuf::from(out);
    }
    spec.dry_run = args.flag("--dry-run");
    spec.verify = args.flag("--verify");
    let tasks = mine::mine(&spec)?;
    for task in &tasks {
        let path = task.path.display();
        let commit = &task.commit;
        match &task.status {
            MineStatus::Written => println!("wrote {path} from {commit}"),
            MineStatus::DryRun => println!("would write {path} from {commit}"),
            MineStatus::Exists => println!("kept {path} (it exists)"),
            MineStatus::Rejected(reason) => println!("refused {commit}: {reason}"),
        }
    }
    if tasks.is_empty() {
        println!("no commit in the range changed both tests and code");
    }
    Ok(EXIT_OK)
}

/// What `run` and `ab` share: the suite, the agent and the run options,
/// from the words of either command.
struct Prepared {
    tasks: Vec<(crate::Task, crate::TaskRef)>,
    agent: Box<dyn crate::Agent>,
    options: RunOptions,
}

/// The options `run` and `ab` both take.
const RUN_OPTIONS: &[&str] = &[
    "--agent",
    "--model",
    "--agent-arg",
    "--pass-env",
    "--trials",
    "--jobs",
    "--out-root",
];

fn prepare(args: &Args, cwd: &Path) -> Result<Prepared, EvalError> {
    let kind = agent_kind(
        args,
        &[AgentKind::ClaudeCode, AgentKind::Codex, AgentKind::Command],
    )?;
    if kind == AgentKind::Command && args.trailing.is_empty() {
        return Err(EvalError::Usage(
            "--agent command needs the program after --".to_owned(),
        ));
    }
    if kind != AgentKind::Command && !args.trailing.is_empty() {
        return Err(EvalError::Usage(format!(
            "a program after -- is for --agent command, not {}",
            kind.name()
        )));
    }
    let pass_env = args.all("--pass-env");
    crate::agent::check_pass_env(&pass_env)?;
    let root = git::toplevel(cwd)?;
    let paths: Vec<PathBuf> = if args.positionals.is_empty() {
        vec![PathBuf::from(DEFAULT_TASKS)]
    } else {
        args.positionals
            .iter()
            .map(|path| absolute(cwd, path))
            .collect()
    };
    let tasks = task::load_suite(&root, &paths)?;
    let spec = AgentSpec {
        kind,
        model: args.one("--model")?.map(str::to_owned),
        command: args.trailing.clone(),
        extra_args: args.all("--agent-arg"),
        pass_env,
    };
    let agent = agent_for(&spec)?;
    let options = RunOptions {
        out_root: match args.one("--out-root")? {
            Some(dir) => absolute(cwd, dir),
            None => runner::default_out_root(&root)?,
        },
        repo_root: root,
        agent: spec,
        trials: args.number("--trials", 1..=100, 1)?,
        jobs: args.number("--jobs", 1..=16, 1)?,
        keep_worktrees: args.flag("--keep-worktrees"),
        progress: true,
        give_pack: false,
    };
    Ok(Prepared {
        tasks,
        agent,
        options,
    })
}

/// The lines `run` (and each arm of `ab`) prints for a finished run.
fn finished(run: &RunRecord, run_dir: &Path) -> String {
    let summary = run.summary();
    let cost = summary
        .cost_microusd
        .map_or_else(|| "cost n/a".to_owned(), runner::dollars);
    let memory = if run.memory_given.is_some() {
        ", the agent given memprove's Pack"
    } else {
        ""
    };
    format!(
        "run {}: {} of {} trials passed, {cost}{memory}\nrun directory: {}\n",
        run.run_id,
        summary.passed,
        summary.trials,
        run_dir.display(),
    )
}

fn run_command(args: &Args, cwd: &Path, memory: Option<&dyn MemoryProbe>) -> Result<u8, EvalError> {
    let options: Vec<&str> = RUN_OPTIONS.iter().copied().chain(["--memory"]).collect();
    args.allow(
        &options,
        &["--keep-worktrees", "--no-memory"],
        usize::MAX,
        true,
    )?;
    let give_pack = match args.one("--memory")? {
        None | Some("none") => false,
        Some("pack") => true,
        Some(other) => {
            return Err(EvalError::Usage(format!(
                "--memory must be none or pack, not {other:?}"
            )));
        }
    };
    if give_pack && args.flag("--no-memory") {
        return Err(EvalError::Usage(
            "--memory pack gives the agent memprove's memory, and --no-memory reads none"
                .to_owned(),
        ));
    }
    let mut prepared = prepare(args, cwd)?;
    prepared.options.give_pack = give_pack;
    let memory = if args.flag("--no-memory") {
        None
    } else {
        memory
    };
    let (run, run_dir) = runner::run_suite(
        &prepared.options,
        &prepared.tasks,
        prepared.agent.as_ref(),
        memory,
    )?;
    let summary = run.summary();
    println!(
        "{}{}",
        finished(&run, &run_dir),
        runner::libtest_summary(&run)
    );
    Ok(if summary.passed == summary.trials {
        EXIT_OK
    } else {
        EXIT_FAILED
    })
}

fn ab_command(args: &Args, cwd: &Path, memory: Option<&dyn MemoryProbe>) -> Result<u8, EvalError> {
    args.allow(RUN_OPTIONS, &["--keep-worktrees"], usize::MAX, true)?;
    let Some(memory) = memory else {
        return Err(EvalError::invalid(
            None,
            "eval ab compares runs with and without memprove's memory, and this build reads none",
        ));
    };
    let mut prepared = prepare(args, cwd)?;
    // Read once, before any trial: both arms record the same statements,
    // and the second gives the agent the Pack the first did not.
    let read = memory.read(&prepared.options.repo_root).map_err(|reason| {
        EvalError::invalid(
            None,
            format!("eval ab: memprove's memory was not read: {reason}"),
        )
    })?;
    let memory = Fixed(read);
    let without = runner::run_suite(
        &prepared.options,
        &prepared.tasks,
        prepared.agent.as_ref(),
        Some(&memory),
    )?;
    print!("without memory: {}", finished(&without.0, &without.1));
    prepared.options.give_pack = true;
    let with = runner::run_suite(
        &prepared.options,
        &prepared.tasks,
        prepared.agent.as_ref(),
        Some(&memory),
    )?;
    println!("with the Pack: {}", finished(&with.0, &with.1));
    let baseline = Baseline::from_run(&without.0);
    print!(
        "{}",
        report::render(&with.0, Some(&baseline), Format::Markdown)
    );
    Ok(EXIT_OK)
}

/// What a probe read once, given to every run that asks.
struct Fixed(Memory);

impl MemoryProbe for Fixed {
    fn read(&self, _repo_root: &Path) -> Result<Memory, String> {
        Ok(self.0.clone())
    }
}

fn absolute(cwd: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn run_dir(args: &Args, cwd: &Path) -> Result<(PathBuf, PathBuf), EvalError> {
    let root = git::toplevel(cwd)?;
    let dir = match args.positionals.first().map(String::as_str) {
        None | Some("latest") => runner::resolve_run_dir(&runner::default_out_root(&root)?, None)?,
        Some(path) => absolute(cwd, path),
    };
    Ok((root, dir))
}

/// The baseline file at `path`, or the pass counts of the run whose
/// directory `path` is.
fn read_baseline(path: &Path) -> Result<Baseline, EvalError> {
    if path.is_dir() {
        return runner::read_run(path).map(|run| Baseline::from_run(&run));
    }
    let text = fs::read_to_string(path).map_err(|error| EvalError::io(path, error))?;
    Baseline::from_json(&text, Some(path))
}

fn report_command(args: &Args, cwd: &Path) -> Result<u8, EvalError> {
    args.allow(&["--baseline", "--format"], &[], 1, false)?;
    let format = match args.one("--format")? {
        None | Some("markdown") => Format::Markdown,
        Some("json") => Format::Json,
        Some(other) => {
            return Err(EvalError::Usage(format!(
                "--format must be markdown or json, not {other:?}"
            )));
        }
    };
    let (root, dir) = run_dir(args, cwd)?;
    let run = runner::read_run(&dir)?;
    let default = root.join(DEFAULT_BASELINE);
    let baseline = if let Some(path) = args.one("--baseline")? {
        Some(read_baseline(&absolute(cwd, path))?)
    } else if default.is_file() {
        Some(read_baseline(&default)?)
    } else {
        None
    };
    print!("{}", report::render(&run, baseline.as_ref(), format));
    Ok(EXIT_OK)
}

fn baseline_command(args: &Args, cwd: &Path) -> Result<u8, EvalError> {
    args.allow(&["--write"], &[], 1, false)?;
    let (root, dir) = run_dir(args, cwd)?;
    let run = runner::read_run(&dir)?;
    let path = args
        .one("--write")?
        .map_or_else(|| root.join(DEFAULT_BASELINE), |path| absolute(cwd, path));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| EvalError::io(parent, error))?;
    }
    fs::write(&path, Baseline::from_run(&run).to_json())
        .map_err(|error| EvalError::io(&path, error))?;
    let summary = run.summary();
    println!(
        "wrote {} from run {}: {} of {} trials passed",
        path.display(),
        run.run_id,
        summary.passed,
        summary.trials
    );
    Ok(EXIT_OK)
}

fn gate_command(args: &Args, cwd: &Path) -> Result<u8, EvalError> {
    args.allow(
        &["--baseline", "--max-drop"],
        &["--allow-regressions"],
        1,
        false,
    )?;
    let max_drop_permille = match args.one("--max-drop")? {
        None => 0,
        Some(text) => points_to_permille(text).ok_or_else(|| {
            EvalError::Usage(format!(
                "--max-drop must be percentage points with at most one decimal, such as 2.5, not {text:?}"
            ))
        })?,
    };
    let (root, dir) = run_dir(args, cwd)?;
    let run = runner::read_run(&dir)?;
    let path = args
        .one("--baseline")?
        .map_or_else(|| root.join(DEFAULT_BASELINE), |path| absolute(cwd, path));
    let baseline = read_baseline(&path)?;
    let verdict = report::gate(
        &run,
        &baseline,
        &GatePolicy {
            max_drop_permille,
            fail_on_regression: !args.flag("--allow-regressions"),
        },
    );
    if verdict.passed {
        println!(
            "gate: passed (run {} against {})",
            run.run_id,
            path.display()
        );
        Ok(EXIT_OK)
    } else {
        println!(
            "gate: failed (run {} against {})",
            run.run_id,
            path.display()
        );
        for reason in &verdict.reasons {
            println!("  {reason}");
        }
        Ok(EXIT_FAILED)
    }
}

/// `2.5` percentage points as 25 tenths.
fn points_to_permille(text: &str) -> Option<u64> {
    let (whole, tenth) = text.split_once('.').unwrap_or((text, "0"));
    if whole.is_empty()
        || tenth.len() != 1
        || !whole
            .bytes()
            .chain(tenth.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let value = whole
        .parse::<u64>()
        .ok()?
        .checked_mul(10)?
        .checked_add(tenth.parse::<u64>().ok()?)?;
    (value <= 1000).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parses_options_flags_and_the_trailing_command() {
        let args = Args::parse(&words(
            "evals/a.json --agent command --trials=3 --no-memory -- ./agent {prompt_file} --x",
        ))
        .expect("parses");
        assert_eq!(args.positionals, ["evals/a.json"]);
        assert_eq!(args.one("--agent").expect("one"), Some("command"));
        assert_eq!(args.number("--trials", 1..=100, 1).expect("number"), 3);
        assert!(args.flag("--no-memory"));
        assert_eq!(args.trailing, ["./agent", "{prompt_file}", "--x"]);
        let error = Args::parse(&words("--model")).expect_err("no value");
        assert_eq!(error.to_string(), "--model needs a value");
        let twice = Args::parse(&words("--agent codex --agent command")).expect("parses");
        assert!(twice.one("--agent").is_err());
        let args = Args::parse(&words("--trials 0")).expect("parses");
        assert!(args.number("--trials", 1..=100, 1).is_err());
    }

    #[test]
    fn max_drop_takes_points_with_one_decimal() {
        assert_eq!(points_to_permille("0"), Some(0));
        assert_eq!(points_to_permille("2.5"), Some(25));
        assert_eq!(points_to_permille("100"), Some(1000));
        for bad in ["", "2.55", "-1", "1e2", "101", ".5", "x"] {
            assert_eq!(points_to_permille(bad), None, "{bad}");
        }
    }

    #[test]
    fn every_command_has_help_with_usage_and_exit_status() {
        for entry in HELP {
            let text = help_of(entry);
            assert!(text.starts_with(&format!("memprove eval {}: ", entry.name)));
            assert!(text.contains("\nUsage:\n"));
            assert!(text.contains("\nExit status:\n  0 "));
            assert!(
                USAGE.contains(&format!("memprove eval {}", entry.name)),
                "{}",
                entry.name
            );
        }
    }
}
