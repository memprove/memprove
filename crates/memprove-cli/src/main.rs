//! `memprove` CLI entrypoint: one subcommand per Local Control API operation,
//! plus `run`, which runs a command here and submits its result, and `begin`
//! and `end`, which keep the current context of a Workspace (P2-D1), with
//! `task complete` and `context show` on top of it (P2-H), and `decide`
//! (ADR 0013 D2, P3-C).

#![forbid(unsafe_code)]

use std::{
    io::Write,
    path::Path,
    process::ExitCode,
    sync::mpsc::{self, RecvTimeoutError},
};

use memprove_cli::{
    BeginSpec, CapsuleView, DATA_DIR_ENV, Follow, HookCommand, HookStart, Invocation, McpCommand,
    Reply, Request, TOKEN_ENV, TOKEN_FILE_ENV, USAGE, VERSION_LINE, claims,
    context::{
        CLIENT_SESSION_ENV, CONFIG_DIR_ENV, ContextLookup, ContextStore, argv_digest,
        client_session_of, workspace_root,
    },
    flow::{
        self, BeginRequest, BeginStop, Daemon, DraftStop, Failed, Resolved, Saver, Socket, Unmoved,
        keyed, member, number,
    },
    help, hook, hook_session_start_requested, import, mcp, mcp_requested, mcp_serve_config_dir,
    parse_args_deferring, preview, resolve_token, resume, run, usage_hint,
};
use memprove_domain::PackError;
use memprove_protocol::{
    phase1::OperationId,
    strict_json::{JsonValue, parse_strict},
};

/// `run`'s exit code when the command could not be started or its result
/// could not be recorded.
const RUN_FAILED: u8 = 125;

/// The commands that never reach the parser. P4-E (Owner condition o): the
/// `SessionStart` hook exits 0 whatever happens, so it never meets the
/// parser's usage errors. U7 P2 (Owner O4): `mcp serve --config-dir <DIR>`
/// serves with that configuration directory, whatever
/// `MEMPROVE_CONFIG_DIR` says. `None` for every other command.
fn before_the_parser(args: &[std::ffi::OsString]) -> Option<ExitCode> {
    if let Some(start) = hook_session_start_requested(args) {
        hook_session_start(start);
    }
    let config_dir = mcp_serve_config_dir(args)?;
    mcp::run_stdio_with(Some(config_dir));
    Some(ExitCode::SUCCESS)
}

/// U23: `memprove eval ...` is parsed and run by the `memprove-eval` crate,
/// which reads no token and calls no daemon itself; the CLI gives it the
/// memory memprove would give an agent (read-only). `None` for every other
/// command.
fn eval(args: &[std::ffi::OsString]) -> Option<ExitCode> {
    let (first, rest) = args.split_first()?;
    if first != "eval" {
        return None;
    }
    let words: Vec<String> = rest
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect();
    let memory = memprove_cli::eval_memory::DaemonMemory;
    Some(ExitCode::from(memprove_eval::cli::main(
        &words,
        Some(&memory),
    )))
}

/// `memprove verify ...` is parsed and run by the `memprove-verify` crate,
/// which reads no token and calls no daemon: it runs the repository's own
/// checks on a clean copy of the work and writes a receipt. `None` for
/// every other command.
fn verify(args: &[std::ffi::OsString]) -> Option<ExitCode> {
    let (first, rest) = args.split_first()?;
    if first != "verify" {
        return None;
    }
    let words: Vec<String> = rest
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect();
    Some(ExitCode::from(memprove_verify::cli::main(&words)))
}

/// U24 (I1): `memprove import ...`, read here; the parser answers only
/// `import --help`. `None` for every other command.
fn import(args: &[std::ffi::OsString]) -> Option<ExitCode> {
    let (globals, rest) = import::requested(args)?;
    if rest.iter().any(|word| word == "--help" || word == "-h") {
        return None;
    }
    let mut words = globals;
    words.extend(rest.iter().cloned());
    Some(import_statements(&words))
}

/// How many characters of a statement the listing of `import` shows.
const IMPORT_LISTING_WIDTH: usize = 100;

/// A usage error of `import`: exit 2.
fn import_usage(error: &str) -> ExitCode {
    eprintln!("memprove: error: {error}\nmemprove: see `memprove import --help`");
    ExitCode::from(2)
}

/// U24 (I1): lists the statements of the sources; with `--select`, records
/// the selected ones.
fn import_statements(rest: &[std::ffi::OsString]) -> ExitCode {
    let spec = match import::parse_args(rest) {
        Ok(spec) => spec,
        Err(error) => return import_usage(&error),
    };
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => {
            eprintln!("memprove: error: the current directory cannot be read: {error}");
            return ExitCode::from(1);
        }
    };
    let root = workspace_root(&cwd).unwrap_or_else(|_| cwd.clone());
    let sources = if spec.files.is_empty() {
        let claude = import::claude_config_dir(
            std::env::var_os("CLAUDE_CONFIG_DIR"),
            std::env::var_os("HOME"),
        );
        import::default_sources(&root, claude.as_deref())
    } else {
        import::given_sources(&spec.files, &cwd, &root)
    };
    let found = import::collect(&sources);
    for (name, error) in &found.unreadable {
        eprintln!("memprove: error: {name} cannot be read: {error}");
    }
    if !found.unreadable.is_empty() {
        return ExitCode::from(1);
    }
    for passed in &found.passed {
        eprintln!(
            "memprove: {}:{} is not imported: {}",
            passed.source, passed.line, passed.reason
        );
    }
    if found.candidates.is_empty() {
        if found.read.is_empty() {
            eprintln!(
                "memprove: nothing to import: this repository has none of {}, {}/, and \
                 Claude Code's auto-memory",
                import::DEFAULT_FILES.join(", "),
                import::CURSOR_RULES_DIR
            );
        } else {
            eprintln!(
                "memprove: nothing to import: {} hold no statement",
                found.read.join(", ")
            );
        }
        return ExitCode::SUCCESS;
    }
    let Some(select) = spec.select.as_deref() else {
        for (index, candidate) in found.candidates.iter().enumerate() {
            println!(
                "{}",
                import::listing_line(index + 1, candidate, IMPORT_LISTING_WIDTH)
            );
        }
        eprintln!(
            "memprove: {} in {}; nothing was recorded. `memprove import --select all` (or \
             --select 1,3-5) records them as open items of the current Session, each marked \
             imported and not verified",
            import::count(found.candidates.len(), "statement"),
            found.read.join(", ")
        );
        return ExitCode::SUCCESS;
    };
    let chosen: Vec<&import::Candidate> = match import::selection(select, found.candidates.len()) {
        Ok(indexes) => indexes
            .iter()
            .map(|index| &found.candidates[*index])
            .collect(),
        Err(error) => return import_usage(&error),
    };
    record_imported(&chosen, &spec)
}

/// The arguments of the `checkpoint create` that records `items`, after the
/// global options `globals`.
fn import_checkpoint(
    globals: &[std::ffi::OsString],
    items: &[&import::Candidate],
    next: &str,
) -> Vec<std::ffi::OsString> {
    let mut args = globals.to_vec();
    args.extend(["checkpoint".into(), "create".into()]);
    for item in items {
        args.push("--open".into());
        args.push(item.recorded().into());
    }
    args.push("--next".into());
    args.push(next.into());
    args
}

/// U24 (I1): the claims of the Task Capsule of the Task the `checkpoint
/// create` of `invocation` writes to, read with its socket and token; the
/// exit code when they cannot be read.
fn imported_task_claims(invocation: &Invocation) -> Result<claims::CapsuleClaims, ExitCode> {
    let Invocation::Call {
        socket,
        token_file,
        request,
        ..
    } = invocation
    else {
        unreachable!("checkpoint create is a call");
    };
    let Some(task_id) = request
        .pending
        .as_ref()
        .map(|draft| draft.task_id().to_owned())
        .or_else(|| {
            request
                .body
                .as_deref()
                .and_then(|body| member(body, &["task_id"]))
        })
    else {
        unreachable!("checkpoint create with flags names its Task");
    };
    let token = match token_of(token_file.as_deref()) {
        Ok(token) => token,
        Err(error) => {
            eprintln!("memprove: error: {error}");
            return Err(ExitCode::from(2));
        }
    };
    let daemon = Socket {
        socket,
        token: token.as_deref(),
    };
    let capsule = Request::bare(
        OperationId::GetTaskCapsule,
        format!("/v1/tasks/{task_id}/recovery-capsule"),
    );
    let claims = match daemon.exchange(&capsule) {
        Ok(reply) => match claims::CapsuleClaims::from_body(&reply.body) {
            Ok(claims) => claims,
            Err(error) => {
                eprintln!("memprove: error: {error}; nothing was sent");
                return Err(ExitCode::from(1));
            }
        },
        Err(failed) => return Err(ExitCode::from(failed.code())),
    };
    Ok(claims)
}

/// U24 (I1): records `chosen` by one `checkpoint create` of the current
/// context, without the statements in force already as imported open
/// items; `--next` defaults to the next action in force. With `--dry-run`,
/// prints the open items instead and sends nothing.
fn record_imported(chosen: &[&import::Candidate], spec: &import::ImportSpec) -> ExitCode {
    let (store, lookup) = startup_context();
    // The Task, socket, and token of the current context, as
    // `checkpoint create` resolves them.
    let next = spec.next.as_deref();
    let probe = import_checkpoint(&spec.globals, chosen, next.unwrap_or("-"));
    let invocation = match parse(&probe, store.as_ref(), &lookup) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!(
                "memprove: error: {error}\nmemprove: `import --select` records open items in the \
                 current Session, as `checkpoint create` does; run `memprove begin` and \
                 `memprove run` first"
            );
            return ExitCode::from(2);
        }
    };
    let claims = match imported_task_claims(&invocation) {
        Ok(claims) => claims,
        Err(code) => return code,
    };
    let open_items = claims.open_items_in_force();
    let (known, new): (Vec<&import::Candidate>, Vec<&import::Candidate>) = chosen
        .iter()
        .copied()
        .partition(|candidate| candidate.in_force(&open_items));
    for item in &known {
        eprintln!(
            "memprove: {}:{} is in force already as an imported open item; it is left out",
            item.source, item.line
        );
    }
    if new.is_empty() {
        eprintln!(
            "memprove: nothing to import: every selected statement is in force already; \
             nothing was sent"
        );
        return ExitCode::SUCCESS;
    }
    let Some(next) = next.or_else(|| claims.next_action_in_force()) else {
        return import_usage(
            "the Task has no next action in force; give --next <TEXT>, the next action the \
             Checkpoint records with the imported open items",
        );
    };
    if spec.dry_run {
        for item in &new {
            println!("{}", item.recorded());
        }
        eprintln!(
            "memprove: --dry-run: nothing was sent; without it one Checkpoint of the current \
             Session records {}, with the next action {next:?}",
            import::count(new.len(), "open item")
        );
        return ExitCode::SUCCESS;
    }
    eprintln!(
        "memprove: importing {} as open items, not verified",
        import::count(new.len(), "statement")
    );
    let args = import_checkpoint(&spec.globals, &new, next);
    match parse(&args, store.as_ref(), &lookup) {
        Ok(invocation) => dispatch(invocation, store.as_ref(), &lookup, &args),
        Err(error) => {
            eprintln!("memprove: error: {error}");
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if let Some(code) = before_the_parser(&args) {
        return code;
    }
    if let Some(code) = eval(&args).or_else(|| verify(&args)) {
        return code;
    }
    if let Some(code) = import(&args) {
        return code;
    }
    // P4-G (ADR 0014 E7.3): an `mcp` command reads no context and warns
    // about nothing at startup; `mcp serve` does both per tool call.
    let (store, lookup) = if mcp_requested(&args) {
        (None, ContextLookup::Unavailable)
    } else {
        startup_context()
    };
    let invocation = match parse(&args, store.as_ref(), &lookup) {
        Ok(invocation) => invocation,
        Err(error) => {
            // P3-L L9: the error, then which `--help` to read; not the
            // general usage.
            eprintln!("memprove: error: {error}\n{}", usage_hint(&args));
            return ExitCode::from(2);
        }
    };
    dispatch(invocation, store.as_ref(), &lookup, &args)
}

/// Runs a parsed command line (`args`, for its usage hints).
fn dispatch(
    invocation: Invocation,
    store: Option<&ContextStore>,
    lookup: &ContextLookup,
    args: &[std::ffi::OsString],
) -> ExitCode {
    let (socket, token_file) = match &invocation {
        Invocation::Help => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Invocation::Version => {
            println!("{VERSION_LINE}");
            return ExitCode::SUCCESS;
        }
        Invocation::Doctor(spec) => return doctor(spec, store, lookup),
        Invocation::Init(spec) => return init(spec, store, lookup),
        Invocation::Backup { data_dir, out } => {
            return offline("backup", out, memprove_cli::backup::backup(data_dir, out));
        }
        Invocation::Restore { from, data_dir } => {
            return offline(
                "restore",
                data_dir,
                memprove_cli::backup::restore(from, data_dir),
            );
        }
        Invocation::CommandHelp(entries) => {
            print!("{}", help::render(entries));
            return ExitCode::SUCCESS;
        }
        Invocation::ShowContext(context) => {
            println!("{}", context.describe());
            return ExitCode::SUCCESS;
        }
        Invocation::Hook(command) => return hook_config(*command),
        // P4-G (ADR 0014 E7.3): no token, no context, no daemon at startup;
        // every tool call reads them. Always exits 0.
        Invocation::Mcp(McpCommand::Serve) => {
            mcp::run_stdio();
            return ExitCode::SUCCESS;
        }
        Invocation::Mcp(McpCommand::PrintConfig) => return mcp_config(),
        Invocation::Call {
            socket, token_file, ..
        }
        | Invocation::Run {
            socket, token_file, ..
        }
        | Invocation::Begin {
            socket, token_file, ..
        } => (socket.clone(), token_file.clone()),
    };
    let token = match token_of(token_file.as_deref()) {
        Ok(token) => token,
        Err(error) => {
            eprintln!("memprove: error: {error}");
            return ExitCode::from(2);
        }
    };
    if let Some(code) = refuse_before_sending(&invocation, token.as_deref(), args) {
        return code;
    }
    let saver = Saver { store, lookup };
    match invocation {
        Invocation::Call {
            request, follow, ..
        } => call(&socket, request, token.as_deref(), &follow, &saver, args),
        Invocation::Run { spec, .. } => run_and_record(&socket, &spec, token.as_deref(), &saver),
        Invocation::Begin { spec, .. } => begin(&socket, &spec, token.as_deref(), &saver),
        Invocation::Help
        | Invocation::Version
        | Invocation::Doctor(_)
        | Invocation::Init(_)
        | Invocation::Backup { .. }
        | Invocation::Restore { .. }
        | Invocation::CommandHelp(_)
        | Invocation::ShowContext(_)
        | Invocation::Hook(_)
        | Invocation::Mcp(_) => {
            unreachable!("returned above")
        }
    }
}

/// U6 K1 and K3: the refusals that come once the token is known and before
/// anything is sent: no token for a command that needs one, and a query that
/// holds the token.
fn refuse_before_sending(
    invocation: &Invocation,
    token: Option<&str>,
    args: &[std::ffi::OsString],
) -> Option<ExitCode> {
    match token {
        None => refuse_without_token(invocation),
        Some(token) => refuse_held_token_in_query(invocation, token, args),
    }
}

/// U6 K1 (U5 ZR1): a command that needs a token and has none says where it
/// looked and sends nothing, instead of taking the daemon's bare 401. The
/// exit code is the one that 401 gave: `1`, and [`RUN_FAILED`] for `run`
/// (which does not run its command either).
fn refuse_without_token(invocation: &Invocation) -> Option<ExitCode> {
    if !needs_token(invocation) {
        return None;
    }
    let config = configuration_dir();
    eprintln!(
        "memprove: error: {}",
        hook::missing_token(
            config
                .as_ref()
                .map(|(dir, source)| (dir.as_path(), *source))
        )
    );
    Some(ExitCode::from(match invocation {
        Invocation::Run { .. } => RUN_FAILED,
        _ => 1,
    }))
}

/// U6 K3 (U5 N4): a `resume --pack --query` whose query holds the whole
/// token this process holds is refused as a query in the token format is, a
/// usage error (exit 2), before anything is sent.
fn refuse_held_token_in_query(
    invocation: &Invocation,
    token: &str,
    args: &[std::ffi::OsString],
) -> Option<ExitCode> {
    let Invocation::Call { request, .. } = invocation else {
        return None;
    };
    let CapsuleView::PackQuery { query, .. } = &request.capsule_view else {
        return None;
    };
    let error = memprove_cli::query_holding_token(query, token)?;
    eprintln!("memprove: error: {error}\n{}", usage_hint(args));
    Some(ExitCode::from(2))
}

/// U6 K1: whether the command sends a request that the daemon answers only
/// to a token: every one that reaches the daemon but the two health
/// operations, which are anonymous.
fn needs_token(invocation: &Invocation) -> bool {
    match invocation {
        Invocation::Call { request, .. } => !matches!(
            request.operation,
            OperationId::HealthLive | OperationId::HealthReady
        ),
        Invocation::Run { .. } | Invocation::Begin { .. } => true,
        _ => false,
    }
}

/// The token of a command that reaches the daemon: `--token-file`, else
/// `MEMPROVE_TOKEN`, else the file `MEMPROVE_TOKEN_FILE` names; U5 Z-F
/// round 1 (S2): else the token of `<config>/token`, as the hook and the
/// server read it; else none.
fn token_of(token_file: Option<&Path>) -> Result<Option<String>, memprove_cli::TokenSourceError> {
    resolve_token(
        token_file,
        std::env::var_os(TOKEN_ENV),
        std::env::var_os(TOKEN_FILE_ENV),
    )
    .and_then(|token| match (token, configuration_dir()) {
        (None, Some((config, _))) => hook::configured_token(&config),
        (token, _) => Ok(token),
    })
}

/// Sends the request of a call. U4 (Y1, N-3): a mistake in the Evidence of
/// `task complete` was kept aside by the parser; the Session check, which
/// reads the context's Session, comes first, and the kept mistake is
/// printed (exit 2) only when that check lets the command go on.
fn call(
    socket: &Path,
    request: Request,
    token: Option<&str>,
    follow: &Follow,
    saver: &Saver<'_>,
    args: &[std::ffi::OsString],
) -> ExitCode {
    if let Follow::TaskCompleted {
        refusal: Some(error),
        ..
    } = follow
    {
        let daemon = Socket { socket, token };
        if let Some(code) = refuse_inactive_session(&daemon, saver) {
            return code;
        }
        eprintln!("memprove: error: {error}\n{}", usage_hint(args));
        return ExitCode::from(2);
    }
    send(socket, request, token, follow, saver)
}

/// The arguments, with the context of the working directory and (U2, H1,
/// Owner O5) the Project of this client session's last-Pack record, which
/// only `begin` asks for.
fn parse(
    args: &[std::ffi::OsString],
    store: Option<&ContextStore>,
    lookup: &ContextLookup,
) -> Result<Invocation, memprove_cli::UsageError> {
    let recorded_project = || {
        store
            .zip(std::env::current_dir().ok())
            .and_then(|(store, cwd)| store.recorded_project_near(&cwd))
    };
    // U11 N4 (U10 VN14): the Project of the contexts of this Workspace root,
    // which `task list` takes when the current context names none.
    let root_project = || {
        store
            .zip(std::env::current_dir().ok())
            .and_then(|(store, cwd)| flow::project_of_root(store, &cwd))
    };
    // U5 Z-F round 1 (S2): the daemon's location from <config>/data-dir
    // when no option and no MEMPROVE_DATA_DIR names it.
    let configured = || {
        let config = configuration_dir();
        hook::configured_location(
            config
                .as_ref()
                .map(|(dir, source)| (dir.as_path(), *source)),
        )
    };
    parse_args_deferring(
        args.to_vec(),
        std::env::var_os(DATA_DIR_ENV),
        lookup,
        &recorded_project,
        &configured,
        // U8 A3 (Owner O4): the defaults of the agent options.
        &memprove_cli::AgentEnv::of(
            std::env::var_os(memprove_cli::AGENT_NAME_ENV),
            std::env::var_os(memprove_cli::AGENT_ROLE_ENV),
            std::env::var_os(memprove_cli::PARENT_SESSION_ENV),
        ),
        &root_project,
    )
}

/// U17 (M1 O4): what `memprove init` resolved before its first step.
struct InitPlan {
    root: std::path::PathBuf,
    config: std::path::PathBuf,
    config_text: String,
    source: &'static str,
    executable: String,
    home: Option<std::path::PathBuf>,
    clients: Vec<memprove_cli::init::Client>,
    dry_run: bool,
    /// U22 (Owner, 2026-11-11): write Claude Code's allow rules, else only
    /// print them.
    allow_tools: bool,
}

impl InitPlan {
    /// Resolves the repository, the configuration directory, the executable,
    /// and the clients, and prints the heading lines.
    fn resolve(spec: &memprove_cli::init::InitSpec) -> Result<Self, String> {
        use memprove_cli::init;
        let cwd = std::env::current_dir()
            .map_err(|error| format!("cannot resolve the current directory: {error}"))?;
        let root = workspace_root(&cwd).map_err(|error| {
            format!(
                "the current directory is not inside a Git worktree ({error}); init runs in the \
                 repository to enable"
            )
        })?;
        let (config, source) = configuration_dir().ok_or_else(|| {
            "no configuration directory: scripts/install.sh makes ~/.memprove/config; with \
             another --prefix, set MEMPROVE_CONFIG_DIR to its config/ directory"
                .to_owned()
        })?;
        let config_text = config
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| "the configuration directory is not UTF-8".to_owned())?;
        let executable = hook::executable()?;
        let home = std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(std::path::PathBuf::from);
        let clients = if spec.clients.is_empty() {
            init::detect_clients(
                home.as_deref(),
                std::env::var_os("CODEX_HOME").as_deref(),
                std::env::var_os("PATH").as_deref(),
            )
        } else {
            spec.clients.clone()
        };
        let dry = if spec.dry_run { " (dry run)" } else { "" };
        println!("memprove init{dry}: {}", root.display());
        println!(
            "configuration directory: {} (from {source})",
            config.display()
        );
        if clients.is_empty() {
            println!(
                "clients: none detected; --client claude-code, --client codex, or --client cursor \
                 names one"
            );
        } else {
            let names: Vec<&str> = clients.iter().map(|client| client.name()).collect();
            println!("clients: {}", names.join(", "));
        }
        Ok(Self {
            root,
            config,
            config_text,
            source,
            executable,
            home,
            clients,
            dry_run: spec.dry_run,
            allow_tools: spec.allow_tools,
        })
    }

    /// Step 1: the Project, registered with the operator's token.
    fn register(&self, operator_token: Option<&std::path::Path>) -> Result<(), ExitCode> {
        use memprove_cli::init;
        let fail = |error: String| {
            eprintln!("memprove: error: {error}");
            ExitCode::from(1)
        };
        let operator = operator_token.map_or_else(
            || init::installed_operator_token(&self.config),
            std::path::Path::to_path_buf,
        );
        let data_dir =
            hook::configured_location(Some((&self.config, self.source))).map_err(fail)?;
        let socket = data_dir.join(memprove_cli::SOCKET_FILE_NAME);
        let root_text = self
            .root
            .to_str()
            .ok_or_else(|| fail("the repository path is not UTF-8".to_owned()))?;
        let mut request =
            Request::bare(OperationId::RegisterProject, "/v1/projects/register".into());
        request.body = Some(format!(
            r#"{{"schema_version":1,"root":{}}}"#,
            memprove_cli::json_string(root_text)
        ));
        if self.dry_run {
            println!(
                "would register the Project of {} with the operator's token {}",
                self.root.display(),
                operator.display()
            );
            return Ok(());
        }
        let token = match resolve_token(Some(&operator), None, None) {
            Ok(Some(token)) => token,
            Ok(None) => return Err(fail(format!("{} holds no token", operator.display()))),
            Err(error) => {
                return Err(fail(format!(
                    "the operator's token: {error}; --operator-token <FILE> names its file"
                )));
            }
        };
        let request = keyed(request).map_err(fail)?;
        let daemon = Socket {
            socket: &socket,
            token: Some(&token),
        };
        let reply = daemon
            .exchange(&request)
            .map_err(|failed| ExitCode::from(failed.code()))?;
        let registered = parse_strict(&reply.body).ok().and_then(|body| {
            body.get("project_id")
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
        });
        let project = registered
            .clone()
            .unwrap_or_else(|| "(id not in the reply)".to_owned());
        println!("Project {project} registered for {}", self.root.display());
        // U22 (the final check before publishing): the first `begin` here
        // takes this Project without --project, from the directory's record
        // of the Workspace root, written unless a record is there already
        // (one of a Pack names its Project too).
        if let Some(project) = registered {
            let store = ContextStore {
                config_dir: self.config.clone(),
                client_session: None,
            };
            if std::fs::symlink_metadata(store.last_pack_path(&self.root)).is_err() {
                match store.save_no_pack(&self.root, Some(&project)) {
                    Ok(path) => println!(
                        "{} written (the Project for the first `memprove begin` here)",
                        path.display()
                    ),
                    Err(error) => {
                        return Err(fail(format!(
                            "the Project could not be recorded for `memprove begin`: {error}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Step 2: memprove's files stay out of Evidence.
    fn exclude(&self) -> Result<memprove_cli::init::Step, String> {
        use memprove_cli::init;
        let exclude = std::process::Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["rev-parse", "--git-path", "info/exclude"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|path| self.root.join(path.trim_end()))
            .ok_or_else(|| {
                "git rev-parse --git-path info/exclude failed in the repository".to_owned()
            })?;
        let entries = init::exclude_entries(&self.clients);
        init::edit_text(&exclude, false, self.dry_run, |existing| {
            init::exclude_with(existing, &entries)
        })
    }

    /// Step 3: Claude Code: the hook, .mcp.json, and the allow rules.
    fn claude_code(&self) -> Result<Vec<memprove_cli::init::Step>, String> {
        use memprove_cli::init::Step;
        let settings = hook::settings_path(&self.root)?;
        let mcp_json = mcp::config_path(&self.root)?;
        if self.dry_run {
            return Ok(vec![Step::WouldWrite(settings), Step::WouldWrite(mcp_json)]);
        }
        let changes = hook::install(
            &settings,
            &mcp_json,
            &self.executable,
            &self.config_text,
            self.allow_tools,
        )?;
        let mut steps: Vec<Step> = changes.into_iter().map(step_of).collect();
        if !self.allow_tools {
            // U22 (Owner, 2026-11-11): the rules are the operator's to
            // write; init names them.
            let [mcp, bash, absolute] = hook::allow_rules(&self.executable);
            steps.push(Step::Note(format!(
                "permissions.allow was left as it is; the rules an unattended `claude -p` needs \
                 are \"{mcp}\", \"{bash}\", and \"{absolute}\"; `memprove init --allow-tools` \
                 adds them"
            )));
        }
        Ok(steps)
    }

    /// Step 4: Codex: the server in `$CODEX_HOME/config.toml` (else
    /// `~/.codex/config.toml`), the note in AGENTS.md.
    fn codex(&self) -> Result<Vec<memprove_cli::init::Step>, String> {
        use memprove_cli::init;
        let codex_home = init::codex_home_dir(
            self.home.as_deref(),
            std::env::var_os("CODEX_HOME").as_deref(),
        )
        .ok_or_else(|| {
            "neither CODEX_HOME nor HOME is set, so Codex's config.toml cannot be found".to_owned()
        })?;
        let config_toml = codex_home.join("config.toml");
        let server = init::edit_text(&config_toml, true, self.dry_run, |existing| {
            init::codex_config_with(existing, &self.executable, &self.config_text)
        })?;
        // U24 (H1): the SessionStart hook in the project's .codex/hooks.json.
        let hooks_file = self.root.join(hook::CODEX_HOOKS_FILE);
        let hooks = if self.dry_run {
            init::Step::WouldWrite(hooks_file)
        } else {
            step_of(hook::install_codex_hooks(
                &hooks_file,
                &self.executable,
                &self.config_text,
            )?)
        };
        let hooks_written = matches!(hooks, init::Step::Written(_));
        let note = init::edit_text(
            &self.root.join("AGENTS.md"),
            false,
            self.dry_run,
            init::agents_with_note,
        )?;
        let mut steps = vec![server, hooks];
        if hooks_written {
            steps.push(init::Step::Note(init::CODEX_TRUST_NOTE.to_owned()));
        }
        let written = matches!(note, init::Step::Written(_));
        steps.push(note);
        if written {
            steps.push(init::Step::Note(init::AGENTS_COMMIT_NOTE.to_owned()));
        }
        Ok(steps)
    }

    /// Step 5: Cursor: the server in .cursor/mcp.json, the note as a rule.
    fn cursor(&self) -> Result<Vec<memprove_cli::init::Step>, String> {
        use memprove_cli::init::{self, Step};
        let mcp_json = self.root.join(".cursor").join("mcp.json");
        let server = if self.dry_run {
            Step::WouldWrite(mcp_json)
        } else {
            step_of(hook::install_mcp_json(
                &mcp_json,
                &self.executable,
                &self.config_text,
            )?)
        };
        // U24 (H2): the sessionStart hook in .cursor/hooks.json.
        let hooks_file = self.root.join(hook::CURSOR_HOOKS_FILE);
        let hooks = if self.dry_run {
            Step::WouldWrite(hooks_file)
        } else {
            step_of(hook::install_cursor_hooks(
                &hooks_file,
                &self.executable,
                &self.config_text,
            )?)
        };
        let rule = init::cursor_rule();
        let note = init::edit_text(
            &self.root.join(".cursor").join("rules").join("memprove.mdc"),
            false,
            self.dry_run,
            |existing| (existing != Some(rule.as_str())).then(|| rule.clone()),
        )?;
        let mut steps = vec![server, hooks, note];
        // U22 (U20-N1): the rule init wrote under the previous name.
        steps.extend(init::remove_previous_cursor_rule(
            &self
                .root
                .join(".cursor")
                .join("rules")
                .join(init::PREVIOUS_CURSOR_RULE_FILE),
            self.dry_run,
        )?);
        Ok(steps)
    }
}

/// One client's writes in `init`: its steps, or the error that ended it.
type InitWrite = fn(&InitPlan) -> Result<Vec<memprove_cli::init::Step>, String>;

/// A hook installer's change as an `init` step.
fn step_of(change: hook::Change) -> memprove_cli::init::Step {
    use memprove_cli::init::Step;
    match change {
        hook::Change::Written(path) => Step::Written(path),
        hook::Change::Unchanged(path) => Step::Unchanged(path),
    }
}

/// U17 (M1 O4): `memprove init`: enables memprove in the repository of
/// the current directory in one command, then prints `doctor`'s report.
/// Every step says what it did; a step that fails ends the command (exit
/// 1) with the steps before it done.
fn init(
    spec: &memprove_cli::init::InitSpec,
    store: Option<&ContextStore>,
    lookup: &ContextLookup,
) -> ExitCode {
    use memprove_cli::init::Client;
    let fail = |error: String| {
        eprintln!("memprove: error: {error}");
        ExitCode::from(1)
    };
    let plan = match InitPlan::resolve(spec) {
        Ok(plan) => plan,
        Err(error) => return fail(error),
    };
    if let Err(code) = plan.register(spec.operator_token.as_deref()) {
        return code;
    }
    match plan.exclude() {
        Ok(step) => println!("{step}"),
        Err(error) => return fail(error),
    }
    let clients: [(Client, InitWrite); 3] = [
        (Client::ClaudeCode, InitPlan::claude_code),
        (Client::Codex, InitPlan::codex),
        (Client::Cursor, InitPlan::cursor),
    ];
    for (client, write) in clients {
        if !plan.clients.contains(&client) {
            continue;
        }
        match write(&plan) {
            Ok(steps) => {
                for step in steps {
                    println!("{step}");
                }
            }
            Err(error) => return fail(error),
        }
    }

    // 6. The check.
    if plan.dry_run {
        println!("doctor is not run in a dry run");
        return ExitCode::SUCCESS;
    }
    println!("doctor:");
    let report = doctor(
        &memprove_cli::doctor::DoctorSpec {
            data_dir: None,
            socket: None,
            token_file: None,
            json: false,
        },
        store,
        lookup,
    );
    println!(
        "next: memprove begin --new-task \"<TITLE>\" in this repository starts the first \
         Session; the agent's token and the daemon are found through {}",
        plan.config.display()
    );
    report
}

/// U1 (E3): `memprove doctor`: the report on standard output; exit 1
/// when a check failed.
fn doctor(
    spec: &memprove_cli::doctor::DoctorSpec,
    store: Option<&ContextStore>,
    lookup: &ContextLookup,
) -> ExitCode {
    use memprove_cli::doctor;
    let environment = doctor::Environment {
        token: std::env::var_os(TOKEN_ENV),
        token_file: std::env::var_os(TOKEN_FILE_ENV),
        cwd: std::env::current_dir().ok(),
        store: store.cloned(),
        lookup: lookup.clone(),
        config: configuration_dir(),
        executable: hook::executable().ok().map(std::path::PathBuf::from),
        path: std::env::var_os("PATH"),
    };
    let checks = doctor::run(spec, &environment);
    let report = if spec.json {
        doctor::render_json(&checks)
    } else {
        doctor::render_text(&checks)
    };
    print!("{report}");
    if doctor::failed(&checks) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// U1 (E4): the outcome of `backup` or `restore`: the counts on standard
/// output, or why it was refused on standard error (exit 1).
fn offline(
    command: &str,
    written: &Path,
    outcome: Result<memprove_cli::backup::Copied, String>,
) -> ExitCode {
    match outcome {
        Ok(copied) => {
            println!(
                "{command}: {} files and {} directories ({} bytes) written to {}",
                copied.files,
                copied.directories,
                copied.bytes,
                written.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("memprove: {command}: {error}");
            ExitCode::from(1)
        }
    }
}

/// The context store and the context of the working directory, read once
/// at startup. P4-E (ADR 0014 E5, Owner conditions j and k): one context
/// per client session; an invalid value is ignored, never shown.
fn startup_context() -> (Option<ContextStore>, ContextLookup) {
    let client = client_session_of(std::env::var_os(CLIENT_SESSION_ENV)).unwrap_or_else(|_| {
        eprintln!(
            "memprove: warning: {CLIENT_SESSION_ENV} is not 1 to 128 characters of A-Z, a-z, \
             0-9, _, and -; it is ignored, and the context of this directory is used"
        );
        None
    });
    let store = ContextStore::from_env(
        std::env::var_os(CONFIG_DIR_ENV),
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
    .map(|store| store.for_client(client.as_deref()));
    let lookup = match (&store, std::env::current_dir()) {
        (Some(store), Ok(cwd)) => store.lookup(&cwd),
        _ => ContextLookup::Unavailable,
    };
    (store, lookup)
}

/// P4-E: `memprove hook session-start`. The work runs on its own thread;
/// this one prints what it decided, or a statement when it did not decide
/// within [`hook::TIME_LIMIT`] or failed, and exits 0 in every case (Owner
/// condition o), ending that thread with the process.
fn hook_session_start(start: HookStart) -> ! {
    // U24 (H2): Cursor reads the answer as JSON, whatever it says.
    let cursor = matches!(start, HookStart::Cursor(_));
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let outcome = match start {
            // U7 P2 (Owner O4): --config-dir wins over MEMPROVE_CONFIG_DIR.
            HookStart::Run(config_dir) => hook::session_start(
                &mut std::io::stdin().lock(),
                &hook::Environment::from_process().with_config_dir(config_dir),
            ),
            HookStart::Cursor(config_dir) => hook::cursor_session_start(
                &mut std::io::stdin().lock(),
                &hook::Environment::from_process().with_config_dir(config_dir),
                std::env::var_os("CURSOR_PROJECT_DIR").as_deref(),
            ),
            HookStart::Refused(refusal) => {
                hook::Outcome::from_statement(hook::refusal_statement(refusal))
            }
        };
        let _ = sender.send(outcome);
    });
    let text = match receiver.recv_timeout(hook::TIME_LIMIT) {
        Ok(outcome) => outcome.finish(),
        Err(RecvTimeoutError::Timeout) => hook::timeout_statement(),
        Err(RecvTimeoutError::Disconnected) => hook::internal_error_statement(),
    };
    let text = if cursor {
        hook::cursor_output(&text)
    } else {
        text
    };
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
    std::process::exit(0)
}

/// P4-E: `hook print-config`, `hook install`, `hook uninstall`. U5 Z-F
/// round 1 (S1): `install` and `uninstall` edit the settings file and the
/// Workspace root's `.mcp.json`, and say for each what they did.
fn hook_config(command: HookCommand) -> ExitCode {
    let fail = |error: String| {
        eprintln!("memprove: error: {error}");
        ExitCode::from(1)
    };
    let (path, mcp_json) = match std::env::current_dir()
        .map_err(|error| format!("cannot resolve the current directory: {error}"))
        .and_then(|cwd| Ok((hook::settings_path(&cwd)?, mcp::config_path(&cwd)?)))
    {
        Ok(paths) => paths,
        Err(error) => return fail(error),
    };
    let executable = match command {
        HookCommand::Uninstall => String::new(),
        HookCommand::PrintConfig | HookCommand::Install { .. } => match hook::executable() {
            Ok(executable) => executable,
            Err(error) => return fail(error),
        },
    };
    let done = match command {
        HookCommand::PrintConfig => {
            // U8 K2 (U7 V-N2): the handler names the configuration
            // directory, as `mcp print-config` and `install` do.
            let Some((config, _)) = configuration_dir() else {
                return fail(NO_CONFIG_DIR.to_owned());
            };
            let Some(config) = config.to_str() else {
                return fail("the configuration directory is not UTF-8".to_owned());
            };
            print!("{}", hook::config_fragment(&executable, config));
            // P4-G (T20 N-5, accepted in P4-H1): `install` keeps values,
            // the spelling of numbers, and member order, not the bytes.
            eprintln!(
                "memprove: this fragment belongs in {}; `memprove hook install` adds it there \
                 and keeps every other value, the spelling of numbers, and the order of members, \
                 but not the file's bytes: it rewrites the file indented by two spaces",
                path.display()
            );
            return ExitCode::SUCCESS;
        }
        HookCommand::Install { allow_tools } => {
            let Some((config, _)) = configuration_dir() else {
                return fail(NO_CONFIG_DIR.to_owned());
            };
            let Some(config) = config.to_str().map(str::to_owned) else {
                return fail("the configuration directory is not UTF-8".to_owned());
            };
            let done = hook::install(&path, &mcp_json, &executable, &config, allow_tools);
            if done.is_ok() && !allow_tools {
                // U7 P3 (Owner O5): three rules, the last one this
                // executable's absolute path.
                let [mcp, bash, absolute] = hook::allow_rules(&executable);
                eprintln!(
                    "memprove: permissions.allow was left as it is; the rules an unattended \
                     `claude -p` needs are \"{mcp}\", \"{bash}\", and \"{absolute}\"; \
                     `memprove hook install --allow-tools` adds them"
                );
            }
            done
        }
        HookCommand::Uninstall => hook::uninstall(&path, &mcp_json),
    };
    match done {
        Ok(changes) => {
            for change in changes {
                match change {
                    hook::Change::Written(path) => {
                        eprintln!("memprove: {} written", path.display());
                    }
                    hook::Change::Unchanged(path) => {
                        eprintln!("memprove: {} already as asked; not written", path.display());
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

/// U5 P3: the configuration directory of this process, absolute, and the
/// variable it came from.
fn configuration_dir() -> Option<(std::path::PathBuf, &'static str)> {
    hook::configuration_dir(
        std::env::var_os(memprove_cli::context::CONFIG_DIR_ENV).as_deref(),
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
        std::env::current_dir().ok().as_deref(),
    )
}

/// U5 P3: the error when no configuration directory can be named.
const NO_CONFIG_DIR: &str = "no configuration directory: MEMPROVE_CONFIG_DIR, XDG_CONFIG_HOME, \
                             and HOME are all unset";

/// P4-G (ADR 0014 E7.9, Owner condition y): `mcp print-config` prints the
/// fragment on standard output and three statements on standard error, and
/// writes nothing. U5 P3 (Owner O5): the enabling fragment, with this
/// process's configuration directory in `env`; U5 Z-F round 1 (S1): in two
/// parts, `.claude/settings.local.json` and `.mcp.json`.
fn mcp_config() -> ExitCode {
    let fail = |error: String| {
        eprintln!("memprove: error: {error}");
        ExitCode::from(1)
    };
    let resolved = std::env::current_dir()
        .map_err(|error| format!("cannot resolve the current directory: {error}"))
        .and_then(|cwd| Ok((mcp::config_path(&cwd)?, hook::settings_path(&cwd)?)))
        .and_then(|paths| hook::executable().map(|executable| (paths, executable)));
    let ((mcp_json, settings), executable) = match resolved {
        Ok(resolved) => resolved,
        Err(error) => return fail(error),
    };
    let Some((config, source)) = configuration_dir() else {
        return fail(NO_CONFIG_DIR.to_owned());
    };
    let Some(config) = config.to_str() else {
        return fail("the configuration directory is not UTF-8".to_owned());
    };
    print!("{}", mcp::config_fragment(&executable, config));
    for statement in mcp::config_statements(&settings, &mcp_json, &executable, config, source) {
        eprintln!("{statement}");
    }
    ExitCode::SUCCESS
}

/// Runs the command of `spec` in this process's environment, shows its
/// output on standard error, submits the `captureEvidence` request, and
/// exits with the command's own exit code. A program that cannot be started
/// is recorded as `UNAVAILABLE` (P2-C) and exits [`RUN_FAILED`], as does a
/// result that cannot be recorded (P2-D1).
fn run_and_record(
    socket: &Path,
    spec: &run::RunSpec,
    token: Option<&str>,
    saver: &Saver<'_>,
) -> ExitCode {
    let attempted_at = run::utc_now();
    let executed = run::execute(&spec.argv)
        .unwrap_or_else(|error| run::Executed::unavailable(&error, attempted_at));
    let mut stderr = std::io::stderr().lock();
    // The command's own output is shown, not interpreted; a closed stderr
    // does not change what is recorded.
    let _ = stderr.write_all(&executed.stdout);
    let _ = stderr.write_all(&executed.stderr);
    let _ = match &executed.launch_error {
        Some(reason) => writeln!(
            stderr,
            "memprove: {:?} could not be started: {reason}; recording UNAVAILABLE",
            spec.argv[0]
        ),
        None => writeln!(
            stderr,
            "memprove: {:?} exited with {} ({} to {})",
            spec.argv[0], executed.exit_code, executed.started_at, executed.finished_at
        ),
    };
    drop(stderr);
    let mut spec = spec.clone();
    let source = spec
        .test
        .as_mut()
        .and_then(|test| count_test_cases(test, &executed));
    let request = run::uuid_v7()
        .map_err(|error| format!("cannot generate a snapshot id: {error}"))
        .and_then(|snapshot_id| keyed(run::capture_request(&spec, &executed, &snapshot_id)));
    let request = match request {
        Ok(request) => request,
        Err(error) => {
            eprintln!("memprove: error: {error}; the result was not recorded");
            return ExitCode::from(RUN_FAILED);
        }
    };
    // U8 K5 (Owner O5), SF-1: read before the run is recorded, so that the
    // Task's latest run is still the test run the command may repeat.
    let hint = if spec.test.is_none() {
        run::last_passed_hint(&Socket { socket, token }, &spec)
    } else {
        None
    };
    let Ok(reply) = (Socket { socket, token }).exchange(&request) else {
        eprintln!(
            "memprove: the result of {:?} was not recorded; exiting {RUN_FAILED}",
            spec.argv[0]
        );
        return ExitCode::from(RUN_FAILED);
    };
    println!("{}", reply.body);
    let evidence_id = member(&reply.body, &["evidence_id"]);
    let evidence_status = member(&reply.body, &["status"]);
    let labelled = remember_run(
        saver,
        &spec.session_id,
        &reply.body,
        evidence_id.as_ref(),
        evidence_status.as_ref(),
        &spec.argv,
    );
    let code = match (&executed.launch_error, u8::try_from(executed.exit_code)) {
        (Some(reason), _) => {
            eprintln!(
                "memprove: exiting {RUN_FAILED}: {:?} could not be started ({reason})",
                spec.argv[0]
            );
            RUN_FAILED
        }
        (None, Ok(code)) => code,
        (None, Err(_)) => RUN_FAILED,
    };
    // P2-I: the last line of standard error sums up what was recorded.
    let cases = match spec.test.as_ref().map(|test| test.case_count) {
        // U7 P4 (Owner O6): the record says a count came from a pytest
        // progress line.
        Some(Some(count)) if source == Some(run::CountSource::ProgressLine) => {
            format!(", {count} test cases ({})", run::PROGRESS_LINE_NOTE)
        }
        Some(Some(count)) => format!(", {count} test cases"),
        Some(None) => ", no test case count".to_owned(),
        None => String::new(),
    };
    let label = match &labelled {
        Some((label, citable, overruled)) => {
            eprintln!(
                "memprove: runs of this repository state you can cite with --evidence <LABEL>: \
                 {citable}"
            );
            for sentence in overruled {
                eprintln!("memprove: {sentence}");
            }
            format!(", label {label}")
        }
        None => String::new(),
    };
    // U8 K5 (Owner O5): a command run of the Task's last passed test run.
    if let Some(hint) = hint {
        eprintln!("memprove: {hint}");
    }
    eprintln!(
        "memprove: recorded {}{cases}, evidence_id {}{label}",
        evidence_status.as_deref().unwrap_or("an unknown status"),
        evidence_id.as_deref().unwrap_or("unknown")
    );
    ExitCode::from(code)
}

/// Counts the test cases of a run whose `--test-format` is given. U5 (H4):
/// cases a caller gave with `--test-cases` win over the output; U6 K2 (U5
/// N7): when the output can be read and its count differs from the one
/// given, one warning says so, and the one given is still what is recorded.
/// U7 P4 (D2 F12, Owner O6): returns where a count read from the output came
/// from; a count from a pytest progress line says so, and a pytest run with
/// no count says that pytest printed no summary.
fn count_test_cases(
    test: &mut run::TestSpec,
    executed: &run::Executed,
) -> Option<run::CountSource> {
    let format = test.format?;
    if let Some(given) = test.case_count {
        if let Some(warning) = run::case_count_warning(given, format, executed) {
            eprintln!("memprove: warning: {warning}");
        }
        return None;
    }
    let counted = format.counted(executed);
    test.case_count = counted.map(|(count, _)| count);
    match counted {
        Some((count, run::CountSource::Summary)) => {
            eprintln!("memprove: counted {count} test cases");
        }
        Some((count, run::CountSource::ProgressLine)) => eprintln!(
            "memprove: counted {count} test cases from the pytest progress line ({})",
            run::PROGRESS_LINE_NOTE
        ),
        None if format == run::TestFormat::Pytest => eprintln!(
            "memprove: could not count the test cases in the output; {}; the run is \
             recorded without a case count and does not pass",
            run::PYTEST_NO_SUMMARY
        ),
        None => eprintln!(
            "memprove: could not count the test cases in the output; the run is \
             recorded without a case count and does not pass"
        ),
    }
    counted.map(|(_, source)| source)
}

/// Records a run in the context when it was recorded in the context's
/// Session (P2-H): its Snapshot, Evidence, and result, the default
/// `--evidence` of `checkpoint create` and `task complete`; and (P3-D) a
/// label for every run the Snapshot seals, this one and the earlier runs of
/// the same state carried over into it. Returns the run's label, the
/// citable runs, and (P3-D3) one sentence per passed run among them that a
/// later run of the same argv overrules.
fn remember_run(
    saver: &Saver<'_>,
    session_id: &str,
    body: &str,
    evidence_id: Option<&String>,
    evidence_status: Option<&String>,
    argv: &[String],
) -> Option<(String, String, Vec<String>)> {
    let snapshot_id = member(body, &["snapshot", "snapshot_id"])?;
    let citable = sealed_runs(body);
    let manifest = member(body, &["snapshot", "capture_manifest_digest"]);
    // P4-B (T18 SF-1): the run's kind, test or command.
    let kind = member(body, &["kind"]);
    let mut labelled = None;
    saver.update(|context| {
        let current = context.session_id.as_deref() == Some(session_id);
        if current {
            context.snapshot_id = Some(snapshot_id);
            // P4-A: the repository state the runs below answer for.
            context.snapshot_manifest.clone_from(&manifest);
            if let Some(subject) = evidence_id {
                let label = context.label_runs(
                    &citable,
                    subject,
                    evidence_status.cloned(),
                    Some(argv_digest(argv)),
                );
                context.note_run_kind(subject, kind.clone());
                // U8 K5: a command run keeps its short argv, for the
                // refusal to cite it as a fact.
                context.note_run_argv(subject, argv);
                labelled = Some((label, context.citable_runs(), context.overruled_runs()));
            }
            context.evidence_id = evidence_id.cloned();
            context.evidence_status = evidence_status.cloned();
        }
        current
    });
    labelled
}

/// The command and test Evidence identities of the Snapshot in a
/// `captureEvidence` response, in the order it lists them.
fn sealed_runs(body: &str) -> Vec<String> {
    let Ok(value) = parse_strict(body) else {
        return Vec::new();
    };
    ["command_evidence_ids", "test_evidence_ids"]
        .iter()
        .filter_map(|name| value.get("snapshot")?.get(name)?.as_array())
        .flatten()
        .filter_map(|id| id.as_str().map(str::to_owned))
        .collect()
}

/// Whether a contract-checked `verifyLedger` body reports a valid ledger.
fn ledger_valid(body: &str) -> bool {
    parse_strict(body)
        .ok()
        .and_then(|value| value.get("valid").and_then(JsonValue::as_bool))
        .unwrap_or(false)
}

/// Builds the body of a drafted request (P3-C) through
/// [`flow::resolve_draft`]: a tampered Capsule, an unlisted number, or a
/// Capsule that cannot be read sends nothing (exit 1, or the exchange's own
/// code). P4-A: when `--reaffirm-all` leaves nothing to record, nothing is
/// sent either, and the code is 0.
fn resolve_draft(daemon: &Socket<'_>, request: &mut Request) -> Result<Resolved, u8> {
    let mut warn = |warning: &str| eprintln!("memprove: warning: {warning}");
    flow::resolve_draft(daemon, request, &mut warn).map_err(|stop| match stop {
        DraftStop::Unread(failed) => {
            eprintln!(
                "memprove: error: the Task Capsule that resolves claim numbers could not be \
                 read; nothing was sent"
            );
            failed.code()
        }
        DraftStop::Capsule(error) => {
            eprintln!("memprove: error: {error}");
            1
        }
        // U8 A5: a `--withdraw-session` that names no Session, or one with
        // nothing (or too much) in force, is a usage error.
        DraftStop::Claim(error) if error.is_usage() => {
            eprintln!(
                "memprove: error: {error}\nmemprove: for the usage of this command, run \
                 `memprove checkpoint create --help`"
            );
            2
        }
        DraftStop::Claim(error) => {
            eprintln!("memprove: error: {error}");
            1
        }
        DraftStop::Nothing(report) => {
            eprintln!(
                "memprove: --reaffirm-all found no fact to reaffirm and the command records \
                 nothing else (its --next is the next action in force); nothing was sent"
            );
            for line in report.lines(None) {
                eprintln!("memprove: {line}");
            }
            0
        }
    })
}

/// U5 P2: what memproved's detail says when it refuses a token in a text.
const TOKEN_REFUSAL: &str = "holds a string in the format of a memprove token";

/// U5 P2 (Owner O4 d): the hint after that refusal: the rule, in words.
const TOKEN_HINT: &str = "the text named above holds a string memproved takes for a \
    memprove token: a run of exactly 43 characters of A-Z, a-z, 0-9, '-', and '_' (nothing \
    else of them next to it) with at least one upper-case letter, one lower-case letter, and one \
    digit, or a token this memproved issued, whatever its characters. Write that part another \
    way (a test name such as test_calculate_metrics_rejects_empty_series is not one) and send \
    it again; nothing was recorded.";

/// Hints after a Problem that `checkpoint create --fact` or `task complete`
/// can act on.
fn explain_refusal(follow: &Follow, failed: &Failed) {
    // U5 P2 (D1 F2, Owner O4 d): a refusal of a string in the format of a
    // memprove token gets a hint that says the rule, not one about
    // `--evidence`, whichever command sent it.
    if let Failed::Problem(reply) = failed
        && reply.status == 400
        && reply.problem_code().as_deref() == Some("invalid_request")
        && reply
            .problem_detail()
            .is_some_and(|detail| detail.contains(TOKEN_REFUSAL))
    {
        eprintln!("memprove: hint: {TOKEN_HINT}");
        return;
    }
    if let (Follow::CheckpointFacts, Failed::Problem(reply)) = (follow, failed)
        && reply.status == 400
        && reply.problem_code().as_deref() == Some("invalid_request")
    {
        eprintln!(
            "memprove: hint: each --fact needs a passed test run as --evidence (exit \
             code 0 and at least one test case), and every test it cites must have \
             passed. To record a failing or unverified result, use --open <TEXT> \
             --evidence <ID> instead of --fact."
        );
    }
    // P3-L3 (T16 S-2): an `evidence_stale` with a detail is a `tampered`
    // Task; the failure line shows the detail, and a rerun does not help.
    if let (Follow::TaskCompleted { .. }, Failed::Problem(reply)) = (follow, failed)
        && reply.problem_code().as_deref() == Some("evidence_stale")
        && reply.problem_detail().is_none()
    {
        eprintln!(
            "memprove: hint: each completion Evidence must be a PASS run of this Task \
             that still holds here: same commit and same worktree state as when it was \
             recorded. Commit first, then rerun the tests with `memprove run`, then \
             `memprove task complete`."
        );
    }
}

/// U3 (K1, W-B-1, Owner O3): `task complete` reads the context's Session
/// once before it sends `transitionTask`; when `listSessions` shows it not
/// `active`, or does not list it, the refusal is printed, nothing is sent,
/// and the exit code is 1. A failed exchange is reported with its exit code
/// and nothing is sent either. `None` when the Session is active, or when
/// memproved refuses the listing with a Problem (the parser has refused a
/// context that names no Session).
fn refuse_inactive_session(daemon: &Socket<'_>, saver: &Saver<'_>) -> Option<ExitCode> {
    let context = saver.lookup.context()?;
    let session = context.session_id.as_deref()?;
    let why = match flow::session_state(&SessionProbe(*daemon), &context.workspace_id, session) {
        Ok(Some(state)) if state == "active" => return None,
        Ok(Some(state)) => format!("is {state}, not active"),
        Ok(None) => "is not listed, so it is not active".to_owned(),
        // U4 (Y1): a listing memproved refuses with a Problem, a daemon
        // that cannot be reached, a token that cannot be sent, or a
        // response that breaks the contract: the Session is not known to be
        // active, so it is reported as `send` reports a failed exchange
        // (`listSessions was refused` has exit 1), and nothing is sent.
        Err(failure) => {
            eprintln!("memprove: error: {failure}; task complete was not sent");
            return Some(ExitCode::from(failure.code()));
        }
    };
    eprintln!(
        "memprove: error: the Session {session} of the current context {why}; task complete \
         was not sent. Completing a Task needs an active Session: run `memprove begin`, then \
         `memprove run`, then `memprove task complete`"
    );
    Some(ExitCode::from(1))
}

/// The reads `send` makes before the request goes: U3 (K1) the Session
/// of `task complete`, U10 T7 the revision of `session end <ID>
/// --abandoned`. `Some` is the exit code when nothing is to be sent.
fn before_sending(
    daemon: &Socket<'_>,
    follow: &Follow,
    saver: &Saver<'_>,
    request: &mut Request,
) -> Option<ExitCode> {
    match follow {
        Follow::TaskCompleted { .. } => refuse_inactive_session(daemon, saver),
        Follow::SessionEnded {
            session_id,
            unread: Some(later),
        } => read_end_revision(daemon, saver, session_id, later, request).err(),
        _ => None,
    }
}

/// U10 T7 (Owner O4; D3 F24): `session end <ID> --abandoned` without
/// `--revision` (and not the context's own Session): the body is made with
/// the Session's current revision, read once from `listSessions` of the
/// Workspace (the context's, else the one every context of this Workspace
/// root records). A Session that Workspace does not list is a usage error
/// asking for `--revision` (exit 2), and a failed read is reported as `send`
/// reports a failed exchange; nothing is sent either way.
fn read_end_revision(
    daemon: &Socket<'_>,
    saver: &Saver<'_>,
    session_id: &str,
    later: &memprove_cli::EndLater,
    request: &mut Request,
) -> Result<(), ExitCode> {
    let usage = |why: String| {
        eprintln!(
            "memprove: error: session end {session_id} --abandoned without --revision reads \
             the Session's current revision, but {why}; pass --revision <N> (`memprove \
             session list --workspace <WORKSPACE_ID>` shows it); session end was not sent"
        );
        ExitCode::from(2)
    };
    let workspace = later
        .workspace_id
        .clone()
        .or_else(|| {
            let cwd = std::env::current_dir().ok()?;
            flow::workspace_of_root(saver.store?, &cwd)
        })
        .ok_or_else(|| {
            // U11 N2 (U10 VN10; Owner O6): a reader with only a token has
            // no context of this Workspace root; it can say the Workspace.
            eprintln!(
                "memprove: error: session end {session_id} --abandoned without --revision \
                 reads the Session's current revision from the Sessions of its Workspace, but \
                 no context of this configuration directory names its Workspace; run the \
                 command in the Workspace's directory where this configuration directory has a \
                 context, pass --workspace <WORKSPACE_ID> (`memprove workspace resolve \
                 --project <PROJECT_ID> <PATH>` prints it), or pass --revision <N> (`memprove \
                 session list --workspace <WORKSPACE_ID>` shows it); session end was not sent"
            );
            ExitCode::from(2)
        })?;
    let listed = flow::listed(
        &SessionProbe(*daemon),
        OperationId::ListSessions,
        &format!("/v1/sessions?workspace_id={workspace}"),
        "session_id",
        session_id,
    );
    let revision = match listed {
        Ok(Some(item)) => item
            .get("revision")
            .and_then(JsonValue::as_i64)
            .and_then(|revision| u64::try_from(revision).ok())
            .filter(|revision| *revision > 0),
        Ok(None) => {
            return Err(usage(format!("the Workspace {workspace} does not list it")));
        }
        Err(failure) => {
            eprintln!("memprove: error: {failure}; session end was not sent");
            return Err(ExitCode::from(failure.code()));
        }
    };
    let Some(revision) = revision else {
        eprintln!(
            "memprove: error: listSessions returned no revision of {session_id}; session end \
             was not sent"
        );
        return Err(ExitCode::from(4));
    };
    request.body = Some(memprove_cli::end_body_by(
        revision,
        later.reason.as_deref(),
        true,
        later.ended_by.as_ref(),
    ));
    Ok(())
}

/// U3 (K1): how the quiet read of [`refuse_inactive_session`] failed.
enum ProbeFailure {
    /// memproved answered with a Problem.
    Problem,
    /// The exchange failed.
    Call(memprove_cli::CallError),
    /// A successful response the flow could not use, and why.
    Malformed(String),
}

impl ProbeFailure {
    /// The exit code `send` gives the same failure of an exchange.
    fn code(&self) -> u8 {
        match self {
            Self::Problem => 1,
            Self::Call(memprove_cli::CallError::Transport { .. }) => 3,
            Self::Call(memprove_cli::CallError::InvalidToken) => 2,
            Self::Call(memprove_cli::CallError::ResponseTooLarge { .. }) => {
                flow::RESPONSE_TOO_LARGE
            }
            Self::Call(memprove_cli::CallError::Contract(_)) | Self::Malformed(_) => 4,
        }
    }
}

impl std::fmt::Display for ProbeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Problem => formatter.write_str("listSessions was refused"),
            Self::Call(error) => write!(formatter, "{error}"),
            Self::Malformed(why) => formatter.write_str(why),
        }
    }
}

/// U3 (K1): the socket as [`refuse_inactive_session`] reads it: quietly,
/// telling a Problem apart from a failed exchange.
struct SessionProbe<'a>(Socket<'a>);

impl Daemon for SessionProbe<'_> {
    type Failed = Failed;
    type Unread = ProbeFailure;

    fn exchange(&self, request: &Request) -> Result<Reply, Failed> {
        self.0.exchange(request)
    }

    fn read(&self, request: &Request) -> Result<Reply, ProbeFailure> {
        match memprove_cli::call(self.0.socket, request, self.0.token) {
            Ok(reply) if reply.is_success() => Ok(reply),
            Ok(_) => Err(ProbeFailure::Problem),
            Err(error) => Err(ProbeFailure::Call(error)),
        }
    }

    fn malformed(_: OperationId, why: String) -> ProbeFailure {
        ProbeFailure::Malformed(why)
    }

    fn problem_code(failed: &Failed) -> Option<String> {
        Socket::problem_code(failed)
    }
}

fn send(
    socket: &Path,
    mut request: Request,
    token: Option<&str>,
    follow: &Follow,
    saver: &Saver<'_>,
) -> ExitCode {
    let daemon = Socket { socket, token };
    if let Some(code) = before_sending(&daemon, follow, saver, &mut request) {
        return code;
    }
    // P3-L L8: which facts are reaffirmations, known only from the draft.
    let resolved = match resolve_draft(&daemon, &mut request) {
        Ok(resolved) => resolved,
        Err(code) => return ExitCode::from(code),
    };
    let request = match keyed(request) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("memprove: error: {error}");
            return ExitCode::from(2);
        }
    };
    let operation = request.operation;
    // P4-C2 revision 7: a long statement may show only in part in the Pack;
    // a note only, the request is sent as given.
    if operation == OperationId::CreateCheckpoint
        && let Some(body) = &request.body
    {
        for note in claims::long_statement_notes(body) {
            eprintln!("memprove: note: {note}");
        }
    }
    let reply = match daemon.exchange(&request) {
        Ok(reply) => reply,
        Err(failed) => {
            explain_refusal(follow, &failed);
            // P4-B (T18 SF-1): what --reaffirm-all would have recorded,
            // and which fact each position of the detail reaffirms.
            if let (Some(report), Failed::Problem(reply)) = (&resolved.reaffirm_all, &failed) {
                for line in report.refused_lines(reply.problem_detail().as_deref()) {
                    eprintln!("memprove: {line}");
                }
            }
            return ExitCode::from(failed.code());
        }
    };
    if let Some(code) = print_capsule_view(&request, &reply, saver) {
        return code;
    }
    match (request.summary)
        .then(|| match operation {
            OperationId::GetTaskCapsule => {
                resume::render_as(&reply.body, saver.current_session(), request.all_items)
            }
            _ => preview::summary(&reply.body),
        })
        .flatten()
    {
        Some(sentence) => println!("{sentence}"),
        None => println!("{}", reply.body),
    }
    if operation == OperationId::CreateCheckpoint {
        report_checkpoint(&daemon, &request, &reply, &resolved);
    }
    if operation == OperationId::CreateClientToken && reply.status == 201 {
        eprintln!("memprove: store the secret now; it is shown only once and cannot be recovered");
    }
    if operation == OperationId::VerifyLedger && !ledger_valid(&reply.body) {
        eprintln!("memprove: the ledger does not verify; see first_failure");
        return ExitCode::from(5);
    }
    if let Follow::TaskCompleted { cited, .. } = follow
        && !cited.is_empty()
    {
        // P3-L L11: which runs the default citation named.
        eprintln!(
            "memprove: the Task was completed citing the runs {}",
            cited.join(", ")
        );
    }
    match follow {
        Follow::SessionEnded { session_id, .. } => saver.update(|context| {
            let current = context.session_id.as_deref() == Some(session_id.as_str());
            if current {
                context.session_id = None;
                context.session_revision = None;
                eprintln!("memprove: the Session was cleared from the current context");
            }
            current
        }),
        Follow::TaskTransitioned { task_id } | Follow::TaskCompleted { task_id, .. } => {
            saver.update(|context| {
                let current = context.task_id.as_deref() == Some(task_id.as_str());
                if current {
                    context.task_revision = number(&reply.body, "revision");
                    context.task_state = member(&reply.body, &["state"]);
                }
                current
            });
        }
        Follow::Nothing | Follow::CheckpointFacts => {}
    }
    ExitCode::SUCCESS
}

/// P4-C: prints the Context Pack (`resume --pack`) or the lines of given
/// claim numbers (`resume --text --claims`, and P4-C2's `resume --pack
/// --claims`) and returns the exit code; `None` for every other request,
/// which prints as before. A Pack that does not fit its budget even at
/// level 5 exits 1, a Capsule the Pack cannot render exits 4, and a claim
/// number the Capsule does not list exits 2; nothing is printed on standard
/// output then.
/// U8 A5 (Owner O4): `resume --text --session <k>`; a number that names no
/// Session, or one that wrote nothing, is a usage error.
fn print_session_text(
    request: &Request,
    reply: &Reply,
    saver: &Saver<'_>,
    number: u64,
) -> ExitCode {
    match resume::render_session(
        &reply.body,
        saver.current_session(),
        request.all_items,
        number,
    ) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!(
                "memprove: error: {why}\nmemprove: for the usage of this command, run \
                 `memprove resume --help`"
            );
            ExitCode::from(2)
        }
    }
}

fn print_capsule_view(request: &Request, reply: &Reply, saver: &Saver<'_>) -> Option<ExitCode> {
    // U7 P1 (Owner O3): the Session of the context this command uses, and
    // a Session that declared the Pack its last-Pack record names, are the
    // reader's own; the Pack gives every other open Session the takeover
    // hint.
    let recorded = resume::recorded_pack(saver.store, std::env::current_dir().ok().as_deref());
    let own = resume::Own::of(
        saver.current_session().map(|current| current.session_id),
        recorded.as_ref(),
    );
    match &request.capsule_view {
        CapsuleView::Plain => None,
        // U8 A5 (Owner O4): one Session's statements.
        CapsuleView::SessionText(number) => {
            Some(print_session_text(request, reply, saver, *number))
        }
        CapsuleView::Pack { budget } => Some(match resume::pack(&reply.body, *budget, own) {
            Ok(text) => {
                print!("{text}");
                resume::remember_pack(
                    saver.store,
                    std::env::current_dir(),
                    &reply.body,
                    &text,
                    *budget,
                    None,
                );
                ExitCode::SUCCESS
            }
            Err(error) => pack_failure(error),
        }),
        // U3 G4 (Owner O8): a query Pack. It is not the whole Pack, so
        // nothing is recorded for `begin`.
        CapsuleView::PackQuery { budget, query } => {
            Some(match resume::query_pack(&reply.body, query, *budget, own) {
                Ok(pack) => {
                    print!("{pack}");
                    ExitCode::SUCCESS
                }
                Err(resume::QueryPackFailure::Pack(error)) => pack_failure(error),
                Err(resume::QueryPackFailure::Refused(_)) => {
                    eprintln!(
                        "memprove: error: --query is refused; the query is not repeated\n\
                         memprove: for the usage of this command, run `memprove resume --help`"
                    );
                    ExitCode::from(2)
                }
                Err(resume::QueryPackFailure::Index(why)) => {
                    eprintln!("memprove: error: {why}; nothing was printed");
                    ExitCode::from(1)
                }
            })
        }
        CapsuleView::PackClaims(ranges) => Some(match resume::pack_claims(&reply.body, ranges) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(error @ PackError::NoSuchClaim { .. }) => {
                eprintln!(
                    "memprove: error: --claims {error}\nmemprove: for the usage of this \
                     command, run `memprove resume --help`"
                );
                ExitCode::from(2)
            }
            Err(error) => {
                eprintln!("memprove: error: {error}");
                ExitCode::from(4)
            }
        }),
        CapsuleView::Claims(ranges) => Some(
            match resume::render_claims(&reply.body, saver.current_session(), ranges) {
                Ok(lines) => {
                    println!("{lines}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!(
                        "memprove: error: {error}\nmemprove: for the usage of this command, \
                         run `memprove resume --help`"
                    );
                    ExitCode::from(2)
                }
            },
        ),
    }
}

/// A Pack that could not be made: exit 1 when even level
/// 5 does not fit, with the length it needs, else exit 4.
fn pack_failure(error: PackError) -> ExitCode {
    match error {
        PackError::OverBudget { budget, needed } => {
            eprintln!(
                "memprove: error: the Context Pack of this Task needs {needed} UTF-16 code \
                 units even at level 5 (the Task line, integrity, Sessions, reruns, the next \
                 action, and the counts), over the budget of {budget}; pass --budget {needed} \
                 or more, or read `memprove resume --text`"
            );
            ExitCode::from(1)
        }
        error => {
            eprintln!("memprove: error: {error}");
            ExitCode::from(4)
        }
    }
}

/// P3-L L8: after a Checkpoint was recorded, writes on standard error the
/// number and kind of each new statement and the numbers each supersession,
/// withdrawal, and reaffirmation touched, read from the Task Capsule now
/// ([`flow::read_back`]). Standard output and the exit code are not
/// affected; when the Capsule cannot be read, a warning says so.
fn report_checkpoint(daemon: &Socket<'_>, request: &Request, reply: &Reply, resolved: &Resolved) {
    let Some(read) = flow::read_back(
        daemon,
        request.body.as_deref().unwrap_or("{}"),
        reply,
        &resolved.reaffirmed,
    ) else {
        return;
    };
    match &read.report {
        Ok(report) => {
            for line in report.lines() {
                eprintln!("memprove: {line}");
            }
        }
        Err(error) => eprintln!(
            "memprove: warning: the Checkpoint was recorded, but its claim numbers could not \
             be read ({error}); run `memprove resume --text`"
        ),
    }
    // P4-A: what --reaffirm-all reaffirmed and skipped; the count is last.
    // P4-B (T18 N-b): with the actual verdict of each reaffirmation, read
    // back from the Capsule after the write.
    let after = read
        .capsule
        .as_deref()
        .ok()
        .map(|body| (body, read.checkpoint_id.as_str()));
    for line in resolved
        .reaffirm_all
        .iter()
        .flat_map(|report| report.lines(after))
    {
        eprintln!("memprove: {line}");
    }
}

/// The local failures of `begin`: the error, exit 2.
fn local_error(message: &str) -> ExitCode {
    eprintln!("memprove: error: {message}");
    ExitCode::from(2)
}

/// `memprove begin`: the local checks, then the shared flow
/// ([`flow::begin`]): refuses while the context's Session is still active,
/// resolves the Workspace containing the current directory, creates the
/// Task when asked (refusing a finished one), creates a Session continuing
/// it, moves the Task to `in_progress`, and records the current context.
/// Nothing is recorded locally unless the Session was created; once it is,
/// the context is recorded even when the Task could not be moved, so that
/// `end` works.
fn begin(socket: &Path, spec: &BeginSpec, token: Option<&str>, saver: &Saver<'_>) -> ExitCode {
    let Some(store) = saver.store else {
        return local_error(&format!(
            "no configuration directory for the current context; set {CONFIG_DIR_ENV} or HOME"
        ));
    };
    let root = match std::env::current_dir().and_then(|cwd| workspace_root(&cwd)) {
        Ok(root) => root,
        Err(error) => {
            return local_error(&format!("cannot resolve the current directory: {error}"));
        }
    };
    if let Err(error) = store.check_outside(&root) {
        return local_error(&error.to_string());
    }
    let Some(root_text) = root.to_str() else {
        return local_error(&format!("{} is not valid UTF-8", root.display()));
    };
    let previous = saver
        .lookup
        .context()
        .filter(|context| context.workspace_root == root)
        .and_then(|context| {
            context
                .session_id
                .as_deref()
                .map(|session| (session, context.workspace_id.as_str()))
        });
    let request = BeginRequest {
        spec,
        root: &root,
        root_text,
        store,
        previous,
    };
    let begun = flow::begin(&Socket { socket, token }, &request, &mut |note| {
        eprintln!("{}", note.line(&request));
    });
    let begun = match begun {
        Ok(begun) => begun,
        Err(BeginStop::Local(failure)) => return local_error(&failure.to_string()),
        Err(
            BeginStop::Active(refusal)
            | BeginStop::Unconfirmed(refusal, _)
            | BeginStop::Finished(refusal, _),
        ) => {
            eprintln!("memprove: error: {refusal}");
            return ExitCode::from(1);
        }
        Err(BeginStop::Failed(failed)) => return ExitCode::from(failed.code()),
    };
    // P2-H: a refusal to move the Task is reported after the context is
    // written, so that `end` works.
    let advanced = begun.advanced.map_err(|unmoved| match unmoved {
        Unmoved::Generate(error) => {
            eprintln!("memprove: error: {error}");
            2
        }
        Unmoved::Failed(failed) => failed.code(),
    });
    let context = begun.context;
    match store.save(&context) {
        Ok(path) => {
            println!("{}", context.to_json());
            eprintln!(
                "memprove: Session started; current context written to {}",
                path.display()
            );
            if let Err(code) = advanced {
                eprintln!(
                    "memprove: error: the Session started but the Task was not moved to \
                     in_progress; see above, then `memprove task transition --to in_progress`"
                );
                return ExitCode::from(code);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "memprove: error: the Session started but the context was not written: {error}"
            );
            println!("{}", context.to_json());
            ExitCode::from(1)
        }
    }
}
