//! U1 (E3, ADR 0015): `memprove doctor`, a read-only self-check.
//!
//! Each check gives one `PASS`, `WARN`, or `FAIL` line; the command exits 1
//! when any check fails. It writes nothing: the daemon calls it makes are
//! reads (`healthLive`, `healthReady`, `getVersion`, `getProject`,
//! `getStatus`, `verifyLedger`, which records nothing), and the one write
//! operation it names, `resolveWorkspace`, is sent with an empty body that
//! the daemon refuses before it reads anything (`400` when the token may
//! write, `403` when it may not). No output holds a token's text.

use std::{
    ffi::OsString,
    fmt::Write as _,
    fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use memprove_protocol::{
    phase1::OperationId,
    strict_json::{JsonValue, parse_strict},
};

use crate::{
    BUILD_ID, Request, SOCKET_FILE_NAME, TOKEN_ENV, TOKEN_FILE_ENV, call,
    context::{ContextLookup, ContextStore},
    generate_idempotency_key, json_string, resolve_token,
};

/// What `doctor` was asked to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorSpec {
    /// The data directory (`--data-dir`, else `$MEMPROVE_DATA_DIR`).
    pub data_dir: Option<PathBuf>,
    /// `--socket`, when given.
    pub socket: Option<PathBuf>,
    /// `--token-file`, when given.
    pub token_file: Option<PathBuf>,
    /// `--json`.
    pub json: bool,
}

/// What `doctor` reads from its process.
#[derive(Debug, Clone)]
pub struct Environment {
    /// `MEMPROVE_TOKEN`.
    pub token: Option<OsString>,
    /// `MEMPROVE_TOKEN_FILE`.
    pub token_file: Option<OsString>,
    /// The working directory.
    pub cwd: Option<PathBuf>,
    /// The configuration directory, when one is set.
    pub store: Option<ContextStore>,
    /// The context of the working directory.
    pub lookup: ContextLookup,
    /// U5 Z-F round 1 (S2): the configuration directory as the CLI
    /// resolves it (absolute) and the variable it came from, for the
    /// fallbacks `<config>/data-dir` and `<config>/token`.
    pub config: Option<(PathBuf, &'static str)>,
    /// U7 P3: this executable's canonical absolute path, when it is known.
    pub executable: Option<PathBuf>,
    /// U7 P3: `PATH`.
    pub path: Option<OsString>,
}

/// The outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Nothing wrong.
    Pass,
    /// It works, but something deserves a look, or it could not be checked.
    Warn,
    /// Broken.
    Fail,
}

impl Status {
    /// `PASS`, `WARN`, or `FAIL`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// The check's name.
    pub check: &'static str,
    /// Its outcome.
    pub status: Status,
    /// What was found, in one sentence.
    pub detail: String,
}

fn check(check: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        check,
        status,
        detail: detail.into(),
    }
}

/// The Project id the read probe asks for: a `UUIDv7` of 2024, older than
/// any Project a daemon has issued, so the answer is `404` (or `403`).
const PROBE_PROJECT: &str = "018f47a0-0000-7000-8000-000000000001";
/// The most bytes of a settings file read.
const MAX_SETTINGS_BYTES: u64 = 4 << 20;

/// The daemon and the token, as far as the checks could reach them.
struct Reach {
    socket: Option<PathBuf>,
    alive: bool,
    token: Option<String>,
    accepted: bool,
}

impl Reach {
    fn usable(&self) -> Option<(&Path, &str)> {
        match (&self.socket, &self.token) {
            (Some(socket), Some(token)) if self.alive && self.accepted => {
                Some((socket.as_path(), token.as_str()))
            }
            _ => None,
        }
    }

    /// Why a check that needs the daemon and the token was not made.
    fn why_not(&self) -> &'static str {
        if self.socket.is_none() {
            "not checked: no data directory or socket is configured"
        } else if !self.alive {
            "not checked: the daemon does not answer"
        } else if self.token.is_none() {
            "not checked: there is no usable token"
        } else {
            "not checked: the daemon does not accept the token"
        }
    }
}

fn get(socket: &Path, token: Option<&str>, operation: OperationId, target: &str) -> Option<u16> {
    send(socket, token, operation, target, None).map(|(status, _)| status)
}

fn send(
    socket: &Path,
    token: Option<&str>,
    operation: OperationId,
    target: &str,
    body: Option<&str>,
) -> Option<(u16, String)> {
    let mut request = Request::bare(operation, target.to_owned());
    request.body = body.map(str::to_owned);
    if operation == OperationId::VerifyLedger {
        request.idempotency_key = generate_idempotency_key().ok();
    }
    call(socket, &request, token)
        .ok()
        .map(|reply| (reply.status, reply.body))
}

/// Runs every check, in report order.
#[must_use]
pub fn run(spec: &DoctorSpec, environment: &Environment) -> Vec<Check> {
    let mut checks = Vec::new();
    // U5 Z-F round 1 (S2): with neither --data-dir, --socket, nor
    // MEMPROVE_DATA_DIR, the data directory of <config>/data-dir, as the
    // CLI, the hook, and the server take it.
    let config = environment
        .config
        .as_ref()
        .map(|(dir, source)| (dir.as_path(), *source));
    let (spec, fallback) = if spec.data_dir.is_none() && spec.socket.is_none() {
        match crate::hook::configured_location(config) {
            Ok(dir) => (
                DoctorSpec {
                    data_dir: Some(dir),
                    ..spec.clone()
                },
                Fallback::NamedBy(config.map_or_else(PathBuf::new, |(dir, _)| {
                    dir.join(crate::hook::DATA_DIR_FILE_NAME)
                })),
            ),
            Err(clause) => (spec.clone(), Fallback::None(clause)),
        }
    } else {
        (spec.clone(), Fallback::Unused)
    };
    let spec = &spec;
    checks.push(data_dir_check(spec, &fallback));
    checks.push(projects_dir_check(spec));
    let socket = spec
        .socket
        .clone()
        .or_else(|| spec.data_dir.as_ref().map(|dir| dir.join(SOCKET_FILE_NAME)));
    checks.push(socket_check(socket.as_deref()));
    let (daemon, alive) = daemon_check(socket.as_deref());
    checks.push(daemon);
    let (token_file, token) = token_file_check(spec, environment);
    checks.push(token_file);
    let mut reach = Reach {
        socket,
        alive,
        token,
        accepted: false,
    };
    checks.push(token_check(&mut reach));
    checks.push(build_check(&reach));
    checks.push(config_dir_check(environment.store.as_ref()));
    checks.push(path_check(
        environment.executable.as_deref(),
        environment.path.as_deref(),
    ));
    checks.push(guide_check(environment.executable.as_deref(), BUILD_ID));
    let Some(root) = environment.cwd.as_deref().and_then(git_top) else {
        checks.push(check(
            "workspace",
            Status::Pass,
            format!(
                "the current directory {} is not inside a Git worktree; the context, hook, and \
                 ledger checks apply inside one",
                environment
                    .cwd
                    .as_deref()
                    .map_or_else(|| "?".to_owned(), |cwd| cwd.display().to_string())
            ),
        ));
        return checks;
    };
    // U22: the Project `memprove init` recorded for the first `begin`.
    let recorded = environment
        .store
        .as_ref()
        .and_then(|store| store.recorded_project_near(&root));
    checks.push(workspace_check(
        &root,
        &environment.lookup,
        recorded.as_deref(),
        &reach,
    ));
    let config = environment
        .store
        .as_ref()
        .map(|store| store.config_dir.as_path());
    checks.push(hook_check(&root, config));
    checks.push(mcp_entry_check(&root, config));
    if let Some(line) = client_hooks_check(&root, config) {
        checks.push(line);
    }
    checks.push(ledger_check(&environment.lookup, &reach));
    checks
}

/// U5 Z-F round 1 (S2): whether the data directory came from
/// `<config>/data-dir`.
enum Fallback {
    /// An option or `MEMPROVE_DATA_DIR` named it (or `--socket` alone was
    /// given).
    Unused,
    /// `<config>/data-dir`, this file, named it.
    NamedBy(PathBuf),
    /// Nothing named it; the clause says which file was read.
    None(String),
}

fn data_dir_check(spec: &DoctorSpec, fallback: &Fallback) -> Check {
    let Some(dir) = &spec.data_dir else {
        return if spec.socket.is_some() {
            check(
                "data-dir",
                Status::Warn,
                "not checked: only --socket was given",
            )
        } else {
            let clause = match fallback {
                Fallback::None(clause) => format!("; {clause}"),
                Fallback::Unused | Fallback::NamedBy(_) => String::new(),
            };
            check(
                "data-dir",
                Status::Fail,
                format!(
                    "no data directory: pass --data-dir <PATH> or set MEMPROVE_DATA_DIR{clause}"
                ),
            )
        };
    };
    let named_by = match fallback {
        Fallback::NamedBy(file) => format!(" (named by {})", file.display()),
        Fallback::Unused | Fallback::None(_) => String::new(),
    };
    match fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => {
            let mode = metadata.permissions().mode() & 0o7777;
            if mode & 0o077 != 0 {
                check(
                    "data-dir",
                    Status::Fail,
                    format!(
                        "{} has mode {mode:04o}; group or others can enter it, and memproved \
                         refuses it (chmod 700)",
                        dir.display()
                    ),
                )
            } else {
                check(
                    "data-dir",
                    Status::Pass,
                    format!("{} has mode {mode:04o}{named_by}", dir.display()),
                )
            }
        }
        Ok(_) => check(
            "data-dir",
            Status::Fail,
            format!("{} is not a directory", dir.display()),
        ),
        Err(error) => check(
            "data-dir",
            Status::Fail,
            format!("{} cannot be read: {error}", dir.display()),
        ),
    }
}

/// U2 (S2): `Err` with the `projects-dir` failure when `path` is not a
/// directory of mode 0700 or stricter (a symbolic link is not followed).
fn owner_only_directory(path: &Path) -> Result<(), Check> {
    let fail = |detail: String| Err(check("projects-dir", Status::Fail, detail));
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            let mode = metadata.permissions().mode() & 0o7777;
            if mode & 0o077 != 0 {
                fail(format!(
                    "{} has mode {mode:04o}; group or others can enter it (chmod 700)",
                    path.display()
                ))
            } else {
                Ok(())
            }
        }
        Ok(_) => fail(format!("{} is not a directory", path.display())),
        Err(error) => fail(format!("{} cannot be read: {error}", path.display())),
    }
}

/// U2 (S2, N-5, original #131): `projects/` of the data directory and
/// each directory in it (one per Project) are mode 0700 or stricter, as
/// memproved creates them; one that group or others can enter, or an entry
/// that is not a directory, fails. U3 (K6, V-N-7): `tmp/` of the data
/// directory too, on the same line, after them; one that does not exist
/// is not reported, and the detail is then as before.
fn projects_dir_check(spec: &DoctorSpec) -> Check {
    let Some(dir) = &spec.data_dir else {
        return check(
            "projects-dir",
            Status::Warn,
            "not checked: no data directory is configured",
        );
    };
    let projects = dir.join("projects");
    let tmp = dir.join("tmp");
    let tmp_exists = !matches!(fs::symlink_metadata(&tmp),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound);
    if matches!(fs::symlink_metadata(&projects),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        if tmp_exists && let Err(failed) = owner_only_directory(&tmp) {
            return failed;
        }
        return check(
            "projects-dir",
            Status::Pass,
            if tmp_exists {
                format!(
                    "{} does not exist yet: no Project is registered; {} has mode 0700 or \
                     stricter",
                    projects.display(),
                    tmp.display()
                )
            } else {
                format!(
                    "{} does not exist yet: no Project is registered",
                    projects.display()
                )
            },
        );
    }
    let checked = owner_only_directory(&projects).and_then(|()| {
        let mut paths = fs::read_dir(&projects)
            .and_then(|entries| {
                entries
                    .map(|entry| entry.map(|entry| entry.path()))
                    .collect::<std::io::Result<Vec<_>>>()
            })
            .map_err(|error| {
                check(
                    "projects-dir",
                    Status::Fail,
                    format!("{} cannot be read: {error}", projects.display()),
                )
            })?;
        paths.sort();
        paths
            .iter()
            .try_for_each(|path| owner_only_directory(path))
            .map(|()| paths.len())
    });
    let checked = checked.and_then(|count| {
        if tmp_exists {
            owner_only_directory(&tmp)?;
        }
        Ok(count)
    });
    match checked {
        Ok(count) => {
            let plural = if count == 1 { "y" } else { "ies" };
            check(
                "projects-dir",
                Status::Pass,
                if tmp_exists {
                    format!(
                        "{} and its {count} Project director{plural}, and {}, have mode 0700 \
                         or stricter",
                        projects.display(),
                        tmp.display()
                    )
                } else {
                    format!(
                        "{} and its {count} Project director{plural} have mode 0700 or \
                         stricter",
                        projects.display()
                    )
                },
            )
        }
        Err(failed) => failed,
    }
}

fn socket_check(socket: Option<&Path>) -> Check {
    let Some(socket) = socket else {
        return check(
            "socket",
            Status::Fail,
            "no socket: no data directory or socket is configured",
        );
    };
    match fs::symlink_metadata(socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            let mode = metadata.permissions().mode() & 0o7777;
            if mode & 0o077 != 0 {
                check(
                    "socket",
                    Status::Fail,
                    format!(
                        "{} has mode {mode:04o}; it must not be accessible by group or others",
                        socket.display()
                    ),
                )
            } else {
                check(
                    "socket",
                    Status::Pass,
                    format!("{} has mode {mode:04o}", socket.display()),
                )
            }
        }
        Ok(_) => check(
            "socket",
            Status::Fail,
            format!("{} is not a socket", socket.display()),
        ),
        Err(_) => check(
            "socket",
            Status::Fail,
            format!(
                "there is no socket at {}: memproved is not running",
                socket.display()
            ),
        ),
    }
}

fn daemon_check(socket: Option<&Path>) -> (Check, bool) {
    let Some(socket) = socket else {
        return (
            check(
                "daemon",
                Status::Fail,
                "not reachable: no data directory or socket is configured",
            ),
            false,
        );
    };
    match get(socket, None, OperationId::HealthLive, "/health/live") {
        Some(200) => match get(socket, None, OperationId::HealthReady, "/health/ready") {
            Some(200) => (
                check(
                    "daemon",
                    Status::Pass,
                    format!("memproved answers and is ready on {}", socket.display()),
                ),
                true,
            ),
            _ => (
                check(
                    "daemon",
                    Status::Warn,
                    format!("memproved answers on {} but is not ready", socket.display()),
                ),
                true,
            ),
        },
        _ => (
            check(
                "daemon",
                Status::Fail,
                format!(
                    "no memproved answers on {}; start it (for an installed copy, \
                     <prefix>/bin/ensure-daemon.sh)",
                    socket.display()
                ),
            ),
            false,
        ),
    }
}

/// The token source, as `resolve_token` chooses it, checked; the token
/// when it is usable.
fn token_file_check(spec: &DoctorSpec, environment: &Environment) -> (Check, Option<String>) {
    let env_token = environment.token.clone().filter(|token| !token.is_empty());
    let file = spec.token_file.clone().or_else(|| {
        if env_token.is_some() {
            None
        } else {
            environment
                .token_file
                .clone()
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
        }
    });
    let resolved = resolve_token(
        spec.token_file.as_deref(),
        environment.token.clone(),
        environment.token_file.clone(),
    );
    // U5 Z-F round 1 (S2): with no source named, <config>/token, as the
    // CLI, the hook, and the server read it.
    let (resolved, file, missing) = match (resolved, &environment.config) {
        (Ok(None), Some((dir, source))) => (
            crate::hook::configured_token(dir),
            Some(dir.join(crate::hook::TOKEN_FILE_NAME)),
            format!(
                "; {} does not exist {}",
                dir.join(crate::hook::TOKEN_FILE_NAME).display(),
                crate::hook::configured_from(dir, source)
            ),
        ),
        (Ok(None), None) => (
            Ok(None),
            file,
            "; there is no configuration directory to read a token file from \
             (MEMPROVE_CONFIG_DIR, XDG_CONFIG_HOME, and HOME are all unset)"
                .to_owned(),
        ),
        (resolved, _) => (resolved, file, String::new()),
    };
    match resolved {
        Ok(Some(token)) => {
            let detail = match &file {
                Some(path) => {
                    let mode = fs::metadata(path)
                        .map(|metadata| metadata.permissions().mode() & 0o7777)
                        .unwrap_or_default();
                    format!("{} has mode {mode:04o} and holds one token", path.display())
                }
                None => format!("the token comes from {TOKEN_ENV}; there is no file to check"),
            };
            (check("token-file", Status::Pass, detail), Some(token))
        }
        Ok(None) => (
            check(
                "token-file",
                Status::Fail,
                format!(
                    "no token: set {TOKEN_FILE_ENV} to a mode-0600 token file (for an installed \
                     copy, <prefix>/config/token), set {TOKEN_ENV}, or pass --token-file{missing}"
                ),
            ),
            None,
        ),
        Err(error) => (check("token-file", Status::Fail, error.to_string()), None),
    }
}

fn token_check(reach: &mut Reach) -> Check {
    let (Some(socket), Some(token)) = (reach.socket.clone(), reach.token.clone()) else {
        return check("token", Status::Warn, reach.why_not());
    };
    if !reach.alive {
        return check("token", Status::Warn, reach.why_not());
    }
    let token = token.as_str();
    match get(&socket, Some(token), OperationId::GetVersion, "/v1/version") {
        Some(200) => reach.accepted = true,
        Some(401) => {
            return check(
                "token",
                Status::Fail,
                "memproved does not accept the token (unknown or revoked); issue a new one with \
                 `memprove token create` and the control token",
            );
        }
        _ => {
            return check(
                "token",
                Status::Warn,
                "not checked: getVersion did not answer",
            );
        }
    }
    let read = get(
        &socket,
        Some(token),
        OperationId::GetProject,
        &format!("/v1/projects/{PROBE_PROJECT}"),
    );
    let write = send(
        &socket,
        Some(token),
        OperationId::ResolveWorkspace,
        "/v1/workspaces/resolve",
        Some("{}"),
    )
    .map(|(status, _)| status);
    let control = get(&socket, Some(token), OperationId::GetStatus, "/v1/status") == Some(200);
    let can_read = matches!(read, Some(200 | 404));
    let can_write = write == Some(400);
    match (can_read, can_write, control) {
        (true, true, false) => check(
            "token",
            Status::Pass,
            "memproved accepts the token, and it reaches the mcp-read and mcp-write operations",
        ),
        (true, true, true) => check(
            "token",
            Status::Warn,
            "memproved accepts the token, and it is a control token: give agents an mcp-read \
             and mcp-write token and keep control for the operator",
        ),
        _ => check(
            "token",
            Status::Fail,
            format!(
                "memproved accepts the token, but it cannot {}: an agent needs mcp-read and \
                 mcp-write",
                match (can_read, can_write) {
                    (false, false) => "read or write",
                    (false, true) => "read",
                    _ => "write",
                }
            ),
        ),
    }
}

fn build_check(reach: &Reach) -> Check {
    let own = format!("{} ({BUILD_ID})", env!("CARGO_PKG_VERSION"));
    let Some((socket, token)) = reach.usable() else {
        return check(
            "build",
            Status::Warn,
            format!("{}; memprove is {own}", reach.why_not()),
        );
    };
    let Some((200, body)) = send(
        socket,
        Some(token),
        OperationId::GetVersion,
        "/v1/version",
        None,
    ) else {
        return check(
            "build",
            Status::Warn,
            "not checked: getVersion did not answer",
        );
    };
    let body = parse_strict(&body).ok();
    let field = |name: &str| {
        body.as_ref()
            .and_then(|body| body.get(name))
            .and_then(JsonValue::as_str)
            .map(str::to_owned)
    };
    let version = field("application_version").unwrap_or_default();
    let Some(build) = field("build") else {
        return check(
            "build",
            Status::Fail,
            format!(
                "memproved {version} reports no build (it was built before U1-E1) and \
                 memprove is {own}: install both from one build"
            ),
        );
    };
    let daemon = format!("{version} ({build})");
    if daemon != own {
        check(
            "build",
            Status::Fail,
            format!("memprove is {own} but memproved is {daemon}: install both from one build"),
        )
    } else if BUILD_ID == "unknown" {
        check(
            "build",
            Status::Warn,
            format!(
                "memprove and memproved both report {own}; an unknown build cannot be compared"
            ),
        )
    } else {
        check(
            "build",
            Status::Pass,
            format!("memprove and memproved are the same build, {own}"),
        )
    }
}

/// The top of the Git worktree holding `directory`, when there is one.
fn git_top(directory: &Path) -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["--no-optional-locks", "rev-parse", "--show-toplevel"])
        .current_dir(directory)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let top = String::from_utf8(output.stdout).ok()?;
    let top = top.trim_end_matches(['\n', '\r']);
    (!top.is_empty())
        .then(|| fs::canonicalize(top).ok())
        .flatten()
}

/// U7 P3 (D2 F11, Owner O5): the `path` line: PASS when the directory of
/// this executable is one of the directories of `PATH` (compared once both
/// resolve), so that a `memprove run` an agent types runs it and the rule
/// `Bash(memprove run:*)` matches; else WARN, with the `export` line that
/// puts it there.
fn path_check(executable: Option<&Path>, path: Option<&std::ffi::OsStr>) -> Check {
    let Some(dir) = executable.and_then(Path::parent) else {
        return check(
            "path",
            Status::Warn,
            "the directory of this executable cannot be found, so whether it is on PATH is not \
             checked",
        );
    };
    if dir_on_path(dir, path) {
        check(
            "path",
            Status::Pass,
            format!(
                "{} is on PATH, so `memprove run` runs this executable and the rule \
                 Bash(memprove run:*) matches it",
                dir.display()
            ),
        )
    } else {
        check(
            "path",
            Status::Warn,
            format!(
                "{dir} is not on PATH: a `memprove run` the agent types is not found, and the \
                 rule Bash(memprove run:*) does not match the absolute path it runs instead \
                 (`memprove hook install --allow-tools` also allows that path); in the shell \
                 profile of whoever starts Claude Code: export PATH=\"{dir}:$PATH\"",
                dir = dir.display()
            ),
        )
    }
}

/// U10 N9 (D3 F28; Owner O6): the first line of the guide
/// `scripts/install.sh` writes at `<prefix>/share/guide.md`, around
/// the build of the binaries installed with it.
const GUIDE_COMMENT: (&str, &str) = ("<!-- installed with build ", " -->");

/// U10 N9: the `guide` line. This executable is in an installation made by
/// `scripts/install.sh` when it is `<prefix>/bin/<name>` and the prefix has
/// the guide, or `data/` and `config/` beside `bin/`. There, the first line
/// of `<prefix>/share/guide.md` must name `build`, the build of this
/// binary: PASS when it does; WARN when it names another build, when it has
/// no such line (the guide was installed before U10), or when there is no
/// guide or it cannot be read. A wrong guide does not stop the product, so
/// none of these is a FAIL. Elsewhere (a build tree, a binary copied by
/// hand) there is no installed guide to compare: PASS, saying so.
fn guide_check(executable: Option<&Path>, build: &str) -> Check {
    let prefix = executable
        .and_then(Path::parent)
        .filter(|bin| bin.file_name() == Some(std::ffi::OsStr::new("bin")))
        .and_then(Path::parent);
    let guide = prefix.map(|prefix| prefix.join("share").join("guide.md"));
    let installed = prefix.zip(guide.as_deref()).filter(|(prefix, guide)| {
        guide.is_file() || (prefix.join("data").is_dir() && prefix.join("config").is_dir())
    });
    let Some((_, guide)) = installed else {
        return check(
            "guide",
            Status::Pass,
            "this executable is not in an installation made by scripts/install.sh (<prefix>/bin \
             beside <prefix>/data and <prefix>/config), so there is no installed guide to \
             compare with it",
        );
    };
    let cure = "run scripts/install.sh again to bring the guide to this binary";
    let warn = |detail: String| check("guide", Status::Warn, detail);
    if !guide.is_file() {
        return warn(format!(
            "there is no guide at {}: an agent that has only this installation cannot read how \
             to use it; {cure}",
            guide.display()
        ));
    }
    let Some(first) = first_line(guide) else {
        return warn(format!(
            "the guide at {} cannot be read; {cure}",
            guide.display()
        ));
    };
    let named = first
        .strip_prefix(GUIDE_COMMENT.0)
        .and_then(|rest| rest.strip_suffix(GUIDE_COMMENT.1));
    match named {
        Some(named) if named == build => check(
            "guide",
            Status::Pass,
            format!(
                "the guide at {} was installed with this binary (build {build})",
                guide.display()
            ),
        ),
        Some(named) => warn(format!(
            "the guide at {} was installed with build {}, and this binary is build {build}: it \
             may describe commands this binary does not have, or lack ones it has; {cure}",
            guide.display(),
            shown(named)
        )),
        None => warn(format!(
            "the guide at {} has no build comment on its first line, so whether it is the \
             version of this binary is not known (it was installed before U10); {cure}",
            guide.display()
        )),
    }
}

/// The first line of `file` (at most 256 bytes of it, UTF-8), without its
/// line break; `None` when it cannot be read or is not UTF-8.
fn first_line(file: &Path) -> Option<String> {
    use std::io::Read as _;
    let mut head = Vec::new();
    std::fs::File::open(file)
        .ok()?
        .take(256)
        .read_to_end(&mut head)
        .ok()?;
    let line = head.split(|byte| *byte == b'\n').next()?;
    String::from_utf8(line.to_vec()).ok()
}

/// A build name as the `guide` line shows another build's: printable ASCII
/// of at most 40 characters, else a placeholder.
fn shown(named: &str) -> String {
    if named.len() <= 40 && named.bytes().all(|byte| matches!(byte, b' '..=b'~')) {
        named.to_owned()
    } else {
        "(not a build name)".to_owned()
    }
}

/// Whether `dir` is one of the directories of `path` (compared once both
/// resolve). U10 T7: also how the takeover hint chooses its program
/// ([`crate::resume::program_for`]).
pub(crate) fn dir_on_path(dir: &Path, path: Option<&std::ffi::OsStr>) -> bool {
    path.map(std::env::split_paths)
        .into_iter()
        .flatten()
        .filter(|entry| !entry.as_os_str().is_empty())
        .any(|entry| same_dir(&entry, dir))
}

fn config_dir_check(store: Option<&ContextStore>) -> Check {
    let Some(store) = store else {
        return check(
            "config-dir",
            Status::Warn,
            "no configuration directory: MEMPROVE_CONFIG_DIR, XDG_CONFIG_HOME, and HOME are \
             all unset",
        );
    };
    let dir = &store.config_dir;
    let nearest = dir
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .map(Path::to_path_buf);
    if let Some(top) = nearest.as_deref().and_then(git_top) {
        return check(
            "config-dir",
            Status::Fail,
            format!(
                "{} is inside the Git worktree {}: a context file there is an untracked file and \
                 keeps runs from being verified; move it outside every worktree",
                dir.display(),
                top.display()
            ),
        );
    }
    match fs::metadata(dir) {
        Ok(metadata) if metadata.permissions().mode() & 0o077 != 0 => check(
            "config-dir",
            Status::Warn,
            format!(
                "{} is outside every Git worktree, but group or others can enter it (mode {:04o}; \
                 chmod 700)",
                dir.display(),
                metadata.permissions().mode() & 0o7777
            ),
        ),
        Ok(_) => check(
            "config-dir",
            Status::Pass,
            format!("{} is outside every Git worktree", dir.display()),
        ),
        Err(_) => check(
            "config-dir",
            Status::Pass,
            format!(
                "{} does not exist yet and is outside every Git worktree",
                dir.display()
            ),
        ),
    }
}

fn workspace_check(
    root: &Path,
    lookup: &ContextLookup,
    recorded: Option<&str>,
    reach: &Reach,
) -> Check {
    let context = match lookup {
        ContextLookup::Found(context) => context,
        ContextLookup::Broken(reason) => {
            return check(
                "workspace",
                Status::Fail,
                format!("the context of {} cannot be used: {reason}", root.display()),
            );
        }
        _ => {
            // U22: after `memprove init`, the recorded Project needs no
            // --project.
            let detail = recorded.map_or_else(
                || {
                    format!(
                        "the Workspace {} has no current context: run `memprove begin --project \
                         <PROJECT_ID> --new-task <TITLE>` there (the operator registers the Project)",
                        root.display()
                    )
                },
                |project| {
                    format!(
                        "the Workspace {} has no current context yet: `memprove begin --new-task \
                         <TITLE>` there starts the first Session, in Project {project} (the one \
                         `memprove init` registered)",
                        root.display()
                    )
                },
            );
            return check("workspace", Status::Warn, detail);
        }
    };
    let described = format!(
        "the Workspace {} has a context: Project {}, Task {}, Session {}",
        context.workspace_root.display(),
        context.project_id,
        context.task_id.as_deref().unwrap_or("none"),
        context.session_id.as_deref().unwrap_or("none (ended)")
    );
    let Some((socket, token)) = reach.usable() else {
        return check(
            "workspace",
            Status::Warn,
            format!(
                "{described}; whether the Project is registered is {}",
                reach.why_not()
            ),
        );
    };
    match get(
        socket,
        Some(token),
        OperationId::GetProject,
        &format!("/v1/projects/{}", context.project_id),
    ) {
        Some(200) => check(
            "workspace",
            Status::Pass,
            format!("{described}; the Project is registered"),
        ),
        Some(404) => check(
            "workspace",
            Status::Fail,
            format!("{described}; this daemon has no such Project"),
        ),
        status => check(
            "workspace",
            Status::Warn,
            format!(
                "{described}; getProject answered {}",
                status.map_or_else(|| "nothing".to_owned(), |status| status.to_string())
            ),
        ),
    }
}

/// The program of each `SessionStart` handler that runs `memprove hook
/// session-start` in `settings`: the exec form's `command` with the
/// arguments `hook session-start`, or a shell command whose words after
/// the first are `hook session-start`; U7 P2 (Owner O4): with the directory
/// of a `--config-dir <DIR>` that follows them, when one does.
fn hook_programs(settings: &JsonValue) -> Vec<(String, Option<String>)> {
    let mut programs = Vec::new();
    let groups = settings
        .get("hooks")
        .and_then(|hooks| hooks.get("SessionStart"))
        .and_then(JsonValue::as_array)
        .unwrap_or_default();
    for handler in groups
        .iter()
        .filter_map(|group| group.get("hooks").and_then(JsonValue::as_array))
        .flatten()
    {
        let Some(command) = handler.get("command").and_then(JsonValue::as_str) else {
            continue;
        };
        let args: Option<Vec<&str>> = handler
            .get("args")
            .and_then(JsonValue::as_array)
            .map(|args| args.iter().filter_map(JsonValue::as_str).collect());
        match args.as_deref() {
            Some(["hook", "session-start"]) => programs.push((command.to_owned(), None)),
            Some(["hook", "session-start", option, dir]) if *option == crate::CONFIG_DIR_OPTION => {
                programs.push((command.to_owned(), Some((*dir).to_owned())));
            }
            Some(_) => {}
            None => {
                let words: Vec<&str> = command.split_whitespace().collect();
                let unquote = |word: &str| word.trim_matches(['"', '\'']).to_owned();
                match words.as_slice() {
                    [program, "hook", "session-start"] => programs.push((unquote(program), None)),
                    [program, "hook", "session-start", option, dir]
                        if *option == crate::CONFIG_DIR_OPTION =>
                    {
                        programs.push((unquote(program), Some(unquote(dir))));
                    }
                    _ => {}
                }
            }
        }
    }
    programs
}

/// One settings file read as JSON: `Ok(None)` when it does not exist, `Err`
/// the line when it is too large or not JSON.
fn read_json(path: &Path, check_name: &'static str) -> Result<Option<JsonValue>, Check> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(None);
    };
    if metadata.len() > MAX_SETTINGS_BYTES {
        return Err(check(
            check_name,
            Status::Fail,
            format!("{} is larger than 4 MiB", path.display()),
        ));
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|text| parse_strict(&text).ok())
        .map(Some)
        .ok_or_else(|| {
            check(
                check_name,
                Status::Fail,
                format!("{} cannot be read as JSON", path.display()),
            )
        })
}

/// U5 P3: whether two configuration directories are one: the same path, or
/// the same directory once both resolve.
fn same_dir(left: &Path, right: &Path) -> bool {
    left == right
        || matches!(
            (fs::canonicalize(left), fs::canonicalize(right)),
            (Ok(left), Ok(right)) if left == right
        )
}

/// `env.MEMPROVE_CONFIG_DIR` of `value`, when it is a string.
fn config_env(value: &JsonValue) -> Option<&str> {
    value
        .get("env")
        .and_then(|env| env.get(crate::context::CONFIG_DIR_ENV))
        .and_then(JsonValue::as_str)
}

/// U5 P3 (D1 F5, Owner O5): what `env.MEMPROVE_CONFIG_DIR` of `file` (the
/// value `value`, or none) says against the configuration directory doctor
/// uses: the status of the line and the clause that says so.
fn env_against(
    file: &str,
    value: Option<&str>,
    config: Option<&Path>,
    who: &str,
) -> (Status, String) {
    let Some(config) = config else {
        return (
            Status::Warn,
            "whether its env.MEMPROVE_CONFIG_DIR is the configuration directory is not \
             checked: doctor has none (MEMPROVE_CONFIG_DIR, XDG_CONFIG_HOME, and HOME are \
             unset)"
                .to_owned(),
        );
    };
    match value {
        None => (
            Status::Warn,
            format!(
                "{file} has no env.MEMPROVE_CONFIG_DIR, so {who} uses MEMPROVE_CONFIG_DIR of \
                 the environment Claude Code starts it in, else the default directory, which may \
                 not be {}, the configuration directory doctor uses (`memprove hook install` \
                 writes it)",
                config.display()
            ),
        ),
        Some(value) if same_dir(Path::new(value), config) => (
            Status::Pass,
            format!(
                "env.MEMPROVE_CONFIG_DIR is {}, the configuration directory doctor uses",
                config.display()
            ),
        ),
        Some(value) => (
            Status::Fail,
            format!(
                "env.MEMPROVE_CONFIG_DIR of {file} is {value}, but doctor uses {}: {who} would \
                 look for the contexts in another directory",
                config.display()
            ),
        ),
    }
}

/// U7 P2 (D2 F13, Owner O4): what a `--config-dir <DIR>` argument of an
/// entry says against the configuration directory doctor uses: PASS when it
/// is that directory, FAIL when it is another (the argument wins over the
/// entry's `env` and over the environment Claude Code starts it in), WARN
/// when doctor has none.
fn argument_against(dirs: &[&str], config: Option<&Path>, who: &str) -> (Status, String) {
    let Some(config) = config else {
        return (
            Status::Warn,
            "whether its --config-dir is the configuration directory is not checked: doctor has \
             none (MEMPROVE_CONFIG_DIR, XDG_CONFIG_HOME, and HOME are unset)"
                .to_owned(),
        );
    };
    match dirs.iter().find(|dir| !same_dir(Path::new(dir), config)) {
        None => (
            Status::Pass,
            format!(
                "its --config-dir is {}, the configuration directory doctor uses (the argument \
                 wins over env.MEMPROVE_CONFIG_DIR)",
                config.display()
            ),
        ),
        Some(dir) => (
            Status::Fail,
            format!(
                "its --config-dir is {dir}, but doctor uses {}: {who} would look for the contexts \
                 in another directory",
                config.display()
            ),
        ),
    }
}

fn hook_check(root: &Path, config: Option<&Path>) -> Check {
    let mut found = Vec::new();
    // U5 P3: the env Claude Code applies; settings.local.json wins.
    let mut env: Option<(PathBuf, Option<String>)> = None;
    for name in ["settings.json", "settings.local.json"] {
        let path = root.join(".claude").join(name);
        let settings = match read_json(&path, "hook") {
            Ok(Some(settings)) => settings,
            Ok(None) => continue,
            Err(line) => return line,
        };
        if let Some(value) = config_env(&settings) {
            env = Some((path.clone(), Some(value.to_owned())));
        } else if env.as_ref().is_none_or(|(_, value)| value.is_none()) {
            env = Some((path.clone(), None));
        }
        for (program, dir) in hook_programs(&settings) {
            found.push((path.clone(), program, dir));
        }
    }
    if found.is_empty() {
        return check(
            "hook",
            Status::Warn,
            format!(
                "no SessionStart hook runs `memprove hook session-start` in {}/.claude/settings.json \
                 or settings.local.json (`memprove hook install` adds one)",
                root.display()
            ),
        );
    }
    let mut detail = String::new();
    let mut broken = false;
    for (path, program, _) in &found {
        let executable = fs::metadata(program)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0);
        let state = if !Path::new(program).is_absolute() {
            broken = true;
            "which is not an absolute path"
        } else if executable {
            "which exists"
        } else {
            broken = true;
            "which does not exist or is not executable"
        };
        if !detail.is_empty() {
            detail.push_str("; ");
        }
        write!(
            detail,
            "{} runs {program} hook session-start, {state}",
            path.display()
        )
        .expect("writing to a String cannot fail");
    }
    let (file, value) = env.map_or((String::new(), None), |(path, value)| {
        (path.display().to_string(), value)
    });
    // U7 P2 (Owner O4): an argument is checked, else the env.
    let arguments = found
        .iter()
        .filter_map(|(_, _, dir)| dir.as_deref())
        .collect::<Vec<_>>();
    let (status, clause) = if arguments.is_empty() {
        env_against(&file, value.as_deref(), config, "the hook")
    } else {
        argument_against(&arguments, config, "the hook")
    };
    write!(detail, "; {clause}").expect("writing to a String cannot fail");
    let status = if broken { Status::Fail } else { status };
    check("hook", status, detail)
}

/// The worse of two statuses.
fn worse(left: Status, right: Status) -> Status {
    match (left, right) {
        (Status::Fail, _) | (_, Status::Fail) => Status::Fail,
        (Status::Warn, _) | (_, Status::Warn) => Status::Warn,
        _ => Status::Pass,
    }
}

/// U24 follow-up: the `client-hooks` line, made only when the Workspace
/// root has Codex's `.codex/hooks.json`, Cursor's `.cursor/hooks.json`, or
/// TRAE's `.trae/hooks.json` (`memprove init --client codex|cursor|trae`
/// writes them). Each file must hold
/// the handler `init` writes: WARN when it has none; FAIL when its program
/// is not an absolute path to an executable file, when Cursor's lacks
/// `--client cursor` (Cursor would get text where it reads JSON), or when
/// its `--config-dir` names another configuration directory than doctor
/// uses; WARN when it has no `--config-dir`. Whether Codex trusts the
/// project and approved the hook in `/hooks`, or TRAE trusts the folder and
/// enabled the hook, is the client's own state and is not checked; the line
/// says so. TRAE's `.trae/mcp.json` is checked too ([`trae_mcp_clause`]).
#[allow(clippy::too_many_lines)] // One pass over every client's hooks file.
fn client_hooks_check(root: &Path, config: Option<&Path>) -> Option<Check> {
    let mut status = Status::Pass;
    let mut detail = String::new();
    let mut dirs = Vec::new();
    let mut codex = false;
    let mut trae = false;
    for (file, cursor, client) in [
        (crate::hook::CODEX_HOOKS_FILE, false, "codex"),
        (crate::hook::CURSOR_HOOKS_FILE, true, "cursor"),
        (crate::hook::TRAE_HOOKS_FILE, false, "trae"),
    ] {
        let path = root.join(file);
        let value = match read_json(&path, "client-hooks") {
            Ok(Some(value)) => value,
            Ok(None) => continue,
            Err(line) => return Some(line),
        };
        codex |= client == "codex";
        trae |= client == "trae";
        if !detail.is_empty() {
            detail.push_str("; ");
        }
        let commands = crate::hook::client_hook_commands(&value, cursor);
        if commands.is_empty() {
            status = worse(status, Status::Warn);
            write!(
                detail,
                "{} runs no `memprove hook session-start` (`memprove init --client {client}` \
                 writes one)",
                path.display()
            )
            .expect("writing to a String cannot fail");
            continue;
        }
        for words in &commands {
            let program = words.first().map_or("", String::as_str);
            let executable = fs::metadata(program).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            });
            let state = if !Path::new(program).is_absolute() {
                status = Status::Fail;
                "which is not an absolute path"
            } else if executable {
                "which exists"
            } else {
                status = Status::Fail;
                "which does not exist or is not executable"
            };
            write!(
                detail,
                "{} runs {program} hook session-start, {state}",
                path.display()
            )
            .expect("writing to a String cannot fail");
            let rest = words.get(3..).unwrap_or_default();
            if cursor
                && !rest
                    .windows(2)
                    .any(|pair| pair == crate::hook::CURSOR_CLIENT_ARGUMENTS)
            {
                status = Status::Fail;
                detail.push_str(
                    ", without --client cursor, so Cursor gets text where it reads JSON \
                     (`memprove init --client cursor` writes it again)",
                );
            }
            if let Some(pair) = rest
                .windows(2)
                .find(|pair| pair[0] == crate::CONFIG_DIR_OPTION)
            {
                dirs.push(pair[1].clone());
            } else {
                status = worse(status, Status::Warn);
                detail.push_str(
                    ", with no --config-dir, so it uses MEMPROVE_CONFIG_DIR of the \
                     client's environment, else the default directory",
                );
            }
        }
    }
    let trae_mcp = match trae_mcp_clause(root) {
        Ok(clause) => clause,
        Err(line) => return Some(line),
    };
    if detail.is_empty() && trae_mcp.is_none() {
        return None;
    }
    if !dirs.is_empty() {
        let dirs: Vec<&str> = dirs.iter().map(String::as_str).collect();
        let (dir_status, clause) = argument_against(&dirs, config, "the client's hook");
        status = worse(status, dir_status);
        write!(detail, "; {clause}").expect("writing to a String cannot fail");
    }
    if let Some((mcp_status, clause)) = &trae_mcp {
        status = worse(status, *mcp_status);
        if !detail.is_empty() {
            detail.push_str("; ");
        }
        detail.push_str(clause);
    }
    if codex {
        detail.push_str(
            "; Codex runs it only in a project you trust, after you approve it in /hooks \
             (not checked here)",
        );
    }
    if trae {
        detail.push_str(
            "; TRAE runs it only in a folder you trust, once the hook is enabled in Settings > \
             Hooks (not checked here)",
        );
    }
    if trae_mcp.is_some() {
        detail.push_str(
            "; TRAE starts the server only once Enable Project MCP and the memprove server are \
             both switched on in Settings > MCP (not checked here)",
        );
    }
    Some(check("client-hooks", status, detail))
}

/// TRAE's `.trae/mcp.json` (`memprove init --client trae` writes it): TRAE
/// starts a project's MCP servers in the user's home directory and sets no
/// `CLAUDE_PROJECT_DIR`, so its `mcpServers.memprove` must carry the
/// Workspace root in `env.CLAUDE_PROJECT_DIR`, else the server resolves no
/// Workspace: PASS when it is `root`, WARN when it is missing (0.3.0 wrote
/// none), FAIL when it names another directory. `None` when there is no
/// such file or entry; `Err` the line when the file cannot be read.
fn trae_mcp_clause(root: &Path) -> Result<Option<(Status, String)>, Check> {
    let path = root.join(crate::init::TRAE_MCP_FILE);
    let Some(value) = read_json(&path, "client-hooks")? else {
        return Ok(None);
    };
    let Some(entry) = value
        .get("mcpServers")
        .and_then(|servers| servers.get("memprove"))
    else {
        return Ok(None);
    };
    let variable = crate::mcp::PROJECT_DIR_ENV;
    let project_dir = entry
        .get("env")
        .and_then(|env| env.get(variable))
        .and_then(JsonValue::as_str);
    Ok(Some(match project_dir {
        Some(dir) if same_dir(Path::new(dir), root) => (
            Status::Pass,
            format!(
                "{} gives the memprove MCP server the Workspace root as {variable}",
                path.display()
            ),
        ),
        Some(dir) => (
            Status::Fail,
            format!(
                "{} gives the memprove MCP server {variable}={dir}, not the Workspace root {}, \
                 so its tools would use another Workspace (`memprove init --client trae` writes \
                 it again)",
                path.display(),
                root.display()
            ),
        ),
        None => (
            Status::Warn,
            format!(
                "{} gives the memprove MCP server no {variable}; TRAE starts it in your home \
                 directory, so its tools find no Workspace (`memprove init --client trae` \
                 writes it)",
                path.display()
            ),
        ),
    }))
}

/// U5 P3 (Owner O5): the `mcp-entry` line; U5 Z-F round 1 (S1, the
/// Owner's O5 revision): `mcpServers.memprove` of `<Workspace
/// root>/.mcp.json`, the file Claude Code reads it from: PASS when its
/// `env.MEMPROVE_CONFIG_DIR` is the configuration directory doctor uses,
/// WARN when there is none or it has no such `env`, FAIL when it names
/// another directory or the file cannot be read. An `mcpServers.memprove`
/// in `.claude/settings.local.json` or `.claude/settings.json` counts for
/// nothing (Claude Code does not read it); the line says so.
fn mcp_entry_check(root: &Path, config: Option<&Path>) -> Check {
    let mut ignored = String::new();
    for name in ["settings.local.json", "settings.json"] {
        let path = root.join(".claude").join(name);
        // A settings file that cannot be read is the hook line's to report.
        let Ok(Some(value)) = read_json(&path, "mcp-entry") else {
            continue;
        };
        if value
            .get("mcpServers")
            .and_then(|servers| servers.get("memprove"))
            .is_some()
        {
            write!(
                ignored,
                "; {} has an mcpServers.memprove, which Claude Code does not read \
                 (`memprove hook install` takes out one it wrote)",
                path.display()
            )
            .expect("writing to a String cannot fail");
        }
    }
    let path = root.join(crate::mcp::PROJECT_CONFIG_FILE);
    let entry = match read_json(&path, "mcp-entry") {
        Ok(Some(value)) => value
            .get("mcpServers")
            .and_then(|servers| servers.get("memprove"))
            .cloned(),
        Ok(None) => None,
        Err(line) => return line,
    };
    let file = path.display().to_string();
    let Some(entry) = entry else {
        return check(
            "mcp-entry",
            Status::Warn,
            format!(
                "no mcpServers.memprove in {file} (`memprove hook install` writes one; \
                 `memprove mcp print-config` prints it){ignored}"
            ),
        );
    };
    let command = entry
        .get("command")
        .and_then(JsonValue::as_str)
        .unwrap_or("(no command)");
    // U7 P2 (Owner O4): `mcp serve --config-dir <DIR>` is checked, else the
    // env.
    let args = entry
        .get("args")
        .and_then(JsonValue::as_array)
        .map(|args| {
            args.iter()
                .filter_map(JsonValue::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let (status, clause) = match args.as_slice() {
        ["mcp", "serve", option, dir] if *option == crate::CONFIG_DIR_OPTION => {
            argument_against(&[dir], config, "the server")
        }
        _ => env_against(&file, config_env(&entry), config, "the server"),
    };
    check(
        "mcp-entry",
        status,
        format!("{file} has mcpServers.memprove, which runs {command}; {clause}{ignored}"),
    )
}

fn ledger_check(lookup: &ContextLookup, reach: &Reach) -> Check {
    let Some(context) = lookup.context() else {
        return check(
            "ledger",
            Status::Warn,
            "not checked: no context names a Project here",
        );
    };
    let Some((socket, token)) = reach.usable() else {
        return check("ledger", Status::Warn, reach.why_not());
    };
    let body = format!(
        r#"{{"schema_version":1,"project_id":{}}}"#,
        json_string(&context.project_id)
    );
    let Some((status, reply)) = send(
        socket,
        Some(token),
        OperationId::VerifyLedger,
        "/v1/verification/ledger",
        Some(&body),
    ) else {
        return check(
            "ledger",
            Status::Warn,
            "not checked: verifyLedger did not answer",
        );
    };
    let Some(report) = (status == 200).then(|| parse_strict(&reply).ok()).flatten() else {
        return check(
            "ledger",
            Status::Warn,
            format!("not checked: verifyLedger answered {status}"),
        );
    };
    let number = |value: Option<&JsonValue>| value.and_then(JsonValue::as_i64).unwrap_or_default();
    let checked = report.get("checked");
    let counted = |name: &str| number(checked.and_then(|checked| checked.get(name)));
    let head = report
        .get("head_event_sha256")
        .and_then(JsonValue::as_str)
        .unwrap_or("none");
    let summary = format!(
        "Project {}: {} events, {} evidence, {} snapshots, {} checkpoints, {} tasks; sequence {}, \
         head {head}",
        context.project_id,
        counted("events"),
        counted("evidence"),
        counted("snapshots"),
        counted("checkpoints"),
        counted("tasks"),
        number(report.get("project_sequence")),
    );
    if report.get("valid") == Some(&JsonValue::Bool(true)) {
        return check("ledger", Status::Pass, format!("valid; {summary}"));
    }
    let failure = report.get("first_failure");
    let text = |name: &str| {
        failure
            .and_then(|failure| failure.get(name))
            .and_then(JsonValue::as_str)
            .unwrap_or("?")
            .to_owned()
    };
    check(
        "ledger",
        Status::Fail,
        format!(
            "a record does not hold: {} {} ({}); {summary}",
            text("record_type"),
            text("record_id"),
            text("reason")
        ),
    )
}

/// The report as text: one line per check, then the counts.
#[must_use]
pub fn render_text(checks: &[Check]) -> String {
    let mut out = String::new();
    for entry in checks {
        writeln!(
            out,
            "{} {:<11} {}",
            entry.status.as_str(),
            format!("{}:", entry.check),
            entry.detail
        )
        .expect("writing to a String cannot fail");
    }
    let (pass, warn, fail) = counts(checks);
    writeln!(
        out,
        "memprove doctor: {pass} PASS, {warn} WARN, {fail} FAIL"
    )
    .expect("writing to a String cannot fail");
    out
}

/// The report as one JSON document.
#[must_use]
pub fn render_json(checks: &[Check]) -> String {
    let (pass, warn, fail) = counts(checks);
    let items: Vec<String> = checks
        .iter()
        .map(|entry| {
            format!(
                r#"{{"check":{},"status":{},"detail":{}}}"#,
                json_string(entry.check),
                json_string(entry.status.as_str()),
                json_string(&entry.detail)
            )
        })
        .collect();
    format!(
        r#"{{"schema_version":1,"cli":{},"checks":[{}],"pass":{pass},"warn":{warn},"fail":{fail}}}"#,
        json_string(&format!("{} ({BUILD_ID})", env!("CARGO_PKG_VERSION"))),
        items.join(",")
    ) + "\n"
}

fn counts(checks: &[Check]) -> (usize, usize, usize) {
    let count = |status: Status| checks.iter().filter(|entry| entry.status == status).count();
    (
        count(Status::Pass),
        count(Status::Warn),
        count(Status::Fail),
    )
}

/// Whether any check failed.
#[must_use]
pub fn failed(checks: &[Check]) -> bool {
    checks.iter().any(|entry| entry.status == Status::Fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_programs_finds_the_exec_and_the_shell_form_only() {
        let settings = parse_strict(
            r#"{"hooks":{"SessionStart":[
                {"hooks":[{"type":"command","command":"/a/memprove","args":["hook","session-start"]}]},
                {"hooks":[{"type":"command","command":"/b/memprove hook session-start"}]},
                {"hooks":[{"type":"command","command":"/c/other","args":["x"]}]},
                {"hooks":[{"type":"command","command":"echo hi"}]},
                {"hooks":[{"type":"command","command":"/d/memprove","args":["hook","session-start","--config-dir","/cfg"]}]},
                {"hooks":[{"type":"command","command":"/e/memprove hook session-start --config-dir /cfg2"}]}
            ]}}"#,
        )
        .unwrap();
        // U7 P2: with the directory of --config-dir, when there is one.
        assert_eq!(
            hook_programs(&settings),
            [
                ("/a/memprove".to_owned(), None),
                ("/b/memprove".to_owned(), None),
                ("/d/memprove".to_owned(), Some("/cfg".to_owned())),
                ("/e/memprove".to_owned(), Some("/cfg2".to_owned())),
            ]
        );
        assert!(hook_programs(&parse_strict("{}").unwrap()).is_empty());
    }

    /// U10 N9 (D3 F28): the `guide` line by layout and content.
    #[test]
    fn u10_n9_the_guide_line_compares_the_first_line_with_the_build() {
        let prefix = tempfile::tempdir().unwrap();
        let root = prefix.path();
        // Not an installation: a build tree's `debug/` directory.
        let loose = root.join("debug/memprove");
        let outside = guide_check(Some(&loose), "abc123def456");
        assert_eq!(outside.status, Status::Pass, "{}", outside.detail);
        assert!(outside.detail.contains("not in an installation"));
        assert_eq!(guide_check(None, "abc123def456").status, Status::Pass);

        // An installation: `bin/` beside `data/` and `config/`.
        for dir in ["bin", "data", "config", "share"] {
            std::fs::create_dir(root.join(dir)).unwrap();
        }
        let exe = root.join("bin/memprove");
        let guide = root.join("share/guide.md");
        let seen = |content: Option<&[u8]>| {
            match content {
                Some(content) => std::fs::write(&guide, content).unwrap(),
                None => drop(std::fs::remove_file(&guide)),
            }
            guide_check(Some(&exe), "abc123def456")
        };
        let same = seen(Some(
            b"<!-- installed with build abc123def456 -->\n# Guide\n",
        ));
        assert_eq!(same.status, Status::Pass, "{}", same.detail);
        let dirty = seen(Some(
            b"<!-- installed with build abc123def456-dirty -->\n# Guide\n",
        ));
        assert_eq!(dirty.status, Status::Warn);
        assert!(
            dirty.detail.contains("abc123def456-dirty"),
            "{}",
            dirty.detail
        );
        let plain = seen(Some(b"# Guide\n"));
        assert_eq!(plain.status, Status::Warn);
        assert!(
            plain.detail.contains("no build comment"),
            "{}",
            plain.detail
        );
        let binary = seen(Some(b"<!-- installed with build \xff\xfe -->\n"));
        assert_eq!(binary.status, Status::Warn);
        let loud = seen(Some(
            format!("<!-- installed with build {} -->\n", "x".repeat(200)).as_bytes(),
        ));
        assert_eq!(loud.status, Status::Warn);
        let gone = seen(None);
        assert_eq!(gone.status, Status::Warn);
        assert!(gone.detail.contains("there is no guide"), "{}", gone.detail);
    }

    /// U24 follow-up: the `client-hooks` line reads `.codex/hooks.json` and
    /// `.cursor/hooks.json` and is left out when neither exists.
    #[test]
    fn u24_the_client_hooks_line_checks_the_codex_and_cursor_handlers() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("repo");
        let config = scratch.path().join("config");
        let bin = scratch.path().join("bin dir");
        for dir in [
            &root,
            &config,
            &bin,
            &root.join(".codex"),
            &root.join(".cursor"),
        ] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let exe = bin.join("memprove");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (exe, dir) = (exe.to_str().unwrap(), config.to_str().unwrap());
        let codex_file = root.join(crate::hook::CODEX_HOOKS_FILE);
        let cursor_file = root.join(crate::hook::CURSOR_HOOKS_FILE);
        let write = |path: &Path, text: &str| std::fs::write(path, text).unwrap();
        let line = || client_hooks_check(&root, Some(&config));

        assert_eq!(line(), None, "no hooks file, no line");

        // What `init` writes passes, both files at once.
        crate::hook::install_codex_hooks(&codex_file, exe, dir).unwrap();
        crate::hook::install_cursor_hooks(&cursor_file, exe, dir).unwrap();
        let both = line().unwrap();
        assert_eq!(both.check, "client-hooks");
        assert_eq!(both.status, Status::Pass, "{}", both.detail);
        assert!(
            both.detail
                .contains(&format!("runs {exe} hook session-start, which exists"))
        );
        assert!(
            both.detail.contains("/hooks (not checked here)"),
            "{}",
            both.detail
        );

        // Cursor alone: no Codex sentence.
        std::fs::remove_file(&codex_file).unwrap();
        let cursor = line().unwrap();
        assert_eq!(cursor.status, Status::Pass, "{}", cursor.detail);
        assert!(!cursor.detail.contains("in /hooks"), "{}", cursor.detail);

        // Another configuration directory fails.
        let other = scratch.path().join("other");
        std::fs::create_dir(&other).unwrap();
        crate::hook::install_cursor_hooks(&cursor_file, exe, other.to_str().unwrap()).unwrap();
        let moved = line().unwrap();
        assert_eq!(moved.status, Status::Fail, "{}", moved.detail);

        // Cursor's handler without --client cursor fails.
        write(
            &cursor_file,
            &format!(
                r#"{{"version":1,"hooks":{{"sessionStart":[{{"command":"'{exe}' hook session-start --config-dir '{dir}'"}}]}}}}"#
            ),
        );
        let plain = line().unwrap();
        assert_eq!(plain.status, Status::Fail, "{}", plain.detail);
        assert!(
            plain.detail.contains("without --client cursor"),
            "{}",
            plain.detail
        );

        // A program that is gone fails; no --config-dir warns.
        write(
            &cursor_file,
            r#"{"version":1,"hooks":{"sessionStart":[{"command":"/gone/memprove hook session-start --client cursor"}]}}"#,
        );
        let gone = line().unwrap();
        assert_eq!(gone.status, Status::Fail, "{}", gone.detail);
        assert!(gone.detail.contains("does not exist"), "{}", gone.detail);
        assert!(gone.detail.contains("no --config-dir"), "{}", gone.detail);

        // A file without memprove's handler warns; one that is not JSON fails.
        write(
            &cursor_file,
            r#"{"version":1,"hooks":{"sessionStart":[{"command":"echo hi"}]}}"#,
        );
        let foreign = line().unwrap();
        assert_eq!(foreign.status, Status::Warn, "{}", foreign.detail);
        assert!(
            foreign.detail.contains("memprove init --client cursor"),
            "{}",
            foreign.detail
        );
        write(&cursor_file, "{");
        assert_eq!(line().unwrap().status, Status::Fail);
    }

    /// TRAE: the `client-hooks` line reads `.trae/hooks.json` as Codex's
    /// (the same `SessionStart` groups and shell command line) and says
    /// that TRAE's trust is not checked, without the Codex sentence.
    #[test]
    fn trae_the_client_hooks_line_checks_the_trae_handler() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("repo");
        let config = scratch.path().join("config");
        let bin = scratch.path().join("bin");
        for dir in [&root, &config, &bin] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let exe = bin.join("memprove");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (exe, dir) = (exe.to_str().unwrap(), config.to_str().unwrap());
        let trae_file = root.join(crate::hook::TRAE_HOOKS_FILE);
        crate::hook::install_trae_hooks(&trae_file, exe, dir).unwrap();
        let line = client_hooks_check(&root, Some(&config)).unwrap();
        assert_eq!(line.status, Status::Pass, "{}", line.detail);
        assert!(
            line.detail
                .contains(&format!("runs {exe} hook session-start, which exists")),
            "{}",
            line.detail
        );
        assert!(
            line.detail.contains("Settings > Hooks (not checked here)"),
            "{}",
            line.detail
        );
        assert!(!line.detail.contains("in /hooks"), "{}", line.detail);

        // Another configuration directory fails; no handler warns.
        let other = scratch.path().join("other");
        std::fs::create_dir(&other).unwrap();
        crate::hook::install_trae_hooks(&trae_file, exe, other.to_str().unwrap()).unwrap();
        let moved = client_hooks_check(&root, Some(&config)).unwrap();
        assert_eq!(moved.status, Status::Fail, "{}", moved.detail);
        std::fs::write(
            &trae_file,
            r#"{"version":1,"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo hi"}]}]}}"#,
        )
        .unwrap();
        let foreign = client_hooks_check(&root, Some(&config)).unwrap();
        assert_eq!(foreign.status, Status::Warn, "{}", foreign.detail);
        assert!(
            foreign.detail.contains("memprove init --client trae"),
            "{}",
            foreign.detail
        );

        // .trae/mcp.json: the Workspace root as CLAUDE_PROJECT_DIR passes,
        // none (as 0.3.0 wrote it) warns, another directory fails.
        crate::hook::install_trae_hooks(&trae_file, exe, dir).unwrap();
        let mcp_file = root.join(crate::init::TRAE_MCP_FILE);
        let root_text = root.to_str().unwrap();
        crate::hook::install_trae_mcp_json(&mcp_file, exe, dir, root_text).unwrap();
        let served = client_hooks_check(&root, Some(&config)).unwrap();
        assert_eq!(served.status, Status::Pass, "{}", served.detail);
        assert!(
            served
                .detail
                .contains("the Workspace root as CLAUDE_PROJECT_DIR"),
            "{}",
            served.detail
        );
        assert!(
            served.detail.contains("Settings > MCP (not checked here)"),
            "{}",
            served.detail
        );
        crate::hook::install_mcp_json(&mcp_file, exe, dir).unwrap();
        let unset = client_hooks_check(&root, Some(&config)).unwrap();
        assert_eq!(unset.status, Status::Warn, "{}", unset.detail);
        assert!(
            unset
                .detail
                .contains("no CLAUDE_PROJECT_DIR; TRAE starts it in your home"),
            "{}",
            unset.detail
        );
        crate::hook::install_trae_mcp_json(&mcp_file, exe, dir, other.to_str().unwrap()).unwrap();
        let elsewhere = client_hooks_check(&root, Some(&config)).unwrap();
        assert_eq!(elsewhere.status, Status::Fail, "{}", elsewhere.detail);
        // The MCP file alone still gets the line.
        std::fs::remove_file(&trae_file).unwrap();
        crate::hook::install_trae_mcp_json(&mcp_file, exe, dir, root_text).unwrap();
        let alone = client_hooks_check(&root, Some(&config)).unwrap();
        assert_eq!(alone.status, Status::Pass, "{}", alone.detail);
        assert!(
            !alone.detail.contains("Settings > Hooks"),
            "{}",
            alone.detail
        );
        std::fs::write(&mcp_file, "{").unwrap();
        assert_eq!(
            client_hooks_check(&root, Some(&config)).unwrap().status,
            Status::Fail
        );
    }

    #[test]
    fn the_text_report_counts_its_lines() {
        let checks = [
            check("daemon", Status::Pass, "up"),
            check("token", Status::Warn, "control"),
            check("build", Status::Fail, "differs"),
        ];
        assert_eq!(
            render_text(&checks),
            "PASS daemon:     up\nWARN token:      control\nFAIL build:      differs\n\
             memprove doctor: 1 PASS, 1 WARN, 1 FAIL\n"
        );
        assert!(failed(&checks));
        assert!(render_json(&checks).contains(r#""pass":1,"warn":1,"fail":1}"#));
    }
}
