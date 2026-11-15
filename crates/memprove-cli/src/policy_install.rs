//! `memprove policy init`'s hooks: the [`memprove_policy::cli::Installer`]
//! the CLI gives the policy crate, writing the policy hook of each client
//! into the repository's client settings with the same editing `memprove
//! init` uses (other entries kept, the file rewritten only when it changes),
//! and keeping those files out of Evidence (`.git/info/exclude`).

use std::path::Path;

use memprove_policy::Client;

use crate::{
    hook::{self, Change},
    init::{self, Step},
};

/// What Codex needs before it runs the policy hook.
pub const CODEX_TRUST_NOTE: &str = "Codex runs this hook only after you trust it: start Codex in \
                                    this repository, trust the project, and approve the memprove \
                                    policy hook in /hooks";

/// What Cursor needs before it runs the policy hook.
pub const CURSOR_TRUST_NOTE: &str = "Cursor runs project hooks only in a trusted workspace; its \
                                     Hooks output channel shows each run";

/// What `policy init` says when it detects TRAE, which has no policy hook
/// yet.
pub const TRAE_NOTE: &str = "TRAE is detected, but memprove policy has no hook for it yet: \
                             TRAE's tool calls are not checked against the policy";

/// The installer `memprove policy init` uses.
#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyInstaller;

/// The policy client of a client `init` detects; `None` for TRAE, which has
/// no policy hook yet ([`TRAE_NOTE`]).
const fn client_of(client: init::Client) -> Option<Client> {
    match client {
        init::Client::ClaudeCode => Some(Client::ClaudeCode),
        init::Client::Codex => Some(Client::Codex),
        init::Client::Cursor => Some(Client::Cursor),
        init::Client::Trae => None,
    }
}

/// The settings file of `client` that holds its policy hook, relative to
/// the repository root.
#[must_use]
pub const fn hooks_file(client: Client) -> &'static str {
    match client {
        Client::ClaudeCode => hook::SETTINGS_FILE,
        Client::Codex => hook::CODEX_HOOKS_FILE,
        Client::Cursor => hook::CURSOR_HOOKS_FILE,
    }
}

fn step_of(change: Change) -> Step {
    match change {
        Change::Written(path) => Step::Written(path),
        Change::Unchanged(path) => Step::Unchanged(path),
    }
}

fn exclude_file(root: &Path) -> Result<std::path::PathBuf, String> {
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--git-path", "info/exclude"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|path| root.join(path.trim_end()))
        .ok_or_else(|| "git rev-parse --git-path info/exclude failed in the repository".to_owned())
}

impl memprove_policy::cli::Installer for PolicyInstaller {
    fn install(
        &self,
        root: &Path,
        clients: &[Client],
        dry_run: bool,
    ) -> Result<Vec<String>, String> {
        let mut trae = false;
        let clients: Vec<Client> = if clients.is_empty() {
            let home = std::env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map(std::path::PathBuf::from);
            let detected = init::detect_clients(
                home.as_deref(),
                std::env::var_os("CODEX_HOME").as_deref(),
                std::env::var_os("PATH").as_deref(),
            );
            trae = detected.contains(&init::Client::Trae);
            detected.into_iter().filter_map(client_of).collect()
        } else {
            clients.to_vec()
        };
        if clients.is_empty() {
            let mut lines = vec![
                "clients: none detected; --client claude-code, --client codex, or --client \
                 cursor names one"
                    .to_owned(),
            ];
            if trae {
                lines.push(format!("note: {TRAE_NOTE}"));
            }
            return Ok(lines);
        }
        let names: Vec<&str> = clients.iter().map(|client| client.name()).collect();
        let mut lines = vec![format!("clients: {}", names.join(", "))];
        let executable = hook::executable()?;
        let entries: Vec<&str> = clients.iter().map(|client| hooks_file(*client)).collect();
        let exclude = exclude_file(root)?;
        lines.push(
            init::edit_text(&exclude, false, dry_run, |existing| {
                init::exclude_with(existing, &entries)
            })?
            .to_string(),
        );
        for client in clients {
            let file = root.join(hooks_file(client));
            let step = if dry_run {
                Step::WouldWrite(file)
            } else {
                step_of(match client {
                    Client::ClaudeCode => hook::install_policy_claude(&file, &executable)?,
                    Client::Codex => hook::install_policy_codex(&file, &executable)?,
                    Client::Cursor => hook::install_policy_cursor(&file, &executable)?,
                })
            };
            lines.push(format!("{}: {step}", client.title()));
            match client {
                Client::Codex => lines.push(format!("note: {CODEX_TRUST_NOTE}")),
                Client::Cursor => lines.push(format!("note: {CURSOR_TRUST_NOTE}")),
                Client::ClaudeCode => {}
            }
        }
        if trae {
            lines.push(format!("note: {TRAE_NOTE}"));
        }
        Ok(lines)
    }
}
