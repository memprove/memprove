//! U17 (M1 O4): `memprove init`, the one command that enables memprove
//! in a repository after `scripts/install.sh`: it registers the Project with
//! the operator's token, keeps memprove's files out of Evidence
//! (`.git/info/exclude`), writes the `SessionStart` hook and the MCP server
//! entry for Claude Code, the MCP server entry for Codex
//! (`~/.codex/config.toml`) and Cursor (`.cursor/mcp.json`), U24 (H1, H2):
//! their session-start hooks (`.codex/hooks.json`, `.cursor/hooks.json`), a
//! short note for the agent that reads no Pack at the start of its session
//! (AGENTS.md, `.cursor/rules/memprove.mdc`), for TRAE and TRAE CN the hook,
//! the server and the note in `.trae/` (`hooks.json`, `mcp.json`,
//! `rules/memprove.md`), and runs `doctor`. Which clients it
//! writes for is detected from the home directory and `PATH`, or given with
//! `--client`. The operator's and the agent's tokens stay hidden: the
//! operator's is read from the installation, the agent's was written by
//! `scripts/install.sh` into the configuration directory, where `begin`
//! reads it.
//!
//! The pure parts (what a file becomes) are here and unit-tested; the
//! orchestration that reads the process environment and talks to the
//! daemon is in the binary.

use std::{
    ffi::OsStr,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

/// A client `init` can enable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Client {
    /// Claude Code: the `SessionStart` hook, `.mcp.json`, and the allow rules.
    ClaudeCode,
    /// Codex: `~/.codex/config.toml`, U24 (H1) the hook in
    /// `.codex/hooks.json`, and a note in AGENTS.md.
    Codex,
    /// Cursor: `.cursor/mcp.json`, U24 (H2) the hook in `.cursor/hooks.json`,
    /// and `.cursor/rules/memprove.mdc`.
    Cursor,
    /// TRAE and TRAE CN: the hook in `.trae/hooks.json`, `.trae/mcp.json`, and
    /// `.trae/rules/memprove.md`.
    Trae,
}

impl Client {
    /// Every client, in the order `init` handles them.
    pub const ALL: [Self; 4] = [Self::ClaudeCode, Self::Codex, Self::Cursor, Self::Trae];

    /// The name `--client` takes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::Trae => "trae",
        }
    }

    /// The client named `name`, if any.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|client| client.name() == name)
    }
}

/// What `init` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitSpec {
    /// `--client`, each once; empty means detect.
    pub clients: Vec<Client>,
    /// `--operator-token`, the operator's control token file; the default
    /// is the installation's (`<configuration directory>/../operator-token`).
    pub operator_token: Option<PathBuf>,
    /// `--dry-run`: say what would be written, write nothing, send nothing.
    pub dry_run: bool,
    /// U22 (Owner, 2026-11-11): `--allow-tools`: also write Claude Code's
    /// `permissions.allow` rules; without it they are only printed.
    pub allow_tools: bool,
}

/// The clients found on this machine: Claude Code when `~/.claude` exists
/// or `claude` is on `PATH`; Codex when its home (`$CODEX_HOME`, else `~/.codex`) exists or `codex` is on
/// `PATH`; Cursor when `~/.cursor` exists, `cursor` is on `PATH`, or
/// `/Applications/Cursor.app` exists; TRAE when `~/.trae-cn` (TRAE CN) or
/// `~/.trae` (TRAE) exists, the directories that hold its user hooks and
/// rules.
#[must_use]
pub fn detect_clients(
    home: Option<&Path>,
    codex_home: Option<&OsStr>,
    path: Option<&OsStr>,
) -> Vec<Client> {
    let on_path = |program: &str| {
        path.is_some_and(|path| std::env::split_paths(path).any(|dir| dir.join(program).is_file()))
    };
    let in_home = |name: &str| home.is_some_and(|home| home.join(name).is_dir());
    let mut found = Vec::new();
    if in_home(".claude") || on_path("claude") {
        found.push(Client::ClaudeCode);
    }
    if codex_home_dir(home, codex_home).is_some_and(|dir| dir.is_dir()) || on_path("codex") {
        found.push(Client::Codex);
    }
    if in_home(".cursor") || on_path("cursor") || Path::new("/Applications/Cursor.app").is_dir() {
        found.push(Client::Cursor);
    }
    if in_home(".trae-cn") || in_home(".trae") {
        found.push(Client::Trae);
    }
    found
}

/// Codex's home directory, where its `config.toml` lives: `$CODEX_HOME`
/// when it is set and not empty (Codex reads the same variable), else
/// `~/.codex`; `None` when neither is known.
#[must_use]
pub fn codex_home_dir(home: Option<&Path>, codex_home: Option<&OsStr>) -> Option<PathBuf> {
    match codex_home.filter(|value| !value.is_empty()) {
        Some(value) => Some(PathBuf::from(value)),
        None => home.map(|home| home.join(".codex")),
    }
}

/// The entries `init` adds to `.git/info/exclude`: the files it writes
/// inside the Workspace, which must not become untracked files (an untracked
/// file keeps a run's Evidence from being `verified`). The Codex hooks file
/// (U24 H1) is added when Codex is among `clients`, the Cursor files when
/// Cursor is, the TRAE files when TRAE is.
#[must_use]
pub fn exclude_entries(clients: &[Client]) -> Vec<&'static str> {
    let mut entries = vec![".claude/settings.local.json", ".mcp.json"];
    if clients.contains(&Client::Codex) {
        entries.push(crate::hook::CODEX_HOOKS_FILE);
    }
    if clients.contains(&Client::Cursor) {
        entries.push(".cursor/mcp.json");
        entries.push(".cursor/rules/memprove.mdc");
        entries.push(crate::hook::CURSOR_HOOKS_FILE);
    }
    if clients.contains(&Client::Trae) {
        entries.push(crate::hook::TRAE_HOOKS_FILE);
        entries.push(TRAE_MCP_FILE);
        entries.push(TRAE_RULE_FILE);
    }
    entries
}

/// `existing` (the text of an exclude file, or nothing) with each of
/// `entries` on a line of its own, added once; `None` when every entry is
/// there already.
#[must_use]
pub fn exclude_with(existing: Option<&str>, entries: &[&str]) -> Option<String> {
    let existing = existing.unwrap_or("");
    let present: Vec<&str> = existing.lines().map(str::trim).collect();
    let missing: Vec<&str> = entries
        .iter()
        .copied()
        .filter(|entry| !present.contains(entry))
        .collect();
    if missing.is_empty() {
        return None;
    }
    let mut text = existing.to_owned();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for entry in missing {
        text.push_str(entry);
        text.push('\n');
    }
    Some(text)
}

/// The first and last line of the note `init` keeps in AGENTS.md, so that
/// it is written once and replaced, never duplicated.
pub const NOTE_BEGIN: &str = "<!-- memprove:begin -->";
/// See [`NOTE_BEGIN`].
pub const NOTE_END: &str = "<!-- memprove:end -->";

/// What `init` says after writing AGENTS.md: the file is content of the
/// repository, so it is committed, not excluded like the client files.
pub const AGENTS_COMMIT_NOTE: &str = "AGENTS.md is content of the repository: commit it, since \
                                      an untracked file keeps a run's Evidence from being verified";

/// U24 (H1): what `init` says after writing `.codex/hooks.json`: Codex
/// runs a project's hooks only in a project it trusts, and a new or changed
/// hook only after the user trusted it; `init` does not trust it for them.
pub const CODEX_TRUST_NOTE: &str = "Codex runs this hook only after you trust it: start Codex \
                                    in this repository, trust the project, and approve the \
                                    memprove hook in /hooks; until then the note in AGENTS.md \
                                    tells the agent to read the Pack through the MCP tool pack";

/// TRAE: the file TRAE reads a project's MCP servers from, relative to the
/// Workspace root; TRAE loads it once project MCP is turned on in its
/// settings.
pub const TRAE_MCP_FILE: &str = ".trae/mcp.json";

/// TRAE: the project rule `init` writes, relative to the Workspace root.
pub const TRAE_RULE_FILE: &str = ".trae/rules/memprove.md";

/// TRAE: what `init` says after writing `.trae/hooks.json`: TRAE runs a
/// project's hooks only in a folder the user trusts, once the hook is
/// enabled, and reads `.trae/mcp.json` only with project MCP on; `init`
/// turns on none of them. A hook TRAE runs in its sandbox has restricted
/// file access, so it may not reach the configuration directory or the
/// daemon's socket. With its import of Claude Code hooks on, TRAE also runs
/// the handler of `.claude/settings.local.json`.
pub const TRAE_TRUST_NOTE: &str = "TRAE runs this hook only after you allow it: open this \
                                   repository in TRAE (or TRAE CN), trust the folder, enable the \
                                   memprove hook in Settings > Hooks with local runs (in the \
                                   sandbox it may not reach memprove), turn on project MCP in \
                                   Settings > MCP, and keep the import of Claude Code hooks off, \
                                   or TRAE runs memprove's Claude Code hook as well; until then \
                                   the rule in .trae/rules tells the agent to read the Pack \
                                   through the MCP tool pack";

/// The note for an agent whose session started without a Pack (AGENTS.md
/// for Codex, a Cursor rule; U24: a hook Codex has not been allowed to run,
/// or Cursor's Agents Window, which drops a `sessionStart` hook's context):
/// one sentence, under five lines in all with its markers, that tells the
/// agent to read the Context Pack through the MCP tool `pack` first.
pub const NOTE: &str = "memprove keeps this repository's task ledger. Before changing anything, \
call the MCP tool `pack` of the server `memprove` and read the Context Pack it returns; record \
facts with its `checkpoint` tool, citing a `memprove run` of the tests, and end your Session \
with `end`.";

/// U22 (U20-N1): the markers of the note `init` wrote under the previous
/// name, `continuity`; [`agents_with_note`] puts this note in its place.
pub const PREVIOUS_NOTE_BEGIN: &str = "<!-- continuity:begin -->";
/// See [`PREVIOUS_NOTE_BEGIN`].
pub const PREVIOUS_NOTE_END: &str = "<!-- continuity:end -->";

/// U22 (U20-N1): the note `init` wrote under the previous name, which its
/// Cursor rule `.cursor/rules/continuity.mdc` held.
const PREVIOUS_NOTE: &str = "Continuity keeps this repository's task ledger. Before changing \
anything, call the MCP tool `pack` of the server `continuity` and read the Context Pack it \
returns; record facts with its `checkpoint` tool, citing a `continuity run` of the tests, and \
end your Session with `end`.";

/// U22 (U20-N1): the file name of the Cursor rule `init` wrote under the
/// previous name, in `.cursor/rules/`.
pub const PREVIOUS_CURSOR_RULE_FILE: &str = "continuity.mdc";

/// U22 (U20-N1): whether `text` is exactly the Cursor rule `init` wrote under
/// the previous name, so that removing the file loses nothing anyone wrote.
#[must_use]
pub fn is_previous_cursor_rule(text: &str) -> bool {
    text == format!("---\nalwaysApply: true\n---\n{PREVIOUS_NOTE}\n")
}

/// The span of the note between `begin` and `end` in `text`, with the line
/// end after `end` when there is one.
fn marked(text: &str, begin: &str, end: &str) -> Option<(usize, usize)> {
    let start = text.find(begin)?;
    let stop = text.find(end).filter(|stop| *stop >= start)?;
    let after = stop + end.len();
    Some((
        start,
        if text[after..].starts_with('\n') {
            after + 1
        } else {
            after
        },
    ))
}

/// `existing` (AGENTS.md, or nothing) with the note between its markers:
/// appended when absent, replaced when a marked note is there; `None` when
/// the file already holds exactly this note. U22 (U20-N1): a note of the
/// previous name ([`PREVIOUS_NOTE_BEGIN`]) is taken out, and this note goes
/// in its place when the file holds none of its own.
#[must_use]
pub fn agents_with_note(existing: Option<&str>) -> Option<String> {
    let block = format!("{NOTE_BEGIN}\n{NOTE}\n{NOTE_END}\n");
    let original = existing.unwrap_or("");
    let (text, previous_at) = match marked(original, PREVIOUS_NOTE_BEGIN, PREVIOUS_NOTE_END) {
        Some((start, after)) => (
            format!("{}{}", &original[..start], &original[after..]),
            Some(start),
        ),
        None => (original.to_owned(), None),
    };
    let text = if let Some((start, after)) = marked(&text, NOTE_BEGIN, NOTE_END) {
        format!("{}{block}{}", &text[..start], &text[after..])
    } else if let Some(start) = previous_at {
        format!("{}{block}{}", &text[..start], &text[start..])
    } else {
        let mut text = text;
        if !text.is_empty() {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push('\n');
        }
        text.push_str(&block);
        text
    };
    (text != original).then_some(text)
}

/// The Cursor rule `init` writes at `.cursor/rules/memprove.mdc`: always
/// applied, the one sentence of [`NOTE`].
#[must_use]
pub fn cursor_rule() -> String {
    format!("---\nalwaysApply: true\n---\n{NOTE}\n")
}

/// TRAE: the project rule `init` writes at `.trae/rules/memprove.md`:
/// always applied (TRAE's rule frontmatter is Cursor's), the one sentence
/// of [`NOTE`].
#[must_use]
pub fn trae_rule() -> String {
    format!("---\nalwaysApply: true\n---\n{NOTE}\n")
}

/// The header of the table `init` writes into `~/.codex/config.toml`.
pub const CODEX_TABLE: &str = "[mcp_servers.memprove]";

/// U22 (U20-N1): the header of the table `init` wrote under the previous name.
pub const PREVIOUS_CODEX_TABLE: &str = "[mcp_servers.continuity]";

/// The table of the memprove server for Codex: the stdio server
/// `<executable> mcp serve --config-dir <config_dir>`, with
/// `MEMPROVE_CONFIG_DIR` in its environment as the other clients' entries
/// have it. Paths are written as TOML basic strings (`"` and `\` escaped).
#[must_use]
pub fn codex_table(executable: &str, config_dir: &str) -> String {
    let quote = |text: &str| format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""));
    format!(
        "{CODEX_TABLE}\ncommand = {}\nargs = [\"mcp\", \"serve\", \"--config-dir\", {}]\nenv = {{ \
         MEMPROVE_CONFIG_DIR = {} }}\n",
        quote(executable),
        quote(config_dir),
        quote(config_dir)
    )
}

/// `existing` (`~/.codex/config.toml`, or nothing) with the table of
/// [`codex_table`]: appended when there is none, replaced (the header and
/// the lines up to the next table header or the end) when one is there;
/// `None` when the file already holds exactly this table. Every other line
/// is kept as it is; a `[mcp_servers]` header a user wrote stays, since the
/// server's own table is a sub-table of its own. U22 (U20-N1): a table of
/// the previous name ([`PREVIOUS_CODEX_TABLE`]) whose `command` is a program
/// named `continuity` is taken out, and this table goes in its place when
/// the file holds none of its own.
#[must_use]
pub fn codex_config_with(
    existing: Option<&str>,
    executable: &str,
    config_dir: &str,
) -> Option<String> {
    let table = codex_table(executable, config_dir);
    let existing = existing.unwrap_or("");
    let lines: Vec<&str> = existing.split_inclusive('\n').collect();
    let previous = table_span(&lines, PREVIOUS_CODEX_TABLE)
        .filter(|span| is_previous_table(&lines[span.clone()]));
    let mut text = String::new();
    if let Some(target) = table_span(&lines, CODEX_TABLE).or_else(|| previous.clone()) {
        let mut index = 0;
        while index < lines.len() {
            if index == target.start {
                text.push_str(&table);
                if target.end < lines.len() {
                    text.push('\n');
                }
                index = target.end;
            } else if let Some(span) = previous.as_ref().filter(|span| span.start == index) {
                index = span.end;
            } else {
                text.push_str(lines[index]);
                index += 1;
            }
        }
    } else {
        text.push_str(existing);
        if !existing.is_empty() {
            if !existing.ends_with('\n') {
                text.push('\n');
            }
            text.push('\n');
        }
        text.push_str(&table);
    }
    (text != existing).then_some(text)
}

/// The lines of the table under `header`, up to the next table header or the
/// end.
fn table_span(lines: &[&str], header: &str) -> Option<std::ops::Range<usize>> {
    let start = lines.iter().position(|line| line.trim_end() == header)?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map_or(lines.len(), |offset| start + 1 + offset);
    Some(start..end)
}

/// U22 (U20-N1): whether the table `lines` runs a program named
/// `continuity`, as the table `init` wrote under the previous name does.
fn is_previous_table(lines: &[&str]) -> bool {
    lines.iter().any(|line| {
        line.split_once('=').is_some_and(|(key, value)| {
            key.trim() == "command"
                && Path::new(value.trim().trim_matches('"'))
                    .file_name()
                    .is_some_and(|name| name == "continuity")
        })
    })
}

/// What one step of `init` did to a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The file was written.
    Written(PathBuf),
    /// The file already held what `init` writes.
    Unchanged(PathBuf),
    /// `--dry-run`: the file would be written.
    WouldWrite(PathBuf),
    /// A sentence about a step, printed after it.
    Note(String),
    /// U22 (U20-N1): the file, which `init` wrote under the previous name,
    /// was removed.
    Removed(PathBuf),
    /// U22: `--dry-run`: the file would be removed.
    WouldRemove(PathBuf),
}

impl std::fmt::Display for Step {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Written(path) => write!(formatter, "{} written", path.display()),
            Self::Unchanged(path) => write!(formatter, "{} already as asked", path.display()),
            Self::WouldWrite(path) => write!(formatter, "{} would be written", path.display()),
            Self::Note(text) => write!(formatter, "note: {text}"),
            Self::Removed(path) => write!(formatter, "{} removed", path.display()),
            Self::WouldRemove(path) => write!(formatter, "{} would be removed", path.display()),
        }
    }
}

/// Writes `path` with `change(existing)` when it changes the file; the file
/// is created with mode 0600 when `private`. A parent directory that does
/// not exist is created (mode 0700). Nothing is written with `dry_run`.
///
/// # Errors
///
/// When the file or its directory cannot be read or written.
pub fn edit_text(
    path: &Path,
    private: bool,
    dry_run: bool,
    change: impl FnOnce(Option<&str>) -> Option<String>,
) -> Result<Step, String> {
    let existing = match fs::read(path) {
        Ok(bytes) => Some(
            String::from_utf8(bytes)
                .map_err(|_| format!("{} is not UTF-8 text", path.display()))?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("{} cannot be read: {error}", path.display())),
    };
    let Some(text) = change(existing.as_deref()) else {
        return Ok(Step::Unchanged(path.to_path_buf()));
    };
    if dry_run {
        return Ok(Step::WouldWrite(path.to_path_buf()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("{} cannot be created: {error}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if private {
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
    }
    let staging = path.with_extension(format!(
        "{}.new",
        path.extension().and_then(OsStr::to_str).unwrap_or("")
    ));
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(if private { 0o600 } else { 0o644 });
        }
        let mut file = options
            .open(&staging)
            .map_err(|error| format!("{} cannot be written: {error}", staging.display()))?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("{} cannot be written: {error}", staging.display()))?;
    }
    fs::rename(&staging, path)
        .map_err(|error| format!("{} cannot be written: {error}", path.display()))?;
    Ok(Step::Written(path.to_path_buf()))
}

/// U22 (U20-N1): removes `path` when it holds exactly the Cursor rule `init`
/// wrote under the previous name ([`is_previous_cursor_rule`]); a file that
/// differs is kept, with a note; nothing when it does not exist.
///
/// # Errors
///
/// When the file cannot be read or removed.
pub fn remove_previous_cursor_rule(path: &Path, dry_run: bool) -> Result<Option<Step>, String> {
    let text = match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{} cannot be read: {error}", path.display())),
    };
    if !is_previous_cursor_rule(&text) {
        return Ok(Some(Step::Note(format!(
            "{} was left as it is: it is not the rule init wrote under the previous name",
            path.display()
        ))));
    }
    if dry_run {
        return Ok(Some(Step::WouldRemove(path.to_path_buf())));
    }
    fs::remove_file(path)
        .map_err(|error| format!("{} cannot be removed: {error}", path.display()))?;
    Ok(Some(Step::Removed(path.to_path_buf())))
}

/// The operator's token file of the installation whose configuration
/// directory is `config_dir`: `scripts/install.sh` writes it as
/// `<prefix>/operator-token` beside `<prefix>/config`.
#[must_use]
pub fn installed_operator_token(config_dir: &Path) -> PathBuf {
    config_dir.parent().map_or_else(
        || PathBuf::from("operator-token"),
        |prefix| prefix.join("operator-token"),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CODEX_TABLE, Client, NOTE, NOTE_BEGIN, NOTE_END, PREVIOUS_CODEX_TABLE, PREVIOUS_NOTE_BEGIN,
        PREVIOUS_NOTE_END, agents_with_note, codex_config_with, codex_home_dir, codex_table,
        cursor_rule, detect_clients, exclude_entries, exclude_with, installed_operator_token,
        is_previous_cursor_rule, trae_rule,
    };
    use std::path::Path;

    #[test]
    fn clients_are_named_and_parsed() {
        for client in Client::ALL {
            assert_eq!(Client::parse(client.name()), Some(client));
        }
        assert_eq!(Client::parse("trae"), Some(Client::Trae));
        assert_eq!(Client::parse("vim"), None);
    }

    #[test]
    fn detection_reads_the_home_directory_and_path() {
        // Cursor's application bundle counts on a machine where it is
        // installed, so only the other two are asserted absent.
        let without_cursor = |home: &std::path::Path, path: Option<&std::ffi::OsStr>| {
            detect_clients(Some(home), None, path)
                .into_iter()
                .filter(|client| *client != Client::Cursor)
                .collect::<Vec<_>>()
        };
        let home = tempfile::tempdir().unwrap();
        assert!(without_cursor(home.path(), None).is_empty());
        std::fs::create_dir(home.path().join(".codex")).unwrap();
        assert_eq!(without_cursor(home.path(), None), [Client::Codex]);
        let bin = tempfile::tempdir().unwrap();
        std::fs::write(bin.path().join("claude"), "").unwrap();
        let path = std::env::join_paths([bin.path()]).unwrap();
        assert_eq!(
            without_cursor(home.path(), Some(&path)),
            [Client::ClaudeCode, Client::Codex]
        );
        // The directory in the home directory counts always.
        std::fs::create_dir(home.path().join(".cursor")).unwrap();
        assert!(detect_clients(Some(home.path()), None, None).contains(&Client::Cursor));
        // TRAE: ~/.trae-cn (TRAE CN) or ~/.trae (TRAE) in the home directory.
        let trae =
            |home: &std::path::Path| detect_clients(Some(home), None, None).contains(&Client::Trae);
        assert!(!trae(home.path()));
        for name in [".trae-cn", ".trae"] {
            let home = tempfile::tempdir().unwrap();
            std::fs::create_dir(home.path().join(name)).unwrap();
            assert!(trae(home.path()), "{name}");
        }
        // CODEX_HOME names Codex's home instead of ~/.codex.
        let elsewhere = tempfile::tempdir().unwrap();
        let codex_home = elsewhere.path().join("codex-home");
        assert_eq!(
            codex_home_dir(Some(home.path()), Some(codex_home.as_os_str())),
            Some(codex_home.clone())
        );
        assert_eq!(
            codex_home_dir(Some(home.path()), Some(std::ffi::OsStr::new(""))),
            Some(home.path().join(".codex"))
        );
        let other_home = tempfile::tempdir().unwrap();
        assert!(
            !detect_clients(Some(other_home.path()), Some(codex_home.as_os_str()), None)
                .contains(&Client::Codex)
        );
        std::fs::create_dir(&codex_home).unwrap();
        assert!(
            detect_clients(Some(other_home.path()), Some(codex_home.as_os_str()), None)
                .contains(&Client::Codex)
        );
    }

    #[test]
    fn the_exclude_file_gains_each_entry_once() {
        let entries = exclude_entries(&[Client::ClaudeCode]);
        assert_eq!(entries, [".claude/settings.local.json", ".mcp.json"]);
        assert_eq!(
            exclude_with(None, &entries).as_deref(),
            Some(".claude/settings.local.json\n.mcp.json\n")
        );
        assert_eq!(
            exclude_with(Some("# comment\n.mcp.json"), &entries).as_deref(),
            Some("# comment\n.mcp.json\n.claude/settings.local.json\n")
        );
        assert_eq!(
            exclude_with(Some(".claude/settings.local.json\n.mcp.json\n"), &entries),
            None
        );
        // U24 (H1, H2): the hooks files of Codex and Cursor.
        assert_eq!(
            exclude_entries(&[Client::Cursor]),
            [
                ".claude/settings.local.json",
                ".mcp.json",
                ".cursor/mcp.json",
                ".cursor/rules/memprove.mdc",
                ".cursor/hooks.json"
            ]
        );
        assert_eq!(
            exclude_entries(&[Client::Codex]),
            [
                ".claude/settings.local.json",
                ".mcp.json",
                ".codex/hooks.json"
            ]
        );
        // TRAE: its hooks, MCP and rule files.
        assert_eq!(
            exclude_entries(&[Client::Trae]),
            [
                ".claude/settings.local.json",
                ".mcp.json",
                ".trae/hooks.json",
                ".trae/mcp.json",
                ".trae/rules/memprove.md"
            ]
        );
    }

    #[test]
    fn the_note_is_appended_once_and_replaced_in_place() {
        let note = format!("{NOTE_BEGIN}\n{NOTE}\n{NOTE_END}\n");
        assert_eq!(agents_with_note(None).as_deref(), Some(note.as_str()));
        let first = agents_with_note(Some("# Agents\n\nRules.\n")).unwrap();
        assert_eq!(first, format!("# Agents\n\nRules.\n\n{note}"));
        assert_eq!(agents_with_note(Some(&first)), None);
        let stale = first.replace(NOTE, "an older note");
        assert_eq!(
            agents_with_note(Some(&stale)).as_deref(),
            Some(first.as_str())
        );
        assert!(NOTE.lines().count() + 2 <= 5);
        assert!(cursor_rule().contains(NOTE) && cursor_rule().starts_with("---\n"));
        assert_eq!(
            trae_rule(),
            format!("---\nalwaysApply: true\n---\n{NOTE}\n")
        );
    }

    #[test]
    fn the_codex_table_is_appended_once_and_replaced_in_place() {
        let table = codex_table("/opt/c/bin/memprove", "/opt/c/config");
        assert!(table.starts_with(CODEX_TABLE));
        assert!(table.contains("args = [\"mcp\", \"serve\", \"--config-dir\", \"/opt/c/config\"]"));
        assert_eq!(
            codex_config_with(None, "/opt/c/bin/memprove", "/opt/c/config").as_deref(),
            Some(table.as_str())
        );
        let other = "model = \"x\"\n\n[mcp_servers.other]\ncommand = \"o\"\n";
        let appended =
            codex_config_with(Some(other), "/opt/c/bin/memprove", "/opt/c/config").unwrap();
        assert_eq!(appended, format!("{other}\n{table}"));
        assert_eq!(
            codex_config_with(Some(&appended), "/opt/c/bin/memprove", "/opt/c/config"),
            None
        );
        // Replaced in place, the tables after it kept.
        let middle = format!("model = \"x\"\n\n{CODEX_TABLE}\ncommand = \"old\"\n\n[tui]\na = 1\n");
        let replaced =
            codex_config_with(Some(&middle), "/opt/c/bin/memprove", "/opt/c/config").unwrap();
        assert_eq!(
            replaced,
            format!("model = \"x\"\n\n{table}\n[tui]\na = 1\n")
        );
        // A quote in a path is escaped.
        assert!(codex_table("/a\"b", "/c").contains("\"/a\\\"b\""));
    }

    /// U22 (U20-N1): what `init` wrote under the previous name is replaced
    /// in its place (the AGENTS.md note, the Codex table) or recognised for
    /// removal (the Cursor rule); a look-alike that is not the previous
    /// name's is kept.
    #[test]
    fn u22_the_previous_name_entries_are_replaced_and_look_alikes_kept() {
        let note = format!("{NOTE_BEGIN}\n{NOTE}\n{NOTE_END}\n");
        let old = format!(
            "# Agents\n\n{PREVIOUS_NOTE_BEGIN}\nContinuity keeps this repository's task \
             ledger.\n{PREVIOUS_NOTE_END}\n\nMore rules.\n"
        );
        let renewed = agents_with_note(Some(&old)).unwrap();
        assert_eq!(renewed, format!("# Agents\n\n{note}\nMore rules.\n"));
        assert_eq!(agents_with_note(Some(&renewed)), None);
        // Both notes: the previous one goes, this one is replaced in its place.
        let both = format!("{renewed}\n{PREVIOUS_NOTE_BEGIN}\nold\n{PREVIOUS_NOTE_END}\n");
        assert_eq!(
            agents_with_note(Some(&both)).as_deref(),
            Some(format!("{renewed}\n").as_str())
        );

        let table = codex_table("/opt/c/bin/memprove", "/opt/c/config");
        let previous = format!(
            "model = \"x\"\n\n{PREVIOUS_CODEX_TABLE}\ncommand = \"/opt/c/bin/continuity\"\nargs = \
             [\"mcp\", \"serve\", \"--config-dir\", \"/opt/c/config\"]\nenv = {{ \
             CONTINUITY_CONFIG_DIR = \"/opt/c/config\" }}\n\n[tui]\na = 1\n"
        );
        let replaced =
            codex_config_with(Some(&previous), "/opt/c/bin/memprove", "/opt/c/config").unwrap();
        assert_eq!(
            replaced,
            format!("model = \"x\"\n\n{table}\n[tui]\na = 1\n")
        );
        assert_eq!(
            codex_config_with(Some(&replaced), "/opt/c/bin/memprove", "/opt/c/config"),
            None
        );
        // Both tables: the previous one goes, this one stays in its place.
        let both = format!(
            "{table}\n{PREVIOUS_CODEX_TABLE}\ncommand = \"/x/continuity\"\nargs = [\"mcp\", \"serve\"]\n"
        );
        assert_eq!(
            codex_config_with(Some(&both), "/opt/c/bin/memprove", "/opt/c/config").as_deref(),
            Some(format!("{table}\n").as_str())
        );
        // A continuity table of another program is not the previous name's.
        let other = format!(
            "{PREVIOUS_CODEX_TABLE}\ncommand = \"/usr/bin/other\"\nargs = [\"mcp\", \"serve\"]\n"
        );
        assert_eq!(
            codex_config_with(Some(&other), "/opt/c/bin/memprove", "/opt/c/config"),
            Some(format!("{other}\n{table}"))
        );

        let rule = "---\nalwaysApply: true\n---\nContinuity keeps this repository's task ledger. \
                    Before changing anything, call the MCP tool `pack` of the server `continuity` \
                    and read the Context Pack it returns; record facts with its `checkpoint` tool, \
                    citing a `continuity run` of the tests, and end your Session with `end`.\n";
        assert!(is_previous_cursor_rule(rule));
        assert!(!is_previous_cursor_rule(&format!("{rule}My own line.\n")));
        assert!(!is_previous_cursor_rule(&cursor_rule()));
    }

    #[test]
    fn the_operator_token_is_beside_the_configuration_directory() {
        assert_eq!(
            installed_operator_token(Path::new("/home/u/.memprove/config")),
            Path::new("/home/u/.memprove/operator-token")
        );
    }
}
