//! Finding a repository's sessions on this machine: the Claude Code
//! transcripts and Codex rollouts whose recorded working directory is in
//! the repository.

use std::{
    ffi::OsString,
    fs,
    io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::SystemTime,
};

use crate::{claude, codex, model::Client, time};

/// The most characters of a Claude Code project directory's name; longer
/// names are cut there (and given a suffix of their own).
const CLAUDE_DIR_NAME_MAX: usize = 200;

/// The bytes of a transcript's head read to find its working directory;
/// the line they end in is read to its end.
const HEAD_BYTES: usize = 1 << 20;

/// The most bytes read for a transcript's head, when a line is long (a
/// record that holds a pasted image).
const HEAD_BYTES_MAX: u64 = 64 << 20;

/// The bytes of a transcript's end read to find its last timestamp.
const TAIL_BYTES: u64 = 256 << 10;

/// Where the clients keep their transcripts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Homes {
    /// Claude Code's configuration directory (`$CLAUDE_CONFIG_DIR`, else
    /// `~/.claude`).
    pub claude: Option<PathBuf>,
    /// Codex's home (`$CODEX_HOME`, else `~/.codex`).
    pub codex: Option<PathBuf>,
}

impl Homes {
    /// The directories `var` names: `CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
    /// `HOME`.
    #[must_use]
    pub fn from_vars(var: &dyn Fn(&str) -> Option<OsString>) -> Self {
        let set = |name: &str| {
            var(name)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        };
        let home = set("HOME");
        Self {
            claude: set("CLAUDE_CONFIG_DIR")
                .or_else(|| home.as_ref().map(|home| home.join(".claude"))),
            codex: set("CODEX_HOME").or_else(|| home.as_ref().map(|home| home.join(".codex"))),
        }
    }
}

/// One session's transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// Its client.
    pub client: Client,
    /// The transcript file.
    pub path: PathBuf,
    /// The session's id.
    pub id: String,
    /// When the session was last active, in milliseconds since 1970: the
    /// last timestamp its transcript records, else when the file last
    /// changed (a copied file keeps its timestamps, not its change time).
    pub last_active_ms: i64,
}

/// The repository whose `.git` is at `start` or above it; `start` itself
/// when there is none.
#[must_use]
pub fn repository_root(start: &Path) -> PathBuf {
    let start = start.canonicalize().unwrap_or_else(|_| start.to_owned());
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .map_or_else(|| start.clone(), Path::to_owned)
}

/// The name Claude Code gives the project directory of `path`: every
/// character but an ASCII letter or digit becomes `-`.
#[must_use]
pub fn claude_dir_name(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect()
}

/// Whether the working directory `cwd`, as a transcript records it, is in
/// `root`.
#[must_use]
pub fn in_root(cwd: &str, root: &Path) -> bool {
    let cwd = Path::new(cwd);
    cwd.starts_with(root) || cwd.canonicalize().is_ok_and(|real| real.starts_with(root))
}

/// The sessions of `clients` in the repository at `root`, the most recently
/// active first.
#[must_use]
pub fn sessions(homes: &Homes, root: &Path, clients: &[Client]) -> Vec<Found> {
    let mut found = Vec::new();
    if clients.contains(&Client::ClaudeCode)
        && let Some(dir) = &homes.claude
    {
        found.extend(claude_sessions(&dir.join("projects"), root));
    }
    if clients.contains(&Client::Codex)
        && let Some(dir) = &homes.codex
    {
        found.extend(codex_sessions(&dir.join("sessions"), root));
    }
    found.sort_by(|a, b| {
        b.last_active_ms
            .cmp(&a.last_active_ms)
            .then_with(|| a.path.cmp(&b.path))
    });
    found
}

/// When the file at `path` last changed, in milliseconds since 1970.
fn modified_ms(path: &Path) -> i64 {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.duration_since(SystemTime::UNIX_EPOCH).ok())
        .and_then(|since| i64::try_from(since.as_millis()).ok())
        .unwrap_or(0)
}

/// When the session in the transcript at `path` was last active: the last
/// `"timestamp":"…"` in the file's end, else when the file last changed
/// (also for a compressed rollout, whose end cannot be read alone).
fn last_active_ms(path: &Path) -> i64 {
    let compressed = path.extension().is_some_and(|extension| extension == "zst");
    (!compressed)
        .then(|| tail(path))
        .flatten()
        .and_then(|text| last_timestamp(&text))
        .unwrap_or_else(|| modified_ms(path))
}

/// The last [`TAIL_BYTES`] of the file at `path`.
fn tail(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(length.saturating_sub(TAIL_BYTES)))
        .ok()?;
    let mut bytes = Vec::new();
    file.take(TAIL_BYTES).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The last timestamp a record of `text` carries. A timestamp quoted inside
/// a JSON string is escaped there, so it is not found.
fn last_timestamp(text: &str) -> Option<i64> {
    const KEY: &str = "\"timestamp\":\"";
    text.rmatch_indices(KEY).find_map(|(at, _)| {
        let rest = &text[at + KEY.len()..];
        time::unix_ms(&rest[..rest.find('"')?])
    })
}

fn claude_sessions(projects: &Path, root: &Path) -> Vec<Found> {
    let name = claude_dir_name(root);
    let cut = &name[..name.len().min(CLAUDE_DIR_NAME_MAX)];
    let Ok(entries) = fs::read_dir(projects) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let dir_name = entry.file_name().to_string_lossy().into_owned();
        let candidate = dir_name == name
            || dir_name.starts_with(&format!("{name}-"))
            || (name.len() > CLAUDE_DIR_NAME_MAX && dir_name.starts_with(cut));
        if !candidate {
            continue;
        }
        let Ok(files) = fs::read_dir(entry.path()) else {
            continue;
        };
        for file in files.filter_map(Result::ok).map(|file| file.path()) {
            if file
                .extension()
                .is_none_or(|extension| extension != "jsonl")
            {
                continue;
            }
            let Some(cwd) = head(&file).and_then(|text| claude::first_cwd(&text)) else {
                continue;
            };
            if in_root(&cwd, root) {
                found.push(Found {
                    client: Client::ClaudeCode,
                    id: file
                        .file_stem()
                        .map(|stem| stem.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    last_active_ms: last_active_ms(&file),
                    path: file,
                });
            }
        }
    }
    found
}

fn codex_sessions(sessions: &Path, root: &Path) -> Vec<Found> {
    let mut files = Vec::new();
    collect_rollouts(sessions, 0, &mut files);
    files
        .into_iter()
        .filter_map(|file| {
            let cwd = if file.extension().is_some_and(|extension| extension == "zst") {
                zstd_head(&file)
            } else {
                head(&file)
            }
            .and_then(|text| codex::first_cwd(&text))?;
            in_root(&cwd, root).then(|| Found {
                client: Client::Codex,
                id: codex::id_of(&file).unwrap_or_default(),
                last_active_ms: last_active_ms(&file),
                path: file,
            })
        })
        .collect()
}

/// The rollout files under `dir`, three levels down (`YYYY/MM/DD`).
fn collect_rollouts(dir: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for path in entries.filter_map(Result::ok).map(|entry| entry.path()) {
        if path.is_dir() && depth < 3 {
            collect_rollouts(&path, depth + 1, files);
        } else if path.file_name().is_some_and(|name| {
            let name = name.to_string_lossy();
            name.starts_with("rollout-")
                && (name.ends_with(".jsonl") || name.ends_with(".jsonl.zst"))
        }) {
            files.push(path);
        }
    }
}

/// The first lines of the file at `path`: whole lines until they hold
/// [`HEAD_BYTES`], read as bytes, so that neither a long first record nor a
/// character the limit would cut hides the session.
fn head(path: &Path) -> Option<String> {
    let mut reader = BufReader::new(fs::File::open(path).ok()?.take(HEAD_BYTES_MAX));
    let mut bytes = Vec::new();
    while bytes.len() < HEAD_BYTES {
        if reader.read_until(b'\n', &mut bytes).ok()? == 0 {
            break;
        }
    }
    // A last line without its line break is not whole.
    let whole = bytes.iter().rposition(|byte| *byte == b'\n')?;
    Some(String::from_utf8_lossy(&bytes[..=whole]).into_owned())
}

/// The first line of a compressed rollout, through `zstd -dc`.
fn zstd_head(path: &Path) -> Option<String> {
    let mut child = Command::new("zstd")
        .arg("-dc")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut line = Vec::new();
    let read = child
        .stdout
        .take()
        .map(|stdout| BufReader::new(stdout.take(HEAD_BYTES_MAX)).read_until(b'\n', &mut line));
    let _ = child.kill();
    let _ = child.wait();
    read?.ok()?;
    Some(String::from_utf8_lossy(&line).into_owned())
}

/// The one session among `found` whose id starts with `wanted`.
///
/// # Errors
///
/// When none does, or more than one.
pub fn select<'a>(found: &'a [Found], wanted: &str) -> Result<&'a Found, String> {
    let matching: Vec<&Found> = found
        .iter()
        .filter(|session| session.id.starts_with(wanted))
        .collect();
    match matching.as_slice() {
        [one] => Ok(one),
        [] => Err(format!(
            "no session of this repository has an id starting with {wanted}"
        )),
        several => Err(format!(
            "{} sessions have an id starting with {wanted}: {}",
            several.len(),
            several
                .iter()
                .map(|session| session.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn claude_names_project_directories_by_their_path() {
        assert_eq!(claude_dir_name(Path::new("/home/user")), "-home-user");
        assert_eq!(
            claude_dir_name(Path::new("/Users/a/Desktop/my.app_x")),
            "-Users-a-Desktop-my-app-x"
        );
    }

    #[test]
    fn the_last_timestamp_is_a_records_own() {
        let text = "{\"timestamp\":\"2026-11-16T10:00:00.000Z\",\"type\":\"user\"}\n\
                    {\"timestamp\":\"2026-11-16T10:05:00.500Z\",\"content\":\"{\\\"timestamp\\\":\\\"2030-01-01T00:00:00Z\\\"}\"}\n\
                    {\"type\":\"last-prompt\"}\n";
        assert_eq!(
            last_timestamp(text),
            time::unix_ms("2026-11-16T10:05:00.500Z")
        );
        assert_eq!(last_timestamp("{\"type\":\"user\"}\n"), None);
    }

    #[test]
    fn a_long_record_or_a_character_at_the_limit_does_not_hide_a_session() {
        let home = tempfile::tempdir().unwrap();
        let repo = home.path().join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let dir = home
            .path()
            .join("claude/projects")
            .join(claude_dir_name(&repo));
        fs::create_dir_all(&dir).unwrap();
        // More than the head's bytes of three-byte characters.
        let long = "汉".repeat(HEAD_BYTES / 3 + 1000);
        // The head's limit falls inside the second record, and (for one of
        // the three paddings) inside a character of it.
        for padding in 0..3 {
            fs::write(
                dir.join(format!("cut{padding}.jsonl")),
                format!(
                    "{{\"type\":\"user\",\"cwd\":\"{}\"}}{}\n{{\"type\":\"user\",\"message\":\"{long}\"}}\n",
                    repo.display(),
                    " ".repeat(padding)
                ),
            )
            .unwrap();
        }
        // The first record is longer than the limit (a pasted image).
        fs::write(
            dir.join("long.jsonl"),
            format!(
                "{{\"type\":\"user\",\"message\":\"{long}\",\"cwd\":\"{}\"}}\n",
                repo.display()
            ),
        )
        .unwrap();
        // A record still being written is not read.
        fs::write(dir.join("partial.jsonl"), "{\"type\":\"user\",\"cwd\":\"/").unwrap();
        let homes = Homes {
            claude: Some(home.path().join("claude")),
            codex: None,
        };
        let mut ids: Vec<String> = sessions(&homes, &repo, &[Client::ClaudeCode])
            .into_iter()
            .map(|session| session.id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["cut0", "cut1", "cut2", "long"]);
    }

    #[test]
    fn sessions_are_found_by_their_directory_and_most_recently_active_first() {
        let home = tempfile::tempdir().unwrap();
        let repo = home.path().join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(repo.join("sub")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let projects = home.path().join("claude/projects");
        let write = |dir: &str, file: &str, cwd: &Path, at: &str| {
            let dir = projects.join(dir);
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join(file);
            fs::write(
                &path,
                format!(
                    "{{\"type\":\"user\",\"cwd\":\"{}\",\"timestamp\":\"{at}\"}}\n",
                    cwd.display()
                ),
            )
            .unwrap();
            path
        };
        let name = claude_dir_name(&repo);
        // The older session's file changed last (a copy, or a late write):
        // its records' timestamps decide, not the file's.
        let newer = write(
            &format!("{name}-sub"),
            "bbbb.jsonl",
            &repo.join("sub"),
            "2026-11-16T12:00:00.000Z",
        );
        let older = write(&name, "aaaa.jsonl", &repo, "2026-11-16T09:00:00.000Z");
        write(
            &format!("{name}-other"),
            "cccc.jsonl",
            &home.path().join("repo-other"),
            "2026-11-16T13:00:00.000Z",
        );
        let file = fs::File::options().write(true).open(&newer).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        let codex_dir = home.path().join("codex/sessions/2026/11/17");
        fs::create_dir_all(&codex_dir).unwrap();
        fs::write(
            codex_dir.join("rollout-2026-11-17T01-00-00-0199.jsonl"),
            format!(
                "{{\"timestamp\":\"2026-11-17T01:00:00.000Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"0199\",\"cwd\":\"{}\"}}}}\n",
                repo.display()
            ),
        )
        .unwrap();
        let homes = Homes {
            claude: Some(home.path().join("claude")),
            codex: Some(home.path().join("codex")),
        };
        let found = sessions(&homes, &repo, &[Client::ClaudeCode]);
        assert_eq!(
            found
                .iter()
                .map(|session| session.path.clone())
                .collect::<Vec<_>>(),
            vec![newer, older]
        );
        let all = sessions(&homes, &repo, &Client::ALL);
        assert_eq!(all.len(), 3);
        assert_eq!(select(&all, "0199").unwrap().client, Client::Codex);
        assert!(select(&all, "zz").is_err());
        assert!(select(&all, "").unwrap_err().contains("3 sessions"));
        assert_eq!(repository_root(&repo.join("sub")), repo);
    }
}
