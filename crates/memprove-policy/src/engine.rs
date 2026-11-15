//! Decides a call by the rules of a policy: every command, file and MCP tool
//! the call touches is one check; each check is decided by the first rule of
//! its tool that matches (memprove's built-in rules first), and the call by
//! the strictest of its checks.

use std::path::{Path, PathBuf};

use crate::{
    commands::{self, PathUse, Place},
    glob,
    rules::{Decision, Policy, Rule, Tool},
};

/// The policy file, relative to the repository root.
pub const POLICY_FILE: &str = ".memprove/policy.rules";

/// The reason of the built-in rules.
pub const BUILT_IN_REASON: &str = "the policy file and the agents' hook settings are changed by a \
                                   person, not by an agent";

/// The paths the built-in rules protect: a change to one needs a person's
/// approval, whatever the policy says.
pub const PROTECTED: [&str; 7] = [
    ".memprove/**",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".codex/hooks.json",
    ".codex/config.toml",
    ".cursor/hooks.json",
    ".cursor/cli.json",
];

/// memprove's built-in rules, line 0.
#[must_use]
pub fn built_in_rules() -> Vec<Rule> {
    PROTECTED
        .iter()
        .map(|pattern| Rule {
            line: 0,
            decision: Decision::Ask,
            tool: Tool::Edit,
            pattern: (*pattern).to_owned(),
            reason: Some(BUILT_IN_REASON.to_owned()),
        })
        .collect()
}

/// A call to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// A shell command.
    Bash(String),
    /// Reading files (absolute, or relative to the working directory).
    Read(Vec<String>),
    /// Changing files.
    Edit(Vec<String>),
    /// An MCP tool: its server when known, and its name.
    Mcp {
        /// The server's name.
        server: Option<String>,
        /// The tool's name.
        tool: String,
    },
}

/// Where a call runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// The repository root, which holds the policy file.
    pub root: PathBuf,
    /// The working directory of the call.
    pub cwd: PathBuf,
    /// The home directory.
    pub home: Option<PathBuf>,
}

/// One thing a call touches, and the rule that decides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// The tool of the check.
    pub tool: Tool,
    /// What it touches: a command, a path (relative to the root when inside
    /// it), or `server.tool`.
    pub subject: String,
    /// The rule that decides it, if any.
    pub rule: Option<Rule>,
}

/// What a policy says about a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The decision: none when no rule matched.
    pub decision: Option<Decision>,
    /// The index in `checks` of the check that decides, if any.
    pub deciding: Option<usize>,
    /// Every check, in order.
    pub checks: Vec<Check>,
    /// Why the call could not be read in full; such a call needs a person.
    pub problem: Option<String>,
}

impl Verdict {
    /// The deciding check.
    #[must_use]
    pub fn deciding_check(&self) -> Option<&Check> {
        self.checks.get(self.deciding?)
    }
}

/// `path` relative to `root` when inside it, as text.
#[must_use]
pub fn shown(path: &Path, root: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(relative) if relative.as_os_str().is_empty() => ".".to_owned(),
        Ok(relative) => relative.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

fn segments(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// Whether the path rule `pattern` matches `used`.
#[must_use]
pub fn path_rule_matches(pattern: &str, used: &PathUse, place: &Site) -> bool {
    path_rule_matches_as(pattern, used, place, used.tree)
}

/// [`path_rule_matches`], with `tree` saying whether a rule matching only
/// part of a tree counts: it does for `deny` and `ask`, not for `allow`,
/// which must cover the whole tree.
fn path_rule_matches_as(pattern: &str, used: &PathUse, place: &Site, tree: bool) -> bool {
    let pattern = if pattern.len() > 1 {
        pattern.trim_end_matches('/')
    } else {
        pattern
    };
    let anchored = if pattern == "~" || pattern.starts_with("~/") {
        let Some(home) = &place.home else {
            return false;
        };
        Some(home.join(pattern.trim_start_matches('~').trim_start_matches('/')))
    } else if pattern.starts_with('/') {
        Some(PathBuf::from(pattern))
    } else if pattern.contains('/') {
        Some(place.root.join(pattern.trim_start_matches("./")))
    } else {
        None
    };
    let path = segments(&used.path);
    let path: Vec<&str> = path.iter().map(String::as_str).collect();
    match anchored {
        Some(anchored) => {
            let pattern = segments(&commands::clean(&anchored));
            let pattern: Vec<&str> = pattern.iter().map(String::as_str).collect();
            glob::path_or_ancestor_matches(&pattern, &path)
                || (tree && glob::subtree_may_match(&pattern, &path))
        }
        None => match used.path.strip_prefix(&place.root) {
            Ok(relative) => segments(relative)
                .iter()
                .any(|segment| glob::segment_matches(pattern, segment)),
            Err(_) => path
                .last()
                .is_some_and(|name| glob::segment_matches(pattern, name)),
        },
    }
}

fn mcp_matches(pattern: &str, server: Option<&str>, tool: &str) -> bool {
    if let Some(server) = server {
        glob::text_matches(pattern, &format!("{server}.{tool}"))
    } else {
        let tool_pattern = pattern.split_once('.').map_or(pattern, |(_, tool)| tool);
        glob::text_matches(tool_pattern, tool)
    }
}

enum Subject {
    Command(String),
    Path(PathUse),
    Mcp(Option<String>, String),
}

/// `path` with its symbolic links resolved, as far as it exists (the rest
/// joined as given), in the terms of `root` when it is below the resolved
/// root: `/tmp/repo/.env` for `/private/tmp/repo/.env` on macOS, and the
/// target of a link in the repository. `None` when that is `path` itself
/// or nothing of it can be resolved.
fn real_path(path: &Path, root: &Path, real_root: Option<&Path>) -> Option<PathBuf> {
    let mut existing = path;
    let mut rest = Vec::new();
    let resolved = loop {
        if let Ok(resolved) = std::fs::canonicalize(existing) {
            break resolved;
        }
        rest.push(existing.file_name()?);
        existing = existing.parent()?;
    };
    let mut real = resolved;
    for part in rest.iter().rev() {
        real.push(part);
    }
    if let Some(real_root) = real_root
        && let Ok(relative) = real.strip_prefix(real_root)
    {
        real = root.join(relative);
    }
    (real != path).then_some(real)
}

/// Decides `call` by `policy`.
#[must_use]
#[allow(clippy::too_many_lines)] // The checks of a call, then their decision.
pub fn evaluate(policy: &Policy, call: &Call, place: &Site) -> Verdict {
    let mut subjects: Vec<(Tool, Subject)> = Vec::new();
    let mut problem = None;
    let resolve = |word: &str| commands::resolve(word, &place.cwd, place.home.as_deref());
    match call {
        Call::Bash(command) => {
            let effects = commands::effects(
                command,
                Place {
                    cwd: &place.cwd,
                    home: place.home.as_deref(),
                },
            );
            subjects.extend(
                effects
                    .commands
                    .into_iter()
                    .map(|text| (Tool::Bash, Subject::Command(text))),
            );
            subjects.extend(
                effects
                    .reads
                    .into_iter()
                    .map(|used| (Tool::Read, Subject::Path(used))),
            );
            subjects.extend(
                effects
                    .writes
                    .into_iter()
                    .map(|used| (Tool::Edit, Subject::Path(used))),
            );
            problem = effects.problem.map(str::to_owned);
        }
        Call::Read(paths) => subjects.extend(
            paths
                .iter()
                .filter_map(|word| resolve(word))
                .map(|path| (Tool::Read, Subject::Path(PathUse { path, tree: false }))),
        ),
        Call::Edit(paths) => subjects.extend(
            paths
                .iter()
                .filter_map(|word| resolve(word))
                .map(|path| (Tool::Edit, Subject::Path(PathUse { path, tree: false }))),
        ),
        Call::Mcp { server, tool } => {
            subjects.push((Tool::Mcp, Subject::Mcp(server.clone(), tool.clone())));
        }
    }
    // A path is also checked where its links lead, so that a rule cannot
    // be passed by a link or by another name of the repository.
    let real_root = std::fs::canonicalize(&place.root).ok();
    let subjects: Vec<(Tool, Subject)> = subjects
        .into_iter()
        .flat_map(|(tool, subject)| {
            let real = match &subject {
                Subject::Path(used) => real_path(&used.path, &place.root, real_root.as_deref())
                    .map(|path| {
                        (
                            tool,
                            Subject::Path(PathUse {
                                path,
                                tree: used.tree,
                            }),
                        )
                    }),
                _ => None,
            };
            std::iter::once((tool, subject)).chain(real)
        })
        .collect();
    let built_in = built_in_rules();
    let mut checks: Vec<Check> = Vec::new();
    for (tool, subject) in subjects {
        let matches = |rule: &&Rule| {
            rule.tool == tool
                && match &subject {
                    Subject::Command(text) => glob::command_matches(&rule.pattern, text),
                    Subject::Path(used) => path_rule_matches_as(
                        &rule.pattern,
                        used,
                        place,
                        used.tree && rule.decision != Decision::Allow,
                    ),
                    Subject::Mcp(server, name) => {
                        mcp_matches(&rule.pattern, server.as_deref(), name)
                    }
                }
        };
        let rule = built_in
            .iter()
            .find(matches)
            .or_else(|| policy.rules.iter().find(matches))
            .cloned();
        let shown_subject = match &subject {
            Subject::Command(text) => text.clone(),
            Subject::Path(used) => {
                let path = shown(&used.path, &place.root);
                if used.tree {
                    format!("{path} (and everything in it)")
                } else {
                    path
                }
            }
            Subject::Mcp(server, name) => format!("{}.{name}", server.as_deref().unwrap_or("?")),
        };
        let check = Check {
            tool,
            subject: shown_subject,
            rule,
        };
        if !checks.contains(&check) {
            checks.push(check);
        }
    }
    let mut decision = None;
    let mut deciding = None;
    for (index, check) in checks.iter().enumerate() {
        if let Some(rule) = &check.rule
            && decision.is_none_or(|current| rule.decision > current)
        {
            decision = Some(rule.decision);
            deciding = Some(index);
        }
    }
    let readable_rules = policy.rules.iter().any(|rule| rule.tool != Tool::Mcp);
    if problem.is_some() && readable_rules && decision.is_none_or(|current| current < Decision::Ask)
    {
        decision = Some(Decision::Ask);
        deciding = None;
    }
    if !readable_rules {
        problem = None;
    }
    Verdict {
        decision,
        deciding,
        checks,
        problem,
    }
}

/// The repository root of `start` that holds a policy file: the first
/// directory from `start` up that has [`POLICY_FILE`], not going above the
/// first one that has `.git`.
#[must_use]
pub fn find_root(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        if current.join(POLICY_FILE).is_file() {
            return Some(current.to_path_buf());
        }
        if current.join(".git").exists() {
            return None;
        }
        dir = current.parent();
    }
    None
}

/// The repository root of `start` for `init`: the first directory from
/// `start` up that has `.git` (or `start` itself when there is none).
#[must_use]
pub fn repository_root(start: &Path) -> PathBuf {
    let mut dir = Some(start);
    while let Some(current) = dir {
        if current.join(".git").exists() {
            return current.to_path_buf();
        }
        dir = current.parent();
    }
    start.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parse;

    fn place() -> Site {
        Site {
            root: PathBuf::from("/repo"),
            cwd: PathBuf::from("/repo"),
            home: Some(PathBuf::from("/home/me")),
        }
    }

    fn decide(policy: &str, call: &Call) -> Option<Decision> {
        evaluate(&parse(policy).unwrap(), call, &place()).decision
    }

    const POLICY: &str = "allow Read(.env.example)\n\
        deny Read(.env*) -- secrets\n\
        deny Bash(git push *--force*)\n\
        deny Bash(git push -f *)\n\
        deny Bash(git push * -f *)\n\
        ask Bash(git push *)\n\
        allow Edit(db/migrations/README.md)\n\
        deny Edit(db/migrations/**)\n\
        deny Read(~/.ssh/**)\n\
        deny Mcp(github.merge_*)\n";

    fn bash(command: &str) -> Option<Decision> {
        decide(POLICY, &Call::Bash(command.to_owned()))
    }

    #[test]
    fn the_strictest_check_of_a_command_decides() {
        assert_eq!(bash("git status"), None);
        assert_eq!(bash("git push origin feature/x"), Some(Decision::Ask));
        assert_eq!(
            bash("cd app && git push origin main --force"),
            Some(Decision::Deny)
        );
        assert_eq!(bash("git -C app push -f origin main"), Some(Decision::Deny));
        assert_eq!(bash("git push origin x -f"), Some(Decision::Deny));
        assert_eq!(bash("git push origin feature-fix"), Some(Decision::Ask));
        assert_eq!(bash("sudo /usr/bin/git push --force"), Some(Decision::Deny));
        assert_eq!(
            bash("bash -c \"echo hi; git push -f\""),
            Some(Decision::Deny)
        );
        assert_eq!(bash("echo $(git push --force)"), Some(Decision::Deny));
    }

    #[test]
    fn read_and_edit_rules_apply_to_shell_commands() {
        assert_eq!(bash("cat .env"), Some(Decision::Deny));
        assert_eq!(bash("cat .env.example"), Some(Decision::Allow));
        assert_eq!(bash("grep .env .gitignore"), None);
        assert_eq!(bash("echo .env >> .gitignore"), None);
        assert_eq!(bash("cp config/.env.local /tmp/x"), Some(Decision::Deny));
        assert_eq!(bash("cat ~/.ssh/id_ed25519"), Some(Decision::Deny));
        assert_eq!(bash("echo x > db/migrations/001.sql"), Some(Decision::Deny));
        assert_eq!(bash("cd db && rm -rf migrations"), Some(Decision::Deny));
        assert_eq!(bash("rm -rf db"), Some(Decision::Deny));
        assert_eq!(bash("rm db"), None);
        assert_eq!(
            bash("echo x > db/migrations/README.md"),
            Some(Decision::Allow)
        );
        assert_eq!(bash("echo x > .memprove/policy.rules"), Some(Decision::Ask));
    }

    #[test]
    fn tool_calls_are_checked_by_path_and_name() {
        assert_eq!(
            decide(POLICY, &Call::Read(vec!["/repo/sub/.env".to_owned()])),
            Some(Decision::Deny)
        );
        assert_eq!(
            decide(POLICY, &Call::Read(vec!["/elsewhere/.env.prod".to_owned()])),
            Some(Decision::Deny)
        );
        assert_eq!(
            decide(
                POLICY,
                &Call::Edit(vec!["/repo/db/migrations/x.sql".to_owned()])
            ),
            Some(Decision::Deny)
        );
        assert_eq!(
            decide(
                POLICY,
                &Call::Edit(vec!["db/migrations/README.md".to_owned()])
            ),
            Some(Decision::Allow)
        );
        assert_eq!(
            decide(
                POLICY,
                &Call::Edit(vec!["/repo/.claude/settings.local.json".to_owned()])
            ),
            Some(Decision::Ask)
        );
        let mcp = |server: Option<&str>, tool: &str| {
            decide(
                POLICY,
                &Call::Mcp {
                    server: server.map(str::to_owned),
                    tool: tool.to_owned(),
                },
            )
        };
        assert_eq!(
            mcp(Some("github"), "merge_pull_request"),
            Some(Decision::Deny)
        );
        assert_eq!(mcp(Some("github"), "get_issue"), None);
        assert_eq!(mcp(None, "merge_pull_request"), Some(Decision::Deny));
    }

    #[test]
    fn a_command_not_read_in_full_needs_a_person() {
        let verdict = evaluate(
            &parse(POLICY).unwrap(),
            &Call::Bash("echo 'open".to_owned()),
            &place(),
        );
        assert_eq!(verdict.decision, Some(Decision::Ask));
        assert_eq!(verdict.problem.as_deref(), Some("an unclosed quote"));
        let only_mcp = evaluate(
            &parse("deny Mcp(x)\n").unwrap(),
            &Call::Bash("echo 'open".to_owned()),
            &place(),
        );
        assert_eq!(only_mcp.decision, None);
    }

    #[test]
    fn a_link_or_another_name_of_the_repository_is_checked_where_it_leads() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("repo");
        std::fs::create_dir_all(root.join("secrets")).unwrap();
        std::fs::write(root.join(".env"), "K=1\n").unwrap();
        std::os::unix::fs::symlink(&root, base.path().join("alias")).unwrap();
        std::os::unix::fs::symlink(root.join(".env"), root.join("notes.txt")).unwrap();
        let policy = parse("deny Read(.env*)\ndeny Edit(secrets/**)\n").unwrap();
        let site = Site {
            root: root.clone(),
            cwd: root.clone(),
            home: None,
        };
        let decide = |call: Call| evaluate(&policy, &call, &site).decision;
        assert_eq!(
            decide(Call::Read(vec!["notes.txt".to_owned()])),
            Some(Decision::Deny)
        );
        let through_alias = base.path().join("alias/secrets/new.key");
        assert_eq!(
            decide(Call::Edit(vec![through_alias.display().to_string()])),
            Some(Decision::Deny)
        );
        assert_eq!(
            decide(Call::Bash(format!(
                "cat {}",
                base.path().join("alias/.env").display()
            ))),
            Some(Decision::Deny)
        );
        assert_eq!(decide(Call::Read(vec!["README.md".to_owned()])), None);
    }

    #[test]
    fn the_deciding_check_names_its_rule() {
        let verdict = evaluate(
            &parse(POLICY).unwrap(),
            &Call::Bash("git status && cat .env".to_owned()),
            &place(),
        );
        let check = verdict.deciding_check().unwrap();
        assert_eq!(check.subject, ".env");
        assert_eq!(check.rule.as_ref().unwrap().line, 2);
    }
}
