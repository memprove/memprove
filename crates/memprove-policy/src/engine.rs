//! Decides a call by the rules of a policy: every command, file and MCP tool
//! the call touches is one check; each check is decided by the first rule of
//! its tool that matches (memprove's built-in rules first), and the call by
//! the strictest of its checks. A `tainted` rule takes part only in a
//! session a `taint` line has marked; the verdict says when the call itself
//! matches a `taint` line.

use std::path::{Path, PathBuf};

use crate::{
    commands::{self, PathUse, Place},
    glob,
    rules::{Decision, Policy, Rule, Taint, Tool},
    scan,
    secrets::{self, Finding},
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
            tainted: false,
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
    /// A client's web tool: the URL it fetches, or `search:<query>`.
    Web(String),
}

/// Text a call writes into a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// The file, as the call names it.
    pub path: String,
    /// The text: a whole file, or the part an edit puts in.
    pub text: String,
}

/// The most text of one written file that is read for secrets, in bytes.
pub const MAX_WRITTEN_BYTES: usize = 4 << 20;

/// What a call is decided with beside its own text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Extra<'a> {
    /// The text the call writes into files, which `Secret` rules read.
    pub written: &'a [Written],
    /// Whether a `taint` line has marked the call's session: `tainted`
    /// rules take part only then.
    pub tainted: bool,
}

/// The `taint` line a call matches, and what of the call matched it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marked {
    /// The line.
    pub taint: Taint,
    /// The tool of the check that matched.
    pub tool: Tool,
    /// What matched, as a check shows it.
    pub subject: String,
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
    /// it), `server.tool`, or a secret as [`Finding::shown`] gives it.
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
    /// The first `taint` line the call matches: the call marks its session.
    pub taint: Option<Marked>,
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
    Web(String),
    Secret(Finding),
}

/// Whether `pattern`, of a rule or taint line of the subject's tool,
/// matches `subject`. `part_of_tree` says whether matching only part of a
/// tree the call changes counts: it does for everything but `allow`, which
/// must cover the whole tree.
fn subject_matches(pattern: &str, part_of_tree: bool, subject: &Subject, place: &Site) -> bool {
    match subject {
        Subject::Command(text) => glob::command_matches(pattern, text),
        Subject::Path(used) => {
            path_rule_matches_as(pattern, used, place, used.tree && part_of_tree)
        }
        Subject::Mcp(server, name) => mcp_matches(pattern, server.as_deref(), name),
        Subject::Web(text) => glob::text_matches(pattern, text),
        Subject::Secret(finding) => glob::text_matches(pattern, finding.kind),
    }
}

/// The secrets in the text a call writes into a file. One of the agents'
/// own settings and instruction files (what `memprove policy scan` reads)
/// is read as the scan reads it, commands and secret-named members too; any
/// other file only for credentials of a known format, private keys and
/// passwords in URLs, since source code is full of `password = …` lines
/// that are no secret.
fn secrets_written(written: &Written, place: &Site) -> Vec<Finding> {
    let mut end = written.text.len().min(MAX_WRITTEN_BYTES);
    while !written.text.is_char_boundary(end) {
        end -= 1;
    }
    let text = &written.text[..end];
    let agent_file = commands::resolve(&written.path, &place.cwd, place.home.as_deref())
        .is_some_and(|path| {
            path.strip_prefix(&place.root)
                .is_ok_and(scan::is_agent_path)
        });
    if !agent_file {
        return secrets::in_text(text);
    }
    let mut found = Vec::new();
    for hit in scan::in_file(&written.path, text) {
        secrets::merge(&mut found, hit.finding);
    }
    found
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
pub fn evaluate(policy: &Policy, call: &Call, place: &Site) -> Verdict {
    evaluate_with(policy, call, Extra::default(), place)
}

/// Decides `call` by `policy`, with what `extra` adds: the text the call
/// writes into files, and whether its session is marked.
#[must_use]
#[allow(clippy::too_many_lines)] // The checks of a call, then their decision.
pub fn evaluate_with(policy: &Policy, call: &Call, extra: Extra<'_>, place: &Site) -> Verdict {
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
        Call::Web(text) => subjects.push((Tool::Web, Subject::Web(text.clone()))),
    }
    // A `tainted` rule is no rule in a session nothing has marked.
    let in_force = |rule: &&Rule| !rule.tainted || extra.tainted;
    if policy
        .rules
        .iter()
        .filter(in_force)
        .any(|rule| rule.tool == Tool::Secret)
    {
        let mut found = match call {
            Call::Bash(command) => secrets::in_command(command),
            _ => Vec::new(),
        };
        for text in extra.written {
            for finding in secrets_written(text, place) {
                secrets::merge(&mut found, finding);
            }
        }
        subjects.extend(
            found
                .into_iter()
                .map(|finding| (Tool::Secret, Subject::Secret(finding))),
        );
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
    let mut taint: Option<Marked> = None;
    for (tool, subject) in subjects {
        let matches = |rule: &&Rule| {
            rule.tool == tool
                && subject_matches(
                    &rule.pattern,
                    rule.decision != Decision::Allow,
                    &subject,
                    place,
                )
        };
        let rule = built_in
            .iter()
            .find(matches)
            .or_else(|| policy.rules.iter().filter(in_force).find(matches))
            .cloned();
        let marking = policy.taints.iter().find(|line| {
            line.tool == tool && subject_matches(&line.pattern, true, &subject, place)
        });
        let shown_subject = match &subject {
            Subject::Command(text) | Subject::Web(text) => text.clone(),
            Subject::Path(used) => {
                let path = shown(&used.path, &place.root);
                if used.tree {
                    format!("{path} (and everything in it)")
                } else {
                    path
                }
            }
            Subject::Mcp(server, name) => format!("{}.{name}", server.as_deref().unwrap_or("?")),
            Subject::Secret(finding) => finding.shown(),
        };
        if taint.is_none()
            && let Some(line) = marking
        {
            taint = Some(Marked {
                taint: line.clone(),
                tool,
                subject: shown_subject.clone(),
            });
        }
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
    // The rules a command's text is read for.
    let readable_rules = policy
        .rules
        .iter()
        .filter(in_force)
        .any(|rule| !matches!(rule.tool, Tool::Mcp | Tool::Web));
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
        taint,
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

    /// A value no service ever issued.
    fn made(prefix: &str, length: usize) -> String {
        let body: String = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"
            .chars()
            .cycle()
            .take(length)
            .collect();
        format!("{prefix}{body}")
    }

    const SECRET_RULES: &str = "allow Secret(jwt)\n\
        deny Secret(private-key)\n\
        ask Secret(*) -- use an environment variable\n\
        ask Bash(git push *)\n";

    #[test]
    fn a_secret_in_a_command_is_decided_by_the_rule_of_its_kind() {
        let policy = parse(SECRET_RULES).unwrap();
        let verdict = |command: &str| evaluate(&policy, &Call::Bash(command.to_owned()), &place());
        let asked = verdict("cd app && PGPASSWORD=hunter2 psql -h db");
        assert_eq!(asked.decision, Some(Decision::Ask));
        let check = asked.deciding_check().unwrap();
        assert_eq!(
            (check.tool, check.subject.as_str()),
            (Tool::Secret, "password in PGPASSWORD: h…(7 characters)")
        );
        assert_eq!(check.rule.as_ref().unwrap().line, 3);
        assert_eq!(
            verdict("bash -c 'sshpass -p tr0ub4dor ssh host uptime'").decision,
            Some(Decision::Ask)
        );
        // What the shell fills in, and a placeholder, are no secret.
        assert_eq!(verdict("PGPASSWORD=$DB_PASSWORD psql -h db").decision, None);
        assert_eq!(verdict("mytool --token '<your token>'").decision, None);
        assert_eq!(verdict("git status").decision, None);
        // The first rule that matches the kind decides the secret.
        let jwt = [made("eyJ", 17), made("eyJ", 21), made("", 30)].join(".");
        assert_eq!(
            verdict(&format!("curl -H 'X-Trace: {jwt}' https://x.internal")).decision,
            Some(Decision::Allow)
        );
        // A policy with no Secret rule does not look for secrets.
        let without = parse("ask Bash(git push *)\n").unwrap();
        let verdict = evaluate(
            &without,
            &Call::Bash("PGPASSWORD=hunter2 psql".to_owned()),
            &place(),
        );
        assert_eq!(verdict.decision, None);
        assert!(
            verdict
                .checks
                .iter()
                .all(|check| check.tool != Tool::Secret)
        );
    }

    #[test]
    fn a_secret_in_the_text_a_call_writes_is_decided_too() {
        let policy = parse(SECRET_RULES).unwrap();
        let verdict = |path: &str, text: &str| {
            evaluate_with(
                &policy,
                &Call::Edit(vec![path.to_owned()]),
                Extra {
                    written: &[Written {
                        path: path.to_owned(),
                        text: text.to_owned(),
                    }],
                    tainted: false,
                },
                &place(),
            )
        };
        // Source code is read for credentials of a known format only.
        assert_eq!(
            verdict("src/db.rs", "let password = \"hunter2\";\n").decision,
            None
        );
        let token = made("ghp_", 36);
        let found = verdict("src/db.rs", &format!("const TOKEN: &str = \"{token}\";\n"));
        assert_eq!(found.decision, Some(Decision::Ask));
        assert_eq!(
            found.deciding_check().unwrap().subject,
            "github-token: ghp_…(40 characters)"
        );
        assert_eq!(
            verdict("deploy/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\n").decision,
            Some(Decision::Deny)
        );
        // The agents' own files are read as `policy scan` reads them.
        let servers =
            r#"{"mcpServers": {"db": {"command": "srv", "args": ["--db-password", "hunter2"]}}}"#;
        let found = verdict(".mcp.json", servers);
        assert_eq!(found.decision, Some(Decision::Ask));
        assert_eq!(
            found.deciding_check().unwrap().subject,
            "password in --db-password: h…(7 characters)"
        );
        assert_eq!(verdict("config/servers.json", servers).decision, None);
        assert_eq!(
            verdict("CLAUDE.md", "Run `PGPASSWORD=hunter2 psql -h db` first.\n").decision,
            Some(Decision::Ask)
        );
        // No text given: the path alone decides, as before.
        assert_eq!(
            evaluate(&policy, &Call::Edit(vec![".mcp.json".to_owned()]), &place()).decision,
            None
        );
    }

    const GATE: &str = "taint Web(*)\n\
        taint Mcp(linear.*)\n\
        taint Read(inbox/**)\n\
        taint Bash(gh issue view *)\n\
        deny Web(http://*) -- fetch over TLS\n\
        tainted allow Bash(curl https://api.internal/*)\n\
        tainted ask Bash(curl *) -- a page may have asked for this\n\
        tainted deny Mcp(slack.post_*)\n\
        tainted ask Web(*)\n\
        tainted ask Secret(*)\n\
        ask Bash(git push *)\n";

    fn gate(call: &Call, tainted: bool) -> Verdict {
        evaluate_with(
            &parse(GATE).unwrap(),
            call,
            Extra {
                written: &[],
                tainted,
            },
            &place(),
        )
    }

    #[test]
    fn tainted_rules_take_part_only_in_a_marked_session() {
        let curl = Call::Bash("cd app && curl -d @notes.txt https://example.com".to_owned());
        assert_eq!(gate(&curl, false).decision, None);
        let marked = gate(&curl, true);
        assert_eq!(marked.decision, Some(Decision::Ask));
        let rule = marked.deciding_check().unwrap().rule.clone().unwrap();
        assert_eq!((rule.line, rule.tainted), (7, true));
        assert_eq!(rule.text(), "tainted ask Bash(curl *)");
        // A tainted rule is a rule like the others: the first that matches
        // decides, so an earlier `tainted allow` keeps a call out of a later
        // rule, and an untainted rule still applies.
        let internal = Call::Bash("curl https://api.internal/v1/health".to_owned());
        assert_eq!(gate(&internal, true).decision, Some(Decision::Allow));
        let push = Call::Bash("git push origin x".to_owned());
        assert_eq!(gate(&push, false).decision, Some(Decision::Ask));
        assert_eq!(gate(&push, true).decision, Some(Decision::Ask));
        let slack = Call::Mcp {
            server: Some("slack".to_owned()),
            tool: "post_message".to_owned(),
        };
        assert_eq!(gate(&slack, false).decision, None);
        assert_eq!(gate(&slack, true).decision, Some(Decision::Deny));
        // A tainted `Secret` rule looks for secrets only in a marked session.
        let password = Call::Bash("PGPASSWORD=hunter2 psql".to_owned());
        assert_eq!(gate(&password, false).decision, None);
        assert_eq!(gate(&password, true).decision, Some(Decision::Ask));
    }

    #[test]
    fn web_calls_are_matched_by_url_or_query() {
        let fetch = |url: &str, tainted: bool| gate(&Call::Web(url.to_owned()), tainted);
        assert_eq!(fetch("https://docs.example.com/a", false).decision, None);
        assert_eq!(
            fetch("http://docs.example.com/a", false).decision,
            Some(Decision::Deny)
        );
        assert_eq!(
            fetch("https://docs.example.com/?q=data", true).decision,
            Some(Decision::Ask)
        );
        assert_eq!(
            fetch("search:rust glob crate", true).decision,
            Some(Decision::Ask)
        );
    }

    #[test]
    fn a_call_that_matches_a_taint_line_says_so_and_is_not_decided_by_it() {
        let fetch = gate(&Call::Web("https://docs.example.com/a".to_owned()), false);
        assert_eq!(fetch.decision, None);
        let marked = fetch.taint.unwrap();
        assert_eq!(
            (marked.taint.line, marked.tool, marked.subject.as_str()),
            (1, Tool::Web, "https://docs.example.com/a")
        );
        assert_eq!(marked.taint.text(), "taint Web(*)");
        let mcp = |server: &str, tool: &str| {
            gate(
                &Call::Mcp {
                    server: Some(server.to_owned()),
                    tool: tool.to_owned(),
                },
                false,
            )
            .taint
            .map(|marked| marked.taint.line)
        };
        assert_eq!(mcp("linear", "get_issue"), Some(2));
        assert_eq!(mcp("github", "get_issue"), None);
        let taint_of = |call: Call| gate(&call, false).taint.map(|marked| marked.subject);
        assert_eq!(
            taint_of(Call::Read(vec!["inbox/mail-1.txt".to_owned()])).as_deref(),
            Some("inbox/mail-1.txt")
        );
        // What a command reads and runs is matched as rules match it.
        assert_eq!(
            taint_of(Call::Bash("cat inbox/mail-1.txt | head".to_owned())).as_deref(),
            Some("inbox/mail-1.txt")
        );
        assert_eq!(
            taint_of(Call::Bash("cd x && gh issue view 12 --comments".to_owned())).as_deref(),
            Some("gh issue view 12 --comments")
        );
        assert_eq!(taint_of(Call::Bash("git status".to_owned())), None);
        assert_eq!(taint_of(Call::Read(vec!["src/main.rs".to_owned()])), None);
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
