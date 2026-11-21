//! The policy file: one rule or expectation per line.
//!
//! ```text
//! # a comment
//! deny  Bash(git push *--force*)  -- push a new branch instead
//! ask   Bash(git push *)
//! deny  Read(.env*)
//! allow Edit(db/migrations/README.md)
//! ask   Secret(*)                 -- use an environment variable
//! taint Web(*)
//! tainted ask Bash(curl *)        -- only once a taint line has marked the session
//! expect deny Bash(cd app && git push -f)
//! expect tainted ask Bash(curl https://example.com)
//! ```

use std::fmt;

/// What a rule says about a call. The order is strictness: `Deny` is the
/// strictest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decision {
    /// The policy does not object (it never approves a call for a client).
    Allow,
    /// A person must approve the call.
    Ask,
    /// The call is refused.
    Deny,
}

impl Decision {
    /// The word of the decision in a policy file.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }

    /// The decision named `word`.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "allow" => Some(Self::Allow),
            "ask" => Some(Self::Ask),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.word())
    }
}

/// What a rule is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tool {
    /// A shell command, by its text.
    Bash,
    /// Reading a file, by its path.
    Read,
    /// Writing, changing, renaming or deleting a file, by its path.
    Edit,
    /// An MCP tool, by `server.tool`.
    Mcp,
    /// A client's own web tool: a fetch by its URL, a search as
    /// `search:<query>`.
    Web,
    /// A secret in a shell command or in the text a call writes into a
    /// file, by its kind ([`crate::secrets::KINDS`]). A rule's tool only: no
    /// call is a `Secret`.
    Secret,
}

impl Tool {
    /// The name of the tool in a policy file.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bash => "Bash",
            Self::Read => "Read",
            Self::Edit => "Edit",
            Self::Mcp => "Mcp",
            Self::Web => "Web",
            Self::Secret => "Secret",
        }
    }

    /// The tool named `name` (any case; `Shell` is `Bash`, `Write` is
    /// `Edit`).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "bash" | "shell" => Some(Self::Bash),
            "read" => Some(Self::Read),
            "edit" | "write" => Some(Self::Edit),
            "mcp" => Some(Self::Mcp),
            "web" | "webfetch" | "websearch" => Some(Self::Web),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Its line in the file (1-based; 0 for a built-in rule).
    pub line: usize,
    /// What it decides.
    pub decision: Decision,
    /// What it is about.
    pub tool: Tool,
    /// Its pattern: for `Bash` with whitespace runs as one space and `:*`
    /// as ` *`; for `Mcp` as `server.tool`; for `Secret` in lower case.
    pub pattern: String,
    /// The text after `--`, for the agent and the person.
    pub reason: Option<String>,
    /// A `tainted` rule: it exists only in a session a [`Taint`] line has
    /// marked.
    pub tainted: bool,
}

impl Rule {
    /// The rule as a policy file would hold it, without its reason.
    #[must_use]
    pub fn text(&self) -> String {
        let rule = format!("{} {}({})", self.decision, self.tool.name(), self.pattern);
        if self.tainted {
            format!("tainted {rule}")
        } else {
            rule
        }
    }
}

/// One `taint` line: a call that matches it marks its session as having
/// read content nobody here wrote. It decides no call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taint {
    /// Its line in the file.
    pub line: usize,
    /// The tool of the calls it matches.
    pub tool: Tool,
    /// Its pattern, as a rule of that tool holds it.
    pub pattern: String,
}

impl Taint {
    /// The line as a policy file would hold it.
    #[must_use]
    pub fn text(&self) -> String {
        format!("taint {}({})", self.tool.name(), self.pattern)
    }
}

/// One `expect` line: the decision a call must get.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    /// Its line in the file.
    pub line: usize,
    /// The decision expected; `allow` also accepts no decision.
    pub decision: Decision,
    /// `expect tainted …`: the call is decided as in a marked session.
    pub tainted: bool,
    /// The call's tool.
    pub tool: Tool,
    /// The call's command, path or MCP tool.
    pub subject: String,
}

/// A policy file read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Its rules, in order.
    pub rules: Vec<Rule>,
    /// Its `expect` lines, in order.
    pub expectations: Vec<Expectation>,
    /// Its `taint` lines, in order.
    pub taints: Vec<Taint>,
}

impl Policy {
    /// Whether sessions matter to this policy: it has a `taint` line or a
    /// `tainted` rule.
    #[must_use]
    pub fn follows_sessions(&self) -> bool {
        !self.taints.is_empty() || self.rules.iter().any(|rule| rule.tainted)
    }
}

/// A line the policy file cannot hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineError {
    /// The line (1-based).
    pub line: usize,
    /// What is wrong with it.
    pub message: String,
}

impl fmt::Display for LineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {}: {}", self.line, self.message)
    }
}

/// The largest policy file read, in bytes.
pub const MAX_POLICY_BYTES: usize = 1 << 20;

/// Reads the text of a policy file.
///
/// # Errors
///
/// Every line that is not a comment, a rule or an expectation.
pub fn parse(text: &str) -> Result<Policy, Vec<LineError>> {
    let mut policy = Policy::default();
    let mut errors = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (first, rest) = split_word(trimmed);
        let parsed = if first == "expect" {
            parse_expectation(rest).map(|(tainted, decision, tool, subject)| {
                policy.expectations.push(Expectation {
                    line,
                    decision,
                    tainted,
                    tool,
                    subject,
                });
            })
        } else if first == "taint" {
            parse_rule(rest).and_then(|(tool, pattern, _)| {
                if tool == Tool::Secret {
                    return Err(
                        "a taint line names what the session reads, as in taint Web(*) or taint \
                         Mcp(*), not a Secret"
                            .to_owned(),
                    );
                }
                policy.taints.push(Taint {
                    line,
                    tool,
                    pattern,
                });
                Ok(())
            })
        } else if first == "tainted" {
            let (word, rest) = split_word(rest);
            match Decision::parse(word) {
                Some(decision) => parse_rule(rest).map(|(tool, pattern, reason)| {
                    policy.rules.push(Rule {
                        line,
                        decision,
                        tool,
                        pattern,
                        reason,
                        tainted: true,
                    });
                }),
                None => Err(
                    "`tainted` is followed by deny, ask or allow, then a rule such as Bash(curl *)"
                        .to_owned(),
                ),
            }
        } else if let Some(decision) = Decision::parse(first) {
            parse_rule(rest).map(|(tool, pattern, reason)| {
                policy.rules.push(Rule {
                    line,
                    decision,
                    tool,
                    pattern,
                    reason,
                    tainted: false,
                });
            })
        } else {
            Err(format!(
                "a line starts with deny, ask, allow, taint, tainted or expect, not `{}`",
                shorten(first, 40)
            ))
        };
        if let Err(message) = parsed {
            errors.push(LineError { line, message });
        }
    }
    if errors.is_empty() {
        Ok(policy)
    } else {
        Err(errors)
    }
}

fn split_word(text: &str) -> (&str, &str) {
    match text.find(char::is_whitespace) {
        Some(at) => (&text[..at], text[at..].trim_start()),
        None => (text, ""),
    }
}

fn shorten(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        text.to_owned()
    } else {
        let mut short: String = text.chars().take(limit).collect();
        short.push('…');
        short
    }
}

/// `Tool(` at the start of `text`: the tool and the text after `(`.
fn tool_call(text: &str) -> Result<(Tool, &str), String> {
    let Some(open) = text.find('(') else {
        return Err("a rule names a tool and its pattern, as in Bash(git push *)".to_owned());
    };
    let name = text[..open].trim();
    let tool = Tool::parse(name).ok_or_else(|| {
        format!(
            "the tool is Bash, Read, Edit, Mcp, Web or Secret, not `{}`",
            shorten(name, 40)
        )
    })?;
    Ok((tool, &text[open + 1..]))
}

/// The pattern as a rule of `tool` holds it.
#[must_use]
pub fn normalize(tool: Tool, pattern: &str) -> String {
    match tool {
        Tool::Bash => crate::glob::command_pattern(pattern),
        Tool::Read | Tool::Edit | Tool::Web => pattern.trim().to_owned(),
        Tool::Mcp => mcp_name(pattern.trim()),
        Tool::Secret => pattern.trim().to_ascii_lowercase(),
    }
}

/// An MCP tool's name as `server.tool`: Claude Code's and Codex's
/// `mcp__server__tool` is taken apart; a name without a `.` stands for every
/// tool of that server.
#[must_use]
pub fn mcp_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("mcp__") {
        return match rest.split_once("__") {
            Some((server, tool)) => format!("{server}.{tool}"),
            None => format!("{rest}.*"),
        };
    }
    if name.contains('.') {
        name.to_owned()
    } else {
        format!("{name}.*")
    }
}

fn parse_rule(text: &str) -> Result<(Tool, String, Option<String>), String> {
    let (tool, after) = tool_call(text)?;
    // The pattern ends at the first `)` followed by nothing, by ` -- …`, or
    // by ` # …`.
    let close = after
        .char_indices()
        .filter(|(_, character)| *character == ')')
        .map(|(at, _)| at)
        .find(|at| {
            let tail = &after[at + 1..];
            let trimmed = tail.trim_start();
            trimmed.is_empty()
                || (tail.len() > trimmed.len()
                    && (trimmed == "--"
                        || trimmed.starts_with("-- ")
                        || trimmed.starts_with("--\t")
                        || trimmed.starts_with('#')))
        })
        .ok_or_else(|| "the pattern is not closed with `)`".to_owned())?;
    let pattern = normalize(tool, &after[..close]);
    if pattern.is_empty() {
        return Err("the pattern is empty".to_owned());
    }
    if tool == Tool::Secret
        && !crate::secrets::KINDS
            .iter()
            .any(|kind| crate::glob::text_matches(&pattern, kind))
    {
        return Err(format!(
            "no kind of secret is `{}`; the kinds are {} (`*` is every kind)",
            shorten(&pattern, 40),
            crate::secrets::KINDS.join(", ")
        ));
    }
    let tail = after[close + 1..].trim();
    let reason = tail
        .strip_prefix("--")
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(str::to_owned);
    Ok((tool, pattern, reason))
}

fn parse_expectation(text: &str) -> Result<(bool, Decision, Tool, String), String> {
    let (word, rest) = split_word(text);
    let (tainted, word, rest) = if word == "tainted" {
        let (word, rest) = split_word(rest);
        (true, word, rest)
    } else {
        (false, word, rest)
    };
    let decision = Decision::parse(word).ok_or_else(|| {
        "`expect` is followed by deny, ask or allow (after `tainted`, for a marked session), \
         then a call such as Bash(git push -f)"
            .to_owned()
    })?;
    let (tool, subject) = parse_call(rest)?;
    Ok((tainted, decision, tool, subject))
}

/// A call as `check` and `expect` take it: `Tool(subject)`, the subject up
/// to the last `)`.
///
/// # Errors
///
/// When it is not such a call.
pub fn parse_call(text: &str) -> Result<(Tool, String), String> {
    let (tool, after) = tool_call(text.trim())?;
    let close = after
        .rfind(')')
        .filter(|at| after[at + 1..].trim().is_empty())
        .ok_or_else(|| "the call is not closed with `)`".to_owned())?;
    let subject = after[..close].trim();
    if subject.is_empty() {
        return Err("the call is empty".to_owned());
    }
    if tool == Tool::Secret {
        return Err(
            "`Secret` is a rule, not a call: give the command that holds the secret, as in \
             Bash(PGPASSWORD=hunter2 psql)"
                .to_owned(),
        );
    }
    let subject = if tool == Tool::Mcp {
        mcp_name(subject)
    } else {
        subject.to_owned()
    };
    Ok((tool, subject))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_rules_reasons_and_expectations() {
        let policy = parse(
            "# policy\n\
             deny  Bash(git push *--force*)  -- push a new branch (not main) instead\n\
             ask bash(git   push:*)\n\
             deny Read(.env*) # secrets\n\
             deny Mcp(mcp__github__merge_pull_request)\n\
             deny Mcp(linear)\n\
             allow Write(db/migrations/README.md)\n\
             \n\
             expect deny Bash(echo (x) && git push -f)\n",
        )
        .unwrap();
        let texts: Vec<String> = policy.rules.iter().map(Rule::text).collect();
        assert_eq!(
            texts,
            vec![
                "deny Bash(git push *--force*)",
                "ask Bash(git push *)",
                "deny Read(.env*)",
                "deny Mcp(github.merge_pull_request)",
                "deny Mcp(linear.*)",
                "allow Edit(db/migrations/README.md)",
            ]
        );
        assert_eq!(
            policy.rules[0].reason.as_deref(),
            Some("push a new branch (not main) instead")
        );
        assert_eq!(policy.rules[0].line, 2);
        assert_eq!(policy.rules[2].reason, None);
        assert_eq!(
            policy.expectations,
            vec![Expectation {
                line: 9,
                decision: Decision::Deny,
                tainted: false,
                tool: Tool::Bash,
                subject: "echo (x) && git push -f".to_owned(),
            }]
        );
    }

    #[test]
    fn says_which_lines_are_wrong() {
        let errors = parse("deny Bash(x)\nblock Bash(y)\ndeny Run(z)\ndeny Bash(open\ndeny Bash( )\nexpect maybe Bash(x)\n")
            .unwrap_err();
        let lines: Vec<usize> = errors.iter().map(|error| error.line).collect();
        assert_eq!(lines, vec![2, 3, 4, 5, 6]);
        assert!(errors[0].message.contains("`block`"));
        assert!(errors[1].message.contains("`Run`"));
        assert!(errors[2].message.contains("not closed"));
        assert!(errors[3].message.contains("empty"));
    }

    #[test]
    fn secret_rules_name_a_kind_and_no_call_is_a_secret() {
        let policy = parse(
            "ask Secret(*) -- use an environment variable\n\
             deny secret( Private-Key )\n\
             allow Secret(*-token)\n",
        )
        .unwrap();
        let texts: Vec<String> = policy.rules.iter().map(Rule::text).collect();
        assert_eq!(
            texts,
            vec![
                "ask Secret(*)",
                "deny Secret(private-key)",
                "allow Secret(*-token)"
            ]
        );
        let errors = parse("ask Secret(pasword)\nexpect ask Secret(password)\n").unwrap_err();
        assert!(
            errors[0].message.contains("no kind of secret is `pasword`")
                && errors[0].message.contains("private-key"),
            "{}",
            errors[0].message
        );
        assert!(errors[1].message.contains("`Secret` is a rule, not a call"));
        assert!(parse_call("Secret(password)").is_err());
    }

    #[test]
    fn taint_lines_and_tainted_rules_are_read() {
        let policy = parse(
            "taint Web(*)\n\
             taint mcp(mcp__linear__get_issue) -- issue text is written by anyone\n\
             tainted ask Bash(curl:*) -- a page may have asked for this\n\
             tainted deny WebFetch(*)\n\
             deny Web(http://*)\n\
             expect tainted ask Bash(curl https://example.com)\n\
             expect allow Bash(curl https://example.com)\n",
        )
        .unwrap();
        let taints: Vec<String> = policy.taints.iter().map(Taint::text).collect();
        assert_eq!(taints, vec!["taint Web(*)", "taint Mcp(linear.get_issue)"]);
        assert_eq!(policy.taints[1].line, 2);
        let rules: Vec<String> = policy.rules.iter().map(Rule::text).collect();
        assert_eq!(
            rules,
            vec![
                "tainted ask Bash(curl *)",
                "tainted deny Web(*)",
                "deny Web(http://*)"
            ]
        );
        assert_eq!(
            policy.rules[0].reason.as_deref(),
            Some("a page may have asked for this")
        );
        let expected: Vec<(bool, Decision)> = policy
            .expectations
            .iter()
            .map(|expectation| (expectation.tainted, expectation.decision))
            .collect();
        assert_eq!(
            expected,
            vec![(true, Decision::Ask), (false, Decision::Allow)]
        );
        assert!(policy.follows_sessions());
        assert!(!parse("deny Bash(x)\n").unwrap().follows_sessions());

        let errors =
            parse("taint Secret(*)\ntainted Bash(curl *)\ntaint\nexpect tainted Bash(x)\n")
                .unwrap_err();
        let lines: Vec<usize> = errors.iter().map(|error| error.line).collect();
        assert_eq!(lines, vec![1, 2, 3, 4]);
        assert!(errors[0].message.contains("not a Secret"));
        assert!(errors[1].message.contains("`tainted` is followed by"));
    }

    #[test]
    fn a_dash_dash_inside_the_pattern_is_part_of_it() {
        let policy = parse("deny Bash(git push --force) -- no\n").unwrap();
        assert_eq!(policy.rules[0].pattern, "git push --force");
        assert_eq!(policy.rules[0].reason.as_deref(), Some("no"));
    }

    #[test]
    fn decisions_are_ordered_by_strictness() {
        assert!(Decision::Deny > Decision::Ask);
        assert!(Decision::Ask > Decision::Allow);
    }
}
