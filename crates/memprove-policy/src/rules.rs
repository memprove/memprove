//! The policy file: one rule or expectation per line.
//!
//! ```text
//! # a comment
//! deny  Bash(git push *--force*)  -- push a new branch instead
//! ask   Bash(git push *)
//! deny  Read(.env*)
//! allow Edit(db/migrations/README.md)
//! expect deny Bash(cd app && git push -f)
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
    /// as ` *`; for `Mcp` as `server.tool`.
    pub pattern: String,
    /// The text after `--`, for the agent and the person.
    pub reason: Option<String>,
}

impl Rule {
    /// The rule as a policy file would hold it, without its reason.
    #[must_use]
    pub fn text(&self) -> String {
        format!("{} {}({})", self.decision, self.tool.name(), self.pattern)
    }
}

/// One `expect` line: the decision a call must get.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    /// Its line in the file.
    pub line: usize,
    /// The decision expected; `allow` also accepts no decision.
    pub decision: Decision,
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
            parse_expectation(rest).map(|(decision, tool, subject)| {
                policy.expectations.push(Expectation {
                    line,
                    decision,
                    tool,
                    subject,
                });
            })
        } else if let Some(decision) = Decision::parse(first) {
            parse_rule(rest).map(|(tool, pattern, reason)| {
                policy.rules.push(Rule {
                    line,
                    decision,
                    tool,
                    pattern,
                    reason,
                });
            })
        } else {
            Err(format!(
                "a line starts with deny, ask, allow or expect, not `{}`",
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
            "the tool is Bash, Read, Edit or Mcp, not `{}`",
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
        Tool::Read | Tool::Edit => pattern.trim().to_owned(),
        Tool::Mcp => mcp_name(pattern.trim()),
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
    let tail = after[close + 1..].trim();
    let reason = tail
        .strip_prefix("--")
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(str::to_owned);
    Ok((tool, pattern, reason))
}

fn parse_expectation(text: &str) -> Result<(Decision, Tool, String), String> {
    let (word, rest) = split_word(text);
    let decision = Decision::parse(word).ok_or_else(|| {
        "`expect` is followed by deny, ask or allow, then a call such as Bash(git push -f)"
            .to_owned()
    })?;
    let (tool, subject) = parse_call(rest)?;
    Ok((decision, tool, subject))
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
