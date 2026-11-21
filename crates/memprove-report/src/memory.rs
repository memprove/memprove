//! The memprove statements an agent was given, as it read them: the claim
//! lines of a Context Pack (`#4 fact stale: 「…」 (…)`) and of `resume
//! --text` or the MCP `claims` tool, which share their first words. A fact
//! the line does not call `verified` was not verified when the agent read
//! it.

use std::collections::BTreeMap;

/// The format of the Context Packs this crate reads, as their first line
/// names it (`Pack: memprove-pack v1; …`).
pub const PACK_FORMAT: &str = "memprove-pack v1";

/// The format a Context Pack's first line names (`Pack: <name>-pack
/// v<N>; …`), if `line` is one. Packs written before memprove 0.1 have a
/// full-width colon and semicolon here.
#[must_use]
pub fn pack_format(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("Pack: ")
        .or_else(|| line.strip_prefix("Pack："))?;
    let format = rest.split([';', '；']).next()?.trim();
    let (name, version) = format.split_once("-pack v")?;
    let named = !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '-');
    let versioned = !version.is_empty() && version.chars().all(|digit| digit.is_ascii_digit());
    (named && versioned).then_some(format)
}

/// Whether `text` holds a Context Pack's first line, of any format.
#[must_use]
pub fn holds_pack(text: &str) -> bool {
    text.lines()
        .any(|line| pack_format(line.trim_end_matches('\r')).is_some())
}

/// Where the quote that `body` continues ends: the byte index of its
/// closing `」`. A backslash escapes the character after it (`\」`, `\\`),
/// as the Pack and `resume --text` write an agent's text.
fn quote_end(body: &str) -> Option<usize> {
    let mut escaped = false;
    for (at, character) in body.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '」' => return Some(at),
            _ => {}
        }
    }
    None
}

/// The quote that `body` continues, still escaped, and what follows its
/// closing `」`; all of `body` when it does not close.
fn quote(body: &str) -> (&str, &str) {
    quote_end(body).map_or((body, ""), |at| {
        (&body[..at], &body[at + '」'.len_utf8()..])
    })
}

/// A statement's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A fact, with a verdict.
    Fact,
    /// An open item.
    OpenItem,
    /// A decision.
    Decision,
    /// The next action.
    NextAction,
}

impl Kind {
    /// The kind as the claim lines write it.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::Fact => "fact",
            Self::OpenItem => "open item",
            Self::Decision => "decision",
            Self::NextAction => "next action",
        }
    }

    /// The kind as JSON names it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fact => "fact",
            Self::OpenItem => "open_item",
            Self::Decision => "decision",
            Self::NextAction => "next_action",
        }
    }

    fn parse(words: &str) -> Option<Self> {
        [Self::Fact, Self::OpenItem, Self::Decision, Self::NextAction]
            .into_iter()
            .find(|kind| kind.words() == words)
    }
}

/// Whether a statement was still in force when the agent read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// In force.
    Active,
    /// A later statement replaced it.
    Superseded,
    /// It was withdrawn.
    Withdrawn,
}

impl Standing {
    /// The standing as JSON names it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Withdrawn => "withdrawn",
        }
    }
}

/// One statement as the agent read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// Its number in the Task (`#4`).
    pub number: u64,
    /// Its kind.
    pub kind: Kind,
    /// A fact's verdict word (`verified`, `stale`, `unconfirmed`,
    /// `tampered`); `None` for other kinds and for a replaced fact.
    pub verdict: Option<String>,
    /// Whether it was in force.
    pub standing: Standing,
    /// The reason codes the line gave (`head_changed`, …).
    pub reasons: Vec<String>,
    /// Its text as the line quoted it: with the line's escapes (`\」`,
    /// `\n`, …), and possibly shortened by the Pack.
    pub text: String,
    /// Where the agent read it: `hook`, a tool name, or `message`.
    pub source: String,
}

impl Statement {
    /// Whether this is a fact in force that the line did not call verified.
    #[must_use]
    pub fn unverified_fact(&self) -> bool {
        self.kind == Kind::Fact
            && self.standing == Standing::Active
            && self
                .verdict
                .as_deref()
                .is_some_and(|verdict| verdict != "verified")
    }
}

/// One Context Pack the agent read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackRead {
    /// Where: `hook`, a tool name, or `message`.
    pub source: String,
    /// The Task's title, from its `Task「…」` line, as quoted there.
    pub task: Option<String>,
    /// The Pack's `Digest: sha256:…`, when the text holds it.
    pub digest: Option<String>,
}

/// Every memprove statement and Pack an agent read in a session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemorySeen {
    /// The Packs, in the order read.
    pub packs: Vec<PackRead>,
    /// The statements by number; a later reading replaces an earlier one.
    pub statements: BTreeMap<u64, Statement>,
    /// How many texts held statements (a Pack, a `claims` answer, …).
    pub reads: u64,
    /// The Packs of another format than [`PACK_FORMAT`] the agent was
    /// given, by the format their first line names: none of their lines
    /// is read.
    pub other_packs: BTreeMap<String, u64>,
}

impl MemorySeen {
    /// Reads the statements and Packs in `text`, which the agent received
    /// from `source`.
    pub fn feed(&mut self, source: &str, text: &str) {
        let mut found = false;
        let mut pack: Option<PackRead> = None;
        // Inside a Pack of another format, up to its `Digest` line.
        let mut other = false;
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(format) = pack_format(line) {
                if let Some(done) = pack.take() {
                    self.packs.push(done);
                }
                other = format != PACK_FORMAT;
                if other {
                    *self.other_packs.entry(format.to_owned()).or_default() += 1;
                } else {
                    pack = Some(PackRead {
                        source: source.to_owned(),
                        task: None,
                        digest: None,
                    });
                    found = true;
                }
                continue;
            }
            if other {
                other = !line.starts_with("Digest");
                continue;
            }
            if let Some(open) = pack.as_mut() {
                if open.task.is_none()
                    && let Some(rest) = line.strip_prefix("Task「")
                {
                    open.task = quote_end(rest).map(|end| rest[..end].to_owned());
                }
                if let Some(digest) = line.strip_prefix("Digest: ") {
                    open.digest = Some(digest.trim().to_owned());
                    if let Some(done) = pack.take() {
                        self.packs.push(done);
                    }
                }
            }
            if let Some(statement) = statement_line(line, source) {
                self.statements.insert(statement.number, statement);
                found = true;
            }
        }
        if let Some(done) = pack {
            self.packs.push(done);
        }
        if found {
            self.reads += 1;
        }
    }

    /// The facts in force that were not verified when read, by number.
    pub fn unverified_facts(&self) -> impl Iterator<Item = &Statement> {
        self.statements
            .values()
            .filter(|statement| statement.unverified_fact())
    }

    /// Whether the agent was given nothing from memprove.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packs.is_empty() && self.statements.is_empty() && self.other_packs.is_empty()
    }
}

/// The statement of one claim line, if `line` is one: `#<n> <label>:
/// 「<text>」…`, where the label is `verified`, `fact <verdict>`, a kind, or
/// a kind followed by `, superseded by …` or `, withdrawn`.
#[must_use]
pub fn statement_line(line: &str, source: &str) -> Option<Statement> {
    let rest = line.strip_prefix('#')?;
    let digits = rest.find(|character: char| !character.is_ascii_digit())?;
    if digits == 0 {
        return None;
    }
    let number: u64 = rest[..digits].parse().ok()?;
    let rest = rest[digits..].strip_prefix(' ')?;
    let (label, body) = rest.split_once(": 「")?;
    let (head, standing) = if let Some((kind, _)) = label.split_once(", superseded by ") {
        (kind, Standing::Superseded)
    } else if let Some(kind) = label.strip_suffix(", withdrawn") {
        (kind, Standing::Withdrawn)
    } else {
        (label, Standing::Active)
    };
    let (kind, verdict) = match head {
        "verified" if standing == Standing::Active => (Kind::Fact, Some("verified".to_owned())),
        _ => match head.strip_prefix("fact ") {
            Some(word @ ("stale" | "unconfirmed" | "tampered")) if standing == Standing::Active => {
                (Kind::Fact, Some(word.to_owned()))
            }
            Some(_) => return None,
            None => (Kind::parse(head)?, None),
        },
    };
    let (text, after) = quote(body);
    let reasons = after
        .split_once("(reasons: ")
        .map(|(_, codes)| {
            codes
                .split([';', ')'])
                .next()
                .unwrap_or_default()
                .split(", ")
                .filter(|code| !code.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Some(Statement {
        number,
        kind,
        verdict,
        standing,
        reasons,
        text: text.to_owned(),
        source: source.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACK: &str = "memprove: the current Task is「Fix the parser」.\n\
```text\n\
Pack: memprove-pack v1; capsule_digest sha256:aa; ledger sequence 12; HEAD 1234567; budget 9000 UTF-16 code units\n\
Ontology: memprove-ontology v3\n\
Task「Fix the parser」 (in_progress): stale (head_changed); statements: 4 active, 1 superseded, 0 withdrawn\n\
#1 verified: 「The tokenizer keeps quotes」 (evidence bound to commit 1234567; from Session 1)\n\
#2 fact stale: 「cargo test passes」 (reasons: head_changed, worktree_changed; evidence bound to commit 89abcde; from Session 1)\n\
#3 open item: 「Escapes in heredocs are not read」 (no evidence cited; from Session 2)\n\
#5 next action: 「Add a heredoc test」 (no evidence cited; from Session 2)\n\
Digest: sha256:bb\n\
```\n";

    #[test]
    fn a_pack_gives_its_statements_and_verdicts() {
        let mut seen = MemorySeen::default();
        seen.feed("hook", PACK);
        assert_eq!(seen.reads, 1);
        assert_eq!(
            seen.packs,
            vec![PackRead {
                source: "hook".to_owned(),
                task: Some("Fix the parser".to_owned()),
                digest: Some("sha256:bb".to_owned()),
            }]
        );
        assert_eq!(seen.statements.len(), 4);
        let stale: Vec<&Statement> = seen.unverified_facts().collect();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].number, 2);
        assert_eq!(stale[0].verdict.as_deref(), Some("stale"));
        assert_eq!(stale[0].reasons, vec!["head_changed", "worktree_changed"]);
        assert_eq!(stale[0].text, "cargo test passes");
        assert_eq!(seen.statements[&3].kind, Kind::OpenItem);
        assert_eq!(seen.statements[&5].kind, Kind::NextAction);
    }

    #[test]
    fn a_quote_ends_at_its_own_closing_bracket() {
        let line = "#48 fact stale: 「Owner \\「agreed\\」 on a\\\\b」 (reasons: head_changed; from Session 7)";
        let statement = statement_line(line, "hook").unwrap();
        assert_eq!(statement.text, "Owner \\「agreed\\」 on a\\\\b");
        assert_eq!(statement.reasons, vec!["head_changed"]);
        // A quote the Pack cut, or a line cut by a tool, does not close.
        let cut = statement_line("#1 verified: 「no end \\」", "hook").unwrap();
        assert_eq!(cut.text, "no end \\」");

        let mut seen = MemorySeen::default();
        seen.feed(
            "hook",
            "Pack: memprove-pack v1; HEAD 1234567\nTask「A \\「quoted\\」 title」 (in_progress)\nDigest: sha256:bb\n",
        );
        assert_eq!(
            seen.packs[0].task.as_deref(),
            Some("A \\「quoted\\」 title")
        );
    }

    #[test]
    fn a_pack_of_another_format_is_counted_and_not_read() {
        assert_eq!(
            pack_format("Pack: memprove-pack v1; capsule_digest sha256:aa"),
            Some(PACK_FORMAT)
        );
        assert_eq!(
            pack_format("Pack：continuity-pack v1；账本序号 12"),
            Some("continuity-pack v1")
        );
        for line in [
            "Pack: a parcel; of things",
            "Pack: -pack v1;",
            "Packs: x-pack v1;",
        ] {
            assert_eq!(pack_format(line), None, "{line}");
        }

        let mut seen = MemorySeen::default();
        seen.feed(
            "hook",
            "Pack: memprove-pack v2; HEAD 1234567\n\
             #1 verified: 「read by a later grammar」 (from Session 1)\n\
             Digest: sha256:cc\n\
             #2 fact stale: 「after the Pack」 (reasons: head_changed; from Session 1)\n",
        );
        seen.feed(
            "hook",
            "Pack：continuity-pack v1；账本序号 12\n#3 事实 已过期：「旧」\n",
        );
        assert_eq!(seen.packs, vec![]);
        assert_eq!(
            seen.other_packs,
            BTreeMap::from([
                ("continuity-pack v1".to_owned(), 1),
                ("memprove-pack v2".to_owned(), 1)
            ])
        );
        // Only the line after the other Pack's end is a statement read.
        assert_eq!(seen.statements.keys().copied().collect::<Vec<_>>(), [2]);
        assert_eq!(seen.reads, 1);
        assert!(!seen.is_empty());
        assert!(holds_pack("intro\r\nPack: memprove-pack v1; x\r\n"));
        assert!(!holds_pack("the Pack: memprove-pack v1; is quoted here"));
    }

    #[test]
    fn later_readings_replace_earlier_ones() {
        let mut seen = MemorySeen::default();
        seen.feed("hook", PACK);
        seen.feed(
            "mcp__memprove__claims",
            "#2 fact, superseded by #6: 「cargo test passes」 (evidence: passed; from Session 1)\n\
             #6 verified: 「cargo test passes on 4567890」 (evidence bound to commit 4567890; from Session 3)\n",
        );
        assert_eq!(seen.reads, 2);
        assert_eq!(seen.statements[&2].standing, Standing::Superseded);
        assert_eq!(seen.unverified_facts().count(), 0);
        assert_eq!(seen.statements[&6].source, "mcp__memprove__claims");
    }

    #[test]
    fn other_lines_are_not_statements() {
        for line in [
            "#2 fact maybe: 「x」",
            "# heading: 「x」",
            "#x verified: 「x」",
            "#4 verified 「x」",
            "#4 decision, withdrawn「x」",
            "#4 verified, withdrawn: 「x」",
            "issue #4 verified: 「x」",
        ] {
            assert_eq!(statement_line(line, "t"), None, "{line}");
        }
        let withdrawn = statement_line(
            "#4 decision, withdrawn: 「Use tabs」 (withdrawal reason 「wrong」; no evidence cited; from Session 1)",
            "t",
        )
        .unwrap();
        assert_eq!(withdrawn.standing, Standing::Withdrawn);
        assert_eq!(withdrawn.kind, Kind::Decision);
        assert!(!withdrawn.unverified_fact());
        let unconfirmed = statement_line(
            "#7 fact unconfirmed: 「x」 (reasons: evidence_not_passed; …)",
            "t",
        )
        .unwrap();
        assert!(unconfirmed.unverified_fact());
        assert_eq!(unconfirmed.reasons, vec!["evidence_not_passed"]);
    }
}
