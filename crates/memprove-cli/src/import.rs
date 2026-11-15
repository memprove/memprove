//! U24 (I1): `memprove import`. The instructions and memories a repository
//! already keeps for coding agents (CLAUDE.md, AGENTS.md, Cursor's rules,
//! Claude Code's auto-memory) become open items of the current Session, one
//! per bullet or paragraph, each marked as imported and not verified: the
//! Context Pack carries them from then on, and none is a fact until a test
//! run supports it.
//!
//! Without `--select` nothing is sent: the numbered list of what would be
//! imported is printed. With `--select`, the selected statements are
//! recorded by one `checkpoint create --open ... --next ...` of the current
//! context; a statement already in force as an imported open item is left
//! out, so importing twice records nothing twice.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use memprove_protocol::phase1::CLAIM_TEXT_MAX_CHARS;

use crate::init::{NOTE_BEGIN, NOTE_END, PREVIOUS_NOTE_BEGIN, PREVIOUS_NOTE_END};

/// The files `memprove import` reads by default, relative to the Workspace
/// root, in this order; those that are not files are passed over.
pub const DEFAULT_FILES: [&str; 7] = [
    "CLAUDE.md",
    "CLAUDE.local.md",
    ".claude/CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
    ".github/copilot-instructions.md",
    ".cursorrules",
];

/// Cursor's rules directory: every `*.mdc` and `*.md` file in it, in name
/// order, except the rule `memprove init` writes.
pub const CURSOR_RULES_DIR: &str = ".cursor/rules";

/// The rules of Cursor's directory that memprove itself writes.
const OWN_RULES: [&str; 2] = ["memprove.mdc", "continuity.mdc"];

/// What the source of an auto-memory file is called.
pub const AUTO_MEMORY: &str = "auto-memory";

/// Where an imported statement's mark starts: `<text> (imported from
/// <source>:<line>; not verified)`.
pub const MARK_START: &str = " (imported from ";

/// What every mark ends with.
pub const MARK_END: &str = "; not verified)";

/// One file to read and the name its statements cite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The name the mark cites: relative to the Workspace root, or
    /// `auto-memory/<file>`.
    pub name: String,
    /// The file.
    pub path: PathBuf,
}

/// One statement found in a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The source's name.
    pub source: String,
    /// The line the statement starts on, from 1.
    pub line: usize,
    /// The statement, its whitespace collapsed.
    pub text: String,
}

impl Candidate {
    /// The open item's text: the statement and its mark.
    #[must_use]
    pub fn recorded(&self) -> String {
        format!(
            "{}{MARK_START}{}:{}{MARK_END}",
            self.text, self.source, self.line
        )
    }

    /// Whether `open_items` (the texts of the open items in force) already
    /// hold this statement as an imported one, from any line of any source.
    #[must_use]
    pub fn in_force(&self, open_items: &[&str]) -> bool {
        open_items.iter().any(|item| {
            item.strip_prefix(self.text.as_str())
                .and_then(|rest| rest.strip_prefix(MARK_START))
                .is_some_and(|rest| rest.ends_with(MARK_END))
        })
    }
}

/// A statement that cannot be imported, and why; its text is not repeated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passed {
    /// The source's name.
    pub source: String,
    /// The line it starts on.
    pub line: usize,
    /// Why, as a clause.
    pub reason: String,
}

/// What the sources hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// The sources read, by name.
    pub read: Vec<String>,
    /// The statements, in source order.
    pub candidates: Vec<Candidate>,
    /// The statements passed over.
    pub passed: Vec<Passed>,
    /// The sources that could not be read, each with its error.
    pub unreadable: Vec<(String, String)>,
}

/// `memprove import`'s arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportSpec {
    /// `--file`, in order; empty for the default sources.
    pub files: Vec<PathBuf>,
    /// `--select`.
    pub select: Option<String>,
    /// `--next`.
    pub next: Option<String>,
    /// `--dry-run`.
    pub dry_run: bool,
    /// The global options given, each with its value, in order: passed on
    /// to the `checkpoint create` that records the statements.
    pub globals: Vec<OsString>,
}

/// The global options `import` passes on.
pub const GLOBAL_OPTIONS: [&str; 3] = ["--data-dir", "--socket", "--token-file"];

/// `memprove [GLOBAL OPTIONS] import ...`: the global options before
/// `import` and the arguments after it; `None` for another command.
#[must_use]
pub fn requested(args: &[OsString]) -> Option<(Vec<OsString>, &[OsString])> {
    let mut globals = Vec::new();
    let mut rest = args;
    while let [name, value, tail @ ..] = rest {
        if !GLOBAL_OPTIONS.iter().any(|global| name == global) {
            break;
        }
        globals.extend([name.clone(), value.clone()]);
        rest = tail;
    }
    let (first, rest) = rest.split_first()?;
    (first == "import").then_some((globals, rest))
}

/// Parses the arguments after `import`.
///
/// # Errors
///
/// An argument it does not take, an option without its value, or an option
/// given twice that takes one value.
pub fn parse_args(args: &[OsString]) -> Result<ImportSpec, String> {
    let mut spec = ImportSpec::default();
    let mut rest = args.iter();
    while let Some(argument) = rest.next() {
        let text = argument.to_string_lossy();
        let mut value = |name: &str| {
            rest.next()
                .filter(|value| !value.is_empty())
                .cloned()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        match text.as_ref() {
            "--file" => spec.files.push(PathBuf::from(value("--file")?)),
            "--select" | "--next" => {
                let name = if text == "--select" {
                    "--select"
                } else {
                    "--next"
                };
                let given = value(name)?.to_string_lossy().into_owned();
                let slot = if name == "--select" {
                    &mut spec.select
                } else {
                    &mut spec.next
                };
                if slot.replace(given).is_some() {
                    return Err(format!("{name} is given more than once"));
                }
            }
            "--dry-run" => spec.dry_run = true,
            global if GLOBAL_OPTIONS.contains(&global) => {
                let given = value(global)?;
                spec.globals.extend([argument.clone(), given]);
            }
            other => return Err(format!("import does not take {other}")),
        }
    }
    if spec.select.is_none() && (spec.next.is_some() || spec.dry_run) {
        return Err(
            "--next and --dry-run go with --select; without it import only lists the statements"
                .to_owned(),
        );
    }
    Ok(spec)
}

/// The name of Claude Code's project directory for `root`: every character
/// that is not an ASCII letter or digit becomes `-`.
#[must_use]
pub fn claude_project_name(root: &Path) -> String {
    root.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Claude Code's configuration directory: `CLAUDE_CONFIG_DIR`, else
/// `~/.claude`.
#[must_use]
pub fn claude_config_dir(config_dir: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    config_dir
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            home.filter(|home| !home.is_empty())
                .map(|home| PathBuf::from(home).join(".claude"))
        })
}

/// The default sources of the Workspace `root`: [`DEFAULT_FILES`], Cursor's
/// rules, then the auto-memory files of the project `root` in
/// `claude_dir` (`MEMORY.md` first, then the rest in name order).
#[must_use]
pub fn default_sources(root: &Path, claude_dir: Option<&Path>) -> Vec<Source> {
    let mut sources: Vec<Source> = DEFAULT_FILES
        .iter()
        .map(|name| Source {
            name: (*name).to_owned(),
            path: root.join(name),
        })
        .filter(|source| source.path.is_file())
        .collect();
    for name in files_in(&root.join(CURSOR_RULES_DIR), &["mdc", "md"]) {
        if !OWN_RULES.contains(&name.as_str()) {
            sources.push(Source {
                path: root.join(CURSOR_RULES_DIR).join(&name),
                name: format!("{CURSOR_RULES_DIR}/{name}"),
            });
        }
    }
    if let Some(claude_dir) = claude_dir {
        let memory = claude_dir
            .join("projects")
            .join(claude_project_name(root))
            .join("memory");
        let mut names = files_in(&memory, &["md"]);
        names.sort_by_key(|name| name != "MEMORY.md");
        for name in names {
            sources.push(Source {
                path: memory.join(&name),
                name: format!("{AUTO_MEMORY}/{name}"),
            });
        }
    }
    sources
}

/// The sources `--file` names: each is called by its path relative to
/// `root` when it is inside it, else as given.
#[must_use]
pub fn given_sources(files: &[PathBuf], cwd: &Path, root: &Path) -> Vec<Source> {
    files
        .iter()
        .map(|file| {
            let path = cwd.join(file);
            let name = fs::canonicalize(&path)
                .ok()
                .and_then(|full| {
                    full.strip_prefix(root)
                        .ok()
                        .map(|inside| inside.to_string_lossy().into_owned())
                })
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| file.to_string_lossy().into_owned());
            Source { name, path }
        })
        .collect()
}

/// The names of the files in `dir` with one of `extensions`, in name order.
fn files_in(dir: &Path, extensions: &[&str]) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| {
            Path::new(name)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extensions.contains(&extension))
        })
        .collect();
    names.sort();
    names
}

/// Reads every source and collects its statements.
#[must_use]
pub fn collect(sources: &[Source]) -> Found {
    let mut found = Found::default();
    for source in sources {
        let markdown = match fs::read_to_string(&source.path) {
            Ok(markdown) => markdown,
            Err(error) => {
                found
                    .unreadable
                    .push((source.name.clone(), error.to_string()));
                continue;
            }
        };
        found.read.push(source.name.clone());
        for (line, text) in statements(&markdown) {
            let candidate = Candidate {
                source: source.name.clone(),
                line,
                text,
            };
            let length = candidate.recorded().chars().count();
            let reason = if memprove_domain::holds_token_shape(&candidate.text) {
                Some("it holds a string in the format of a memprove token".to_owned())
            } else if length > CLAIM_TEXT_MAX_CHARS {
                Some(format!(
                    "with its mark it is {length} characters, more than the \
                     {CLAIM_TEXT_MAX_CHARS} a statement may have; split it"
                ))
            } else {
                None
            };
            match reason {
                Some(reason) => found.passed.push(Passed {
                    source: candidate.source,
                    line,
                    reason,
                }),
                None if found
                    .candidates
                    .iter()
                    .any(|other| other.text == candidate.text) => {}
                None => found.candidates.push(candidate),
            }
        }
    }
    found
}

/// The statements of a Markdown text, each with the line it starts on:
/// one per list item (with its continuation lines) and one per paragraph.
/// Passed over: YAML front matter, headings, fenced code, HTML comments
/// and tags, tables, rules, Claude Code's `@path` imports, memprove's own
/// note, and anything without a letter or digit.
#[must_use]
pub fn statements(markdown: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut current: Option<(usize, String)> = None;
    let flush = |current: &mut Option<(usize, String)>, out: &mut Vec<(usize, String)>| {
        if let Some((line, text)) = current.take() {
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            if text.chars().any(char::is_alphanumeric) && !is_only_a_link(&text) {
                out.push((line, text));
            }
        }
    };
    let mut front_matter = false;
    let mut fence: Option<(char, usize)> = None;
    let mut comment = false;
    let mut note = false;
    let mut quote = false;
    for (index, raw) in markdown.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();
        if index == 0 && line == "---" {
            front_matter = true;
            continue;
        }
        if front_matter {
            front_matter = line != "---" && line != "...";
            continue;
        }
        if note {
            note = !(line.contains(NOTE_END) || line.contains(PREVIOUS_NOTE_END));
            continue;
        }
        if let Some((mark, length)) = fence {
            // Closed by a run of the same mark, at least as long, alone.
            if line.chars().count() >= length && line.chars().all(|c| c == mark) {
                fence = None;
            }
            continue;
        }
        if comment {
            comment = !line.contains("-->");
            continue;
        }
        if line.starts_with(NOTE_BEGIN) || line.starts_with(PREVIOUS_NOTE_BEGIN) {
            flush(&mut current, &mut out);
            note = !(line.contains(NOTE_END) || line.contains(PREVIOUS_NOTE_END));
            continue;
        }
        if line.starts_with("```") || line.starts_with("~~~") {
            flush(&mut current, &mut out);
            let mark = line.chars().next().unwrap_or('`');
            fence = Some((mark, line.chars().take_while(|c| *c == mark).count()));
            continue;
        }
        if line.starts_with("<!--") {
            flush(&mut current, &mut out);
            comment = !line.contains("-->");
            continue;
        }
        if line.is_empty()
            || is_heading(line)
            || line.starts_with('|')
            || (line.starts_with('<') && line.ends_with('>'))
            || (line.starts_with('@') && !line.contains(char::is_whitespace))
        {
            flush(&mut current, &mut out);
            continue;
        }
        if is_rule(line) {
            // A setext underline makes the paragraph above it a heading.
            if current.is_some() && (line.starts_with('=') || line.starts_with('-')) {
                current = None;
            }
            flush(&mut current, &mut out);
            continue;
        }
        // A block quote begins a statement of its own, and so does its end.
        let in_quote = line.starts_with('>');
        if in_quote != quote {
            flush(&mut current, &mut out);
            quote = in_quote;
        }
        let quoted = line.trim_start_matches(|c: char| c == '>' || c.is_whitespace());
        if let Some(item) = list_item(quoted) {
            flush(&mut current, &mut out);
            current = Some((number, item.to_owned()));
        } else if let Some((_, text)) = &mut current {
            text.push(' ');
            text.push_str(quoted);
        } else {
            current = Some((number, quoted.to_owned()));
        }
    }
    flush(&mut current, &mut out);
    out
}

/// `# Heading` through `###### Heading`.
fn is_heading(line: &str) -> bool {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    (1..=6).contains(&hashes)
        && line[hashes..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
}

/// A thematic break or a setext underline: three or more of one of `-`,
/// `=`, `*`, `_`, and spaces.
fn is_rule(line: &str) -> bool {
    let Some(mark) = line.chars().next() else {
        return false;
    };
    matches!(mark, '-' | '=' | '*' | '_')
        && line.chars().filter(|c| *c == mark).count() >= 3
        && line.chars().all(|c| c == mark || c == ' ')
}

/// The text of a list item, without its marker and task box: `- `, `* `,
/// `+ `, `1. `, or `1) `.
fn list_item(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| line.strip_prefix("+ "))
        .or_else(|| {
            let digits = line.chars().take_while(char::is_ascii_digit).count();
            (1..=9)
                .contains(&digits)
                .then(|| &line[digits..])
                .and_then(|rest| rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") ")))
        })?;
    let rest = rest.trim_start();
    Some(
        ["[ ] ", "[x] ", "[X] "]
            .iter()
            .find_map(|task| rest.strip_prefix(task))
            .unwrap_or(rest),
    )
}

/// `[text](target)` and nothing else.
fn is_only_a_link(text: &str) -> bool {
    text.starts_with('[')
        && text.ends_with(')')
        && text
            .find("](")
            .is_some_and(|middle| !text[middle + 2..].contains(char::is_whitespace))
}

/// `--select`: `all`, or numbers and ranges such as `1,3,5-7`, each from 1
/// to `count`; the indexes (from 0) in ascending order, each once.
///
/// # Errors
///
/// A number outside 1 to `count`, a range that runs backwards, or anything
/// else.
pub fn selection(value: &str, count: usize) -> Result<Vec<usize>, String> {
    if value == "all" {
        return Ok((0..count).collect());
    }
    let number = |word: &str| {
        word.trim()
            .parse::<usize>()
            .ok()
            .filter(|number| (1..=count).contains(number))
            .ok_or_else(|| {
                format!(
                    "--select takes `all` or numbers from 1 to {count} (as `import` lists \
                     them), such as 1,3,5-7; {word:?} is not one"
                )
            })
    };
    let mut indexes = Vec::new();
    for part in value.split(',') {
        let (first, last) = part.split_once('-').unwrap_or((part, part));
        let (first, last) = (number(first)?, number(last)?);
        if last < first {
            return Err(format!("--select: the range {part:?} runs backwards"));
        }
        indexes.extend(first - 1..last);
    }
    indexes.sort_unstable();
    indexes.dedup();
    Ok(indexes)
}

/// The listing's line for statement `number`: at most `width` characters of
/// its text.
#[must_use]
pub fn listing_line(number: usize, candidate: &Candidate, width: usize) -> String {
    let mut text: String = candidate.text.chars().take(width).collect();
    if candidate.text.chars().count() > width {
        text.push('…');
    }
    format!(
        "{number:>3}  {}:{}  {text}",
        candidate.source, candidate.line
    )
}

/// `1 statement`, `2 statements`: `count` and `noun`, plural but for one.
#[must_use]
pub fn count(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u24_statements_are_bullets_and_paragraphs() {
        let markdown = "---\ndescription: rules\nglobs: *.rs\n---\n\
            # Project\n\
            \n\
            This is a Rust workspace.\nIt has five crates.\n\
            \n\
            ## Testing\n\
            - Run `cargo test --workspace`\n  before every commit.\n\
            * [ ] never push to main\n\
            1. Use rustfmt.\n\
            2) Keep clippy clean.\n\
            > Quoted advice.\n\
            \n\
            ```sh\ncargo build\n- not a bullet\n```\n\
            <!-- a comment\n- hidden\n-->\n\
            | a | b |\n|---|---|\n\
            @docs/more.md\n\
            ---\n\
            <!-- memprove:begin -->\nmemprove's own note\n<!-- memprove:end -->\n\
            Setext heading\n==============\n\
            - [Link only](other.md)\n\
            - [Debugging](debugging.md): read before a bisect\n\
            ***\n\
            - --- !\n";
        assert_eq!(
            statements(markdown),
            [
                (
                    7,
                    "This is a Rust workspace. It has five crates.".to_owned()
                ),
                (
                    11,
                    "Run `cargo test --workspace` before every commit.".to_owned()
                ),
                (13, "never push to main".to_owned()),
                (14, "Use rustfmt.".to_owned()),
                (15, "Keep clippy clean.".to_owned()),
                (16, "Quoted advice.".to_owned()),
                (
                    35,
                    "[Debugging](debugging.md): read before a bisect".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn u24_a_rule_without_front_matter_is_not_front_matter_later() {
        assert_eq!(
            statements("Intro.\n\n---\n\nAfter the rule."),
            [(1, "Intro.".to_owned()), (5, "After the rule.".to_owned())]
        );
        assert_eq!(statements("````\n```\nx\n````\ny"), [(5, "y".to_owned())]);
    }

    #[test]
    fn u24_selection_takes_all_numbers_and_ranges() {
        assert_eq!(selection("all", 3).unwrap(), [0, 1, 2]);
        assert_eq!(selection("3,1-2,2", 4).unwrap(), [0, 1, 2]);
        assert!(selection("0", 3).is_err());
        assert!(selection("4", 3).is_err());
        assert!(selection("3-1", 3).is_err());
        assert!(selection("a", 3).is_err());
        assert!(selection("", 3).is_err());
    }

    #[test]
    fn u24_an_imported_statement_is_in_force_from_any_line() {
        let candidate = Candidate {
            source: "CLAUDE.md".to_owned(),
            line: 3,
            text: "Use rustfmt.".to_owned(),
        };
        let recorded = candidate.recorded();
        assert_eq!(
            recorded,
            "Use rustfmt. (imported from CLAUDE.md:3; not verified)"
        );
        assert!(candidate.in_force(&[recorded.as_str()]));
        assert!(candidate.in_force(&["Use rustfmt. (imported from AGENTS.md:9; not verified)"]));
        assert!(!candidate.in_force(&["Use rustfmt."]));
        assert!(!candidate.in_force(&["Use rustfmt. Always."]));
    }

    #[test]
    fn u24_claude_code_names_its_project_directory_by_the_root() {
        assert_eq!(
            claude_project_name(Path::new("/Users/a/my.repo_x")),
            "-Users-a-my-repo-x"
        );
        assert_eq!(
            claude_config_dir(None, Some("/home/a".into())),
            Some(PathBuf::from("/home/a/.claude"))
        );
        assert_eq!(
            claude_config_dir(Some("/c".into()), Some("/home/a".into())),
            Some(PathBuf::from("/c"))
        );
    }

    #[test]
    fn u24_the_default_sources_and_what_they_hold() {
        let root = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(root.path()).unwrap();
        let claude = tempfile::tempdir().unwrap();
        fs::write(root.join("CLAUDE.md"), "- Run the tests.\n- Use rustfmt.\n").unwrap();
        fs::write(
            root.join("AGENTS.md"),
            "Use rustfmt.\n\nAsk before deleting.\n",
        )
        .unwrap();
        fs::create_dir_all(root.join(".cursor/rules")).unwrap();
        fs::write(
            root.join(".cursor/rules/style.mdc"),
            "---\nglobs: *\n---\nNo unwrap.\n",
        )
        .unwrap();
        fs::write(root.join(".cursor/rules/memprove.mdc"), "Not this.\n").unwrap();
        let memory = claude
            .path()
            .join("projects")
            .join(claude_project_name(&root))
            .join("memory");
        fs::create_dir_all(&memory).unwrap();
        fs::write(memory.join("debugging.md"), "Bisect with git.\n").unwrap();
        fs::write(
            memory.join("MEMORY.md"),
            "- [Debugging](debugging.md)\n- CI runs on Linux.\n",
        )
        .unwrap();
        let token = format!("{}x", "aB3".repeat(14));
        fs::write(root.join("GEMINI.md"), format!("Key {token}\n")).unwrap();
        let sources = default_sources(&root, Some(claude.path()));
        let names: Vec<&str> = sources.iter().map(|source| source.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "CLAUDE.md",
                "AGENTS.md",
                "GEMINI.md",
                ".cursor/rules/style.mdc",
                "auto-memory/MEMORY.md",
                "auto-memory/debugging.md"
            ]
        );
        let found = collect(&sources);
        let texts: Vec<(&str, usize, &str)> = found
            .candidates
            .iter()
            .map(|c| (c.source.as_str(), c.line, c.text.as_str()))
            .collect();
        assert_eq!(
            texts,
            [
                ("CLAUDE.md", 1, "Run the tests."),
                ("CLAUDE.md", 2, "Use rustfmt."),
                ("AGENTS.md", 3, "Ask before deleting."),
                (".cursor/rules/style.mdc", 4, "No unwrap."),
                ("auto-memory/MEMORY.md", 2, "CI runs on Linux."),
                ("auto-memory/debugging.md", 1, "Bisect with git."),
            ]
        );
        assert_eq!(found.passed.len(), 1, "{:?}", found.passed);
        assert_eq!(found.passed[0].source, "GEMINI.md");
        assert!(found.passed[0].reason.contains("token"));
    }

    #[test]
    fn u24_import_arguments() {
        let args = |words: &[&str]| -> Vec<OsString> { words.iter().map(OsString::from).collect() };
        assert_eq!(parse_args(&[]).unwrap(), ImportSpec::default());
        let spec = parse_args(&args(&[
            "--file",
            "a.md",
            "--select",
            "1-2",
            "--next",
            "n",
            "--file",
            "b.md",
            "--dry-run",
        ]))
        .unwrap();
        assert_eq!(spec.files, [PathBuf::from("a.md"), PathBuf::from("b.md")]);
        assert_eq!(spec.select.as_deref(), Some("1-2"));
        assert_eq!(spec.next.as_deref(), Some("n"));
        assert!(spec.dry_run);
        assert!(parse_args(&args(&["--select", "1", "--select", "2"])).is_err());
        assert!(parse_args(&args(&["--file"])).is_err());
        assert!(parse_args(&args(&["--next", "n"])).is_err());
        assert!(parse_args(&args(&["--dry-run"])).is_err());
        assert!(parse_args(&args(&["extra"])).is_err());
        let spec = parse_args(&args(&["--socket", "/s", "--select", "all"])).unwrap();
        assert_eq!(spec.globals, args(&["--socket", "/s"]));
        let words = args(&["--token-file", "/t", "import", "--select", "all"]);
        let (globals, rest) = requested(&words).unwrap();
        assert_eq!(globals, args(&["--token-file", "/t"]));
        assert_eq!(rest, &words[3..]);
        assert!(requested(&args(&["checkpoint", "create"])).is_none());
        assert!(requested(&args(&["--socket"])).is_none());
    }
}
