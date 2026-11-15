//! Reads the text of a shell command as a POSIX shell would split it,
//! without running or expanding anything: its simple commands (each the
//! words after quote removal), the files each redirects from and to, and the
//! text a heredoc or here-string feeds it. Command substitutions (`$(…)`,
//! `` `…` ``, `<(…)`, `>(…)`) are read as commands of their own.
//!
//! Ported from the shell reader of the takeover evaluation's denial classes
//! (U12 T1) and extended with redirection targets, heredoc bodies and
//! substitutions.

/// The deepest substitution or nested shell the reader follows.
pub const MAX_DEPTH: usize = 8;

/// One simple command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Command {
    /// Its words after quote removal; a substitution stays as its text.
    pub words: Vec<String>,
    /// The files it redirects its input from (`<`, `<>`).
    pub reads: Vec<String>,
    /// The files it redirects its output to (`>`, `>>`, `>|`, `&>`, `<>`,
    /// `>&file`).
    pub writes: Vec<String>,
    /// The text a heredoc or here-string gives it on standard input.
    pub input: Option<String>,
}

impl Command {
    fn is_empty(&self) -> bool {
        self.words.is_empty()
            && self.reads.is_empty()
            && self.writes.is_empty()
            && self.input.is_none()
    }
}

/// What the text of a command says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Script {
    /// Its simple commands, a substitution's before the command it is in.
    pub commands: Vec<Command>,
    /// Why part of it could not be read (an unclosed quote, …); what was
    /// read before is kept.
    pub problem: Option<&'static str>,
}

/// The redirection the next word completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Read,
    Write,
    ReadWrite,
    /// `>&` or `<&`: digits or `-` copy a descriptor; anything else is a file
    /// written (`>&`) or read (`<&`).
    Descriptor {
        write: bool,
    },
    /// The delimiter of a heredoc (`<<-` when `true`).
    Heredoc(bool),
    HereString,
}

/// Reads `text`.
#[must_use]
pub fn read(text: &str) -> Script {
    read_at(text, 0)
}

/// Reads `text` as a script nested `depth` levels deep.
#[must_use]
pub fn read_at(text: &str, depth: usize) -> Script {
    let mut reader = Reader {
        chars: text.chars().collect(),
        at: 0,
        depth,
        script: Script::default(),
        command: Command::default(),
        word: None,
        target: None,
        heredocs: Vec::new(),
        pending: Vec::new(),
    };
    if depth > MAX_DEPTH {
        reader.script.problem = Some("commands nested too deeply");
        return reader.script;
    }
    while reader.at < reader.chars.len() {
        let character = reader.chars[reader.at];
        reader.at += 1;
        reader.step(character);
    }
    reader.end_command();
    if !reader.heredocs.is_empty() {
        // A heredoc whose body never came: nothing more to read.
        reader.heredocs.clear();
    }
    reader.script
}

struct Reader {
    chars: Vec<char>,
    at: usize,
    depth: usize,
    script: Script,
    command: Command,
    word: Option<String>,
    target: Option<Target>,
    /// Heredocs of the current command: delimiter and whether tabs are
    /// stripped.
    pending: Vec<(String, bool)>,
    /// Heredocs of finished commands of this line, with the index of their
    /// command (none when it was empty).
    heredocs: Vec<(String, bool, Option<usize>)>,
}

impl Reader {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.at + offset).copied()
    }

    fn problem(&mut self, why: &'static str) {
        self.script.problem.get_or_insert(why);
    }

    fn push(&mut self, character: char) {
        self.word.get_or_insert_with(String::new).push(character);
    }

    fn push_str(&mut self, text: &str) {
        self.word.get_or_insert_with(String::new).push_str(text);
    }

    fn end_word(&mut self) {
        let Some(word) = self.word.take() else {
            return;
        };
        match self.target.take() {
            None => self.command.words.push(word),
            Some(Target::Read) => self.command.reads.push(word),
            Some(Target::Write) => self.command.writes.push(word),
            Some(Target::ReadWrite) => {
                self.command.reads.push(word.clone());
                self.command.writes.push(word);
            }
            Some(Target::Descriptor { write }) => {
                let copies =
                    word == "-" || (!word.is_empty() && word.bytes().all(|b| b.is_ascii_digit()));
                if !copies {
                    if write {
                        self.command.writes.push(word);
                    } else {
                        self.command.reads.push(word);
                    }
                }
            }
            Some(Target::Heredoc(strip_tabs)) => self.pending.push((word, strip_tabs)),
            Some(Target::HereString) => {
                let input = self.command.input.get_or_insert_with(String::new);
                input.push_str(&word);
                input.push('\n');
            }
        }
    }

    fn end_command(&mut self) {
        self.end_word();
        self.target = None;
        let command = std::mem::take(&mut self.command);
        let index = if command.is_empty() {
            None
        } else {
            self.script.commands.push(command);
            Some(self.script.commands.len() - 1)
        };
        for (delimiter, strip_tabs) in std::mem::take(&mut self.pending) {
            self.heredocs.push((delimiter, strip_tabs, index));
        }
    }

    /// After a newline: the bodies of the heredocs of that line.
    fn heredoc_bodies(&mut self) {
        for (delimiter, strip_tabs, index) in std::mem::take(&mut self.heredocs) {
            let mut body = String::new();
            loop {
                if self.at >= self.chars.len() {
                    break;
                }
                let mut line = String::new();
                while let Some(character) = self.peek() {
                    self.at += 1;
                    if character == '\n' {
                        break;
                    }
                    line.push(character);
                }
                let line = if strip_tabs {
                    line.trim_start_matches('\t').to_owned()
                } else {
                    line
                };
                if line == delimiter {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            if let Some(index) = index {
                let input = self.script.commands[index]
                    .input
                    .get_or_insert_with(String::new);
                input.push_str(&body);
            }
        }
    }

    /// The text up to the `close` that balances an `open` already read,
    /// quotes respected; `None` when it never closes.
    fn balanced(&mut self, open: char, close: char) -> Option<String> {
        let mut text = String::new();
        let mut level = 1usize;
        while let Some(character) = self.peek() {
            self.at += 1;
            match character {
                '\\' => {
                    text.push(character);
                    if let Some(next) = self.peek() {
                        self.at += 1;
                        text.push(next);
                    }
                }
                '\'' => {
                    text.push(character);
                    while let Some(next) = self.peek() {
                        self.at += 1;
                        text.push(next);
                        if next == '\'' {
                            break;
                        }
                    }
                }
                '"' => {
                    text.push(character);
                    while let Some(next) = self.peek() {
                        self.at += 1;
                        text.push(next);
                        if next == '\\' {
                            if let Some(escaped) = self.peek() {
                                self.at += 1;
                                text.push(escaped);
                            }
                        } else if next == '"' {
                            break;
                        }
                    }
                }
                _ if character == close => {
                    level -= 1;
                    if level == 0 {
                        return Some(text);
                    }
                    text.push(character);
                }
                _ if character == open => {
                    level += 1;
                    text.push(character);
                }
                _ => text.push(character),
            }
        }
        None
    }

    /// The text up to the next unescaped backtick; `None` when there is
    /// none.
    fn backquoted(&mut self) -> Option<String> {
        let mut text = String::new();
        while let Some(character) = self.peek() {
            self.at += 1;
            match character {
                '`' => return Some(text),
                '\\' => {
                    if let Some(next) = self.peek() {
                        self.at += 1;
                        if !matches!(next, '`' | '\\' | '$') {
                            text.push('\\');
                        }
                        text.push(next);
                    }
                }
                _ => text.push(character),
            }
        }
        None
    }

    /// The commands of a substitution, read before the command it is in.
    fn substituted(&mut self, inner: &str) {
        let nested = read_at(inner, self.depth + 1);
        if let Some(problem) = nested.problem {
            self.problem(problem);
        }
        self.script.commands.extend(nested.commands);
    }

    /// `$` was read: a substitution, an arithmetic expansion, a parameter
    /// expansion, or a plain `$`. Returns the text the word keeps.
    fn dollar(&mut self) -> String {
        match (self.peek(), self.peek_at(1)) {
            (Some('('), Some('(')) => {
                self.at += 2;
                if let Some(inner) = self.balanced('(', ')') {
                    // `$((…))`: the closing `)` of the pair.
                    if self.peek() == Some(')') {
                        self.at += 1;
                    }
                    format!("$(({inner}))")
                } else {
                    self.problem("an unclosed arithmetic expansion");
                    String::new()
                }
            }
            (Some('('), _) => {
                self.at += 1;
                if let Some(inner) = self.balanced('(', ')') {
                    self.substituted(&inner);
                    format!("$({inner})")
                } else {
                    self.problem("an unclosed command substitution");
                    String::new()
                }
            }
            (Some('{'), _) => {
                self.at += 1;
                if let Some(inner) = self.balanced('{', '}') {
                    format!("${{{inner}}}")
                } else {
                    self.problem("an unclosed parameter expansion");
                    String::new()
                }
            }
            _ => "$".to_owned(),
        }
    }

    fn single_quoted(&mut self) {
        self.word.get_or_insert_with(String::new);
        while let Some(character) = self.peek() {
            self.at += 1;
            if character == '\'' {
                return;
            }
            self.push(character);
        }
        self.problem("an unclosed quote");
    }

    fn double_quoted(&mut self) {
        self.word.get_or_insert_with(String::new);
        while let Some(character) = self.peek() {
            self.at += 1;
            match character {
                '"' => return,
                '\\' => match self.peek() {
                    Some('\n') => self.at += 1,
                    Some(next @ ('"' | '\\' | '$' | '`')) => {
                        self.at += 1;
                        self.push(next);
                    }
                    Some(next) => {
                        self.at += 1;
                        self.push('\\');
                        self.push(next);
                    }
                    None => self.push('\\'),
                },
                '`' => match self.backquoted() {
                    Some(inner) => {
                        self.substituted(&inner);
                        self.push_str(&format!("$({inner})"));
                    }
                    None => self.problem("an unclosed command substitution"),
                },
                '$' => {
                    let text = self.dollar();
                    self.push_str(&text);
                }
                _ => self.push(character),
            }
        }
        self.problem("an unclosed quote");
    }

    /// A redirection operator that starts with `first` (`>` or `<`).
    fn redirection(&mut self, first: char) {
        // A word of digits just before the operator is its descriptor.
        if self
            .word
            .as_deref()
            .is_some_and(|word| !word.is_empty() && word.bytes().all(|b| b.is_ascii_digit()))
        {
            self.word = None;
        }
        self.end_word();
        let next = self.peek();
        let target = match (first, next) {
            ('<', Some('<')) => {
                self.at += 1;
                match self.peek() {
                    Some('<') => {
                        self.at += 1;
                        Target::HereString
                    }
                    Some('-') => {
                        self.at += 1;
                        Target::Heredoc(true)
                    }
                    _ => Target::Heredoc(false),
                }
            }
            (_, Some('&')) => {
                self.at += 1;
                Target::Descriptor {
                    write: first == '>',
                }
            }
            ('>', Some('>' | '|')) => {
                self.at += 1;
                Target::Write
            }
            ('<', Some('>')) => {
                self.at += 1;
                Target::ReadWrite
            }
            ('>', _) => Target::Write,
            _ => Target::Read,
        };
        self.target = Some(target);
    }

    /// `<(…)` or `>(…)`: a process substitution.
    fn process_substitution(&mut self, first: char) {
        self.at += 1;
        if let Some(inner) = self.balanced('(', ')') {
            self.substituted(&inner);
            self.push_str(&format!("{first}({inner})"));
        } else {
            self.problem("an unclosed process substitution");
        }
    }

    fn step(&mut self, character: char) {
        match character {
            '\'' => self.single_quoted(),
            '"' => self.double_quoted(),
            '\\' => match self.peek() {
                Some('\n') => self.at += 1,
                None => {}
                Some(next) => {
                    self.at += 1;
                    self.push(next);
                }
            },
            '#' if self.word.is_none() => {
                while self.peek().is_some_and(|next| next != '\n') {
                    self.at += 1;
                }
            }
            ' ' | '\t' | '\r' => self.end_word(),
            '\n' => {
                self.end_command();
                self.heredoc_bodies();
            }
            '`' => match self.backquoted() {
                Some(inner) => {
                    self.substituted(&inner);
                    self.push_str(&format!("$({inner})"));
                }
                None => self.problem("an unclosed command substitution"),
            },
            '$' => {
                let text = self.dollar();
                self.push_str(&text);
            }
            ';' | '(' | ')' => self.end_command(),
            '|' => {
                if matches!(self.peek(), Some('|' | '&')) {
                    self.at += 1;
                }
                self.end_command();
            }
            '&' => match self.peek() {
                Some('&') => {
                    self.at += 1;
                    self.end_command();
                }
                Some('>') => {
                    self.at += 1;
                    self.end_word();
                    if self.peek() == Some('>') {
                        self.at += 1;
                    }
                    self.target = Some(Target::Write);
                }
                _ => self.end_command(),
            },
            '<' | '>' if self.peek() == Some('(') => self.process_substitution(character),
            '>' | '<' => self.redirection(character),
            _ => self.push(character),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(script: &Script) -> Vec<Vec<&str>> {
        script
            .commands
            .iter()
            .map(|command| command.words.iter().map(String::as_str).collect())
            .collect()
    }

    #[test]
    fn splits_commands_at_separators_and_removes_quotes() {
        let script = read("cd 'my dir' && git push \"--force\"; ls|wc -l & echo a\\ b || x\ny");
        assert_eq!(
            words(&script),
            vec![
                vec!["cd", "my dir"],
                vec!["git", "push", "--force"],
                vec!["ls"],
                vec!["wc", "-l"],
                vec!["echo", "a b"],
                vec!["x"],
                vec!["y"],
            ]
        );
        assert_eq!(script.problem, None);
    }

    #[test]
    fn reads_substitutions_as_commands_before_their_command() {
        let script = read("echo \"$(git push -f)\" `rm x` $(( 1 + 2 )) ${HOME} done");
        assert_eq!(
            words(&script),
            vec![
                vec!["git", "push", "-f"],
                vec!["rm", "x"],
                vec![
                    "echo",
                    "$(git push -f)",
                    "$(rm x)",
                    "$(( 1 + 2 ))",
                    "${HOME}",
                    "done"
                ],
            ]
        );
    }

    #[test]
    fn keeps_redirection_targets() {
        let script = read("cat < in.txt > out.txt 2>&1 2>>err.log &>all.log >&2 <>both");
        let command = &script.commands[0];
        assert_eq!(command.words, vec!["cat"]);
        assert_eq!(command.reads, vec!["in.txt", "both"]);
        assert_eq!(
            command.writes,
            vec!["out.txt", "err.log", "all.log", "both"]
        );
    }

    #[test]
    fn keeps_heredoc_bodies_as_input_not_commands() {
        let script =
            read("cat > f.txt <<'EOF'\ngit push --force\nEOF\nbash <<-X\n\trm -rf y\n\tX\nls");
        assert_eq!(words(&script), vec![vec!["cat"], vec!["bash"], vec!["ls"]]);
        assert_eq!(script.commands[0].writes, vec!["f.txt"]);
        assert_eq!(
            script.commands[0].input.as_deref(),
            Some("git push --force\n")
        );
        assert_eq!(script.commands[1].input.as_deref(), Some("rm -rf y\n"));
        let here = read("bash <<< 'git push -f'");
        assert_eq!(here.commands[0].input.as_deref(), Some("git push -f\n"));
    }

    #[test]
    fn process_substitutions_are_commands() {
        let script = read("diff <(cat .env) >(tee x)");
        assert_eq!(
            words(&script),
            vec![
                vec!["cat", ".env"],
                vec!["tee", "x"],
                vec!["diff", "<(cat .env)", ">(tee x)"]
            ]
        );
    }

    #[test]
    fn says_what_it_could_not_read() {
        assert_eq!(read("echo 'open").problem, Some("an unclosed quote"));
        assert_eq!(read("echo \"open").problem, Some("an unclosed quote"));
        assert_eq!(
            read("echo $(open").problem,
            Some("an unclosed command substitution")
        );
        assert_eq!(
            read_at("x", MAX_DEPTH + 1).problem,
            Some("commands nested too deeply")
        );
    }

    #[test]
    fn comments_and_line_continuations() {
        let script = read("git \\\n push # --force\n# rm -rf /");
        assert_eq!(words(&script), vec![vec!["git", "push"]]);
    }
}
