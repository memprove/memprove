//! Small readers over [`memprove_protocol::strict_json`] values, shared by
//! the transcript readers.

use std::{
    fs,
    io::Read as _,
    path::Path,
    process::{Command, Stdio},
};

use memprove_protocol::strict_json::JsonValue;

/// The most bytes of one transcript the report reads.
pub const MAX_TRANSCRIPT_BYTES: u64 = 1 << 30;

/// The string at `name` of `value`.
#[must_use]
pub fn str_at<'a>(value: &'a JsonValue, name: &str) -> Option<&'a str> {
    value.get(name)?.as_str()
}

/// The whole number at `name` of `value`, 0 when it is missing, negative or
/// not a whole number.
#[must_use]
pub fn count_at(value: &JsonValue, name: &str) -> u64 {
    value
        .get(name)
        .and_then(JsonValue::as_i64)
        .and_then(|number| u64::try_from(number).ok())
        .unwrap_or(0)
}

/// The text of a message or tool result's content: a string, or the
/// `text` of each item of an array (joined by newlines).
#[must_use]
pub fn text_of(content: &JsonValue) -> String {
    match content {
        JsonValue::String(text) => text.clone(),
        JsonValue::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                JsonValue::String(text) => Some(text.as_str()),
                item => str_at(item, "text"),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Whether a tool call reads memprove: its name names memprove (an MCP
/// tool of the `memprove` server) or its command runs `memprove` (the
/// program of a simple command, not an argument such as a directory).
#[must_use]
pub fn reads_memprove(name: &str, command: &str) -> bool {
    name.contains("memprove") || runs_memprove(command)
}

/// The words that may come before a simple command's program.
const PREFIXES: [&str; 8] = [
    "sudo", "env", "exec", "time", "command", "nohup", "then", "do",
];

/// Whether a shell command line runs `memprove` (or `…/memprove`) as the
/// program of one of its simple commands.
#[must_use]
pub fn runs_memprove(command: &str) -> bool {
    command
        .split(['\n', ';', '&', '|', '(', ')', '`', '{', '}'])
        .any(|simple| {
            simple
                .split_whitespace()
                .map(|word| word.trim_matches(['"', '\'', '$']))
                .find(|word| !word.is_empty() && !PREFIXES.contains(word) && !assigns(word))
                .is_some_and(|program| program == "memprove" || program.ends_with("/memprove"))
        })
}

/// Whether `word` is a variable assignment (`NAME=value`) before a program.
fn assigns(word: &str) -> bool {
    word.split_once('=')
        .is_some_and(|(name, _)| !name.is_empty() && !name.contains('/'))
}

/// The command line of a tool call's input or arguments: its `command` or
/// `cmd` string; for an argument list, the script of a shell's `-c` flag,
/// or the words joined.
#[must_use]
pub fn command_of(input: &JsonValue) -> String {
    let value = input.get("command").or_else(|| input.get("cmd"));
    match value {
        Some(JsonValue::String(line)) => line.clone(),
        Some(JsonValue::Array(words)) => {
            let words: Vec<&str> = words.iter().filter_map(JsonValue::as_str).collect();
            match words.as_slice() {
                [_, flag, script, ..] if flag.starts_with('-') && flag.contains('c') => {
                    (*script).to_owned()
                }
                _ => words.join(" "),
            }
        }
        _ => String::new(),
    }
}

/// The text of the transcript at `path`; a `.zst` file is read with
/// `zstd -dc`.
///
/// # Errors
///
/// One sentence saying why the file cannot be read.
pub fn transcript_text(path: &Path) -> Result<String, String> {
    let shown = path.display();
    if path.extension().is_some_and(|extension| extension == "zst") {
        let output = Command::new("zstd")
            .arg("-dc")
            .arg(path)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|error| format!("{shown} is compressed and zstd cannot be run ({error})"))?;
        if !output.status.success() {
            return Err(format!("{shown} cannot be decompressed by zstd"));
        }
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let file = fs::File::open(path).map_err(|error| format!("{shown} cannot be read: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_TRANSCRIPT_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{shown} cannot be read: {error}"))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use memprove_protocol::strict_json::parse_strict;

    use super::*;

    #[test]
    fn contents_and_commands() {
        let content = parse_strict(r#"[{"type":"text","text":"a"},"b",{"type":"image"}]"#).unwrap();
        assert_eq!(text_of(&content), "a\nb");
        assert_eq!(text_of(&parse_strict(r#""c""#).unwrap()), "c");
        assert_eq!(count_at(&parse_strict(r#"{"n":-1}"#).unwrap(), "n"), 0);
        assert!(reads_memprove("mcp__memprove__pack", ""));
        assert!(reads_memprove("Bash", "cd app && memprove resume --pack"));
        assert!(reads_memprove(
            "Bash",
            "MEMPROVE_X=1 sudo ~/.local/bin/memprove claims"
        ));
        assert!(reads_memprove("Bash", "x=$(memprove resume --pack)"));
        for line in [
            "cat docs/memprove-notes.md",
            "cd /home/user/memprove/memprove && cargo test",
            "ls ~/src/memprove",
            "cargo run --bin memprove -- report",
        ] {
            assert!(!reads_memprove("Bash", line), "{line}");
        }
        let command = |json: &str| command_of(&parse_strict(json).unwrap());
        assert_eq!(command(r#"{"cmd":"memprove claims"}"#), "memprove claims");
        assert_eq!(
            command(r#"{"command":["bash","-lc","memprove resume --pack"]}"#),
            "memprove resume --pack"
        );
        assert_eq!(
            command(r#"{"command":["memprove","claims"]}"#),
            "memprove claims"
        );
        assert_eq!(command(r#"{"path":"x"}"#), "");
    }
}
