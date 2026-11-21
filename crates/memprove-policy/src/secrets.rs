//! Finds credentials in text, from the text alone: nothing is run, nothing
//! is sent, and no secret is ever checked against the service it belongs to.
//!
//! Two kinds of evidence are read. A credential of a known format
//! (`ghp_…`, `sk-ant-…`, `AKIA…`, a private key block, …) is found wherever
//! it stands. A password is found by where it stands: the value of a
//! secret-named variable (`PGPASSWORD=…`), of a secret-named option
//! (`--password …`, `sshpass -p …`, `mysql -p…`), of a credential header
//! (`Authorization: Bearer …`), of `user:password@` in a URL, or of a
//! secret-named `key=value` pair. A command line is read as a shell reads
//! it ([`crate::shell`]), so quotes, `bash -c '…'` and `$(…)` do not hide
//! one.
//!
//! What stands for a secret without being one is not a finding: a variable
//! (`$PGPASSWORD`), a placeholder (`<password>`, `xxxx`, `changeme`), and
//! the well-known default values of development databases (`postgres`,
//! `root`, `password`, …).

use crate::{commands::basename, shell};

/// The kind of a password found by where it stands.
pub const PASSWORD: &str = "password";
/// The kind of a private key block.
pub const PRIVATE_KEY: &str = "private-key";
/// The kind of a JSON Web Token.
pub const JWT: &str = "jwt";

/// A credential found in text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// [`PASSWORD`], or the name of the format (`github-token`, …).
    pub kind: &'static str,
    /// What holds it: a variable, an option, a header, a URL; none for a
    /// credential found by its format alone.
    pub name: Option<String>,
    /// The secret itself, for redacting: never printed.
    pub value: String,
}

/// `value` as it may be shown: at most its first four characters (and never
/// more than a quarter of it), then its length.
#[must_use]
pub fn redacted(value: &str) -> String {
    let length = value.chars().count();
    let shown: String = value.chars().take((length / 4).min(4)).collect();
    format!("{shown}…({length} characters)")
}

/// `text` with the value of each of `findings` replaced by its
/// [`redacted`] form.
#[must_use]
pub fn hidden(text: &str, findings: &[Finding]) -> String {
    let mut values: Vec<&str> = findings
        .iter()
        .map(|finding| finding.value.as_str())
        .filter(|value| !value.is_empty())
        .collect();
    // Longest first, so that a value inside another is not cut in two.
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    let mut out = text.to_owned();
    for value in values {
        out = out.replace(value, &redacted(value));
    }
    out
}

fn alnum(character: char) -> bool {
    character.is_ascii_alphanumeric()
}

fn upper_or_digit(character: char) -> bool {
    character.is_ascii_uppercase() || character.is_ascii_digit()
}

fn word_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
}

fn dotted(character: char) -> bool {
    word_char(character) || character == '.'
}

/// A credential format: a prefix, then a run of body characters.
struct Format {
    kind: &'static str,
    prefix: &'static str,
    body: fn(char) -> bool,
    /// The fewest body characters.
    min: usize,
    /// The most, when the format has a fixed length.
    max: Option<usize>,
}

const fn format(
    kind: &'static str,
    prefix: &'static str,
    body: fn(char) -> bool,
    min: usize,
    max: Option<usize>,
) -> Format {
    Format {
        kind,
        prefix,
        body,
        min,
        max,
    }
}

/// The formats, a longer prefix before a shorter one it starts with.
const FORMATS: &[Format] = &[
    format("aws-access-key", "AKIA", upper_or_digit, 16, Some(16)),
    format("aws-access-key", "ASIA", upper_or_digit, 16, Some(16)),
    format("github-token", "github_pat_", word_char, 40, None),
    format("github-token", "ghp_", alnum, 36, None),
    format("github-token", "gho_", alnum, 36, None),
    format("github-token", "ghu_", alnum, 36, None),
    format("github-token", "ghs_", alnum, 36, None),
    format("github-token", "ghr_", alnum, 36, None),
    format("gitlab-token", "glpat-", word_char, 20, None),
    format("anthropic-key", "sk-ant-", word_char, 20, None),
    format("openai-key", "sk-proj-", word_char, 20, None),
    format("openai-key", "sk-svcacct-", word_char, 20, None),
    format("openai-key", "sk-admin-", word_char, 20, None),
    format("openai-key", "sk-", alnum, 40, None),
    format("slack-token", "xoxb-", word_char, 20, None),
    format("slack-token", "xoxp-", word_char, 20, None),
    format("slack-token", "xoxa-", word_char, 20, None),
    format("slack-token", "xoxr-", word_char, 20, None),
    format("slack-token", "xoxs-", word_char, 20, None),
    format("slack-token", "xapp-", word_char, 20, None),
    format("stripe-key", "sk_live_", alnum, 16, None),
    format("stripe-key", "rk_live_", alnum, 16, None),
    format("stripe-key", "sk_test_", alnum, 16, None),
    format("stripe-key", "rk_test_", alnum, 16, None),
    format("google-api-key", "AIza", word_char, 35, Some(35)),
    format("npm-token", "npm_", alnum, 36, Some(36)),
    format("huggingface-token", "hf_", alnum, 30, None),
    format("sendgrid-key", "SG.", dotted, 60, None),
    format("digitalocean-token", "dop_v1_", alnum, 64, Some(64)),
    format("pypi-token", "pypi-AgEIcHlwaS5vcmc", word_char, 50, None),
];

/// Every kind a finding can have, for rules that name one.
pub const KINDS: &[&str] = &[
    PASSWORD,
    PRIVATE_KEY,
    JWT,
    "aws-access-key",
    "github-token",
    "gitlab-token",
    "anthropic-key",
    "openai-key",
    "slack-token",
    "stripe-key",
    "google-api-key",
    "npm-token",
    "huggingface-token",
    "sendgrid-key",
    "digitalocean-token",
    "pypi-token",
];

/// Values that stand for a secret in examples and development setups.
const STAND_INS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "token",
    "key",
    "apikey",
    "api_key",
    "api-key",
    "changeme",
    "change-me",
    "change_me",
    "example",
    "placeholder",
    "redacted",
    "dummy",
    "test",
    "testing",
    "none",
    "null",
    "nil",
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
    "user",
    "username",
    "root",
    "admin",
    "postgres",
    "mysql",
    "guest",
    "demo",
    "foo",
    "bar",
    "foobar",
];

/// Whether `value` is written out, and is not a variable, a placeholder or
/// a well-known default.
#[must_use]
pub fn is_literal(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.contains(['$', '`', '*', '…'])
        || value.starts_with(['<', '{', '['])
    {
        return false;
    }
    let wrapped = |open: char, close: char| value.starts_with(open) && value.ends_with(close);
    if wrapped('<', '>') || wrapped('{', '}') || wrapped('[', ']') || wrapped('%', '%') {
        return false;
    }
    if value.starts_with('%') && value.len() <= 3 {
        // `%s`, `%d`.
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if STAND_INS.contains(&lower.as_str())
        || ["your-", "your_", "your ", "my-", "my_"]
            .iter()
            .any(|start| lower.starts_with(start))
        || ["redacted", "placeholder", "changeme", "example", "xxxx"]
            .iter()
            .any(|part| lower.contains(part))
    {
        return false;
    }
    if value.len() <= 2 && value.chars().all(|character| character.is_ascii_digit()) {
        return false;
    }
    // A reference to the environment, or a file that holds the secret.
    if ["env.", "environ", "getenv"]
        .iter()
        .any(|part| lower.contains(part))
        || names_a_file(&lower)
    {
        return false;
    }
    distinct(value) > 1
}

/// Endings of files that hold a secret or a setting.
const FILE_ENDINGS: &[&str] = &[
    ".pem", ".key", ".json", ".txt", ".yaml", ".yml", ".toml", ".p12", ".pfx", ".crt", ".cer",
    ".der", ".env", ".cfg", ".conf", ".ini", ".gpg", ".asc", ".sock",
];

/// Whether `value` (in lower case) is written as a path: `./pw`, `~/.pw`,
/// `/run/secrets/db`, `@token.txt`, `key.pem`.
fn names_a_file(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
        || value.starts_with('@')
        || value
            .strip_prefix('/')
            .is_some_and(|rest| rest.contains('/'))
        || FILE_ENDINGS.iter().any(|ending| value.ends_with(ending))
}

fn distinct(value: &str) -> usize {
    let mut seen: Vec<char> = Vec::new();
    for character in value.chars() {
        if !seen.contains(&character) {
            seen.push(character);
        }
    }
    seen.len()
}

/// Whether `value` looks like a generated token: long, of several
/// character classes, and not a path or a sentence.
#[must_use]
pub fn looks_random(value: &str) -> bool {
    let classes = [
        value
            .chars()
            .any(|character| character.is_ascii_lowercase()),
        value
            .chars()
            .any(|character| character.is_ascii_uppercase()),
        value.chars().any(|character| character.is_ascii_digit()),
    ]
    .iter()
    .filter(|present| **present)
    .count();
    value.chars().count() >= 16
        && classes >= 2
        && distinct(value) >= 8
        && !value.contains(char::is_whitespace)
        && !value.starts_with(['/', '.', '~'])
}

/// How a name says that its value is a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Named {
    /// By itself: `PASSWORD`, `API_TOKEN`, `clientSecret`.
    Secret,
    /// Only when the value also looks generated: `CACHE_KEY`, `auth`.
    IfRandom,
}

/// `name` in capitals with `_` between its words: `apiKey`, `api-key` and
/// `API_KEY` alike give `API_KEY`.
fn normalized(name: &str) -> String {
    let mut out = String::new();
    let mut before: Option<char> = None;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase()
                && before.is_some_and(|before| before.is_ascii_lowercase())
            {
                out.push('_');
            }
            out.push(character.to_ascii_uppercase());
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
        before = Some(character);
    }
    out.trim_end_matches('_').to_owned()
}

/// Last words of a name that say its value is about a secret, not one.
const NOT_A_SECRET: &[&str] = &[
    "FILE",
    "FILES",
    "PATH",
    "DIR",
    "URL",
    "URI",
    "ENDPOINT",
    "NAME",
    "ID",
    "IDS",
    "STDIN",
    "ENV",
    "VAR",
    "CMD",
    "COMMAND",
    "PROMPT",
    "LENGTH",
    "LEN",
    "SIZE",
    "TTL",
    "EXPIRY",
    "EXPIRES",
    "EXPIRATION",
    "TYPE",
    "HEADER",
    "VERSION",
    "PREFIX",
    "HOST",
    "PORT",
    "USER",
    "USERNAME",
    "LIMIT",
    "COUNT",
    "ALGORITHM",
    "ALG",
    "HELPER",
    "PROVIDER",
    "REQUIRED",
    "ENABLED",
    "DISABLED",
    "POLICY",
    "SCOPE",
    "SCOPES",
    "BUDGET",
    "TOKENS",
    "KEYS",
    "SECRETS",
    "PASSWORDS",
];

/// First words of a name that make it a setting, not a secret.
const SETTING: &[&str] = &[
    "MAX", "MIN", "NUM", "USE", "NO", "SKIP", "ENABLE", "DISABLE", "HAS", "IS", "WITH", "WITHOUT",
    "REQUIRE", "ALLOW", "SHOW", "HIDE", "PRINT", "ASK", "PROMPT", "GENERATE", "ROTATE", "RESET",
    "FORGOT", "VERIFY", "VALIDATE", "CHECK", "GET", "LIST", "DELETE", "REVOKE",
];

/// Words that may follow the secret's word in a name: which one it is
/// (`DB_PASSWORD_PROD`, `SECRET_KEY_BASE`, `API_TOKEN_2`).
const WHICH: &[&str] = &[
    "PROD",
    "PRODUCTION",
    "STAGING",
    "STAGE",
    "DEV",
    "TEST",
    "QA",
    "LOCAL",
    "OLD",
    "NEW",
    "BASE",
    "PRIMARY",
    "SECONDARY",
    "DEFAULT",
    "MAIN",
    "BACKUP",
    "RO",
    "RW",
    "B64",
    "BASE64",
    "VALUE",
    "PLAIN",
    "TEXT",
];

/// Words that make a key one that is meant to be seen.
const SEEN: &[&str] = &["PUBLIC", "PUB", "PUBLISHABLE", "ANON"];

/// Words that make a name a secret's when one of its words ends with them
/// (`PGPASSWORD`, `AUTH_TOKEN`, `clientsecret`).
const SECRET_WORDS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "SECRET",
    "TOKEN",
    "APIKEY",
    "CREDENTIAL",
    "CREDENTIALS",
];

/// Words before `KEY` that make the pair a secret's name.
const KEY_OF: &[&str] = &[
    "API",
    "ACCESS",
    "SECRET",
    "PRIVATE",
    "AUTH",
    "SIGNING",
    "ENCRYPTION",
    "MASTER",
    "LICENSE",
    "ACCOUNT",
    "SERVICE",
];

/// Whether `name` (a variable, an option without its dashes, a JSON member,
/// a header) names a secret.
#[must_use]
pub fn secret_name(name: &str) -> Option<Named> {
    let name = normalized(name);
    let parts: Vec<&str> = name.split('_').collect();
    let (first, last) = (*parts.first()?, *parts.last()?);
    if matches!(name.as_str(), "PWD" | "OLDPWD")
        || NOT_A_SECRET.contains(&last)
        || SETTING.contains(&first)
        || parts.iter().any(|part| SEEN.contains(part))
    {
        return None;
    }
    // The secret's word is the last one, or only says-which words follow it:
    // `SECRET_ROTATION` and `TOKEN_REFRESH_INTERVAL` are settings.
    let is_which = |part: &str| {
        WHICH.contains(&part) || part.chars().all(|character| character.is_ascii_digit())
    };
    let ends_at = parts.len() - parts.iter().rev().take_while(|part| is_which(part)).count();
    let named = &parts[..ends_at];
    let word = named.last()?;
    if matches!(name.as_str(), "SECRET" | "CREDENTIAL" | "CREDENTIALS") {
        // `--secret db-password` names a secret more often than it holds one.
        return Some(Named::IfRandom);
    }
    if SECRET_WORDS.iter().any(|secret| word.ends_with(secret))
        || matches!(*word, "PASS" | "PWD")
        || (*word == "KEY" && named.len() >= 2 && KEY_OF.contains(&named[named.len() - 2]))
    {
        return Some(Named::Secret);
    }
    matches!(*word, "KEY" | "AUTH" | "BEARER").then_some(Named::IfRandom)
}

/// The finding for `value` held by `name`, when the name is a secret's and
/// the value is written out.
#[must_use]
pub fn in_member(name: &str, value: &str) -> Option<Finding> {
    if normalized(name).ends_with("AUTHORIZATION") {
        return authorization(name, value);
    }
    let found = match secret_name(name)? {
        Named::Secret => is_literal(value),
        Named::IfRandom => is_literal(value) && looks_random(value),
    };
    found.then(|| Finding {
        kind: PASSWORD,
        name: Some(name.to_owned()),
        value: value.trim().to_owned(),
    })
}

/// The credential of an `Authorization` header's value: what follows its
/// scheme, or all of it.
fn authorization(name: &str, value: &str) -> Option<Finding> {
    let value = value.trim();
    let credential = match value.split_once(char::is_whitespace) {
        Some((scheme, rest))
            if ["bearer", "basic", "token", "apikey", "bot", "digest"]
                .contains(&scheme.to_ascii_lowercase().as_str()) =>
        {
            rest.trim()
        }
        _ => value,
    };
    is_literal(credential).then(|| Finding {
        kind: PASSWORD,
        name: Some(name.to_owned()),
        value: credential.to_owned(),
    })
}

/// Adds `finding`, or merges it with a finding of the same secret: the
/// format's kind wins over [`PASSWORD`], and a name is kept.
pub fn merge(out: &mut Vec<Finding>, finding: Finding) {
    if finding.value.is_empty() {
        return;
    }
    for known in out.iter_mut() {
        if known.value.contains(&finding.value) || finding.value.contains(&known.value) {
            if known.kind == PASSWORD && finding.kind != PASSWORD {
                known.kind = finding.kind;
                known.value = finding.value;
            }
            if known.name.is_none() {
                known.name = finding.name;
            }
            return;
        }
    }
    out.push(finding);
}

/// Whether the body of a credential of a known format is a stand-in
/// (`ghp_xxxxxxxx…`, AWS's documented `AKIAIOSFODNN7EXAMPLE`).
fn stand_in_body(body: &str) -> bool {
    distinct(body) < 4 || body.to_ascii_uppercase().contains("EXAMPLE")
}

/// Credentials of a known format in `text`, private key blocks, JSON Web
/// Tokens, and passwords in the user part of URLs.
#[must_use]
pub fn in_text(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut before: Option<char> = None;
    let mut rest = text;
    while let Some(character) = rest.chars().next() {
        let at_start = before.is_none_or(|before| !before.is_ascii_alphanumeric());
        let mut taken = 0;
        if at_start {
            taken = format_at(rest, &mut out)
                .or_else(|| jwt_at(rest, &mut out))
                .unwrap_or(0);
        }
        if taken == 0 && rest.starts_with("-----BEGIN ") {
            taken = private_key_at(rest, &mut out).unwrap_or(0);
        }
        if taken == 0 && rest.starts_with("://") {
            url_at(text, text.len() - rest.len(), &mut out);
        }
        let step = taken.max(character.len_utf8());
        before = rest[..step].chars().next_back();
        rest = &rest[step..];
    }
    out
}

/// The credential of a known format that `rest` starts with: its length.
fn format_at(rest: &str, out: &mut Vec<Finding>) -> Option<usize> {
    for format in FORMATS {
        let Some(after) = rest.strip_prefix(format.prefix) else {
            continue;
        };
        let body: String = after.chars().take_while(|c| (format.body)(*c)).collect();
        let length = body.chars().count();
        if length < format.min || format.max.is_some_and(|max| length > max) {
            continue;
        }
        let taken = format.prefix.len() + body.len();
        if !stand_in_body(&body) {
            merge(
                out,
                Finding {
                    kind: format.kind,
                    name: None,
                    value: rest[..taken].to_owned(),
                },
            );
        }
        return Some(taken);
    }
    None
}

/// The JSON Web Token that `rest` starts with: three base64url parts, the
/// first two of them JSON objects (`eyJ…`).
fn jwt_at(rest: &str, out: &mut Vec<Finding>) -> Option<usize> {
    let mut taken = 0;
    for part in 0..3 {
        let from = &rest[taken..];
        if part < 2 && !from.starts_with("eyJ") {
            return None;
        }
        let length: usize = from
            .chars()
            .take_while(|character| word_char(*character))
            .map(char::len_utf8)
            .sum();
        if length < 10 {
            return None;
        }
        taken += length;
        if part < 2 {
            if !rest[taken..].starts_with('.') {
                return None;
            }
            taken += 1;
        }
    }
    merge(
        out,
        Finding {
            kind: JWT,
            name: None,
            value: rest[..taken].to_owned(),
        },
    );
    Some(taken)
}

/// The `-----BEGIN … PRIVATE KEY-----` line that `rest` starts with.
fn private_key_at(rest: &str, out: &mut Vec<Finding>) -> Option<usize> {
    let line = rest.lines().next()?;
    let end = line.find("PRIVATE KEY")?;
    let label = &line["-----BEGIN ".len()..end];
    if !label
        .chars()
        .all(|character| character.is_ascii_uppercase() || character == ' ')
    {
        return None;
    }
    let after = &line[end + "PRIVATE KEY".len()..];
    let after = after.strip_prefix(" BLOCK").unwrap_or(after);
    if !after.starts_with("-----") {
        return None;
    }
    let taken = line.len() - after.len() + "-----".len();
    merge(
        out,
        Finding {
            kind: PRIVATE_KEY,
            name: None,
            value: rest[..taken].to_owned(),
        },
    );
    Some(taken)
}

/// The password in the user part of the URL whose `://` is at `at`.
fn url_at(text: &str, at: usize, out: &mut Vec<Finding>) {
    let scheme: String = text[..at]
        .chars()
        .rev()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '.' | '-')
        })
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    if scheme.len() < 2 || !scheme.starts_with(|first: char| first.is_ascii_alphabetic()) {
        return;
    }
    let authority: &str = text[at + 3..]
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    '/' | '?' | '#' | '"' | '\'' | '\\' | ')' | '>' | '`'
                )
        })
        .next()
        .unwrap_or_default();
    let Some((user_part, host)) = authority.rsplit_once('@') else {
        return;
    };
    if host.is_empty() {
        return;
    }
    let name = Some(format!("{scheme}:// URL"));
    match user_part.split_once(':') {
        Some((_, password)) if is_literal(password) => merge(
            out,
            Finding {
                kind: PASSWORD,
                name,
                value: password.to_owned(),
            },
        ),
        None if is_literal(user_part) && looks_random(user_part) && user_part.len() >= 20 => merge(
            out,
            Finding {
                kind: PASSWORD,
                name,
                value: user_part.to_owned(),
            },
        ),
        _ => {}
    }
}

/// Secret-named `key=value` pairs in `text`, between `,` `;` `&` `?` and
/// white space: a query string, a connection string, mount options.
#[must_use]
pub fn in_pairs(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for pair in text.split(|character: char| {
        character.is_whitespace() || matches!(character, ',' | ';' | '&' | '?')
    }) {
        // `--from-literal=password=…` holds a pair in a pair.
        let mut rest = pair;
        while let Some((name, value)) = rest.split_once('=') {
            rest = value;
            let name = name.trim_start_matches('-');
            if name.is_empty() || !name.chars().all(dotted) {
                continue;
            }
            let value = value.trim_matches(['"', '\'']);
            if secret_name(name) == Some(Named::Secret) && is_literal(value) {
                merge(
                    &mut out,
                    Finding {
                        kind: PASSWORD,
                        name: Some(name.to_owned()),
                        value: value.to_owned(),
                    },
                );
                break;
            }
        }
    }
    out
}

/// How a program takes a password as the value of a short option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Taken {
    /// As the next word (`redis-cli -a secret`).
    Next,
    /// In the same word (`mysql -psecret`).
    Attached,
    /// Either way (`sshpass -p secret`, `sshpass -psecret`).
    Either,
    /// After the user and a separator in the next word (`curl -u
    /// me:secret`, `smbclient -U me%secret`, `lftp -u me,secret`).
    UserThen(char),
    /// As `pass:secret` in the next word (`openssl … -passin pass:secret`).
    PassColon,
}

struct ProgramOption {
    programs: &'static [&'static str],
    /// A word the command must also have (`login` for `docker`).
    with: Option<&'static str>,
    options: &'static [&'static str],
    taken: Taken,
}

const PROGRAM_OPTIONS: &[ProgramOption] = &[
    ProgramOption {
        programs: &["sshpass"],
        with: None,
        options: &["-p"],
        taken: Taken::Either,
    },
    ProgramOption {
        programs: &[
            "mysql",
            "mysqldump",
            "mysqladmin",
            "mysqlimport",
            "mysqlshow",
            "mysqlcheck",
            "mariadb",
            "mariadb-dump",
            "mariadb-admin",
            "mycli",
        ],
        with: None,
        options: &["-p"],
        taken: Taken::Attached,
    },
    ProgramOption {
        programs: &["7z", "7za", "7zz", "7zr", "rar", "unrar"],
        with: None,
        options: &["-p"],
        taken: Taken::Attached,
    },
    ProgramOption {
        programs: &["redis-cli"],
        with: None,
        options: &["-a"],
        taken: Taken::Next,
    },
    ProgramOption {
        programs: &[
            "mongo",
            "mongosh",
            "mongodump",
            "mongorestore",
            "mongoexport",
            "mongoimport",
        ],
        with: None,
        options: &["-p"],
        taken: Taken::Next,
    },
    ProgramOption {
        programs: &["docker", "podman", "nerdctl", "buildah", "skopeo", "helm"],
        with: Some("login"),
        options: &["-p"],
        taken: Taken::Either,
    },
    ProgramOption {
        programs: &["sqlcmd", "bcp", "osql", "mssql-cli"],
        with: None,
        options: &["-P"],
        taken: Taken::Next,
    },
    ProgramOption {
        programs: &["zip", "unzip"],
        with: None,
        options: &["-P"],
        taken: Taken::Next,
    },
    ProgramOption {
        programs: &[
            "ldapsearch",
            "ldapadd",
            "ldapmodify",
            "ldapdelete",
            "ldappasswd",
            "ldapwhoami",
        ],
        with: None,
        options: &["-w"],
        taken: Taken::Next,
    },
    ProgramOption {
        programs: &["curl"],
        with: None,
        options: &["-u", "--user", "-U", "--proxy-user"],
        taken: Taken::UserThen(':'),
    },
    ProgramOption {
        programs: &["smbclient", "rpcclient"],
        with: None,
        options: &["-U", "--user"],
        taken: Taken::UserThen('%'),
    },
    ProgramOption {
        programs: &["lftp"],
        with: None,
        options: &["-u", "--user"],
        taken: Taken::UserThen(','),
    },
    ProgramOption {
        programs: &["az"],
        with: Some("login"),
        options: &["-p"],
        taken: Taken::Either,
    },
    ProgramOption {
        programs: &["openssl"],
        with: None,
        options: &["-k"],
        taken: Taken::Next,
    },
    ProgramOption {
        programs: &["openssl"],
        with: None,
        options: &["-passin", "-passout", "-pass"],
        taken: Taken::PassColon,
    },
];

/// Shells whose `-c` word is a script.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish", "ash"];

fn is_variable_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && name
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn password(name: impl Into<String>, value: &str) -> Finding {
    Finding {
        kind: PASSWORD,
        name: Some(name.into()),
        value: value.to_owned(),
    }
}

/// A value an option may take: written out, and not another option.
fn option_value(value: &str) -> bool {
    !value.starts_with('-') && is_literal(value)
}

/// Passwords among the words of one simple command (after quote removal):
/// in assignments, options, headers and pairs.
fn in_words_at(words: &[String], depth: usize, out: &mut Vec<Finding>) {
    let scripts = script_words(words);
    for (index, word) in words.iter().enumerate() {
        if scripts.contains(&index) {
            // Read as a command of its own, below.
            continue;
        }
        let next = words.get(index + 1).map(String::as_str);
        // `NAME=value`, also after `env`, `export` and `docker run -e`.
        if let Some((name, value)) = word.split_once('=')
            && is_variable_name(name)
            && let Some(finding) = in_member(name, value)
        {
            merge(out, finding);
            continue;
        }
        // `--password value`, `--password=value`, `-token value`.
        if let Some(option) = word.strip_prefix('-') {
            let option = option.trim_start_matches('-');
            let (name, attached) = match option.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (option, None),
            };
            if name.len() >= 4
                && name.chars().all(word_char)
                && secret_name(name) == Some(Named::Secret)
            {
                let dashes = &word[..word.len() - option.len()];
                match attached.or(next) {
                    Some(value) if attached.is_some() && is_literal(value) => {
                        merge(out, password(format!("{dashes}{name}"), value));
                    }
                    Some(value) if attached.is_none() && option_value(value) => {
                        merge(out, password(format!("{dashes}{name}"), value));
                    }
                    _ => {}
                }
                continue;
            }
        }
        // `Authorization: Bearer …` anywhere; another secret-named header
        // after `-H`.
        if let Some((name, value)) = word.split_once(':')
            && !name.is_empty()
            && name.chars().all(word_char)
            && !value.starts_with("//")
        {
            let header = normalized(name);
            let after_h = index > 0
                && matches!(
                    words[index - 1].as_str(),
                    "-H" | "--header" | "--proxy-header"
                );
            if header.ends_with("AUTHORIZATION") || after_h {
                if let Some(finding) = in_member(name, value) {
                    merge(out, finding);
                }
                continue;
            }
        }
        if word.contains('=') {
            for finding in in_pairs(word) {
                merge(out, finding);
            }
        }
    }
    program_options(words, out);
    positional(words, out);
    if depth < shell::MAX_DEPTH {
        if let Some(eval_at) = words.iter().position(|word| word == "eval") {
            in_command_at(&words[eval_at + 1..].join(" "), depth + 1, out);
        } else {
            for index in scripts {
                in_command_at(&words[index], depth + 1, out);
            }
        }
    }
}

/// Passwords a command takes as a word of its own, after what names them:
/// `htpasswd -b <file> <user> <password>`, and a generated value after a
/// secret-named word (`aws configure set aws_secret_access_key …`, `npm
/// config set //host/:_authToken …`).
fn positional(words: &[String], out: &mut Vec<Finding>) {
    if let Some(start) = words.iter().position(|word| basename(word) == "htpasswd")
        && words[start + 1..]
            .iter()
            .any(|word| word.starts_with('-') && !word.starts_with("--") && word.contains('b'))
        && words.len() >= start + 5
        && let Some(last) = words.last()
        && option_value(last)
    {
        merge(out, password("htpasswd -b", last));
    }
    for pair in words.windows(2) {
        let (word, value) = (&pair[0], &pair[1]);
        if word.starts_with('-') || word.contains('=') {
            continue;
        }
        let name = word.rsplit([':', '/']).next().unwrap_or(word);
        if !name.is_empty()
            && name.chars().all(dotted)
            && secret_name(name) == Some(Named::Secret)
            && option_value(value)
            && looks_random(value)
        {
            merge(out, password(name, value));
        }
    }
}

/// Passwords given to programs through their own short options.
fn program_options(words: &[String], out: &mut Vec<Finding>) {
    for rule in PROGRAM_OPTIONS {
        let Some(start) = words
            .iter()
            .position(|word| rule.programs.contains(&basename(word)))
        else {
            continue;
        };
        let program = basename(&words[start]);
        if rule
            .with
            .is_some_and(|with| !words[start..].iter().any(|word| word == with))
        {
            continue;
        }
        for (index, word) in words.iter().enumerate().skip(start + 1) {
            let next = words.get(index + 1).map(String::as_str);
            for option in rule.options {
                let name = format!("{program} {option}");
                let separate = (word == option).then_some(next).flatten();
                let attached = word
                    .strip_prefix(option)
                    .filter(|rest| !rest.is_empty() && !option.starts_with("--"));
                match rule.taken {
                    Taken::Next | Taken::Either if separate.is_some_and(option_value) => {
                        merge(out, password(name, separate.unwrap_or_default()));
                    }
                    Taken::Attached | Taken::Either
                        if attached
                            .is_some_and(|value| !value.starts_with('=') && is_literal(value)) =>
                    {
                        merge(out, password(name, attached.unwrap_or_default()));
                    }
                    Taken::UserThen(separator) => {
                        let pair = separate.or_else(|| {
                            word.strip_prefix(option)
                                .and_then(|rest| rest.strip_prefix('='))
                        });
                        if let Some((_, secret)) = pair.and_then(|pair| pair.split_once(separator))
                            && is_literal(secret)
                        {
                            merge(out, password(name, secret));
                        }
                    }
                    Taken::PassColon => {
                        if let Some(secret) = separate.and_then(|value| value.strip_prefix("pass:"))
                            && is_literal(secret)
                        {
                            merge(out, password(name, secret));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// The words of a command that are scripts handed to a shell: the word
/// after a shell's `-c`, the words of `eval`, and the remote command of
/// `ssh`.
fn script_words(words: &[String]) -> Vec<usize> {
    let mut scripts = Vec::new();
    if let Some(eval_at) = words.iter().position(|word| word == "eval") {
        return (eval_at + 1..words.len()).collect();
    }
    if let Some(shell_at) = words
        .iter()
        .position(|word| SHELLS.contains(&basename(word)))
    {
        let flag = words
            .iter()
            .enumerate()
            .skip(shell_at + 1)
            .find(|(_, word)| {
                word.starts_with('-')
                    && !word.starts_with("--")
                    && word.ends_with('c')
                    && word[1..].chars().all(|letter| letter.is_ascii_alphabetic())
            });
        if let Some((at, _)) = flag
            && at + 1 < words.len()
        {
            scripts.push(at + 1);
        }
    }
    if let Some(ssh_at) = words.iter().position(|word| basename(word) == "ssh") {
        scripts.extend(
            (ssh_at + 1..words.len()).filter(|at| words[*at].contains(char::is_whitespace)),
        );
    }
    scripts
}

fn in_command_at(command: &str, depth: usize, out: &mut Vec<Finding>) {
    for simple in shell::read_at(command, depth).commands {
        in_words_at(&simple.words, depth, out);
    }
}

/// Passwords among words that are one command already split (a `command`
/// with its `args`), and credentials of a known format in them.
#[must_use]
pub fn in_words(words: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();
    in_words_at(words, 0, &mut out);
    for word in words {
        for finding in in_text(word) {
            merge(&mut out, finding);
        }
    }
    out
}

/// Credentials in the text of a shell command: passwords by where they
/// stand, and credentials of a known format anywhere in it (a heredoc's
/// body included).
#[must_use]
pub fn in_command(command: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    in_command_at(command, 0, &mut out);
    for finding in in_text(command) {
        merge(&mut out, finding);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value no service ever issued: built here, from a label.
    fn made(prefix: &str, length: usize) -> String {
        let alphabet = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ";
        let body: String = alphabet.chars().cycle().take(length).collect();
        format!("{prefix}{body}")
    }

    fn kinds(findings: &[Finding]) -> Vec<(&'static str, Option<&str>, &str)> {
        findings
            .iter()
            .map(|finding| {
                (
                    finding.kind,
                    finding.name.as_deref(),
                    finding.value.as_str(),
                )
            })
            .collect()
    }

    #[test]
    fn a_value_is_shown_by_a_few_characters_and_its_length() {
        assert_eq!(redacted("hunter2"), "h…(7 characters)");
        assert_eq!(redacted("abc"), "…(3 characters)");
        assert_eq!(redacted(&made("ghp_", 36)), "ghp_…(40 characters)");
        let findings = in_command("PGPASSWORD=s3cr3t-Value psql -h db");
        assert_eq!(
            hidden("PGPASSWORD=s3cr3t-Value psql -h db", &findings),
            "PGPASSWORD=s3c…(12 characters) psql -h db"
        );
    }

    #[test]
    fn names_say_whether_their_value_is_a_secret() {
        for name in [
            "PGPASSWORD",
            "MYSQL_PWD",
            "DB_PASS",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "apiKey",
            "clientSecret",
            "aws_secret_access_key",
            "X-Api-Key",
            "access-token",
            "PRIVATE-TOKEN",
            "password",
        ] {
            assert_eq!(secret_name(name), Some(Named::Secret), "{name}");
        }
        for name in [
            "DB_PASSWORD_PROD",
            "SECRET_KEY_BASE",
            "API_TOKEN_2",
            "JWT_SECRET",
        ] {
            assert_eq!(secret_name(name), Some(Named::Secret), "{name}");
        }
        for name in [
            "CACHE_KEY",
            "key",
            "_auth",
            "SORT_KEY",
            "secret",
            "credentials",
        ] {
            assert_eq!(secret_name(name), Some(Named::IfRandom), "{name}");
        }
        for name in [
            "PWD",
            "OLDPWD",
            "PASSWORD_FILE",
            "TOKEN_URL",
            "AWS_ACCESS_KEY_ID",
            "MAX_TOKENS",
            "MAX_THINKING_TOKENS",
            "SSH_PUBLIC_KEY",
            "USE_TOKEN",
            "PATH",
            "HOME",
            "password-stdin",
            "CLIENT_ID",
            "SESSION_SECRET_ROTATION",
            "TOKEN_REFRESH_INTERVAL",
            "passphrase-fd",
            "ask-vault-pass",
            "STRIPE_PUBLISHABLE_KEY",
            "GIT_ASKPASS",
            "SSH_AUTH_SOCK",
            "credential.helper",
        ] {
            assert_eq!(secret_name(name), None, "{name}");
        }
    }

    #[test]
    fn variables_placeholders_and_defaults_are_not_literal() {
        for value in [
            "",
            "$PGPASSWORD",
            "${DB_PASS}",
            "$(cat pw)",
            "<password>",
            "{{token}}",
            "[redacted]",
            "%PASS%",
            "%s",
            "xxxxxxxx",
            "****",
            "changeme",
            "your-token-here",
            "password",
            "postgres",
            "true",
            "1",
            "EXAMPLE_VALUE",
            "./pw.txt",
            "~/.config/tool/token",
            "/run/secrets/db",
            "@token.txt",
            "key.pem",
            "process.env.API_KEY",
            "os.environ['TOKEN']",
        ] {
            assert!(!is_literal(value), "{value}");
        }
        for value in ["hunter2", "s3cr3t", "123456", "Tr0ub4dor&3"] {
            assert!(is_literal(value), "{value}");
        }
    }

    #[test]
    fn credentials_of_a_known_format_are_found_anywhere() {
        let github = made("ghp_", 36);
        let anthropic = made("sk-ant-api03-", 40);
        let aws = made("AKIA", 16).to_uppercase();
        let text = format!("token={github}, key \"{anthropic}\" and {aws}.");
        assert_eq!(
            kinds(&in_text(&text)),
            [
                ("github-token", None, github.as_str()),
                ("anthropic-key", None, anthropic.as_str()),
                ("aws-access-key", None, aws.as_str()),
            ]
        );
        for (kind, value) in [
            ("github-token", made("github_pat_", 60)),
            ("gitlab-token", made("glpat-", 20)),
            ("openai-key", made("sk-proj-", 48)),
            ("openai-key", made("sk-", 48)),
            ("slack-token", made("xoxb-", 40)),
            ("stripe-key", made("sk_live_", 24)),
            ("google-api-key", made("AIza", 35)),
            ("npm-token", made("npm_", 36)),
            ("huggingface-token", made("hf_", 34)),
        ] {
            assert_eq!(
                kinds(&in_text(&format!("x {value} y"))),
                [(kind, None, value.as_str())],
                "{kind}"
            );
        }
    }

    #[test]
    fn what_only_resembles_a_format_is_not_found() {
        for text in [
            // AWS's documented example and a run of one letter.
            "AKIAIOSFODNN7EXAMPLE".to_owned(),
            format!("ghp_{}", "x".repeat(36)),
            // Too short, too long for a fixed length, or inside a word.
            made("ghp_", 20),
            made("AKIA", 24).to_ascii_uppercase(),
            format!("task-{}", made("proj-", 40)),
            format!("abc{}", made("ghp_", 36)),
            "hf_hub_download(repo_id, filename)".to_owned(),
            "sk-learn and sk-image are libraries".to_owned(),
        ] {
            assert_eq!(in_text(&text), [], "{text}");
        }
    }

    #[test]
    fn private_keys_and_json_web_tokens_are_found() {
        let found = in_text("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n");
        assert_eq!(
            kinds(&found),
            [(PRIVATE_KEY, None, "-----BEGIN OPENSSH PRIVATE KEY-----")]
        );
        assert_eq!(in_text("-----BEGIN PRIVATE KEY-----")[0].kind, PRIVATE_KEY);
        assert_eq!(in_text("-----BEGIN PUBLIC KEY-----"), []);
        assert_eq!(in_text("-----BEGIN CERTIFICATE-----"), []);
        let jwt = [made("eyJ", 17), made("eyJ", 21), made("", 30)].join(".");
        assert_eq!(
            kinds(&in_text(&format!("Bearer {jwt}"))),
            [(JWT, None, jwt.as_str())]
        );
        assert_eq!(in_text("eyJhbGciOiJIUzI1NiJ9.not-a-token"), []);
    }

    #[test]
    fn a_password_in_a_url_is_found() {
        assert_eq!(
            kinds(&in_text(
                "psql postgres://app:s3cr3tPw@db.internal:5432/app"
            )),
            [(PASSWORD, Some("postgres:// URL"), "s3cr3tPw")]
        );
        let token = made("", 40);
        assert_eq!(
            kinds(&in_text(&format!(
                "git clone https://{token}@github.com/a/b"
            ))),
            [(PASSWORD, Some("https:// URL"), token.as_str())]
        );
        for text in [
            "postgres://postgres:postgres@localhost/app",
            "https://user:$TOKEN@host/x",
            "https://user:<password>@host/x",
            "ssh://git@github.com/a/b.git",
            "https://example.com/a@b",
            "see https://docs.example.com/guide",
        ] {
            assert_eq!(in_text(text), [], "{text}");
        }
    }

    #[test]
    fn a_password_in_an_assignment_is_found_as_a_shell_reads_it() {
        for command in [
            "PGPASSWORD=hunter2 psql -h db -U app",
            "PGPASSWORD='hunter2' psql -h db",
            "PGPASSWORD=\"hunter2\" psql",
            "cd app && PGPASSWORD=hunter2 psql",
            "env PGPASSWORD=hunter2 psql",
            "export PGPASSWORD=hunter2",
            "sudo -u postgres env PGPASSWORD=hunter2 psql",
            "bash -c 'PGPASSWORD=hunter2 psql -h db'",
            "bash -lc \"PGPASSWORD=hunter2 psql\"",
            "echo $(PGPASSWORD=hunter2 psql -c 'select 1')",
            "docker run -e PGPASSWORD=hunter2 postgres",
            "ssh db 'PGPASSWORD=hunter2 pg_dump app'",
            "eval PGPASSWORD=hunter2 psql",
        ] {
            assert_eq!(
                kinds(&in_command(command)),
                [(PASSWORD, Some("PGPASSWORD"), "hunter2")],
                "{command}"
            );
        }
        for command in [
            "PGPASSWORD=$DB_PASSWORD psql",
            "PGPASSWORD=\"${PGPASSWORD}\" psql",
            "PGPASSWORD= psql",
            "PGPASSWORD=postgres psql -h localhost",
            "PWD=/tmp ls",
            "PASSWORD_FILE=/run/secrets/db psql",
            "git commit -m 'rename the token field'",
            "MAX_TOKENS=4096 claude -p hi",
            "CACHE_KEY=users sort data",
        ] {
            assert_eq!(in_command(command), [], "{command}");
        }
    }

    #[test]
    fn a_password_in_an_option_is_found() {
        for (command, name, value) in [
            ("sshpass -p hunter2 ssh me@host", "sshpass -p", "hunter2"),
            ("sshpass -phunter2 ssh me@host", "sshpass -p", "hunter2"),
            ("mysql -uroot -phunter2 app", "mysql -p", "hunter2"),
            (
                "/usr/bin/mysqldump -u app -phunter2 app",
                "mysqldump -p",
                "hunter2",
            ),
            ("redis-cli -a hunter2 ping", "redis-cli -a", "hunter2"),
            ("mongosh -u app -p hunter2 db", "mongosh -p", "hunter2"),
            (
                "docker login -u me -p hunter2 ghcr.io",
                "docker -p",
                "hunter2",
            ),
            ("unzip -P hunter2 a.zip", "unzip -P", "hunter2"),
            ("curl -u me:hunter2 https://host/x", "curl -u", "hunter2"),
            (
                "curl --user=me:hunter2 https://host/x",
                "curl --user",
                "hunter2",
            ),
            (
                "openssl rsa -in k.pem -passin pass:hunter2",
                "openssl -passin",
                "hunter2",
            ),
            ("mytool --password hunter2 run", "--password", "hunter2"),
            ("mytool --password=hunter2 run", "--password", "hunter2"),
            ("mytool --api-key hunter2", "--api-key", "hunter2"),
            ("mytool -token hunter2", "-token", "hunter2"),
            (
                "sudo sshpass -p hunter2 ssh me@host",
                "sshpass -p",
                "hunter2",
            ),
            (
                "smbclient //nas/share -U svc%hunter2",
                "smbclient -U",
                "hunter2",
            ),
            ("lftp -u svc,hunter2 sftp://host", "lftp -u", "hunter2"),
            ("az login -u me -p hunter2", "az -p", "hunter2"),
            (
                "openssl enc -aes-256-cbc -k hunter2 -in f",
                "openssl -k",
                "hunter2",
            ),
            (
                "htpasswd -bc /etc/nginx/.htpasswd admin hunter2",
                "htpasswd -b",
                "hunter2",
            ),
            (
                "kubectl create secret generic db --from-literal=password=hunter2",
                "password",
                "hunter2",
            ),
        ] {
            assert_eq!(
                kinds(&in_command(command)),
                [(PASSWORD, Some(name), value)],
                "{command}"
            );
        }
        for command in [
            "mysql -u root -p app",
            "mysql -uroot -p$MYSQL_ROOT_PASSWORD app",
            "mysql -P 3306 -u root",
            "docker run -p 8080:80 nginx",
            "docker login --password-stdin ghcr.io",
            "curl -u me https://host/x",
            "curl -u \"me:$PASS\" https://host/x",
            "mytool --password --verbose",
            "mytool --password-file /run/pw",
            "mytool --token-url https://host/token",
            "sshpass -p \"$PW\" ssh me@host",
            "sshpass -e ssh me@host",
            "ssh -p 2222 me@host",
            "grep -p pattern file",
            "htpasswd /etc/nginx/.htpasswd admin",
            "az vm list -p hunter2",
            "smbclient //nas/share -U svc",
            "kubectl get secret db -o yaml",
            "grep -rn token src/handlers",
            "echo the token expired",
            "gcloud secrets versions access latest --secret=db-password",
            "docker build --secret id=npmrc,src=.npmrc .",
            "ansible-playbook --ask-vault-pass site.yml",
            "ansible-playbook site.yml --private-key deploy.pem",
            "kubectl create secret generic db --from-file=password=./pw.txt",
            "gpg --batch --passphrase-fd 0 -d secrets.gpg",
            "GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/key.json terraform plan",
            "SESSION_SECRET_ROTATION=weekly ./run.sh",
        ] {
            assert_eq!(in_command(command), [], "{command}");
        }
    }

    #[test]
    fn a_credential_in_a_header_or_a_pair_is_found() {
        let token = made("", 32);
        assert_eq!(
            kinds(&in_command(&format!(
                "curl -H 'Authorization: Bearer {token}' https://host/x"
            ))),
            [(PASSWORD, Some("Authorization"), token.as_str())]
        );
        assert_eq!(
            kinds(&in_command("curl -H 'X-Api-Key: hunter2' https://host/x")),
            [(PASSWORD, Some("X-Api-Key"), "hunter2")]
        );
        assert_eq!(
            kinds(&in_command(
                "curl 'https://host/x?user=me&access_token=hunter2&page=2'"
            )),
            [(PASSWORD, Some("access_token"), "hunter2")]
        );
        assert_eq!(
            kinds(&in_command("psql 'host=db user=app password=hunter2'")),
            [(PASSWORD, Some("password"), "hunter2")]
        );
        assert_eq!(
            kinds(&in_command(
                "mount -t cifs //nas/share /mnt -o username=me,password=hunter2"
            )),
            [(PASSWORD, Some("password"), "hunter2")]
        );
        for command in [
            "curl -H 'Authorization: Bearer $TOKEN' https://host/x",
            "curl -H 'Content-Type: application/json' https://host/x",
            "curl -H 'Accept: text/plain' https://host/x",
            "echo note: token rotation is due",
            "curl 'https://host/x?page=2&sort=key'",
        ] {
            assert_eq!(in_command(command), [], "{command}");
        }
    }

    #[test]
    fn a_format_names_a_secret_that_a_position_also_found() {
        let token = made("ghp_", 36);
        assert_eq!(
            kinds(&in_command(&format!("GITHUB_TOKEN={token} gh pr list"))),
            [("github-token", Some("GITHUB_TOKEN"), token.as_str())]
        );
        assert_eq!(
            kinds(&in_command(&format!(
                "git clone https://x-access-token:{token}@github.com/a/b"
            ))),
            [("github-token", Some("https:// URL"), token.as_str())]
        );
        assert_eq!(
            kinds(&in_command(&format!(
                "cat > .env <<EOF\nGITHUB_TOKEN={token}\nEOF"
            ))),
            [("github-token", None, token.as_str())]
        );
    }

    #[test]
    fn a_generated_value_after_a_secret_named_word_is_found() {
        let value = made("", 40);
        for (command, name) in [
            (
                format!("aws configure set aws_secret_access_key {value}"),
                "aws_secret_access_key",
            ),
            (
                format!("npm config set //registry.internal/:_authToken {value}"),
                "_authToken",
            ),
        ] {
            assert_eq!(
                kinds(&in_command(&command)),
                [(PASSWORD, Some(name), value.as_str())],
                "{command}"
            );
        }
        // A word that is not generated is not taken for one.
        assert_eq!(in_command("git config user.password prompt"), []);
        assert_eq!(in_command("vault kv get secret database/config"), []);
    }

    #[test]
    fn words_already_split_are_read_as_one_command() {
        let words: Vec<String> = ["npx", "server", "--api-key", "hunter2"]
            .iter()
            .map(|word| (*word).to_owned())
            .collect();
        assert_eq!(
            kinds(&in_words(&words)),
            [(PASSWORD, Some("--api-key"), "hunter2")]
        );
    }

    #[test]
    fn every_format_has_a_listed_kind() {
        for format in FORMATS {
            assert!(KINDS.contains(&format.kind), "{}", format.kind);
        }
    }
}
