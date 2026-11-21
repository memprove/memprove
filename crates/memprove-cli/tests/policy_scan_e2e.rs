//! `memprove policy scan`, through the real `memprove`: it reads the files
//! agents write in a repository, names each secret by file, line and kind
//! without printing it, says what Git does with the file, and exits 1 when
//! it finds one. Every secret here is made up in this file.

#[path = "u1e_support/mod.rs"]
mod support;

use std::{fs, path::Path, process::Output};

use memprove_protocol::strict_json::{JsonValue, parse_strict};
use support::{cli_binary, git, isolated, short_tempdir, text};

fn memprove(directory: &Path, args: &[&str]) -> Output {
    let output = isolated(cli_binary())
        .current_dir(directory)
        .env("HOME", directory.join("home"))
        .args(args)
        .output()
        .unwrap();
    println!(
        "$ memprove {}\n{}{}[exit {:?}]",
        args.join(" "),
        text(&output.stdout),
        text(&output.stderr),
        output.status.code()
    );
    output
}

/// A token of GitHub's format that GitHub never issued.
fn made_token() -> String {
    let body: String = "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"
        .chars()
        .cycle()
        .take(36)
        .collect();
    format!("ghp_{body}")
}

const PASSWORD: &str = "s3cr3t-Value";

/// A repository with a committed `.mcp.json` that holds a token, an ignored
/// `.claude/settings.local.json` whose allowed command holds a password, an
/// untracked `CLAUDE.md` that quotes the same command, and a clean
/// `AGENTS.md`.
fn repo() -> (tempfile::TempDir, std::path::PathBuf) {
    let (guard, root) = short_tempdir();
    let repo = root.join("repo");
    fs::create_dir_all(repo.join(".claude")).unwrap();
    git(&root, &["init", "-q", "repo"]);
    fs::write(
        repo.join(".mcp.json"),
        format!(
            "{{\n  \"mcpServers\": {{\n    \"github\": {{\n      \"command\": \"npx\",\n      \
             \"args\": [\"-y\", \"server-github\"],\n      \"env\": {{\"GITHUB_TOKEN\": \
             \"{}\"}}\n    }}\n  }}\n}}\n",
            made_token()
        ),
    )
    .unwrap();
    fs::write(repo.join("AGENTS.md"), "# Rules\n\n- Use `$PGPASSWORD`.\n").unwrap();
    git(&repo, &["add", ".mcp.json", "AGENTS.md"]);
    git(&repo, &["commit", "-q", "-m", "settings"]);
    fs::write(
        repo.join(".claude/settings.local.json"),
        format!(
            "{{\n  \"permissions\": {{\n    \"allow\": [\n      \"Bash(git status)\",\n      \
             \"Bash(PGPASSWORD={PASSWORD} psql -h db.internal -U app:*)\"\n    ]\n  }}\n}}\n"
        ),
    )
    .unwrap();
    fs::write(
        repo.join(".git/info/exclude"),
        ".claude/settings.local.json\n",
    )
    .unwrap();
    fs::write(
        repo.join("CLAUDE.md"),
        format!("# Notes\n\nConnect with `PGPASSWORD={PASSWORD} psql -h db.internal`.\n"),
    )
    .unwrap();
    (guard, repo)
}

#[test]
fn scan_names_each_secret_by_file_line_and_kind_and_never_prints_it() {
    let (_guard, repo) = repo();
    let scanned = memprove(&repo, &["policy", "scan"]);
    assert_eq!(scanned.status.code(), Some(1));
    let out = text(&scanned.stdout);
    for line in [
        ".claude/settings.local.json:5: password in PGPASSWORD: s3c…(12 characters) (file \
         ignored by Git)",
        "    at permissions.allow[1]",
        ".mcp.json:6: github-token in GITHUB_TOKEN: ghp_…(40 characters) (file tracked by Git)",
        "    at mcpServers.github.env.GITHUB_TOKEN",
        "CLAUDE.md:3: password in PGPASSWORD: s3c…(12 characters) (file not tracked and not \
         ignored)",
        "3 secrets in 3 of 4 files read; 1 in files Git tracks",
    ] {
        assert!(
            out.lines().any(|printed| printed.starts_with(line)),
            "no line `{line}` in:\n{out}"
        );
    }
    let all = format!("{out}{}", text(&scanned.stderr));
    assert!(!all.contains(PASSWORD) && !all.contains(&made_token()));

    // From a subdirectory the repository is the same.
    fs::create_dir_all(repo.join("src/deep")).unwrap();
    let below = memprove(&repo.join("src/deep"), &["policy", "scan"]);
    assert_eq!(below.status.code(), Some(1));
    assert!(text(&below.stdout).contains(".mcp.json:6: github-token"));
}

#[test]
fn scan_json_gives_the_findings_without_the_values() {
    let (_guard, repo) = repo();
    let scanned = memprove(&repo, &["policy", "scan", "--json"]);
    assert_eq!(scanned.status.code(), Some(1));
    let out = text(&scanned.stdout);
    assert!(!out.contains(PASSWORD) && !out.contains(&made_token()));
    let value = parse_strict(&out).unwrap();
    let string = |value: &JsonValue, name: &str| {
        value
            .get(name)
            .and_then(JsonValue::as_str)
            .map(str::to_owned)
    };
    assert_eq!(
        string(&value, "schema").as_deref(),
        Some("memprove.policy.scan.v1")
    );
    assert_eq!(value.get("files_read").unwrap().as_i64(), Some(4));
    let findings = value.get("findings").unwrap().as_array().unwrap();
    let rows: Vec<(String, i64, String, String, String, i64)> = findings
        .iter()
        .map(|finding| {
            (
                string(finding, "path").unwrap(),
                finding.get("line").unwrap().as_i64().unwrap(),
                string(finding, "kind").unwrap(),
                string(finding, "name").unwrap(),
                string(finding, "git").unwrap(),
                finding.get("length").unwrap().as_i64().unwrap(),
            )
        })
        .collect();
    let row = |path: &str, line: i64, kind: &str, name: &str, git: &str, length: i64| {
        (
            path.to_owned(),
            line,
            kind.to_owned(),
            name.to_owned(),
            git.to_owned(),
            length,
        )
    };
    assert_eq!(
        rows,
        [
            row(
                ".claude/settings.local.json",
                5,
                "password",
                "PGPASSWORD",
                "ignored",
                12
            ),
            row(
                ".mcp.json",
                6,
                "github-token",
                "GITHUB_TOKEN",
                "tracked",
                40
            ),
            row("CLAUDE.md", 3, "password", "PGPASSWORD", "untracked", 12),
        ]
    );
    assert_eq!(
        string(&findings[0], "place").as_deref(),
        Some("permissions.allow[1]")
    );
    assert_eq!(
        string(&findings[0], "redacted").as_deref(),
        Some("s3c…(12 characters)")
    );
    assert_eq!(findings[2].get("place"), Some(&JsonValue::Null));
}

#[test]
fn scan_exits_0_when_it_finds_nothing_and_reads_the_paths_it_is_given() {
    let (_guard, repo) = repo();
    for file in [".mcp.json", ".claude/settings.local.json", "CLAUDE.md"] {
        fs::remove_file(repo.join(file)).unwrap();
    }
    let clean = memprove(&repo, &["policy", "scan"]);
    assert_eq!(clean.status.code(), Some(0));
    assert!(text(&clean.stdout).contains("no secret found in 1 file read"));

    // A path that is not an agent file is read when it is named: a file, or
    // a directory with what is below it.
    fs::create_dir_all(repo.join("ops/notes")).unwrap();
    fs::write(
        repo.join("ops/notes/deploy.sh"),
        format!("#!/bin/sh\nsshpass -p '{PASSWORD}' ssh deploy@host uptime\n"),
    )
    .unwrap();
    let still_clean = memprove(&repo, &["policy", "scan"]);
    assert_eq!(still_clean.status.code(), Some(0));
    for target in ["ops", "ops/notes/deploy.sh"] {
        let named = memprove(&repo, &["policy", "scan", target]);
        assert_eq!(named.status.code(), Some(1), "{target}");
        let out = text(&named.stdout);
        assert!(
            out.contains("ops/notes/deploy.sh:2: password in sshpass -p: s3c…(12 characters)"),
            "{out}"
        );
        assert!(!out.contains(PASSWORD));
    }

    let missing = memprove(&repo, &["policy", "scan", "no/such/file"]);
    assert_eq!(missing.status.code(), Some(3));
    assert!(text(&missing.stderr).contains("does not exist"));
    let unknown = memprove(&repo, &["policy", "scan", "--fix"]);
    assert_eq!(unknown.status.code(), Some(2));
}

#[test]
fn scan_works_where_there_is_no_repository_and_no_agent_file() {
    let (_guard, root) = short_tempdir();
    let empty = memprove(&root, &["policy", "scan"]);
    assert_eq!(empty.status.code(), Some(0));
    assert!(text(&empty.stdout).contains("no agent settings or instruction file found here"));

    fs::write(
        root.join(".cursorrules"),
        format!("Use MYSQL_PWD={PASSWORD} for the staging database.\n"),
    )
    .unwrap();
    let found = memprove(&root, &["policy", "scan"]);
    assert_eq!(found.status.code(), Some(1));
    let out = text(&found.stdout);
    // Git has no answer here, so nothing is said about it.
    assert!(
        out.lines()
            .any(|line| line == ".cursorrules:1: password in MYSQL_PWD: s3c…(12 characters)"),
        "{out}"
    );
}
