//! `memprove report` over made-up transcripts of both clients in a
//! throwaway home: the session is found by its repository, a message
//! written over several lines is counted once, sub-agents add their tokens
//! and calls, the policy log's records of the session's client and time are
//! its own, and the statements the agent read are listed with the facts
//! that were not verified.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use memprove_policy::log::{Record, append};
use memprove_protocol::strict_json::{JsonValue, parse_strict};
use memprove_report::{
    CurrentStatement, Present,
    cli::{EXIT_NOT_FOUND, EXIT_OK, EXIT_USAGE, Env, run},
    find::{Homes, claude_dir_name},
};

const CLAUDE_ID: &str = "5d0c2a4e-1111-4222-8333-944455556666";
const CODEX_ID: &str = "019a7f00-aaaa-7bbb-8ccc-0d0e0f101112";

const PACK: &str = "memprove: the current Task is「Fix the parser」.\n\
Pack: memprove-pack v1; capsule_digest sha256:aa; ledger sequence 12; HEAD 1234567; budget 9000 UTF-16 code units\n\
Task「Fix the parser」 (in_progress): stale (head_changed); statements: 3 active, 0 superseded, 0 withdrawn\n\
#1 verified: 「The tokenizer keeps quotes」 (evidence bound to commit 1234567; from Session 1)\n\
#2 fact stale: 「cargo test passes」 (reasons: head_changed; evidence bound to commit 89abcde; from Session 1)\n\
#3 open item: 「Escapes in heredocs are not read」 (no evidence cited; from Session 2)\n\
Digest: sha256:bb\n";

struct Fixture {
    _guard: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
}

fn fixture() -> Fixture {
    let guard = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(guard.path()).unwrap();
    let repo = base.join("repo");
    let home = base.join("home");
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(&home).unwrap();
    let status = Command::new("git")
        .args(["init", "-q"])
        .arg(&repo)
        .status()
        .unwrap();
    assert!(status.success());
    Fixture {
        _guard: guard,
        repo,
        home,
    }
}

fn env(fixture: &Fixture, cwd: &Path) -> Env {
    Env {
        cwd: cwd.to_owned(),
        homes: Homes {
            claude: Some(fixture.home.join(".claude")),
            codex: Some(fixture.home.join(".codex")),
        },
    }
}

fn quoted(text: &str) -> String {
    memprove_policy::json::string(text)
}

/// A Claude Code session in `repo`, 10:00:00 to 10:05:00.5: two model
/// requests (the first written as three lines), a synthetic message, a
/// `memprove claims` call, a failed Edit, the hook's Pack, a Pack of
/// another format, and a sub-agent.
fn write_claude(fixture: &Fixture) -> PathBuf {
    let cwd = quoted(&fixture.repo.join("src").to_string_lossy());
    let header =
        format!(r#""cwd":{cwd},"version":"2.1.326","gitBranch":"main","sessionId":"{CLAUDE_ID}""#);
    let usage1 = r#"{"input_tokens":10,"cache_creation_input_tokens":1000,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":1000},"cache_read_input_tokens":5000,"output_tokens":200}"#;
    let usage2 = r#"{"input_tokens":5,"cache_creation_input_tokens":0,"cache_read_input_tokens":6000,"output_tokens":100}"#;
    let claims = "#2 fact stale: 「cargo test passes」 (reasons: head_changed; evidence bound to commit 89abcde; from Session 1)\n\
#4 verified: 「The lexer is in src/lex.rs」 (evidence bound to commit 1234567; from Session 3)\n";
    let lines = [
        format!(
            r#"{{"type":"user",{header},"timestamp":"2026-11-16T10:00:00.000Z","message":{{"role":"user","content":"fix the parser"}}}}"#
        ),
        // Claude Code writes what the SessionStart hook printed, and the
        // context it made of it, as two records: one read, not two.
        format!(
            r#"{{"type":"attachment",{header},"timestamp":"2026-11-16T10:00:00.100Z","attachment":{{"type":"hook_success","hookName":"SessionStart:startup","hookEvent":"SessionStart","content":"","stdout":{},"stderr":"","exitCode":0}}}}"#,
            quoted(PACK)
        ),
        format!(
            r#"{{"type":"attachment",{header},"timestamp":"2026-11-16T10:00:00.150Z","attachment":{{"type":"hook_additional_context","hookName":"SessionStart","hookEvent":"SessionStart","content":"[]","heldContent":[{}]}}}}"#,
            quoted(PACK)
        ),
        // A hook of another event that printed a statement line: its plain
        // output is not given to the agent.
        format!(
            r#"{{"type":"attachment",{header},"timestamp":"2026-11-16T10:00:00.200Z","attachment":{{"type":"hook_success","hookName":"PostToolUse:Bash","hookEvent":"PostToolUse","content":"","stdout":{},"stderr":"","exitCode":0}}}}"#,
            quoted(
                "#9 fact stale: 「not given to the agent」 (reasons: head_changed; from Session 1)\n"
            )
        ),
        // A Pack of a format this version does not read: counted, and none
        // of its lines is a statement read.
        format!(
            r#"{{"type":"attachment",{header},"timestamp":"2026-11-16T10:00:00.300Z","attachment":{{"type":"hook_success","hookName":"UserPromptSubmit","hookEvent":"UserPromptSubmit","content":"","stdout":{},"stderr":"","exitCode":0}}}}"#,
            quoted(
                "Pack: memprove-pack v2; HEAD 1234567\n#8 fact stale: 「of a later grammar」 (reasons: head_changed; from Session 1)\nDigest: sha256:cc\n"
            )
        ),
        format!(
            r#"{{"type":"assistant",{header},"requestId":"req_1","timestamp":"2026-11-16T10:00:05.000Z","message":{{"model":"claude-opus-5-5","id":"msg_1","role":"assistant","content":[{{"type":"thinking","thinking":""}}],"usage":{usage1}}}}}"#
        ),
        format!(
            r#"{{"type":"assistant",{header},"requestId":"req_1","timestamp":"2026-11-16T10:00:05.100Z","message":{{"model":"claude-opus-5-5","id":"msg_1","role":"assistant","content":[{{"type":"tool_use","id":"toolu_1","name":"Bash","input":{{"command":"cd src && memprove claims"}}}}],"usage":{usage1}}}}}"#
        ),
        format!(
            r#"{{"type":"assistant",{header},"requestId":"req_1","timestamp":"2026-11-16T10:00:05.200Z","message":{{"model":"claude-opus-5-5","id":"msg_1","role":"assistant","content":[{{"type":"tool_use","id":"toolu_2","name":"Edit","input":{{"file_path":"/x"}}}}],"usage":{usage1}}}}}"#
        ),
        format!(
            r#"{{"type":"user",{header},"timestamp":"2026-11-16T10:00:09.000Z","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"toolu_1","content":{}}},{{"type":"tool_result","tool_use_id":"toolu_2","is_error":true,"content":"File has not been read yet"}}]}}}}"#,
            quoted(claims)
        ),
        "not json".to_owned(),
        format!(
            r#"{{"type":"assistant",{header},"timestamp":"2026-11-16T10:01:00.000Z","message":{{"model":"<synthetic>","id":"msg_x","role":"assistant","content":[{{"type":"text","text":"API Error"}}],"usage":{{"input_tokens":0,"output_tokens":0}}}}}}"#
        ),
        format!(
            r#"{{"type":"assistant",{header},"requestId":"req_2","timestamp":"2026-11-16T10:05:00.500Z","message":{{"model":"claude-opus-5-5","id":"msg_2","role":"assistant","content":[{{"type":"text","text":"done"}}],"usage":{usage2}}}}}"#
        ),
    ];
    let dir = fixture
        .home
        .join(".claude/projects")
        .join(claude_dir_name(&fixture.repo.join("src")));
    fs::create_dir_all(dir.join(CLAUDE_ID).join("subagents")).unwrap();
    let path = dir.join(format!("{CLAUDE_ID}.jsonl"));
    fs::write(&path, lines.join("\n") + "\n").unwrap();
    let agent = format!(
        r#"{{"type":"assistant","isSidechain":true,"cwd":{cwd},"timestamp":"2026-11-16T10:02:00.000Z","message":{{"model":"claude-haiku-4-5-20251001","id":"msg_a","role":"assistant","content":[{{"type":"tool_use","id":"toolu_a","name":"Read","input":{{"file_path":"/y"}}}}],"usage":{{"input_tokens":100,"output_tokens":50}}}}}}"#
    );
    fs::write(
        dir.join(CLAUDE_ID).join("subagents/agent-a1.jsonl"),
        agent + "\n",
    )
    .unwrap();
    path
}

/// A Codex rollout in `repo`, 11:00:00 to 11:02:00: two requests from
/// running totals (one repeated), `memprove resume --pack` through
/// `exec_command`, and an MCP call.
fn write_codex(fixture: &Fixture) -> PathBuf {
    let cwd = quoted(&fixture.repo.to_string_lossy());
    let totals = |input: u64, cached: u64, output: u64| {
        format!(
            r#"{{"input_tokens":{input},"cached_input_tokens":{cached},"output_tokens":{output},"reasoning_output_tokens":0,"total_tokens":{}}}"#,
            input + output
        )
    };
    let lines = [
        format!(
            r#"{{"timestamp":"2026-11-16T11:00:00.000Z","type":"session_meta","payload":{{"id":"{CODEX_ID}","cwd":{cwd},"cli_version":"0.130.0","git":{{"branch":"main"}}}}}}"#
        ),
        format!(
            r#"{{"timestamp":"2026-11-16T11:00:00.100Z","type":"turn_context","payload":{{"cwd":{cwd},"model":"gpt-5.6-terra"}}}}"#
        ),
        r#"{"timestamp":"2026-11-16T11:00:10.000Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"memprove resume --pack\"}","call_id":"call_1"}}"#.to_owned(),
        format!(
            r#"{{"timestamp":"2026-11-16T11:00:11.000Z","type":"response_item","payload":{{"type":"function_call_output","call_id":"call_1","output":{}}}}}"#,
            quoted(PACK)
        ),
        format!(
            r#"{{"timestamp":"2026-11-16T11:00:12.000Z","type":"event_msg","payload":{{"type":"token_count","info":{{"total_token_usage":{},"last_token_usage":{}}}}}}}"#,
            totals(1000, 800, 50),
            totals(1000, 800, 50)
        ),
        r#"{"timestamp":"2026-11-16T11:01:00.000Z","type":"response_item","payload":{"type":"function_call","name":"search","namespace":"mcp__docs__","arguments":"{}","call_id":"call_2"}}"#.to_owned(),
        format!(
            r#"{{"timestamp":"2026-11-16T11:01:30.000Z","type":"event_msg","payload":{{"type":"token_count","info":{{"total_token_usage":{}}}}}}}"#,
            totals(1000, 800, 50)
        ),
        format!(
            r#"{{"timestamp":"2026-11-16T11:02:00.000Z","type":"event_msg","payload":{{"type":"token_count","info":{{"total_token_usage":{}}}}}}}"#,
            totals(3000, 2500, 80)
        ),
    ];
    let dir = fixture.home.join(".codex/sessions/2026/11/16");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("rollout-2026-11-16T11-00-00-{CODEX_ID}.jsonl"));
    fs::write(&path, lines.join("\n") + "\n").unwrap();
    path
}

fn write_policy_log(fixture: &Fixture) {
    for (time, client, sent) in [
        ("2026-11-16T09:59:59Z", "claude-code", "deny"),
        ("2026-11-16T10:01:00Z", "claude-code", "deny"),
        ("2026-11-16T10:02:00Z", "claude-code", "ask"),
        ("2026-11-16T10:03:00Z", "codex", "deny"),
        ("2026-11-16T10:05:04Z", "claude-code", "deny"),
        ("2026-11-16T10:05:07Z", "claude-code", "deny"),
    ] {
        append(
            &fixture.repo,
            &Record {
                time: time.to_owned(),
                client: client.to_owned(),
                tool: "Bash".to_owned(),
                subject: "git push --force".to_owned(),
                decision: sent.to_owned(),
                sent: sent.to_owned(),
                line: Some(3),
                rule: Some("deny Bash(git push *--force*)".to_owned()),
            },
        )
        .unwrap();
    }
}

fn report(env: &Env, words: &[&str], present: Option<&dyn Present>) -> (u8, String, String) {
    let words: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(&words, env, present, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn number(value: &JsonValue, path: &[&str]) -> i64 {
    let mut at = value;
    for name in path {
        at = at
            .get(name)
            .unwrap_or_else(|| panic!("no {name} in {path:?}"));
    }
    at.as_i64()
        .unwrap_or_else(|| panic!("{path:?} is not a number"))
}

fn text_at<'a>(value: &'a JsonValue, name: &str) -> &'a str {
    value
        .get(name)
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
}

#[test]
fn a_claude_code_session_reports_cost_tools_policy_and_memory() {
    let fixture = fixture();
    let transcript = write_claude(&fixture);
    write_codex(&fixture);
    write_policy_log(&fixture);
    let env = env(&fixture, &fixture.repo.join("src"));

    let (code, out, err) = report(&env, &[&CLAUDE_ID[..8], "--json"], None);
    assert_eq!(code, EXIT_OK, "{err}");
    let value = parse_strict(&out).unwrap();
    assert_eq!(text_at(&value, "schema"), "memprove.report.session.v1");
    assert_eq!(text_at(&value, "session_id"), CLAUDE_ID);
    assert_eq!(
        text_at(&value, "repository"),
        fixture.repo.to_string_lossy()
    );
    assert_eq!(text_at(&value, "started_at"), "2026-11-16T10:00:00.000Z");
    assert_eq!(text_at(&value, "ended_at"), "2026-11-16T10:05:00.500Z");
    assert_eq!(number(&value, &["subagent_transcripts"]), 1);
    assert_eq!(number(&value, &["unreadable_lines"]), 1);

    // msg_1 is three lines but one request; the synthetic message is none.
    assert_eq!(number(&value, &["total", "requests"]), 3);
    assert_eq!(number(&value, &["total", "cache_write_1h_tokens"]), 1000);
    assert_eq!(number(&value, &["total", "cache_read_tokens"]), 11_000);
    assert_eq!(number(&value, &["total", "output_tokens"]), 350);
    // Opus 5.5: 10×$4 + 1000×$8 + 11000×$0.20 + 300×$20 + 5×$4 per MTok =
    // $0.01626; Haiku 4.5: 100×$1 + 50×$5 = $0.00035.
    assert_eq!(number(&value, &["total", "cost_microusd"]), 16_610);
    let models = value.get("models").and_then(JsonValue::as_array).unwrap();
    let names: Vec<&str> = models.iter().map(|row| text_at(row, "model")).collect();
    assert_eq!(names, ["claude-haiku-4-5-20251001", "claude-opus-5-5"]);

    assert_eq!(number(&value, &["tool_calls"]), 3);
    assert_eq!(number(&value, &["tool_failures"]), 1);
    let tools = value.get("tools").and_then(JsonValue::as_array).unwrap();
    let edit = tools
        .iter()
        .find(|tool| text_at(tool, "name") == "Edit")
        .unwrap();
    assert_eq!(number(edit, &["failed"]), 1);

    // Its client's records from 10:00:00 to 5 s after 10:05:00.5.
    assert_eq!(number(&value, &["policy", "refused"]), 2);
    assert_eq!(number(&value, &["policy", "asked"]), 1);

    // The hook's Pack, then `memprove claims` (which adds #4); #2 stale.
    assert_eq!(number(&value, &["memory", "reads"]), 2);
    let packs = value
        .get("memory")
        .and_then(|memory| memory.get("packs"))
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(packs.len(), 1);
    assert_eq!(text_at(&packs[0], "source"), "hook");
    assert_eq!(text_at(&packs[0], "task"), "Fix the parser");
    let unread = value
        .get("memory")
        .and_then(|memory| memory.get("unread_packs"))
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(unread.len(), 1);
    assert_eq!(text_at(&unread[0], "format"), "memprove-pack v2");
    assert_eq!(number(&unread[0], &["packs"]), 1);
    let statements = value
        .get("memory")
        .and_then(|memory| memory.get("statements"))
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(statements.len(), 4);
    let unverified = value
        .get("memory")
        .and_then(|memory| memory.get("unverified_facts"))
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(unverified.len(), 1);
    assert_eq!(number(&unverified[0], &["number"]), 2);
    assert_eq!(text_at(&unverified[0], "source"), "Bash");

    // The text report says the same, and the transcript file gives it too.
    let (code, text, _) = report(&env, &["--transcript", &transcript.to_string_lossy()], None);
    assert_eq!(code, EXIT_OK);
    for expected in [
        "memprove report: claude-code session 5d0c2a4e-1111-4222-8333-944455556666",
        "2026-11-16 10:00 to 10:05 UTC (5 min) · claude-code 2.1.326 · branch main",
        "(+1 sub-agent transcript)",
        "Cost: $0.0166 (estimated at list prices",
        "Tool calls: 3, 1 failed",
        "Edit 1 (1 failed)",
        "Policy: 2 refused, 1 sent to a person",
        "10:01:00  refused  Bash  git push --force (line 3: deny Bash(git push *--force*))",
        "Memory: read 1 Pack (hook), 4 statements; 1 fact not verified when read",
        "#2 stale (head_changed): 「cargo test passes」",
        "  not read: 1 Pack of the format memprove-pack v2\n",
    ] {
        assert!(text.contains(expected), "{expected}\n---\n{text}");
    }
    assert!(!text.contains("10:05:07"), "{text}");
}

#[test]
fn a_codex_session_counts_running_totals_and_says_failures_are_not_recorded() {
    let fixture = fixture();
    write_claude(&fixture);
    write_codex(&fixture);
    write_policy_log(&fixture);
    let env = env(&fixture, &fixture.repo);

    let (code, out, err) = report(&env, &["--client", "codex", "--json"], None);
    assert_eq!(code, EXIT_OK, "{err}");
    let value = parse_strict(&out).unwrap();
    assert_eq!(text_at(&value, "session_id"), CODEX_ID);
    assert_eq!(text_at(&value, "client_version"), "0.130.0");
    // Two increases of the running total; the repeated total is none.
    assert_eq!(number(&value, &["total", "requests"]), 2);
    assert_eq!(number(&value, &["total", "input_tokens"]), 500);
    assert_eq!(number(&value, &["total", "cache_read_tokens"]), 2500);
    assert_eq!(number(&value, &["total", "output_tokens"]), 80);
    // No built-in price for an OpenAI model.
    assert_eq!(
        value
            .get("total")
            .and_then(|total| total.get("cost_microusd")),
        Some(&JsonValue::Null)
    );
    assert_eq!(value.get("tool_failures"), Some(&JsonValue::Null));
    assert_eq!(number(&value, &["tool_calls"]), 2);
    let tools = value.get("tools").and_then(JsonValue::as_array).unwrap();
    assert!(
        tools
            .iter()
            .any(|tool| text_at(tool, "name") == "mcp__docs__search")
    );
    // The codex record at 10:03 is outside this session's time.
    assert_eq!(number(&value, &["policy", "refused"]), 0);
    assert_eq!(number(&value, &["memory", "reads"]), 1);

    let prices = fixture.home.join("prices.txt");
    fs::write(
        &prices,
        "# OpenAI list prices\ngpt-5.6-* input=1.25 output=10 cache_read=0.125\n",
    )
    .unwrap();
    let (code, text, err) = report(
        &env,
        &["--client", "codex", "--prices", &prices.to_string_lossy()],
        None,
    );
    assert_eq!(code, EXIT_OK, "{err}");
    // 500×$1.25 + 2500×$0.125 + 80×$10 per MTok = $0.0017375.
    assert!(text.contains("Cost: $0.0017 "), "{text}");
    assert!(text.contains("Tool calls: 2\n"), "{text}");
    assert!(
        text.contains("a codex transcript does not record which tool calls failed"),
        "{text}"
    );
}

#[test]
fn the_list_is_most_recently_active_first_and_errors_have_their_exit_codes() {
    let fixture = fixture();
    let claude = write_claude(&fixture);
    let codex = write_codex(&fixture);
    let env = env(&fixture, &fixture.repo);
    // The Codex session's last record (11:02) is later than the Claude Code
    // session's (10:05). The files' own times say the opposite (as after a
    // copy): the records decide.
    let earlier = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    for (path, age) in [(&codex, 3600), (&claude, 0)] {
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(earlier - std::time::Duration::from_secs(age))
            .unwrap();
    }

    let (code, out, _) = report(&env, &["--list"], None);
    assert_eq!(code, EXIT_OK);
    let mut lines = out.lines();
    assert!(
        lines
            .next()
            .is_some_and(|line| line.ends_with("(2 of 2, the most recently active first):")),
        "{out}"
    );
    assert!(
        lines
            .next()
            .is_some_and(|line| line.starts_with("  last record UTC ")),
        "{out}"
    );
    let rows: Vec<&str> = lines.collect();
    assert_eq!(rows.len(), 2, "{out}");
    assert!(
        rows[0].starts_with("  2026-11-16 11:02       2 min  codex ")
            && rows[0].contains(&CODEX_ID[..8]),
        "{out}"
    );
    assert!(
        rows[1].starts_with("  2026-11-16 10:05       5 min  claude-code ")
            && rows[1].contains(&CLAUDE_ID[..8])
            && rows[1].ends_with("1 unverified fact read, 1 Pack not read (memprove-pack v2)"),
        "{out}"
    );
    // No session named: the most recently active one.
    let (code, out, _) = report(&env, &[], None);
    assert_eq!(code, EXIT_OK);
    assert!(out.starts_with("memprove report: codex session "), "{out}");

    let (code, out, _) = report(&env, &["--list", "--last", "1", "--json"], None);
    assert_eq!(code, EXIT_OK);
    let value = parse_strict(&out).unwrap();
    assert_eq!(text_at(&value, "schema"), "memprove.report.list.v1");
    let latest = &value.get("sessions").and_then(JsonValue::as_array).unwrap()[0];
    assert_eq!(number(latest, &["packs"]), 1);
    assert_eq!(number(latest, &["unread_packs"]), 0);
    assert_eq!(
        value
            .get("sessions")
            .and_then(JsonValue::as_array)
            .map(<[JsonValue]>::len),
        Some(1)
    );

    let (code, _, err) = report(&env, &["ffffffff"], None);
    assert_eq!(code, EXIT_NOT_FOUND);
    assert!(err.contains("ffffffff"), "{err}");
    let elsewhere = fixture.home.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let (code, _, err) = report(
        &Env {
            cwd: elsewhere,
            ..env.clone()
        },
        &[],
        None,
    );
    assert_eq!(code, EXIT_NOT_FOUND);
    assert!(
        err.contains("no claude-code or codex session found"),
        "{err}"
    );
    let (code, _, err) = report(&env, &["--last", "2"], None);
    assert_eq!(code, EXIT_USAGE);
    assert!(err.contains("--last goes with --list"), "{err}");
    let bad = fixture.home.join("bad-prices.txt");
    fs::write(&bad, "gpt-5 input=abc output=1\n").unwrap();
    let (code, _, err) = report(&env, &["--prices", &bad.to_string_lossy()], None);
    assert_eq!(code, EXIT_USAGE);
    assert!(
        err.contains("bad-prices.txt:1: `abc` is not a price"),
        "{err}"
    );
    let (code, out, _) = report(&env, &["--help"], None);
    assert_eq!(code, EXIT_OK);
    assert!(out.starts_with("memprove report:"));
}

struct Now(Vec<CurrentStatement>);

impl Present for Now {
    fn statements(&self, _: &Path) -> Result<Vec<CurrentStatement>, String> {
        Ok(self.0.clone())
    }
}

#[test]
fn now_names_the_facts_read_as_verified_that_are_not_verified_now() {
    let fixture = fixture();
    write_claude(&fixture);
    let env = env(&fixture, &fixture.repo);
    let now = Now(vec![
        CurrentStatement {
            label: "#1".to_owned(),
            kind: "fact".to_owned(),
            verdict: "stale".to_owned(),
            text: "The tokenizer keeps quotes".to_owned(),
        },
        CurrentStatement {
            label: "#4".to_owned(),
            kind: "fact".to_owned(),
            verdict: "verified".to_owned(),
            text: "The lexer is in src/lex.rs".to_owned(),
        },
    ]);
    let (code, out, _) = report(&env, &["--now"], Some(&now));
    assert_eq!(code, EXIT_OK);
    assert!(
        out.contains("now: 1 fact read as verified is not verified any more"),
        "{out}"
    );
    assert!(
        out.contains("#1 now stale: 「The tokenizer keeps quotes」"),
        "{out}"
    );
    // Without --now, memprove is not asked.
    let (_, out, _) = report(&env, &[], Some(&now));
    assert!(!out.contains("now:"), "{out}");
    let (_, json, _) = report(&env, &["--now", "--json"], Some(&now));
    let value = parse_strict(&json).unwrap();
    let stale = value
        .get("memory")
        .and_then(|memory| memory.get("now"))
        .and_then(|now| now.get("not_verified_now"))
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(stale.len(), 1);
    assert_eq!(number(&stale[0], &["number"]), 1);
}
