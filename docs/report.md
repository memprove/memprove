# memprove report

`memprove report` tells you what one coding-agent session in this repository did: what it cost, which tools it
called, which calls `memprove policy` refused or sent to a person, and which memprove statements the agent read,
with the facts that were not verified when it read them. It reads files on this machine only: the client's own
transcript of the session and the repository's policy log. It writes nothing, sends nothing anywhere, and calls no
daemon unless you pass `--now`.

```bash
memprove report                 # the most recently active Claude Code or Codex session of this repository
memprove report --list          # the 10 most recently active sessions, one line each
memprove report 5d0c2a4e        # the session whose id starts with 5d0c2a4e
memprove report --json          # the same as JSON (memprove.report.session.v1)
```

```text
memprove report: claude-code session 5d0c2a4e-1111-4222-8333-944455556666
  2026-11-16 10:00 to 10:05 UTC (5 min) · claude-code 2.1.326 · branch main
  repository /home/me/src/parser
  transcript /home/me/.claude/projects/-home-me-src-parser/5d0c2a4e-….jsonl (+1 sub-agent transcript)

Cost: $0.0166 (estimated at list prices; a subscription is not billed per token)
  model                      requests    input  cache write  cache read   output       cost
  claude-haiku-4-5-20251001         1      100            0           0       50    $0.0004
  claude-opus-5-5                   2       15         1.0k       11.0k      300    $0.0163
  prices: Anthropic API list prices, platform.claude.com/docs/en/about-claude/pricing, read 2026-11-17

Tool calls: 3, 1 failed
  Bash 1, Edit 1 (1 failed), Read 1

Policy: 2 refused, 1 sent to a person (/home/me/src/parser/.git/memprove-policy/log.jsonl)
  10:01:00  refused  Bash  git push --force (line 3: deny Bash(git push *--force*))
  10:02:00  asked    Bash  git push origin main (line 4: ask Bash(git push *))
  10:05:04  refused  Bash  git push --force (line 3: deny Bash(git push *--force*))

Memory: read 1 Pack (hook), 4 statements; 1 fact not verified when read
  #2 stale (head_changed): 「cargo test passes」
```

## Where sessions are found

| client | transcripts | the session's repository |
|---|---|---|
| Claude Code | `$CLAUDE_CONFIG_DIR/projects/` or `~/.claude/projects/`, one `<session id>.jsonl` per session, sub-agents in `<session id>/subagents/` | the directory the session started in |
| Codex | `$CODEX_HOME/sessions/` or `~/.codex/sessions/`, `YYYY/MM/DD/rollout-<time>-<thread id>.jsonl` (`.jsonl.zst` is read with `zstd`) | the `cwd` of its `session_meta` |

A session belongs to the repository when it started in the repository's root or below it (the first directory
its transcript records). `--client claude-code`
or `--client codex` looks at one client only; `--transcript <FILE>` reports one transcript file wherever it is.
Cursor keeps no transcript on disk that `memprove report` can read, so it is not supported.

Sessions are ordered by their last record's time, the most recently active first, not by when their files changed
(a copied or synced transcript keeps its records' times). A compressed rollout is ordered by its file's time. The
report's first line and each `--list` row give the session's first and last record: a session that was resumed
later spans the time it was idle, so the span is not the time the agent worked. A row's last column says what the
agent was given from memprove: `nothing read`, the facts it read that were not verified, and the Packs of a format
this version does not read.

```text
Sessions of /home/me/src/parser (2 of 2, the most recently active first):
  last record UTC         span  client       session   models  requests  cost  tool calls  policy  memory
  2026-11-16 11:02       2 min  codex        019a7f00  gpt-5.6-terra  2 requests  unknown  2 tool calls  0 refused  1 unverified fact read
  2026-11-16 10:05       5 min  claude-code  5d0c2a4e  claude-haiku-4-5-20251001,claude-opus-5-5  3 requests  $0.0166  3 tool calls  2 refused  1 unverified fact read
```

## What each part means

- **Cost.** Model requests and tokens per model, from the transcript. Claude Code writes one line per content block
  of a reply, each with the reply's whole usage; a reply is counted once, by its message id, and messages Claude Code
  wrote itself (`<synthetic>`) are not requests. Sub-agents' transcripts are added. Codex writes running totals; each
  increase is one request of the model its last turn named, and its input tokens include the cached ones. The cost
  is an estimate at list prices: Anthropic's models are built in (cache writes of 5 minutes and 1 hour, cache reads,
  fast mode, US-only inference, and the long-prompt price of Claude Haiku 5.5); other models are `unknown` until a
  price file names them. A subscription is not billed per token, so on one the cost is what the same tokens would
  cost on the API.
- **Tool calls.** Each tool call by its tool's name (MCP tools as `mcp__<server>__<tool>`), and for Claude Code the
  ones whose result was an error. Codex does not record which calls failed, so its report gives no failure count.
- **Policy.** The records of `<git common dir>/memprove-policy/log.jsonl` (see [`policy.md`](policy.md)) of the
  session's client from the session's first timestamp to five seconds after its last. The log names no session, so
  two sessions of one client running in one repository at the same time each count the other's records too.
- **Memory.** The memprove statements the agent was given: the `SessionStart` hook's Context Pack, the answers of
  memprove's MCP tools, and the output of `memprove` commands the agent ran (`memprove resume --pack`,
  `memprove claims`, …), each statement as last read. Claude Code records what a hook printed and the context it
  made of it as two records; one run of a hook is one read. A statement's text is shown as its line quotes it,
  with the line's escapes (`\」`, `\n`). This version reads Packs of the format `memprove-pack v1`: a Pack whose
  first line names another format is counted as `not read`, and none of its lines is read. The facts listed are those in force whose verdict was not
  `verified` when the agent read them (`stale`, `unconfirmed`, `tampered`). Other output that merely mentions
  memprove is not read.
- **`--now`.** Also reads, without writing anything, the statements memprove would give a new session in the
  repository now (the same read-only requests as `memprove eval`), and lists the facts the agent read as verified
  that are not verified now. Without a daemon or a memprove context it says so and still reports the rest.

## Price file

`--prices <FILE>` adds prices, or replaces the built-in ones, in dollars per million tokens, one model per line; a
`*` matches any run of characters, and the first matching line wins:

```text
# OpenAI list prices
gpt-5.6-*        input=1.25 output=10 cache_read=0.125
claude-opus-5-5  input=4 output=20 cache_read=0.40 cache_write=5 cache_write_1h=8
```

`cache_read` and `cache_write` default to `input`, and `cache_write_1h` to `cache_write`. The built-in modifiers
(fast mode, US-only) apply to the built-in prices only.

## JSON

`--json` prints `memprove.report.session.v1`: `client`, `session_id`, `repository`, `cwd`, `client_version`,
`branch`, `started_at`, `ended_at`, `transcripts`, `models` (per model: `requests`, the five token counts,
`cost_microusd` or `null`, `price_source`), `total` (with `cost_complete`), `tool_calls`, `tool_failures` (`null` for
Codex), `tools`, `policy` (`log`, `refused`, `asked`, `records`), `memory` (`packs`, `unread_packs`, `reads`,
`statements`, `unverified_facts`, `now`) and `unreadable_lines`. `--list --json` prints `memprove.report.list.v1`,
one summary per session.

## Exit status

| code | meaning |
|---|---|
| 0 | the report or the listing was printed |
| 1 | no session was found, or its transcript cannot be read |
| 2 | a usage error, or the price file cannot be read |
