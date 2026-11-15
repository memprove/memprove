# memprove policy

`memprove policy` gives every coding agent in a repository one set of tool rules. The rules live in one committed file,
`.memprove/policy.rules`; before each tool call, Claude Code, Codex and Cursor run `memprove policy hook`, which
decides the call by the first rule that matches and refuses it, or has a person approve it. It runs on the developer's
machine, reads nothing but the hook's input and the policy file, and sends nothing anywhere.

```bash
memprove policy init                       # .memprove/policy.rules (starter rules) and each client's hook
memprove policy test                       # every `expect` line holds (run it in CI)
memprove policy check 'Bash(cd app && git push -f)'
memprove policy log                        # the last refusals and approvals asked for
```

Commit `.memprove/policy.rules`. The hooks `init` writes go into each developer's own client settings
(`.claude/settings.local.json`, `.codex/hooks.json`, `.cursor/hooks.json`, all kept out of Git through
`.git/info/exclude`), so each developer runs `memprove policy init` once; a second run changes nothing.

## Rules

```text
# <deny|ask|allow> <Bash|Read|Edit|Mcp>(<pattern>)  [-- what the agent is told]
allow Read(.env.example)
deny  Read(.env*)                  -- secrets stay out of the agent's context
deny  Bash(git push *--force*)     -- do not rewrite shared history; push a new branch
ask   Bash(git push *)
deny  Edit(db/migrations/**)       -- migrations are generated: run `make migration`
deny  Mcp(github.merge_*)
expect deny Bash(cd app && git push origin main --force)
expect ask  Bash(git push origin feature/x)
```

- **The first rule that matches decides** a check. A command line is several checks (`cd app && git push -f` is two
  commands; `cat .env` is a command and a read), and the call gets the strictest decision of its checks: `deny` over
  `ask` over `allow`.
- **`allow` never approves a call.** It only stops later rules from matching (`allow Read(.env.example)` before
  `deny Read(.env*)`). With no objection, the client's own permission settings decide as they would without memprove.
- **`ask`** has a person approve the call. A client that cannot ask from a hook refuses the call instead, and the
  agent is told to have a person run it or change the policy (see [Clients](#clients)).
- **`Bash(...)`** matches each simple command, its words joined by single spaces: `*` matches any run of characters,
  spaces too, and a pattern that ends in ` *` also matches without it (`git push *` matches `git push`). Claude Code's
  `git push:*` means the same.
- **`Read(...)` and `Edit(...)`** match paths: a pattern with no `/` is a name anywhere (`.env*`, `*.pem`), one with a
  `/` is below the repository root (`db/migrations/**`), `~/...` is below your home and `/...` is absolute. `*` stays in
  one directory and `**` matches any number of them. A rule on a directory covers what is in it, and a path is also
  checked where its symbolic links lead (a link to `.env` is `.env`).
- **`Mcp(server.tool)`** matches an MCP tool (`github.merge_pull_request`, `github.merge_*`, or `github` for every tool
  of that server).
- **`expect`** lines are tests of the file itself: `memprove policy test` decides each one as the hook would and exits
  1 if one does not hold, so a change that breaks a rule fails CI. `expect allow` holds when nothing refuses or asks.

## How a command line is read

The hook reads a command line the way a shell would, without running anything: `;`, `&&`, `||`, `|`, `&`, newlines,
quotes, heredocs, `$(...)`, backquotes and `<(...)`. It looks through `sudo`, `env`, `command`, `exec`, `nohup`,
`time`, `nice`, `timeout`, `xargs` and similar wrappers, `VAR=value` prefixes and Git's global options
(`git -C x push -f` is `git push -f`), and into `bash -c '...'`, `sh <<EOF`, `eval` and `find -exec`. It follows `cd`
and `pushd`, so `cd db && rm -rf migrations` changes `db/migrations`.

`Read` and `Edit` rules also cover what a command does to files: `cat`, `less`, `grep`, `head`, `cp` sources, `<` and
the like read; `>`, `>>`, `rm`, `mv`, `cp` targets, `sed -i`, `tee`, `touch`, `chmod`, `git rm`, `git checkout --`,
`git clean`, `find -delete` and the like change. `rm -r`, `git clean` and `find -delete` change a whole tree, so a
`deny` or `ask` rule on anything below it applies.

A command line that cannot be read in full (an unclosed quote, a substitution nested more than eight deep) is
treated as `ask`, as long as the policy has a `Bash`, `Read` or `Edit` rule.

## Built-in rules

Whatever the policy says, an agent's change to `.memprove/**`, `.claude/settings.json`, `.claude/settings.local.json`,
`.codex/hooks.json`, `.codex/config.toml`, `.cursor/hooks.json` or `.cursor/cli.json` needs a person: an agent does not
loosen its own rules. A policy file that cannot be read or parsed makes every call need a person until it is fixed,
and the agent is told which line is wrong.

## Clients

| client | hook `init` writes | what it can do |
|---|---|---|
| Claude Code | `PreToolUse` in `.claude/settings.local.json` (Bash, Read, Write, Edit, MultiEdit, NotebookEdit, Grep, MCP tools) | `deny` and `ask` |
| Codex | `PreToolUse` in `.codex/hooks.json` (Bash, `apply_patch`, MCP tools) | `deny`; `ask` refuses, as Codex hooks cannot ask. Codex runs the hook after you trust the project and approve the hook in `/hooks` |
| Cursor | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, and `preToolUse` for writes and deletes, in `.cursor/hooks.json` | `deny` everywhere, `ask` for shell commands and MCP tools; elsewhere `ask` refuses. Cursor runs project hooks in a trusted workspace |

Cursor also runs Claude Code's hooks from `.claude/`; when its own policy hooks are in place, the Claude Code handler
leaves the call to them, so a call is decided once.

## The log

Each refusal and each approval asked for is appended to `<git common dir>/memprove-policy/log.jsonl` (mode 0600, one
JSON object per line: time, client, tool, subject, decision, what the client was told, and the deciding rule). A
subject is cut at 200 characters, and runs of 32 or more token-like characters are written as `[redacted]`. Calls
nothing objects to are not logged. `memprove policy log --last 50` prints the last fifty.

## Exit codes

| code | meaning |
|---|---|
| 0 | done; for `check`, no rule refuses the call or asks; for `test`, every expectation holds |
| 1 | for `check`, the call is refused or needs a person; for `test`, an expectation does not hold |
| 2 | usage error |
| 3 | the policy file is missing or cannot be read, or a file cannot be written |

`memprove policy hook` always exits 0 and answers in the client's own JSON.

## Limits

- It is a guard on the agent's tool calls, not a sandbox: a program the agent writes and then runs can do what that
  program does, and a command built at run time (`$VAR`, `eval "$x"`) is matched by what can be read from its text.
  Use the client's sandbox, or a container, where that matters.
- The hooks run only where they are installed and, for Codex and Cursor, trusted. `memprove policy init` on each
  developer's machine, and `memprove policy test` in CI, keep the two in step.
- Shell commands are matched by their words; a rule on `git push *` does not see a push a script makes inside.
- TRAE has no policy hook yet. When `memprove policy init` detects TRAE it says so and writes nothing for it; TRAE's
  tool calls are not checked against the policy.
