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
memprove policy scan                       # secrets the agents left in their settings and instruction files
```

Commit `.memprove/policy.rules`. The hooks `init` writes go into each developer's own client settings
(`.claude/settings.local.json`, `.codex/hooks.json`, `.cursor/hooks.json`, all kept out of Git through
`.git/info/exclude`), so each developer runs `memprove policy init` once; a second run changes nothing.

## Rules

```text
# <deny|ask|allow> <Bash|Read|Edit|Mcp|Secret>(<pattern>)  [-- what the agent is told]
allow Read(.env.example)
deny  Read(.env*)                  -- secrets stay out of the agent's context
deny  Bash(git push *--force*)     -- do not rewrite shared history; push a new branch
ask   Bash(git push *)
deny  Edit(db/migrations/**)       -- migrations are generated: run `make migration`
deny  Mcp(github.merge_*)
ask   Secret(*)                    -- keep secrets out of commands and files: use an environment variable
expect deny Bash(cd app && git push origin main --force)
expect ask  Bash(git push origin feature/x)
expect ask  Bash(PGPASSWORD=hunter2 psql -h db.internal)
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
- **`Secret(kind)`** is about a secret the agent writes out, whatever the command or the file: a password in a
  command line (`PGPASSWORD=hunter2 psql`, `sshpass -p …`, `curl -u me:…`, `--token …`, read as described under
  [Secrets in the agents' files](#secrets-in-the-agents-files)), or a credential in the text a call writes into a
  file. The pattern matches the kind: `password`, `private-key`, `jwt`, `aws-access-key`, `github-token`,
  `gitlab-token`, `anthropic-key`, `openai-key`, `slack-token`, `stripe-key`, `google-api-key`, `npm-token`,
  `huggingface-token`, `sendgrid-key`, `digitalocean-token`, `pypi-token`; `*` is every kind, `*-token` every token.
  `$PGPASSWORD`, `<placeholder>` and a file name are not secrets, so the way out the agent is told works: pass the
  secret through the environment. Text written into a file is read for credentials of a known format, private keys
  and passwords in URLs; the agents' own settings and instruction files (the ones `policy scan` reads) are read in
  full, as the scan reads them. What an edit removes is not read. The answer and the log name the secret
  (`password in PGPASSWORD: h…(7 characters)`) and never hold it. `memprove policy init`'s starter file has
  `ask Secret(*)`; a policy without a `Secret` rule does not look for secrets.
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
secret the detectors find in a subject is written redacted (`sshpass -p tr…(9 characters) ssh host`), runs of 32 or
more token-like characters are written as `[redacted]`, and a subject is cut at 200 characters. Calls nothing objects
to are not logged. `memprove policy log --last 50` prints the last fifty.

## Secrets in the agents' files

Coding agents leave secrets in the files they write. An "always allow" click stores the whole command in
`.claude/settings.local.json`, password and all; an MCP entry keeps an API key in its `env`; an instruction file
quotes the command that worked. `memprove policy scan` reads those files and names each secret by file, line and
kind. It needs no policy file and no hook. A `Secret` rule keeps new ones from being written; the scan finds the
ones that are already there.

```text
$ memprove policy scan
memprove policy scan: /work/app
.claude/settings.local.json:5: password in PGPASSWORD: s3c…(12 characters) (file ignored by Git)
    at permissions.allow[1]
.mcp.json:6: github-token in GITHUB_TOKEN: ghp_…(40 characters) (file tracked by Git)
    at mcpServers.github.env.GITHUB_TOKEN
CLAUDE.md:3: password in PGPASSWORD: s3c…(12 characters) (file not tracked and not ignored)
3 secrets in 3 of 4 files read; 1 in files Git tracks: those are in the repository's history or will be with the next commit
next: revoke and reissue each one (every agent and tool that reads the file has seen it), then give it through the environment: a variable such as $PGPASSWORD, or an env file Git ignores
```

- **What it reads.** With no path: `.claude/`, `.mcp.json`, `.codex/`, `.cursor/`, `.cursorrules`, `.trae/`,
  `.gemini/`, `.specstory/`, `.memprove/`, `.vscode/mcp.json`, `.windsurfrules`, `.clinerules`,
  `.github/copilot-instructions.md`, `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` and `GEMINI.md` at the repository
  root. With paths (`memprove policy scan ops docs/runbook.md`): those files, and what is below those directories. It
  does not enter `.git`, `node_modules` or `target`, goes eight directories deep, reads at most 5000 files, and
  skips a file over 4 MiB or one that is not UTF-8 text, saying so.
- **Passwords in command lines**, read as a shell reads them (the same reader as the hook's): assignments to
  secret-named variables (`PGPASSWORD=… psql`, `export API_TOKEN=…`), option values (`--password …`, `--token=…`),
  the options of programs that take a password in one (`sshpass -p`, `mysql -p…`, `redis-cli -a`, `curl -u me:…`,
  `docker login -p`, `smbclient -U me%…`, `openssl -passin pass:…`, `htpasswd -b`, and others), `Authorization` and
  other secret-named headers, `scheme://user:password@host`, `password=…` pairs in connection strings, and the
  scripts given to `bash -c`, `eval` and `ssh`. In JSON, a `command` with its `args` and a `Bash(…)` permission rule
  are read this way; in other files, code blocks, code spans, quoted strings and shell scripts are. In
  `.memprove/policy.rules` a `Bash(…)` rule is read this way too, and `expect` lines, which are tests, are skipped.
- **Values of secret-named keys**: `"env": {"SERVICE_API_KEY": "…"}`, `"headers": {"Authorization": "Bearer …"}`,
  and `name = value` or `name: value` lines.
- **Credentials of a known format**, wherever they stand: AWS access key IDs, GitHub, GitLab, Slack, npm, PyPI,
  Hugging Face and DigitalOcean tokens, Anthropic, OpenAI, Stripe, Google and SendGrid keys, JSON Web Tokens and
  private key blocks.
- **What is not a finding**: `$VAR`, `${VAR}` and other values the shell fills in, `<placeholder>`, `your-token`,
  `changeme`, `example`, `xxxx`, a file name (`--password-file`, `./key.pem`), and names that only look secret
  (`MAX_TOKENS`, `PWD`, `--ask-vault-pass`, publishable keys). A key whose name is only `key` or `auth` counts when
  its value looks random.
- **What it says**: `file:line`, the kind, the variable, option or header that holds the value, at most the first
  four characters of the value (never more than a quarter of it) with its length, the place in a JSON file, and
  what Git does with the file: tracked, ignored, or neither (the next `git add .` takes it). Outside a repository it
  says nothing about Git.
- **`--json`** prints the same as one object, schema `memprove.policy.scan.v1` (`root`, `files_read`, `skipped`,
  and `findings` with `path`, `line`, `kind`, `name`, `place`, `redacted`, `length`, `git`), for CI.
- **What it never does**: print a secret, check one against its service, change a file, or send anything. It runs
  one program, `git ls-files`, to learn what Git tracks.

### What the detectors were checked against

`crates/memprove-policy/tests/secrets_corpus.rs` builds a corpus from a fixed seed: a settings file of allowed
commands, an MCP file and an instruction file, one case per line. Every value in it is made up by the generator; no
leaked or real credential was collected or tested. `cargo test -p memprove-policy --test secrets_corpus` prints:

| group | cases | result |
|---|---|---|
| inline passwords: 59 command shapes in allowed commands, 3 MCP shapes, 15 shapes quoted in code spans | 1315 | 1215 found (92.4%) |
| format credentials: 20 prefixes and JSON Web Tokens, each in an allowed command, an MCP entry and a sentence; 4 private key lines | 634 | 634 found (100%) |
| lines with no secret: commands with `$VAR`, placeholders, file names and secret-looking names; MCP entries; sentences | 234 | 0 flagged |

Read these numbers for what they are: the shapes and the detectors were written together, so they show which
shapes are covered and that a change which loses one fails the test (each shape must be found in every variant). They
are not a measure of how many real leaks the scan finds; a secret in a shape that is not listed can be missed. The
100 misses are five shapes the scan does not read, kept in the corpus so the number counts them:

- `echo <password> | sudo -S …` and other passwords passed as plain words to `echo` or `printf`;
- `vault login <token>`, `mc alias set <name> <url> <key> <secret>`, `net use … <password>`: a positional argument
  of a program the scan has no rule for, when the value has no known format;
- `expect` scripts (`send "<password>\r"`).

The corpus has not been run through other scanners (gitleaks, TruffleHog): NOT RUN.

## Exit codes

| code | meaning |
|---|---|
| 0 | done; for `check`, no rule refuses the call or asks; for `test`, every expectation holds; for `scan`, no secret is found |
| 1 | for `check`, the call is refused or needs a person; for `test`, an expectation does not hold; for `scan`, a secret is found |
| 2 | usage error |
| 3 | the policy file is missing or cannot be read, a file cannot be written, or a path given to `scan` does not exist |

`memprove policy hook` always exits 0 and answers in the client's own JSON.

## Limits

- It is a guard on the agent's tool calls, not a sandbox: a program the agent writes and then runs can do what that
  program does, and a command built at run time (`$VAR`, `eval "$x"`) is matched by what can be read from its text.
  Use the client's sandbox, or a container, where that matters.
- The hooks run only where they are installed and, for Codex and Cursor, trusted. `memprove policy init` on each
  developer's machine, and `memprove policy test` in CI, keep the two in step.
- Shell commands are matched by their words; a rule on `git push *` does not see a push a script makes inside.
- A `Secret` rule sees what the detectors see. A secret in a shape they do not read (see
  [What the detectors were checked against](#what-the-detectors-were-checked-against)), one the agent splits or
  encodes, one in an MCP tool's arguments, or one past the first 4 MiB of a written file is not seen; in source code
  only credentials of a known format are. Cursor's file writes are read where its hook input carries the text.
- `memprove policy scan` reads the files as they are now. It does not read Git history, the clients' saved
  sessions under your home directory, or source code unless you name the path, and it does not stop an agent from
  writing a secret: it tells you after.
- TRAE has no policy hook yet. When `memprove policy init` detects TRAE it says so and writes nothing for it; TRAE's
  tool calls are not checked against the policy.
