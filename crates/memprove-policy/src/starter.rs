//! The policy file `memprove policy init` writes when there is none.

/// The text of a new `.memprove/policy.rules`.
pub const STARTER: &str = "\
# memprove policy: rules for every coding agent in this repository.
# Claude Code, Codex and Cursor check each tool call against this file
# before it runs. Commit it.
#
#   <deny|ask|allow> <Bash|Read|Edit|Mcp>(<pattern>)  [-- what the agent is told]
#
# Bash matches each command of a command line (`cd x && git push -f` is two),
# also inside `bash -c`, `$(...)`, `sudo`, `env`, `xargs` and `find -exec`.
# Read and Edit match paths: `.env*` is a file name anywhere, `db/**` is below
# the repository root, `~/.ssh/**` is below your home; they also cover shell
# commands that read or change the file (`cat .env`, `> file`, `rm -r db`).
# Mcp matches `server.tool` (`github.merge_*`, or `github` for all of them).
# `*` matches anything (in paths, inside one directory), `**` any directories.
#
# The first rule that matches decides; a command line gets the strictest
# decision of its commands. `allow` only stops later rules from matching: it
# never approves a call the agent's own settings would ask about. `ask` makes
# a person approve; Codex hooks cannot ask, so there `ask` refuses the call.
#
# `expect` lines are tests: `memprove policy test` runs them (also in CI), and
# `memprove policy check 'Bash(git push -f)'` shows which line decides a call.

allow Read(.env.example)
deny  Read(.env*)                  -- secrets stay out of the agent's context
deny  Read(~/.ssh/**)              -- keys stay out of the agent's context

deny  Bash(git push *--force*)     -- do not rewrite shared history; push a new branch
deny  Bash(git push -f *)          -- do not rewrite shared history; push a new branch
deny  Bash(git push * -f *)        -- do not rewrite shared history; push a new branch
ask   Bash(git push *)
ask   Bash(npm publish *)
ask   Bash(cargo publish *)

expect deny  Read(.env)
expect allow Read(.env.example)
expect deny  Bash(cat config/.env.local)
expect deny  Bash(cd app && git push origin main --force)
expect deny  Bash(git push -f)
expect ask   Bash(git push origin feature/x)
expect allow Bash(git status)
";
