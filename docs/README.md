# Documentation

| file | what it is for |
|---|---|
| [`guide.md`](guide.md) | the agent's manual: install, enable a repository, one Session start to end, the Context Pack, the hook, the MCP server, taking over, correcting, exit codes |
| [`architecture.md`](architecture.md) | one page on the daemon, the ledger, Evidence and verdicts, the Pack, the hook and the MCP server |
| [`verify.md`](verify.md) | `memprove verify`: the contract, what a run does and how it judges, the receipt, the Claude Code hooks, the limits |
| [`policy.md`](policy.md) | `memprove policy`: one set of tool rules for Claude Code, Codex and Cursor, its syntax, how a command line is read, the clients, the log |
| [`report.md`](report.md) | `memprove report`: one Claude Code or Codex session's tokens and estimated cost, tool calls, policy refusals, and the memory it read |
| [`takeover-eval.md`](takeover-eval.md) | the takeover evaluation: six scenarios, a real client, a deterministic scorer, the pass line |
| `../openapi/control-api-v1.yaml` | the control API the daemon serves over its Unix socket |
| `../schemas/` | the JSON schemas of the Task Capsule and the other documents |

`memprove --help` and `memprove <command> --help` print the usage of
every command without a daemon; the guide says the same as the help does.
