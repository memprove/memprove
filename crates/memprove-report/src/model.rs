//! What a report holds: one agent session as its transcript tells it.

use std::{collections::BTreeMap, path::PathBuf};

use crate::memory::MemorySeen;

/// The coding agent whose session is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Client {
    /// Claude Code: `~/.claude/projects/<dir>/<session>.jsonl`.
    ClaudeCode,
    /// Codex: `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`.
    Codex,
}

impl Client {
    /// Every client, in the order a listing names them.
    pub const ALL: [Self; 2] = [Self::ClaudeCode, Self::Codex];

    /// The client's name on the command line and in the policy log.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }

    /// The client named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|client| client.name() == name)
    }
}

/// Tokens of model requests, by how they are priced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Input tokens read neither from nor into the prompt cache.
    pub input: u64,
    /// Input tokens written to the prompt cache for five minutes (or for an
    /// unstated time).
    pub cache_write: u64,
    /// Input tokens written to the prompt cache for an hour.
    pub cache_write_1h: u64,
    /// Input tokens read from the prompt cache.
    pub cache_read: u64,
    /// Output tokens, reasoning included.
    pub output: u64,
}

impl Usage {
    /// Adds `other` to these tokens.
    pub fn add(&mut self, other: &Self) {
        self.input += other.input;
        self.cache_write += other.cache_write;
        self.cache_write_1h += other.cache_write_1h;
        self.cache_read += other.cache_read;
        self.output += other.output;
    }

    /// Every input token of the requests: the prompt length.
    #[must_use]
    pub const fn prompt(&self) -> u64 {
        self.input + self.cache_write + self.cache_write_1h + self.cache_read
    }

    /// Every token.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.prompt() + self.output
    }
}

/// Requests of one model priced alike.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bucket {
    /// The model the client named.
    pub model: String,
    /// Run in fast mode (`usage.speed` = `fast`).
    pub fast: bool,
    /// Run in the United States only (`usage.inference_geo` = `us`).
    pub us_only: bool,
    /// The request's prompt was over 100,000 tokens (priced higher on some
    /// models).
    pub long_prompt: bool,
}

impl Bucket {
    /// A bucket of `model` at standard prices.
    #[must_use]
    pub fn plain(model: &str) -> Self {
        Self {
            model: model.to_owned(),
            fast: false,
            us_only: false,
            long_prompt: false,
        }
    }
}

/// The requests and tokens of one [`Bucket`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Spend {
    /// Model requests (Claude Code: assistant messages; Codex: token counts
    /// that grew).
    pub requests: u64,
    /// Their tokens.
    pub usage: Usage,
}

/// The calls of one tool.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ToolUse {
    /// How many times the agent called it.
    pub calls: u64,
    /// How many of those the client recorded as failed.
    pub failed: u64,
}

/// One session as read from its transcript.
#[derive(Debug, Clone)]
pub struct Session {
    /// Its client.
    pub client: Client,
    /// Its id (Claude Code: the session id; Codex: the thread id).
    pub id: String,
    /// The transcript files read: the session's, then its sub-agents'.
    pub files: Vec<PathBuf>,
    /// How many of [`Session::files`] are sub-agent transcripts.
    pub subagents: usize,
    /// The directory the session started in.
    pub cwd: Option<String>,
    /// The client's version.
    pub version: Option<String>,
    /// The Git branch the client recorded last.
    pub branch: Option<String>,
    /// The first timestamp, in milliseconds since 1970.
    pub started_ms: Option<i64>,
    /// The last timestamp, in milliseconds since 1970.
    pub ended_ms: Option<i64>,
    /// Model requests and tokens by how they are priced.
    pub spend: BTreeMap<Bucket, Spend>,
    /// Tool calls by tool name.
    pub tools: BTreeMap<String, ToolUse>,
    /// Whether the transcript records which tool calls failed.
    pub failures_recorded: bool,
    /// The memprove statements the agent was given.
    pub memory: MemorySeen,
    /// Lines that are not JSON records the reader knows.
    pub unreadable_lines: u64,
}

impl Session {
    /// An empty session of `client` with id `id`.
    #[must_use]
    pub fn new(client: Client, id: &str) -> Self {
        Self {
            client,
            id: id.to_owned(),
            files: Vec::new(),
            subagents: 0,
            cwd: None,
            version: None,
            branch: None,
            started_ms: None,
            ended_ms: None,
            spend: BTreeMap::new(),
            tools: BTreeMap::new(),
            failures_recorded: false,
            memory: MemorySeen::default(),
            unreadable_lines: 0,
        }
    }

    /// Widens the session's time span to `ms`.
    pub fn saw_time(&mut self, ms: i64) {
        self.started_ms = Some(self.started_ms.map_or(ms, |start| start.min(ms)));
        self.ended_ms = Some(self.ended_ms.map_or(ms, |end| end.max(ms)));
    }

    /// Records a call of `tool`.
    pub fn called(&mut self, tool: &str) {
        self.tools.entry(tool.to_owned()).or_default().calls += 1;
    }

    /// Records that a call of `tool` failed.
    pub fn failed(&mut self, tool: &str) {
        self.tools.entry(tool.to_owned()).or_default().failed += 1;
    }

    /// Adds one request of `usage` to `bucket`.
    pub fn spent(&mut self, bucket: Bucket, usage: &Usage) {
        let spend = self.spend.entry(bucket).or_default();
        spend.requests += 1;
        spend.usage.add(usage);
    }

    /// Every tool call.
    #[must_use]
    pub fn tool_calls(&self) -> u64 {
        self.tools.values().map(|tool| tool.calls).sum()
    }

    /// Every failed tool call.
    #[must_use]
    pub fn tool_failures(&self) -> u64 {
        self.tools.values().map(|tool| tool.failed).sum()
    }

    /// Every model request.
    #[must_use]
    pub fn requests(&self) -> u64 {
        self.spend.values().map(|spend| spend.requests).sum()
    }

    /// Every token.
    #[must_use]
    pub fn usage(&self) -> Usage {
        let mut usage = Usage::default();
        for spend in self.spend.values() {
            usage.add(&spend.usage);
        }
        usage
    }

    /// The models used, each once, in name order.
    #[must_use]
    pub fn models(&self) -> Vec<&str> {
        let mut models: Vec<&str> = self
            .spend
            .keys()
            .map(|bucket| bucket.model.as_str())
            .collect();
        models.dedup();
        models
    }
}
