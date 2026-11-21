//! memprove report: one local report per coding-agent session. It reads a
//! Claude Code or Codex session's transcript on this machine and the
//! repository's `memprove policy` log, and reports what the session cost
//! (tokens per model, estimated at list prices), which tools it called,
//! which calls the policy refused or sent to a person, and which memprove
//! statements the agent read, with the facts that were not verified when it
//! read them.
//!
//! The crate only reads files: it writes nothing, sends nothing anywhere,
//! and calls no daemon. The `memprove` CLI runs [`cli::main`] for
//! `memprove report …` and gives it a [`report::Present`] that reads the
//! statements memprove holds now for `--now`.

#![forbid(unsafe_code)]

pub mod claude;
pub mod cli;
pub mod codex;
pub mod find;
pub mod memory;
pub mod model;
pub mod policy;
pub mod prices;
pub mod read;
pub mod render;
pub mod report;
pub mod time;

pub use model::{Bucket, Client, Session, Spend, ToolUse, Usage};
pub use report::{CurrentStatement, Now, Present, Report};
