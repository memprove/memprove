//! memprove policy: one set of tool rules for every coding agent in a
//! repository. The rules live in `.memprove/policy.rules`, committed with the
//! code; Claude Code, Codex and Cursor run `memprove policy hook` before each
//! tool call, and the hook refuses the call or has a person approve it when a
//! rule says so. The decision is made locally, from the text of the call
//! alone: nothing is run, nothing is sent anywhere, and no model judges.
//!
//! The crate reads no token and calls no daemon. The `memprove` CLI runs
//! [`cli::main`] for `memprove policy …` and gives it an [`cli::Installer`]
//! that writes the clients' hook settings.

#![forbid(unsafe_code)]

pub mod cli;
pub mod commands;
pub mod engine;
pub mod glob;
pub mod hook;
pub mod json;
pub mod log;
pub mod rules;
pub mod scan;
pub mod secrets;
pub mod shell;
pub mod starter;

pub use engine::{Call, Check, POLICY_FILE, Site, Verdict, evaluate};
pub use hook::Client;
pub use rules::{Decision, Policy, Rule, Tool};
