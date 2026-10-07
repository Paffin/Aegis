//! `aegis-guard`: the check that runs on the developer's machine before an agent's tool call.
//!
//! The gateway sees what the model says; it does not see what the agent is about to do to the
//! machine. The guard is a small program that the agent's hooks start before every tool call
//! (Claude Code `PreToolUse`): it reads the call, applies the rules of the company (files that
//! are never read, commands that need a human, hosts that may be contacted) and answers allow,
//! ask or deny within a few milliseconds.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod config;
pub mod decide;
pub mod hook;
