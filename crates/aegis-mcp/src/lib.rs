//! `aegis-mcp`: a filter between an MCP client and an MCP server.
//!
//! Between the agent and a tool server it does what the policy of the gateway cannot, because the
//! gateway only sees the model's side: it hides tools that are not on the allow-list, refuses calls
//! whose arguments break the rules (patterns, enumerations, SQL that is not read-only), and removes
//! fields from results before the agent, and through it the model, sees them. Pseudonymization stays
//! with the gateway.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod audit;
pub mod config;
pub mod filter;
pub mod http;
pub mod sql;
pub mod stdio;
