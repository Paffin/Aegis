//! Aegis gateway: protocol adapters and server around `aegis-core`.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod anthropic;
pub mod audit;
pub mod bundle_loader;
pub mod common;
pub mod config;
pub mod engine;
pub mod gemini;
pub mod harden;
pub mod json;
pub mod metrics;
pub mod openai_chat;
pub mod openai_completions;
pub mod openai_embeddings;
pub mod openai_responses;
pub mod server;
pub mod stream;
