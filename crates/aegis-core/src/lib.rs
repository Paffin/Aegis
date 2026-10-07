//! Aegis core: detection, pseudonymization and restoration.
//!
//! The crate performs no I/O. Every function is deterministic in its inputs
//! (INV-1) and never logs or formats sensitive values (INV-6).
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod crypto;
pub mod detect;
pub mod policy;
pub mod pseudo;
pub mod restore;
pub mod sensitive;
pub mod shell;
pub mod types;

pub use sensitive::Sensitive;
pub use types::{Class, Entity, EntityType, Span};
