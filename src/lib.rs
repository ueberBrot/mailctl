//! Controlled email discovery through a shared embedded application contract.
pub mod config;
pub mod domain;
pub mod draft_journal;
mod encoding;
mod file_storage;
#[cfg(any(feature = "cli", feature = "mcp"))]
pub mod frontends;
pub mod imap;
pub mod policy;
pub mod service;
