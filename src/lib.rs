//! Controlled email discovery through a shared embedded application contract.
pub mod authentication;
pub mod config;
pub mod credentials;
pub mod domain;
pub mod draft_journal;
mod encoding;
mod file_storage;
#[cfg(any(feature = "cli", feature = "mcp"))]
pub mod frontends;
pub mod imap;
#[cfg(target_os = "macos")]
pub mod isolation;
pub mod policy;
mod search;
pub mod service;
