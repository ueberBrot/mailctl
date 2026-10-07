//! Controlled email discovery through a shared embedded application contract.
pub mod authentication;
pub mod config;
pub mod credentials;
pub mod domain;
pub mod draft;
pub mod draft_journal;
mod encoding;
#[cfg(feature = "cli")]
pub mod export;
mod file_storage;
#[cfg(any(feature = "cli", feature = "mcp"))]
pub mod frontends;
#[cfg(all(test, feature = "mcp"))]
#[path = "../tests/fuzz_support/mod.rs"]
mod fuzz_support;
pub mod host;
pub mod imap;
#[cfg(target_os = "macos")]
pub mod isolation;
#[cfg(all(test, feature = "mcp"))]
#[path = "../tests/fuzz_support/mcp_corpus.rs"]
mod mcp_corpus;
pub mod policy;
mod search;
pub mod service;
