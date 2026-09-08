//! Controlled email discovery through a shared embedded application contract.
pub mod adapters;
pub mod config;
pub mod domain;
mod encoding;
#[cfg(any(feature = "cli", feature = "mcp"))]
pub mod frontends;
pub mod policy;
pub mod secret;
pub mod service;
