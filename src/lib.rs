//! Shared email application boundaries. Email behavior arrives in subsequent slices.
pub mod adapters;
pub mod backend;
pub mod domain;
pub mod frontends;
pub mod ipc;
pub mod policy;
pub mod secret;
pub mod service;
