//! File Sharing (§11)
//!
//! # What is File Sharing?
//!
//! File sharing in Mesh Infinity operates at two levels:
//!
//! 1. **Direct file transfer** (§11.1) — peer-to-peer chunked transfer
//!    with resumption, sliding window ACK, and SHA-256 verification.
//!
//! 2. **Distributed object storage** (§11.2) — Freenet-style content-
//!    addressed storage with multiple security levels, stop-storing
//!    signals, and pluggable storage backends.
//!
//! # Module Layout
//!
//! - **transfer** — direct peer-to-peer file transfer protocol
//! - **storage** — distributed object storage, manifests, and chunking
//! - **hosted** — public file hosting and group file repositories

pub mod transfer;
pub mod storage;
pub mod hosted;
pub mod backend_adapter;
