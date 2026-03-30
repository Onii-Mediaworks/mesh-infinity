//! Testing, Diagnostics, and Developer Infrastructure (Spec SS 21)
//!
//! This module provides the testing infrastructure for Mesh Infinity:
//!
//! - **Fuzz testing targets** (`fuzz.rs`) -- harnesses for all protocol-critical
//!   parsers that process externally-originating bytes.  Each target accepts
//!   arbitrary `&[u8]` input and must never panic.  External tools like
//!   `cargo-fuzz` drive these targets with random/mutated inputs.
//!
//! - **Diagnostic report generation** (`diagnostics.rs`) -- produces a
//!   privacy-safe snapshot of the node's current state for debugging.
//!   Diagnostic reports contain zero message content, zero private keys,
//!   and zero contact names (SS 21.3.2 sanitization rules).
//!
//! - **Network simulator** (`simulator.rs`) -- an in-memory simulated mesh
//!   for multi-node scenario testing.  Supports configurable latency,
//!   packet loss, bandwidth limits, and network partitions.

/// Fuzz testing targets for protocol-critical parsers (SS 21.1.3, SS 21.2).
pub mod fuzz;

/// Diagnostic report generation with privacy sanitization (SS 21.3).
pub mod diagnostics;

/// In-memory network simulator for multi-node testing (SS 21.5).
pub mod simulator;
