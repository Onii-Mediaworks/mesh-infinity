//! Mesh Infinity — unified crate root.
//!
//! This is the single Rust crate for the Mesh Infinity backend.
//! All modules are re-exported from here.

/// Unified error type — every fallible operation returns `Result<T, MeshError>`.
/// See `backend/error.rs` for the full variant list and usage guide.
#[path = "../backend/error.rs"]
pub mod error;

#[path = "../backend/crypto/lib.rs"]
pub mod crypto;

#[path = "../backend/storage/mod.rs"]
pub mod storage;

#[path = "../backend/identity/mod.rs"]
pub mod identity;

#[path = "../backend/trust/mod.rs"]
pub mod trust;

#[path = "../backend/network/mod.rs"]
pub mod network;

#[path = "../backend/transport/mod.rs"]
pub mod transport;

#[path = "../backend/routing/mod.rs"]
pub mod routing;

#[path = "../backend/pairing/mod.rs"]
pub mod pairing;

#[path = "../backend/groups/mod.rs"]
pub mod groups;

#[path = "../backend/calls/mod.rs"]
pub mod calls;

#[path = "../backend/files/mod.rs"]
pub mod files;

#[path = "../backend/services/mod.rs"]
pub mod services;

#[path = "../backend/vpn/mod.rs"]
pub mod vpn;

#[path = "../backend/mesh/mod.rs"]
pub mod mesh;

#[path = "../backend/notifications/mod.rs"]
pub mod notifications;

#[path = "../backend/messaging/mod.rs"]
pub mod messaging;

#[path = "../backend/service/mod.rs"]
pub mod service;

#[path = "../backend/ffi/lib.rs"]
pub mod ffi;

pub mod runtime;
