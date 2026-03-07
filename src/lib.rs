// Mesh Infinity unified crate.

#[path = "../backend/auth/lib.rs"]
pub mod auth;
#[path = "../backend/lib.rs"]
pub mod backend;
#[path = "../backend/core/lib.rs"]
pub mod core;
#[path = "../backend/crypto/lib.rs"]
pub mod crypto;
#[path = "../backend/discovery/lib.rs"]
pub mod discovery;
#[path = "../backend/ffi/lib.rs"]
pub mod ffi;
pub mod runtime;
#[path = "../backend/transport/lib.rs"]
pub mod transport;

pub use backend::{
    FileTransferSummary, MeshInfinityService, Message, NodeMode, PeerSummary, RoomSummary,
    ServiceConfig, Settings,
};
pub use runtime::{MeshInfinityRuntime, RuntimeConfig};
