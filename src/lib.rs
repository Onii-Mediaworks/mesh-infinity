// NetInfinity unified crate.

#[path = "backend/core/src/lib.rs"]
pub mod core;
#[path = "backend/auth/src/lib.rs"]
pub mod auth;
#[path = "backend/crypto/src/lib.rs"]
pub mod crypto;
#[path = "backend/mesh/src/lib.rs"]
pub mod mesh;
#[path = "backend/transport/src/lib.rs"]
pub mod transport;
#[path = "backend/discovery/src/lib.rs"]
pub mod discovery;
#[path = "backend/src/lib.rs"]
pub mod backend;
#[path = "backend/ffi/src/lib.rs"]
pub mod ffi;

pub use backend::{
    FileTransferSummary, Message, NetInfinityService, NodeMode, PeerSummary, RoomSummary,
    ServiceConfig, Settings,
};
