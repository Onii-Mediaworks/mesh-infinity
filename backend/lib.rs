//! Backend crate root re-export surface.
//!
//! Exposes service-layer types used by runtime and FFI callers.
mod service;

pub use service::{
    FileTransferSummary, HostedServicePolicy, HostedServiceSummary, IdentitySummary,
    MeshInfinityService, Message, NodeMode, PeerSummary, ReconnectSyncSnapshot, RoomSummary,
    ServiceConfig, Settings,
};

pub use std::sync::mpsc::Receiver;
