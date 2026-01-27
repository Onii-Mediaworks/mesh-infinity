// SeasonCom Mesh Networking Layer
// This module implements the WireGuard-based mesh networking

pub mod wireguard;
pub mod routing;
pub mod peer;

pub use peer::{PeerManager, TrustLevel as MeshTrustLevel, VerificationMethod};
pub use routing::{
    Endpoint as MeshEndpoint, PathInfo as MeshPathInfo, RouteInfo as MeshRouteInfo,
    RoutingTable as MeshRoutingTable,
};
pub use wireguard::{WGConfig, WGPeer, WireGuardMesh};
