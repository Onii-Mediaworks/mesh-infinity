// Mesh Infinity Authentication Module
// This module implements the web of trust and identity management

pub mod web_of_trust;
pub mod identity;

pub use identity::{Identity as LocalIdentity, IdentityManager};
pub use web_of_trust::{
    Identity as TrustIdentity, SharedSecret, TrustAttestation, TrustEndorsement, TrustMarker,
    TrustPropagation, TrustRelationship, VerificationMethod, WebOfTrust,
};
