// Mesh Infinity Authentication Module
// This module implements the web of trust and identity management

pub mod identity;
pub mod keystore;
pub mod persistence;
pub mod storage;
pub mod web_of_trust;

pub use identity::{Identity as LocalIdentity, IdentityManager};
pub use persistence::{IdentityStore, PersistedIdentity};
pub use storage::{
    ExportedTrustGraph, RevocationCertificate, RevocationReason, SerializableTrustRelationship,
    TrustStorage,
};
pub use web_of_trust::{
    Identity as TrustIdentity, TrustAttestation, TrustMarker, TrustRelationship,
    VerificationMethod, WebOfTrust,
};
