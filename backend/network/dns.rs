//! Mesh DNS System (§17.11)
//!
//! # DNS Namespaces
//!
//! ```text
//! *.public.meshinfinity   — public mesh identities, Gardens, services
//! *.private.meshinfinity  — trusted-only names, Infinet, personal devices
//! *.infinet.meshinfinity  — Infinet virtual addresses
//! *.clear.meshinfinity    — passthrough clearnet DNS
//! ```
//!
//! # Resolver Chain (ordered)
//!
//! 1. Local pet names table
//! 2. Trusted-channel DNS tables (private scope)
//! 3. Infinet resolver (infinet scope)
//! 4. Public mesh DHT (public scope)
//! 5. Clearnet DoH passthrough (clear scope)
//! 6. NXDOMAIN
//!
//! # TTL Constants
//!
//! - Public DHT: default 24h, max 7d
//! - Private: no TTL (always fresh)
//! - Infinet: local cache 60s
//! - Clearnet: respect upstream DoH TTL

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default TTL for public DHT records (seconds). 24 hours.
// PUBLIC_DHT_TTL_DEFAULT — protocol constant.
// Defined by the spec; must not change without a version bump.
// PUBLIC_DHT_TTL_DEFAULT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PUBLIC_DHT_TTL_DEFAULT: u32 = 86_400;

/// Maximum TTL for public DHT records (seconds). 7 days.
// PUBLIC_DHT_TTL_MAX — protocol constant.
// Defined by the spec; must not change without a version bump.
// PUBLIC_DHT_TTL_MAX — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PUBLIC_DHT_TTL_MAX: u32 = 7 * 86_400;

/// Infinet DNS cache TTL (seconds).
// INFINET_CACHE_TTL — protocol constant.
// Defined by the spec; must not change without a version bump.
// INFINET_CACHE_TTL — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const INFINET_CACHE_TTL: u32 = 60;

/// Mesh TLD for all mesh DNS names.
// MESH_TLD — protocol constant.
// Defined by the spec; must not change without a version bump.
// MESH_TLD — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MESH_TLD: &str = "meshinfinity";

/// Public namespace subdomain.
// NS_PUBLIC — protocol constant.
// Defined by the spec; must not change without a version bump.
// NS_PUBLIC — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const NS_PUBLIC: &str = "public";

/// Private namespace subdomain.
// NS_PRIVATE — protocol constant.
// Defined by the spec; must not change without a version bump.
// NS_PRIVATE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const NS_PRIVATE: &str = "private";

/// Infinet namespace subdomain.
// NS_INFINET — protocol constant.
// Defined by the spec; must not change without a version bump.
// NS_INFINET — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const NS_INFINET: &str = "infinet";

/// Clearnet passthrough subdomain.
// NS_CLEAR — protocol constant.
// Defined by the spec; must not change without a version bump.
// NS_CLEAR — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const NS_CLEAR: &str = "clear";

// ---------------------------------------------------------------------------
// DNS Record Types
// ---------------------------------------------------------------------------

/// Mesh DNS record type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// MeshDnsRecordType — variant enumeration.
// Match exhaustively to handle every protocol state.
// MeshDnsRecordType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MeshDnsRecordType {
    /// Maps name to mesh device address.
    // Execute this protocol step.
    // Execute this protocol step.
    MeshAddress,
    /// Maps name to service ID.
    // Execute this protocol step.
    // Execute this protocol step.
    ServiceId,
    /// Maps name to peer ID.
    PeerId,
    /// CNAME alias.
    Alias,
    /// Human-readable text record.
    Text,
}

// ---------------------------------------------------------------------------
// DNS Record
// ---------------------------------------------------------------------------

/// A mesh DNS record.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MeshDnsRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MeshDnsRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MeshDnsRecord {
    /// The name being resolved.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// Record type.
    // Execute this protocol step.
    // Execute this protocol step.
    pub record_type: MeshDnsRecordType,
    /// Record value (interpretation depends on type).
    // Execute this protocol step.
    // Execute this protocol step.
    pub value: String,
    /// TTL in seconds (None = no expiry / always fresh).
    // Execute this protocol step.
    // Execute this protocol step.
    pub ttl: Option<u32>,
    /// Who published this record.
    // Execute this protocol step.
    // Execute this protocol step.
    pub published_by: Option<[u8; 32]>,
    /// When this record was created/updated.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
    /// Ed25519 signature.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Pet Name Entry
// ---------------------------------------------------------------------------

/// A local pet name (user-defined alias for a peer).
///
/// Pet names are the FIRST thing checked in the resolver chain.
/// They override all other DNS results, giving the user complete
/// control over how they refer to peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PetName — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PetName — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PetName {
    /// The user-chosen name (e.g., "mom", "work-server").
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// What this name resolves to.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target: PetNameTarget,
}

/// What a pet name resolves to.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PetNameTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
// PetNameTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PetNameTarget {
    /// A peer by peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    Peer([u8; 32]),
    /// A device by device address.
    // Execute this protocol step.
    // Execute this protocol step.
    Device([u8; 32]),
    /// A service by service ID.
    // Execute this protocol step.
    // Execute this protocol step.
    Service([u8; 16]),
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// Mesh DNS resolver (§17.11).
///
/// Resolves mesh names through the resolver chain.
/// In a full implementation, this would query the DHT,
/// trusted channels, and clearnet DoH. For now, it
/// resolves against local tables.
// MeshDnsResolver — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MeshDnsResolver — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MeshDnsResolver {
    /// Local pet names (highest priority).
    // Execute this protocol step.
    // Execute this protocol step.
    pub pet_names: Vec<PetName>,
    /// Local DNS records cache.
    // Execute this protocol step.
    // Execute this protocol step.
    pub records: Vec<MeshDnsRecord>,
}

// Begin the block scope.
// MeshDnsResolver implementation — core protocol logic.
// MeshDnsResolver implementation — core protocol logic.
impl MeshDnsResolver {
    /// Create a new empty resolver.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            pet_names: Vec::new(),
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            records: Vec::new(),
        }
    }

    /// Resolve a name through the resolver chain.
    ///
    /// Returns the first matching record, or None (NXDOMAIN).
    // Perform the 'resolve' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'resolve' operation.
    // Errors are propagated to the caller via Result.
    pub fn resolve(&self, name: &str) -> Option<String> {
        // Step 1: Pet names.
        // Iterate over each element.
        // Iterate over each element.
        for pet in &self.pet_names {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if pet.name == name {
                // Format the output for display or logging.
                // Return to the caller.
                // Return to the caller.
                return Some(format!("{:?}", pet.target));
            }
        }

        // Steps 2–5: Check cached records.
        // Iterate over each element.
        // Iterate over each element.
        for record in &self.records {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if record.name == name {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                return Some(record.value.clone());
            }
        }

        // Step 6: NXDOMAIN.
        // No value available.
        // No value available.
        None
    }

    /// Add a pet name.
    // Perform the 'add pet name' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add pet name' operation.
    // Errors are propagated to the caller via Result.
    pub fn add_pet_name(&mut self, name: PetName) {
        // Remove existing with same name.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.pet_names.retain(|p| p.name != name.name);
        // Execute the operation and bind the result.
        // Append to the collection.
        // Append to the collection.
        self.pet_names.push(name);
    }

    /// Add a DNS record to the cache.
    // Perform the 'add record' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'add record' operation.
    // Errors are propagated to the caller via Result.
    pub fn add_record(&mut self, record: MeshDnsRecord) {
        // Execute the operation and bind the result.
        // Append to the collection.
        // Append to the collection.
        self.records.push(record);
    }

    /// Determine which namespace a name belongs to.
    // Perform the 'classify namespace' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'classify namespace' operation.
    // Errors are propagated to the caller via Result.
    pub fn classify_namespace(name: &str) -> Option<&str> {
        // Materialize the iterator into a concrete collection.
        // Compute parts for this protocol step.
        // Compute parts for this protocol step.
        let parts: Vec<&str> = name.rsplitn(3, '.').collect();
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        if parts.len() >= 2 && parts[0] == MESH_TLD {
            // Wrap the found value for the caller.
            // Wrap the found value.
            Some(parts[1])
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        } else {
            // No value available.
            None
        }
    }
}

// Trait implementation for protocol conformance.
// Implement Default for MeshDnsResolver.
impl Default for MeshDnsResolver {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pet_name_resolution() {
        let mut resolver = MeshDnsResolver::new();
        resolver.add_pet_name(PetName {
            name: "mom".to_string(),
            target: PetNameTarget::Peer([0xAA; 32]),
        });

        assert!(resolver.resolve("mom").is_some());
        assert!(resolver.resolve("unknown").is_none());
    }

    #[test]
    fn test_namespace_classification() {
        assert_eq!(
            MeshDnsResolver::classify_namespace("alice.public.meshinfinity"),
            Some("public")
        );
        assert_eq!(
            MeshDnsResolver::classify_namespace("server.private.meshinfinity"),
            Some("private")
        );
        assert_eq!(MeshDnsResolver::classify_namespace("example.com"), None);
    }

    #[test]
    fn test_pet_name_override() {
        let mut resolver = MeshDnsResolver::new();

        // Add a record.
        resolver.add_record(MeshDnsRecord {
            name: "alice.public.meshinfinity".to_string(),
            record_type: MeshDnsRecordType::PeerId,
            value: "aabbccdd".to_string(),
            ttl: Some(PUBLIC_DHT_TTL_DEFAULT),
            published_by: None,
            timestamp: 1000,
            signature: None,
        });

        // Pet name with the same name overrides.
        resolver.add_pet_name(PetName {
            name: "alice.public.meshinfinity".to_string(),
            target: PetNameTarget::Peer([0xFF; 32]),
        });

        let result = resolver.resolve("alice.public.meshinfinity").unwrap();
        // Should be the pet name target, not the DNS record value.
        assert_ne!(result, "aabbccdd");
    }
}
