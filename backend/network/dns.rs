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
pub const PUBLIC_DHT_TTL_DEFAULT: u32 = 86_400;

/// Maximum TTL for public DHT records (seconds). 7 days.
pub const PUBLIC_DHT_TTL_MAX: u32 = 7 * 86_400;

/// Infinet DNS cache TTL (seconds).
pub const INFINET_CACHE_TTL: u32 = 60;

/// Mesh TLD for all mesh DNS names.
pub const MESH_TLD: &str = "meshinfinity";

/// Public namespace subdomain.
pub const NS_PUBLIC: &str = "public";

/// Private namespace subdomain.
pub const NS_PRIVATE: &str = "private";

/// Infinet namespace subdomain.
pub const NS_INFINET: &str = "infinet";

/// Clearnet passthrough subdomain.
pub const NS_CLEAR: &str = "clear";

// ---------------------------------------------------------------------------
// DNS Record Types
// ---------------------------------------------------------------------------

/// Mesh DNS record type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshDnsRecordType {
    /// Maps name to mesh device address.
    MeshAddress,
    /// Maps name to service ID.
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
pub struct MeshDnsRecord {
    /// The name being resolved.
    pub name: String,
    /// Record type.
    pub record_type: MeshDnsRecordType,
    /// Record value (interpretation depends on type).
    pub value: String,
    /// TTL in seconds (None = no expiry / always fresh).
    pub ttl: Option<u32>,
    /// Who published this record.
    pub published_by: Option<[u8; 32]>,
    /// When this record was created/updated.
    pub timestamp: u64,
    /// Ed25519 signature.
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
pub struct PetName {
    /// The user-chosen name (e.g., "mom", "work-server").
    pub name: String,
    /// What this name resolves to.
    pub target: PetNameTarget,
}

/// What a pet name resolves to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PetNameTarget {
    /// A peer by peer ID.
    Peer([u8; 32]),
    /// A device by device address.
    Device([u8; 32]),
    /// A service by service ID.
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
pub struct MeshDnsResolver {
    /// Local pet names (highest priority).
    pub pet_names: Vec<PetName>,
    /// Local DNS records cache.
    pub records: Vec<MeshDnsRecord>,
}

impl MeshDnsResolver {
    /// Create a new empty resolver.
    pub fn new() -> Self {
        Self {
            pet_names: Vec::new(),
            records: Vec::new(),
        }
    }

    /// Resolve a name through the resolver chain.
    ///
    /// Returns the first matching record, or None (NXDOMAIN).
    pub fn resolve(&self, name: &str) -> Option<String> {
        // Step 1: Pet names.
        for pet in &self.pet_names {
            if pet.name == name {
                return Some(format!("{:?}", pet.target));
            }
        }

        // Steps 2–5: Check cached records.
        for record in &self.records {
            if record.name == name {
                return Some(record.value.clone());
            }
        }

        // Step 6: NXDOMAIN.
        None
    }

    /// Add a pet name.
    pub fn add_pet_name(&mut self, name: PetName) {
        // Remove existing with same name.
        self.pet_names.retain(|p| p.name != name.name);
        self.pet_names.push(name);
    }

    /// Add a DNS record to the cache.
    pub fn add_record(&mut self, record: MeshDnsRecord) {
        self.records.push(record);
    }

    /// Determine which namespace a name belongs to.
    pub fn classify_namespace(name: &str) -> Option<&str> {
        let parts: Vec<&str> = name.rsplitn(3, '.').collect();
        if parts.len() >= 2 && parts[0] == MESH_TLD {
            Some(parts[1])
        } else {
            None
        }
    }
}

impl Default for MeshDnsResolver {
    fn default() -> Self {
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
        assert_eq!(
            MeshDnsResolver::classify_namespace("example.com"),
            None
        );
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
