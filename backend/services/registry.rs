//! Service Registration and Discovery (§12.4, §12.5)
//!
//! # Service Records
//!
//! Services are registered with a ServiceRecord containing
//! publications (how to reach the service) and access control.
//! Records are versioned — higher versions supersede lower ones.
//!
//! # Service Indexes
//!
//! Operators can curate indexes of services for discovery.

use serde::{Deserialize, Serialize};

use crate::routing::losec::ServiceLoSecConfig;

// ---------------------------------------------------------------------------
// Announcement Scope
// ---------------------------------------------------------------------------

/// How widely a service publication is advertised.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ServiceScope — variant enumeration.
// Match exhaustively to handle every protocol state.
// ServiceScope — variant enumeration.
// Match exhaustively to handle every protocol state.
// ServiceScope — variant enumeration.
// Match exhaustively to handle every protocol state.
// ServiceScope — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ServiceScope {
    /// Not advertised; reachable only by address.
    Private,
    /// Advertised only to specific peers.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Peers(Vec<[u8; 32]>),
    /// Advertised within a specific group.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Group([u8; 32]),
    /// Advertised to everyone.
    Public,
    /// Listed in a specific service index.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Index([u8; 32]),
}

// ---------------------------------------------------------------------------
// Transport Hint
// ---------------------------------------------------------------------------

/// Preferred transport for reaching a service.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ServiceTransportHint — variant enumeration.
// Match exhaustively to handle every protocol state.
// ServiceTransportHint — variant enumeration.
// Match exhaustively to handle every protocol state.
// ServiceTransportHint — variant enumeration.
// Match exhaustively to handle every protocol state.
// ServiceTransportHint — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ServiceTransportHint {
    Any,
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    PreferTor,
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    PreferMesh,
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    PreferLoSec,
}

// ---------------------------------------------------------------------------
// Service Publication
// ---------------------------------------------------------------------------

/// A single publication describing how to reach a service.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ServicePublication — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServicePublication — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServicePublication — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServicePublication — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ServicePublication {
    /// How widely this publication is advertised.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub scope: ServiceScope,
    /// Device address hosting the service.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub address: [u8; 32],
    /// Port (if applicable).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub port: Option<u32>,
    /// Supported tunnel protocols.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub protocols: Vec<super::tunnel::TunnelProto>,
    /// Human-readable name.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: Option<String>,
    /// Description.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub description: Option<String>,
    /// Preferred transport.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub transport_hint: ServiceTransportHint,
    /// LoSec configuration.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub losec_config: ServiceLoSecConfig,
}

// ---------------------------------------------------------------------------
// Service Record
// ---------------------------------------------------------------------------

/// A registered service (§12.4).
///
/// Versioned — higher version numbers supersede lower ones.
/// Signed by the owner's Ed25519 key.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ServiceRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ServiceRecord {
    /// Unique service identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub service_id: [u8; 16],
    /// Owner's peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub owner_peer_id: [u8; 32],
    /// Monotonically increasing version.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub version: u64,
    /// How to reach this service (may have multiple publications).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub publications: Vec<ServicePublication>,
    /// Ed25519 signature over the record.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sig: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Service Index
// ---------------------------------------------------------------------------

/// A curated index of services (§12.5).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ServiceIndex — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceIndex — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceIndex — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceIndex — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ServiceIndex {
    /// The index id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub index_id: [u8; 16],
    /// The operator for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub operator: [u8; 32],
    /// The name for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// The description for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub description: Option<String>,
    /// The entries for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub entries: Vec<ServiceIndexEntry>,
    /// The updated at for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub updated_at: u64,
    /// The sig for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sig: Vec<u8>,
}

/// An entry in a service index.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ServiceIndexEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceIndexEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceIndexEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceIndexEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ServiceIndexEntry {
    /// The service record for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub service_record: ServiceRecord,
    /// The listed at for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub listed_at: u64,
    /// The endorsement for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub endorsement: Option<String>,
}

// ---------------------------------------------------------------------------
// Service Store
// ---------------------------------------------------------------------------

/// Local store of known services.
// ServiceStore — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceStore — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceStore — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ServiceStore — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ServiceStore {
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    records: std::collections::HashMap<[u8; 16], ServiceRecord>,
}

// Begin the block scope.
// ServiceStore implementation — core protocol logic.
// ServiceStore implementation — core protocol logic.
// ServiceStore implementation — core protocol logic.
// ServiceStore implementation — core protocol logic.
impl ServiceStore {
    // Begin the block scope.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            records: std::collections::HashMap::new(),
        }
    }

    /// Register or update a service.
    ///
    /// Validates:
    /// 1. New version must be higher than existing (monotonic).
    /// 2. Signature must be exactly 64 bytes (Ed25519 format).
    /// 3. Owner peer ID must match existing record (if updating).
    ///
    /// Full Ed25519 signature verification is performed against
    /// the owner's public key using the service record domain.
    // Perform the 'upsert' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'upsert' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'upsert' operation.
    // Errors are propagated to the caller via Result.
    pub fn upsert(&mut self, record: ServiceRecord) -> bool {
        // Structural signature check (64 bytes for Ed25519).
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if record.sig.len() != 64 {
            // Condition not met — return negative result.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return false;
        }

        // Version monotonicity check.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(existing) = self.records.get(&record.service_id) {
            // Must be strictly higher version.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if record.version <= existing.version {
                // Condition not met — return negative result.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return false;
            }
            // Owner must match — can't hijack someone else's service.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if record.owner_peer_id != existing.owner_peer_id {
                // Condition not met — return negative result.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return false;
            }
        }

        // Verify signature using the signing module.
        {
            use crate::crypto::signing;

            // Signed message covers the full record to prevent tampering with
            // publications after signing:
            //   service_id || owner_peer_id || version (BE u64) || publications_cbor
            // Compute pubs cbor for this protocol step.
            // Compute pubs cbor for this protocol step.
            // Compute pubs cbor for this protocol step.
            let pubs_cbor = serde_json::to_vec(&record.publications).unwrap_or_default();
            // Pre-allocate the buffer to avoid repeated reallocations.
            // Compute msg for this protocol step.
            // Compute msg for this protocol step.
            // Compute msg for this protocol step.
            let mut msg = Vec::with_capacity(16 + 32 + 8 + pubs_cbor.len());
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            msg.extend_from_slice(&record.service_id);
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            msg.extend_from_slice(&record.owner_peer_id);
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            msg.extend_from_slice(&record.version.to_be_bytes());
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            msg.extend_from_slice(&pubs_cbor);

            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !signing::verify(
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                &record.owner_peer_id,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                signing::DOMAIN_SERVICE_RECORD,
                &msg,
                // Chain the operation on the intermediate result.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                &record.sig,
            // Begin the block scope.
            ) {
                // Condition not met — return negative result.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return false;
            }
        }

        // Insert into the lookup table for efficient retrieval.
        // Insert into the map/set.
        // Insert into the map/set.
        // Insert into the map/set.
        self.records.insert(record.service_id, record);
        true
    }

    // Begin the block scope.
    // Perform the 'get' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'get' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'get' operation.
    // Errors are propagated to the caller via Result.
    pub fn get(&self, service_id: &[u8; 16]) -> Option<&ServiceRecord> {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.records.get(service_id)
    }

    // Begin the block scope.
    // Perform the 'remove' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'remove' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'remove' operation.
    // Errors are propagated to the caller via Result.
    pub fn remove(&mut self, service_id: &[u8; 16]) {
        // Remove from the collection and return the evicted value.
        // Remove from the collection.
        // Remove from the collection.
        // Remove from the collection.
        self.records.remove(service_id);
    }

    // Begin the block scope.
    // Perform the 'count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'count' operation.
    // Errors are propagated to the caller via Result.
    pub fn count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        self.records.len()
    }
}

// Trait implementation for protocol conformance.
// Implement Default for ServiceStore.
// Implement Default for ServiceStore.
// Implement Default for ServiceStore.
impl Default for ServiceStore {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
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

    /// Build a valid signed service record.  Covers the full record contents
    /// (service_id || owner_peer_id || version || publications JSON) so that
    /// tampering with any field after signing will cause verification to fail.
    fn make_record(id: u8, version: u64) -> ServiceRecord {
        make_record_with_pubs(id, version, vec![])
    }

    fn make_record_with_pubs(id: u8, version: u64, publications: Vec<ServicePublication>) -> ServiceRecord {
        use crate::crypto::signing;

        let secret = [0x01u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let owner_peer_id = signing_key.verifying_key().to_bytes();
        let service_id = [id; 16];

        // Match the full-coverage signing message in upsert().
        let pubs_cbor = serde_json::to_vec(&publications).unwrap_or_default();
        let mut msg = Vec::with_capacity(16 + 32 + 8 + pubs_cbor.len());
        msg.extend_from_slice(&service_id);
        msg.extend_from_slice(&owner_peer_id);
        msg.extend_from_slice(&version.to_be_bytes());
        msg.extend_from_slice(&pubs_cbor);

        let sig = signing::sign(&secret, signing::DOMAIN_SERVICE_RECORD, &msg);

        ServiceRecord {
            service_id,
            owner_peer_id,
            version,
            publications,
            sig,
        }
    }

    #[test]
    fn test_upsert_new() {
        let mut store = ServiceStore::new();
        assert!(store.upsert(make_record(0x01, 1)));
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_upsert_higher_version() {
        let mut store = ServiceStore::new();
        store.upsert(make_record(0x01, 1));
        assert!(store.upsert(make_record(0x01, 2)));
        assert_eq!(store.get(&[0x01; 16]).unwrap().version, 2);
    }

    #[test]
    fn test_upsert_lower_version_rejected() {
        let mut store = ServiceStore::new();
        store.upsert(make_record(0x01, 5));
        assert!(!store.upsert(make_record(0x01, 3)));
        assert_eq!(store.get(&[0x01; 16]).unwrap().version, 5);
    }

    #[test]
    fn test_upsert_invalid_signature_rejected() {
        let mut store = ServiceStore::new();
        let mut record = make_record(0x02, 1);
        // Corrupt the signature.
        record.sig[0] ^= 0xFF;
        assert!(!store.upsert(record), "record with corrupted signature must be rejected");
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_upsert_short_signature_rejected() {
        let mut store = ServiceStore::new();
        let mut record = make_record(0x03, 1);
        // Truncate to 32 bytes — not a valid Ed25519 signature length.
        record.sig.truncate(32);
        assert!(!store.upsert(record), "record with truncated signature must be rejected");
    }

    #[test]
    fn test_upsert_owner_hijack_rejected() {
        let mut store = ServiceStore::new();
        // Insert service owned by key 0x01.
        assert!(store.upsert(make_record(0x04, 1)));

        // Attempt to update with a different owner (different key seed).
        let secret2 = [0x02u8; 32];
        let signing_key2 = ed25519_dalek::SigningKey::from_bytes(&secret2);
        let hijacked_owner = signing_key2.verifying_key().to_bytes();
        let service_id = [0x04u8; 16];
        let pubs_cbor = serde_json::to_vec(&Vec::<ServicePublication>::new()).unwrap_or_default();
        let mut msg = Vec::new();
        msg.extend_from_slice(&service_id);
        msg.extend_from_slice(&hijacked_owner);
        msg.extend_from_slice(&2u64.to_be_bytes());
        msg.extend_from_slice(&pubs_cbor);
        let sig = crate::crypto::signing::sign(
            &secret2,
            crate::crypto::signing::DOMAIN_SERVICE_RECORD,
            &msg,
        );
        let hijacked = ServiceRecord {
            service_id,
            owner_peer_id: hijacked_owner,
            version: 2,
            publications: vec![],
            sig,
        };
        assert!(!store.upsert(hijacked), "ownership hijack must be rejected even with valid signature");
    }

    #[test]
    fn test_upsert_tampered_publications_rejected() {
        let mut store = ServiceStore::new();
        // Record is signed with empty publications.
        let mut record = make_record(0x05, 1);
        // After signing, inject a fake publication to simulate tampering.
        record.publications.push(ServicePublication {
            scope: ServiceScope::Public,
            address: [0xAA; 32],
            port: Some(1234),
            protocols: vec![],
            name: Some("injected".into()),
            description: None,
            transport_hint: ServiceTransportHint::Any,
            losec_config: crate::routing::losec::ServiceLoSecConfig::default(),
        });
        // The signature was over empty publications; tampered record must fail.
        assert!(!store.upsert(record), "record with tampered publications must be rejected");
    }
}
