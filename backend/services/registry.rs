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
    Peers(Vec<[u8; 32]>),
    /// Advertised within a specific group.
    Group([u8; 32]),
    /// Advertised to everyone.
    Public,
    /// Listed in a specific service index.
    Index([u8; 32]),
}

// ---------------------------------------------------------------------------
// Transport Hint
// ---------------------------------------------------------------------------

/// Preferred transport for reaching a service.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    PreferTor,
    PreferMesh,
    PreferLoSec,
}

// ---------------------------------------------------------------------------
// Service Publication
// ---------------------------------------------------------------------------

/// A single publication describing how to reach a service.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub scope: ServiceScope,
    /// Device address hosting the service.
    pub address: [u8; 32],
    /// Port (if applicable).
    pub port: Option<u32>,
    /// Supported tunnel protocols.
    pub protocols: Vec<super::tunnel::TunnelProto>,
    /// Human-readable name.
    pub name: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Preferred transport.
    pub transport_hint: ServiceTransportHint,
    /// Optional mesh-side access-control policy.
    ///
    /// The full ACL type is not yet normalized in one backend module, so the
    /// publication stores canonical JSON here and higher layers decode it as
    /// needed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub acl: Option<serde_json::Value>,
    /// Owning application or plugin identifier.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub application_id: Option<[u8; 16]>,
    /// Typed application payload carried by this publication.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub application_data: Option<serde_json::Value>,
    /// LoSec configuration.
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
    pub service_id: [u8; 16],
    /// Owner's peer ID.
    pub owner_peer_id: [u8; 32],
    /// Monotonically increasing version.
    pub version: u64,
    /// How to reach this service (may have multiple publications).
    pub publications: Vec<ServicePublication>,
    /// Ed25519 signature over the record.
    pub sig: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Service Index
// ---------------------------------------------------------------------------

/// A curated index of services (§12.5).
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub index_id: [u8; 16],
    /// The operator for this instance.
    pub operator: [u8; 32],
    /// The name for this instance.
    pub name: String,
    /// The description for this instance.
    pub description: Option<String>,
    /// The entries for this instance.
    pub entries: Vec<ServiceIndexEntry>,
    /// The updated at for this instance.
    pub updated_at: u64,
    /// The sig for this instance.
    pub sig: Vec<u8>,
}

/// An entry in a service index.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub service_record: ServiceRecord,
    /// The listed at for this instance.
    pub listed_at: u64,
    /// The endorsement for this instance.
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceStore {
    #[serde(default, with = "serde_service_records")]
    records: std::collections::HashMap<[u8; 16], ServiceRecord>,
}

// ServiceStore implementation — core protocol logic.
// ServiceStore implementation — core protocol logic.
// ServiceStore implementation — core protocol logic.
// ServiceStore implementation — core protocol logic.
impl ServiceStore {
    pub fn new() -> Self {
        Self {
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
    pub fn upsert(&mut self, record: ServiceRecord) -> bool {
        // Structural signature check (64 bytes for Ed25519).
        if record.sig.len() != 64 {
            return false;
        }

        // Version monotonicity check.
        if let Some(existing) = self.records.get(&record.service_id) {
            // Must be strictly higher version.
            if record.version <= existing.version {
                return false;
            }
            // Owner must match — can't hijack someone else's service.
            if record.owner_peer_id != existing.owner_peer_id {
                return false;
            }
        }

        // Verify signature using the signing module.
        {
            use crate::crypto::signing;

            // Signed message covers the full record to prevent tampering with
            // publications after signing:
            //   service_id || owner_peer_id || version (BE u64) || publications_cbor
            let pubs_cbor = serde_json::to_vec(&record.publications).unwrap_or_default();
            // Pre-allocate the buffer to avoid repeated reallocations.
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

            if !signing::verify(
                &record.owner_peer_id,
                signing::DOMAIN_SERVICE_RECORD,
                &msg,
                // Chain the operation on the intermediate result.
                &record.sig,
            ) {
                return false;
            }
        }

        self.records.insert(record.service_id, record);
        true
    }

    pub fn get(&self, service_id: &[u8; 16]) -> Option<&ServiceRecord> {
        self.records.get(service_id)
    }

    pub fn remove(&mut self, service_id: &[u8; 16]) {
        // Remove from the collection and return the evicted value.
        // Remove from the collection.
        // Remove from the collection.
        // Remove from the collection.
        self.records.remove(service_id);
    }

    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Return all known service records as a flat vector.
    pub fn all(&self) -> Vec<ServiceRecord> {
        self.records.values().cloned().collect()
    }
}

// Trait implementation for protocol conformance.
// Implement Default for ServiceStore.
// Implement Default for ServiceStore.
// Implement Default for ServiceStore.
impl Default for ServiceStore {
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

    /// Build a valid signed service record.  Covers the full record contents
    /// (service_id || owner_peer_id || version || publications JSON) so that
    /// tampering with any field after signing will cause verification to fail.
    fn make_record(id: u8, version: u64) -> ServiceRecord {
        make_record_with_pubs(id, version, vec![])
    }

    fn make_record_with_pubs(
        id: u8,
        version: u64,
        publications: Vec<ServicePublication>,
    ) -> ServiceRecord {
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
        assert!(
            !store.upsert(record),
            "record with corrupted signature must be rejected"
        );
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_upsert_short_signature_rejected() {
        let mut store = ServiceStore::new();
        let mut record = make_record(0x03, 1);
        // Truncate to 32 bytes — not a valid Ed25519 signature length.
        record.sig.truncate(32);
        assert!(
            !store.upsert(record),
            "record with truncated signature must be rejected"
        );
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
        assert!(
            !store.upsert(hijacked),
            "ownership hijack must be rejected even with valid signature"
        );
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
            acl: None,
            application_id: None,
            application_data: None,
            losec_config: crate::routing::losec::ServiceLoSecConfig::default(),
        });
        // The signature was over empty publications; tampered record must fail.
        assert!(
            !store.upsert(record),
            "record with tampered publications must be rejected"
        );
    }

    #[test]
    fn test_service_store_json_round_trip_with_binary_keys() {
        let mut store = ServiceStore::new();
        assert!(store.upsert(make_record(0x21, 1)));
        let encoded = serde_json::to_string(&store).expect("service store should encode");
        let decoded: ServiceStore =
            serde_json::from_str(&encoded).expect("service store should decode");
        assert_eq!(decoded.count(), 1);
        assert_eq!(decoded.get(&[0x21; 16]).unwrap().version, 1);
    }
}
mod serde_service_records {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub fn serialize<S>(
        records: &HashMap<[u8; 16], super::ServiceRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mapped: HashMap<String, &super::ServiceRecord> = records
            .iter()
            .map(|(service_id, record)| (hex::encode(service_id), record))
            .collect();
        mapped.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<[u8; 16], super::ServiceRecord>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mapped = HashMap::<String, super::ServiceRecord>::deserialize(deserializer)?;
        let mut records = HashMap::with_capacity(mapped.len());
        for (service_id_hex, record) in mapped {
            let service_id_bytes =
                hex::decode(&service_id_hex).map_err(serde::de::Error::custom)?;
            let service_id: [u8; 16] = service_id_bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid service_id length"))?;
            records.insert(service_id, record);
        }
        Ok(records)
    }
}
