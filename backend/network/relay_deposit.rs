//! Relay Deposits (§10.3)
//!
//! # What is a Relay?
//!
//! A relay is a dead drop — deposit a message, pick it up later.
//! Unlike store-and-forward (§6.8), relays are anonymous and
//! use size-class padding to prevent traffic analysis.
//!
//! # Size Classes (§10.3)
//!
//! All deposits are padded to one of 8 fixed size classes to
//! prevent observers from inferring content type by size:
//!
//! | Class | Padded Size |
//! |-------|-------------|
//! | 0 | 1 KB |
//! | 1 | 4 KB |
//! | 2 | 16 KB |
//! | 3 | 64 KB |
//! | 4 | 256 KB |
//! | 5 | 1 MB |
//! | 6 | 4 MB |
//! | 7 | 16 MB |
//!
//! # Retrieval Gate
//!
//! Optional HMAC-based gate that prevents anyone without the
//! secret key from retrieving the deposit. The depositor sets
//! an HMAC over the relay_id; the retriever must present a
//! matching proof derived from the same secret.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size class padded sizes (bytes).
pub const SIZE_CLASSES: [usize; 8] = [
    1_024,          // Class 0: 1 KB
    4_096,          // Class 1: 4 KB
    16_384,         // Class 2: 16 KB
    65_536,         // Class 3: 64 KB
    262_144,        // Class 4: 256 KB
    1_048_576,      // Class 5: 1 MB
    4_194_304,      // Class 6: 4 MB
    16_777_216,     // Class 7: 16 MB
];

/// Minimum relay expiry (seconds). 1 hour.
pub const MIN_EXPIRY_SECS: u64 = 3600;

/// Maximum relay expiry (seconds). 30 days.
pub const MAX_EXPIRY_SECS: u64 = 30 * 24 * 3600;

/// Maximum deposits held by a single relay server.
pub const MAX_DEPOSITS: usize = 10_000;

/// Maximum total storage for relay deposits (bytes). 500 MB.
pub const MAX_TOTAL_STORAGE: u64 = 500 * 1_048_576;

// ---------------------------------------------------------------------------
// Protocol Messages
// ---------------------------------------------------------------------------

/// A relay deposit (§10.3).
///
/// The depositor puts an encrypted payload into the relay.
/// The payload is padded to the size class boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayDeposit {
    /// Unique relay identifier.
    pub relay_id: [u8; 32],
    /// The padded encrypted payload.
    pub payload: Vec<u8>,
    /// When this deposit expires.
    pub expiry: u64,
    /// Depositor's ephemeral public key.
    pub deposit_pubkey: [u8; 32],
    /// Ed25519 signature over (relay_id || expiry).
    pub expiry_sig: Vec<u8>,
    /// Size class (0–7).
    pub size_class: u8,
    /// Optional retrieval gate (HMAC-based).
    pub retrieval_gate: Option<RetrievalGate>,
}

/// HMAC-based retrieval gate.
///
/// The retriever must present a proof that matches the HMAC
/// to retrieve the deposit. Prevents brute-force enumeration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetrievalGate {
    /// HMAC-SHA256(secret_key, relay_id).
    pub hmac: [u8; 32],
}

/// Request to retrieve a deposit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayRetrieve {
    /// Which relay to retrieve from.
    pub relay_id: [u8; 32],
    /// Gate proof (required if the deposit has a gate).
    pub gate_proof: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Size Class Helpers
// ---------------------------------------------------------------------------

/// Determine the size class for a given payload size.
///
/// Returns the smallest class that fits the payload.
/// Payloads larger than 16 MB are rejected.
pub fn size_class_for(payload_size: usize) -> Option<u8> {
    for (i, &class_size) in SIZE_CLASSES.iter().enumerate() {
        if payload_size <= class_size {
            return Some(i as u8);
        }
    }
    None // Too large.
}

/// Get the padded size for a size class.
pub fn padded_size(class: u8) -> usize {
    SIZE_CLASSES.get(class as usize).copied().unwrap_or(0)
}

/// Pad a payload to its size class boundary.
///
/// Appends a 4-byte little-endian length prefix, then the payload,
/// then zero-fill to the padded size. The receiver reads the length
/// prefix to know where real data ends.
///
/// Returns None if the payload is too large for any size class.
pub fn pad_payload(payload: &[u8]) -> Option<Vec<u8>> {
    let class = size_class_for(payload.len() + 4)?; // +4 for length prefix
    let target_size = padded_size(class);

    let mut padded = Vec::with_capacity(target_size);
    // 4-byte LE length prefix.
    padded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    padded.extend_from_slice(payload);
    // Zero-fill to target size.
    padded.resize(target_size, 0);

    Some(padded)
}

/// Remove padding from a relay payload.
///
/// Reads the 4-byte LE length prefix and extracts the real data.
/// Returns None if the format is invalid.
pub fn unpad_payload(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if 4 + len > padded.len() {
        return None;
    }
    Some(padded[4..4 + len].to_vec())
}

/// Compute an HMAC gate for a relay deposit.
///
/// `secret_key`: the shared secret between depositor and retriever.
/// `relay_id`: the unique relay identifier.
///
/// Returns the 32-byte HMAC that the retriever must present.
pub fn compute_gate_hmac(secret_key: &[u8], relay_id: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret_key)
        .expect("HMAC accepts any key length");
    mac.update(relay_id);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Verify a retrieval gate proof.
///
/// Checks that the provided proof matches the stored HMAC.
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_gate(gate: &RetrievalGate, proof: &[u8; 32]) -> bool {
    // Constant-time comparison.
    let mut diff = 0u8;
    for (a, b) in gate.hmac.iter().zip(proof.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Deposit Result
// ---------------------------------------------------------------------------

/// Result of attempting to store a relay deposit.
#[derive(Debug, PartialEq, Eq)]
pub enum DepositResult {
    /// Deposit accepted.
    Accepted,
    /// Payload too large for any size class.
    PayloadTooLarge,
    /// Deposit has already expired.
    AlreadyExpired,
    /// Expiry is out of allowed range.
    ExpiryOutOfRange,
    /// Server is at deposit capacity.
    CapacityFull,
    /// Invalid signature format.
    InvalidSignature,
    /// Size class doesn't match payload.
    SizeClassMismatch,
}

/// Result of attempting to retrieve a deposit.
#[derive(Debug, PartialEq, Eq)]
pub enum RetrieveResult {
    /// Deposit not found (wrong relay_id or already expired/collected).
    NotFound,
    /// Gate proof required but not provided.
    GateRequired,
    /// Gate proof doesn't match.
    GateInvalid,
}

// ---------------------------------------------------------------------------
// Relay Server
// ---------------------------------------------------------------------------

/// A relay deposit server (§10.3).
///
/// Manages anonymous dead-drop deposits with size-class padding,
/// HMAC retrieval gates, and expiry enforcement.
pub struct RelayServer {
    /// Stored deposits. Key: relay_id.
    deposits: HashMap<[u8; 32], RelayDeposit>,
    /// Total bytes stored across all deposits.
    total_bytes: u64,
}

impl RelayServer {
    /// Create a new relay server.
    pub fn new() -> Self {
        Self {
            deposits: HashMap::new(),
            total_bytes: 0,
        }
    }

    /// Accept a deposit.
    ///
    /// Validates: size class, expiry range, signature format,
    /// capacity limits.
    pub fn deposit(&mut self, deposit: RelayDeposit, now: u64) -> DepositResult {
        // Check expiry is in the future.
        if deposit.expiry <= now {
            return DepositResult::AlreadyExpired;
        }

        // Check expiry is within allowed range.
        let ttl = deposit.expiry - now;
        if !(MIN_EXPIRY_SECS..=MAX_EXPIRY_SECS).contains(&ttl) {
            return DepositResult::ExpiryOutOfRange;
        }

        // Verify the expiry signature using the depositor's public key.
        // Signs: DOMAIN_RELAY_REQUEST || relay_id || expiry (BE u64).
        // Prevents the relay from accepting forged expiry windows.
        {
            use crate::crypto::signing;
            if deposit.expiry_sig.len() != 64 {
                return DepositResult::InvalidSignature;
            }
            let mut msg = Vec::with_capacity(32 + 8);
            msg.extend_from_slice(&deposit.relay_id);
            msg.extend_from_slice(&deposit.expiry.to_be_bytes());
            if !signing::verify(
                &deposit.deposit_pubkey,
                signing::DOMAIN_RELAY_REQUEST,
                &msg,
                &deposit.expiry_sig,
            ) {
                return DepositResult::InvalidSignature;
            }
        }

        // Check size class validity.
        if deposit.size_class > 7 {
            return DepositResult::PayloadTooLarge;
        }

        // Check payload matches declared size class.
        let expected_size = padded_size(deposit.size_class);
        if deposit.payload.len() != expected_size {
            return DepositResult::SizeClassMismatch;
        }

        // Check capacity.
        if self.deposits.len() >= MAX_DEPOSITS {
            return DepositResult::CapacityFull;
        }
        if self.total_bytes + deposit.payload.len() as u64 > MAX_TOTAL_STORAGE {
            return DepositResult::CapacityFull;
        }

        // Accept the deposit.
        let bytes = deposit.payload.len() as u64;
        self.deposits.insert(deposit.relay_id, deposit);
        self.total_bytes += bytes;

        DepositResult::Accepted
    }

    /// Retrieve a deposit.
    ///
    /// If the deposit has a gate, the retriever must provide a
    /// valid proof. On successful retrieval, the deposit is removed.
    pub fn retrieve(
        &mut self,
        request: &RelayRetrieve,
        now: u64,
    ) -> Result<RelayDeposit, RetrieveResult> {
        // Check if the deposit exists and hasn't expired.
        let deposit = match self.deposits.get(&request.relay_id) {
            Some(d) if d.expiry > now => d,
            _ => return Err(RetrieveResult::NotFound),
        };

        // Check gate if present.
        if let Some(ref gate) = deposit.retrieval_gate {
            match &request.gate_proof {
                None => return Err(RetrieveResult::GateRequired),
                Some(proof) => {
                    if !verify_gate(gate, proof) {
                        return Err(RetrieveResult::GateInvalid);
                    }
                }
            }
        }

        // Remove and return the deposit.
        let deposit = self.deposits.remove(&request.relay_id).unwrap();
        self.total_bytes -= deposit.payload.len() as u64;
        Ok(deposit)
    }

    /// Garbage-collect expired deposits.
    pub fn gc(&mut self, now: u64) {
        let before = self.deposits.len();
        self.deposits.retain(|_, d| d.expiry > now);
        if self.deposits.len() < before {
            // Recalculate total bytes.
            self.total_bytes = self.deposits.values().map(|d| d.payload.len() as u64).sum();
        }
    }

    /// Number of stored deposits.
    pub fn count(&self) -> usize {
        self.deposits.len()
    }

    /// Total bytes stored.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

impl Default for RelayServer {
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

    /// Build a properly-signed relay deposit.
    ///
    /// Uses a deterministic keypair derived from `id` so tests are reproducible.
    fn make_deposit(id: u8, class: u8, expiry: u64) -> RelayDeposit {
        use crate::crypto::signing;
        let secret = [id; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let deposit_pubkey = signing_key.verifying_key().to_bytes();
        let relay_id = [id; 32];

        // Build the signed message exactly as deposit() expects.
        let mut msg = Vec::with_capacity(32 + 8);
        msg.extend_from_slice(&relay_id);
        msg.extend_from_slice(&expiry.to_be_bytes());
        let expiry_sig = signing::sign(&secret, signing::DOMAIN_RELAY_REQUEST, &msg);

        let psize = padded_size(class);
        RelayDeposit {
            relay_id,
            payload: vec![0x42; psize],
            expiry,
            deposit_pubkey,
            expiry_sig,
            size_class: class,
            retrieval_gate: None,
        }
    }

    #[test]
    fn test_size_class_selection() {
        assert_eq!(size_class_for(100), Some(0));
        assert_eq!(size_class_for(1024), Some(0));
        assert_eq!(size_class_for(1025), Some(1));
        assert_eq!(size_class_for(1_000_000), Some(5));
        assert_eq!(size_class_for(16_777_216), Some(7));
        assert_eq!(size_class_for(16_777_217), None);
    }

    #[test]
    fn test_padded_size() {
        assert_eq!(padded_size(0), 1_024);
        assert_eq!(padded_size(7), 16_777_216);
        assert_eq!(padded_size(8), 0);
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let data = b"hello relay world";
        let padded = pad_payload(data).unwrap();
        assert_eq!(padded.len(), 1_024); // Class 0.
        let recovered = unpad_payload(&padded).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_deposit_and_retrieve() {
        let mut server = RelayServer::new();
        let now = 1000;

        let dep = make_deposit(0x01, 0, now + 3600);
        assert_eq!(server.deposit(dep, now), DepositResult::Accepted);
        assert_eq!(server.count(), 1);

        let req = RelayRetrieve {
            relay_id: [0x01; 32],
            gate_proof: None,
        };
        let result = server.retrieve(&req, now);
        assert!(result.is_ok());
        assert_eq!(server.count(), 0);
    }

    #[test]
    fn test_gate_verification() {
        let secret = b"my-secret-key";
        let relay_id = [0xAA; 32];

        let hmac = compute_gate_hmac(secret, &relay_id);
        let gate = RetrievalGate { hmac };

        // Correct proof.
        let proof = compute_gate_hmac(secret, &relay_id);
        assert!(verify_gate(&gate, &proof));

        // Wrong proof.
        let wrong = [0xFF; 32];
        assert!(!verify_gate(&gate, &wrong));
    }

    #[test]
    fn test_gated_deposit() {
        let mut server = RelayServer::new();
        let now = 1000;
        let secret = b"secret";
        let relay_id = [0x02; 32];

        let hmac = compute_gate_hmac(secret, &relay_id);
        let mut dep = make_deposit(0x02, 0, now + 3600);
        dep.retrieval_gate = Some(RetrievalGate { hmac });

        server.deposit(dep, now);

        // Without proof: fails.
        let req_no_proof = RelayRetrieve { relay_id, gate_proof: None };
        assert_eq!(
            server.retrieve(&req_no_proof, now).unwrap_err(),
            RetrieveResult::GateRequired
        );

        // Wrong proof: fails.
        let req_wrong = RelayRetrieve { relay_id, gate_proof: Some([0xFF; 32]) };
        assert_eq!(
            server.retrieve(&req_wrong, now).unwrap_err(),
            RetrieveResult::GateInvalid
        );

        // Correct proof: succeeds.
        let proof = compute_gate_hmac(secret, &relay_id);
        let req_ok = RelayRetrieve { relay_id, gate_proof: Some(proof) };
        assert!(server.retrieve(&req_ok, now).is_ok());
    }

    #[test]
    fn test_expired_deposit_rejected() {
        let mut server = RelayServer::new();
        let dep = make_deposit(0x01, 0, 500); // Already expired at now=1000.
        assert_eq!(server.deposit(dep, 1000), DepositResult::AlreadyExpired);
    }

    #[test]
    fn test_size_class_mismatch() {
        let mut server = RelayServer::new();
        let mut dep = make_deposit(0x01, 0, 5000);
        dep.payload = vec![0; 500]; // Doesn't match class 0 (1024).
        assert_eq!(server.deposit(dep, 1000), DepositResult::SizeClassMismatch);
    }

    #[test]
    fn test_gc_removes_expired() {
        let mut server = RelayServer::new();
        let now = 1000;
        // Both deposits need TTL >= MIN_EXPIRY_SECS to be accepted.
        server.deposit(make_deposit(0x01, 0, now + MIN_EXPIRY_SECS + 100), now);
        server.deposit(make_deposit(0x02, 0, now + MIN_EXPIRY_SECS + 5000), now);
        assert_eq!(server.count(), 2);

        // GC after first expires, before second.
        server.gc(now + MIN_EXPIRY_SECS + 200);
        assert_eq!(server.count(), 1);
    }

    #[test]
    fn test_invalid_expiry_sig_rejected() {
        let mut server = RelayServer::new();
        let now = 1000;
        let mut dep = make_deposit(0x01, 0, now + MIN_EXPIRY_SECS + 100);
        // Corrupt the signature.
        dep.expiry_sig[0] ^= 0xFF;
        assert_eq!(server.deposit(dep, now), DepositResult::InvalidSignature,
            "corrupted expiry signature must be rejected");
    }

    #[test]
    fn test_wrong_key_expiry_sig_rejected() {
        use crate::crypto::signing;
        let mut server = RelayServer::new();
        let now = 1000;
        // Build a deposit signed by a different key (id=0xFF, not id=0x01).
        let mut dep = make_deposit(0x01, 0, now + MIN_EXPIRY_SECS + 100);
        let wrong_secret = [0xFFu8; 32];
        let mut msg = Vec::new();
        msg.extend_from_slice(&dep.relay_id);
        msg.extend_from_slice(&dep.expiry.to_be_bytes());
        dep.expiry_sig = signing::sign(&wrong_secret, signing::DOMAIN_RELAY_REQUEST, &msg);
        // deposit_pubkey still claims to be 0x01's key — signature won't verify.
        assert_eq!(server.deposit(dep, now), DepositResult::InvalidSignature,
            "expiry sig from wrong key must be rejected");
    }

    #[test]
    fn test_tampered_expiry_rejected() {
        let mut server = RelayServer::new();
        let now = 1000;
        let mut dep = make_deposit(0x01, 0, now + MIN_EXPIRY_SECS + 100);
        // Tamper with expiry after signing — signature covers original value.
        dep.expiry += 86400; // extend by 1 day
        assert_eq!(server.deposit(dep, now), DepositResult::InvalidSignature,
            "deposit with tampered expiry must be rejected");
    }
}
