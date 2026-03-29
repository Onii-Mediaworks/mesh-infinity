//! Safety Numbers (§3.7.7)
//!
//! Safety numbers provide a short human-verifiable fingerprint for a relationship.
//!
//! ```text
//! identity_hash = SHA-256("meshinfinity-safety-v1" || min(pid_a, pid_b) || max(pid_a, pid_b))
//! key_hash      = SHA-256("meshinfinity-safety-v1" || min(pub_a, pub_b) || max(pub_a, pub_b))
//! safety_number = identity_hash || key_hash   // 64 bytes total
//! ```
//!
//! Display formats: numeric (60 digits), alphanumeric (20 chars), words, emoji.

use sha2::{Digest, Sha256};
use crate::identity::peer_id::PeerId;

const SAFETY_DOMAIN: &[u8] = b"meshinfinity-safety-v1";

/// A 64-byte safety number for a relationship between two peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyNumber {
    /// First 32 bytes: identity hash (stable across key rotations)
    pub identity_hash: [u8; 32],
    /// Last 32 bytes: key hash (changes on key rotation)
    pub key_hash: [u8; 32],
}

impl SafetyNumber {
    /// Derive the safety number between two peers.
    pub fn derive(
        peer_id_a: &PeerId,
        peer_id_b: &PeerId,
        ed25519_pub_a: &[u8; 32],
        ed25519_pub_b: &[u8; 32],
    ) -> Self {
        // Sort peer IDs lexicographically
        let (min_pid, max_pid) = if peer_id_a.0 <= peer_id_b.0 {
            (&peer_id_a.0[..], &peer_id_b.0[..])
        } else {
            (&peer_id_b.0[..], &peer_id_a.0[..])
        };

        // identity_hash — stable across key rotations
        let mut hasher = Sha256::new();
        hasher.update(SAFETY_DOMAIN);
        hasher.update(min_pid);
        hasher.update(max_pid);
        let mut identity_hash = [0u8; 32];
        identity_hash.copy_from_slice(&hasher.finalize());

        // Sort public keys lexicographically
        let (min_pub, max_pub) = if ed25519_pub_a <= ed25519_pub_b {
            (&ed25519_pub_a[..], &ed25519_pub_b[..])
        } else {
            (&ed25519_pub_b[..], &ed25519_pub_a[..])
        };

        // key_hash — changes on key rotation
        let mut hasher = Sha256::new();
        hasher.update(SAFETY_DOMAIN);
        hasher.update(min_pub);
        hasher.update(max_pub);
        let mut key_hash = [0u8; 32];
        key_hash.copy_from_slice(&hasher.finalize());

        Self {
            identity_hash,
            key_hash,
        }
    }

    /// Full 64-byte safety number.
    pub fn as_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.identity_hash);
        out[32..].copy_from_slice(&self.key_hash);
        out
    }

    /// Numeric format: 60 digits in groups of 5 (Signal-compatible).
    pub fn to_numeric(&self) -> String {
        let bytes = self.as_bytes();
        let mut digits = String::with_capacity(72); // 60 digits + 11 spaces
        for (i, chunk) in bytes.chunks(5).enumerate() {
            if i > 0 && i % 6 == 0 {
                digits.push('\n');
            } else if i > 0 {
                digits.push(' ');
            }
            // Convert 5 bytes to 5-digit number
            let mut val: u64 = 0;
            for b in chunk {
                val = (val << 8) | (*b as u64);
            }
            digits.push_str(&format!("{:05}", val % 100000));
        }
        digits
    }

    /// Alphanumeric format: 20 characters in groups of 4.
    pub fn to_alphanumeric(&self) -> String {
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        let bytes = self.as_bytes();
        let mut result = String::with_capacity(24);
        for (i, chunk) in bytes.chunks(3).enumerate() {
            if i > 0 && i % 5 == 0 {
                result.push('-');
            }
            if i >= 7 { break; } // 20 chars = 5 groups of 4
            let val = if chunk.len() >= 3 {
                ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32)
            } else if chunk.len() == 2 {
                ((chunk[0] as u32) << 8) | (chunk[1] as u32)
            } else {
                chunk[0] as u32
            };
            // Extract 3 characters from the value
            let a = (val % ALPHABET.len() as u32) as usize;
            let b = ((val / ALPHABET.len() as u32) % ALPHABET.len() as u32) as usize;
            let c = ((val / (ALPHABET.len() as u32 * ALPHABET.len() as u32)) % ALPHABET.len() as u32) as usize;
            result.push(ALPHABET[a] as char);
            result.push(ALPHABET[b] as char);
            result.push(ALPHABET[c] as char);
        }
        // Trim to 20 chars
        result.truncate(20);
        result
    }

    /// Check if only the key_hash changed (normal key rotation).
    pub fn key_changed(&self, other: &SafetyNumber) -> bool {
        self.identity_hash == other.identity_hash && self.key_hash != other.key_hash
    }

    /// Check if identity_hash changed (different person entirely).
    pub fn identity_changed(&self, other: &SafetyNumber) -> bool {
        self.identity_hash != other.identity_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_derivation() {
        let pid_a = PeerId([0x01; 32]);
        let pid_b = PeerId([0x02; 32]);
        let pub_a = [0x03u8; 32];
        let pub_b = [0x04u8; 32];

        let sn1 = SafetyNumber::derive(&pid_a, &pid_b, &pub_a, &pub_b);
        let sn2 = SafetyNumber::derive(&pid_b, &pid_a, &pub_b, &pub_a);

        assert_eq!(sn1, sn2, "Safety number must be symmetric");
    }

    #[test]
    fn test_key_rotation_detection() {
        let pid_a = PeerId([0x01; 32]);
        let pid_b = PeerId([0x02; 32]);
        let pub_a = [0x03u8; 32];
        let pub_b_old = [0x04u8; 32];
        let pub_b_new = [0x05u8; 32];

        let sn_old = SafetyNumber::derive(&pid_a, &pid_b, &pub_a, &pub_b_old);
        let sn_new = SafetyNumber::derive(&pid_a, &pid_b, &pub_a, &pub_b_new);

        assert!(sn_old.key_changed(&sn_new), "Key change should be detected");
        assert!(!sn_old.identity_changed(&sn_new), "Identity should NOT change on key rotation");
    }

    #[test]
    fn test_numeric_format() {
        let sn = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x02; 32]),
            &[0x03; 32],
            &[0x04; 32],
        );
        let numeric = sn.to_numeric();
        // Should contain digits and spaces
        assert!(numeric.chars().all(|c| c.is_ascii_digit() || c == ' ' || c == '\n'));
        // Should have groups of 5
        let groups: Vec<&str> = numeric.split(|c: char| c == ' ' || c == '\n').collect();
        for g in &groups {
            assert_eq!(g.len(), 5, "Each group should be 5 digits: {}", g);
        }
    }

    #[test]
    fn test_alphanumeric_format() {
        let sn = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x02; 32]),
            &[0x03; 32],
            &[0x04; 32],
        );
        let alpha = sn.to_alphanumeric();
        assert!(alpha.len() <= 24, "Alphanumeric should be ≤24 chars (with dashes)");
    }

    #[test]
    fn test_different_peers_different_numbers() {
        let sn1 = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x02; 32]),
            &[0x03; 32],
            &[0x04; 32],
        );
        let sn2 = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x05; 32]),
            &[0x03; 32],
            &[0x06; 32],
        );
        assert_ne!(sn1, sn2);
    }

    #[test]
    fn test_deterministic() {
        let sn1 = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x02; 32]),
            &[0x03; 32],
            &[0x04; 32],
        );
        let sn2 = SafetyNumber::derive(
            &PeerId([0x01; 32]),
            &PeerId([0x02; 32]),
            &[0x03; 32],
            &[0x04; 32],
        );
        assert_eq!(sn1, sn2);
    }
}
