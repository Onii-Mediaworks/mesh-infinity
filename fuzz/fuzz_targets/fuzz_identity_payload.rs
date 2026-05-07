// fuzz_targets/fuzz_identity_payload.rs — decrypted identity payload parser
// fuzz target (§3.6.2, §21.1.3)
//
// # What this target tests
//
// The decrypted identity payload contains secret key material and metadata.
// `SelfIdentity::from_payload()` must reject malformed payloads cleanly and
// reconstruct valid payloads without panicking or producing internally
// inconsistent key state.
//
// # Harness strategy
//
// 1. Feed arbitrary bytes directly into `SelfIdentity::from_payload()`.
// 2. Generate a valid identity, serialize its payload, and apply bounded
//    mutations to the length prefix, JSON segment, and secret-key tails.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::identity::self_identity::SelfIdentity;
use mesh_infinity::testing::arbitrary::ByteCursor;
use x25519_dalek::PublicKey as X25519Public;

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);

    let _ = SelfIdentity::from_payload(data);

    let display_name = if cursor.take_bool() {
        Some(String::from_utf8_lossy(cursor.take_bytes(32)).to_string())
    } else {
        None
    };
    let identity = SelfIdentity::generate(display_name);
    let mut payload = identity.serialize_payload().to_vec();

    match cursor.take_u8() % 5 {
        0 => {}
        1 => {
            if !payload.is_empty() {
                payload.truncate(cursor.take_bounded_usize(payload.len().saturating_sub(1)));
            }
        }
        2 => {
            if payload.len() >= 4 {
                payload[..4].copy_from_slice(&u32::MAX.to_le_bytes());
            }
        }
        3 => {
            if payload.len() > 4 {
                let index = 4 + cursor.take_bounded_usize(payload.len().saturating_sub(5));
                if let Some(byte) = payload.get_mut(index) {
                    *byte ^= cursor.take_u8().max(1);
                }
            }
        }
        4 => {
            if payload.len() >= 32 {
                let start = payload.len().saturating_sub(32);
                let end = start + 32;
                payload[start..end].copy_from_slice(&[0u8; 32]);
            }
        }
        _ => unreachable!(),
    }

    if let Some(decoded) = SelfIdentity::from_payload(&payload) {
        assert_eq!(
            decoded.ed25519_signing.verifying_key().to_bytes(),
            decoded.ed25519_pub,
            "decoded identity must keep Ed25519 public key consistent",
        );
        assert_eq!(
            X25519Public::from(&decoded.x25519_secret),
            decoded.x25519_pub,
            "decoded identity must keep X25519 public key consistent",
        );
        assert!(
            decoded.kem_decapsulation_key.is_empty() && decoded.kem_encapsulation_key.is_empty(),
            "from_payload must not fabricate KEM state before master-key reinjection",
        );
    }
});
