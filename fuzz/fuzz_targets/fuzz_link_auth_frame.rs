// fuzz_targets/fuzz_link_auth_frame.rs — link handshake frame fuzz target (§5.1)
//
// # What this target tests
//
// Every accepted TCP socket feeds its first frames into
// `transport::link_auth` before the connection is keyed on a peer id.  Those
// bytes come from an unauthenticated stranger, so the parser and the
// responder verifier must:
//   - never panic on any byte sequence,
//   - never return `Ok` from `ResponderLink::accept_auth` unless the
//     presented key signed the responder's nonce (an attacker who did not
//     generate the key cannot do this, so an `Ok` here with a fuzz-chosen
//     signature would be a verifier bug),
//   - reject every hello whose claimed sender is not the hash of its key.
//
// # Input layout
//
// The first byte selects the step under test; the rest is the frame.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::identity::peer_id::PeerId;
use mesh_infinity::transport::link_auth::{
    claimed_sender_matches, parse_auth, parse_hello, LinkHello, LinkSigner, ResponderLink,
};

/// A fixed local signer so the responder path can be exercised; the seed is
/// a test-only constant, never a real identity.
fn fixture_signer() -> LinkSigner {
    let seed = [0x5Au8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    LinkSigner::new(signing_key.verifying_key().to_bytes(), seed)
}

fuzz_target!(|data: &[u8]| {
    let Some((&step, frame_bytes)) = data.split_first() else {
        return;
    };
    // Must not panic regardless of input.
    let Ok(frame) = serde_json::from_slice::<serde_json::Value>(frame_bytes) else {
        return;
    };
    match step % 4 {
        0 => {
            if let Ok(hello) = parse_hello(&frame) {
                // Invariant: the id is always the hash of the presented key.
                assert_eq!(
                    hello.peer_id,
                    PeerId::from_ed25519_pub(&hello.ed25519_public)
                );
            }
        }
        1 => {
            if let Ok(auth) = parse_auth(&frame) {
                assert_eq!(auth.peer_id, PeerId::from_ed25519_pub(&auth.ed25519_public));
                assert_eq!(auth.signature.len(), 64);
            }
        }
        2 => {
            // Responder path: answer a hello built from fuzz bytes, then feed
            // the same fuzz frame as the initiator's auth.  Without the hello
            // key's private half the signature cannot verify.
            let key = [0x11u8; 32];
            let hello = LinkHello {
                peer_id: PeerId::from_ed25519_pub(&key),
                ed25519_public: key,
                nonce: [0x22u8; 32],
            };
            let (responder, _challenge) =
                ResponderLink::answer(fixture_signer(), hello, [0x33u8; 32]);
            assert!(responder.accept_auth(&frame).is_err());
        }
        _ => {
            // Sender binding never panics on arbitrary field shapes.
            let _ = claimed_sender_matches(&frame, &PeerId([0u8; 32]));
        }
    }
});
