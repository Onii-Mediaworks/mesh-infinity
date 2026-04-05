//! Fuzz testing targets for protocol-critical parsers (Spec SS 21.1.3, SS 21.2).
//!
//! # Purpose
//!
//! Every code path that processes externally-originating bytes is a potential
//! attack surface.  Fuzz testing feeds random, mutated, and adversarial inputs
//! into these parsers to find crashes, panics, hangs, and memory-safety
//! violations before an attacker does.
//!
//! # How these targets are used
//!
//! Each `fuzz_*` function is a self-contained harness that:
//! 1. Accepts arbitrary `&[u8]` input (provided by `cargo-fuzz` or similar).
//! 2. Feeds the input to the parser under test.
//! 3. Returns `true` if no panic occurred (the expected outcome for all inputs).
//!
//! The actual fuzzing loop is driven by external tools (`cargo fuzz`,
//! `libFuzzer`, `AFL`, etc.) -- this module only provides the targets.
//!
//! # Panic-safety contract
//!
//! Every fuzz target catches panics via `std::panic::catch_unwind`.  A target
//! that panics on ANY input is a bug that must be fixed.  The `catch_unwind`
//! wrapper is present so that the fuzz harness can report failures cleanly
//! without aborting the entire fuzz campaign.
//!
//! # CI integration
//!
//! Per SS 21.2.3, CI runs each target for 60 seconds on every PR (smoke mode)
//! and 24 hours nightly on main (extended mode).  Crash-triggering inputs are
//! committed to `fuzz/corpus/<target>/` as regression entries.

use std::panic;

use crate::crypto::double_ratchet::RatchetHeader;
use crate::crypto::ring_sig::{ring_verify, RingSignature};
use crate::identity::peer_id::PeerId;
use crate::transport::kcp::KcpState;
use crate::transport::mixnet::{MixRole, MixnetNode, MixnetPacket, MIXNET_MTU};
use crate::transport::wireguard::{respond_to_handshake, PendingInitiatorHandshake};

// ---------------------------------------------------------------------------
// Target 1: KCP packet parsing
// ---------------------------------------------------------------------------

/// Fuzz target: KCP packet parsing.
///
/// Feeds random bytes into `KcpState::input()`, which parses the KCP segment
/// header (24 bytes: conv, cmd, frg, wnd, ts, sn, una, len) and processes the
/// payload.  Malformed packets must be silently dropped -- never panic.
///
/// Attack surface: any peer on the mesh can send arbitrary KCP segments inside
/// a WireGuard tunnel.  A compromised peer could craft pathological headers
/// (e.g. `len` exceeding remaining data, `frg` overflow, `sn` wrap-around).
pub fn fuzz_kcp_input(data: &[u8]) -> bool {
    // Wrap the entire parsing path in catch_unwind to detect panics.
    let result = panic::catch_unwind(|| {
        // Create a KcpState with conversation ID 0 and a no-op output callback.
        // The conv value doesn't matter for fuzz testing -- we're testing the
        // parser, not the session negotiation.
        let mut kcp = KcpState::new(0, |_output: &[u8]| {
            // Discard all output -- we only care about crash-safety.
        });

        // Feed the arbitrary bytes into the KCP input parser.
        // This exercises the full segment parsing path: header decode,
        // command dispatch (PUSH/ACK/WASK/WINS), fragment reassembly,
        // and window management.
        kcp.input(data);

        // Also exercise the flush path, which processes the parsed segments
        // and may trigger retransmission logic, window probes, etc.
        kcp.flush();
    });

    // Return true if no panic occurred; false if the parser panicked.
    result.is_ok()
}

// ---------------------------------------------------------------------------
// Target 2: WireGuard packet decryption
// ---------------------------------------------------------------------------

/// Fuzz target: WireGuard packet decryption.
///
/// Tests that malformed WireGuard packets (arbitrary ciphertext with invalid
/// nonces, truncated tags, wrong-length payloads) don't cause panics.  The
/// `decrypt()` method must return `Err(...)` for all invalid inputs without
/// crashing.
///
/// Attack surface: the WireGuard decryption path processes raw bytes from the
/// network before any higher-layer parsing occurs.  It is the first line of
/// defense against malformed packets.
pub fn fuzz_wireguard_decrypt(data: &[u8]) -> bool {
    // Wrap in catch_unwind to detect panics in the decryption path.
    let result = panic::catch_unwind(|| {
        // Create a WireGuard session via the full handshake protocol.
        // We use deterministic keys so the session is consistently constructed
        // across fuzz runs -- the fuzz input is the *packet*, not the keys.
        let initiator_secret = x25519_dalek::StaticSecret::from([0xAA; 32]);
        let responder_secret = x25519_dalek::StaticSecret::from([0xBB; 32]);
        let responder_pub = x25519_dalek::PublicKey::from(&responder_secret);
        let psk = zeroize::Zeroizing::new([0u8; 32]);

        // Peer IDs for both sides of the handshake.
        let initiator_id = PeerId([0x11; 32]);
        let responder_id = PeerId([0x22; 32]);

        // Step 1: Initiator creates handshake.
        let (pending, init_msg) =
            PendingInitiatorHandshake::new(initiator_secret, responder_pub, psk.clone());

        // Step 2: Responder processes the handshake init and produces a session.
        let (responder_session, response) = match respond_to_handshake(
            &init_msg,
            &responder_secret,
            &psk,
            responder_id,
            initiator_id,
        ) {
            Ok(result) => result,
            // If the handshake fails (e.g. due to key issues), skip decrypt test.
            Err(_) => return,
        };

        // Step 3: Initiator completes the handshake to get a session.
        let _initiator_session = match pending.complete(&response, initiator_id, responder_id) {
            Ok(session) => session,
            Err(_) => return,
        };

        // Feed arbitrary bytes into the responder's decrypt path.  This exercises:
        // - Nonce extraction (first 8 bytes)
        // - Anti-replay window check
        // - ChaCha20-Poly1305 AEAD decryption
        // - Tag verification
        // All invalid inputs must return Err, never panic.
        let _result = responder_session.decrypt(data);
    });

    // Return true if no panic occurred.
    result.is_ok()
}

// ---------------------------------------------------------------------------
// Target 3: JSON frame parsing
// ---------------------------------------------------------------------------

/// Fuzz target: JSON frame parsing (inbound messages).
///
/// Tests that arbitrary bytes fed to `serde_json::from_slice` with our
/// message types don't cause panics.  JSON is the wire format for all FFI
/// boundary data and for some internal message framing.
///
/// Attack surface: JSON strings arrive from the Flutter UI via FFI and
/// potentially from other peers (in future protocol versions).  A malformed
/// JSON payload must be rejected, not cause undefined behavior.
pub fn fuzz_json_frame(data: &[u8]) -> bool {
    // Wrap in catch_unwind for panic safety.
    let result = panic::catch_unwind(|| {
        // Attempt to parse the input as a generic JSON value first.
        // This exercises the full JSON parser: string escapes, number parsing,
        // nested objects/arrays, UTF-8 validation, etc.
        let _generic: Result<serde_json::Value, _> = serde_json::from_slice(data);

        // Also attempt to parse as specific protocol types that cross the
        // FFI boundary.  These exercise serde's field matching, missing-field
        // handling, and type coercion logic.

        // Room JSON: {id, name, lastMessage, unreadCount, timestamp}
        let room: Result<FuzzRoom, _> = serde_json::from_slice(data);

        // Message JSON: {id, roomId, sender, text, timestamp, isOutgoing}
        let msg: Result<FuzzMessage, _> = serde_json::from_slice(data);

        // Settings JSON: {nodeMode, enableTor, enableClearnet, ...}
        let settings: Result<FuzzSettings, _> = serde_json::from_slice(data);

        // Peer JSON: {id, name, trustLevel, status}
        let peer: Result<FuzzPeer, _> = serde_json::from_slice(data);

        let _ = room.as_ref().ok().map(FuzzRoom::touch);
        let _ = msg.as_ref().ok().map(FuzzMessage::touch);
        let _ = settings.as_ref().ok().map(FuzzSettings::touch);
        let _ = peer.as_ref().ok().map(FuzzPeer::touch);
    });

    // Return true if no panic occurred.
    result.is_ok()
}

/// Minimal Room struct for JSON fuzz testing.
/// Mirrors the FFI JSON contract without importing runtime-dependent types.
#[derive(serde::Deserialize)]
struct FuzzRoom {
    /// Room identifier.
    id: Option<String>,
    /// Room display name.
    name: Option<String>,
    /// Last message preview text.
    #[serde(rename = "lastMessage")]
    last_message: Option<String>,
    /// Count of unread messages.
    #[serde(rename = "unreadCount")]
    unread_count: Option<u32>,
    /// Unix timestamp of last activity.
    timestamp: Option<u64>,
}

impl FuzzRoom {
    fn touch(&self) -> usize {
        self.id.as_deref().unwrap_or_default().len()
            + self.name.as_deref().unwrap_or_default().len()
            + self.last_message.as_deref().unwrap_or_default().len()
            + self.unread_count.unwrap_or_default() as usize
            + self.timestamp.unwrap_or_default() as usize
    }
}

/// Minimal Message struct for JSON fuzz testing.
/// Mirrors the FFI JSON contract for message objects.
#[derive(serde::Deserialize)]
struct FuzzMessage {
    /// Message identifier.
    id: Option<String>,
    /// Room this message belongs to.
    #[serde(rename = "roomId")]
    room_id: Option<String>,
    /// Sender peer ID or display name.
    sender: Option<String>,
    /// Message body text.
    text: Option<String>,
    /// Unix timestamp.
    timestamp: Option<u64>,
    /// Whether this message was sent by us.
    #[serde(rename = "isOutgoing")]
    is_outgoing: Option<bool>,
}

impl FuzzMessage {
    fn touch(&self) -> usize {
        self.id.as_deref().unwrap_or_default().len()
            + self.room_id.as_deref().unwrap_or_default().len()
            + self.sender.as_deref().unwrap_or_default().len()
            + self.text.as_deref().unwrap_or_default().len()
            + self.timestamp.unwrap_or_default() as usize
            + usize::from(self.is_outgoing.unwrap_or(false))
    }
}

/// Minimal Settings struct for JSON fuzz testing.
/// Mirrors the FFI JSON contract for settings objects.
#[derive(serde::Deserialize)]
struct FuzzSettings {
    /// Node operating mode (full, relay, client).
    #[serde(rename = "nodeMode")]
    node_mode: Option<String>,
    /// Whether Tor transport is enabled.
    #[serde(rename = "enableTor")]
    enable_tor: Option<bool>,
    /// Whether clearnet transport is enabled.
    #[serde(rename = "enableClearnet")]
    enable_clearnet: Option<bool>,
    /// Whether mesh discovery (mDNS) is active.
    #[serde(rename = "meshDiscovery")]
    mesh_discovery: Option<bool>,
}

impl FuzzSettings {
    fn touch(&self) -> usize {
        self.node_mode.as_deref().unwrap_or_default().len()
            + usize::from(self.enable_tor.unwrap_or(false))
            + usize::from(self.enable_clearnet.unwrap_or(false))
            + usize::from(self.mesh_discovery.unwrap_or(false))
    }
}

/// Minimal Peer struct for JSON fuzz testing.
/// Mirrors the FFI JSON contract for peer objects.
#[derive(serde::Deserialize)]
struct FuzzPeer {
    /// Peer identifier (hex public key hash).
    id: Option<String>,
    /// Peer display name.
    name: Option<String>,
    /// Trust level (0 = untrusted, 3 = fully trusted).
    #[serde(rename = "trustLevel")]
    trust_level: Option<u32>,
    /// Online status string (online/offline/idle).
    status: Option<String>,
}

impl FuzzPeer {
    fn touch(&self) -> usize {
        self.id.as_deref().unwrap_or_default().len()
            + self.name.as_deref().unwrap_or_default().len()
            + self.trust_level.unwrap_or_default() as usize
            + self.status.as_deref().unwrap_or_default().len()
    }
}

// ---------------------------------------------------------------------------
// Target 4: Double Ratchet header parsing
// ---------------------------------------------------------------------------

/// Fuzz target: Double Ratchet header parsing.
///
/// The `RatchetHeader` is deserialized from bytes on every incoming encrypted
/// message.  It contains the sender's ratchet public key (32 bytes) and two
/// u32 counters (previous chain length, message number).  Malformed headers
/// must be rejected without panic.
///
/// Attack surface: any peer can send an encrypted message with an arbitrary
/// header.  The header is parsed BEFORE decryption of the message body, so
/// it processes untrusted bytes directly.
pub fn fuzz_ratchet_header(data: &[u8]) -> bool {
    // Wrap in catch_unwind for panic safety.
    let result = panic::catch_unwind(|| {
        // Attempt binary deserialization of the header.
        // A valid RatchetHeader is 40 bytes: 32 (ratchet_pub) + 4 (prev_chain_len)
        // + 4 (msg_num).  Inputs of other sizes must not crash.
        if data.len() >= 40 {
            // Extract the ratchet public key (32 bytes).
            let mut ratchet_pub = [0u8; 32];
            ratchet_pub.copy_from_slice(&data[..32]);

            // Extract the previous chain length (4 bytes, little-endian).
            let prev_chain_len = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);

            // Extract the message number (4 bytes, little-endian).
            let msg_num = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

            // Construct the header to verify the struct can handle any values.
            let _header = RatchetHeader {
                ratchet_pub,
                prev_chain_len,
                msg_num,
            };
        }

        // Also attempt JSON deserialization (the header may arrive as JSON
        // in some protocol paths, e.g. debug/diagnostic dumps).
        let _json_header: Result<RatchetHeader, _> = serde_json::from_slice(data);
    });

    // Return true if no panic occurred.
    result.is_ok()
}

// ---------------------------------------------------------------------------
// Target 5: Ring signature verification
// ---------------------------------------------------------------------------

/// Fuzz target: Ring signature verification.
///
/// Tests that arbitrary bytes interpreted as ring signature components don't
/// cause panics in the verification path.  The AOS ring signature verifier
/// (SS 3.5.2) must gracefully reject malformed signatures without crashing.
///
/// Attack surface: ring signatures arrive from group members and are verified
/// by every recipient.  A malicious group member could craft a pathological
/// signature to crash other nodes.
pub fn fuzz_ring_verify(data: &[u8]) -> bool {
    // Wrap in catch_unwind for panic safety.
    let result = panic::catch_unwind(|| {
        // We need at least enough bytes to construct a minimal ring (2 keys)
        // and a minimal signature (2 challenges + 2 responses).
        //
        // Ring: 2 * 32 = 64 bytes for public keys.
        // Signature: 2*32 (challenges) + 2*32 (responses) = 128 bytes.
        // Total minimum: 64 + 128 = 192 bytes.
        //
        // For shorter inputs, we pad with zeros to exercise the verifier
        // with degenerate but structurally complete inputs.

        // Build a ring of 2 public keys from the fuzz input.
        let mut ring = [[0u8; 32]; 2];
        if data.len() >= 32 {
            ring[0].copy_from_slice(&data[..32]);
        }
        if data.len() >= 64 {
            ring[1].copy_from_slice(&data[32..64]);
        }

        // Build a signature from the remaining bytes (or zeros if too short).
        let mut c0 = [0u8; 32];
        let mut c1 = [0u8; 32];
        let mut r0 = [0u8; 32];
        let mut r1 = [0u8; 32];

        // Fill signature fields from fuzz data if available.
        let mut offset = 64;
        if data.len() >= offset + 32 {
            c0.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
        }
        if data.len() >= offset + 32 {
            c1.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
        }
        if data.len() >= offset + 32 {
            r0.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
        }
        if data.len() >= offset + 32 {
            r1.copy_from_slice(&data[offset..offset + 32]);
        }

        // Construct the RingSignature and call verify.
        let sig = RingSignature {
            c: vec![c0, c1],
            r: vec![r0, r1],
        };

        // The message to verify against is whatever bytes remain, or empty.
        let msg_start = 64 + 128;
        let message = if data.len() > msg_start {
            &data[msg_start..]
        } else {
            &[]
        };

        // Call the verifier -- must never panic, only return true/false.
        let _valid = ring_verify(&ring, message, &sig);
    });

    // Return true if no panic occurred.
    result.is_ok()
}

// ---------------------------------------------------------------------------
// Target 6: Cover traffic packet generation
// ---------------------------------------------------------------------------

/// Fuzz target: cover traffic packet generation and parsing.
///
/// Tests that the mixnet packet construction and parsing path handles
/// arbitrary byte inputs without panicking.  Cover traffic is generated
/// continuously by mix nodes and must be indistinguishable from real
/// traffic (SS 5.25).
///
/// Attack surface: mixnet packets arrive from the network as raw 1500-byte
/// frames.  A malicious node could inject malformed packets into the mix
/// network to crash relaying nodes.
pub fn fuzz_cover_traffic(data: &[u8]) -> bool {
    // Wrap in catch_unwind for panic safety.
    let result = panic::catch_unwind(|| {
        // Test 1: Parse arbitrary bytes as a MixnetPacket.
        // The parser expects exactly MIXNET_MTU (1500) bytes.  If the input
        // is exactly that size, exercise from_bytes().  Otherwise verify
        // that out-of-range sizes are handled gracefully.
        if data.len() == MIXNET_MTU {
            // Exactly 1500 bytes -- parse as a complete packet.
            let buf: &[u8; MIXNET_MTU] = data.try_into().expect("length verified");
            let packet = MixnetPacket::from_bytes(buf);

            // Exercise accessors that inspect the parsed packet fields.
            let _is_dummy = packet.is_dummy();
            let _version = packet.version;

            // Round-trip: serialize back and verify the bytes match.
            let rebuf = packet.to_bytes();
            assert_eq!(
                &rebuf[..],
                data,
                "round-trip serialization must be lossless"
            );
        }

        // Test 2: Exercise the MixnetNode receive path with padded input.
        // The receive() method requires exactly MIXNET_MTU bytes, so we
        // construct a correctly-sized buffer from the fuzz data.
        let mut padded = [0u8; MIXNET_MTU];
        let copy_len = data.len().min(MIXNET_MTU);
        padded[..copy_len].copy_from_slice(&data[..copy_len]);

        // Create a minimal MixnetNode (client role, dummy key) and feed it
        // the padded packet.  The node should handle any content gracefully.
        let mut node = MixnetNode::new(MixRole::Client, [0x42; 32]);
        let _result = node.receive(&padded);

        // Test 3: Also exercise the tick() path, which processes queued
        // packets and may generate cover traffic.
        node.tick();
    });

    // Return true if no panic occurred.
    result.is_ok()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- KCP input fuzz target tests ----------------------------------------

    /// Empty input must not panic -- the KCP parser should silently discard
    /// packets shorter than the 24-byte header.
    #[test]
    fn kcp_empty_input_no_panic() {
        assert!(fuzz_kcp_input(&[]));
    }

    /// Single byte input -- below the minimum header size (24 bytes).
    /// The parser must discard it without crashing.
    #[test]
    fn kcp_short_input_no_panic() {
        assert!(fuzz_kcp_input(&[0xFF]));
    }

    /// Random 256-byte input -- large enough to contain a header plus payload.
    /// Exercises the full parsing path with garbage data.
    #[test]
    fn kcp_random_input_no_panic() {
        let data: Vec<u8> = (0..256).map(|i| (i * 37 + 13) as u8).collect();
        assert!(fuzz_kcp_input(&data));
    }

    /// Exactly 24 bytes (minimum header size) with all zeros.
    /// Tests the boundary condition where the header is complete but the
    /// payload is empty.
    #[test]
    fn kcp_header_only_no_panic() {
        assert!(fuzz_kcp_input(&[0u8; 24]));
    }

    /// Large input (4 KB) to test buffer handling beyond normal packet sizes.
    #[test]
    fn kcp_large_input_no_panic() {
        let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        assert!(fuzz_kcp_input(&data));
    }

    // --- WireGuard decrypt fuzz target tests --------------------------------

    /// Empty input -- too short for even the nonce (8 bytes) + tag (16 bytes).
    #[test]
    fn wireguard_empty_input_no_panic() {
        assert!(fuzz_wireguard_decrypt(&[]));
    }

    /// Exactly 24 bytes (minimum: 8-byte nonce + 16-byte tag, zero payload).
    #[test]
    fn wireguard_min_length_no_panic() {
        assert!(fuzz_wireguard_decrypt(&[0u8; 24]));
    }

    /// Random 128-byte input -- large enough for a realistic packet.
    #[test]
    fn wireguard_random_input_no_panic() {
        let data: Vec<u8> = (0..128).map(|i| (i * 53 + 7) as u8).collect();
        assert!(fuzz_wireguard_decrypt(&data));
    }

    // --- JSON frame fuzz target tests ---------------------------------------

    /// Empty input -- not valid JSON.
    #[test]
    fn json_empty_input_no_panic() {
        assert!(fuzz_json_frame(&[]));
    }

    /// Valid JSON object with unexpected fields.
    #[test]
    fn json_valid_but_wrong_fields_no_panic() {
        let data = br#"{"foo": "bar", "baz": 42}"#;
        assert!(fuzz_json_frame(data));
    }

    /// Deeply nested JSON to test stack depth handling.
    #[test]
    fn json_deeply_nested_no_panic() {
        // 128 levels of nesting -- serde_json handles this gracefully.
        let mut data = String::new();
        for _ in 0..128 {
            data.push('{');
            data.push_str("\"a\":");
        }
        data.push_str("1");
        for _ in 0..128 {
            data.push('}');
        }
        assert!(fuzz_json_frame(data.as_bytes()));
    }

    /// Binary garbage -- not valid UTF-8.
    #[test]
    fn json_binary_garbage_no_panic() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        assert!(fuzz_json_frame(&data));
    }

    // --- Ratchet header fuzz target tests -----------------------------------

    /// Empty input -- too short for a valid header.
    #[test]
    fn ratchet_empty_input_no_panic() {
        assert!(fuzz_ratchet_header(&[]));
    }

    /// Exactly 40 bytes -- valid header size.
    #[test]
    fn ratchet_exact_size_no_panic() {
        assert!(fuzz_ratchet_header(&[0xAA; 40]));
    }

    /// Oversized input -- more bytes than needed.
    #[test]
    fn ratchet_oversized_no_panic() {
        let data: Vec<u8> = (0..200).map(|i| (i * 41) as u8).collect();
        assert!(fuzz_ratchet_header(&data));
    }

    /// Valid JSON representation of a RatchetHeader.
    #[test]
    fn ratchet_valid_json_no_panic() {
        let json = br#"{"ratchet_pub":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"prev_chain_len":5,"msg_num":10}"#;
        assert!(fuzz_ratchet_header(json));
    }

    // --- Ring signature verify fuzz target tests ----------------------------

    /// Empty input -- degenerate ring with zero-filled keys.
    #[test]
    fn ring_verify_empty_input_no_panic() {
        assert!(fuzz_ring_verify(&[]));
    }

    /// Random 256-byte input -- enough to populate ring keys and partial sig.
    #[test]
    fn ring_verify_random_input_no_panic() {
        let data: Vec<u8> = (0..256).map(|i| (i * 59 + 3) as u8).collect();
        assert!(fuzz_ring_verify(&data));
    }

    /// All-ones input -- tests degenerate key values.
    #[test]
    fn ring_verify_all_ones_no_panic() {
        assert!(fuzz_ring_verify(&[0xFF; 300]));
    }

    // --- Cover traffic fuzz target tests ------------------------------------

    /// Empty input -- padded to MIXNET_MTU internally.
    #[test]
    fn cover_traffic_empty_input_no_panic() {
        assert!(fuzz_cover_traffic(&[]));
    }

    /// Exactly MIXNET_MTU bytes -- exercises the from_bytes() path.
    #[test]
    fn cover_traffic_exact_mtu_no_panic() {
        assert!(fuzz_cover_traffic(&[0x42; MIXNET_MTU]));
    }

    /// Short input (100 bytes) -- exercises padding logic.
    #[test]
    fn cover_traffic_short_input_no_panic() {
        let data: Vec<u8> = (0..100).map(|i| (i * 71) as u8).collect();
        assert!(fuzz_cover_traffic(&data));
    }

    /// Large input (3000 bytes, beyond MTU) -- must not panic.
    #[test]
    fn cover_traffic_oversized_no_panic() {
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        assert!(fuzz_cover_traffic(&data));
    }
}
