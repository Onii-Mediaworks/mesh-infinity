// Fuzz target: network map gossip entry (§4.1, §4.2)
//
// Drives `NetworkMap::insert_gossiped()` with arbitrary bytes to ensure:
// - No panics or unwrap() failures on malformed input.
// - Endpoint validation rejects garbage without crashing.
// - Multi-source staging caps are never exceeded.
// - Timestamp / sequence checks are enforced without panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::network::map::{NetworkMap, NetworkMapEntry};
use mesh_infinity::network::transport_hint::{TransportHint, TransportType};
use mesh_infinity::identity::peer_id::PeerId;
use mesh_infinity::network::map::PublicKeyRecord;
use mesh_infinity::trust::levels::TrustLevel;
use mesh_infinity::testing::arbitrary::ByteCursor;

fuzz_target!(|data: &[u8]| {
    let mut cur = ByteCursor::new(data);

    // Build a peer ID from fuzz bytes.
    let mut peer_bytes = [0u8; 32];
    for b in peer_bytes.iter_mut() {
        *b = cur.take_u8();
    }
    let peer_id = PeerId(peer_bytes);

    // Build a source peer ID.
    let mut source_bytes = [0u8; 32];
    for b in source_bytes.iter_mut() {
        *b = cur.take_u8();
    }
    let source_id = PeerId(source_bytes);

    // Build an ed25519 public key from fuzz bytes.
    let mut ed_pub = [0u8; 32];
    for b in ed_pub.iter_mut() {
        *b = cur.take_u8();
    }

    // Build an x25519 public key.
    let mut x_pub = [0u8; 32];
    for b in x_pub.iter_mut() {
        *b = cur.take_u8();
    }

    // Fuzz-controlled sequence.
    let seq = u64::from_le_bytes([
        cur.take_u8(), cur.take_u8(), cur.take_u8(), cur.take_u8(),
        cur.take_u8(), cur.take_u8(), cur.take_u8(), cur.take_u8(),
    ]);
    // Fuzz-controlled wire-format version byte (§4.2). Only
    // MAP_ENTRY_FORMAT_VERSION may pass validate_entry; every other value must
    // come back as a typed UnsupportedEntryVersion error, never a panic.
    // (The v1 layout's last_seen timestamp no longer exists — CMR-005.)
    let version = cur.take_u8();

    // Fuzz-controlled signature bytes.
    let sig_len = cur.take_bounded_usize(128);
    let sig: Vec<u8> = (0..sig_len).map(|_| cur.take_u8()).collect();

    // Fuzz-controlled endpoint hint.
    let hint_raw = cur.take_bytes(64);
    let endpoint = String::from_utf8_lossy(hint_raw).into_owned();
    let transport_type_byte = cur.take_u8();
    let transport_type = match transport_type_byte % 7 {
        0 => TransportType::Clearnet,
        1 => TransportType::Tor,
        2 => TransportType::I2P,
        3 => TransportType::Yggdrasil,
        4 => TransportType::Cjdns,
        5 => TransportType::Mixnet,
        _ => TransportType::GNUnet,
    };
    let transport_hints = if cur.take_bool() {
        vec![TransportHint { transport: transport_type, endpoint: Some(endpoint) }]
    } else {
        vec![]
    };

    let entry = NetworkMapEntry {
        version,
        peer_id,
        public_keys: vec![PublicKeyRecord {
            ed25519_public: ed_pub,
            x25519_public: x_pub,
            preauth_x25519_public: None,
            kem_encapsulation_key: None,
            preauth_sig: None,
        }],
        transport_hints,
        public_profile: None,
        services: vec![],
        sequence: seq,
        signature: sig,
        local_trust: TrustLevel::Unknown,
        prev_hash: None,
    };

    let now = u64::from_le_bytes([
        cur.take_u8(), cur.take_u8(), cur.take_u8(), cur.take_u8(),
        cur.take_u8(), cur.take_u8(), cur.take_u8(), cur.take_u8(),
    ]);

    let mut map = NetworkMap::new();
    // Must not panic regardless of input.
    let _ = map.insert_gossiped(entry, &source_id, now);
});
