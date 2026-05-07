// fuzz_targets/fuzz_parse_pairing_qr.rs — Pairing QR/deep-link parser fuzz
// target (§8.3, §21.1.3)
//
// # What this target tests
//
// Pairing QR codes and deep links deliver hostile bytes into Mesh Infinity's
// first-contact boundary. The parser must survive malformed JSON, malformed
// hex fields, missing required fields, invalid peer_id derivation, expired
// payloads, and extension-field type confusion without panicking.
//
// # Harness strategy
//
// 1. Feed arbitrary bytes directly into `parse_pairing_qr_payload_json()`.
// 2. Build a structurally valid QR payload and apply bounded mutations so the
//    parser exercises both the happy path and specific semantic failures.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh_infinity::identity::peer_id::PeerId;
use mesh_infinity::pairing::methods::{
    parse_pairing_qr_payload_json, PAIRING_VERSION, QR_EXPIRY_LIVE,
};
use mesh_infinity::testing::arbitrary::ByteCursor;

fn take_array<const N: usize>(cursor: &mut ByteCursor<'_>) -> [u8; N] {
    let mut out = [0u8; N];
    let bytes = cursor.take_bytes(N);
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fn take_u64(cursor: &mut ByteCursor<'_>) -> u64 {
    u64::from_be_bytes(take_array::<8>(cursor))
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn build_valid_payload_json(cursor: &mut ByteCursor<'_>, now: u64) -> String {
    let ed25519_public = take_array::<32>(cursor);
    let peer_id = PeerId::from_ed25519_pub(&ed25519_public);
    let x25519_public = take_array::<32>(cursor);
    let pairing_token = take_array::<32>(cursor);
    let mesh_x25519_public = take_array::<32>(cursor);
    let preauth_x25519_public = take_array::<32>(cursor);
    let preauth_sig = take_array::<64>(cursor);
    let kem_pub = take_array::<32>(cursor);
    let display_name = if cursor.take_bool() {
        Some(String::from_utf8_lossy(cursor.take_bytes(32)).to_string())
    } else {
        None
    };
    let display_name_sig = display_name
        .as_ref()
        .map(|_| hex_string(&take_array::<64>(cursor)));

    let transport_hints = if cursor.take_bool() {
        vec![serde_json::json!({
            "transport": "clearnet",
            "endpoint": format!("127.0.0.1:{}", 1024 + u16::from(cursor.take_u8())),
        })]
    } else {
        vec![serde_json::json!({
            "transport": "tor",
            "endpoint": format!("example{}.onion:{}", cursor.take_u8(), 80 + u16::from(cursor.take_u8() % 32)),
        })]
    };

    serde_json::json!({
        "version": PAIRING_VERSION,
        "peer_id": peer_id.to_hex(),
        "ed25519_public": hex_string(&ed25519_public),
        "x25519_public": hex_string(&x25519_public),
        "pairing_token": hex_string(&pairing_token),
        "display_name": display_name,
        "display_name_sig": display_name_sig,
        "transport_hints": transport_hints,
        "expiry": now.saturating_add(QR_EXPIRY_LIVE),
        "mesh_x25519_public": hex_string(&mesh_x25519_public),
        "preauth_x25519_public": hex_string(&preauth_x25519_public),
        "preauth_sig": hex_string(&preauth_sig),
        "kem_pub": hex_string(&kem_pub),
    })
    .to_string()
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);
    let now = take_u64(&mut cursor);

    let _ = parse_pairing_qr_payload_json(data, now);

    let mut payload: serde_json::Value =
        match serde_json::from_str(&build_valid_payload_json(&mut cursor, now)) {
            Ok(payload) => payload,
            Err(_) => return,
        };

    match cursor.take_u8() % 8 {
        0 => {}
        1 => {
            payload["ed25519_public"] = serde_json::json!("zz");
        }
        2 => {
            payload["peer_id"] = serde_json::json!(hex_string(&take_array::<32>(&mut cursor)));
        }
        3 => {
            payload["expiry"] = serde_json::json!(now.saturating_sub(1));
        }
        4 => {
            payload["display_name"] = serde_json::json!("Alice");
            payload["display_name_sig"] = serde_json::Value::Null;
        }
        5 => {
            payload["transport_hints"] = serde_json::json!({"transport": "clearnet"});
        }
        6 => {
            payload["pairing_token"] = serde_json::json!(true);
        }
        7 => {
            payload["version"] = serde_json::json!(u64::from(PAIRING_VERSION) + 1);
        }
        _ => unreachable!(),
    }

    let serialized = match serde_json::to_vec(&payload) {
        Ok(serialized) => serialized,
        Err(_) => return,
    };

    if let Ok(decoded) = parse_pairing_qr_payload_json(&serialized, now) {
        assert_eq!(
            decoded.payload.peer_id,
            PeerId::from_ed25519_pub(&decoded.payload.ed25519_public),
            "decoded QR payload must preserve peer_id derivation invariant",
        );
        assert!(
            decoded.payload.expiry > now,
            "decoded QR payload must not accept expired payload",
        );
        if decoded.payload.display_name.is_some() {
            assert!(
                decoded.payload.display_name_sig.is_some(),
                "decoded QR payload must keep display-name signature requirement",
            );
        }
    }
});
