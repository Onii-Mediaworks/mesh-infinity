//! Spike S5's checks on the Rust side.
//!
//! - `fixtures`: writes every sample envelope as one framed stream to
//!   `$SPIKE_FIXTURES/rust.bin`, for Kotlin and Dart to decode and re-encode.
//! - `peers_match`: with `SPIKE_VERIFY=1`, reads `kotlin.bin` and `dart.bin`
//!   back and requires them byte-identical to `rust.bin`, and strictly valid.
//! - the strictness tests: unknown fields, oversized and truncated frames.

use mesh_ui_protocol_spike::v1::{self, envelope::Kind};
use mesh_ui_protocol_spike::{decode_strict, read_frame, read_stream, schema_hash, write_frame, FrameError, MAX_FRAME};
use std::path::PathBuf;

/// Wraps a request method in an envelope.
fn request(id: u64, method: v1::request::Method) -> v1::Envelope {
    v1::Envelope { kind: Some(Kind::Request(v1::Request { id, method: Some(method) })) }
}

/// Wraps a reply outcome in an envelope.
fn reply(id: u64, outcome: v1::reply::Outcome) -> v1::Envelope {
    v1::Envelope { kind: Some(Kind::Reply(v1::Reply { id, outcome: Some(outcome) })) }
}

/// Wraps an event body in an envelope.
fn event(seq: u64, body: v1::event::Body) -> v1::Envelope {
    v1::Envelope { kind: Some(Kind::Event(v1::Event { seq, body: Some(body) })) }
}

/// A success reply carrying `value`.
fn success(id: u64, value: v1::success::Value) -> v1::Envelope {
    reply(id, v1::reply::Outcome::Ok(v1::Success { value: Some(value) }))
}

/// A sample message, with non-ASCII text to check UTF-8 handling.
fn chat_message() -> v1::ChatMessage {
    v1::ChatMessage {
        message_id: "m-1".into(),
        room_id: "r-1".into(),
        sender_name: "Ana".into(),
        text: "héllo, mesh ✓".into(),
        timestamp_ms: 1_762_400_000_000,
        blob_refs: vec!["b-1".into(), "b-2".into()],
    }
}

/// Every sample envelope: the handshake, ten requests, all four outcomes, five events, cancel and a blob chunk.
fn samples() -> Vec<v1::Envelope> {
    use v1::request::Method as M;
    use v1::success::Value as V;
    let peer = v1::Peer { peer_id: "p-1".into(), display_name: "Bo".into(), trust: v1::TrustLevel::Trusted as i32, online: true };
    let transport = v1::TransportState {
        transport: "tor".into(),
        enabled: true,
        availability: v1::Availability::PermissionDenied as i32,
    };
    vec![
        v1::Envelope {
            kind: Some(Kind::Hello(v1::Hello { protocol_major: 1, schema_hash: schema_hash().to_vec(), launch_nonce: vec![7; 32] })),
        },
        request(1, M::GetRoomList(v1::GetRoomList {})),
        request(2, M::GetMessages(v1::GetMessages { room_id: "r-1".into(), before_ts: Some(0), limit: 50 })),
        request(3, M::GetMessages(v1::GetMessages { room_id: "r-1".into(), before_ts: None, limit: 50 })),
        request(4, M::SendMessage(v1::SendMessage { room_id: "r-1".into(), mask_id: "k-1".into(), text: "hi ✓".into() })),
        request(5, M::CreateRoom(v1::CreateRoom { peer_id: "p-1".into() })),
        request(6, M::SetTrustLevel(v1::SetTrustLevel { peer_id: "p-1".into(), level: v1::TrustLevel::HighlyTrusted as i32 })),
        request(7, M::GetPeerList(v1::GetPeerList {})),
        request(8, M::GetSettings(v1::GetSettings {})),
        request(9, M::ToggleTransport(v1::ToggleTransport { transport: "ble".into(), enabled: false })),
        request(10, M::RequestUnlock(v1::RequestUnlock {})),
        request(u64::MAX, M::RequestPickFile(v1::RequestPickFile { purpose: v1::FilePurpose::Send as i32 })),
        success(1, V::RoomList(v1::RoomList {
            rooms: vec![
                v1::Room { room_id: "r-1".into(), name: "Ana".into(), unread: 3, last_preview: Some("see you".into()) },
                v1::Room { room_id: "r-2".into(), name: "".into(), unread: 0, last_preview: Some(String::new()) },
            ],
        })),
        success(2, V::MessageList(v1::MessageList { messages: vec![chat_message()] })),
        success(4, V::Sent(v1::Sent { message_id: "m-2".into() })),
        success(5, V::RoomCreated(v1::RoomCreated { room_id: "r-3".into() })),
        success(7, V::PeerList(v1::PeerList { peers: vec![peer.clone()] })),
        success(8, V::Settings(v1::Settings { transports: vec![transport.clone()], threat_level: 2 })),
        success(9, V::Done(v1::Done {})),
        success(u64::MAX, V::FilePicked(v1::FilePicked { handle_id: "h-1".into(), display_name: "photo.jpg".into(), size: 1 << 40 })),
        reply(6, v1::reply::Outcome::Unavailable(v1::Unavailable { reason: "no such peer".into() })),
        reply(3, v1::reply::Outcome::Error(v1::Failure { code: 22, message: "limit too large".into() })),
        reply(10, v1::reply::Outcome::Pending(v1::Pending { request_token: "t-1".into() })),
        event(1, v1::event::Body::MessageReceived(v1::MessageReceived { message: Some(chat_message()) })),
        event(2, v1::event::Body::PeerUpdated(v1::PeerUpdated { peer: Some(peer) })),
        event(3, v1::event::Body::TransportStatus(v1::TransportStatus { state: Some(transport) })),
        event(4, v1::event::Body::ResyncRequired(v1::ResyncRequired {})),
        event(5, v1::event::Body::UnlockOutcome(v1::UnlockOutcome { outcome: v1::unlock_outcome::Outcome::Unlocked as i32 })),
        v1::Envelope { kind: Some(Kind::Cancel(v1::Cancel { id: 2 })) },
        v1::Envelope {
            kind: Some(Kind::BlobChunk(v1::BlobChunk { blob_ref: "b-1".into(), offset: 0, data: (0..=255).collect(), last: true })),
        },
    ]
}

/// The fixtures folder: `$SPIKE_FIXTURES`, or a temporary one.
fn fixtures_dir() -> PathBuf {
    let dir = std::env::var("SPIKE_FIXTURES").map(PathBuf::from).unwrap_or_else(|_| std::env::temp_dir().join("mesh_ui_spike"));
    std::fs::create_dir_all(&dir).expect("fixtures folder");
    dir
}

/// The samples as one framed stream.
fn stream() -> Vec<u8> {
    let mut out = Vec::new();
    for envelope in samples() {
        write_frame(&envelope, &mut out);
    }
    out
}

#[test]
fn fixtures() {
    let bytes = stream();
    // Our own stream reads back to the same envelopes, strictly.
    assert_eq!(read_stream(&bytes).expect("own stream is strict"), samples());
    std::fs::write(fixtures_dir().join("rust.bin"), &bytes).expect("write rust.bin");
    println!("schema_hash {}", schema_hash().iter().map(|b| format!("{b:02x}")).collect::<String>());
}

#[test]
fn peers_match() {
    if std::env::var("SPIKE_VERIFY").is_err() {
        return;
    }
    let expected = stream();
    for peer in ["kotlin.bin", "dart.bin"] {
        let bytes = std::fs::read(fixtures_dir().join(peer)).unwrap_or_else(|e| panic!("{peer}: {e}"));
        read_stream(&bytes).unwrap_or_else(|e| panic!("{peer} is not strictly valid: {e:?}"));
        assert_eq!(bytes, expected, "{peer} differs from rust.bin");
    }
}

#[test]
fn unknown_field_is_refused() {
    let mut body = prost::Message::encode_to_vec(&samples()[1]);
    // Field 99, varint 1: valid protobuf, unknown to the schema.
    body.extend_from_slice(&[0x98, 0x06, 0x01]);
    assert_eq!(decode_strict(&body), Err(FrameError::NotCanonical));
}

#[test]
fn explicit_default_is_refused() {
    // Request.id = 0 written explicitly: proto3 omits defaults, so this is not canonical.
    let body = [0x12, 0x02, 0x08, 0x00];
    assert_eq!(decode_strict(&body), Err(FrameError::NotCanonical));
}

#[test]
fn oversized_frame_is_refused() {
    let prefix = ((MAX_FRAME + 1) as u32).to_be_bytes();
    assert_eq!(read_frame(&prefix), Err(FrameError::TooLarge(MAX_FRAME + 1)));
}

#[test]
fn truncated_frame_waits() {
    let bytes = stream();
    assert_eq!(read_frame(&bytes[..2]), Err(FrameError::Incomplete));
    assert_eq!(read_frame(&bytes[..6]), Err(FrameError::Incomplete));
}
