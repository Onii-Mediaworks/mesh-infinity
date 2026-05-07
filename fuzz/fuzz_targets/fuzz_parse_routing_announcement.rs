// fuzz_targets/fuzz_parse_routing_announcement.rs — Reachability announcement
// parse/process fuzz target (§6.2, §21.1.3)
//
// # What this target tests
//
// Reachability announcements cross an external byte boundary before they reach
// the routing processor. Hostile peers can send malformed JSON, stale routing
// updates, loop-inducing duplicates, or announcements with forged signatures.
// Both the deserializer and the semantic processor must reject bad inputs
// without panicking or mutating trusted state incorrectly.
//
// # Harness strategy
//
// 1. Feed arbitrary bytes into `serde_json::from_slice::<ReachabilityAnnouncement>`.
// 2. If parse succeeds, run the parsed value through `AnnouncementProcessor`.
// 3. Independently build a valid signed announcement, then mutate destination,
//    announcement_id, timestamp, hop count, scope, and signature before
//    calling `process()`.
//
// This gives the target both random parse failures and deep semantic coverage
// through replay, age, hop-bound, and signature-verification paths.

#![no_main]

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use mesh_infinity::crypto::signing;
use mesh_infinity::routing::announcement::{
    AcceptedResult, AnnouncementProcessor, AnnouncementScope, ProcessResult, ReachabilityAnnouncement,
    RejectReason, MAX_ANNOUNCEMENT_AGE_SECS, MAX_ANNOUNCEMENT_HOPS,
};
use mesh_infinity::routing::table::{DeviceAddress, GroupId};
use mesh_infinity::testing::arbitrary::ByteCursor;
use mesh_infinity::trust::levels::TrustLevel;

fn take_array<const N: usize>(cursor: &mut ByteCursor<'_>) -> [u8; N] {
    let mut out = [0u8; N];
    let bytes = cursor.take_bytes(N);
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fn take_u32(cursor: &mut ByteCursor<'_>) -> u32 {
    u32::from_be_bytes(take_array::<4>(cursor))
}

fn take_u64(cursor: &mut ByteCursor<'_>) -> u64 {
    u64::from_be_bytes(take_array::<8>(cursor))
}

fn take_scope(cursor: &mut ByteCursor<'_>) -> AnnouncementScope {
    match cursor.take_u8() % 3 {
        0 => AnnouncementScope::Public,
        1 => AnnouncementScope::Private,
        _ => AnnouncementScope::Group(GroupId(take_array::<16>(cursor))),
    }
}

fn take_trust_level(cursor: &mut ByteCursor<'_>) -> TrustLevel {
    TrustLevel::from_value(cursor.take_u8() % 9).unwrap_or(TrustLevel::Unknown)
}

fn signed_message(
    destination: &DeviceAddress,
    announcement_id: &[u8; 32],
    timestamp: u64,
) -> Vec<u8> {
    let mut signed_msg = Vec::with_capacity(72);
    signed_msg.extend_from_slice(&destination.0);
    signed_msg.extend_from_slice(announcement_id);
    signed_msg.extend_from_slice(&timestamp.to_be_bytes());
    signed_msg
}

fn build_valid_announcement(cursor: &mut ByteCursor<'_>) -> ReachabilityAnnouncement {
    let secret = take_array::<32>(cursor);
    let signing_key = SigningKey::from_bytes(&secret);
    let destination = DeviceAddress(signing_key.verifying_key().to_bytes());
    let announcement_id = take_array::<32>(cursor);
    let timestamp = take_u64(cursor);
    let signed_msg = signed_message(&destination, &announcement_id, timestamp);
    let signature = signing::sign(&secret, signing::DOMAIN_ROUTING_ANNOUNCEMENT, &signed_msg);

    ReachabilityAnnouncement {
        destination,
        hop_count: cursor.take_u8() % MAX_ANNOUNCEMENT_HOPS,
        latency_ms: take_u32(cursor),
        next_hop_trust: take_trust_level(cursor),
        announcement_id,
        timestamp,
        scope: take_scope(cursor),
        signature,
    }
}

fn process_with_context(
    processor: &mut AnnouncementProcessor,
    announcement: &ReachabilityAnnouncement,
    from_neighbour: DeviceAddress,
    our_trust: TrustLevel,
    now: u64,
    link_latency_ms: Option<u32>,
) -> ProcessResult {
    processor.process(announcement, from_neighbour, our_trust, now, link_latency_ms)
}

fn assert_accept_invariants(
    announcement: &ReachabilityAnnouncement,
    from_neighbour: DeviceAddress,
    now: u64,
    link_latency_ms: Option<u32>,
    default_link_latency_ms: u32,
    accepted: &AcceptedResult,
) {
    let actual_link_latency = link_latency_ms.unwrap_or(default_link_latency_ms);

    assert_eq!(accepted.entry.destination, announcement.destination);
    assert_eq!(accepted.entry.next_hop, from_neighbour);
    assert_eq!(
        accepted.entry.hop_count,
        announcement.hop_count.saturating_add(1),
    );
    assert_eq!(
        accepted.entry.latency_ms,
        announcement.latency_ms.saturating_add(actual_link_latency),
    );
    assert_eq!(accepted.entry.last_updated, now);
    assert_eq!(accepted.entry.announcement_id, announcement.announcement_id);
    assert_eq!(
        accepted.should_forward,
        announcement.scope.is_forwardable(),
    );

    if accepted.should_forward {
        let forwarded = accepted
            .forward_announcement
            .as_ref()
            .expect("forwardable announcement must include forwarding copy");
        assert_eq!(forwarded.destination, announcement.destination);
        assert_eq!(
            forwarded.hop_count,
            announcement.hop_count.saturating_add(1),
        );
        assert_eq!(
            forwarded.latency_ms,
            announcement.latency_ms.saturating_add(actual_link_latency),
        );
        assert_eq!(forwarded.announcement_id, announcement.announcement_id);
        assert_eq!(forwarded.timestamp, announcement.timestamp);
        assert_eq!(forwarded.scope, announcement.scope);
        assert!(
            forwarded.signature.is_empty(),
            "forwarding copy must be re-signed by caller",
        );
    } else {
        assert!(
            accepted.forward_announcement.is_none(),
            "private announcements must not produce forwarding copy",
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);

    let default_link_latency_ms = take_u32(&mut cursor);
    let parsed_from_neighbour = DeviceAddress(take_array::<32>(&mut cursor));
    let parsed_our_address = DeviceAddress(take_array::<32>(&mut cursor));
    let parsed_our_trust = take_trust_level(&mut cursor);
    let parsed_now = take_u64(&mut cursor);
    let parsed_link_latency = if cursor.take_bool() {
        Some(take_u32(&mut cursor))
    } else {
        None
    };

    // First hit the raw JSON byte boundary directly.
    if let Ok(parsed) = serde_json::from_slice::<ReachabilityAnnouncement>(data) {
        let mut processor = AnnouncementProcessor::new(parsed_our_address, default_link_latency_ms);
        let result = process_with_context(
            &mut processor,
            &parsed,
            parsed_from_neighbour,
            parsed_our_trust,
            parsed_now,
            parsed_link_latency,
        );

        if let ProcessResult::Accepted(accepted) = &result {
            assert_accept_invariants(
                &parsed,
                parsed_from_neighbour,
                parsed_now,
                parsed_link_latency,
                default_link_latency_ms,
                accepted,
            );
        }
    }

    // Then build a semantically valid announcement and selectively corrupt it.
    let mut announcement = build_valid_announcement(&mut cursor);
    let from_neighbour = DeviceAddress(take_array::<32>(&mut cursor));
    let mut our_address = DeviceAddress(take_array::<32>(&mut cursor));
    let our_trust = take_trust_level(&mut cursor);
    let now = take_u64(&mut cursor);
    let link_latency_ms = if cursor.take_bool() {
        Some(take_u32(&mut cursor))
    } else {
        None
    };

    if cursor.take_bool() {
        our_address = announcement.destination;
    }

    let mutation = cursor.take_u8() % 8;
    match mutation {
        0 => {}
        1 => {
            announcement.announcement_id = take_array::<32>(&mut cursor);
        }
        2 => {
            announcement.timestamp = now.saturating_sub(MAX_ANNOUNCEMENT_AGE_SECS + 1);
        }
        3 => {
            announcement.hop_count = MAX_ANNOUNCEMENT_HOPS;
        }
        4 => {
            announcement.signature = take_array::<64>(&mut cursor).to_vec();
        }
        5 => {
            announcement.signature.clear();
        }
        6 => {
            announcement.destination = DeviceAddress(take_array::<32>(&mut cursor));
        }
        7 => {
            announcement.scope = take_scope(&mut cursor);
        }
        _ => unreachable!(),
    }

    let mut processor = AnnouncementProcessor::new(our_address, default_link_latency_ms);
    let result = process_with_context(
        &mut processor,
        &announcement,
        from_neighbour,
        our_trust,
        now,
        link_latency_ms,
    );

    if let ProcessResult::Accepted(accepted) = &result {
        assert_accept_invariants(
            &announcement,
            from_neighbour,
            now,
            link_latency_ms,
            default_link_latency_ms,
            accepted,
        );

        let duplicate = process_with_context(
            &mut processor,
            &announcement,
            from_neighbour,
            our_trust,
            now,
            link_latency_ms,
        );
        assert!(
            matches!(duplicate, ProcessResult::Rejected(RejectReason::Duplicate)),
            "accepted announcement must be deduplicated on replay",
        );
    }
});
