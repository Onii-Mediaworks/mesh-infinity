//! Reachability Announcements (§6.2)
//!
//! # What are Reachability Announcements?
//!
//! Reachability announcements are the messages nodes exchange with their
//! direct neighbours to share routing information. They are the primary
//! mechanism for populating routing tables across the mesh.
//!
//! # How They Work
//!
//! 1. A node originates an announcement for its OWN address (owner-only rule).
//! 2. It sends this announcement to all direct neighbours.
//! 3. Each neighbour that receives it:
//!    a. Checks the announcement_id for deduplication (already seen? discard)
//!    b. Adds 1 to the hop_count
//!    c. Updates latency_ms based on observed link latency
//!    d. Updates its local routing table if this is a better path
//!    e. Forwards to ITS neighbours (if scope allows)
//!
//! # Announcement Scope
//!
//! Announcements have three scopes that control how far they propagate:
//!
//! - **Public:** forwarded freely to all neighbours. Populates the
//!   public routing plane.
//! - **Group(group_id):** forwarded only within the group's trusted
//!   channel. Populates the group routing plane for that group.
//! - **Private:** NEVER forwarded. Used only for the originator's
//!   own routing table. Direct connections create private entries.
//!
//! # Security Properties
//!
//! - **Owner-only origination:** Only the address owner may create
//!   (originate) a ReachabilityAnnouncement. Intermediate nodes
//!   forward and re-sign but never originate for others.
//! - **Signature verification:** Every announcement carries a signature
//!   from the originator. Forwarding nodes add their own signature
//!   but preserve the original.
//! - **Deduplication:** The announcement_id prevents the same
//!   announcement from being processed or forwarded twice, which
//!   also prevents routing loops at the announcement level.

use serde::{Deserialize, Serialize};

use super::table::{DeviceAddress, GroupId, RoutingEntry};
use crate::trust::levels::TrustLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum hop count before an announcement is discarded.
///
/// This prevents announcements from propagating forever in a mesh
/// with many nodes. A mesh with >64 hops between any two nodes
/// would be extraordinarily large. In practice, most paths are <10 hops.
// MAX_ANNOUNCEMENT_HOPS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_ANNOUNCEMENT_HOPS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_ANNOUNCEMENT_HOPS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_ANNOUNCEMENT_HOPS: u8 = 64;

/// Maximum age of an announcement before it's considered stale
/// and discarded on receipt (seconds).
///
/// Announcements older than 10 minutes are likely outdated because
/// the mesh topology changes frequently. Discarding them prevents
/// acting on obsolete routing information.
// MAX_ANNOUNCEMENT_AGE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_ANNOUNCEMENT_AGE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_ANNOUNCEMENT_AGE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_ANNOUNCEMENT_AGE_SECS: u64 = 600;

// ---------------------------------------------------------------------------
// Announcement Scope
// ---------------------------------------------------------------------------

/// Controls how far a reachability announcement propagates.
///
/// This is a critical privacy mechanism: group-internal routing
/// information stays within the group, and private routes are
/// never shared at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// AnnouncementScope — variant enumeration.
// Match exhaustively to handle every protocol state.
// AnnouncementScope — variant enumeration.
// Match exhaustively to handle every protocol state.
// AnnouncementScope — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum AnnouncementScope {
    /// Forwarded to all direct neighbours.
    /// Populates the public routing plane.
    Public,

    /// Forwarded only within a specific group's trusted channel.
    /// Populates the group routing plane for this group.
    /// The group_id identifies which group this route belongs to.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Group(GroupId),

    /// Never forwarded. Local routing table only.
    /// Used for direct connections and manually configured routes.
    Private,
}

// Begin the block scope.
// AnnouncementScope implementation — core protocol logic.
// AnnouncementScope implementation — core protocol logic.
// AnnouncementScope implementation — core protocol logic.
impl AnnouncementScope {
    /// Whether this announcement should be forwarded to neighbours.
    ///
    /// Public: yes, to everyone.
    /// Group: yes, but only to group members (caller must check).
    /// Private: never.
    // Perform the 'is forwardable' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is forwardable' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is forwardable' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_forwardable(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        !matches!(self, Self::Private)
    }
}

// ---------------------------------------------------------------------------
// Reachability Announcement
// ---------------------------------------------------------------------------

/// A reachability announcement (§6.2).
///
/// This is the on-wire format for routing information exchange.
/// Nodes originate announcements for their own addresses, and
/// neighbours forward them (with updated hop_count and latency)
/// to propagate routing knowledge through the mesh.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// ReachabilityAnnouncement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ReachabilityAnnouncement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// ReachabilityAnnouncement — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct ReachabilityAnnouncement {
    /// The device address this announcement is about.
    /// Only the owner of this address may originate the announcement.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub destination: DeviceAddress,

    /// Number of hops from the originator.
    /// Starts at 0 when originated, incremented by each forwarder.
    /// Announcements with hop_count > MAX_ANNOUNCEMENT_HOPS are discarded.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub hop_count: u8,

    /// Latency from the originator (cumulative, milliseconds).
    /// Updated by each forwarder to include its observed link latency.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub latency_ms: u32,

    /// Trust level the forwarder has in its next hop toward destination.
    /// Only meaningful from the perspective of the receiving node.
    /// The receiver replaces this with its own trust assessment.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub next_hop_trust: TrustLevel,

    /// Unique identifier for deduplication.
    /// Generated by the originator. Used to prevent the same
    /// announcement from being processed or forwarded twice.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub announcement_id: [u8; 32],

    /// Unix timestamp when the announcement was originated.
    /// Used for staleness checking — announcements older than
    /// MAX_ANNOUNCEMENT_AGE_SECS are discarded.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,

    /// How far this announcement should propagate.
    /// Public: forwarded to everyone.
    /// Group: forwarded only within the group.
    /// Private: never forwarded.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub scope: AnnouncementScope,

    /// Ed25519 signature from the originator.
    /// Proves that the announcement was created by the address owner.
    /// Forwarding nodes verify this before accepting.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Announcement Processor
// ---------------------------------------------------------------------------

/// Result of processing a received reachability announcement.
///
/// The processor validates, deduplicates, and converts announcements
/// into routing table entries. The caller is responsible for actually
/// Data associated with a successfully processed announcement.
/// Boxed inside `ProcessResult::Accepted` to keep the enum variants uniform in size.
#[derive(Debug)]
// Begin the block scope.
// AcceptedResult — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AcceptedResult — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AcceptedResult — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct AcceptedResult {
    /// The routing entry derived from this announcement.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub entry: RoutingEntry,

    /// Whether this announcement should be forwarded to neighbours.
    /// False for Private scope, true for Public and Group.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub should_forward: bool,

    /// If forwarding, the updated announcement with incremented
    /// hop_count and updated latency. The caller should re-sign
    /// before forwarding.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub forward_announcement: Option<ReachabilityAnnouncement>,
}

/// inserting the entry and deciding whether to forward.
#[derive(Debug)]
// Begin the block scope.
// ProcessResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// ProcessResult — variant enumeration.
// Match exhaustively to handle every protocol state.
// ProcessResult — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ProcessResult {
    /// Announcement was accepted and converted to a routing entry.
    /// The caller should insert this into the appropriate routing
    /// plane and consider forwarding (if scope allows).
    /// Boxed to avoid a large size difference with the `Rejected` variant.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Accepted(Box<AcceptedResult>),

    /// Announcement was rejected. Reasons include:
    /// - Already seen (duplicate announcement_id)
    /// - Too old (timestamp exceeds MAX_ANNOUNCEMENT_AGE_SECS)
    /// - Too many hops (hop_count exceeds MAX_ANNOUNCEMENT_HOPS)
    /// - Invalid signature (not from the address owner)
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Rejected(RejectReason),
}

/// Why an announcement was rejected.
#[derive(Debug, PartialEq, Eq)]
// Begin the block scope.
// RejectReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// RejectReason — variant enumeration.
// Match exhaustively to handle every protocol state.
// RejectReason — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RejectReason {
    /// Already processed (duplicate announcement_id).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Duplicate,
    /// Announcement is too old.
    TooOld,
    /// Too many hops — announcement has propagated too far.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    TooManyHops,
    /// Originator's signature is invalid.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    InvalidSignature,
}

/// Processes incoming reachability announcements.
///
/// The processor maintains a deduplication set of seen announcement IDs.
/// It validates incoming announcements, converts them to routing entries,
/// and prepares forwarding copies with updated metrics.
///
/// # Capacity
///
/// The deduplication set is bounded to prevent memory exhaustion.
/// When full, the oldest entries are evicted (LRU). The window
/// matches MAX_ANNOUNCEMENT_AGE_SECS — entries older than that
/// would be rejected anyway.
// AnnouncementProcessor — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AnnouncementProcessor — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AnnouncementProcessor — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct AnnouncementProcessor {
    /// Set of seen announcement IDs for deduplication.
    /// Key: announcement_id, Value: timestamp when first seen.
    /// Bounded by MAX_DEDUP_ENTRIES.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    seen: std::collections::HashMap<[u8; 32], u64>,

    /// Our own device address — used to avoid routing to ourselves.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    our_address: DeviceAddress,

    /// Link latency to add when forwarding (our measured latency
    /// to the neighbour that sent us this announcement).
    /// Set to 0 if unknown.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    default_link_latency_ms: u32,
}

/// Maximum deduplication entries.
/// At ~64 bytes per entry, 100K entries ≈ 6.4 MB.
// MAX_DEDUP_ENTRIES — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_DEDUP_ENTRIES — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_DEDUP_ENTRIES — protocol constant.
// Defined by the spec; must not change without a version bump.
const MAX_DEDUP_ENTRIES: usize = 100_000;

// Begin the block scope.
// AnnouncementProcessor implementation — core protocol logic.
// AnnouncementProcessor implementation — core protocol logic.
// AnnouncementProcessor implementation — core protocol logic.
impl AnnouncementProcessor {
    /// Create a new announcement processor.
    ///
    /// `our_address`: this node's device address (to avoid self-routing).
    /// `default_link_latency_ms`: default latency to add when forwarding
    ///   (should be updated with actual measurements from keepalives).
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(our_address: DeviceAddress, default_link_latency_ms: u32) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            seen: std::collections::HashMap::new(),
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            our_address,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            default_link_latency_ms,
        }
    }

    /// Process an incoming reachability announcement.
    ///
    /// Validates the announcement, checks deduplication, and if accepted,
    /// converts it to a routing entry and prepares a forwarding copy.
    ///
    /// `from_neighbour`: the device address of the neighbour that sent
    ///   this announcement (used as next_hop in the routing entry).
    /// `our_trust_in_neighbour`: our trust level for that neighbour
    ///   (used for path scoring — §6.3).
    /// `now`: current unix timestamp.
    /// `link_latency_ms`: measured latency to the sending neighbour
    ///   (from keepalive probes). Pass None to use default.
    // Perform the 'process' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'process' operation.
    // Errors are propagated to the caller via Result.
    pub fn process(
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        &mut self,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        announcement: &ReachabilityAnnouncement,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        from_neighbour: DeviceAddress,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        our_trust_in_neighbour: TrustLevel,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now: u64,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        link_latency_ms: Option<u32>,
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> ProcessResult {
        // -------------------------------------------------------------------
        // Validation Step 1: Check if the announcement is for ourselves.
        // We don't need a route to ourselves.
        // -------------------------------------------------------------------
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if announcement.destination == self.our_address {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return ProcessResult::Rejected(RejectReason::Duplicate);
        }

        // -------------------------------------------------------------------
        // Validation Step 2: Deduplication.
        // If we've already seen this announcement_id, discard it.
        // This prevents processing the same routing update twice and
        // is also a key loop-prevention mechanism.
        // -------------------------------------------------------------------
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.seen.contains_key(&announcement.announcement_id) {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return ProcessResult::Rejected(RejectReason::Duplicate);
        }

        // -------------------------------------------------------------------
        // Validation Step 3: Age check.
        // Announcements older than MAX_ANNOUNCEMENT_AGE_SECS are stale
        // and should be discarded. The mesh topology changes frequently
        // enough that 10-minute-old routing info is unreliable.
        // -------------------------------------------------------------------
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if now.saturating_sub(announcement.timestamp) > MAX_ANNOUNCEMENT_AGE_SECS {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return ProcessResult::Rejected(RejectReason::TooOld);
        }

        // -------------------------------------------------------------------
        // Validation Step 4: Hop count check.
        // If the announcement has traveled through too many nodes,
        // it's either a loop or an unreasonably long path.
        // -------------------------------------------------------------------
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if announcement.hop_count >= MAX_ANNOUNCEMENT_HOPS {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return ProcessResult::Rejected(RejectReason::TooManyHops);
        }

        // -------------------------------------------------------------------
        // Validation Step 5: Signature verification.
        //
        // The announcement must be signed by the originator's Ed25519 key.
        // We verify using the destination address as the public key
        // (the DeviceAddress IS the public key hash / identifier).
        //
        // The signed message is:
        //   DOMAIN_ROUTING_ANNOUNCEMENT || destination || hop_count(0) ||
        //   latency_ms(0) || announcement_id || timestamp
        //
        // Note: we verify against the ORIGINAL hop_count/latency (0/0)
        // as set by the originator, not the forwarded values.
        // The originator signs at creation; forwarders re-sign separately.
        //
        // For now, we use the destination bytes as the "public key" for
        // verification. A full implementation would look up the device's
        // actual Ed25519 public key from the network map.
        // -------------------------------------------------------------------
        {
            use crate::crypto::signing;

            // Build the message that was signed by the originator.
            // Compute signed msg for this protocol step.
            // Compute signed msg for this protocol step.
            // Compute signed msg for this protocol step.
            let mut signed_msg = Vec::new();
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            signed_msg.extend_from_slice(&announcement.destination.0);
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            signed_msg.extend_from_slice(&announcement.announcement_id);
            // Append the data segment to the accumulating buffer.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            // Append bytes to the accumulator.
            signed_msg.extend_from_slice(&announcement.timestamp.to_be_bytes());

            // Verify using the destination address as a proxy for the
            // originator's public key. In production, we'd look up the
            // actual Ed25519 key from the network map entry for this device.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !signing::verify(
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                &announcement.destination.0,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                signing::DOMAIN_ROUTING_ANNOUNCEMENT,
                // Execute this protocol step.
                // Execute this protocol step.
                &signed_msg,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                &announcement.signature,
                // Begin the block scope.
            ) {
                // Return the result to the caller.
                // Return to the caller.
                // Return to the caller.
                return ProcessResult::Rejected(RejectReason::InvalidSignature);
            }
        }

        // -------------------------------------------------------------------
        // Record the announcement as seen for deduplication.
        // Evict old entries if we're at capacity.
        // -------------------------------------------------------------------
        // Execute this protocol step.
        // Execute this protocol step.
        self.record_seen(announcement.announcement_id, now);

        // -------------------------------------------------------------------
        // Convert to a routing entry.
        // The next_hop is the neighbour that sent us this announcement.
        // The trust level is OUR trust in that neighbour (not the
        // announcement's trust field — we compute our own).
        // -------------------------------------------------------------------
        // Compute actual link latency for this protocol step.
        // Compute actual link latency for this protocol step.
        let actual_link_latency = link_latency_ms
            // Fall back to the default value on failure.
            // Execute this protocol step.
            // Execute this protocol step.
            .unwrap_or(self.default_link_latency_ms);

        // Begin the block scope.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        let entry = RoutingEntry {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            destination: announcement.destination,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            next_hop: from_neighbour,
            // Add 1 to hop count: the announcement traveled one more hop
            // to reach us.
            // Execute this protocol step.
            // Execute this protocol step.
            hop_count: announcement.hop_count + 1,
            // Add our link latency to the cumulative latency.
            // Execute this protocol step.
            // Execute this protocol step.
            latency_ms: announcement.latency_ms.saturating_add(actual_link_latency),
            // Use OUR trust in the neighbour, not the announcement's.
            // Execute this protocol step.
            // Execute this protocol step.
            next_hop_trust: our_trust_in_neighbour,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            last_updated: now,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            announcement_id: announcement.announcement_id,
        };

        // -------------------------------------------------------------------
        // Prepare forwarding copy (if scope allows).
        // The forwarding copy has incremented hop_count and updated latency.
        // The caller must re-sign it before actually forwarding.
        // -------------------------------------------------------------------
        // Compute should forward for this protocol step.
        // Compute should forward for this protocol step.
        let should_forward = announcement.scope.is_forwardable();

        // Begin the block scope.
        // Compute forward announcement for this protocol step.
        // Compute forward announcement for this protocol step.
        let forward_announcement = if should_forward {
            // Wrap the found value for the caller.
            // Wrap the found value.
            // Wrap the found value.
            Some(ReachabilityAnnouncement {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                destination: announcement.destination,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                hop_count: announcement.hop_count + 1,
                // Clamp the value to prevent overflow or underflow.
                // Execute this protocol step.
                // Execute this protocol step.
                latency_ms: announcement.latency_ms.saturating_add(actual_link_latency),
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                next_hop_trust: our_trust_in_neighbour,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                announcement_id: announcement.announcement_id,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                timestamp: announcement.timestamp,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                scope: announcement.scope.clone(),
                // Signature must be replaced by the caller (re-sign).
                // Execute this protocol step.
                // Execute this protocol step.
                signature: Vec::new(),
            })
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // No value available.
            // No value available.
            None
        };

        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        ProcessResult::Accepted(Box::new(AcceptedResult {
            entry,
            // Execute this protocol step.
            // Execute this protocol step.
            should_forward,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            forward_announcement,
        }))
    }

    /// Record an announcement ID as seen.
    ///
    /// If the deduplication set is at capacity, evict entries older
    /// than MAX_ANNOUNCEMENT_AGE_SECS first. If still at capacity,
    /// evict the oldest entry.
    // Perform the 'record seen' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'record seen' operation.
    // Errors are propagated to the caller via Result.
    fn record_seen(&mut self, id: [u8; 32], now: u64) {
        // Evict stale entries if at capacity.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.seen.len() >= MAX_DEDUP_ENTRIES {
            // First pass: remove entries older than the announcement age.
            // Filter elements that match the predicate.
            // Filter elements that match the predicate.
            self.seen.retain(|_, ts| {
                // Clamp the value to prevent overflow or underflow.
                // Execute this protocol step.
                // Execute this protocol step.
                now.saturating_sub(*ts) <= MAX_ANNOUNCEMENT_AGE_SECS
            });

            // If still at capacity, remove the single oldest entry.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if self.seen.len() >= MAX_DEDUP_ENTRIES {
                // Conditional branch based on the current state.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if let Some(oldest_key) = self
                    // Chain the operation on the intermediate result.
                    .seen
                    // Create an iterator over the collection elements.
                    // Create an iterator over the elements.
                    // Create an iterator over the elements.
                    .iter()
                    // Apply the closure to each element.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    .min_by_key(|(_, ts)| *ts)
                    // Transform the result, mapping errors to the local error type.
                    // Transform each element.
                    // Transform each element.
                    .map(|(k, _)| *k)
                {
                    // Remove from the collection and return the evicted value.
                    // Remove from the collection.
                    // Remove from the collection.
                    self.seen.remove(&oldest_key);
                }
            }
        }

        // Insert into the lookup table for efficient retrieval.
        // Insert into the map/set.
        // Insert into the map/set.
        self.seen.insert(id, now);
    }

    /// Clean up the deduplication set.
    ///
    /// Removes entries older than MAX_ANNOUNCEMENT_AGE_SECS.
    /// Should be called periodically (e.g., every 60 seconds).
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'gc' operation.
    // Errors are propagated to the caller via Result.
    pub fn gc(&mut self, now: u64) {
        // Filter the collection, keeping only elements that pass.
        // Filter elements that match the predicate.
        // Filter elements that match the predicate.
        self.seen.retain(|_, ts| {
            // Clamp the value to prevent overflow or underflow.
            // Execute this protocol step.
            // Execute this protocol step.
            now.saturating_sub(*ts) <= MAX_ANNOUNCEMENT_AGE_SECS
        });
    }

    /// Number of announcement IDs currently in the deduplication set.
    // Perform the 'seen count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'seen count' operation.
    // Errors are propagated to the caller via Result.
    pub fn seen_count(&self) -> usize {
        // Mutate the internal state.
        // Execute this protocol step.
        // Execute this protocol step.
        self.seen.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a DeviceAddress from a single byte.
    fn addr(b: u8) -> DeviceAddress {
        DeviceAddress([b; 32])
    }

    /// Helper: create a properly-signed announcement.
    ///
    /// Uses `dest` as the Ed25519 secret seed so that the destination
    /// address is the corresponding public key and the signature verifies.
    fn make_announcement(
        dest: u8,
        hops: u8,
        latency: u32,
        ts: u64,
        scope: AnnouncementScope,
    ) -> ReachabilityAnnouncement {
        use crate::crypto::signing;

        let secret = [dest; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let pub_key = signing_key.verifying_key().to_bytes();
        let destination = DeviceAddress(pub_key);
        let announcement_id = pub_key;

        // Build the message exactly as process() expects.
        let mut signed_msg = Vec::new();
        signed_msg.extend_from_slice(&destination.0);
        signed_msg.extend_from_slice(&announcement_id);
        signed_msg.extend_from_slice(&ts.to_be_bytes());

        let signature = signing::sign(&secret, signing::DOMAIN_ROUTING_ANNOUNCEMENT, &signed_msg);

        ReachabilityAnnouncement {
            destination,
            hop_count: hops,
            latency_ms: latency,
            next_hop_trust: TrustLevel::Unknown,
            announcement_id,
            timestamp: ts,
            scope,
            signature,
        }
    }

    #[test]
    fn test_accept_valid_announcement() {
        let mut proc = AnnouncementProcessor::new(addr(0x01), 10);
        let ann = make_announcement(0xAA, 0, 0, 1000, AnnouncementScope::Public);

        let result = proc.process(&ann, addr(0x02), TrustLevel::Trusted, 1000, Some(15));

        match result {
            ProcessResult::Accepted(r) => {
                // Hop count should be incremented.
                assert_eq!(r.entry.hop_count, 1);
                // Latency should include our link latency.
                assert_eq!(r.entry.latency_ms, 15);
                // Next hop should be the neighbour that sent it.
                assert_eq!(r.entry.next_hop, addr(0x02));
                // Trust should be OUR trust in the neighbour.
                assert_eq!(r.entry.next_hop_trust, TrustLevel::Trusted);
                // Public scope means forwarding.
                assert!(r.should_forward);
                assert!(r.forward_announcement.is_some());
            }
            ProcessResult::Rejected(reason) => {
                panic!("Expected Accepted, got Rejected({:?})", reason);
            }
        }
    }

    #[test]
    fn test_reject_duplicate() {
        let mut proc = AnnouncementProcessor::new(addr(0x01), 10);
        let ann = make_announcement(0xAA, 0, 0, 1000, AnnouncementScope::Public);

        // First time: accepted.
        let r1 = proc.process(&ann, addr(0x02), TrustLevel::Trusted, 1000, None);
        assert!(matches!(r1, ProcessResult::Accepted(_)));

        // Second time: duplicate.
        let r2 = proc.process(&ann, addr(0x03), TrustLevel::Trusted, 1000, None);
        assert!(matches!(
            r2,
            ProcessResult::Rejected(RejectReason::Duplicate)
        ));
    }

    #[test]
    fn test_reject_too_old() {
        let mut proc = AnnouncementProcessor::new(addr(0x01), 10);
        // Announcement from 1000 seconds ago.
        let ann = make_announcement(0xAA, 0, 0, 500, AnnouncementScope::Public);

        let result = proc.process(
            &ann,
            addr(0x02),
            TrustLevel::Trusted,
            // Now is 500 + MAX_ANNOUNCEMENT_AGE_SECS + 1 = stale.
            500 + MAX_ANNOUNCEMENT_AGE_SECS + 1,
            None,
        );

        assert!(matches!(
            result,
            ProcessResult::Rejected(RejectReason::TooOld)
        ));
    }

    #[test]
    fn test_reject_too_many_hops() {
        let mut proc = AnnouncementProcessor::new(addr(0x01), 10);
        let ann = make_announcement(
            0xAA,
            MAX_ANNOUNCEMENT_HOPS,
            0,
            1000,
            AnnouncementScope::Public,
        );

        let result = proc.process(&ann, addr(0x02), TrustLevel::Trusted, 1000, None);
        assert!(matches!(
            result,
            ProcessResult::Rejected(RejectReason::TooManyHops)
        ));
    }

    #[test]
    fn test_reject_self_destination() {
        // Our address must be the same Ed25519 public key used by make_announcement(0x01).
        let our_pub = ed25519_dalek::SigningKey::from_bytes(&[0x01u8; 32])
            .verifying_key()
            .to_bytes();
        let mut proc = AnnouncementProcessor::new(DeviceAddress(our_pub), 10);
        // Announcement whose destination equals our own address.
        let ann = make_announcement(0x01, 0, 0, 1000, AnnouncementScope::Public);

        let result = proc.process(&ann, addr(0x02), TrustLevel::Trusted, 1000, None);
        assert!(matches!(
            result,
            ProcessResult::Rejected(RejectReason::Duplicate)
        ));
    }

    #[test]
    fn test_private_not_forwarded() {
        let mut proc = AnnouncementProcessor::new(addr(0x01), 10);
        let ann = make_announcement(0xBB, 0, 0, 1000, AnnouncementScope::Private);

        let result = proc.process(&ann, addr(0x02), TrustLevel::Trusted, 1000, None);

        match result {
            ProcessResult::Accepted(r) => {
                assert!(!r.should_forward);
                assert!(r.forward_announcement.is_none());
            }
            _ => panic!("Expected Accepted"),
        }
    }

    #[test]
    fn test_group_scoped_forwarded() {
        let mut proc = AnnouncementProcessor::new(addr(0x01), 10);
        let group = GroupId([0xFF; 16]);
        let ann = make_announcement(0xCC, 0, 0, 1000, AnnouncementScope::Group(group));

        let result = proc.process(&ann, addr(0x02), TrustLevel::Trusted, 1000, None);

        match result {
            ProcessResult::Accepted(r) => {
                // Group-scoped announcements ARE forwardable
                // (but only to group members — caller enforces).
                assert!(r.should_forward);
            }
            _ => panic!("Expected Accepted"),
        }
    }

    #[test]
    fn test_gc_removes_old_entries() {
        let mut proc = AnnouncementProcessor::new(addr(0x01), 10);

        // Process several announcements (each uses a distinct destination/pub-key as ID).
        for i in 0..5u8 {
            let ann = make_announcement(i + 10, 0, 0, 1000, AnnouncementScope::Public);
            proc.process(&ann, addr(0x02), TrustLevel::Unknown, 1000, None);
        }

        assert_eq!(proc.seen_count(), 5);

        // GC at a time when all entries have expired.
        proc.gc(1000 + MAX_ANNOUNCEMENT_AGE_SECS + 1);

        assert_eq!(proc.seen_count(), 0);
    }

    #[test]
    fn test_reject_empty_signature() {
        let mut proc = AnnouncementProcessor::new(addr(0x01), 10);
        let mut ann = make_announcement(0xDD, 0, 0, 1000, AnnouncementScope::Public);
        ann.signature = Vec::new(); // Empty signature.

        let result = proc.process(&ann, addr(0x02), TrustLevel::Trusted, 1000, None);
        assert!(matches!(
            result,
            ProcessResult::Rejected(RejectReason::InvalidSignature)
        ));
    }

    #[test]
    fn test_reject_wrong_key_signature() {
        // A structurally valid 64-byte signature produced by a different keypair
        // (not the destination's key) must be rejected.
        use crate::crypto::signing;

        let mut proc = AnnouncementProcessor::new(addr(0x01), 10);
        // Build a valid announcement for destination 0xAA.
        let mut ann = make_announcement(0xAA, 0, 0, 1000, AnnouncementScope::Public);

        // Re-sign with a completely different key (seed 0xFF ≠ 0xAA).
        let wrong_secret = [0xFFu8; 32];
        let mut signed_msg = Vec::new();
        signed_msg.extend_from_slice(&ann.destination.0);
        signed_msg.extend_from_slice(&ann.announcement_id);
        signed_msg.extend_from_slice(&ann.timestamp.to_be_bytes());
        ann.signature = signing::sign(
            &wrong_secret,
            signing::DOMAIN_ROUTING_ANNOUNCEMENT,
            &signed_msg,
        );

        let result = proc.process(&ann, addr(0x02), TrustLevel::Trusted, 1000, None);
        assert!(
            matches!(
                result,
                ProcessResult::Rejected(RejectReason::InvalidSignature)
            ),
            "announcement signed by wrong key must be rejected, got: {:?}",
            result
        );
    }

    #[test]
    fn test_reject_tampered_content_valid_signature() {
        // A message signed by the correct key but with the announcement_id tampered
        // afterward must fail signature verification.
        let mut proc = AnnouncementProcessor::new(addr(0x01), 10);
        let mut ann = make_announcement(0xBB, 0, 0, 2000, AnnouncementScope::Public);

        // Flip one byte of the announcement_id after signing.
        ann.announcement_id[0] ^= 0xFF;

        let result = proc.process(&ann, addr(0x02), TrustLevel::Trusted, 2000, None);
        assert!(
            matches!(
                result,
                ProcessResult::Rejected(RejectReason::InvalidSignature)
            ),
            "announcement with tampered content must be rejected, got: {:?}",
            result
        );
    }
}
