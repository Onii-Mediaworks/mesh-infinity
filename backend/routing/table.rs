//! Routing Table (§6.1, §6.2, §6.4)
//!
//! # What is the Routing Table?
//!
//! The routing table stores known paths to other nodes in the mesh.
//! When a packet arrives destined for address X, the routing table is
//! consulted to determine the best next hop.
//!
//! # Four Routing Planes (§6.4)
//!
//! The table is split into four planes that serve different privacy
//! and scope requirements:
//!
//! 1. **Public plane** — routes learned from public reachability
//!    announcements. Any node can route here. Handles delivery until
//!    a node with private knowledge takes over.
//!
//! 2. **Group plane** — routes scoped to specific groups. Only members
//!    of a group see these routes. Enables group-internal routing
//!    without leaking topology to outsiders.
//!
//! 3. **Local/private plane** — routes that are NEVER forwarded.
//!    Direct connections and manually configured routes live here.
//!    This is the "private routing plane" from §6.4.
//!
//! 4. **BLE ephemeral plane** — short-lived routes for Bluetooth
//!    proximity relay. Untrusted BLE nodes get ephemeral entries,
//!    not full reachability announcements. These expire quickly.
//!
//! # Two-Plane Routing Model (§6.4)
//!
//! The critical insight is that no static mapping of private addresses
//! to public gateways is EVER advertised. The handoff from public to
//! private routing happens dynamically — an adversary monitoring the
//! public plane cannot determine whether an endpoint is the final
//! destination or just a gateway to the private plane.
//!
//! # Next-Hop Selection
//!
//! When forwarding a packet:
//! 1. Check local plane first (direct connections)
//! 2. Check group plane if the packet has group context
//! 3. Check public plane for general routing
//! 4. If no route exists, trigger dynamic private routing discovery
//!    (query trusted peers in real time)
//!
//! # Capacity Limits
//!
//! The routing table enforces per-plane capacity limits to prevent
//! memory exhaustion from an adversary flooding announcements.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::trust::levels::TrustLevel;

// ---------------------------------------------------------------------------
// Constants — routing table capacity and timing
// ---------------------------------------------------------------------------

/// Maximum entries in the public routing plane.
/// This is generous — a large mesh might have tens of thousands of nodes.
/// Beyond this, LRU eviction kicks in.
pub const MAX_PUBLIC_ENTRIES: usize = 100_000;

/// Maximum entries in each group routing plane.
/// Groups are typically smaller than the whole mesh.
pub const MAX_GROUP_ENTRIES: usize = 10_000;

/// Maximum entries in the local/private routing plane.
/// These are direct connections, so the count is bounded by hardware.
pub const MAX_LOCAL_ENTRIES: usize = 1_000;

/// Maximum entries in the BLE ephemeral plane.
/// BLE connections are short-range and short-lived.
pub const MAX_BLE_ENTRIES: usize = 256;

/// How long a routing entry is valid before it's considered stale (seconds).
/// After this, the entry is deprioritised but not removed — removal
/// happens at 2× this value.
pub const ROUTE_STALENESS_SECS: u64 = 300;

/// How long before a stale route is fully removed (seconds).
/// 2× the staleness threshold.
pub const ROUTE_EXPIRY_SECS: u64 = ROUTE_STALENESS_SECS * 2;

/// How long BLE ephemeral entries last before expiry (seconds).
/// Much shorter than regular routes because BLE is proximity-only.
pub const BLE_ROUTE_EXPIRY_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Device Address
// ---------------------------------------------------------------------------

/// A 32-byte device address used for routing.
///
/// This is the routing-layer address derived from the device's mesh identity
/// (Layer 1 WireGuard key). It is NOT the same as a PeerId (which is
/// derived from a mask's Ed25519 key at Layer 3).
///
/// The distinction matters: a single device has one DeviceAddress but may
/// present many PeerIds (one per mask). Routing operates at the device
/// level; identity operates at the mask level.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct DeviceAddress(pub [u8; 32]);

impl DeviceAddress {
    /// Create a DeviceAddress from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Truncated hex for display purposes (first 8 hex chars).
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

// ---------------------------------------------------------------------------
// Group ID
// ---------------------------------------------------------------------------

/// A 16-byte group identifier for scoped routing.
///
/// Groups have their own routing plane — routes within a group are only
/// visible to group members. This prevents group topology from leaking
/// to the wider mesh.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 16]);

// ---------------------------------------------------------------------------
// BLE Token
// ---------------------------------------------------------------------------

/// An ephemeral token for BLE proximity routing.
///
/// BLE relay nodes don't get full reachability announcements — they get
/// short-lived tokens that map to ephemeral routing entries. This prevents
/// an untrusted BLE device from learning about the wider mesh topology.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BleToken(pub [u8; 16]);

// ---------------------------------------------------------------------------
// Routing Entry
// ---------------------------------------------------------------------------

/// A single entry in the routing table.
///
/// Represents a known path to a destination through a specific next hop.
/// The routing table may hold multiple entries for the same destination
/// (via different next hops) — the path selection algorithm picks the best.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingEntry {
    /// The destination device address this route leads to.
    pub destination: DeviceAddress,

    /// The next hop to reach the destination.
    /// If this is a direct connection, next_hop == destination.
    pub next_hop: DeviceAddress,

    /// Number of hops to the destination (1 = direct neighbour).
    /// Used in path selection scoring — fewer hops is better.
    pub hop_count: u8,

    /// Measured or announced latency to the destination (milliseconds).
    /// Updated when keepalive probes succeed or when reachability
    /// announcements carry latency information.
    pub latency_ms: u32,

    /// Our trust level for the NEXT HOP (not the destination).
    ///
    /// This is critical: §6.3 specifies that scoring uses ONLY
    /// our trust in the immediate next hop. We don't know (and
    /// can't verify) the trust relationships along the rest of
    /// the path in hop-by-hop routing.
    pub next_hop_trust: TrustLevel,

    /// Unix timestamp when this entry was last updated.
    /// Used for staleness detection and expiry.
    pub last_updated: u64,

    /// The announcement ID that created this entry.
    /// Used for deduplication — if we receive an announcement
    /// with the same ID, we skip it.
    pub announcement_id: [u8; 32],
}

impl RoutingEntry {
    /// Whether this entry is stale (older than ROUTE_STALENESS_SECS).
    ///
    /// Stale entries are deprioritised in path selection (scored lower)
    /// but not immediately removed — they serve as fallback routes.
    pub fn is_stale(&self, now: u64) -> bool {
        now.saturating_sub(self.last_updated) > ROUTE_STALENESS_SECS
    }

    /// Whether this entry has expired and should be removed.
    ///
    /// Expired entries are garbage collected during periodic maintenance.
    /// The expiry threshold is 2× the staleness threshold.
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.last_updated) > ROUTE_EXPIRY_SECS
    }

    /// Whether this entry represents a direct connection
    /// (next hop IS the destination).
    pub fn is_direct(&self) -> bool {
        self.next_hop == self.destination
    }
}

// ---------------------------------------------------------------------------
// BLE Ephemeral Routing Entry
// ---------------------------------------------------------------------------

/// A short-lived routing entry for BLE proximity relay.
///
/// These are simpler than full routing entries — no trust scoring,
/// no announcement IDs. They exist only to forward packets to
/// nearby BLE devices and expire quickly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphemeralRoutingEntry {
    /// The destination reachable through this BLE connection.
    pub destination: DeviceAddress,

    /// Unix timestamp when this entry was created.
    pub created_at: u64,

    /// Signal strength (RSSI) at creation time.
    /// Used to prefer closer devices when multiple BLE routes exist.
    pub rssi: Option<i8>,
}

impl EphemeralRoutingEntry {
    /// Whether this BLE entry has expired.
    ///
    /// BLE entries expire much faster than regular routes (60 seconds)
    /// because BLE is a proximity transport — if the device has
    /// moved away, the route is no longer valid.
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) > BLE_ROUTE_EXPIRY_SECS
    }
}

// ---------------------------------------------------------------------------
// Routing Table
// ---------------------------------------------------------------------------

/// The four-plane routing table (§6.2, §6.4).
///
/// This is the core data structure for hop-by-hop routing. Each plane
/// serves a different scope and privacy level:
///
/// - `public`: open routes visible to everyone, populated by reachability
///   announcements with `AnnouncementScope::Public`
/// - `groups`: per-group scoped routes, populated by group-scoped
///   announcements, only visible to group members
/// - `local`: private routes (direct connections), NEVER forwarded
/// - `ble_ephemeral`: short-lived BLE proximity routes
///
/// The routing table does NOT store peer identity information — it
/// operates purely on DeviceAddresses. The identity layer maps
/// PeerIds to DeviceAddresses separately.
pub struct RoutingTable {
    /// Public routing plane — routes learned from public announcements.
    /// Key: destination address, Value: best known route(s).
    pub public: HashMap<DeviceAddress, RoutingEntry>,

    /// Group-scoped routing planes — one per group.
    /// Key: group ID → (destination address → route).
    pub groups: HashMap<GroupId, HashMap<DeviceAddress, RoutingEntry>>,

    /// Local/private routing plane — direct connections and manually
    /// configured routes. NEVER forwarded to other nodes.
    pub local: HashMap<DeviceAddress, RoutingEntry>,

    /// BLE ephemeral routing plane — short-lived proximity routes.
    /// Key: BLE token (not DeviceAddress, because BLE relay nodes
    /// don't have known mesh addresses).
    pub ble_ephemeral: HashMap<BleToken, EphemeralRoutingEntry>,
}

impl RoutingTable {
    /// Create an empty routing table.
    pub fn new() -> Self {
        Self {
            public: HashMap::new(),
            groups: HashMap::new(),
            local: HashMap::new(),
            ble_ephemeral: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Lookup — the core routing decision
    // -----------------------------------------------------------------------

    /// Look up the best route to a destination.
    ///
    /// Search order (§6.1):
    /// 1. Local plane first — if we have a direct connection, use it
    /// 2. Group plane — if a group context is provided
    /// 3. Public plane — general mesh routing
    ///
    /// Returns None if no route is known. In that case, the caller
    /// should trigger dynamic private routing discovery (§6.4).
    pub fn lookup(
        &self,
        destination: &DeviceAddress,
        group: Option<&GroupId>,
        now: u64,
    ) -> Option<&RoutingEntry> {
        // Priority 1: local/private plane (direct connections).
        // These are always preferred because they're the most direct
        // path and don't involve forwarding through other nodes.
        if let Some(entry) = self.local.get(destination) {
            if !entry.is_expired(now) {
                return Some(entry);
            }
        }

        // Priority 2: group-scoped plane.
        // If the caller has group context, check the group's routing
        // table. Group routes are only visible to group members, so
        // they're more private than public routes.
        if let Some(gid) = group {
            if let Some(group_table) = self.groups.get(gid) {
                if let Some(entry) = group_table.get(destination) {
                    if !entry.is_expired(now) {
                        return Some(entry);
                    }
                }
            }
        }

        // Priority 3: public plane.
        // The general mesh routing table — populated by public
        // reachability announcements.
        if let Some(entry) = self.public.get(destination) {
            if !entry.is_expired(now) {
                return Some(entry);
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // Insertion
    // -----------------------------------------------------------------------

    /// Insert or update a route in the public plane.
    ///
    /// Only updates if the new route is better than the existing one
    /// (fewer hops, lower latency, or the existing route is stale).
    /// Enforces the MAX_PUBLIC_ENTRIES capacity limit.
    pub fn update_public(&mut self, entry: RoutingEntry, now: u64) -> bool {
        // Check capacity — if we're at the limit and this is a new
        // destination, we need to evict the stalest entry first.
        if !self.public.contains_key(&entry.destination)
            && self.public.len() >= MAX_PUBLIC_ENTRIES
        {
            self.evict_stalest_public(now);
        }

        let dominated = self.is_dominated_by_existing(
            self.public.get(&entry.destination),
            &entry,
            now,
        );

        // Only insert if the new route is not dominated by the existing one.
        if !dominated {
            self.public.insert(entry.destination, entry);
            true
        } else {
            false
        }
    }

    /// Insert or update a route in a group's routing plane.
    ///
    /// Similar to update_public but scoped to a specific group.
    /// Creates the group's routing table if it doesn't exist yet.
    pub fn update_group(
        &mut self,
        group: GroupId,
        entry: RoutingEntry,
        now: u64,
    ) -> bool {
        let group_table = self.groups.entry(group).or_default();

        // Enforce per-group capacity.
        if !group_table.contains_key(&entry.destination)
            && group_table.len() >= MAX_GROUP_ENTRIES
        {
            // Find and remove the stalest entry.
            if let Some(stalest_key) = group_table
                .iter()
                .filter(|(_, e)| e.is_stale(now))
                .min_by_key(|(_, e)| e.last_updated)
                .map(|(k, _)| *k)
            {
                group_table.remove(&stalest_key);
            }
        }

        // Check if the existing route dominates the new one.
        // We inline the check here to avoid borrow conflicts.
        let dominated = if let Some(old) = group_table.get(&entry.destination) {
            if old.is_stale(now) {
                false
            } else {
                old.hop_count <= entry.hop_count && old.latency_ms <= entry.latency_ms
            }
        } else {
            false
        };

        if !dominated {
            group_table.insert(entry.destination, entry);
            true
        } else {
            false
        }
    }

    /// Insert or update a direct connection in the local plane.
    ///
    /// Local entries are NEVER forwarded. They represent direct
    /// connections to peers we can reach without relaying.
    pub fn update_local(&mut self, entry: RoutingEntry) -> bool {
        // Local plane is small (direct connections only), so we
        // simply insert/update without complex eviction.
        if self.local.len() < MAX_LOCAL_ENTRIES
            || self.local.contains_key(&entry.destination)
        {
            self.local.insert(entry.destination, entry);
            true
        } else {
            false
        }
    }

    /// Insert a BLE ephemeral route.
    ///
    /// BLE routes are short-lived and don't go through the normal
    /// reachability announcement process.
    pub fn update_ble(
        &mut self,
        token: BleToken,
        entry: EphemeralRoutingEntry,
        now: u64,
    ) {
        // Evict expired BLE entries first.
        self.ble_ephemeral.retain(|_, e| !e.is_expired(now));

        // Enforce capacity.
        if self.ble_ephemeral.len() < MAX_BLE_ENTRIES {
            self.ble_ephemeral.insert(token, entry);
        }
    }

    // -----------------------------------------------------------------------
    // Removal
    // -----------------------------------------------------------------------

    /// Remove a route from the local plane (peer disconnected).
    pub fn remove_local(&mut self, destination: &DeviceAddress) {
        self.local.remove(destination);
    }

    /// Remove all routes that use a specific next hop.
    ///
    /// Called when a direct neighbour disconnects — all routes
    /// through that neighbour are no longer valid.
    pub fn remove_via_next_hop(&mut self, next_hop: &DeviceAddress) {
        self.public.retain(|_, e| e.next_hop != *next_hop);

        for group_table in self.groups.values_mut() {
            group_table.retain(|_, e| e.next_hop != *next_hop);
        }

        self.local.retain(|_, e| e.next_hop != *next_hop);
    }

    // -----------------------------------------------------------------------
    // Maintenance
    // -----------------------------------------------------------------------

    /// Garbage-collect expired entries across all planes.
    ///
    /// Should be called periodically (e.g., every 60 seconds).
    /// Removes entries older than ROUTE_EXPIRY_SECS and cleans up
    /// empty group tables.
    pub fn gc(&mut self, now: u64) {
        // Public plane: remove expired entries.
        self.public.retain(|_, e| !e.is_expired(now));

        // Group planes: remove expired entries and empty groups.
        for group_table in self.groups.values_mut() {
            group_table.retain(|_, e| !e.is_expired(now));
        }
        self.groups.retain(|_, table| !table.is_empty());

        // BLE plane: remove expired entries.
        self.ble_ephemeral.retain(|_, e| !e.is_expired(now));
    }

    /// Total number of routes across all planes.
    ///
    /// Useful for diagnostics and network status display.
    pub fn total_route_count(&self) -> usize {
        self.public.len()
            + self.groups.values().map(|t| t.len()).sum::<usize>()
            + self.local.len()
            + self.ble_ephemeral.len()
    }

    /// Number of directly connected peers (local plane entries).
    pub fn direct_peer_count(&self) -> usize {
        self.local.len()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Check if a new entry is dominated by an existing one.
    ///
    /// A new entry is "dominated" (and should be discarded) if:
    /// - The existing entry is NOT stale, AND
    /// - The existing entry has equal or fewer hops, AND
    /// - The existing entry has equal or lower latency
    ///
    /// If the existing entry is stale, we always prefer the fresh one.
    fn is_dominated_by_existing(
        &self,
        existing: Option<&RoutingEntry>,
        new: &RoutingEntry,
        now: u64,
    ) -> bool {
        match existing {
            Some(old) => {
                // Always prefer fresh over stale.
                if old.is_stale(now) {
                    return false;
                }
                // New route must be strictly better in at least one dimension.
                old.hop_count <= new.hop_count && old.latency_ms <= new.latency_ms
            }
            // No existing entry — always accept the new one.
            None => false,
        }
    }

    /// Evict the stalest entry from the public plane.
    ///
    /// Called when the public plane is at capacity and a new entry
    /// needs to be inserted. Removes the entry with the oldest
    /// last_updated timestamp.
    fn evict_stalest_public(&mut self, now: u64) {
        // First try to evict an already-stale entry (cheapest eviction).
        if let Some(stale_key) = self
            .public
            .iter()
            .filter(|(_, e)| e.is_stale(now))
            .min_by_key(|(_, e)| e.last_updated)
            .map(|(k, _)| *k)
        {
            self.public.remove(&stale_key);
            return;
        }

        // If nothing is stale, evict the oldest entry regardless.
        if let Some(oldest_key) = self
            .public
            .iter()
            .min_by_key(|(_, e)| e.last_updated)
            .map(|(k, _)| *k)
        {
            self.public.remove(&oldest_key);
        }
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingTable {
    /// Total number of routing entries across all planes.
    pub fn len(&self) -> usize {
        let group_count: usize = self.groups.values().map(|m| m.len()).sum();
        self.public.len() + self.local.len() + self.ble_ephemeral.len() + group_count
    }

    /// Returns `true` when there are no routing entries in any plane.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a DeviceAddress from a single byte (repeated).
    fn addr(b: u8) -> DeviceAddress {
        DeviceAddress([b; 32])
    }

    /// Helper: create a GroupId from a single byte (repeated).
    fn gid(b: u8) -> GroupId {
        GroupId([b; 16])
    }

    /// Helper: create a basic routing entry.
    fn entry(dest: u8, next: u8, hops: u8, latency: u32, ts: u64) -> RoutingEntry {
        RoutingEntry {
            destination: addr(dest),
            next_hop: addr(next),
            hop_count: hops,
            latency_ms: latency,
            next_hop_trust: TrustLevel::Trusted,
            last_updated: ts,
            announcement_id: [dest; 32],
        }
    }

    #[test]
    fn test_empty_table() {
        let table = RoutingTable::new();
        assert_eq!(table.total_route_count(), 0);
        assert_eq!(table.direct_peer_count(), 0);
    }

    #[test]
    fn test_local_lookup_priority() {
        let mut table = RoutingTable::new();
        let now = 1000;

        // Insert same destination in local and public planes.
        // Local should win.
        table.update_local(entry(0xAA, 0xAA, 1, 10, now));
        table.update_public(entry(0xAA, 0xBB, 3, 100, now), now);

        let result = table.lookup(&addr(0xAA), None, now);
        assert!(result.is_some());
        // Should be the local (direct) route.
        assert_eq!(result.unwrap().hop_count, 1);
        assert!(result.unwrap().is_direct());
    }

    #[test]
    fn test_group_lookup() {
        let mut table = RoutingTable::new();
        let now = 1000;
        let group = gid(0x01);

        table.update_group(group, entry(0xCC, 0xDD, 2, 50, now), now);

        // Without group context: not found.
        assert!(table.lookup(&addr(0xCC), None, now).is_none());

        // With group context: found.
        let result = table.lookup(&addr(0xCC), Some(&group), now);
        assert!(result.is_some());
        assert_eq!(result.unwrap().hop_count, 2);
    }

    #[test]
    fn test_staleness_and_expiry() {
        let mut table = RoutingTable::new();
        let now = 1000;

        let e = entry(0xEE, 0xFF, 2, 50, now);
        table.update_public(e, now);

        // Not stale yet.
        assert!(table.lookup(&addr(0xEE), None, now).is_some());

        // Stale but not expired — still returned (but deprioritised).
        let stale_time = now + ROUTE_STALENESS_SECS + 1;
        assert!(table.lookup(&addr(0xEE), None, stale_time).is_some());

        // Expired — not returned.
        let expired_time = now + ROUTE_EXPIRY_SECS + 1;
        assert!(table.lookup(&addr(0xEE), None, expired_time).is_none());
    }

    #[test]
    fn test_better_route_replaces() {
        let mut table = RoutingTable::new();
        let now = 1000;

        // Insert a 3-hop route.
        table.update_public(entry(0xAA, 0xBB, 3, 100, now), now);

        // A better 1-hop route should replace it.
        let replaced = table.update_public(entry(0xAA, 0xCC, 1, 20, now + 1), now + 1);
        assert!(replaced);

        let result = table.lookup(&addr(0xAA), None, now + 1).unwrap();
        assert_eq!(result.hop_count, 1);
        assert_eq!(result.next_hop, addr(0xCC));
    }

    #[test]
    fn test_gc_removes_expired() {
        let mut table = RoutingTable::new();
        let now = 1000;

        table.update_public(entry(0x01, 0x02, 1, 10, now), now);
        table.update_public(entry(0x03, 0x04, 2, 20, now), now);

        assert_eq!(table.public.len(), 2);

        // GC at a time when entries have expired.
        let expired = now + ROUTE_EXPIRY_SECS + 1;
        table.gc(expired);

        assert_eq!(table.public.len(), 0);
    }

    #[test]
    fn test_remove_via_next_hop() {
        let mut table = RoutingTable::new();
        let now = 1000;

        // Two routes through next_hop 0xBB.
        table.update_public(entry(0x01, 0xBB, 2, 30, now), now);
        table.update_public(entry(0x02, 0xBB, 3, 40, now), now);
        // One route through a different next hop.
        table.update_public(entry(0x03, 0xCC, 1, 10, now), now);

        assert_eq!(table.public.len(), 3);

        // Remove all routes through 0xBB (neighbour disconnected).
        table.remove_via_next_hop(&addr(0xBB));

        assert_eq!(table.public.len(), 1);
        assert!(table.public.contains_key(&addr(0x03)));
    }

    #[test]
    fn test_ble_ephemeral_expiry() {
        let mut table = RoutingTable::new();
        let now = 1000;
        let token = BleToken([0xAA; 16]);

        table.update_ble(
            token,
            EphemeralRoutingEntry {
                destination: addr(0x01),
                created_at: now,
                rssi: Some(-50),
            },
            now,
        );

        assert_eq!(table.ble_ephemeral.len(), 1);

        // After BLE expiry, entry should be cleaned up on next insert.
        let expired = now + BLE_ROUTE_EXPIRY_SECS + 1;
        table.update_ble(
            BleToken([0xBB; 16]),
            EphemeralRoutingEntry {
                destination: addr(0x02),
                created_at: expired,
                rssi: None,
            },
            expired,
        );

        // Old entry gone, new entry present.
        assert_eq!(table.ble_ephemeral.len(), 1);
        assert!(!table.ble_ephemeral.contains_key(&token));
    }

    #[test]
    fn test_dominated_route_rejected() {
        let mut table = RoutingTable::new();
        let now = 1000;

        // Insert a good route: 1 hop, 10ms.
        table.update_public(entry(0xAA, 0xBB, 1, 10, now), now);

        // Try to insert a worse route: 3 hops, 100ms.
        // Should be rejected (dominated by existing).
        let accepted = table.update_public(entry(0xAA, 0xCC, 3, 100, now + 1), now + 1);
        assert!(!accepted);

        // The original route should still be there.
        let result = table.lookup(&addr(0xAA), None, now + 1).unwrap();
        assert_eq!(result.next_hop, addr(0xBB));
    }
}
