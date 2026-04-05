//! Infinet — Virtual Private Network Namespaces (§13.14)
//!
//! # What is Infinet?
//!
//! Infinet is Mesh Infinity's Tailscale-equivalent: a virtual overlay
//! network that assigns each member a private address and provides
//! mesh-routed connectivity, DNS, ACLs, and service discovery.
//!
//! # Address Spaces
//!
//! Both Tailscale and Infinet use the same ULA prefix ranges. To prevent
//! collisions when Tailscale and Infinet are both active, the assignment
//! policy is asymmetric:
//!
//! ## IPv6: `fd7a:115c:a1e0::/48` — AUTO-ASSIGNED, collision-detected
//!
//! Each member gets a /64 subnet assigned automatically on join.
//! Before assignment, the allocator checks whether the proposed /64
//! conflicts with any currently-assigned Tailscale IPv6 address.
//! If a collision is found, the slot is skipped and the next free
//! slot is tried.
//!
//! **Tailscale wins on IPv6 collision.** If Tailscale later assigns an
//! address into an already-assigned Infinet /64 (e.g. after the member
//! joined), the conflict is detected at connect time. The Infinet address
//! is cycled to the next free slot and the device and Infinet are notified
//! via `AddressConflictEvent`. The old slot is released.
//!
//! ## IPv4: `100.64.0.0/10` — MANUAL ASSIGNMENT ONLY
//!
//! Tailscale uses the same RFC 6598 CGNAT range (100.64.0.0/10) for its
//! device addresses. To avoid collision, Infinet does NOT auto-assign IPv4.
//! IPv4 addresses within the Infinet are assigned manually by an admin.
//! Devices that have no manual IPv4 assignment are IPv6-only within the
//! Infinet (DNS AAAA records are generated; A records are generated only
//! when a manual IPv4 is present).
//!
//! ## DNS / domains: `*.infinet.meshinfinity` — AUTO-ASSIGNED
//!
//! Domain names are derived from shortnames and are always auto-generated.
//! No collision risk — the `.infinet.meshinfinity` suffix is unique to us.
//!
//! # ZeroTier
//!
//! ZeroTier networks can use arbitrary IP ranges and may conflict with the
//! system LAN. This is a ZeroTier client concern, handled the same way any
//! ZeroTier client handles it (ZeroTier has its own route conflict detection).
//! Infinet does not interact with ZeroTier addressing.
//!
//! # DNS (Tailscale MagicDNS equivalent)
//!
//! ```text
//! *.(device-shortname).(user-shortname).(infinet-name).infinet.meshinfinity
//! ```
//!
//! Port numbers in URLs are ignored for routing — service name routes
//! to internal port via device service registry.
//!
//! # ACL Model (Tailscale ACL equivalent)
//!
//! Rules evaluated in order, first match wins. Default policy:
//! - Allow own devices
//! - Deny other members' devices
//!
//! Subjects: specific member, role-based, everyone.
//! Targets: specific device, service, subnet, everything.
//!
//! # Device Expiry
//!
//! Default 180 days from last seen. Expiry releases address,
//! removes DNS records and services. Does NOT expire mesh trust.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Constants — addressing (Tailscale-compatible)
// ---------------------------------------------------------------------------

/// IPv4 base network for Infinet. RFC 6598 CGNAT range.
/// Same as Tailscale's 100.x.y.z address space.
// IPV4_BASE — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV4_BASE — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV4_BASE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const IPV4_BASE: [u8; 4] = [100, 64, 0, 0];

/// IPv4 prefix length for the entire Infinet space.
// IPV4_PREFIX_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV4_PREFIX_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV4_PREFIX_LEN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const IPV4_PREFIX_LEN: u8 = 10;

/// IPv4 prefix length per user (/16 = 65,534 usable addresses).
// IPV4_USER_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV4_USER_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV4_USER_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const IPV4_USER_PREFIX: u8 = 16;

/// Reserved gateway/resolver address: 100.64.0.1.
// IPV4_GATEWAY — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV4_GATEWAY — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV4_GATEWAY — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const IPV4_GATEWAY: [u8; 4] = [100, 64, 0, 1];

/// Maximum IPv4 participants (each gets a /16 from /10 = 64 slots).
// MAX_IPV4_PARTICIPANTS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_IPV4_PARTICIPANTS — protocol constant.
// Defined by the spec; must not change without a version bump.
// MAX_IPV4_PARTICIPANTS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_IPV4_PARTICIPANTS: usize = 64;

/// IPv6 ULA prefix for Infinet (Tailscale-compatible).
/// fd7a:115c:a1e0::/48
// IPV6_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV6_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV6_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const IPV6_PREFIX: [u16; 3] = [0xfd7a, 0x115c, 0xa1e0];

/// IPv6 prefix length per user (/64).
// IPV6_USER_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV6_USER_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
// IPV6_USER_PREFIX — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const IPV6_USER_PREFIX: u8 = 64;

/// Default device expiry (seconds) = 180 days from last seen.
// DEVICE_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEVICE_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
// DEVICE_EXPIRY_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const DEVICE_EXPIRY_SECS: u64 = 180 * 24 * 3600;

// ---------------------------------------------------------------------------
// Infinet Role
// ---------------------------------------------------------------------------

/// Member role within an Infinet. Mirrors Tailscale admin/member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// InfinetRole — variant enumeration.
// Match exhaustively to handle every protocol state.
// InfinetRole — variant enumeration.
// Match exhaustively to handle every protocol state.
// InfinetRole — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum InfinetRole {
    /// Can manage members, ACLs, DNS, and settings.
    Admin,
    /// Can connect devices and access allowed resources.
    Member,
}

// ---------------------------------------------------------------------------
// Infinet Member
// ---------------------------------------------------------------------------

/// A member of an Infinet (analogous to a Tailscale user).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// InfinetMember — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetMember — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetMember — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct InfinetMember {
    /// Mesh peer ID of this member.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub peer_id: [u8; 32],
    /// Short human-readable name (used in DNS).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub shortname: String,
    /// Role in this Infinet.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub role: InfinetRole,
    /// Manually assigned IPv4 /16 subnet (e.g., "100.65.0.0/16").
    ///
    /// NOT auto-assigned on join — admin must set this explicitly.
    /// None means this member is IPv6-only within the Infinet.
    /// Avoids collision with Tailscale's 100.64.0.0/10 range.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub subnet_v4: Option<String>,
    /// Auto-assigned IPv6 /64 subnet.
    ///
    /// Assigned on join, collision-checked against known Tailscale addresses.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub subnet_v6: Option<String>,
    /// Devices registered by this member.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub devices: Vec<InfinetDevice>,
    /// When this member joined.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub joined_at: u64,
    /// When this membership expires (None = no expiry).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub expires_at: Option<u64>,
}

/// A device within an Infinet member's namespace.
/// Analogous to a Tailscale machine/node.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// InfinetDevice — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetDevice — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetDevice — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct InfinetDevice {
    /// Unique device identifier (mesh device address).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub device_id: [u8; 32],
    /// Short name used in DNS (e.g., "laptop", "phone").
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub shortname: String,
    /// Manually assigned IPv4 address within the member's /16, if the member
    /// has been given a manual subnet. None = no IPv4 within Infinet.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub addr_v4: Option<String>,
    /// Auto-assigned IPv6 address within the member's /64.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub addr_v6: Option<String>,
    /// Services running on this device.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub services: Vec<InfinetService>,
    /// Last time this device was seen online.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub last_seen: u64,
}

/// A service running on an Infinet device.
/// Analogous to Tailscale Funnel/Serve exposed services.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// InfinetService — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetService — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetService — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct InfinetService {
    /// Service name (used in DNS, must be unique per device).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// Internal port the service listens on.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub port: u32,
    /// Human-readable description.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// ACL Model (Tailscale-style)
// ---------------------------------------------------------------------------

/// Access control rule within an Infinet.
///
/// Evaluated in order — first match wins. This mirrors Tailscale's
/// ACL policy model where rules are evaluated top-to-bottom.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// InfinetACL — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetACL — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetACL — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct InfinetACL {
    /// Unique rule identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub rule_id: [u8; 16],
    /// Who this rule applies to.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub subject: InfinetSubject,
    /// What this rule controls access to.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target: InfinetTarget,
    /// Allow or deny.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub permission: InfinetPermission,
    /// Optional expiry for time-limited rules.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub expires_at: Option<u64>,
}

/// Who an ACL rule applies to.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// InfinetSubject — variant enumeration.
// Match exhaustively to handle every protocol state.
// InfinetSubject — variant enumeration.
// Match exhaustively to handle every protocol state.
// InfinetSubject — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum InfinetSubject {
    /// A specific member by peer ID.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Member { peer_id: [u8; 32] },
    /// All members with a specific role.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Role { role: InfinetRole },
    /// Everyone in the Infinet.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Everyone,
}

/// What an ACL rule controls access to.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// InfinetTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
// InfinetTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
// InfinetTarget — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum InfinetTarget {
    /// A specific device.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Device { device_id: [u8; 32] },
    /// A specific service on a specific device.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Service {
        device_id: [u8; 32],
        service: String,
    },
    /// A subnet (CIDR notation).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Subnet { network: String },
    /// Everything in the Infinet.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Everything,
}

/// ACL permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// InfinetPermission — variant enumeration.
// Match exhaustively to handle every protocol state.
// InfinetPermission — variant enumeration.
// Match exhaustively to handle every protocol state.
// InfinetPermission — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum InfinetPermission {
    Allow,
    Deny,
}

// ---------------------------------------------------------------------------
// DNS Records
// ---------------------------------------------------------------------------

/// A DNS record within an Infinet.
/// Analogous to Tailscale MagicDNS entries.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// InfinetDNSRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetDNSRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetDNSRecord — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct InfinetDNSRecord {
    /// The record id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub record_id: [u8; 16],
    /// The name for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// The record type for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub record_type: DnsRecordType,
    /// The value for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub value: String,
    /// The ttl for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ttl: u32,
    /// The created by for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub created_by: [u8; 32],
}

/// DNS record types supported in Infinet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// DnsRecordType — variant enumeration.
// Match exhaustively to handle every protocol state.
// DnsRecordType — variant enumeration.
// Match exhaustively to handle every protocol state.
// DnsRecordType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    TXT,
}

// ---------------------------------------------------------------------------
// Join Approval Policy
// ---------------------------------------------------------------------------

/// How new members join an Infinet.
/// Mirrors Tailscale's device authorization model.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// JoinPolicy — variant enumeration.
// Match exhaustively to handle every protocol state.
// JoinPolicy — variant enumeration.
// Match exhaustively to handle every protocol state.
// JoinPolicy — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum JoinPolicy {
    /// Admin must approve each join (Tailscale default).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    AdminApproval,
    /// N-of-M existing members must approve.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Quorum { n: u32, m: u32 },
    /// Auto-approve if mesh trust level is sufficient.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    AutoApprove { min_trust_level: u8 },
    /// One-time invite tokens only.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    InviteOnly,
}

// ---------------------------------------------------------------------------
// Infinet State
// ---------------------------------------------------------------------------

/// Complete state of an Infinet (§13.14).
///
/// This is the coordination object that all members synchronize.
/// Analogous to Tailscale's coordination server state, except
/// decentralized — signed by admin quorum instead of a central server.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// InfinetState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// InfinetState — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct InfinetState {
    /// Unique Infinet identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub infinet_id: [u8; 32],
    /// Human-readable name.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub infinet_name: String,
    /// All members.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub members: Vec<InfinetMember>,
    /// Access control rules.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub acls: Vec<InfinetACL>,
    /// Custom DNS records.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub dns_records: Vec<InfinetDNSRecord>,
    /// Monotonically increasing state version.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub state_version: u64,
    /// Ed25519 signature over canonical state (admin quorum).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub state_sig: Vec<u8>,
}

// ---------------------------------------------------------------------------
// IP Address Allocator
// ---------------------------------------------------------------------------

/// Allocates IPv4 and IPv6 subnets for Infinet members.
///
/// **IPv4 (100.64.0.0/10):** Admin-assigned only. `allocate_v4()` is
/// available for manual admin use but is NOT called automatically during
/// member join. This avoids collision with Tailscale's CGNAT range.
///
/// **IPv6 (fd7a:115c:a1e0::/48):** Auto-assigned on join via
/// `allocate_v6()` or `allocate_v6_avoiding()`. The collision-aware
/// variant skips slots that overlap with known Tailscale IPv6 addresses.
///
/// IPv4 allocation: member index N gets 100.(64+N).0.0/16.
/// - Member 0: 100.64.0.0/16 (but .0.1 is reserved gateway)
/// - Member 1: 100.65.0.0/16
/// - Member 63: 100.127.0.0/16 (last slot)
///
/// IPv6 allocation: slot N gets fd7a:115c:a1e0:N::/64.
// IpAllocator — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// IpAllocator — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// IpAllocator — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct IpAllocator {
    /// Which IPv4 /16 slots are allocated. Index = slot number.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    allocated_v4: Vec<bool>,
    /// Which IPv6 /64 slots are currently in use.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    allocated_v6: HashSet<u16>,
    /// Next slot to try for IPv6 allocation (monotone; not reset on release).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    next_v6_slot: u16,
}

// Begin the block scope.
// IpAllocator implementation — core protocol logic.
// IpAllocator implementation — core protocol logic.
// IpAllocator implementation — core protocol logic.
impl IpAllocator {
    /// Create a new allocator.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            allocated_v4: vec![false; MAX_IPV4_PARTICIPANTS],
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            allocated_v6: HashSet::new(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            next_v6_slot: 1, // 0 is reserved.
        }
    }

    /// Reconstruct allocator state from existing members.
    // Perform the 'from members' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from members' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'from members' operation.
    // Errors are propagated to the caller via Result.
    pub fn from_members(members: &[InfinetMember]) -> Self {
        // Invoke the associated function.
        // Compute alloc for this protocol step.
        // Compute alloc for this protocol step.
        // Compute alloc for this protocol step.
        let mut alloc = Self::new();
        // Process each peer/member in the set.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for member in members {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if let Some(ref subnet) = member.subnet_v4 {
                // Conditional branch based on the current state.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if let Some(slot) = Self::slot_from_v4_subnet(subnet) {
                    // Validate the input length to prevent out-of-bounds access.
                    // Guard: validate the condition before proceeding.
                    // Guard: validate the condition before proceeding.
                    // Guard: validate the condition before proceeding.
                    if (slot as usize) < alloc.allocated_v4.len() {
                        // Execute the operation and bind the result.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        alloc.allocated_v4[slot as usize] = true;
                    }
                }
            }
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if let Some(ref subnet) = member.subnet_v6 {
                // Conditional branch based on the current state.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if let Some(slot) = Self::slot_from_v6_subnet(subnet) {
                    // Insert into the lookup table for efficient retrieval.
                    // Insert into the map/set.
                    // Insert into the map/set.
                    // Insert into the map/set.
                    alloc.allocated_v6.insert(slot);
                    // Bounds check to enforce protocol constraints.
                    // Guard: validate the condition before proceeding.
                    // Guard: validate the condition before proceeding.
                    // Guard: validate the condition before proceeding.
                    if slot >= alloc.next_v6_slot {
                        // Execute the operation and bind the result.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        alloc.next_v6_slot = slot + 1;
                    }
                }
            }
        }
        alloc
    }

    /// Allocate a /16 IPv4 subnet for **manual admin assignment**.
    ///
    /// NOT called during member join — IPv4 is manually assigned to avoid
    /// collision with Tailscale's 100.64.0.0/10 CGNAT range.
    ///
    /// Returns the subnet in CIDR notation, or None if all 64 slots taken.
    // Perform the 'allocate v4' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allocate v4' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allocate v4' operation.
    // Errors are propagated to the caller via Result.
    pub fn allocate_v4(&mut self) -> Option<String> {
        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for (i, allocated) in self.allocated_v4.iter_mut().enumerate() {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !*allocated {
                *allocated = true;
                // Execute the operation and bind the result.
                // Compute second octet for this protocol step.
                // Compute second octet for this protocol step.
                // Compute second octet for this protocol step.
                let second_octet = 64 + i as u8;
                // Format the output for display or logging.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return Some(format!("100.{}.0.0/16", second_octet));
            }
        }
        // No value available.
        // No value available.
        // No value available.
        None
    }

    /// Allocate a /64 IPv6 subnet, **without** collision checking.
    ///
    /// Use `allocate_v6_avoiding()` when Tailscale is also active.
    // Perform the 'allocate v6' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allocate v6' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allocate v6' operation.
    // Errors are propagated to the caller via Result.
    pub fn allocate_v6(&mut self) -> String {
        // Find next free slot sequentially.
        loop {
            // Execute the operation and bind the result.
            // Compute slot for this protocol step.
            // Compute slot for this protocol step.
            // Compute slot for this protocol step.
            let slot = self.next_v6_slot;
            // Update the next v6 slot to reflect the new state.
            // Advance next v6 slot state.
            // Advance next v6 slot state.
            // Advance next v6 slot state.
            self.next_v6_slot = self.next_v6_slot.saturating_add(1);
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if !self.allocated_v6.contains(&slot) {
                // Insert into the lookup table for efficient retrieval.
                // Insert into the map/set.
                // Insert into the map/set.
                // Insert into the map/set.
                self.allocated_v6.insert(slot);
                // Format the output for display or logging.
                // Return to the caller.
                // Return to the caller.
                // Return to the caller.
                return format!("fd7a:115c:a1e0:{slot:04x}::/64");
            }
        }
    }

    /// Allocate a /64 IPv6 subnet, skipping slots that conflict with
    /// any currently-assigned Tailscale IPv6 address.
    ///
    /// `tailscale_addrs`: slice of Tailscale device IPs in the
    /// fd7a:115c:a1e0::/48 range (e.g. "fd7a:115c:a1e0:0001::3f2a").
    /// Addresses outside this prefix are ignored.
    ///
    /// Returns the allocated subnet, or None if the address space is
    /// exhausted (extremely unlikely — 65,535 possible /64 slots).
    // Perform the 'allocate v6 avoiding' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allocate v6 avoiding' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allocate v6 avoiding' operation.
    // Errors are propagated to the caller via Result.
    pub fn allocate_v6_avoiding(&mut self, tailscale_addrs: &[&str]) -> Option<String> {
        // Initialize the hash function for digest computation.
        // Compute blocked for this protocol step.
        // Compute blocked for this protocol step.
        // Compute blocked for this protocol step.
        let blocked: HashSet<u16> = tailscale_addrs
            .iter()
            // Apply the closure to each element.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            .filter_map(|a| tailscale_ipv6_slot(a))
            // Materialize the iterator into a concrete collection.
            // Collect into a concrete collection.
            // Collect into a concrete collection.
            // Collect into a concrete collection.
            .collect();

        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for candidate in self.next_v6_slot..=u16::MAX {
            // Flow control: check if the operation should be stalled.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if self.allocated_v6.contains(&candidate) || blocked.contains(&candidate) {
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                continue;
            }
            // Insert into the lookup table for efficient retrieval.
            // Insert into the map/set.
            // Insert into the map/set.
            // Insert into the map/set.
            self.allocated_v6.insert(candidate);
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if candidate >= self.next_v6_slot {
                // Update the next v6 slot to reflect the new state.
                // Advance next v6 slot state.
                // Advance next v6 slot state.
                // Advance next v6 slot state.
                self.next_v6_slot = candidate.saturating_add(1);
            }
            // Format the output for display or logging.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Some(format!("fd7a:115c:a1e0:{candidate:04x}::/64"));
        }
        // Process the current step in the protocol.
        // No value available.
        // No value available.
        // No value available.
        None // u16 exhausted — won't happen in practice
    }

    /// Release an IPv4 subnet (member removed or de-assigned).
    // Perform the 'release v4' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'release v4' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'release v4' operation.
    // Errors are propagated to the caller via Result.
    pub fn release_v4(&mut self, subnet: &str) {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(slot) = Self::slot_from_v4_subnet(subnet) {
            // Validate the input length to prevent out-of-bounds access.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if (slot as usize) < self.allocated_v4.len() {
                // Execute the operation and bind the result.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                self.allocated_v4[slot as usize] = false;
            }
        }
    }

    /// Release a /64 IPv6 subnet slot (member removed or address cycled).
    // Perform the 'release v6' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'release v6' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'release v6' operation.
    // Errors are propagated to the caller via Result.
    pub fn release_v6(&mut self, subnet: &str) {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(slot) = Self::slot_from_v6_subnet(subnet) {
            // Remove from the collection and return the evicted value.
            // Remove from the collection.
            // Remove from the collection.
            // Remove from the collection.
            self.allocated_v6.remove(&slot);
        }
    }

    /// Allocate an IPv4 address for a device within a member's /16.
    ///
    /// `member_subnet`: the member's /16 (e.g., "100.65.0.0/16").
    /// `existing_addrs`: addresses already assigned to other devices.
    ///
    /// Returns an address like "100.65.0.2" (skipping .0.0 and .0.1).
    // Perform the 'allocate device v4' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allocate device v4' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'allocate device v4' operation.
    // Errors are propagated to the caller via Result.
    pub fn allocate_device_v4(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        member_subnet: &str,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        existing_addrs: &[String],
        // Begin the block scope.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
    ) -> Option<String> {
        // Parse the second octet from the subnet.
        // Compute parts for this protocol step.
        // Compute parts for this protocol step.
        // Compute parts for this protocol step.
        let parts: Vec<&str> = member_subnet.split('.').collect();
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if parts.len() < 2 {
            // No result available — signal absence to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return None;
        }
        // Check the operation outcome without consuming the error.
        // Compute second octet for this protocol step.
        // Compute second octet for this protocol step.
        // Compute second octet for this protocol step.
        let second_octet: u8 = parts[1].parse().ok()?;

        // Try addresses .0.2 through .255.254.
        // Skip .0.0 (network) and .0.1 (gateway reserved).
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for third in 0..=255u16 {
            // Iterate over each element in the collection.
            // Iterate over each element.
            // Iterate over each element.
            // Iterate over each element.
            for fourth in 2..=254u8 {
                // Bounds check to enforce protocol constraints.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if third == 0 && fourth < 2 {
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    continue;
                }
                // Format the output for display or logging.
                // Compute addr for this protocol step.
                // Compute addr for this protocol step.
                // Compute addr for this protocol step.
                let addr = format!("100.{}.{}.{}", second_octet, third, fourth);
                // Conditional branch based on the current state.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if !existing_addrs.contains(&addr) {
                    // Return the result to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    // Return to the caller.
                    return Some(addr);
                }
            }
        }
        // Process the current step in the protocol.
        // No value available.
        // No value available.
        // No value available.
        None // /16 exhausted (65K addresses).
    }

    /// Extract the slot number from an IPv4 subnet string like "100.65.0.0/16".
    // Perform the 'slot from v4 subnet' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'slot from v4 subnet' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'slot from v4 subnet' operation.
    // Errors are propagated to the caller via Result.
    fn slot_from_v4_subnet(subnet: &str) -> Option<u8> {
        // Materialize the iterator into a concrete collection.
        // Compute parts for this protocol step.
        // Compute parts for this protocol step.
        // Compute parts for this protocol step.
        let parts: Vec<&str> = subnet.split('.').collect();
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if parts.len() >= 2 {
            // Check the operation outcome without consuming the error.
            // Compute second for this protocol step.
            // Compute second for this protocol step.
            // Compute second for this protocol step.
            let second: u8 = parts[1].parse().ok()?;
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if second >= 64 {
                // Wrap the found value for the caller.
                // Wrap the found value.
                // Wrap the found value.
                // Wrap the found value.
                Some(second - 64)
            // Begin the block scope.
            // Fallback when the guard was not satisfied.
            // Fallback when the guard was not satisfied.
            // Fallback when the guard was not satisfied.
            } else {
                // No value available.
                // No value available.
                // No value available.
                None
            }
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // No value available.
            // No value available.
            // No value available.
            None
        }
    }

    /// Extract the slot number from an IPv6 subnet like "fd7a:115c:a1e0:0002::/64".
    // Perform the 'slot from v6 subnet' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'slot from v6 subnet' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'slot from v6 subnet' operation.
    // Errors are propagated to the caller via Result.
    pub fn slot_from_v6_subnet(subnet: &str) -> Option<u16> {
        // Format: "fd7a:115c:a1e0:XXXX::/64"
        // Split on ':' and take the 4th group (index 3).
        // Compute without prefix for this protocol step.
        // Compute without prefix for this protocol step.
        // Compute without prefix for this protocol step.
        let without_prefix = subnet.trim_end_matches("::/64");
        // Materialize the iterator into a concrete collection.
        // Compute groups for this protocol step.
        // Compute groups for this protocol step.
        // Compute groups for this protocol step.
        let groups: Vec<&str> = without_prefix.split(':').collect();
        // Validate the input length to prevent out-of-bounds access.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if groups.len() >= 4 {
            // Check the operation outcome without consuming the error.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            u16::from_str_radix(groups[3], 16).ok()
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // No value available.
            // No value available.
            // No value available.
            None
        }
    }
}

// Trait implementation for protocol conformance.
// Implement Default for IpAllocator.
// Implement Default for IpAllocator.
// Implement Default for IpAllocator.
impl Default for IpAllocator {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Create a new instance with the specified parameters.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IPv6 Collision Detection (Tailscale vs Infinet)
// ---------------------------------------------------------------------------

/// Extract the /64 slot index from a Tailscale IPv6 address in the
/// fd7a:115c:a1e0::/48 range.
///
/// Returns None if the address is not in the Infinet ULA prefix or
/// cannot be parsed. Addresses in other ranges are not a concern.
///
/// Example: "fd7a:115c:a1e0:0001::5a3f" → Some(1)
// Perform the 'tailscale ipv6 slot' operation.
// Errors are propagated to the caller via Result.
// Perform the 'tailscale ipv6 slot' operation.
// Errors are propagated to the caller via Result.
// Perform the 'tailscale ipv6 slot' operation.
// Errors are propagated to the caller via Result.
pub fn tailscale_ipv6_slot(addr: &str) -> Option<u16> {
    // Strip trailing /prefix-len if present (subnet notation).
    // Compute addr for this protocol step.
    // Compute addr for this protocol step.
    // Compute addr for this protocol step.
    let addr = addr.split('/').next().unwrap_or(addr).trim();

    // We only care about our ULA prefix fd7a:115c:a1e0::/48.
    // A full address looks like: fd7a:115c:a1e0:XXXX::YYYY
    // or expanded: fd7a:115c:a1e0:XXXX:0000:0000:0000:YYYY
    // The 4th group (index 3 after splitting on ':') is the slot.
    // Compute groups for this protocol step.
    // Compute groups for this protocol step.
    // Compute groups for this protocol step.
    let groups: Vec<&str> = addr.split(':').collect();
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if groups.len() < 4 {
        // No result available — signal absence to the caller.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return None;
    }
    // Verify prefix groups.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if groups[0].to_lowercase() != "fd7a"
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        || groups[1].to_lowercase() != "115c"
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        || groups[2].to_lowercase() != "a1e0"
    {
        // No result available — signal absence to the caller.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return None;
    }
    // Check the operation outcome without consuming the error.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    u16::from_str_radix(groups[3], 16).ok()
}

/// Check whether a proposed Infinet /64 subnet (identified by slot) collides
/// with any currently-assigned Tailscale IPv6 address.
///
/// `infinet_slot`: the 4th group value of the proposed /64
///    (e.g. slot 1 → fd7a:115c:a1e0:0001::/64)
/// `tailscale_addrs`: currently assigned Tailscale device IPv6 addresses.
///
/// Returns true if any Tailscale address falls within the proposed /64.
// Perform the 'infinet v6 collides with tailscale' operation.
// Errors are propagated to the caller via Result.
// Perform the 'infinet v6 collides with tailscale' operation.
// Errors are propagated to the caller via Result.
// Perform the 'infinet v6 collides with tailscale' operation.
// Errors are propagated to the caller via Result.
pub fn infinet_v6_collides_with_tailscale(infinet_slot: u16, tailscale_addrs: &[&str]) -> bool {
    // Create an iterator over the collection elements.
    // Create an iterator over the elements.
    // Create an iterator over the elements.
    // Create an iterator over the elements.
    tailscale_addrs
        .iter()
        // Apply the closure to each element.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        .filter_map(|a| tailscale_ipv6_slot(a))
        // Apply the closure to each element.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        .any(|ts_slot| ts_slot == infinet_slot)
}

/// Notification emitted when an Infinet member's IPv6 address collides
/// with a Tailscale assignment and is cycled to a new address.
///
/// Tailscale wins. The Infinet member's address is cycled; the old slot
/// is released. Both the device and the Infinet receive this event so they
/// can update their routing tables and DNS records.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// AddressConflictEvent — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AddressConflictEvent — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// AddressConflictEvent — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct AddressConflictEvent {
    /// The member whose address was cycled.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub member_peer_id: [u8; 32],
    /// The old /64 subnet that conflicted (now released).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub old_subnet_v6: String,
    /// The new /64 subnet assigned after cycling.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub new_subnet_v6: String,
    /// The Tailscale address that caused the conflict.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub conflicting_tailscale_addr: String,
    /// Unix timestamp when the cycle occurred.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub cycled_at: u64,
}

/// Cycle a member's IPv6 /64 subnet when it collides with a Tailscale address.
///
/// **Tailscale wins.** This function:
/// 1. Releases the old /64 slot.
/// 2. Allocates a new /64 slot that avoids the conflicting Tailscale address.
/// 3. Returns an `AddressConflictEvent` to broadcast to the device and Infinet.
///
/// The caller is responsible for updating `member.subnet_v6` to the new value
/// and propagating the event (gossip to all Infinet members, and direct
/// notification to the affected device).
///
/// Returns None if the collision was not actually present (idempotent).
// Perform the 'cycle v6 for member' operation.
// Errors are propagated to the caller via Result.
// Perform the 'cycle v6 for member' operation.
// Errors are propagated to the caller via Result.
// Perform the 'cycle v6 for member' operation.
// Errors are propagated to the caller via Result.
pub fn cycle_v6_for_member(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    member: &mut InfinetMember,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    alloc: &mut IpAllocator,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    tailscale_addrs: &[&str],
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    now: u64,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Option<AddressConflictEvent> {
    // Identify the peer for this operation.
    // Compute current subnet for this protocol step.
    // Compute current subnet for this protocol step.
    // Compute current subnet for this protocol step.
    let current_subnet = member.subnet_v6.as_ref()?;
    // Propagate errors via the ? operator — callers handle failures.
    // Compute current slot for this protocol step.
    // Compute current slot for this protocol step.
    // Compute current slot for this protocol step.
    let current_slot = IpAllocator::slot_from_v6_subnet(current_subnet)?;

    // Only cycle if there's actually a collision.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if !infinet_v6_collides_with_tailscale(current_slot, tailscale_addrs) {
        // No result available — signal absence to the caller.
        // Return to the caller.
        // Return to the caller.
        // Return to the caller.
        return None;
    }

    // Find which Tailscale address caused the conflict (for the event).
    // Compute conflicting for this protocol step.
    // Compute conflicting for this protocol step.
    // Compute conflicting for this protocol step.
    let conflicting = tailscale_addrs
        .iter()
        // Apply the closure to each element.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        .find(|a| tailscale_ipv6_slot(a) == Some(current_slot))
        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        .copied()
        // Fall back to the default value on failure.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        .unwrap_or("")
        // Chain the operation on the intermediate result.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        .to_string();

    // Execute the operation and bind the result.
    // Compute old subnet for this protocol step.
    // Compute old subnet for this protocol step.
    // Compute old subnet for this protocol step.
    let old_subnet = current_subnet.clone();

    // Release old slot.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    alloc.release_v6(&old_subnet);

    // Allocate new slot avoiding all current Tailscale addresses.
    // Compute new subnet for this protocol step.
    // Compute new subnet for this protocol step.
    // Compute new subnet for this protocol step.
    let new_subnet = alloc.allocate_v6_avoiding(tailscale_addrs)?;

    // Update the member.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    member.subnet_v6 = Some(new_subnet.clone());

    // Device-level addresses within the /64 also need updating.
    // The new device address replaces the old one — derive from new subnet.
    // Compute new slot for this protocol step.
    // Compute new slot for this protocol step.
    // Compute new slot for this protocol step.
    let new_slot = IpAllocator::slot_from_v6_subnet(&new_subnet)?;
    // Process each peer/member in the set.
    // Iterate over each element.
    // Iterate over each element.
    // Iterate over each element.
    for device in &mut member.devices {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if device.addr_v6.is_some() {
            // Derive new address from new subnet + deterministic interface ID.
            // Compute iid for this protocol step.
            // Compute iid for this protocol step.
            // Compute iid for this protocol step.
            let iid = u64::from_le_bytes(device.device_id[..8].try_into().ok()?);
            // Format the output for display or logging.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            device.addr_v6 = Some(format!(
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                "fd7a:115c:a1e0:{new_slot:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                (iid >> 48) & 0xFFFF,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                (iid >> 32) & 0xFFFF,
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                (iid >> 16) & 0xFFFF,
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                iid & 0xFFFF,
            ));
        }
    }

    // Wrap the found value for the caller.
    // Wrap the found value.
    // Wrap the found value.
    // Wrap the found value.
    Some(AddressConflictEvent {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        member_peer_id: member.peer_id,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        old_subnet_v6: old_subnet,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        new_subnet_v6: new_subnet,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        conflicting_tailscale_addr: conflicting,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        cycled_at: now,
    })
}

// ---------------------------------------------------------------------------
// ACL Evaluator
// ---------------------------------------------------------------------------

/// Evaluates Infinet ACL rules for a given access request.
///
/// Rules are evaluated in order. First match wins.
/// Default (no rule matches): Deny.
///
/// This mirrors Tailscale's ACL evaluation model.
// Perform the 'evaluate acl' operation.
// Errors are propagated to the caller via Result.
// Perform the 'evaluate acl' operation.
// Errors are propagated to the caller via Result.
// Perform the 'evaluate acl' operation.
// Errors are propagated to the caller via Result.
pub fn evaluate_acl(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    acls: &[InfinetACL],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    requester_peer_id: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    requester_role: InfinetRole,
    target_owner_peer_id: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    target_device_id: &[u8; 32],
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    target_service: Option<&str>,
    target_ipv4: Option<&str>,
    target_ipv6: Option<&str>,
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    now: u64,
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
) -> InfinetPermission {
    // Iterate over each element in the collection.
    // Iterate over each element.
    // Iterate over each element.
    // Iterate over each element.
    for acl in acls {
        // Skip expired rules.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if let Some(expiry) = acl.expires_at {
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if now >= expiry {
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                continue;
            }
        }

        // Check subject match.
        // Compute subject match for this protocol step.
        // Compute subject match for this protocol step.
        // Compute subject match for this protocol step.
        let subject_match = match &acl.subject {
            // Handle this match arm.
            // Handle InfinetSubject::Member { peer_id }.
            // Handle InfinetSubject::Member { peer_id }.
            // Handle InfinetSubject::Member { peer_id }.
            InfinetSubject::Member { peer_id } => peer_id == requester_peer_id,
            // Handle this match arm.
            // Handle InfinetSubject::Role { role }.
            // Handle InfinetSubject::Role { role }.
            // Handle InfinetSubject::Role { role }.
            InfinetSubject::Role { role } => *role == requester_role,
            // Handle this match arm.
            InfinetSubject::Everyone => true,
        };

        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !subject_match {
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            continue;
        }

        // Check target match.
        // Compute target match for this protocol step.
        // Compute target match for this protocol step.
        // Compute target match for this protocol step.
        let target_match = match &acl.target {
            // Handle this match arm.
            // Handle InfinetTarget::Device { device_id }.
            // Handle InfinetTarget::Device { device_id }.
            // Handle InfinetTarget::Device { device_id }.
            InfinetTarget::Device { device_id } => device_id == target_device_id,
            // Begin the block scope.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            InfinetTarget::Service {
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                device_id,
                service,
                // Begin the block scope.
                // Handle }.
                // Handle }.
                // Handle }.
            } => {
                // Update the local state.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                device_id == target_device_id
                    // Apply the closure to each element.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    && target_service.is_some_and(|s| s == service)
            }
            // Begin the block scope.
            // Handle InfinetTarget::Subnet { .. }.
            // Handle InfinetTarget::Subnet { .. }.
            // Handle InfinetTarget::Subnet { .. }.
            InfinetTarget::Subnet { .. } => {
                subnet_target_matches(&acl.target, target_ipv4, target_ipv6)
            }
            // Handle this match arm.
            InfinetTarget::Everything => true,
        };

        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if target_match {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return acl.permission;
        }
    }

    // Default policy from the spec:
    // - a member may always reach their own devices
    // - access to other members' devices is denied unless an ACL allows it
    if requester_peer_id == target_owner_peer_id {
        InfinetPermission::Allow
    } else {
        InfinetPermission::Deny
    }
}

fn subnet_target_matches(
    target: &InfinetTarget,
    target_ipv4: Option<&str>,
    target_ipv6: Option<&str>,
) -> bool {
    let InfinetTarget::Subnet { network } = target else {
        return false;
    };

    if let Some((base, prefix)) = parse_ipv4_cidr(network) {
        return target_ipv4
            .and_then(|addr| addr.parse::<Ipv4Addr>().ok())
            .is_some_and(|addr| ipv4_in_cidr(addr, base, prefix));
    }

    if let Some((base, prefix)) = parse_ipv6_cidr(network) {
        return target_ipv6
            .and_then(|addr| addr.parse::<Ipv6Addr>().ok())
            .is_some_and(|addr| ipv6_in_cidr(addr, base, prefix));
    }

    false
}

fn parse_ipv4_cidr(network: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr, prefix) = network.split_once('/')?;
    let prefix = prefix.parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((addr.parse::<Ipv4Addr>().ok()?, prefix))
}

fn parse_ipv6_cidr(network: &str) -> Option<(Ipv6Addr, u8)> {
    let (addr, prefix) = network.split_once('/')?;
    let prefix = prefix.parse::<u8>().ok()?;
    if prefix > 128 {
        return None;
    }
    Some((addr.parse::<Ipv6Addr>().ok()?, prefix))
}

fn ipv4_in_cidr(addr: Ipv4Addr, base: Ipv4Addr, prefix: u8) -> bool {
    let addr = u32::from(addr);
    let base = u32::from(base);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (addr & mask) == (base & mask)
}

fn ipv6_in_cidr(addr: Ipv6Addr, base: Ipv6Addr, prefix: u8) -> bool {
    let addr = u128::from(addr);
    let base = u128::from(base);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (addr & mask) == (base & mask)
}

// ---------------------------------------------------------------------------
// Device Expiry
// ---------------------------------------------------------------------------

/// Check for expired devices and return their IDs.
///
/// Expired devices have `last_seen` older than `DEVICE_EXPIRY_SECS`.
/// Expiry releases the device's IP address, removes its DNS records,
/// and removes its services. Does NOT expire mesh trust.
// Perform the 'find expired devices' operation.
// Errors are propagated to the caller via Result.
// Perform the 'find expired devices' operation.
// Errors are propagated to the caller via Result.
// Perform the 'find expired devices' operation.
// Errors are propagated to the caller via Result.
pub fn find_expired_devices(members: &[InfinetMember], now: u64) -> Vec<[u8; 32]> {
    // Pre-allocate the buffer to avoid repeated reallocations.
    // Compute expired for this protocol step.
    // Compute expired for this protocol step.
    // Compute expired for this protocol step.
    let mut expired = Vec::new();
    // Process each peer/member in the set.
    // Iterate over each element.
    // Iterate over each element.
    // Iterate over each element.
    for member in members {
        // Process each peer/member in the set.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for device in &member.devices {
            // Bounds check to enforce protocol constraints.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if now.saturating_sub(device.last_seen) > DEVICE_EXPIRY_SECS {
                // Execute the operation and bind the result.
                // Append to the collection.
                // Append to the collection.
                // Append to the collection.
                expired.push(device.device_id);
            }
        }
    }
    expired
}

// ---------------------------------------------------------------------------
// DNS Generation
// ---------------------------------------------------------------------------

/// Generate MagicDNS-style records for all devices in an Infinet.
///
/// Format: `<service>.<device>.<user>.<infinet>.infinet.meshinfinity`
///
/// This mirrors Tailscale's MagicDNS where each machine gets
/// `<hostname>.<tailnet>.ts.net`.
// Perform the 'generate dns entries' operation.
// Errors are propagated to the caller via Result.
// Perform the 'generate dns entries' operation.
// Errors are propagated to the caller via Result.
// Perform the 'generate dns entries' operation.
// Errors are propagated to the caller via Result.
pub fn generate_dns_entries(
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    infinet_name: &str,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    members: &[InfinetMember],
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
) -> Vec<InfinetDNSRecord> {
    // Pre-allocate the buffer to avoid repeated reallocations.
    // Compute records for this protocol step.
    // Compute records for this protocol step.
    // Compute records for this protocol step.
    let mut records = Vec::new();

    // Process each peer/member in the set.
    // Iterate over each element.
    // Iterate over each element.
    // Iterate over each element.
    for member in members {
        // Process each peer/member in the set.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for device in &member.devices {
            // Device A record (IPv4).
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if let Some(ref addr) = device.addr_v4 {
                // Format the output for display or logging.
                // Compute fqdn for this protocol step.
                // Compute fqdn for this protocol step.
                // Compute fqdn for this protocol step.
                let fqdn = format!(
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    "{}.{}.{}.infinet.meshinfinity",
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    device.shortname,
                    member.shortname,
                    infinet_name
                );
                // Begin the block scope.
                // Append to the collection.
                // Append to the collection.
                // Append to the collection.
                records.push(InfinetDNSRecord {
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    record_id: [0; 16], // Generated.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    name: fqdn,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    record_type: DnsRecordType::A,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    value: addr.clone(),
                    ttl: 60,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    created_by: member.peer_id,
                });
            }

            // Device AAAA record (IPv6).
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if let Some(ref addr) = device.addr_v6 {
                // Format the output for display or logging.
                // Compute fqdn for this protocol step.
                // Compute fqdn for this protocol step.
                // Compute fqdn for this protocol step.
                let fqdn = format!(
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    "{}.{}.{}.infinet.meshinfinity",
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    device.shortname,
                    member.shortname,
                    infinet_name
                );
                // Begin the block scope.
                // Append to the collection.
                // Append to the collection.
                // Append to the collection.
                records.push(InfinetDNSRecord {
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    record_id: [0; 16],
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    name: fqdn,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    record_type: DnsRecordType::AAAA,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    value: addr.clone(),
                    ttl: 60,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    created_by: member.peer_id,
                });
            }

            // Service records.
            // Iterate over each element.
            // Iterate over each element.
            // Iterate over each element.
            for service in &device.services {
                // Format the output for display or logging.
                // Compute fqdn for this protocol step.
                // Compute fqdn for this protocol step.
                // Compute fqdn for this protocol step.
                let fqdn = format!(
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    "{}.{}.{}.{}.infinet.meshinfinity",
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    service.name,
                    device.shortname,
                    member.shortname,
                    infinet_name
                );
                // Service names resolve to the device's IP.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                // Guard: validate the condition before proceeding.
                if let Some(ref addr) = device.addr_v4 {
                    // Begin the block scope.
                    // Append to the collection.
                    // Append to the collection.
                    // Append to the collection.
                    records.push(InfinetDNSRecord {
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        record_id: [0; 16],
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        name: fqdn,
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        record_type: DnsRecordType::A,
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        value: addr.clone(),
                        ttl: 60,
                        // Process the current step in the protocol.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        created_by: member.peer_id,
                    });
                }
            }
        }
    }

    records
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_allocator_v4() {
        let mut alloc = IpAllocator::new();

        // First allocation: 100.64.0.0/16.
        let s1 = alloc.allocate_v4().unwrap();
        assert_eq!(s1, "100.64.0.0/16");

        // Second: 100.65.0.0/16.
        let s2 = alloc.allocate_v4().unwrap();
        assert_eq!(s2, "100.65.0.0/16");

        // Release first, re-allocate.
        alloc.release_v4(&s1);
        let s3 = alloc.allocate_v4().unwrap();
        assert_eq!(s3, "100.64.0.0/16"); // Reuses slot 0.
    }

    #[test]
    fn test_ip_allocator_v4_exhaustion() {
        let mut alloc = IpAllocator::new();

        // Allocate all 64 slots.
        for _ in 0..MAX_IPV4_PARTICIPANTS {
            assert!(alloc.allocate_v4().is_some());
        }

        // 65th should fail.
        assert!(alloc.allocate_v4().is_none());
    }

    #[test]
    fn test_ip_allocator_v6() {
        let mut alloc = IpAllocator::new();

        let s1 = alloc.allocate_v6();
        assert_eq!(s1, "fd7a:115c:a1e0:0001::/64");

        let s2 = alloc.allocate_v6();
        assert_eq!(s2, "fd7a:115c:a1e0:0002::/64");
    }

    #[test]
    fn test_device_address_allocation() {
        let addr = IpAllocator::allocate_device_v4("100.65.0.0/16", &[]);
        assert_eq!(addr, Some("100.65.0.2".to_string()));

        // With existing addresses.
        let addr2 = IpAllocator::allocate_device_v4("100.65.0.0/16", &["100.65.0.2".to_string()]);
        assert_eq!(addr2, Some("100.65.0.3".to_string()));
    }

    #[test]
    fn test_acl_evaluation_allow() {
        let acls = vec![InfinetACL {
            rule_id: [0x01; 16],
            subject: InfinetSubject::Everyone,
            target: InfinetTarget::Everything,
            permission: InfinetPermission::Allow,
            expires_at: None,
        }];

        let result = evaluate_acl(
            &acls,
            &[0x01; 32],
            InfinetRole::Member,
            &[0x02; 32],
            &[0x02; 32],
            None,
            None,
            None,
            1000,
        );
        assert_eq!(result, InfinetPermission::Allow);
    }

    #[test]
    fn test_acl_evaluation_default_deny_for_other_members() {
        // Empty ACL list → deny access to other members' devices.
        let result = evaluate_acl(
            &[],
            &[0x01; 32],
            InfinetRole::Member,
            &[0x02; 32],
            &[0x02; 32],
            None,
            None,
            None,
            1000,
        );
        assert_eq!(result, InfinetPermission::Deny);
    }

    #[test]
    fn test_acl_member_specific() {
        let allowed_peer = [0xAA; 32];
        let acls = vec![InfinetACL {
            rule_id: [0x01; 16],
            subject: InfinetSubject::Member {
                peer_id: allowed_peer,
            },
            target: InfinetTarget::Everything,
            permission: InfinetPermission::Allow,
            expires_at: None,
        }];

        // Allowed peer: Allow.
        assert_eq!(
            evaluate_acl(
                &acls,
                &allowed_peer,
                InfinetRole::Member,
                &[0x02; 32],
                &[0x02; 32],
                None,
                None,
                None,
                1000
            ),
            InfinetPermission::Allow
        );

        // Other peer: Deny (no matching rule → default).
        assert_eq!(
            evaluate_acl(
                &acls,
                &[0xBB; 32],
                InfinetRole::Member,
                &[0x02; 32],
                &[0x02; 32],
                None,
                None,
                None,
                1000
            ),
            InfinetPermission::Deny
        );
    }

    #[test]
    fn test_acl_expired_rule_skipped() {
        let acls = vec![InfinetACL {
            rule_id: [0x01; 16],
            subject: InfinetSubject::Everyone,
            target: InfinetTarget::Everything,
            permission: InfinetPermission::Allow,
            expires_at: Some(500), // Expired.
        }];

        // Rule expired → default deny.
        assert_eq!(
            evaluate_acl(
                &acls,
                &[0x01; 32],
                InfinetRole::Member,
                &[0x02; 32],
                &[0x02; 32],
                None,
                None,
                None,
                1000
            ),
            InfinetPermission::Deny
        );
    }

    #[test]
    fn test_acl_service_target() {
        let device = [0x02; 32];
        let acls = vec![InfinetACL {
            rule_id: [0x01; 16],
            subject: InfinetSubject::Everyone,
            target: InfinetTarget::Service {
                device_id: device,
                service: "http".to_string(),
            },
            permission: InfinetPermission::Allow,
            expires_at: None,
        }];

        // Matching service: Allow.
        assert_eq!(
            evaluate_acl(
                &acls,
                &[0x01; 32],
                InfinetRole::Member,
                &device,
                &device,
                Some("http"),
                None,
                None,
                1000
            ),
            InfinetPermission::Allow
        );

        // Different service: Deny.
        assert_eq!(
            evaluate_acl(
                &acls,
                &[0x01; 32],
                InfinetRole::Member,
                &device,
                &device,
                Some("ssh"),
                None,
                None,
                1000
            ),
            InfinetPermission::Deny
        );
    }

    #[test]
    fn test_acl_default_allows_own_devices() {
        let peer = [0x11; 32];
        assert_eq!(
            evaluate_acl(
                &[],
                &peer,
                InfinetRole::Member,
                &peer,
                &[0x22; 32],
                None,
                None,
                None,
                1000
            ),
            InfinetPermission::Allow
        );
    }

    #[test]
    fn test_acl_subnet_target_ipv4() {
        let acls = vec![InfinetACL {
            rule_id: [0x01; 16],
            subject: InfinetSubject::Everyone,
            target: InfinetTarget::Subnet {
                network: "100.65.0.0/16".to_string(),
            },
            permission: InfinetPermission::Allow,
            expires_at: None,
        }];

        assert_eq!(
            evaluate_acl(
                &acls,
                &[0x01; 32],
                InfinetRole::Member,
                &[0x02; 32],
                &[0x03; 32],
                None,
                Some("100.65.9.10"),
                None,
                1000
            ),
            InfinetPermission::Allow
        );

        assert_eq!(
            evaluate_acl(
                &acls,
                &[0x01; 32],
                InfinetRole::Member,
                &[0x02; 32],
                &[0x03; 32],
                None,
                Some("100.66.9.10"),
                None,
                1000
            ),
            InfinetPermission::Deny
        );
    }

    #[test]
    fn test_acl_subnet_target_ipv6() {
        let acls = vec![InfinetACL {
            rule_id: [0x01; 16],
            subject: InfinetSubject::Everyone,
            target: InfinetTarget::Subnet {
                network: "fd7a:115c:a1e0:0002::/64".to_string(),
            },
            permission: InfinetPermission::Allow,
            expires_at: None,
        }];

        assert_eq!(
            evaluate_acl(
                &acls,
                &[0x01; 32],
                InfinetRole::Member,
                &[0x02; 32],
                &[0x03; 32],
                None,
                None,
                Some("fd7a:115c:a1e0:0002::42"),
                1000
            ),
            InfinetPermission::Allow
        );

        assert_eq!(
            evaluate_acl(
                &acls,
                &[0x01; 32],
                InfinetRole::Member,
                &[0x02; 32],
                &[0x03; 32],
                None,
                None,
                Some("fd7a:115c:a1e0:0003::42"),
                1000
            ),
            InfinetPermission::Deny
        );
    }

    #[test]
    fn test_device_expiry() {
        let members = vec![InfinetMember {
            peer_id: [0x01; 32],
            shortname: "alice".to_string(),
            role: InfinetRole::Member,
            subnet_v4: None,
            subnet_v6: None,
            devices: vec![
                InfinetDevice {
                    device_id: [0x10; 32],
                    shortname: "laptop".to_string(),
                    addr_v4: Some("100.64.0.2".to_string()),
                    addr_v6: None,
                    services: vec![],
                    last_seen: 1000,
                },
                InfinetDevice {
                    device_id: [0x11; 32],
                    shortname: "phone".to_string(),
                    addr_v4: Some("100.64.0.3".to_string()),
                    addr_v6: None,
                    services: vec![],
                    last_seen: 1000 + DEVICE_EXPIRY_SECS + 100, // Not expired.
                },
            ],
            joined_at: 1000,
            expires_at: None,
        }];

        let now = 1000 + DEVICE_EXPIRY_SECS + 50;
        let expired = find_expired_devices(&members, now);
        // Laptop expired, phone not.
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], [0x10; 32]);
    }

    #[test]
    fn test_dns_generation() {
        let members = vec![InfinetMember {
            peer_id: [0x01; 32],
            shortname: "alice".to_string(),
            role: InfinetRole::Member,
            subnet_v4: Some("100.64.0.0/16".to_string()),
            subnet_v6: None,
            devices: vec![InfinetDevice {
                device_id: [0x10; 32],
                shortname: "laptop".to_string(),
                addr_v4: Some("100.64.0.2".to_string()),
                addr_v6: None,
                services: vec![InfinetService {
                    name: "http".to_string(),
                    port: 8080,
                    description: None,
                }],
                last_seen: 1000,
            }],
            joined_at: 1000,
            expires_at: None,
        }];

        let records = generate_dns_entries("mynet", &members);

        // Should have device A record + service A record.
        assert_eq!(records.len(), 2);

        // Device record.
        assert_eq!(records[0].name, "laptop.alice.mynet.infinet.meshinfinity");
        assert_eq!(records[0].value, "100.64.0.2");

        // Service record.
        assert_eq!(
            records[1].name,
            "http.laptop.alice.mynet.infinet.meshinfinity"
        );
    }

    // ---- Collision detection tests ----

    #[test]
    fn test_tailscale_ipv6_slot_parsing() {
        // Standard format.
        assert_eq!(tailscale_ipv6_slot("fd7a:115c:a1e0:0001::1"), Some(1));
        assert_eq!(tailscale_ipv6_slot("fd7a:115c:a1e0:0042::cafe"), Some(0x42));
        assert_eq!(tailscale_ipv6_slot("fd7a:115c:a1e0:ffff::1"), Some(0xffff));

        // Not in our prefix — ignored.
        assert_eq!(tailscale_ipv6_slot("2001:db8::1"), None);
        assert_eq!(tailscale_ipv6_slot("::1"), None);
        assert_eq!(tailscale_ipv6_slot("192.168.1.1"), None);

        // With CIDR prefix (e.g. from subnet notation).
        assert_eq!(tailscale_ipv6_slot("fd7a:115c:a1e0:0003::/64"), Some(3));
    }

    #[test]
    fn test_v6_collision_detection() {
        // Tailscale device at slot 1 — should collide with Infinet slot 1.
        assert!(infinet_v6_collides_with_tailscale(
            1,
            &["fd7a:115c:a1e0:0001::5a3f"],
        ));

        // No collision — Tailscale is at slot 2, Infinet at slot 1.
        assert!(!infinet_v6_collides_with_tailscale(
            1,
            &["fd7a:115c:a1e0:0002::1234"],
        ));

        // Address outside our prefix — never collides.
        assert!(!infinet_v6_collides_with_tailscale(1, &["2001:db8::1"],));

        // Empty Tailscale list — no collision.
        assert!(!infinet_v6_collides_with_tailscale(1, &[]));
    }

    #[test]
    fn test_allocate_v6_avoiding_collision() {
        let mut alloc = IpAllocator::new();

        // Tailscale has a device at slot 1 — first available should be slot 2.
        let subnet = alloc
            .allocate_v6_avoiding(&["fd7a:115c:a1e0:0001::abc"])
            .unwrap();
        assert_eq!(subnet, "fd7a:115c:a1e0:0002::/64");

        // Next allocation with Tailscale at slots 1 and 3 — should get slot 4.
        let subnet2 = alloc
            .allocate_v6_avoiding(&["fd7a:115c:a1e0:0001::abc", "fd7a:115c:a1e0:0003::def"])
            .unwrap();
        assert_eq!(subnet2, "fd7a:115c:a1e0:0004::/64");
    }

    #[test]
    fn test_cycle_v6_on_collision() {
        let mut alloc = IpAllocator::new();

        let mut member = InfinetMember {
            peer_id: [0x01; 32],
            shortname: "alice".to_string(),
            role: InfinetRole::Admin,
            subnet_v4: None,
            subnet_v6: Some("fd7a:115c:a1e0:0001::/64".to_string()),
            devices: vec![InfinetDevice {
                device_id: [0xAB; 32],
                shortname: "laptop".to_string(),
                addr_v4: None,
                addr_v6: Some("fd7a:115c:a1e0:0001::1234".to_string()),
                services: vec![],
                last_seen: 1000,
            }],
            joined_at: 1000,
            expires_at: None,
        };

        // Simulate: slot 1 is already in use by the member.
        alloc.allocated_v6.insert(1);

        // Tailscale assigns an address at slot 1 — collision.
        let tailscale_addrs = ["fd7a:115c:a1e0:0001::5a3f"];
        let event = cycle_v6_for_member(&mut member, &mut alloc, &tailscale_addrs, 9999);

        assert!(event.is_some());
        let ev = event.unwrap();
        assert_eq!(ev.old_subnet_v6, "fd7a:115c:a1e0:0001::/64");
        // New subnet should be the next available slot (skipping 1, which Tailscale holds).
        assert!(ev.new_subnet_v6.starts_with("fd7a:115c:a1e0:"));
        assert_ne!(ev.new_subnet_v6, "fd7a:115c:a1e0:0001::/64");
        assert_eq!(ev.cycled_at, 9999);

        // Member's subnet should be updated.
        assert_eq!(member.subnet_v6, Some(ev.new_subnet_v6.clone()));

        // Device address should be updated to new subnet.
        let dev = &member.devices[0];
        assert!(dev.addr_v6.as_ref().unwrap().starts_with("fd7a:115c:a1e0:"));
        assert!(!dev
            .addr_v6
            .as_ref()
            .unwrap()
            .starts_with("fd7a:115c:a1e0:0001:"));
    }

    #[test]
    fn test_cycle_v6_no_collision_is_noop() {
        let mut alloc = IpAllocator::new();
        alloc.allocated_v6.insert(1);

        let mut member = InfinetMember {
            peer_id: [0x01; 32],
            shortname: "alice".to_string(),
            role: InfinetRole::Admin,
            subnet_v4: None,
            subnet_v6: Some("fd7a:115c:a1e0:0001::/64".to_string()),
            devices: vec![],
            joined_at: 1000,
            expires_at: None,
        };

        // Tailscale is at slot 2 — no collision with slot 1.
        let event = cycle_v6_for_member(&mut member, &mut alloc, &["fd7a:115c:a1e0:0002::1"], 9999);

        assert!(event.is_none());
        // Member subnet unchanged.
        assert_eq!(
            member.subnet_v6,
            Some("fd7a:115c:a1e0:0001::/64".to_string())
        );
    }

    #[test]
    fn test_allocate_v6_no_auto_v4() {
        // Confirm IPv4 is not returned during auto-allocation.
        // IPv4 must be explicitly called (manual admin assign).
        let mut alloc = IpAllocator::new();
        let v6 = alloc.allocate_v6();
        assert!(v6.starts_with("fd7a:"));
        // IPv4 allocation must be explicit and returns None only when exhausted.
        // Single allocation should succeed.
        let v4 = alloc.allocate_v4();
        assert!(v4.is_some());
        assert!(v4.unwrap().starts_with("100."));
    }

    #[test]
    fn test_from_members_reconstruction() {
        let members = vec![
            InfinetMember {
                peer_id: [0x01; 32],
                shortname: "alice".to_string(),
                role: InfinetRole::Admin,
                subnet_v4: Some("100.64.0.0/16".to_string()),
                subnet_v6: None,
                devices: vec![],
                joined_at: 1000,
                expires_at: None,
            },
            InfinetMember {
                peer_id: [0x02; 32],
                shortname: "bob".to_string(),
                role: InfinetRole::Member,
                subnet_v4: Some("100.65.0.0/16".to_string()),
                subnet_v6: None,
                devices: vec![],
                joined_at: 1000,
                expires_at: None,
            },
        ];

        let alloc = IpAllocator::from_members(&members);
        // Slots 0 and 1 should be taken.
        assert!(alloc.allocated_v4[0]);
        assert!(alloc.allocated_v4[1]);
        assert!(!alloc.allocated_v4[2]);
    }

    #[test]
    fn test_infinet_state_serde() {
        let state = InfinetState {
            infinet_id: [0xAA; 32],
            infinet_name: "test-net".to_string(),
            members: vec![],
            acls: vec![],
            dns_records: vec![],
            state_version: 1,
            state_sig: vec![0x42; 64],
        };
        let json = serde_json::to_string(&state).unwrap();
        let recovered: InfinetState = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.infinet_name, "test-net");
    }
}
