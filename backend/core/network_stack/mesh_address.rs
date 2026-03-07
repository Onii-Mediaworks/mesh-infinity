// Mesh Address - 256-bit addressing scheme for Mesh Infinity PMWAN
// Format: 8 groups of 8 hexadecimal digits (32 bytes total)
// Example: a1b2c3d4:e5f6a7b8:12345678:90abcdef:01234567:89abcdef:fedcba98:76543210
//
// Address Structure:
// - First 5 groups (20 bytes): Device address portion (ephemeral, one device can have many)
// - Last 3 groups (12 bytes): Conversation identifier within a connection
//
// Address Types:
// - Primary Address: Shared publicly, used for initial contact with untrusted peers
// - Trusted Channel Address: Private address negotiated per trusted peer (never shared publicly)
//
// Conversation Identification:
// A conversation is uniquely identified by the tuple:
// (source_address, destination_address, conversation_id)

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use crate::core::error::{MeshInfinityError, Result};
use crate::core::PeerId;

/// Size constants for address structure
pub const DEVICE_PORTION_SIZE: usize = 20; // 5 groups, 160 bits
pub const CONVERSATION_PORTION_SIZE: usize = 12; // 3 groups, 96 bits
pub const TOTAL_ADDRESS_SIZE: usize = 32; // 8 groups, 256 bits

/// 256-bit mesh network address
/// Structure: [device_address: 20 bytes][conversation_id: 12 bytes]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MeshAddress([u8; TOTAL_ADDRESS_SIZE]);

/// Device portion of an address (first 20 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceAddress([u8; DEVICE_PORTION_SIZE]);

/// Conversation identifier (last 12 bytes of address)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConversationId([u8; CONVERSATION_PORTION_SIZE]);

/// Types of device addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressType {
    /// Primary address - shared publicly for initial contact
    Primary,
    /// Trusted channel - private address for a specific trusted peer
    TrustedChannel,
    /// Ephemeral - temporary address for a single session
    Ephemeral,
}

/// Full conversation identifier tuple
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConversationTuple {
    pub source: MeshAddress,
    pub destination: MeshAddress,
    pub conversation_id: ConversationId,
}

impl MeshAddress {
    /// Create a new MeshAddress from raw bytes
    pub fn new(bytes: [u8; TOTAL_ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }

    /// Create from device address and conversation ID
    pub fn from_parts(device: DeviceAddress, conversation: ConversationId) -> Self {
        let mut bytes = [0u8; TOTAL_ADDRESS_SIZE];
        bytes[..DEVICE_PORTION_SIZE].copy_from_slice(&device.0);
        bytes[DEVICE_PORTION_SIZE..].copy_from_slice(&conversation.0);
        Self(bytes)
    }

    /// Create a zero address (used for unspecified/any)
    pub fn zero() -> Self {
        Self([0u8; TOTAL_ADDRESS_SIZE])
    }

    /// Create a broadcast address (all 1s)
    pub fn broadcast() -> Self {
        Self([0xff; TOTAL_ADDRESS_SIZE])
    }

    /// Create a loopback address (::1 equivalent)
    pub fn loopback() -> Self {
        let mut bytes = [0u8; TOTAL_ADDRESS_SIZE];
        bytes[TOTAL_ADDRESS_SIZE - 1] = 1;
        Self(bytes)
    }

    /// Extract the device address portion
    pub fn device_address(&self) -> DeviceAddress {
        let mut bytes = [0u8; DEVICE_PORTION_SIZE];
        bytes.copy_from_slice(&self.0[..DEVICE_PORTION_SIZE]);
        DeviceAddress(bytes)
    }

    /// Extract the conversation ID portion
    pub fn conversation_id(&self) -> ConversationId {
        let mut bytes = [0u8; CONVERSATION_PORTION_SIZE];
        bytes.copy_from_slice(&self.0[DEVICE_PORTION_SIZE..]);
        ConversationId(bytes)
    }

    /// Create a new address with a different conversation ID
    pub fn with_conversation(&self, conversation: ConversationId) -> Self {
        Self::from_parts(self.device_address(), conversation)
    }

    /// Get the raw bytes of the address
    pub fn as_bytes(&self) -> &[u8; TOTAL_ADDRESS_SIZE] {
        &self.0
    }

    /// Check if this is the zero address
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Check if this is the broadcast address
    pub fn is_broadcast(&self) -> bool {
        self.0.iter().all(|&b| b == 0xff)
    }

    /// Check if this is the loopback address
    pub fn is_loopback(&self) -> bool {
        self.0[..TOTAL_ADDRESS_SIZE - 1].iter().all(|&b| b == 0)
            && self.0[TOTAL_ADDRESS_SIZE - 1] == 1
    }

    /// Check if two addresses share the same device portion
    pub fn same_device(&self, other: &MeshAddress) -> bool {
        self.device_address() == other.device_address()
    }

    /// Get a specific group (0-7) as a u32
    pub fn group(&self, index: usize) -> Option<u32> {
        if index >= 8 {
            return None;
        }
        let start = index * 4;
        Some(u32::from_be_bytes([
            self.0[start],
            self.0[start + 1],
            self.0[start + 2],
            self.0[start + 3],
        ]))
    }

    /// Create from 8 group values
    pub fn from_groups(groups: [u32; 8]) -> Self {
        let mut bytes = [0u8; TOTAL_ADDRESS_SIZE];
        for (i, group) in groups.iter().enumerate() {
            let group_bytes = group.to_be_bytes();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&group_bytes);
        }
        Self(bytes)
    }
}

impl DeviceAddress {
    /// Create a new device address from raw bytes
    pub fn new(bytes: [u8; DEVICE_PORTION_SIZE]) -> Self {
        Self(bytes)
    }

    /// Generate a random ephemeral device address
    pub fn random() -> Self {
        let mut bytes = [0u8; DEVICE_PORTION_SIZE];
        // Use system time + thread ID as entropy source
        use std::time::{SystemTime, UNIX_EPOCH};
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let mut hasher = Sha256::new();
        hasher.update(b"device-addr-ephemeral");
        hasher.update(time.to_le_bytes());
        hasher.update(format!("{:?}", std::thread::current().id()).as_bytes());

        // Add extra randomness from pointer addresses
        let stack_var = 0u8;
        hasher.update((&stack_var as *const u8 as usize).to_le_bytes());

        let result = hasher.finalize();
        bytes.copy_from_slice(&result[..DEVICE_PORTION_SIZE]);
        Self(bytes)
    }

    /// Generate a primary device address from a public key
    /// This is deterministic - same key always produces same primary address
    pub fn primary_from_key(public_key: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"meshinfinity-primary-addr-v1");
        hasher.update(public_key);
        let result = hasher.finalize();
        let mut bytes = [0u8; DEVICE_PORTION_SIZE];
        bytes.copy_from_slice(&result[..DEVICE_PORTION_SIZE]);
        Self(bytes)
    }

    /// Generate a trusted channel address for a specific peer relationship
    /// Deterministic based on both peers' keys (order-independent)
    pub fn trusted_channel(our_key: &[u8; 32], their_key: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"meshinfinity-trusted-channel-v1");

        // Order keys deterministically (smaller first)
        if our_key < their_key {
            hasher.update(our_key);
            hasher.update(their_key);
        } else {
            hasher.update(their_key);
            hasher.update(our_key);
        }

        let result = hasher.finalize();
        let mut bytes = [0u8; DEVICE_PORTION_SIZE];
        bytes.copy_from_slice(&result[..DEVICE_PORTION_SIZE]);
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; DEVICE_PORTION_SIZE] {
        &self.0
    }

    /// Create a full address with a new conversation ID
    pub fn with_conversation(&self, conversation: ConversationId) -> MeshAddress {
        MeshAddress::from_parts(*self, conversation)
    }

    /// Create a full address with a zero conversation ID
    pub fn with_zero_conversation(&self) -> MeshAddress {
        MeshAddress::from_parts(*self, ConversationId::zero())
    }
}

impl ConversationId {
    /// Create a new conversation ID from raw bytes
    pub fn new(bytes: [u8; CONVERSATION_PORTION_SIZE]) -> Self {
        Self(bytes)
    }

    /// Create a zero conversation ID
    pub fn zero() -> Self {
        Self([0u8; CONVERSATION_PORTION_SIZE])
    }

    /// Generate a random conversation ID
    pub fn random() -> Self {
        let mut bytes = [0u8; CONVERSATION_PORTION_SIZE];
        use std::time::{SystemTime, UNIX_EPOCH};

        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let mut hasher = Sha256::new();
        hasher.update(b"conversation-id");
        hasher.update(time.to_le_bytes());
        hasher.update(format!("{:?}", std::thread::current().id()).as_bytes());

        let result = hasher.finalize();
        bytes.copy_from_slice(&result[..CONVERSATION_PORTION_SIZE]);
        Self(bytes)
    }

    /// Generate a conversation ID from a session identifier
    pub fn from_session(session_id: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"conversation-from-session");
        hasher.update(session_id);
        let result = hasher.finalize();
        let mut bytes = [0u8; CONVERSATION_PORTION_SIZE];
        bytes.copy_from_slice(&result[..CONVERSATION_PORTION_SIZE]);
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; CONVERSATION_PORTION_SIZE] {
        &self.0
    }

    /// Check if this is a zero conversation ID
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl ConversationTuple {
    /// Create a new conversation tuple
    pub fn new(source: MeshAddress, destination: MeshAddress) -> Self {
        Self {
            conversation_id: source.conversation_id(),
            source,
            destination,
        }
    }

    /// Get the reverse tuple (for response routing)
    pub fn reverse(&self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            conversation_id: self.conversation_id,
        }
    }

    /// Check if two tuples represent the same conversation (bidirectional)
    pub fn same_conversation(&self, other: &ConversationTuple) -> bool {
        self.conversation_id == other.conversation_id
            && ((self.source == other.source && self.destination == other.destination)
                || (self.source == other.destination && self.destination == other.source))
    }
}

// Display implementations

impl fmt::Display for MeshAddress {
    /// Render full mesh address as eight 32-bit hex groups.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let groups: Vec<String> = (0..8)
            .map(|i| {
                let start = i * 4;
                format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    self.0[start],
                    self.0[start + 1],
                    self.0[start + 2],
                    self.0[start + 3]
                )
            })
            .collect();
        write!(f, "{}", groups.join(":"))
    }
}

impl fmt::Debug for MeshAddress {
    /// Render debug form with explicit type wrapper.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MeshAddress({})", self)
    }
}

impl fmt::Display for DeviceAddress {
    /// Render device portion as five 32-bit hex groups.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let groups: Vec<String> = (0..5)
            .map(|i| {
                let start = i * 4;
                format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    self.0[start],
                    self.0[start + 1],
                    self.0[start + 2],
                    self.0[start + 3]
                )
            })
            .collect();
        write!(f, "{}", groups.join(":"))
    }
}

impl fmt::Debug for DeviceAddress {
    /// Render debug form with explicit type wrapper.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceAddress({})", self)
    }
}

impl fmt::Display for ConversationId {
    /// Render conversation id as three 32-bit hex groups.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let groups: Vec<String> = (0..3)
            .map(|i| {
                let start = i * 4;
                format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    self.0[start],
                    self.0[start + 1],
                    self.0[start + 2],
                    self.0[start + 3]
                )
            })
            .collect();
        write!(f, "{}", groups.join(":"))
    }
}

impl fmt::Debug for ConversationId {
    /// Render debug form with explicit type wrapper.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConversationId({})", self)
    }
}

// FromStr implementations

impl FromStr for MeshAddress {
    type Err = MeshInfinityError;

    /// Parse canonical mesh-address string into binary form.
    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() != 8 {
            return Err(MeshInfinityError::NetworkError(format!(
                "Invalid mesh address: expected 8 groups, got {}",
                parts.len()
            )));
        }

        let mut bytes = [0u8; TOTAL_ADDRESS_SIZE];

        for (i, part) in parts.iter().enumerate() {
            if part.len() != 8 {
                return Err(MeshInfinityError::NetworkError(format!(
                    "Invalid group {}: expected 8 hex chars, got {}",
                    i,
                    part.len()
                )));
            }

            let group_value = u32::from_str_radix(part, 16).map_err(|_| {
                MeshInfinityError::NetworkError(format!("Invalid hex in group {}: {}", i, part))
            })?;

            let group_bytes = group_value.to_be_bytes();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&group_bytes);
        }

        Ok(Self(bytes))
    }
}

impl FromStr for DeviceAddress {
    type Err = MeshInfinityError;

    /// Parse canonical device-address string into binary form.
    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() != 5 {
            return Err(MeshInfinityError::NetworkError(format!(
                "Invalid device address: expected 5 groups, got {}",
                parts.len()
            )));
        }

        let mut bytes = [0u8; DEVICE_PORTION_SIZE];

        for (i, part) in parts.iter().enumerate() {
            if part.len() != 8 {
                return Err(MeshInfinityError::NetworkError(format!(
                    "Invalid group {}: expected 8 hex chars",
                    i
                )));
            }

            let group_value = u32::from_str_radix(part, 16).map_err(|_| {
                MeshInfinityError::NetworkError(format!("Invalid hex in group {}", i))
            })?;

            let group_bytes = group_value.to_be_bytes();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&group_bytes);
        }

        Ok(Self(bytes))
    }
}

impl FromStr for ConversationId {
    type Err = MeshInfinityError;

    /// Parse canonical conversation-id string into binary form.
    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() != 3 {
            return Err(MeshInfinityError::NetworkError(format!(
                "Invalid conversation ID: expected 3 groups, got {}",
                parts.len()
            )));
        }

        let mut bytes = [0u8; CONVERSATION_PORTION_SIZE];

        for (i, part) in parts.iter().enumerate() {
            if part.len() != 8 {
                return Err(MeshInfinityError::NetworkError(format!(
                    "Invalid group {}: expected 8 hex chars",
                    i
                )));
            }

            let group_value = u32::from_str_radix(part, 16).map_err(|_| {
                MeshInfinityError::NetworkError(format!("Invalid hex in group {}", i))
            })?;

            let group_bytes = group_value.to_be_bytes();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&group_bytes);
        }

        Ok(Self(bytes))
    }
}

// Hash implementation

impl Hash for MeshAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// Serde implementations

impl Serialize for MeshAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MeshAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        MeshAddress::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for DeviceAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DeviceAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DeviceAddress::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ConversationId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ConversationId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ConversationId::from_str(&s).map_err(serde::de::Error::custom)
    }
}

// From implementations

impl From<[u8; TOTAL_ADDRESS_SIZE]> for MeshAddress {
    /// Wrap raw 32-byte array as a mesh address.
    fn from(bytes: [u8; TOTAL_ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<MeshAddress> for [u8; TOTAL_ADDRESS_SIZE] {
    /// Convert mesh address back into raw bytes.
    fn from(addr: MeshAddress) -> Self {
        addr.0
    }
}

impl From<&PeerId> for DeviceAddress {
    /// Derive deterministic primary device address from peer id/public key.
    fn from(peer_id: &PeerId) -> Self {
        Self::primary_from_key(peer_id)
    }
}

/// Device address registry - tracks all addresses for a device
#[derive(Debug, Clone)]
pub struct DeviceAddressRegistry {
    /// Our public key
    our_key: [u8; 32],
    /// Primary address (shared publicly)
    primary: DeviceAddress,
    /// Trusted channel addresses per peer
    trusted_channels: std::collections::HashMap<PeerId, DeviceAddress>,
    /// Active ephemeral addresses
    ephemeral: Vec<DeviceAddress>,
}

impl DeviceAddressRegistry {
    /// Create a new registry for a device
    pub fn new(public_key: [u8; 32]) -> Self {
        let primary = DeviceAddress::primary_from_key(&public_key);
        Self {
            our_key: public_key,
            primary,
            trusted_channels: std::collections::HashMap::new(),
            ephemeral: Vec::new(),
        }
    }

    /// Get our primary device address
    pub fn primary(&self) -> DeviceAddress {
        self.primary
    }

    /// Get or create a trusted channel address for a peer
    pub fn trusted_channel_for(&mut self, peer_key: &[u8; 32]) -> DeviceAddress {
        let peer_id: PeerId = *peer_key;

        if let Some(&addr) = self.trusted_channels.get(&peer_id) {
            return addr;
        }

        let addr = DeviceAddress::trusted_channel(&self.our_key, peer_key);
        self.trusted_channels.insert(peer_id, addr);
        addr
    }

    /// Create a new ephemeral address
    pub fn new_ephemeral(&mut self) -> DeviceAddress {
        let addr = DeviceAddress::random();
        self.ephemeral.push(addr);
        addr
    }

    /// Check if an address belongs to us
    pub fn is_ours(&self, addr: &DeviceAddress) -> bool {
        if *addr == self.primary {
            return true;
        }
        if self.trusted_channels.values().any(|a| a == addr) {
            return true;
        }
        self.ephemeral.contains(addr)
    }

    /// Get the address type for one of our addresses
    pub fn address_type(&self, addr: &DeviceAddress) -> Option<AddressType> {
        if *addr == self.primary {
            return Some(AddressType::Primary);
        }
        if self.trusted_channels.values().any(|a| a == addr) {
            return Some(AddressType::TrustedChannel);
        }
        if self.ephemeral.contains(addr) {
            return Some(AddressType::Ephemeral);
        }
        None
    }

    /// Remove an ephemeral address
    pub fn remove_ephemeral(&mut self, addr: &DeviceAddress) {
        self.ephemeral.retain(|a| a != addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Display formatting should be stable and fully zero-padded.
    #[test]
    fn test_address_display() {
        let addr = MeshAddress::zero();
        assert_eq!(
            addr.to_string(),
            "00000000:00000000:00000000:00000000:00000000:00000000:00000000:00000000"
        );

        let addr = MeshAddress::from_groups([
            0x12345678, 0x9abcdef0, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555,
            0x66666666,
        ]);
        assert_eq!(
            addr.to_string(),
            "12345678:9abcdef0:11111111:22222222:33333333:44444444:55555555:66666666"
        );
    }

    /// Parser should round-trip canonical mesh-address strings.
    #[test]
    fn test_address_parse() {
        let addr_str = "12345678:9abcdef0:11111111:22222222:33333333:44444444:55555555:66666666";
        let addr: MeshAddress = addr_str.parse().unwrap();
        assert_eq!(addr.to_string(), addr_str);
    }

    /// Splitting and recombining device/conversation portions should be lossless.
    #[test]
    fn test_device_conversation_split() {
        let addr = MeshAddress::from_groups([
            0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0xaaaaaaaa, 0xbbbbbbbb,
            0xcccccccc,
        ]);

        let device = addr.device_address();
        let conv = addr.conversation_id();

        // Reconstruct and verify
        let reconstructed = MeshAddress::from_parts(device, conv);
        assert_eq!(addr, reconstructed);
    }

    /// Primary device address derivation should be deterministic for same key.
    #[test]
    fn test_primary_address_deterministic() {
        let key = [0x42u8; 32];
        let addr1 = DeviceAddress::primary_from_key(&key);
        let addr2 = DeviceAddress::primary_from_key(&key);
        assert_eq!(addr1, addr2);
    }

    /// Trusted-channel derivation should be symmetric across peer ordering.
    #[test]
    fn test_trusted_channel_symmetric() {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];

        let channel_ab = DeviceAddress::trusted_channel(&key_a, &key_b);
        let channel_ba = DeviceAddress::trusted_channel(&key_b, &key_a);

        // Same channel regardless of order
        assert_eq!(channel_ab, channel_ba);
    }

    /// Forward/reverse tuples should map to the same conversation identity.
    #[test]
    fn test_conversation_tuple() {
        let src = MeshAddress::from_groups([1, 2, 3, 4, 5, 0xa, 0xb, 0xc]);
        let dst = MeshAddress::from_groups([6, 7, 8, 9, 10, 0xd, 0xe, 0xf]);

        let tuple = ConversationTuple::new(src, dst);
        let reverse = tuple.reverse();

        assert!(tuple.same_conversation(&reverse));
    }

    /// Registry should classify and track owned address variants correctly.
    #[test]
    fn test_device_registry() {
        let key = [0x55u8; 32];
        let mut registry = DeviceAddressRegistry::new(key);

        assert!(registry.is_ours(&registry.primary()));

        let peer_key = [0x66u8; 32];
        let channel = registry.trusted_channel_for(&peer_key);
        assert!(registry.is_ours(&channel));

        let ephemeral = registry.new_ephemeral();
        assert!(registry.is_ours(&ephemeral));

        registry.remove_ephemeral(&ephemeral);
        assert!(!registry.is_ours(&ephemeral));
    }

    /// Same-device check should ignore conversation component differences.
    #[test]
    fn test_same_device_check() {
        let device = DeviceAddress::random();
        let conv1 = ConversationId::random();
        let conv2 = ConversationId::random();

        let addr1 = device.with_conversation(conv1);
        let addr2 = device.with_conversation(conv2);

        assert!(addr1.same_device(&addr2));

        let other_device = DeviceAddress::random();
        let addr3 = other_device.with_conversation(conv1);

        assert!(!addr1.same_device(&addr3));
    }
}
