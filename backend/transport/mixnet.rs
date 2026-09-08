//! Native fixed-size mixnet packets and relay batching (§5.25).
//!
//! Packet construction and per-hop transformation are delegated to Nym's
//! maintained `sphinx-packet` implementation. Mesh adds fixed framing,
//! routing-key epochs, epoch-lifetime replay retention, batching, and cover
//! policy. No stable packet identifier or cover marker is visible on the wire.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use sphinx_packet::constants::{
    DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH,
};
use sphinx_packet::header::delays::Delay;
use sphinx_packet::packet::ProcessedPacketData;
use sphinx_packet::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes};
use sphinx_packet::SphinxPacket;
use sphinx_packet::SphinxPacketBuilder;
use x25519_dalek_v3::{PublicKey as SphinxPublicKey, StaticSecret as SphinxSecret};

/// All observable native-mixnet packets use the Ethernet MTU.
pub const MIXNET_MTU: usize = 1500;
/// The selected Sphinx construction supports paths of at most five nodes.
pub const MAX_HOPS: usize = 5;
/// Mesh framing stores a version and routing-key epoch outside Sphinx.
pub const SPHINX_OVERHEAD: usize = 1 + 8;
/// The opaque Sphinx packet fills all remaining bytes.
pub const SPHINX_PACKET_SIZE: usize = MIXNET_MTU - SPHINX_OVERHEAD;
/// Nym Sphinx uses a fixed 408-byte header for its five-hop maximum.
pub const SPHINX_HEADER_SIZE: usize = 348;
/// Payload size is selected so the complete Mesh frame is exactly one MTU.
pub const MIXNET_PAYLOAD_SIZE: usize = SPHINX_PACKET_SIZE - SPHINX_HEADER_SIZE;
/// Relays shuffle all packets accumulated during this interval.
pub const BATCH_WINDOW_MS: u64 = 500;

const MIXNET_VERSION: u8 = 2;
const SPHINX_PAYLOAD_OVERHEAD: usize = 17;
const PAYLOAD_KIND_SIZE: usize = 1;
const MAX_PLAINTEXT_SIZE: usize = MIXNET_PAYLOAD_SIZE - SPHINX_PAYLOAD_OVERHEAD - PAYLOAD_KIND_SIZE;
const PAYLOAD_DATA: u8 = 0;
const PAYLOAD_COVER: u8 = 1;
const MAX_REPLAY_TAGS_PER_EPOCH: usize = 1_000_000;

/// A fixed Mesh frame containing one opaque, fully authenticated Sphinx packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixnetPacket {
    pub version: u8,
    pub key_epoch: u64,
    pub sphinx_packet: [u8; SPHINX_PACKET_SIZE],
}

impl MixnetPacket {
    pub fn to_bytes(&self) -> [u8; MIXNET_MTU] {
        let mut wire = [0u8; MIXNET_MTU];
        wire[0] = self.version;
        wire[1..9].copy_from_slice(&self.key_epoch.to_be_bytes());
        wire[9..].copy_from_slice(&self.sphinx_packet);
        wire
    }

    /// Fixed framing is lossless. Cryptographic validation happens in
    /// `MixnetNode::receive` before replay state or queues are modified.
    pub fn from_bytes(wire: &[u8; MIXNET_MTU]) -> Self {
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&wire[1..9]);
        let mut sphinx_packet = [0u8; SPHINX_PACKET_SIZE];
        sphinx_packet.copy_from_slice(&wire[9..]);
        Self {
            version: wire[0],
            key_epoch: u64::from_be_bytes(epoch),
            sphinx_packet,
        }
    }
}

/// A valid path used to create cover through the normal Sphinx constructor.
#[derive(Clone)]
pub struct CoverRoute {
    pub key_epoch: u64,
    pub path_pubkeys: Vec<[u8; 32]>,
    pub path_addresses: Vec<[u8; NODE_ADDRESS_LENGTH]>,
}

/// Mixnet participation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixRole {
    Client,
    MixNode,
    Gateway { katzenpost_mode: bool },
}

#[derive(Clone)]
struct RoutingKey {
    epoch: u64,
    private_key: [u8; 32],
}

/// Replay entries live exactly as long as their associated routing key.
struct ReplayCache {
    by_epoch: HashMap<u64, HashSet<[u8; 32]>>,
}

impl ReplayCache {
    fn new(epoch: u64) -> Self {
        Self {
            by_epoch: HashMap::from([(epoch, HashSet::new())]),
        }
    }

    fn add_epoch(&mut self, epoch: u64) {
        self.by_epoch.entry(epoch).or_default();
    }

    fn retire_epoch(&mut self, epoch: u64) {
        self.by_epoch.remove(&epoch);
    }

    fn check_and_insert(&mut self, epoch: u64, tag: [u8; 32]) -> Result<(), MixnetError> {
        let entries = self
            .by_epoch
            .get_mut(&epoch)
            .ok_or(MixnetError::UnknownKeyEpoch(epoch))?;
        if entries.contains(&tag) {
            return Err(MixnetError::Replay);
        }
        // Cache exhaustion fails closed. A routing-key rotation is required
        // before the relay can accept more packets for this epoch.
        if entries.len() >= MAX_REPLAY_TAGS_PER_EPOCH {
            return Err(MixnetError::ReplayCacheFull(epoch));
        }
        entries.insert(tag);
        Ok(())
    }

    #[cfg(test)]
    fn len_for_epoch(&self, epoch: u64) -> usize {
        self.by_epoch.get(&epoch).map_or(0, HashSet::len)
    }
}

struct MixBatch {
    packets: VecDeque<(MixnetPacket, [u8; NODE_ADDRESS_LENGTH])>,
    created_at: Instant,
}

impl MixBatch {
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
            created_at: Instant::now(),
        }
    }

    fn ready(&self) -> bool {
        self.created_at.elapsed() >= Duration::from_millis(BATCH_WINDOW_MS)
    }

    fn flush(&mut self, rng: &mut ChaCha20Rng) -> Vec<(MixnetPacket, [u8; NODE_ADDRESS_LENGTH])> {
        let mut packets: Vec<_> = self.packets.drain(..).collect();
        for index in (1..packets.len()).rev() {
            let swap_with = (rng.next_u64() as usize) % (index + 1);
            packets.swap(index, swap_with);
        }
        packets
    }
}

/// Stateful receive, replay, batching, and cover engine for one participant.
pub struct MixnetNode {
    pub role: MixRole,
    current_key: RoutingKey,
    previous_key: Option<RoutingKey>,
    replay: ReplayCache,
    batch: MixBatch,
    cover_route: Option<CoverRoute>,
    pub outbound: Vec<([u8; NODE_ADDRESS_LENGTH], [u8; MIXNET_MTU])>,
    pub inbound: Vec<Vec<u8>>,
    rng: ChaCha20Rng,
    relayed_in_window: u32,
}

impl MixnetNode {
    /// Epoch zero preserves the former constructor while directory publication
    /// migrates callers to explicit routing-key epochs.
    pub fn new(role: MixRole, private_key: [u8; 32]) -> Self {
        Self::new_with_epoch(role, 0, private_key)
    }

    pub fn new_with_epoch(role: MixRole, epoch: u64, private_key: [u8; 32]) -> Self {
        Self::new_with_rng(role, epoch, private_key, ChaCha20Rng::from_os_rng())
    }

    /// Construct a node with deterministic batching randomness for tests and
    /// fuzzing. This API is absent from production builds.
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn new_with_epoch_and_seed(
        role: MixRole,
        epoch: u64,
        private_key: [u8; 32],
        rng_seed: [u8; 32],
    ) -> Self {
        Self::new_with_rng(role, epoch, private_key, ChaCha20Rng::from_seed(rng_seed))
    }

    fn new_with_rng(role: MixRole, epoch: u64, private_key: [u8; 32], rng: ChaCha20Rng) -> Self {
        Self {
            role,
            current_key: RoutingKey { epoch, private_key },
            previous_key: None,
            replay: ReplayCache::new(epoch),
            batch: MixBatch::new(),
            cover_route: None,
            outbound: Vec::new(),
            inbound: Vec::new(),
            rng,
            relayed_in_window: 0,
        }
    }

    /// Retain one overlap key and its complete replay set during rotation.
    pub fn rotate_routing_key(
        &mut self,
        epoch: u64,
        private_key: [u8; 32],
    ) -> Result<(), MixnetError> {
        if epoch <= self.current_key.epoch {
            return Err(MixnetError::NonMonotonicEpoch {
                current: self.current_key.epoch,
                proposed: epoch,
            });
        }
        if let Some(retired) = self.previous_key.take() {
            self.replay.retire_epoch(retired.epoch);
        }
        let previous = std::mem::replace(&mut self.current_key, RoutingKey { epoch, private_key });
        self.previous_key = Some(previous);
        self.replay.add_epoch(epoch);
        Ok(())
    }

    pub fn retire_previous_key(&mut self) {
        if let Some(retired) = self.previous_key.take() {
            self.replay.retire_epoch(retired.epoch);
        }
    }

    pub fn set_cover_route(&mut self, route: CoverRoute) -> Result<(), MixnetError> {
        validate_path(&route.path_pubkeys, &route.path_addresses)?;
        self.cover_route = Some(route);
        Ok(())
    }

    /// Sphinx authentication succeeds before the hop-local replay tag enters
    /// the cache, preventing malformed traffic from consuming replay memory.
    pub fn receive(&mut self, wire: &[u8; MIXNET_MTU]) -> Result<(), MixnetError> {
        let packet = MixnetPacket::from_bytes(wire);
        if packet.version != MIXNET_VERSION {
            return Err(MixnetError::UnsupportedVersion(packet.version));
        }
        let private_key = if packet.key_epoch == self.current_key.epoch {
            self.current_key.private_key
        } else if self
            .previous_key
            .as_ref()
            .is_some_and(|key| key.epoch == packet.key_epoch)
        {
            self.previous_key
                .as_ref()
                .expect("epoch checked")
                .private_key
        } else {
            return Err(MixnetError::UnknownKeyEpoch(packet.key_epoch));
        };

        let sphinx = SphinxPacket::from_bytes(&packet.sphinx_packet)
            .map_err(|_| MixnetError::AuthenticationFailed)?;
        // Alpha is blinded at every hop by the vetted Sphinx construction. A
        // replay repeats the same authenticated processing state at this hop,
        // while different hops never expose a common wire identifier.
        let replay_tag = replay_tag(packet.key_epoch, sphinx.shared_secret().as_bytes());
        let processed = sphinx
            .process(&SphinxSecret::from(private_key))
            .map_err(|_| MixnetError::AuthenticationFailed)?;
        match processed.data {
            ProcessedPacketData::ForwardHop {
                next_hop_packet,
                next_hop_address,
                ..
            } => {
                if matches!(self.role, MixRole::Client) {
                    return Err(MixnetError::RelayDisabled);
                }
                self.replay.check_and_insert(packet.key_epoch, replay_tag)?;
                let forwarded = encode_sphinx_packet(packet.key_epoch, next_hop_packet)?;
                self.batch
                    .packets
                    .push_back((forwarded, next_hop_address.to_bytes()));
                self.relayed_in_window = self.relayed_in_window.saturating_add(1);
            }
            ProcessedPacketData::FinalHop { payload, .. } => {
                let plaintext = payload
                    .recover_plaintext()
                    .map_err(|_| MixnetError::MalformedPayload)?;
                let delivery = match plaintext.split_first() {
                    Some((&PAYLOAD_DATA, message)) => Some(message.to_vec()),
                    Some((&PAYLOAD_COVER, message)) if message.is_empty() => None,
                    _ => return Err(MixnetError::MalformedPayload),
                };
                self.replay.check_and_insert(packet.key_epoch, replay_tag)?;
                if let Some(message) = delivery {
                    self.inbound.push(message);
                }
            }
        }
        Ok(())
    }

    /// Flush a ready batch. Empty relays require a real configured cover route;
    /// the engine never emits recognizable random junk or a zero-address packet.
    pub fn tick(&mut self) -> Result<(), MixnetError> {
        if !self.batch.ready() {
            return Ok(());
        }
        let relays = matches!(self.role, MixRole::MixNode | MixRole::Gateway { .. });
        let flushed = self.batch.flush(&mut self.rng);
        if relays {
            for (packet, address) in flushed {
                self.outbound.push((address, packet.to_bytes()));
            }
            if self.relayed_in_window == 0 {
                self.emit_cover()?;
            }
        }
        self.relayed_in_window = 0;
        self.batch = MixBatch::new();
        Ok(())
    }

    fn emit_cover(&mut self) -> Result<(), MixnetError> {
        let route = self
            .cover_route
            .clone()
            .ok_or(MixnetError::CoverRouteUnavailable)?;
        let entry_address = route.path_addresses[0];
        let packet = wrap_payload(
            route.key_epoch,
            &route.path_pubkeys,
            &route.path_addresses,
            &[],
            PAYLOAD_COVER,
            &mut self.rng,
        )?
        .into_iter()
        .next()
        .ok_or(MixnetError::MalformedPayload)?;
        self.outbound.push((entry_address, packet.to_bytes()));
        Ok(())
    }
}

/// Build data packets for compatibility epoch zero.
pub fn wrap_for_path(
    path_pubkeys: &[[u8; 32]],
    path_addresses: &[[u8; NODE_ADDRESS_LENGTH]],
    plaintext: &[u8],
    rng: &mut ChaCha20Rng,
) -> Result<Vec<MixnetPacket>, MixnetError> {
    wrap_for_path_epoch(0, path_pubkeys, path_addresses, plaintext, rng)
}

pub fn wrap_for_path_epoch(
    key_epoch: u64,
    path_pubkeys: &[[u8; 32]],
    path_addresses: &[[u8; NODE_ADDRESS_LENGTH]],
    plaintext: &[u8],
    rng: &mut ChaCha20Rng,
) -> Result<Vec<MixnetPacket>, MixnetError> {
    wrap_payload(
        key_epoch,
        path_pubkeys,
        path_addresses,
        plaintext,
        PAYLOAD_DATA,
        rng,
    )
}

fn wrap_payload(
    key_epoch: u64,
    path_pubkeys: &[[u8; 32]],
    path_addresses: &[[u8; NODE_ADDRESS_LENGTH]],
    plaintext: &[u8],
    kind: u8,
    rng: &mut ChaCha20Rng,
) -> Result<Vec<MixnetPacket>, MixnetError> {
    validate_path(path_pubkeys, path_addresses)?;
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[]]
    } else {
        plaintext.chunks(MAX_PLAINTEXT_SIZE).collect()
    };
    chunks
        .into_iter()
        .map(|chunk| build_packet(key_epoch, path_pubkeys, path_addresses, chunk, kind, rng))
        .collect()
}

fn build_packet(
    key_epoch: u64,
    path_pubkeys: &[[u8; 32]],
    path_addresses: &[[u8; NODE_ADDRESS_LENGTH]],
    plaintext: &[u8],
    kind: u8,
    rng: &mut ChaCha20Rng,
) -> Result<MixnetPacket, MixnetError> {
    let route: Vec<Node> = path_pubkeys
        .iter()
        .zip(path_addresses)
        .map(|(public_key, address)| {
            Node::new(
                NodeAddressBytes::from_bytes(*address),
                SphinxPublicKey::from(*public_key),
            )
        })
        .collect();
    let mut identifier = [0u8; IDENTIFIER_LENGTH];
    rng.fill_bytes(&mut identifier);
    let destination = Destination::new(
        DestinationAddressBytes::from_bytes(destination_address(path_addresses)),
        identifier,
    );
    let delays = vec![Delay::new_from_nanos(0); route.len()];
    let mut initial_secret = [0u8; 32];
    rng.fill_bytes(&mut initial_secret);
    let initial_secret = SphinxSecret::from(initial_secret);
    let message: Vec<u8> = std::iter::once(kind)
        .chain(plaintext.iter().copied())
        .collect();
    let packet = SphinxPacketBuilder::new()
        .with_payload_size(MIXNET_PAYLOAD_SIZE)
        .with_initial_secret(&initial_secret)
        .build_packet(message, &route, &destination, &delays)
        .map_err(|_| MixnetError::CryptoError)?;
    encode_sphinx_packet(key_epoch, packet)
}

fn encode_sphinx_packet(key_epoch: u64, packet: SphinxPacket) -> Result<MixnetPacket, MixnetError> {
    let bytes = packet.to_bytes();
    let sphinx_packet: [u8; SPHINX_PACKET_SIZE] = bytes
        .try_into()
        .map_err(|_| MixnetError::UnexpectedSphinxSize)?;
    Ok(MixnetPacket {
        version: MIXNET_VERSION,
        key_epoch,
        sphinx_packet,
    })
}

fn validate_path(
    path_pubkeys: &[[u8; 32]],
    path_addresses: &[[u8; NODE_ADDRESS_LENGTH]],
) -> Result<(), MixnetError> {
    if path_pubkeys.is_empty() || path_pubkeys.len() > MAX_HOPS {
        return Err(MixnetError::InvalidPath(path_pubkeys.len()));
    }
    if path_addresses.len() != path_pubkeys.len() {
        return Err(MixnetError::InvalidAddressCount {
            keys: path_pubkeys.len(),
            addresses: path_addresses.len(),
        });
    }
    Ok(())
}

fn destination_address(
    path_addresses: &[[u8; NODE_ADDRESS_LENGTH]],
) -> [u8; DESTINATION_ADDRESS_LENGTH] {
    // Both lengths are 32 in the selected construction. Copying keeps the
    // boundary explicit if the upstream type aliases ever change.
    let mut destination = [0u8; DESTINATION_ADDRESS_LENGTH];
    destination.copy_from_slice(&path_addresses[path_addresses.len() - 1]);
    destination
}

fn replay_tag(epoch: u64, blinded_alpha: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"mesh-mixnet-v2-replay");
    hasher.update(epoch.to_be_bytes());
    hasher.update(blinded_alpha);
    hasher.finalize().into()
}

/// Shared handle used by service and transport loops.
#[derive(Clone)]
pub struct MixnetHandle(pub Arc<Mutex<MixnetNode>>);

impl MixnetHandle {
    pub fn new(role: MixRole, private_key: [u8; 32]) -> Self {
        Self(Arc::new(Mutex::new(MixnetNode::new(role, private_key))))
    }

    pub fn receive(&self, wire: &[u8; MIXNET_MTU]) -> Result<(), MixnetError> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .receive(wire)
    }

    pub fn tick(&self) -> Result<(), MixnetError> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .tick()
    }

    pub fn drain_outbound(&self) -> Vec<([u8; NODE_ADDRESS_LENGTH], [u8; MIXNET_MTU])> {
        std::mem::take(
            &mut self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .outbound,
        )
    }

    pub fn drain_inbound(&self) -> Vec<Vec<u8>> {
        std::mem::take(
            &mut self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .inbound,
        )
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MixnetError {
    #[error("path length {0} out of range (1..={MAX_HOPS})")]
    InvalidPath(usize),
    #[error("path has {keys} keys but {addresses} routing addresses")]
    InvalidAddressCount { keys: usize, addresses: usize },
    #[error("unsupported mixnet version {0}")]
    UnsupportedVersion(u8),
    #[error("Sphinx packet authentication or processing failed")]
    AuthenticationFailed,
    #[error("malformed final Sphinx payload")]
    MalformedPayload,
    #[error("Sphinx packet construction failed")]
    CryptoError,
    #[error("Sphinx implementation returned an unexpected packet size")]
    UnexpectedSphinxSize,
    #[error("authenticated mixnet layer was replayed")]
    Replay,
    #[error("routing-key epoch {0} is not active")]
    UnknownKeyEpoch(u64),
    #[error("replay cache for routing-key epoch {0} is full")]
    ReplayCacheFull(u64),
    #[error("routing-key epoch must increase from {current}, received {proposed}")]
    NonMonotonicEpoch { current: u64, proposed: u64 },
    #[error("client role cannot relay a non-final mixnet packet")]
    RelayDisabled,
    #[error("cover traffic requires a valid configured route")]
    CoverRouteUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xDEAD_BEEF_CAFE_1337)
    }

    fn route(count: usize) -> (Vec<[u8; 32]>, Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let secrets: Vec<[u8; 32]> = (1..=count).map(|index| [index as u8; 32]).collect();
        let public_keys = secrets
            .iter()
            .map(|secret| SphinxPublicKey::from(&SphinxSecret::from(*secret)).to_bytes())
            .collect();
        let addresses = (0..count)
            .map(|index| {
                let mut address = [0u8; NODE_ADDRESS_LENGTH];
                address[0] = index as u8;
                address
            })
            .collect();
        (secrets, public_keys, addresses)
    }

    #[test]
    fn packet_roundtrip_is_exact_mtu() {
        let (_, keys, addresses) = route(1);
        let packet = wrap_for_path_epoch(7, &keys, &addresses, b"hello", &mut seeded_rng())
            .expect("wrap")
            .remove(0);
        let wire = packet.to_bytes();
        assert_eq!(wire.len(), MIXNET_MTU);
        assert_eq!(MixnetPacket::from_bytes(&wire), packet);
    }

    #[test]
    fn every_hop_transforms_the_complete_sphinx_packet() {
        let (secrets, keys, addresses) = route(3);
        let wire = wrap_for_path_epoch(9, &keys, &addresses, b"private message", &mut seeded_rng())
            .expect("wrap")[0]
            .to_bytes();
        let mut first = MixnetNode::new_with_epoch(MixRole::MixNode, 9, secrets[0]);
        first.receive(&wire).expect("first hop");
        first.batch.created_at = Instant::now() - Duration::from_secs(1);
        first.relayed_in_window = 1;
        first.tick().expect("first flush");
        let first_wire = first.outbound.pop().expect("first output").1;
        assert_ne!(wire[9..], first_wire[9..]);

        let mut second = MixnetNode::new_with_epoch(MixRole::MixNode, 9, secrets[1]);
        second.receive(&first_wire).expect("second hop");
        second.batch.created_at = Instant::now() - Duration::from_secs(1);
        second.relayed_in_window = 1;
        second.tick().expect("second flush");
        let second_wire = second.outbound.pop().expect("second output").1;
        assert_ne!(first_wire[9..], second_wire[9..]);

        let mut destination = MixnetNode::new_with_epoch(MixRole::Client, 9, secrets[2]);
        destination.receive(&second_wire).expect("final hop");
        assert_eq!(destination.inbound, vec![b"private message".to_vec()]);
    }

    #[test]
    fn complete_packet_validation_precedes_replay_insertion() {
        let (secrets, keys, addresses) = route(1);
        let mut node = MixnetNode::new_with_epoch(MixRole::Client, 3, secrets[0]);
        let mut wire = wrap_for_path_epoch(3, &keys, &addresses, b"hello", &mut seeded_rng())
            .expect("wrap")[0]
            .to_bytes();
        wire[MIXNET_MTU - 1] ^= 1;
        assert_eq!(node.receive(&wire), Err(MixnetError::MalformedPayload));
        assert_eq!(node.replay.len_for_epoch(3), 0);
    }

    #[test]
    fn replay_survives_batch_windows() {
        let (secrets, keys, addresses) = route(1);
        let mut node = MixnetNode::new_with_epoch(MixRole::Client, 4, secrets[0]);
        let wire = wrap_for_path_epoch(4, &keys, &addresses, b"hello", &mut seeded_rng())
            .expect("wrap")[0]
            .to_bytes();
        node.receive(&wire).expect("first delivery");
        node.batch.created_at = Instant::now() - Duration::from_secs(60);
        node.tick().expect("tick");
        assert_eq!(node.receive(&wire), Err(MixnetError::Replay));
    }

    #[test]
    fn previous_epoch_replay_is_retained_until_key_retirement() {
        let (secrets, keys, addresses) = route(1);
        let mut node = MixnetNode::new_with_epoch(MixRole::Client, 10, secrets[0]);
        let wire = wrap_for_path_epoch(10, &keys, &addresses, b"hello", &mut seeded_rng())
            .expect("wrap")[0]
            .to_bytes();
        node.receive(&wire).expect("first delivery");
        node.rotate_routing_key(11, [8u8; 32]).expect("rotation");
        assert_eq!(node.receive(&wire), Err(MixnetError::Replay));
        node.retire_previous_key();
        assert_eq!(node.receive(&wire), Err(MixnetError::UnknownKeyEpoch(10)));
    }

    #[test]
    fn cover_uses_normal_sphinx_and_is_discarded_at_destination() {
        let (secrets, keys, addresses) = route(1);
        let mut relay = MixnetNode::new_with_epoch(MixRole::MixNode, 12, [9u8; 32]);
        relay
            .set_cover_route(CoverRoute {
                key_epoch: 12,
                path_pubkeys: keys,
                path_addresses: addresses,
            })
            .expect("route");
        relay.batch.created_at = Instant::now() - Duration::from_secs(1);
        relay.tick().expect("cover generation");
        let wire = relay.outbound.pop().expect("cover packet").1;
        let mut destination = MixnetNode::new_with_epoch(MixRole::Client, 12, secrets[0]);
        destination.receive(&wire).expect("authenticated cover");
        assert!(destination.inbound.is_empty());
    }

    #[test]
    fn empty_relay_without_cover_route_fails_closed() {
        let mut relay = MixnetNode::new(MixRole::MixNode, [3u8; 32]);
        relay.batch.created_at = Instant::now() - Duration::from_secs(1);
        assert_eq!(relay.tick(), Err(MixnetError::CoverRouteUnavailable));
        assert!(relay.outbound.is_empty());
    }

    #[test]
    fn validation_rejects_bad_paths_and_epoch_rollback() {
        let (_, keys, _) = route(1);
        assert!(matches!(
            wrap_for_path(&keys, &[], b"x", &mut seeded_rng()),
            Err(MixnetError::InvalidAddressCount { .. })
        ));
        let mut node = MixnetNode::new_with_epoch(MixRole::Client, 20, [1u8; 32]);
        assert!(matches!(
            node.rotate_routing_key(19, [2u8; 32]),
            Err(MixnetError::NonMonotonicEpoch { .. })
        ));
    }
}
