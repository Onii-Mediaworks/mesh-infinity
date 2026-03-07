//! WireGuard-inspired active mesh channel implementation.
//!
//! This module is responsible for the "active" encrypted path used by the
//! backend when a peer can be reached over an available transport underlay.
//! It maintains peer session state (key epoch + nonce counters), applies
//! obfuscation, packages packets with per-hop relay tags, and attempts delivery
//! using configured underlay transports in policy order.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use super::obfuscation::{ObfuscationMode, TrafficObfuscator};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::{PeerId, PeerInfo, TransportType, TrustLevel};
use crate::transport::TransportManager;
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use x25519_dalek::{PublicKey, StaticSecret};

const WIRE_PACKET_VERSION: u8 = 1;
const RELAY_TAG_LEN: usize = 16;
const ROTATION_INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub struct WGConfig {
    pub interface: String,
    pub private_key: [u8; 32],
    pub port: u16,
    pub mtu: u16,
}

pub struct WireGuardMesh {
    config: WGConfig,
    public_key: [u8; 32],
    peers: Arc<Mutex<HashMap<PeerId, WGPeer>>>,
    ip_to_peer: Arc<Mutex<HashMap<IpAddr, PeerId>>>,
    next_index: AtomicU32,
    transport_manager: Option<Arc<TransportManager>>,
    obfuscator: Arc<Mutex<TrafficObfuscator>>,
}

pub struct WGPeer {
    pub public_key: [u8; 32],
    pub allowed_ips: Vec<IpAddr>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
    pub latest_handshake: Option<std::time::SystemTime>,
    session: PeerSession,
    underlay_preference: Vec<TransportType>,
    last_outbound: Option<Vec<u8>>,
}

struct PeerSession {
    epoch: u64,
    key: [u8; 32],
    relay_seed: [u8; 32],
    nonce_counter: u64,
    last_rotated: SystemTime,
}

impl WireGuardMesh {
    /// Create a new mesh instance from validated WireGuard configuration.
    ///
    /// This initializes local runtime state only; no peer handshakes or network
    /// listeners are started here.
    pub fn new(config: WGConfig) -> Result<Self> {
        if config.mtu < 576 {
            return Err(MeshInfinityError::WireGuardError(
                "invalid MTU for WireGuard mesh".to_string(),
            ));
        }

        Ok(Self {
            public_key: derive_public_key(config.private_key),
            config,
            peers: Arc::new(Mutex::new(HashMap::new())),
            ip_to_peer: Arc::new(Mutex::new(HashMap::new())),
            next_index: AtomicU32::new(1),
            transport_manager: None,
            obfuscator: Arc::new(Mutex::new(TrafficObfuscator::new(ObfuscationMode::None))),
        })
    }

    /// Return the immutable local WireGuard configuration.
    pub fn config(&self) -> &WGConfig {
        &self.config
    }

    /// Return this node's public key derived from [`WGConfig::private_key`].
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Register or replace a peer and initialize its per-peer session state.
    ///
    /// Also updates the reverse index from allowed IPs to peer id so incoming
    /// traffic can map directly to a known peer.
    pub fn add_peer(
        &self,
        peer_id: PeerId,
        public_key: [u8; 32],
        allowed_ips: Vec<IpAddr>,
        endpoint: Option<SocketAddr>,
        persistent_keepalive: Option<u16>,
    ) -> Result<()> {
        let _ = self.next_index.fetch_add(1, Ordering::Relaxed);

        if allowed_ips.is_empty() {
            return Err(MeshInfinityError::WireGuardError(
                "peer requires at least one allowed IP".to_string(),
            ));
        }

        let underlays = self.default_underlay_order();

        let peer = WGPeer {
            public_key,
            allowed_ips: allowed_ips.clone(),
            endpoint,
            persistent_keepalive,
            latest_handshake: None,
            session: PeerSession::new()?,
            underlay_preference: underlays,
            last_outbound: None,
        };

        let mut ip_map = self
            .ip_to_peer
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("IP map lock poisoned: {}", e)))?;
        for ip in &allowed_ips {
            ip_map.insert(*ip, peer_id);
        }
        drop(ip_map);

        self.peers
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Peers lock poisoned: {}", e)))?
            .insert(peer_id, peer);
        Ok(())
    }

    /// Remove a peer and clean up all IP-to-peer index entries owned by it.
    pub fn remove_peer(&self, peer_id: &PeerId) -> Result<()> {
        let mut peers = self
            .peers
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Peers lock poisoned: {}", e)))?;

        if let Some(peer) = peers.get(peer_id) {
            let mut ip_map = self.ip_to_peer.lock().map_err(|e| {
                MeshInfinityError::LockError(format!("IP map lock poisoned: {}", e))
            })?;
            for ip in &peer.allowed_ips {
                ip_map.remove(ip);
            }
        }

        peers.remove(peer_id);
        Ok(())
    }

    /// Resolve a destination IP to a known peer id, if indexed.
    pub fn get_peer_by_ip(&self, ip: &IpAddr) -> Option<PeerId> {
        self.ip_to_peer.lock().ok()?.get(ip).copied()
    }

    /// Attach the shared transport manager used for underlay send attempts.
    pub fn set_transport_manager(&mut self, transport_manager: Arc<TransportManager>) {
        self.transport_manager = Some(transport_manager);
    }

    /// Encrypt, obfuscate, and dispatch payload to `target` over active underlays.
    ///
    /// Processing pipeline:
    /// 1. rotate per-peer session keys if epoch expired,
    /// 2. stream-encrypt payload using the current session key + nonce,
    /// 3. apply configured obfuscation mode,
    /// 4. package packet with epoch/nonce/tag metadata,
    /// 5. attempt send over available transports in peer preference order.
    pub fn send_message(&self, target: &PeerId, payload: &[u8]) -> Result<()> {
        let mut peers = self
            .peers
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Peers lock poisoned: {}", e)))?;

        let peer = peers
            .get_mut(target)
            .ok_or_else(|| MeshInfinityError::PeerNotFound(format!("{:?}", target)))?;

        peer.session.rotate_if_needed()?;

        let encrypted = xor_stream(payload, &peer.session.key, peer.session.nonce_counter);

        let obfuscated = {
            let obfuscator = self.obfuscator.lock().map_err(|e| {
                MeshInfinityError::LockError(format!("Obfuscator lock poisoned: {}", e))
            })?;
            obfuscator.obfuscate(&encrypted)?
        };

        let packet = encode_wire_packet(
            peer.session.epoch,
            peer.session.nonce_counter,
            &peer.session.relay_seed,
            &obfuscated,
        )?;

        peer.session.nonce_counter = peer.session.nonce_counter.saturating_add(1);

        peer.latest_handshake = Some(std::time::SystemTime::now());
        peer.last_outbound = Some(packet.clone());

        let send_result = self.try_send_over_underlay(*target, peer, &packet);
        drop(peers);

        send_result
    }

    /// Decode and decrypt an inbound packet from `source` peer.
    ///
    /// Validates packet version and relay tag, reverses obfuscation, then
    /// stream-decrypts using the source peer's active session key.
    pub fn receive_message(&self, source: &PeerId, obfuscated: &[u8]) -> Result<Vec<u8>> {
        let mut peers = self
            .peers
            .lock()
            .map_err(|e| MeshInfinityError::LockError(format!("Peers lock poisoned: {}", e)))?;

        let peer = peers
            .get_mut(source)
            .ok_or_else(|| MeshInfinityError::PeerNotFound(format!("{:?}", source)))?;

        peer.session.rotate_if_needed()?;

        let (_epoch, nonce_counter, ciphertext) =
            decode_wire_packet(obfuscated, &peer.session.relay_seed)?;

        let obfuscator = self.obfuscator.lock().map_err(|e| {
            MeshInfinityError::LockError(format!("Obfuscator lock poisoned: {}", e))
        })?;
        let encrypted = obfuscator.deobfuscate(&ciphertext)?;
        let plain = xor_stream(&encrypted, &peer.session.key, nonce_counter);
        Ok(plain)
    }

    /// Test/debug helper: take and clear the last encoded outbound packet.
    pub fn consume_outbound_packet(&self, target: &PeerId) -> Option<Vec<u8>> {
        self.peers
            .lock()
            .ok()?
            .get_mut(target)
            .and_then(|peer| peer.last_outbound.take())
    }

    /// Switch obfuscation mode using the default mode-specific keying strategy.
    pub fn set_obfuscation(&self, mode: ObfuscationMode) -> Result<()> {
        let mut obfuscator = self.obfuscator.lock().map_err(|e| {
            MeshInfinityError::LockError(format!("Obfuscator lock poisoned: {}", e))
        })?;
        *obfuscator = TrafficObfuscator::new(mode);
        Ok(())
    }

    /// Switch obfuscation mode while forcing a caller-provided static key.
    ///
    /// Useful for deterministic tests and controlled interoperability scenarios.
    pub fn set_obfuscation_with_key(&self, mode: ObfuscationMode, key: [u8; 32]) -> Result<()> {
        let mut obfuscator = self.obfuscator.lock().map_err(|e| {
            MeshInfinityError::LockError(format!("Obfuscator lock poisoned: {}", e))
        })?;
        *obfuscator = TrafficObfuscator::with_key(mode, key);
        Ok(())
    }

    /// Return the currently configured obfuscation mode.
    pub fn get_obfuscation_mode(&self) -> Result<ObfuscationMode> {
        let obfuscator = self.obfuscator.lock().map_err(|e| {
            MeshInfinityError::LockError(format!("Obfuscator lock poisoned: {}", e))
        })?;
        Ok(obfuscator.mode())
    }
}

/// Derive the X25519 public key bytes from a 32-byte private key.
fn derive_public_key(private_key: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(private_key);
    let public = PublicKey::from(&secret);
    public.to_bytes()
}

impl WireGuardMesh {
    /// Build underlay transport order used for peer send attempts.
    ///
    /// If a transport manager is present, this uses its available set and
    /// transport priorities; otherwise it falls back to a static privacy-first
    /// ordering.
    fn default_underlay_order(&self) -> Vec<TransportType> {
        let mut underlays = if let Some(manager) = &self.transport_manager {
            manager.available_transports()
        } else {
            vec![
                TransportType::Tor,
                TransportType::I2P,
                TransportType::Bluetooth,
                TransportType::Clearnet,
            ]
        };

        underlays.sort_by_key(|t| {
            self.transport_manager
                .as_ref()
                .and_then(|m| m.get_transport(t))
                .map(|tpt| tpt.priority())
                .unwrap_or(u8::MAX)
        });
        underlays
    }

    /// Attempt packet transmission over each preferred underlay transport.
    ///
    /// Returns success on the first full write (`written == packet.len()`).
    /// Any failed/partial transport attempt is treated as soft failure and the
    /// next underlay is tried.
    fn try_send_over_underlay(&self, target: PeerId, peer: &WGPeer, packet: &[u8]) -> Result<()> {
        let manager = self
            .transport_manager
            .as_ref()
            .ok_or(MeshInfinityError::NoAvailableTransport)?;

        let endpoint = peer.endpoint.ok_or_else(|| {
            MeshInfinityError::TransportError("peer endpoint unavailable".to_string())
        })?;

        let peer_info = PeerInfo {
            peer_id: target,
            public_key: peer.public_key,
            trust_level: TrustLevel::Trusted,
            available_transports: peer.underlay_preference.clone(),
            last_seen: None,
            endpoint: Some(endpoint),
            transport_endpoints: std::collections::HashMap::new(),
        };

        for transport_type in &peer_info.available_transports {
            let Some(transport) = manager.get_transport(transport_type) else {
                continue;
            };
            if !transport.is_available() {
                continue;
            }

            if let Ok(mut conn) = transport.connect(&peer_info) {
                match conn.send(packet) {
                    Ok(written) if written == packet.len() => return Ok(()),
                    Ok(_) => continue,
                    Err(_) => continue,
                }
            }
        }

        Err(MeshInfinityError::NoAvailableTransport)
    }
}

impl PeerSession {
    /// Create a fresh peer session with random keying material.
    fn new() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        let mut relay_seed = [0u8; 32];
        rng.fill(&mut key).map_err(|_| {
            MeshInfinityError::CryptoError("failed to initialize WireGuard session key".to_string())
        })?;
        rng.fill(&mut relay_seed).map_err(|_| {
            MeshInfinityError::CryptoError("failed to initialize WireGuard relay seed".to_string())
        })?;

        Ok(Self {
            epoch: 1,
            key,
            relay_seed,
            nonce_counter: 0,
            last_rotated: SystemTime::now(),
        })
    }

    /// Rotate session key material when the configured epoch interval expires.
    ///
    /// Rotation resets nonce counters and advances epoch id to maintain bounded
    /// key lifetime and avoid long-lived relay-tag linkability.
    fn rotate_if_needed(&mut self) -> Result<()> {
        let elapsed = self
            .last_rotated
            .elapsed()
            .unwrap_or_else(|_| Duration::from_secs(0));
        if elapsed < ROTATION_INTERVAL {
            return Ok(());
        }

        let rng = SystemRandom::new();
        let mut next_key = [0u8; 32];
        let mut next_seed = [0u8; 32];
        rng.fill(&mut next_key).map_err(|_| {
            MeshInfinityError::CryptoError("failed to rotate WireGuard session key".to_string())
        })?;
        rng.fill(&mut next_seed).map_err(|_| {
            MeshInfinityError::CryptoError("failed to rotate WireGuard relay seed".to_string())
        })?;

        self.epoch = self.epoch.saturating_add(1);
        self.key = next_key;
        self.relay_seed = next_seed;
        self.nonce_counter = 0;
        self.last_rotated = SystemTime::now();
        Ok(())
    }
}

/// Encode an outbound wire packet with protocol metadata and relay tag.
fn encode_wire_packet(
    epoch: u64,
    nonce_counter: u64,
    relay_seed: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let tag = relay_tag(relay_seed, epoch, nonce_counter);
    let payload_len = u32::try_from(ciphertext.len()).map_err(|_| {
        MeshInfinityError::WireGuardError("wire packet payload exceeds supported size".to_string())
    })?;

    let mut packet = Vec::with_capacity(1 + 8 + 8 + RELAY_TAG_LEN + 4 + ciphertext.len());
    packet.push(WIRE_PACKET_VERSION);
    packet.extend_from_slice(&epoch.to_be_bytes());
    packet.extend_from_slice(&nonce_counter.to_be_bytes());
    packet.extend_from_slice(&tag);
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.extend_from_slice(ciphertext);
    Ok(packet)
}

/// Decode and validate inbound wire packet structure and relay tag.
fn decode_wire_packet(packet: &[u8], relay_seed: &[u8; 32]) -> Result<(u64, u64, Vec<u8>)> {
    if packet.len() < 1 + 8 + 8 + RELAY_TAG_LEN + 4 {
        return Err(MeshInfinityError::InvalidMessageFormat);
    }

    let version = packet[0];
    if version != WIRE_PACKET_VERSION {
        return Err(MeshInfinityError::ProtocolMismatch);
    }

    let epoch = u64::from_be_bytes(
        packet[1..9]
            .try_into()
            .map_err(|_| MeshInfinityError::InvalidMessageFormat)?,
    );
    let nonce_counter = u64::from_be_bytes(
        packet[9..17]
            .try_into()
            .map_err(|_| MeshInfinityError::InvalidMessageFormat)?,
    );

    let mut observed_tag = [0u8; RELAY_TAG_LEN];
    observed_tag.copy_from_slice(&packet[17..(17 + RELAY_TAG_LEN)]);
    let expected_tag = relay_tag(relay_seed, epoch, nonce_counter);
    if observed_tag != expected_tag {
        return Err(MeshInfinityError::SecurityError(
            "invalid relay metadata tag".to_string(),
        ));
    }

    let payload_len = u32::from_be_bytes(
        packet[(17 + RELAY_TAG_LEN)..(21 + RELAY_TAG_LEN)]
            .try_into()
            .map_err(|_| MeshInfinityError::InvalidMessageFormat)?,
    ) as usize;
    let payload_offset = 21 + RELAY_TAG_LEN;
    let payload_end = payload_offset + payload_len;
    if payload_end > packet.len() {
        return Err(MeshInfinityError::InvalidMessageFormat);
    }

    Ok((
        epoch,
        nonce_counter,
        packet[payload_offset..payload_end].to_vec(),
    ))
}

/// Compute hop-scoped relay tag from relay seed, epoch, and nonce counter.
fn relay_tag(relay_seed: &[u8; 32], epoch: u64, nonce_counter: u64) -> [u8; RELAY_TAG_LEN] {
    let mut material = Vec::with_capacity(32 + 8 + 8);
    material.extend_from_slice(relay_seed);
    material.extend_from_slice(&epoch.to_be_bytes());
    material.extend_from_slice(&nonce_counter.to_be_bytes());
    let hashed = digest(&SHA256, &material);

    let mut out = [0u8; RELAY_TAG_LEN];
    out.copy_from_slice(&hashed.as_ref()[..RELAY_TAG_LEN]);
    out
}

/// Lightweight XOR stream transform used by the current active packet format.
///
/// This is symmetric: applying it twice with the same `(key, nonce_counter)`
/// recovers the original bytes.
fn xor_stream(input: &[u8], key: &[u8; 32], nonce_counter: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let counter_bytes = nonce_counter.to_be_bytes();

    for (i, b) in input.iter().enumerate() {
        let k = key[i % key.len()] ^ counter_bytes[i % counter_bytes.len()];
        out.push(*b ^ k);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    /// Verifies encode/decode symmetry for protocol packet framing.
    #[test]
    fn test_packet_roundtrip() {
        let seed = [9u8; 32];
        let payload = vec![1, 2, 3, 4, 5];
        let packet = encode_wire_packet(3, 7, &seed, &payload).unwrap();
        let (epoch, nonce, back) = decode_wire_packet(&packet, &seed).unwrap();
        assert_eq!(epoch, 3);
        assert_eq!(nonce, 7);
        assert_eq!(back, payload);
    }

    /// Verifies XOR stream transform is reversible with identical parameters.
    #[test]
    fn test_stream_xor_reversible() {
        let key = [0xA5u8; 32];
        let payload = b"mesh-infinity".to_vec();
        let encrypted = xor_stream(&payload, &key, 42);
        let plain = xor_stream(&encrypted, &key, 42);
        assert_eq!(plain, payload);
    }

    /// Guards against placeholder key derivation behavior.
    #[test]
    fn test_public_key_derivation_not_placeholder() {
        let private_key = [7u8; 32];
        let pubkey = derive_public_key(private_key);
        assert_ne!(pubkey, private_key);
    }

    /// Ensures forced-expiry rotation advances epoch and refreshes key state.
    #[test]
    fn test_rotation_advances_epoch() {
        let mut session = PeerSession::new().unwrap();
        session.last_rotated = UNIX_EPOCH;
        let epoch_before = session.epoch;
        session.rotate_if_needed().unwrap();
        assert!(session.epoch > epoch_before);
    }
}
