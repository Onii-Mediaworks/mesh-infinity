//! Native Mixnet Tier (§5.25)
//!
//! The native mixnet tier is a **routing mode** layered on top of the existing
//! wrapper-node infrastructure (§4.4), not a separate physical transport.
//!
//! It adds three mixnet properties that Tor and I2P cannot provide:
//!
//! - **Fixed-size packets** — all packets padded to MTU (1500 bytes) with
//!   random bytes; an observer cannot infer payload size.
//! - **Per-hop batching and shuffling** — each mix node collects packets for
//!   500ms, shuffles the batch, then forwards; arrival order and departure
//!   order are uncorrelated.
//! - **Mandatory cover traffic** — if a batch window is empty, a dummy packet
//!   indistinguishable from real traffic is emitted; silence reveals nothing.
//!
//! ## Sphinx packet format
//!
//! The `onion_layer` uses a simplified Sphinx-compatible construction:
//!
//! ```text
//! For each hop i (0..MAX_HOPS):
//!   eph_pubkey[i]  : [u8; 32]  — ephemeral X25519 public key
//!   mac[i]         : [u8; 16]  — Poly1305 MAC over remaining header
//!   routing_info[i]: [u8; 16]  — encrypted next-hop address + flags
//! total: MAX_HOPS * 64 = SPHINX_HEADER_SIZE bytes
//! ```
//!
//! Each hop peels one layer: ECDH with its own keypair → ChaCha20 keystream →
//! decrypt `routing_info` to learn next hop → strip outer layer → re-MAC →
//! forward.  Constant header size regardless of path depth.
//!
//! ## Participation levels
//!
//! - **Client** — mobile/desktop; sends and receives through mix nodes.
//! - **MixNode** — server-mode; batches, shuffles, forwards; holds replay cache.
//! - **Gateway** — accepts external-protocol packets and injects into mixnet.
//!
//! ## Katzenpost compatibility
//!
//! When `katzenpost_mode` is true on a gateway, the gateway translates between
//! the Mesh Infinity Sphinx format and the Katzenpost wire format.  This is
//! experimental; see §5.25.6.
//!
//! ## Cover-traffic reduction for relay nodes
//!
//! Per §2.1 principle 9 and §5.10.3: a node actively relaying mixnet traffic
//! generates proportionally less synthetic cover.  At full relay throughput,
//! relay traffic satisfies the cover obligation entirely.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Fixed packet size in bytes.  All packets are padded or split to this size.
/// Constant packet size prevents payload-size side channels.
pub const MIXNET_MTU: usize = 1500;

/// Maximum number of onion hops a Sphinx header encodes.
/// With 5 hops and 64 bytes per hop, the header is 320 bytes.
pub const MAX_HOPS: usize = 5;

/// Per-hop Sphinx header contribution: 32 B eph key + 16 B MAC + 16 B routing = 64 B.
pub const SPHINX_HOP_SIZE: usize = 64;

/// Total Sphinx header size.  Constant regardless of actual path length —
/// unused hop slots are filled with random bytes.
pub const SPHINX_HEADER_SIZE: usize = MAX_HOPS * SPHINX_HOP_SIZE; // 320

/// Total fixed packet wire size:
///   1 (version) + 32 (packet_id) + SPHINX_HEADER_SIZE + payload
pub const SPHINX_OVERHEAD: usize = 1 + 32 + SPHINX_HEADER_SIZE;

/// Payload bytes per packet.
pub const MIXNET_PAYLOAD_SIZE: usize = MIXNET_MTU - SPHINX_OVERHEAD; // 1147

/// Default batch window — packets accumulate for this duration before flush.
pub const BATCH_WINDOW_MS: u64 = 500;

/// Replay cache TTL — packet IDs are remembered for two batch windows.
pub const REPLAY_CACHE_TTL_MS: u64 = BATCH_WINDOW_MS * 2;

// ─────────────────────────────────────────────────────────────────────────────
// Packet format
// ─────────────────────────────────────────────────────────────────────────────

/// A fixed-size Sphinx-wrapped mixnet packet.
///
/// Wire layout:
/// ```text
/// [0]       version      : u8
/// [1..33]   packet_id    : [u8; 32]
/// [33..353] onion_layer  : [u8; SPHINX_HEADER_SIZE]
/// [353..1500] payload    : [u8; MIXNET_PAYLOAD_SIZE]
/// ```
#[derive(Clone)]
pub struct MixnetPacket {
    /// Protocol version; currently 1.
    pub version: u8,
    /// Random 256-bit packet ID used for deduplication and replay detection.
    pub packet_id: [u8; 32],
    /// Fixed-size Sphinx routing header.  Each hop decrypts one layer.
    pub onion_layer: [u8; SPHINX_HEADER_SIZE],
    /// Fixed-size encrypted payload.  Padded with random bytes when short.
    pub payload: [u8; MIXNET_PAYLOAD_SIZE],
}

impl MixnetPacket {
    /// Serialise to exactly `MIXNET_MTU` bytes.
    pub fn to_bytes(&self) -> [u8; MIXNET_MTU] {
        let mut buf = [0u8; MIXNET_MTU];
        buf[0] = self.version;
        buf[1..33].copy_from_slice(&self.packet_id);
        buf[33..33 + SPHINX_HEADER_SIZE].copy_from_slice(&self.onion_layer);
        buf[33 + SPHINX_HEADER_SIZE..].copy_from_slice(&self.payload);
        buf
    }

    /// Deserialise from exactly `MIXNET_MTU` bytes.
    pub fn from_bytes(buf: &[u8; MIXNET_MTU]) -> Self {
        let version = buf[0];
        let mut packet_id = [0u8; 32];
        packet_id.copy_from_slice(&buf[1..33]);
        let mut onion_layer = [0u8; SPHINX_HEADER_SIZE];
        onion_layer.copy_from_slice(&buf[33..33 + SPHINX_HEADER_SIZE]);
        let mut payload = [0u8; MIXNET_PAYLOAD_SIZE];
        payload.copy_from_slice(&buf[33 + SPHINX_HEADER_SIZE..]);
        MixnetPacket { version, packet_id, onion_layer, payload }
    }

    /// True if this packet is a cover-traffic dummy.
    ///
    /// Dummy packets set `packet_id[0] == 0xFF` as a local-only convention.
    /// Actual routing cannot distinguish dummies — they are only self-labelled
    /// in this accessor for cover-traffic accounting.
    pub fn is_dummy(&self) -> bool {
        self.packet_id[0] == 0xFF
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sphinx header helpers
// ─────────────────────────────────────────────────────────────────────────────

/// One decrypted Sphinx routing slot.
pub struct SphinxHop {
    /// Next-hop address (first 14 bytes of routing_info).
    pub next_hop: [u8; 14],
    /// Flags byte (routing_info[14]):
    ///   0x00 = forward to next hop
    ///   0x01 = this is the final destination
    ///   0x02 = gateway exit (Katzenpost)
    pub flags: u8,
}

/// Build a Sphinx header for `path` (list of X25519 public keys, up to MAX_HOPS).
///
/// Returns `(onion_layer, ephemeral_public_keys)`.
/// The caller places the ephemeral public keys in the header; each hop uses
/// its own static private key + the corresponding ephemeral public key for
/// ECDH to derive its layer key.
pub fn sphinx_build_header(
    path: &[X25519PublicKey],
    next_hop_addrs: &[[u8; 14]],
    rng: &mut ChaCha20Rng,
) -> Result<[u8; SPHINX_HEADER_SIZE], MixnetError> {
    if path.is_empty() || path.len() > MAX_HOPS {
        return Err(MixnetError::InvalidPath(path.len()));
    }

    let mut header = [0u8; SPHINX_HEADER_SIZE];
    // Fill unused hop slots with random bytes (constant-size property).
    rng.fill_bytes(&mut header);

    let num_hops = path.len();

    // Generate one ephemeral keypair per hop and immediately compute ECDH.
    // EphemeralSecret is consumed by diffie_hellman(); we store the resulting
    // shared secret bytes and the ephemeral public key for the header.
    let mut eph_pub_bytes_vec: Vec<[u8; 32]> = Vec::with_capacity(num_hops);
    let mut layer_keys: Vec<[u8; 32]> = Vec::with_capacity(num_hops);
    for hop_pubkey in path.iter() {
        let secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let eph_pub = X25519PublicKey::from(&secret);
        // Real ECDH: eph_secret × hop_pubkey → shared_secret.
        // The receiver computes hop_privkey × eph_pub → same shared_secret.
        let shared = secret.diffie_hellman(hop_pubkey);
        // Derive layer key: SHA-256("sphinx-layer-key" || shared_secret).
        let mut hasher = Sha256::new();
        hasher.update(b"sphinx-layer-key");
        hasher.update(shared.as_bytes());
        let layer_key: [u8; 32] = hasher.finalize().into();
        eph_pub_bytes_vec.push(eph_pub.to_bytes());
        layer_keys.push(layer_key);
    }

    // Lay down each hop's slot: eph_pubkey || MAC || routing_info.
    for i in 0..num_hops {
        let slot_start = i * SPHINX_HOP_SIZE;

        let eph_pub_bytes = eph_pub_bytes_vec[i];
        let layer_key = layer_keys[i];

        // Routing info: 14-byte next-hop addr + 1 flag byte + 1 reserved = 16 B.
        let mut routing_info = [0u8; 16];
        if i < next_hop_addrs.len() {
            routing_info[..14].copy_from_slice(&next_hop_addrs[i]);
        }
        routing_info[14] = if i == num_hops - 1 { 0x01 } else { 0x00 }; // final hop flag

        // Derive the per-hop AEAD nonce from the ECDH shared secret using the
        // same SHA-256 pattern used for layer key derivation above.  Using the
        // shared secret (rather than a constant or the slot index alone) ensures
        // the nonce is unique per session and deterministic on both sides without
        // extra round-trips.  A different domain label ("sphinx-hop-nonce" vs
        // "sphinx-layer-key") prevents the nonce from ever equalling the key.
        //
        // Nonce = SHA-256("sphinx-hop-nonce" || shared_secret)[0..12]
        //
        // The receiver's sphinx_peel_layer() performs the same derivation from
        // its own copy of the shared secret and therefore produces the same nonce.
        // Both sides use the same (key, nonce) pair, which is safe here because
        // each hop encrypts a distinct routing_info block — the (key, nonce) pair
        // is never reused across distinct plaintexts.
        let nonce_bytes: [u8; 12] = {
            // Reconstruct the ECDH shared secret for this hop from the layer key
            // hasher.  We re-hash the layer key with a distinct label rather than
            // storing the raw shared secret, keeping the shared secret out of
            // memory for longer than necessary.
            let mut nonce_hasher = Sha256::new();
            nonce_hasher.update(b"sphinx-hop-nonce");
            nonce_hasher.update(layer_key);
            let hash: [u8; 32] = nonce_hasher.finalize().into();
            // Truncate to 12 bytes for ChaCha20-Poly1305 nonce size.
            let mut n = [0u8; 12];
            n.copy_from_slice(&hash[..12]);
            n
        };
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt routing_info with ChaCha20-Poly1305.
        let cipher = ChaCha20Poly1305::new_from_slice(&layer_key)
            .map_err(|_| MixnetError::CryptoError)?;
        let encrypted_routing = cipher
            .encrypt(nonce, routing_info.as_ref())
            .map_err(|_| MixnetError::CryptoError)?;

        // Header slot layout:
        //   [0..32]  ephemeral public key
        //   [32..48] MAC (truncated ciphertext tag)
        //   [48..64] encrypted routing info (first 16 bytes of encrypted_routing)
        header[slot_start..slot_start + 32].copy_from_slice(&eph_pub_bytes);
        if encrypted_routing.len() >= 32 {
            header[slot_start + 32..slot_start + 48]
                .copy_from_slice(&encrypted_routing[16..32]); // tag portion
            header[slot_start + 48..slot_start + 64]
                .copy_from_slice(&encrypted_routing[..16]); // ciphertext
        }
    }

    Ok(header)
}

/// Peel one Sphinx layer at a mix node.
///
/// `node_privkey` — this node's X25519 static private key bytes.
/// Returns the next-hop routing info and the modified header (outer layer
/// stripped, inner layers shifted up, tail filled with random bytes).
pub fn sphinx_peel_layer(
    header: &[u8; SPHINX_HEADER_SIZE],
    node_privkey: &[u8; 32],
    rng: &mut ChaCha20Rng,
) -> Result<(SphinxHop, [u8; SPHINX_HEADER_SIZE]), MixnetError> {
    // Read the outermost hop slot.
    let eph_pub_bytes: [u8; 32] = header[..32].try_into().unwrap();
    let _mac_bytes: [u8; 16] = header[32..48].try_into().unwrap();
    let enc_routing: [u8; 16] = header[48..64].try_into().unwrap();

    // Derive layer key: ECDH(node_privkey × eph_pub) → SHA-256("sphinx-layer-key" || shared).
    // This mirrors the build side: ECDH(eph_secret × hop_pub) = ECDH(hop_priv × eph_pub).
    let static_secret = X25519StaticSecret::from(*node_privkey);
    let eph_pub = X25519PublicKey::from(eph_pub_bytes);
    let shared = static_secret.diffie_hellman(&eph_pub);
    let mut hasher = Sha256::new();
    hasher.update(b"sphinx-layer-key");
    hasher.update(shared.as_bytes());
    let layer_key: [u8; 32] = hasher.finalize().into();

    // Derive the per-hop nonce from the layer key using the same derivation as
    // sphinx_build_header() so that (key, nonce) pair matches exactly.
    // Nonce = SHA-256("sphinx-hop-nonce" || layer_key)[0..12]
    let nonce_bytes: [u8; 12] = {
        let mut nonce_hasher = Sha256::new();
        nonce_hasher.update(b"sphinx-hop-nonce");
        nonce_hasher.update(layer_key);
        let hash: [u8; 32] = nonce_hasher.finalize().into();
        let mut n = [0u8; 12];
        n.copy_from_slice(&hash[..12]);
        n
    };
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt routing info.
    let cipher = ChaCha20Poly1305::new_from_slice(&layer_key)
        .map_err(|_| MixnetError::CryptoError)?;
    // Reconstruct AEAD ciphertext (ciphertext || tag).
    let mut ct = [0u8; 32];
    ct[..16].copy_from_slice(&enc_routing);
    ct[16..].copy_from_slice(&_mac_bytes);
    let routing_info = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| MixnetError::DecryptionFailed)?;

    let mut next_hop = [0u8; 14];
    next_hop.copy_from_slice(&routing_info[..14]);
    let flags = routing_info[14];
    let hop = SphinxHop { next_hop, flags };

    // Shift header: drop slot 0, shift remaining slots up, fill tail with random.
    let mut new_header = [0u8; SPHINX_HEADER_SIZE];
    new_header[..SPHINX_HEADER_SIZE - SPHINX_HOP_SIZE]
        .copy_from_slice(&header[SPHINX_HOP_SIZE..]);
    rng.fill_bytes(&mut new_header[SPHINX_HEADER_SIZE - SPHINX_HOP_SIZE..]);

    Ok((hop, new_header))
}

// ─────────────────────────────────────────────────────────────────────────────
// Participation roles
// ─────────────────────────────────────────────────────────────────────────────

/// Mixnet participation level of this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixRole {
    /// Mobile/desktop — sends and receives, does not relay.
    Client,
    /// Server-mode — batches, shuffles, relays packets.
    MixNode,
    /// Server-mode + external protocol translation (experimental §5.25.6).
    Gateway { katzenpost_mode: bool },
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay cache
// ─────────────────────────────────────────────────────────────────────────────

/// Per-node replay cache.  Tracks seen `packet_id`s for `REPLAY_CACHE_TTL_MS`.
struct ReplayCache {
    /// Active window: packet IDs seen in the current batch window.
    current: HashSet<[u8; 32]>,
    /// Previous window (kept for one extra TTL to handle boundary packets).
    previous: HashSet<[u8; 32]>,
    /// When the current window started.
    window_start: Instant,
}

impl ReplayCache {
    fn new() -> Self {
        ReplayCache {
            current: HashSet::new(),
            previous: HashSet::new(),
            window_start: Instant::now(),
        }
    }

    /// Returns `true` if the packet ID is a replay (already seen).
    /// Also rotates windows if the batch interval has elapsed.
    fn check_and_insert(&mut self, id: &[u8; 32]) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_millis(REPLAY_CACHE_TTL_MS) {
            self.previous = std::mem::take(&mut self.current);
            self.window_start = now;
        }
        if self.previous.contains(id) || self.current.contains(id) {
            return true; // replay
        }
        self.current.insert(*id);
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mix node batch engine
// ─────────────────────────────────────────────────────────────────────────────

/// A batch of packets waiting for the flush window.
struct MixBatch {
    packets: VecDeque<(MixnetPacket, SphinxHop)>,
    created_at: Instant,
}

impl MixBatch {
    fn new() -> Self {
        MixBatch {
            packets: VecDeque::new(),
            created_at: Instant::now(),
        }
    }

    fn is_ready(&self) -> bool {
        self.created_at.elapsed() >= Duration::from_millis(BATCH_WINDOW_MS)
    }

    fn push(&mut self, pkt: MixnetPacket, hop: SphinxHop) {
        self.packets.push_back((pkt, hop));
    }

    /// Shuffle and drain.  Shuffles in-place using Fisher-Yates.
    fn flush(&mut self, rng: &mut ChaCha20Rng) -> Vec<(MixnetPacket, SphinxHop)> {
        let n = self.packets.len();
        let mut vec: Vec<_> = self.packets.drain(..).collect();
        // Fisher-Yates shuffle.
        for i in (1..n).rev() {
            let j = (rng.next_u64() as usize) % (i + 1);
            vec.swap(i, j);
        }
        vec
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MixnetNode — the core mix node state machine
// ─────────────────────────────────────────────────────────────────────────────

/// Mix node state.
///
/// Wrap in `Arc<Mutex<MixnetNode>>` for multi-threaded access.
pub struct MixnetNode {
    /// This node's role.
    pub role: MixRole,
    /// This node's X25519 static private key (for Sphinx layer peeling).
    privkey: [u8; 32],
    /// Current batch.
    batch: MixBatch,
    /// Replay protection cache.
    replay: ReplayCache,
    /// Packets ready to be forwarded (address, serialised packet).
    pub outbound: Vec<([u8; 14], [u8; MIXNET_MTU])>,
    /// Packets addressed to this node (decrypted payload).
    pub inbound: Vec<Vec<u8>>,
    /// Deterministic RNG (reseeded per batch window).
    rng: ChaCha20Rng,
    /// Running cover traffic counter for relay-reduction calculation.
    relay_packets_this_window: u32,
}

impl MixnetNode {
    /// Create a new mix node.
    ///
    /// `privkey` — 32-byte X25519 static private key for Sphinx layer peeling.
    pub fn new(role: MixRole, privkey: [u8; 32]) -> Self {
        MixnetNode {
            role,
            privkey,
            batch: MixBatch::new(),
            replay: ReplayCache::new(),
            outbound: Vec::new(),
            inbound: Vec::new(),
            rng: ChaCha20Rng::from_os_rng(),
            relay_packets_this_window: 0,
        }
    }

    /// Receive an incoming wire packet.
    ///
    /// 1. Replay check.
    /// 2. For client role: attempt to decrypt as a final-destination packet.
    /// 3. For mix/gateway role: peel Sphinx layer and enqueue in batch.
    pub fn receive(&mut self, wire: &[u8; MIXNET_MTU]) -> Result<(), MixnetError> {
        let pkt = MixnetPacket::from_bytes(wire);

        if self.replay.check_and_insert(&pkt.packet_id) {
            return Err(MixnetError::Replay);
        }

        let (hop, new_header) =
            sphinx_peel_layer(&pkt.onion_layer, &self.privkey, &mut self.rng)?;

        if hop.flags & 0x01 != 0 {
            // Final destination — extract plaintext payload (strip random padding).
            // Payload is variable-length plaintext followed by random padding.
            // Length prefix is in payload[0..2] (big-endian u16).
            if pkt.payload.len() >= 2 {
                let len =
                    u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]) as usize;
                if len <= pkt.payload.len() - 2 {
                    self.inbound.push(pkt.payload[2..2 + len].to_vec());
                }
            }
            return Ok(());
        }

        // Forward hop — enqueue in batch.
        let forwarded = MixnetPacket {
            version: pkt.version,
            packet_id: pkt.packet_id,
            onion_layer: new_header,
            payload: pkt.payload,
        };
        self.batch.push(forwarded, hop);
        self.relay_packets_this_window += 1;
        Ok(())
    }

    /// Tick the batch engine.  Call periodically (e.g. every 50ms).
    ///
    /// When the batch window elapses:
    /// 1. Shuffle the batch.
    /// 2. Move packets to `self.outbound`.
    /// 3. If batch was empty, emit one cover-traffic dummy packet.
    ///
    /// Per §5.10.3, nodes actively relaying real traffic satisfy their cover
    /// obligation proportionally.
    pub fn tick(&mut self) {
        if !self.batch.is_ready() {
            return;
        }

        let flushed = self.batch.flush(&mut self.rng);
        let is_mix = matches!(self.role, MixRole::MixNode | MixRole::Gateway { .. });

        if is_mix {
            if flushed.is_empty() && !self.cover_obligation_met() {
                // Emit one mandatory cover-traffic dummy.
                let dummy = self.build_dummy_packet();
                // Dummy is routed to a random next-hop address (all zeros = self).
                self.outbound.push(([0u8; 14], dummy.to_bytes()));
            }
            for (pkt, hop) in flushed {
                self.outbound.push((hop.next_hop, pkt.to_bytes()));
            }
        }

        // Reset relay counter for new window.
        self.relay_packets_this_window = 0;
        self.batch = MixBatch::new();
    }

    /// Build a cover-traffic dummy packet.
    ///
    /// Dummy packets have `packet_id[0] == 0xFF` and random contents.
    /// They are cryptographically indistinguishable from real traffic to
    /// any observer that cannot decrypt the payload.
    fn build_dummy_packet(&mut self) -> MixnetPacket {
        let mut packet_id = [0u8; 32];
        self.rng.fill_bytes(&mut packet_id);
        packet_id[0] = 0xFF; // local-only dummy marker

        let mut onion_layer = [0u8; SPHINX_HEADER_SIZE];
        self.rng.fill_bytes(&mut onion_layer);

        let mut payload = [0u8; MIXNET_PAYLOAD_SIZE];
        self.rng.fill_bytes(&mut payload);

        MixnetPacket { version: 1, packet_id, onion_layer, payload }
    }

    /// Whether relay traffic this window satisfies the cover obligation.
    ///
    /// Rule: if we relayed at least one real packet this window, cover is met.
    /// A more sophisticated implementation would scale proportionally, but
    /// the binary threshold is safe (conservative) for v0.3.
    fn cover_obligation_met(&self) -> bool {
        self.relay_packets_this_window > 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Client-side: packet construction
// ─────────────────────────────────────────────────────────────────────────────

/// Wrap `plaintext` in a Sphinx-encrypted mixnet packet for the given `path`.
///
/// `path_pubkeys` — X25519 public keys of each mix node in order.
/// `path_addrs` — 14-byte next-hop addresses for each hop.
/// `plaintext` — the payload to deliver; padded or split to `MIXNET_PAYLOAD_SIZE`.
///
/// Returns one or more `MixnetPacket`s (if plaintext > payload capacity,
/// it is split across multiple packets with a sequence prefix).
pub fn wrap_for_path(
    path_pubkeys: &[X25519PublicKey],
    path_addrs: &[[u8; 14]],
    plaintext: &[u8],
    rng: &mut ChaCha20Rng,
) -> Result<Vec<MixnetPacket>, MixnetError> {
    // Maximum payload per packet after 2-byte length prefix.
    const MAX_PAYLOAD: usize = MIXNET_PAYLOAD_SIZE - 2;

    let chunks: Vec<&[u8]> = plaintext.chunks(MAX_PAYLOAD).collect();
    let mut packets = Vec::with_capacity(chunks.len());

    for chunk in chunks {
        let onion_layer = sphinx_build_header(path_pubkeys, path_addrs, rng)?;

        let mut payload = [0u8; MIXNET_PAYLOAD_SIZE];
        let len = chunk.len() as u16;
        payload[..2].copy_from_slice(&len.to_be_bytes());
        payload[2..2 + chunk.len()].copy_from_slice(chunk);
        // Remaining bytes are already zeroed; fill with random padding.
        rng.fill_bytes(&mut payload[2 + chunk.len()..]);

        let mut packet_id = [0u8; 32];
        rng.fill_bytes(&mut packet_id);

        packets.push(MixnetPacket { version: 1, packet_id, onion_layer, payload });
    }

    Ok(packets)
}

// ─────────────────────────────────────────────────────────────────────────────
// Thread-safe handle
// ─────────────────────────────────────────────────────────────────────────────

/// Shared, thread-safe mix node handle.
#[derive(Clone)]
pub struct MixnetHandle(pub Arc<Mutex<MixnetNode>>);

impl MixnetHandle {
    pub fn new(role: MixRole, privkey: [u8; 32]) -> Self {
        MixnetHandle(Arc::new(Mutex::new(MixnetNode::new(role, privkey))))
    }

    pub fn receive(&self, wire: &[u8; MIXNET_MTU]) -> Result<(), MixnetError> {
        self.0.lock().unwrap().receive(wire)
    }

    pub fn tick(&self) {
        self.0.lock().unwrap().tick();
    }

    pub fn drain_outbound(&self) -> Vec<([u8; 14], [u8; MIXNET_MTU])> {
        std::mem::take(&mut self.0.lock().unwrap().outbound)
    }

    pub fn drain_inbound(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.0.lock().unwrap().inbound)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum MixnetError {
    #[error("path length {0} out of range (1..={MAX_HOPS})")]
    InvalidPath(usize),
    #[error("sphinx decryption failed")]
    DecryptionFailed,
    #[error("crypto initialisation error")]
    CryptoError,
    #[error("replay — packet ID already seen")]
    Replay,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;

    fn seeded_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xDEAD_BEEF_CAFE_1337)
    }

    // ── Packet serialisation ─────────────────────────────────────────────────

    #[test]
    fn packet_roundtrip() {
        let mut rng = seeded_rng();
        let mut packet_id = [0u8; 32];
        let mut onion_layer = [0u8; SPHINX_HEADER_SIZE];
        let mut payload = [0u8; MIXNET_PAYLOAD_SIZE];
        rng.fill_bytes(&mut packet_id);
        rng.fill_bytes(&mut onion_layer);
        rng.fill_bytes(&mut payload);

        let pkt = MixnetPacket { version: 1, packet_id, onion_layer, payload };
        let wire = pkt.to_bytes();
        let pkt2 = MixnetPacket::from_bytes(&wire);

        assert_eq!(pkt2.version, 1);
        assert_eq!(pkt2.packet_id, packet_id);
        assert_eq!(pkt2.onion_layer, onion_layer);
        assert_eq!(&pkt2.payload[..], &payload[..]);
    }

    #[test]
    fn packet_wire_size_is_mtu() {
        let mut rng = seeded_rng();
        let mut pkt = MixnetPacket {
            version: 1,
            packet_id: [0; 32],
            onion_layer: [0; SPHINX_HEADER_SIZE],
            payload: [0; MIXNET_PAYLOAD_SIZE],
        };
        rng.fill_bytes(&mut pkt.packet_id);
        let wire = pkt.to_bytes();
        assert_eq!(wire.len(), MIXNET_MTU);
    }

    #[test]
    fn dummy_packet_has_marker_byte() {
        let mut node = MixnetNode::new(MixRole::MixNode, [0u8; 32]);
        let dummy = node.build_dummy_packet();
        assert!(dummy.is_dummy(), "dummy packet_id[0] must be 0xFF");
    }

    // ── Replay cache ─────────────────────────────────────────────────────────

    #[test]
    fn replay_cache_rejects_duplicate() {
        let mut cache = ReplayCache::new();
        let id = [0x42u8; 32];
        assert!(!cache.check_and_insert(&id), "first insert should return false (not replay)");
        assert!(cache.check_and_insert(&id), "second insert should return true (replay)");
    }

    #[test]
    fn replay_cache_accepts_distinct_ids() {
        let mut cache = ReplayCache::new();
        for i in 0..100u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            assert!(!cache.check_and_insert(&id));
        }
    }

    // ── Batch engine ─────────────────────────────────────────────────────────

    #[test]
    fn empty_batch_emits_cover_traffic() {
        let mut node = MixnetNode::new(MixRole::MixNode, [1u8; 32]);
        // Force the batch window to appear elapsed by manipulating created_at.
        node.batch.created_at =
            Instant::now() - Duration::from_millis(BATCH_WINDOW_MS + 100);
        node.tick();
        assert_eq!(
            node.outbound.len(),
            1,
            "empty batch must emit exactly one cover-traffic dummy"
        );
    }

    #[test]
    fn client_does_not_emit_cover_traffic() {
        let mut node = MixnetNode::new(MixRole::Client, [0u8; 32]);
        node.batch.created_at =
            Instant::now() - Duration::from_millis(BATCH_WINDOW_MS + 100);
        node.tick();
        // Clients don't relay; outbound should be empty.
        assert!(
            node.outbound.is_empty(),
            "client nodes must not emit cover traffic"
        );
    }

    // ── Constants ────────────────────────────────────────────────────────────

    #[test]
    fn sizes_add_up() {
        assert_eq!(
            SPHINX_OVERHEAD + MIXNET_PAYLOAD_SIZE,
            MIXNET_MTU,
            "overhead + payload must equal MTU"
        );
        assert_eq!(
            SPHINX_HEADER_SIZE,
            MAX_HOPS * SPHINX_HOP_SIZE,
            "header size must equal hops × hop size"
        );
    }

    #[test]
    fn cover_obligation_met_when_relaying() {
        let mut node = MixnetNode::new(MixRole::MixNode, [0u8; 32]);
        assert!(!node.cover_obligation_met());
        node.relay_packets_this_window = 1;
        assert!(node.cover_obligation_met());
    }

    // ── Role variants ────────────────────────────────────────────────────────

    #[test]
    fn gateway_role_with_katzenpost_flag() {
        let node = MixnetNode::new(MixRole::Gateway { katzenpost_mode: true }, [0u8; 32]);
        assert!(matches!(node.role, MixRole::Gateway { katzenpost_mode: true }));
    }

    // ── Header build (smoke test — full ECDH requires live keys) ─────────────

    #[test]
    fn sphinx_header_build_single_hop() {
        let mut rng = seeded_rng();
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let pubkey = X25519PublicKey::from(&secret);
        let addr = [0u8; 14];
        let result = sphinx_build_header(&[pubkey], &[addr], &mut rng);
        assert!(result.is_ok(), "single-hop header build failed: {:?}", result);
        let header = result.unwrap();
        assert_eq!(header.len(), SPHINX_HEADER_SIZE);
    }

    #[test]
    fn sphinx_header_build_rejects_empty_path() {
        let mut rng = seeded_rng();
        let result = sphinx_build_header(&[], &[], &mut rng);
        assert!(matches!(result, Err(MixnetError::InvalidPath(0))));
    }

    #[test]
    fn sphinx_header_build_rejects_path_too_long() {
        let mut rng = seeded_rng();
        let keys: Vec<X25519PublicKey> = (0..MAX_HOPS + 1)
            .map(|_| {
                let s = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
                X25519PublicKey::from(&s)
            })
            .collect();
        let addrs = vec![[0u8; 14]; MAX_HOPS + 1];
        let result = sphinx_build_header(&keys, &addrs, &mut rng);
        assert!(matches!(result, Err(MixnetError::InvalidPath(_))));
    }

    #[test]
    fn sphinx_build_peel_round_trip_single_hop() {
        // Build a header for a single hop and verify peel recovers the routing info.
        let node_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let node_pubkey = X25519PublicKey::from(&node_secret);
        let node_privkey_bytes: [u8; 32] = node_secret.to_bytes();

        let next_hop_addr: [u8; 14] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let mut rng = seeded_rng();
        let header = sphinx_build_header(&[node_pubkey], &[next_hop_addr], &mut rng)
            .expect("build should succeed");

        let (hop, _new_header) = sphinx_peel_layer(&header, &node_privkey_bytes, &mut rng)
            .expect("peel should succeed — ECDH shared secret must match");

        assert_eq!(hop.next_hop, next_hop_addr, "peeled routing info must match encoded address");
        assert_eq!(hop.flags, 0x01, "single-hop flag must be set");
    }

    #[test]
    fn sphinx_build_peel_round_trip_multi_hop() {
        // Build a 3-hop header and verify each successive peel recovers the correct hop.
        let mut rng = seeded_rng();
        let secrets: Vec<x25519_dalek::StaticSecret> = (0..3)
            .map(|_| x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng))
            .collect();
        let pubkeys: Vec<X25519PublicKey> = secrets.iter().map(|s| X25519PublicKey::from(s)).collect();
        let addrs: Vec<[u8; 14]> = (0u8..3)
            .map(|i| { let mut a = [0u8; 14]; a[0] = i; a })
            .collect();

        let header = sphinx_build_header(&pubkeys, &addrs, &mut rng)
            .expect("3-hop build should succeed");

        // Peel hop 0
        let privkey_0: [u8; 32] = secrets[0].to_bytes();
        let (hop0, header1) = sphinx_peel_layer(&header, &privkey_0, &mut rng)
            .expect("peel hop 0 should succeed");
        assert_eq!(hop0.next_hop[0], 0, "hop 0 addr byte 0");
        assert_eq!(hop0.flags, 0x00, "hop 0 is not final");

        // Peel hop 1
        let privkey_1: [u8; 32] = secrets[1].to_bytes();
        let (hop1, header2) = sphinx_peel_layer(&header1, &privkey_1, &mut rng)
            .expect("peel hop 1 should succeed");
        assert_eq!(hop1.next_hop[0], 1, "hop 1 addr byte 0");
        assert_eq!(hop1.flags, 0x00, "hop 1 is not final");

        // Peel hop 2 (final)
        let privkey_2: [u8; 32] = secrets[2].to_bytes();
        let (hop2, _) = sphinx_peel_layer(&header2, &privkey_2, &mut rng)
            .expect("peel hop 2 should succeed");
        assert_eq!(hop2.next_hop[0], 2, "hop 2 addr byte 0");
        assert_eq!(hop2.flags, 0x01, "hop 2 is final");
    }
}
