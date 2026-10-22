//! Tor transport (§5.3)
//!
//! Implements the Tor anonymising transport using the `arti` Rust Tor client.
//!
//! ## Architecture
//!
//! The Tor client is async (tokio-based) while the rest of the backend is sync.
//! We bridge the gap with a dedicated `tokio::runtime::Runtime` stored inside
//! `TorTransport`.  All async operations are entered via `runtime.block_on()`.
//! Background I/O tasks are spawned on the runtime's handle.
//!
//! ## Connection model (sync/async bridge)
//!
//! For each Tor peer connection we create a localhost TCP loopback pair:
//!   - The **sync side** is inserted into `MeshContext::clearnet_connections`
//!     exactly like a direct TCP connection, so all existing send/receive
//!     logic works without modification.
//!   - The **async side** is bridged to the Tor `DataStream` by a tokio task
//!     that copies bytes in both directions.
//!
//! ## Keypair / onion address (§5.3)
//!
//! The Tor root keypair is an independent sibling of the mesh identity:
//! `tor_root_secret` is 32 random bytes generated with the self identity
//! (`SelfIdentity::tor_root_secret`) and stored beside it, never derived
//! from the identity master key.  The root is never used directly; each
//! hosted service gets its own keypair:
//!
//! ```text
//! service_tor_key = HKDF-SHA256(
//!     ikm  = tor_root_secret,
//!     salt = tor_root_public,
//!     info = "meshinfinity-tor-service-v1" || service_id || BE64(rotation_counter),
//! )  →  ed25519 signing key → onion pubkey → .onion address
//! ```
//!
//! Compromising the mesh keypair therefore says nothing about any onion
//! address, and no onion address leads back to the mesh peer ID.  The mesh
//! endpoint is one service (`MESH_ENDPOINT_SERVICE_ID`); its `.onion` is
//! stable across restarts while the root and rotation counter are, and it
//! is included in the node's network map `transport_hints`.
//!
//! For the hidden service, arti's built-in keystore persists the keypair in the
//! state directory and the address remains constant across restarts.  We seed
//! the nickname with our peer ID hex so the service is identifiable.
//!
//! ## Circuit rotation (§5.3)
//!
//! Per-peer circuit isolation is enforced via `IsolationToken` — each peer
//! gets its own token so Tor routes each on a separate circuit.
//! Circuits are rotated (token replaced, triggering a new circuit):
//! - every `CIRCUIT_ROTATION_SECS` (10 minutes), or
//! - after `CIRCUIT_ROTATION_MESSAGES` (200) on a single circuit.

use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::Context as _;
use data_encoding::BASE32_NOPAD;
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest as Sha3Digest, Sha3_256};
use tokio::runtime::Runtime;
use tor_circmgr::IsolationToken;
use tor_proto::stream::IncomingStreamRequest;

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

/// How long a circuit lives before being proactively rotated (§5.3).
const CIRCUIT_ROTATION_SECS: u64 = 600; // 10 minutes

/// Maximum messages before a circuit is rotated (§5.3).
const CIRCUIT_ROTATION_MESSAGES: u64 = 200;

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

/// Per-peer circuit metadata for rotation bookkeeping.
struct CircuitStats {
    established_at: Instant,
    message_count: u64,
    /// Isolation token for this circuit.  Replaced on rotation.
    isolation: arti_client::IsolationToken,
}

impl CircuitStats {
    fn new() -> Self {
        Self {
            established_at: Instant::now(),
            message_count: 0,
            isolation: IsolationToken::new(),
        }
    }

    fn should_rotate(&self) -> bool {
        self.established_at.elapsed().as_secs() >= CIRCUIT_ROTATION_SECS
            || self.message_count >= CIRCUIT_ROTATION_MESSAGES
    }

    fn rotate(&mut self) {
        self.established_at = Instant::now();
        self.message_count = 0;
        self.isolation = IsolationToken::new();
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Onion address helpers
// ────────────────────────────────────────────────────────────────────────────

/// Tor v3 onion address version byte.
const HSID_ONION_VERSION: u8 = 0x03;

/// Compute the Tor v3 `.onion` address from an ed25519 public key (32 bytes).
///
/// Format (rend-spec-v3 §6 \[ONIONADDRESS]):
/// ```text
/// base32( pubkey[32] || checksum[2] || version[1] ) + ".onion"
/// checksum = SHA3-256(".onion checksum" || pubkey || version)[..2]
/// ```
pub fn onion_address_v3(pubkey: &[u8; 32]) -> String {
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pubkey);
    h.update([HSID_ONION_VERSION]);
    let hash = h.finalize();

    let mut binary = Vec::with_capacity(35);
    binary.extend_from_slice(pubkey);
    binary.push(hash[0]);
    binary.push(hash[1]);
    binary.push(HSID_ONION_VERSION);

    let mut b32 = BASE32_NOPAD.encode(&binary);
    b32.make_ascii_lowercase();
    format!("{b32}.onion")
}

/// HKDF info prefix for service key derivation (§5.3).
const TOR_SERVICE_INFO: &[u8] = b"meshinfinity-tor-service-v1";

/// `service_id` of the node's own mesh endpoint hidden service.
///
/// Other hosted services (§12) derive their own keys under their own ids,
/// so their onion addresses are unlinkable to this one.
pub const MESH_ENDPOINT_SERVICE_ID: &[u8] = b"mesh-endpoint";

/// Derive one service's ed25519 signing key from the Tor root (§5.3).
///
/// `ikm` is the root secret, `salt` the root's public key (so the root
/// seed alone, without its public half, is not the HKDF input), and `info`
/// is the fixed prefix followed by the service id and the big-endian
/// rotation counter.  Bumping the counter yields an unrelated key, which is
/// how a service's onion address is rotated without touching the root.
pub fn derive_tor_service_key(
    tor_root_secret: &[u8; 32],
    service_id: &[u8],
    rotation_counter: u64,
) -> ed25519_dalek::SigningKey {
    // The root's public key is the HKDF salt; the root itself never signs.
    let tor_root_public = ed25519_dalek::SigningKey::from_bytes(tor_root_secret)
        .verifying_key()
        .to_bytes();
    let hk = Hkdf::<Sha256>::new(Some(tor_root_public.as_slice()), tor_root_secret);
    // info = prefix || service_id || BE64(rotation_counter), fixed-width
    // counter so no service id can collide with another id plus counter.
    let mut info = Vec::with_capacity(TOR_SERVICE_INFO.len() + service_id.len() + 8);
    info.extend_from_slice(TOR_SERVICE_INFO);
    info.extend_from_slice(service_id);
    info.extend_from_slice(&rotation_counter.to_be_bytes());
    let mut okm = [0u8; 32];
    // Infallible: HKDF-SHA256 expand fails only above 255 × 32 output
    // bytes; 32 bytes never reaches that guard.
    hk.expand(&info, &mut okm).expect("HKDF-SHA256 expand to 32 bytes is infallible");
    ed25519_dalek::SigningKey::from_bytes(&okm)
}

/// The Tor v3 `.onion` address of one service under the Tor root (§5.3).
pub fn derive_onion_address(
    tor_root_secret: &[u8; 32],
    service_id: &[u8],
    rotation_counter: u64,
) -> String {
    let signing_key = derive_tor_service_key(tor_root_secret, service_id, rotation_counter);
    let pubkey = signing_key.verifying_key().to_bytes();
    onion_address_v3(&pubkey)
}

// ────────────────────────────────────────────────────────────────────────────
// TorTransport
// ────────────────────────────────────────────────────────────────────────────

/// The Tor transport layer (§5.3).
///
/// Owns a dedicated tokio `Runtime` and a bootstrapped `arti_client::TorClient`.
pub struct TorTransport {
    /// Tokio runtime dedicated to Tor I/O.
    runtime: Runtime,
    /// Bootstrapped arti Tor client.
    client: Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>,
    /// Our mesh endpoint's Tor v3 `.onion` address (derived from the Tor
    /// root, §5.3 — never from the identity).
    pub onion_address: String,
    /// Per-peer circuit stats for rotation (isolation tokens + counters).
    circuit_stats: Mutex<HashMap<String, CircuitStats>>,
    /// Receiver of sync-side TcpStreams bridged from inbound hidden-service circuits.
    inbound_rx: Mutex<Option<std::sync::mpsc::Receiver<TcpStream>>>,
}

impl TorTransport {
    // ────────────────────────────────────────────────────────────────────
    // Construction
    // ────────────────────────────────────────────────────────────────────

    /// Bootstrap a Tor client, launch the hidden service, and return a ready
    /// `TorTransport`.
    ///
    /// `tor_root_secret`  — the independent Tor root (§5.3), never the identity key.
    /// `rotation_counter` — the mesh endpoint's current service-key rotation.
    /// `peer_id_hex`      — hex peer ID used to name the hidden service in arti's keystore.
    /// `state_dir`        — directory for arti's Tor state and descriptor cache.
    /// `listen_port`      — the TCP port advertised in the hidden service descriptor.
    ///
    /// Blocks the calling thread for the duration of Tor bootstrapping (typically
    /// a few seconds on a normal internet connection).
    pub fn bootstrap(
        tor_root_secret: &[u8; 32],
        rotation_counter: u64,
        peer_id_hex: &str,
        state_dir: &std::path::Path,
        listen_port: u16,
    ) -> anyhow::Result<Self> {
        let runtime = Runtime::new().context("create tokio runtime for Tor")?;

        // The mesh endpoint's onion address under the Tor root (§5.3).
        let service_id = MESH_ENDPOINT_SERVICE_ID;
        let onion_address = derive_onion_address(tor_root_secret, service_id, rotation_counter);

        // Configure arti storage in our state directory.
        let mut config_builder = arti_client::TorClientConfig::builder();
        {
            let storage = config_builder.storage();
            let cache = state_dir.join("tor_cache");
            let state = state_dir.join("tor_state");
            storage.cache_dir(arti_client::config::CfgPath::new(
                cache.to_string_lossy().into_owned(),
            ));
            storage.state_dir(arti_client::config::CfgPath::new(
                state.to_string_lossy().into_owned(),
            ));
        }
        let config = config_builder.build().context("build TorClientConfig")?;

        // Bootstrap inside the dedicated runtime.
        let client = runtime
            .block_on(async { arti_client::TorClient::create_bootstrapped(config).await })
            .context("Tor bootstrap")?;

        // --- Launch hidden service ---
        //
        // We use arti's built-in keystore to persist the HS keypair across
        // restarts.  The nickname encodes our peer ID so the keystore entry
        // is tied to this identity.
        let nickname_str = format!("mi{}", &peer_id_hex[..16]);
        let nickname = tor_hsservice::HsNickname::new(nickname_str)
            .unwrap_or_else(|_| tor_hsservice::HsNickname::new("meshinfinity".into()).unwrap());

        let mut hs_cfg_builder = tor_hsservice::config::OnionServiceConfigBuilder::default();
        hs_cfg_builder.nickname(nickname);
        let hs_config = hs_cfg_builder
            .build()
            .map_err(|e| anyhow::anyhow!("OnionServiceConfig: {e}"))?;

        let (inbound_tx, inbound_rx) = std::sync::mpsc::channel::<TcpStream>();

        {
            let client_for_hs = Arc::clone(&client);
            runtime.handle().spawn(async move {
                Self::run_hidden_service(client_for_hs, hs_config, listen_port, inbound_tx).await;
            });
        }

        Ok(Self {
            runtime,
            client,
            onion_address,
            circuit_stats: Mutex::new(HashMap::new()),
            inbound_rx: Mutex::new(Some(inbound_rx)),
        })
    }

    // ────────────────────────────────────────────────────────────────────
    // Hidden service task
    // ────────────────────────────────────────────────────────────────────

    async fn run_hidden_service(
        client: Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>,
        config: tor_hsservice::OnionServiceConfig,
        listen_port: u16,
        tx: std::sync::mpsc::Sender<TcpStream>,
    ) {
        use futures::StreamExt as _;

        let result = client.launch_onion_service(config);
        let (running, rend_stream) = match result {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                tracing::info!("Tor hidden service disabled in config");
                return;
            }
            Err(e) => {
                tracing::error!("Failed to launch Tor hidden service: {e}");
                return;
            }
        };
        let _keep_alive = running;

        let mut stream_reqs = tor_hsservice::handle_rend_requests(rend_stream);

        while let Some(req) = stream_reqs.next().await {
            // handle_rend_requests yields StreamRequest directly (no Result wrapper).
            // Only serve Begin (TCP) requests on the mesh port; reject everything else.
            let port = match req.request() {
                IncomingStreamRequest::Begin(b) => b.port(),
                _ => 0,
            };
            if port != listen_port {
                let _ = req
                    .reject(tor_cell::relaycell::msg::End::new_with_reason(
                        tor_cell::relaycell::msg::EndReason::DONE,
                    ))
                    .await;
                continue;
            }

            let tx2 = tx.clone();
            tokio::spawn(Self::accept_hs_stream(req, tx2));
        }
    }

    async fn accept_hs_stream(
        req: tor_hsservice::StreamRequest,
        tx: std::sync::mpsc::Sender<TcpStream>,
    ) {
        let tor_stream = match req
            .accept(tor_cell::relaycell::msg::Connected::new_empty())
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("Tor HS accept: {e}");
                return;
            }
        };

        // Create loopback bridge for the sync layer.
        let local_listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("Tor HS bridge bind: {e}");
                return;
            }
        };
        let local_addr = local_listener.local_addr().unwrap();

        // Connect sync side first so the upper layer can start processing.
        let sync_stream = match std::net::TcpStream::connect(local_addr) {
            Ok(s) => {
                let _ = s.set_nonblocking(true);
                s
            }
            Err(e) => {
                tracing::warn!("Tor HS bridge connect: {e}");
                return;
            }
        };

        if tx.send(sync_stream).is_err() {
            return; // upper layer dropped the receiver
        }

        let (local_stream, _) = match local_listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Tor HS bridge accept: {e}");
                return;
            }
        };

        let (mut local_r, mut local_w) = tokio::io::split(local_stream);
        let (mut tor_r, mut tor_w) = tokio::io::split(tor_stream);

        tokio::select! {
            _ = tokio::io::copy(&mut tor_r, &mut local_w) => {}
            _ = tokio::io::copy(&mut local_r, &mut tor_w) => {}
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Outbound connections
    // ────────────────────────────────────────────────────────────────────

    /// Open a TCP connection to a peer via the Tor network.
    ///
    /// Returns a non-blocking `TcpStream` backed by a Tor `DataStream`.
    /// The stream can be inserted directly into `MeshContext::clearnet_connections`.
    ///
    /// Circuit isolation: each peer uses its own `IsolationToken`, causing Tor
    /// to route each peer on a separate circuit (§5.3).
    pub fn connect(
        &self,
        peer_id_hex: &str,
        onion_addr: &str,
        port: u16,
    ) -> anyhow::Result<TcpStream> {
        let isolation = {
            let mut stats = self.circuit_stats.lock().unwrap_or_else(|e| e.into_inner());
            let entry = stats
                .entry(peer_id_hex.to_string())
                .or_insert_with(CircuitStats::new);
            if entry.should_rotate() {
                entry.rotate();
                tracing::debug!(peer=%peer_id_hex, "Tor: rotating circuit");
            }
            entry.isolation
        };

        // Loopback bridge.
        let local_listener =
            TcpListener::bind("127.0.0.1:0").context("bind Tor loopback bridge")?;
        let local_addr: SocketAddr = local_listener.local_addr()?;

        let client = Arc::clone(&self.client);
        let target = format!("{onion_addr}:{port}");

        self.runtime.handle().spawn(async move {
            let async_listener = tokio::net::TcpListener::from_std(local_listener).unwrap();
            let (local_stream, _) = match async_listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Tor bridge accept: {e}");
                    return;
                }
            };

            let mut prefs = arti_client::StreamPrefs::new();
            prefs.set_isolation(isolation);

            let tor_stream = match client.connect_with_prefs(&target as &str, &prefs).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Tor connect to {target}: {e}");
                    return;
                }
            };

            let (mut local_r, mut local_w) = tokio::io::split(local_stream);
            let (mut tor_r, mut tor_w) = tokio::io::split(tor_stream);

            tokio::select! {
                _ = tokio::io::copy(&mut tor_r, &mut local_w) => {}
                _ = tokio::io::copy(&mut local_r, &mut tor_w) => {}
            }
        });

        let stream = TcpStream::connect(local_addr).context("Tor bridge connect")?;
        stream
            .set_nonblocking(true)
            .context("Tor bridge nonblocking")?;
        Ok(stream)
    }

    // ────────────────────────────────────────────────────────────────────
    // Inbound poll
    // ────────────────────────────────────────────────────────────────────

    /// Drain any inbound connections from the hidden service.
    ///
    /// Returns a list of non-blocking `TcpStream`s ready for identification
    /// (the same pairing handshake flow as direct TCP connections).
    pub fn drain_inbound(&self) -> Vec<TcpStream> {
        let guard = self.inbound_rx.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(rx) = guard.as_ref() {
            let mut out = Vec::new();
            while let Ok(stream) = rx.try_recv() {
                out.push(stream);
            }
            out
        } else {
            Vec::new()
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Circuit rotation helpers
    // ────────────────────────────────────────────────────────────────────

    /// Record a sent message on `peer_id_hex`'s circuit counter.
    pub fn record_message(&self, peer_id_hex: &str) {
        let mut stats = self.circuit_stats.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = stats.get_mut(peer_id_hex) {
            s.message_count += 1;
        }
    }

    /// Remove circuit stats for a peer on disconnect.
    pub fn remove_peer(&self, peer_id_hex: &str) {
        self.circuit_stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(peer_id_hex);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::self_identity::SelfIdentity;
    use tempfile::TempDir;

    /// What the pre-§5.3 code derived the onion key from: HKDF of the
    /// identity master key with no salt and the bare info prefix.
    fn legacy_identity_derived_key(master_key: &[u8; 32]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, master_key);
        let mut okm = [0u8; 32];
        hk.expand(TOR_SERVICE_INFO, &mut okm).unwrap();
        okm
    }

    /// Whether `addr` is a well-formed v3 address: 56 base32 characters
    /// followed by `.onion` (the §4.5 transport-hint grammar).
    fn is_v3_onion(addr: &str) -> bool {
        let Some(body) = addr.strip_suffix(".onion") else {
            return false;
        };
        body.len() == 56 && body.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    }

    /// The service key is no longer the identity-derived value: neither
    /// the real derivation from the Tor root nor the old formula applied to
    /// the root reproduces what the master key used to yield, and the
    /// master key is not an input at all.
    #[test]
    fn service_key_is_not_the_identity_derived_value() {
        let identity = SelfIdentity::generate(None);
        let legacy = legacy_identity_derived_key(&identity.master_key);
        let service = derive_tor_service_key(
            &identity.tor_root_secret,
            MESH_ENDPOINT_SERVICE_ID,
            identity.tor_rotation_counter,
        );
        assert_ne!(service.to_bytes(), legacy, "key is master-key derived");
        assert_ne!(
            service.to_bytes(),
            *identity.tor_root_secret,
            "root is never used directly"
        );
        // Even misusing the master key as the root does not recover the old
        // key: the derivation itself (salt, info layout) changed.
        let misuse = derive_tor_service_key(&identity.master_key, MESH_ENDPOINT_SERVICE_ID, 0);
        assert_ne!(misuse.to_bytes(), legacy);
        // Two identities' roots give unrelated addresses; one root is stable.
        let other = SelfIdentity::generate(None);
        let addr = derive_onion_address(&identity.tor_root_secret, MESH_ENDPOINT_SERVICE_ID, 0);
        assert_ne!(
            addr,
            derive_onion_address(&other.tor_root_secret, MESH_ENDPOINT_SERVICE_ID, 0)
        );
        assert_eq!(
            addr,
            derive_onion_address(&identity.tor_root_secret, MESH_ENDPOINT_SERVICE_ID, 0)
        );
        assert!(is_v3_onion(&addr), "not a v3 onion address: {addr}");
    }

    /// Services under one root, and rotations of one service, have
    /// independent addresses (§5.3), and the fixed-width counter keeps a
    /// service id from aliasing another id plus counter bytes.
    #[test]
    fn services_and_rotations_get_independent_addresses() {
        let root = [0x5Au8; 32];
        let endpoint = derive_onion_address(&root, MESH_ENDPOINT_SERVICE_ID, 0);
        let file_share = derive_onion_address(&root, b"file-share", 0);
        let rotated = derive_onion_address(&root, MESH_ENDPOINT_SERVICE_ID, 1);
        assert_ne!(endpoint, file_share);
        assert_ne!(endpoint, rotated);
        assert_ne!(file_share, rotated);
        // `mesh-endpoint` with counter 1 is not `mesh-endpoint\0..\x01` with counter 0.
        let mut aliased = MESH_ENDPOINT_SERVICE_ID.to_vec();
        aliased.extend_from_slice(&1u64.to_be_bytes());
        assert_ne!(rotated, derive_onion_address(&root, &aliased, 0));
        assert!(is_v3_onion(&endpoint));
        assert!(is_v3_onion(&file_share));
        assert!(is_v3_onion(&rotated));
    }

    /// The onion address an identity advertises survives a restart: the
    /// root reloaded from `identity.dat` derives the same address.
    #[test]
    fn onion_address_survives_identity_restart() {
        let dir = TempDir::new().unwrap();
        let identity = SelfIdentity::generate(Some("Node".into()));
        let before = derive_onion_address(
            &identity.tor_root_secret,
            MESH_ENDPOINT_SERVICE_ID,
            identity.tor_rotation_counter,
        );
        identity.save_to_disk(dir.path(), None).expect("save");
        drop(identity);
        let reloaded = SelfIdentity::load_from_disk(dir.path(), None).expect("load");
        let after = derive_onion_address(
            &reloaded.tor_root_secret,
            MESH_ENDPOINT_SERVICE_ID,
            reloaded.tor_rotation_counter,
        );
        assert_eq!(before, after, "onion address must survive restart");
    }
}
