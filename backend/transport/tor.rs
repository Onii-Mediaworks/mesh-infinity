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
//! The spec requires a deterministic onion address derived from the mesh
//! identity.  We derive an ed25519 keypair from the identity master key:
//!
//! ```text
//! ikm  = identity.master_key (32 bytes)
//! info = "meshinfinity-tor-service-v1"
//! okm  = 32 bytes  →  ed25519 signing key → onion pubkey → .onion address
//! ```
//!
//! The resulting `.onion` address is stable across restarts.  It is included
//! in the node's network map `transport_hints` so peers can connect via Tor.
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
use tor_proto::client::stream::IncomingStreamRequest;

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

/// Derive the Tor service ed25519 signing key from the identity master key.
///
/// HKDF-SHA256 with fixed info for domain separation (§5.3).
pub fn derive_tor_signing_key(master_key: &[u8; 32]) -> ed25519_dalek::SigningKey {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];
    hk.expand(b"meshinfinity-tor-service-v1", &mut okm)
        .expect("HKDF output length is valid");
    ed25519_dalek::SigningKey::from_bytes(&okm)
}

/// Derive our stable Tor v3 `.onion` address from the identity master key.
pub fn derive_onion_address(master_key: &[u8; 32]) -> String {
    let signing_key = derive_tor_signing_key(master_key);
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
    /// Our stable Tor v3 `.onion` address (derived from identity).
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
    /// `master_key`  — identity master key used to derive the onion address.
    /// `peer_id_hex` — hex peer ID used to name the hidden service in arti's keystore.
    /// `state_dir`   — directory for arti's Tor state and descriptor cache.
    /// `listen_port` — the TCP port advertised in the hidden service descriptor.
    ///
    /// Blocks the calling thread for the duration of Tor bootstrapping (typically
    /// a few seconds on a normal internet connection).
    pub fn bootstrap(
        master_key: &[u8; 32],
        peer_id_hex: &str,
        state_dir: &std::path::Path,
        listen_port: u16,
    ) -> anyhow::Result<Self> {
        let runtime = Runtime::new().context("create tokio runtime for Tor")?;

        // Derive stable onion address from identity master key.
        let onion_address = derive_onion_address(master_key);

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
        let client = Arc::new(client);

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
        let hs_config = hs_cfg_builder.build()
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
                let _ = req.reject(tor_cell::relaycell::msg::End::new_with_reason(
                    tor_cell::relaycell::msg::EndReason::DONE,
                )).await;
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

        let tor_stream = match req.accept(
            tor_cell::relaycell::msg::Connected::new_empty()
        ).await {
            Ok(s) => s,
            Err(e) => { tracing::debug!("Tor HS accept: {e}"); return; }
        };

        // Create loopback bridge for the sync layer.
        let local_listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => { tracing::warn!("Tor HS bridge bind: {e}"); return; }
        };
        let local_addr = local_listener.local_addr().unwrap();

        // Connect sync side first so the upper layer can start processing.
        let sync_stream = match std::net::TcpStream::connect(local_addr) {
            Ok(s) => { let _ = s.set_nonblocking(true); s }
            Err(e) => { tracing::warn!("Tor HS bridge connect: {e}"); return; }
        };

        if tx.send(sync_stream).is_err() {
            return; // upper layer dropped the receiver
        }

        let (local_stream, _) = match local_listener.accept().await {
            Ok(v) => v,
            Err(e) => { tracing::warn!("Tor HS bridge accept: {e}"); return; }
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
            let mut stats = self.circuit_stats.lock().unwrap();
            let entry = stats.entry(peer_id_hex.to_string()).or_insert_with(CircuitStats::new);
            if entry.should_rotate() {
                entry.rotate();
                tracing::debug!(peer=%peer_id_hex, "Tor: rotating circuit");
            }
            entry.isolation
        };

        // Loopback bridge.
        let local_listener = TcpListener::bind("127.0.0.1:0")
            .context("bind Tor loopback bridge")?;
        let local_addr: SocketAddr = local_listener.local_addr()?;

        let client = Arc::clone(&self.client);
        let target = format!("{onion_addr}:{port}");

        self.runtime.handle().spawn(async move {
            let async_listener = tokio::net::TcpListener::from_std(local_listener).unwrap();
            let (local_stream, _) = match async_listener.accept().await {
                Ok(v) => v,
                Err(e) => { tracing::warn!("Tor bridge accept: {e}"); return; }
            };

            let mut prefs = arti_client::StreamPrefs::new();
            prefs.set_isolation(isolation);

            let tor_stream = match client.connect_with_prefs(&target as &str, &prefs).await {
                Ok(s) => s,
                Err(e) => { tracing::warn!("Tor connect to {target}: {e}"); return; }
            };

            let (mut local_r, mut local_w) = tokio::io::split(local_stream);
            let (mut tor_r, mut tor_w) = tokio::io::split(tor_stream);

            tokio::select! {
                _ = tokio::io::copy(&mut tor_r, &mut local_w) => {}
                _ = tokio::io::copy(&mut local_r, &mut tor_w) => {}
            }
        });

        let stream = TcpStream::connect(local_addr).context("Tor bridge connect")?;
        stream.set_nonblocking(true).context("Tor bridge nonblocking")?;
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
        let guard = self.inbound_rx.lock().unwrap();
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
        let mut stats = self.circuit_stats.lock().unwrap();
        if let Some(s) = stats.get_mut(peer_id_hex) {
            s.message_count += 1;
        }
    }

    /// Remove circuit stats for a peer on disconnect.
    pub fn remove_peer(&self, peer_id_hex: &str) {
        self.circuit_stats.lock().unwrap().remove(peer_id_hex);
    }
}
