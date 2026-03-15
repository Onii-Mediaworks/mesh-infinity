//! High-level backend service orchestration for Mesh Infinity.
//!
//! This module exposes the primary stateful service used by UI/FFI callers.
//! It coordinates peer management, messaging, file transfer queues, trust
//! relationships, transport preferences, passive fallback delivery, and runtime
//! mode transitions.
//!
//! # What is this module?
//!
//! Think of `MeshInfinityService` as the "brain" of the whole application.
//! Every action the Flutter UI takes — sending a message, pairing with a new
//! peer, queuing a file upload, toggling Tor on — ultimately calls a method on
//! this service. The service then coordinates all the specialised subsystems
//! (crypto, routing, discovery, file transfers, etc.) to make that action happen.
//!
//! # How is this module organised?
//!
//! The service is large, so its methods are split across child modules in the
//! same directory. Each child module (`messaging.rs`, `peers.rs`, etc.) adds
//! its own `impl MeshInfinityService { ... }` block. Rust collects them all
//! into one type at compile time. This file (`mod.rs`) defines:
//!
//! - The shared *data structures* (`ServiceState`, `MeshInfinityService`, etc.)
//! - The *constructor* (`MeshInfinityService::new`)
//! - Small *utility helpers* used by multiple child modules
//! - The *test suite* that exercises the whole service together
//!
//! # Thread safety — a brief primer
//!
//! Mesh Infinity runs multiple threads simultaneously:
//! - The Flutter/UI thread calls FFI methods.
//! - A background routing worker thread drains the outbound message queue.
//! - Potentially more threads for transports (Tor, I2P, etc.).
//!
//! Any data shared across threads must be protected. Rust enforces this at
//! compile time: if you try to share unprotected data across threads, the
//! compiler will refuse to compile. The main tools used here are:
//!
//! - **`Arc<T>`** — "Atomically Reference Counted". Lets multiple owners share
//!   the same heap-allocated value. Think of it as a reference-counting smart
//!   pointer that works safely across threads. Cloning an `Arc` gives you a new
//!   pointer to the same data — it does NOT copy the data.
//!
//! - **`RwLock<T>`** — "Read-Write Lock". Multiple threads can READ simultaneously
//!   (`rw_lock.read()`), but only ONE thread at a time can WRITE (`rw_lock.write()`).
//!   This is ideal for state that is read often but written rarely.
//!
//! - **`Mutex<T>`** — "Mutual Exclusion". Only ONE thread at a time can access
//!   the value at all (whether reading or writing). Simpler than `RwLock` and
//!   appropriate when reads and writes are equally rare.
//!
//! - **`AtomicBool`** — a boolean that can be read and written safely by multiple
//!   threads simultaneously without any lock, because the CPU guarantees that
//!   each read-modify-write is indivisible.

// ---------------------------------------------------------------------------
// External imports
// ---------------------------------------------------------------------------
//
// `use` statements bring names from other crates or modules into scope.
// Think of them like `import` in Python or Dart.

// `crossbeam_channel::Sender` — a thread-safe "end" of a message channel.
// A channel has a `Sender` (the sending end) and a `Receiver` (the reading end).
// We use channels to notify the UI when new messages or file-transfer updates arrive.
use crossbeam_channel::Sender;

// Standard library data structures.
// `HashMap<K, V>` — a hash table mapping keys of type K to values of type V.
//   Used here to map room IDs → message lists, peer IDs → passive outboxes, etc.
// `VecDeque<T>` — a double-ended queue (add/remove from either end efficiently).
//   Used for the bounded acknowledgement history.
use std::collections::{HashMap, VecDeque};

// Atomic types for lock-free flags (see `AtomicBool` primer above).
// `Ordering` controls the memory-ordering semantics of atomic operations.
use std::sync::atomic::{AtomicBool, Ordering};

// Standard synchronisation primitives.
// `Arc`   — thread-safe shared ownership (see primer above).
// `Mutex` — exclusive lock (see primer above).
// `RwLock`— read-write lock (see primer above).
use std::sync::{Arc, Mutex, RwLock};

// `JoinHandle` — a handle to a running thread; calling `.join()` on it waits
// for that thread to finish.
use std::thread::JoinHandle;

// Time utilities.
// `Duration` — a span of time (e.g. "7 days").
// `SystemTime` — an absolute point in time (like an OS clock reading).
use std::time::{Duration, SystemTime};

// Our own subsystem types, imported from sibling crates/modules.

// `IdentityManager` — manages the node's cryptographic identity (key pairs).
use crate::auth::identity::IdentityManager;

// `WotIdentity` and `WebOfTrust` — the "web of trust" subsystem.
// A web of trust is a decentralised way of deciding how much to trust a peer:
// if peers YOU trust say they trust peer X, you might extend some trust to X too.
use crate::auth::web_of_trust::{Identity as WotIdentity, WebOfTrust};

// Core mesh types used throughout the service.
use crate::core::core::{MeshConfig, PeerId, TransportType, TrustLevel as CoreTrustLevel};

// Our custom error/result types.
use crate::core::error::{MeshInfinityError, Result};

// File transfer management types.
// `FileTransferManager` — orchestrates queuing, progress tracking, and completion.
// `TransferDirection` — Send or Receive.
// `TransferItem` — represents one file transfer in progress.
// `TransferStatus` — Queued / InProgress / Completed / Failed / Canceled.
use crate::core::file_transfer::{
    FileTransferManager, TransferDirection, TransferItem, TransferStatus,
};

// Mesh message routing types.
// `EncryptedPayload` — an encrypted blob ready to be sent.
// `Endpoint`         — a (peer_id, address) pair describing where to send.
// `MessagePriority`  — how urgently to process a message.
// `MessageRouter`    — the subsystem that takes outbound messages and delivers them.
// `OutboundMessage`  — a message queued for delivery (payload + routing metadata).
// `PathInfo`         — describes one possible route to a peer (transport + endpoint).
// `PeerManager`      — tracks known peers and their capabilities/trust levels.
use crate::core::mesh::{
    EncryptedPayload, Endpoint, MessagePriority, MessageRouter, OutboundMessage, PathInfo,
    PeerManager,
};

// Cryptography subsystems.
// `MessageCrypto` — encrypts/decrypts individual message payloads.
// `PfsManager`    — manages Perfect Forward Secrecy sessions.
//   PFS means: even if an attacker records all traffic NOW and later steals
//   a long-term private key, they CANNOT decrypt past messages because each
//   session used a fresh ephemeral key that has since been deleted.
use crate::crypto::{MessageCrypto, PfsManager};

// Network-level peer discovery service (mDNS / local broadcast / etc.).
use crate::discovery::DiscoveryService;

// The concrete implementation of the transport manager — the subsystem that
// actually sends bytes over Tor, I2P, Bluetooth, clearnet, etc.
use crate::transport::TransportManagerImpl;

// `fill` fills a byte slice with cryptographically random bytes from the OS.
use getrandom::fill;

// `digest` computes a cryptographic hash. `SHA256` is the algorithm.
// SHA-256 produces a fixed 32-byte "fingerprint" of any input — even a tiny
// change to the input produces a completely different fingerprint.
use ring::digest::{digest, SHA256};

// Time formatting for human-readable timestamps shown in the UI.
use time::format_description;

// ---------------------------------------------------------------------------
// Child module declarations
// ---------------------------------------------------------------------------
//
// Each `mod foo;` tells Rust to look for `backend/service/foo.rs` and include
// it as a child module named `foo`. The methods defined in those files are all
// `impl MeshInfinityService { ... }` blocks that extend this type.

/// Peer discovery (mDNS, local broadcast, manual entry).
mod discovery;

/// File transfer operations (queue, progress, cancel).
mod file_transfers;

/// Hosted service configuration and access-control policy.
mod hosted_services;

/// Service lifecycle: start, stop, mode transitions (see `lifecycle.rs`).
mod lifecycle;

/// Messaging operations: send, receive, rooms, history.
mod messaging;

/// Network statistics and counters.
mod metrics;

/// Passive fallback delivery (store-and-forward when peers are offline).
mod passive;

/// Peer management: pair, list, trust updates, QR code exchange.
mod peers;

/// Settings read/write (transport toggles, node mode, etc.).
mod settings;

/// Trust management: promote/demote peer trust levels.
mod trust;

/// Public data types shared between the service and its callers (see `types.rs`).
mod types;

// Re-export the public types from `types.rs` so that callers who depend on
// `service` don't need to know about the internal module structure. They can
// just write `use service::Message` instead of `use service::types::Message`.
pub use types::{
    FileTransferSummary, HostedServicePolicy, HostedServiceSummary, IdentitySummary, LocalProfile,
    Message, NetworkStatsSummary, NodeMode, PeerSummary, PreloadedIdentity, ReconnectSyncSnapshot,
    RoomSummary, ServiceConfig, Settings,
};

// ---------------------------------------------------------------------------
// ServiceState — the mutable heart of the service
// ---------------------------------------------------------------------------

/// All runtime-mutable state belonging to the service, bundled into one struct.
///
/// This struct is wrapped in `Arc<RwLock<ServiceState>>` (see `MeshInfinityService`
/// below). That combination means:
/// - `Arc`    — the state can be owned by multiple threads simultaneously.
/// - `RwLock` — only one thread may write at a time; many may read simultaneously.
///
/// Bundling everything into one struct keeps the locking straightforward: to
/// read any piece of state, acquire one read lock; to write any piece, acquire
/// one write lock. The trade-off is that an unrelated write (e.g. updating
/// `bytes_sent`) briefly blocks an unrelated read (e.g. listing rooms).
/// For a service of this scale that is an acceptable simplification.
struct ServiceState {
    /// All chat rooms this node participates in, in display order.
    /// Each `RoomSummary` holds just the headline view (name, last message, etc.).
    rooms: Vec<RoomSummary>,

    /// Full message history, keyed by room ID.
    /// `HashMap<room_id, Vec<Message>>` — for each room, a list of all messages
    /// in chronological order.
    messages: HashMap<String, Vec<Message>>,

    /// Summary view of all known peers, used to populate the Peers tab.
    peers: Vec<PeerSummary>,

    /// The room ID that the user is currently viewing (if any).
    /// `None` means no room is selected (the list view is showing).
    active_room_id: Option<String>,

    /// Current user-visible settings (transports, node mode, pairing code, etc.).
    settings: Settings,

    /// Low-level mesh networking configuration (transport parameters, relay rules).
    mesh_config: MeshConfig,

    /// Map from hosted-service ID to its configuration summary.
    /// Hosted services are local network services exposed to trusted mesh peers.
    hosted_services: HashMap<String, HostedServiceSummary>,

    /// Optional VPN routing configuration string (reserved for future use).
    vpn_route_config: Option<String>,

    /// Optional clearnet routing configuration string (reserved for future use).
    clearnet_route_config: Option<String>,

    /// Running total of bytes sent across all transports since startup.
    bytes_sent: u64,

    /// Running total of bytes received across all transports since startup.
    bytes_received: u64,

    /// The passive fallback outbox: messages waiting to be delivered to peers
    /// who are currently offline.
    ///
    /// Key = peer ID (`PeerId` = `[u8; 32]`).
    /// Value = a bounded list of `PassiveEnvelope`s (encrypted, deduplicated,
    ///         time-limited message blobs waiting for that peer to come online).
    passive_outbox: HashMap<PeerId, Vec<PassiveEnvelope>>,

    /// Per-peer history of delivery "keys" that have already been acknowledged.
    ///
    /// When a peer comes back online and we deliver the passive outbox to them,
    /// we record the dedupe key of each delivered envelope here. If the same
    /// message is somehow generated again (e.g. the user retypes the same text),
    /// we won't re-queue it — we know the peer already received it.
    ///
    /// `VecDeque` is used instead of `Vec` so we can efficiently discard the
    /// OLDEST acknowledgements when the history grows too large (front removal
    /// is O(1) for a `VecDeque`, but O(n) for a plain `Vec`).
    passive_acked: HashMap<PeerId, VecDeque<String>>,

    /// Channels to notify the UI when a new message arrives in real time.
    ///
    /// The FFI layer can subscribe by calling a "set listener" function, which
    /// pushes a `Sender` handle here. When a message arrives, the service
    /// iterates this list and sends a copy of the message to each subscriber.
    /// The Flutter side holds the `Receiver` end and awaits new items.
    message_listeners: Vec<Sender<Message>>,

    /// Channels to notify the UI when a file transfer's progress changes.
    /// Same pattern as `message_listeners`.
    transfer_listeners: Vec<Sender<FileTransferSummary>>,
}

// ---------------------------------------------------------------------------
// PassiveEnvelope — a stored-and-forward message blob
// ---------------------------------------------------------------------------

/// An encrypted, time-limited message blob held in the passive outbox.
///
/// When this node tries to send a message to a peer but the peer is offline
/// (no active transport path exists), the message is not dropped. Instead it
/// is encrypted and stored here until the peer comes back online, at which
/// point we deliver the stored envelopes and clear the queue.
///
/// All fields are prefixed with `_` because they are currently accessed only
/// through the struct as a whole (the Rust compiler would otherwise warn
/// "field is never read" for fields accessed by reference in tests).
///
/// `#[derive(Clone, Debug)]` — lets Rust copy the struct and print it for
/// debugging.
#[derive(Clone, Debug)]
struct PassiveEnvelope {
    /// Unique random ID for this envelope (format: `"passive-XXXXXXXXXXXXXXXX"`).
    _id: String,

    /// The wall-clock time when this envelope was created.
    /// Used together with `_expires_at` to check if the envelope is stale.
    _created_at: SystemTime,

    /// The wall-clock time after which this envelope should be discarded,
    /// even if the peer never came online to receive it.
    /// Default retention is `PASSIVE_RETENTION_SECS` (7 days).
    _expires_at: SystemTime,

    /// A collision-resistant fingerprint (SHA-256 hash) of the target peer ID
    /// and the plaintext payload. Used to prevent the same message from being
    /// stored twice in the outbox for the same peer.
    _dedupe_key: String,

    /// The encrypted ciphertext of the original payload.
    /// The plaintext is NEVER stored — only this opaque blob.
    /// Even if someone inspects process memory or a crash dump, they will
    /// not find the original message content here.
    _ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Module-level constants
// ---------------------------------------------------------------------------

/// How long (in seconds) a passive envelope is retained before being discarded.
/// 7 days = 7 * 24 hours * 60 minutes * 60 seconds = 604,800 seconds.
const PASSIVE_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

/// Maximum number of pending envelopes kept per peer.
/// If a peer is offline long enough that 64 messages pile up, the oldest
/// messages are dropped to make room for newer ones. This bounds memory usage.
const MAX_PASSIVE_ENVELOPES_PER_PEER: usize = 64;

/// Maximum number of acknowledgement keys kept per peer in `passive_acked`.
/// After 256 entries the oldest are discarded. This prevents unbounded growth.
const MAX_PASSIVE_ACK_HISTORY: usize = 256;

// ---------------------------------------------------------------------------
// MeshInfinityService — the top-level service struct
// ---------------------------------------------------------------------------

/// The primary backend service for Mesh Infinity.
///
/// This struct is the single object that the FFI layer (`backend/ffi/lib.rs`)
/// holds onto for the lifetime of the application. Flutter calls Rust functions
/// that receive a pointer to this struct (wrapped in an opaque `Context` type)
/// and dispatch to its methods.
///
/// Each field is described below. Where a field is wrapped in `Arc`, that
/// means it is shared with the routing worker thread spawned in `lifecycle.rs`.
pub struct MeshInfinityService {
    /// All mutable application state — rooms, messages, peers, settings, etc.
    ///
    /// Wrapped in `Arc<RwLock<...>>` so it can be safely shared and mutated
    /// across the UI thread, the routing worker thread, and any transport threads.
    /// The `RwLock` allows many simultaneous readers but only one writer.
    state: Arc<RwLock<ServiceState>>,

    /// Tracks all known peers: their capabilities, available transports, and
    /// trust levels. Internally thread-safe (uses its own locking).
    peers: PeerManager,

    /// Manages the node's cryptographic identity (Ed25519 signing key pair,
    /// X25519 Diffie-Hellman key pair, optional display name).
    ///
    /// `pub(super)` means this field is accessible to child modules in the
    /// same directory (e.g. `trust.rs`, `settings.rs`) but NOT to external callers.
    pub(super) identity_manager: IdentityManager,

    /// The web-of-trust graph: which peers this node has endorsed, which peers
    /// peers have endorsed, and the resulting composite trust scores.
    pub(super) web_of_trust: WebOfTrust,

    /// Manages all active and pending file transfers.
    ///
    /// Wrapped in `Arc<Mutex<...>>` rather than using the shared `state` lock,
    /// so that file-transfer progress updates (which happen frequently during
    /// large transfers) don't block unrelated operations like sending messages.
    file_transfers: Arc<Mutex<FileTransferManager>>,

    /// The transport layer: manages Tor, I2P, Bluetooth, clearnet, and RF
    /// connections. Responsible for actually sending bytes over the network.
    transport_manager: TransportManagerImpl,

    /// Routes outbound messages through the available transport paths.
    ///
    /// Wrapped in `Arc` because the routing worker thread (spawned in
    /// `lifecycle.rs`) holds its own clone of this pointer and calls
    /// `router.process_queue()` every 50 ms.
    message_router: Arc<MessageRouter>,

    /// Manages Perfect Forward Secrecy (PFS) sessions.
    ///
    /// PFS generates a fresh ephemeral key pair for every session with every
    /// peer. Old session keys are deleted after use, so past traffic cannot be
    /// decrypted even if a long-term key is later compromised.
    ///
    /// `Arc<Mutex<...>>` because both the message-send path (UI thread) and
    /// potentially the routing worker can create new PFS sessions.
    pfs_manager: Arc<Mutex<PfsManager>>,

    /// Encrypts and decrypts individual message payloads using the session
    /// keys produced by the `pfs_manager`.
    ///
    /// `Arc<Mutex<...>>` for the same reason as `pfs_manager`.
    message_crypto: Arc<Mutex<MessageCrypto>>,

    /// Atomic flag indicating whether the routing worker thread is (should be)
    /// running. `AtomicBool` is used instead of a `Mutex<bool>` because atomic
    /// operations are cheaper and sufficient for a simple on/off flag.
    ///
    /// Wrapped in `Arc` so the worker thread can read the flag to know when to stop.
    running: Arc<AtomicBool>,

    /// A handle to the routing worker thread, if one is currently running.
    ///
    /// `Mutex<Option<JoinHandle<()>>>`:
    /// - `Mutex` — only one thread at a time should start or stop the worker.
    /// - `Option` — `None` when the worker is not running; `Some(handle)` when it is.
    /// - `JoinHandle<()>` — lets us call `.join()` to wait for the thread to exit.
    routing_worker: Mutex<Option<JoinHandle<()>>>,

    /// The peer discovery service: listens for mDNS announcements on the local
    /// network so peers on the same Wi-Fi can be found automatically.
    ///
    /// `Arc<Mutex<...>>` so that discovery can be started/stopped independently
    /// of other service operations.
    discovery: Arc<Mutex<DiscoveryService>>,

    /// `true` once the identity has been explicitly saved to disk.
    ///
    /// On first launch, an identity is generated in memory and `identity_persisted`
    /// is `false`. The onboarding screen is shown. After the user completes
    /// onboarding and the identity is written to encrypted storage, this becomes
    /// `true`, and subsequent launches will skip onboarding.
    pub(super) identity_persisted: bool,

    /// Local profile fields (display name visibility, private bio, etc.).
    /// See `LocalProfile` in `types.rs` for the full description.
    pub(super) local_profile: LocalProfile,
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl MeshInfinityService {
    /// Construct a fully wired service instance from caller configuration.
    ///
    /// This is the only way to create a `MeshInfinityService`. It performs every
    /// initialisation step in a specific order; understanding that order is key
    /// to understanding the service as a whole.
    ///
    /// **Step 1 — Identity**
    ///
    /// If `config.preloaded_identity` is `Some`, the service restores the
    /// existing identity from its serialised key material and marks it as
    /// persisted (onboarding is skipped on the next UI frame). Otherwise a
    /// fresh identity is generated in memory and `identity_persisted` is `false`
    /// (onboarding will be shown so the user can name themselves and save their keys).
    ///
    /// **Step 2 — Web of Trust**
    ///
    /// The identity is registered in the web-of-trust graph as the root node
    /// (this device trusts itself implicitly).
    ///
    /// **Step 3 — Pairing code**
    ///
    /// A short human-friendly code (e.g. `"A1B2-C3D4-E5F6-7890"`) is derived
    /// from the first 8 bytes of the peer ID and stored in `settings.pairing_code`.
    ///
    /// **Step 4 — Transport manager**
    ///
    /// Each transport (Tor, I2P, Bluetooth, clearnet, RF) is enabled or disabled
    /// according to `config.mesh_config`.
    ///
    /// **Step 5 — Crypto subsystems**
    ///
    /// A `PfsManager` (Perfect Forward Secrecy) and a `MessageCrypto` (payload
    /// encryption) are initialised. If key generation fails for any reason, a
    /// deterministic fallback derived from the peer ID is used so the service
    /// can always start — even in degraded environments.
    ///
    /// **Step 6 — Message router**
    ///
    /// The `MessageRouter` is wired to the transport manager and given the local
    /// peer ID so it knows how to address outbound messages.
    ///
    /// **Step 7 — State initialisation**
    ///
    /// The `ServiceState` struct is filled with empty collections and the
    /// settings derived from `config`. It is then wrapped in `Arc<RwLock<...>>`
    /// for shared, thread-safe access.
    ///
    /// **Step 8 — Auto-start**
    ///
    /// If the initial mode is `Server` or `Dual`, the routing worker thread is
    /// started immediately. `Client` mode starts with the worker off.
    pub fn new(config: ServiceConfig) -> Self {
        // --- Step 1: Identity ---

        let mut identity_manager = IdentityManager::new();

        // `if let Some(ref preloaded) = config.preloaded_identity` is pattern
        // matching: if the optional field is present (`Some`), bind it to
        // `preloaded` and execute the first branch; otherwise execute `else`.
        //
        // The three-tuple `(peer_id, persisted, profile)` is returned from
        // both branches, so `identity_peer_id`, `identity_persisted`, and
        // `local_profile` all get their values from whichever branch runs.
        let (identity_peer_id, identity_persisted, local_profile) =
            if let Some(ref preloaded) = config.preloaded_identity {
                // Restore an existing identity from the saved secret key bytes.
                // `.unwrap_or_else(|_| random_peer_id())` means: if loading fails
                // for any reason, fall back to a freshly generated random peer ID
                // rather than panicking. Robustness over perfection.
                let peer_id = identity_manager
                    .load_identity(
                        &preloaded.ed25519_secret,
                        &preloaded.x25519_secret,
                        preloaded.name.clone(),
                    )
                    .unwrap_or_else(|_| random_peer_id());
                (peer_id, true, preloaded.profile.clone())
            } else {
                // Generate a brand-new identity (first launch or explicit reset).
                let peer_id = identity_manager
                    .generate_identity(config.identity_name.clone())
                    .unwrap_or_else(|_| random_peer_id());
                (peer_id, false, LocalProfile::default())
            };

        // --- Step 2: Web of Trust ---

        // Build the `WotIdentity` (the web-of-trust representation of this node)
        // from the newly created or restored identity manager.
        //
        // `.map(|identity| ...)` transforms the `Option<PrimaryIdentity>` returned
        // by `get_primary_identity()` by extracting just the fields WOT needs.
        // `.unwrap_or_else(|| ...)` provides a fallback if no primary identity
        // is available (should not happen in practice, but is defensive).
        let wot_identity = identity_manager
            .get_primary_identity()
            .map(|identity| WotIdentity {
                peer_id: identity.peer_id,
                // `.verifying_key().to_bytes()` extracts the 32-byte PUBLIC key
                // from the signing key pair. The private half is never exposed here.
                public_key: identity.signing_key.verifying_key().to_bytes(),
                name: identity.name.clone(),
            })
            .unwrap_or_else(|| WotIdentity {
                peer_id: identity_peer_id,
                public_key: [0u8; 32], // Zeroed key as a safe fallback sentinel.
                name: config.identity_name.clone(),
            });

        // Register this node as the root of the web of trust.
        let web_of_trust = WebOfTrust::with_identity(wot_identity);

        // --- Step 3: Pairing code ---

        // Derive a short, human-typeable code from the first 8 bytes of the
        // peer ID. Format: "XXXX-XXXX-XXXX-XXXX" (16 uppercase hex digits, dashes
        // every 4 characters). Used for QR-code-free manual peer pairing.
        let pairing_code = pairing_code_from_peer_id(&identity_peer_id);

        // --- Step 4: Transport manager ---

        let mesh_config = config.mesh_config;
        let transport_manager = TransportManagerImpl::new();

        // Configure each transport individually based on the mesh config.
        // This does not yet establish any connections — it just registers
        // which transports are available for the router to use.
        transport_manager.set_tor_enabled(mesh_config.enable_tor);
        transport_manager.set_clearnet_enabled(mesh_config.enable_clearnet);
        transport_manager.set_i2p_enabled(mesh_config.enable_i2p);
        transport_manager.set_bluetooth_enabled(mesh_config.enable_bluetooth);
        transport_manager.set_rf_enabled(mesh_config.enable_rf);

        // --- Step 5: Crypto subsystems ---

        // PfsManager parameters:
        //   - Session lifetime: 1 hour (60 * 60 seconds). After an hour, a new
        //     ephemeral key pair is generated for that peer. Old keys are deleted.
        //   - Maximum concurrent sessions: 8. Beyond this, the oldest session is
        //     evicted to prevent unbounded memory growth.
        let pfs_manager = Arc::new(Mutex::new(PfsManager::new(Duration::from_secs(60 * 60), 8)));

        // MessageCrypto generates its own Ed25519 signing key for payload signing.
        // If generation fails (e.g. on a system with a broken RNG), we construct
        // a deterministic fallback from the peer ID bytes. This is NOT cryptographically
        // ideal but keeps the service functional in edge environments (e.g. a
        // constrained embedded device). A comment in the code flags this explicitly.
        let message_crypto = Arc::new(Mutex::new(MessageCrypto::generate().unwrap_or_else(|_| {
            // Deterministic fallback only for service bootstrap resilience.
            let mut seed = [0u8; 32];
            // Copy as many bytes of the peer ID into the seed as fit (32 bytes in, 32 bytes seed).
            seed[..identity_peer_id.len()].copy_from_slice(&identity_peer_id);
            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            MessageCrypto::new(signing_key, seed)
        })));

        // --- Step 6: Message router ---

        // `transport_manager.get_manager()` returns the inner transport manager
        // object that the router needs to actually dispatch bytes over the network.
        let message_router = Arc::new(MessageRouter::new(
            transport_manager.get_manager(),
            identity_peer_id,
        ));

        // --- Step 7: State initialisation ---

        // Build the initial ServiceState with empty collections and settings
        // derived from the mesh config.
        let state = ServiceState {
            rooms: Vec::new(),
            messages: HashMap::new(),
            peers: Vec::new(),
            active_room_id: None,
            settings: Settings {
                node_mode: config.initial_mode,
                enable_tor: mesh_config.enable_tor,
                enable_clearnet: mesh_config.enable_clearnet,
                mesh_discovery: mesh_config.mesh_discovery,
                allow_relays: mesh_config.allow_relays,
                enable_i2p: mesh_config.enable_i2p,
                enable_bluetooth: mesh_config.enable_bluetooth,
                enable_rf: mesh_config.enable_rf,
                pairing_code,
                // Convert the 32-byte peer ID to a 64-character uppercase hex string.
                local_peer_id: peer_id_string(&identity_peer_id),
            },
            mesh_config,
            hosted_services: HashMap::new(),
            vpn_route_config: None,
            clearnet_route_config: None,
            bytes_sent: 0,
            bytes_received: 0,
            passive_outbox: HashMap::new(),
            passive_acked: HashMap::new(),
            message_listeners: Vec::new(),
            transfer_listeners: Vec::new(),
        };

        // Assemble the fully wired service.
        // `Arc::new(RwLock::new(state))` wraps the state struct in a read-write lock
        // and then in an Arc, making it safe to share across threads.
        let service = Self {
            state: Arc::new(RwLock::new(state)),
            peers: PeerManager::new(),
            identity_manager,
            web_of_trust,
            // 64 * 1024 = 65,536 bytes chunk size for file transfers.
            // Splitting files into 64 KB chunks keeps each chunk small enough
            // to fit comfortably in memory and to be re-sent independently on failure.
            file_transfers: Arc::new(Mutex::new(FileTransferManager::new(64 * 1024))),
            transport_manager,
            message_router,
            pfs_manager,
            message_crypto,
            // Start with the running flag set to `false`. The auto-start logic
            // below will call `start()` if needed, which sets it to `true`.
            running: Arc::new(AtomicBool::new(false)),
            // No worker thread yet — `None` means "not started".
            routing_worker: Mutex::new(None),
            discovery: Arc::new(Mutex::new(DiscoveryService::new())),
            identity_persisted,
            local_profile,
        };

        // --- Step 8: Auto-start ---

        // If the node is supposed to relay messages for others (Server or Dual
        // mode), start the routing worker thread immediately.
        // `matches!(value, Pattern1 | Pattern2)` is a convenient macro that
        // returns `true` if `value` matches any of the listed patterns.
        if matches!(config.initial_mode, NodeMode::Server | NodeMode::Dual) {
            let _ = service.start();
        }

        service
    }

    // -----------------------------------------------------------------------
    // Simple state snapshots
    // -----------------------------------------------------------------------

    /// Return snapshot of known room summaries.
    ///
    /// Acquires a read lock on `state`, clones the `rooms` vector, and releases
    /// the lock. The caller receives an independent copy — changes to `state.rooms`
    /// after this call will not affect the returned vector.
    pub fn rooms(&self) -> Vec<RoomSummary> {
        self.state.read().unwrap().rooms.clone()
    }

    /// Return snapshot of known peer summaries.
    ///
    /// Same pattern as `rooms()`: read lock → clone → release.
    pub fn peers(&self) -> Vec<PeerSummary> {
        self.state.read().unwrap().peers.clone()
    }
}

// ---------------------------------------------------------------------------
// Private utility functions
// ---------------------------------------------------------------------------
//
// These small helper functions are used by multiple child modules. Placing them
// in `mod.rs` keeps them accessible to all siblings without needing to make
// them public.

/// Generate a random ID string with a stable `<prefix>-<HEX>` format.
///
/// For example, `random_id("msg")` might produce `"msg-A3F70C8E1B2D4E6F"`.
/// The hex suffix is 8 random bytes = 16 hex characters, giving 2^64 possible
/// IDs — collision probability is negligible for any realistic usage.
fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    // `fill` asks the OS for 8 cryptographically random bytes.
    // We `expect(...)` here because a system without a working RNG is a
    // fundamental failure condition — not something we can sensibly recover from.
    fill(&mut bytes).expect("system RNG unavailable");
    format!("{}-{}", prefix, hex_encode(&bytes))
}

/// Generate a random 32-byte peer identifier.
///
/// Used as a last-resort fallback when identity generation or loading fails.
/// A 32-byte (256-bit) random value has vanishingly small collision probability.
fn random_peer_id() -> PeerId {
    let mut bytes = [0u8; 32];
    fill(&mut bytes).expect("system RNG unavailable");
    bytes
}

/// Encode a peer ID (`[u8; 32]`) as an uppercase hexadecimal string (64 chars).
///
/// The string form is used everywhere the peer ID needs to cross the FFI boundary
/// or be displayed to the user, because Rust byte arrays don't map directly to
/// Dart or JSON types.
pub(super) fn peer_id_string(peer_id: &PeerId) -> String {
    hex_encode(peer_id)
}

/// Encode a file ID (`[u8; 32]`) as an uppercase hexadecimal string (64 chars).
fn file_id_string(file_id: &[u8; 32]) -> String {
    hex_encode(file_id)
}

/// Derive a short human-friendly pairing code from the first 8 bytes of a peer ID.
///
/// The pairing code is used when two devices want to pair without scanning a QR code.
/// Format: `"XXXX-XXXX-XXXX-XXXX"` (16 uppercase hex chars, grouped in 4s with dashes).
///
/// Only the first 8 bytes (16 hex chars) of the 32-byte peer ID are used — enough
/// for a unique short code while being short enough to type manually.
///
/// Example output: `"A1B2-C3D4-E5F6-7890"`
pub(super) fn pairing_code_from_peer_id(peer_id: &PeerId) -> String {
    let hex = hex_encode(peer_id);
    // Take only the first 16 hex characters (= first 8 bytes of the 32-byte peer ID).
    let short = &hex[..16];
    format!(
        "{}-{}-{}-{}",
        &short[0..4],
        &short[4..8],
        &short[8..12],
        &short[12..16]
    )
}

/// Hex-encode arbitrary bytes using the uppercase alphabet (0–9, A–F).
///
/// Each byte becomes two hex characters:
/// - The high nibble (upper 4 bits): `byte >> 4` gives a value 0–15.
/// - The low nibble (lower 4 bits): `byte & 0x0F` gives a value 0–15.
/// Each nibble is looked up in the `HEX` table to get the character.
///
/// We implement this ourselves (rather than using a library) to avoid adding
/// a dependency for such a simple, hot-path operation.
fn hex_encode(bytes: &[u8]) -> String {
    // Lookup table: index 0–15 maps to '0'–'9', 'A'–'F'.
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    // Pre-allocate the output string: 2 characters per input byte.
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);  // High nibble
        out.push(HEX[(byte & 0x0F) as usize] as char); // Low nibble
    }
    out
}

/// Parse a peer ID from a pairing code or any hex-like string.
///
/// Strips all non-hex characters (dashes, spaces, etc.) and interprets the
/// remaining hex digits as the beginning of a 32-byte peer ID. The unspecified
/// bytes default to zero.
///
/// Returns `None` if fewer than 16 hex digits are present (minimum needed for
/// the pairing-code prefix).
fn peer_id_from_pairing_code(code: &str) -> Option<PeerId> {
    // Strip everything except hex digits: 0-9, a-f, A-F.
    let mut hex = String::new();
    for ch in code.chars() {
        if ch.is_ascii_hexdigit() {
            hex.push(ch);
        }
    }

    // Require at least 16 hex digits (= 8 bytes = the pairing code width).
    if hex.len() < 16 {
        return None;
    }

    // Decode hex pairs into bytes, filling as many of the 32-byte array as
    // the input covers. Remaining bytes stay zero.
    let mut bytes = [0u8; 32];
    let available = hex.len() / 2; // Number of complete byte pairs available.
    let count = usize::min(bytes.len(), available); // Don't overrun the array.
    for (i, slot) in bytes.iter_mut().enumerate().take(count) {
        let idx = i * 2;
        // `u8::from_str_radix(&hex[idx..idx+2], 16)` parses two hex chars into
        // one byte. `ok()?` converts a failure into `None`, propagating it up.
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16).ok()?;
        *slot = byte;
    }
    Some(bytes)
}

/// Parse a full 32-byte file ID from a 64-character hex string.
///
/// Returns `None` if the input has fewer than 64 hex digits.
fn file_id_from_string(value: &str) -> Option<[u8; 32]> {
    // Strip non-hex characters (same approach as `peer_id_from_pairing_code`).
    let mut hex = String::new();
    for ch in value.chars() {
        if ch.is_ascii_hexdigit() {
            hex.push(ch);
        }
    }

    // A full 32-byte ID requires exactly 64 hex characters.
    if hex.len() < 64 {
        return None;
    }

    let mut bytes = [0u8; 32];
    for (i, slot) in bytes.iter_mut().enumerate() {
        let idx = i * 2;
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16).ok()?;
        *slot = byte;
    }
    Some(bytes)
}

/// Convert a trust level enum variant into a human-readable UI label.
///
/// Used when building `PeerSummary.status` strings for the Flutter UI.
fn trust_label(level: CoreTrustLevel) -> String {
    // `match` exhaustively covers every variant of `CoreTrustLevel`.
    // If a new variant is added to the enum, the compiler will force us to
    // handle it here — preventing silent bugs.
    match level {
        CoreTrustLevel::Untrusted => "Untrusted",
        CoreTrustLevel::Caution => "Caution",
        CoreTrustLevel::Trusted => "Trusted",
        CoreTrustLevel::HighlyTrusted => "Highly trusted",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Routing and passive fallback methods
// ---------------------------------------------------------------------------

impl MeshInfinityService {
    /// Encrypt and route an outbound payload to a target peer.
    ///
    /// This is the core delivery function. It ties together:
    /// 1. PFS session creation (fresh ephemeral encryption keys).
    /// 2. Payload encryption into an `EncryptedPayload`.
    /// 3. Path selection (which transports to try, based on trust and availability).
    /// 4. Message routing (handing the encrypted blob to the `MessageRouter`).
    /// 5. Passive fallback (if routing fails, store the message for later delivery).
    ///
    /// The caller provides the raw bytes of the payload; this function handles
    /// all encryption. The plaintext is never written to disk or the network.
    fn route_outbound_message(&self, target: PeerId, payload: &[u8]) -> Result<()> {
        // --- Step 1: Establish a PFS session ---
        //
        // A PFS session produces a one-time encryption key and a MAC (Message
        // Authentication Code) key. The MAC key lets the receiver verify that
        // the message hasn't been tampered with in transit.
        //
        // We lock `pfs_manager`, call `new_session`, then immediately release
        // the lock (the `{ }` block limits the lock's lifetime). This is
        // important: holding a lock while doing slow work (like network I/O)
        // would block other threads unnecessarily.
        let session = {
            let mut manager = self.pfs_manager.lock().unwrap();
            manager.new_session(&target)?
        };

        // --- Step 2: Build the encrypted payload struct ---
        //
        // `EncryptedPayload` bundles the raw bytes with the key IDs needed for
        // the receiver to look up the right decryption keys.
        let encrypted_payload = EncryptedPayload {
            data: payload.to_vec(), // `.to_vec()` converts a slice into an owned Vec.
            encryption_key_id: session.encryption_key,
            mac: session.mac_key,
        };

        // --- Step 3: Select preferred delivery paths ---
        //
        // `preferred_paths_for_peer` inspects:
        //   a) Which transports the peer supports (learned during discovery/pairing).
        //   b) Which transports are currently enabled on this device.
        //   c) Which transports are allowed for the peer's current trust level
        //      (e.g. untrusted peers can only be reached via Tor, not clearnet).
        let paths = self.preferred_paths_for_peer(target);

        // --- Step 4: Enqueue the message for routing ---
        //
        // `OutboundMessage` carries all the metadata the router needs:
        // - `ttl: 4` — "Time to Live": the message can be forwarded through at
        //   most 4 relay hops before being dropped. Prevents infinite loops.
        // - `max_retries: 3` — if delivery fails, try up to 3 more times.
        let message = OutboundMessage {
            payload: encrypted_payload,
            target,
            priority: MessagePriority::Normal,
            preferred_paths: paths,
            ttl: 4,
            max_retries: 3,
            current_retry: 0,
        };

        // `route_message` adds the message to the router's outbound queue.
        // If the service is stopped (not running as Server/Dual), we immediately
        // call `process_queue()` ourselves to try one-shot delivery. In Server/Dual
        // mode the background worker handles queue draining every 50 ms.
        let route_result = self.message_router.route_message(message).and_then(|_| {
            if !self.running.load(Ordering::Relaxed) {
                self.message_router.process_queue()
            } else {
                Ok(())
            }
        });

        // --- Step 5: Passive fallback on failure ---
        //
        // If routing failed (no available transport paths, peer unreachable, etc.),
        // store the PLAINTEXT payload in the passive outbox for later delivery.
        // `enqueue_passive_fallback` will encrypt it before storing.
        if route_result.is_err() {
            self.enqueue_passive_fallback(target, payload)?;
        }

        // Update the bytes-sent counter (saturating_add prevents overflow:
        // if adding would exceed u64::MAX, it stays at u64::MAX instead of
        // wrapping around to 0, which would silently corrupt the counter).
        let mut state = self.state.write().unwrap();
        state.bytes_sent = state.bytes_sent.saturating_add(payload.len() as u64);
        Ok(())
    }

    /// Queue a payload for passive (store-and-forward) delivery to an offline peer.
    ///
    /// This function implements several important properties:
    ///
    /// - **Encryption**: the payload is encrypted before storage. The plaintext
    ///   is never persisted. An attacker who can read process memory or a crash
    ///   dump will only see ciphertext.
    ///
    /// - **Per-peer session keys**: different peers get different ciphertexts for
    ///   the same plaintext. This prevents an observer from linking the messages
    ///   destined for peer A with those destined for peer B, even if they capture
    ///   the passive outbox.
    ///
    /// - **Deduplication**: if the exact same payload has already been queued for
    ///   this peer (same dedupe key), it is not queued again.
    ///
    /// - **Replay prevention**: if the payload was already delivered and acknowledged
    ///   (its dedupe key appears in `passive_acked`), it is silently discarded.
    ///
    /// - **Bounded storage**: the queue is capped at `MAX_PASSIVE_ENVELOPES_PER_PEER`
    ///   entries. Overflow discards the oldest envelopes.
    ///
    /// - **Expiry**: stale envelopes (past their `_expires_at` timestamp) are pruned
    ///   before new ones are inserted.
    fn enqueue_passive_fallback(&self, target: PeerId, payload: &[u8]) -> Result<()> {
        // Read our own peer ID from settings (needed to derive the session key).
        let local_peer = {
            let state = self.state.read().unwrap();
            parse_peer_id_hex(&state.settings.local_peer_id).unwrap_or([0u8; 32])
        };

        // Compute the dedupe key: a SHA-256 hash of (target_peer_id || payload).
        // The same plaintext sent to the same peer always produces the same key,
        // enabling deduplication without storing the plaintext.
        let dedupe_key = passive_dedupe_key(&target, payload);

        // Derive a per-peer session key: a SHA-256 hash of (local_peer || target).
        // Because the key is unique per (sender, receiver) pair, encrypting the
        // same plaintext for two different peers produces completely different
        // ciphertexts, preventing correlation attacks.
        let session_key = derive_passive_session_key(&local_peer, &target);

        // Encrypt the payload using the per-peer session key.
        let ciphertext = {
            let mut crypto = self.message_crypto.lock().unwrap();
            crypto.session_encrypt(&session_key, payload)?
        };

        // Build the envelope with metadata for expiry tracking and deduplication.
        let envelope = PassiveEnvelope {
            _id: random_id("passive"),
            _created_at: SystemTime::now(),
            _expires_at: SystemTime::now() + Duration::from_secs(PASSIVE_RETENTION_SECS),
            _dedupe_key: dedupe_key.clone(),
            _ciphertext: ciphertext,
        };

        // Acquire exclusive write access to the state for queue manipulation.
        let mut state = self.state.write().unwrap();

        // Replay prevention: if the dedupe key is already in the ack history,
        // this payload was already delivered. Discard it silently.
        let already_acked = state
            .passive_acked
            .get(&target)
            .map(|history| history.iter().any(|item| item == &dedupe_key))
            .unwrap_or(false);
        if already_acked {
            return Ok(());
        }

        // Get (or create) the outbox queue for this peer.
        // `entry(target).or_default()` inserts an empty Vec if none exists.
        let queue = state.passive_outbox.entry(target).or_default();

        // Prune expired envelopes before inserting (avoids storing stale data).
        queue.retain(|item| SystemTime::now() <= item._expires_at);

        // Deduplication: if the same payload is already queued, don't add it again.
        if queue.iter().any(|item| item._dedupe_key == dedupe_key) {
            return Ok(());
        }

        // Add the new envelope.
        queue.push(envelope);

        // Enforce the per-peer queue capacity limit.
        // If the queue is over the limit, remove the oldest entries from the front.
        if queue.len() > MAX_PASSIVE_ENVELOPES_PER_PEER {
            let overflow = queue.len() - MAX_PASSIVE_ENVELOPES_PER_PEER;
            queue.drain(0..overflow); // `drain(range)` removes and discards elements.
        }

        Ok(())
    }

    /// Build the ordered list of preferred delivery paths for a given peer.
    ///
    /// A "path" describes one possible route to the peer: which transport to use
    /// and the peer's address on that transport.
    ///
    /// The selection logic has three layers of filtering:
    ///
    /// 1. **Peer capabilities**: which transports the peer actually supports
    ///    (learned during discovery or pairing). If the peer doesn't support Tor,
    ///    we can't send via Tor regardless of our preferences.
    ///
    /// 2. **Local availability**: which transports are currently enabled on THIS
    ///    device. If the user has Tor disabled in settings, we can't use it.
    ///    The `transport_manager` provides these in preference order (privacy-first:
    ///    Tor > I2P > Bluetooth > RF > Clearnet).
    ///
    /// 3. **Trust gating**: even if a transport is enabled and the peer supports it,
    ///    the peer's trust level may restrict which transports can be used.
    ///    `allowed_transports_for_trust()` enforces this policy:
    ///    - Untrusted → Tor only (maximum anonymity).
    ///    - Caution → Tor, I2P.
    ///    - Trusted/Highly Trusted → all transports including clearnet.
    fn preferred_paths_for_peer(&self, target: PeerId) -> Vec<PathInfo> {
        // Query the peer manager for which transports the target peer supports.
        // If the peer is not in our list (new/unknown), assume all transports as
        // a conservative default — the router will fail gracefully if they don't work.
        let available = self
            .peers
            .get_peer(&target)
            .map(|peer| peer.available_transports)
            .unwrap_or_else(|| {
                vec![
                    TransportType::Tor,
                    TransportType::I2P,
                    TransportType::Bluetooth,
                    TransportType::Rf,
                    TransportType::Clearnet,
                ]
            });

        // Look up the peer's trust level; default to Untrusted if unknown.
        let trust = self
            .peers
            .get_trust_level(&target)
            .unwrap_or(CoreTrustLevel::Untrusted);

        // Get the set of transports permitted at this trust level.
        let trust_allowed = allowed_transports_for_trust(trust);

        // Build the final ordered list of `PathInfo` structs:
        // 1. Start with the locally-enabled transports in preference order.
        // 2. Keep only those also in `available` (peer supports them).
        //    (`enabled_transport_order_for_available` handles step 1 + 2 combined.)
        // 3. Filter by `trust_allowed` (step 3 above).
        // 4. Convert each passing transport into a `PathInfo` with a default endpoint.
        self.transport_manager
            .enabled_transport_order_for_available(&available)
            .into_iter()
            .filter(|transport| trust_allowed.contains(transport))
            .map(|transport| default_path(target, transport))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Trust-level transport policy
// ---------------------------------------------------------------------------

/// Return the set of transports that are permitted for a given trust level.
///
/// This function encodes the privacy policy of the mesh:
///
/// | Trust Level    | Allowed Transports                                 |
/// |----------------|-----------------------------------------------------|
/// | Untrusted      | Tor only — highest anonymity, IP never exposed     |
/// | Caution        | Tor, I2P — still anonymous, slightly more flexible  |
/// | Trusted        | All transports, including Bluetooth and clearnet    |
/// | Highly Trusted | Same as Trusted                                     |
///
/// `&'static [TransportType]` is a reference to a slice of `TransportType` values
/// that lives for the entire program lifetime (`'static`). The `&[...]` literals
/// here are baked into the compiled binary, so no allocation is needed.
fn allowed_transports_for_trust(level: CoreTrustLevel) -> &'static [TransportType] {
    match level {
        // Untrusted peers: route only over Tor. Tor hides this node's real IP
        // address by relaying through volunteer exit nodes worldwide.
        CoreTrustLevel::Untrusted => &[TransportType::Tor],

        // Cautious peers: Tor or I2P. Both are anonymity networks; I2P is a
        // peer-to-peer overlay (traffic doesn't leave the I2P network).
        CoreTrustLevel::Caution => &[TransportType::Tor, TransportType::I2P],

        // Trusted or highly trusted peers: all transports are allowed, including
        // Bluetooth (short-range wireless) and clearnet (standard internet,
        // IP addresses visible to both parties).
        CoreTrustLevel::Trusted | CoreTrustLevel::HighlyTrusted => &[
            TransportType::Tor,
            TransportType::I2P,
            TransportType::Bluetooth,
            TransportType::Rf,
            TransportType::Clearnet,
        ],
    }
}

// ---------------------------------------------------------------------------
// Passive delivery helpers
// ---------------------------------------------------------------------------

/// Deterministically derive a per-peer session key for passive envelope encryption.
///
/// The key is a SHA-256 hash of the concatenation of the local peer ID and the
/// target peer ID. This makes the key unique per (sender, recipient) pair without
/// requiring any key-exchange round-trip with the offline peer.
///
/// Why not just use the global `MessageCrypto` key for everything?
/// Because that would produce identical ciphertexts for the same plaintext sent
/// to different peers, which would allow a passive observer to link the envelopes.
fn derive_passive_session_key(local_peer: &PeerId, target: &PeerId) -> [u8; 32] {
    // Concatenate the two peer IDs into a single byte string.
    let mut seed = Vec::with_capacity(local_peer.len() + target.len());
    seed.extend_from_slice(local_peer);
    seed.extend_from_slice(target);

    // Hash the concatenation with SHA-256.
    let hashed = digest(&SHA256, &seed);

    // Copy the 32-byte hash output into a fixed-size array.
    let mut key = [0u8; 32];
    key.copy_from_slice(&hashed.as_ref()[..32]);
    key
}

/// Parse a canonical 32-byte peer ID from a 64-character hex string.
///
/// Returns `None` if the string has fewer than 64 valid hex digits.
/// Non-hex characters are silently stripped (allows strings with dashes, spaces, etc.).
fn parse_peer_id_hex(value: &str) -> Option<PeerId> {
    // Keep only hex characters; discard dashes, spaces, etc.
    let normalized: String = value.chars().filter(|ch| ch.is_ascii_hexdigit()).collect();

    // Need at least 64 hex digits to fill 32 bytes.
    if normalized.len() < 64 {
        return None;
    }

    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        *byte = u8::from_str_radix(&normalized[start..start + 2], 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Routing path helpers
// ---------------------------------------------------------------------------

/// Build a default `PathInfo` for the given peer and transport.
///
/// `PathInfo` is what the message router uses to describe one potential delivery
/// route. The "default" values here represent reasonable estimates when we don't
/// have real latency or bandwidth measurements for this peer yet:
/// - `latency: None` — unknown.
/// - `reliability: 0.8` — 80% success rate assumed (conservative).
/// - `bandwidth: None` — unknown.
/// - `cost: 0.1` — low routing cost (not penalised by default).
fn default_path(target: PeerId, transport: TransportType) -> PathInfo {
    PathInfo {
        transport,
        endpoint: Endpoint {
            peer_id: target,
            // Use the hex peer ID as the address placeholder.
            // Real transport-specific addresses (Tor .onion, I2P b32, etc.) would
            // replace this once a connection has been established.
            address: peer_id_string(&target),
        },
        latency: None,
        reliability: 0.8,
        bandwidth: None,
        cost: 0.1,
    }
}

// ---------------------------------------------------------------------------
// Messaging helpers
// ---------------------------------------------------------------------------

/// Build a deterministic direct-message (DM) room ID for a peer.
///
/// Format: `"dm-<64-char-hex-peer-id>"`.
///
/// Using the FULL 32-byte peer ID (64 hex chars) as the room ID suffix ensures
/// that two peers with the same first few bytes (e.g. `0xAABBCC01` vs `0xAABBCC02`)
/// get distinct room IDs. A shorter suffix (like the pairing code) could collide.
fn dm_room_id(peer_id: &PeerId) -> String {
    // Use the full peer identity for deterministic, collision-resistant DM rooms.
    format!("dm-{}", peer_id_string(peer_id))
}

/// Guard that a room ID exists in the current room collection.
///
/// Returns `Ok(())` if a room with the given ID exists, or an
/// `InvalidConfiguration` error if it doesn't. Used to validate room IDs
/// before performing operations (send message, select room, etc.) so that
/// callers get a clear error rather than a panic or silent no-op.
fn ensure_room_exists(rooms: &[RoomSummary], room_id: &str) -> Result<()> {
    if rooms.iter().any(|room| room.id == room_id) {
        Ok(())
    } else {
        Err(MeshInfinityError::InvalidConfiguration(
            "room not found".to_string(),
        ))
    }
}

/// Compute a collision-resistant dedupe key for a passive envelope.
///
/// The key is a SHA-256 hash of (target_peer_id || payload_bytes).
/// The same plaintext sent to the same peer always produces the same key,
/// enabling deduplication without storing the plaintext itself.
fn passive_dedupe_key(target: &PeerId, payload: &[u8]) -> String {
    let mut input = Vec::with_capacity(target.len() + payload.len());
    input.extend_from_slice(target);
    input.extend_from_slice(payload);
    let hash = digest(&SHA256, &input);
    // Encode the 32-byte hash as a 64-char hex string for easy comparison.
    hex_encode(hash.as_ref())
}

// ---------------------------------------------------------------------------
// File transfer helpers
// ---------------------------------------------------------------------------

/// Convert an internal `TransferItem` into the UI-facing `FileTransferSummary`.
///
/// This is the translation layer between the engine's rich internal type and the
/// flat, FFI-friendly summary that Flutter can display without needing to know
/// anything about Rust internals.
fn transfer_summary(item: &TransferItem) -> FileTransferSummary {
    FileTransferSummary {
        id: file_id_string(&item.id),
        peer_id: peer_id_string(&item.peer_id),
        name: item.metadata.name.clone(),
        size_bytes: item.metadata.size_bytes,
        transferred_bytes: item.progress.transferred_bytes,
        // Convert the enum variants into display strings.
        status: transfer_status_label(item.status),
        direction: transfer_direction_label(item.direction),
    }
}

/// Convert a `TransferStatus` enum into a user-facing label string.
fn transfer_status_label(status: TransferStatus) -> String {
    match status {
        TransferStatus::Queued => "Queued",
        TransferStatus::InProgress => "In progress",
        TransferStatus::Completed => "Completed",
        TransferStatus::Failed => "Failed",
        TransferStatus::Canceled => "Canceled",
    }
    .to_string()
}

/// Convert a `TransferDirection` enum into a user-facing label string.
fn transfer_direction_label(direction: TransferDirection) -> String {
    match direction {
        TransferDirection::Send => "Send",
        TransferDirection::Receive => "Receive",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

/// Build a short local timestamp label for display on message and room rows.
///
/// Returns the current UTC time formatted as `"HH:MM"` (e.g. `"14:37"`).
/// If formatting fails for any reason, returns an empty string rather than
/// propagating an error — a missing timestamp is cosmetic, not critical.
fn now_label() -> String {
    // Parse the format string at runtime. This can fail if the format string
    // is invalid, but `"[hour]:[minute]"` is hardcoded and always valid.
    let format = format_description::parse("[hour]:[minute]").ok();
    let now = time::OffsetDateTime::now_utc();
    match format {
        Some(format) => now.format(&format).unwrap_or_default(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// `#[cfg(test)]` means this module is compiled ONLY when running `cargo test`.
// It does not appear in the final application binary.
//
// The tests here exercise the service at the integration level — they construct
// a real `MeshInfinityService` and call its public API, verifying end-to-end
// behaviour. This is more valuable than mocking internals because it catches
// regressions in how the subsystems work together.

#[cfg(test)]
mod tests {
    // `use super::*` imports everything from the parent module (`mod.rs`) into
    // the test module's scope, so tests can call private helpers and access
    // private types without going through the public API.
    use super::*;
    // `VerificationMethod` is an enum that describes HOW a trust upgrade was
    // verified — for example, `SharedSecret` means the user confirmed a shared
    // secret (like a pairing code), `OutOfBand` means the trust was established
    // outside the app (e.g. face-to-face). Used here to call
    // `update_trust_level(...)` in tests that need to promote a peer to Trusted.
    use crate::core::mesh::VerificationMethod;
    // NOTE: The closing `}` here ends the `use` / import region of the test
    // module. The `#[test]` functions below are defined at the same nesting level
    // as `mod tests { ... }` (i.e. they are free functions within the `tests`
    // module). This is a Rust formatting choice — it is valid because Rust
    // collects all items at the same module level together regardless of their
    // physical position in the file.
    }

    /// When all transports are disabled, routing fails and the message should be
    /// queued in the passive outbox rather than dropped on the floor.
    ///
    /// This test verifies the "passive fallback" guarantee: messages are NEVER
    /// silently dropped when the peer is unreachable — they are held in storage
    /// until the peer reconnects.
    //
    // `#[test]` is a Rust attribute that marks this function as a unit test.
    // Running `cargo test` compiles and runs every function marked `#[test]`
    // in the codebase. The test passes if the function returns without panicking;
    // it fails if it panics (e.g. from an `assert!` that evaluates to `false`,
    // or an `.expect(...)` on an `Err` value).
    #[test]
    fn passive_fallback_queues_when_no_transport_paths() {
        // --- ARRANGE: Create a service with ALL transports disabled. ---
        // When no transports are available, any attempt to route a message
        // will immediately fail. The test relies on this to force passive fallback.
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        // Pair a peer using a pairing code. Because all transports are disabled,
        // any message to this peer cannot be delivered immediately.
        let _ = service.pair_peer("A1B2-C3D4-E5F6-1122");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        // --- ACT: Send a message into a room that includes this peer. ---
        let room_id = service.create_room("fallback-room").expect("room create");
        service
            .send_message_to_room(&room_id, "hello fallback")
            .expect("send message");

        // --- ASSERT: The passive outbox for this peer must have at least one entry. ---
        // If the message were dropped instead of queued, `pending` would be 0
        // and the `assert!` would panic, failing the test.
        let state = service.state.read().unwrap();
        let pending = state
            .passive_outbox
            .get(&peer_id)
            .map(|v| v.len())
            .unwrap_or(0);
        assert!(pending >= 1);
    }

    /// When a peer reconnects and we drain the passive outbox, the queue should
    /// be empty afterwards — messages have been delivered, not just removed.
    ///
    /// This test verifies that `drain_passive_for_peer` both delivers the queued
    /// messages AND clears the queue (rather than leaving stale copies behind).
    #[test]
    fn passive_fallback_drains_on_reconciliation() {
        // --- ARRANGE: Queue at least one message to an offline peer. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("1122-3344-5566-7788");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("reconcile-room").expect("room create");
        service
            .send_message_to_room(&room_id, "reconcile me")
            .expect("send message");

        // --- ACT: Drain the passive outbox (simulates the peer reconnecting). ---
        // `drain_passive_for_peer` returns the number of envelopes that were
        // delivered. We assert it is at least 1 to confirm there was something to drain.
        let delivered = service
            .drain_passive_for_peer(&peer_id)
            .expect("drain passive queue");
        assert!(delivered >= 1);

        // --- ASSERT: Queue is now empty (nothing left to re-deliver). ---
        // `assert_eq!(remaining, 0)` panics if any envelopes remain, which would
        // mean drain didn't actually clear the queue.
        let state = service.state.read().unwrap();
        let remaining = state
            .passive_outbox
            .get(&peer_id)
            .map(|v| v.len())
            .unwrap_or(0);
        assert_eq!(remaining, 0);
    }

    /// Envelopes in the passive outbox must contain ciphertext, not plaintext.
    /// This ensures that inspecting process memory or a crash dump does not
    /// reveal message content.
    ///
    /// This is a security property: even if an attacker can read the process's
    /// heap memory (e.g. through a memory-inspection exploit), they must NOT be
    /// able to find the original message text in the passive outbox.
    #[test]
    fn passive_fallback_stores_ciphertext_not_plaintext() {
        // --- ARRANGE: Queue a message with a known plaintext string. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("99AA-BBCC-DDEE-FF00");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("cipher-room").expect("room create");
        // The known plaintext. We will verify it does NOT appear verbatim in the stored bytes.
        let plain = b"origin-hidden-payload";
        service
            .send_message_to_room(&room_id, std::str::from_utf8(plain).unwrap())
            .expect("send message");

        // --- ACT + ASSERT: Inspect the stored ciphertext. ---
        let state = service.state.read().unwrap();
        let queued = state
            .passive_outbox
            .get(&peer_id)
            .and_then(|v| v.first())
            .expect("queued envelope should exist");

        // The stored bytes must not equal the plaintext byte-for-byte.
        assert_ne!(queued._ciphertext, plain);
        // The plaintext must not appear as a substring anywhere in the ciphertext.
        // `.windows(n)` iterates every n-byte sliding window of the ciphertext slice.
        // If ANY window matches `plain`, the test fails — the plaintext leaked.
        assert!(!queued
            ._ciphertext
            .windows(plain.len())
            .any(|slice| slice == plain));
    }

    /// Sending the same plaintext to two different peers must produce different
    /// ciphertexts in their respective outboxes. An observer who can see both
    /// outboxes should not be able to link the two envelopes as containing the
    /// same message, nor should they be able to extract peer identity bytes
    /// from the ciphertext.
    ///
    /// This tests the "per-peer session key" property of `enqueue_passive_fallback`:
    /// a different encryption key is derived for each (sender, recipient) pair,
    /// so identical plaintexts become unrelated ciphertexts in each peer's outbox.
    #[test]
    fn passive_fallback_observer_cannot_link_origin_beyond_previous_hop() {
        // --- ARRANGE: Two peers, both with all transports disabled. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("AAAA-BBBB-CCCC-DDDD");
        let _ = service.pair_peer("1111-2222-3333-4444");

        let peers = service.peers.get_all_peers();
        assert!(peers.len() >= 2, "expected two paired peers");
        let peer_a = peers[0].peer_id;
        let peer_b = peers[1].peer_id;

        // --- ACT: Send the SAME plaintext to a room that includes both peers. ---
        let room_id = service.create_room("observer-room").expect("room create");
        service
            .send_message_to_room(&room_id, "same payload")
            .expect("send message");

        // Read the local node's peer ID for the identity-leakage check below.
        let local_peer = {
            let state = service.state.read().unwrap();
            parse_peer_id_hex(&state.settings.local_peer_id).expect("local peer id parse")
        };

        // --- ASSERT: The ciphertexts must differ AND must not expose peer IDs. ---
        let state = service.state.read().unwrap();
        let env_a = state
            .passive_outbox
            .get(&peer_a)
            .and_then(|items| items.first())
            .expect("peer A should have passive envelope");
        let env_b = state
            .passive_outbox
            .get(&peer_b)
            .and_then(|items| items.first())
            .expect("peer B should have passive envelope");

        // Ciphertexts for the same plaintext must differ when keys are per-peer.
        // If they were equal, an observer could link the messages by comparison.
        assert_ne!(env_a._ciphertext, env_b._ciphertext);

        // The raw bytes of any peer ID must NOT appear verbatim inside the
        // ciphertext stored for peer A. If they did, an observer could extract
        // peer identities from the encrypted blob without decrypting it.
        assert!(!env_a
            ._ciphertext
            .windows(peer_a.len())
            .any(|window| window == peer_a));
        assert!(!env_a
            ._ciphertext
            .windows(peer_b.len())
            .any(|window| window == peer_b));
        assert!(!env_a
            ._ciphertext
            .windows(local_peer.len())
            .any(|window| window == local_peer));
    }

    /// Even when clearnet is enabled on the device, a peer at "Caution" trust
    /// level must NOT be reachable via clearnet. Only privacy transports (Tor, I2P)
    /// should be offered to untrusted or cautious peers.
    ///
    /// This tests the trust-gating layer of `preferred_paths_for_peer`. Even if
    /// the user has switched clearnet on globally, the per-peer trust check should
    /// strip it from the path list for any peer below `Trusted`.
    #[test]
    fn preferred_paths_gate_clearnet_for_low_trust_even_if_enabled() {
        // --- ARRANGE: Only clearnet is enabled; Tor and I2P are off. ---
        // The key insight: clearnet is ON at the device level, but the peer's
        // trust level is Caution (set automatically by `pair_peer`), so clearnet
        // must still be withheld.
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(true);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("ABCD-1234-EEEE-9999");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        // --- ACT + ASSERT ---
        // `pair_peer` assigns Caution trust by default (one step above Untrusted).
        // `allowed_transports_for_trust(Caution)` returns only [Tor, I2P].
        // Since both Tor and I2P are disabled, the intersection is empty.
        // An empty `paths` list means: no route available → message goes to passive queue.
        let paths = service.preferred_paths_for_peer(peer_id);
        assert!(paths.is_empty(), "clearnet must be gated for caution peers");
    }

    /// Once a peer is explicitly promoted to "Trusted", clearnet should be
    /// offered as a path (when it is the only enabled transport).
    ///
    /// This is the counterpart to the previous test: it verifies that the trust
    /// gate OPENS for trusted peers, not just that it blocks low-trust peers.
    #[test]
    fn preferred_paths_allow_clearnet_for_trusted_when_privacy_transports_disabled() {
        // --- ARRANGE: Same transport setup (only clearnet enabled). ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(true);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("CAFE-BEEF-0000-1111");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        // Explicitly upgrade the peer's trust from Caution → Trusted.
        // `VerificationMethod::SharedSecret` means the upgrade was done by
        // confirming a shared secret code, which is the standard pairing flow.
        service
            .peers
            .update_trust_level(
                &peer_id,
                CoreTrustLevel::Trusted,
                VerificationMethod::SharedSecret,
            )
            .expect("update trust");

        // --- ACT + ASSERT: Now clearnet should appear in the path list. ---
        // `allowed_transports_for_trust(Trusted)` includes all transports.
        // Clearnet is enabled and the peer's trust allows it → exactly one path.
        let paths = service.preferred_paths_for_peer(peer_id);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].transport, TransportType::Clearnet);
    }

    /// Switching between node modes must correctly start and stop the routing
    /// worker thread. Client mode → no worker; Server/Dual mode → worker running.
    ///
    /// This verifies that `set_node_mode` is wired correctly to `start()`/`stop()`,
    /// and that `is_running()` accurately reflects the worker's state after each transition.
    #[test]
    fn node_mode_transitions_toggle_routing_worker_lifecycle() {
        // --- ARRANGE: Start in Client mode — worker should NOT be running. ---
        // The `..ServiceConfig::default()` syntax fills all other fields with their
        // default values (all transports off, no preloaded identity).
        let service = MeshInfinityService::new(ServiceConfig {
            initial_mode: NodeMode::Client,
            ..ServiceConfig::default()
        });

        // Client mode should have no background routing worker.
        assert!(!service.is_running());

        // --- ACT + ASSERT: Transition through all modes and verify each time. ---

        // Client → Dual: should start the routing worker.
        service.set_node_mode(NodeMode::Dual);
        assert!(service.is_running());

        // Dual → Client: should stop the routing worker.
        service.set_node_mode(NodeMode::Client);
        assert!(!service.is_running());

        // Client → Server: should start the routing worker again.
        service.set_node_mode(NodeMode::Server);
        assert!(service.is_running());
    }

    /// Calling `start()` multiple times must not spawn duplicate threads, and
    /// calling `stop()` multiple times must not panic.
    ///
    /// "Idempotent" means calling the function multiple times has the same
    /// effect as calling it once. This test verifies that property for both
    /// `start()` and `stop()` — defensive callers shouldn't have to track
    /// whether the service is already started before calling these functions.
    #[test]
    fn start_stop_are_idempotent_across_role_transitions() {
        // --- ARRANGE: Start in Server mode (worker running from construction). ---
        let service = MeshInfinityService::new(ServiceConfig {
            initial_mode: NodeMode::Server,
            ..ServiceConfig::default()
        });

        // Construction with Server mode calls start() automatically.
        assert!(service.is_running());

        // --- Calling start() again must be a safe no-op. ---
        service.start().expect("start should be idempotent");
        assert!(service.is_running()); // Still running — not double-started.

        // --- Stopping works the first time. ---
        service.stop().expect("stop should succeed");
        assert!(!service.is_running());

        // --- Calling stop() again on an already-stopped service must not panic. ---
        service.stop().expect("stop should be idempotent");
        assert!(!service.is_running()); // Still stopped — not double-stopped.

        // --- Restarting after stop must work. ---
        service.start().expect("restart should succeed");
        assert!(service.is_running());
    }

    /// Two peers whose peer IDs share the same first 3 bytes must still get
    /// distinct DM room IDs, because `dm_room_id` uses the full 32-byte identity.
    ///
    /// This would regress if `dm_room_id` were ever shortened to use just a
    /// prefix (like the pairing code, which is only 8 bytes). This test
    /// ensures the full 32-byte peer ID is always used for room IDs.
    #[test]
    fn receive_message_uses_collision_resistant_dm_room_ids() {
        let service = MeshInfinityService::new(ServiceConfig::default());

        // Build two peer IDs that share the first 3 bytes exactly (same hex prefix)
        // but differ in byte index 3. A short room-ID scheme would collide on these.
        let mut peer_a = [0u8; 32];
        let mut peer_b = [0u8; 32];
        // Same first 3 bytes (same 6-hex prefix), different full identities.
        peer_a[0] = 0xAA;
        peer_a[1] = 0xBB;
        peer_a[2] = 0xCC;
        peer_a[3] = 0x01; // peer_a ends in ...01...

        peer_b[0] = 0xAA;
        peer_b[1] = 0xBB;
        peer_b[2] = 0xCC;
        peer_b[3] = 0x02; // peer_b ends in ...02... — one byte different.

        // Simulate receiving one message from each peer. `receive_message`
        // will automatically create a DM room for each peer if one doesn't exist.
        service
            .receive_message(peer_a, None, "hello from a")
            .expect("receive A");
        service
            .receive_message(peer_b, None, "hello from b")
            .expect("receive B");

        // Both rooms should exist and their IDs must be different.
        let rooms = service.rooms();
        assert!(rooms.iter().any(|room| room.id == dm_room_id(&peer_a)));
        assert!(rooms.iter().any(|room| room.id == dm_room_id(&peer_b)));
        assert_ne!(dm_room_id(&peer_a), dm_room_id(&peer_b));
    }

    /// Attempting to select a room that does not exist must return an error.
    ///
    /// This guards against calling UI code that passes a stale or fabricated
    /// room ID. The error variant is `InvalidConfiguration` (a programming
    /// error, not a network error).
    #[test]
    fn select_room_requires_existing_room() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        // `.expect_err(msg)` asserts that the result is `Err(...)` and returns
        // the inner error value. If the result is `Ok(...)`, it panics with `msg`.
        let err = service
            .select_room("room-does-not-exist")
            .expect_err("select must fail for unknown room");
        // `matches!(value, Pattern)` returns `true` if `value` matches the pattern.
        // Here we verify the error is specifically `InvalidConfiguration`, not some
        // other error type (e.g. a network failure or crypto error).
        assert!(matches!(err, MeshInfinityError::InvalidConfiguration(_)));
    }

    /// Attempting to send to a room that does not exist must return an error.
    ///
    /// Symmetrical to `select_room_requires_existing_room` — the same guard
    /// must exist on the send path to prevent orphaned messages.
    #[test]
    fn send_message_requires_existing_room() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        let err = service
            .send_message_to_room("room-does-not-exist", "hello")
            .expect_err("send must fail for unknown room");
        assert!(matches!(err, MeshInfinityError::InvalidConfiguration(_)));
    }

    /// Pairing with the same code twice must not produce a duplicate peer entry.
    ///
    /// A user might accidentally tap "Pair" twice, or the UI might call `pair_peer`
    /// on reconnection even if the peer was already known. The peer list must stay
    /// deduplicated in all these cases.
    #[test]
    fn pair_peer_is_idempotent_for_same_code_summary() {
        let service = MeshInfinityService::new(ServiceConfig::default());
        let code = "ABCD-1234-EEEE-9999";

        // Call pair_peer twice with the identical code.
        service.pair_peer(code).expect("first pair");
        service.pair_peer(code).expect("second pair");

        // Derive the expected peer ID string from the pairing code so we can
        // count exactly how many summary entries in `state.peers` have that ID.
        let peer_id = peer_id_string(&peer_id_from_pairing_code(code).expect("peer id from code"));
        let state = service.state.read().unwrap();
        // `filter(...)` counts how many `PeerSummary` entries match this ID.
        // It must be exactly 1 — not 0 (peer wasn't added) and not 2 (duplicated).
        let count = state.peers.iter().filter(|peer| peer.id == peer_id).count();
        assert_eq!(
            count, 1,
            "pairing same code should not duplicate peer summary"
        );
    }

    /// Sending the exact same message text twice to the same offline peer must
    /// result in only ONE envelope in the passive outbox, not two.
    ///
    /// Deduplication is important because: without it, if a user accidentally
    /// taps "Send" twice or the UI retries on a timeout, the peer would receive
    /// the same message multiple times on reconnection — confusing and noisy.
    #[test]
    fn passive_fallback_dedupes_identical_payloads() {
        // --- ARRANGE: All transports off → every send goes to passive outbox. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("D00D-BEEF-1111-2222");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        // --- ACT: Send the SAME text twice. ---
        let room_id = service.create_room("dedupe-room").expect("room create");
        service
            .send_message_to_room(&room_id, "same payload")
            .expect("first send");
        service
            .send_message_to_room(&room_id, "same payload") // identical text
            .expect("second send");

        // --- ASSERT: Only one envelope in the queue. ---
        // The SHA-256 dedupe key for (peer_id, "same payload") is the same both times,
        // so the second call should be a no-op.
        let state = service.state.read().unwrap();
        let pending = state
            .passive_outbox
            .get(&peer_id)
            .map(|items| items.len())
            .unwrap_or(0);
        assert_eq!(pending, 1, "identical pending payload should be deduped");
    }

    /// Sending more messages than the per-peer queue limit allows must cap the
    /// queue at `MAX_PASSIVE_ENVELOPES_PER_PEER`, dropping the oldest entries.
    ///
    /// Without this bound, an offline peer that is never reachable again could
    /// cause the passive outbox to grow without limit, eventually exhausting
    /// the device's memory. The cap discards the oldest messages first (a
    /// "sliding window" of the most recent `MAX_PASSIVE_ENVELOPES_PER_PEER`).
    #[test]
    fn passive_fallback_queue_is_bounded() {
        // --- ARRANGE: All transports off; send more messages than the cap allows. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("ABBA-ABBA-ABBA-ABBA");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("bound-room").expect("room create");
        // Send MAX + 12 unique messages (unique text → unique dedupe keys → all
        // different payloads, so deduplication does not reduce the count here).
        // The loop variable `i` makes each message text unique.
        for i in 0..(MAX_PASSIVE_ENVELOPES_PER_PEER + 12) {
            service
                .send_message_to_room(&room_id, &format!("payload-{}", i))
                .expect("send");
        }

        // --- ASSERT: Queue is capped at MAX_PASSIVE_ENVELOPES_PER_PEER. ---
        // Even though we sent MAX+12 messages, the queue should hold exactly MAX.
        // The oldest 12 messages were silently discarded to make room.
        let state = service.state.read().unwrap();
        let pending = state
            .passive_outbox
            .get(&peer_id)
            .map(|items| items.len())
            .unwrap_or(0);
        assert_eq!(pending, MAX_PASSIVE_ENVELOPES_PER_PEER);
    }

    /// After a passive envelope is delivered (acked), re-sending the same payload
    /// must NOT re-enqueue it. The ack history prevents replay.
    ///
    /// "Replay" here means: the same message being delivered twice to a peer.
    /// This can happen if the user resends a message or the UI retries after
    /// a transient error. The ack history ensures the peer only ever receives
    /// each distinct payload once, no matter how many times it is sent.
    #[test]
    fn passive_fallback_replay_is_rejected_after_ack() {
        // --- ARRANGE: Queue a message (all transports off → goes to passive outbox). ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("FACE-B00C-1234-5678");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("replay-room").expect("room create");
        service
            .send_message_to_room(&room_id, "replay-safe-payload")
            .expect("first send");

        // --- ACT 1: Drain the outbox (simulates peer reconnecting and receiving). ---
        // After draining, the dedupe key of the delivered envelope is moved to
        // the `passive_acked` history for this peer.
        let delivered = service
            .drain_passive_for_peer(&peer_id)
            .expect("drain should succeed");
        assert!(delivered >= 1);

        // --- ACT 2: Re-send the SAME payload text. ---
        // The dedupe key matches one already in `passive_acked`, so `enqueue_passive_fallback`
        // should silently discard this call without adding anything to the queue.
        service
            .send_message_to_room(&room_id, "replay-safe-payload")
            .expect("second send with same payload");

        // --- ASSERT: Queue must still be empty (replay was rejected). ---
        let state = service.state.read().unwrap();
        let pending = state
            .passive_outbox
            .get(&peer_id)
            .map(|items| items.len())
            .unwrap_or(0);
        assert_eq!(pending, 0, "acked payload should not be re-enqueued");
    }

    /// After draining the passive outbox, the ack checkpoint must reflect the
    /// dedupe key of the last delivered envelope.
    ///
    /// The "ack checkpoint" is the dedupe key of the most recently delivered
    /// envelope for a given peer. It is used by the reconnect-sync flow to let
    /// a peer tell us "I've received up to key X; only send me newer envelopes."
    /// This test verifies that the checkpoint is correctly set after a drain.
    #[test]
    fn passive_ack_checkpoint_advances_after_drain() {
        // --- ARRANGE: Queue a message, record its dedupe key before draining. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("ABCD-ABCD-ABCD-ABCD");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("checkpoint-room").expect("room create");
        service
            .send_message_to_room(&room_id, "checkpoint-payload")
            .expect("send");

        // Read the dedupe key of the envelope that was just queued. This is the
        // expected value of the checkpoint after we drain the queue.
        // The block `{ }` ensures the read lock is released before `drain_passive_for_peer`
        // tries to acquire a write lock on the same state.
        let expected = {
            let state = service.state.read().unwrap();
            state
                .passive_outbox
                .get(&peer_id)
                .and_then(|items| items.first())
                .map(|env| env._dedupe_key.clone())
                .expect("queued envelope")
        };

        // --- ACT: Drain the passive outbox. ---
        let delivered = service
            .drain_passive_for_peer(&peer_id)
            .expect("drain should succeed");
        assert!(delivered >= 1);

        // --- ASSERT: The checkpoint now equals the dedupe key we recorded above. ---
        // `passive_ack_checkpoint` returns the dedupe key of the last delivered envelope.
        let checkpoint = service
            .passive_ack_checkpoint(&peer_id)
            .expect("checkpoint should exist");
        assert_eq!(checkpoint, expected);
    }

    /// Envelopes whose expiry timestamp has passed must be removed by compaction,
    /// even if they were never delivered.
    ///
    /// Compaction is a periodic cleanup pass. Without it, envelopes for peers
    /// who never reconnect would sit in memory forever. After `PASSIVE_RETENTION_SECS`
    /// (7 days), an undelivered message is presumed too stale to be useful and
    /// should be discarded to reclaim memory.
    #[test]
    fn passive_compaction_removes_expired_envelopes() {
        // --- ARRANGE: Queue a message, then backdate its expiry to the past. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        service.set_enable_tor(false);
        service.set_enable_i2p(false);
        service.set_enable_clearnet(false);
        service.set_enable_bluetooth(false);

        let _ = service.pair_peer("EEEE-FFFF-0000-1111");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        let room_id = service.create_room("compact-room").expect("room create");
        service
            .send_message_to_room(&room_id, "expire-me")
            .expect("send");

        // Forcibly backdate the expiry to the Unix epoch (1970-01-01T00:00:00Z)
        // so all envelopes appear expired.
        // `SystemTime::UNIX_EPOCH` is the epoch: January 1, 1970, 00:00:00 UTC.
        // Any `SystemTime::now() <= UNIX_EPOCH` comparison returns false, meaning
        // every envelope appears expired immediately.
        // The `{ }` block ensures the write lock is released before compaction
        // tries to acquire its own write lock on the same state.
        {
            let mut state = service.state.write().unwrap();
            if let Some(queue) = state.passive_outbox.get_mut(&peer_id) {
                for env in queue.iter_mut() {
                    env._expires_at = SystemTime::UNIX_EPOCH;
                }
            }
        }

        // --- ACT: Run compaction. ---
        // `compact_passive_state` scans all queues and removes expired envelopes.
        // It returns the total count of envelopes it removed.
        let removed = service.compact_passive_state();
        assert!(removed >= 1);

        // --- ASSERT: Queue is now empty (expired envelope was removed). ---
        let state = service.state.read().unwrap();
        let remaining = state
            .passive_outbox
            .get(&peer_id)
            .map(|items| items.len())
            .unwrap_or(0);
        assert_eq!(remaining, 0);
    }

    /// `sync_room_messages_since` given a cursor message ID must return only the
    /// messages AFTER that cursor (i.e. the ones the UI hasn't seen yet).
    ///
    /// The "cursor" is a bookmark: the ID of the last message the UI has already
    /// displayed. By passing it to `sync_room_messages_since`, the UI says:
    /// "I have seen up to this point — give me everything newer."
    #[test]
    fn reconnect_sync_room_since_returns_only_newer_messages() {
        // --- ARRANGE: Send three messages to a room. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        let room_id = service.create_room("sync-room").expect("room create");

        service
            .send_message_to_room(&room_id, "m1")
            .expect("send m1");
        service
            .send_message_to_room(&room_id, "m2")
            .expect("send m2");
        service
            .send_message_to_room(&room_id, "m3")
            .expect("send m3");

        // The cursor is the ID of the FIRST message (m1).
        // This simulates a UI that has seen m1 but missed m2 and m3.
        let all = service.messages_for_room(&room_id);
        let cursor = all.first().expect("m1 exists").id.clone();

        // --- ACT + ASSERT: Only m2 and m3 should be in the delta. ---
        // `sync_room_messages_since` returns messages AFTER the cursor, so m1
        // is excluded (we already have it) and only m2, m3 are returned.
        let delta = service
            .sync_room_messages_since(&room_id, Some(&cursor))
            .expect("sync since cursor");
        assert_eq!(delta.len(), 2);
        assert_eq!(delta[0].text, "m2");
        assert_eq!(delta[1].text, "m3");
    }

    /// If the given cursor is not found in the room's history (the UI is too far
    /// behind or the history was trimmed), return the entire room history as a
    /// safe fallback.
    ///
    /// This handles the edge case where a cursor is stale or invalid — for example
    /// if the backend pruned old messages while the UI was disconnected. Rather than
    /// returning an error (which would leave the UI blank), the full history is
    /// returned so the UI can display something meaningful.
    #[test]
    fn reconnect_sync_room_with_unknown_cursor_returns_full_room() {
        // --- ARRANGE: Two messages in a room. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        let room_id = service.create_room("sync-room-full").expect("room create");
        service
            .send_message_to_room(&room_id, "x1")
            .expect("send x1");
        service
            .send_message_to_room(&room_id, "x2")
            .expect("send x2");

        // --- ACT + ASSERT: A completely unknown cursor returns the full history. ---
        // `"cursor-that-does-not-exist"` will never match any message ID, so
        // the function should fall back to returning ALL messages (both x1 and x2).
        let synced = service
            .sync_room_messages_since(&room_id, Some("cursor-that-does-not-exist"))
            .expect("sync full fallback");
        assert_eq!(synced.len(), 2);
    }

    /// `resumable_file_transfers()` must exclude completed and cancelled transfers
    /// and include only those in Queued or InProgress state.
    ///
    /// "Resumable" means: could be re-tried if the connection was interrupted.
    /// A Completed transfer is done — there is nothing to resume.
    /// A Canceled transfer was explicitly stopped — resuming it would be wrong.
    /// Only Queued and InProgress transfers make sense to offer in a "Resume" UI.
    #[test]
    fn resumable_file_transfers_excludes_completed_and_canceled() {
        // --- ARRANGE: Queue three transfers and put each in a different terminal state. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        let peer = "1111-2222-3333-4444";

        // Three transfers start in `Queued` state.
        let completed_id = service
            .queue_file_send(peer, "done.bin", 10)
            .expect("queue completed candidate");
        let canceled_id = service
            .queue_file_send(peer, "cancel.bin", 10)
            .expect("queue canceled candidate");
        let queued_id = service
            .queue_file_send(peer, "queued.bin", 10)
            .expect("queue resumable candidate");

        // Move the first to `Completed` by reporting that all 10 bytes transferred.
        service
            .update_file_transfer_progress(&completed_id, 10)
            .expect("complete transfer");
        // Move the second to `Canceled` explicitly.
        service
            .cancel_file_transfer(&canceled_id)
            .expect("cancel transfer");
        // The third stays in `Queued` — this is the one we expect to find in resumable.

        // --- ASSERT: Only the still-queued transfer appears in the resumable list. ---
        let resumable = service.resumable_file_transfers();
        // The queued transfer MUST be in the list.
        assert!(resumable.iter().any(|t| t.id == queued_id));
        // The completed transfer must NOT be in the list.
        assert!(!resumable.iter().any(|t| t.id == completed_id));
        // The canceled transfer must NOT be in the list.
        assert!(!resumable.iter().any(|t| t.id == canceled_id));
    }

    /// A reconnect sync snapshot must bundle both the message delta (messages
    /// after the cursor) AND the set of resumable file transfers into one struct.
    ///
    /// This tests that `reconnect_sync_snapshot` correctly combines results from
    /// `sync_room_messages_since` and `resumable_file_transfers` into one atomic
    /// bundle — the struct a Flutter UI receives when a peer reconnects.
    #[test]
    fn reconnect_sync_snapshot_includes_message_delta_and_transfer_resume_set() {
        // --- ARRANGE: Two messages in a room; cursor points to the first. ---
        let service = MeshInfinityService::new(ServiceConfig::default());
        let room_id = service.create_room("sync-snap").expect("room create");

        service
            .send_message_to_room(&room_id, "s1")
            .expect("send s1");
        service
            .send_message_to_room(&room_id, "s2")
            .expect("send s2");

        // The cursor is at s1, so the delta should contain only s2.
        let cursor = service
            .messages_for_room(&room_id)
            .first()
            .expect("message exists")
            .id
            .clone();

        // Also queue a file transfer that should appear in `resumable_transfers`.
        let queued_id = service
            .queue_file_send("AAAA-BBBB-CCCC-DDDD", "resume.bin", 42)
            .expect("queue transfer");

        // --- ACT + ASSERT: The snapshot must contain BOTH the message delta and the transfer. ---
        let snapshot = service
            .reconnect_sync_snapshot(&room_id, Some(&cursor))
            .expect("build snapshot");
        // Message delta: only s2 (s1 was before the cursor).
        assert_eq!(snapshot.missed_messages.len(), 1);
        assert_eq!(snapshot.missed_messages[0].text, "s2");
        // Resumable transfers: the queued_id should be present.
        assert!(snapshot
            .resumable_transfers
            .iter()
            .any(|transfer| transfer.id == queued_id));
    }

    /// A hosted service configured with `min_trust_level = Trusted` and
    /// `allowed_transports = [Tor]` must:
    /// - Deny access to a peer with Caution trust.
    /// - Allow access to a peer with Trusted trust over Tor.
    /// - Deny access to a Trusted peer attempting to connect over clearnet.
    ///
    /// This covers the two independent access-control axes of a hosted service:
    /// 1. The peer's trust level must meet or exceed `min_trust_level`.
    /// 2. The transport used to make the request must be in `allowed_transports`.
    /// BOTH conditions must be satisfied simultaneously.
    #[test]
    fn hosted_service_access_policy_enforces_trust_and_transport() {
        // --- ARRANGE: Configure a service that requires Trusted peers over Tor only. ---
        let service = MeshInfinityService::new(ServiceConfig::default());

        // `configure_hosted_service_with_policy` registers a service with:
        //   - id: "svc-work" — used to look it up in subsequent access checks
        //   - name: "Work API" — display name (not used by policy logic)
        //   - path: "/work" — the URL path prefix on the mesh
        //   - address: "10.0.0.10:8443" — the private local network target
        //   - enabled: true — service is active
        //   - policy: Trusted trust level minimum; only Tor transport allowed
        service
            .configure_hosted_service_with_policy(
                "svc-work",
                "Work API",
                "/work",
                "10.0.0.10:8443",
                true,
                HostedServicePolicy {
                    min_trust_level: CoreTrustLevel::Trusted,
                    allowed_transports: vec![TransportType::Tor],
                },
            )
            .expect("configure hosted service");

        // Pair a peer (starts at Caution trust by default — below Trusted).
        let _ = service.pair_peer("ABCD-EF01-2345-6789");
        let peer_id = service
            .peers
            .get_all_peers()
            .first()
            .map(|p| p.peer_id)
            .expect("peer should exist");

        // --- CHECK 1: Caution trust → access denied (trust level too low). ---
        // Even though Tor is the allowed transport, Caution < Trusted, so no access.
        let denied_low_trust = service
            .hosted_service_access_allowed("svc-work", &peer_id, TransportType::Tor)
            .expect("policy check");
        assert!(!denied_low_trust);

        // Promote the peer to Trusted.
        service
            .peers
            .update_trust_level(
                &peer_id,
                CoreTrustLevel::Trusted,
                VerificationMethod::SharedSecret,
            )
            .expect("raise trust");

        // --- CHECK 2: Trusted trust + Tor transport → access granted. ---
        // Both conditions satisfied: trust level ≥ Trusted AND transport is Tor.
        let allowed = service
            .hosted_service_access_allowed("svc-work", &peer_id, TransportType::Tor)
            .expect("policy check trusted tor");
        assert!(allowed);

        // --- CHECK 3: Trusted trust but Clearnet transport → access denied. ---
        // Trust level is fine, but Clearnet is not in the allowed_transports list.
        // This enforces the transport policy even for highly trusted peers.
        let denied_transport = service
            .hosted_service_access_allowed("svc-work", &peer_id, TransportType::Clearnet)
            .expect("policy check trusted clearnet");
        assert!(!denied_transport);
    }
