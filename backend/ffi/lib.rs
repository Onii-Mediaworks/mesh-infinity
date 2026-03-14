// FFI Bridge for Mesh Infinity
// Provides a C-compatible interface for Flutter integration.
//
// =============================================================================
// WHAT IS FFI?
// =============================================================================
//
// FFI stands for "Foreign Function Interface".  It is the mechanism that lets
// two programs written in DIFFERENT programming languages call each other's
// functions as if they were native.
//
// In Mesh Infinity, the backend is written in Rust and the UI is written in
// Dart (Flutter).  Dart cannot directly call Rust functions because each
// language compiles to a different binary format.  FFI solves this by agreeing
// on a shared "lowest common denominator" — the C calling convention — that
// both languages understand.
//
// Think of it like a universal power adapter: Rust speaks "Rust plug", Dart
// speaks "Dart plug", and FFI is the adapter in the middle that lets them
// connect even though they're different shapes.
//
// =============================================================================
// HOW IT WORKS IN PRACTICE
// =============================================================================
//
// 1. Rust compiles to a shared library (.so on Linux/Android, .dylib on macOS,
//    .dll on Windows).
// 2. Dart loads that library at runtime using `dart:ffi`.
// 3. Dart declares the function signatures it expects (in backend_bridge.dart).
// 4. Dart calls those functions; the OS routes the call into the Rust library.
// 5. Rust executes the function and returns a result back to Dart.
//
// Every function in this file that is callable from Dart has two special
// attributes:
//
//   #[no_mangle]      — tells the Rust compiler NOT to rename the function
//                       (Rust normally mangles names for uniqueness; that would
//                       break Dart's lookup).
//   pub extern "C"    — tells the compiler to use the C calling convention
//                       (the agreed-upon protocol for how arguments are passed
//                       in CPU registers/stack, and how return values come back).
//
// =============================================================================
// MEMORY OWNERSHIP ACROSS THE BOUNDARY
// =============================================================================
//
// Dart is garbage-collected; Rust uses ownership + lifetimes.  When Rust
// returns a pointer to heap-allocated data (e.g. a JSON string), Dart must call
// the matching "free" function (mi_free_string) when it's done with it, or the
// memory will leak.  Rust has no garbage collector to clean it up automatically.

// `VecDeque` is a double-ended queue ("deque").  We use it as a FIFO event buffer
// because both appending to the back (new event arrives) and removing from the
// front (Dart polls for the next event) are O(1) — much faster than using a
// plain `Vec`, where removing from the front requires shifting all elements.
use std::collections::VecDeque;
// `CStr`    — a borrowed view of a C string (null-terminated bytes).  Used to safely
//             read string pointers that arrive from Dart without copying them.
// `CString` — an owned, null-terminated string that Rust can hand back to Dart.
//             We allocate it on the heap, give Dart a raw pointer, and Dart must
//             call `mi_free_string` when done so we can drop it.
use std::ffi::{CStr, CString};
// `c_char`  — equivalent to C's `char` type (an 8-bit signed or unsigned byte,
//             depending on the platform).  C strings are `*const c_char`.
// `c_void`  — equivalent to C's `void *` — a pointer with no assumed type.
//             Used for the "user data" callback pattern where Dart passes an
//             arbitrary pointer that Rust echoes back in callbacks.
use std::os::raw::{c_char, c_void};
// `Path` is a borrowed filesystem path (like `&str` for strings, but for paths).
// Used when computing or validating the config directory location.
use std::path::Path;
// X25519 is a Diffie-Hellman key agreement algorithm used for encrypted tunnels.
// `StaticSecret` is a long-lived private key (as opposed to an ephemeral one
// used only for a single session).
use x25519_dalek::StaticSecret as X25519StaticSecret;
use std::sync::{
    // `AtomicBool` — a boolean that can be read/written safely from multiple threads
    // without a lock.  Used for the "should I shut down?" flag.
    atomic::{AtomicBool, Ordering},
    // `Arc`   — Atomic Reference Counted smart pointer.  Lets multiple owners share
    //           the same heap value; the value is dropped when the last owner goes away.
    // `Mutex` — Mutual exclusion lock.  Only one thread can hold it at a time.
    Arc, Mutex,
};
// A `JoinHandle` lets us wait for a background thread to finish.
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

// `IdentityStore`      — handles reading/writing the user's cryptographic identity
//                        (private key + display name) to/from an encrypted file on disk.
// `PersistedIdentity`  — the on-disk representation of the identity (serialised bytes).
use crate::auth::persistence::{IdentityStore, PersistedIdentity};
// `VerificationMethod` — an enum describing HOW a trust relationship was established
//                        (e.g. in-person QR scan, introductions via a mutual contact).
use crate::auth::web_of_trust::VerificationMethod as WotVerificationMethod;
// The core backend types that the FFI layer orchestrates:
// `FileTransferSummary`    — progress snapshot of a single file send/receive
// `HostedServicePolicy`    — rules for whether to host a relay service
// `HostedServiceSummary`   — metadata about a relay this node is running
// `IdentitySummary`        — the public-facing identity info (peer_id, name, key)
// `LocalProfile`           — the user's own display name + bio (public and private)
// `MeshInfinityService`    — the main backend object (owns all transports, rooms, peers)
// `Message`                — a single decrypted chat message
// `NodeMode`               — enum: normal peer / relay / bridge / gateway
// `PeerSummary`            — lightweight snapshot of a peer (id, name, trust, status)
// `PreloadedIdentity`      — a persisted identity loaded from disk and handed to the service
// `ReconnectSyncSnapshot`  — data used to efficiently resync state after reconnecting
// `RoomSummary`            — lightweight snapshot of a chat room (name, last message, etc.)
// `ServiceConfig`          — all settings needed to start the backend service
// `Settings`               — user-visible app settings (toggles for Tor, I2P, mDNS, etc.)
use crate::backend::{
    FileTransferSummary, HostedServicePolicy, HostedServiceSummary, IdentitySummary, LocalProfile,
    MeshInfinityService, Message, NodeMode, PeerSummary, PreloadedIdentity, ReconnectSyncSnapshot,
    RoomSummary, ServiceConfig, Settings,
};
// `TrustLevel` — how much we trust a peer: Untrusted / Known / Trusted / Admin.
use crate::core::TrustLevel;
// `MeshConfig`         — wire-level configuration (ports, transport toggles, etc.)
// `MeshInfinityError`  — the app's unified error enum (used for rich error codes)
// `PeerId`             — a `[u8; 32]` (32-byte) unique node identity
// `Result`             — `std::result::Result<T, MeshInfinityError>` type alias
// `TransportType`      — enum of the available transports (Clearnet, Tor, I2P, BLE, RF)
use crate::core::{MeshConfig, MeshInfinityError, PeerId, Result, TransportType};
// `BackupManager`  — creates and restores encrypted backups of the user's identity
//                    and room history.
// `EncryptedBackup`— the serialised, encrypted blob produced/consumed by BackupManager.
use crate::crypto::{BackupManager, EncryptedBackup};
// `crossbeam_channel` is a fast, multi-producer multi-consumer channel for
// passing data between threads.  `Receiver` is the reading end of a channel;
// `RecvTimeoutError` is the error returned when no message arrives within a
// deadline.
use crossbeam_channel::{Receiver, RecvTimeoutError};
// `serde_json` serialises Rust data structures to JSON strings (and back).
// `json!` is a macro that lets you write JSON-like syntax inline in Rust code.
// `Value` is a generic "any JSON value" type.
use serde_json::{json, Value};

// =============================================================================
// HELPER UTILITIES
// =============================================================================

/// Acquire a Mutex lock and convert a "poisoned" error into a plain String.
///
/// A Mutex becomes "poisoned" when the thread that was holding it panicked.
/// Rust's standard library then refuses to hand the lock to new callers
/// (because the data inside might be in an inconsistent state).
///
/// In an FFI context we'd rather return an error string to the caller than
/// propagate a panic across the C boundary (which would be undefined behaviour).
/// This helper converts the poisoning case into a normal `Err(String)`.
fn safe_lock<T>(mutex: &Mutex<T>) -> std::result::Result<std::sync::MutexGuard<'_, T>, String> {
    mutex
        .lock()
        .map_err(|e| format!("Mutex lock poisoned: {}", e))
}

/// Macro to catch panics at FFI boundaries.
///
/// # Why this matters
///
/// In normal Rust code a panic unwinds the stack and cleans up automatically.
/// But if a panic unwinds *across* an FFI boundary (i.e. into C or Dart code),
/// the behaviour is undefined — the program may crash, corrupt memory, or behave
/// randomly.
///
/// This macro wraps the expression `$body` in a `catch_unwind` call.  If the
/// code panics, the macro catches it, records the panic message in LAST_ERROR
/// (so Dart can retrieve it with `mi_last_error`), and returns `$default`
/// (typically a null pointer or -1) instead of crashing the whole process.
///
/// # Why it is `#[allow(unused_macros)]`
///
/// The macro exists as a safety net for functions that aren't yet guarded by it.
/// The compiler warns about declared-but-unused macros; this attribute silences
/// that warning while the codebase is still being hardened.
#[allow(unused_macros)]
macro_rules! ffi_catch_panic {
    ($body:expr, $default:expr) => {
        match panic::catch_unwind(panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(e) => {
                // `catch_unwind` returns the panic payload as `Box<dyn Any>`.
                // We try to downcast it to the two most common types (&str and
                // String) to get a human-readable message.
                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                    format!("Panic: {}", s)
                } else if let Some(s) = e.downcast_ref::<String>() {
                    format!("Panic: {}", s)
                } else {
                    "Unknown panic".to_string()
                };
                set_last_error(&msg);
                $default
            }
        }
    };
}

// =============================================================================
// C-COMPATIBLE DATA STRUCTURES  (#[repr(C)])
// =============================================================================
//
// When Rust and C (or Dart via FFI) share a data structure, both sides must
// agree on EXACTLY how the fields are laid out in memory: which field is at
// which byte offset, how many bytes each field occupies, and how they're aligned.
//
// By default Rust is free to reorder and pack struct fields however it likes for
// performance.  `#[repr(C)]` forces the compiler to use the C layout rules
// instead, which are well-defined and understood by every language that supports
// C FFI.

/// Configuration passed from Dart to `mesh_init` when starting the backend.
///
/// Each field corresponds to a user-facing setting in the app.  Using a struct
/// lets us pass all settings in a single call rather than one function per
/// setting.
#[repr(C)]
pub struct FfiMeshConfig {
    /// Filesystem path to the directory where config/identity files are stored.
    /// This is a C string (null-terminated UTF-8).  Null means "use the default".
    pub config_path: *const c_char,
    /// Verbosity of log output (0 = off, 1 = error, 2 = warn, 3 = info, etc.)
    pub log_level: u8,
    /// Whether to route traffic through the Tor anonymity network.
    pub enable_tor: bool,
    /// Whether to allow direct (unencrypted-at-transport-layer) connections.
    /// Even with clearnet enabled, messages are still end-to-end encrypted.
    pub enable_clearnet: bool,
    /// Whether to use mDNS/LAN discovery to find peers automatically.
    pub mesh_discovery: bool,
    /// Whether this node can act as a relay (forwarding traffic for other peers).
    pub allow_relays: bool,
    /// Whether to route traffic through the I2P (Invisible Internet Project) network.
    pub enable_i2p: bool,
    /// Whether to use Bluetooth LE for peer discovery and short-range transport.
    pub enable_bluetooth: bool,
    /// Whether to use RF radio (Meshtastic hardware) for long-range peer links.
    pub enable_rf: bool,
    /// UDP port used for WireGuard-style encrypted tunnels between peers.
    /// 0 means "use the compiled-in default".
    pub wireguard_port: u16,
    /// Maximum number of peers this node will track.  0 = use default.
    pub max_peers: u32,
    /// Maximum number of simultaneous open connections.  0 = use default.
    pub max_connections: u32,
    /// Operating mode of this node (see `node_mode_from_u8`).
    /// 0 = normal peer, other values = relay/bridge/etc.
    pub node_mode: u8,
}

/// A compact, C-compatible description of a remote peer.
///
/// Used when Dart needs peer identity information in binary form
/// (as opposed to the JSON form used by most other API calls).
#[repr(C)]
pub struct FfiPeerInfo {
    /// The peer's unique 32-byte identity (derived from its public key).
    pub peer_id: [u8; 32],
    /// The peer's 32-byte X25519 public key, used for key agreement.
    pub public_key: [u8; 32],
    /// Numeric trust level (0 = Untrusted, 1 = Known, 2 = Trusted, 3 = Admin).
    pub trust_level: u8,
    /// Bit-field of available transport types (bit 0 = clearnet, bit 1 = Tor, etc.)
    pub available_transports: u32,
}

/// A single message crossing the FFI boundary.
///
/// Because Dart and Rust use different memory models, the payload is represented
/// as a raw pointer + length rather than a Rust `Vec` or a Dart `Uint8List`.
#[repr(C)]
pub struct FfiMessage {
    /// 32-byte identity of the node that sent the message.
    pub sender_id: [u8; 32],
    /// 32-byte identity of the intended recipient (or all-zeros for broadcast).
    pub target_id: [u8; 32],
    /// Pointer to the raw message bytes in memory.
    /// IMPORTANT: this pointer is only valid for the duration of the FFI call.
    /// The caller must copy the data if it needs to keep it.
    pub payload: *const u8,
    /// Number of bytes pointed to by `payload`.
    pub payload_len: usize,
    /// Unix timestamp (seconds since 1970-01-01) when the message was created.
    pub timestamp: u64,
}

/// An opaque handle to the Mesh Infinity backend context.
///
/// "Opaque" means Dart can hold a pointer to it but cannot see inside it.
/// All it can do is pass the pointer back to Rust functions that need it.
///
/// This pattern (sometimes called an "opaque pointer" or "handle") is the
/// standard way to give a foreign language a reference to a complex Rust object
/// without exposing Rust's internal types across the FFI boundary.
///
/// The zero-size private field `_private: [u8; 0]` makes the struct non-empty
/// (which matters for pointer validity) while consuming no bytes at runtime.
/// The lack of public fields ensures that Dart code cannot accidentally modify
/// the internals — it can only pass the pointer around.
#[repr(C)]
pub struct MeshContext {
    _private: [u8; 0],
}

// =============================================================================
// CONSTANTS
// =============================================================================

// Lookup table for converting a nibble (4 bits, value 0-15) to its uppercase
// hex character.  Used when encoding binary IDs as human-readable hex strings.
const HEX: &[u8; 16] = b"0123456789ABCDEF";

// Maximum byte length of a chat message.  8 KiB is generous for text; larger
// payloads (files, images) use the separate file-transfer subsystem instead.
const MAX_TEXT_LEN: usize = 8192;

// Maximum byte length of a display name (username, room name, etc.)
const MAX_NAME_LEN: usize = 128;

// Maximum byte length of an ID string (room_id, message_id, peer_id hex, etc.)
const MAX_ID_LEN: usize = 128;

// Maximum byte length of a cryptographic key passed over FFI (e.g. PEM-encoded
// public key).  4 KiB is more than enough for any key format we use.
const MAX_KEY_LEN: usize = 4096;

// Maximum number of events that can queue up before older ones are dropped.
// This is a safety valve: if the Flutter UI is paused (e.g. the app is
// backgrounded) we don't want the queue to grow without bound and exhaust RAM.
// The oldest events are silently dropped when the limit is reached.
const MAX_EVENTS: usize = 256;

// =============================================================================
// PROCESS-WIDE (STATIC) STATE
// =============================================================================
//
// Because the FFI boundary is stateless (each call is independent), we need
// somewhere to store long-lived data between calls.  Rust `static` variables
// live for the entire duration of the process, just like C globals.
//
// Each one is wrapped in a `Mutex` so that concurrent calls from multiple
// threads (Dart isolates) don't cause data races.

/// The running backend service instance, stored as a reference-counted mutex-
/// guarded `ServiceHandle`.
///
/// The type is `Option<Arc<Mutex<ServiceHandle>>>`:
/// - `Option`  — `None` before `mesh_init` is called; `Some(...)` after.
/// - `Arc`     — lets us give a copy of the reference to `mesh_init`'s return
///               value (the `*mut MeshContext` pointer) AND keep one here for
///               global access via `get_service()`.
/// - `Mutex`   — the `ServiceHandle` is mutated by multiple threads.
static MESH_STATE: Mutex<Option<Arc<Mutex<ServiceHandle>>>> = Mutex::new(None);

/// The most recent error message from any FFI call.
///
/// Because C functions can't return rich error types, we follow the errno
/// convention: the function returns -1 (or null), and the error detail is
/// stored here.  Dart calls `mi_last_error()` to retrieve it.
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// The identity persistence layer, initialised during `mesh_init`.
///
/// Stored globally so that identity-related FFI calls (e.g. `mi_set_name`)
/// can access it without having to pass an extra pointer from Dart.
static IDENTITY_STORE: Mutex<Option<IdentityStore>> = Mutex::new(None);

/// An optional override for the directory where config/identity files are stored.
///
/// On Android the app data directory is only known at runtime (the OS assigns
/// it), so Dart calls `mi_set_config_dir` (or the JNI equivalent) BEFORE
/// `mesh_init` to tell Rust where to look.  This static holds that value.
static CONFIG_DIR_OVERRIDE: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

// =============================================================================
// SERVICE HANDLE — the internal owner of the running backend
// =============================================================================

/// `ServiceHandle` wraps the live `MeshInfinityService` together with
/// everything needed to bridge it into the FFI event model.
///
/// Dart polls for events by calling `mi_poll_events`.  Under the hood,
/// `ServiceHandle` maintains a bounded FIFO queue of `BackendEvent` values.
/// Background listener threads populate the queue; poll drains it.
///
/// This struct is NOT visible to Dart — Dart only ever sees the opaque
/// `*mut MeshContext` pointer that secretly points to a
/// `Mutex<ServiceHandle>` on the heap.
struct ServiceHandle {
    /// The actual backend — manages peers, rooms, messages, file transfers,
    /// transport connections, and cryptographic state.
    service: MeshInfinityService,

    /// A thread-safe FIFO queue of events waiting to be delivered to Dart.
    ///
    /// `VecDeque` (double-ended queue) is used rather than `Vec` because
    /// adding to the back and removing from the front are both O(1).
    events: Arc<Mutex<VecDeque<BackendEvent>>>,

    /// Cooperative shutdown flag shared with background listener threads.
    ///
    /// When set to `true`, each background thread notices on its next iteration
    /// and exits cleanly.  `AtomicBool` can be read/written from multiple
    /// threads without a Mutex, making the check very cheap.
    shutdown: Arc<AtomicBool>,

    /// Handle for the thread that listens for newly-received chat messages
    /// from the backend and enqueues `BackendEvent::MessageAdded` events.
    message_thread: Option<JoinHandle<()>>,

    /// Handle for the thread that listens for file-transfer progress updates
    /// and enqueues `BackendEvent::TransferUpdated` events.
    transfer_thread: Option<JoinHandle<()>>,
}

impl ServiceHandle {
    /// Construct a new `ServiceHandle` around a freshly-created service.
    ///
    /// Registers listeners on the service's internal channels, then spawns
    /// one background thread per listener to forward events into the shared
    /// queue.  The threads run until `shutdown()` is called.
    fn new(service: MeshInfinityService) -> Self {
        // Create the shared event queue.  Starts empty.
        let events = Arc::new(Mutex::new(VecDeque::new()));

        // The shutdown flag starts `false` (threads should keep running).
        let shutdown = Arc::new(AtomicBool::new(false));

        // `register_message_listener` returns a crossbeam `Receiver<Message>`.
        // Whenever the backend receives a new encrypted message, decrypts it,
        // and processes it, it sends a copy on this channel.
        let message_receiver = service.register_message_listener();

        // Same pattern for file-transfer progress updates.
        let transfer_receiver = service.register_transfer_listener();

        // Spawn the listener thread for messages.
        // `BackendEvent::MessageAdded` is a function-pointer that converts a
        // `Message` into a `BackendEvent` — passed as the `mapper` argument.
        let message_thread = Some(spawn_listener(
            message_receiver,
            Arc::clone(&events),
            Arc::clone(&shutdown),
            BackendEvent::MessageAdded,
        ));

        // Spawn the listener thread for file-transfer updates.
        let transfer_thread = Some(spawn_listener(
            transfer_receiver,
            Arc::clone(&events),
            Arc::clone(&shutdown),
            BackendEvent::TransferUpdated,
        ));

        Self {
            service,
            events,
            shutdown,
            message_thread,
            transfer_thread,
        }
    }

    /// Push a single event into the queue.
    ///
    /// If the queue is already at `MAX_EVENTS` capacity, the oldest event is
    /// silently dropped to make room.  This prevents unbounded memory growth
    /// when Dart is not polling (e.g. the app is in the background).
    fn push_event(&self, event: BackendEvent) {
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= MAX_EVENTS {
                // Drop the oldest event (front of the queue) rather than the
                // newest, on the theory that fresh data is more useful.
                events.pop_front();
            }
            events.push_back(event);
        }
    }

    /// Remove and return up to `max` events from the front of the queue.
    ///
    /// Called by the Dart-facing `mi_poll_events` function.  Returns an
    /// empty `Vec` if the queue is empty or if the lock is poisoned.
    fn drain_events(&self, max: usize) -> Vec<BackendEvent> {
        let Ok(mut events) = self.events.lock() else {
            return Vec::new();
        };
        let mut drained = Vec::new();
        for _ in 0..max {
            if let Some(event) = events.pop_front() {
                drained.push(event);
            } else {
                break;
            }
        }
        drained
    }

    /// Signal background threads to exit and wait for them to finish.
    ///
    /// `shutdown.store(true, ...)` is seen by each thread on its next
    /// iteration, causing it to `break` out of its loop.  `handle.join()`
    /// blocks until the thread has actually exited, ensuring no thread is
    /// still accessing `events` or `service` when this struct is dropped.
    fn shutdown(&mut self) {
        // Signal all threads to stop.
        self.shutdown.store(true, Ordering::Relaxed);
        // Wait for the message thread.
        if let Some(handle) = self.message_thread.take() {
            let _ = handle.join();
        }
        // Wait for the transfer thread.
        if let Some(handle) = self.transfer_thread.take() {
            let _ = handle.join();
        }
    }
}

// =============================================================================
// BACKEND EVENT ENUM
// =============================================================================

/// Every kind of thing that can happen inside the Rust backend that Dart
/// needs to know about.
///
/// This is an internal Rust enum — it is never sent across the FFI boundary
/// as-is.  Instead, `mi_poll_events` serialises whichever events are queued
/// into a JSON array and hands the string to Dart, which parses it in
/// `event_models.dart`.
///
/// The design is a **poll model** (Dart asks "anything new?") rather than a
/// **push model** (Rust calls back into Dart).  Push callbacks across FFI
/// are tricky to get right on all platforms (especially iOS where Dart
/// isolates have strict threading constraints), so polling every 200 ms is
/// simpler and reliable.
enum BackendEvent {
    /// A new chat message was received and decrypted.
    /// Carries the full `Message` struct with sender, text, timestamp, etc.
    MessageAdded(Message),

    /// The metadata of a room changed (new message, name change, unread count).
    /// Dart uses this to refresh the conversation list without re-fetching all rooms.
    RoomUpdated(RoomSummary),

    /// A room was deleted.  The `String` is the room's ID.
    RoomDeleted(String),

    /// A specific message within a room was deleted (e.g. by the sender).
    /// Struct variant with named fields because both IDs are needed to
    /// locate the message in Dart's state.
    MessageDeleted { room_id: String, message_id: String },

    /// A peer's status or trust level changed (came online, went offline, etc.)
    PeerUpdated(PeerSummary),

    /// A file transfer's progress was updated (bytes sent/received, status change).
    TransferUpdated(FileTransferSummary),

    /// The user changed a setting that affects behaviour (e.g. toggled Tor).
    /// Dart refreshes the settings screen when it sees this.
    SettingsUpdated(Settings),

    /// The currently-focused room changed.
    /// `None` means no room is active (e.g. the user navigated away from chat).
    ActiveRoomChanged(Option<String>),

    /// The trust level for a specific peer was updated.
    /// Sent after the user approves/revokes a peer in the UI.
    TrustUpdated { peer_id: String, trust_level: i32 },
}

// =============================================================================
// GENERIC LISTENER THREAD FACTORY
// =============================================================================

/// Spawn a background thread that reads items from `receiver`, converts each
/// one to a `BackendEvent` using `mapper`, and pushes the result into `events`.
///
/// This is a *generic* helper: `T` is the concrete type of item on the channel
/// (e.g. `Message` for the message listener, `FileTransferSummary` for the
/// transfer listener).
///
/// # Type bounds
/// - `T: Send`     — the item type must be safe to move to another thread.
/// - `T: 'static`  — the item type must not contain borrowed references, because
///                   threads can outlive the scope they were created in.
///
/// # Parameters
/// - `receiver`  — the channel end to read from
/// - `events`    — shared queue to push events onto
/// - `shutdown`  — flag to check for cooperative shutdown
/// - `mapper`    — function that wraps a `T` into the appropriate `BackendEvent`
///                 variant (e.g. `BackendEvent::MessageAdded`)
fn spawn_listener<T: Send + 'static>(
    receiver: Receiver<T>,
    events: Arc<Mutex<VecDeque<BackendEvent>>>,
    shutdown: Arc<AtomicBool>,
    mapper: fn(T) -> BackendEvent,
) -> JoinHandle<()> {
    std::thread::spawn(move || loop {
        // Check the cooperative shutdown flag first.
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Wait up to 250 ms for an item.  This timeout exists so we check the
        // shutdown flag at least every 250 ms — otherwise a thread waiting on an
        // empty channel would block forever and never notice the shutdown signal.
        match receiver.recv_timeout(Duration::from_millis(250)) {
            // An item arrived: convert it to an event and enqueue it.
            Ok(item) => {
                let event = mapper(item);
                if let Ok(mut queue) = events.lock() {
                    // Enforce the queue size cap (same logic as `push_event`).
                    if queue.len() >= MAX_EVENTS {
                        queue.pop_front();
                    }
                    queue.push_back(event);
                }
            }
            // No item arrived within 250 ms — loop back and check shutdown flag.
            Err(RecvTimeoutError::Timeout) => continue,
            // The sending end of the channel was dropped (service shut down).
            // Exit the thread cleanly.
            Err(RecvTimeoutError::Disconnected) => break,
        }
    })
}

// =============================================================================
// EXPORTED FFI FUNCTIONS
// =============================================================================
//
// These are the functions Dart calls.  Each one:
//   1. Starts with `#[no_mangle]` so the compiler preserves the exact name.
//   2. Is declared `pub extern "C"` so the linker exports it with C ABI.
//   3. Validates all pointer arguments before dereferencing them, because
//      Dart might pass null or a stale pointer.
//   4. On error: calls `set_last_error(...)` and returns -1 or null.
//      Dart retrieves the human-readable message via `mi_last_error()`.

/// Initialise the Mesh Infinity backend.
///
/// This is the FIRST function Dart calls after loading the shared library.
/// It must be called exactly once before any other `mesh_*` or `mi_*` function.
///
/// Internally this function:
/// 1. Converts the C config struct into a Rust `MeshConfig`.
/// 2. Determines the config directory (checking the override set by
///    `mi_set_config_dir` first, then falling back to platform defaults).
/// 3. Loads a persisted identity from disk if one exists.
/// 4. Creates a `MeshInfinityService` (starts transports, crypto, etc.).
/// 5. Wraps everything in a `ServiceHandle`, stores it in `MESH_STATE`.
/// 6. Returns an opaque pointer that Dart must pass to every subsequent call.
///
/// The function is **idempotent**: calling it a second time returns the
/// already-running instance without creating a new one.
///
/// # Return value
/// - Non-null pointer on success (the `MeshContext` handle).
/// - Null pointer on failure; call `mi_last_error()` for details.
///
/// # Safety
/// `config` must be a valid, non-null pointer to a `FfiMeshConfig` struct.
/// The `config_path` field within it (if non-null) must point to a valid
/// null-terminated C string.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mesh_init(config: *const FfiMeshConfig) -> *mut MeshContext {
    // Guard against a null config pointer — Dart might pass one if it forgot
    // to initialise the struct.
    if config.is_null() {
        set_last_error("config pointer was null");
        return std::ptr::null_mut();
    }

    // Dereference the config pointer.  This is `unsafe` because Rust cannot
    // verify at compile time that the pointer is valid — we've already checked
    // for null above, so this is safe in practice.
    let config = unsafe { config_ref(config) };

    // Build a `MeshConfig::default()` so we have sensible fallback values for
    // any field the caller left as 0.
    let defaults = MeshConfig::default();

    // --- Translate C struct → Rust struct ------------------------------------
    let rust_config = MeshConfig {
        // `config_path` is a nullable C string.  If null, use None (no override).
        config_path: if config.config_path.is_null() {
            None
        } else {
            // `CStr::from_ptr` interprets raw bytes as a null-terminated C string.
            // `to_string_lossy` converts to a Rust `&str`, replacing invalid UTF-8
            // with U+FFFD replacement characters.
            let c_str = unsafe { CStr::from_ptr(config.config_path) };
            Some(c_str.to_string_lossy().into_owned())
        },
        log_level: config.log_level,
        enable_tor: config.enable_tor,
        enable_clearnet: config.enable_clearnet,
        mesh_discovery: config.mesh_discovery,
        allow_relays: config.allow_relays,
        enable_i2p: config.enable_i2p,
        enable_bluetooth: config.enable_bluetooth,
        enable_rf: config.enable_rf,
        // For numeric settings, 0 is treated as "not specified; use default".
        // This lets Dart omit fields it doesn't care about without having to
        // know the default values.
        wireguard_port: if config.wireguard_port == 0 {
            defaults.wireguard_port
        } else {
            config.wireguard_port
        },
        max_peers: if config.max_peers == 0 {
            defaults.max_peers
        } else {
            config.max_peers as usize
        },
        max_connections: if config.max_connections == 0 {
            defaults.max_connections
        } else {
            config.max_connections as usize
        },
    };

    // --- Resolve the config directory ----------------------------------------
    //
    // Priority order (highest to lowest):
    //   1. An explicit override set via `mi_set_config_dir` or the JNI variant.
    //      This is how Android passes its app-private data directory.
    //   2. The `config_path` field from the config struct passed to this call.
    //   3. `$HOME/.mesh-infinity` — sensible default on desktop platforms.
    //   4. `.mesh-infinity` in the current working directory — last resort.
    let config_dir = if let Ok(override_guard) = CONFIG_DIR_OVERRIDE.lock() {
        override_guard.clone().unwrap_or_else(|| {
            rust_config
                .config_path
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::var("HOME")
                        .map(|h| std::path::PathBuf::from(h).join(".mesh-infinity"))
                        .unwrap_or_else(|_| std::path::PathBuf::from(".mesh-infinity"))
                })
        })
    } else {
        // The lock was poisoned — fall back to the same priority chain without
        // the override.
        rust_config
            .config_path
            .as_deref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".mesh-infinity"))
                    .unwrap_or_else(|_| std::path::PathBuf::from(".mesh-infinity"))
            })
    };

    // --- Identity persistence ------------------------------------------------
    //
    // The identity (private key + display name) is stored encrypted on disk so
    // that the user keeps the same cryptographic identity across app restarts.
    // We create an `IdentityStore` pointing at `config_dir` and store it in the
    // global so later FFI calls (e.g. `mi_set_name`) can use it too.
    let store = IdentityStore::new(&config_dir);
    if let Ok(mut store_guard) = IDENTITY_STORE.lock() {
        *store_guard = Some(IdentityStore::new(&config_dir));
    }

    // Try to load a previously-saved identity.  If none exists yet (first run)
    // `store.exists()` returns false and we pass `None` to the service, which
    // will generate a fresh identity.
    let preloaded_identity = if store.exists() {
        match store.load() {
            Ok(persisted) => {
                // `try_into()` converts a `Vec<u8>` to a `[u8; 32]`.
                // It fails if the stored bytes are not exactly 32 bytes long
                // (which would indicate a corrupted or incompatible key file).
                let ed25519_ok: Option<[u8; 32]> =
                    persisted.ed25519_secret.as_slice().try_into().ok();
                let x25519_ok: Option<[u8; 32]> =
                    persisted.x25519_secret.as_slice().try_into().ok();
                match (ed25519_ok, x25519_ok) {
                    // Both keys loaded and have the correct length — reconstruct
                    // the identity and hand it to the service.
                    (Some(ed25519), Some(x25519)) => {
                        let profile = LocalProfile {
                            public_display_name: persisted.public_display_name,
                            identity_is_public: persisted.identity_is_public,
                            private_display_name: persisted.private_display_name,
                            private_bio: persisted.private_bio,
                        };
                        Some(PreloadedIdentity {
                            ed25519_secret: ed25519,
                            x25519_secret: x25519,
                            name: persisted.name,
                            profile,
                        })
                    }
                    // One or both keys are the wrong length — the file is
                    // corrupted.  Log the error but continue (the service will
                    // generate a new identity, effectively resetting the user).
                    _ => {
                        set_last_error("Persisted identity has malformed key material");
                        None
                    }
                }
            }
            Err(e) => {
                set_last_error(format!("Failed to load persisted identity: {}", e));
                None
            }
        }
    } else {
        // First run — no identity on disk yet.
        None
    };

    // --- Assemble the service config and start --------------------------------
    let service_config = ServiceConfig {
        initial_mode: node_mode_from_u8(config.node_mode),
        mesh_config: rust_config,
        identity_name: None,
        preloaded_identity,
    };

    let Ok(mut state) = MESH_STATE.lock() else {
        set_last_error("Failed to acquire mesh state lock");
        return std::ptr::null_mut();
    };

    // Idempotency: if the service is already running, return the existing
    // context pointer rather than creating a second instance.
    // `Arc::clone` increments the reference count; `Arc::into_raw` gives us
    // a raw pointer to the `Arc`'s heap allocation.  Dart stores this as the
    // context handle and passes it back on every subsequent call.
    if let Some(existing) = state.as_ref() {
        return Arc::into_raw(Arc::clone(existing)) as *mut MeshContext;
    }

    // First-time initialisation: create the service and wrap it.
    let service = MeshInfinityService::new(service_config);
    let handle = ServiceHandle::new(service);
    // Wrap in Arc<Mutex<>> so the handle can be shared between the global
    // MESH_STATE and the returned pointer without lifetime issues.
    let arc_handle = Arc::new(Mutex::new(handle));

    // Store in global so `get_service()` can find it.
    *state = Some(arc_handle.clone());

    // Cast the Arc pointer to `*mut MeshContext`.  From Dart's perspective this
    // is just an opaque integer-sized address.  The actual data on the heap is
    // a `Mutex<ServiceHandle>` — but Dart never needs to know that.
    Arc::into_raw(arc_handle) as *mut MeshContext
}

/// Override the directory where identity and config files are stored.
///
/// Must be called **before** `mesh_init`.  On desktop platforms the default
/// (`$HOME/.mesh-infinity`) is usually fine.  On Android the OS assigns a
/// private per-app directory at runtime (e.g. `/data/data/com.example.app/files`),
/// so this function (or its JNI equivalent below) must be called from Dart or
/// Java before the backend is initialised.
///
/// # Return value
/// - 0  on success
/// - -1 on failure (null pointer, empty string, or lock failure)
#[no_mangle]
pub extern "C" fn mi_set_config_dir(path_ptr: *const c_char) -> i32 {
    if path_ptr.is_null() {
        set_last_error("config path pointer was null");
        return -1;
    }

    // `read_cstr` copies the C string into an owned Rust `String`, enforcing
    // the maximum length to prevent buffer-overread attacks.
    let path = match read_cstr(path_ptr, 4096, "config_path") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return -1;
        }
    };

    let trimmed = path.trim();
    if trimmed.is_empty() {
        set_last_error("config path was empty");
        return -1;
    }

    let mut guard = CONFIG_DIR_OVERRIDE.lock().unwrap();
    *guard = Some(std::path::PathBuf::from(trimmed));
    0
}

/// Android-only JNI entry point for setting the config directory from Java/Kotlin.
///
/// # What is JNI?
///
/// JNI (Java Native Interface) is Android's equivalent of FFI for calling native
/// code from Java/Kotlin.  The function name must follow the JNI naming convention
/// exactly: `Java_<package_underscored>_<ClassName>_<methodName>`.
///
/// On Android, Flutter runs inside an `Activity` (the Android equivalent of a
/// view-controller).  Before Dart's isolate is ready, the Java `MainActivity`
/// can call this native method directly to pass the app's private storage path.
///
/// This approach is needed because on Android:
/// - The app-private directory is not a fixed path — it includes the app's package
///   name and a user-specific numeric ID.
/// - The Rust code cannot call Android APIs to discover this path itself without
///   going through the JNI layer first.
///
/// `#[cfg(target_os = "android")]` means this function is compiled ONLY when
/// building for Android.  On other platforms it simply doesn't exist, which is
/// correct because JNI is Android-specific.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_MainActivity_nativeSetConfigDir(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    path: jni::objects::JString,
) -> jni::sys::jint {
    // `env.get_string` converts the Java `String` object into a Rust string.
    // Java strings are UTF-16 internally; the JNI library handles the conversion.
    let Ok(path_str) = env.get_string(&path) else {
        set_last_error("Failed to read config dir from Java");
        return -1;
    };
    let trimmed = path_str.to_string_lossy();
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        set_last_error("config path was empty");
        return -1;
    }
    let mut guard = CONFIG_DIR_OVERRIDE.lock().unwrap();
    *guard = Some(std::path::PathBuf::from(trimmed));
    0
}

/// Send a chat message in the currently-active room.
///
/// Dart calls this when the user taps "Send".  The message is:
/// 1. Validated (non-null, non-empty, not too long, valid UTF-8).
/// 2. Encrypted end-to-end by the backend for all room members.
/// 3. Sent to connected peers over whichever transports are active.
/// 4. Stored locally so it appears in the sender's own chat history.
///
/// After sending, `push_room_update` enqueues a `RoomUpdated` event so the
/// Flutter UI refreshes the conversation list (e.g. updates the preview text
/// and timestamp).
///
/// # Return value
/// - 0  on success
/// - -1 on argument error
/// - Other negative codes map to specific `MeshInfinityError` variants
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mesh_send_message(ctx: *mut MeshContext, message: *const FfiMessage) -> i32 {
    if ctx.is_null() || message.is_null() {
        set_last_error("message pointer was null");
        return -1;
    }

    let message = unsafe { message_ref(message) };

    // Guard against an empty payload — sending a zero-length message is a no-op.
    if message.payload.is_null() || message.payload_len == 0 {
        set_last_error("message payload was empty");
        return -1;
    }

    // Enforce the maximum message size.  Messages larger than 8 KiB should use
    // the file-transfer subsystem instead.
    if message.payload_len > MAX_TEXT_LEN {
        set_last_error("message payload too large");
        return rust_error_to_c_code(&MeshInfinityError::InvalidMessageFormat);
    }

    // Reinterpret the raw bytes pointed to by `payload` as a Rust slice.
    // This is safe because we've verified the pointer is non-null and the
    // length is within bounds.
    let payload = unsafe { std::slice::from_raw_parts(message.payload, message.payload_len) };

    // Verify the bytes are valid UTF-8.  All chat messages in Mesh Infinity are
    // text strings; binary data should travel via file transfer instead.
    let text = match std::str::from_utf8(payload) {
        Ok(value) => value,
        Err(_) => {
            set_last_error("message payload was not valid utf-8");
            return rust_error_to_c_code(&MeshInfinityError::InvalidMessageFormat);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let Ok(mut guard) = service.lock() else {
        set_last_error("Failed to acquire service lock");
        return -1;
    };
    match guard.service.send_message(text) {
        Ok(()) => {
            // After sending, tell Flutter to refresh the room list so the
            // new message appears as the conversation's preview text.
            push_room_update(&mut guard, None);
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

/// Legacy callback-based message delivery (superseded by `mi_poll_events`).
///
/// This function uses a **callback** pattern: the caller passes a function pointer,
/// and Rust calls that function once for each pending message.
///
/// # Why does this exist alongside `mi_poll_events`?
///
/// This function predates the polling event system.  It is kept for backwards
/// compatibility with any Dart code that still uses the callback approach.
/// New Dart code should use `mi_poll_events` instead, because:
///   - Callbacks across FFI are harder to reason about on multi-threaded Dart.
///   - `mi_poll_events` returns all event types in one JSON array, whereas this
///     function only surfaces `MessageAdded` events.
///   - The polling model avoids re-entrant calls from the Rust side into Dart.
///
/// # Parameters
/// - `ctx`       — opaque context pointer returned by `mesh_init`
/// - `callback`  — function pointer that Dart provides; Rust calls it with each message
/// - `user_data` — arbitrary pointer that Dart passes through unchanged to its
///                 own callback; useful for associating the callback with a
///                 specific Dart object (like a closure capture)
///
/// # Memory note
/// The `FfiMessage` struct passed to the callback is stack-allocated inside this
/// function.  The callback must NOT store the pointer past the callback's return —
/// the memory is freed when this function returns.
#[no_mangle]
pub extern "C" fn mesh_receive_messages(
    ctx: *mut MeshContext,
    callback: extern "C" fn(*const FfiMessage, *mut c_void),
    user_data: *mut c_void,
) {
    if ctx.is_null() {
        return;
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(_) => return,
    };

    // Drain the event queue and release the lock before calling `callback`.
    // Holding the lock while calling into Dart would risk deadlock if Dart
    // calls back into Rust from within the callback.
    let events = {
        let guard = service.lock().unwrap();
        guard.drain_events(MAX_EVENTS)
    };

    for event in events {
        // Only forward MessageAdded events through this legacy API.
        // Other event types (RoomUpdated, PeerUpdated, etc.) are silently
        // discarded here — use mi_poll_events to receive all event types.
        if let BackendEvent::MessageAdded(message) = event {
            let bytes = message.text.as_bytes();
            // Build a stack-allocated FfiMessage pointing at the bytes.
            // sender_id and target_id are zero-filled here because the legacy
            // API predates the full message model.
            let ffi_message = FfiMessage {
                sender_id: [0u8; 32],
                target_id: [0u8; 32],
                payload: bytes.as_ptr(),
                payload_len: bytes.len(),
                timestamp: 0,
            };
            // Call Dart's function pointer.  The `extern "C"` ensures the
            // call uses the C calling convention both sides agreed on.
            callback(&ffi_message as *const FfiMessage, user_data);
        }
    }
}

/// Shut down the Mesh Infinity backend and release all resources.
///
/// Dart calls this when the application is closing (e.g. in `dispose()` or
/// the Flutter lifecycle `detached` state).
///
/// This function:
/// 1. Signals all background threads to stop (via the shutdown `AtomicBool`).
/// 2. Waits for each thread to exit (`join()`), ensuring no thread is still
///    running after this call returns.
/// 3. Drops the `ServiceHandle`, which in turn drops the `MeshInfinityService`,
///    closing all open network sockets and freeing associated memory.
/// 4. Clears `MESH_STATE` to `None` so that subsequent calls to `get_service()`
///    correctly report "not initialised".
///
/// After this call, the context pointer `ctx` is invalid.  Dart must not use
/// it again.  To restart the backend, call `mesh_init` again.
///
/// # Memory ownership
/// The `ctx` pointer was created by `Arc::into_raw` in `mesh_init`.
/// `Arc::from_raw` here is the matching operation that reconstructs the
/// `Arc` and allows Rust to drop it (decrementing the reference count).
/// Once the count reaches zero the heap allocation is freed.
#[no_mangle]
pub extern "C" fn mesh_destroy(ctx: *mut MeshContext) {
    if ctx.is_null() {
        return;
    }

    // Validate the context pointer matches our stored state before dereferencing
    let Ok(mut state) = MESH_STATE.lock() else {
        set_last_error("Failed to acquire mesh state lock during destroy");
        return;
    };

    if state.is_none() {
        set_last_error("Attempted to destroy uninitialized mesh context");
        return;
    }

    // Reconstruct the Arc from the raw pointer.  `Arc::from_raw` is the exact
    // inverse of `Arc::into_raw` used in mesh_init.  Once this `arc` variable
    // goes out of scope at the end of this function, Rust's ownership system
    // decrements the reference count and frees the memory if it reaches zero.
    let arc = unsafe { Arc::from_raw(ctx as *const Mutex<ServiceHandle>) };
    if let Ok(mut guard) = arc.lock() {
        // Tell all background listener threads to exit and wait for them.
        guard.shutdown();
    }

    // Remove the stored Arc from the global state.  This drops the last
    // remaining strong reference, allowing the ServiceHandle to be freed.
    *state = None;
}

/// Return the version number of this FFI interface.
///
/// Dart can call this to verify it is talking to a compatible version of
/// the Rust library before attempting any other calls.  If the version
/// number Dart expects does not match what the library returns, Dart should
/// refuse to proceed and show an error to the user.
///
/// This is a simple forward-compatibility check: if we ever change the FFI
/// ABI in a breaking way, we increment this number so older Dart code can
/// detect the mismatch immediately rather than crashing with a segfault.
///
/// Returns: 1 (the current FFI API version)
#[no_mangle]
pub extern "C" fn mesh_infinity_ffi_version() -> u32 {
    1
}

/// Return all chat rooms as a JSON array string.
///
/// Dart calls this to populate the conversation list screen.  Each element
/// in the array represents one room with fields:
///   `id`, `name`, `lastMessage`, `unreadCount`, `timestamp`
///
/// # Why JSON instead of a struct array?
///
/// Passing an array of C structs across FFI requires Dart to declare the
/// exact memory layout of each struct and keep it perfectly in sync with the
/// Rust definition.  Any mismatch (padding, field order, alignment) causes
/// silent memory corruption.
///
/// A JSON string is just bytes.  Dart calls `jsonDecode()` on it, which
/// produces a plain Dart `Map<String, dynamic>`.  There is no memory layout
/// to get wrong.  The downside is a small serialisation cost, which is
/// negligible for typical room list sizes (< 1000 rooms).
///
/// # Return value
/// - Non-null `*mut c_char` pointing to a null-terminated UTF-8 JSON string on success.
/// - Null pointer on failure; call `mi_last_error()` for the message.
///
/// # Memory ownership
/// **The caller (Dart) is responsible for freeing this string** by calling
/// `mi_free_string(ptr)`.  If Dart does not free it, the memory leaks because
/// Rust has no garbage collector to reclaim it.
#[no_mangle]
pub extern "C" fn mi_rooms_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    // `rooms()` returns a Vec of RoomSummary structs.
    // `room_to_json` converts each one to a serde_json::Value.
    // `json_to_c_string` serialises the whole array and allocates a C string.
    let rooms = service.lock().unwrap().service.rooms();
    let value = Value::Array(rooms.iter().map(room_to_json).collect());
    json_to_c_string(value)
}

/// Return messages for a room as a JSON array string.
///
/// Dart calls this when the user opens a conversation thread.  Each element
/// in the returned array represents one message with fields:
///   `id`, `roomId`, `sender`, `text`, `timestamp`, `isOutgoing`
///
/// # Parameters
/// - `ctx`     — opaque context pointer returned by `mesh_init`
/// - `room_id` — null-terminated UTF-8 string containing the room's ID,
///               OR null to get messages for whichever room is currently active
///
/// # Return value
/// - Non-null `*mut c_char` pointing to a null-terminated UTF-8 JSON string on success.
/// - Null pointer on failure; call `mi_last_error()` for the message.
///
/// # Memory ownership
/// The caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_messages_json(ctx: *mut MeshContext, room_id: *const c_char) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    // If room_id is null, fall back to the currently-active room.
    // This allows Dart to call this function without knowing the current room ID
    // (e.g. when first opening the app and the backend already has an active room).
    let messages = if room_id.is_null() {
        service.lock().unwrap().service.messages_for_active_room()
    } else {
        match read_cstr(room_id, MAX_ID_LEN, "room_id") {
            Ok(id) => service.lock().unwrap().service.messages_for_room(&id),
            Err(err) => {
                set_last_error(err.to_string());
                return std::ptr::null_mut();
            }
        }
    };

    let value = Value::Array(messages.iter().map(message_to_json).collect());
    json_to_c_string(value)
}

/// Fetch messages in a room that arrived after a specific message ID.
///
/// This is used for incremental sync: instead of re-fetching the entire
/// message history every time (which could be thousands of messages),
/// Dart provides the ID of the last message it already has, and Rust
/// returns only the newer ones.
///
/// Example usage in Dart:
///   - User opens a room that was last read at message "msg_42"
///   - Dart calls `mi_sync_room_messages_json(ctx, "room_1", "msg_42")`
///   - Rust returns only messages after "msg_42" (e.g. "msg_43", "msg_44")
///   - Dart appends those to its existing list — no full re-fetch needed
///
/// # Parameters
/// - `ctx`              — opaque context pointer returned by `mesh_init`
/// - `room_id`          — null-terminated UTF-8 string: the room to query
/// - `after_message_id` — null-terminated UTF-8 string: return messages after
///                        this ID, OR null to return all messages (full fetch)
///
/// # Return value
/// - Non-null JSON array string on success.
/// - Null pointer on failure; call `mi_last_error()` for the message.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_sync_room_messages_json(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    after_message_id: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let room_id = match read_cstr(room_id, MAX_ID_LEN, "room_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    // `after_message_id` is optional.  Convert null to Rust's `None` (no filter).
    let after_message_id = if after_message_id.is_null() {
        None
    } else {
        match read_cstr(after_message_id, MAX_ID_LEN, "after_message_id") {
            Ok(value) => Some(value),
            Err(err) => {
                set_last_error(err.to_string());
                return std::ptr::null_mut();
            }
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let messages = match service
        .lock()
        .unwrap()
        .service
        .sync_room_messages_since(&room_id, after_message_id.as_deref())
    {
        Ok(items) => items,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let value = Value::Array(messages.iter().map(message_to_json).collect());
    json_to_c_string(value)
}

/// Return file transfers that can be resumed as a JSON array string.
///
/// Dart calls this on startup and after a reconnection to discover any
/// in-progress file transfers that were interrupted (e.g. by the app being
/// killed, a network dropout, or the peer going offline).
///
/// Each element in the returned array has the fields defined by the
/// `FileTransfer` model in `frontend/lib/backend/models/file_transfer.dart`:
///   `id`, `peerId`, `name`, `sizeBytes`, `transferredBytes`, `status`, `direction`
///
/// Dart uses this list to display the Files screen and offer the user the
/// option to resume or cancel each interrupted transfer.
///
/// # Return value
/// - Non-null JSON array string on success (may be an empty array `[]`).
/// - Null pointer on failure; call `mi_last_error()` for the message.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_resumable_file_transfers_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let transfers = service.lock().unwrap().service.resumable_file_transfers();
    let value = Value::Array(transfers.iter().map(transfer_to_json).collect());
    json_to_c_string(value)
}

/// Return the passive acknowledgement checkpoint for a specific peer.
///
/// # What is a "passive ack checkpoint"?
///
/// In Mesh Infinity's store-and-forward protocol, messages are relayed through
/// intermediate nodes when the sender and recipient are not directly connected.
/// A "passive acknowledgement" is an implicit delivery confirmation: when a
/// peer relays a message (or acknowledges receiving it without explicitly
/// responding), the backend records the highest message sequence number that
/// peer has seen.  This is the "checkpoint".
///
/// Dart uses this checkpoint to:
///   1. Know which messages have been delivered to a peer and can be cleaned up.
///   2. Decide where to start a sync (from the checkpoint onward) when the
///      peer reconnects after being offline.
///
/// # Parameters
/// - `ctx`     — opaque context pointer
/// - `peer_id` — null-terminated UTF-8 string: the peer's public key / ID
///
/// # Return value
/// JSON object: `{ "peerId": "...", "checkpoint": <integer> }`
/// Returns null on error; call `mi_last_error()` for the message.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_passive_ack_checkpoint_json(
    ctx: *mut MeshContext,
    peer_id: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let peer_id = match read_cstr(peer_id, MAX_ID_LEN, "peer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    // `parse_peer_id` decodes the base64/hex peer ID string into the internal
    // byte-array representation used by the backend.
    let parsed_peer_id = match parse_peer_id(&peer_id) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let checkpoint = service
        .lock()
        .unwrap()
        .service
        .passive_ack_checkpoint(&parsed_peer_id);

    // `json!({...})` is a macro from serde_json that builds a JSON Value
    // from Rust expressions using literal JSON syntax.  Much more readable
    // than constructing Value::Object(map) manually.
    json_to_c_string(json!({
        "peerId": peer_id_string(&parsed_peer_id),
        "checkpoint": checkpoint,
    }))
}

/// Compact (garbage-collect) the passive acknowledgement state.
///
/// Over time, the backend accumulates records of which messages each peer has
/// seen (passive ack state).  For long-running nodes with many peers this
/// table can grow large.  This function removes entries that are no longer
/// needed (peers that have confirmed receipt of all messages, or peers that
/// have been offline so long they are no longer tracked).
///
/// Dart calls this periodically (e.g. on app background / resume) to keep
/// the backend's memory and disk usage bounded.
///
/// # Return value
/// JSON object: `{ "removed": <count_of_removed_entries> }`
/// Returns null on error; call `mi_last_error()` for the message.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_compact_passive_state(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    // `compact_passive_state` returns the number of records removed.
    // We return this count to Dart so it can log the result for debugging.
    let removed = service.lock().unwrap().service.compact_passive_state();
    json_to_c_string(json!({ "removed": removed }))
}

/// Compact (garbage-collect) completed or cancelled file transfer records.
///
/// Similar to `mi_compact_passive_state`, but for the file transfer subsystem.
/// Once a transfer is completed or explicitly cancelled, its tracking record
/// can be removed from the backend's internal state.
///
/// Dart calls this after the user dismisses completed transfers from the Files
/// screen, or periodically to keep memory usage in check.
///
/// # Return value
/// JSON object: `{ "removed": <count_of_removed_entries> }`
/// Returns null on error; call `mi_last_error()` for the message.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_compact_file_transfers(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let removed = service.lock().unwrap().service.compact_file_transfers();
    json_to_c_string(json!({ "removed": removed }))
}

/// Return a "reconnect sync snapshot" for a room — the full state needed to
/// bring a peer up to date after a period of being offline.
///
/// When a peer reconnects after being offline, simply sending them missed
/// messages is not always sufficient: the peer may also need to know about
/// rooms that were created, members that were added or removed, and metadata
/// changes that happened while they were gone.  A "reconnect snapshot" bundles
/// all of this into one response.
///
/// # Parameters
/// - `ctx`              — opaque context pointer
/// - `room_id`          — the room to generate the snapshot for
/// - `after_message_id` — only include messages newer than this ID
///                        (null = include all messages = full resync)
///
/// # Return value
/// A JSON object containing the room's current state and any missed messages.
/// Returns null on error; call `mi_last_error()` for the message.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_reconnect_sync_snapshot_json(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    after_message_id: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let room_id = match read_cstr(room_id, MAX_ID_LEN, "room_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let after_message_id = if after_message_id.is_null() {
        None
    } else {
        match read_cstr(after_message_id, MAX_ID_LEN, "after_message_id") {
            Ok(value) => Some(value),
            Err(err) => {
                set_last_error(err.to_string());
                return std::ptr::null_mut();
            }
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let snapshot = match service
        .lock()
        .unwrap()
        .service
        .reconnect_sync_snapshot(&room_id, after_message_id.as_deref())
    {
        Ok(snapshot) => snapshot,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    json_to_c_string(reconnect_snapshot_to_json(&snapshot))
}

/// Return all known peers as a JSON array string.
///
/// Dart calls this to populate the Peers screen.  Each element in the array
/// has the fields defined in `frontend/lib/backend/models/peer.dart`:
///   `id`, `name`, `trustLevel` (0-3), `status` (online/offline/idle)
///
/// "Trust level" encodes how the user has verified this peer:
///   0 = unknown / unverified
///   1 = introduced by a trusted peer (transitive trust)
///   2 = verified manually (e.g. by comparing fingerprints in person)
///   3 = fully trusted (explicitly marked by the user)
///
/// # Return value
/// Non-null JSON array string on success; null on failure.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_peers_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let peers = service.lock().unwrap().service.peers();
    let value = Value::Array(peers.iter().map(peer_to_json).collect());
    json_to_c_string(value)
}

/// Alias for `mi_peers_json` — retained for backwards compatibility.
///
/// Early versions of the Dart backend bridge called this function `mi_get_peer_list`.
/// Rather than updating all call sites simultaneously, this thin wrapper keeps
/// the old name working while the codebase migrates to the canonical name.
#[no_mangle]
pub extern "C" fn mi_get_peer_list(ctx: *mut MeshContext) -> *mut c_char {
    mi_peers_json(ctx)
}

/// Return all active and recently-completed file transfers as a JSON array.
///
/// Unlike `mi_resumable_file_transfers_json` (which only returns interrupted
/// transfers), this function returns ALL transfers regardless of state:
///   - Queued (waiting to start)
///   - Active (in progress)
///   - Completed
///   - Failed
///   - Cancelled
///
/// Dart uses this to drive the Files screen, showing a live progress view
/// for each transfer.  Completed and failed entries remain in the list until
/// `mi_compact_file_transfers` is called to remove them.
///
/// # Return value
/// Non-null JSON array on success; null on failure.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_file_transfers_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let transfers = service.lock().unwrap().service.file_transfers();
    let value = Value::Array(transfers.iter().map(transfer_to_json).collect());
    json_to_c_string(value)
}

/// Return the current application settings as a JSON object.
///
/// Dart calls this on startup and whenever a `SettingsUpdated` event arrives,
/// to refresh the Settings screen.  The JSON object has the fields defined in
/// `frontend/lib/backend/models/settings.dart`:
///   `nodeMode`, `enableTor`, `enableClearnet`, `meshDiscovery`, `allowRelays`,
///   `enableI2p`, `enableBluetooth`, `enableRf`, `pairingCode`, `localPeerId`
///
/// Settings are stored persistently on disk.  Changes made via `mi_update_settings`
/// are written to disk immediately and take effect without restarting the backend.
///
/// # Return value
/// Non-null JSON object string on success; null on failure.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_settings_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let settings = service.lock().unwrap().service.settings();
    json_to_c_string(settings_to_json(&settings))
}

/// Return the local node's identity as a JSON object.
///
/// Dart calls this on the Onboarding screen and the Identity settings screen to
/// display the user's peer ID, public key, and display name.
///
/// The JSON object has the fields defined in `identity_to_json`:
///   `peerId`    — the node's public key as a base64/hex string; this is the
///                 unique identifier that other nodes use to address this node
///   `publicKey` — the raw Ed25519 public key bytes (same data as peerId,
///                 different encoding) used for verifying signatures
///   `name`      — the user's chosen display name (e.g. "Alice")
///
/// The peer ID is stable across app restarts (it is derived from the private
/// key stored on disk).  If no identity has been generated yet (first run
/// before `mesh_init` completes), this function returns null.
///
/// # Return value
/// Non-null JSON object string if an identity exists; null if no identity
/// has been generated yet, or on error.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_local_identity_json(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let identity = service.lock().unwrap().service.local_identity_summary();
    match identity {
        // Identity exists — serialise and return it.
        Some(identity) => json_to_c_string(identity_to_json(&identity)),
        // No identity yet (first-run race or error) — return null.
        // Dart checks for null and shows the onboarding screen.
        None => std::ptr::null_mut(),
    }
}

/// Record a trust attestation: one peer endorsing another at a given trust level.
///
/// # What is a trust attestation?
///
/// Mesh Infinity uses a web-of-trust model for peer verification.  Instead of
/// a central certificate authority (like HTTPS certificates), trust flows
/// between nodes organically:
///   - Alice verifies Bob in person (scans his QR code) → Alice trusts Bob at level 2
///   - Bob introduces Charlie to Alice → Alice trusts Charlie at level 1 (transitive)
///   - Alice revokes trust in Bob → she un-trusts him (level 0)
///
/// `mi_trust_attest` records one link in this web of trust: the `endorser`
/// peer (usually the local node) attesting that `target` should be trusted at
/// `trust_level`, verified by `verification_method`.
///
/// # Parameters
/// - `ctx`                 — opaque context pointer
/// - `endorser_peer_id`    — the peer making the attestation (usually the local node's ID)
/// - `target_peer_id`      — the peer being attested
/// - `trust_level`         — integer 0-3:
///                           0 = revoked/unknown, 1 = introduced, 2 = verified, 3 = fully trusted
/// - `verification_method` — how the endorser verified the target:
///                           0 = unknown, 1 = QR scan, 2 = fingerprint comparison, 3 = out-of-band
///
/// # Return value
/// - 0 on success; the `TrustUpdated` event is also enqueued for Dart to pick up.
/// - Negative error code on failure; call `mi_last_error()` for the message.
#[no_mangle]
pub extern "C" fn mi_trust_attest(
    ctx: *mut MeshContext,
    endorser_peer_id: *const c_char,
    target_peer_id: *const c_char,
    trust_level: i32,
    verification_method: u8,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let endorser = match read_cstr(endorser_peer_id, MAX_ID_LEN, "endorser_peer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };
    let target = match read_cstr(target_peer_id, MAX_ID_LEN, "target_peer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let endorser_peer_id = match parse_peer_id(&endorser) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };
    let target_peer_id = match parse_peer_id(&target) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let trust_level = trust_level_from_i32(trust_level);
    let method = verification_method_from_u8(verification_method);

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    match guard
        .service
        .trust_attest(&endorser_peer_id, &target_peer_id, trust_level, method)
    {
        Ok(()) => {
            guard.push_event(BackendEvent::TrustUpdated {
                peer_id: peer_id_string(&target_peer_id),
                trust_level: trust_level as i32,
            });
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

/// Compute the effective trust level for a peer, incorporating external markers.
///
/// Where `mi_trust_attest` records a new attestation, this function *reads*
/// the trust graph and returns the computed trust level for a given peer.
///
/// # Parameters
/// - `ctx`            — opaque context pointer
/// - `target_peer_id` — the peer whose trust level to compute
/// - `markers_json`   — a JSON array of additional trust markers (e.g. from a QR code
///                      scan or a third-party attestation) to incorporate into the
///                      computation, OR null to use only the stored attestations.
///                      If null, defaults to an empty array `[]`.
///
/// # Return value
/// JSON object: `{ "peerId": "...", "trustLevel": <0-3> }`
/// Returns null on error; call `mi_last_error()` for the message.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_trust_verify_json(
    ctx: *mut MeshContext,
    target_peer_id: *const c_char,
    markers_json: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let target = match read_cstr(target_peer_id, MAX_ID_LEN, "target_peer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let markers_json = if markers_json.is_null() {
        "[]".to_string()
    } else {
        match read_cstr(markers_json, MAX_KEY_LEN, "markers_json") {
            Ok(value) => value,
            Err(err) => {
                set_last_error(err.to_string());
                return std::ptr::null_mut();
            }
        }
    };

    let target_peer_id = match parse_peer_id(&target) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let markers = match parse_trust_markers(&markers_json) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let trust_level = service
        .lock()
        .unwrap()
        .service
        .trust_verify(&target_peer_id, markers);

    json_to_c_string(json!({
        "peerId": peer_id_string(&target_peer_id),
        "trustLevel": trust_level as i32,
    }))
}

/// Return the ID of the currently-active chat room, or null if none is active.
///
/// The "active room" is the room the user currently has open on screen.  The
/// backend tracks this so it can:
///   - Mark arriving messages for that room as "read" immediately.
///   - Know which room to use when `mi_messages_json` is called with a null
///     room_id argument.
///   - Emit `ActiveRoomChanged` events when the active room changes so other
///     parts of the state can react.
///
/// # Return value
/// - Non-null `*mut c_char` containing the room ID as a null-terminated UTF-8
///   string, if a room is active.
/// - Null pointer if no room is currently active (e.g. user is on the room
///   list, not inside a specific conversation).
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
/// The null case requires NO free call (there is nothing to free).
#[no_mangle]
pub extern "C" fn mi_active_room_id(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let room_id = service.lock().unwrap().service.active_room_id();
    match room_id {
        Some(id) => string_to_c_string(&id),
        None => std::ptr::null_mut(),
    }
}

/// Create a new chat room and return its newly-assigned ID.
///
/// Dart calls this when the user taps "New Conversation" and confirms a name.
///
/// After the room is created this function enqueues two events so the UI
/// updates without Dart needing to explicitly re-fetch:
///   1. `RoomUpdated(room)` — adds the new room to Dart's conversation list.
///   2. `ActiveRoomChanged(Some(room_id))` — automatically navigates Dart
///      into the new room so the user can start typing immediately.
///
/// # Parameters
/// - `ctx`  — opaque context pointer
/// - `name` — null-terminated UTF-8 string: the desired room display name.
///            Maximum length: MAX_NAME_LEN bytes.
///
/// # Return value
/// - Non-null `*mut c_char` containing the new room's ID string on success.
/// - Null on failure (name too long, lock failure, etc.); call `mi_last_error()`.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned ID string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_create_room(ctx: *mut MeshContext, name: *const c_char) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let name = match read_cstr(name, MAX_NAME_LEN, "room name") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let guard = service.lock().unwrap();
    match guard.service.create_room(&name) {
        Ok(room_id) => {
            if let Some(room) = guard
                .service
                .rooms()
                .into_iter()
                .find(|room| room.id == room_id)
            {
                guard.push_event(BackendEvent::RoomUpdated(room.clone()));
                guard.push_event(BackendEvent::ActiveRoomChanged(Some(room_id.clone())));
            }
            string_to_c_string(&room_id)
        }
        Err(err) => {
            set_last_error(err.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Set the currently-active room (i.e. the conversation the user has open).
///
/// Dart calls this whenever the user taps on a conversation to open it.
/// The backend uses the active room to:
///   - Mark new messages in that room as "read" automatically.
///   - Return the correct messages when `mi_messages_json` is called with
///     a null room_id.
///
/// After changing the active room this function enqueues:
///   1. `RoomUpdated(room)` — refreshes the room's unread count (reset to 0).
///   2. `ActiveRoomChanged(Some(room_id))` — tells other Dart listeners
///      that the active room changed.
///
/// # Parameters
/// - `ctx`     — opaque context pointer
/// - `room_id` — null-terminated UTF-8 string: the ID of the room to activate
///
/// # Return value
/// - 0 on success.
/// - Negative code on failure; call `mi_last_error()` for the message.
#[no_mangle]
pub extern "C" fn mi_select_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let room_id = match read_cstr(room_id, MAX_ID_LEN, "room_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    match guard.service.select_room(&room_id) {
        Ok(()) => {
            if let Some(room) = guard
                .service
                .rooms()
                .into_iter()
                .find(|room| room.id == room_id)
            {
                guard.push_event(BackendEvent::RoomUpdated(room.clone()));
            }
            guard.push_event(BackendEvent::ActiveRoomChanged(Some(room_id)));
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

/// Delete a chat room and all its stored messages.
///
/// Dart calls this when the user long-presses a conversation and chooses "Delete".
/// This is a destructive operation: the messages are removed from local storage
/// and the room is removed from the room list.  The deletion is not propagated
/// to other peers — their local copies of the room remain intact.
///
/// After deletion this function enqueues a `RoomDeleted(room_id)` event so
/// Dart's MessagingState can remove the room from its in-memory list without
/// needing to re-fetch all rooms.
///
/// # Parameters
/// - `ctx`     — opaque context pointer
/// - `room_id` — null-terminated UTF-8 string: the ID of the room to delete
///
/// # Return value
/// - 0 on success.
/// - Negative code on failure; call `mi_last_error()` for the message.
#[no_mangle]
pub extern "C" fn mi_delete_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let room_id = match read_cstr(room_id, MAX_ID_LEN, "room_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    let active_before = guard.service.active_room_id();
    match guard.service.delete_room(&room_id) {
        Ok(()) => {
            guard.push_event(BackendEvent::RoomDeleted(room_id.clone()));
            let active_after = guard.service.active_room_id();
            if active_before != active_after {
                guard.push_event(BackendEvent::ActiveRoomChanged(active_after));
            }
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

/// Send a text message to a specific room, or to the currently-active room.
///
/// This is the modern, preferred send API (as opposed to `mesh_send_message`
/// which sends only to the active room and uses the older `FfiMessage` struct).
///
/// # Parameters
/// - `ctx`     — opaque context pointer
/// - `room_id` — null-terminated UTF-8 string: the room to send to,
///               OR null to send to the currently-active room
/// - `text`    — null-terminated UTF-8 string: the message text.
///               Maximum length: MAX_TEXT_LEN bytes (8 KiB).
///               For larger content, use the file-transfer API instead.
///
/// # Return value
/// - 0 on success.
/// - -1 on null context or text pointer.
/// - Other negative codes map to `MeshInfinityError` variants.
#[no_mangle]
pub extern "C" fn mi_send_text_message(
    ctx: *mut MeshContext,
    room_id: *const c_char,
    text: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let text = match read_cstr(text, MAX_TEXT_LEN, "message text") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let room_id = if room_id.is_null() {
        None
    } else {
        match read_cstr(room_id, MAX_ID_LEN, "room_id") {
            Ok(value) => Some(value),
            Err(err) => {
                set_last_error(err.to_string());
                return rust_error_to_c_code(&err);
            }
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let mut guard = service.lock().unwrap();
    let target_room_id = room_id.clone();
    let result = if let Some(room_id) = room_id.as_deref() {
        guard.service.send_message_to_room(room_id, &text)
    } else {
        guard.service.send_message(&text)
    };

    match result {
        Ok(()) => {
            push_room_update(&mut guard, target_room_id);
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

/// Delete a specific message by its ID.
///
/// Dart calls this when the user long-presses a message bubble and chooses
/// "Delete".  The message is removed from local storage.  As with room
/// deletion, the deletion is local-only — other peers keep their copies.
///
/// After deletion this function enqueues two events:
///   1. `RoomUpdated(room)` — updates the room's preview text (which may have
///      been the deleted message's text).
///   2. `MessageDeleted { room_id, message_id }` — tells Dart's MessagingState
///      to remove the specific message bubble from the conversation view.
///
/// # Parameters
/// - `ctx`        — opaque context pointer
/// - `message_id` — null-terminated UTF-8 string: the ID of the message to delete
///
/// # Return value
/// - 0 on success.
/// - Negative code on failure; call `mi_last_error()` for the message.
#[no_mangle]
pub extern "C" fn mi_delete_message(ctx: *mut MeshContext, message_id: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let message_id = match read_cstr(message_id, MAX_ID_LEN, "message_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    match guard.service.delete_message(&message_id) {
        Ok(room_id) => {
            if let Some(room) = guard
                .service
                .rooms()
                .into_iter()
                .find(|room| room.id == room_id)
            {
                guard.push_event(BackendEvent::RoomUpdated(room.clone()));
            }
            guard.push_event(BackendEvent::MessageDeleted {
                room_id,
                message_id,
            });
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

/// Set the node's operating mode (e.g. full node, relay, client-only).
///
/// The node mode controls how this device participates in the mesh:
///   0 = Client       — connects to peers but does not relay traffic for others.
///                      Best for battery-constrained mobile devices.
///   1 = Relay        — forwards packets between peers that can't reach each other
///                      directly.  Requires more bandwidth and battery.
///   2 = Full node    — fully participates, stores-and-forwards messages, and
///                      helps maintain the mesh topology.
///
/// After changing the mode, a `SettingsUpdated` event is enqueued so Dart's
/// NetworkState refreshes the transport toggle display.
///
/// # Parameters
/// - `ctx`  — opaque context pointer
/// - `mode` — u8 mode value (see above)
///
/// # Return value
/// - 0 on success.
/// - Negative code on failure.
#[no_mangle]
pub extern "C" fn mi_set_node_mode(ctx: *mut MeshContext, mode: u8) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    let node_mode = node_mode_from_u8(mode);
    guard.service.set_node_mode(node_mode);
    let settings = guard.service.settings();
    guard.push_event(BackendEvent::SettingsUpdated(settings));
    0
}

/// Enable or disable individual transport subsystems at runtime.
///
/// Dart calls this when the user toggles a switch on the Network settings screen.
/// Changes take effect immediately — transports are started or stopped without
/// needing to restart the backend.
///
/// # Why individual flags instead of a settings struct?
///
/// Passing a full settings struct across FFI would require keeping the Dart
/// and Rust struct layouts perfectly in sync.  Individual scalar flags (u8)
/// are simpler and less error-prone to pass across the FFI boundary.
///
/// # Parameters — each is 0 (disabled) or 1 (enabled)
/// - `enable_tor`       — route connections through the Tor anonymity network
/// - `enable_clearnet`  — allow direct TCP/UDP connections over the internet
/// - `mesh_discovery`   — use mDNS to find peers on the local network
/// - `allow_relays`     — allow other nodes to relay traffic on our behalf
/// - `enable_i2p`       — route connections through the I2P anonymity network
/// - `enable_bluetooth` — use Bluetooth Low Energy for nearby peer discovery
/// - `enable_rf`        — use LoRa/RF radio transport (Meshtastic)
///
/// # Return value
/// - 0 on success; `SettingsUpdated` event enqueued.
/// - Negative code on failure.
#[no_mangle]
pub extern "C" fn mi_set_transport_flags(
    ctx: *mut MeshContext,
    enable_tor: u8,
    enable_clearnet: u8,
    mesh_discovery: u8,
    allow_relays: u8,
    enable_i2p: u8,
    enable_bluetooth: u8,
    enable_rf: u8,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    guard.service.set_enable_tor(enable_tor != 0);
    guard.service.set_enable_clearnet(enable_clearnet != 0);
    guard.service.set_mesh_discovery(mesh_discovery != 0);
    guard.service.set_allow_relays(allow_relays != 0);
    guard.service.set_enable_i2p(enable_i2p != 0);
    guard.service.set_enable_bluetooth(enable_bluetooth != 0);
    guard.service.set_enable_rf(enable_rf != 0);
    let settings = guard.service.settings();
    guard.push_event(BackendEvent::SettingsUpdated(settings));
    0
}

/// Initiate pairing with a new peer using a pairing code.
///
/// Mesh Infinity uses QR-code-based peer pairing for initial key exchange.
/// The pairing flow works as follows:
///   1. Alice's app displays a QR code containing her pairing code.
///   2. Bob scans Alice's QR code with his app.
///   3. Bob's app calls `mi_pair_peer` with Alice's code.
///   4. The backends exchange public keys and establish the peer relationship.
///   5. Alice appears in Bob's peer list (and vice versa on Alice's device
///      once the mutual exchange completes over the transport layer).
///
/// The pairing code is a compact encoding of the local node's public key and
/// connection hints (e.g. current IP address or .onion address).
///
/// On success, a `PeerUpdated` event is enqueued with the newly-added peer so
/// Dart's PeersState can add them to the list without a full re-fetch.
///
/// # Parameters
/// - `ctx`  — opaque context pointer
/// - `code` — null-terminated UTF-8 string: the pairing code from the peer's QR code
///
/// # Return value
/// - 0 on success.
/// - Negative code on failure; call `mi_last_error()` for the message.
#[no_mangle]
pub extern "C" fn mi_pair_peer(ctx: *mut MeshContext, code: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let code = match read_cstr(code, MAX_ID_LEN, "pairing code") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let guard = service.lock().unwrap();
    match guard.service.pair_peer(&code) {
        Ok(()) => {
            if let Some(peer) = guard.service.peers().first().cloned() {
                guard.push_event(BackendEvent::PeerUpdated(peer));
            }
            0
        }
        Err(err) => {
            set_last_error(err.to_string());
            rust_error_to_c_code(&err)
        }
    }
}

/// Poll for backend events — the MAIN communication channel from Rust to Dart.
///
/// This is the heart of the Rust → Dart communication.  Dart calls this in a
/// tight loop (every ~200 ms, see `event_bus.dart`) from a background isolate
/// and dispatches any returned events to the relevant ChangeNotifiers.
///
/// # How the event system works end-to-end
///
/// 1. Something happens in the Rust backend: a message arrives, a peer comes
///    online, a file transfer progresses, etc.
/// 2. The relevant subsystem calls `push_event(BackendEvent::...)` to enqueue
///    the event into the shared `VecDeque<BackendEvent>`.
/// 3. Meanwhile, Dart's background isolate is polling this function every 200 ms.
/// 4. `mi_poll_events` dequeues up to `max_events` items, serialises each one
///    to JSON (via `event_to_json`), and returns the whole array as one JSON string.
/// 5. Dart calls `jsonDecode(result)` and dispatches each event object to the
///    relevant state class (MessagingState, NetworkState, etc.).
///
/// # Why polling instead of Rust calling Dart directly (push)?
///
/// Push callbacks from Rust into Dart are possible but fragile:
///   - Dart isolates have thread-affinity rules; calling into the wrong isolate
///     crashes the app.
///   - iOS has additional restrictions on calling into Flutter from native threads.
///   - Polling is simple, predictable, and easy to test.
///
/// The 200 ms polling interval is imperceptible to users for non-real-time
/// updates (peer status, file progress).  For incoming messages the `MessageAdded`
/// event keeps latency acceptable.
///
/// # Parameters
/// - `ctx`        — opaque context pointer
/// - `max_events` — maximum number of events to dequeue in this call.
///                  Pass 0 to use the internal default (MAX_EVENTS).
///                  This cap prevents returning an unbounded JSON blob if the
///                  queue backed up while the app was backgrounded.
///
/// # Return value
/// - A JSON array string (may be empty: `[]`) on success.
/// - Null on hard failure (null context, lock poisoned).
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
/// Even the empty-array `[]` case returns an allocated string that must be freed.
#[no_mangle]
pub extern "C" fn mi_poll_events(ctx: *mut MeshContext, max_events: u32) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    // Clamp max_events: 0 means "use the default"; anything above MAX_EVENTS
    // is silently capped to prevent returning excessively large JSON blobs.
    let max_events = if max_events == 0 {
        MAX_EVENTS
    } else {
        usize::min(max_events as usize, MAX_EVENTS)
    };

    // Drain at most `max_events` items from the queue.
    // `drain_events` removes the items from the queue atomically under the lock.
    let events = service.lock().unwrap().drain_events(max_events);
    // Convert each BackendEvent to a serde_json::Value and wrap in an array.
    let value = Value::Array(events.iter().map(event_to_json).collect());
    // Serialise to JSON and allocate a C string for Dart to receive.
    json_to_c_string(value)
}

/// Return the last error message as a null-terminated UTF-8 C string.
///
/// Every FFI function that fails calls `set_last_error("...")` before returning
/// -1 or null.  Dart calls `mi_last_error_message()` immediately after a
/// failure to retrieve the human-readable explanation.
///
/// # Error reporting pattern in Dart
/// ```dart
/// final result = nativeLib.mi_some_function(ctx, ...);
/// if (result < 0 || result == null) {
///   final errPtr = nativeLib.mi_last_error_message();
///   final errMsg = errPtr.toDartString();
///   nativeLib.mi_string_free(errPtr);  // Don't forget to free!
///   throw Exception('Backend error: $errMsg');
/// }
/// ```
///
/// # Return value
/// - Non-null C string pointer if an error message is available.
/// - Null if no error occurred since the last call to this function.
///   (The last error is consumed — calling this a second time returns null
///   unless another error occurred in between.)
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string` (or
/// `mi_string_free` — they are the same function).
#[no_mangle]
pub extern "C" fn mi_last_error_message() -> *mut c_char {
    match take_last_error() {
        Some(message) => string_to_c_string(&message),
        None => std::ptr::null_mut(),
    }
}

/// Check whether this node has a persisted cryptographic identity on disk.
///
/// Dart calls this immediately after `mesh_init` to decide whether to show
/// the onboarding screen:
///   - 0 (false) → first run, no identity yet → show onboarding
///   - 1 (true)  → identity loaded from disk  → go straight to the app shell
///
/// Note: `mesh_init` always generates a fresh in-memory identity if none
/// exists on disk.  This function specifically checks whether that identity
/// has been *saved* to disk.  An identity is saved after the user completes
/// onboarding and taps "Get Started".
///
/// # Return value
/// - 1 if a persisted identity exists on disk.
/// - 0 if no identity is persisted yet, or if any step fails.
///   (Returns 0 rather than an error code because a missing identity is a
///   normal condition on first run, not an error.)
#[no_mangle]
pub extern "C" fn mi_has_identity(ctx: *mut MeshContext) -> u8 {
    if ctx.is_null() {
        return 0;
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(_) => return 0,
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(_) => return 0,
    };

    // `is_identity_persisted()` checks whether the key file exists on disk.
    // Map to 1/0 because Dart's FFI layer represents booleans as integers.
    if guard.service.is_identity_persisted() {
        1
    } else {
        0
    }
}

/// Free a string that was allocated by Rust and returned to Dart.
///
/// # This is one of the most important functions in the FFI layer.
///
/// Every function in this file that returns a `*mut c_char` (a pointer to a
/// C string) has allocated that string on the Rust heap using `CString::new`
/// (via `json_to_c_string` or `string_to_c_string`).  Rust's allocator owns
/// that memory.  Dart's garbage collector does NOT know about it.
///
/// If Dart does not call this function after it is done with the string,
/// the memory will never be freed — this is a **memory leak**.  In a long-
/// running app like a chat client, even small leaks accumulate and eventually
/// exhaust memory.
///
/// # How to use correctly in Dart
/// ```dart
/// final ptr = nativeLib.mi_rooms_json(ctx);     // Rust allocates
/// if (ptr != nullptr) {
///   final json = ptr.toDartString();            // Dart copies the bytes
///   nativeLib.mi_string_free(ptr);              // Rust frees the original
///   // `json` is now a safe Dart String; `ptr` must not be used again
/// }
/// ```
///
/// # Why not use Dart's `malloc`/`free`?
/// The string is allocated by Rust's allocator, which may be a different
/// allocator than Dart's (especially on Android and iOS where each native
/// library can have its own heap).  Freeing Rust-allocated memory with
/// Dart's `free()` would be undefined behaviour.  Only Rust's `drop` /
/// `CString::from_raw` can correctly free Rust-allocated memory, which is
/// exactly what `free_c_string` does internally.
///
/// # Safety
/// `value` must be a pointer returned by one of the `*_json` or similar
/// functions in this file, and must not have been freed already.
/// Passing null is safe (this function checks and returns early).
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mi_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    // `free_c_string` reconstructs the `CString` from the raw pointer and then
    // immediately drops it, which calls `CString`'s destructor and frees the heap
    // allocation through Rust's allocator.
    unsafe { free_c_string(value) };
}

// =============================================================================
// mDNS Discovery FFI functions
// =============================================================================
//
// mDNS (multicast DNS) is used to discover other Mesh Infinity nodes on the
// same local network without needing any external infrastructure.  When mDNS
// is enabled, the backend broadcasts a DNS-SD service record on the local
// subnet, and listens for records from other nodes.
//
// These functions map directly to the toggles on the Network screen in the app.

/// Start the mDNS service discovery subsystem.
///
/// This causes the backend to:
///   1. Announce this node's presence on the local subnet (so other nodes
///      can discover us).
///   2. Listen for announcements from other Mesh Infinity nodes (so we can
///      discover them).
///
/// Discovered peers are added to the peer list and a `PeerUpdated` event is
/// enqueued for each one.
///
/// # Parameters
/// - `ctx`  — opaque context pointer
/// - `port` — the UDP port to advertise in the mDNS record (the port this
///            node is listening on for direct connections)
///
/// # Return value
/// - 0 on success.
/// - Negative code on failure (e.g. the mDNS subsystem is already running).
#[no_mangle]
pub extern "C" fn mi_mdns_enable(ctx: *mut MeshContext, port: u16) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return rust_error_to_c_code(&MeshInfinityError::InvalidConfiguration(
            "context was null".to_string(),
        ));
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return rust_error_to_c_code(&err);
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return rust_error_to_c_code(&MeshInfinityError::LockError(err));
        }
    };

    match service_handle.service.enable_mdns(port) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("Failed to enable mDNS: {}", e));
            rust_error_to_c_code(&e)
        }
    }
}

/// Stop the mDNS service discovery subsystem.
///
/// This stops both the announcement broadcast and the listener.  Already-
/// discovered peers remain in the peer list; they are not removed when mDNS
/// is disabled.
///
/// # Return value
/// - 0 on success.
/// - Negative code on failure (e.g. mDNS was not running).
#[no_mangle]
pub extern "C" fn mi_mdns_disable(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return rust_error_to_c_code(&MeshInfinityError::InvalidConfiguration(
            "context was null".to_string(),
        ));
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return rust_error_to_c_code(&err);
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return rust_error_to_c_code(&MeshInfinityError::LockError(err));
        }
    };

    match service_handle.service.disable_mdns() {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("Failed to disable mDNS: {}", e));
            rust_error_to_c_code(&e)
        }
    }
}

/// Check whether the mDNS subsystem is currently running.
///
/// Dart uses this to sync the toggle switch on the Network screen with the
/// actual backend state (e.g. after app restart, to restore the correct
/// toggle position without relying on stored UI state).
///
/// # Return value
/// - 1 if mDNS is running.
/// - 0 if mDNS is stopped.
/// - Negative code on hard failure (null context, lock error).
#[no_mangle]
pub extern "C" fn mi_mdns_is_running(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return rust_error_to_c_code(&MeshInfinityError::InvalidConfiguration(
            "context was null".to_string(),
        ));
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return rust_error_to_c_code(&err);
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return rust_error_to_c_code(&MeshInfinityError::LockError(err));
        }
    };

    if service_handle.service.is_mdns_running() {
        1
    } else {
        0
    }
}

/// Return all peers discovered via mDNS as a JSON array.
///
/// Unlike `mi_peers_json` which returns all known peers (including those
/// paired via QR code or other means), this function returns ONLY peers
/// discovered through mDNS on the local network.
///
/// Dart uses this to populate the "Discovered on local network" section of
/// the Peers screen, allowing the user to tap a discovered peer and initiate
/// pairing with a single tap (no QR code scan required for LAN peers).
///
/// # Return value
/// - Non-null JSON array string on success (may be empty `[]`).
/// - Null on failure; call `mi_last_error()` for the message.
///
/// # Memory ownership
/// Caller (Dart) MUST free the returned string with `mi_free_string`.
#[no_mangle]
pub extern "C" fn mi_mdns_get_discovered_peers(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return std::ptr::null_mut();
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return std::ptr::null_mut();
        }
    };

    match service_handle.service.get_discovered_peers() {
        Ok(peers) => {
            let peers_json: Vec<Value> = peers
                .iter()
                .map(|peer| {
                    json!({
                        "id": peer.id,
                        "name": peer.name,
                        "trustLevel": peer.trust_level,
                        "status": peer.status,
                    })
                })
                .collect();

            json_to_c_string(Value::Array(peers_json))
        }
        Err(e) => {
            set_last_error(format!("Failed to get discovered peers: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Export discovery jumpstart payload JSON.
///
/// `limit` controls maximum number of peers embedded in payload.
#[no_mangle]
pub extern "C" fn mi_discovery_export_jumpstart(
    ctx: *mut MeshContext,
    limit: usize,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return std::ptr::null_mut();
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return std::ptr::null_mut();
        }
    };

    match service_handle.service.export_discovery_jumpstart(limit) {
        Ok(payload) => string_to_c_string(&payload),
        Err(e) => {
            set_last_error(format!("Failed to export jumpstart payload: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Import discovery jumpstart payload JSON.
///
/// Returns number of peers ingested, or negative error code.
#[no_mangle]
pub extern "C" fn mi_discovery_import_jumpstart(
    ctx: *mut MeshContext,
    payload_json: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return rust_error_to_c_code(&MeshInfinityError::InvalidConfiguration(
            "context was null".to_string(),
        ));
    }

    let payload = match read_cstr(payload_json, 1024 * 1024, "payload_json") {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("Invalid payload JSON string: {}", e));
            return rust_error_to_c_code(&MeshInfinityError::InvalidConfiguration(e.to_string()));
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(err) => {
            set_last_error(format!("Failed to access service: {}", err));
            return rust_error_to_c_code(&err);
        }
    };

    let service_handle = match safe_lock(&service) {
        Ok(handle) => handle,
        Err(err) => {
            set_last_error(format!("Failed to acquire service lock: {}", err));
            return rust_error_to_c_code(&MeshInfinityError::LockError(err));
        }
    };

    match service_handle.service.import_discovery_jumpstart(&payload) {
        Ok(count) => i32::try_from(count).unwrap_or(i32::MAX),
        Err(e) => {
            set_last_error(format!("Failed to import jumpstart payload: {}", e));
            rust_error_to_c_code(&e)
        }
    }
}

/// Get network statistics (bytes sent/received, active connections)
/// Returns JSON: {"bytesSent": 0, "bytesReceived": 0, "activeConnections": 0}
#[no_mangle]
pub extern "C" fn mi_get_network_stats(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return std::ptr::null_mut();
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return std::ptr::null_mut();
        }
    };

    let stats = guard.service.network_stats();

    json_to_c_string(json!({
        "bytesSent": stats.bytes_sent,
        "bytesReceived": stats.bytes_received,
        "activeConnections": stats.active_connections,
        "pendingRoutes": stats.pending_routes,
        "deliveredRoutes": stats.delivered_routes,
        "failedRoutes": stats.failed_routes,
        "packetsLost": 0,
        "avgLatencyMs": 0,
        "bandwidthKbps": 0,
    }))
}

/// Start a file transfer (send or host)
/// direction: "send" or "host"
/// peer_id: target peer ID for send, null for host
/// file_path: path to the file
/// Returns transfer ID as JSON string or null on error
#[no_mangle]
pub extern "C" fn mi_file_transfer_start(
    ctx: *mut MeshContext,
    direction: *const c_char,
    _peer_id: *const c_char,
    file_path: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let direction_str = match read_cstr(direction, 16, "direction") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let peer_id = if _peer_id.is_null() {
        String::new()
    } else {
        match read_cstr(_peer_id, 256, "peer_id") {
            Ok(value) => value,
            Err(err) => {
                set_last_error(err.to_string());
                return std::ptr::null_mut();
            }
        }
    };

    let file_path_str = match read_cstr(file_path, 4096, "file_path") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let file_name = Path::new(&file_path_str)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .unwrap_or_else(|| file_path_str.clone());
    let file_size = std::fs::metadata(&file_path_str)
        .map(|meta| meta.len())
        .unwrap_or(0);

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return std::ptr::null_mut();
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return std::ptr::null_mut();
        }
    };

    let resolved_peer_id = if peer_id.trim().is_empty() {
        guard.service.settings().local_peer_id
    } else {
        peer_id.clone()
    };

    let result = match direction_str.as_str() {
        "send" => {
            if peer_id.trim().is_empty() {
                set_last_error("peer_id is required for send direction");
                return std::ptr::null_mut();
            }
            guard
                .service
                .queue_file_send(&resolved_peer_id, &file_name, file_size)
        }
        "host" | "receive" => {
            guard
                .service
                .queue_file_receive(&resolved_peer_id, &file_name, file_size)
        }
        _ => {
            set_last_error("direction must be 'send' or 'host'");
            return std::ptr::null_mut();
        }
    };

    match result {
        Ok(transfer_id) => json_to_c_string(json!({
            "transferId": transfer_id,
            "status": "pending",
        })),
        Err(e) => {
            set_last_error(format!("Failed to queue file transfer: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Cancel an active file transfer
/// transfer_id: ID of the transfer to cancel
/// Returns 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn mi_file_transfer_cancel(
    ctx: *mut MeshContext,
    transfer_id: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let transfer_id = match read_cstr(transfer_id, 256, "transfer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return rust_error_to_c_code(&err);
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return -1;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return -1;
        }
    };

    match guard.service.cancel_file_transfer(&transfer_id) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("Failed to update transfer state: {}", e));
            rust_error_to_c_code(&e)
        }
    }
}

/// Get status of a specific file transfer
/// transfer_id: ID of the transfer
/// Returns JSON with transfer status or null on error
#[no_mangle]
pub extern "C" fn mi_file_transfer_status(
    ctx: *mut MeshContext,
    transfer_id: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return std::ptr::null_mut();
    }

    let _transfer_id = match read_cstr(transfer_id, 256, "transfer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return std::ptr::null_mut();
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return std::ptr::null_mut();
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return std::ptr::null_mut();
        }
    };

    let transfer = guard.service.file_transfer(&_transfer_id);

    match transfer {
        Some(item) => json_to_c_string(json!({
            "transferId": item.id,
            "status": item.status,
            "name": item.name,
            "direction": item.direction,
            "peerId": item.peer_id,
            "sizeBytes": item.size_bytes,
            "transferredBytes": item.transferred_bytes,
        })),
        None => {
            set_last_error("Transfer not found");
            std::ptr::null_mut()
        }
    }
}

/// Gets list of configured services
/// Returns JSON array of services or empty array on error
#[no_mangle]
pub extern "C" fn mi_get_service_list(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        set_last_error("context was null");
        return json_to_c_string(json!([]));
    }

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return json_to_c_string(json!([]));
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return json_to_c_string(json!([]));
        }
    };

    let services = guard.service.hosted_services();
    let value = Value::Array(services.iter().map(hosted_service_to_json).collect());
    json_to_c_string(value)
}

/// Configures a service with the given parameters
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn mi_configure_service(
    ctx: *mut MeshContext,
    service_id: *const c_char,
    config_json: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let service_id = match read_cstr(service_id, 256, "service_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let config_json = match read_cstr(config_json, 4096, "config_json") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let parsed: Value = match serde_json::from_str(&config_json) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(format!("invalid config_json: {}", err));
            return 0;
        }
    };

    let name = parsed
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(&service_id)
        .to_string();
    let path = parsed
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let address = parsed
        .get("address")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let enabled = parsed
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let min_trust_level = parsed
        .get("minTrustLevel")
        .and_then(Value::as_i64)
        .map(|value| trust_level_from_i32(value as i32))
        .unwrap_or(TrustLevel::Trusted);
    let allowed_transports = parsed
        .get("allowedTransports")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str())
                .filter_map(transport_type_from_name)
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
        .unwrap_or_else(|| {
            vec![
                TransportType::Tor,
                TransportType::I2P,
                TransportType::Bluetooth,
            ]
        });

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return 0;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return 0;
        }
    };

    match guard.service.configure_hosted_service_with_policy(
        &service_id,
        &name,
        &path,
        &address,
        enabled,
        HostedServicePolicy {
            min_trust_level,
            allowed_transports,
        },
    ) {
        Ok(()) => 1,
        Err(err) => {
            set_last_error(err.to_string());
            0
        }
    }
}

/// Checks whether a peer/transport tuple is allowed to access a hosted service.
/// Returns 1 when allowed, 0 when denied or on error.
#[no_mangle]
pub extern "C" fn mi_check_service_access(
    ctx: *mut MeshContext,
    service_id: *const c_char,
    peer_id: *const c_char,
    transport_name: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let service_id = match read_cstr(service_id, 256, "service_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let peer_id = match read_cstr(peer_id, 256, "peer_id") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let transport_name = match read_cstr(transport_name, 64, "transport_name") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let peer_id = match parse_peer_id(&peer_id) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let transport = match transport_type_from_name(&transport_name) {
        Some(value) => value,
        None => {
            set_last_error(format!("unknown transport: {}", transport_name));
            return 0;
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return 0;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return 0;
        }
    };

    match guard
        .service
        .hosted_service_access_allowed(&service_id, &peer_id, transport)
    {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(err) => {
            set_last_error(err.to_string());
            0
        }
    }
}

/// Toggles a transport flag (enable/disable transport)
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn mi_toggle_transport_flag(
    ctx: *mut MeshContext,
    transport_name: *const c_char,
    enabled: i32,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let transport_name = match read_cstr(transport_name, 64, "transport_name") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let enabled = enabled != 0;

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return 0;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return 0;
        }
    };

    match transport_name.to_ascii_lowercase().as_str() {
        "tor" => guard.service.set_enable_tor(enabled),
        "clearnet" => guard.service.set_enable_clearnet(enabled),
        "mesh_discovery" | "mdns" | "discovery" => guard.service.set_mesh_discovery(enabled),
        "relay" | "relays" => guard.service.set_allow_relays(enabled),
        "i2p" => guard.service.set_enable_i2p(enabled),
        "bluetooth" => guard.service.set_enable_bluetooth(enabled),
        "rf" => guard.service.set_enable_rf(enabled),
        _ => {
            set_last_error(format!("Unknown transport flag: {}", transport_name));
            return 0;
        }
    }
    1
}

/// Sets VPN route configuration
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn mi_set_vpn_route(ctx: *mut MeshContext, route_config_json: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let route_config = match read_cstr(route_config_json, 4096, "route_config_json") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return 0;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return 0;
        }
    };

    guard.service.set_vpn_route_config(route_config);
    1
}

/// Sets clearnet route configuration
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn mi_set_clearnet_route(
    ctx: *mut MeshContext,
    route_config_json: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return 0;
    }

    let route_config = match read_cstr(route_config_json, 4096, "route_config_json") {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err.to_string());
            return 0;
        }
    };

    let service = match get_service() {
        Ok(service) => service,
        Err(e) => {
            set_last_error(format!("Failed to access service: {}", e));
            return 0;
        }
    };

    let guard = match safe_lock(&service) {
        Ok(guard) => guard,
        Err(e) => {
            set_last_error(format!("Failed to acquire service lock: {}", e));
            return 0;
        }
    };

    guard.service.set_clearnet_route_config(route_config);
    1
}

// ---------------------------------------------------------------------------
// Identity persistence FFI
// ---------------------------------------------------------------------------

/// Persist the current in-memory identity to disk for the first time.
///
/// Identity material (keypair, DH key) is already generated by `mesh_init`.
/// This call encrypts it into `identity.dat` / `identity.key` under the
/// config directory and marks `hasIdentity()` as true for future launches.
///
/// `name_ptr` may be null (no display name).
#[no_mangle]
pub extern "C" fn mi_create_identity(ctx: *mut MeshContext, name_ptr: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let name = if name_ptr.is_null() {
        None
    } else {
        match read_cstr(name_ptr, MAX_NAME_LEN, "name") {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }
            Err(e) => {
                set_last_error(e.to_string());
                return -1;
            }
        }
    };

    let service = match get_service() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };
    let mut guard = service.lock().unwrap();

    if let Some(n) = name.clone() {
        if let Err(e) = guard.service.set_identity_name(Some(n)) {
            set_last_error(e.to_string());
            return -1;
        }
    }

    let (ed25519, x25519) = match guard.service.primary_secret_key_bytes() {
        Some(keys) => keys,
        None => {
            set_last_error("No primary identity available");
            return -1;
        }
    };

    let profile = guard.service.local_profile().clone();
    let persisted = PersistedIdentity {
        ed25519_secret: ed25519.to_vec(),
        x25519_secret: x25519.to_vec(),
        name,
        public_display_name: profile.public_display_name,
        identity_is_public: profile.identity_is_public,
        private_display_name: profile.private_display_name,
        private_bio: profile.private_bio,
    };

    let store_guard = IDENTITY_STORE.lock().unwrap();
    let store = match store_guard.as_ref() {
        Some(s) => s,
        None => {
            set_last_error("Identity store not initialised");
            return -1;
        }
    };

    if let Err(e) = store.save(&persisted) {
        set_last_error(e.to_string());
        return -1;
    }

    guard.service.set_identity_persisted(true);
    0
}

/// Update the public profile fields and re-persist the identity.
///
/// Expects JSON: `{"displayName":"Alice","isPublic":false}`
#[no_mangle]
pub extern "C" fn mi_set_public_profile(ctx: *mut MeshContext, json_ptr: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let json_str = match read_cstr(json_ptr, MAX_KEY_LEN, "json") {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };

    let parsed: Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("Invalid JSON: {}", e));
            return -1;
        }
    };

    let display_name = parsed
        .get("displayName")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let is_public = parsed
        .get("isPublic")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let service = match get_service() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };
    let mut guard = service.lock().unwrap();

    let mut profile = guard.service.local_profile().clone();
    profile.public_display_name = display_name;
    profile.identity_is_public = is_public;
    guard.service.set_local_profile(profile);

    if let Err(e) = persist_identity(&mut guard.service) {
        set_last_error(e.to_string());
        return -1;
    }
    0
}

/// Update the private profile fields and re-persist the identity.
///
/// Expects JSON: `{"displayName":"Alice Smith","bio":"..."}`
#[no_mangle]
pub extern "C" fn mi_set_private_profile(ctx: *mut MeshContext, json_ptr: *const c_char) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let json_str = match read_cstr(json_ptr, MAX_KEY_LEN, "json") {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };

    let parsed: Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("Invalid JSON: {}", e));
            return -1;
        }
    };

    let display_name = parsed
        .get("displayName")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let bio = parsed
        .get("bio")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let service = match get_service() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };
    let mut guard = service.lock().unwrap();

    let mut profile = guard.service.local_profile().clone();
    profile.private_display_name = display_name;
    profile.private_bio = bio;
    guard.service.set_local_profile(profile);

    if let Err(e) = persist_identity(&mut guard.service) {
        set_last_error(e.to_string());
        return -1;
    }
    0
}

/// Import an identity from an encrypted backup.
///
/// `backup_json_ptr` is the JSON-serialised `EncryptedBackup` payload.
/// `passphrase_ptr` is the passphrase used to decrypt it.
///
/// On success the new identity is persisted to disk and the service switches
/// to it immediately.
#[no_mangle]
pub extern "C" fn mi_import_identity(
    ctx: *mut MeshContext,
    backup_json_ptr: *const c_char,
    passphrase_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let backup_json = match read_cstr(backup_json_ptr, 1024 * 1024, "backup_json") {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };
    let passphrase = match read_cstr(passphrase_ptr, MAX_KEY_LEN, "passphrase") {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };

    let backup: EncryptedBackup = match serde_json::from_str(&backup_json) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(format!("Invalid backup JSON: {}", e));
            return -1;
        }
    };

    let manager = BackupManager::new();
    let (keypair_bytes, _trust_store, _network_map, settings) =
        match manager.restore_backup(&backup, &passphrase) {
            Ok(result) => result,
            Err(e) => {
                set_last_error(e.to_string());
                return -1;
            }
        };

    if keypair_bytes.len() < 32 {
        set_last_error("Backup keypair too short");
        return -1;
    }

    let ed25519: [u8; 32] = match keypair_bytes[..32].try_into() {
        Ok(b) => b,
        Err(_) => {
            set_last_error("Failed to extract ed25519 secret key from backup");
            return -1;
        }
    };

    // Generate a fresh X25519 DH secret — the backup format does not preserve it.
    let dh_secret = X25519StaticSecret::random_from_rng(rand_core::OsRng);
    let x25519 = dh_secret.to_bytes();

    let name = settings.display_name.clone();
    let profile = LocalProfile::default();

    let service = match get_service() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.to_string());
            return -1;
        }
    };
    let mut guard = service.lock().unwrap();

    if let Err(e) =
        guard
            .service
            .load_identity_from_bytes(ed25519, x25519, name.clone(), profile.clone())
    {
        set_last_error(e.to_string());
        return -1;
    }

    let persisted = PersistedIdentity {
        ed25519_secret: ed25519.to_vec(),
        x25519_secret: x25519.to_vec(),
        name,
        public_display_name: profile.public_display_name,
        identity_is_public: profile.identity_is_public,
        private_display_name: profile.private_display_name,
        private_bio: profile.private_bio,
    };

    let store_guard = IDENTITY_STORE.lock().unwrap();
    let store = match store_guard.as_ref() {
        Some(s) => s,
        None => {
            set_last_error("Identity store not initialised");
            return -1;
        }
    };

    if let Err(e) = store.save(&persisted) {
        set_last_error(e.to_string());
        return -1;
    }

    0
}

/// Killswitch: overwrite the keyfile with random bytes and remove all identity
/// files, permanently destroying the on-disk identity.
///
/// The in-memory identity remains active until the next restart.
#[no_mangle]
pub extern "C" fn mi_reset_identity(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        set_last_error("context was null");
        return -1;
    }

    let store_guard = IDENTITY_STORE.lock().unwrap();
    let store = match store_guard.as_ref() {
        Some(s) => s,
        None => {
            set_last_error("Identity store not initialised");
            return -1;
        }
    };

    if let Err(e) = store.destroy() {
        set_last_error(e.to_string());
        return -1;
    }

    if let Ok(service) = get_service() {
        if let Ok(mut guard) = service.lock() {
            guard.service.set_identity_persisted(false);
        }
    }

    0
}

// Helper: serialise the current service identity + profile and re-save to disk.
fn persist_identity(service: &mut MeshInfinityService) -> Result<()> {
    let (ed25519, x25519) = service
        .primary_secret_key_bytes()
        .ok_or(MeshInfinityError::AuthError("No primary identity".to_string()))?;

    let summary = service.local_identity_summary();
    let name = summary.and_then(|s| s.name);
    let profile = service.local_profile().clone();

    let persisted = PersistedIdentity {
        ed25519_secret: ed25519.to_vec(),
        x25519_secret: x25519.to_vec(),
        name,
        public_display_name: profile.public_display_name,
        identity_is_public: profile.identity_is_public,
        private_display_name: profile.private_display_name,
        private_bio: profile.private_bio,
    };

    let store_guard = IDENTITY_STORE
        .lock()
        .map_err(|_| MeshInfinityError::LockError("IDENTITY_STORE poisoned".to_string()))?;
    let store = store_guard
        .as_ref()
        .ok_or(MeshInfinityError::InvalidConfiguration(
            "Identity store not initialised".to_string(),
        ))?;

    store.save(&persisted)
}

/// Get service.
fn get_service() -> Result<Arc<Mutex<ServiceHandle>>> {
    MESH_STATE
        .lock()
        .unwrap()
        .clone()
        .ok_or(MeshInfinityError::ResourceUnavailable)
}

unsafe fn config_ref<'a>(ptr: *const FfiMeshConfig) -> &'a FfiMeshConfig {
    &*ptr
}

unsafe fn message_ref<'a>(ptr: *const FfiMessage) -> &'a FfiMessage {
    &*ptr
}

unsafe fn free_c_string(value: *mut c_char) {
    let _ = CString::from_raw(value);
}

/// Read cstr.
fn read_cstr(ptr: *const c_char, max_len: usize, field: &str) -> Result<String> {
    if ptr.is_null() {
        return Err(MeshInfinityError::InvalidConfiguration(format!(
            "{field} pointer was null"
        )));
    }
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let bytes = c_str.to_bytes();
    if bytes.len() > max_len {
        return Err(MeshInfinityError::InvalidConfiguration(format!(
            "{field} exceeded max length"
        )));
    }
    std::str::from_utf8(bytes)
        .map(|value| value.to_string())
        .map_err(|_| {
            MeshInfinityError::InvalidConfiguration(format!("{field} was not valid utf-8"))
        })
}

/// Parse peer id.
fn parse_peer_id(value: &str) -> Result<[u8; 32]> {
    let mut hex = String::new();
    for ch in value.chars() {
        if ch.is_ascii_hexdigit() {
            hex.push(ch);
        }
    }

    if hex.len() < 16 {
        return Err(MeshInfinityError::InvalidConfiguration(
            "peer_id too short".to_string(),
        ));
    }

    let mut bytes = [0u8; 32];
    let available = hex.len() / 2;
    let count = usize::min(bytes.len(), available);
    for (i, slot) in bytes.iter_mut().enumerate().take(count) {
        let idx = i * 2;
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16).map_err(|_| {
            MeshInfinityError::InvalidConfiguration("peer_id was not valid hex".to_string())
        })?;
        *slot = byte;
    }
    Ok(bytes)
}

/// Parse trust markers.
fn parse_trust_markers(json_str: &str) -> Result<Vec<(PeerId, PeerId, TrustLevel, SystemTime)>> {
    let parsed: Value = serde_json::from_str(json_str)
        .map_err(|err| MeshInfinityError::DeserializationError(err.to_string()))?;
    let array = parsed.as_array().cloned().unwrap_or_default();
    let mut markers = Vec::new();

    for marker in array {
        let obj = marker.as_object().ok_or_else(|| {
            MeshInfinityError::InvalidConfiguration("invalid trust marker".to_string())
        })?;
        let endorser = obj
            .get("endorser")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                MeshInfinityError::InvalidConfiguration("missing endorser".to_string())
            })?;
        let target = obj
            .get("target")
            .and_then(|value| value.as_str())
            .ok_or_else(|| MeshInfinityError::InvalidConfiguration("missing target".to_string()))?;
        let trust_level = obj
            .get("trustLevel")
            .and_then(|value| value.as_i64())
            .unwrap_or(0) as i32;
        let timestamp = obj
            .get("timestamp")
            .and_then(|value| value.as_i64())
            .unwrap_or(0);

        let endorser = parse_peer_id(endorser)?;
        let target = parse_peer_id(target)?;
        let trust_level = trust_level_from_i32(trust_level);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp.max(0) as u64);
        markers.push((endorser, target, trust_level, timestamp));
    }

    Ok(markers)
}

/// Set last error.
fn set_last_error(message: impl Into<String>) {
    *LAST_ERROR.lock().unwrap() = Some(message.into());
}

/// Take last error.
fn take_last_error() -> Option<String> {
    LAST_ERROR.lock().unwrap().take()
}

/// Json to c string.
fn json_to_c_string(value: Value) -> *mut c_char {
    match serde_json::to_string(&value) {
        Ok(serialized) => string_to_c_string(&serialized),
        Err(err) => {
            set_last_error(err.to_string());
            std::ptr::null_mut()
        }
    }
}

/// String to c string.
fn string_to_c_string(value: &str) -> *mut c_char {
    match CString::new(value) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Room to json.
fn room_to_json(room: &RoomSummary) -> Value {
    json!({
        "id": room.id,
        "title": room.name,
        "preview": room.last_message,
        "lastSeen": room.timestamp,
        "unreadCount": room.unread_count,
        "threadType": if room.id.starts_with("dm-") { "direct" } else { "group" },
    })
}

/// Message to json.
fn message_to_json(message: &Message) -> Value {
    json!({
        "id": message.id,
        "roomId": message.room_id,
        "sender": message.sender,
        "text": message.text,
        "timestamp": message.timestamp,
        "isOutgoing": message.is_outgoing,
    })
}

/// Peer to json.
fn peer_to_json(peer: &PeerSummary) -> Value {
    json!({
        "id": peer.id,
        "name": peer.name,
        "trustLevel": peer.trust_level,
        "status": peer.status,
    })
}

/// Identity to json.
fn identity_to_json(identity: &IdentitySummary) -> Value {
    json!({
        "peerId": peer_id_string(&identity.peer_id),
        "publicKey": hex_encode(&identity.public_key),
        "dhPublicKey": hex_encode(&identity.dh_public),
        "name": identity.name,
    })
}

/// Transfer to json.
fn transfer_to_json(transfer: &FileTransferSummary) -> Value {
    json!({
        "id": transfer.id,
        "peerId": transfer.peer_id,
        "name": transfer.name,
        "sizeBytes": transfer.size_bytes,
        "transferredBytes": transfer.transferred_bytes,
        "status": transfer.status,
        "direction": transfer.direction,
    })
}

/// Reconnect snapshot to json.
fn reconnect_snapshot_to_json(snapshot: &ReconnectSyncSnapshot) -> Value {
    json!({
        "missedMessages": snapshot
            .missed_messages
            .iter()
            .map(message_to_json)
            .collect::<Vec<_>>(),
        "resumableTransfers": snapshot
            .resumable_transfers
            .iter()
            .map(transfer_to_json)
            .collect::<Vec<_>>(),
    })
}

/// Hosted service to json.
fn hosted_service_to_json(service: &HostedServiceSummary) -> Value {
    json!({
        "id": service.id,
        "name": service.name,
        "path": service.path,
        "address": service.address,
        "enabled": service.enabled,
        "minTrustLevel": service.min_trust_level,
        "allowedTransports": service.allowed_transports,
    })
}

/// Parse transport type from user-facing transport name.
fn transport_type_from_name(name: &str) -> Option<TransportType> {
    match name.to_ascii_lowercase().as_str() {
        "tor" => Some(TransportType::Tor),
        "i2p" => Some(TransportType::I2P),
        "bluetooth" => Some(TransportType::Bluetooth),
        "rf" => Some(TransportType::Rf),
        "clearnet" => Some(TransportType::Clearnet),
        _ => None,
    }
}

/// Settings to json.
fn settings_to_json(settings: &Settings) -> Value {
    json!({
        "nodeMode": node_mode_label(settings.node_mode),
        "enableTor": settings.enable_tor,
        "enableClearnet": settings.enable_clearnet,
        "meshDiscovery": settings.mesh_discovery,
        "allowRelays": settings.allow_relays,
        "enableI2p": settings.enable_i2p,
        "enableBluetooth": settings.enable_bluetooth,
        "enableRf": settings.enable_rf,
        "pairingCode": settings.pairing_code,
        "localPeerId": settings.local_peer_id,
    })
}

/// Peer id string.
fn peer_id_string(peer_id: &PeerId) -> String {
    hex_encode(peer_id)
}

/// Hex encode.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Push room update.
fn push_room_update(guard: &mut ServiceHandle, room_id: Option<String>) {
    let target_room_id = room_id.or_else(|| guard.service.active_room_id());
    if let Some(room_id) = target_room_id {
        if let Some(room) = guard
            .service
            .rooms()
            .into_iter()
            .find(|room| room.id == room_id)
        {
            guard.push_event(BackendEvent::RoomUpdated(room));
        }
    }
}

/// Node mode from u8.
fn node_mode_from_u8(mode: u8) -> NodeMode {
    match mode {
        1 => NodeMode::Server,
        2 => NodeMode::Dual,
        _ => NodeMode::Client,
    }
}

/// Node mode label.
fn node_mode_label(mode: NodeMode) -> &'static str {
    match mode {
        NodeMode::Client => "client",
        NodeMode::Server => "server",
        NodeMode::Dual => "dual",
    }
}

/// Trust level from i32.
fn trust_level_from_i32(level: i32) -> TrustLevel {
    match level {
        3 => TrustLevel::HighlyTrusted,
        2 => TrustLevel::Trusted,
        1 => TrustLevel::Caution,
        _ => TrustLevel::Untrusted,
    }
}

/// Verification method from u8.
fn verification_method_from_u8(method: u8) -> WotVerificationMethod {
    match method {
        1 => WotVerificationMethod::InPerson,
        2 => WotVerificationMethod::SharedSecret,
        3 => WotVerificationMethod::TrustedIntroduction,
        4 => WotVerificationMethod::PKI,
        _ => WotVerificationMethod::SharedSecret,
    }
}

/// Event to json.
fn event_to_json(event: &BackendEvent) -> Value {
    match event {
        BackendEvent::MessageAdded(message) => json!({
            "type": "message_added",
            "roomId": message.room_id,
            "message": message_to_json(message),
        }),
        BackendEvent::RoomUpdated(room) => json!({
            "type": "room_updated",
            "room": room_to_json(room),
        }),
        BackendEvent::RoomDeleted(room_id) => json!({
            "type": "room_deleted",
            "roomId": room_id,
        }),
        BackendEvent::PeerUpdated(peer) => json!({
            "type": "peer_updated",
            "peer": peer_to_json(peer),
        }),
        BackendEvent::MessageDeleted {
            room_id,
            message_id,
        } => json!({
            "type": "message_deleted",
            "roomId": room_id,
            "messageId": message_id,
        }),
        BackendEvent::TransferUpdated(transfer) => json!({
            "type": "transfer_updated",
            "transfer": transfer_to_json(transfer),
        }),
        BackendEvent::SettingsUpdated(settings) => json!({
            "type": "settings_updated",
            "settings": settings_to_json(settings),
        }),
        BackendEvent::ActiveRoomChanged(room_id) => json!({
            "type": "active_room_changed",
            "roomId": room_id,
        }),
        BackendEvent::TrustUpdated {
            peer_id,
            trust_level,
        } => json!({
            "type": "trust_updated",
            "peerId": peer_id,
            "trustLevel": trust_level,
        }),
    }
}

/// Rust error to c code.
fn rust_error_to_c_code(err: &MeshInfinityError) -> i32 {
    match err {
        MeshInfinityError::InvalidConfiguration(_) => -100,
        MeshInfinityError::NetworkError(_) => -200,
        MeshInfinityError::CryptoError(_) => -300,
        MeshInfinityError::AuthError(_) => -400,
        MeshInfinityError::TransportError(_) => -500,
        MeshInfinityError::WireGuardError(_) => -600,
        MeshInfinityError::DiscoveryError(_) => -700,
        MeshInfinityError::FileTransferError(_) => -800,
        MeshInfinityError::ExitNodeError(_) => -900,
        MeshInfinityError::AppGatewayError(_) => -1000,
        MeshInfinityError::SecurityError(_) => -1100,
        MeshInfinityError::NoAvailableTransport => -501,
        MeshInfinityError::NoActiveSession => -502,
        MeshInfinityError::PeerNotFound(_) => -503,
        MeshInfinityError::ConnectionTimeout => -504,
        MeshInfinityError::InvalidMessageFormat => -505,
        MeshInfinityError::InsufficientTrust => -506,
        MeshInfinityError::UntrustedPeer => -509,
        MeshInfinityError::ConnectionRejected(_) => -510,
        MeshInfinityError::ProtocolMismatch => -511,
        MeshInfinityError::ResourceUnavailable => -507,
        MeshInfinityError::OperationNotSupported => -508,
        MeshInfinityError::IoError(_) => -1001,
        MeshInfinityError::SerializationError(_) => -1002,
        MeshInfinityError::DeserializationError(_) => -1003,
        MeshInfinityError::LockError(_) => -1004,
        MeshInfinityError::InvalidInput(_) => -1005,
        MeshInfinityError::VpnRoutingNotEnabled => -1006,
        MeshInfinityError::InsufficientPrivileges(_) => -1007,
    }
}
