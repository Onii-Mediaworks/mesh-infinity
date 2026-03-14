//! Public service-facing data models.
//!
//! This file defines stable backend service types consumed by callers (FFI/UI)
//! and by service submodules. It intentionally excludes runtime state internals.
//!
//! # What is this file?
//!
//! Think of this file as the "vocabulary" shared between the Rust backend and
//! the Flutter UI. Every piece of information the UI will ever display — a chat
//! message, a peer's name, a file download's progress — is described here as a
//! simple Rust struct (a named collection of fields, like a data class in Dart).
//!
//! The types in here are deliberately simple. They carry only the fields that
//! the UI actually needs, with no internal implementation detail. This keeps the
//! boundary between the engine and the display layer clean and stable.
//!
//! # Why are so many fields plain `String` or `i32` instead of typed enums?
//!
//! Rust enums, like `TrustLevel::Trusted`, do not exist in the Dart language
//! that Flutter uses. The bridge between Rust and Flutter (called FFI —
//! Foreign Function Interface) serialises data as JSON strings. Keeping fields
//! as `String` or integer means Flutter can read them without needing any
//! special Rust knowledge. The richer typed versions (using proper Rust enums)
//! live in the "policy" structs used internally by the backend.
//!
//! # What is a `#[derive(...)]` annotation?
//!
//! `#[derive(Clone, Debug)]` is an instruction to the Rust compiler to
//! automatically generate code for those "traits" (think: interfaces):
//! - `Clone`  — lets you call `.clone()` to make an independent copy of a value.
//!              Without `Clone`, you can only have one owner at a time.
//! - `Copy`   — even cheaper than `Clone`. Instead of calling `.clone()`,
//!              the value is just copied by the CPU when assigned. Only small
//!              types (a few bytes) should be `Copy`.
//! - `Debug`  — lets Rust print the value for debugging using `{:?}` format,
//!              e.g. `println!("{:?}", my_value)`.
//! - `PartialEq` / `Eq` — lets you use `==` to compare two values of this type.
//! - `Default` — lets Rust construct a "blank" instance with zero/false/None for
//!              all fields. See the `impl Default` blocks at the bottom of this file.

// Import the underlying "core" types that some of our types reference.
// `PeerId` is a 32-byte array (`[u8; 32]`) that uniquely identifies a node on
// the mesh network. It is derived from the node's Ed25519 public signing key.
//
// `TransportType` is an enum describing the *channel* over which two nodes
// communicate. Examples: Tor (anonymous relay), Bluetooth (short-range radio),
// Clearnet (regular internet).
//
// `TrustLevel` describes how much this device trusts a given peer, on a scale
// from `Untrusted` (a stranger) to `HighlyTrusted` (a verified contact).
// We import it as `CoreTrustLevel` to avoid a name collision with our own types.
//
// `MeshConfig` holds low-level mesh networking parameters: which transports are
// enabled, whether relaying is allowed, whether local discovery is on, etc.
use crate::core::core::{MeshConfig, PeerId, TransportType, TrustLevel as CoreTrustLevel};

// ---------------------------------------------------------------------------
// NodeMode
// ---------------------------------------------------------------------------

/// The operating role that this device plays on the mesh network.
///
/// A mesh network can have different kinds of participants. Think of a postal
/// system: some nodes are just mailboxes (they only send and receive their own
/// mail), while others are sorting offices (they also forward mail for others).
///
/// This enum captures the three roles a Mesh Infinity node can take:
///
/// - **Client** — a leaf node (the "mailbox"). It only connects to other nodes
///   when it needs to send or receive data for itself. It does NOT forward
///   messages for other peers and does NOT run a background routing worker.
///   This is the right choice for phones with limited battery — the app
///   stays quiet when the user isn't actively messaging.
///
/// - **Server** — a relay / infrastructure node (the "sorting office"). It runs
///   a persistent routing worker thread that continuously forwards queued
///   messages between peers. Suitable for always-on devices like a home server
///   or a Raspberry Pi that can stay on 24/7.
///
/// - **Dual** — acts as both a client and a server simultaneously. It routes
///   for other peers AND participates directly in conversations. Suitable for
///   desktop machines that are nearly always on but are also used directly by
///   the owner.
///
/// The `#[derive(...)]` line automatically generates several useful traits:
/// - `Clone`  — lets Rust make a copy of the value when needed.
/// - `Copy`   — very cheap copies (no heap allocation); the value can be
///              duplicated just by copying a handful of bytes on the stack.
///              Enums with no data in their variants (like this one) are ideal
///              candidates for `Copy` because they are just a tiny integer
///              internally.
/// - `Debug`  — lets Rust print it for debugging (`{:?}` format).
/// - `PartialEq` / `Eq` — lets Rust compare two `NodeMode` values with `==`.
///              `PartialEq` is the weaker form (covers most cases); `Eq`
///              additionally promises that `x == x` is always true (reflexivity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeMode {
    /// Leaf node — no background routing, battery-friendly.
    ///
    /// Suitable for: phones, tablets, any device where battery life matters.
    /// The routing worker thread is NOT started in this mode.
    Client,

    /// Always-on relay — runs the routing worker thread.
    ///
    /// Suitable for: servers, Raspberry Pi, NAS boxes. The device acts as
    /// infrastructure for other peers but does not need to have a user sitting
    /// at it. Routing happens in a background thread every 50 ms.
    Server,

    /// Full participant — routes for others AND sends/receives directly.
    ///
    /// Suitable for: desktop machines that are on most of the day. The same
    /// background routing worker runs as in `Server` mode, AND the user can
    /// use all the chat/file features as in `Client` mode.
    Dual,
}

// ---------------------------------------------------------------------------
// RoomSummary
// ---------------------------------------------------------------------------

/// A lightweight snapshot of a chat room, used to populate the conversation list.
///
/// In a chat application like Signal or WhatsApp you see a list of conversations
/// on the home screen. Each row in that list shows the room name, the last
/// message preview, how many unread messages there are, and a timestamp. That
/// is exactly what `RoomSummary` carries — nothing more, nothing less.
///
/// The full message history lives in a separate data structure keyed by room ID.
/// This struct is only the "headline view" — the minimal data needed to render
/// one row in the conversation list without loading every single message.
///
/// Why keep it separate from the full history?
/// Because loading all messages for all rooms just to draw the list would be
/// slow and wasteful, especially for rooms with thousands of messages. Instead,
/// the UI asks for the list of `RoomSummary`s (fast), then only loads the full
/// message history when the user taps a specific room (lazy loading).
#[derive(Clone, Debug)]
pub struct RoomSummary {
    /// Stable unique identifier for this room (e.g. `"dm-AABBCC..."`).
    ///
    /// This ID is generated once when the room is created and never changes,
    /// even if the room is renamed. It is used as the key in the `messages`
    /// map that stores the full conversation history.
    ///
    /// For direct-message (DM) rooms, the format is `"dm-<64-hex-peer-id>"`.
    /// For group rooms, the format is `"room-<16-hex-random>"`.
    pub id: String,

    /// Human-readable display name shown in the conversation list.
    ///
    /// For DMs this is the other person's display name or peer ID.
    /// For group rooms this is whatever name was chosen when creating the room.
    pub name: String,

    /// Preview text of the most recent message in this room.
    ///
    /// Shown as the subtitle (secondary text) under the room name in the list.
    /// If no messages have been sent yet, this is an empty string.
    pub last_message: String,

    /// Number of messages that have arrived since the user last opened this room.
    ///
    /// Displayed as a badge (a small number bubble) on the room row — the same
    /// kind of unread count you see on a messaging app icon or chat thread.
    /// Resets to 0 when the user opens the room.
    pub unread_count: i32,

    /// Formatted timestamp of the most recent activity in the room.
    ///
    /// Displayed on the right-hand side of the room row, in `"HH:MM"` format.
    /// This is the time of the last message, NOT the time the room was created.
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// A single chat message, as shown in a conversation thread.
///
/// This is the individual item rendered inside an open chat room — the text
/// bubble on the screen. It knows which room it belongs to, who sent it, what
/// it says, and whether this device was the one that sent it.
///
/// # Why does `is_outgoing` matter?
///
/// Chat UIs conventionally display your own messages on the RIGHT side of the
/// screen (as "outgoing" bubbles) and messages from others on the LEFT side.
/// This field tells the Flutter UI which side to render each bubble on — without
/// it, the UI would have to compare the sender ID to the local peer ID every
/// time it draws a message, which requires more state passing.
///
/// # What about encryption?
///
/// Messages travel over the network as encrypted ciphertext. The `text` field
/// here holds the *already-decrypted* plaintext. Decryption happens inside the
/// backend when the message is received; by the time it reaches this struct the
/// content is safe to display.
#[derive(Clone, Debug)]
pub struct Message {
    /// Stable unique identifier for this message.
    ///
    /// Format: `"msg-<16-hex-random>"` (e.g. `"msg-A3F70C8E1B2D4E6F"`).
    /// Random and unique — no two messages share the same ID even across devices.
    pub id: String,

    /// The ID of the room this message belongs to.
    ///
    /// Matches exactly one `RoomSummary::id`. Used to look up where to insert
    /// this message in the `messages` hash map.
    pub room_id: String,

    /// Display name or peer ID of the person who sent this message.
    ///
    /// If the sender has a display name configured, that is used. Otherwise
    /// the hex peer ID is used as a fallback. The UI displays this text above
    /// the message bubble in group rooms.
    pub sender: String,

    /// The plain-text body of the message.
    ///
    /// Note: this is the decrypted content. Messages travel encrypted over the
    /// network; decryption is performed by the backend before filling this field.
    /// The ciphertext is never stored in this struct.
    pub text: String,

    /// Formatted timestamp string shown on the message bubble.
    ///
    /// Format: `"HH:MM"` in UTC (e.g. `"14:37"`). This is a display string,
    /// not a machine-parseable timestamp — it is computed once and stored so
    /// the UI does not need to parse or format dates itself.
    pub timestamp: String,

    /// `true` if this device sent this message; `false` if it was received.
    ///
    /// The UI uses this field to align bubbles:
    /// - `is_outgoing == true`  → render the bubble on the RIGHT (blue/green)
    /// - `is_outgoing == false` → render the bubble on the LEFT (grey/white)
    ///
    /// This is the standard chat UI convention used by iMessage, WhatsApp, Signal, etc.
    pub is_outgoing: bool,
}

// ---------------------------------------------------------------------------
// PeerSummary
// ---------------------------------------------------------------------------

/// A lightweight view of a known peer (another device on the mesh).
///
/// Shown in the "Peers" section of the app. Each row displays who the peer
/// is, how trusted they are, and whether they appear to be online right now.
///
/// "A peer" in this context means any other Mesh Infinity node that this device
/// has been introduced to — either through QR-code pairing, manual pairing code
/// entry, or automatic local network discovery. Unknown devices are not peers
/// until a pairing step takes place.
#[derive(Clone, Debug)]
pub struct PeerSummary {
    /// Stable unique identifier for this peer.
    ///
    /// This is the hex-encoded 32-byte public signing key (64 hex characters).
    /// It uniquely identifies the peer across all networks and all time — no
    /// two devices share the same peer ID because each is generated from a
    /// fresh random key pair.
    ///
    /// Example: `"A3F70C8E1B2D4E6F...A3F70C8E1B2D4E6F"` (64 chars).
    pub id: String,

    /// Human-readable display name for this peer.
    ///
    /// Set during pairing (either from the peer's own profile or from a name
    /// the user assigns locally). Purely cosmetic — the peer ID is the stable
    /// identifier; the name can be changed without affecting routing.
    pub name: String,

    /// Numeric trust level: 0 = Untrusted, 1 = Caution, 2 = Trusted, 3 = Highly trusted.
    ///
    /// Stored as a plain integer (`i32`) rather than the `TrustLevel` enum so
    /// that the FFI layer — the bridge between Rust and Flutter — can pass it
    /// across without needing to know anything about Rust enums, which don't
    /// exist in Dart. Flutter maps these integers to labels and icons.
    ///
    /// The corresponding Rust enum has these variants:
    ///   0 = `CoreTrustLevel::Untrusted`     — a stranger; minimal privileges
    ///   1 = `CoreTrustLevel::Caution`       — acknowledged but not verified
    ///   2 = `CoreTrustLevel::Trusted`       — verified contact
    ///   3 = `CoreTrustLevel::HighlyTrusted` — deeply trusted (e.g. your own device)
    pub trust_level: i32,

    /// Connection status string: `"online"`, `"offline"`, or `"idle"`.
    ///
    /// Also a plain string (not an enum) for the same FFI-friendly reason as
    /// `trust_level`. The Flutter UI maps these strings to status indicator dots:
    ///   "online"  → green dot
    ///   "idle"    → yellow dot
    ///   "offline" → grey dot
    pub status: String,
}

// ---------------------------------------------------------------------------
// FileTransferSummary
// ---------------------------------------------------------------------------

/// A snapshot of a single file transfer (send or receive), used in the Files tab.
///
/// File transfers happen in the background. This struct captures everything
/// the UI needs to render one row in the transfers list: the file name, total
/// size, how much has been transferred so far, the current status label, and
/// whether this device is the sender or the receiver.
///
/// # Progress bar math
///
/// The UI computes the fraction complete as:
/// `progress = transferred_bytes / size_bytes`
/// This gives a value between 0.0 and 1.0 which is then drawn as a progress bar.
/// For example: 256 KB transferred out of 1024 KB → 0.25 → 25% bar.
///
/// # Why split into chunks?
///
/// The `FileTransferManager` internally splits files into 64 KB chunks.
/// `transferred_bytes` increases by one chunk's worth each time a chunk is
/// confirmed delivered. This means the progress bar updates smoothly even for
/// very large files.
#[derive(Clone, Debug)]
pub struct FileTransferSummary {
    /// Stable unique identifier for this transfer.
    ///
    /// Format: hex-encoded 32-byte random ID (64 characters).
    /// Used to look up, update, or cancel a specific transfer.
    pub id: String,

    /// The peer ID of the other device involved in this transfer.
    ///
    /// For a Send transfer, this is the *recipient* peer.
    /// For a Receive transfer, this is the *sender* peer.
    pub peer_id: String,

    /// Original file name (e.g. `"photo.jpg"`, `"document.pdf"`).
    ///
    /// This is the name the sender reports; it is NOT guaranteed to be the
    /// name the file will be saved as on the receiving device (the OS may
    /// append a suffix if a file with that name already exists).
    pub name: String,

    /// Total size of the file in bytes.
    ///
    /// `u64` (unsigned 64-bit integer) is used so we can represent files up to
    /// approximately 18 exabytes — far beyond any realistic file size today.
    /// An `i32` would only fit files up to ~2 GB, which is too small.
    pub size_bytes: u64,

    /// How many bytes have been successfully sent or received so far.
    ///
    /// The UI computes `transferred_bytes / size_bytes` to draw a progress bar.
    /// When `transferred_bytes == size_bytes`, the transfer is complete.
    pub transferred_bytes: u64,

    /// Human-readable status string.
    ///
    /// One of: `"Queued"`, `"In progress"`, `"Completed"`, `"Failed"`, or `"Canceled"`.
    /// Stored as a plain string for FFI compatibility — the Flutter UI maps these
    /// to icons and colour codes.
    pub status: String,

    /// Direction of this transfer: `"Send"` or `"Receive"`.
    ///
    /// `"Send"`    — this device is sending the file to the peer.
    /// `"Receive"` — this device is receiving the file from the peer.
    /// Also a plain string for FFI compatibility.
    pub direction: String,
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// All user-visible application settings, mirroring the Settings screen in the UI.
///
/// This struct is the single source of truth for what the user has configured
/// in the Settings screen. It is kept inside `ServiceState` (wrapped in an
/// `RwLock` for thread safety) and a copy is handed to the Flutter UI whenever
/// the Settings screen opens.
///
/// # Why is a copy returned to the UI rather than a reference?
///
/// Because the UI runs on a different thread from the backend. If we returned
/// a reference, the UI would need to hold the `RwLock` the entire time it is
/// reading the settings, which would block the backend from writing.
/// Returning a clone (a full copy of the struct) lets the UI read the settings
/// without holding any lock.
///
/// # What is a transport?
///
/// A "transport" is the network channel used to carry messages between two
/// nodes. The settings here control which channels are active:
///
/// - **Tor** — routes traffic through the Tor anonymity network, which hides
///   both endpoints' IP addresses by bouncing traffic through volunteer relays
///   worldwide. Slow but highly private.
///
/// - **I2P** — the "Invisible Internet Project", another anonymity overlay.
///   Traffic stays entirely within the I2P network (a separate peer-to-peer
///   overlay). Faster than Tor for I2P-to-I2P traffic.
///
/// - **Clearnet** — plain internet. Both devices can see each other's IP
///   addresses. Fast, but no anonymity.
///
/// - **Bluetooth** — short-range (typically 10–100 m) radio. Works with NO
///   internet connection at all. Ideal for in-person use or when infrastructure
///   is unavailable.
///
/// - **RF** (Radio Frequency) — long-range radio (LoRa / software-defined
///   radio). Can reach kilometres without any infrastructure. Very slow.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The current operating role of this node (Client, Server, or Dual).
    ///
    /// See `NodeMode` above for a full explanation. Changing this at runtime
    /// via the Settings screen calls `set_node_mode()` which automatically
    /// starts or stops the background routing worker.
    pub node_mode: NodeMode,

    /// Whether to route traffic through the Tor anonymity network.
    ///
    /// When `true`, all outbound messages to Tor-capable peers travel through
    /// three or more Tor relay nodes, hiding this device's real IP address.
    /// Enabling Tor requires the `tor` binary to be accessible on the system.
    pub enable_tor: bool,

    /// Whether to allow direct (non-anonymised) internet connections.
    ///
    /// "Clearnet" means the regular internet, where both endpoints can see
    /// each other's IP address. Enabling this is faster but less private.
    /// Only offered to peers with `Trusted` or `HighlyTrusted` trust level.
    pub enable_clearnet: bool,

    /// Whether to use local network discovery (mDNS / Bonjour) to find peers
    /// on the same Wi-Fi or Ethernet automatically.
    ///
    /// mDNS (Multicast DNS, also called Bonjour on Apple platforms) lets
    /// devices announce themselves on the local network without needing a
    /// central server. When this is on, Mesh Infinity peers on the same LAN
    /// will be discovered automatically and show up in the Peers list.
    pub mesh_discovery: bool,

    /// Whether this node is permitted to forward messages on behalf of others.
    ///
    /// Enabling relays means this device will forward messages for peers that
    /// are not directly reachable by the sender. This helps the mesh be more
    /// resilient but uses this device's bandwidth and battery.
    pub allow_relays: bool,

    /// Whether to route traffic through I2P (Invisible Internet Project).
    ///
    /// I2P is an anonymity overlay network. Unlike Tor (which routes to the
    /// regular internet), I2P traffic stays entirely within the I2P overlay.
    /// Good for communicating with other I2P users without exposing IP addresses.
    pub enable_i2p: bool,

    /// Whether to communicate via Bluetooth when peers are physically nearby.
    ///
    /// Bluetooth works without ANY internet connection. Two phones can exchange
    /// messages as long as they are within Bluetooth range (~10–100 m).
    /// Ideal for protests, conferences, or areas with poor connectivity.
    pub enable_bluetooth: bool,

    /// Whether to use radio-frequency transports (LoRa / software-defined radio).
    ///
    /// RF can carry messages kilometres away without any infrastructure at all.
    /// Very low bandwidth (a few kB/s) but extremely resilient. Useful in
    /// remote areas or during infrastructure outages.
    pub enable_rf: bool,

    /// A short, human-friendly code for manual peer pairing.
    ///
    /// Format: `"XXXX-XXXX-XXXX-XXXX"` (16 uppercase hex digits in groups of 4).
    /// Derived from the first 8 bytes of this device's peer ID.
    ///
    /// Another device can type or scan this code to initiate pairing, without
    /// needing to scan a QR code. Useful when cameras are unavailable.
    ///
    /// Example: `"A1B2-C3D4-E5F6-7890"`.
    pub pairing_code: String,

    /// The full hex-encoded 32-byte peer ID for this device (64 hex characters).
    ///
    /// This is the canonical, globally unique identifier for this node.
    /// Used when a remote peer needs to address messages directly to this device,
    /// and displayed on the Identity screen as a long hex string or QR code.
    pub local_peer_id: String,
}

// ---------------------------------------------------------------------------
// IdentitySummary
// ---------------------------------------------------------------------------

/// The cryptographic identity of this device, shown on the Identity screen.
///
/// Every Mesh Infinity node has two key pairs:
///
/// **Ed25519** (signing key pair):
///   Used to *sign* messages so recipients can verify they genuinely came from
///   this device. Think of it like a digital signature on a letter — anyone
///   can verify the signature with the public key, but only the holder of the
///   private key can create the signature.
///
/// **X25519** (Diffie-Hellman key pair):
///   Used to *negotiate shared secrets* with other nodes. When two nodes want
///   to have a private conversation, they each use their X25519 private key
///   and the other's X25519 public key to independently compute the same shared
///   secret. This is the "magic" of Diffie-Hellman: two parties can agree on
///   a secret key without ever transmitting that key over the network.
///
/// This struct exposes ONLY the *public* halves of those key pairs. The private
/// (secret) halves never leave the backend and are never shown to anyone.
/// Showing someone your public keys is safe — they cannot be used to impersonate
/// you or decrypt messages sent to you.
///
/// `[u8; 32]` means "an array of exactly 32 bytes". The number 32 comes from
/// the elliptic curve used (Curve25519), where keys are always exactly 32 bytes.
#[derive(Clone, Debug)]
pub struct IdentitySummary {
    /// The 32-byte peer ID, derived from the Ed25519 public signing key.
    ///
    /// In practice this IS the Ed25519 public key — the peer ID is just a
    /// stable, well-known name for the same 32 bytes. Stored as `PeerId`
    /// (`[u8; 32]`) for type safety; converted to a 64-char hex string for display.
    pub peer_id: PeerId,

    /// The Ed25519 public signing key (32 bytes).
    ///
    /// Other peers use this key to verify that messages they receive were
    /// genuinely signed by this device. If the signature matches, the message
    /// has not been tampered with and really came from this device.
    pub public_key: [u8; 32],

    /// The X25519 public Diffie-Hellman key (32 bytes).
    ///
    /// Other peers use this key to establish an encrypted session with this
    /// device. Combined with their own X25519 private key, they can compute
    /// a shared secret that only the two of them know.
    pub dh_public: [u8; 32],

    /// Optional human-readable name associated with this identity.
    ///
    /// Set by the user during onboarding (e.g. "Alice's Phone"). Shared with
    /// peers so they can see a friendly name instead of a raw hex peer ID.
    /// `None` means no name has been set yet.
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// LocalProfile
// ---------------------------------------------------------------------------

/// Device-local profile fields that supplement the cryptographic identity.
///
/// The cryptographic identity (`IdentitySummary`) is about *who you are* on the
/// network — mathematically provable via key signatures. This struct is about
/// *how you present yourself* — socially. The fields here are stored only on
/// this device and are shared with other peers only if the user explicitly
/// enables public profile visibility.
///
/// # Why have both a public and a private display name?
///
/// - `public_display_name`: what other peers see when they look at your profile.
///   You might set this to "Alice" so your friends know who you are.
///
/// - `private_display_name`: a reminder only you can see, stored locally and
///   never sent to anyone. Useful if you manage multiple identities (e.g.
///   "My work profile", "My personal profile") and want a quick way to tell
///   them apart without exposing those labels to contacts.
///
/// # `#[derive(Default)]`
///
/// This annotation tells Rust to automatically generate a `default()` method
/// that creates an instance with all fields set to their "zero values":
/// - `Option<String>` → `None`
/// - `bool`           → `false`
///
/// This is used when a brand-new identity is generated (e.g. on first launch),
/// where the user hasn't filled in any profile information yet.
#[derive(Clone, Debug, Default)]
pub struct LocalProfile {
    /// The name that peers who can see this node's public profile will see.
    ///
    /// `None` means no public name has been set — the node is "anonymous" on
    /// the mesh (other peers will see the raw peer ID hex instead).
    pub public_display_name: Option<String>,

    /// Controls whether unknown peers can find this node through browsing.
    ///
    /// If `false` (the default), this node only appears to peers that already
    /// know its peer ID (e.g. via a QR code scan or manual pairing code entry).
    /// Unknown devices scanning the local network will not see it.
    ///
    /// If `true`, this node announces itself publicly and any peer can initiate
    /// contact without prior introduction.
    pub identity_is_public: bool,

    /// A private display name stored ONLY on this device, never shared.
    ///
    /// Useful as a personal reminder of which identity this is. For example,
    /// if you have multiple Mesh Infinity profiles, you might label this one
    /// "Personal phone" to distinguish it from "Work tablet". This label is
    /// never transmitted to any peer.
    pub private_display_name: Option<String>,

    /// A private free-form biography stored ONLY on this device, never shared.
    ///
    /// An optional note you can write to yourself — e.g. "Generated for the
    /// 2025 hackathon, discard after." Never sent to peers.
    pub private_bio: Option<String>,
}

// ---------------------------------------------------------------------------
// PreloadedIdentity
// ---------------------------------------------------------------------------

/// Key material supplied to `MeshInfinityService::new` when the app restores
/// an identity that was previously saved to disk.
///
/// # Why is this needed?
///
/// Every Mesh Infinity node has a cryptographic identity — a pair of key pairs
/// that uniquely identify it on the mesh. On the very first launch, a fresh
/// identity is generated at random. After the user completes onboarding, that
/// identity is saved ("persisted") to encrypted storage on the device.
///
/// On every SUBSEQUENT launch, the app reads those saved keys from disk and
/// passes them here so the service can reconstruct the same identity. Without
/// this, every restart would generate a new random identity and the user would
/// appear as a completely different person to all their contacts — all their
/// chats and paired peers would become inaccessible.
///
/// # What are "secret keys"?
///
/// A key pair has two halves:
/// - **Public key** — safe to share. Other peers use it to verify your signatures.
/// - **Private (secret) key** — must NEVER be shared. Used to create signatures
///   and decrypt messages. Whoever has the private key can impersonate the identity.
///
/// The fields `ed25519_secret` and `x25519_secret` hold the private halves.
/// They are kept in memory only while the app is running and wiped when the
/// service is destroyed. They are NEVER logged, printed, or sent over the network.
#[derive(Clone, Debug)]
pub struct PreloadedIdentity {
    /// The Ed25519 private signing key seed (32 bytes).
    ///
    /// "Seed" because the actual signing key is derived (expanded) from this
    /// 32-byte seed using a deterministic algorithm. Storing the seed rather
    /// than the expanded key is standard practice — the seed is smaller and
    /// the full key can always be re-derived from it.
    pub ed25519_secret: [u8; 32],

    /// The X25519 private Diffie-Hellman key (32 bytes).
    ///
    /// Used to reconstruct the encrypted-session-negotiation key pair.
    /// Without this, the service cannot read messages that were encrypted
    /// for this identity.
    pub x25519_secret: [u8; 32],

    /// Optional display name that was saved with this identity.
    ///
    /// If the user set a name during onboarding, it is saved alongside the
    /// key material so it is restored on subsequent launches.
    pub name: Option<String>,

    /// The saved local profile fields (visibility preferences, private bio, etc.).
    ///
    /// Restored from disk so the user's settings carry over across restarts.
    pub profile: LocalProfile,
}

// ---------------------------------------------------------------------------
// ServiceConfig
// ---------------------------------------------------------------------------

/// All configuration needed to construct a `MeshInfinityService`.
///
/// Passed to `MeshInfinityService::new(...)`. Think of it like named arguments
/// to a constructor function: it bundles together everything the service needs
/// to know before it can start — what role to play, how the mesh is configured,
/// and (optionally) the identity to restore from disk.
///
/// # Typical usage on first launch
///
/// ```rust,ignore
/// let config = ServiceConfig {
///     initial_mode: NodeMode::Client,
///     mesh_config: MeshConfig::default(),
///     identity_name: Some("Alice".to_string()),
///     preloaded_identity: None, // Generate fresh identity
/// };
/// let service = MeshInfinityService::new(config);
/// ```
///
/// # Typical usage on subsequent launches (restoring saved identity)
///
/// ```rust,ignore
/// let config = ServiceConfig {
///     preloaded_identity: Some(saved_identity_from_disk),
///     ..ServiceConfig::default()
/// };
/// ```
///
/// The `..ServiceConfig::default()` syntax means "fill all other fields with
/// their default values" — a convenient shorthand so you only specify what
/// you want to override.
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    /// Which role this node should play when it starts up.
    ///
    /// `Client` is the safest default for a first-launch app: no background
    /// threads, no relaying, battery-friendly. The user can upgrade to
    /// `Server` or `Dual` in settings later.
    pub initial_mode: NodeMode,

    /// Low-level mesh networking parameters.
    ///
    /// Controls which transports are initially enabled, relay policy, and
    /// discovery settings. These can be overridden at runtime via the Settings
    /// screen, but `ServiceConfig` sets the starting point.
    pub mesh_config: MeshConfig,

    /// Optional display name to assign to a freshly generated identity.
    ///
    /// Only used when `preloaded_identity` is `None` (i.e. first launch).
    /// If `preloaded_identity` is `Some`, the name stored in that struct is
    /// used instead and this field is ignored.
    ///
    /// Setting this to `None` on first launch means the identity starts
    /// with no display name; the user can set one during onboarding.
    pub identity_name: Option<String>,

    /// Pre-loaded identity key material from disk.
    ///
    /// When `Some`, the service restores this identity instead of generating
    /// a fresh one. All key pairs, the display name, and the local profile
    /// are restored from the contained data.
    ///
    /// When `None`, a brand-new cryptographic identity is generated.
    pub preloaded_identity: Option<PreloadedIdentity>,
}

// ---------------------------------------------------------------------------
// HostedServiceSummary
// ---------------------------------------------------------------------------

/// A summary of a service that this node is hosting and exposing to trusted peers.
///
/// Mesh Infinity can act as a secure gateway into a local network service. For
/// example, you might run a small web server on your home network at
/// `10.0.0.10:8443` and want to expose it to trusted peers over Tor, without
/// opening any firewall ports or exposing your home IP address. This struct
/// describes one such "hosted service".
///
/// # How does this work?
///
/// When a trusted remote peer wants to access the hosted service, their request
/// arrives at this node over Tor (or another allowed transport). This node then
/// acts as a proxy: it forwards the request to `address` on the local network
/// and sends the response back. The remote peer never sees `address` — they
/// only see the mesh peer ID and the service path.
///
/// # Access control
///
/// The `min_trust_level` and `allowed_transports` fields control who can access
/// the service and how. For example, you might require `Trusted` peers
/// connecting over `Tor` only, blocking clearnet access even from trusted peers.
#[derive(Clone, Debug)]
pub struct HostedServiceSummary {
    /// Stable unique identifier for this hosted service.
    ///
    /// Chosen by the user when configuring the service (e.g. `"svc-work"`).
    /// Used as the key in the `hosted_services` HashMap inside `ServiceState`.
    pub id: String,

    /// Human-readable name shown in the UI (e.g. `"Work API"`, `"Home NAS"`).
    pub name: String,

    /// The URL path prefix at which this service is accessible on the mesh.
    ///
    /// For example, `"/work"` or `"/nas"`. Remote peers append their request
    /// path to this prefix when accessing the service.
    pub path: String,

    /// The local network address the service is actually running at.
    ///
    /// Format: `"host:port"` (e.g. `"10.0.0.10:8443"`, `"127.0.0.1:3000"`).
    /// This address is only reachable from within the local network; it is
    /// never exposed to remote peers (they only see the mesh path).
    pub address: String,

    /// Whether this hosted service is currently active and accepting connections.
    ///
    /// `false` means the service is configured but not serving requests (paused).
    /// Toggled by the "Enable" switch in the hosted services UI.
    pub enabled: bool,

    /// Minimum trust level a peer must have to access this service.
    ///
    /// Stored as an `i32` for FFI compatibility (see `PeerSummary::trust_level`
    /// for the mapping: 0=Untrusted, 1=Caution, 2=Trusted, 3=HighlyTrusted).
    pub min_trust_level: i32,

    /// Which transport types are permitted to carry requests to this service.
    ///
    /// Stored as strings for FFI compatibility. The UI might display these as
    /// checkboxes (e.g. `["Tor", "I2P"]`). A peer connecting over a transport
    /// not in this list will be denied even if their trust level is sufficient.
    pub allowed_transports: Vec<String>,
}

// ---------------------------------------------------------------------------
// HostedServicePolicy
// ---------------------------------------------------------------------------

/// The access-control policy for a hosted service, using strongly typed values.
///
/// This is the "internal" counterpart to `HostedServiceSummary`. Where that
/// struct uses plain integers and strings for FFI friendliness, this one uses
/// proper Rust enums so the backend can make correct policy decisions without
/// having to parse strings.
///
/// # Why two separate structs for the same concept?
///
/// The Flutter UI communicates via JSON strings. Rust enums like
/// `CoreTrustLevel::Trusted` and `TransportType::Tor` do not survive the
/// serialisation boundary — they become numbers and strings. The summary
/// (with `i32` and `Vec<String>`) is the public, FFI-facing version. The
/// policy (with typed enums) is the internal, backend-facing version that
/// enforcement code uses.
///
/// When the UI calls `configure_hosted_service_with_policy`, it passes a
/// `HostedServicePolicy` and the backend stores BOTH: the typed policy for
/// access-control decisions, and a converted `HostedServiceSummary` for
/// display purposes.
#[derive(Clone, Debug)]
pub struct HostedServicePolicy {
    /// The minimum trust level a connecting peer must have to gain access.
    ///
    /// Uses the typed `CoreTrustLevel` enum (Untrusted / Caution / Trusted /
    /// HighlyTrusted). For example, `CoreTrustLevel::Trusted` means only peers
    /// with trust level 2 or 3 can access the service.
    pub min_trust_level: CoreTrustLevel,

    /// The set of transport types permitted to carry requests to this service.
    ///
    /// For example, `vec![TransportType::Tor, TransportType::I2P]` means only
    /// requests arriving over Tor or I2P are allowed. A request arriving over
    /// clearnet would be rejected even from a fully trusted peer.
    ///
    /// This allows fine-grained control: a highly sensitive service might be
    /// Tor-only, while a less sensitive service might allow Bluetooth too.
    pub allowed_transports: Vec<TransportType>,
}

// ---------------------------------------------------------------------------
// NetworkStatsSummary
// ---------------------------------------------------------------------------

/// A snapshot of network-level counters, shown on the Network screen.
///
/// These numbers help the user understand what the mesh node is doing: how
/// much data has flowed, how many connections are open, and how routing
/// attempts are going. They are updated by the service as traffic flows.
///
/// All fields are plain integers because:
/// 1. They are just counters — there are no enums or strings needed.
/// 2. `#[derive(Copy)]` is therefore possible, meaning the struct can be
///    cheaply duplicated on the stack without any heap allocation.
///    The UI can receive a snapshot value without worrying about the original
///    being modified underneath it.
///
/// # Why use `u64` for byte counts?
///
/// A `u32` (32-bit unsigned integer) can count up to ~4 GB. A busy node could
/// exceed 4 GB of traffic in minutes. `u64` can count up to ~18 exabytes,
/// effectively unlimited for any foreseeable lifetime of the application.
#[derive(Clone, Copy, Debug)]
pub struct NetworkStatsSummary {
    /// Total bytes sent by this node across all transports since startup.
    ///
    /// Incremented each time a message or file chunk is sent. Does NOT reset
    /// between sessions — this is a cumulative counter since the last `new()`.
    pub bytes_sent: u64,

    /// Total bytes received by this node across all transports since startup.
    ///
    /// Incremented each time an incoming message or file chunk is processed.
    pub bytes_received: u64,

    /// Number of transport connections that are currently open and active.
    ///
    /// A "connection" here means one persistent link to another node: one
    /// Tor circuit, one Bluetooth connection, etc. Connections are opened
    /// lazily when needed and closed after a period of inactivity.
    pub active_connections: usize,

    /// Number of outbound messages currently waiting in the routing queue.
    ///
    /// These messages have been submitted to the router but not yet confirmed
    /// delivered to their target. A high number here may indicate that the
    /// target peer is offline or that transports are having trouble.
    pub pending_routes: usize,

    /// Cumulative count of messages that were successfully delivered.
    ///
    /// A message counts as "delivered" when the target peer's transport layer
    /// confirms receipt. Incremented by the routing worker each time a queue
    /// entry is successfully sent.
    pub delivered_routes: u64,

    /// Cumulative count of messages that could not be delivered.
    ///
    /// These messages were either dropped (if all retry attempts failed and
    /// the passive queue is also full) or moved to the passive fallback outbox
    /// for later delivery when the peer comes back online.
    pub failed_routes: u64,
}

// ---------------------------------------------------------------------------
// ReconnectSyncSnapshot
// ---------------------------------------------------------------------------

/// A bundle of data used to bring the UI up to date after a reconnection.
///
/// When a peer comes back online after being offline, there may be messages
/// and file transfers that arrived or changed during their absence. This
/// snapshot is computed by the backend and given to the Flutter UI so it can
/// show everything the user missed, without reloading the entire app state.
///
/// # How is it used?
///
/// 1. The UI tells the backend the ID of the last message it has seen in a
///    room (the "cursor"). This is like a bookmark in the message history.
/// 2. The backend calls `reconnect_sync_snapshot(room_id, cursor)`.
/// 3. The backend returns this struct, which contains:
///    - Any messages that arrived AFTER the cursor (what the user missed).
///    - Any file transfers that are in a resumable state (paused mid-way).
/// 4. The UI displays the new messages and offers to resume the transfers.
///
/// This is more efficient than a full reload: only the "delta" (difference)
/// is sent, not the entire history.
#[derive(Clone, Debug)]
pub struct ReconnectSyncSnapshot {
    /// Messages that arrived after the last known cursor position.
    ///
    /// These are the messages the UI hadn't seen yet when it disconnected.
    /// Ordered chronologically (oldest first). If the cursor is not found in
    /// the room's history, the entire room history is returned as a fallback.
    pub missed_messages: Vec<Message>,

    /// File transfers that are paused mid-way and can be resumed.
    ///
    /// These are transfers in `Queued` or `InProgress` state at the time of
    /// the snapshot. Completed and cancelled transfers are excluded.
    /// The UI offers a "Resume" button for each entry in this list.
    pub resumable_transfers: Vec<FileTransferSummary>,
}

// ---------------------------------------------------------------------------
// Default implementations
// ---------------------------------------------------------------------------
//
// Rust's `Default` trait provides a standard way to construct a "zero/blank"
// value for a type. You invoke it by calling `ServiceConfig::default()` or
// using the struct update syntax `ServiceConfig { field: value, ..ServiceConfig::default() }`.
//
// We implement `Default` manually (instead of `#[derive(Default)]`) here
// because the derived version would give `NodeMode` a default of `Client`
// (the first variant), and `MeshConfig` a default of all-false — which is
// exactly what we want, but we spell it out explicitly to make the choices
// visible and intentional.

impl Default for ServiceConfig {
    /// Provide a safe baseline service configuration for local startup.
    ///
    /// The defaults are chosen to be the safest, most conservative options:
    ///
    /// - `initial_mode: NodeMode::Client`
    ///   Start as a leaf node. No background routing threads, no relaying.
    ///   This is appropriate for a first-run app before the user has configured
    ///   anything. The user can switch to `Server` or `Dual` in Settings.
    ///
    /// - `mesh_config: MeshConfig::default()`
    ///   All transports start DISABLED. No network connections are made until
    ///   the user explicitly enables a transport in Settings. This ensures that
    ///   a brand-new install does not make any network activity without consent.
    ///
    /// - `identity_name: None`
    ///   No display name pre-configured. The onboarding screen will prompt the
    ///   user to choose one.
    ///
    /// - `preloaded_identity: None`
    ///   Generate a fresh identity (appropriate for first launch). On subsequent
    ///   launches, the caller provides the saved key material here.
    fn default() -> Self {
        Self {
            initial_mode: NodeMode::Client,
            mesh_config: MeshConfig::default(),
            identity_name: None,
            preloaded_identity: None,
        }
    }
}

impl Default for HostedServicePolicy {
    /// Provide a secure default hosted-service access policy.
    ///
    /// The defaults here are intentionally conservative — a newly configured
    /// hosted service should be as secure as possible until the operator
    /// explicitly relaxes it:
    ///
    /// - `min_trust_level: CoreTrustLevel::Trusted`
    ///   Require at least "Trusted" before a peer can access the service.
    ///   This blocks strangers (Untrusted) and acquaintances (Caution) by default.
    ///
    /// - `allowed_transports: [Tor, I2P, Bluetooth]`
    ///   Allow only privacy-preserving or local transports. Clearnet is
    ///   deliberately excluded from the default because:
    ///   1. Clearnet exposes the IP address of the device hosting the service.
    ///   2. If an operator really wants clearnet, they should make that choice
    ///      explicitly, not stumble into it by default.
    ///   RF is excluded because it is very low-bandwidth and unusual for
    ///   service hosting.
    fn default() -> Self {
        Self {
            min_trust_level: CoreTrustLevel::Trusted,
            // Default: allow only anonymity-preserving and local transports.
            // Clearnet is excluded to prevent accidental IP exposure.
            allowed_transports: vec![
                TransportType::Tor,
                TransportType::I2P,
                TransportType::Bluetooth,
            ],
        }
    }
}
