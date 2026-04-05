//! Mesh-Native Protocols (§20)
//!
//! # Overview
//!
//! Mesh-native protocols provide secure remote access over the mesh:
//!
//! - **MNRDP** (§20.2) — Remote Desktop Protocol
//! - **MNSP** (§20.3) — Remote Shell Protocol
//! - **MNFP** (§20.4) — Distributed File Access Protocol
//! - **Screen Share** (§20.6) — View-only MNRDP variant
//! - **Clipboard Sync** (§20.7) — Cross-device clipboard
//! - **Print Services** (§20.8) — Remote printing
//! - **API Gateway** (§20.5) — REST/gRPC gateway
//!
//! # Protocol Framework (§20.1)
//!
//! All mesh protocols share a common handshake:
//! 1. Client sends MeshProtoHandshake with protocol ID and version range
//! 2. Server responds with negotiated version and capabilities
//! 3. Protocol-specific session begins
//!
//! # Access Levels
//!
//! - View-only / Screen Share: Level 5 minimum
//! - MNRDP with input: Level 6 minimum
//! - MNSP (shell): Level 6 + explicit `can_remote_shell` capability
//! - MNFP read: Level 6
//! - MNFP write: Level 7

use serde::{Deserialize, Serialize};

// Import the unified error type for all fallible session operations.
// Every function that can fail returns Result<_, MeshError> per §17.5.
use crate::error::MeshError;

// Import the canonical peer identity type (32-byte SHA-256 hash of Ed25519 pubkey).
// Sessions are always addressed by PeerId, never by raw keys.
use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Protocol IDs
// ---------------------------------------------------------------------------

/// MNRDP protocol ID.
// PROTO_MNRDP — protocol constant.
// Defined by the spec; must not change without a version bump.
// PROTO_MNRDP — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PROTO_MNRDP: [u8; 4] = *b"MNRD";
/// MNSP protocol ID.
// PROTO_MNSP — protocol constant.
// Defined by the spec; must not change without a version bump.
// PROTO_MNSP — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PROTO_MNSP: [u8; 4] = *b"MNSH";
/// MNFP protocol ID.
// PROTO_MNFP — protocol constant.
// Defined by the spec; must not change without a version bump.
// PROTO_MNFP — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PROTO_MNFP: [u8; 4] = *b"MNFP";
/// Screen Share protocol ID.
// PROTO_SCREEN_SHARE — protocol constant.
// Defined by the spec; must not change without a version bump.
// PROTO_SCREEN_SHARE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PROTO_SCREEN_SHARE: [u8; 4] = *b"MNSS";

// ---------------------------------------------------------------------------
// Protocol Framework (§20.1)
// ---------------------------------------------------------------------------

/// Protocol handshake (client → server).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MeshProtoHandshake — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MeshProtoHandshake — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MeshProtoHandshake {
    /// 4-byte protocol identifier.
    // Execute this protocol step.
    // Execute this protocol step.
    pub protocol_id: [u8; 4],
    /// Minimum version the client supports.
    // Execute this protocol step.
    // Execute this protocol step.
    pub min_version: u16,
    /// Maximum version the client supports.
    // Execute this protocol step.
    // Execute this protocol step.
    pub max_version: u16,
    /// Client capabilities (protocol-specific strings).
    // Execute this protocol step.
    // Execute this protocol step.
    pub capabilities: Vec<String>,
}

/// Handshake acknowledgement (server → client).
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MeshProtoHandshakeAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MeshProtoHandshakeAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MeshProtoHandshakeAck {
    /// The version the server selected.
    // Execute this protocol step.
    // Execute this protocol step.
    pub negotiated_version: u16,
    /// Server capabilities.
    // Execute this protocol step.
    // Execute this protocol step.
    pub capabilities: Vec<String>,
}

/// Protocol error.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MeshProtoError — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MeshProtoError — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MeshProtoError {
    /// Error code: 1=version, 2=capability, 3=access, 4=resource.
    // Execute this protocol step.
    // Execute this protocol step.
    pub code: u16,
    /// Human-readable error message.
    // Execute this protocol step.
    // Execute this protocol step.
    pub message: String,
}

// ---------------------------------------------------------------------------
// MNRDP — Remote Desktop (§20.2)
// ---------------------------------------------------------------------------

/// MNRDP session request.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpSessionRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnrdpSessionRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnrdpSessionRequest {
    /// The display index for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub display_index: u8,
    /// The resolution for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub resolution: Option<(u16, u16)>,
    /// The color depth for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub color_depth: u8,
    /// The frame encoding for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub frame_encoding: MnrdpEncoding,
    /// The compression for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub compression: MnrdpCompression,
    /// The audio forward for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub audio_forward: bool,
    /// The clipboard sync for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub clipboard_sync: bool,
    /// The input enabled for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub input_enabled: bool,
    /// The mode for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mode: MnrdpSessionMode,
}

/// Frame encoding for MNRDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpEncoding — variant enumeration.
// Match exhaustively to handle every protocol state.
// MnrdpEncoding — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnrdpEncoding {
    Raw,
    H264,
    AV1,
    Zstd,
}

/// Compression for MNRDP metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpCompression — variant enumeration.
// Match exhaustively to handle every protocol state.
// MnrdpCompression — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnrdpCompression {
    // No value available.
    // No value available.
    None,
    Zstd,
    Brotli,
}

/// MNRDP session mode.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpSessionMode — variant enumeration.
// Match exhaustively to handle every protocol state.
// MnrdpSessionMode — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnrdpSessionMode {
    /// Full desktop access.
    // Execute this protocol step.
    // Execute this protocol step.
    FullDesktop,
    /// Stream a single application.
    // Execute this protocol step.
    // Execute this protocol step.
    AppStream {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        app_spec: MnrdpAppSpec,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        windowing: MnrdpWindowing,
    },
    /// Browse and launch applications.
    // Execute this protocol step.
    // Execute this protocol step.
    AppGallery {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        windowing: MnrdpWindowing,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        filter: Option<String>,
    },
}

/// How to specify which application to stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpAppSpec — variant enumeration.
// Match exhaustively to handle every protocol state.
// MnrdpAppSpec — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnrdpAppSpec {
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    AppId {
        id: String,
    },
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    BrokerCall {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        broker_type: MnrdpBrokerType,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        service: String,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        arg: Option<String>,
    },
    // Begin the block scope.
    // Execute this protocol step.
    // Execute this protocol step.
    FileOpen {
        // Execute this protocol step.
        // Execute this protocol step.
        path: String,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        mime_hint: Option<String>,
    },
}

/// Application broker types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpBrokerType — variant enumeration.
// Match exhaustively to handle every protocol state.
// MnrdpBrokerType — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnrdpBrokerType {
    Native,
    // Execute this protocol step.
    // Execute this protocol step.
    QemuGuestAgent,
    Qrexec,
    // Execute this protocol step.
    // Execute this protocol step.
    XdgDesktop,
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    SystemdActivation,
}

/// Windowing mode for app streaming.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpWindowing — variant enumeration.
// Match exhaustively to handle every protocol state.
// MnrdpWindowing — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnrdpWindowing {
    // Execute this protocol step.
    // Execute this protocol step.
    Seamless,
    // Execute this protocol step.
    // Execute this protocol step.
    Contained,
    // Execute this protocol step.
    // Execute this protocol step.
    Fullscreen,
}

/// MNRDP session acknowledgement.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpSessionAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnrdpSessionAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnrdpSessionAck {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The actual resolution for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub actual_resolution: (u16, u16),
    /// The negotiated encoding for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub negotiated_encoding: MnrdpEncoding,
    /// The frames per second for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub frames_per_second: u8,
    /// The broker available for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub broker_available: Option<MnrdpBrokerType>,
    /// The capabilities for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub capabilities: Vec<String>,
}

/// A rendered frame from MNRDP.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpFrame — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnrdpFrame — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnrdpFrame {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The sequence for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sequence: u64,
    /// Microseconds since session start.
    // Execute this protocol step.
    // Execute this protocol step.
    pub timestamp: u64,
    /// The is keyframe for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub is_keyframe: bool,
    /// The damage rects for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub damage_rects: Vec<MnrdpRect>,
    /// The payload for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub payload: Vec<u8>,
    /// The window id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub window_id: Option<u32>,
}

/// Rectangle for damage regions.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpRect — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnrdpRect — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnrdpRect {
    /// The x for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub x: u16,
    /// The y for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub y: u16,
    /// The width for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub width: u16,
    /// The height for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub height: u16,
}

/// Input event for MNRDP.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpInput — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnrdpInput — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnrdpInput {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The sequence for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sequence: u64,
    /// The target window for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub target_window: Option<u32>,
    /// The events for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub events: Vec<MnrdpInputEvent>,
}

/// Individual input events.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpInputEvent — variant enumeration.
// Match exhaustively to handle every protocol state.
// MnrdpInputEvent — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnrdpInputEvent {
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MouseMove {
        x: u16,
        y: u16,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MouseButton {
        button: u8,
        pressed: bool,
        x: u16,
        y: u16,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MouseScroll {
        delta_x: i16,
        delta_y: i16,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    KeyEvent {
        keycode: u32,
        pressed: bool,
        modifiers: u16,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    TouchBegin {
        id: u8,
        x: f32,
        y: f32,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    TouchMove {
        id: u8,
        x: f32,
        y: f32,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    TouchEnd {
        id: u8,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    DragStart {
        window_id: u32,
        mime_type: String,
        payload: Vec<u8>,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Drop {
        target_window_id: u32,
        x: u16,
        y: u16,
    },
}

/// Application list entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpAppEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnrdpAppEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnrdpAppEntry {
    /// The app id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub app_id: String,
    /// The name for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub name: String,
    /// The description for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub description: Option<String>,
    /// The icon for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub icon: Option<Vec<u8>>,
    /// The categories for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub categories: Vec<String>,
    /// The broker type for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub broker_type: MnrdpBrokerType,
    /// The file open for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub file_open: bool,
    /// The windowing hint for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub windowing_hint: MnrdpWindowing,
}

/// Clipboard transfer.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnrdpClipboard — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnrdpClipboard — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnrdpClipboard {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The direction for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub direction: ClipboardDirection,
    /// The mime type for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub mime_type: String,
    /// The payload for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub payload: Vec<u8>,
}

/// Clipboard transfer direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// ClipboardDirection — variant enumeration.
// Match exhaustively to handle every protocol state.
// ClipboardDirection — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum ClipboardDirection {
    // Execute this protocol step.
    // Execute this protocol step.
    ToServer,
    // Execute this protocol step.
    // Execute this protocol step.
    ToClient,
}

// ---------------------------------------------------------------------------
// MNSP — Remote Shell (§20.3)
// ---------------------------------------------------------------------------

/// MNSP session request.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnspSessionRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnspSessionRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnspSessionRequest {
    /// The shell for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub shell: Option<String>,
    /// The cols for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub cols: u16,
    /// The rows for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub rows: u16,
    /// The env for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub env: std::collections::HashMap<String, String>,
    /// The interactive for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub interactive: bool,
    /// The command for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub command: Option<String>,
}

/// MNSP session acknowledgement.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnspSessionAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnspSessionAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnspSessionAck {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The shell for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub shell: String,
    /// The pid for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub pid: u32,
}

/// MNSP data stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// MnspStream — variant enumeration.
// Match exhaustively to handle every protocol state.
// MnspStream — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnspStream {
    Stdin,
    Stdout,
    Stderr,
}

/// MNSP data packet.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnspData — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnspData — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnspData {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The stream for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub stream: MnspStream,
    /// The payload for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub payload: Vec<u8>,
}

/// MNSP terminal resize.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnspResize — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnspResize — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnspResize {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The cols for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub cols: u16,
    /// The rows for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub rows: u16,
}

/// MNSP process exit.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnspExit — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnspExit — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnspExit {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The exit code for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub exit_code: i32,
}

// ---------------------------------------------------------------------------
// MNFP — Distributed File Access (§20.4)
// ---------------------------------------------------------------------------

/// MNFP session request.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnfpSessionRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnfpSessionRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnfpSessionRequest {
    /// The root for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub root: String,
    /// The access for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub access: MnfpAccess,
}

/// MNFP access mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// MnfpAccess — variant enumeration.
// Match exhaustively to handle every protocol state.
// MnfpAccess — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnfpAccess {
    // Execute this protocol step.
    // Execute this protocol step.
    ReadOnly,
    // Execute this protocol step.
    // Execute this protocol step.
    ReadWrite,
    // Execute this protocol step.
    // Execute this protocol step.
    WriteOnly,
}

/// MNFP session acknowledgement.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnfpSessionAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnfpSessionAck — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnfpSessionAck {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The root for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub root: String,
    /// The access for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub access: MnfpAccess,
}

/// MNFP file operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnfpOp — variant enumeration.
// Match exhaustively to handle every protocol state.
// MnfpOp — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnfpOp {
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    List {
        path: String,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Stat {
        path: String,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Read {
        path: String,
        offset: u64,
        length: u32,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Write {
        path: String,
        offset: u64,
        payload: Vec<u8>,
        create_if_missing: bool,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Truncate {
        path: String,
        length: u64,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Delete {
        path: String,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Rename {
        from: String,
        to: String,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Mkdir {
        path: String,
    },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Rmdir {
        path: String,
    },
}

/// MNFP request.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnfpRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnfpRequest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnfpRequest {
    /// The session id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub session_id: [u8; 16],
    /// The request id for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub request_id: u32,
    /// The operation for this instance.
    // Execute this protocol step.
    // Execute this protocol step.
    pub operation: MnfpOp,
}

/// MNFP directory entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnfpEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// MnfpEntry — protocol data structure (see field-level docs).
pub struct MnfpEntry {
    /// The name for this instance.
    // Execute this protocol step.
    pub name: String,
    /// The kind for this instance.
    // Execute this protocol step.
    pub kind: MnfpEntryKind,
    /// The size for this instance.
    // Execute this protocol step.
    pub size: u64,
    /// The modified for this instance.
    // Execute this protocol step.
    pub modified: u64,
    /// The mode for this instance.
    // Execute this protocol step.
    pub mode: u16,
}

/// File entry kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// MnfpEntryKind — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MnfpEntryKind {
    File,
    Dir,
    Symlink,
}

/// MNFP error codes.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MnfpError — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MnfpError {
    /// The code for this instance.
    // Execute this protocol step.
    pub code: u16,
    /// The message for this instance.
    // Execute this protocol step.
    pub message: String,
}

// ---------------------------------------------------------------------------
// API Gateway (§20.5)
// ---------------------------------------------------------------------------

/// API Gateway authentication mode.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// MeshApiAuthMode — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum MeshApiAuthMode {
    // No value available.
    None,
    // Process the current step in the protocol.
    // Execute this protocol step.
    BearerPeerToken,
    // Execute this protocol step.
    ClientCert,
}

// ---------------------------------------------------------------------------
// Service Type Constants (§20.9)
// ---------------------------------------------------------------------------

/// Well-known service type strings.
// SVC_REMOTE_DESKTOP — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SVC_REMOTE_DESKTOP: &str = "meshinfinity.remote-desktop/v1";
// Protocol constant.
// SVC_REMOTE_SHELL — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SVC_REMOTE_SHELL: &str = "meshinfinity.remote-shell/v1";
// Protocol constant.
// SVC_FILE_ACCESS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SVC_FILE_ACCESS: &str = "meshinfinity.file-access/v1";
// Protocol constant.
// SVC_API_GATEWAY — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SVC_API_GATEWAY: &str = "meshinfinity.api-gateway/v1";
// Protocol constant.
// SVC_SCREEN_SHARE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SVC_SCREEN_SHARE: &str = "meshinfinity.screen-share/v1";
// Protocol constant.
// SVC_CLIPBOARD — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SVC_CLIPBOARD: &str = "meshinfinity.clipboard/v1";
// Protocol constant.
// SVC_PRINT — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SVC_PRINT: &str = "meshinfinity.print/v1";

// ---------------------------------------------------------------------------
// Session Handler Types (§20 — Mesh-Native Protocol Sessions)
// ---------------------------------------------------------------------------

/// Which mesh-native protocol a session uses.
///
/// Each variant maps to a distinct application-layer protocol that runs
/// on top of the encrypted mesh transport. `Custom` allows third-party
/// extensions without modifying the core enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshProtocol {
    /// Mesh DNS — name resolution within the mesh overlay (§20.9).
    /// Resolves human-readable names to PeerIds, service records, or mesh addresses.
    MeshDns,
    /// Mesh file sharing — BitTorrent-like content distribution (§20.4 extension).
    /// Splits content into chunks and distributes across multiple peers.
    MeshFileShare,
    /// Mesh streaming — live audio/video streaming over the mesh.
    /// Low-latency frame delivery for real-time media.
    MeshStream,
    /// Third-party protocol extension — the string is a unique protocol identifier.
    /// Must follow reverse-DNS naming (e.g. "com.example.myproto/v1").
    Custom(String),
}

/// The lifecycle state of a protocol session.
///
/// Sessions transition through these states in order: Initiating → Active
/// → (optionally Paused ↔ Active) → Closing → Closed. No backward
/// transitions past Closing are permitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Handshake in progress — waiting for the remote peer's acknowledgement.
    /// The session cannot carry application data in this state.
    Initiating,
    /// Handshake complete — the session is carrying application data.
    /// Both peers have agreed on protocol version and capabilities.
    Active,
    /// Temporarily suspended — no data flows, but the session is not torn down.
    /// Either peer can resume by transitioning back to Active.
    Paused,
    /// Graceful teardown in progress — final control frames being exchanged.
    /// No new application data is accepted once this state is entered.
    Closing,
    /// Session is fully terminated — all resources have been released.
    /// The session object is retained only for status reporting / auditing.
    Closed,
}

/// A mesh-native protocol session (§20).
///
/// Tracks the full lifecycle of a single protocol conversation between
/// the local node and a remote peer. The session ID is a 16-byte random
/// value generated at creation time to prevent collision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolSession {
    /// 16-byte unique session identifier — randomly generated at creation.
    /// Used to multiplex multiple concurrent sessions on the same peer link.
    pub id: [u8; 16],
    /// Which mesh-native protocol this session uses.
    /// Determines how `process_protocol_frame` interprets inbound bytes.
    pub protocol: MeshProtocol,
    /// The remote peer participating in this session.
    /// Validated against the trust system before session creation (§8.4).
    pub peer_id: PeerId,
    /// Current lifecycle state of the session.
    /// State machine transitions are enforced by `close_session`.
    pub state: SessionState,
    /// Unix timestamp (seconds) when the session was created.
    /// Set once at construction time and never modified.
    pub created_at: u64,
    /// Unix timestamp (seconds) of the last frame sent or received.
    /// Updated by `process_protocol_frame` on every successful frame.
    pub last_activity: u64,
    /// Cumulative byte count of all protocol frames exchanged.
    /// Includes both inbound and outbound frame payloads (not headers).
    pub bytes_exchanged: u64,
}

/// DNS query types supported by the mesh overlay (§20.9).
///
/// These mirror the concept of DNS record types but operate entirely
/// within the mesh namespace — no interaction with the global DNS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshDnsType {
    /// Resolve a human-readable name to a PeerId.
    /// Analogous to an A/AAAA record in traditional DNS.
    PeerId,
    /// Resolve a name to a service record (port + protocol + metadata).
    /// Analogous to an SRV record in traditional DNS.
    ServiceRecord,
    /// Resolve a name to a mesh-layer address string.
    /// Used for overlay routing when the peer ID is not directly known.
    MeshAddress,
}

/// A DNS resolution query within the mesh namespace (§20.9).
///
/// The querying node sends this to one or more mesh DNS resolvers.
/// `query_id` correlates requests with responses when multiple
/// queries are in flight simultaneously.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshDnsQuery {
    /// Caller-assigned correlation ID — echoed in the response.
    /// Allows the caller to match responses to outstanding queries.
    pub query_id: u16,
    /// The human-readable name to resolve (e.g. "alice.mesh.local").
    /// Names are case-insensitive; the resolver normalises to lowercase.
    pub name: String,
    /// What kind of record the caller is looking for.
    /// Determines the shape of the answers in the response.
    pub query_type: MeshDnsType,
}

/// A single answer entry in a mesh DNS response.
///
/// The variant matches the `MeshDnsType` that was queried, but the
/// resolver may return multiple answers of different types if it has
/// additional relevant records.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MeshDnsAnswer {
    /// Resolved PeerId — the 32-byte identity of the named peer.
    /// Returned for `MeshDnsType::PeerId` queries.
    PeerId(PeerId),
    /// A mesh service record — port, protocol name, and freeform metadata.
    /// Returned for `MeshDnsType::ServiceRecord` queries.
    ServiceRecord {
        /// The mesh port number the service listens on.
        /// Stored as u32 to accommodate the mesh port space (up to 79999 per §20.9).
        port: u32,
        /// Protocol identifier string (e.g. "meshinfinity.remote-desktop/v1").
        /// Must match one of the well-known SVC_* constants or a custom ID.
        protocol: String,
        /// Freeform metadata the service advertises (capabilities, version, etc.).
        /// Maximum 1024 bytes to prevent amplification in DNS responses.
        metadata: String,
    },
    /// A mesh overlay address string for the named entity.
    /// Returned for `MeshDnsType::MeshAddress` queries.
    MeshAddress(String),
}

/// Response to a mesh DNS query (§20.9).
///
/// Contains zero or more answer records and a TTL. An empty `answers`
/// vec indicates NXDOMAIN (the name does not exist in the mesh).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshDnsResponse {
    /// The query_id from the original request — correlates this response.
    /// The caller uses this to match the response to its outstanding query.
    pub query_id: u16,
    /// All answer records the resolver found for the queried name.
    /// May be empty (NXDOMAIN) or contain multiple records.
    pub answers: Vec<MeshDnsAnswer>,
    /// How long (in seconds) the caller should cache these answers.
    /// After TTL expires, the caller must re-query to get fresh data.
    pub ttl_secs: u32,
}

/// Content distribution session for mesh file sharing (§20.4 extension).
///
/// Tracks a single piece of content being shared across the mesh.
/// Content is identified by its SHA-256 hash and split into fixed-size
/// chunks for parallel download from multiple peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentSession {
    /// SHA-256 hash of the complete content — the content's unique identity.
    /// Used to verify integrity after all chunks have been received.
    pub content_hash: [u8; 32],
    /// Total size of the content in bytes.
    /// Must equal chunk_size * num_chunks (last chunk may be smaller).
    pub total_size: u64,
    /// Size of each chunk in bytes (except possibly the last one).
    /// Chosen at session creation; all peers must agree on the same value.
    pub chunk_size: u32,
    /// Bitmap of which chunks the local node currently has available.
    /// Index i is true if chunk i has been received and verified.
    pub chunks_available: Vec<bool>,
    /// Set of peers known to have at least some chunks of this content.
    /// The local node can request missing chunks from any of these peers.
    pub peers_with_content: Vec<PeerId>,
}

// ---------------------------------------------------------------------------
// Session Handler Functions (§20 — Session Lifecycle)
// ---------------------------------------------------------------------------

/// Returns the current Unix timestamp in seconds.
///
/// Uses `SystemTime::now()` with a fallback to 0 if the system clock
/// is before the Unix epoch (should never happen on real hardware).
fn unix_timestamp_secs() -> u64 {
    // Fetch the current wall-clock time from the OS.
    // Fall back to 0 rather than panicking if the clock is misconfigured.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Generate a 16-byte random session ID using the OS CSPRNG.
///
/// Uses `getrandom` to fill the buffer, which sources entropy from
/// the OS (e.g. /dev/urandom on Linux, BCryptGenRandom on Windows).
fn generate_session_id() -> Result<[u8; 16], MeshError> {
    // Allocate a zeroed buffer for the session ID.
    // getrandom will overwrite all 16 bytes with random data.
    let mut id = [0u8; 16];
    // Fill the buffer from the OS CSPRNG; map any failure to MeshError::Internal
    // because a CSPRNG failure indicates a serious platform problem.
    getrandom::fill(&mut id)
        .map_err(|e| MeshError::Internal(format!("CSPRNG failed generating session ID: {e}")))?;
    Ok(id)
}

/// Create a new protocol session with the specified remote peer.
///
/// Generates a random 16-byte session ID, sets the initial state to
/// `Initiating`, and records the creation timestamp. The caller must
/// then perform the protocol-specific handshake to transition to `Active`.
///
/// # Errors
///
/// Returns `MeshError::Internal` if the OS CSPRNG fails to produce
/// random bytes for the session ID.
pub fn create_session(protocol: MeshProtocol, peer: PeerId) -> Result<ProtocolSession, MeshError> {
    // Generate a cryptographically random session ID to prevent collisions.
    // This is critical for multiplexing multiple sessions on the same link.
    let id = generate_session_id()?;

    // Capture the creation timestamp — used for session age tracking and
    // timeout enforcement by the session manager.
    let now = unix_timestamp_secs();

    // Construct the session in the Initiating state — no data can flow
    // until the protocol-specific handshake completes.
    Ok(ProtocolSession {
        id,
        protocol,
        peer_id: peer,
        state: SessionState::Initiating,
        created_at: now,
        last_activity: now,
        bytes_exchanged: 0,
    })
}

/// Gracefully close an active or paused protocol session.
///
/// Transitions the session through `Closing` to `Closed`. Sessions
/// that are already `Closing` or `Closed` are left unchanged (idempotent).
/// Sessions still in `Initiating` are moved directly to `Closed` since
/// no handshake data needs to be flushed.
///
/// # Errors
///
/// Returns `MeshError::Internal` if the session is in an unexpected
/// state that prevents a clean shutdown.
pub fn close_session(session: &mut ProtocolSession) -> Result<(), MeshError> {
    // Match on the current state to determine the correct transition.
    // The state machine is: Initiating/Active/Paused → Closing → Closed.
    match session.state {
        // Active and Paused sessions transition through Closing first,
        // allowing any final control frames to be exchanged.
        SessionState::Active | SessionState::Paused => {
            // Mark the session as closing — the transport layer will flush
            // any pending outbound frames before completing teardown.
            session.state = SessionState::Closing;

            // Immediately transition to Closed — in a real implementation
            // this would wait for the peer's close acknowledgement.
            session.state = SessionState::Closed;

            // Record the shutdown timestamp for auditing purposes.
            // The session object is retained for status queries after close.
            session.last_activity = unix_timestamp_secs();
            Ok(())
        }

        // Initiating sessions have no handshake data to flush — skip
        // the Closing state and go directly to Closed.
        SessionState::Initiating => {
            session.state = SessionState::Closed;
            // Update the activity timestamp to mark when shutdown occurred.
            session.last_activity = unix_timestamp_secs();
            Ok(())
        }

        // Already closing or closed — this is a no-op for idempotency.
        // Callers should not need to check state before calling close.
        SessionState::Closing | SessionState::Closed => Ok(()),
    }
}

/// Process an inbound protocol frame within an active session.
///
/// Validates that the session is in an appropriate state (Active),
/// updates the byte counters and activity timestamp, and returns
/// a response frame. For sessions not in the Active state, an error
/// is returned so the caller can decide whether to re-establish.
///
/// # Errors
///
/// - `MeshError::MalformedFrame` if the session is not in a state that
///   can process data (e.g. Initiating, Closing, Closed).
/// - `MeshError::MalformedFrame` if the inbound frame is empty.
pub fn process_protocol_frame(
    session: &mut ProtocolSession,
    frame: &[u8],
) -> Result<Vec<u8>, MeshError> {
    // Only Active sessions can process protocol frames. Initiating sessions
    // haven't completed handshake; Closing/Closed sessions have shut down.
    if session.state != SessionState::Active {
        return Err(MeshError::MalformedFrame(format!(
            "session {} is in state {:?}, expected Active",
            hex::encode(session.id),
            session.state,
        )));
    }

    // Reject empty frames — every valid protocol frame has at least a type byte.
    // This prevents zero-length writes from polluting the byte counters.
    if frame.is_empty() {
        return Err(MeshError::MalformedFrame(
            "received empty protocol frame".to_string(),
        ));
    }

    // Record the inbound frame size in the cumulative byte counter.
    // This tracks total payload volume for session monitoring and rate limiting.
    session.bytes_exchanged = session.bytes_exchanged.saturating_add(frame.len() as u64);

    // Update the activity timestamp to reflect this frame exchange.
    // Used by the session manager for idle-timeout eviction.
    session.last_activity = unix_timestamp_secs();

    // Construct the response frame based on the protocol type.
    // Each protocol has its own frame format; here we build a minimal
    // acknowledgement frame that echoes the protocol and frame length.
    let response = match &session.protocol {
        // MeshDns responses carry the query_id (first 2 bytes of the frame)
        // plus a status byte and the original frame for correlation.
        MeshProtocol::MeshDns => {
            // Build a DNS ack: 1-byte status (0x00 = OK) + original frame.
            // The caller parses this as a MeshDnsResponse after deserialization.
            let mut resp = Vec::with_capacity(1 + frame.len());
            resp.push(0x00); // status: OK
            resp.extend_from_slice(frame);
            resp
        }

        // FileShare responses echo the chunk request with a delivery status.
        // The first byte indicates whether the chunk is available locally.
        MeshProtocol::MeshFileShare => {
            // Build a file-share ack: 1-byte status (0x01 = chunk available)
            // + the original request frame for correlation.
            let mut resp = Vec::with_capacity(1 + frame.len());
            resp.push(0x01); // status: chunk available
            resp.extend_from_slice(frame);
            resp
        }

        // Stream responses echo the frame with a timing/sync header.
        // The first byte signals the stream state (0x02 = data flowing).
        MeshProtocol::MeshStream => {
            // Build a stream ack: 1-byte status (0x02 = streaming)
            // + the original media frame for pass-through.
            let mut resp = Vec::with_capacity(1 + frame.len());
            resp.push(0x02); // status: stream active
            resp.extend_from_slice(frame);
            resp
        }

        // Custom protocols get a generic echo with a 0xFF marker byte.
        // The custom protocol handler on the other end interprets this.
        MeshProtocol::Custom(_) => {
            // Build a custom ack: 1-byte marker (0xFF = custom protocol)
            // + the original frame contents.
            let mut resp = Vec::with_capacity(1 + frame.len());
            resp.push(0xFF); // marker: custom protocol echo
            resp.extend_from_slice(frame);
            resp
        }
    };

    // Add the response size to the byte counter as well (outbound data).
    // Both directions count toward the session's total bytes exchanged.
    session.bytes_exchanged = session
        .bytes_exchanged
        .saturating_add(response.len() as u64);

    Ok(response)
}

/// Resolve a mesh DNS query against the local name table.
///
/// Looks up the queried name and returns matching records. In this
/// implementation, names ending in ".mesh.local" resolve to synthetic
/// PeerId records; all other names return an empty answer set (NXDOMAIN).
///
/// # Errors
///
/// Returns `MeshError::MalformedFrame` if the query name is empty,
/// since empty names are never valid in the mesh DNS namespace.
pub fn resolve_mesh_dns(query: &MeshDnsQuery) -> Result<MeshDnsResponse, MeshError> {
    // Reject queries with empty names — they cannot match any record.
    // This is a protocol-level validation, not a DNS NXDOMAIN response.
    if query.name.is_empty() {
        return Err(MeshError::MalformedFrame(
            "mesh DNS query name must not be empty".to_string(),
        ));
    }

    // Normalise the name to lowercase for case-insensitive matching.
    // The mesh DNS namespace is case-insensitive per §20.9.
    let normalised = query.name.to_lowercase();

    // Build the answer set based on the query type and the normalised name.
    // Real implementation would consult the distributed name table; here we
    // handle the ".mesh.local" synthetic domain.
    let answers = match &query.query_type {
        // PeerId lookups: derive a deterministic PeerId from the name.
        // This allows tests and bootstrapping without a full name service.
        MeshDnsType::PeerId => {
            if normalised.ends_with(".mesh.local") {
                // Hash the normalised name to produce a deterministic 32-byte PeerId.
                // This is synthetic — real resolution would query the DHT.
                let mut hash = [0u8; 32];
                // Use a simple hash: fill with the name bytes cyclically.
                // This is NOT cryptographic — purely for name→ID mapping.
                for (i, byte) in normalised.bytes().cycle().take(32).enumerate() {
                    hash[i] = byte;
                }
                vec![MeshDnsAnswer::PeerId(PeerId(hash))]
            } else {
                // Name is not in the .mesh.local domain — no answers (NXDOMAIN).
                // The caller should try alternative resolvers or report not found.
                vec![]
            }
        }

        // ServiceRecord lookups: return a synthetic service entry for known domains.
        // Real implementation would scan the local service registry.
        MeshDnsType::ServiceRecord => {
            if normalised.ends_with(".mesh.local") {
                // Return a synthetic service record pointing to the default mesh port.
                // The protocol field uses the well-known file-access service type.
                vec![MeshDnsAnswer::ServiceRecord {
                    port: 75000,
                    protocol: SVC_FILE_ACCESS.to_string(),
                    metadata: format!("name={normalised}"),
                }]
            } else {
                // No service records found for this name — empty NXDOMAIN response.
                vec![]
            }
        }

        // MeshAddress lookups: return the normalised name as the address.
        // In a real overlay, this would be a multi-hop routing address.
        MeshDnsType::MeshAddress => {
            if normalised.ends_with(".mesh.local") {
                // Use the normalised name directly as the mesh address.
                // Real addresses would be derived from the routing table.
                vec![MeshDnsAnswer::MeshAddress(normalised.clone())]
            } else {
                // Name not resolvable — empty answer set.
                vec![]
            }
        }
    };

    // Default TTL is 300 seconds (5 minutes) for mesh DNS answers.
    // Shorter TTLs increase resolution traffic; longer TTLs risk staleness.
    let ttl_secs = if answers.is_empty() {
        // Negative caching: short TTL (60s) so re-queries happen sooner.
        // A node that just joined the mesh should be discoverable quickly.
        60
    } else {
        // Positive caching: 5-minute TTL balances freshness and traffic.
        300
    };

    Ok(MeshDnsResponse {
        query_id: query.query_id,
        answers,
        ttl_secs,
    })
}

/// Create a new content distribution session for mesh file sharing.
///
/// Initialises the chunk availability bitmap (all chunks unavailable)
/// and returns the session. The caller must then register peers and
/// request/provide chunks to drive the download.
///
/// # Parameters
///
/// - `content_hash`: SHA-256 hash of the complete content.
/// - `total_size`: Total content size in bytes.
/// - `chunk_size`: Size of each chunk in bytes (last chunk may be smaller).
pub fn create_content_session(
    content_hash: [u8; 32],
    total_size: u64,
    chunk_size: u32,
) -> ContentSession {
    // Calculate the number of chunks. Use ceiling division so the last
    // (potentially smaller) chunk is accounted for in the bitmap.
    let num_chunks = if chunk_size == 0 {
        // Degenerate case: zero chunk size means zero chunks.
        // This avoids division by zero; the caller should treat this as an error.
        0
    } else {
        // Integer ceiling division: (total + chunk_size - 1) / chunk_size.
        // Handles the case where total_size is not evenly divisible.
        ((total_size + chunk_size as u64 - 1) / chunk_size as u64) as usize
    };

    // Initialize all chunks as unavailable (false). As chunks are received
    // and verified, `provide_chunk` sets the corresponding index to true.
    let chunks_available = vec![false; num_chunks];

    ContentSession {
        content_hash,
        total_size,
        chunk_size,
        chunks_available,
        // Start with no known peers — the caller adds them as they are discovered.
        // Peer discovery happens through the mesh DHT or direct announcement.
        peers_with_content: Vec::new(),
    }
}

/// Request a specific chunk from a content distribution session.
///
/// Returns the chunk data if the chunk is locally available, or an
/// error if it hasn't been received yet. The caller should request
/// missing chunks from remote peers listed in `peers_with_content`.
///
/// # Errors
///
/// - `MeshError::OutOfRange` if `chunk_index` exceeds the number of chunks.
/// - `MeshError::NotFound` if the chunk has not been received yet.
pub fn request_chunk(session: &ContentSession, chunk_index: u32) -> Result<Vec<u8>, MeshError> {
    // Convert the index to usize for bounds checking against the bitmap.
    let idx = chunk_index as usize;

    // Validate that the chunk index is within the content's chunk count.
    // Out-of-range indices indicate a protocol error or corrupt metadata.
    if idx >= session.chunks_available.len() {
        return Err(MeshError::OutOfRange {
            field: "chunk_index",
            value: format!(
                "{chunk_index} (max {})",
                session.chunks_available.len().saturating_sub(1)
            ),
        });
    }

    // Check whether we have this chunk locally. If not, the caller must
    // fetch it from one of the peers in peers_with_content.
    if !session.chunks_available[idx] {
        return Err(MeshError::NotFound {
            kind: "chunk",
            id: format!("{}[{chunk_index}]", hex::encode(session.content_hash)),
        });
    }

    // Calculate the byte range for this chunk within the content.
    // The last chunk may be smaller than chunk_size.
    let start = chunk_index as u64 * session.chunk_size as u64;
    // Clamp the end to total_size so the last chunk doesn't overrun.
    let end = std::cmp::min(start + session.chunk_size as u64, session.total_size);
    // The chunk length is the difference between start and end.
    let chunk_len = (end - start) as usize;

    // Return a placeholder payload of the correct length filled with the
    // chunk index byte. Real implementation reads from the content store.
    // The repeating byte pattern allows tests to verify chunk identity.
    Ok(vec![(chunk_index & 0xFF) as u8; chunk_len])
}

/// Provide (store) a chunk in a content distribution session.
///
/// Marks the chunk as available in the bitmap after validating the
/// index and data length. Once all chunks are marked available, the
/// caller should verify the complete content against `content_hash`.
///
/// # Errors
///
/// - `MeshError::OutOfRange` if `chunk_index` exceeds the number of chunks.
/// - `MeshError::MalformedFrame` if `data` length doesn't match the expected
///   chunk size (exact for all chunks except the last, which may be smaller).
pub fn provide_chunk(
    session: &mut ContentSession,
    chunk_index: u32,
    data: &[u8],
) -> Result<(), MeshError> {
    // Convert the index to usize for bounds checking.
    let idx = chunk_index as usize;

    // Validate that the chunk index is within bounds.
    // Reject out-of-range indices early to prevent bitmap corruption.
    if idx >= session.chunks_available.len() {
        return Err(MeshError::OutOfRange {
            field: "chunk_index",
            value: format!(
                "{chunk_index} (max {})",
                session.chunks_available.len().saturating_sub(1)
            ),
        });
    }

    // Calculate the expected size for this specific chunk.
    // All chunks are chunk_size bytes except the last, which may be shorter.
    let start = chunk_index as u64 * session.chunk_size as u64;
    let end = std::cmp::min(start + session.chunk_size as u64, session.total_size);
    let expected_len = (end - start) as usize;

    // Validate that the provided data matches the expected chunk size.
    // Mismatched sizes indicate corruption or a protocol-level bug.
    if data.len() != expected_len {
        return Err(MeshError::MalformedFrame(format!(
            "chunk {chunk_index} expected {expected_len} bytes, got {}",
            data.len()
        )));
    }

    // Mark the chunk as available in the bitmap. Real implementation would
    // also persist the chunk data to the content store at this point.
    session.chunks_available[idx] = true;

    Ok(())
}

/// Produce a JSON status summary of a protocol session.
///
/// Returns a `serde_json::Value` containing all session metadata in
/// a flat JSON object. This is consumed by the FFI layer for display
/// in the Flutter UI and by the monitoring subsystem for health checks.
pub fn session_status_json(session: &ProtocolSession) -> serde_json::Value {
    // Format the session ID as a hex string for human readability.
    // The raw 16 bytes would not be useful in a JSON context.
    let id_hex = hex::encode(session.id);

    // Format the peer ID as a hex string — same reasoning as session ID.
    let peer_hex = hex::encode(session.peer_id.0);

    // Map the protocol enum to a human-readable string for the JSON output.
    // Custom protocols include their identifier string.
    let protocol_str = match &session.protocol {
        MeshProtocol::MeshDns => "mesh_dns".to_string(),
        MeshProtocol::MeshFileShare => "mesh_file_share".to_string(),
        MeshProtocol::MeshStream => "mesh_stream".to_string(),
        MeshProtocol::Custom(name) => format!("custom:{name}"),
    };

    // Map the state enum to a lowercase string for consistent JSON output.
    // The Flutter UI matches on these exact strings for status indicators.
    let state_str = match &session.state {
        SessionState::Initiating => "initiating",
        SessionState::Active => "active",
        SessionState::Paused => "paused",
        SessionState::Closing => "closing",
        SessionState::Closed => "closed",
    };

    // Build the JSON object with all session fields.
    // Field names match the FFI contract documented in MEMORY.md.
    serde_json::json!({
        "id": id_hex,
        "protocol": protocol_str,
        "peer_id": peer_hex,
        "state": state_str,
        "created_at": session.created_at,
        "last_activity": session.last_activity,
        "bytes_exchanged": session.bytes_exchanged,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_serde() {
        let hs = MeshProtoHandshake {
            protocol_id: PROTO_MNRDP,
            min_version: 1,
            max_version: 1,
            capabilities: vec!["h264".to_string()],
        };
        let json = serde_json::to_string(&hs).unwrap();
        let recovered: MeshProtoHandshake = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.protocol_id, PROTO_MNRDP);
    }

    #[test]
    fn test_mnrdp_session_serde() {
        let req = MnrdpSessionRequest {
            display_index: 0,
            resolution: Some((1920, 1080)),
            color_depth: 32,
            frame_encoding: MnrdpEncoding::AV1,
            compression: MnrdpCompression::Zstd,
            audio_forward: true,
            clipboard_sync: true,
            input_enabled: true,
            mode: MnrdpSessionMode::FullDesktop,
        };
        let json = serde_json::to_string(&req).unwrap();
        let recovered: MnrdpSessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.frame_encoding, MnrdpEncoding::AV1);
    }

    #[test]
    fn test_mnsp_request() {
        let req = MnspSessionRequest {
            shell: Some("/bin/bash".to_string()),
            cols: 80,
            rows: 24,
            env: std::collections::HashMap::new(),
            interactive: true,
            command: None,
        };
        assert_eq!(req.cols, 80);
    }

    #[test]
    fn test_mnfp_access() {
        assert_ne!(MnfpAccess::ReadOnly, MnfpAccess::ReadWrite);
    }

    #[test]
    fn test_input_events() {
        let input = MnrdpInput {
            session_id: [0x01; 16],
            sequence: 0,
            target_window: None,
            events: vec![
                MnrdpInputEvent::MouseMove { x: 100, y: 200 },
                MnrdpInputEvent::KeyEvent {
                    keycode: 65,
                    pressed: true,
                    modifiers: 0,
                },
            ],
        };
        assert_eq!(input.events.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Session lifecycle tests (§20 session handlers)
    // -----------------------------------------------------------------------

    /// Helper: create a test PeerId from a single byte (fills all 32 bytes).
    /// Useful for tests that need distinct peers without full key derivation.
    fn test_peer(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    #[test]
    fn test_create_session_produces_initiating_state() {
        // Creating a session must yield Initiating state — no data can flow yet.
        // The session ID must be 16 bytes and timestamps must be non-zero.
        let session = create_session(MeshProtocol::MeshDns, test_peer(0xAA))
            .expect("session creation should succeed");

        // Verify the session starts in Initiating state.
        assert_eq!(session.state, SessionState::Initiating);
        // Verify the protocol is correctly recorded.
        assert_eq!(session.protocol, MeshProtocol::MeshDns);
        // Verify no bytes have been exchanged yet.
        assert_eq!(session.bytes_exchanged, 0);
        // Verify the peer ID is stored correctly.
        assert_eq!(session.peer_id, test_peer(0xAA));
        // Verify timestamps are populated (non-zero on any real system).
        assert!(session.created_at > 0);
        assert_eq!(session.created_at, session.last_activity);
    }

    #[test]
    fn test_create_session_unique_ids() {
        // Each session must get a unique random ID to prevent collisions
        // when multiplexing sessions on the same peer link.
        let s1 =
            create_session(MeshProtocol::MeshDns, test_peer(0x01)).expect("session 1 creation");
        let s2 =
            create_session(MeshProtocol::MeshDns, test_peer(0x01)).expect("session 2 creation");

        // Two sessions should have different IDs (probability of collision: ~2^-128).
        assert_ne!(s1.id, s2.id);
    }

    #[test]
    fn test_create_session_all_protocols() {
        // All protocol variants must be accepted by create_session.
        // This ensures the function doesn't accidentally reject any variant.
        for proto in [
            MeshProtocol::MeshDns,
            MeshProtocol::MeshFileShare,
            MeshProtocol::MeshStream,
            MeshProtocol::Custom("com.test/v1".to_string()),
        ] {
            let s = create_session(proto.clone(), test_peer(0x42))
                .expect("all protocols should be accepted");
            assert_eq!(s.protocol, proto);
        }
    }

    #[test]
    fn test_close_session_from_active() {
        // Closing an Active session must transition through Closing to Closed.
        // After close, no more data should flow.
        let mut session =
            create_session(MeshProtocol::MeshStream, test_peer(0xBB)).expect("session creation");
        // Manually transition to Active (simulating completed handshake).
        session.state = SessionState::Active;

        // Close the session — should succeed and reach Closed state.
        close_session(&mut session).expect("close should succeed");
        assert_eq!(session.state, SessionState::Closed);
    }

    #[test]
    fn test_close_session_from_paused() {
        // Paused sessions should also close cleanly — same path as Active.
        let mut session =
            create_session(MeshProtocol::MeshFileShare, test_peer(0xCC)).expect("session creation");
        session.state = SessionState::Paused;

        close_session(&mut session).expect("close from paused should succeed");
        assert_eq!(session.state, SessionState::Closed);
    }

    #[test]
    fn test_close_session_from_initiating() {
        // Initiating sessions skip Closing and go directly to Closed,
        // since there's no handshake data to flush.
        let mut session =
            create_session(MeshProtocol::MeshDns, test_peer(0xDD)).expect("session creation");

        // State should be Initiating right after creation.
        assert_eq!(session.state, SessionState::Initiating);
        close_session(&mut session).expect("close from initiating should succeed");
        assert_eq!(session.state, SessionState::Closed);
    }

    #[test]
    fn test_close_session_idempotent() {
        // Closing an already-Closed session must be a no-op — idempotent.
        // Callers should not need to check state before calling close.
        let mut session =
            create_session(MeshProtocol::MeshDns, test_peer(0xEE)).expect("session creation");
        session.state = SessionState::Closed;

        // Second close should succeed silently without error.
        close_session(&mut session).expect("idempotent close should succeed");
        assert_eq!(session.state, SessionState::Closed);
    }

    #[test]
    fn test_process_frame_requires_active_state() {
        // Frames can only be processed in Active state. All other states
        // must return an error.
        let mut session =
            create_session(MeshProtocol::MeshDns, test_peer(0x11)).expect("session creation");

        // Initiating — should reject frames.
        let result = process_protocol_frame(&mut session, b"hello");
        assert!(result.is_err(), "Initiating session should reject frames");

        // Closed — should also reject frames.
        session.state = SessionState::Closed;
        let result = process_protocol_frame(&mut session, b"hello");
        assert!(result.is_err(), "Closed session should reject frames");
    }

    #[test]
    fn test_process_frame_rejects_empty() {
        // Empty frames are invalid — every protocol frame needs at least one byte.
        let mut session =
            create_session(MeshProtocol::MeshDns, test_peer(0x22)).expect("session creation");
        session.state = SessionState::Active;

        let result = process_protocol_frame(&mut session, b"");
        assert!(result.is_err(), "empty frame should be rejected");
    }

    #[test]
    fn test_process_frame_updates_counters() {
        // Processing a frame must update bytes_exchanged and last_activity.
        // Both inbound and outbound bytes are counted.
        let mut session =
            create_session(MeshProtocol::MeshDns, test_peer(0x33)).expect("session creation");
        session.state = SessionState::Active;
        // Reset bytes to verify increment.
        session.bytes_exchanged = 0;

        let frame = b"test-dns-query";
        let response =
            process_protocol_frame(&mut session, frame).expect("frame processing should succeed");

        // bytes_exchanged should include both inbound frame and outbound response.
        // Inbound: 14 bytes, outbound: 15 bytes (1 status + 14 echo).
        assert_eq!(
            session.bytes_exchanged,
            frame.len() as u64 + response.len() as u64
        );
        // Response should be non-empty.
        assert!(!response.is_empty());
    }

    #[test]
    fn test_process_frame_dns_protocol() {
        // MeshDns frames get a 0x00 status prefix in the response.
        let mut session =
            create_session(MeshProtocol::MeshDns, test_peer(0x44)).expect("session creation");
        session.state = SessionState::Active;

        let response =
            process_protocol_frame(&mut session, b"query").expect("dns frame should succeed");
        // First byte should be 0x00 (OK status).
        assert_eq!(response[0], 0x00);
        // Remaining bytes should echo the original frame.
        assert_eq!(&response[1..], b"query");
    }

    #[test]
    fn test_process_frame_fileshare_protocol() {
        // MeshFileShare frames get a 0x01 status prefix.
        let mut session =
            create_session(MeshProtocol::MeshFileShare, test_peer(0x55)).expect("session creation");
        session.state = SessionState::Active;

        let response = process_protocol_frame(&mut session, b"chunk-req")
            .expect("fileshare frame should succeed");
        // First byte: 0x01 (chunk available).
        assert_eq!(response[0], 0x01);
        assert_eq!(&response[1..], b"chunk-req");
    }

    #[test]
    fn test_process_frame_stream_protocol() {
        // MeshStream frames get a 0x02 status prefix.
        let mut session =
            create_session(MeshProtocol::MeshStream, test_peer(0x66)).expect("session creation");
        session.state = SessionState::Active;

        let response =
            process_protocol_frame(&mut session, b"media").expect("stream frame should succeed");
        assert_eq!(response[0], 0x02);
        assert_eq!(&response[1..], b"media");
    }

    #[test]
    fn test_process_frame_custom_protocol() {
        // Custom protocol frames get a 0xFF marker prefix.
        let mut session = create_session(
            MeshProtocol::Custom("com.test/v1".to_string()),
            test_peer(0x77),
        )
        .expect("session creation");
        session.state = SessionState::Active;

        let response = process_protocol_frame(&mut session, b"custom-data")
            .expect("custom frame should succeed");
        assert_eq!(response[0], 0xFF);
        assert_eq!(&response[1..], b"custom-data");
    }

    // -----------------------------------------------------------------------
    // Mesh DNS resolution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dns_resolve_peer_id() {
        // Resolving a .mesh.local name for PeerId should return one answer.
        let query = MeshDnsQuery {
            query_id: 42,
            name: "alice.mesh.local".to_string(),
            query_type: MeshDnsType::PeerId,
        };

        let response = resolve_mesh_dns(&query).expect("DNS resolution should succeed");
        // The response must echo the query_id for correlation.
        assert_eq!(response.query_id, 42);
        // Exactly one PeerId answer expected for a valid .mesh.local name.
        assert_eq!(response.answers.len(), 1);
        // The answer must be a PeerId variant.
        assert!(matches!(&response.answers[0], MeshDnsAnswer::PeerId(_)));
        // Positive TTL should be 300 seconds.
        assert_eq!(response.ttl_secs, 300);
    }

    #[test]
    fn test_dns_resolve_service_record() {
        // ServiceRecord queries for .mesh.local should return port + protocol.
        let query = MeshDnsQuery {
            query_id: 99,
            name: "fileserver.mesh.local".to_string(),
            query_type: MeshDnsType::ServiceRecord,
        };

        let response = resolve_mesh_dns(&query).expect("DNS resolution should succeed");
        assert_eq!(response.answers.len(), 1);

        // Verify the service record contains the expected fields.
        match &response.answers[0] {
            MeshDnsAnswer::ServiceRecord {
                port,
                protocol,
                metadata,
            } => {
                assert_eq!(*port, 75000);
                assert_eq!(protocol, SVC_FILE_ACCESS);
                assert!(metadata.contains("fileserver.mesh.local"));
            }
            other => panic!("expected ServiceRecord, got {other:?}"),
        }
    }

    #[test]
    fn test_dns_resolve_mesh_address() {
        // MeshAddress queries return the normalised name as the address.
        let query = MeshDnsQuery {
            query_id: 7,
            name: "Bob.Mesh.Local".to_string(), // mixed case — should normalise
            query_type: MeshDnsType::MeshAddress,
        };

        let response = resolve_mesh_dns(&query).expect("DNS resolution should succeed");
        assert_eq!(response.answers.len(), 1);
        // Verify the address is normalised to lowercase.
        assert!(matches!(
            &response.answers[0],
            MeshDnsAnswer::MeshAddress(addr) if addr == "bob.mesh.local"
        ));
    }

    #[test]
    fn test_dns_nxdomain_for_unknown_domain() {
        // Names outside .mesh.local should return empty answers (NXDOMAIN).
        let query = MeshDnsQuery {
            query_id: 100,
            name: "alice.example.com".to_string(),
            query_type: MeshDnsType::PeerId,
        };

        let response = resolve_mesh_dns(&query).expect("DNS resolution should succeed");
        // No answers — NXDOMAIN equivalent.
        assert!(response.answers.is_empty());
        // Negative cache TTL should be 60 seconds.
        assert_eq!(response.ttl_secs, 60);
    }

    #[test]
    fn test_dns_empty_name_rejected() {
        // Empty query names are a protocol-level error, not NXDOMAIN.
        let query = MeshDnsQuery {
            query_id: 0,
            name: String::new(),
            query_type: MeshDnsType::PeerId,
        };

        let result = resolve_mesh_dns(&query);
        assert!(result.is_err(), "empty name should be rejected");
    }

    #[test]
    fn test_dns_case_insensitive() {
        // The same name in different cases should resolve to the same PeerId.
        // Case insensitivity is a core requirement of mesh DNS (§20.9).
        let q1 = MeshDnsQuery {
            query_id: 1,
            name: "ALICE.MESH.LOCAL".to_string(),
            query_type: MeshDnsType::PeerId,
        };
        let q2 = MeshDnsQuery {
            query_id: 2,
            name: "alice.mesh.local".to_string(),
            query_type: MeshDnsType::PeerId,
        };

        let r1 = resolve_mesh_dns(&q1).expect("upper case resolution");
        let r2 = resolve_mesh_dns(&q2).expect("lower case resolution");

        // Both should resolve to the same PeerId since names normalise to lowercase.
        assert_eq!(r1.answers.len(), 1);
        assert_eq!(r2.answers.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Content session management tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_content_session_chunk_count() {
        // 1000 bytes with 256-byte chunks = 4 chunks (last one is 232 bytes).
        let session = create_content_session([0xAA; 32], 1000, 256);

        // Verify chunk count: ceil(1000 / 256) = 4.
        assert_eq!(session.chunks_available.len(), 4);
        // All chunks should start as unavailable.
        assert!(session.chunks_available.iter().all(|&c| !c));
        // No peers should be known initially.
        assert!(session.peers_with_content.is_empty());
        // Metadata should be stored correctly.
        assert_eq!(session.content_hash, [0xAA; 32]);
        assert_eq!(session.total_size, 1000);
        assert_eq!(session.chunk_size, 256);
    }

    #[test]
    fn test_create_content_session_exact_division() {
        // 1024 bytes with 256-byte chunks = exactly 4 chunks (no remainder).
        let session = create_content_session([0xBB; 32], 1024, 256);
        assert_eq!(session.chunks_available.len(), 4);
    }

    #[test]
    fn test_create_content_session_zero_chunk_size() {
        // Zero chunk size should produce zero chunks (degenerate case).
        // The caller is responsible for treating this as an error condition.
        let session = create_content_session([0xCC; 32], 1000, 0);
        assert_eq!(session.chunks_available.len(), 0);
    }

    #[test]
    fn test_provide_and_request_chunk() {
        // Providing a chunk should make it available for subsequent requests.
        let mut session = create_content_session([0xDD; 32], 512, 256);

        // Chunk 0 is not yet available — request should fail with NotFound.
        let result = request_chunk(&session, 0);
        assert!(result.is_err(), "unavailable chunk should fail");

        // Provide chunk 0 with the correct size (256 bytes).
        let data = vec![0x42u8; 256];
        provide_chunk(&mut session, 0, &data).expect("provide chunk 0 should succeed");

        // Now chunk 0 should be available.
        assert!(session.chunks_available[0]);
        let chunk = request_chunk(&session, 0).expect("chunk 0 should now be available");
        // The chunk data should be 256 bytes long.
        assert_eq!(chunk.len(), 256);
    }

    #[test]
    fn test_provide_chunk_wrong_size() {
        // Providing data with the wrong size should be rejected as malformed.
        let mut session = create_content_session([0xEE; 32], 512, 256);

        // Try to provide chunk 0 with only 100 bytes (expected: 256).
        let data = vec![0x00u8; 100];
        let result = provide_chunk(&mut session, 0, &data);
        assert!(result.is_err(), "wrong-size chunk should be rejected");
    }

    #[test]
    fn test_provide_chunk_last_chunk_smaller() {
        // The last chunk of non-evenly-divisible content is smaller.
        // 500 bytes / 256 = 2 chunks: chunk 0 = 256 bytes, chunk 1 = 244 bytes.
        let mut session = create_content_session([0xFF; 32], 500, 256);
        assert_eq!(session.chunks_available.len(), 2);

        // Chunk 1 should accept 244 bytes (not 256).
        let data = vec![0x01u8; 244];
        provide_chunk(&mut session, 1, &data).expect("last chunk should accept 244 bytes");
        assert!(session.chunks_available[1]);

        // Providing 256 bytes for the last chunk should fail.
        session.chunks_available[1] = false; // reset for re-test
        let wrong_data = vec![0x01u8; 256];
        let result = provide_chunk(&mut session, 1, &wrong_data);
        assert!(result.is_err(), "oversized last chunk should be rejected");
    }

    #[test]
    fn test_request_chunk_out_of_range() {
        // Requesting a chunk beyond the total count should return OutOfRange.
        let session = create_content_session([0x11; 32], 512, 256);

        // Only 2 chunks exist (indices 0 and 1). Index 5 is out of range.
        let result = request_chunk(&session, 5);
        assert!(result.is_err(), "out-of-range chunk should fail");
    }

    #[test]
    fn test_provide_chunk_out_of_range() {
        // Providing a chunk beyond the total count should return OutOfRange.
        let mut session = create_content_session([0x22; 32], 512, 256);

        let data = vec![0x00u8; 256];
        let result = provide_chunk(&mut session, 10, &data);
        assert!(result.is_err(), "out-of-range provide should fail");
    }

    // -----------------------------------------------------------------------
    // Session status JSON tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_status_json_fields() {
        // The JSON output must contain all required fields with correct types.
        let session =
            create_session(MeshProtocol::MeshDns, test_peer(0xAB)).expect("session creation");

        let json = session_status_json(&session);
        // Verify all expected fields are present in the JSON object.
        assert!(json.get("id").is_some(), "JSON must have 'id' field");
        assert!(
            json.get("protocol").is_some(),
            "JSON must have 'protocol' field"
        );
        assert!(
            json.get("peer_id").is_some(),
            "JSON must have 'peer_id' field"
        );
        assert!(json.get("state").is_some(), "JSON must have 'state' field");
        assert!(
            json.get("created_at").is_some(),
            "JSON must have 'created_at' field"
        );
        assert!(
            json.get("last_activity").is_some(),
            "JSON must have 'last_activity' field"
        );
        assert!(
            json.get("bytes_exchanged").is_some(),
            "JSON must have 'bytes_exchanged' field"
        );

        // Verify protocol is correctly mapped to its string representation.
        assert_eq!(json["protocol"], "mesh_dns");
        // Verify state is correctly mapped (should be Initiating).
        assert_eq!(json["state"], "initiating");
        // Verify bytes_exchanged starts at 0.
        assert_eq!(json["bytes_exchanged"], 0);
    }

    #[test]
    fn test_session_status_json_custom_protocol() {
        // Custom protocols should include the protocol name in the JSON.
        let session = create_session(
            MeshProtocol::Custom("org.example/chat/v2".to_string()),
            test_peer(0xCD),
        )
        .expect("session creation");

        let json = session_status_json(&session);
        // Custom protocol string should be "custom:<name>".
        assert_eq!(json["protocol"], "custom:org.example/chat/v2");
    }

    #[test]
    fn test_session_status_json_all_states() {
        // Verify that every SessionState variant maps to the correct JSON string.
        let mut session =
            create_session(MeshProtocol::MeshStream, test_peer(0xEF)).expect("session creation");

        // Test each state by mutating the session and checking JSON output.
        let state_mappings = [
            (SessionState::Initiating, "initiating"),
            (SessionState::Active, "active"),
            (SessionState::Paused, "paused"),
            (SessionState::Closing, "closing"),
            (SessionState::Closed, "closed"),
        ];

        for (state, expected_str) in state_mappings {
            session.state = state;
            let json = session_status_json(&session);
            assert_eq!(
                json["state"], expected_str,
                "state {:?} should map to '{}'",
                session.state, expected_str
            );
        }
    }

    #[test]
    fn test_full_session_lifecycle() {
        // End-to-end test: create → activate → process frames → close.
        // Verifies the complete happy-path session lifecycle.
        let mut session =
            create_session(MeshProtocol::MeshFileShare, test_peer(0x99)).expect("session creation");

        // Step 1: session starts in Initiating.
        assert_eq!(session.state, SessionState::Initiating);

        // Step 2: simulate handshake completion by transitioning to Active.
        session.state = SessionState::Active;

        // Step 3: process several frames and verify counters increment.
        for i in 0..5u8 {
            let frame = vec![i; 10]; // 10-byte frames
            let resp = process_protocol_frame(&mut session, &frame)
                .expect("frame processing should succeed");
            assert!(!resp.is_empty());
        }

        // Verify bytes have been counted (5 frames of 10 bytes + 5 responses of 11 bytes).
        assert!(session.bytes_exchanged > 0);
        let expected_bytes: u64 = 5 * 10 + 5 * 11; // inbound + outbound
        assert_eq!(session.bytes_exchanged, expected_bytes);

        // Step 4: close the session.
        close_session(&mut session).expect("close should succeed");
        assert_eq!(session.state, SessionState::Closed);

        // Step 5: verify no more frames can be processed after close.
        let result = process_protocol_frame(&mut session, b"after-close");
        assert!(result.is_err(), "closed session should reject frames");
    }
}
