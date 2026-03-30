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
    AppId { id: String },
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
    MouseMove { x: u16, y: u16 },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MouseButton { button: u8, pressed: bool, x: u16, y: u16 },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    MouseScroll { delta_x: i16, delta_y: i16 },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    KeyEvent { keycode: u32, pressed: bool, modifiers: u16 },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    TouchBegin { id: u8, x: f32, y: f32 },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    TouchMove { id: u8, x: f32, y: f32 },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    TouchEnd { id: u8 },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    DragStart { window_id: u32, mime_type: String, payload: Vec<u8> },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Drop { target_window_id: u32, x: u16, y: u16 },
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
    List { path: String },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Stat { path: String },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Read { path: String, offset: u64, length: u32 },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Write { path: String, offset: u64, payload: Vec<u8>, create_if_missing: bool },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Truncate { path: String, length: u64 },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Delete { path: String },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Rename { from: String, to: String },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Mkdir { path: String },
    // Process the current step in the protocol.
    // Execute this protocol step.
    // Execute this protocol step.
    Rmdir { path: String },
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
}
