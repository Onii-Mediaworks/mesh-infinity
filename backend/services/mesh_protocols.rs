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
pub const PROTO_MNRDP: [u8; 4] = *b"MNRD";
/// MNSP protocol ID.
pub const PROTO_MNSP: [u8; 4] = *b"MNSH";
/// MNFP protocol ID.
pub const PROTO_MNFP: [u8; 4] = *b"MNFP";
/// Screen Share protocol ID.
pub const PROTO_SCREEN_SHARE: [u8; 4] = *b"MNSS";

// ---------------------------------------------------------------------------
// Protocol Framework (§20.1)
// ---------------------------------------------------------------------------

/// Protocol handshake (client → server).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshProtoHandshake {
    /// 4-byte protocol identifier.
    pub protocol_id: [u8; 4],
    /// Minimum version the client supports.
    pub min_version: u16,
    /// Maximum version the client supports.
    pub max_version: u16,
    /// Client capabilities (protocol-specific strings).
    pub capabilities: Vec<String>,
}

/// Handshake acknowledgement (server → client).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshProtoHandshakeAck {
    /// The version the server selected.
    pub negotiated_version: u16,
    /// Server capabilities.
    pub capabilities: Vec<String>,
}

/// Protocol error.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshProtoError {
    /// Error code: 1=version, 2=capability, 3=access, 4=resource.
    pub code: u16,
    /// Human-readable error message.
    pub message: String,
}

// ---------------------------------------------------------------------------
// MNRDP — Remote Desktop (§20.2)
// ---------------------------------------------------------------------------

/// MNRDP session request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnrdpSessionRequest {
    pub display_index: u8,
    pub resolution: Option<(u16, u16)>,
    pub color_depth: u8,
    pub frame_encoding: MnrdpEncoding,
    pub compression: MnrdpCompression,
    pub audio_forward: bool,
    pub clipboard_sync: bool,
    pub input_enabled: bool,
    pub mode: MnrdpSessionMode,
}

/// Frame encoding for MNRDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MnrdpEncoding {
    Raw,
    H264,
    AV1,
    Zstd,
}

/// Compression for MNRDP metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MnrdpCompression {
    None,
    Zstd,
    Brotli,
}

/// MNRDP session mode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MnrdpSessionMode {
    /// Full desktop access.
    FullDesktop,
    /// Stream a single application.
    AppStream {
        app_spec: MnrdpAppSpec,
        windowing: MnrdpWindowing,
    },
    /// Browse and launch applications.
    AppGallery {
        windowing: MnrdpWindowing,
        filter: Option<String>,
    },
}

/// How to specify which application to stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MnrdpAppSpec {
    AppId { id: String },
    BrokerCall {
        broker_type: MnrdpBrokerType,
        service: String,
        arg: Option<String>,
    },
    FileOpen {
        path: String,
        mime_hint: Option<String>,
    },
}

/// Application broker types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MnrdpBrokerType {
    Native,
    QemuGuestAgent,
    Qrexec,
    XdgDesktop,
    SystemdActivation,
}

/// Windowing mode for app streaming.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MnrdpWindowing {
    Seamless,
    Contained,
    Fullscreen,
}

/// MNRDP session acknowledgement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnrdpSessionAck {
    pub session_id: [u8; 16],
    pub actual_resolution: (u16, u16),
    pub negotiated_encoding: MnrdpEncoding,
    pub frames_per_second: u8,
    pub broker_available: Option<MnrdpBrokerType>,
    pub capabilities: Vec<String>,
}

/// A rendered frame from MNRDP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnrdpFrame {
    pub session_id: [u8; 16],
    pub sequence: u64,
    /// Microseconds since session start.
    pub timestamp: u64,
    pub is_keyframe: bool,
    pub damage_rects: Vec<MnrdpRect>,
    pub payload: Vec<u8>,
    pub window_id: Option<u32>,
}

/// Rectangle for damage regions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnrdpRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

/// Input event for MNRDP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnrdpInput {
    pub session_id: [u8; 16],
    pub sequence: u64,
    pub target_window: Option<u32>,
    pub events: Vec<MnrdpInputEvent>,
}

/// Individual input events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MnrdpInputEvent {
    MouseMove { x: u16, y: u16 },
    MouseButton { button: u8, pressed: bool, x: u16, y: u16 },
    MouseScroll { delta_x: i16, delta_y: i16 },
    KeyEvent { keycode: u32, pressed: bool, modifiers: u16 },
    TouchBegin { id: u8, x: f32, y: f32 },
    TouchMove { id: u8, x: f32, y: f32 },
    TouchEnd { id: u8 },
    DragStart { window_id: u32, mime_type: String, payload: Vec<u8> },
    Drop { target_window_id: u32, x: u16, y: u16 },
}

/// Application list entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnrdpAppEntry {
    pub app_id: String,
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<Vec<u8>>,
    pub categories: Vec<String>,
    pub broker_type: MnrdpBrokerType,
    pub file_open: bool,
    pub windowing_hint: MnrdpWindowing,
}

/// Clipboard transfer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnrdpClipboard {
    pub session_id: [u8; 16],
    pub direction: ClipboardDirection,
    pub mime_type: String,
    pub payload: Vec<u8>,
}

/// Clipboard transfer direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClipboardDirection {
    ToServer,
    ToClient,
}

// ---------------------------------------------------------------------------
// MNSP — Remote Shell (§20.3)
// ---------------------------------------------------------------------------

/// MNSP session request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnspSessionRequest {
    pub shell: Option<String>,
    pub cols: u16,
    pub rows: u16,
    pub env: std::collections::HashMap<String, String>,
    pub interactive: bool,
    pub command: Option<String>,
}

/// MNSP session acknowledgement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnspSessionAck {
    pub session_id: [u8; 16],
    pub shell: String,
    pub pid: u32,
}

/// MNSP data stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MnspStream {
    Stdin,
    Stdout,
    Stderr,
}

/// MNSP data packet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnspData {
    pub session_id: [u8; 16],
    pub stream: MnspStream,
    pub payload: Vec<u8>,
}

/// MNSP terminal resize.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnspResize {
    pub session_id: [u8; 16],
    pub cols: u16,
    pub rows: u16,
}

/// MNSP process exit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnspExit {
    pub session_id: [u8; 16],
    pub exit_code: i32,
}

// ---------------------------------------------------------------------------
// MNFP — Distributed File Access (§20.4)
// ---------------------------------------------------------------------------

/// MNFP session request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnfpSessionRequest {
    pub root: String,
    pub access: MnfpAccess,
}

/// MNFP access mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MnfpAccess {
    ReadOnly,
    ReadWrite,
    WriteOnly,
}

/// MNFP session acknowledgement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnfpSessionAck {
    pub session_id: [u8; 16],
    pub root: String,
    pub access: MnfpAccess,
}

/// MNFP file operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MnfpOp {
    List { path: String },
    Stat { path: String },
    Read { path: String, offset: u64, length: u32 },
    Write { path: String, offset: u64, payload: Vec<u8>, create_if_missing: bool },
    Truncate { path: String, length: u64 },
    Delete { path: String },
    Rename { from: String, to: String },
    Mkdir { path: String },
    Rmdir { path: String },
}

/// MNFP request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnfpRequest {
    pub session_id: [u8; 16],
    pub request_id: u32,
    pub operation: MnfpOp,
}

/// MNFP directory entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnfpEntry {
    pub name: String,
    pub kind: MnfpEntryKind,
    pub size: u64,
    pub modified: u64,
    pub mode: u16,
}

/// File entry kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MnfpEntryKind {
    File,
    Dir,
    Symlink,
}

/// MNFP error codes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MnfpError {
    pub code: u16,
    pub message: String,
}

// ---------------------------------------------------------------------------
// API Gateway (§20.5)
// ---------------------------------------------------------------------------

/// API Gateway authentication mode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MeshApiAuthMode {
    None,
    BearerPeerToken,
    ClientCert,
}

// ---------------------------------------------------------------------------
// Service Type Constants (§20.9)
// ---------------------------------------------------------------------------

/// Well-known service type strings.
pub const SVC_REMOTE_DESKTOP: &str = "meshinfinity.remote-desktop/v1";
pub const SVC_REMOTE_SHELL: &str = "meshinfinity.remote-shell/v1";
pub const SVC_FILE_ACCESS: &str = "meshinfinity.file-access/v1";
pub const SVC_API_GATEWAY: &str = "meshinfinity.api-gateway/v1";
pub const SVC_SCREEN_SHARE: &str = "meshinfinity.screen-share/v1";
pub const SVC_CLIPBOARD: &str = "meshinfinity.clipboard/v1";
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
