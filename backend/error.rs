//! Unified error type for the Mesh Infinity backend (§17.5).
//!
//! # Design Philosophy
//!
//! Every fallible operation in this codebase returns `Result<T, MeshError>`
//! (or `anyhow::Result<T>` at module boundaries where the caller only needs
//! a human-readable message, not a matchable type).
//!
//! `MeshError` provides typed variants so callers can pattern-match on the
//! exact failure mode and take different recovery actions rather than parsing
//! error strings. This replaces the ad-hoc `unwrap()` and `expect()` patterns
//! scattered across the codebase (all 810 call sites must be migrated here).
//!
//! # FFI boundary
//!
//! FFI shims in `ffi/lib.rs` convert `MeshError` to a human-readable string
//! stored in `MeshRuntime::last_error`. Key material is NEVER included in
//! error messages that cross the FFI boundary (§15.1). The `safe_description`
//! method is the single controlled path for that conversion.
//!
//! # Dependency on `thiserror`
//!
//! `thiserror` derives `std::error::Error`, `Display`, and `From` impls
//! automatically from the `#[error("...")]` annotations. This avoids hundreds
//! of lines of hand-written boilerplate while keeping error messages readable.
//!
//! # Relationship to `anyhow`
//!
//! `anyhow::Error` is the "I don't care about the exact type" escape hatch,
//! used when a subsystem just wants to propagate context with `?`. The
//! `MeshError::Other` variant wraps it for callers that need a `MeshError`.

use thiserror::Error;

// ---------------------------------------------------------------------------
// Primary error type
// ---------------------------------------------------------------------------

/// The unified, typed error type for all fallible backend operations.
///
/// Use this as the `Err` variant in any `Result` that crosses a module
/// boundary. Within a single function body, `anyhow::Result<T>` is fine;
/// convert to `MeshError` before returning to the caller.
#[derive(Debug, Error)]
pub enum MeshError {
    // -----------------------------------------------------------------------
    // Identity errors (§3.1, §9)
    // -----------------------------------------------------------------------

    /// No identity exists on disk — the user must create one first.
    ///
    /// Returned by: `mi_unlock_identity`, `mi_get_identity_summary`, and any
    /// operation that requires Layer 2 (§3.1.2) to be present on disk.
    #[error("no identity found — create one with mi_create_identity")]
    NoIdentity,

    /// Identity exists but the vault is locked — unlock before proceeding.
    ///
    /// Returned by any operation that requires Layer 2 to be decrypted.
    /// The Flutter UI should navigate to the unlock screen when it sees this.
    #[error("identity is locked — call mi_unlock_identity first")]
    IdentityLocked,

    /// The supplied passphrase was rejected by Argon2id verification.
    ///
    /// The caller should prompt the user to retry. After N failures (configured
    /// in settings) the vault may apply a lockout delay (§9.1.3).
    #[error("wrong passphrase")]
    WrongPassphrase,

    /// A required identity field is missing or the persisted bytes are corrupt.
    ///
    /// The `String` describes which field or structure is malformed.
    /// Recovery: the user may need to restore from backup (§3.7.4).
    #[error("identity data corrupt: {0}")]
    IdentityCorrupt(String),

    // -----------------------------------------------------------------------
    // Cryptographic errors (§7)
    // -----------------------------------------------------------------------

    /// Ed25519 or X25519 key material was invalid.
    ///
    /// Common causes: wrong length, low-order Curve25519 point, or an
    /// all-zero key (which is invalid for Ed25519).
    #[error("invalid key material: {0}")]
    InvalidKey(String),

    /// Ed25519 signature verification failed.
    ///
    /// Could indicate tampering, a wrong domain separator, or the wrong key.
    /// See `crypto::signing::verify` for domain-separation rules.
    #[error("signature verification failed")]
    InvalidSignature,

    /// AEAD decryption authentication tag mismatch.
    ///
    /// The ciphertext is corrupt or was encrypted with a different key.
    /// MUST be treated as a security event — do not silently discard.
    #[error("decryption failed — ciphertext corrupt or key mismatch")]
    DecryptionFailed,

    /// Double Ratchet session not found for the specified peer.
    ///
    /// The `String` is the hex-encoded peer ID. Recovery: attempt a new X3DH
    /// handshake to establish a fresh session (§7.0.2).
    #[error("no ratchet session for peer {0}")]
    NoRatchetSession(String),

    // -----------------------------------------------------------------------
    // Transport errors (§5)
    // -----------------------------------------------------------------------

    /// A network connection attempt failed.
    ///
    /// `endpoint` is the address we tried to reach; `reason` is the OS or
    /// protocol-level error message. Both are safe to log (no key material).
    #[error("connection to {endpoint} failed: {reason}")]
    ConnectionFailed {
        /// The endpoint we attempted to connect to (IP:port, .onion, MAC, etc.).
        endpoint: String,
        /// Human-readable reason for the failure (OS error string is fine).
        reason: String,
    },

    /// Transport not enabled or not available on this platform.
    ///
    /// The user must enable the transport in Settings before it can be used.
    /// The solver (§5.10) must never select a disabled transport for routing.
    #[error("transport '{0}' is not enabled")]
    TransportDisabled(String),

    /// A required transport feature is not available at runtime.
    ///
    /// This is distinct from `TransportDisabled` — the user has enabled the
    /// transport but the runtime precondition failed (e.g., Tor failed to
    /// bootstrap, or the BLE adapter is physically absent).
    #[error("transport '{0}' not available: {1}")]
    TransportUnavailable(String, String),

    /// An I/O error from the operating system.
    ///
    /// Wraps `std::io::Error` via the `From` impl that thiserror generates
    /// for `#[from]` variants. Propagate with `?` freely within I/O code.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // -----------------------------------------------------------------------
    // Serialization errors (§17.5)
    // -----------------------------------------------------------------------

    /// JSON parsing or serialization failed.
    ///
    /// Used when decoding inbound frames or encoding outbound JSON responses.
    /// The `serde_json::Error` is wrapped directly via `#[from]`.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // -----------------------------------------------------------------------
    // Storage errors (§17.9)
    // -----------------------------------------------------------------------

    /// The vault could not be opened, or a named collection is missing.
    ///
    /// The `String` describes which vault operation failed. Recovery: check
    /// that the data directory is writable and not out of space.
    #[error("vault error: {0}")]
    Vault(String),

    /// A requested resource does not exist.
    ///
    /// Used when looking up a room, peer, message, or file transfer by ID
    /// that is not present in the in-memory store or vault.
    #[error("{kind} not found: {id}")]
    NotFound {
        /// The kind of resource (e.g., "room", "peer", "message", "transfer").
        kind: &'static str,
        /// The ID that was looked up (hex string, UUID, etc.).
        id: String,
    },

    // -----------------------------------------------------------------------
    // Protocol errors (§6, §8)
    // -----------------------------------------------------------------------

    /// An inbound frame had an unrecognized or malformed format.
    ///
    /// The `String` describes the specific problem (e.g., "missing `type` field").
    /// The frame should be dropped, not forwarded.
    #[error("malformed frame: {0}")]
    MalformedFrame(String),

    /// A peer's trust level is insufficient for the requested operation.
    ///
    /// The spec defines minimum trust levels for privileged operations (§8.4).
    /// Return this error rather than silently ignoring the request.
    #[error("peer {peer} trust level {level} is too low for this operation")]
    TrustInsufficient {
        /// Hex-encoded peer ID.
        peer: String,
        /// The peer's current trust level (0 = untrusted, 3 = intimate).
        level: u8,
    },

    /// A pairing attempt contained an invalid or expired payload.
    ///
    /// The `String` describes the specific validation failure. The pairing
    /// attempt must be rejected entirely — do not accept partial data (§8.3).
    #[error("pairing payload invalid: {0}")]
    PairingInvalid(String),

    // -----------------------------------------------------------------------
    // FFI input validation (§17.5)
    // -----------------------------------------------------------------------

    /// A caller-supplied C string pointer was null.
    ///
    /// FFI shims check all `*const c_char` parameters before dereferencing.
    /// Returning this error is safer than dereferencing a null pointer, which
    /// would be undefined behaviour and crash the app.
    #[error("null pointer passed to FFI function")]
    NullPointer,

    /// A caller-supplied C string was not valid UTF-8.
    ///
    /// All strings crossing the FFI boundary must be UTF-8 (JSON is UTF-8).
    /// Flutter's `dart:ffi` produces UTF-8 strings, so this indicates a bug
    /// on the Dart side.
    #[error("FFI string is not valid UTF-8")]
    InvalidUtf8,

    /// A caller-supplied argument was outside the accepted range.
    ///
    /// `field` names the parameter that was invalid; `value` is the string
    /// representation of the out-of-range value (safe to include in logs).
    #[error("argument '{field}' out of range: {value}")]
    OutOfRange {
        /// The name of the out-of-range parameter.
        field: &'static str,
        /// String representation of the bad value.
        value: String,
    },

    // -----------------------------------------------------------------------
    // Catch-all
    // -----------------------------------------------------------------------

    /// An unexpected internal error occurred.
    ///
    /// Use this when none of the typed variants above apply. The `String`
    /// MUST be informative enough to diagnose without attaching a debugger,
    /// but MUST NOT contain key material (§15.1).
    #[error("internal error: {0}")]
    Internal(String),

    /// Wraps an arbitrary `anyhow::Error` for ergonomic `?` propagation.
    ///
    /// Use when the root cause is already described and you just need to
    /// return a `MeshError` at the module boundary. Prefer typed variants
    /// above when the caller needs to match on the error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// ---------------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------------

impl MeshError {
    /// Returns a short, safe description suitable for the FFI last-error string.
    ///
    /// This MUST NOT include key material, passphrases, or raw cryptographic
    /// bytes (§15.1). The `Display` impl (`to_string()`) already satisfies
    /// this invariant for all variants; this method is a named wrapper that
    /// makes the safety intent explicit at call sites.
    pub fn safe_description(&self) -> String {
        // All Display impls are written to exclude key material.
        // Keep this as a named method so reviewers can audit the invariant.
        self.to_string()
    }

    /// Returns true if this error indicates the identity is not yet available.
    ///
    /// Used by the FFI layer to decide whether to return a specific error code
    /// so Flutter can navigate to the identity setup / unlock screen.
    pub fn is_identity_unavailable(&self) -> bool {
        matches!(self, MeshError::NoIdentity | MeshError::IdentityLocked)
    }

    /// Returns true if this error is a cryptographic verification failure.
    ///
    /// Callers that log security events should check this to decide whether
    /// to escalate to the threat context system (§16.9).
    pub fn is_security_failure(&self) -> bool {
        matches!(
            self,
            MeshError::InvalidSignature
                | MeshError::DecryptionFailed
                | MeshError::TrustInsufficient { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Convenience conversions
// ---------------------------------------------------------------------------

/// Convert a CString/CStr Nul-byte error into `MeshError::InvalidUtf8`.
///
/// These appear when a C string passed through FFI contains an embedded
/// null byte, which `CStr::from_ptr` or `CStr::to_str` rejects.
impl From<std::ffi::NulError> for MeshError {
    fn from(_: std::ffi::NulError) -> Self {
        // A NulError means the string had an embedded null — treat as invalid UTF-8
        // for the purposes of the error type (both indicate a malformed FFI string).
        MeshError::InvalidUtf8
    }
}

/// Convert a `std::str::Utf8Error` into `MeshError::InvalidUtf8`.
impl From<std::str::Utf8Error> for MeshError {
    fn from(_: std::str::Utf8Error) -> Self {
        MeshError::InvalidUtf8
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that safe_description never panics and returns a non-empty string.
    #[test]
    fn test_safe_description_non_empty() {
        // Test a representative sample of variants to ensure Display works.
        let errors = [
            MeshError::NoIdentity,
            MeshError::IdentityLocked,
            MeshError::WrongPassphrase,
            MeshError::InvalidSignature,
            MeshError::DecryptionFailed,
            MeshError::NullPointer,
            MeshError::InvalidUtf8,
            MeshError::Internal("test internal error".to_string()),
        ];

        for e in &errors {
            let desc = e.safe_description();
            assert!(
                !desc.is_empty(),
                "safe_description() must never return an empty string; got empty for {:?}",
                e
            );
        }
    }

    /// Verify identity_unavailable detection works correctly.
    #[test]
    fn test_is_identity_unavailable() {
        // These two MUST return true — they control Flutter navigation.
        assert!(MeshError::NoIdentity.is_identity_unavailable());
        assert!(MeshError::IdentityLocked.is_identity_unavailable());

        // Other errors must not trigger the identity-unavailable path.
        assert!(!MeshError::WrongPassphrase.is_identity_unavailable());
        assert!(!MeshError::InvalidSignature.is_identity_unavailable());
        assert!(!MeshError::NullPointer.is_identity_unavailable());
    }

    /// Verify security failure detection catches the right variants.
    #[test]
    fn test_is_security_failure() {
        // These are security events — the threat context system (§16.9) cares.
        assert!(MeshError::InvalidSignature.is_security_failure());
        assert!(MeshError::DecryptionFailed.is_security_failure());
        assert!(
            MeshError::TrustInsufficient {
                peer: "abc".to_string(),
                level: 0
            }
            .is_security_failure()
        );

        // These are NOT security events.
        assert!(!MeshError::NoIdentity.is_security_failure());
        assert!(!MeshError::NullPointer.is_security_failure());
        assert!(!MeshError::WrongPassphrase.is_security_failure());
    }

    /// Verify NotFound carries the right context through Display.
    #[test]
    fn test_not_found_display() {
        let e = MeshError::NotFound {
            kind: "room",
            id: "deadbeef".to_string(),
        };
        let s = e.to_string();
        // Display must include both kind and id so log messages are useful.
        assert!(s.contains("room"), "Display must include kind");
        assert!(s.contains("deadbeef"), "Display must include id");
    }

    /// Verify that std::io::Error converts via From without ambiguity.
    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let mesh_err: MeshError = io_err.into();
        assert!(matches!(mesh_err, MeshError::Io(_)));
    }

    /// Verify that serde_json errors convert via From.
    #[test]
    fn test_json_error_conversion() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let mesh_err: MeshError = json_err.into();
        assert!(matches!(mesh_err, MeshError::Json(_)));
    }
}
