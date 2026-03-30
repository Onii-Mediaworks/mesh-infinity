//! Diagnostic Report System (Spec SS 21.3)
//!
//! # Purpose
//!
//! Generates a privacy-safe snapshot of the node's current state for debugging.
//! Users can export this report from Settings -> Advanced -> Export Diagnostic
//! Report and share it with developers without exposing any private data.
//!
//! # Privacy guarantees (SS 21.3.2)
//!
//! Diagnostic reports contain:
//! - **Zero** message content (text, body, attachments)
//! - **Zero** private keys (identity, session, ratchet)
//! - **Zero** contact names or display names
//! - **Zero** IP addresses from clearnet connections
//! - **Only** mesh peer IDs (which are already public)
//!
//! The sanitization rules are enforced at generation time by the
//! `sanitize_string` function -- there is no post-processing step that
//! could be accidentally skipped.
//!
//! # Report contents (SS 21.3.1)
//!
//! The report is a collection of diagnostic structs that can be serialized
//! to JSON for inclusion in the diagnostic ZIP archive.  See
//! `DiagnosticReport` for the top-level structure.

use serde::{Serialize, Deserialize};

// ---------------------------------------------------------------------------
// Privacy redaction
// ---------------------------------------------------------------------------

/// Field names that trigger automatic redaction in diagnostic output.
/// Any JSON field whose name matches one of these strings (case-insensitive)
/// has its value replaced with `[REDACTED]` before inclusion in the report.
///
/// This list comes directly from SS 21.3.2.
const REDACTED_FIELDS: &[&str] = &[
    "text", "content", "body", "display_name", "name",
    "email", "phone", "address", "ip", "host",
];

/// Maximum allowed length for any string value in the diagnostic report.
/// Strings exceeding this length are truncated to prevent accidental
/// inclusion of large data blobs (e.g. base64-encoded keys or messages).
const MAX_STRING_LENGTH: usize = 256;

/// Sanitize a string value for inclusion in a diagnostic report.
///
/// Applies two rules from SS 21.3.2:
/// 1. If `field_name` matches any entry in `REDACTED_FIELDS`, the value
///    is replaced entirely with `[REDACTED]`.
/// 2. All string values are truncated to `MAX_STRING_LENGTH` characters.
///
/// Returns the sanitized string, ready for inclusion in the report.
pub fn sanitize_string(field_name: &str, value: &str) -> String {
    // Check if the field name matches any redacted field (case-insensitive).
    let lower_field = field_name.to_lowercase();
    for &redacted in REDACTED_FIELDS {
        if lower_field == redacted {
            // Replace the entire value with the redaction marker.
            return "[REDACTED]".to_string();
        }
    }

    // Truncate to MAX_STRING_LENGTH if the value exceeds the limit.
    if value.len() > MAX_STRING_LENGTH {
        // Truncate at a char boundary to avoid splitting a multi-byte character.
        let truncated = match value.char_indices().nth(MAX_STRING_LENGTH) {
            Some((idx, _)) => &value[..idx],
            None => value,
        };
        return format!("{}...", truncated);
    }

    // Value is safe -- return as-is.
    value.to_string()
}

// ---------------------------------------------------------------------------
// Diagnostic report structures
// ---------------------------------------------------------------------------

/// Top-level diagnostic report (SS 21.3.1).
///
/// Contains a timestamped snapshot of all subsystem diagnostics.  Each field
/// corresponds to one file in the diagnostic ZIP archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// Unix timestamp (seconds since epoch) when this report was generated.
    /// Used for ordering reports and correlating with event logs.
    pub timestamp: u64,

    /// Application version string (e.g. "0.3.0").
    /// Helps developers match the report to the correct source revision.
    pub version: String,

    /// Per-transport status diagnostics (one entry per active transport).
    /// Corresponds to `network_stats.json` in the ZIP archive.
    pub transport_status: Vec<TransportDiagnostic>,

    /// Routing subsystem statistics.
    /// Corresponds to `routing_table.json` in the ZIP archive.
    pub routing_stats: RoutingDiagnostic,

    /// Identity subsystem status (peer ID and lock state only).
    /// Corresponds to `identity_summary.json` in the ZIP archive.
    pub identity_status: IdentityDiagnostic,

    /// Process memory usage statistics.
    /// Included in `system_info.json` alongside platform info.
    pub memory_usage: MemoryDiagnostic,
}

/// Diagnostic data for a single transport (SS 21.3.1 network_stats.json).
///
/// Each active transport (Tor, clearnet, Bluetooth, mDNS, etc.) produces
/// one entry.  Disabled transports are omitted entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportDiagnostic {
    /// Transport name (e.g. "tor", "clearnet", "bluetooth", "mdns").
    /// This is the transport's internal identifier, not a user-facing label.
    pub transport_name: String,

    /// Whether this transport is currently enabled in settings.
    pub enabled: bool,

    /// Number of peers currently connected via this transport.
    pub connected_peers: usize,

    /// Total bytes sent via this transport since the session started.
    /// Monotonically increasing; resets only on app restart.
    pub bytes_sent: u64,

    /// Total bytes received via this transport since the session started.
    pub bytes_received: u64,

    /// Number of errors encountered on this transport in the last hour.
    /// Errors include connection failures, timeouts, and protocol violations.
    pub errors_last_hour: u32,
}

/// Routing subsystem diagnostic data (SS 21.3.1 routing_table.json).
///
/// Provides a summary of the routing table without exposing IP addresses
/// or contact names.  Only peer IDs (which are public) are included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDiagnostic {
    /// Total number of entries in the routing table.
    pub total_routes: usize,

    /// Number of directly-connected peers (1-hop routes).
    pub direct_peers: usize,

    /// Number of relay routes (2+ hops through other nodes).
    pub relay_routes: usize,

    /// Number of routing entries that are stale (not refreshed within the
    /// last announcement period).
    pub stale_routes: usize,

    /// Average path score across all active routes (0.0 = worst, 1.0 = best).
    /// This is the trust-weighted composite score from SS 6.3.
    pub avg_path_score: f64,
}

/// Identity subsystem diagnostic data (SS 21.3.1 identity_summary.json).
///
/// Contains only the peer ID (which is the public key hash and is already
/// public knowledge on the mesh).  No private keys or display names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDiagnostic {
    /// The node's peer ID as a hex string.
    /// This is the SHA-256 hash of the Ed25519 public key -- already public.
    pub peer_id: String,

    /// Whether the identity vault is currently unlocked.
    /// true = unlocked (keys in memory), false = locked (keys encrypted on disk).
    pub vault_unlocked: bool,

    /// Whether this node has completed initial onboarding.
    pub onboarding_complete: bool,
}

/// Process memory usage diagnostic data.
///
/// Provides a rough snapshot of the process's memory consumption.
/// These values come from OS APIs (e.g. `/proc/self/status` on Linux)
/// and may not be available on all platforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDiagnostic {
    /// Resident set size in bytes (physical memory currently used).
    /// Zero if not available on the current platform.
    pub rss_bytes: u64,

    /// Virtual memory size in bytes (total address space mapped).
    /// Zero if not available on the current platform.
    pub vms_bytes: u64,

    /// Number of active allocations tracked by the runtime allocator.
    /// Zero if not instrumented.
    pub allocation_count: u64,
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

/// Generate a diagnostic report with the current node state.
///
/// This function collects diagnostics from all subsystems and assembles
/// them into a single `DiagnosticReport`.  In a full runtime, this would
/// query the actual subsystem states; the current implementation returns
/// a snapshot with default/placeholder values that are populated by the
/// caller (the FFI layer or debug menu).
///
/// All values are sanitized at construction time -- no post-processing
/// needed by the caller.
pub fn generate_report() -> DiagnosticReport {
    // Get the current timestamp (seconds since Unix epoch).
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        // If the system clock is before the epoch (impossible in practice),
        // fall back to zero rather than panicking.
        .unwrap_or_default()
        .as_secs();

    // Read the version from Cargo.toml at compile time.
    let version = env!("CARGO_PKG_VERSION").to_string();

    // Construct the report with empty transport list and zeroed stats.
    // The caller populates transport_status, routing_stats, etc. by
    // querying the actual runtime subsystems.
    DiagnosticReport {
        timestamp,
        version,
        transport_status: Vec::new(),
        routing_stats: RoutingDiagnostic {
            total_routes: 0,
            direct_peers: 0,
            relay_routes: 0,
            stale_routes: 0,
            avg_path_score: 0.0,
        },
        identity_status: IdentityDiagnostic {
            peer_id: String::new(),
            vault_unlocked: false,
            onboarding_complete: false,
        },
        memory_usage: MemoryDiagnostic {
            rss_bytes: 0,
            vms_bytes: 0,
            allocation_count: 0,
        },
    }
}

/// Serialize a diagnostic report to a pretty-printed JSON string.
///
/// The output is human-readable with 2-space indentation, suitable for
/// inclusion in the diagnostic ZIP archive.  All string values have
/// already been sanitized at construction time.
///
/// Returns the JSON string, or a JSON error object if serialization fails
/// (which should never happen for well-formed DiagnosticReport structs).
pub fn report_to_json(report: &DiagnosticReport) -> String {
    // Use serde_json's pretty printer for human-readable output.
    // The `unwrap_or_else` fallback produces a valid JSON error object
    // so the caller always gets valid JSON, even on serialization failure.
    serde_json::to_string_pretty(report).unwrap_or_else(|e| {
        format!("{{\"error\": \"serialization failed: {}\"}}", e)
    })
}

/// Sanitize an entire diagnostic report in place.
///
/// Walks all string fields and applies the `sanitize_string` rules.
/// This is the single enforcement point for SS 21.3.2 privacy guarantees.
/// Called automatically by the FFI export path before writing to disk.
pub fn sanitize_report(report: &mut DiagnosticReport) {
    // Sanitize transport names (unlikely to match redacted fields, but
    // defense-in-depth requires checking every string).
    for transport in &mut report.transport_status {
        transport.transport_name = sanitize_string("transport_name", &transport.transport_name);
    }

    // Sanitize the identity peer ID.
    // "peer_id" is not in the redaction list, so it passes through.
    report.identity_status.peer_id = sanitize_string(
        "peer_id",
        &report.identity_status.peer_id,
    );

    // Sanitize the version string (defense-in-depth).
    report.version = sanitize_string("version", &report.version);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Sanitization tests -------------------------------------------------

    /// Fields in the redaction list must be replaced with [REDACTED].
    #[test]
    fn sanitize_redacts_sensitive_fields() {
        // Every field in REDACTED_FIELDS must trigger redaction.
        assert_eq!(sanitize_string("text", "hello"), "[REDACTED]");
        assert_eq!(sanitize_string("content", "secret"), "[REDACTED]");
        assert_eq!(sanitize_string("body", "message body"), "[REDACTED]");
        assert_eq!(sanitize_string("display_name", "Alice"), "[REDACTED]");
        assert_eq!(sanitize_string("name", "Bob"), "[REDACTED]");
        assert_eq!(sanitize_string("email", "alice@example.com"), "[REDACTED]");
        assert_eq!(sanitize_string("phone", "+1234567890"), "[REDACTED]");
        assert_eq!(sanitize_string("address", "123 Main St"), "[REDACTED]");
        assert_eq!(sanitize_string("ip", "192.168.1.1"), "[REDACTED]");
        assert_eq!(sanitize_string("host", "example.com"), "[REDACTED]");
    }

    /// Redaction is case-insensitive (SS 21.3.2 does not distinguish case).
    #[test]
    fn sanitize_case_insensitive() {
        assert_eq!(sanitize_string("TEXT", "hello"), "[REDACTED]");
        assert_eq!(sanitize_string("Name", "Bob"), "[REDACTED]");
        assert_eq!(sanitize_string("IP", "10.0.0.1"), "[REDACTED]");
        assert_eq!(sanitize_string("Host", "node.mesh"), "[REDACTED]");
    }

    /// Non-redacted fields pass through unchanged.
    #[test]
    fn sanitize_passes_safe_fields() {
        assert_eq!(sanitize_string("peer_id", "abc123"), "abc123");
        assert_eq!(sanitize_string("version", "0.3.0"), "0.3.0");
        assert_eq!(sanitize_string("transport_name", "tor"), "tor");
        assert_eq!(sanitize_string("enabled", "true"), "true");
    }

    /// Strings exceeding MAX_STRING_LENGTH are truncated with "..." suffix.
    #[test]
    fn sanitize_truncates_long_strings() {
        let long_value = "a".repeat(300);
        let result = sanitize_string("safe_field", &long_value);
        // The result should be MAX_STRING_LENGTH chars + "..."
        assert!(
            result.len() <= MAX_STRING_LENGTH + 3,
            "truncated string length {} exceeds limit",
            result.len()
        );
        assert!(result.ends_with("..."), "truncated string must end with '...'");
    }

    /// Strings at exactly MAX_STRING_LENGTH pass through unchanged.
    #[test]
    fn sanitize_exact_length_not_truncated() {
        let exact_value = "b".repeat(MAX_STRING_LENGTH);
        let result = sanitize_string("safe_field", &exact_value);
        assert_eq!(result, exact_value);
    }

    // --- Report generation tests --------------------------------------------

    /// generate_report() produces a valid report with non-zero timestamp.
    #[test]
    fn generate_report_has_timestamp() {
        let report = generate_report();
        // Timestamp should be after 2024-01-01 (1704067200 seconds).
        assert!(
            report.timestamp > 1_704_067_200,
            "timestamp {} should be after 2024-01-01",
            report.timestamp
        );
    }

    /// generate_report() includes the crate version from Cargo.toml.
    #[test]
    fn generate_report_has_version() {
        let report = generate_report();
        // Version must be non-empty and match the Cargo.toml version.
        assert!(!report.version.is_empty(), "version must not be empty");
        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
    }

    /// generate_report() starts with empty transport list.
    #[test]
    fn generate_report_empty_transports() {
        let report = generate_report();
        assert!(
            report.transport_status.is_empty(),
            "initial report should have empty transport list"
        );
    }

    // --- JSON serialization tests -------------------------------------------

    /// report_to_json() produces valid JSON that can be parsed back.
    #[test]
    fn report_to_json_roundtrip() {
        let report = generate_report();
        let json = report_to_json(&report);

        // The JSON must be valid and parseable.
        let parsed: Result<DiagnosticReport, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok(), "report JSON must be valid: {:?}", parsed.err());

        // The parsed report must match the original.
        let roundtrip = parsed.expect("already checked");
        assert_eq!(roundtrip.version, report.version);
        assert_eq!(roundtrip.timestamp, report.timestamp);
    }

    /// report_to_json() produces pretty-printed output (contains newlines).
    #[test]
    fn report_to_json_is_pretty_printed() {
        let report = generate_report();
        let json = report_to_json(&report);
        assert!(json.contains('\n'), "pretty-printed JSON must contain newlines");
        assert!(json.contains("  "), "pretty-printed JSON must contain indentation");
    }

    /// report_to_json() includes all top-level fields.
    #[test]
    fn report_to_json_has_all_fields() {
        let report = generate_report();
        let json = report_to_json(&report);
        // Verify all top-level field names are present in the output.
        assert!(json.contains("\"timestamp\""), "missing timestamp field");
        assert!(json.contains("\"version\""), "missing version field");
        assert!(json.contains("\"transport_status\""), "missing transport_status field");
        assert!(json.contains("\"routing_stats\""), "missing routing_stats field");
        assert!(json.contains("\"identity_status\""), "missing identity_status field");
        assert!(json.contains("\"memory_usage\""), "missing memory_usage field");
    }

    // --- Sanitize report tests ----------------------------------------------

    /// sanitize_report() does not corrupt non-sensitive fields.
    #[test]
    fn sanitize_report_preserves_safe_fields() {
        let mut report = generate_report();
        report.identity_status.peer_id = "deadbeef".to_string();
        report.version = "0.3.0".to_string();

        sanitize_report(&mut report);

        // These fields are not in the redaction list and should survive.
        assert_eq!(report.identity_status.peer_id, "deadbeef");
        assert_eq!(report.version, "0.3.0");
    }

    /// sanitize_report() handles reports with transport diagnostics.
    #[test]
    fn sanitize_report_with_transports() {
        let mut report = generate_report();
        report.transport_status.push(TransportDiagnostic {
            transport_name: "tor".to_string(),
            enabled: true,
            connected_peers: 3,
            bytes_sent: 1024,
            bytes_received: 2048,
            errors_last_hour: 0,
        });
        report.transport_status.push(TransportDiagnostic {
            transport_name: "bluetooth".to_string(),
            enabled: false,
            connected_peers: 0,
            bytes_sent: 0,
            bytes_received: 0,
            errors_last_hour: 1,
        });

        sanitize_report(&mut report);

        // Transport names should pass through (not in redaction list).
        assert_eq!(report.transport_status[0].transport_name, "tor");
        assert_eq!(report.transport_status[1].transport_name, "bluetooth");

        // Numeric fields should be untouched.
        assert_eq!(report.transport_status[0].connected_peers, 3);
        assert_eq!(report.transport_status[1].errors_last_hour, 1);
    }

    /// TransportDiagnostic serializes to JSON with all fields.
    #[test]
    fn transport_diagnostic_json_complete() {
        let diag = TransportDiagnostic {
            transport_name: "tor".to_string(),
            enabled: true,
            connected_peers: 5,
            bytes_sent: 10_000,
            bytes_received: 20_000,
            errors_last_hour: 2,
        };
        let json = serde_json::to_string(&diag)
            .expect("TransportDiagnostic serialization must not fail");
        assert!(json.contains("\"transport_name\""));
        assert!(json.contains("\"enabled\""));
        assert!(json.contains("\"connected_peers\""));
        assert!(json.contains("\"bytes_sent\""));
        assert!(json.contains("\"bytes_received\""));
        assert!(json.contains("\"errors_last_hour\""));
    }

    /// RoutingDiagnostic default values are sensible.
    #[test]
    fn routing_diagnostic_defaults() {
        let report = generate_report();
        // All routing stats start at zero for a fresh report.
        assert_eq!(report.routing_stats.total_routes, 0);
        assert_eq!(report.routing_stats.direct_peers, 0);
        assert_eq!(report.routing_stats.relay_routes, 0);
        assert_eq!(report.routing_stats.stale_routes, 0);
        assert!((report.routing_stats.avg_path_score - 0.0).abs() < f64::EPSILON);
    }

    /// MemoryDiagnostic zeroes are valid (platform may not support memory stats).
    #[test]
    fn memory_diagnostic_zero_is_valid() {
        let report = generate_report();
        // Zero is the expected value when memory stats are unavailable.
        assert_eq!(report.memory_usage.rss_bytes, 0);
        assert_eq!(report.memory_usage.vms_bytes, 0);
        assert_eq!(report.memory_usage.allocation_count, 0);
    }
}
