//! Clientless build-profile metadata.
//!
//! The clientless profile is not a feature flag fiction.  It is a concrete
//! binary target that runs the shared Rust backend without embedding Flutter.
//! This module keeps that contract in executable code so packaging, WebUI
//! status, and future installers can all report the same support matrix.

use serde_json::json;

/// Cargo binary name for the headless node.
pub const BINARY_NAME: &str = "mesh-infinity-clientless";

/// Stable release application/service identity.
pub const RELEASE_APP_ID: &str = "com.oniimediaworks.meshinfinity-clientless";

/// Stable debug application/service identity.
pub const DEBUG_APP_ID: &str = "com.oniimediaworks.meshinfinity-clientless-debug";

/// One supported host class for the clientless binary.
struct ClientlessTarget {
    /// Human-readable target family shown in diagnostics.
    family: &'static str,
    /// Representative Rust target triples for packaging/build scripts.
    triples: &'static [&'static str],
    /// Current support tier for this host family.
    support: &'static str,
    /// Practical deployment note for operators and package maintainers.
    note: &'static str,
}

const TARGETS: &[ClientlessTarget] = &[
    ClientlessTarget {
        family: "linux_server",
        triples: &["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"],
        support: "first_class",
        note: "Primary headless deployment target for servers, SBCs, and routers that can run a Linux userspace.",
    },
    ClientlessTarget {
        family: "linux_musl",
        triples: &["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"],
        support: "package_target",
        note: "Static-link packaging target for minimal Unix hosts where glibc is unavailable.",
    },
    ClientlessTarget {
        family: "android_node",
        triples: &["aarch64-linux-android", "armv7-linux-androideabi"],
        support: "native_service",
        note: "Android remains the primary platform focus; clientless behavior runs through the native startup and VPN services.",
    },
    ClientlessTarget {
        family: "desktop_tray",
        triples: &[
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        ],
        support: "incidental",
        note: "Supported when the operator wants a local WebUI and tray/shell wrapper instead of Flutter.",
    },
];

/// Return the current process target as reported by Rust compile-time cfgs.
pub fn current_target() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    {
        return "x86_64-unknown-linux-gnu";
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64", target_env = "gnu"))]
    {
        return "aarch64-unknown-linux-gnu";
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "musl"))]
    {
        return "x86_64-unknown-linux-musl";
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64", target_env = "musl"))]
    {
        return "aarch64-unknown-linux-musl";
    }
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    {
        return "aarch64-linux-android";
    }
    #[cfg(all(target_os = "android", target_arch = "arm"))]
    {
        return "armv7-linux-androideabi";
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return "x86_64-apple-darwin";
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return "aarch64-apple-darwin";
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return "x86_64-pc-windows-msvc";
    }
    #[allow(unreachable_code)]
    "unknown"
}

/// Structured profile contract returned by the WebUI API.
pub fn profile_json() -> serde_json::Value {
    json!({
        "binary": BINARY_NAME,
        "releaseAppId": RELEASE_APP_ID,
        "debugAppId": DEBUG_APP_ID,
        "currentTarget": current_target(),
        "usesFlutterUi": false,
        "usesSharedRustBackend": true,
        "requiresCloudServices": false,
        "localWebui": true,
        "meshControlPlaneWebui": false,
        "targets": TARGETS.iter().map(|target| {
            json!({
                "family": target.family,
                "triples": target.triples,
                "support": target.support,
                "note": target.note,
            })
        }).collect::<Vec<_>>(),
    })
}
