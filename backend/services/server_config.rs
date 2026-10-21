//! Protocol server configuration (§20.2–§20.8, edited by the §22.54.4–§22.54.9
//! screens).
//!
//! # What lives here
//!
//! The five Tier 4 servers this node can host — Remote Desktop (MNRDP),
//! Remote Shell (MNSP), File Access (MNFP), the API Gateway and Print
//! Services — each have a small block of operator settings that §20 already
//! defines: trust floors, adapters, user mappings, share roots, the upstream
//! URL and the IPP queue URLs.  This module holds the typed form of those
//! settings, their defaults, and the validation rules that the UI and the
//! backend share, so a value the screen accepts is never rejected here for a
//! format reason (§22.54.4 "Validation").
//!
//! # Trust boundary
//!
//! Every struct here is deserialised from JSON that arrives over the FFI
//! boundary.  Per `TESTING_METHODOLOGY.md` that is untrusted input: parsing
//! never panics, every limit is checked before the value is stored, and the
//! errors are typed (`ServerConfigError`) rather than stringly silent.
//!
//! # Hard floors
//!
//! §20 fixes a minimum trust level per protocol ("Server operator can raise
//! the floor; cannot lower it", §20.2.1).  Those floors are constants here and
//! enforced on every save, so no UI or JSON payload can ask the server to
//! admit a peer below what the protocol allows.
//!
//! # Host checks
//!
//! Some rules depend on the machine the server runs on: a mapped local user
//! must exist, a share root must be a readable directory, a starting folder
//! must exist.  Those checks go through the `HostProbe` trait so unit tests
//! can describe a host without touching the real filesystem, while
//! production uses `OsHostProbe`.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::services::mesh_protocols::{MeshApiAuthMode, MnfpAccess};

// ---------------------------------------------------------------------------
// Protocol floors and limits (§20, §22.54.5–§22.54.9)
// ---------------------------------------------------------------------------

/// Highest trust level in the §8.1 table (`InnerCircle`).
pub const TRUST_MAX: u8 = 8;
/// §20.2.1: view-only Remote Desktop needs at least `Acquaintance`.
pub const MNRDP_VIEW_FLOOR: u8 = 5;
/// §20.2.1: input, `AppStream` and `AppGallery` need at least `Trusted`.
pub const MNRDP_INPUT_FLOOR: u8 = 6;
/// §22.54.5: the simultaneous-session slider runs 1–8.
pub const MNRDP_MAX_SESSIONS: u8 = 8;
/// §20.3.1: shell access needs at least `Trusted`.
pub const MNSP_FLOOR: u8 = 6;
/// §20.4.1: file read access needs at least `Trusted`.
pub const MNFP_FLOOR: u8 = 6;
/// §20.4.1: file write access defaults to `HighlyTrusted`.
pub const MNFP_WRITE_DEFAULT: u8 = 7;
/// §20.5.1: the API gateway needs at least `Acquaintance`.
pub const API_GATEWAY_FLOOR: u8 = 5;
/// §22.54.8: the per-contact rate limit runs 1–100 000 requests per minute.
pub const API_GATEWAY_RATE_MAX: u32 = 100_000;
/// §20.8.1: printing needs at least `Acquaintance`.
pub const PRINT_FLOOR: u8 = 5;
/// §22.54.7 / §22.54.9: share and printer names are 1–64 characters.
pub const NAME_MAX_CHARS: usize = 64;
/// Upper bound on list lengths accepted over FFI, so a hostile payload cannot
/// make the vault record unbounded.  Far above any realistic configuration.
pub const LIST_MAX: usize = 256;
/// Upper bound on any single string accepted over FFI (paths, URLs, commands).
pub const STRING_MAX_BYTES: usize = 4096;
/// The HTTP methods the §22.54.8 chip set offers, in display order.
pub const HTTP_METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a configuration payload was refused.
///
/// `field` names the offending field in the same `snake_case` the JSON uses,
/// so the UI can highlight it; `reason` is the plain-language inline text the
/// §22.54 tables prescribe.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ServerConfigError {
    /// The JSON could not be parsed into the expected shape.
    #[error("malformed configuration: {0}")]
    Malformed(String),
    /// A field holds a value outside its documented range or rule.
    #[error("{field}: {reason}")]
    Invalid {
        /// Field path such as `shares[2].root_path`.
        field: String,
        /// Plain-language reason shown next to the field.
        reason: String,
    },
}

impl ServerConfigError {
    /// Build an `Invalid` error from borrowed parts.
    fn invalid(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Host probe — environment facts the validators need
// ---------------------------------------------------------------------------

/// Facts about the machine that configuration rules depend on.
///
/// Production code uses [`OsHostProbe`]; tests supply a fake so the rules can
/// be exercised without real users, shells or directories.
pub trait HostProbe {
    /// Whether `name` is a login account on this machine.
    fn user_exists(&self, name: &str) -> bool;
    /// Whether `path` exists and is a directory.
    fn is_dir(&self, path: &str) -> bool;
    /// Whether the app can list `path` (readability for share roots).
    fn dir_readable(&self, path: &str) -> bool;
    /// The app's own data directory, which must never be shared (§20.4.1).
    fn data_dir(&self) -> PathBuf;
    /// The machine's own hostname, if it can be determined without DNS.
    fn hostname(&self) -> Option<String>;
}

/// `HostProbe` backed by the real operating system.
pub struct OsHostProbe {
    /// The runtime's data directory (vault files live under it).
    pub data_dir: PathBuf,
}

impl HostProbe for OsHostProbe {
    fn user_exists(&self, name: &str) -> bool {
        local_user_exists(name)
    }

    fn is_dir(&self, path: &str) -> bool {
        Path::new(path).is_dir()
    }

    fn dir_readable(&self, path: &str) -> bool {
        // `read_dir` is the operation MNFP `List` performs, so success here
        // is exactly the readability the share needs.
        std::fs::read_dir(path).is_ok()
    }

    fn data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    fn hostname(&self) -> Option<String> {
        local_hostname()
    }
}

/// Whether `name` is a local login account.
///
/// Unix reads `/etc/passwd`, which is world-readable by design; Windows has
/// no equivalent text database without extra crates, so it accepts the
/// signed-in account and any account with a profile folder under
/// `%SystemDrive%\Users`.  Both checks are real lookups, not assumptions.
pub fn local_user_exists(name: &str) -> bool {
    if name.is_empty() || name.contains(['/', '\\', ':', '\0']) {
        return false;
    }
    if cfg!(target_os = "windows") {
        // The signed-in account is always valid.
        if std::env::var("USERNAME").map(|u| u.eq_ignore_ascii_case(name)) == Ok(true) {
            return true;
        }
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        return Path::new(&format!("{drive}\\Users\\{name}")).is_dir();
    }
    // Unix family: Android and iOS have no passwd file for app users, so the
    // signed-in name from the environment is the only valid mapping there.
    if std::env::var("USER").map(|u| u == name) == Ok(true) {
        return true;
    }
    std::fs::read_to_string("/etc/passwd")
        .map(|db| db.lines().any(|line| line.split(':').next() == Some(name)))
        .unwrap_or(false)
}

/// The machine's hostname from the environment or `/etc/hostname`, without
/// any DNS lookup (a lookup would leak the name to the resolver).
pub fn local_hostname() -> Option<String> {
    let from_env = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty());
    if from_env.is_some() {
        return from_env;
    }
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
}

/// Shells available on this machine, in the order the OS lists them.
///
/// Unix reads `/etc/shells`; Windows reports the interpreters that exist in
/// `System32` plus `pwsh` when it is on the `PATH`.  The result feeds the
/// §22.54.6 "Allowed shells" multi-select.
pub fn local_shells() -> Vec<String> {
    if cfg!(target_os = "windows") {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let mut shells = Vec::new();
        for exe in ["cmd.exe", "WindowsPowerShell\\v1.0\\powershell.exe"] {
            let path = format!("{root}\\System32\\{exe}");
            if Path::new(&path).is_file() {
                shells.push(path);
            }
        }
        if let Some(pwsh) = find_on_path("pwsh.exe") {
            shells.push(pwsh);
        }
        return shells;
    }
    std::fs::read_to_string("/etc/shells")
        .map(|db| {
            db.lines()
                .map(str::trim)
                .filter(|l| l.starts_with('/') && Path::new(l).is_file())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Login accounts a shell grant may map to, for the §22.54.6 sheet's inline
/// "No local account called <name>" check.
///
/// Unix lists `/etc/passwd` entries with a real login shell and a regular
/// user ID (≥ 1000, or the signed-in user); Windows lists the profile
/// folders under `%SystemDrive%\Users` minus the system templates.  The
/// signed-in account is always included.  The backend still re-checks on
/// save with `local_user_exists`, so this list only drives the UI.
pub fn local_users() -> Vec<String> {
    let mut users = Vec::new();
    let (me, _) = local_user_and_home();
    if !me.is_empty() {
        users.push(me.clone());
    }
    if cfg!(target_os = "windows") {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        if let Ok(entries) = std::fs::read_dir(format!("{drive}\\Users")) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let system = matches!(
                    name.as_str(),
                    "Public" | "Default" | "Default User" | "All Users"
                ) || name.starts_with("defaultuser");
                if !system
                    && entry.path().is_dir()
                    && !users.iter().any(|u| u.eq_ignore_ascii_case(&name))
                {
                    users.push(name);
                }
            }
        }
        return users;
    }
    if let Ok(db) = std::fs::read_to_string("/etc/passwd") {
        for line in db.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            let (Some(name), Some(uid), Some(shell)) =
                (fields.first(), fields.get(2), fields.get(6))
            else {
                continue;
            };
            let regular = uid.parse::<u32>().map(|u| u >= 1000).unwrap_or(false);
            let can_login =
                !shell.ends_with("nologin") && !shell.ends_with("/false") && !shell.is_empty();
            if regular && can_login && !users.iter().any(|u| u == name) {
                users.push((*name).to_string());
            }
        }
    }
    users
}

/// Locate `exe` on the `PATH`, returning its full path when found.
fn find_on_path(exe: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(exe))
        .find(|candidate| candidate.is_file())
        .map(|p| p.to_string_lossy().into_owned())
}

/// The signed-in OS user and their home directory, for the §22.54.6 sheet
/// defaults ("the app's own OS user" / "the local account's home").
pub fn local_user_and_home() -> (String, String) {
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    let home = dirs_next::home_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    (user, home)
}

// ---------------------------------------------------------------------------
// Shared field validators
// ---------------------------------------------------------------------------

/// Check a trust floor against its protocol minimum and the §8.1 maximum.
fn check_floor(field: &str, value: u8, floor: u8, protocol: &str) -> Result<(), ServerConfigError> {
    if value < floor {
        return Err(ServerConfigError::invalid(
            field,
            format!("{protocol} never allows below Level {floor}"),
        ));
    }
    if value > TRUST_MAX {
        return Err(ServerConfigError::invalid(
            field,
            format!("Trust levels go up to Level {TRUST_MAX}"),
        ));
    }
    Ok(())
}

/// Check a display name for the 1–64 character rule shared by shares and
/// printers, trimming surrounding whitespace first.
fn check_name(field: &str, name: &str) -> Result<(), ServerConfigError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ServerConfigError::invalid(field, "Enter a name"));
    }
    if trimmed.chars().count() > NAME_MAX_CHARS {
        return Err(ServerConfigError::invalid(
            field,
            format!("Names are at most {NAME_MAX_CHARS} characters"),
        ));
    }
    // Control characters would corrupt the advertised ServiceRecord metadata.
    if trimmed.chars().any(char::is_control) {
        return Err(ServerConfigError::invalid(
            field,
            "Names can't contain control characters",
        ));
    }
    Ok(())
}

/// Reject strings that could not have come from the UI: oversized or
/// containing NUL (which would truncate the value at the C boundary).
fn check_string(field: &str, value: &str) -> Result<(), ServerConfigError> {
    if value.len() > STRING_MAX_BYTES {
        return Err(ServerConfigError::invalid(field, "Value is too long"));
    }
    if value.contains('\0') {
        return Err(ServerConfigError::invalid(
            field,
            "Value contains an invalid character",
        ));
    }
    Ok(())
}

/// Reject lists longer than the FFI bound.
fn check_len<T>(field: &str, list: &[T]) -> Result<(), ServerConfigError> {
    if list.len() > LIST_MAX {
        return Err(ServerConfigError::invalid(
            field,
            format!("At most {LIST_MAX} entries are supported"),
        ));
    }
    Ok(())
}

/// Check a peer ID: lowercase hex, 64 characters (a 32-byte Ed25519-derived
/// identifier rendered the way the rest of the FFI surface renders it).
fn check_peer_id(field: &str, peer_id: &str) -> Result<(), ServerConfigError> {
    let ok = peer_id.len() == 64 && peer_id.bytes().all(|b| b.is_ascii_hexdigit());
    if !ok {
        return Err(ServerConfigError::invalid(field, "Not a valid contact ID"));
    }
    Ok(())
}

/// Split `url` into (scheme, host, port, path) without any resolution.
///
/// Accepts `scheme://host[:port][/path]` with IPv6 hosts in brackets.
/// Returns `None` for anything that does not have that shape.
pub fn split_url(url: &str) -> Option<(String, String, Option<u16>, String)> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // Userinfo is never meaningful for a local upstream; refuse it outright
    // rather than silently forwarding credentials.
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']')?;
        let host = &stripped[..end];
        let after = &stripped[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p != 0)?),
            None if after.is_empty() => None,
            None => return None,
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                Some(p.parse::<u16>().ok().filter(|p| *p != 0)?),
            ),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme.to_ascii_lowercase(), host, port, path.to_string()))
}

/// Whether `host` names this machine without consulting DNS: a loopback
/// literal, `localhost` and its subdomains, or the machine's own hostname.
pub fn is_local_host(host: &str, hostname: Option<&str>) -> bool {
    let lower = host.to_ascii_lowercase();
    if let Ok(ip) = lower.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    if lower == "localhost" || lower.ends_with(".localhost") || lower == "localhost.localdomain" {
        return true;
    }
    match hostname {
        Some(own) => lower == own.to_ascii_lowercase(),
        None => false,
    }
}

/// Whether `host` is on the local network: loopback, RFC 1918, link-local,
/// unique-local IPv6, or an mDNS/LAN name (`.local`, `.lan`, `.home`, or a
/// single label).  Public addresses and public domain names are refused so
/// the print adapter cannot be aimed at the internet (§22.54.9).
pub fn is_lan_host(host: &str, hostname: Option<&str>) -> bool {
    if is_local_host(host, hostname) {
        return true;
    }
    let lower = host.to_ascii_lowercase();
    if let Ok(ip) = lower.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                // fc00::/7 unique-local and fe80::/10 link-local.
                let first = v6.segments()[0];
                (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
            }
        };
    }
    if lower.is_empty() || lower.contains(['/', '\\', ' ']) {
        return false;
    }
    !lower.contains('.')
        || lower.ends_with(".local")
        || lower.ends_with(".lan")
        || lower.ends_with(".home")
        || lower.ends_with(".internal")
}

// ---------------------------------------------------------------------------
// MNRDP — Remote Desktop (§20.2, §22.54.5)
// ---------------------------------------------------------------------------

/// Operator settings for the Remote Desktop server.
///
/// `enabled` is not here: the on/off switch is `ModuleConfig.protocols
/// .mnrdp_server` (§17.13), toggled from the Hosting list, so the module flag
/// stays the single source of truth for whether the server runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MnrdpServerConfig {
    /// Lowest level allowed to connect in view-only mode (≥ 5).
    pub view_floor: u8,
    /// Lowest level allowed input, `AppStream` and `AppGallery` (≥ 6, ≥ view).
    pub input_floor: u8,
    /// Offer `FullDesktop` sessions.
    pub full_desktop: bool,
    /// Offer `AppStream` sessions.
    pub app_stream: bool,
    /// Offer `AppGallery` sessions.
    pub app_gallery: bool,
    /// Bridge the VNC adapter (§20.2.3).
    pub vnc_adapter: bool,
    /// Bridge the NX adapter (§20.2.4).
    pub nx_adapter: bool,
    /// Bridge the Apple Remote Desktop adapter (§20.2.5, macOS only).
    pub ard_adapter: bool,
    /// Simultaneous sessions allowed, 1–8.
    pub max_sessions: u8,
}

impl Default for MnrdpServerConfig {
    fn default() -> Self {
        Self {
            view_floor: MNRDP_VIEW_FLOOR,
            input_floor: MNRDP_INPUT_FLOOR,
            full_desktop: true,
            app_stream: true,
            app_gallery: true,
            vnc_adapter: false,
            nx_adapter: false,
            ard_adapter: false,
            max_sessions: 2,
        }
    }
}

impl MnrdpServerConfig {
    /// Apply the §22.54.5 rules.
    pub fn validate(&self) -> Result<(), ServerConfigError> {
        check_floor(
            "view_floor",
            self.view_floor,
            MNRDP_VIEW_FLOOR,
            "Remote Desktop",
        )?;
        check_floor(
            "input_floor",
            self.input_floor,
            MNRDP_INPUT_FLOOR,
            "Remote Desktop",
        )?;
        if self.input_floor < self.view_floor {
            return Err(ServerConfigError::invalid(
                "input_floor",
                "Must be at least the view-only level",
            ));
        }
        if !(self.full_desktop || self.app_stream || self.app_gallery) {
            return Err(ServerConfigError::invalid(
                "full_desktop",
                "Keep at least one mode on, or turn Remote Desktop off",
            ));
        }
        if self.max_sessions == 0 || self.max_sessions > MNRDP_MAX_SESSIONS {
            return Err(ServerConfigError::invalid(
                "max_sessions",
                format!("Choose between 1 and {MNRDP_MAX_SESSIONS} sessions"),
            ));
        }
        // ARD exists only on macOS (§20.2.5); refusing it elsewhere keeps a
        // stale vault from re-enabling an adapter the platform cannot run.
        if self.ard_adapter && !cfg!(target_os = "macos") {
            return Err(ServerConfigError::invalid(
                "ard_adapter",
                "Apple Remote Desktop is only available on macOS",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MNSP — Remote Shell (§20.3, §22.54.6)
// ---------------------------------------------------------------------------

/// One `mnsp_user_map` row (§20.3.1): the explicit `can_remote_shell` grant
/// for a peer and the OS account it lands in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MnspUserMapping {
    /// Hex mesh peer ID of the contact.
    pub peer_id: String,
    /// Display name captured when the grant was made, for the row label.
    #[serde(default)]
    pub display_name: String,
    /// Local OS account the session runs as.
    pub local_user: String,
    /// Shells the peer may request; at least one.
    pub allowed_shells: Vec<String>,
    /// `None` = any command; `Some(list)` = command allowlist.
    #[serde(default)]
    pub allowed_commands: Option<Vec<String>>,
    /// Starting folder for the session.
    pub working_dir: String,
}

/// Operator settings for the Remote Shell server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MnspServerConfig {
    /// Lowest level that may hold a shell grant (≥ 6).
    pub trust_floor: u8,
    /// Explicit per-peer grants; empty means nobody can connect.
    pub user_map: Vec<MnspUserMapping>,
    /// Forward mesh connections to the local sshd (§20.3.2).
    pub ssh_adapter: bool,
    /// Local sshd port, 1–65535.
    pub sshd_port: u16,
}

impl Default for MnspServerConfig {
    fn default() -> Self {
        Self {
            trust_floor: MNSP_FLOOR,
            user_map: Vec::new(),
            ssh_adapter: false,
            sshd_port: 22,
        }
    }
}

impl MnspServerConfig {
    /// Apply the §22.54.6 rules against `host`.
    pub fn validate(&self, host: &dyn HostProbe) -> Result<(), ServerConfigError> {
        check_floor("trust_floor", self.trust_floor, MNSP_FLOOR, "Remote Shell")?;
        if self.sshd_port == 0 {
            return Err(ServerConfigError::invalid(
                "sshd_port",
                "Enter a port from 1 to 65535",
            ));
        }
        check_len("user_map", &self.user_map)?;
        let mut seen = BTreeSet::new();
        for (i, m) in self.user_map.iter().enumerate() {
            let f = |name: &str| format!("user_map[{i}].{name}");
            check_peer_id(&f("peer_id"), &m.peer_id)?;
            if !seen.insert(m.peer_id.clone()) {
                return Err(ServerConfigError::invalid(
                    f("peer_id"),
                    "This person is already in the list",
                ));
            }
            check_string(&f("display_name"), &m.display_name)?;
            check_string(&f("local_user"), &m.local_user)?;
            if !host.user_exists(&m.local_user) {
                return Err(ServerConfigError::invalid(
                    f("local_user"),
                    format!("No local account called {}", m.local_user),
                ));
            }
            check_len(&f("allowed_shells"), &m.allowed_shells)?;
            if m.allowed_shells.is_empty() {
                return Err(ServerConfigError::invalid(
                    f("allowed_shells"),
                    "Choose at least one shell",
                ));
            }
            for shell in &m.allowed_shells {
                check_string(&f("allowed_shells"), shell)?;
                if shell.trim().is_empty() {
                    return Err(ServerConfigError::invalid(
                        f("allowed_shells"),
                        "Shell paths can't be empty",
                    ));
                }
            }
            if let Some(commands) = &m.allowed_commands {
                check_len(&f("allowed_commands"), commands)?;
                for command in commands {
                    check_string(&f("allowed_commands"), command)?;
                    if command.trim().is_empty() {
                        return Err(ServerConfigError::invalid(
                            f("allowed_commands"),
                            "Each command line must have a command",
                        ));
                    }
                }
            }
            check_string(&f("working_dir"), &m.working_dir)?;
            if !host.is_dir(&m.working_dir) {
                return Err(ServerConfigError::invalid(
                    f("working_dir"),
                    "That folder doesn't exist",
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MNFP — File Access (§20.4, §22.54.7)
// ---------------------------------------------------------------------------

/// A per-contact exception on a share (§20.4.1 `peer_overrides`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MnfpPeerOverride {
    /// Hex mesh peer ID of the contact.
    pub peer_id: String,
    /// Display name captured when the override was made.
    #[serde(default)]
    pub display_name: String,
    /// Access this contact gets instead of the share's access.
    pub access: MnfpAccess,
}

/// One `mnfp_share` entry (§20.4.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MnfpShare {
    /// Share name, 1–64 characters, unique among shares.
    pub name: String,
    /// Absolute directory on this machine.
    pub root_path: String,
    /// Maximum access granted; clients may request lower.
    pub access: MnfpAccess,
    /// Lowest level for read access (≥ 6).
    pub min_trust_level: u8,
    /// Lowest level for write access (≥ read floor).
    #[serde(default = "default_write_floor")]
    pub write_trust_level: u8,
    /// Per-contact exceptions.
    #[serde(default)]
    pub peer_overrides: Vec<MnfpPeerOverride>,
    /// Not advertised in the `ServiceRecord`; reachable by name only.
    #[serde(default)]
    pub hidden: bool,
}

/// Serde default for `write_trust_level`.
fn default_write_floor() -> u8 {
    MNFP_WRITE_DEFAULT
}

/// Operator settings for the File Access server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MnfpServerConfig {
    /// Shared folders.
    pub shares: Vec<MnfpShare>,
    /// Bridge the SMB adapter (§20.4.2).
    pub smb_adapter: bool,
    /// Bridge the NFS adapter (§20.4.3).
    pub nfs_adapter: bool,
    /// SFTP rides the SSH adapter (§20.4.4); needs MNSP `ssh_adapter`.
    pub sftp_via_ssh: bool,
}

impl MnfpServerConfig {
    /// Apply the §22.54.7 rules against `host`.  `ssh_adapter_on` is the
    /// MNSP setting the SFTP switch depends on.
    pub fn validate(
        &self,
        host: &dyn HostProbe,
        ssh_adapter_on: bool,
    ) -> Result<(), ServerConfigError> {
        if self.sftp_via_ssh && !ssh_adapter_on {
            return Err(ServerConfigError::invalid(
                "sftp_via_ssh",
                "Turn on the SSH adapter in Remote Shell first",
            ));
        }
        check_len("shares", &self.shares)?;
        let data_dir = host.data_dir();
        let mut names = BTreeSet::new();
        for (i, share) in self.shares.iter().enumerate() {
            let f = |name: &str| format!("shares[{i}].{name}");
            check_name(&f("name"), &share.name)?;
            let key = share.name.trim().to_lowercase();
            if !names.insert(key) {
                return Err(ServerConfigError::invalid(
                    f("name"),
                    format!("You already have a share called {}", share.name.trim()),
                ));
            }
            check_string(&f("root_path"), &share.root_path)?;
            if share.root_path.trim().is_empty() {
                return Err(ServerConfigError::invalid(
                    f("root_path"),
                    "Choose a folder",
                ));
            }
            if !host.is_dir(&share.root_path) {
                return Err(ServerConfigError::invalid(
                    f("root_path"),
                    "That folder doesn't exist",
                ));
            }
            if !host.dir_readable(&share.root_path) {
                return Err(ServerConfigError::invalid(
                    f("root_path"),
                    "Mesh Infinity can't read that folder",
                ));
            }
            if overlaps_data_dir(Path::new(&share.root_path), &data_dir) {
                return Err(ServerConfigError::invalid(
                    f("root_path"),
                    "Mesh Infinity can't share its own data folder",
                ));
            }
            check_floor(
                &f("min_trust_level"),
                share.min_trust_level,
                MNFP_FLOOR,
                "File Access",
            )?;
            check_floor(
                &f("write_trust_level"),
                share.write_trust_level,
                MNFP_FLOOR,
                "File Access",
            )?;
            if share.write_trust_level < share.min_trust_level {
                return Err(ServerConfigError::invalid(
                    f("write_trust_level"),
                    "Must be at least the read level",
                ));
            }
            check_len(&f("peer_overrides"), &share.peer_overrides)?;
            let mut peers = BTreeSet::new();
            for (j, o) in share.peer_overrides.iter().enumerate() {
                let field = format!("shares[{i}].peer_overrides[{j}].peer_id");
                check_peer_id(&field, &o.peer_id)?;
                check_string(&field, &o.display_name)?;
                if !peers.insert(o.peer_id.clone()) {
                    return Err(ServerConfigError::invalid(
                        field,
                        "This person already has an exception",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Whether `root` is the data directory, contains it, or sits inside it.
///
/// Both paths are canonicalised when they exist so symlinks and `..`
/// segments cannot smuggle the vault into a share.
fn overlaps_data_dir(root: &Path, data_dir: &Path) -> bool {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let data = data_dir
        .canonicalize()
        .unwrap_or_else(|_| data_dir.to_path_buf());
    root.starts_with(&data) || data.starts_with(&root)
}

// ---------------------------------------------------------------------------
// API Gateway (§20.5, §22.54.8)
// ---------------------------------------------------------------------------

/// The `http_gateway` block (§20.5.1), shared by gRPC and WebSocket.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiGatewayConfig {
    /// Local service the gateway forwards to.
    pub upstream_url: String,
    /// Lowest level allowed through the gateway (≥ 5).
    pub min_trust_level: u8,
    /// What the upstream receives to identify the peer.
    pub auth_mode: MeshApiAuthMode,
    /// Requests per minute per peer; `None` = unlimited.
    pub rate_limit: Option<u32>,
    /// Methods allowed through; `None` = all.
    pub allowed_methods: Option<Vec<String>>,
    /// Only forward paths starting with this prefix; `None` = all paths.
    pub path_prefix: Option<String>,
}

impl Default for ApiGatewayConfig {
    fn default() -> Self {
        Self {
            upstream_url: "http://127.0.0.1:8080".to_string(),
            min_trust_level: API_GATEWAY_FLOOR,
            auth_mode: MeshApiAuthMode::None,
            rate_limit: None,
            allowed_methods: None,
            path_prefix: None,
        }
    }
}

impl ApiGatewayConfig {
    /// Apply the §22.54.8 rules against `host`.
    pub fn validate(&self, host: &dyn HostProbe) -> Result<(), ServerConfigError> {
        check_string("upstream_url", &self.upstream_url)?;
        let (scheme, url_host, _, _) = split_url(self.upstream_url.trim()).ok_or_else(|| {
            ServerConfigError::invalid(
                "upstream_url",
                "Enter an address like http://127.0.0.1:8080",
            )
        })?;
        if scheme != "http" && scheme != "https" {
            return Err(ServerConfigError::invalid(
                "upstream_url",
                "The address must start with http:// or https://",
            ));
        }
        let hostname = host.hostname();
        if !is_local_host(&url_host, hostname.as_deref()) {
            return Err(ServerConfigError::invalid(
                "upstream_url",
                "The gateway only forwards to services on this device",
            ));
        }
        check_floor(
            "min_trust_level",
            self.min_trust_level,
            API_GATEWAY_FLOOR,
            "The API Gateway",
        )?;
        if let Some(limit) = self.rate_limit {
            if limit == 0 || limit > API_GATEWAY_RATE_MAX {
                return Err(ServerConfigError::invalid(
                    "rate_limit",
                    "Enter a number from 1 to 100 000",
                ));
            }
        }
        if let Some(methods) = &self.allowed_methods {
            check_len("allowed_methods", methods)?;
            if methods.is_empty() {
                return Err(ServerConfigError::invalid(
                    "allowed_methods",
                    "Allow at least one method",
                ));
            }
            for method in methods {
                if !HTTP_METHODS.contains(&method.as_str()) {
                    return Err(ServerConfigError::invalid(
                        "allowed_methods",
                        format!("{method} is not a supported method"),
                    ));
                }
            }
        }
        if let Some(prefix) = &self.path_prefix {
            check_string("path_prefix", prefix)?;
            if !prefix.starts_with('/') {
                return Err(ServerConfigError::invalid(
                    "path_prefix",
                    "The prefix must start with /",
                ));
            }
            if prefix.split('/').any(|seg| seg == "..") {
                return Err(ServerConfigError::invalid(
                    "path_prefix",
                    "The prefix can't contain ..",
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Print Services (§20.8, §22.54.9)
// ---------------------------------------------------------------------------

/// One `ipp_adapter` entry (§20.8.1): a shared printer queue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedPrinter {
    /// IPP queue URL on this machine or the local network.
    pub ipp_url: String,
    /// Name shown to contacts, 1–64 characters.
    pub printer_name: String,
    /// Lowest level allowed to print (≥ 5).
    pub min_trust_level: u8,
    /// Capability tags discovered from the queue (`duplex`, `color`, sizes).
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Operator settings for Print Services.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PrintServiceConfig {
    /// Shared printers.
    pub printers: Vec<SharedPrinter>,
}

impl PrintServiceConfig {
    /// Apply the §22.54.9 rules against `host`.
    pub fn validate(&self, host: &dyn HostProbe) -> Result<(), ServerConfigError> {
        check_len("printers", &self.printers)?;
        let hostname = host.hostname();
        let mut urls = BTreeSet::new();
        for (i, p) in self.printers.iter().enumerate() {
            let f = |name: &str| format!("printers[{i}].{name}");
            check_string(&f("ipp_url"), &p.ipp_url)?;
            let (scheme, url_host, _, _) = split_url(p.ipp_url.trim()).ok_or_else(|| {
                ServerConfigError::invalid(
                    f("ipp_url"),
                    "Enter an address like ipp://127.0.0.1:631/printers/office",
                )
            })?;
            if !matches!(scheme.as_str(), "ipp" | "ipps" | "http" | "https") {
                return Err(ServerConfigError::invalid(
                    f("ipp_url"),
                    "The address must start with ipp://, ipps://, http:// or https://",
                ));
            }
            if !is_lan_host(&url_host, hostname.as_deref()) {
                return Err(ServerConfigError::invalid(
                    f("ipp_url"),
                    "Only printers on this device or your local network can be shared",
                ));
            }
            if !urls.insert(p.ipp_url.trim().to_lowercase()) {
                return Err(ServerConfigError::invalid(
                    f("ipp_url"),
                    "This printer is already shared",
                ));
            }
            check_name(&f("printer_name"), &p.printer_name)?;
            check_floor(
                &f("min_trust_level"),
                p.min_trust_level,
                PRINT_FLOOR,
                "Print Services",
            )?;
            check_len(&f("capabilities"), &p.capabilities)?;
            for cap in &p.capabilities {
                check_string(&f("capabilities"), cap)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Persisted bundle
// ---------------------------------------------------------------------------

/// All five server configurations, persisted together in `settings.vault`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ProtocolServerConfig {
    /// Remote Desktop (§20.2).
    pub mnrdp: MnrdpServerConfig,
    /// Remote Shell (§20.3).
    pub mnsp: MnspServerConfig,
    /// File Access (§20.4).
    pub mnfp: MnfpServerConfig,
    /// API Gateway (§20.5).
    pub api_gateway: ApiGatewayConfig,
    /// Print Services (§20.8).
    pub print: PrintServiceConfig,
}

/// Parse one configuration block from FFI JSON with a typed error.
pub fn parse_config<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, ServerConfigError> {
    if json.len() > STRING_MAX_BYTES * LIST_MAX {
        return Err(ServerConfigError::Malformed(
            "payload too large".to_string(),
        ));
    }
    serde_json::from_str(json).map_err(|e| ServerConfigError::Malformed(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A host with one user, two directories and a known data directory.
    struct FakeHost;

    impl HostProbe for FakeHost {
        fn user_exists(&self, name: &str) -> bool {
            name == "alice"
        }
        fn is_dir(&self, path: &str) -> bool {
            matches!(
                path,
                "/home/alice" | "/srv/share" | "/data/mesh" | "/data/mesh/vault" | "/data"
            )
        }
        fn dir_readable(&self, path: &str) -> bool {
            path != "/srv/share/locked" && self.is_dir(path)
        }
        fn data_dir(&self) -> PathBuf {
            PathBuf::from("/data/mesh")
        }
        fn hostname(&self) -> Option<String> {
            Some("workstation".to_string())
        }
    }

    fn peer(n: u8) -> String {
        format!("{:02x}", n).repeat(32)
    }

    fn field_of(err: ServerConfigError) -> String {
        match err {
            ServerConfigError::Invalid { field, .. } => field,
            ServerConfigError::Malformed(m) => panic!("unexpected malformed: {m}"),
        }
    }

    // ---- MNRDP ----

    #[test]
    fn mnrdp_defaults_are_valid_and_round_trip() {
        let cfg = MnrdpServerConfig::default();
        assert!(cfg.validate().is_ok());
        let json = serde_json::to_string(&cfg).unwrap();
        let back: MnrdpServerConfig = parse_config(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn mnrdp_cannot_lower_floors_below_protocol() {
        let cfg = MnrdpServerConfig {
            view_floor: 4,
            ..Default::default()
        };
        assert_eq!(field_of(cfg.validate().unwrap_err()), "view_floor");
        let cfg = MnrdpServerConfig {
            input_floor: 5,
            ..Default::default()
        };
        assert_eq!(field_of(cfg.validate().unwrap_err()), "input_floor");
    }

    #[test]
    fn mnrdp_input_floor_at_least_view_floor() {
        let cfg = MnrdpServerConfig {
            view_floor: 7,
            input_floor: 6,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert_eq!(
            err,
            ServerConfigError::invalid("input_floor", "Must be at least the view-only level")
        );
    }

    #[test]
    fn mnrdp_needs_one_mode_and_bounded_sessions() {
        let cfg = MnrdpServerConfig {
            full_desktop: false,
            app_stream: false,
            app_gallery: false,
            ..Default::default()
        };
        assert_eq!(field_of(cfg.validate().unwrap_err()), "full_desktop");
        for sessions in [0u8, 9, 255] {
            let cfg = MnrdpServerConfig {
                max_sessions: sessions,
                ..Default::default()
            };
            assert_eq!(field_of(cfg.validate().unwrap_err()), "max_sessions");
        }
    }

    #[test]
    fn mnrdp_level_above_max_is_refused() {
        let cfg = MnrdpServerConfig {
            view_floor: 9,
            input_floor: 9,
            ..Default::default()
        };
        assert_eq!(field_of(cfg.validate().unwrap_err()), "view_floor");
    }

    // ---- MNSP ----

    fn mapping() -> MnspUserMapping {
        MnspUserMapping {
            peer_id: peer(1),
            display_name: "Alice".to_string(),
            local_user: "alice".to_string(),
            allowed_shells: vec!["/bin/bash".to_string()],
            allowed_commands: None,
            working_dir: "/home/alice".to_string(),
        }
    }

    #[test]
    fn mnsp_defaults_mean_nobody_can_connect() {
        let cfg = MnspServerConfig::default();
        assert!(cfg.user_map.is_empty());
        assert!(cfg.validate(&FakeHost).is_ok());
    }

    #[test]
    fn mnsp_valid_mapping_round_trips() {
        let cfg = MnspServerConfig {
            user_map: vec![mapping()],
            ..Default::default()
        };
        assert!(cfg.validate(&FakeHost).is_ok());
        let json = serde_json::to_string(&cfg).unwrap();
        let back: MnspServerConfig = parse_config(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn mnsp_rejects_unknown_user_missing_dir_and_bad_peer() {
        let cfg = MnspServerConfig {
            user_map: vec![MnspUserMapping {
                local_user: "mallory".into(),
                ..mapping()
            }],
            ..Default::default()
        };
        assert_eq!(
            cfg.validate(&FakeHost).unwrap_err(),
            ServerConfigError::invalid("user_map[0].local_user", "No local account called mallory")
        );
        let cfg = MnspServerConfig {
            user_map: vec![MnspUserMapping {
                working_dir: "/nowhere".into(),
                ..mapping()
            }],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "user_map[0].working_dir"
        );
        let cfg = MnspServerConfig {
            user_map: vec![MnspUserMapping {
                peer_id: "zz".into(),
                ..mapping()
            }],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "user_map[0].peer_id"
        );
    }

    #[test]
    fn mnsp_rejects_duplicates_empty_shells_and_blank_commands() {
        let cfg = MnspServerConfig {
            user_map: vec![mapping(), mapping()],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "user_map[1].peer_id"
        );
        let cfg = MnspServerConfig {
            user_map: vec![MnspUserMapping {
                allowed_shells: vec![],
                ..mapping()
            }],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "user_map[0].allowed_shells"
        );
        let cfg = MnspServerConfig {
            user_map: vec![MnspUserMapping {
                allowed_commands: Some(vec!["ls".into(), "  ".into()]),
                ..mapping()
            }],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "user_map[0].allowed_commands"
        );
    }

    #[test]
    fn mnsp_floor_and_port_bounds() {
        let cfg = MnspServerConfig {
            trust_floor: 5,
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "trust_floor"
        );
        let cfg = MnspServerConfig {
            sshd_port: 0,
            ..Default::default()
        };
        assert_eq!(field_of(cfg.validate(&FakeHost).unwrap_err()), "sshd_port");
    }

    #[test]
    fn mnsp_list_bound_is_enforced() {
        let cfg = MnspServerConfig {
            user_map: (0..=LIST_MAX)
                .map(|i| MnspUserMapping {
                    peer_id: format!("{i:064x}"),
                    ..mapping()
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(field_of(cfg.validate(&FakeHost).unwrap_err()), "user_map");
    }

    // ---- MNFP ----

    fn share() -> MnfpShare {
        MnfpShare {
            name: "documents".to_string(),
            root_path: "/srv/share".to_string(),
            access: MnfpAccess::ReadOnly,
            min_trust_level: 6,
            write_trust_level: 7,
            peer_overrides: vec![],
            hidden: false,
        }
    }

    #[test]
    fn mnfp_valid_share_round_trips() {
        let cfg = MnfpServerConfig {
            shares: vec![share()],
            ..Default::default()
        };
        assert!(cfg.validate(&FakeHost, false).is_ok());
        let json = serde_json::to_string(&cfg).unwrap();
        let back: MnfpServerConfig = parse_config(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn mnfp_never_shares_the_data_dir() {
        for root in ["/data/mesh", "/data/mesh/vault", "/data"] {
            let cfg = MnfpServerConfig {
                shares: vec![MnfpShare {
                    root_path: root.into(),
                    ..share()
                }],
                ..Default::default()
            };
            assert_eq!(
                cfg.validate(&FakeHost, false).unwrap_err(),
                ServerConfigError::invalid(
                    "shares[0].root_path",
                    "Mesh Infinity can't share its own data folder"
                ),
                "root {root}"
            );
        }
    }

    #[test]
    fn mnfp_rejects_missing_unreadable_and_duplicate() {
        let cfg = MnfpServerConfig {
            shares: vec![MnfpShare {
                root_path: "/missing".into(),
                ..share()
            }],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost, false).unwrap_err()),
            "shares[0].root_path"
        );
        let cfg = MnfpServerConfig {
            shares: vec![
                share(),
                MnfpShare {
                    name: "Documents".into(),
                    ..share()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            cfg.validate(&FakeHost, false).unwrap_err(),
            ServerConfigError::invalid(
                "shares[1].name",
                "You already have a share called Documents"
            )
        );
    }

    #[test]
    fn mnfp_floors_and_sftp_dependency() {
        let cfg = MnfpServerConfig {
            shares: vec![MnfpShare {
                min_trust_level: 5,
                ..share()
            }],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost, false).unwrap_err()),
            "shares[0].min_trust_level"
        );
        let cfg = MnfpServerConfig {
            shares: vec![MnfpShare {
                min_trust_level: 8,
                write_trust_level: 7,
                ..share()
            }],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost, false).unwrap_err()),
            "shares[0].write_trust_level"
        );
        let cfg = MnfpServerConfig {
            sftp_via_ssh: true,
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost, false).unwrap_err()),
            "sftp_via_ssh"
        );
        assert!(cfg.validate(&FakeHost, true).is_ok());
    }

    #[test]
    fn mnfp_override_peer_ids_are_checked() {
        let cfg = MnfpServerConfig {
            shares: vec![MnfpShare {
                peer_overrides: vec![MnfpPeerOverride {
                    peer_id: "nope".into(),
                    display_name: String::new(),
                    access: MnfpAccess::ReadWrite,
                }],
                ..share()
            }],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost, false).unwrap_err()),
            "shares[0].peer_overrides[0].peer_id"
        );
    }

    #[test]
    fn mnfp_name_limits() {
        let cfg = MnfpServerConfig {
            shares: vec![MnfpShare {
                name: "x".repeat(65),
                ..share()
            }],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost, false).unwrap_err()),
            "shares[0].name"
        );
        let cfg = MnfpServerConfig {
            shares: vec![MnfpShare {
                name: "   ".into(),
                ..share()
            }],
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost, false).unwrap_err()),
            "shares[0].name"
        );
    }

    // ---- API Gateway ----

    #[test]
    fn gateway_defaults_valid_and_round_trip() {
        let cfg = ApiGatewayConfig::default();
        assert!(cfg.validate(&FakeHost).is_ok());
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ApiGatewayConfig = parse_config(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn gateway_refuses_non_local_upstream() {
        for url in [
            "http://example.com:8080",
            "http://10.0.0.5:80",
            "http://user@127.0.0.1/",
            "ftp://127.0.0.1/",
            "not a url",
            "http://",
        ] {
            let cfg = ApiGatewayConfig {
                upstream_url: url.into(),
                ..Default::default()
            };
            assert_eq!(
                field_of(cfg.validate(&FakeHost).unwrap_err()),
                "upstream_url",
                "{url}"
            );
        }
    }

    #[test]
    fn gateway_accepts_loopback_forms() {
        for url in [
            "http://127.0.0.1:8080",
            "https://localhost/api",
            "http://[::1]:9000/",
            "http://app.localhost:3000",
            "http://workstation:8080",
        ] {
            let cfg = ApiGatewayConfig {
                upstream_url: url.into(),
                ..Default::default()
            };
            assert!(cfg.validate(&FakeHost).is_ok(), "{url}");
        }
    }

    #[test]
    fn gateway_limits_methods_rate_and_prefix() {
        let cfg = ApiGatewayConfig {
            rate_limit: Some(0),
            ..Default::default()
        };
        assert_eq!(field_of(cfg.validate(&FakeHost).unwrap_err()), "rate_limit");
        let cfg = ApiGatewayConfig {
            rate_limit: Some(100_001),
            ..Default::default()
        };
        assert_eq!(field_of(cfg.validate(&FakeHost).unwrap_err()), "rate_limit");
        let cfg = ApiGatewayConfig {
            allowed_methods: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "allowed_methods"
        );
        let cfg = ApiGatewayConfig {
            allowed_methods: Some(vec!["TRACE".into()]),
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "allowed_methods"
        );
        let cfg = ApiGatewayConfig {
            path_prefix: Some("api".into()),
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "path_prefix"
        );
        let cfg = ApiGatewayConfig {
            path_prefix: Some("/api/../x".into()),
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "path_prefix"
        );
        let cfg = ApiGatewayConfig {
            path_prefix: Some("/api/v1".into()),
            allowed_methods: Some(vec!["GET".into(), "POST".into()]),
            rate_limit: Some(600),
            ..Default::default()
        };
        assert!(cfg.validate(&FakeHost).is_ok());
    }

    #[test]
    fn gateway_floor_is_enforced() {
        let cfg = ApiGatewayConfig {
            min_trust_level: 4,
            ..Default::default()
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "min_trust_level"
        );
    }

    // ---- Print ----

    fn printer() -> SharedPrinter {
        SharedPrinter {
            ipp_url: "ipp://127.0.0.1:631/printers/office".to_string(),
            printer_name: "Office Laser".to_string(),
            min_trust_level: 5,
            capabilities: vec!["duplex".into(), "a4".into()],
        }
    }

    #[test]
    fn print_valid_round_trips() {
        let cfg = PrintServiceConfig {
            printers: vec![printer()],
        };
        assert!(cfg.validate(&FakeHost).is_ok());
        let json = serde_json::to_string(&cfg).unwrap();
        let back: PrintServiceConfig = parse_config(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn print_accepts_lan_and_refuses_public() {
        for url in [
            "ipp://192.168.1.20/ipp/print",
            "ipps://printer.local:631/ipp/print",
            "http://[fe80::1]:631/printers/x",
            "ipp://officejet/ipp/print",
        ] {
            let cfg = PrintServiceConfig {
                printers: vec![SharedPrinter {
                    ipp_url: url.into(),
                    ..printer()
                }],
            };
            assert!(cfg.validate(&FakeHost).is_ok(), "{url}");
        }
        for url in [
            "ipp://8.8.8.8/printers/x",
            "ipp://printers.example.com/ipp",
            "smb://127.0.0.1/printer",
            "garbage",
        ] {
            let cfg = PrintServiceConfig {
                printers: vec![SharedPrinter {
                    ipp_url: url.into(),
                    ..printer()
                }],
            };
            assert_eq!(
                field_of(cfg.validate(&FakeHost).unwrap_err()),
                "printers[0].ipp_url",
                "{url}"
            );
        }
    }

    #[test]
    fn print_name_floor_and_duplicates() {
        let cfg = PrintServiceConfig {
            printers: vec![SharedPrinter {
                printer_name: String::new(),
                ..printer()
            }],
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "printers[0].printer_name"
        );
        let cfg = PrintServiceConfig {
            printers: vec![SharedPrinter {
                min_trust_level: 4,
                ..printer()
            }],
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "printers[0].min_trust_level"
        );
        let cfg = PrintServiceConfig {
            printers: vec![printer(), printer()],
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "printers[1].ipp_url"
        );
    }

    // ---- JSON boundary ----

    #[test]
    fn parse_rejects_garbage_wrong_types_and_oversize() {
        assert!(matches!(
            parse_config::<MnrdpServerConfig>("{not json"),
            Err(ServerConfigError::Malformed(_))
        ));
        assert!(matches!(
            parse_config::<MnrdpServerConfig>(r#"{"view_floor":"five"}"#),
            Err(ServerConfigError::Malformed(_))
        ));
        assert!(matches!(
            parse_config::<MnrdpServerConfig>(r#"{"max_sessions":300}"#),
            Err(ServerConfigError::Malformed(_))
        ));
        let huge = "x".repeat(STRING_MAX_BYTES * LIST_MAX + 1);
        assert!(matches!(
            parse_config::<PrintServiceConfig>(&huge),
            Err(ServerConfigError::Malformed(_))
        ));
    }

    #[test]
    fn parse_fills_defaults_for_missing_fields() {
        let cfg: MnrdpServerConfig = parse_config("{}").unwrap();
        assert_eq!(cfg, MnrdpServerConfig::default());
        let bundle: ProtocolServerConfig = parse_config(r#"{"mnsp":{"sshd_port":2222}}"#).unwrap();
        assert_eq!(bundle.mnsp.sshd_port, 2222);
        assert_eq!(bundle.api_gateway, ApiGatewayConfig::default());
    }

    #[test]
    fn oversized_strings_are_refused_before_host_checks() {
        let cfg = PrintServiceConfig {
            printers: vec![SharedPrinter {
                ipp_url: format!("ipp://127.0.0.1/{}", "a".repeat(STRING_MAX_BYTES)),
                ..printer()
            }],
        };
        assert_eq!(
            field_of(cfg.validate(&FakeHost).unwrap_err()),
            "printers[0].ipp_url"
        );
    }

    // ---- URL helpers ----

    #[test]
    fn split_url_handles_ports_and_ipv6() {
        assert_eq!(
            split_url("http://127.0.0.1:8080/x"),
            Some(("http".into(), "127.0.0.1".into(), Some(8080), "/x".into()))
        );
        assert_eq!(
            split_url("ipp://[::1]/printers/a"),
            Some(("ipp".into(), "::1".into(), None, "/printers/a".into()))
        );
        assert_eq!(split_url("http://host:0/"), None);
        assert_eq!(split_url("http://host:99999/"), None);
        assert_eq!(split_url("http://[::1"), None);
        assert_eq!(split_url("://x"), None);
    }

    #[test]
    fn local_host_rules() {
        assert!(is_local_host("127.0.0.1", None));
        assert!(is_local_host("::1", None));
        assert!(is_local_host("LOCALHOST", None));
        assert!(is_local_host("box", Some("Box")));
        assert!(!is_local_host("box", None));
        assert!(!is_local_host("10.0.0.1", None));
        assert!(!is_local_host("0.0.0.0", None));
    }

    #[test]
    fn local_users_includes_the_signed_in_account() {
        let (me, _) = local_user_and_home();
        let users = local_users();
        if !me.is_empty() {
            assert!(users.contains(&me));
        }
        // Every listed account must pass the save-time existence check.
        for user in users {
            assert!(local_user_exists(&user), "{user}");
        }
    }

    #[test]
    fn os_probe_finds_current_user() {
        // The signed-in account must always be a valid mapping target.
        let (user, _) = local_user_and_home();
        if !user.is_empty() {
            assert!(local_user_exists(&user));
        }
        assert!(!local_user_exists(""));
        assert!(!local_user_exists("../etc"));
        assert!(!local_user_exists("no-such-user-mesh-infinity-test"));
    }
}
