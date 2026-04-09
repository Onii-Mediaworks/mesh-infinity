//! ClientlessConfig — shell-level configuration for the clientless build profile.
//!
//! # What lives here
//!
//! These are the settings the shell UI exposes directly (§17.16 Shell UI contents):
//!   - `webui_port`       — which HTTPS port the WebUI listens on
//!   - `webui_local_only` — the localhost-only toggle (most critical bootstrap control)
//!   - `data_dir`         — where the backend stores vault and config files
//!
//! This is NOT the full node configuration.  Everything else (transports, module
//! enable/disable, trust settings, peer list, etc.) is managed through the WebUI
//! itself, not through this struct.
//!
//! # Persistence
//!
//! The config is stored as JSON at `<data_dir>/clientless.json`.  JSON is used
//! because:
//!   1. The shell UI (Android Activity / tray popover) needs to write it too,
//!      and JSON is the simplest cross-language interchange format.
//!   2. The file is not security-sensitive — it contains no key material.
//!
//! # Defaults
//!
//! On first run the file does not exist.  `load_or_default()` returns safe
//! defaults: localhost-only, port 8443, data dir from the OS convention.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Default values
// ---------------------------------------------------------------------------

// Default HTTPS port for the WebUI.
//
// 8443 is chosen because:
//   - It does not require root/CAP_NET_BIND_SERVICE (ports below 1024 do).
//   - It does not conflict with the mesh transport listener (7234).
//   - It is memorable and conventional for alternative HTTPS.
const DEFAULT_WEBUI_PORT: u16 = 8443;

// Default: bind to localhost only until the operator explicitly opens access.
// This is the safest default for a freshly deployed node.
const DEFAULT_WEBUI_LOCAL_ONLY: bool = true;

// Config file name inside the data directory.
const CONFIG_FILENAME: &str = "clientless.json";

// ---------------------------------------------------------------------------
// ClientlessConfig
// ---------------------------------------------------------------------------

/// Shell-level configuration for the clientless build profile.
///
/// Serialised to `<data_dir>/clientless.json`.  All fields have sane defaults
/// so the file does not need to exist on first run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientlessConfig {
    // ── WebUI access ─────────────────────────────────────────────────────────

    /// HTTPS port the Node Management Interface WebUI listens on.
    ///
    /// Shown read-only in the shell UI alongside the full URL.  The operator
    /// can change it via the port input field.
    #[serde(default = "default_webui_port")]
    pub webui_port: u16,

    /// Whether the WebUI is accessible to localhost only.
    ///
    /// `true`  → binds to `127.0.0.1` only (shell default; safest for new nodes)
    /// `false` → binds to `0.0.0.0` (operator has explicitly opened remote access)
    ///
    /// This is the most critical bootstrap control: a freshly deployed node is
    /// localhost-only until the operator flips this toggle.  Credential auth
    /// (§17.12) still applies regardless of this setting.
    #[serde(default = "default_webui_local_only")]
    pub webui_local_only: bool,

    // ── Backend data directory ────────────────────────────────────────────────

    /// Absolute path to the directory where the backend stores all persistent
    /// state: identity vault, message store, peer database, TLS certificate.
    ///
    /// Defaults to the OS-conventional user data directory:
    ///   Linux   → ~/.local/share/mesh-infinity-clientless/
    ///   macOS   → ~/Library/Application Support/mesh-infinity-clientless/
    ///   Windows → %APPDATA%\mesh-infinity-clientless\
    ///   Android → managed by the JNI layer; not configured here.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

// ---------------------------------------------------------------------------
// Default value functions (used by serde)
// ---------------------------------------------------------------------------

fn default_webui_port() -> u16 {
    DEFAULT_WEBUI_PORT
}

fn default_webui_local_only() -> bool {
    DEFAULT_WEBUI_LOCAL_ONLY
}

fn default_data_dir() -> String {
    resolve_default_data_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "./data".to_string())
}

// ---------------------------------------------------------------------------
// impl ClientlessConfig
// ---------------------------------------------------------------------------

impl Default for ClientlessConfig {
    fn default() -> Self {
        Self {
            webui_port:       DEFAULT_WEBUI_PORT,
            webui_local_only: DEFAULT_WEBUI_LOCAL_ONLY,
            data_dir:         default_data_dir(),
        }
    }
}

impl ClientlessConfig {
    /// Load configuration from `<data_dir>/clientless.json`, creating it with
    /// safe defaults if it does not exist.
    ///
    /// The data directory itself is determined from the OS convention on first
    /// run (before the config file exists).  If the config file is present, the
    /// `data_dir` field inside it takes precedence.
    pub fn load_or_default() -> Result<Self> {
        // Locate the config file from the default data directory.
        // If the config file specifies a different data_dir, that will take
        // effect on the next call (i.e., the operator can relocate the data).
        let default_dir = resolve_default_data_dir()
            .unwrap_or_else(|| PathBuf::from("./data"));

        let config_path = default_dir.join(CONFIG_FILENAME);

        if config_path.exists() {
            // Read and deserialise the existing config.
            let raw = std::fs::read_to_string(&config_path)
                .with_context(|| format!("failed to read {}", config_path.display()))?;
            let cfg: ClientlessConfig = serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse {}", config_path.display()))?;
            return Ok(cfg);
        }

        // First run: use defaults and persist them so the shell UI can read
        // and edit the file.
        let cfg = ClientlessConfig::default();
        cfg.save()?;
        Ok(cfg)
    }

    /// Persist the current configuration to disk.
    ///
    /// Called by the shell UI after the operator changes a setting.
    pub fn save(&self) -> Result<()> {
        let dir = PathBuf::from(&self.data_dir);

        // Create the data directory if it does not exist yet.
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create data directory {}", dir.display()))?;

        let config_path = dir.join(CONFIG_FILENAME);
        let json = serde_json::to_string_pretty(self)
            .context("failed to serialise ClientlessConfig")?;

        std::fs::write(&config_path, json)
            .with_context(|| format!("failed to write {}", config_path.display()))?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OS-conventional data directory
// ---------------------------------------------------------------------------

/// Returns the OS-conventional user data directory for the clientless node.
///
/// Uses `dirs-next` which follows the XDG Base Directory spec on Linux,
/// `~/Library/Application Support` on macOS, and `%APPDATA%` on Windows.
fn resolve_default_data_dir() -> Option<PathBuf> {
    dirs_next::data_dir().map(|base| base.join("mesh-infinity-clientless"))
}
