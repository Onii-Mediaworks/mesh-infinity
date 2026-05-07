//! ClientlessConfig — shell-level configuration for the clientless build profile.
//!
//! # What lives here
//!
//! These are the settings the shell UI exposes directly (§17.16 Shell UI contents):
//!   - `webui_port`       — which HTTPS port the WebUI listens on
//!   - `webui_local_only` — the localhost-only toggle (most critical bootstrap control)
//!   - `data_dir`         — where the backend stores vault and config files
//!   - `webui_token_*`    — verifier material for the local admin token
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
//!   2. The WebUI token itself is never stored; only verifier material is
//!      persisted so a copied config file does not expose the bearer secret.
//!
//! # Defaults
//!
//! On first run the file does not exist.  `load_or_default()` returns safe
//! defaults: localhost-only, port 8443, data dir from the OS convention.

use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

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

// A 256-bit random bearer token is enough entropy that online guessing is
// dominated by the TLS and rate-limiting posture rather than token length.
const WEBUI_TOKEN_BYTES: usize = 32;

// A separate random salt/key prevents the stored verifier from being a plain
// unsalted hash and lets us use HMAC's constant-time verification path.
const WEBUI_TOKEN_SALT_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

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

    // ── WebUI credential verifier ────────────────────────────────────────────
    /// Base64URL salt used as the HMAC key for the WebUI bearer token verifier.
    ///
    /// This is not the token.  It is public verifier context stored alongside
    /// the HMAC output so the server can validate the token after restart.
    #[serde(default)]
    pub webui_token_salt_b64: String,

    /// Base64URL HMAC-SHA256 output for the generated WebUI bearer token.
    ///
    /// The plaintext token is generated once, printed to stdout for the shell
    /// setup path, and then retained only in the operator's credential store.
    #[serde(default)]
    pub webui_token_mac_b64: String,

    /// Plaintext token generated during this process, if this was first run or
    /// an older config file was upgraded.  Skipped during serialisation so it
    /// is never written to disk.
    #[serde(skip)]
    pub generated_webui_token: Option<String>,
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
            webui_port: DEFAULT_WEBUI_PORT,
            webui_local_only: DEFAULT_WEBUI_LOCAL_ONLY,
            data_dir: default_data_dir(),
            webui_token_salt_b64: String::new(),
            webui_token_mac_b64: String::new(),
            generated_webui_token: None,
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
        let default_dir = resolve_default_data_dir().unwrap_or_else(|| PathBuf::from("./data"));

        let config_path = default_dir.join(CONFIG_FILENAME);

        if config_path.exists() {
            // Read and deserialise the existing config.
            let raw = std::fs::read_to_string(&config_path)
                .with_context(|| format!("failed to read {}", config_path.display()))?;
            let mut cfg: ClientlessConfig = serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse {}", config_path.display()))?;
            if cfg.ensure_webui_token()? {
                cfg.save()?;
            }
            return Ok(cfg);
        }

        // First run: use defaults and persist them so the shell UI can read
        // and edit the file.
        let mut cfg = ClientlessConfig::default();
        cfg.ensure_webui_token()?;
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
        let json =
            serde_json::to_string_pretty(self).context("failed to serialise ClientlessConfig")?;

        std::fs::write(&config_path, json)
            .with_context(|| format!("failed to write {}", config_path.display()))?;

        restrict_config_permissions(&config_path)?;

        Ok(())
    }

    /// Verify a bearer token supplied by a WebUI request.
    ///
    /// The stored verifier is HMAC-SHA256(salt, token).  `verify_slice()` keeps
    /// comparison constant-time for equal-length MAC values and fails closed on
    /// malformed or absent config material.
    pub fn verify_webui_token(&self, token: &str) -> bool {
        let Ok(salt) =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&self.webui_token_salt_b64)
        else {
            return false;
        };
        let Ok(expected_mac) =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&self.webui_token_mac_b64)
        else {
            return false;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(&salt) else {
            return false;
        };

        mac.update(token.as_bytes());
        mac.verify_slice(&expected_mac).is_ok()
    }

    /// Ensure the config contains WebUI token verifier material.
    ///
    /// Returns `true` when the config was changed and should be persisted.  This
    /// upgrades older config files without requiring a separate migration path.
    fn ensure_webui_token(&mut self) -> Result<bool> {
        if !self.webui_token_salt_b64.is_empty() && !self.webui_token_mac_b64.is_empty() {
            return Ok(false);
        }

        let mut token_bytes = [0u8; WEBUI_TOKEN_BYTES];
        let mut salt = [0u8; WEBUI_TOKEN_SALT_BYTES];
        getrandom::fill(&mut token_bytes).context("failed to generate WebUI token")?;
        getrandom::fill(&mut salt).context("failed to generate WebUI token salt")?;

        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
        let mut mac =
            HmacSha256::new_from_slice(&salt).context("failed to initialise WebUI token HMAC")?;
        mac.update(token.as_bytes());
        let mac_bytes = mac.finalize().into_bytes();

        self.webui_token_salt_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(salt);
        self.webui_token_mac_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac_bytes);
        self.generated_webui_token = Some(token);
        Ok(true)
    }
}

/// Lock down the config file where the operating system exposes Unix modes.
///
/// Windows ACLs are left to the user profile directory defaults.  On Unix-like
/// systems a 0600 config prevents other local users from reading verifier
/// material or setup metadata.
fn restrict_config_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to restrict permissions on {}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
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
