//! mesh-infinity-clientless — headless node binary (§17.16)
//!
//! # What this binary is
//!
//! This is the entry point for the clientless build profile.  It starts the
//! full Mesh Infinity Rust backend (identity, crypto, routing, transports,
//! all enabled modules) and then serves the Node Management Interface WebUI
//! (§17.12) over local HTTPS.  No Flutter UI is embedded.
//!
//! # Control surfaces
//!
//! - **Local HTTPS WebUI** — `https://127.0.0.1:<port>` by default.
//!   The accessibility toggle in the shell UI (or the config file) can open
//!   this to a trusted subnet or all interfaces.
//! - **Mesh control plane** — admin mesh identities can reach the management
//!   interface via mesh port block 70 (§12.1.1).
//!
//! # Startup sequence
//!
//! 1. Load `ClientlessConfig` from disk (port, accessibility, data directory).
//! 2. Initialise `MeshRuntime` — the same runtime used by the full-client build.
//! 3. Generate or load the local HTTPS TLS certificate.
//! 4. Start the axum HTTPS server bound to the configured address.
//! 5. Enter the tokio event loop; the server runs until the process is killed
//!    or a SIGTERM/Ctrl-C is received.
//!
//! # Build identity
//!
//! Application ID: `com.oniimediaworks.meshinfinity-clientless` (release)
//!                 `com.oniimediaworks.meshinfinity-clientless-debug` (debug)
//! See §17.16 Build identity for the full scheme.

mod config;
mod webui;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

// The MeshRuntime is the single long-lived state container for the entire
// backend.  It is the same struct used by the full-client build; the clientless
// binary drives it directly without going through the C FFI layer.
use mesh_infinity::service::runtime::MeshRuntime;

use config::ClientlessConfig;

/// Application entry point.
///
/// Starts the backend runtime and the WebUI HTTPS server, then blocks until
/// the process receives a shutdown signal.
#[tokio::main]
async fn main() -> Result<()> {
    // Initialise structured logging.  In a systemd environment the output goes
    // to the journal; on a terminal it goes to stdout.
    tracing_subscriber::fmt()
        .with_env_filter(
            // RUST_LOG=debug overrides the default; info is the production level.
            std::env::var("RUST_LOG").unwrap_or_else(|_| "mesh_infinity=info,tower_http=warn".into()),
        )
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "mesh-infinity-clientless starting"
    );

    // ── Step 1: load configuration ────────────────────────────────────────────
    //
    // ClientlessConfig holds the few settings the shell UI exposes:
    //   - data_dir: where the backend stores its vault and config files
    //   - webui_port: the HTTPS port the WebUI listens on
    //   - webui_local_only: whether to bind to 127.0.0.1 or all interfaces
    //
    // Defaults are used on first run; the config is persisted to disk so the
    // shell UI's changes survive restarts.
    let cfg = ClientlessConfig::load_or_default()
        .context("failed to load clientless configuration")?;

    info!(
        port = cfg.webui_port,
        local_only = cfg.webui_local_only,
        "configuration loaded"
    );

    // ── Step 2: initialise the Rust backend ───────────────────────────────────
    //
    // MeshRuntime::new() allocates all backend subsystems: identity, crypto,
    // routing tables, transport managers, module state, event queue.  It does
    // NOT start any network listeners — those are started explicitly below.
    //
    // The runtime is wrapped in Arc<RwLock<>> so the WebUI handler tasks can
    // share it safely across threads without duplicating state.
    // MeshRuntime::new takes an owned String and returns Self (infallible).
    let runtime = MeshRuntime::new(cfg.data_dir.clone());
    let runtime = Arc::new(RwLock::new(runtime));

    info!(data_dir = %cfg.data_dir, "backend runtime initialised");

    // ── Step 3: TLS certificate ───────────────────────────────────────────────
    //
    // The WebUI is always served over HTTPS (§17.12: "locally generated
    // certificate added to the local trust store at setup").  On first run
    // we generate a self-signed certificate via rcgen and persist it.
    // On subsequent runs we load the persisted certificate.
    let tls_acceptor = webui::tls::load_or_generate_cert(&cfg.data_dir)
        .context("failed to prepare TLS certificate")?;

    // ── Step 4: bind and start the HTTPS server ───────────────────────────────
    //
    // Bind address respects the webui_local_only toggle:
    //   true  → 127.0.0.1:<port>  (shell default; safest for fresh deployments)
    //   false → 0.0.0.0:<port>    (operator has explicitly opened remote access)
    let bind_host = if cfg.webui_local_only { "127.0.0.1" } else { "0.0.0.0" };
    let addr: SocketAddr = format!("{}:{}", bind_host, cfg.webui_port)
        .parse()
        .context("invalid bind address")?;

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind WebUI HTTPS server on {addr}"))?;

    info!(addr = %addr, "WebUI HTTPS server listening");

    // Print the access URL to stdout so operators know where to connect,
    // and so the shell UI (tray popover / Android Activity) can read it.
    // The WEBUI_URL line is a stable, machine-parseable marker.
    println!("WEBUI_URL=https://{}:{}", bind_host, cfg.webui_port);

    // ── Step 5: run the server ────────────────────────────────────────────────
    //
    // `webui::serve` assembles the axum Router (all §17.12 routes), wraps the
    // TCP listener with TLS, and drives it with tokio's select! loop.
    // It returns when a graceful shutdown signal is received (SIGTERM / Ctrl-C).
    if let Err(e) = webui::serve(listener, tls_acceptor, runtime, cfg).await {
        error!(error = %e, "WebUI server exited with error");
        std::process::exit(1);
    }

    info!("mesh-infinity-clientless shut down cleanly");
    Ok(())
}
