//! Node Management Interface WebUI — §17.12
//!
//! This module implements the HTTPS WebUI served by the clientless build profile.
//! It is the primary and complete management interface for clientless deployments.
//!
//! # Two access paths (§17.12)
//!
//! **Path 1 — Local HTTPS** (implemented here):
//!   An axum server bound to `127.0.0.1:<port>` (default) or `0.0.0.0:<port>`
//!   (when webui_local_only is false).  Credential-authenticated.  Always
//!   available regardless of mesh connectivity.
//!
//! **Path 2 — Mesh control plane** (TODO — §17.12 mesh port block 70):
//!   Trusted admin mesh identities reach this interface via the mesh.  Not yet
//!   implemented; planned for a later pass once the HTTP layer is stable.
//!
//! # Route layout
//!
//! | Method | Path                        | Category         |
//! |--------|-----------------------------|-----------------|
//! | GET    | /api/health                 | Health           |
//! | GET    | /api/status                 | Mesh connectivity|
//! | GET    | /api/transports             | Mesh connectivity|
//! | POST   | /api/transports/:id/enable  | Mesh connectivity|
//! | POST   | /api/transports/:id/disable | Mesh connectivity|
//! | GET    | /api/peers                  | Mesh connectivity|
//! | GET    | /api/identity               | Identity         |
//! | GET    | /api/modules                | Module system    |
//! | POST   | /api/modules/:id/enable     | Module system    |
//! | POST   | /api/modules/:id/disable    | Module system    |
//! | GET    | /api/storage                | Storage metrics  |
//! | GET    | /api/updates                | Updates          |
//! | GET    | /                           | WebUI SPA shell  |
//!
//! # Authentication
//!
//! TODO: credential authentication (§17.12 "password or client certificate").
//! The current stub accepts all requests — DO NOT expose beyond localhost until
//! authentication is implemented.

pub mod tls;

use std::sync::Arc;

use anyhow::Result;
use axum::{
    body::Body,
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use hyper::Request;
use hyper_util::{rt::TokioExecutor, rt::TokioIo, server::conn::auto::Builder as HyperBuilder};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio::sync::RwLock;
use tower::ServiceExt;
use tracing::info;

use mesh_infinity::service::runtime::MeshRuntime;

use crate::config::ClientlessConfig;

// ---------------------------------------------------------------------------
// AppState — shared state for all axum handler tasks
// ---------------------------------------------------------------------------

/// Shared application state injected into every axum handler via `State<>`.
///
/// `Arc<>` is used so cloning the state (which axum does per-request) is cheap:
/// it increments a reference count rather than copying the data.
#[derive(Clone)]
pub struct AppState {
    /// The full Mesh Infinity backend runtime.  All management actions are
    /// dispatched through this handle.
    pub runtime: Arc<RwLock<MeshRuntime>>,

    /// Shell-level configuration (port, accessibility).  The WebUI exposes
    /// some of these fields in the Identity / Settings category.
    pub config: Arc<ClientlessConfig>,
}

// ---------------------------------------------------------------------------
// serve — entry point called from main.rs
// ---------------------------------------------------------------------------

/// Start the axum HTTPS server and block until a shutdown signal arrives.
///
/// Assembles the router, wraps the TCP listener with TLS, and drives the
/// tokio event loop.  Returns on graceful shutdown (SIGTERM or Ctrl-C).
pub async fn serve(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    runtime: Arc<RwLock<MeshRuntime>>,
    config: ClientlessConfig,
) -> Result<()> {
    let state = AppState {
        runtime,
        config: Arc::new(config),
    };

    let app = build_router(state);

    // Drive the TLS+HTTP server with graceful shutdown on Ctrl-C / SIGTERM.
    // `axum-server` or manual accept loops are alternatives; we use the axum
    // `serve` helper with a custom acceptor for simplicity.
    axum_server_loop(listener, tls_acceptor, app).await
}

// ---------------------------------------------------------------------------
// build_router — assembles all routes
// ---------------------------------------------------------------------------

/// Build the complete axum Router with all §17.12 management routes.
fn build_router(state: AppState) -> Router {
    Router::new()
        // ── WebUI shell ────────────────────────────────────────────────────
        // The root path serves a minimal HTML page that bootstraps the SPA.
        // In production this would serve a compiled React/Vue/Svelte app
        // embedded in the binary via `include_str!` or `rust-embed`.
        .route("/", get(handle_index))

        // ── Health (unauthenticated — safe to expose, returns no secrets) ──
        .route("/api/health", get(handle_health))

        // ── Mesh connectivity ──────────────────────────────────────────────
        .route("/api/status",   get(handle_status))
        .route("/api/transports", get(handle_transports))
        .route("/api/peers",    get(handle_peers))

        // ── Identity ───────────────────────────────────────────────────────
        .route("/api/identity", get(handle_identity))

        // ── Module system ──────────────────────────────────────────────────
        .route("/api/modules",  get(handle_modules))

        // ── Storage metrics ────────────────────────────────────────────────
        .route("/api/storage",  get(handle_storage))

        // ── Updates ───────────────────────────────────────────────────────
        .route("/api/updates",  get(handle_updates))

        // Inject shared state into all handlers.
        .with_state(state)
}

// ---------------------------------------------------------------------------
// axum_server_loop — TLS accept loop
// ---------------------------------------------------------------------------

/// Accept TLS connections from the bound TCP listener and dispatch them to axum.
///
/// Runs until a Ctrl-C or SIGTERM signal is received, then performs graceful
/// shutdown by breaking the accept loop.
///
/// # Adaptor pattern
///
/// axum's `Router` implements `Service<Request<Body>>` but hyper's connection
/// driver expects `Service<Request<Incoming>>`.  We bridge them with
/// `hyper::service::service_fn`, mapping each `Request<Incoming>` to
/// `Request<Body>` via `req.map(Body::new)`, then calling the router via
/// `tower::ServiceExt::oneshot`.
async fn axum_server_loop(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    app: Router,
) -> Result<()> {
    use tokio::signal;

    // Shutdown signal future — resolves on Ctrl-C.
    let shutdown = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };
    tokio::pin!(shutdown);

    info!("WebUI accept loop started");

    loop {
        tokio::select! {
            // Accept a new TCP connection.
            result = listener.accept() => {
                let (tcp_stream, remote_addr) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "TCP accept error — skipping");
                        continue;
                    }
                };

                // Clone both the TLS acceptor and the router for this task.
                // Router::clone is cheap (Arc-backed internally).
                let tls = tls_acceptor.clone();
                let router = app.clone();

                tokio::spawn(async move {
                    // TLS handshake on a dedicated task so a slow client
                    // does not stall the accept loop.
                    let tls_stream = match tls.accept(tcp_stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(
                                peer = %remote_addr,
                                error = %e,
                                "TLS handshake failed"
                            );
                            return;
                        }
                    };

                    // Adapt `Router` (Service<Request<Body>>) to the
                    // `Service<Request<Incoming>>` that hyper expects.
                    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        // Map Incoming body → axum Body, then drive through
                        // the router as a one-shot service call.
                        router.clone().oneshot(req.map(Body::new))
                    });

                    let io = TokioIo::new(tls_stream);
                    if let Err(e) = HyperBuilder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await
                    {
                        tracing::debug!(error = %e, "connection error");
                    }
                });
            }

            // Graceful shutdown: stop accepting new connections.
            _ = &mut shutdown => {
                info!("shutdown signal received — stopping WebUI server");
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// ── WebUI shell ──────────────────────────────────────────────────────────────

/// Serve the WebUI SPA shell.
///
/// In production this serves a compiled HTML/JS/CSS application embedded in
/// the binary.  This stub returns a minimal page that confirms the server is
/// running and links to the JSON API endpoints.
async fn handle_index() -> impl IntoResponse {
    Html(include_str!("index.html"))
}

// ── Health ───────────────────────────────────────────────────────────────────

/// Health check — returns 200 OK with a minimal JSON body.
///
/// Unauthenticated; returns no secrets.  Used by monitoring tools and the
/// shell UI to confirm the backend is alive before opening the browser.
async fn handle_health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ── Mesh connectivity ─────────────────────────────────────────────────────────

/// Current mesh connectivity status.
///
/// Returns transport states, NAT status, and peer count.
/// Full implementation reads from MeshRuntime transport flags and routing table.
async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    // TODO: read actual transport flags and peer count from runtime.
    // Stub returns a skeleton response so the WebUI can render the shape.
    let _rt = state.runtime.read().await;
    Json(json!({
        "connected": false,
        "peerCount": 0,
        "transports": [],
        "natStatus": "unknown",
    }))
}

/// List available transports and their current enabled/disabled state.
async fn handle_transports(State(state): State<AppState>) -> impl IntoResponse {
    let _rt = state.runtime.read().await;
    // TODO: enumerate TransportFlags from runtime.
    Json(json!({ "transports": [] }))
}

/// List connected peers.
async fn handle_peers(State(state): State<AppState>) -> impl IntoResponse {
    let _rt = state.runtime.read().await;
    // TODO: read peer list from routing table.
    Json(json!({ "peers": [] }))
}

// ── Identity ──────────────────────────────────────────────────────────────────

/// Node identity information.
///
/// Returns the node's mesh identity public key (Layer 1), operating mode
/// (always Server for clientless), and relay reputation.
/// Never returns key material — display-safe data only (§15.1).
async fn handle_identity(State(state): State<AppState>) -> impl IntoResponse {
    let _rt = state.runtime.read().await;
    // TODO: read mesh identity pubkey and relay reputation from runtime.
    Json(json!({
        "mode": "Server",          // Clientless nodes are permanently Server mode.
        "meshPubkey": null,        // TODO: populated once identity is unlocked.
        "relayReputation": null,
        "webuiPort": state.config.webui_port,
        "webuiLocalOnly": state.config.webui_local_only,
    }))
}

// ── Module system ─────────────────────────────────────────────────────────────

/// List all modules and their current enabled/disabled state.
async fn handle_modules(State(state): State<AppState>) -> impl IntoResponse {
    let _rt = state.runtime.read().await;
    // TODO: read ModuleConfig from runtime.
    Json(json!({ "modules": [] }))
}

// ── Storage metrics ───────────────────────────────────────────────────────────

/// Storage usage and retention configuration.
async fn handle_storage(State(state): State<AppState>) -> impl IntoResponse {
    let _rt = state.runtime.read().await;
    // TODO: query vault sizes from runtime.
    Json(json!({
        "vaultBytes": 0,
        "messageStoreBytes": 0,
        "retentionDays": null,
    }))
}

// ── Updates ───────────────────────────────────────────────────────────────────

/// Pending update status.
async fn handle_updates(State(state): State<AppState>) -> impl IntoResponse {
    let _rt = state.runtime.read().await;
    // TODO: check mesh-delivered update manifest (§17.10).
    Json(json!({
        "pendingVersion": null,
        "currentVersion": env!("CARGO_PKG_VERSION"),
    }))
}
