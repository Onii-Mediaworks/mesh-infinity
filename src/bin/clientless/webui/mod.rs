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
//! | GET    | /api/build-profile          | Build profile    |
//! | GET    | /                           | WebUI SPA shell  |
//!
//! # Authentication
//!
//! The server binds to localhost by default. Remote binding is an operator
//! action and must be paired with the certificate trust flow handled by the
//! shell setup path.

pub mod tls;

use std::sync::Arc;

use anyhow::Result;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use hyper::Request;
use hyper_util::{rt::TokioExecutor, rt::TokioIo, server::conn::auto::Builder as HyperBuilder};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::info;

use mesh_infinity::service::runtime::MeshRuntime;

use crate::build_profile;
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
        .route("/api/status", get(handle_status))
        .route("/api/transports", get(handle_transports))
        .route("/api/transports/:id/enable", post(handle_transport_enable))
        .route(
            "/api/transports/:id/disable",
            post(handle_transport_disable),
        )
        .route("/api/peers", get(handle_peers))
        // ── Identity ───────────────────────────────────────────────────────
        .route("/api/identity", get(handle_identity))
        // ── Module system ──────────────────────────────────────────────────
        .route("/api/modules", get(handle_modules))
        .route("/api/modules/:id/enable", post(handle_module_enable))
        .route("/api/modules/:id/disable", post(handle_module_disable))
        // ── Storage metrics ────────────────────────────────────────────────
        .route("/api/storage", get(handle_storage))
        // ── Updates ───────────────────────────────────────────────────────
        .route("/api/updates", get(handle_updates))
        // ── Build profile ────────────────────────────────────────────────
        .route("/api/build-profile", get(handle_build_profile))
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
/// the binary.  The page is deliberately self-contained so the clientless
/// binary does not depend on an external asset pipeline at startup.
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
async fn handle_status(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    let rt = state.runtime.read().await;
    let stats = parse_json_object(&rt.get_network_stats());
    let settings = parse_json_object(&rt.get_settings());
    let layer1 = settings
        .get("layer1Status")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let active_transports = stats
        .get("activeTransports")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false);

    Json(json!({
        "connected": active_transports,
        "peerCount": stats.get("connectedPeers").cloned().unwrap_or_else(|| json!(0)),
        "routingEntries": stats.get("routingEntries").cloned().unwrap_or_else(|| json!(0)),
        "gossipMapSize": stats.get("gossipMapSize").cloned().unwrap_or_else(|| json!(0)),
        "wireGuardSessions": stats.get("wireGuardSessions").cloned().unwrap_or_else(|| json!(0)),
        "storeForwardPending": stats.get("sfPendingMessages").cloned().unwrap_or_else(|| json!(0)),
        "vpnMode": stats.get("vpnMode").cloned().unwrap_or_else(|| json!("Off")),
        "layer1": layer1,
        "natStatus": "unknown",
    }))
    .into_response()
}

/// List available transports and their current enabled/disabled state.
async fn handle_transports(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    let rt = state.runtime.read().await;
    let settings = parse_json_object(&rt.get_settings());
    Json(json!({
        "transports": [
            transport_entry("clearnet", "Clearnet", &settings, "enableClearnet"),
            transport_entry("tor", "Tor", &settings, "enableTor"),
            transport_entry("i2p", "I2P", &settings, "enableI2p"),
            transport_entry("bluetooth", "Bluetooth", &settings, "enableBluetooth"),
            transport_entry("rf", "RF / SDR", &settings, "enableRf"),
            transport_entry("mesh_discovery", "LAN Discovery", &settings, "meshDiscovery"),
            transport_entry("relays", "Relay Participation", &settings, "allowRelays"),
        ]
    }))
    .into_response()
}

/// List connected peers.
async fn handle_peers(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    let rt = state.runtime.read().await;
    let peers = serde_json::from_str::<serde_json::Value>(&rt.get_peer_list())
        .unwrap_or_else(|_| json!([]));
    Json(json!({ "peers": peers })).into_response()
}

// ── Identity ──────────────────────────────────────────────────────────────────

/// Node identity information.
///
/// Returns the node's mesh identity public key (Layer 1), operating mode
/// (always Server for clientless), and relay reputation.
/// Never returns key material — display-safe data only (§15.1).
async fn handle_identity(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    let rt = state.runtime.read().await;
    let identity = parse_json_object(&rt.get_identity_summary());
    let stats = parse_json_object(&rt.get_network_stats());
    Json(json!({
        "mode": "Server",
        "identity": identity,
        "meshPubkey": stats.get("meshIdentityPubkey").cloned().unwrap_or_else(|| json!("")),
        "tunnelGossipKnownNodes": stats.get("tunnelGossipKnownNodes").cloned().unwrap_or_else(|| json!(0)),
        "webuiPort": state.config.webui_port,
        "webuiLocalOnly": state.config.webui_local_only,
    }))
    .into_response()
}

// ── Module system ─────────────────────────────────────────────────────────────

/// List all modules and their current enabled/disabled state.
async fn handle_modules(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    let rt = state.runtime.read().await;
    let modules = serde_json::from_str::<serde_json::Value>(&rt.get_service_list())
        .unwrap_or_else(|_| json!([]));
    Json(json!({ "modules": modules })).into_response()
}

// ── Storage metrics ───────────────────────────────────────────────────────────

/// Storage usage and retention configuration.
async fn handle_storage(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    let bytes = directory_size(std::path::Path::new(&state.config.data_dir));
    Json(json!({
        "dataDir": state.config.data_dir,
        "totalBytes": bytes,
        "retentionDays": null,
    }))
    .into_response()
}

// ── Updates ───────────────────────────────────────────────────────────────────

/// Pending update status.
async fn handle_updates(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    let rt = state.runtime.read().await;
    let diagnostics = parse_json_object(&rt.get_diagnostic_report_json());
    Json(json!({
        "pendingVersion": null,
        "currentVersion": env!("CARGO_PKG_VERSION"),
        "diagnosticGenerated": !diagnostics.is_empty(),
    }))
    .into_response()
}

/// Clientless binary identity and supported build targets.
async fn handle_build_profile(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    Json(build_profile::profile_json()).into_response()
}

/// Enable one transport from the WebUI control surface.
async fn handle_transport_enable(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    set_transport(state, id, true).await
}

/// Disable one transport from the WebUI control surface.
async fn handle_transport_disable(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    set_transport(state, id, false).await
}

/// Enable one module/service from the WebUI control surface.
async fn handle_module_enable(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    set_module(state, id, true).await
}

/// Disable one module/service from the WebUI control surface.
async fn handle_module_disable(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !bearer_authorized(&headers, &state) {
        return unauthorized_response();
    }

    set_module(state, id, false).await
}

async fn set_transport(state: AppState, id: String, enabled: bool) -> axum::response::Response {
    let rt = state.runtime.read().await;
    match rt.toggle_transport_flag(&id, enabled) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "id": id, "enabled": enabled })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": error })),
        )
            .into_response(),
    }
}

async fn set_module(state: AppState, id: String, enabled: bool) -> axum::response::Response {
    let rt = state.runtime.read().await;
    let payload = json!({ "enabled": enabled }).to_string();
    if rt.configure_service(&id, &payload) {
        (
            StatusCode::OK,
            Json(json!({ "ok": true, "id": id, "enabled": enabled })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": "unknown module id" })),
        )
            .into_response()
    }
}

fn bearer_authorized(headers: &HeaderMap, state: &AppState) -> bool {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(header) = value.to_str() else {
        return false;
    };
    let Some((scheme, token)) = header.split_once(' ') else {
        return false;
    };

    scheme.eq_ignore_ascii_case("Bearer")
        && !token.trim().is_empty()
        && state.config.verify_webui_token(token.trim())
}

fn unauthorized_response() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "ok": false,
            "error": "missing or invalid WebUI bearer token",
        })),
    )
        .into_response()
}

fn parse_json_object(raw: &str) -> serde_json::Map<String, serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

fn transport_entry(
    id: &str,
    name: &str,
    settings: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> serde_json::Value {
    json!({
        "id": id,
        "name": name,
        "enabled": settings.get(field).and_then(|value| value.as_bool()).unwrap_or(false),
    })
}

fn directory_size(path: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| {
            entry
                .metadata()
                .map(|meta| {
                    if meta.is_dir() {
                        directory_size(&entry.path())
                    } else {
                        meta.len()
                    }
                })
                .unwrap_or(0)
        })
        .sum()
}
