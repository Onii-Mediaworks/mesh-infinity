//! Transport control FFI shims — clearnet, Tor, mDNS, VPN, overlay, LoSec, WireGuard, SDR (§5).
//! Each function is a thin C-ABI wrapper (null-check → delegate → return).
//! No business logic lives here.

use std::os::raw::c_char;
use std::ptr;

use super::{c_str_to_str, MeshContext};

// ---------------------------------------------------------------------------
// Clearnet transport control (§5.1)
// ---------------------------------------------------------------------------

/// Start the clearnet TCP listener on the configured port.
///
/// Returns 0 on success, -1 if the listener could not be bound.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_start_clearnet_listener(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx has no listener to start.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate listener startup to service layer.
    // Dispatch on the variant.
    match ctx.start_clearnet_listener() {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Stop the clearnet TCP listener and close all active connections.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_stop_clearnet_listener(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx has nothing to stop.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate listener teardown to service layer.
    ctx.stop_clearnet_listener();
    0
}

/// Set the clearnet TCP listen port.  Takes effect on next listener start.
///
/// Returns 0 on success, -1 if port is 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_set_clearnet_port(ctx: *mut MeshContext, port: u16) -> i32 {
    // Guard: null ctx has no port to configure.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_clearnet_port(port) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Configure VPN routing rules from a JSON object.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `route` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_clearnet_route(ctx: *mut MeshContext, route: *const c_char) -> i32 {
    // Guard: null ctx has no routing table to update.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(route) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_clearnet_route(json_str) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Tor transport control (§5.3)
// ---------------------------------------------------------------------------

/// Bootstrap the Tor transport and start the hidden service.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tor_enable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot enable Tor.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate Tor bootstrap to service layer.
    // Dispatch on the variant.
    match ctx.tor_enable() {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Disable the Tor transport and shut down the hidden service.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tor_disable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot disable Tor.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate Tor teardown to service layer.
    ctx.tor_disable();
    0
}

/// Return our Tor v3 `.onion` address as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tor_get_onion_address(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no Tor address.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.tor_get_onion_address() {
        Ok(addr) => ctx.set_response(&serde_json::json!({"onion_address": addr}).to_string()),
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(_) => ctx.set_response(r#"{"error":"Tor not enabled"}"#),
    }
}

/// Connect to a peer via the Tor network.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tor_connect(
    ctx: *mut MeshContext,
    peer_id_hex_ptr: *const c_char,
    onion_addr_ptr: *const c_char,
    port: u16,
) -> i32 {
    // Guard: null ctx or null string args are immediate failures.
    if ctx.is_null() || peer_id_hex_ptr.is_null() || onion_addr_ptr.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees all pointers are valid.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let peer_id_hex = match unsafe { c_str_to_str(peer_id_hex_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let onion_addr = match unsafe { c_str_to_str(onion_addr_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate Tor connection to service layer.
    // Dispatch on the variant.
    match ctx.tor_connect(peer_id_hex, onion_addr, port) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// mDNS / LAN discovery (§4.6)
// ---------------------------------------------------------------------------

/// Enable mDNS peer discovery on the local network.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mdns_enable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot enable mDNS.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate mDNS startup to service layer.
    ctx.mdns_enable();
    0
}

/// Disable mDNS peer discovery and clear the discovered-peers cache.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mdns_disable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot disable mDNS.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate mDNS teardown to service layer.
    ctx.mdns_disable();
    0
}

/// Returns 1 if mDNS is currently running, 0 otherwise.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mdns_is_running(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx → mDNS is not running.
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate status query to service layer.
    if ctx.mdns_is_running() {
        1
    } else {
        0
    }
}

/// Return mDNS-discovered peers as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_mdns_get_discovered_peers(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no discovered peers.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate peer-list retrieval to service layer.
    ctx.set_response(&ctx.mdns_get_discovered_peers())
}

// ---------------------------------------------------------------------------
// VPN routing (§6.9)
// ---------------------------------------------------------------------------

/// Set the VPN routing mode.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `mode_json` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_vpn_mode(ctx: *mut MeshContext, mode_json: *const c_char) -> i32 {
    // Guard: null ctx has no VPN to configure.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(mode_json) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_vpn_mode(json_str) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Set or clear the exit-node peer.  Pass an empty string to clear.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `peer_id_hex` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_set_exit_node(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
) -> i32 {
    // Guard: null ctx has no VPN.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required peer-ID argument.
    let pid = unsafe { c_str_to_str(peer_id_hex) }.unwrap_or("");
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_exit_node(pid) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return the current VPN status as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_vpn_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no VPN status.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.get_vpn_status())
}

/// Return the current App Connector configuration as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_app_connector_config(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_app_connector_config())
}

/// Set the App Connector configuration from a JSON payload.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null. `config_json` must be valid UTF-8 JSON.
#[no_mangle]
pub unsafe extern "C" fn mi_set_app_connector_config(
    ctx: *mut MeshContext,
    config_json: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let json_str = match unsafe { c_str_to_str(config_json) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.set_app_connector_config(json_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Evaluate App Connector selector rules against a connection 4-tuple.
///
/// Given a package name, destination IP (as a dotted-decimal or IPv6 string),
/// destination port, and an optional pre-resolved domain name, this function
/// walks the active `AppConnectorConfig` rules in priority order and returns
/// the routing decision for the packet.
///
/// Return values:
///   0 — block (drop the packet; denylist rule matched)
///   1 — allow_direct (bypass the mesh; packet takes the normal IP path)
///   2 — route_via_mesh (forward the packet through the active mesh tunnel)
///  -1 — invalid arguments (null ctx, unparseable IP string)
///
/// # Parameters
///
/// - `ctx`           — non-null opaque context handle from `mesh_init`.
/// - `package_ptr`   — NUL-terminated UTF-8 Android package name (e.g.
///   `"com.example.browser"`).  Must not be null.
/// - `dst_ip_ptr`    — NUL-terminated IP address string in dotted-decimal
///   (IPv4) or colon-hex (IPv6) notation.  Must not be null.
/// - `dst_port`      — destination port as a C int (0–65535).  Values outside
///   that range are clamped to `u16::MAX`.
/// - `dst_domain_ptr`— optional NUL-terminated domain name (e.g.
///   `"sub.example.com"`).  Pass null when no domain is
///   available (most non-DNS packets).
///
/// # Safety
///
/// `ctx` must be non-null and originate from `mesh_init`.  All non-null
/// string pointers must point to valid NUL-terminated UTF-8 sequences.
#[no_mangle]
pub unsafe extern "C" fn mi_connector_evaluate(
    ctx: *mut MeshContext,
    package_ptr: *const c_char,
    dst_ip_ptr: *const c_char,
    dst_port: std::os::raw::c_int,
    dst_domain_ptr: *const c_char,
) -> std::os::raw::c_int {
    // Guard: null context is always an error.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees ctx is non-null and from mesh_init.
    let ctx = unsafe { &*ctx };

    // Parse the package name — required field, null or empty is an error.
    let package = match unsafe { c_str_to_str(package_ptr) } {
        Some(s) => s,
        None => return -1,
    };

    // Parse the destination IP address string.
    // We reject null and unparseable strings with -1 (invalid args).
    let dst_ip_str = match unsafe { c_str_to_str(dst_ip_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    let dst_ip: std::net::IpAddr = match dst_ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return -1,
    };

    // Clamp the port to u16.  Callers should always pass 0–65535 but we
    // handle out-of-range values gracefully rather than panicking.
    let dst_port_u16: u16 = dst_port.clamp(0, u16::MAX as std::os::raw::c_int) as u16;

    // The domain pointer is optional — null means no domain available.
    // An empty string is also treated as absent so Kotlin callers can pass ""
    // instead of null without triggering spurious domain-pattern mismatches.
    let dst_domain: Option<&str> =
        unsafe { c_str_to_str(dst_domain_ptr) }.filter(|s| !s.is_empty());

    // Retrieve the current App Connector config and run the selector engine.
    let action = ctx.evaluate_connector_connection(package, dst_ip, dst_port_u16, dst_domain);

    // Return the integer encoding: 0=block, 1=allow_direct, 2=route_via_mesh.
    action.as_ffi_int()
}

/// Ingest a raw IP packet from the Android TUN fd into the mesh data plane
/// (§17.5 App Connector `RouteViaMesh` path).
///
/// Called by `AndroidAppConnectorVpnService` for every packet whose
/// `mi_connector_evaluate` result is `ACTION_ROUTE_VIA_MESH` (value 2).
///
/// Returns 1 if the packet was accepted and enqueued, 0 if no route exists,
/// and -1 on invalid arguments.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `packet_ptr` must point to at least `packet_len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn mi_send_raw_packet(
    ctx: *mut MeshContext,
    packet_ptr: *const u8,
    packet_len: usize,
) -> std::os::raw::c_int {
    // Guard: null context or null pointer are invalid.
    if ctx.is_null() || packet_ptr.is_null() {
        return -1;
    }
    // Guard: zero-length packet is a no-op, not an error.
    if packet_len == 0 {
        return 0;
    }
    // SAFETY: caller guarantees ptr..ptr+len is valid for the call duration.
    let bytes = unsafe { std::slice::from_raw_parts(packet_ptr, packet_len) };
    let ctx = unsafe { &*ctx };
    if ctx.ingest_tun_packet(bytes) {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Overlay network (Tailscale, ZeroTier) (§5.5)
// ---------------------------------------------------------------------------

/// Authenticate Tailscale with an auth key.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_auth_key(
    ctx: *mut MeshContext,
    auth_key: *const c_char,
    control_url: *const c_char,
) -> i32 {
    // Guard: null ctx cannot authenticate.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let key = match unsafe { c_str_to_str(auth_key) } {
        Some(s) => s,
        None => return -1,
    };
    // Fall back to the default value on failure.
    let url = unsafe { c_str_to_str(control_url) }.unwrap_or("");
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.tailscale_auth_key(key, url) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Begin Tailscale OAuth flow.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `control_url` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_begin_oauth(
    ctx: *mut MeshContext,
    control_url: *const c_char,
) -> i32 {
    // Guard: null ctx cannot initiate OAuth.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required URL argument.
    let url = unsafe { c_str_to_str(control_url) }.unwrap_or("");
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.tailscale_begin_oauth(url) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Connect to a ZeroTier network.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_connect(
    ctx: *mut MeshContext,
    api_key: *const c_char,
    controller_url: *const c_char,
    network_ids_json: *const c_char,
) -> i32 {
    // Guard: null ctx cannot connect to ZeroTier.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let key = match unsafe { c_str_to_str(api_key) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let controller = match unsafe { c_str_to_str(controller_url) } {
        Some(s) => s,
        None => return -1,
    };
    // Serialize to the wire format for transmission or storage.
    let networks = unsafe { c_str_to_str(network_ids_json) }.unwrap_or("[]");
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.zerotier_connect(key, controller, networks) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Disconnect and forget Tailscale configuration.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_disconnect(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.tailscale_disconnect() {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Refresh Tailscale state from the controller.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_refresh(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.tailscale_refresh() {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Toggle Tailscale mesh-relay preference.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_set_prefer_mesh_relay(
    ctx: *mut MeshContext,
    enabled: i32,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.tailscale_set_prefer_mesh_relay(enabled != 0) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Select or clear the active Tailscale exit node by peer name.
///
/// # Safety
/// `ctx` must be non-null. `peer_name` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_set_exit_node(
    ctx: *mut MeshContext,
    peer_name: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let peer_name = match unsafe { c_str_to_str(peer_name) } {
        Some(value) => value,
        None => return -1,
    };
    match ctx.tailscale_set_exit_node(peer_name) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Disconnect and forget ZeroTier configuration.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_disconnect(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.zerotier_disconnect() {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Refresh ZeroTier state from the controller.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_refresh(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.zerotier_refresh() {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Join an additional ZeroTier network with the stored controller config.
///
/// # Safety
/// `ctx` must be non-null. `network_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_join_network(
    ctx: *mut MeshContext,
    network_id: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let network_id = match unsafe { c_str_to_str(network_id) } {
        Some(value) => value,
        None => return -1,
    };
    match ctx.zerotier_join_network(network_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Toggle ZeroTier mesh-relay preference.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_set_prefer_mesh_relay(
    ctx: *mut MeshContext,
    enabled: i32,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.zerotier_set_prefer_mesh_relay(enabled != 0) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Update a ZeroTier member authorization state.
///
/// # Safety
/// `ctx` must be non-null. Strings must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_set_member_authorized(
    ctx: *mut MeshContext,
    network_id: *const c_char,
    node_id: *const c_char,
    authorized: i32,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let network_id = match unsafe { c_str_to_str(network_id) } {
        Some(value) => value,
        None => return -1,
    };
    let node_id = match unsafe { c_str_to_str(node_id) } {
        Some(value) => value,
        None => return -1,
    };
    match ctx.zerotier_set_member_authorized(network_id, node_id, authorized != 0) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Complete a Tailscale OAuth login after the user finishes the browser flow.
///
/// `token_ptr`: the auth token returned by the control server in the redirect
/// URL query parameters after the user authenticates in-browser.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.  `token_ptr` must be a valid
/// null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_complete_oauth(
    ctx: *mut MeshContext,
    token_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    // The token is required — an empty token cannot authenticate.
    let token = match unsafe { c_str_to_str(token_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.tailscale_complete_oauth(token) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Trigger Tailscale reauthentication.
///
/// Clears the stored auth token and begins a fresh OAuth flow via the stored
/// controller.  Use when the key has expired or the `TailscaleKeyExpiryWarning`
/// event indicates fewer than 7 days remain.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_reauthenticate(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.tailscale_reauthenticate() {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Start the Tailscale background map-poll thread.
///
/// No-op if a poll thread is already running.  The thread polls the control
/// plane every 30 seconds and emits `OverlayStatusChanged` on each update.
///
/// Returns 0 on success, -1 on failure (e.g. Tailscale not configured).
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_start_background_poll(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.tailscale_start_background_poll() {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Stop the Tailscale background map-poll thread.
///
/// Signals the thread to exit on its next wake-up.  Returns immediately;
/// thread cleanup is asynchronous.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_stop_background_poll(ctx: *mut MeshContext) {
    if ctx.is_null() {
        return;
    }
    let ctx = unsafe { &*ctx };
    ctx.tailscale_stop_background_poll();
}

/// Probe ZeroTier PLANET root servers to verify UDP connectivity.
///
/// Returns 1 when the transport socket is bound and probes were dispatched,
/// 0 when ZeroTier is not connected or the socket is not available.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_probe_roots(ctx: *mut MeshContext) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    let ctx = unsafe { &*ctx };
    if ctx.zerotier_probe_roots() {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Tailscale multi-instance FFI (§5.23)
// ---------------------------------------------------------------------------
//
// These functions correspond to the `tailscale_*_instance` methods added in
// service/transport_ops.rs.  Each follows the same three-step pattern as all
// other FFI functions:
//   1. Null-check ctx.
//   2. Parse C-string arguments.
//   3. Call the service method and translate the Result to an i32 / *mut c_char.
//
// For functions that return data (list, add), the result is owned by
// `ctx.last_response` and is valid until the next FFI call that writes to
// that field.  Flutter must copy the string before calling any other FFI fn.

/// Return a JSON array of all configured Tailscale instances.
///
/// Returns a JSON array of instance summary objects.
/// Returns null if ctx is null.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_list_instances(ctx: *mut MeshContext) -> *mut c_char {
    // Guard: null ctx has no instances to list.
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer — never fails; returns "[]" on empty.
    ctx.set_response(&ctx.tailscale_list_instances()) as *mut c_char
}

/// Add a new Tailscale instance and return its id.
///
/// Returns a JSON object `{"id":"<hex>"}` on success, null on failure.
///
/// # Safety
/// `ctx` must be non-null.  `label_ptr` and `control_url_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_add_instance(
    ctx: *mut MeshContext,
    // User-assigned label for the new instance (e.g. "Work tailnet").
    label_ptr: *const c_char,
    // Empty string = official Tailscale server; otherwise a Headscale base URL.
    control_url_ptr: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    let ctx = unsafe { &*ctx };
    // Label is required; control_url may be empty (vendor server default).
    let label = match unsafe { c_str_to_str(label_ptr) } {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let control_url = unsafe { c_str_to_str(control_url_ptr) }.unwrap_or("");
    match ctx.tailscale_add_instance(label, control_url) {
        Ok(json) => ctx.set_response(&json) as *mut c_char,
        Err(e) => {
            ctx.set_error(&e.to_string());
            ptr::null_mut()
        }
    }
}

/// Remove a Tailscale instance by id.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_remove_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.tailscale_remove_instance(instance_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Set a Tailscale instance as the priority for routing conflict resolution.
///
/// Returns 0 on success, -1 if the instance id does not exist.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_set_priority(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.tailscale_set_priority(instance_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Authenticate a Tailscale instance using an auth key.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  All string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_auth_key_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
    // Tailscale pre-auth key (tskey-auth-…) or OAuth token.
    key_ptr: *const c_char,
    // Empty = official Tailscale server; non-empty = Headscale URL.
    url_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    let key = match unsafe { c_str_to_str(key_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    let url = unsafe { c_str_to_str(url_ptr) }.unwrap_or("");
    match ctx.tailscale_auth_key_instance(instance_id, key, url) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Begin the Tailscale OAuth flow for a specific instance.
///
/// Emits `TailscaleOAuthUrl` with the login redirect URL.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  String args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_begin_oauth_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
    // Empty = official Tailscale server; non-empty = Headscale base URL.
    url_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    let url = unsafe { c_str_to_str(url_ptr) }.unwrap_or("");
    match ctx.tailscale_begin_oauth_instance(instance_id, url) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Disconnect a specific Tailscale instance.
///
/// Resets the instance to NotConfigured; keeps its id and label in the list.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_disconnect_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.tailscale_disconnect_instance(instance_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Refresh control-plane state for a specific Tailscale instance.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_refresh_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.tailscale_refresh_instance(instance_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Toggle mesh-relay preference for a specific Tailscale instance.
///
/// `enabled`: non-zero = prefer mesh relay; 0 = prefer DERP relay.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_set_prefer_mesh_relay_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
    // non-zero = prefer mesh relay; 0 = prefer DERP.
    enabled: i32,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.tailscale_set_prefer_mesh_relay_instance(instance_id, enabled != 0) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Set the active exit node for a specific Tailscale instance.
///
/// Pass an empty `peer_name_ptr` to clear the active exit node.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  String args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_set_exit_node_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
    // Name of the Tailscale peer to use as exit node; empty string clears it.
    peer_name_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    // peer_name may be absent (null) or empty — both mean "clear exit node".
    let peer_name = unsafe { c_str_to_str(peer_name_ptr) }.unwrap_or("");
    match ctx.tailscale_set_exit_node_instance(instance_id, peer_name) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Complete the OAuth flow for a specific Tailscale instance.
///
/// Called after `mi_tailscale_begin_oauth_instance` — once the user completes
/// browser-based login and the app extracts `token` from the redirect URL.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  String args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_complete_oauth_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
    // Auth token extracted from the Tailscale/Headscale OAuth redirect.
    token_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    let token = match unsafe { c_str_to_str(token_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.tailscale_complete_oauth_instance(instance_id, token) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Trigger reauthentication for a specific Tailscale instance.
///
/// Clears the auth token and begins a fresh OAuth flow.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_tailscale_reauthenticate_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.tailscale_reauthenticate_instance(instance_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// ZeroTier multi-instance FFI (§5.22)
// ---------------------------------------------------------------------------

/// Return a JSON array of all configured ZeroTier instances.
///
/// Returns a JSON array; null if ctx is null.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_list_instances(ctx: *mut MeshContext) -> *mut c_char {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    let ctx = unsafe { &*ctx };
    // Never fails — returns "[]" on empty.
    ctx.set_response(&ctx.zerotier_list_instances()) as *mut c_char
}

/// Add a new ZeroTier instance and return its id.
///
/// `network_ids_json_ptr`: JSON array of 16-char hex network IDs to join immediately.
/// Returns a JSON object `{"id":"<hex>"}` on success, null on failure.
///
/// # Safety
/// `ctx` must be non-null.  All string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_add_instance(
    ctx: *mut MeshContext,
    // User-assigned label for the new instance.
    label_ptr: *const c_char,
    // ZeroTier Central API key, or empty for self-hosted.
    api_key_ptr: *const c_char,
    // Empty = ZeroTier Central; non-empty = self-hosted controller URL.
    controller_url_ptr: *const c_char,
    // JSON array of 16-char hex network IDs to join immediately.
    network_ids_json_ptr: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    let ctx = unsafe { &*ctx };
    let label = match unsafe { c_str_to_str(label_ptr) } {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let api_key = unsafe { c_str_to_str(api_key_ptr) }.unwrap_or("");
    let controller_url = unsafe { c_str_to_str(controller_url_ptr) }.unwrap_or("");
    // Parse the network IDs JSON array.  Default to empty array on null/invalid.
    let network_ids_json = unsafe { c_str_to_str(network_ids_json_ptr) }.unwrap_or("[]");
    let network_ids: Vec<String> = match serde_json::from_str(network_ids_json) {
        Ok(ids) => ids,
        Err(e) => {
            ctx.set_error(&format!("network_ids_json is not valid JSON: {e}"));
            return ptr::null_mut();
        }
    };
    match ctx.zerotier_add_instance(label, api_key, controller_url, &network_ids) {
        Ok(json) => ctx.set_response(&json) as *mut c_char,
        Err(e) => {
            ctx.set_error(&e.to_string());
            ptr::null_mut()
        }
    }
}

/// Remove a ZeroTier instance by id.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_remove_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.zerotier_remove_instance(instance_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Set a ZeroTier instance as the priority for routing conflict resolution.
///
/// Returns 0 on success, -1 if the instance id does not exist.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_set_priority(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.zerotier_set_priority(instance_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Refresh controller state for a specific ZeroTier instance.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_refresh_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.zerotier_refresh_instance(instance_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Disconnect a specific ZeroTier instance.
///
/// Resets the instance to NotConfigured while keeping its id and label.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_disconnect_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.zerotier_disconnect_instance(instance_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Join an additional ZeroTier network on a specific instance.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  String args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_join_network_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
    // 16-char hex network ID to join.
    network_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    let network_id = match unsafe { c_str_to_str(network_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.zerotier_join_network_instance(instance_id, network_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Leave (un-join) a network on a specific ZeroTier instance.
///
/// Removes the network from the instance's joined list and re-syncs the
/// ZeroTier client so the network is torn down immediately.  If the network
/// was not joined, this is a no-op and returns 0.
/// Returns 0 on success, -1 on failure (error available via mi_get_last_error).
///
/// # Safety
/// `ctx` must be non-null.  Both string pointers must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_leave_network_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
    // 16-char hex network ID to leave.
    network_id_ptr: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    let network_id = match unsafe { c_str_to_str(network_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.zerotier_leave_network_instance(instance_id, network_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Toggle mesh-relay preference for a specific ZeroTier instance.
///
/// `enabled`: non-zero = prefer mesh relay; 0 = prefer PLANET/MOON relay.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `instance_id_ptr` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_set_prefer_mesh_relay_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
    enabled: i32,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.zerotier_set_prefer_mesh_relay_instance(instance_id, enabled != 0) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Authorize or de-authorize a ZeroTier network member on a specific instance.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  All string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_zerotier_set_member_authorized_instance(
    ctx: *mut MeshContext,
    instance_id_ptr: *const c_char,
    // 16-char hex ZeroTier network ID.
    network_id_ptr: *const c_char,
    // 10-char hex ZeroTier Node ID of the member.
    node_id_ptr: *const c_char,
    // non-zero = authorize; 0 = revoke.
    authorized: i32,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let instance_id = match unsafe { c_str_to_str(instance_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    let network_id = match unsafe { c_str_to_str(network_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    let node_id = match unsafe { c_str_to_str(node_id_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    match ctx.zerotier_set_member_authorized_instance(
        instance_id,
        network_id,
        node_id,
        authorized != 0,
    ) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e.to_string());
            -1
        }
    }
}

/// Return overlay network status as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_overlay_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no overlay.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.overlay_status())
}

// ---------------------------------------------------------------------------
// LoSec (§5.4)
// ---------------------------------------------------------------------------

/// Process a LoSec connection-mode request.
///
/// Returns JSON `{"accepted":bool,"rejection_reason":?string}`.
///
/// # Safety
/// `ctx` must be non-null.  `request_json` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_losec_request(
    ctx: *mut MeshContext,
    request_json: *const c_char,
) -> *const c_char {
    // Guard: null ctx cannot process LoSec requests.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(request_json) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.losec_request(json_str) {
        Ok(json) => ctx.set_response(&json),
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => ctx.set_response(&serde_json::json!({"error": e}).to_string()),
    }
}

/// Return the current LoSec ambient traffic status as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_losec_ambient_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no ambient status.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.losec_ambient_status())
}

// ---------------------------------------------------------------------------
// WireGuard (§5.2)
// ---------------------------------------------------------------------------

/// Initiate a WireGuard handshake with a peer.
///
/// Returns JSON `{"init_hex":"..."}` or `{"error":"..."}`.
///
/// # Safety
/// `ctx` must be non-null.  `peer_id_hex` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_wg_initiate_handshake(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
) -> *const c_char {
    // Guard: null ctx cannot initiate WireGuard.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required peer-ID argument.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.wg_initiate_handshake(peer_hex) {
        Ok(json) => ctx.set_response(&json),
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => ctx.set_response(&serde_json::json!({"error": e}).to_string()),
    }
}

/// Respond to an incoming WireGuard handshake initiation.
///
/// Returns JSON `{"response_hex":"..."}` or `{"error":"..."}`.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_wg_respond_to_handshake(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
    init_hex: *const c_char,
) -> *const c_char {
    // Guard: null ctx cannot handle WireGuard.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Dispatch based on the variant to apply type-specific logic.
    let init_hex_ = match unsafe { c_str_to_str(init_hex) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.wg_respond_to_handshake(peer_hex, init_hex_) {
        Ok(json) => ctx.set_response(&json),
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => ctx.set_response(&serde_json::json!({"error": e}).to_string()),
    }
}

/// Complete a WireGuard handshake by processing the responder's reply.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_wg_complete_handshake(
    ctx: *mut MeshContext,
    peer_id_hex: *const c_char,
    response_hex: *const c_char,
) -> i32 {
    // Guard: null ctx cannot complete handshakes.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    let resp_hex = match unsafe { c_str_to_str(response_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.wg_complete_handshake(peer_hex, resp_hex) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// SDR/RF transport (§5.6)
// ---------------------------------------------------------------------------

/// Configure the SDR/RF transport.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `config_json` must be valid JSON UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_sdr_configure(
    ctx: *mut MeshContext,
    config_json: *const c_char,
) -> i32 {
    // Guard: null ctx cannot configure SDR.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    let json_str = match unsafe { c_str_to_str(config_json) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.sdr_configure(json_str) {
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return SDR/RF transport status as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_sdr_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no SDR.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.sdr_status())
}

/// Return the current FHSS channel as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_sdr_current_channel(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no SDR channel.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.sdr_current_channel())
}

/// Return the list of SDR RF profiles as JSON.
///
/// # Safety
/// `_ctx` is unused but retained for ABI consistency.
#[no_mangle]
pub unsafe extern "C" fn mi_sdr_list_profiles(_ctx: *mut MeshContext) -> *const c_char {
    // Profiles are static; no context required.  Delegate to service method.
    // We need a static CString for the response pointer lifetime.
    // Build the list from MeshRuntime if available, else use fallback.
    if _ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*_ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.sdr_list_profiles())
}

/// Return the list of detected SDR hardware as JSON.
///
/// # Safety
/// `_ctx` is unused but retained for ABI consistency.
#[no_mangle]
pub unsafe extern "C" fn mi_sdr_list_hardware(_ctx: *mut MeshContext) -> *const c_char {
    // Hardware detection is static; delegate to service layer.
    if _ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    let ctx = unsafe { &*_ctx };
    // Delegate to service layer.
    ctx.set_response(&ctx.sdr_list_hardware())
}

// ---------------------------------------------------------------------------
