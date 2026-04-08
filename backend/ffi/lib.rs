//! FFI boundary — C-compatible API surface (§17.5).
//!
//! THIS FILE IS A THIN C ABI BOUNDARY ONLY.
//!
//! ## Architecture
//!
//! `MeshContext` is an opaque wrapper around `Box<MeshRuntime>`.  Every
//! `pub unsafe extern "C"` function does exactly three things:
//!   1. Null-check and parse FFI arguments (strings, ints, structs).
//!   2. Call the corresponding method on `MeshRuntime` (via `Deref`).
//!   3. Return the result as an integer code or JSON pointer.
//!
//! No business logic belongs here.  If you find yourself writing more than
//! ~15 lines inside an `extern "C"` fn body, move the logic to `service/`.
//!
//! ## Key material policy (§15.1)
//!
//! No key material ever crosses this boundary.  All returned strings are
//! pre-validated, display-safe JSON produced by the service layer.
//!
//! ## Pointer ownership
//!
//! Flutter calls `mesh_init()` once and receives a `*mut MeshContext`.
//! It holds this pointer for the app lifetime and passes it to every
//! other function.  It must call `mesh_destroy()` exactly once at shutdown.
//! Rust owns the memory; Flutter never frees it directly.
//!
//! ## Return conventions
//!
//! - Integer functions return `0` on success, `-1` on failure.
//! - Pointer functions return `null` on failure; non-null on success.
//! - JSON strings are owned by the context (`last_response`) and are valid
//!   until the next FFI call that writes to `last_response`.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

use crate::service::MeshRuntime;

// JNI types are only needed for the Android Layer 1 headless startup entry.
#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Opaque context handle
// ---------------------------------------------------------------------------

/// Opaque handle passed to every FFI function.
///
/// Wraps a heap-allocated `MeshRuntime`.  Flutter holds a raw pointer;
/// all lifetime management is explicit via `mesh_init` / `mesh_destroy`.
// MeshContext — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct MeshContext(Box<MeshRuntime>);

// Begin the block scope.
// Implement Deref for MeshContext.
impl std::ops::Deref for MeshContext {
    // Type alias for readability.
    // Type alias for protocol readability.
    type Target = MeshRuntime;
    /// Deref to the inner `MeshRuntime` so shims can call service methods
    /// directly without an extra `.0` dereference layer.
    // Perform the 'deref' operation.
    // Errors are propagated to the caller via Result.
    fn deref(&self) -> &MeshRuntime {
        &self.0
    }
}

// Begin the block scope.
// Implement DerefMut for MeshContext.
impl std::ops::DerefMut for MeshContext {
    /// Mutable deref for methods that mutate `MeshRuntime` state.
    // Perform the 'deref mut' operation.
    // Errors are propagated to the caller via Result.
    fn deref_mut(&mut self) -> &mut MeshRuntime {
        &mut self.0
    }
}

// ---------------------------------------------------------------------------
// FFI config struct (matches Dart-side FfiMeshConfig)
// ---------------------------------------------------------------------------

/// Configuration struct passed from Dart to `mesh_init`.
///
/// Layout must match the Dart `FfiMeshConfig` struct exactly (field order,
/// alignment, sizes).  Both sides use `#[repr(C)]` / `@Packed` for a
/// stable ABI.  See `frontend/lib/backend/backend_bridge.dart`.
#[repr(C)]
// Begin the block scope.
// FfiMeshConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FfiMeshConfig {
    /// NUL-terminated UTF-8 path to the data directory.  Null = use default.
    // Execute this protocol step.
    pub config_path: *const c_char,
    /// Logging verbosity: 0 = off, 1 = error, 2 = info, 3 = debug, 4 = trace.
    // Execute this protocol step.
    pub log_level: u8,
    /// 1 = route traffic through Tor, 0 = disabled.
    // Execute this protocol step.
    pub enable_tor: u8,
    /// 1 = allow direct clearnet connections, 0 = disabled.
    // Execute this protocol step.
    pub enable_clearnet: u8,
    /// 1 = enable local-network peer discovery (mDNS/UDP broadcast).
    // Execute this protocol step.
    pub mesh_discovery: u8,
    /// 1 = allow this node to relay traffic for other peers.
    // Execute this protocol step.
    pub allow_relays: u8,
    /// 1 = route traffic through I2P garlic routing.
    // Execute this protocol step.
    pub enable_i2p: u8,
    /// 1 = enable BLE peer discovery and transport.
    // Execute this protocol step.
    pub enable_bluetooth: u8,
    /// 1 = enable SDR/RF transport (LoRa etc.).
    // Execute this protocol step.
    pub enable_rf: u8,
    /// UDP port for the WireGuard tunnel.  0 = OS-assigned.
    // Execute this protocol step.
    pub wireguard_port: u16,
    /// Maximum peers to maintain.  0 = no limit.
    // Execute this protocol step.
    pub max_peers: u32,
    /// Maximum simultaneous network connections.  0 = no limit.
    // Execute this protocol step.
    pub max_connections: u32,
    /// Node operating mode: 0 = leaf, 1 = relay, 2 = gateway.
    // Execute this protocol step.
    pub node_mode: u8,
}

// ---------------------------------------------------------------------------
// Pre-init error storage
// ---------------------------------------------------------------------------

// Thread-local store for errors that occur before a `MeshContext` exists.
// `mi_last_error_message(null)` reads from here after a failed `mesh_init`.
// Execute this protocol step.
thread_local! {
    // Process the current step in the protocol.
    // Execute this protocol step.
    static PREINIT_ERROR: std::cell::RefCell<Option<CString>> =
        // Create a new instance with the specified parameters.
        // Protocol constant.
        const { std::cell::RefCell::new(None) };
}

/// Store `msg` in the pre-init thread-local error slot.
///
/// Called only from `mesh_init` before a `MeshContext` is available.
// Perform the 'set preinit error' operation.
// Errors are propagated to the caller via Result.
fn set_preinit_error(msg: &str) {
    // Apply the closure to each element.
    // Execute this protocol step.
    PREINIT_ERROR.with(|e| {
        // `CString::new` only fails on interior NUL bytes; use a fallback.
        *e.borrow_mut() = CString::new(msg)
            // Check the operation outcome without consuming the error.
            .ok()
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            .or_else(|| CString::new("init error").ok());
    });
}

// ---------------------------------------------------------------------------
// Private helper: C string → &str
// ---------------------------------------------------------------------------

/// Convert a raw C string pointer to a Rust `&str`.
///
/// Returns `None` if the pointer is null or contains invalid UTF-8.
///
/// # Safety
/// Caller must guarantee the pointer is either null or points to a valid,
/// NUL-terminated C string that lives at least as long as the returned borrow.
// Execute this protocol step.
unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    // Null pointers are treated as "no value provided" throughout the API.
    // Guard: validate the condition before proceeding.
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees non-null, NUL-terminated.
    // Execute this protocol step.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Initialise the Mesh Infinity backend and return an opaque context handle.
///
/// `config` must point to a fully-initialised `FfiMeshConfig`.  Dart allocates
/// it with `calloc<FfiMeshConfig>()` (zero-initialised) and fills all fields.
///
/// Returns null on failure; call `mi_last_error_message(null)` for details.
///
/// # Safety
/// `config` must be non-null, correctly aligned, and remain valid for the
/// duration of this call.  All other pointer fields inside `config` must be
/// null or point to valid NUL-terminated UTF-8 strings.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mesh_init(config: *const FfiMeshConfig) -> *mut MeshContext {
    // Null config pointer is a programming error on the Dart side.
    // Guard: validate the condition before proceeding.
    if config.is_null() {
        // Execute the operation and bind the result.
        // Execute this protocol step.
        set_preinit_error("mesh_init: config pointer is null");
        // Return the result to the caller.
        // Return to the caller.
        return ptr::null_mut();
    }

    // SAFETY: caller guarantees config is valid and aligned for this call.
    // Compute cfg for this protocol step.
    let cfg = unsafe { &*config };

    // On Android: if the headless Layer 1 startup path already created a
    // context (§3.1.1 — Layer 1 starts at device unlock before the app opens),
    // adopt that runtime instead of allocating a second one.  Flutter's
    // transport flags are layered on top so the user's preferences apply.
    #[cfg(target_os = "android")]
    {
        let existing = HEADLESS_LAYER1_PTR.load(Ordering::Acquire);
        if existing != 0 {
            let ctx = existing as *mut MeshContext;
            HEADLESS_LAYER1_ATTACHMENTS.fetch_add(1, Ordering::AcqRel);
            // Apply any transport flags that were conservatively disabled during
            // headless startup (Tor, I2P, clearnet, Bluetooth, RF).
            {
                let mut flags = unsafe { &*ctx }
                    .transport_flags
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if cfg.enable_tor != 0 {
                    flags.tor = true;
                }
                if cfg.enable_clearnet != 0 {
                    flags.clearnet = true;
                }
                if cfg.enable_i2p != 0 {
                    flags.i2p = true;
                }
                if cfg.enable_bluetooth != 0 {
                    flags.bluetooth = true;
                }
                if cfg.enable_rf != 0 {
                    flags.rf = true;
                }
            }
            if let Err(e) = unsafe { &*ctx }.reconcile_layer1_runtime() {
                eprintln!("[mesh_init] reconcile after Flutter attach failed: {e}");
            }
            return ctx;
        }
    }

    // Resolve the data-directory path: use the supplied path or a platform default.
    // Compute dir for this protocol step.
    let dir = if cfg.config_path.is_null() {
        // Default: $HOME/.mesh-infinity (Linux/macOS) or %APPDATA%\mesh-infinity (Windows).
        // Execute this protocol step.
        dirs_next::data_local_dir()
            // Apply the closure to each element.
            // Execute this protocol step.
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            // Process the current step in the protocol.
            // Execute this protocol step.
            .join("mesh-infinity")
            // Process the current step in the protocol.
            // Execute this protocol step.
            .to_string_lossy()
            // Chain the operation on the intermediate result.
            // Execute this protocol step.
            .into_owned()
    // Begin the block scope.
    // Fallback when the guard was not satisfied.
    } else {
        // SAFETY: config_path is non-null; caller guarantees valid NUL-terminated UTF-8.
        // Dispatch on the variant.
        match unsafe { c_str_to_str(cfg.config_path) } {
            // Wrap the found value for the caller.
            // Wrap the found value.
            Some(s) => s.to_string(),
            // Update the local state.
            // No value available.
            None => {
                // Execute the operation and bind the result.
                // Execute this protocol step.
                set_preinit_error("mesh_init: config_path is not valid UTF-8");
                // Return the result to the caller.
                // Return to the caller.
                return ptr::null_mut();
            }
        }
    };

    // Create the data directory if it does not exist yet.
    // Guard: validate the condition before proceeding.
    if let Err(e) = std::fs::create_dir_all(&dir) {
        // Execute the operation and bind the result.
        // Execute this protocol step.
        eprintln!("[mesh_init] WARNING: failed to create data directory {dir:?}: {e}");
    }

    // Allocate the context on the heap, seed it from the startup config, then
    // let the backend restore any startup-ready state before handing
    // ownership to Flutter.
    let mut runtime = MeshRuntime::new(dir);
    runtime.load_layer1_startup_config();
    {
        let mut flags = runtime
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        flags.tor = cfg.enable_tor != 0;
        flags.clearnet = cfg.enable_clearnet != 0;
        flags.i2p = cfg.enable_i2p != 0;
        flags.bluetooth = cfg.enable_bluetooth != 0;
        flags.rf = cfg.enable_rf != 0;
        flags.mesh_discovery = cfg.mesh_discovery != 0;
        flags.allow_relays = cfg.allow_relays != 0;
    }
    *runtime.node_mode.lock().unwrap_or_else(|e| e.into_inner()) = cfg.node_mode;
    runtime.initialize_startup_state();
    let ctx = Box::new(MeshContext(Box::new(runtime)));
    // Invoke the associated function.
    // Execute this protocol step.
    Box::into_raw(ctx)
}

// ---------------------------------------------------------------------------
// Layer 1 headless startup (Android only)
// ---------------------------------------------------------------------------
//
// The spec (§3.1.1) requires Layer 1 mesh participation to begin at device
// unlock — before the app process, before Flutter, and before any user
// interaction.  On Android this is achieved by `AndroidStartupService`, a
// foreground `Service` launched by `AndroidStartupReceiver` in response to
// `LOCKED_BOOT_COMPLETED` / `BOOT_COMPLETED` / `USER_UNLOCKED`.
//
// The startup service calls `NativeLayer1Bridge.nativeStartLayer1()` (JNI)
// which maps to `Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeStartLayer1`
// below.  This function creates a minimal `MeshContext`, loads the mesh
// identity keypair (Layer 1), and starts the background subsystems:
// WireGuard tunnel management, cover traffic, relay participation, and gossip.
//
// When Flutter subsequently calls `mesh_init()` it finds the process-global
// `HEADLESS_LAYER1_PTR` set and returns the existing context instead of
// allocating a new one.  This ensures a single `MeshRuntime` is shared
// between the background service and the Flutter UI.

/// Process-global pointer set by the headless Layer 1 startup path.
///
/// Stored as `i64` (matches JNI `jlong`) rather than a raw pointer so the
/// atomic operations are portable.  `0` means "not started".
#[cfg(target_os = "android")]
static HEADLESS_LAYER1_PTR: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// Number of Flutter/UI attachments currently using the headless runtime.
///
/// The Android startup service owns the runtime independently of Flutter.
/// `mesh_init()` increments this counter when it adopts the headless context,
/// and `mesh_destroy()` decrements it when the UI shuts down.
#[cfg(target_os = "android")]
static HEADLESS_LAYER1_ATTACHMENTS: AtomicUsize = AtomicUsize::new(0);

/// Whether the Android startup service currently owns the headless runtime.
///
/// This is set to `true` when `nativeStartLayer1()` succeeds and reset by
/// `nativeStopLayer1()`.  The runtime is dropped only after both:
///   1. the service has released ownership, and
///   2. all Flutter/UI attachments have detached.
#[cfg(target_os = "android")]
static HEADLESS_LAYER1_SERVICE_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "android")]
fn maybe_drop_headless_layer1() {
    let ptr = HEADLESS_LAYER1_PTR.load(Ordering::Acquire);
    if ptr == 0 {
        return;
    }

    let service_active = HEADLESS_LAYER1_SERVICE_ACTIVE.load(Ordering::Acquire);
    let attachments = HEADLESS_LAYER1_ATTACHMENTS.load(Ordering::Acquire);
    if service_active || attachments != 0 {
        return;
    }

    let claimed = HEADLESS_LAYER1_PTR.swap(0, Ordering::AcqRel);
    if claimed == 0 {
        return;
    }

    // SAFETY: the pointer originated from `Box::into_raw` in the headless
    // startup path and is only dropped once after both owners release it.
    unsafe {
        drop(Box::from_raw(claimed as *mut MeshContext));
    }
}

/// Android JNI entry point called by `NativeLayer1Bridge.nativeStartLayer1`.
///
/// Starts Layer 1 participation before Flutter launches:
///   1. Creates a `MeshContext` from the supplied data-directory path.
///   2. Enables mesh-discovery and relay flags so the node participates in
///      routing, cover traffic, and gossip immediately.
///   3. Calls `initialize_startup_state()` and `reconcile_layer1_runtime()`.
///   4. Stores the raw pointer in `HEADLESS_LAYER1_PTR` so `mesh_init()` can
///      reuse it, avoiding a duplicate runtime when Flutter starts.
///
/// Returns the context pointer cast to `i64`, or `0` on failure.
///
/// Thread safety: protected by `HEADLESS_LAYER1_PTR` atomic CAS — only the
/// first successful call allocates; subsequent calls are no-ops that return
/// the existing pointer.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeStartLayer1(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    data_dir: jni::objects::JString,
) -> jni::sys::jlong {
    // If Layer 1 was already started (e.g., service onCreate called twice),
    // return the existing pointer immediately.
    let existing = HEADLESS_LAYER1_PTR.load(Ordering::Acquire);
    if existing != 0 {
        HEADLESS_LAYER1_SERVICE_ACTIVE.store(true, Ordering::Release);
        return existing;
    }

    // Convert the Java String to a Rust &str.
    let dir: String = match env.get_string(&data_dir) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    // Create the data directory if it does not already exist.
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("[Layer1] WARNING: could not create data directory: {dir}");
    }

    // Build a minimal MeshRuntime for Layer 1 participation.
    // Layer 1 only needs: transport (WireGuard), cover traffic, relay, gossip.
    // Identity (Layer 2/3) is not loaded here — that happens at app open.
    let mut runtime = MeshRuntime::new(dir);
    runtime.load_layer1_startup_config();

    // Restore any persisted identity and transport state.
    runtime.initialize_startup_state();

    // Start transport subsystems that are safe to run without a loaded
    // identity: WireGuard tunnel management, cover traffic emission, relay
    // slot acceptance, and tunnel-coordination gossip.
    if let Err(e) = runtime.reconcile_layer1_runtime() {
        eprintln!("[Layer1] reconcile_layer1_runtime failed: {e}");
    }

    // Heap-allocate the context and store the raw pointer.
    let ctx = Box::into_raw(Box::new(MeshContext(Box::new(runtime))));
    let ptr = ctx as i64;

    // CAS: only write if still zero (handles unlikely races on first boot).
    match HEADLESS_LAYER1_PTR.compare_exchange(0, ptr, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {
            HEADLESS_LAYER1_SERVICE_ACTIVE.store(true, Ordering::Release);
            ptr
        }
        Err(existing_ptr) => {
            // Another thread beat us — drop the duplicate and return existing.
            // SAFETY: we just allocated ctx and no one else has seen it.
            unsafe { drop(Box::from_raw(ctx)) };
            HEADLESS_LAYER1_SERVICE_ACTIVE.store(true, Ordering::Release);
            existing_ptr
        }
    }
}

/// Android JNI entry point called when `AndroidStartupService` stops.
///
/// Releases the startup service's ownership of the headless Layer 1 runtime.
/// The runtime is only dropped after both the service and all Flutter/UI
/// attachments have detached.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeStopLayer1(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) {
    HEADLESS_LAYER1_SERVICE_ACTIVE.store(false, Ordering::Release);
    maybe_drop_headless_layer1();
}

/// Android JNI entry point called by `NativeLayer1Bridge.bootstrapLayer1()`.
///
/// Receives the `MeshContext` pointer as a `jlong` (the same value returned by
/// `nativeStartLayer1`) and calls `bootstrap_layer1()` on it to drive deeper
/// Layer 1 subsystem startup:
///
///   1. Verifies the Layer 1 WireGuard keypair is present in memory.
///   2. Syncs the tunnel gossip processor and announcement processor with the
///      mesh public key so WireGuard handshakes and gossip can proceed.
///   3. Refreshes cover traffic parameters for the current activity state.
///   4. Pushes a `Layer1Ready` event for any attached Flutter UI.
///
/// Returns `0` on success, `-1` if the mesh identity keypair is not yet
/// readable (direct-boot mode before first unlock).
///
/// # Safety
///
/// The `ctx` argument must be the exact value previously returned by
/// `nativeStartLayer1`.  Passing any other `jlong` is undefined behaviour.
/// The JVM guarantees the value is not modified between calls.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeBootstrapLayer1(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ctx: jni::sys::jlong,
) -> jni::sys::jint {
    // Guard: a zero pointer means the runtime was never allocated.
    if ctx == 0 {
        return -1;
    }
    // SAFETY: ctx is the pointer returned by nativeStartLayer1 and stored in
    // NativeLayer1Bridge.contextPointer.  It is valid for the lifetime of the
    // startup service, and only freed after both the service and all Flutter
    // attachments have detached (coordinated via HEADLESS_LAYER1_PTR CAS).
    let runtime = unsafe { &*(ctx as *const MeshContext) };
    match runtime.bootstrap_layer1() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[Layer1] nativeBootstrapLayer1 deferred: {e}");
            -1
        }
    }
}

/// Android JNI entry point called by `NativeLayer1Bridge.isLayer1Ready()`.
///
/// Returns `1` if the Layer 1 mesh identity keypair is loaded AND at least
/// one transport type is active.  Returns `0` otherwise.
///
/// This is a lightweight read-only query with no side effects, suitable for
/// polling from the startup service without risk of spurious event emission.
///
/// # Safety
///
/// Same ownership contract as `nativeBootstrapLayer1` above.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeIsLayer1Ready(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ctx: jni::sys::jlong,
) -> jni::sys::jint {
    if ctx == 0 {
        return 0;
    }
    // SAFETY: same as nativeBootstrapLayer1.
    let runtime = unsafe { &*(ctx as *const MeshContext) };
    if runtime.is_layer1_ready() {
        1
    } else {
        0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI entry points for AndroidProximityBridge (Android only)
// ─────────────────────────────────────────────────────────────────────────────
//
// These symbols are called by AndroidProximityBridge.kt via Kotlin `external fun`
// declarations.  The JNI naming convention is:
//
//   Java_<package_path>_<ClassName>_<methodName>
//
// where dots in the package path are replaced with underscores.
//
// The `ctx` parameter is the MeshContext pointer cast to `jlong` (64-bit),
// exactly as stored in `NativeLayer1Bridge.contextPointer`.

/// JNI entry for `AndroidProximityBridge.nativeWifiDirectSessionFd`.
///
/// Receives a connected Wi-Fi Direct TCP socket file descriptor from Kotlin
/// after `WifiP2pManager` establishes a P2P group, and registers it with Rust.
/// After this call Rust exclusively owns the fd — Kotlin must relinquish it.
///
/// # Safety
///
/// `ctx` must be the value returned by `nativeStartLayer1`.
/// `peer_mac` must be a valid non-null JNI string.
/// `fd` must be a valid open connected socket fd detached from the JVM via
/// `ParcelFileDescriptor.fromSocket(socket).detachFd()`.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_AndroidProximityBridge_nativeWifiDirectSessionFd(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ctx: jni::sys::jlong,
    peer_mac: jni::objects::JString,
    fd: jni::sys::jint,
) -> jni::sys::jint {
    if ctx == 0 {
        return -1;
    }
    // Convert JString → Rust &str under a short-lived JavaStr borrow.
    let peer_mac_str = match env.get_string(&peer_mac) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let peer_mac_ref: &str = match peer_mac_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    // SAFETY: ctx is the pointer returned by nativeStartLayer1.
    let runtime = unsafe { &*(ctx as *const MeshContext) };
    match runtime.register_wifi_direct_session_fd(peer_mac_ref, fd) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// JNI entry for `AndroidProximityBridge.nativeWifiDirectDrainSession`.
///
/// Flushes pending outbound frames from Rust's per-session queue to the
/// Rust-owned socket.  Called in a tight loop by the Kotlin drain coroutine.
///
/// Returns the number of frames flushed (>= 0) or -1 on error.
///
/// # Safety
///
/// `ctx` must be the value returned by `nativeStartLayer1`.
/// `peer_mac` must be a valid non-null JNI string.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_AndroidProximityBridge_nativeWifiDirectDrainSession(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ctx: jni::sys::jlong,
    peer_mac: jni::objects::JString,
) -> jni::sys::jint {
    if ctx == 0 {
        return -1;
    }
    let peer_mac_str = match env.get_string(&peer_mac) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let peer_mac_ref: &str = match peer_mac_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    // SAFETY: ctx is the pointer returned by nativeStartLayer1.
    let runtime = unsafe { &*(ctx as *const MeshContext) };
    match runtime.drain_wifi_direct_session(peer_mac_ref) {
        Ok(n) => n as jni::sys::jint,
        Err(_) => -1,
    }
}

/// JNI entry for `AndroidProximityBridge.nativeNfcPopOutboundFrame`.
///
/// Pops one NFC outbound frame from Rust's queue into `buf`.  Called in a
/// tight loop by the Kotlin `nfcOutboundDrainLoop`.
///
/// Returns the number of bytes copied (> 0), 0 if no frame is pending,
/// or -1 on error.
///
/// # Safety
///
/// `ctx` must be the value returned by `nativeStartLayer1`.
/// `buf` must be a valid non-null JNI byte array of at least `buf_len` bytes.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_AndroidProximityBridge_nativeNfcPopOutboundFrame(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ctx: jni::sys::jlong,
    buf: jni::sys::jbyteArray,
    buf_len: jni::sys::jint,
) -> jni::sys::jint {
    if ctx == 0 || buf.is_null() || buf_len <= 0 {
        return -1;
    }
    // Allocate a temporary Rust buffer of the requested size.
    let mut rust_buf = vec![0u8; buf_len as usize];
    let n = match crate::transport::nfc::pop_outbound_frame(&mut rust_buf) {
        Some(n) => n,
        None => return 0, // no frame pending
    };
    // Copy the frame bytes into the JVM byte array.
    // SAFETY: `buf` is a valid JNI byte array of at least `buf_len` bytes.
    let copy_result = unsafe {
        env.set_byte_array_region(
            jni::objects::JByteArray::from_raw(buf),
            0,
            std::slice::from_raw_parts(rust_buf.as_ptr() as *const jni::sys::jbyte, n),
        )
    };
    if copy_result.is_err() {
        return -1;
    }
    n as jni::sys::jint
}

/// JNI entry for `AndroidProximityBridge.nativeNfcPushInboundFrame`.
///
/// Pushes one inbound NFC frame (received from an LLCP link or NDEF read)
/// into the Rust backend's inbound queue.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
///
/// `ctx` must be the value returned by `nativeStartLayer1`.
/// `data` must be a valid non-null JNI byte array.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_AndroidProximityBridge_nativeNfcPushInboundFrame(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ctx: jni::sys::jlong,
    data: jni::sys::jbyteArray,
    data_len: jni::sys::jint,
) -> jni::sys::jint {
    if ctx == 0 || data.is_null() || data_len <= 0 {
        return -1;
    }
    // Copy the JVM byte array into a Rust Vec.
    let mut frame = vec![0i8; data_len as usize];
    let copy_result = unsafe {
        env.get_byte_array_region(
            jni::objects::JByteArray::from_raw(data),
            0,
            &mut frame,
        )
    };
    if copy_result.is_err() {
        return -1;
    }
    // Cast i8 → u8 (JNI signed bytes → Rust unsigned bytes).
    let frame_u8: Vec<u8> = frame.into_iter().map(|b| b as u8).collect();
    // `enqueue_android_inbound_frame` guards on adapter state (available && enabled).
    crate::transport::nfc::enqueue_android_inbound_frame(frame_u8);
    // SAFETY: ctx is the pointer returned by nativeStartLayer1.
    let runtime = unsafe { &*(ctx as *const MeshContext) };
    runtime.push_event(
        "AndroidNfcInboundFrameReceived",
        serde_json::json!({ "byteLength": data_len }),
    );
    0
}

/// Destroy the context and free all resources.
///
/// Must be called exactly once at app shutdown.  After this call, `ctx` is
/// invalid and must not be used again.
///
/// # Safety
/// `ctx` must have been returned by `mesh_init` and not yet destroyed.
/// No other thread may hold a reference to `ctx` at the time of this call.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mesh_destroy(ctx: *mut MeshContext) {
    // Null ctx is a no-op rather than a hard error for defensive robustness.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return;
    }

    #[cfg(target_os = "android")]
    {
        let headless_ptr = HEADLESS_LAYER1_PTR.load(Ordering::Acquire) as *mut MeshContext;
        if ctx == headless_ptr && !headless_ptr.is_null() {
            let _ = HEADLESS_LAYER1_ATTACHMENTS.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |count| count.checked_sub(1),
            );
            maybe_drop_headless_layer1();
            return;
        }
    }

    // SAFETY: `ctx` was allocated by `Box::into_raw` in `mesh_init`; this
    // is the unique ownership-reclaim point.
    // Execute this protocol step.
    unsafe {
        drop(Box::from_raw(ctx));
    }
}

// ---------------------------------------------------------------------------
// Error retrieval
// ---------------------------------------------------------------------------

/// Return the last error string stored in the context.
///
/// Returns null if no error has been set since the last successful call.
/// The pointer is valid until the next FFI call that writes `last_error`.
///
/// # Safety
/// `ctx` must be non-null and point to a valid `MeshContext`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_last_error(ctx: *mut MeshContext) -> *const c_char {
    // Guard: a null ctx means the runtime was never initialised.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null, valid for the duration of this call.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Return the stored error pointer if one exists, null otherwise.
    // Dispatch on the variant.
    match ctx
        .last_error
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s.as_ptr(),
        // Update the local state.
        // No value available.
        None => ptr::null(),
    }
}

/// Return the last error string.
///
/// - If `ctx` is non-null: returns the post-init error stored in the context.
/// - If `ctx` is null: returns the pre-init error from thread-local storage.
///
/// # Safety
/// `ctx` must be null or a valid `MeshContext` pointer.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_last_error_message(ctx: *mut MeshContext) -> *const c_char {
    // Null ctx → read from the pre-init thread-local error store.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        // Apply the closure to each element.
        // Return to the caller.
        return PREINIT_ERROR.with(|e| {
            // Transform the result, mapping errors to the local error type.
            // Transform each element.
            e.borrow()
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(ptr::null())
        });
    }
    // Non-null ctx → delegate to the standard error accessor.
    // Execute this protocol step.
    unsafe { mi_get_last_error(ctx) }
}

/// No-op free stub.
///
/// Strings are owned by the context's `last_response` field — Flutter must
/// not free them.  This stub exists for ABI completeness.
///
/// # Safety
/// `_ptr` is ignored.  Passing any pointer is safe; no memory is freed.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_string_free(_ptr: *mut c_char) {
    // No-op: string lifetime is tied to the MeshContext, not the caller.
}

// ---------------------------------------------------------------------------
// Identity (§3)
// ---------------------------------------------------------------------------

/// Check whether an identity file exists on this device.
///
/// Returns 1 if an identity exists, 0 otherwise.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_has_identity(ctx: *mut MeshContext) -> i32 {
    // Return 0 rather than panicking on a null context.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees non-null, valid for this call.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate the file-existence check to the service layer.
    // Guard: validate the condition before proceeding.
    if ctx.has_identity() {
        1
    } else {
        0
    }
}

/// Create a new identity with an optional display name.
///
/// Generates fresh Ed25519, X25519, preauth-X25519, and ML-KEM-768 key pairs,
/// persists to `identity.dat`, and initialises the vault.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `display_name` may be null (treated as no name), or a valid NUL-terminated
/// UTF-8 string.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_create_identity(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    display_name: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: reject null context immediately.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access during this call.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &mut *ctx };
    // Parse optional display name (null → None).
    // Compute name for this protocol step.
    let name = unsafe { c_str_to_str(display_name) }.map(|s| s.to_string());
    // Dispatch to service layer; map Ok/Err to 0/-1.
    // Dispatch on the variant.
    match ctx.create_identity(name) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Unlock an existing identity from disk.
///
/// Pass null `pin` if no PIN was set.  On success restores vault state and
/// emits `SettingsUpdated`.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `pin` may be null or a valid NUL-terminated UTF-8 string.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_unlock_identity(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    pin: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: reject null context immediately.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &mut *ctx };
    // Parse optional PIN string.
    // Compute pin str for this protocol step.
    let pin_str = unsafe { c_str_to_str(pin) }.map(|s| s.to_string());
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.unlock_identity(pin_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return security configuration for app-lock and emergency-erase settings.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_security_config(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_security_config())
}

/// Persist backend-owned security settings from a JSON payload.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `config_json` must be valid UTF-8 NUL-terminated JSON.
#[no_mangle]
pub unsafe extern "C" fn mi_set_security_config(
    ctx: *mut MeshContext,
    config_json: *const c_char,
) -> i32 {
    if ctx.is_null() || config_json.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(config_json) = (unsafe { c_str_to_str(config_json) }) else {
        ctx.set_error("Security config must be valid UTF-8");
        return -1;
    };
    match ctx.set_security_config(config_json) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Set or replace the app PIN on the currently unlocked identity.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `pin` must be a valid UTF-8 NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn mi_set_pin(ctx: *mut MeshContext, pin: *const c_char) -> i32 {
    if ctx.is_null() || pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let Some(pin_str) = (unsafe { c_str_to_str(pin) }).map(str::to_string) else {
        ctx.set_error("PIN must be valid UTF-8");
        return -1;
    };
    match ctx.set_pin(pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Change the app PIN after verifying the current PIN.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `current_pin` and `new_pin` must be valid UTF-8 NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn mi_change_pin(
    ctx: *mut MeshContext,
    current_pin: *const c_char,
    new_pin: *const c_char,
) -> i32 {
    if ctx.is_null() || current_pin.is_null() || new_pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let Some(current_pin_str) = (unsafe { c_str_to_str(current_pin) }).map(str::to_string) else {
        ctx.set_error("Current PIN must be valid UTF-8");
        return -1;
    };
    let Some(new_pin_str) = (unsafe { c_str_to_str(new_pin) }).map(str::to_string) else {
        ctx.set_error("New PIN must be valid UTF-8");
        return -1;
    };
    match ctx.change_pin(current_pin_str, new_pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Remove the app PIN after verifying the current PIN.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `current_pin` must be a valid UTF-8 NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn mi_remove_pin(ctx: *mut MeshContext, current_pin: *const c_char) -> i32 {
    if ctx.is_null() || current_pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let Some(current_pin_str) = (unsafe { c_str_to_str(current_pin) }).map(str::to_string) else {
        ctx.set_error("Current PIN must be valid UTF-8");
        return -1;
    };
    match ctx.remove_pin(current_pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Set or replace the duress PIN on the currently unlocked identity.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `pin` must be a valid UTF-8 NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn mi_set_duress_pin(ctx: *mut MeshContext, pin: *const c_char) -> i32 {
    if ctx.is_null() || pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(pin_str) = (unsafe { c_str_to_str(pin) }).map(str::to_string) else {
        ctx.set_error("Duress PIN must be valid UTF-8");
        return -1;
    };
    match ctx.set_duress_pin(pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Change the duress PIN after verifying the current duress PIN.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `current_pin` and `new_pin` must be valid UTF-8 NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn mi_change_duress_pin(
    ctx: *mut MeshContext,
    current_pin: *const c_char,
    new_pin: *const c_char,
) -> i32 {
    if ctx.is_null() || current_pin.is_null() || new_pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(current_pin_str) = (unsafe { c_str_to_str(current_pin) }).map(str::to_string) else {
        ctx.set_error("Current duress PIN must be valid UTF-8");
        return -1;
    };
    let Some(new_pin_str) = (unsafe { c_str_to_str(new_pin) }).map(str::to_string) else {
        ctx.set_error("New duress PIN must be valid UTF-8");
        return -1;
    };
    match ctx.change_duress_pin(current_pin_str, new_pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Remove the duress PIN after verifying the current duress PIN.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// `current_pin` must be a valid UTF-8 NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn mi_remove_duress_pin(
    ctx: *mut MeshContext,
    current_pin: *const c_char,
) -> i32 {
    if ctx.is_null() || current_pin.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(current_pin_str) = (unsafe { c_str_to_str(current_pin) }).map(str::to_string) else {
        ctx.set_error("Current duress PIN must be valid UTF-8");
        return -1;
    };
    match ctx.remove_duress_pin(current_pin_str) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return the current identity summary as a JSON string.
///
/// JSON shape: `{"locked":bool,"peerId"?:string,"ed25519Pub"?:string,"displayName"?:string}`.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_identity_summary(ctx: *mut MeshContext) -> *const c_char {
    // Guard: a null ctx cannot hold a summary.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer and store the response string.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_identity_summary())
}

/// Alias for `mi_get_identity_summary` (legacy name).
///
/// # Safety
/// Same as `mi_get_identity_summary`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_local_identity_json(ctx: *mut MeshContext) -> *const c_char {
    // Forward to the canonical implementation.
    // Execute this protocol step.
    unsafe { mi_get_identity_summary(ctx) }
}

/// Return the current device list as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_devices_json(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_devices_json())
}

/// Create a device-enrollment request payload for linking this device.
///
/// # Safety
/// `ctx` must be non-null and `device_name` must be null or valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_create_device_enrollment_request(
    ctx: *mut MeshContext,
    device_name: *const c_char,
) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    let name = if device_name.is_null() {
        None
    } else {
        match unsafe { c_str_to_str(device_name) } {
            Some(value) => Some(value.to_string()),
            None => {
                ctx.set_error("Device name must be valid UTF-8");
                return ptr::null();
            }
        }
    };
    match ctx.create_device_enrollment_request(name) {
        Ok(payload) => ctx.set_response(&payload),
        Err(err) => {
            ctx.set_error(&err);
            ptr::null()
        }
    }
}

/// Complete a device-enrollment request on the primary device.
///
/// # Safety
/// `ctx` and `request_json` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mi_complete_device_enrollment(
    ctx: *mut MeshContext,
    request_json: *const c_char,
) -> *const c_char {
    if ctx.is_null() || request_json.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &mut *ctx };
    let Some(request_json) = (unsafe { c_str_to_str(request_json) }).map(str::to_string) else {
        ctx.set_error("Device enrollment request must be valid UTF-8");
        return ptr::null();
    };
    match ctx.complete_device_enrollment(&request_json) {
        Ok(payload) => ctx.set_response(&payload),
        Err(err) => {
            ctx.set_error(&err);
            ptr::null()
        }
    }
}

/// Accept a device-enrollment package on the target device.
///
/// # Safety
/// `ctx` and `package_json` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mi_accept_device_enrollment(
    ctx: *mut MeshContext,
    package_json: *const c_char,
) -> i32 {
    if ctx.is_null() || package_json.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *ctx };
    let Some(package_json) = (unsafe { c_str_to_str(package_json) }).map(str::to_string) else {
        ctx.set_error("Device enrollment package must be valid UTF-8");
        return -1;
    };
    match ctx.accept_device_enrollment(&package_json) {
        Ok(()) => 0,
        Err(err) => {
            ctx.set_error(&err);
            -1
        }
    }
}

/// Remove a registered secondary device from the shared identity.
///
/// # Safety
/// `ctx` and `device_id` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mi_remove_device(ctx: *mut MeshContext, device_id: *const c_char) -> i32 {
    if ctx.is_null() || device_id.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(device_id) = (unsafe { c_str_to_str(device_id) }) else {
        ctx.set_error("Device id must be valid UTF-8");
        return -1;
    };
    match ctx.remove_device(device_id) {
        Ok(()) => 0,
        Err(err) => {
            ctx.set_error(&err);
            -1
        }
    }
}

/// Return stored mask metadata as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_masks_json(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_masks_json())
}

/// Create a new mask from a JSON payload.
///
/// # Safety
/// `ctx` must be non-null and `mask_json` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_create_mask(ctx: *mut MeshContext, mask_json: *const c_char) -> i32 {
    if ctx.is_null() || mask_json.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let Some(mask_json) = (unsafe { c_str_to_str(mask_json) }) else {
        ctx.set_error("Mask payload must be valid UTF-8");
        return -1;
    };
    match ctx.create_mask(mask_json) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Import social state from an encrypted backup (§3.7).
///
/// `backup_b64_json` may be raw base64 or `{"backup_b64":"..."}`.
/// Identity private keys are never restored — only contacts, rooms, messages.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
/// Both string arguments must be non-null, valid NUL-terminated UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_import_identity(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    backup_b64_json: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    passphrase: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: reject null context.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &mut *ctx };
    // Parse required string arguments.
    // Compute backup str for this protocol step.
    let backup_str = match unsafe { c_str_to_str(backup_b64_json) } {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s,
        // Update the local state.
        // No value available.
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute pass str for this protocol step.
    let pass_str = match unsafe { c_str_to_str(passphrase) } {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s,
        // Update the local state.
        // No value available.
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.import_identity_backup(backup_str, pass_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Non-emergency wipe of in-memory identity and social state.
///
/// Does not remove files from disk.  Call to implement a logout flow.
///
/// Returns 0 (always succeeds if ctx is non-null).
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_reset_identity(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx is a no-op.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &mut *ctx };
    // Delegate wipe to service layer.
    // Execute this protocol step.
    ctx.reset_identity();
    0
}

/// Set the public profile visible to all contacts (§9.1).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `json` must be non-null, valid NUL-terminated UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_public_profile(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    json: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: reject null context.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse JSON argument.
    // Compute profile json for this protocol step.
    let profile_json = match unsafe { c_str_to_str(json) } {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s,
        // Update the local state.
        // No value available.
        None => return -1,
    };
    // Dispatch to service layer.
    // Dispatch on the variant.
    match ctx.set_public_profile(profile_json) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Set the private profile shared only with trusted contacts (§9.2).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `json` must be non-null, valid NUL-terminated UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_private_profile(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    json: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: reject null context.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse JSON argument.
    // Compute profile json for this protocol step.
    let profile_json = match unsafe { c_str_to_str(json) } {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s,
        // Update the local state.
        // No value available.
        None => return -1,
    };
    // Dispatch to service layer.
    // Dispatch on the variant.
    match ctx.set_private_profile(profile_json) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Backup (§3.7)
// ---------------------------------------------------------------------------

/// Create an encrypted backup of contacts, rooms, and optionally messages.
///
/// `backup_type`: 0 = Standard (contacts + rooms), 1 = Extended (+ messages).
/// Returns JSON `{"ok":true,"backup_b64":"..."}` or `{"ok":false,"error":"..."}`.
///
/// # Safety
/// `ctx` must be non-null.  `passphrase` must be non-null, valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_create_backup(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    passphrase: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    backup_type: u8,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot create a backup.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required passphrase.
    // Compute pass for this protocol step.
    let pass = match unsafe { c_str_to_str(passphrase) } {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s,
        // Update the local state.
        // No value available.
        None => return ctx.set_response(r#"{"ok":false,"error":"passphrase required"}"#),
    };
    // Delegate to service layer and return the result JSON.
    // Execute this protocol step.
    ctx.set_response(&ctx.create_backup(pass, backup_type))
}

// ---------------------------------------------------------------------------
// Emergency / duress erase (§3.9)
// ---------------------------------------------------------------------------

/// Standard emergency erase: destroy all identity layers (§3.9.1).
///
/// Returns 0 on success, -1 if ctx is null.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_emergency_erase(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot be erased.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &mut *ctx };
    // Dispatch to service layer for the actual wipe.
    // Execute this protocol step.
    ctx.emergency_erase();
    0
}

/// Duress erase: preserve Layer 1, destroy Layers 2 and 3 (§3.9.2).
///
/// Returns 0 on success, -1 if ctx is null.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_duress_erase(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot be erased.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &mut *ctx };
    // Dispatch duress wipe to service layer.
    // Execute this protocol step.
    ctx.duress_erase();
    0
}

// ---------------------------------------------------------------------------
// Rooms / Conversations
// ---------------------------------------------------------------------------

/// Return the full room list as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_room_list(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no rooms.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate room list serialisation to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_room_list())
}

/// Alias for `mi_get_room_list` (legacy name).
///
/// # Safety
/// Same as `mi_get_room_list`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_rooms_json(ctx: *mut MeshContext) -> *const c_char {
    // Forward to the canonical implementation.
    // Execute this protocol step.
    unsafe { mi_get_room_list(ctx) }
}

/// Create a new room.  `peer_id` may be null for a standalone room.
///
/// Returns JSON `{"id":"...","name":"..."}` or null on failure.
///
/// # Safety
/// `ctx` must be non-null.  `name` must be non-null, valid UTF-8.
/// `peer_id` may be null or a valid hex peer-ID string.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_create_room(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    name: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot hold rooms.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &mut *ctx };
    // Parse room name; default to "New Chat" if null.
    // Compute room name for this protocol step.
    let room_name = unsafe { c_str_to_str(name) }.unwrap_or("New Chat");
    // Parse optional peer ID for DM rooms.
    // Compute pid str for this protocol step.
    let pid_str = unsafe { c_str_to_str(peer_id) };
    // Delegate room creation to service layer.
    // Dispatch on the variant.
    match ctx.create_room(room_name, pid_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(id_hex) => {
            // Serialize to the wire format for transmission or storage.
            // Compute json for this protocol step.
            let json = serde_json::json!({"id": id_hex, "name": room_name}).to_string();
            // Process the current step in the protocol.
            // Execute this protocol step.
            ctx.set_response(&json)
        }
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            ptr::null()
        }
    }
}

/// Delete a room and its message history.
///
/// Returns 0 on success, -1 if the room was not found.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` must be non-null, valid UTF-8.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_delete_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
    // Guard: reject null context.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    // Compute rid for this protocol step.
    let rid = match unsafe { c_str_to_str(room_id) } {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s,
        // Update the local state.
        // No value available.
        None => return -1,
    };
    // Dispatch to service layer; map bool result to 0/-1.
    // Guard: validate the condition before proceeding.
    if ctx.delete_room(rid) {
        0
    } else {
        -1
    }
}

/// Return messages for a room as a JSON array.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` must be non-null, valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_messages(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx has no messages.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    // Compute rid for this protocol step.
    let rid = unsafe { c_str_to_str(room_id) }.unwrap_or("");
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_messages(rid))
}

/// Alias for `mi_get_messages` (legacy name).
///
/// # Safety
/// Same as `mi_get_messages`.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_messages_json(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Forward to the canonical implementation.
    // Execute this protocol step.
    unsafe { mi_get_messages(ctx, room_id) }
}

/// Return the active conversation room ID as a JSON string (`"null"` if none).
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_active_room_id(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no active room.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate active-room query to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.active_room_id())
}

/// Alias for `mi_set_active_conversation` (legacy name).
///
/// # Safety
/// Same as `mi_set_active_conversation`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_select_room(ctx: *mut MeshContext, room_id: *const c_char) -> i32 {
    // Forward to the canonical implementation.
    // Execute this protocol step.
    unsafe { mi_set_active_conversation(ctx, room_id) }
}

// ---------------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------------

/// Send a text message to a room.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` and `text` must be valid UTF-8 strings.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_send_text_message(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    text: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot send messages.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute rid for this protocol step.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute txt for this protocol step.
    let txt = match unsafe { c_str_to_str(text) } {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    // Dispatch to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.send_text_message(rid, txt) {
        0
    } else {
        -1
    }
}

/// Send a message (full form with optional security mode override).
///
/// Delegates to `mi_send_text_message` — the `security_mode` parameter is
/// reserved for future use.
///
/// # Safety
/// Same as `mi_send_text_message`.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_send_message(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    _security_mode: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    text: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Forward to the text-message implementation.
    // Execute this protocol step.
    unsafe { mi_send_text_message(ctx, room_id, text) }
}

/// Delete a message from local storage (local-only).
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null.  `msg_id` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_delete_message(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    msg_id: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot delete messages.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required message-ID argument.
    // Compute mid for this protocol step.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.delete_message(mid);
    0
}

/// Send a reaction emoji to a message and broadcast it to room participants.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  All string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_send_reaction(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    msg_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    emoji: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: reject null context.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse all three required arguments.
    // Compute rid for this protocol step.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute mid for this protocol step.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute emj for this protocol step.
    let emj = match unsafe { c_str_to_str(emoji) } {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    // Delegate to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.send_reaction(rid, mid, emj) {
        0
    } else {
        -1
    }
}

/// Mark a message as read and reset the room's unread counter.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_send_read_receipt(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    msg_id: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no rooms to mark read.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute rid for this protocol step.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute mid for this protocol step.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.send_read_receipt(rid, mid);
    0
}

/// Emit a typing indicator and broadcast it to room participants.
///
/// `active`: non-zero = currently typing, 0 = stopped.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_send_typing_indicator(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Execute this protocol step.
    active: i32,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot broadcast typing events.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    // Compute rid for this protocol step.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.send_typing_indicator(rid, active != 0);
    0
}

/// Send a reply message that quotes an earlier message.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  All string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_reply_to_message(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    reply_to: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    text: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot send messages.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &mut *ctx };
    // Parse all three required arguments.
    // Compute rid for this protocol step.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute rto for this protocol step.
    let rto = match unsafe { c_str_to_str(reply_to) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute txt for this protocol step.
    let txt = match unsafe { c_str_to_str(text) } {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    // Delegate to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.reply_to_message(rid, rto, txt) {
        0
    } else {
        -1
    }
}

/// Edit the text of a previously sent message (own messages only).
///
/// Returns 0 on success, -1 if the message was not found or not editable.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_edit_message(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    msg_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    new_text: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no messages to edit.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute mid for this protocol step.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute ntxt for this protocol step.
    let ntxt = match unsafe { c_str_to_str(new_text) } {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    // Delegate to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.edit_message(mid, ntxt) {
        0
    } else {
        -1
    }
}

/// Delete a message for all participants.
///
/// Returns 0 on success, -1 if not found.
///
/// # Safety
/// `ctx` must be non-null.  `msg_id` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_delete_for_everyone(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    msg_id: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no messages.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required message-ID argument.
    // Compute mid for this protocol step.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.delete_for_everyone(mid).is_some() {
        0
    } else {
        -1
    }
}

/// Forward a message to a different room.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_forward_message(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    msg_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    target_room: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot forward messages.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &mut *ctx };
    // Parse required arguments.
    // Compute mid for this protocol step.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute tgt for this protocol step.
    let tgt = match unsafe { c_str_to_str(target_room) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.forward_message(mid, tgt) {
        0
    } else {
        -1
    }
}

/// Pin a message in the conversation.
///
/// Returns 0 on success, -1 if not found.
///
/// # Safety
/// `ctx` must be non-null.  `msg_id` must be valid UTF-8.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_pin_message(ctx: *mut MeshContext, msg_id: *const c_char) -> i32 {
    // Guard: null ctx has no messages.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required argument.
    // Compute mid for this protocol step.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.pin_message(mid) {
        0
    } else {
        -1
    }
}

/// Unpin a previously pinned message.
///
/// Returns 0 on success, -1 if not found.
///
/// # Safety
/// `ctx` must be non-null.  `msg_id` must be valid UTF-8.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_unpin_message(ctx: *mut MeshContext, msg_id: *const c_char) -> i32 {
    // Guard: null ctx has no messages.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required argument.
    // Compute mid for this protocol step.
    let mid = match unsafe { c_str_to_str(msg_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.unpin_message(mid) {
        0
    } else {
        -1
    }
}

/// Set or clear the disappearing-message timer for a room (0 = disabled).
///
/// Returns 0 on success, -1 if the room was not found.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_disappearing_timer(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Execute this protocol step.
    secs: u64,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no rooms.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    // Compute rid for this protocol step.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.set_disappearing_timer(rid, secs) {
        0
    } else {
        -1
    }
}

/// Full-text search across all in-memory messages.
///
/// Returns a JSON array of matching message objects.
///
/// # Safety
/// `ctx` must be non-null.  `query` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_search_messages(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    query: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx has no messages to search.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse optional query (null → empty → returns []).
    // Compute q for this protocol step.
    let q = unsafe { c_str_to_str(query) }.unwrap_or("");
    // Delegate full-text search to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.search_messages(q))
}

/// Remove expired messages from all rooms.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_prune_expired_messages(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot prune.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate expiry pruning to service layer.
    // Execute this protocol step.
    ctx.prune_expired_messages();
    0
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------

/// Return the peer list as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_peer_list(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no peers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate peer-list serialisation to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_peer_list())
}

/// Pair with a peer by accepting their pairing payload (§8.3).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `peer_data` must be valid JSON UTF-8.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_pair_peer(ctx: *mut MeshContext, peer_data: *const c_char) -> i32 {
    // Guard: reject null context.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse the pairing payload JSON string.
    // Compute json str for this protocol step.
    let json_str = match unsafe { c_str_to_str(peer_data) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate pairing to service layer.
    // Dispatch on the variant.
    match ctx.pair_peer(json_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return the backend-owned Android proximity snapshot as JSON.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_android_proximity_state_json(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_android_proximity_state_json())
}

/// Update the backend-owned Android proximity snapshot from the platform layer.
///
/// # Safety
/// `ctx` must be non-null. `state_json` must be valid UTF-8 JSON.
#[no_mangle]
pub unsafe extern "C" fn mi_android_proximity_update_state(
    ctx: *mut MeshContext,
    state_json: *const c_char,
) -> i32 {
    if ctx.is_null() || state_json.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let state_json = match unsafe { c_str_to_str(state_json) } {
        Some(json) => json,
        None => {
            ctx.set_error("invalid android proximity state");
            return -1;
        }
    };
    match ctx.update_android_proximity_state(state_json) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Return the backend-owned Android startup snapshot as JSON.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_android_startup_state_json(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_android_startup_state_json())
}

/// Update the backend-owned Android startup snapshot from the platform layer.
///
/// # Safety
/// `ctx` must be non-null. `state_json` must be valid UTF-8 JSON.
#[no_mangle]
pub unsafe extern "C" fn mi_android_startup_update_state(
    ctx: *mut MeshContext,
    state_json: *const c_char,
) -> i32 {
    if ctx.is_null() || state_json.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let state_json = match unsafe { c_str_to_str(state_json) } {
        Some(json) => json,
        None => {
            ctx.set_error("invalid android startup state");
            return -1;
        }
    };
    match ctx.update_android_startup_state(state_json) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Bootstrap all Layer 1 subsystems (§3.1.1) after device unlock.
///
/// This is the FFI entry point called by `AndroidStartupService` immediately
/// after `nativeStartLayer1()` returns a valid context pointer.  It is also
/// called by `mi_android_startup_update_state` indirectly (via
/// `reconcile_layer1_runtime`) when the mesh identity keypair becomes
/// available for the first time.
///
/// # What this does
///
/// 1. Verifies the Layer 1 mesh identity keypair is loaded (device-unlock
///    accessible key material; stored without `UserAuthenticationRequired`).
/// 2. Initialises the Layer 1 WireGuard interface by syncing the gossip and
///    announcement processors with the mesh public key.
/// 3. Starts cover traffic emission by refreshing participation state, which
///    picks the correct `CoverTrafficParams` for the current activity state.
/// 4. Starts tunnel-coordination gossip participation.
/// 5. Pushes a `Layer1Ready` event to the event queue so the Flutter UI (if
///    attached) can update its network status display without polling.
///
/// # Return value
///
/// Returns `0` on success.  Returns `-1` if the mesh identity keypair is not
/// yet available — this occurs in direct-boot mode before the first user
/// unlock when device-protected storage has not been unlocked yet.  The
/// caller should retry on the next `USER_UNLOCKED` intent.
///
/// # Safety
/// `ctx` must be non-null and must have been returned by `mesh_init` or
/// `nativeStartLayer1`.
#[no_mangle]
pub unsafe extern "C" fn mi_bootstrap_layer1(ctx: *mut MeshContext) -> i32 {
    // Guard: null context is always an error.
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.bootstrap_layer1() {
        Ok(()) => 0,
        Err(error) => {
            // Store the error so the caller can retrieve it via `mi_last_error`.
            ctx.set_error(&error);
            -1
        }
    }
}

/// Query whether all Layer 1 subsystems are up and participating.
///
/// Returns `1` if the mesh identity keypair is loaded AND at least one
/// transport type is currently active.  Returns `0` otherwise.
///
/// This is a lightweight, lock-based query with no side effects.  It is safe
/// to call repeatedly from the startup service polling loop without risk of
/// spurious event emission.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_is_layer1_ready(ctx: *mut MeshContext) -> i32 {
    // Guard: null context → not ready.
    if ctx.is_null() {
        return 0;
    }
    let ctx = unsafe { &*ctx };
    if ctx.is_layer1_ready() {
        1
    } else {
        0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Keystore-backed mesh identity inject / export (§3.1.1)
// ─────────────────────────────────────────────────────────────────────────────
//
// These two C-ABI entry points are the bridge between Android Keystore
// hardware protection and the Rust runtime's in-memory identity slot.
//
// ## Why these exist
//
// `load_or_create_mesh_identity()` writes/reads the 32-byte WireGuard private
// key as raw bytes to `data_dir/mesh_identity.key`.  On Android, an attacker
// with root or physical flash access can read that file.  Wrapping the key with
// an Android Keystore AES-256-GCM entry (`setUserAuthenticationRequired(false)`)
// ties the AES wrapping key to the hardware security module (TEE/StrongBox):
// the ciphertext on disk is useless without the device hardware.
//
// ## Startup flow (§3.1.1)
//
//   Boot / unlock →
//     AndroidStartupService.startLayer1IfNeeded()
//       → NativeLayer1Bridge.startLayer1()          (creates runtime, file-based key loaded)
//       → tryLoadFromKeystore()                     (unwrap Keystore blob → 32 bytes)
//       → mi_layer1_inject_secret()  ← this fn     (overwrite in-memory key with hw-backed copy)
//       → bootstrapLayer1IfNeeded()                 (WireGuard, gossip, cover traffic)
//
//   First boot (no Keystore blob yet):
//       → NativeLayer1Bridge.startLayer1()          (generates + writes file-based key)
//       → mi_layer1_export_secret()  ← this fn     (read 32 bytes from in-memory identity)
//       → KeystoreBridge.wrapKey()                  (AES-256-GCM encrypt with hw key)
//       → keystoreFile.writeBytes()                 (persist wrapped blob)
//       → bootstrapLayer1IfNeeded()

/// Inject 32 raw secret bytes as the in-memory mesh identity, bypassing the
/// filesystem.
///
/// Called by the Android startup service when the Keystore-backed wrapped copy
/// of the Layer 1 secret has been successfully unwrapped.  The Keystore copy
/// takes precedence over the on-disk `mesh_identity.key` file.
///
/// `data`  — pointer to exactly `len` bytes of raw WireGuard private key
///           entropy.  Must be valid for the duration of this call; the bytes
///           are copied into a stack buffer immediately and not retained.
/// `len`   — must be exactly 32; any other value returns `-1`.
///
/// Returns `0` on success, `-1` on error (null pointer, wrong length).
///
/// # Safety
///
/// `ctx` must be the value returned by `mesh_init` or `nativeStartLayer1`.
/// `data` must point to at least `len` readable bytes for the duration of
/// this call.  The caller may zero or free `data` immediately after return.
#[no_mangle]
pub unsafe extern "C" fn mi_layer1_inject_secret(
    ctx: *mut MeshContext,
    data: *const u8,
    len: i32,
) -> i32 {
    // Guard: null context pointer is always a programming error.
    if ctx.is_null() || data.is_null() {
        return -1;
    }

    // Only 32-byte secrets are valid for X25519 / WireGuard.
    if len != 32 {
        return -1;
    }

    // Copy the bytes into a stack buffer so the caller can zero `data`
    // immediately after this function returns without affecting us.
    // SAFETY: caller guarantees `data` is valid for `len` bytes.
    let mut secret = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(data, secret.as_mut_ptr(), 32) };

    // Inject the secret into the runtime.  This overwrites any identity
    // previously loaded from the file-based path, making the Keystore copy
    // the authoritative in-memory value.
    let ctx = unsafe { &*ctx };
    match ctx.inject_mesh_identity_secret(secret) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&format!("mi_layer1_inject_secret: {e}"));
            -1
        }
    }
}

/// Export the current 32-byte mesh identity secret into a caller-supplied
/// buffer.
///
/// Used by the Android startup service on first boot (or after a Keystore
/// entry deletion) to retrieve the freshly generated / file-loaded secret so
/// it can be wrapped with the hardware-backed AES key.  The caller must zero
/// `buf` immediately after passing it to `KeystoreBridge.wrapKey()`.
///
/// `buf`     — pointer to a caller-owned buffer of at least `buf_len` bytes.
/// `buf_len` — must be >= 32; any smaller value returns `-1`.
///
/// Returns `32` on success (number of bytes written), `-1` if no identity is
/// loaded yet or if `buf` is too small.
///
/// # Safety
///
/// `ctx` must be the value returned by `mesh_init` or `nativeStartLayer1`.
/// `buf` must point to at least `buf_len` writable bytes for the duration of
/// this call.
#[no_mangle]
pub unsafe extern "C" fn mi_layer1_export_secret(
    ctx: *mut MeshContext,
    buf: *mut u8,
    buf_len: i32,
) -> i32 {
    // Guard: null pointers or undersized buffer are programming errors.
    if ctx.is_null() || buf.is_null() || buf_len < 32 {
        return -1;
    }

    let ctx = unsafe { &*ctx };
    match ctx.export_mesh_identity_secret() {
        Some(secret) => {
            // Copy into the caller's buffer.
            // SAFETY: caller guarantees `buf` is valid for `buf_len` bytes,
            // and we checked buf_len >= 32 above.
            unsafe { std::ptr::copy_nonoverlapping(secret.as_ptr(), buf, 32) };
            32
        }
        // No identity loaded yet (e.g., called before initialize_startup_state).
        None => -1,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI entry points for NativeLayer1Bridge — Keystore secret inject / export
// ─────────────────────────────────────────────────────────────────────────────
//
// These JNI symbols are the Android-specific bridge between the Kotlin Keystore
// path and the C-ABI functions above.  They translate JNI types (jlong, jbyteArray)
// into Rust types and delegate to `mi_layer1_inject_secret` /
// `mi_layer1_export_secret`.
//
// Naming follows the JNI convention:
//   Java_<package>_<Class>_<methodName>
// where dots in the package name are replaced with underscores.

/// JNI entry point for `NativeLayer1Bridge.nativeInjectLayer1Secret`.
///
/// Receives the context pointer as a `jlong` and the raw secret as a Java
/// `byte[]`.  Copies the bytes into a Rust `[u8; 32]` stack buffer, calls
/// `inject_mesh_identity_secret`, then returns:
///   0  — success
///  -1  — null pointer, wrong array length, or JNI error
///
/// # Safety
///
/// `ctx_long` must be the value returned by `nativeStartLayer1`.
/// `data` must be a valid non-null JNI byte array of exactly 32 bytes.
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "system" fn Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeInjectLayer1Secret(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ctx_long: jni::sys::jlong,
    data: jni::objects::JByteArray,
) -> jni::sys::jint {
    // Guard: a zero context pointer means the runtime was never allocated.
    if ctx_long == 0 {
        return -1;
    }

    // Retrieve the byte array length before copying.
    let len = match env.get_array_length(&data) {
        Ok(n) => n,
        Err(_) => return -1,
    };
    // Only 32-byte secrets are valid.
    if len != 32 {
        return -1;
    }

    // Copy the JVM-managed bytes into a local stack buffer.  We use a signed
    // slice first (jbyte = i8) then transmute to [u8; 32] — the bit patterns
    // are identical; we just change the type interpretation.
    let mut buf = [0i8; 32];
    if env.get_byte_array_region(&data, 0, &mut buf).is_err() {
        return -1;
    }
    // SAFETY: i8 and u8 have the same size and alignment; all bit patterns are
    // valid for both types.  This transmute does not produce undefined behaviour.
    let secret: [u8; 32] = unsafe { std::mem::transmute(buf) };

    // Delegate to the C-ABI inject function via the raw pointer.
    // SAFETY: ctx_long was returned by nativeStartLayer1 and is valid for the
    // lifetime of the startup service, coordinated by HEADLESS_LAYER1_PTR.
    let ctx = unsafe { &*(ctx_long as *const MeshContext) };
    match ctx.inject_mesh_identity_secret(secret) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[Layer1] nativeInjectLayer1Secret: {e}");
            -1
        }
    }
}

/// JNI entry point for `NativeLayer1Bridge.nativeExportLayer1Secret`.
///
/// Retrieves the current 32-byte in-memory mesh identity secret and returns
/// it as a new Java `byte[]`.  Returns `null` if no identity is loaded yet.
///
/// The Kotlin caller (`wrapAndSaveKeypairIfNeeded`) must zero the returned
/// array with `.fill(0)` immediately after passing it to `KeystoreBridge.wrapKey()`.
///
/// # Safety
///
/// `ctx_long` must be the value returned by `nativeStartLayer1`.
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "system" fn Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeExportLayer1Secret(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ctx_long: jni::sys::jlong,
) -> jni::sys::jobject {
    // Null sentinel value used when there is nothing to return.
    let null_obj = std::ptr::null_mut();

    // Guard: a zero context pointer means the runtime was never allocated.
    if ctx_long == 0 {
        return null_obj;
    }

    // SAFETY: ctx_long was returned by nativeStartLayer1 and is still valid
    // (startup service owns the context; HEADLESS_LAYER1_PTR CAS protects it).
    let ctx = unsafe { &*(ctx_long as *const MeshContext) };

    // Retrieve the secret bytes from the runtime.
    let secret = match ctx.export_mesh_identity_secret() {
        Some(s) => s,
        // No identity loaded — caller should retry after initialize_startup_state.
        None => return null_obj,
    };

    // Allocate a new Java byte[] and copy the secret into it.
    // The JVM garbage-collects the array when the Kotlin caller loses the
    // reference — fill(0) in Kotlin ensures it is zeroed before GC.
    let arr = match env.new_byte_array(32) {
        Ok(a) => a,
        Err(_) => return null_obj,
    };
    // Reinterpret [u8; 32] as [i8; 32] for the JNI API (jbyte = i8).
    // SAFETY: same size, alignment, and all bit patterns valid for both types.
    let signed: [i8; 32] = unsafe { std::mem::transmute(secret) };
    if env.set_byte_array_region(&arr, 0, &signed).is_err() {
        return null_obj;
    }

    // Return a raw jobject.  The JVM owns the array; the Kotlin caller must
    // zero it with `.fill(0)` after use to minimise secret dwell time in GC.
    // SAFETY: JByteArray is a transparent wrapper around jobject.
    unsafe { jni::objects::JObject::from(arr).as_raw() }
}

/// Submit a pairing payload received over Android NFC or Wi-Fi Direct.
///
/// # Safety
/// `ctx` must be non-null. String pointers must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_android_proximity_ingest_pairing_payload(
    ctx: *mut MeshContext,
    payload_json: *const c_char,
    source: *const c_char,
) -> i32 {
    if ctx.is_null() || payload_json.is_null() || source.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let payload_json = match unsafe { c_str_to_str(payload_json) } {
        Some(json) => json,
        None => {
            ctx.set_error("invalid android pairing payload");
            return -1;
        }
    };
    let source = match unsafe { c_str_to_str(source) } {
        Some(source) => source,
        None => {
            ctx.set_error("invalid android pairing source");
            return -1;
        }
    };
    match ctx.ingest_android_pairing_payload(payload_json, source) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Queue a backend-authored Wi-Fi Direct pairing payload for Android-native exchange.
///
/// # Safety
/// `ctx` must be non-null. `payload_json` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_android_wifi_direct_queue_pairing_payload(
    ctx: *mut MeshContext,
    payload_json: *const c_char,
) -> i32 {
    if ctx.is_null() || payload_json.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let payload_json = match unsafe { c_str_to_str(payload_json) } {
        Some(json) => json,
        None => {
            ctx.set_error("invalid android wifi direct payload");
            return -1;
        }
    };
    match ctx.queue_android_wifi_direct_pairing_payload(payload_json) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Dequeue the next backend-authored Wi-Fi Direct pairing payload as JSON.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_android_wifi_direct_dequeue_pairing_payload(
    ctx: *mut MeshContext,
) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.dequeue_android_wifi_direct_pairing_payload_json())
}

/// Submit one generic Wi-Fi Direct session frame from Android as hex.
///
/// # Safety
/// `ctx` must be non-null. `frame_hex` must be valid UTF-8 hex.
#[no_mangle]
pub unsafe extern "C" fn mi_android_wifi_direct_ingest_session_frame(
    ctx: *mut MeshContext,
    frame_hex: *const c_char,
) -> i32 {
    if ctx.is_null() || frame_hex.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let frame_hex = match unsafe { c_str_to_str(frame_hex) } {
        Some(value) => value,
        None => {
            ctx.set_error("invalid android wifi direct session frame");
            return -1;
        }
    };
    let frame_bytes = match hex::decode(frame_hex) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => {
            ctx.set_error("android wifi direct session frame must be non-empty hex");
            return -1;
        }
    };
    match ctx.ingest_android_wifi_direct_session_frame(&frame_bytes) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Queue one backend-authored Wi-Fi Direct session frame for Android exchange.
///
/// # Safety
/// `ctx` must be non-null. `frame_hex` must be valid UTF-8 hex.
#[no_mangle]
pub unsafe extern "C" fn mi_android_wifi_direct_queue_session_frame(
    ctx: *mut MeshContext,
    frame_hex: *const c_char,
) -> i32 {
    if ctx.is_null() || frame_hex.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let frame_hex = match unsafe { c_str_to_str(frame_hex) } {
        Some(value) => value,
        None => {
            ctx.set_error("invalid android wifi direct session frame");
            return -1;
        }
    };
    let frame_bytes = match hex::decode(frame_hex) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => {
            ctx.set_error("android wifi direct session frame must be non-empty hex");
            return -1;
        }
    };
    match ctx.queue_android_wifi_direct_session_frame(&frame_bytes) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Dequeue the next backend-authored Wi-Fi Direct session frame as JSON.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_android_wifi_direct_dequeue_session_frame(
    ctx: *mut MeshContext,
) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.dequeue_android_wifi_direct_session_frame_json())
}

// ─────────────────────────────────────────────────────────────────────────────
// Android Wi-Fi Direct — fd-session handoff (§5.8)
// ─────────────────────────────────────────────────────────────────────────────
//
// These two functions implement the "Rust owns the socket" contract described
// in the Android proximity transport audit.  The flow is:
//
//   1. Kotlin establishes a Wi-Fi Direct P2P group using `WifiP2pManager`.
//   2. Kotlin connects (or accepts) a TCP socket on the group interface.
//   3. Kotlin detaches the fd from the JVM:
//        val pfd = ParcelFileDescriptor.fromSocket(socket)
//        val fd  = pfd.detachFd()   // JVM no longer owns the fd
//   4. Kotlin calls `mi_wifi_direct_session_fd(ctx, peerMac, fd)`.
//        - Rust wraps the fd in a `TcpStream` via `from_raw_fd`.
//        - Ownership is now exclusively with Rust.
//        - Kotlin MUST NOT touch the socket or fd after this call.
//   5. Kotlin starts a drain coroutine that repeatedly calls
//      `mi_wifi_direct_drain_session(ctx, peerMac)`.
//        - Each call flushes pending outbound frames from Rust's queue
//          directly to the socket without returning to Kotlin between frames.
//        - Returns the frame count flushed (>= 0) or -1 on socket error.

/// Hand a connected Wi-Fi Direct socket file descriptor to Rust.
///
/// After this call Rust owns the fd exclusively — Kotlin must not close,
/// read, or write the fd or the wrapping `java.net.Socket` object.
///
/// # Arguments
///
/// * `ctx`          — non-null `MeshContext` pointer.
/// * `peer_mac_ptr` — null-terminated UTF-8 MAC address string
///                    (`WifiP2pDevice.deviceAddress`, e.g. `"aa:bb:cc:dd:ee:ff"`).
/// * `fd`           — connected TCP socket file descriptor obtained by
///                    `ParcelFileDescriptor.fromSocket(socket).detachFd()`.
///
/// # Return value
///
/// Returns `0` on success, `-1` on error.
///
/// # Safety
///
/// `ctx` must be non-null.  `peer_mac_ptr` must be a valid null-terminated
/// UTF-8 string.  `fd` must be a valid open connected socket fd; Rust takes
/// ownership and will close it on drop — the caller must not close it.
#[no_mangle]
#[cfg(target_os = "android")]
pub unsafe extern "C" fn mi_wifi_direct_session_fd(
    ctx: *mut MeshContext,
    peer_mac_ptr: *const c_char,
    fd: c_int,
) -> c_int {
    if ctx.is_null() || peer_mac_ptr.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    // Convert the peer MAC C string to a Rust &str.
    let peer_mac = match unsafe { std::ffi::CStr::from_ptr(peer_mac_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            ctx.set_error("mi_wifi_direct_session_fd: peer_mac is not valid UTF-8");
            return -1;
        }
    };
    match ctx.register_wifi_direct_session_fd(peer_mac, fd) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Drain pending outbound frames to a Rust-owned Wi-Fi Direct session socket.
///
/// Intended to be called from a Kotlin coroutine loop after registering a
/// session via `mi_wifi_direct_session_fd`:
///
/// ```text
/// while (sessionActive) {
///     val n = mi_wifi_direct_drain_session(ctxPtr, peerMacCStr)
///     if (n < 0) break          // socket error — stop draining
///     if (n == 0) delay(5)      // nothing queued — yield briefly
/// }
/// ```
///
/// # Arguments
///
/// * `ctx`          — non-null `MeshContext` pointer.
/// * `peer_mac_ptr` — null-terminated UTF-8 MAC address of the registered session.
///
/// # Return value
///
/// Returns the number of frames flushed (`>= 0`) or `-1` on socket error or
/// if no session is registered for the given MAC.
///
/// # Safety
///
/// `ctx` must be non-null.  `peer_mac_ptr` must be a valid null-terminated
/// UTF-8 string.
#[no_mangle]
#[cfg(target_os = "android")]
pub unsafe extern "C" fn mi_wifi_direct_drain_session(
    ctx: *mut MeshContext,
    peer_mac_ptr: *const c_char,
) -> c_int {
    if ctx.is_null() || peer_mac_ptr.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let peer_mac = match unsafe { std::ffi::CStr::from_ptr(peer_mac_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            ctx.set_error("mi_wifi_direct_drain_session: peer_mac is not valid UTF-8");
            return -1;
        }
    };
    match ctx.drain_wifi_direct_session(peer_mac) {
        Ok(n) => n as c_int,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Android NFC — backend-driven outbound drain + inbound push (§5.9)
// ─────────────────────────────────────────────────────────────────────────────
//
// The NFC transport audit identified that the native bridge was not draining
// backend-authored outbound frames — only ingesting inbound frames.  These two
// functions close that loop:
//
//   mi_nfc_push_inbound_frame  — Kotlin → Rust (inbound NFC data)
//   mi_nfc_pop_outbound_frame  — Rust → Kotlin (outbound NFC data to send)
//
// The Kotlin `nfcOutboundDrainLoop()` coroutine calls `mi_nfc_pop_outbound_frame`
// in a tight loop, writing each returned frame to the active LLCP connection.
// This makes the NFC transport fully backend-driven: Rust decides what to send
// and when; Kotlin is a thin I/O driver.

/// Push one inbound NFC frame (received from an LLCP peer or NDEF tag read)
/// into the Rust backend's inbound queue.
///
/// The backend's NFC poll loop and higher layers consume frames from this
/// queue via `NfcTransport::recv()` / `read_ndef_tag()`.
///
/// # Arguments
///
/// * `ctx`     — non-null `MeshContext` pointer.
/// * `data`    — pointer to the raw frame bytes.
/// * `data_len`— byte count (must be > 0).
///
/// # Return value
///
/// Returns `0` on success, `-1` on error (null pointer, zero length).
///
/// # Safety
///
/// `ctx` must be non-null.  `data` must point to at least `data_len` readable
/// bytes.  The bytes are copied into Rust-owned memory before this function
/// returns; the caller may free `data` immediately after the call.
#[no_mangle]
pub unsafe extern "C" fn mi_nfc_push_inbound_frame(
    ctx: *mut MeshContext,
    data: *const u8,
    data_len: c_int,
) -> c_int {
    if ctx.is_null() || data.is_null() || data_len <= 0 {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    // SAFETY: `data` is a valid readable pointer to `data_len` bytes per caller contract.
    let frame = unsafe { std::slice::from_raw_parts(data, data_len as usize) };
    // `enqueue_android_inbound_frame` guards on adapter state (available && enabled)
    // before queuing, so we do not need a separate availability check here.
    crate::transport::nfc::enqueue_android_inbound_frame(frame.to_vec());
    // Emit an event so the Flutter event bus can react to inbound NFC activity.
    ctx.push_event(
        "AndroidNfcInboundFrameReceived",
        serde_json::json!({ "byteLength": data_len }),
    );
    0
}

/// Pop the next outbound NFC frame Rust wants to send over an LLCP link or
/// NDEF write, copying its bytes into the caller-supplied buffer.
///
/// The Kotlin `nfcOutboundDrainLoop()` coroutine calls this in a loop:
///
/// ```text
/// val buf = ByteArray(256)
/// while (nfcActive) {
///     val n = mi_nfc_pop_outbound_frame(ctxPtr, buf, buf.size)
///     when {
///         n < 0  -> break                    // error
///         n == 0 -> delay(5)                 // queue empty — yield and retry
///         else   -> nfcLlcpWrite(buf, 0, n)  // send `n` bytes on LLCP link
///     }
/// }
/// ```
///
/// # Arguments
///
/// * `ctx`    — non-null `MeshContext` pointer.
/// * `buf`    — caller-allocated buffer to receive the frame bytes.
/// * `buf_len`— size of `buf` in bytes.  Must be at least `NFC_MAX_FRAME_BYTES`
///              (244) to guarantee all queued frames can be popped.
///
/// # Return value
///
/// - `> 0` — actual frame length copied into `buf`.
/// - `0`   — no frame is pending; caller should yield and retry.
/// - `-1`  — error (null pointer or zero-length buffer).
///
/// # Safety
///
/// `ctx` must be non-null.  `buf` must point to at least `buf_len` writable
/// bytes.  Frame bytes are copied into `buf` before this function returns.
#[no_mangle]
pub unsafe extern "C" fn mi_nfc_pop_outbound_frame(
    ctx: *mut MeshContext,
    buf: *mut u8,
    buf_len: c_int,
) -> c_int {
    if ctx.is_null() || buf.is_null() || buf_len <= 0 {
        return -1;
    }
    // `ctx` is not used beyond the null check here — the NFC queue is module-global.
    // The parameter is present so the call site is consistent with all other FFI
    // functions (callers always hold a ctx pointer) and for future per-context
    // transport isolation.
    let _ctx = unsafe { &*ctx };
    // SAFETY: `buf` is a valid writable pointer to `buf_len` bytes per caller contract.
    let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf, buf_len as usize) };
    match crate::transport::nfc::pop_outbound_frame(buf_slice) {
        // A frame was copied — return its length.
        Some(n) => n as c_int,
        // No frame pending — return 0 (not an error; caller should retry after yield).
        None => 0,
    }
}

/// Return the local pairing payload as JSON.
///
/// The payload contains our public keys, a fresh pairing token, and transport hints.
/// Encode as a QR code for peer scanning.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_pairing_payload(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no identity to advertise.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate payload construction to service layer.
    // Dispatch on the variant.
    match ctx.get_pairing_payload() {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(json) => ctx.set_response(&json),
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => ctx.set_response(&serde_json::json!({"error": e}).to_string()),
    }
}

/// Set a peer's trust level.
///
/// Returns 0 on success, -1 if the peer was not found.
///
/// # Safety
/// `ctx` must be non-null.  `peer_id` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_trust_level(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id: *const c_char,
    // Execute this protocol step.
    level: u8,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no contacts.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse the peer-ID hex string.
    // Compute pid hex for this protocol step.
    let pid_hex = match unsafe { c_str_to_str(peer_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate trust update to service layer.
    // Dispatch on the variant.
    match ctx.set_trust_level(pid_hex, level) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Alias for `mi_set_trust_level` (trust attestation variant).
///
/// # Safety
/// Same as `mi_set_trust_level`.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_trust_attest(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id: *const c_char,
    // Execute this protocol step.
    level: i32,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Forward to canonical implementation with a u8 cast.
    // Execute this protocol step.
    unsafe { mi_set_trust_level(ctx, peer_id, level as u8) }
}

/// Return trust verification details for a peer as JSON.
///
/// # Safety
/// `ctx` must be non-null.  `peer_id` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_trust_verify_json(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx has no contacts.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse the peer-ID hex string.
    // Compute pid hex for this protocol step.
    let pid_hex = unsafe { c_str_to_str(peer_id) }.unwrap_or("");
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.trust_verify(pid_hex))
}

// ---------------------------------------------------------------------------
// File transfers
// ---------------------------------------------------------------------------

/// Return active file transfers as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_file_transfers_json(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no transfers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_file_transfers())
}

/// Start a file transfer.
///
/// `direction`: `"outgoing"` or `"incoming"`.
/// `peer_id`:   hex peer ID of the remote party (may be null for incoming).
/// `path`:      local filesystem path (source for outgoing, destination for incoming).
///
/// Returns JSON `{"id":"...","status":"pending",...}` or null on error.
///
/// # Safety
/// `ctx` must be non-null.  `direction`, `path` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_file_transfer_start(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    direction: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    path: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot start transfers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute dir for this protocol step.
    let dir = unsafe { c_str_to_str(direction) }.unwrap_or("outgoing");
    // Identify the peer for this operation.
    // Compute pid for this protocol step.
    let pid = unsafe { c_str_to_str(peer_id) }.unwrap_or("");
    // Dispatch based on the variant to apply type-specific logic.
    // Compute p for this protocol step.
    let p = match unsafe { c_str_to_str(path) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate transfer initiation to service layer.
    // Dispatch on the variant.
    match ctx.start_file_transfer(dir, pid, p) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(json) => ctx.set_response(&json),
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(_) => ptr::null(),
    }
}

/// Cancel an active file transfer.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `transfer_id` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_file_transfer_cancel(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    transfer_id: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no transfers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required transfer-ID argument.
    // Compute tid for this protocol step.
    let tid = match unsafe { c_str_to_str(transfer_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.cancel_file_transfer(tid) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Accept an incoming file transfer.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_file_transfer_accept(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    transfer_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    save_path: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot accept transfers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute tid for this protocol step.
    let tid = match unsafe { c_str_to_str(transfer_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute path for this protocol step.
    let path = match unsafe { c_str_to_str(save_path) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.accept_file_transfer(tid, path) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Events (polling)
// ---------------------------------------------------------------------------

/// Poll for pending backend events.
///
/// Drains all queued events and advances the clearnet transport loop.
/// Returns a JSON array; `[]` means no events are pending.
/// Each element: `{"type":"EventName","data":{...}}`.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_poll_events(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no events.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Advance all transports (TCP, Tor, LAN, file, gossip, keepalives, etc.).
    // Execute this protocol step.
    ctx.advance_clearnet_transport();
    // Drain the event queue and return as JSON.
    // Compute queue for this protocol step.
    let mut queue = ctx.event_queue.lock().unwrap_or_else(|e| e.into_inner());
    // Validate the input length to prevent out-of-bounds access.
    // Guard: validate the condition before proceeding.
    if queue.is_empty() {
        // Return the result to the caller.
        // Return to the caller.
        return ctx.set_response("[]");
    }
    // Serialize to the wire format for transmission or storage.
    // Compute events for this protocol step.
    let events: Vec<serde_json::Value> = queue.drain(..).collect();
    // Execute this step in the protocol sequence.
    // Execute this protocol step.
    drop(queue);
    // Apply the closure to each element.
    // Execute this protocol step.
    ctx.set_response(&serde_json::to_string(&events).unwrap_or_else(|_| "[]".into()))
}

// ---------------------------------------------------------------------------
// Network — settings and threat context
// ---------------------------------------------------------------------------

/// Return the current backend settings as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_settings(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no settings.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate settings serialisation to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_settings())
}

/// Alias for `mi_get_settings` (legacy name).
///
/// # Safety
/// Same as `mi_get_settings`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_settings_json(ctx: *mut MeshContext) -> *const c_char {
    // Forward to canonical implementation.
    // Execute this protocol step.
    unsafe { mi_get_settings(ctx) }
}

/// Set the threat context level (0 = Normal … 4 = Critical).
///
/// Returns 0 on success, -1 if the level is invalid.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_threat_context(ctx: *mut MeshContext, level: u8) -> i32 {
    // Guard: null ctx cannot have its threat context updated.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null and exclusive access.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &mut *ctx };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_threat_context(level) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return the current threat context level as a `u8`.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_threat_context(ctx: *mut MeshContext) -> u8 {
    // Guard: return Normal (0) for a null context.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.get_threat_context()
}

/// Set the active conversation for read-receipt priority escalation (§16.9.3).
///
/// Pass null `room_id` to clear the active conversation.
///
/// Returns 0.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` may be null or a valid hex room-ID string.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_active_conversation(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no conversations.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Null → clear; non-null → parse and set.
    // Compute id str for this protocol step.
    let id_str = unsafe { c_str_to_str(room_id) };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_active_conversation(id_str);
    0
}

/// Set the message security mode for a room (§6.7).
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `room_id` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_conversation_security_mode(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    room_id: *const c_char,
    // Execute this protocol step.
    mode: u8,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no rooms.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required room-ID argument.
    // Compute rid for this protocol step.
    let rid = match unsafe { c_str_to_str(room_id) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_conversation_security_mode(rid, mode) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Set the node operating mode (0 = client, 1 = relay, 2 = server).
///
/// Returns 0 on success, -1 if the mode is invalid.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_node_mode(ctx: *mut MeshContext, mode: i32) -> i32 {
    // Guard: null ctx cannot change modes.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Validate and cast the mode value.
    // Guard: validate the condition before proceeding.
    if !(0..=2).contains(&mode) {
        return -1;
    }
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_node_mode(mode as u8) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Persist the mesh participation profile (0 = minimal, 1 = standard, 2 = generous).
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_set_bandwidth_profile(ctx: *mut MeshContext, profile: u8) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.set_bandwidth_profile(profile) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Persist the highest unlocked feature tier (0 = social .. 4 = power).
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_set_active_tier(ctx: *mut MeshContext, tier: u8) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    match ctx.set_active_tier(tier) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Apply a JSON transport-flags patch to the current flag set.
///
/// Each key in `flags_json` is optional; missing keys leave the current value
/// unchanged.  Emits `SettingsUpdated` and persists to vault.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `flags_json_ptr` must be valid JSON UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_transport_flags(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    flags_json_ptr: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no transport flags.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    // Compute json str for this protocol step.
    let json_str = match unsafe { c_str_to_str(flags_json_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_transport_flags(json_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Toggle a single transport flag by name.
///
/// Valid names: `"tor"`, `"clearnet"`, `"clearnet_fallback"`, `"i2p"`,
/// `"bluetooth"`, `"rf"`, `"mesh_discovery"`, `"relays"`.
///
/// Returns 0 on success, -1 if the name is unrecognised.
///
/// # Safety
/// `ctx` must be non-null.  `transport` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_toggle_transport_flag(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    transport: *const c_char,
    // Execute this protocol step.
    enabled: i32,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no flags.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required transport-name argument.
    // Compute name for this protocol step.
    let name = match unsafe { c_str_to_str(transport) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.toggle_transport_flag(name, enabled != 0) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return live network statistics as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_network_stats(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no stats.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate stats collection to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_network_stats())
}

/// Return a privacy-safe diagnostic report as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_diagnostic_report(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_diagnostic_report_json())
}

/// Return the backend-owned Android VPN enforcement policy as a JSON string.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_get_android_vpn_policy(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_android_vpn_policy())
}

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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_start_clearnet_listener(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx has no listener to start.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate listener startup to service layer.
    // Dispatch on the variant.
    match ctx.start_clearnet_listener() {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_stop_clearnet_listener(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx has nothing to stop.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate listener teardown to service layer.
    // Execute this protocol step.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_clearnet_port(ctx: *mut MeshContext, port: u16) -> i32 {
    // Guard: null ctx has no port to configure.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_clearnet_port(port) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_clearnet_route(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    route: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no routing table to update.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    // Compute json str for this protocol step.
    let json_str = match unsafe { c_str_to_str(route) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_clearnet_route(json_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_tor_enable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot enable Tor.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate Tor bootstrap to service layer.
    // Dispatch on the variant.
    match ctx.tor_enable() {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_tor_disable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot disable Tor.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate Tor teardown to service layer.
    // Execute this protocol step.
    ctx.tor_disable();
    0
}

/// Return our Tor v3 `.onion` address as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_tor_get_onion_address(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no Tor address.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.tor_get_onion_address() {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_tor_connect(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id_hex_ptr: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    onion_addr_ptr: *const c_char,
    // Execute this protocol step.
    port: u16,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx or null string args are immediate failures.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() || peer_id_hex_ptr.is_null() || onion_addr_ptr.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees all pointers are valid.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute peer id hex for this protocol step.
    let peer_id_hex = match unsafe { c_str_to_str(peer_id_hex_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute onion addr for this protocol step.
    let onion_addr = match unsafe { c_str_to_str(onion_addr_ptr) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate Tor connection to service layer.
    // Dispatch on the variant.
    match ctx.tor_connect(peer_id_hex, onion_addr, port) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_mdns_enable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot enable mDNS.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate mDNS startup to service layer.
    // Execute this protocol step.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_mdns_disable(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx cannot disable mDNS.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate mDNS teardown to service layer.
    // Execute this protocol step.
    ctx.mdns_disable();
    0
}

/// Returns 1 if mDNS is currently running, 0 otherwise.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_mdns_is_running(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx → mDNS is not running.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate status query to service layer.
    // Guard: validate the condition before proceeding.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_mdns_get_discovered_peers(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no discovered peers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate peer-list retrieval to service layer.
    // Execute this protocol step.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_vpn_mode(ctx: *mut MeshContext, mode_json: *const c_char) -> i32 {
    // Guard: null ctx has no VPN to configure.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    // Compute json str for this protocol step.
    let json_str = match unsafe { c_str_to_str(mode_json) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_vpn_mode(json_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_exit_node(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx has no VPN.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required peer-ID argument.
    // Compute pid for this protocol step.
    let pid = unsafe { c_str_to_str(peer_id_hex) }.unwrap_or("");
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_exit_node(pid) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_vpn_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no VPN status.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
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
///                     `"com.example.browser"`).  Must not be null.
/// - `dst_ip_ptr`    — NUL-terminated IP address string in dotted-decimal
///                     (IPv4) or colon-hex (IPv6) notation.  Must not be null.
/// - `dst_port`      — destination port as a C int (0–65535).  Values outside
///                     that range are clamped to `u16::MAX`.
/// - `dst_domain_ptr`— optional NUL-terminated domain name (e.g.
///                     `"sub.example.com"`).  Pass null when no domain is
///                     available (most non-DNS packets).
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
    let dst_domain: Option<&str> = unsafe { c_str_to_str(dst_domain_ptr) }
        .filter(|s| !s.is_empty());

    // Retrieve the current App Connector config and run the selector engine.
    let action = ctx.evaluate_connector_connection(package, dst_ip, dst_port_u16, dst_domain);

    // Return the integer encoding: 0=block, 1=allow_direct, 2=route_via_mesh.
    action.as_ffi_int()
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_tailscale_auth_key(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    auth_key: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    control_url: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot authenticate.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute key for this protocol step.
    let key = match unsafe { c_str_to_str(auth_key) } {
        Some(s) => s,
        None => return -1,
    };
    // Fall back to the default value on failure.
    // Compute url for this protocol step.
    let url = unsafe { c_str_to_str(control_url) }.unwrap_or("");
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.tailscale_auth_key(key, url) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_tailscale_begin_oauth(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    control_url: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot initiate OAuth.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required URL argument.
    // Compute url for this protocol step.
    let url = unsafe { c_str_to_str(control_url) }.unwrap_or("");
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.tailscale_begin_oauth(url) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_zerotier_connect(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    api_key: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    controller_url: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    network_ids_json: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot connect to ZeroTier.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute key for this protocol step.
    let key = match unsafe { c_str_to_str(api_key) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute controller for this protocol step.
    let controller = match unsafe { c_str_to_str(controller_url) } {
        Some(s) => s,
        None => return -1,
    };
    // Serialize to the wire format for transmission or storage.
    // Compute networks for this protocol step.
    let networks = unsafe { c_str_to_str(network_ids_json) }.unwrap_or("[]");
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.zerotier_connect(key, controller, networks) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
    if ctx.zerotier_probe_roots() { 1 } else { 0 }
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_overlay_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no overlay.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_losec_request(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    request_json: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot process LoSec requests.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    // Compute json str for this protocol step.
    let json_str = match unsafe { c_str_to_str(request_json) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.losec_request(json_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_losec_ambient_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no ambient status.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_wg_initiate_handshake(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot initiate WireGuard.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required peer-ID argument.
    // Compute peer hex for this protocol step.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.wg_initiate_handshake(peer_hex) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_wg_respond_to_handshake(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id_hex: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    init_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot handle WireGuard.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute peer hex for this protocol step.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute init hex  for this protocol step.
    let init_hex_ = match unsafe { c_str_to_str(init_hex) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.wg_respond_to_handshake(peer_hex, init_hex_) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_wg_complete_handshake(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id_hex: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    response_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot complete handshakes.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute peer hex for this protocol step.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute resp hex for this protocol step.
    let resp_hex = match unsafe { c_str_to_str(response_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.wg_complete_handshake(peer_hex, resp_hex) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_sdr_configure(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    config_json: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot configure SDR.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    // Compute json str for this protocol step.
    let json_str = match unsafe { c_str_to_str(config_json) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.sdr_configure(json_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_sdr_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no SDR.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.sdr_status())
}

/// Return the current FHSS channel as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_sdr_current_channel(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no SDR channel.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.sdr_current_channel())
}

/// Return the list of SDR RF profiles as JSON.
///
/// # Safety
/// `_ctx` is unused but retained for ABI consistency.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_sdr_list_profiles(_ctx: *mut MeshContext) -> *const c_char {
    // Profiles are static; no context required.  Delegate to service method.
    // We need a static CString for the response pointer lifetime.
    // Build the list from MeshRuntime if available, else use fallback.
    // Guard: validate the condition before proceeding.
    if _ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*_ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.sdr_list_profiles())
}

/// Return the list of detected SDR hardware as JSON.
///
/// # Safety
/// `_ctx` is unused but retained for ABI consistency.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_sdr_list_hardware(_ctx: *mut MeshContext) -> *const c_char {
    // Hardware detection is static; delegate to service layer.
    // Guard: validate the condition before proceeding.
    if _ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*_ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.sdr_list_hardware())
}

// ---------------------------------------------------------------------------
// Groups (§10.3)
// ---------------------------------------------------------------------------

/// Create a new group.
///
/// Returns JSON `{"groupId":"...","name":"..."}` or null on failure.
///
/// # Safety
/// `ctx` must be non-null.  `name` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_create_group(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    name: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    _member_ids: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot create groups.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // Parse required group name argument.
    // Compute gname for this protocol step.
    let gname = match unsafe { c_str_to_str(name) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Parse optional member IDs (JSON array of hex peer IDs).
    // Compute members str for this protocol step.
    let members_str = unsafe { c_str_to_str(_member_ids) }.unwrap_or("[]");
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    // Compute ctx mut for this protocol step.
    let ctx_mut = unsafe { &mut *ctx };
    // Dispatch based on the variant to apply type-specific logic.
    // Dispatch on the variant.
    match ctx_mut.create_group(gname, members_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(ref json) => ctx_mut.set_response(json),
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(ref e) => {
            ctx_mut.set_error(e);
            ptr::null()
        }
    }
}

/// Return the list of groups as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_list_groups(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no groups.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.list_groups())
}

/// Return the member list for a group as a JSON array.
///
/// # Safety
/// `ctx` must be non-null.  `group_id_hex` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_group_members(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    group_id_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx has no groups.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required group-ID argument.
    // Compute gid for this protocol step.
    let gid = match unsafe { c_str_to_str(group_id_hex) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.group_members(gid))
}

/// Leave a group.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `group_id_hex` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_leave_group(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    group_id_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot leave groups.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // Parse required group-ID argument.
    // Compute gid for this protocol step.
    let gid = match unsafe { c_str_to_str(group_id_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    // Compute ctx mut for this protocol step.
    let ctx_mut = unsafe { &mut *ctx };
    // Dispatch based on the variant to apply type-specific logic.
    // Dispatch on the variant.
    match ctx_mut.leave_group(gid) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(ref e) => {
            ctx_mut.set_error(e);
            -1
        }
    }
}

/// Send a message to a group.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_group_send_message(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    group_id_hex: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    text: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot send group messages.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // Parse required arguments.
    // Compute gid for this protocol step.
    let gid = match unsafe { c_str_to_str(group_id_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute txt for this protocol step.
    let txt = match unsafe { c_str_to_str(text) } {
        Some(s) if !s.is_empty() => s,
        _ => return -1,
    };
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    // Compute ctx mut for this protocol step.
    let ctx_mut = unsafe { &mut *ctx };
    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    if ctx_mut.group_send_message(gid, txt) {
        0
    } else {
        -1
    }
}

/// Invite a peer to a group.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_group_invite_peer(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    group_id_hex: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot invite peers.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // Parse required arguments.
    // Compute gid for this protocol step.
    let gid = match unsafe { c_str_to_str(group_id_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute pid for this protocol step.
    let pid = match unsafe { c_str_to_str(peer_id_hex) } {
        Some(s) => s,
        None => return -1,
    };
    // SAFETY: caller guarantees non-null; mutable borrow is exclusive for this call.
    // Compute ctx mut for this protocol step.
    let ctx_mut = unsafe { &mut *ctx };
    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    if ctx_mut.group_invite_peer(gid, pid) {
        0
    } else {
        -1
    }
}

// ---------------------------------------------------------------------------
// Calls (§12)
// ---------------------------------------------------------------------------

/// Initiate an outgoing call to a peer.
///
/// Returns JSON `{"ok":true,"callId":"..."}` or `{"ok":false,"error":"..."}`.
///
/// # Safety
/// `ctx` must be non-null.  `peer_id_hex` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_call_offer(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    peer_id_hex: *const c_char,
    // Execute this protocol step.
    is_video: i32,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx cannot initiate calls.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() || peer_id_hex.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required peer-ID argument.
    // Compute peer hex for this protocol step.
    let peer_hex = match unsafe { c_str_to_str(peer_id_hex) } {
        Some(s) => s,
        None => return ptr::null(),
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.call_offer(peer_hex, is_video != 0, "") {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(call_id) => {
            ctx.set_response(&serde_json::json!({"ok":true,"callId":call_id}).to_string())
        }
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => ctx.set_response(&serde_json::json!({"ok":false,"error":e}).to_string()),
    }
}

/// Answer an incoming call.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `session_desc` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_call_answer(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    session_desc: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot answer calls.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse optional session description.
    // Compute sdp for this protocol step.
    let sdp = unsafe { c_str_to_str(session_desc) }.unwrap_or("");
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.call_answer(sdp) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Hang up the active call.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_call_hangup(ctx: *mut MeshContext) -> i32 {
    // Guard: null ctx has no active call.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.call_hangup() {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        Ok(()) => 0,
        // Signal failure to the caller with a descriptive error.
        // Error path — signal failure.
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Return the current call status as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_call_status(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no call status.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.call_status())
}

// ---------------------------------------------------------------------------
// Notifications (§14)
// ---------------------------------------------------------------------------

/// Return the current notification configuration as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_notification_config(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no notification config.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_notification_config())
}

/// Update the notification configuration.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null.  `json` must be valid JSON UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_set_notification_config(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    json: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx cannot update notification config.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() || json.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required JSON argument.
    // Compute json str for this protocol step.
    let json_str = match unsafe { c_str_to_str(json) } {
        Some(s) => s,
        None => return -1,
    };
    // Delegate to service layer.
    // Dispatch on the variant.
    match ctx.set_notification_config(json_str) {
        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
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
// Service list (§17.13)
// ---------------------------------------------------------------------------

/// Return the module/service list as a JSON array.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_get_service_list(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no services.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.get_service_list())
}

/// Toggle or configure a service/module.
///
/// Returns 1 if the service ID was recognised, 0 otherwise.
///
/// # Safety
/// `ctx` must be non-null.  Both string args must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_configure_service(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    service_id: *const c_char,
    // Process the current step in the protocol.
    // Execute this protocol step.
    config_json: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> i32 {
    // Guard: null ctx or null args → failure.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() || service_id.is_null() || config_json.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required arguments.
    // Compute sid for this protocol step.
    let sid = match unsafe { c_str_to_str(service_id) } {
        Some(s) => s,
        None => return 0,
    };
    // Dispatch based on the variant to apply type-specific logic.
    // Compute json for this protocol step.
    let json = match unsafe { c_str_to_str(config_json) } {
        Some(s) => s,
        None => return 0,
    };
    // Delegate to service layer.
    // Guard: validate the condition before proceeding.
    if ctx.configure_service(sid, json) {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Routing table queries (§6)
// ---------------------------------------------------------------------------

/// Return routing table statistics as JSON.
///
/// # Safety
/// `ctx` must be non-null and from `mesh_init`.
#[no_mangle]
// Begin the block scope.
// Execute this protocol step.
pub unsafe extern "C" fn mi_routing_table_stats(ctx: *mut MeshContext) -> *const c_char {
    // Guard: null ctx has no routing table.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.routing_table_stats())
}

/// Look up the best next-hop for a destination peer ID.
///
/// Returns JSON `{"found":true,...}` or `{"found":false}`.
///
/// # Safety
/// `ctx` must be non-null.  `dest_peer_id_hex` must be valid UTF-8.
#[no_mangle]
// Process the current step in the protocol.
// Execute this protocol step.
pub unsafe extern "C" fn mi_routing_lookup(
    // Process the current step in the protocol.
    // Execute this protocol step.
    ctx: *mut MeshContext,
    // Process the current step in the protocol.
    // Execute this protocol step.
    dest_peer_id_hex: *const c_char,
    // Begin the block scope.
    // Execute this protocol step.
) -> *const c_char {
    // Guard: null ctx has no routing table.
    // Guard: validate the condition before proceeding.
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: caller guarantees non-null.
    // Compute ctx for this protocol step.
    let ctx = unsafe { &*ctx };
    // Parse required destination peer-ID argument.
    // Compute dest for this protocol step.
    let dest = match unsafe { c_str_to_str(dest_peer_id_hex) } {
        // Wrap the found value for the caller.
        // Wrap the found value.
        Some(s) => s,
        // Update the local state.
        // No value available.
        None => return ctx.set_response(r#"{"found":false}"#),
    };
    // Delegate to service layer.
    // Execute this protocol step.
    ctx.set_response(&ctx.routing_lookup(dest))
}

// ---------------------------------------------------------------------------
// Garden — posts and discovery (§22.6)
// ---------------------------------------------------------------------------

/// Return the post feed for a specific garden as a JSON array.
///
/// Each element: `{ "id": str, "authorId": str, "authorName": str,
/// "gardenId": str, "content": str, "timestamp": i64, "reactionCount": u32 }`.
///
/// # Safety
/// `ctx` must be non-null. `garden_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_garden_posts(
    ctx: *mut MeshContext,
    garden_id: *const c_char,
) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    let garden_id = unsafe { c_str_to_str(garden_id) }.unwrap_or_default();
    ctx.set_response(&ctx.get_garden_posts(garden_id))
}

/// Return a list of gardens discoverable on the local mesh as a JSON array.
///
/// Each element: `{ "id": str, "name": str, "description": str,
/// "memberCount": u32, "networkType": str }`.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_garden_discover(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.discover_gardens())
}

/// Join a discoverable garden by ID.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null. `garden_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_garden_join(ctx: *mut MeshContext, garden_id: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let garden_id = match unsafe { c_str_to_str(garden_id) } {
        Some(value) if !value.is_empty() => value,
        _ => {
            ctx.set_error("missing garden id");
            return -1;
        }
    };
    match ctx.join_garden(garden_id) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

/// Publish a post to a garden.
///
/// `post_json`: `{ "gardenId": str, "content": str }`.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null. `post_json` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_garden_post(ctx: *mut MeshContext, post_json: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let post_json = match unsafe { c_str_to_str(post_json) } {
        Some(value) => value,
        None => {
            ctx.set_error("invalid garden post payload");
            return -1;
        }
    };
    let post_value: serde_json::Value = match serde_json::from_str(post_json) {
        Ok(value) => value,
        Err(_) => {
            ctx.set_error("invalid garden post json");
            return -1;
        }
    };
    let garden_id = match post_value.get("gardenId").and_then(|v| v.as_str()) {
        Some(value) if !value.is_empty() => value,
        _ => {
            ctx.set_error("missing gardenId");
            return -1;
        }
    };
    let content = match post_value.get("content").and_then(|v| v.as_str()) {
        Some(value) if !value.is_empty() => value,
        _ => {
            ctx.set_error("missing post content");
            return -1;
        }
    };
    match ctx.post_to_garden(garden_id, content) {
        Ok(()) => 0,
        Err(error) => {
            ctx.set_error(&error);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Files — distributed storage (§22.7)
// ---------------------------------------------------------------------------

/// Return storage usage statistics as JSON.
///
/// Shape: `{ "usedBytes": u64, "totalBytes": u64, "publishedFiles": u32 }`.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_storage_stats(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_storage_stats())
}

/// Return the list of files this node has published to distributed storage as JSON.
///
/// Each element: `{ "id": str, "name": str, "sizeBytes": u64,
/// "mimeType": str, "publishedAt": i64, "downloadCount": u32 }`.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_published_files(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_published_files())
}

/// Publish a local file to distributed storage.
///
/// `path` is the absolute path of the file to publish.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `ctx` must be non-null. `path` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_publish_file(ctx: *mut MeshContext, path: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let path = match unsafe { c_str_to_str(path) } {
        Some(s) => s,
        None => {
            ctx.set_error("invalid publish path");
            return -1;
        }
    };
    match ctx.publish_local_file(path) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Unpublish a previously published file by its manifest ID.
///
/// Returns 0 on success, -1 if the ID is not found.
///
/// # Safety
/// `ctx` must be non-null. `file_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_unpublish_file(ctx: *mut MeshContext, file_id: *const c_char) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let file_id = match unsafe { c_str_to_str(file_id) } {
        Some(s) => s,
        None => {
            ctx.set_error("invalid file id");
            return -1;
        }
    };
    match ctx.unpublish_local_file(file_id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Services — mesh-hosted service discovery and hosting config (§22.54)
// ---------------------------------------------------------------------------

/// Return services discovered on the local mesh as a JSON array.
///
/// Each element: `{ "id": str, "name": str, "type": str, "hostPeerId": str,
/// "hostName": str, "address": str, "trustRequired": u32 }`.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_mesh_services_discover(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.discover_mesh_services())
}

/// Return this node's hosting configuration as JSON.
///
/// Shape: `{ "remoteDesktop": bool, "remoteShell": bool, "fileAccess": bool,
/// "apiGateway": bool, "clipboardSync": bool, "screenShare": bool,
/// "printService": bool }`.
///
/// # Safety
/// `ctx` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn mi_hosting_config(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    ctx.set_response(&ctx.get_hosting_config())
}

/// Enable or disable a named hosted service.
///
/// `service_id` is one of: "remoteDesktop", "remoteShell", "fileAccess",
/// "apiGateway", "clipboardSync", "screenShare", "printService".
/// Returns 0 on success, -1 if the service_id is unrecognised.
///
/// # Safety
/// `ctx` must be non-null. `service_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_hosting_set(
    ctx: *mut MeshContext,
    service_id: *const c_char,
    enabled: i32,
) -> i32 {
    if ctx.is_null() || service_id.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let service_id = match unsafe { c_str_to_str(service_id) } {
        Some(s) => s,
        None => return -1,
    };
    if ctx.set_hosted_service(service_id, enabled != 0) {
        0
    } else {
        -1
    }
}

// ---------------------------------------------------------------------------
// Message requests (§10.1.1)
// ---------------------------------------------------------------------------

/// Return the pending message request queue as a JSON array.
///
/// Each entry contains: `id`, `peerId`, `senderName`, `trustLevel`,
/// `messagePreview`, `timestamp` (ISO-8601 string).
///
/// Returns a JSON pointer on success, null on failure.
///
/// # Safety
/// `ctx` must be non-null and previously obtained from `mesh_init`.
#[no_mangle]
pub unsafe extern "C" fn mi_message_requests_json(ctx: *mut MeshContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }
    let ctx = unsafe { &*ctx };
    let json = ctx.message_requests_json();
    ctx.set_response(&json)
}

/// Accept a pending message request by ID.
///
/// Creates a `ContactRecord` for the sender at trust level `Acquaintance` (5),
/// moves the first message into the main inbox, and emits `MessageAdded` and
/// `RoomUpdated` events.  The sender receives no explicit accept signal —
/// the first reply from the user serves as implicit confirmation.
///
/// Returns 0 on success, -1 if the request ID was not found.
///
/// # Safety
/// `ctx` must be non-null. `request_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_accept_message_request(
    ctx: *mut MeshContext,
    request_id: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let id = if request_id.is_null() {
        ""
    } else {
        match unsafe { std::ffi::CStr::from_ptr(request_id) }.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    match ctx.accept_message_request(id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

/// Decline a pending message request by ID.
///
/// Removes the request from the queue without notifying the sender.
/// This is intentional — the sender must not be able to infer user activity
/// from a decline signal.
///
/// Returns 0 on success, -1 if the request ID was not found.
///
/// # Safety
/// `ctx` must be non-null. `request_id` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn mi_decline_message_request(
    ctx: *mut MeshContext,
    request_id: *const c_char,
) -> i32 {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*ctx };
    let id = if request_id.is_null() {
        ""
    } else {
        match unsafe { std::ffi::CStr::from_ptr(request_id) }.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    match ctx.decline_message_request(id) {
        Ok(()) => 0,
        Err(e) => {
            ctx.set_error(&e);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::path::Path;
    use tempfile::TempDir;

    fn make_ctx_for_path(path: &Path) -> *mut MeshContext {
        let dir_str = CString::new(path.to_str().unwrap()).unwrap();
        let test_port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|addr| addr.port())
            .unwrap_or(7234);
        let config = FfiMeshConfig {
            config_path: dir_str.as_ptr(),
            log_level: 0,
            enable_tor: 0,
            enable_clearnet: 0,
            mesh_discovery: 0,
            allow_relays: 0,
            enable_i2p: 0,
            enable_bluetooth: 0,
            enable_rf: 0,
            wireguard_port: 0,
            max_peers: 100,
            max_connections: 100,
            node_mode: 0,
        };
        let ctx = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx.is_null());
        assert_eq!(unsafe { mi_set_clearnet_port(ctx, test_port) }, 0);
        ctx
    }

    /// Helper: create a fresh context pointing at a temp directory.
    fn make_ctx() -> (*mut MeshContext, TempDir) {
        let dir = TempDir::new().unwrap();
        let ctx = make_ctx_for_path(dir.path());
        (ctx, dir)
    }

    #[test]
    fn test_init_destroy() {
        // Verify that init and destroy do not crash.
        let (ctx, _dir) = make_ctx();
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_mesh_init_applies_transport_config() {
        let dir = TempDir::new().unwrap();
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        let config = FfiMeshConfig {
            config_path: dir_str.as_ptr(),
            log_level: 0,
            enable_tor: 1,
            enable_clearnet: 0,
            mesh_discovery: 1,
            allow_relays: 1,
            enable_i2p: 1,
            enable_bluetooth: 1,
            enable_rf: 1,
            wireguard_port: 0,
            max_peers: 100,
            max_connections: 100,
            node_mode: 2,
        };
        let ctx = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx.is_null());
        let runtime = unsafe { &*ctx };
        let flags = runtime
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(
            *runtime.node_mode.lock().unwrap_or_else(|e| e.into_inner()),
            2
        );
        assert!(flags.tor);
        assert!(!flags.clearnet);
        assert!(flags.i2p);
        assert!(flags.bluetooth);
        assert!(flags.rf);
        assert!(flags.mesh_discovery);
        assert!(flags.allow_relays);

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_no_identity_initially() {
        // A fresh context must report no identity.
        let (ctx, _dir) = make_ctx();
        assert_eq!(unsafe { mi_has_identity(ctx) }, 0);
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_create_identity() {
        // Create an identity and verify the summary reports unlocked.
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Alice").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx, name.as_ptr()) }, 0);
        assert_eq!(unsafe { mi_has_identity(ctx) }, 1);

        // Summary must parse and report locked = false.
        let summary = unsafe { mi_get_identity_summary(ctx) };
        assert!(!summary.is_null());
        // SAFETY: returned by our own FFI and valid until next call.
        let json_str = unsafe { CStr::from_ptr(summary).to_str().unwrap() };
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(json["locked"], false);

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_unlock_identity() {
        // Create an identity, destroy the context, then re-open and unlock.
        let (ctx, dir) = make_ctx();
        let name = CString::new("Bob").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx, name.as_ptr()) }, 0);
        unsafe { mesh_destroy(ctx) };

        // Re-open context pointing at the same directory.
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        let config2 = FfiMeshConfig {
            config_path: dir_str.as_ptr(),
            log_level: 0,
            enable_tor: 0,
            enable_clearnet: 0,
            mesh_discovery: 0,
            allow_relays: 0,
            enable_i2p: 0,
            enable_bluetooth: 0,
            enable_rf: 0,
            wireguard_port: 0,
            max_peers: 100,
            max_connections: 100,
            node_mode: 0,
        };
        // SAFETY: config2 pointer is valid for this call.
        let ctx2 = unsafe { mesh_init(&config2 as *const FfiMeshConfig) };
        assert!(!ctx2.is_null());
        assert_eq!(unsafe { mi_has_identity(ctx2) }, 1);

        // Unlock without a PIN (none was set at creation).
        assert_eq!(unsafe { mi_unlock_identity(ctx2, ptr::null()) }, 0);

        // Summary must report unlocked with a valid peerId.
        let summary = unsafe { mi_get_identity_summary(ctx2) };
        // SAFETY: returned by our own FFI and valid until next call.
        let json_str = unsafe { CStr::from_ptr(summary).to_str().unwrap() };
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(json["locked"], false);
        assert!(json["peerId"].is_string());

        unsafe { mesh_destroy(ctx2) };
    }

    #[test]
    fn test_startup_state_enables_mdns_when_configured() {
        let dir = TempDir::new().unwrap();
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        let config = FfiMeshConfig {
            config_path: dir_str.as_ptr(),
            log_level: 0,
            enable_tor: 0,
            enable_clearnet: 0,
            mesh_discovery: 1,
            allow_relays: 0,
            enable_i2p: 0,
            enable_bluetooth: 0,
            enable_rf: 0,
            wireguard_port: 0,
            max_peers: 100,
            max_connections: 100,
            node_mode: 0,
        };

        let ctx1 = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx1.is_null());
        let name = CString::new("Startup User").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx1, name.as_ptr()) }, 0);
        assert_eq!(unsafe { mi_mdns_is_running(ctx1) }, 1);
        unsafe { mesh_destroy(ctx1) };

        let ctx2 = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx2.is_null());
        assert_eq!(unsafe { mi_has_identity(ctx2) }, 1);
        assert_eq!(unsafe { mi_mdns_is_running(ctx2) }, 1);
        unsafe { mesh_destroy(ctx2) };
    }

    #[test]
    fn test_startup_state_reports_layer1_status() {
        let dir = TempDir::new().unwrap();
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        let config = FfiMeshConfig {
            config_path: dir_str.as_ptr(),
            log_level: 0,
            enable_tor: 0,
            enable_clearnet: 1,
            mesh_discovery: 1,
            allow_relays: 1,
            enable_i2p: 0,
            enable_bluetooth: 0,
            enable_rf: 0,
            wireguard_port: 0,
            max_peers: 100,
            max_connections: 100,
            node_mode: 0,
        };

        let ctx1 = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx1.is_null());
        let test_port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|addr| addr.port())
            .unwrap_or(7234);
        assert_eq!(unsafe { mi_set_clearnet_port(ctx1, test_port) }, 0);
        let name = CString::new("Layer1 User").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx1, name.as_ptr()) }, 0);

        let settings_ptr = unsafe { mi_get_settings(ctx1) };
        assert!(!settings_ptr.is_null());
        let settings_json = unsafe { CStr::from_ptr(settings_ptr).to_str().unwrap().to_string() };
        let settings: serde_json::Value = serde_json::from_str(&settings_json).unwrap();
        assert_eq!(settings["layer1Status"]["started"], true);
        assert_eq!(settings["layer1Status"]["identityLoaded"], true);
        assert!(
            settings["layer1Status"]["activeTransportTypeCount"]
                .as_u64()
                .unwrap_or(0)
                >= 1
        );
        assert_eq!(settings["layer1Status"]["allowRelays"], true);
        assert!(
            settings["layer1Status"]["coverTraffic"]["targetTunnelsMin"]
                .as_u64()
                .unwrap_or(0)
                >= 2
        );

        unsafe { mesh_destroy(ctx1) };
    }

    #[test]
    fn test_startup_config_persists_layer1_posture() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();
        let dir_str = CString::new(dir_path.to_str().unwrap()).unwrap();
        let config = FfiMeshConfig {
            config_path: dir_str.as_ptr(),
            log_level: 0,
            enable_tor: 0,
            enable_clearnet: 0,
            mesh_discovery: 1,
            allow_relays: 1,
            enable_i2p: 0,
            enable_bluetooth: 0,
            enable_rf: 0,
            wireguard_port: 0,
            max_peers: 100,
            max_connections: 100,
            node_mode: 0,
        };

        let ctx = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx.is_null());
        let name = CString::new("Startup Config User").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx, name.as_ptr()) }, 0);
        assert_eq!(unsafe { mi_set_node_mode(ctx, 2) }, 0);

        let transport_flags = CString::new(
            r#"{"mesh_discovery":false,"allow_relays":false,"clearnet":true,"tor":true}"#,
        )
        .unwrap();
        assert_eq!(unsafe { mi_set_transport_flags(ctx, transport_flags.as_ptr()) }, 0);

        let startup_config_path = dir_path.join("layer1_startup.json");
        let startup_config_bytes = std::fs::read(startup_config_path).unwrap();
        let startup_config: serde_json::Value =
            serde_json::from_slice(&startup_config_bytes).unwrap();
        assert_eq!(startup_config["node_mode"], 2);
        assert_eq!(startup_config["mesh_discovery"], false);
        assert_eq!(startup_config["allow_relays"], false);
        assert_eq!(startup_config["clearnet"], true);
        assert_eq!(startup_config["tor"], true);

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_room_operations() {
        // Create a room and verify it appears in the list.
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Test Room").unwrap();
        let result = unsafe { mi_create_room(ctx, name.as_ptr(), ptr::null()) };
        assert!(!result.is_null());

        // Room list must contain exactly the one new room.
        let rooms = unsafe { mi_get_room_list(ctx) };
        // SAFETY: returned by our own FFI and valid until next call.
        let json_str = unsafe { CStr::from_ptr(rooms).to_str().unwrap() };
        let rooms: Vec<serde_json::Value> = serde_json::from_str(json_str).unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0]["name"], "Test Room");

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_threat_context() {
        // Verify get/set round-trip and invalid level rejection.
        let (ctx, _dir) = make_ctx();
        assert_eq!(unsafe { mi_get_threat_context(ctx) }, 0); // Normal
        assert_eq!(unsafe { mi_set_threat_context(ctx, 2) }, 0);
        assert_eq!(unsafe { mi_get_threat_context(ctx) }, 2);
        assert_eq!(unsafe { mi_set_threat_context(ctx, 5) }, -1); // Invalid
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_threat_context_reconciles_layer1_policy() {
        let dir = TempDir::new().unwrap();
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        let config = FfiMeshConfig {
            config_path: dir_str.as_ptr(),
            log_level: 0,
            enable_tor: 0,
            enable_clearnet: 1,
            mesh_discovery: 1,
            allow_relays: 1,
            enable_i2p: 0,
            enable_bluetooth: 0,
            enable_rf: 0,
            wireguard_port: 0,
            max_peers: 100,
            max_connections: 100,
            node_mode: 0,
        };
        let ctx = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx.is_null());
        let test_port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|addr| addr.port())
            .unwrap_or(7234);
        assert_eq!(unsafe { mi_set_clearnet_port(ctx, test_port) }, 0);
        let name = CString::new("Threat User").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx, name.as_ptr()) }, 0);

        assert_eq!(unsafe { mi_set_threat_context(ctx, 2) }, 0);
        let settings_ptr = unsafe { mi_get_settings(ctx) };
        assert!(!settings_ptr.is_null());
        let settings_json = unsafe { CStr::from_ptr(settings_ptr).to_str().unwrap().to_string() };
        let settings: serde_json::Value = serde_json::from_str(&settings_json).unwrap();

        assert_eq!(settings["layer1Status"]["threatContext"], 2);
        assert_eq!(settings["layer1Status"]["policy"]["allowsMdns"], false);
        assert_eq!(settings["layer1Status"]["policy"]["allowsClearnet"], false);
        assert_eq!(settings["layer1Status"]["activeTransportTypeCount"], 0);
        assert_eq!(settings["layer1Status"]["started"], false);

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_active_conversation() {
        // Verify setting and clearing the active conversation.
        let (ctx, _dir) = make_ctx();
        assert_eq!(unsafe { mi_set_active_conversation(ctx, ptr::null()) }, 0);
        let room_id = CString::new("0102030405060708090a0b0c0d0e0f10").unwrap();
        assert_eq!(
            unsafe { mi_set_active_conversation(ctx, room_id.as_ptr()) },
            0
        );
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_active_conversation_updates_layer1_activity_state() {
        let (ctx, _dir) = make_ctx();
        let name = CString::new("Conversation User").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx, name.as_ptr()) }, 0);
        let room_id = CString::new("0102030405060708090a0b0c0d0e0f10").unwrap();
        assert_eq!(
            unsafe { mi_set_active_conversation(ctx, room_id.as_ptr()) },
            0
        );

        let settings_ptr = unsafe { mi_get_settings(ctx) };
        assert!(!settings_ptr.is_null());
        let settings_json = unsafe { CStr::from_ptr(settings_ptr).to_str().unwrap().to_string() };
        let settings: serde_json::Value = serde_json::from_str(&settings_json).unwrap();
        assert_eq!(
            settings["layer1Status"]["activityState"],
            "activeconversation"
        );
        assert!(
            settings["layer1Status"]["coverTraffic"]["targetTunnelsMin"]
                .as_u64()
                .unwrap_or(0)
                >= 3
        );

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_poll_events_empty() {
        // Startup may emit one initial SettingsUpdated event. After draining
        // that startup state, the queue must return a valid JSON empty array.
        let (ctx, _dir) = make_ctx();
        let first = unsafe { mi_poll_events(ctx) };
        assert!(!first.is_null());
        let second = unsafe { mi_poll_events(ctx) };
        assert!(!second.is_null());
        // SAFETY: returned by our own FFI and valid until next call.
        let json_str = unsafe { CStr::from_ptr(second).to_str().unwrap() };
        assert_eq!(json_str, "[]");
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_device_enrollment_round_trip() {
        let (primary_ctx, _primary_dir) = make_ctx();
        let primary_name = CString::new("Primary").unwrap();
        assert_eq!(
            unsafe { mi_create_identity(primary_ctx, primary_name.as_ptr()) },
            0
        );

        let secondary_dir = TempDir::new().unwrap();
        let secondary_ctx = make_ctx_for_path(secondary_dir.path());
        let secondary_name = CString::new("Field Phone").unwrap();
        let request_ptr =
            unsafe { mi_create_device_enrollment_request(secondary_ctx, secondary_name.as_ptr()) };
        assert!(!request_ptr.is_null());
        let request_json = unsafe { CStr::from_ptr(request_ptr).to_str().unwrap().to_string() };

        let request_cstr = CString::new(request_json).unwrap();
        let package_ptr =
            unsafe { mi_complete_device_enrollment(primary_ctx, request_cstr.as_ptr()) };
        assert!(!package_ptr.is_null());
        let package_json = unsafe { CStr::from_ptr(package_ptr).to_str().unwrap().to_string() };

        let package_cstr = CString::new(package_json).unwrap();
        assert_eq!(
            unsafe { mi_accept_device_enrollment(secondary_ctx, package_cstr.as_ptr()) },
            0
        );
        assert_eq!(unsafe { mi_has_identity(secondary_ctx) }, 1);

        let devices_ptr = unsafe { mi_devices_json(secondary_ctx) };
        assert!(!devices_ptr.is_null());
        let devices_json = unsafe { CStr::from_ptr(devices_ptr).to_str().unwrap() };
        let devices: Vec<serde_json::Value> = serde_json::from_str(devices_json).unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices.iter().any(|device| device["isThisDevice"] == true));
        assert!(devices.iter().any(|device| device["isPrimary"] == true));

        let secondary_device_id = devices
            .iter()
            .find(|device| device["isThisDevice"] == true)
            .and_then(|device| device["id"].as_str())
            .unwrap()
            .to_string();

        let device_id_cstr = CString::new(secondary_device_id).unwrap();
        assert_eq!(
            unsafe { mi_remove_device(primary_ctx, device_id_cstr.as_ptr()) },
            0
        );
        let primary_devices_ptr = unsafe { mi_devices_json(primary_ctx) };
        assert!(!primary_devices_ptr.is_null());
        let primary_devices_json = unsafe { CStr::from_ptr(primary_devices_ptr).to_str().unwrap() };
        let primary_devices: Vec<serde_json::Value> =
            serde_json::from_str(primary_devices_json).unwrap();
        assert_eq!(primary_devices.len(), 1);

        unsafe { mesh_destroy(secondary_ctx) };
        unsafe { mesh_destroy(primary_ctx) };
    }

    #[test]
    fn test_android_proximity_state_round_trip() {
        let (ctx, _dir) = make_ctx();
        let state = CString::new(
            serde_json::json!({
                "isAndroid": true,
                "nfcAvailable": true,
                "nfcEnabled": false,
                "wifiDirectAvailable": true,
                "wifiDirectEnabled": true,
                "wifiDirectPermissionGranted": true,
                "wifiDirectDiscoveryActive": true,
                "wifiDirectConnected": false,
                "wifiDirectConnectionRole": serde_json::Value::Null,
                "wifiDirectGroupOwnerAddress": serde_json::Value::Null,
                "wifiDirectConnectedDeviceAddress": serde_json::Value::Null,
                "peers": [
                    {
                        "deviceName": "Field Phone",
                        "deviceAddress": "02:11:22:33:44:55",
                        "status": "available",
                        "primaryDeviceType": "phone",
                        "secondaryDeviceType": serde_json::Value::Null,
                        "isGroupOwner": false
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            unsafe { mi_android_proximity_update_state(ctx, state.as_ptr()) },
            0
        );
        let ptr = unsafe { mi_android_proximity_state_json(ctx) };
        assert!(!ptr.is_null());
        let json_str = unsafe { CStr::from_ptr(ptr).to_str().unwrap() };
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(json["isAndroid"], true);
        assert_eq!(json["wifiDirectDiscoveryActive"], true);
        assert_eq!(json["peers"][0]["deviceName"], "Field Phone");
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_android_startup_state_round_trip() {
        let (ctx, _dir) = make_ctx();
        let state = CString::new(
            serde_json::json!({
                "isAndroid": true,
                "lockedBootCompleted": true,
                "bootCompleted": true,
                "userUnlocked": false,
                "directBootAware": true,
                "lastEvent": "android.intent.action.LOCKED_BOOT_COMPLETED",
                "lastEventAtMs": 1234,
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            unsafe { mi_android_startup_update_state(ctx, state.as_ptr()) },
            0
        );
        let ptr = unsafe { mi_android_startup_state_json(ctx) };
        assert!(!ptr.is_null());
        let json_str = unsafe { CStr::from_ptr(ptr).to_str().unwrap() };
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(json["isAndroid"], true);
        assert_eq!(json["lockedBootCompleted"], true);
        assert_eq!(json["userUnlocked"], false);
        assert_eq!(
            json["lastEvent"],
            "android.intent.action.LOCKED_BOOT_COMPLETED"
        );
        unsafe { mesh_destroy(ctx) };
    }

    // -----------------------------------------------------------------------
    // bootstrap_layer1 / is_layer1_ready tests (§3.1.1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bootstrap_layer1_on_fresh_context_succeeds() {
        // mesh_init() calls initialize_startup_state() which always loads or
        // creates the mesh identity keypair.  Even without an explicit
        // mi_create_identity() call, the Layer 1 WireGuard keypair is present.
        //
        // A fresh context without an active transport will have
        // layer1_participation_started = false, so bootstrap_layer1 will
        // attempt the gossip/announcement sync steps.  Without a transport,
        // the event is NOT pushed (participation_started stays false after
        // refresh_layer1_participation_state), but the function still returns
        // Ok(()) — success means "subsystems synced", not "transports active".
        //
        // (The -1 scenario only occurs in the headless JNI path where
        // nativeStartLayer1 failed to load the identity because device-
        // protected storage was not yet readable before first unlock.)
        let (ctx, _dir) = make_ctx();
        // No active transport — clearnet is disabled in make_ctx().
        let result = unsafe { mi_bootstrap_layer1(ctx) };
        assert_eq!(
            result, 0,
            "bootstrap_layer1 must return 0 when the mesh identity is loaded \
             (even if no transport is active yet)"
        );
        // is_layer1_ready is 0 because no active transport.
        assert_eq!(
            unsafe { mi_is_layer1_ready(ctx) },
            0,
            "is_layer1_ready must be 0 when no transport is active"
        );
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_is_layer1_ready_false_before_identity() {
        // Without a loaded identity, is_layer1_ready must return 0.
        let (ctx, _dir) = make_ctx();
        assert_eq!(
            unsafe { mi_is_layer1_ready(ctx) },
            0,
            "is_layer1_ready must be 0 before any identity is loaded"
        );
        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_bootstrap_layer1_succeeds_after_identity_created() {
        // After creating an identity (which loads the mesh identity keypair and
        // starts transport listeners), bootstrap_layer1 must succeed and
        // is_layer1_ready must return 1.
        let dir = TempDir::new().unwrap();
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        // Enable clearnet so that at least one transport is active, which is
        // required for layer1_participation_started to become true.
        let config = FfiMeshConfig {
            config_path: dir_str.as_ptr(),
            log_level: 0,
            enable_tor: 0,
            enable_clearnet: 1,
            mesh_discovery: 1,
            allow_relays: 1,
            enable_i2p: 0,
            enable_bluetooth: 0,
            enable_rf: 0,
            wireguard_port: 0,
            max_peers: 100,
            max_connections: 100,
            node_mode: 0,
        };
        let ctx = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx.is_null());

        // Bind to a random port so the clearnet listener can actually start.
        let test_port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .unwrap_or(7234);
        assert_eq!(unsafe { mi_set_clearnet_port(ctx, test_port) }, 0);

        // Create the identity — this loads the mesh identity keypair.
        let name = CString::new("Bootstrap Test User").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx, name.as_ptr()) }, 0);

        // bootstrap_layer1 must now succeed.
        let result = unsafe { mi_bootstrap_layer1(ctx) };
        assert_eq!(
            result, 0,
            "bootstrap_layer1 must return 0 after identity is loaded"
        );

        // is_layer1_ready must return 1.
        assert_eq!(
            unsafe { mi_is_layer1_ready(ctx) },
            1,
            "is_layer1_ready must return 1 after successful bootstrap"
        );

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_bootstrap_layer1_emits_layer1_ready_event() {
        // After a successful bootstrap, the event queue must contain a
        // Layer1Ready event so the Flutter UI can react without polling.
        let dir = TempDir::new().unwrap();
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        let config = FfiMeshConfig {
            config_path: dir_str.as_ptr(),
            log_level: 0,
            enable_tor: 0,
            enable_clearnet: 1,
            mesh_discovery: 1,
            allow_relays: 1,
            enable_i2p: 0,
            enable_bluetooth: 0,
            enable_rf: 0,
            wireguard_port: 0,
            max_peers: 100,
            max_connections: 100,
            node_mode: 0,
        };
        let ctx = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx.is_null());
        let test_port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .unwrap_or(7234);
        assert_eq!(unsafe { mi_set_clearnet_port(ctx, test_port) }, 0);

        let name = CString::new("Layer1 Event Test User").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx, name.as_ptr()) }, 0);

        // Drain any events already in the queue (SettingsUpdated etc.).
        loop {
            let ptr = unsafe { mi_poll_events(ctx) };
            assert!(!ptr.is_null());
            let s = unsafe { CStr::from_ptr(ptr).to_str().unwrap() };
            if s == "[]" {
                break;
            }
        }

        // Call bootstrap_layer1 — this should queue a Layer1Ready event.
        assert_eq!(unsafe { mi_bootstrap_layer1(ctx) }, 0);

        // Poll events — the next batch must include Layer1Ready.
        let ptr = unsafe { mi_poll_events(ctx) };
        assert!(!ptr.is_null());
        let events_json = unsafe { CStr::from_ptr(ptr).to_str().unwrap() };
        let events: Vec<serde_json::Value> = serde_json::from_str(events_json).unwrap();
        let has_layer1_ready = events
            .iter()
            .any(|event| event["type"] == "Layer1Ready");
        assert!(
            has_layer1_ready,
            "bootstrap_layer1 must queue a Layer1Ready event; got: {events_json}"
        );

        // The Layer1Ready event must say participating = true.
        let layer1_event = events
            .iter()
            .find(|event| event["type"] == "Layer1Ready")
            .unwrap();
        assert_eq!(layer1_event["data"]["participating"], true);
        assert_eq!(layer1_event["data"]["headless"], false); // identity_unlocked = true

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_bootstrap_layer1_callable_twice() {
        // Calling mi_bootstrap_layer1 twice must return 0 both times.
        // Duplicate-event suppression is the caller's responsibility:
        // the Android startup service uses its own `layer1Bootstrapped` flag
        // to ensure it calls mi_bootstrap_layer1 at most once per service
        // lifetime.  This test verifies the Rust function doesn't panic or
        // corrupt state when called more than once.
        let dir = TempDir::new().unwrap();
        let dir_str = CString::new(dir.path().to_str().unwrap()).unwrap();
        let config = FfiMeshConfig {
            config_path: dir_str.as_ptr(),
            log_level: 0,
            enable_tor: 0,
            enable_clearnet: 1,
            mesh_discovery: 1,
            allow_relays: 1,
            enable_i2p: 0,
            enable_bluetooth: 0,
            enable_rf: 0,
            wireguard_port: 0,
            max_peers: 100,
            max_connections: 100,
            node_mode: 0,
        };
        let ctx = unsafe { mesh_init(&config as *const FfiMeshConfig) };
        assert!(!ctx.is_null());
        let test_port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .unwrap_or(7234);
        assert_eq!(unsafe { mi_set_clearnet_port(ctx, test_port) }, 0);

        let name = CString::new("Double Bootstrap User").unwrap();
        assert_eq!(unsafe { mi_create_identity(ctx, name.as_ptr()) }, 0);

        // First call must succeed.
        assert_eq!(unsafe { mi_bootstrap_layer1(ctx) }, 0, "first call must return 0");
        // Second call must also return 0 — no panic, no corruption.
        assert_eq!(unsafe { mi_bootstrap_layer1(ctx) }, 0, "second call must also return 0");

        // State must still be consistent — is_layer1_ready must be 1.
        assert_eq!(
            unsafe { mi_is_layer1_ready(ctx) },
            1,
            "is_layer1_ready must remain 1 after two bootstrap calls"
        );

        unsafe { mesh_destroy(ctx) };
    }

    #[test]
    fn test_null_ctx_bootstrap_returns_error() {
        // Null context must not crash — must return -1.
        assert_eq!(unsafe { mi_bootstrap_layer1(ptr::null_mut()) }, -1);
    }

    #[test]
    fn test_null_ctx_is_layer1_ready_returns_zero() {
        // Null context must not crash — must return 0.
        assert_eq!(unsafe { mi_is_layer1_ready(ptr::null_mut()) }, 0);
    }
}
