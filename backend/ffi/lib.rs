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
use std::os::raw::c_char;
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

const MAX_FFI_LOG_LEVEL: u8 = 4;
const MAX_FFI_NODE_MODE: u8 = 2;
const MAX_FFI_PEERS: u32 = 100_000;
const MAX_FFI_CONNECTIONS: u32 = 1_000_000;
fn validate_binary_flag(name: &str, value: u8) -> Result<(), String> {
    if value <= 1 {
        return Ok(());
    }
    Err(format!("{name} must be 0 or 1"))
}

fn validate_ffi_config(cfg: &FfiMeshConfig) -> Result<(), String> {
    if cfg.log_level > MAX_FFI_LOG_LEVEL {
        return Err(format!(
            "log_level must be between 0 and {MAX_FFI_LOG_LEVEL}"
        ));
    }

    validate_binary_flag("enable_tor", cfg.enable_tor)?;
    validate_binary_flag("enable_clearnet", cfg.enable_clearnet)?;
    validate_binary_flag("mesh_discovery", cfg.mesh_discovery)?;
    validate_binary_flag("allow_relays", cfg.allow_relays)?;
    validate_binary_flag("enable_i2p", cfg.enable_i2p)?;
    validate_binary_flag("enable_bluetooth", cfg.enable_bluetooth)?;
    validate_binary_flag("enable_rf", cfg.enable_rf)?;

    if cfg.wireguard_port > 0 && cfg.wireguard_port < 1024 {
        return Err("wireguard_port must be 0 or an unprivileged port >= 1024".into());
    }

    if cfg.max_peers > MAX_FFI_PEERS {
        return Err(format!("max_peers must be <= {MAX_FFI_PEERS}"));
    }

    if cfg.max_connections > MAX_FFI_CONNECTIONS {
        return Err(format!("max_connections must be <= {MAX_FFI_CONNECTIONS}"));
    }

    if cfg.node_mode > MAX_FFI_NODE_MODE {
        return Err(format!(
            "node_mode must be between 0 and {MAX_FFI_NODE_MODE}"
        ));
    }

    Ok(())
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
pub(crate) unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
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

    if let Err(error) = validate_ffi_config(cfg) {
        set_preinit_error(&format!("mesh_init: invalid config: {error}"));
        return ptr::null_mut();
    }

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
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    data_dir: jni::objects::JString<'_>,
) -> jni::sys::jlong {
    // If Layer 1 was already started (e.g., service onCreate called twice),
    // return the existing pointer immediately.
    let existing = HEADLESS_LAYER1_PTR.load(Ordering::Acquire);
    if existing != 0 {
        HEADLESS_LAYER1_SERVICE_ACTIVE.store(true, Ordering::Release);
        return existing;
    }

    // Convert the Java String to a Rust &str.
    let dir: String = match env
        .with_env(|env| -> jni::errors::Result<_> { Ok(env.get_string(&data_dir)?.into()) })
        .into_outcome()
    {
        jni::Outcome::Ok(dir) => dir,
        _ => return 0,
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
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
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
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
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
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
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

/// Android JNI entry point called by `NativeLayer1Bridge.updateStartupState()`.
///
/// The headless startup service owns the first boot/unlock snapshot before
/// Flutter exists.  Syncing it into Rust before `bootstrap_layer1()` keeps the
/// activity state, cover-traffic profile, and `Layer1Ready` event aligned with
/// the actual Android boot milestone instead of defaulting to non-Android
/// background behavior until the UI attaches.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeUpdateStartupState(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    ctx: jni::sys::jlong,
    state_json: jni::objects::JString<'_>,
) -> jni::sys::jint {
    if ctx == 0 {
        return -1;
    }

    let state_json: String = match env
        .with_env(|env| -> jni::errors::Result<_> { Ok(env.get_string(&state_json)?.into()) })
        .into_outcome()
    {
        jni::Outcome::Ok(json) => json,
        _ => return -1,
    };

    let runtime = unsafe { &*(ctx as *const MeshContext) };
    match runtime.update_android_startup_state(&state_json) {
        Ok(()) => 0,
        Err(error) => {
            runtime.set_error(&error);
            -1
        }
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
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    ctx: jni::sys::jlong,
    peer_mac: jni::objects::JString<'_>,
    fd: jni::sys::jint,
) -> jni::sys::jint {
    if ctx == 0 {
        return -1;
    }
    // Convert JString → Rust &str under a short-lived JavaStr borrow.
    let peer_mac: String = match env
        .with_env(|env| -> jni::errors::Result<_> { Ok(env.get_string(&peer_mac)?.into()) })
        .into_outcome()
    {
        jni::Outcome::Ok(peer_mac) => peer_mac,
        _ => return -1,
    };
    // SAFETY: ctx is the pointer returned by nativeStartLayer1.
    let runtime = unsafe { &*(ctx as *const MeshContext) };
    match runtime.register_wifi_direct_session_fd(&peer_mac, fd) {
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
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    ctx: jni::sys::jlong,
    peer_mac: jni::objects::JString<'_>,
) -> jni::sys::jint {
    if ctx == 0 {
        return -1;
    }
    let peer_mac: String = match env
        .with_env(|env| -> jni::errors::Result<_> { Ok(env.get_string(&peer_mac)?.into()) })
        .into_outcome()
    {
        jni::Outcome::Ok(peer_mac) => peer_mac,
        _ => return -1,
    };
    // SAFETY: ctx is the pointer returned by nativeStartLayer1.
    let runtime = unsafe { &*(ctx as *const MeshContext) };
    match runtime.drain_wifi_direct_session(&peer_mac) {
        Ok(n) => n as jni::sys::jint,
        Err(_) => -1,
    }
}

/// JNI entry for `AndroidProximityBridge.nativeWifiDirectRemoveSession`.
///
/// Drops the Rust-owned Wi-Fi Direct socket for a peer after Android reports a
/// P2P disconnect or the drain loop observes a socket error.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_oniimediaworks_meshinfinity_AndroidProximityBridge_nativeWifiDirectRemoveSession(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    ctx: jni::sys::jlong,
    peer_mac: jni::objects::JString<'_>,
) -> jni::sys::jint {
    if ctx == 0 {
        return -1;
    }
    let peer_mac: String = match env
        .with_env(|env| -> jni::errors::Result<_> { Ok(env.get_string(&peer_mac)?.into()) })
        .into_outcome()
    {
        jni::Outcome::Ok(peer_mac) => peer_mac,
        _ => return -1,
    };
    // SAFETY: ctx is the pointer returned by nativeStartLayer1.
    let runtime = unsafe { &*(ctx as *const MeshContext) };
    match runtime.remove_wifi_direct_session(&peer_mac) {
        Ok(()) => 0,
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
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
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
    let copy_result = env
        .with_env(|env| -> jni::errors::Result<_> {
            let buf = unsafe { jni::objects::JByteArray::from_raw(env, buf) };
            // The JNI API exposes byte arrays as signed bytes, but the bit pattern
            // is preserved, so this cast only changes the type interpretation.
            let frame = unsafe {
                std::slice::from_raw_parts(rust_buf.as_ptr() as *const jni::sys::jbyte, n)
            };
            buf.set_region(env, 0, frame)?;
            Ok(())
        })
        .into_outcome();
    if !matches!(copy_result, jni::Outcome::Ok(())) {
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
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    ctx: jni::sys::jlong,
    data: jni::sys::jbyteArray,
    data_len: jni::sys::jint,
) -> jni::sys::jint {
    if ctx == 0 || data.is_null() || data_len <= 0 {
        return -1;
    }
    // Copy the JVM byte array into a Rust Vec.
    let frame_u8 = match env
        .with_env(|env| -> jni::errors::Result<_> {
            let data = unsafe { jni::objects::JByteArray::from_raw(env, data) };
            let mut frame = vec![0i8; data_len as usize];
            data.get_region(env, 0, &mut frame)?;
            Ok(frame
                .into_iter()
                .map(|byte| byte as u8)
                .collect::<Vec<u8>>())
        })
        .into_outcome()
    {
        jni::Outcome::Ok(frame_u8) => frame_u8,
        _ => return -1,
    };
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

pub mod identity;
pub mod backup;
pub mod messaging;
pub mod peers;
pub mod files;
pub mod events;
pub mod network;
pub mod transport;
pub mod app;

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::identity::*;
    use super::backup::*;
    use super::messaging::*;
    use super::peers::*;
    use super::files::*;
    use super::events::*;
    use super::network::*;
    use super::transport::*;
    use super::app::*;
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
        assert_eq!(
            unsafe { mi_set_transport_flags(ctx, transport_flags.as_ptr()) },
            0
        );

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
        let has_layer1_ready = events.iter().any(|event| event["type"] == "Layer1Ready");
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
        assert_eq!(
            unsafe { mi_bootstrap_layer1(ctx) },
            0,
            "first call must return 0"
        );
        // Second call must also return 0 — no panic, no corruption.
        assert_eq!(
            unsafe { mi_bootstrap_layer1(ctx) },
            0,
            "second call must also return 0"
        );

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
