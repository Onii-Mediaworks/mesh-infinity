//! Peers and trust management FFI shims (§8).
//! Each function is a thin C-ABI wrapper (null-check → delegate → return).
//! No business logic lives here.

use std::os::raw::c_char;
use std::ptr;
use std::os::raw::c_int;

use super::{c_str_to_str, MeshContext};

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
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    ctx_long: jni::sys::jlong,
    data: jni::objects::JByteArray,
) -> jni::sys::jint {
    // Guard: a zero context pointer means the runtime was never allocated.
    if ctx_long == 0 {
        return -1;
    }

    // Retrieve the byte array length before copying.
    let len = match env
        .with_env(|env| -> jni::errors::Result<_> { Ok(data.len(env)?) })
        .into_outcome()
    {
        jni::Outcome::Ok(len) => len,
        _ => return -1,
    };
    // Only 32-byte secrets are valid.
    if len != 32 {
        return -1;
    }

    // Copy the JVM-managed bytes into a local stack buffer.  We use a signed
    // slice first (jbyte = i8) then transmute to [u8; 32] — the bit patterns
    // are identical; we just change the type interpretation.
    let mut buf = match env
        .with_env(|env| -> jni::errors::Result<_> {
            let mut buf = [0i8; 32];
            data.get_region(env, 0, &mut buf)?;
            Ok(buf)
        })
        .into_outcome()
    {
        jni::Outcome::Ok(buf) => buf,
        _ => return -1,
    };
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
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
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
    match env
        .with_env(|env| -> jni::errors::Result<_> { Ok(env.byte_array_from_slice(&secret)?) })
        .into_outcome()
    {
        jni::Outcome::Ok(arr) => arr.into_raw() as jni::sys::jobject,
        _ => null_obj,
    }
}

/// JNI entry point for `NativeLayer1Bridge.nativeSendRawPacket`.
///
/// Receives a raw IP packet from the Android App Connector VPN tunnel (§5.10,
/// §17.5) and forwards it into the Rust mesh data plane via
/// `TransportOps::ingest_tun_packet`.
///
/// Returns:
///   1  — packet accepted and queued for mesh transmission.
///   0  — empty packet or no mesh route to the destination; packet dropped.
///  -1  — null/invalid context pointer or JNI error; packet dropped.
///
/// # Safety
///
/// `ctx_long` must be the value returned by `nativeStartLayer1`.
/// `packet` must be a valid non-null JNI byte array.
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "system" fn Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeSendRawPacket(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    ctx_long: jni::sys::jlong,
    packet: jni::objects::JByteArray,
) -> jni::sys::jint {
    // Guard: a zero context pointer means the runtime was never allocated.
    if ctx_long == 0 {
        return -1;
    }

    // Retrieve byte array length.
    let len = match env
        .with_env(|env| -> jni::errors::Result<_> { Ok(packet.len(env)?) })
        .into_outcome()
    {
        jni::Outcome::Ok(len) => len,
        _ => return -1,
    };

    if len == 0 {
        return 0;
    }

    // Copy packet bytes from the JVM into a Rust-owned Vec.
    let bytes: Vec<u8> = match env
        .with_env(|env| -> jni::errors::Result<_> {
            let mut buf = vec![0i8; len as usize];
            packet.get_region(env, 0, &mut buf)?;
            // SAFETY: i8 and u8 have identical representations; all bit patterns valid.
            let ubuf: Vec<u8> = unsafe { std::mem::transmute(buf) };
            Ok(ubuf)
        })
        .into_outcome()
    {
        jni::Outcome::Ok(b) => b,
        _ => return -1,
    };

    // SAFETY: ctx_long was returned by nativeStartLayer1 and is valid while the
    // startup service holds it (coordinated by HEADLESS_LAYER1_PTR).
    let ctx = unsafe { &*(ctx_long as *const MeshContext) };
    if ctx.ingest_tun_packet(&bytes) { 1 } else { 0 }
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

/// Remove a Rust-owned Wi-Fi Direct session socket.
///
/// This is the C ABI counterpart to the Android JNI
/// `nativeWifiDirectRemoveSession` entry point.  It lets any platform adapter
/// that hands a socket fd to Rust explicitly release the backend session when
/// the platform reports disconnect.
///
/// # Safety
///
/// `ctx` must be non-null.  `peer_mac_ptr` must be a valid null-terminated
/// UTF-8 string.
#[no_mangle]
#[cfg(target_os = "android")]
pub unsafe extern "C" fn mi_wifi_direct_remove_session(
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
            ctx.set_error("mi_wifi_direct_remove_session: peer_mac is not valid UTF-8");
            return -1;
        }
    };
    match ctx.remove_wifi_direct_session(peer_mac) {
        Ok(()) => 0,
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
///   (244) to guarantee all queued frames can be popped.
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

