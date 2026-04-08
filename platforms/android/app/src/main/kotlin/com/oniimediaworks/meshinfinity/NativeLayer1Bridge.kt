package com.oniimediaworks.meshinfinity

import android.content.Context
import java.io.File

// NativeLayer1Bridge — Android JNI bridge for headless Layer 1 startup.
//
// The Mesh Infinity spec (§3.1.1) requires Layer 1 mesh participation to begin
// at device unlock, before the app opens and before Flutter initialises.
//
// AndroidStartupService calls startLayer1() during onCreate() so that the Rust
// backend's WireGuard tunnel management, cover traffic emission, relay slot
// acceptance, and gossip propagation all start at unlock time.
//
// When Flutter later calls mesh_init() (via the Dart FFI layer), the Rust code
// detects HEADLESS_LAYER1_PTR != 0 and reuses the existing MeshContext rather
// than allocating a second runtime.  The two code paths share one process-wide
// Rust runtime.
object NativeLayer1Bridge {

    // Whether the native library has been successfully loaded into this process.
    @Volatile
    private var libLoaded = false

    // Raw pointer to the MeshContext created by nativeStartLayer1().
    // Stored as Long (JNI jlong = 64-bit signed integer) so it can be passed
    // between the JVM and native code without loss of precision on 64-bit ARM.
    // 0L means "not started".
    @Volatile
    var contextPointer: Long = 0L
        private set

    init {
        try {
            // mesh_infinity is the cdylib built from the Rust backend.
            // System.loadLibrary() is idempotent — safe to call from multiple
            // sites (Service, MainActivity, etc.).
            System.loadLibrary("mesh_infinity")
            libLoaded = true
        } catch (_: UnsatisfiedLinkError) {
            // Library unavailable — running in a test environment or an
            // architecture where the .so has not been bundled.  Startup
            // continues without Layer 1; Flutter's mesh_init() will
            // initialise the runtime when the app opens.
        }
    }

    // Start Layer 1 mesh participation using device-protected storage.
    //
    // Uses createDeviceProtectedStorageContext() so this can be called in
    // direct-boot mode (before the user has entered their PIN / biometric).
    // Layer 1 does not require credential-protected storage — it only needs
    // the mesh identity keypair, which is stored at device-unlock level
    // (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly equivalent on Android).
    //
    // Returns the raw context pointer (same value as HEADLESS_LAYER1_PTR in
    // Rust), or 0L if startup failed.
    @Synchronized
    fun startLayer1(context: Context): Long {
        if (!libLoaded) return 0L
        if (contextPointer != 0L) return contextPointer

        // Resolve the data directory using device-protected storage so this
        // works in direct-boot mode (before the user credential is available).
        val deviceCtx = context.createDeviceProtectedStorageContext() ?: context
        val dataDir = File(deviceCtx.filesDir, "mesh_infinity_data").absolutePath

        contextPointer = nativeStartLayer1(dataDir)
        return contextPointer
    }

    // Release the startup service's ownership of the native Layer 1 runtime.
    //
    // The Rust backend keeps the runtime alive until both:
    //   1. AndroidStartupService has stopped, and
    //   2. Flutter has detached from the shared MeshContext.
    //
    // This prevents mesh_destroy() from freeing the runtime while the startup
    // service is still active, while still allowing eventual cleanup.
    @Synchronized
    fun stopLayer1() {
        if (!libLoaded) return
        nativeStopLayer1()
        contextPointer = 0L
    }

    // Bootstrap all Layer 1 subsystems by calling mi_bootstrap_layer1() on
    // the existing MeshContext.
    //
    // This must be called after startLayer1() has returned a non-zero context
    // pointer.  It drives the deeper subsystem startup that goes beyond transport
    // reconciliation:
    //
    //   1. Verifies the Layer 1 WireGuard keypair is in memory.
    //   2. Syncs the tunnel gossip processor with the mesh public key so the
    //      node can participate in coverage-request/response gossip (§6.10).
    //   3. Syncs the announcement processor for routing-table propagation.
    //   4. Refreshes cover traffic parameters for the current activity state.
    //   5. Queues a Layer1Ready event for any attached Flutter UI.
    //
    // Returns:
    //   0  — bootstrap succeeded; Layer 1 is now fully active.
    //  -1  — bootstrap deferred; the mesh identity keypair is not yet readable
    //         (direct-boot mode before first unlock).  Retry on USER_UNLOCKED.
    @Synchronized
    fun bootstrapLayer1(): Int {
        if (!libLoaded) return -1
        if (contextPointer == 0L) return -1
        return nativeBootstrapLayer1(contextPointer)
    }

    // Query whether Layer 1 participation is currently active.
    //
    // Returns true if the mesh identity keypair is loaded AND at least one
    // transport type is active.  Safe to call frequently — no side effects.
    @Synchronized
    fun isLayer1Ready(): Boolean {
        if (!libLoaded) return false
        if (contextPointer == 0L) return false
        return nativeIsLayer1Ready(contextPointer) != 0
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Keystore-backed identity inject / export (§3.1.1)
    // ─────────────────────────────────────────────────────────────────────────
    //
    // These two methods are the Kotlin side of the hardware-backed key-protection
    // path.  They wrap the JNI declarations `nativeInjectLayer1Secret` and
    // `nativeExportLayer1Secret` with null-pointer / library-loaded guards.
    //
    // ## Why the Keystore path matters
    //
    // Without Keystore wrapping the 32-byte WireGuard private key lives in
    // `data_dir/mesh_identity.key` as raw bytes.  An attacker with physical
    // flash access or root could extract it.  By wrapping the key with an
    // AES-256-GCM entry in the Android Keystore (`setUserAuthenticationRequired
    // = false`, so it is unlocked on first device boot), the plaintext key
    // material never touches persistent storage — only the ciphertext blob does.
    // The AES wrapping key is bound to the hardware security module (TEE /
    // StrongBox) and cannot be exported.
    //
    // ## Call contract
    //
    // `injectLayer1Secret` — called by AndroidStartupService after a successful
    //   Keystore unwrap.  The 32-byte array passed here is zeroed by the caller
    //   immediately after this method returns.
    //
    // `exportLayer1Secret` — called by AndroidStartupService on first boot (or
    //   after a Keystore entry deletion) to retrieve the key that Rust already
    //   has in memory so Kotlin can wrap it.  The returned array MUST be zeroed
    //   (`.fill(0)`) by the caller immediately after wrapping.

    /** Inject 32 raw secret bytes as the in-memory mesh identity.
     *
     * Overwrites whatever file-based key Rust loaded during `startLayer1()` so
     * the hardware-backed Keystore copy is authoritative for the lifetime of
     * this boot.  The supplied array is copied into a Rust stack buffer on the
     * native side; the caller must zero it with `.fill(0)` immediately after
     * this call returns to minimise the window during which the secret is live
     * in the JVM heap.
     *
     * Returns `true` on success, `false` if the library is not loaded, the
     * context is not yet allocated, or the native side rejected the injection.
     */
    @Synchronized
    fun injectLayer1Secret(secretBytes: ByteArray): Boolean {
        // Guard: library not available (test environment or missing .so).
        if (!libLoaded) return false
        // Guard: runtime was never allocated — nothing to inject into.
        val ptr = contextPointer
        if (ptr == 0L) return false
        // Delegate to the JNI symbol; result 0 = success, -1 = error.
        return nativeInjectLayer1Secret(ptr, secretBytes) == 0
    }

    /** Export the current 32-byte mesh identity secret from native memory.
     *
     * Returns the raw WireGuard private key bytes if a mesh identity is
     * currently loaded, or `null` if the identity has not been loaded yet.
     *
     * ## IMPORTANT — caller must zero the returned array
     *
     * The returned `ByteArray` is a copy of secret key material.  The caller
     * MUST call `.fill(0)` on it as soon as the wrapping operation is complete
     * to prevent the secret from living in the JVM heap until GC.
     */
    @Synchronized
    fun exportLayer1Secret(): ByteArray? {
        // Guard: library not available (test environment or missing .so).
        if (!libLoaded) return null
        // Guard: runtime was never allocated — no identity to export.
        val ptr = contextPointer
        if (ptr == 0L) return null
        // Delegate to the JNI symbol; returns null if no identity is loaded.
        return nativeExportLayer1Secret(ptr)
    }

    // JNI declaration matching the Rust symbol
    //   Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeStartLayer1
    //
    // dataDir: absolute path to the device-protected data directory that Rust
    //          should use for the mesh identity and state files.
    //
    // Returns: the MeshContext pointer cast to i64, or 0 on failure.
    private external fun nativeStartLayer1(dataDir: String): Long

    // JNI declaration matching the Rust symbol
    //   Java_com_oniimediaworks_meshinfinity_NativeLayer1Bridge_nativeStopLayer1
    //
    // Releases the startup service's ownership of the shared MeshContext.
    private external fun nativeStopLayer1()

    // JNI declaration matching the Rust symbol mi_bootstrap_layer1.
    //
    // ctx:     MeshContext pointer (cast to Long / jlong).
    // Returns: 0 on success, -1 if the mesh identity is not yet available.
    private external fun nativeBootstrapLayer1(ctx: Long): Int

    // JNI declaration matching the Rust symbol mi_is_layer1_ready.
    //
    // ctx:     MeshContext pointer (cast to Long / jlong).
    // Returns: 1 if Layer 1 is active, 0 otherwise.
    private external fun nativeIsLayer1Ready(ctx: Long): Int

    // JNI declaration for the Keystore inject path.
    //
    // ctx:  MeshContext pointer (cast to Long / jlong).
    // data: exactly 32 bytes of raw WireGuard private key entropy.
    // Returns: 0 on success, -1 on error (null pointer or wrong length).
    private external fun nativeInjectLayer1Secret(ctx: Long, data: ByteArray): Int

    // JNI declaration for the Keystore export path.
    //
    // ctx:  MeshContext pointer (cast to Long / jlong).
    // Returns: a new 32-byte ByteArray, or null if no identity is loaded.
    // Caller MUST call `.fill(0)` on the returned array after use.
    private external fun nativeExportLayer1Secret(ctx: Long): ByteArray?
}
