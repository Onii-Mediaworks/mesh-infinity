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
}
