package com.oniimediaworks.meshinfinity

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import java.io.File

// AndroidStartupService — headless Layer 1 startup for Mesh Infinity.
//
// ## Purpose (§3.1.1)
//
// The spec requires the Layer 1 mesh identity to be initialised at device-
// unlock time, before the user opens the app.  This service is launched by
// AndroidStartupReceiver when the OS delivers LOCKED_BOOT_COMPLETED,
// BOOT_COMPLETED, or USER_UNLOCKED broadcasts.
//
// ## Startup sequence
//
// 1. Device boots → OS delivers LOCKED_BOOT_COMPLETED.
// 2. AndroidStartupReceiver (directBootAware) calls AndroidStartupService.start().
// 3. onCreate() calls startLayer1IfNeeded() which:
//    a. Calls NativeLayer1Bridge.startLayer1() — this creates a MeshRuntime,
//       loads the Layer 1 WireGuard keypair from device-protected storage, and
//       starts transport reconciliation inside Rust.
//    b. Calls bootstrapLayer1IfNeeded() — if the runtime was successfully
//       allocated, calls mi_bootstrap_layer1() via JNI which drives deeper
//       subsystem startup: gossip processor sync, cover traffic parameters,
//       and a Layer1Ready event for any attached Flutter UI.
// 4. User unlocks device → OS delivers USER_UNLOCKED.
// 5. AndroidStartupReceiver fires again and sends a new startService() intent.
// 6. onStartCommand() calls startLayer1IfNeeded() again.  If Layer 1 was
//    previously stuck waiting for storage (direct-boot / pre-first-unlock),
//    this retry picks up where the first attempt left off.
// 7. Flutter opens → mesh_init() finds HEADLESS_LAYER1_PTR != 0 and adopts
//    the existing MeshContext rather than allocating a second runtime.
//
// ## Layer 1 accessibility model (§3.1.1)
//
// The Layer 1 WireGuard keypair is stored in device-protected storage (via
// createDeviceProtectedStorageContext), which is accessible after first device
// unlock without any user credential.  This corresponds to Android Keystore
// entries with setUserAuthenticationRequired(false).  Layer 2 (self identity)
// and Layer 3 (masks) are never loaded by this service — they require explicit
// app-level authentication and live in credential-protected storage.
//
// ## Failure handling
//
// If bootstrap_layer1 returns -1, it means device-protected storage is not
// yet readable (direct-boot mode, before first unlock).  The service records
// this state and will retry on the next onStartCommand() call, which is
// triggered by the USER_UNLOCKED broadcast.
class AndroidStartupService : Service() {
    companion object {
        private const val TAG = "AndroidStartupService"
        private const val CHANNEL_ID = "mesh_infinity_startup"
        private const val NOTIFICATION_ID = 4101

        fun start(context: Context) {
            val intent = Intent(context, AndroidStartupService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    // Whether mi_bootstrap_layer1() has succeeded at least once during this
    // service lifetime.  Used to avoid duplicate bootstrap calls when
    // onStartCommand fires for multiple intents (BOOT_COMPLETED then
    // USER_UNLOCKED, for example).
    @Volatile
    private var layer1Bootstrapped = false

    // ─────────────────────────────────────────────────────────────────────────
    // Keystore-backed Layer 1 secret storage (§3.1.1)
    // ─────────────────────────────────────────────────────────────────────────
    //
    // The 32-byte WireGuard private key is wrapped with an Android Keystore
    // AES-256-GCM entry (`setUserAuthenticationRequired(false)`) and stored in
    // device-protected storage as a ciphertext blob.
    //
    // ## Accessibility model (§3.1.1)
    //
    // Device-protected storage (createDeviceProtectedStorageContext) is readable
    // after first device unlock — the same accessibility level as the raw
    // `mesh_identity.key` file that Rust uses as a fallback.  Storing the
    // Keystore blob here means it can be read at LOCKED_BOOT_COMPLETED time on
    // devices that have already completed first unlock at least once.
    //
    // The Keystore AES wrapping key is bound to the hardware security module
    // (TEE or StrongBox).  Even if an attacker extracts the blob from device-
    // protected storage, the plaintext key cannot be recovered without the
    // device hardware performing the AES-GCM decryption inside the TEE.
    //
    // ## Fallback
    //
    // Rust's `initialize_startup_state()` continues to write the raw key to
    // `data_dir/mesh_identity.key` as a last-resort fallback.  If the Keystore
    // entry is ever deleted (e.g., a security chip reset that does not wipe
    // storage), the node can still boot using the file-based copy.  On the next
    // boot after a Keystore loss, `tryLoadFromKeystore()` returns null and
    // `wrapAndSaveKeypairIfNeeded()` re-wraps the file-based key.

    // The ciphertext blob produced by KeystoreBridge.wrapKey().
    // Stored in device-protected storage so it is readable at boot time.
    // Lazy so we never allocate until first access and createDeviceProtectedStorageContext
    // is available (it requires a fully constructed Context).
    private val keystoreFile: File by lazy {
        // Device-protected context is readable after first device unlock.
        // Using getDir("layer1", ...) creates a private subdirectory:
        //   /data/user_de/<uid>/com.oniimediaworks.meshinfinity/app_layer1/
        createDeviceProtectedStorageContext()
            .getDir("layer1", Context.MODE_PRIVATE)
            .resolve("layer1_keystore.bin")
    }

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        AndroidStartupStateStore.markStartupServiceStarted(this)
        // §3.1.1 — Drive Layer 1 subsystem startup at device-unlock time, before
        // the app opens.  See class-level comment for the full sequence.
        startLayer1IfNeeded()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        AndroidStartupStateStore.markStartupServiceStarted(this)
        // Re-attempt Layer 1 startup and bootstrap on each command in case:
        //   - The first LOCKED_BOOT_COMPLETED attempt failed because storage
        //     was not yet readable (direct-boot mode before first unlock).
        //   - USER_UNLOCKED fired and we now have access to device-protected
        //     storage for the first time.
        startLayer1IfNeeded()
        return START_STICKY
    }

    // Drive the full Layer 1 startup sequence, using the Android Keystore to
    // protect the 32-byte WireGuard private key.
    //
    // ## Startup sequence (§3.1.1 — Keystore path)
    //
    // Step 1 — Attempt Keystore unwrap BEFORE starting the native runtime.
    //   `tryLoadFromKeystore()` reads the AES-256-GCM ciphertext blob from
    //   device-protected storage and decrypts it using the hardware-backed AES
    //   key.  If the blob is missing (first boot) or decryption fails (hardware
    //   change), the return value is null and we fall through to the file-based
    //   path.
    //
    // Step 2 — Start the native runtime (idempotent CAS guard in Rust).
    //   `NativeLayer1Bridge.startLayer1()` calls the Rust JNI entry point which:
    //     - Creates a MeshRuntime in device-protected storage.
    //     - Calls `load_or_create_mesh_identity()` to read/generate the raw key.
    //     - Calls `reconcile_layer1_runtime()` to start transport listeners.
    //   On repeat calls (BOOT_COMPLETED then USER_UNLOCKED) this is a no-op.
    //
    // Step 3a — Keystore copy available: inject it over the file-based key.
    //   `NativeLayer1Bridge.injectLayer1Secret()` calls `mi_layer1_inject_secret`
    //   which overwrites the in-memory identity loaded by Step 2 with the
    //   hardware-backed copy.  This is the common case after the first boot.
    //
    // Step 3b — No Keystore copy: export the file-based key and wrap it.
    //   `wrapAndSaveKeypairIfNeeded()` calls `mi_layer1_export_secret`, wraps
    //   the bytes with `KeystoreBridge.wrapKey()`, and writes the ciphertext
    //   blob to device-protected storage.  On all subsequent boots Step 3a will
    //   be taken instead.
    //
    // Step 4 — Bootstrap deeper Layer 1 subsystems.
    //   `bootstrapLayer1IfNeeded()` drives gossip, cover traffic, and WireGuard
    //   interface sync.
    private fun startLayer1IfNeeded() {
        // Step 1: Attempt to unwrap the hardware-backed secret.
        // Performed BEFORE startLayer1() so we know whether to inject
        // afterward.  If the Keystore blob is absent or corrupted, this
        // returns null and Rust will use/generate the file-based key in Step 2.
        val keystoreSecret = tryLoadFromKeystore()

        // Step 2: Allocate or retrieve the Rust MeshRuntime.
        // The CAS guard inside Rust ensures only one runtime is allocated even
        // if this method is called multiple times (BOOT + USER_UNLOCKED).
        try {
            // NativeLayer1Bridge.startLayer1() calls the Rust JNI entry point
            // Java_…_NativeLayer1Bridge_nativeStartLayer1, which:
            //   - Creates a minimal MeshRuntime in the device-protected data dir.
            //   - Loads the persisted Layer1StartupConfig (transport flags, node
            //     mode, threat context from the previous app session).
            //   - Calls initialize_startup_state() which loads or creates the
            //     Layer 1 WireGuard keypair from device-protected storage.
            //   - Calls reconcile_layer1_runtime() to start transport listeners.
            //   - Stores the context pointer in HEADLESS_LAYER1_PTR so
            //     mesh_init() in Flutter can adopt it without a second allocation.
            NativeLayer1Bridge.startLayer1(this)
        } catch (e: Exception) {
            // Library unavailable or a native error occurred.  Log and continue —
            // a Layer 1 startup failure must not prevent the foreground service
            // from running or the app from launching.  Flutter's mesh_init() will
            // create a fresh runtime when the app opens.
            Log.w(TAG, "Layer 1 native startup failed: ${e.message}")
        }

        // Step 3: Apply the Keystore secret or persist it for future boots.
        if (keystoreSecret != null) {
            // Step 3a: Keystore blob was available and decrypted successfully.
            // Inject it over whatever the file-based path loaded so the
            // hardware-backed copy is the authoritative in-memory key.
            val ok = NativeLayer1Bridge.injectLayer1Secret(keystoreSecret)
            // Zero the plaintext secret immediately — it is now in Rust memory.
            keystoreSecret.fill(0)
            if (ok) {
                Log.d(TAG, "Layer 1 secret injected from Android Keystore.")
            } else {
                Log.w(TAG, "Layer 1 Keystore injection failed — using file-based key.")
            }
        } else {
            // Step 3b: No Keystore blob available (first boot or entry lost).
            // Export the key that Rust just loaded/generated from the file and
            // wrap it with the hardware-backed AES key for future boots.
            wrapAndSaveKeypairIfNeeded()
        }

        // Step 4: Bootstrap the deeper Layer 1 subsystems if we now have a
        // valid runtime pointer.  This may succeed even if a previous call to
        // startLayer1() failed (e.g., library was loaded but storage was not
        // yet available; storage is now available after USER_UNLOCKED).
        bootstrapLayer1IfNeeded()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Keystore helper methods
    // ─────────────────────────────────────────────────────────────────────────

    // Try to load and AES-256-GCM-unwrap the Keystore-protected mesh secret.
    //
    // Returns the raw 32-byte secret if successful, or null if:
    //   - The ciphertext blob does not exist yet (first boot or Keystore loss).
    //   - Decryption fails (hardware change, tampered blob, etc.).
    //
    // Failure is non-fatal: the Rust runtime will use the file-based key
    // (mesh_identity.key) as a fallback, and wrapAndSaveKeypairIfNeeded() will
    // re-wrap it for subsequent boots.
    private fun tryLoadFromKeystore(): ByteArray? {
        return try {
            // If the blob file does not exist, this is either the first boot
            // or the Keystore entry was lost — both cases handled below.
            if (!keystoreFile.exists()) return null
            val wrapped = keystoreFile.readBytes()
            // Decrypt with the hardware-backed AES key.  Throws on MAC failure.
            KeystoreBridge.unwrapKey(wrapped)
        } catch (e: Exception) {
            // Decryption failure can occur if:
            //   - The Keystore AES entry was deleted (factory reset of TEE).
            //   - The ciphertext blob on disk is corrupted.
            //   - The device was restored to a new device without re-enrolling.
            // In all cases we fall back to the file-based key so the node can
            // still boot.  wrapAndSaveKeypairIfNeeded() will re-wrap after load.
            Log.w(TAG, "Keystore unwrap failed — falling back to file-based key: ${e.message}")
            null
        }
    }

    // Export the in-memory secret from Rust and persist it as a Keystore blob.
    //
    // Called on first boot (or after a Keystore entry deletion) immediately
    // after NativeLayer1Bridge.startLayer1() has loaded or generated the key.
    //
    // ## Why write-once
    //
    // We check keystoreFile.exists() and return early if it does.  This means
    // we never overwrite a valid Keystore blob with a new one — the file-based
    // key may rotate (e.g., after an identity reset) but the Keystore blob is
    // sticky until explicitly deleted.  An identity reset should call
    // KeystoreBridge.deleteKey() and delete keystoreFile before regenerating.
    private fun wrapAndSaveKeypairIfNeeded() {
        // If the blob already exists from a previous boot, nothing to do.
        if (keystoreFile.exists()) return

        // Export the 32-byte secret that Rust has in memory.  Returns null if
        // the runtime was never allocated or the identity is not loaded yet.
        val rawSecret = NativeLayer1Bridge.exportLayer1Secret() ?: return

        try {
            // Wrap with the hardware-backed AES-256-GCM key.
            // KeystoreBridge.wrapKey() creates the Keystore entry on first use.
            val wrapped = KeystoreBridge.wrapKey(rawSecret)

            // Persist the ciphertext blob to device-protected storage.
            // Parent directory was created by getDir() in the lazy initialiser.
            keystoreFile.parentFile?.mkdirs()
            keystoreFile.writeBytes(wrapped)

            Log.i(TAG, "Layer 1 secret wrapped and saved to Android Keystore-backed storage.")
        } catch (e: Exception) {
            // Wrap or write failure — the node continues with the file-based key.
            // On the next boot tryLoadFromKeystore() will return null again and
            // we will retry the wrap.
            Log.w(TAG, "Keystore wrap/write failed — secret not persisted to Keystore: ${e.message}")
        } finally {
            // Zero the raw secret bytes immediately regardless of success or
            // failure.  The secret now lives in Rust memory (or the Keystore
            // blob on disk); keeping it in the JVM heap is unnecessary risk.
            rawSecret.fill(0)
        }
    }

    // Call mi_bootstrap_layer1() via JNI to drive deeper subsystem startup.
    //
    // mi_bootstrap_layer1() returns 0 on success, -1 if the mesh identity
    // keypair is not yet readable (direct-boot mode before first unlock).
    //
    // On success: sets layer1Bootstrapped = true so we do not repeat the call.
    // On failure: logs the result and leaves layer1Bootstrapped = false so the
    //             next onStartCommand() call (triggered by USER_UNLOCKED) will
    //             retry automatically.
    private fun bootstrapLayer1IfNeeded() {
        // If we already bootstrapped successfully in this service lifetime,
        // skip the call to avoid emitting duplicate Layer1Ready events.
        if (layer1Bootstrapped) return

        // If the runtime was never allocated (library unavailable or native
        // error), there is nothing to bootstrap.
        val ptr = NativeLayer1Bridge.contextPointer
        if (ptr == 0L) {
            Log.d(TAG, "Layer 1 bootstrap deferred: no native context pointer yet.")
            return
        }

        try {
            // NativeLayer1Bridge exposes mi_bootstrap_layer1 so we can call it
            // without touching the raw pointer directly from Kotlin.
            val result = NativeLayer1Bridge.bootstrapLayer1()
            if (result == 0) {
                // All Layer 1 subsystems are now active:
                //   - Gossip processor and announcement processor synced with
                //     the mesh WireGuard public key.
                //   - Cover traffic parameters computed for the current activity
                //     state (ScreenOff / Backgrounded at this point).
                //   - Layer1Ready event queued for any attached Flutter UI.
                layer1Bootstrapped = true
                Log.i(TAG, "Layer 1 bootstrap succeeded — WireGuard, cover traffic, and gossip active.")
            } else {
                // -1 means the mesh identity keypair is not yet readable.
                // This is expected during LOCKED_BOOT_COMPLETED before the first
                // user unlock.  The next onStartCommand() (USER_UNLOCKED) will
                // retry automatically.
                Log.d(TAG, "Layer 1 bootstrap deferred: identity not yet available " +
                    "(likely direct-boot mode before first unlock). Will retry on USER_UNLOCKED.")
            }
        } catch (e: Exception) {
            // Native exception — log and leave layer1Bootstrapped = false so
            // the next onStartCommand() can retry.
            Log.w(TAG, "Layer 1 bootstrap exception: ${e.message}")
        }
    }

    override fun onDestroy() {
        AndroidStartupStateStore.markStartupServiceStopped(this)
        NativeLayer1Bridge.stopLayer1()
        layer1Bootstrapped = false
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        AndroidStartupStateStore.markStartupServiceStopped(this)
        NativeLayer1Bridge.stopLayer1()
        layer1Bootstrapped = false
        super.onTaskRemoved(rootIntent)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Mesh Infinity startup",
            NotificationManager.IMPORTANCE_LOW,
        )
        channel.description = "Keeps the Layer 1 startup path alive across boot and unlock."
        channel.setShowBadge(false)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val builder =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(this, CHANNEL_ID)
            } else {
                Notification.Builder(this)
            }
        return builder
            .setContentTitle("Mesh Infinity")
            .setContentText("Maintaining Layer 1 startup state")
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }
}
