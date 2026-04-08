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

    // Drive the full Layer 1 startup sequence.
    //
    // Step 1: Allocate the native MeshRuntime via NativeLayer1Bridge (idempotent
    //         — the Rust CAS guard means only the first call allocates; later
    //         calls return the existing pointer).
    //
    // Step 2: If the runtime is available and we have not yet successfully
    //         bootstrapped the Layer 1 subsystems, call bootstrapLayer1IfNeeded().
    private fun startLayer1IfNeeded() {
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

        // Step 2: Bootstrap the deeper Layer 1 subsystems if we now have a
        // valid runtime pointer.  This may succeed even if a previous call to
        // startLayer1() failed (e.g., library was loaded but storage was not
        // yet available; storage is now available after USER_UNLOCKED).
        bootstrapLayer1IfNeeded()
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
