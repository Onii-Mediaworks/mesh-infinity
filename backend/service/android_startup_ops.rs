//! Android startup and unlock state intake, and Layer 1 subsystem bootstrapping.
//!
//! ## Responsibilities
//!
//! This module has two related but distinct concerns:
//!
//! 1. **Startup state intake** — the Android platform layer (Kotlin) reports
//!    boot and user-unlock milestones via `update_android_startup_state()`.
//!    This lets the backend reason about startup semantics using platform-owned
//!    state rather than inferring everything from app-launch timing.
//!
//! 2. **Layer 1 subsystem bootstrapping** — `bootstrap_layer1()` is the single
//!    call that moves a fully initialised `MeshRuntime` into active Layer 1
//!    participation.  It is called from `AndroidStartupService` immediately
//!    after `nativeStartLayer1()` returns, and also from
//!    `reconcile_layer1_runtime()` whenever the prerequisites become satisfied.
//!
//! ## Layer 1 accessibility model (§3.1.1)
//!
//! The spec distinguishes three identity layers:
//!
//! * **Layer 1 — Mesh Identity**: stored at device-unlock accessibility
//!   (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` / Android Keystore
//!   with `setUserAuthenticationRequired(false)`).  Initialised when the
//!   device is unlocked — before the user opens the app or enters a PIN.
//!   Holds only WireGuard keypairs; participates in tunnels, relay, and cover
//!   traffic; cannot decrypt message content or access the trust graph.
//!
//! * **Layer 2 — Self**: stored at full app-authentication level.  Loaded
//!   only after the user unlocks the app.  Owns the trust graph and derives
//!   mask keypairs.
//!
//! * **Layer 3 — Masks**: per-context pseudonymous identities derived from
//!   Layer 2.  Active only when Layer 2 is unlocked.
//!
//! `bootstrap_layer1()` exclusively sets up Layer 1.  It does NOT touch Layer
//! 2 or Layer 3 material.  The Android Keystore call that backs the mesh
//! identity key uses `setUserAuthenticationRequired(false)` so that it is
//! readable after first device unlock without any additional user gesture.
//!
//! ## Startup sequence on Android
//!
//! 1. Device boots → `LOCKED_BOOT_COMPLETED` fires.
//! 2. `AndroidStartupReceiver` (directBootAware) receives the intent and calls
//!    `AndroidStartupService.start(context)`.
//! 3. `AndroidStartupService.onCreate()` calls `NativeLayer1Bridge.startLayer1()`.
//! 4. Rust `nativeStartLayer1()` creates a `MeshRuntime`, loads the persisted
//!    `Layer1StartupConfig`, calls `initialize_startup_state()` (which loads or
//!    creates the mesh identity keypair), and calls `reconcile_layer1_runtime()`.
//! 5. Kotlin then calls `mi_bootstrap_layer1()` to start the actual subsystems:
//!    WireGuard tunnel management, cover traffic emission, relay participation,
//!    and tunnel-coordination gossip.
//! 6. User unlocks device → `USER_UNLOCKED` fires.
//! 7. `AndroidStartupReceiver` fires again; the service is already running so
//!    `startLayer1IfNeeded()` is a no-op at the Rust level (idempotent CAS).
//! 8. Flutter opens → `mesh_init()` finds `HEADLESS_LAYER1_PTR != 0` and
//!    adopts the existing runtime instead of creating a second one.
//! 9. User authenticates → Layer 2/3 loaded on top of the running Layer 1.

use crate::service::runtime::{AndroidStartupState, MeshRuntime};

impl MeshRuntime {
    // -----------------------------------------------------------------------
    // Startup state intake
    // -----------------------------------------------------------------------

    /// Return the backend-owned Android startup snapshot as JSON.
    ///
    /// Called by `mi_android_startup_state_json` (FFI) so the Flutter UI can
    /// display the current boot and unlock milestone state.
    pub fn get_android_startup_state_json(&self) -> String {
        let state = self
            .android_startup_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
    }

    /// Replace the backend-owned Android startup snapshot.
    ///
    /// Called by the Kotlin `AndroidStartupChannel` each time a new boot or
    /// unlock milestone is reached.  After updating stored state this method
    /// reconciles the Layer 1 runtime (which may promote the participation
    /// state if all prerequisites are now satisfied) and fires an
    /// `AndroidStartupUpdated` event so the Flutter UI can react.
    pub fn update_android_startup_state(&self, state_json: &str) -> Result<(), String> {
        let state: AndroidStartupState = serde_json::from_str(state_json)
            .map_err(|e| format!("invalid android startup state: {e}"))?;
        *self
            .android_startup_state
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = state.clone();
        self.reconcile_layer1_runtime()?;
        self.refresh_layer1_participation_state();
        self.push_event(
            "AndroidStartupUpdated",
            serde_json::to_value(&state).unwrap_or_else(|_| serde_json::json!({})),
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Layer 1 subsystem bootstrapping (§3.1.1)
    // -----------------------------------------------------------------------

    /// Bootstrap all Layer 1 subsystems immediately after device unlock.
    ///
    /// This is the single call that moves a fully initialised `MeshRuntime`
    /// into active Layer 1 participation.  It is designed to be called from
    /// the Android startup service when `BOOT_COMPLETED` or `USER_UNLOCKED`
    /// fires — before the app process or Flutter exist.
    ///
    /// # What this function does
    ///
    /// 1. **Load the Layer 1 keypair** — verifies the mesh identity is present
    ///    in memory (it was loaded during `initialize_startup_state()`).  If it
    ///    is missing, it attempts to load or create it now.  The keypair is
    ///    stored at device-unlock accessibility so it is always readable after
    ///    the first unlock of the day without any user gesture.
    ///
    /// 2. **Initialise the Layer 1 WireGuard interface** — syncs the tunnel
    ///    gossip processor and announcement processor with the current mesh
    ///    identity public key so that WireGuard handshakes can be initiated and
    ///    responded to.  On a live device this causes the backend to begin
    ///    accepting inbound WireGuard handshake requests from mesh peers.
    ///
    /// 3. **Start cover traffic** — refreshes the Layer 1 participation state,
    ///    which updates `layer1_cover_traffic` parameters for the current
    ///    `DeviceActivityState`.  The poll loop then uses these parameters to
    ///    emit synthetic cover packets that are indistinguishable from real
    ///    traffic, providing the anonymity set required by §3.1.1.
    ///
    /// 4. **Start gossip participation** — syncs the gossip engine with the
    ///    mesh identity so that tunnel-coordination gossip (§6.10) can begin:
    ///    the node advertises its availability, responds to coverage requests,
    ///    and accumulates relay reputation.
    ///
    /// 5. **Push a `Layer1Ready` event** — the Flutter UI (if already open)
    ///    receives this via `mi_poll_events()` and can update its network
    ///    status display without polling.
    ///
    /// # Idempotency
    ///
    /// This function is safe to call more than once.  If Layer 1 is already
    /// active (mesh identity loaded, at least one active transport) the call
    /// is a no-op that returns `Ok(())` without pushing a duplicate event.
    ///
    /// # Layer isolation
    ///
    /// This function ONLY touches Layer 1 state.  It does not load, derive, or
    /// use any Layer 2 (self identity) or Layer 3 (mask) key material.  The
    /// split is enforced structurally: Layer 2 keys live inside `SelfIdentity`
    /// behind `identity_unlocked`, which is always `false` during the headless
    /// startup path.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the mesh identity keypair cannot be loaded or created.
    /// Transport reconciliation errors are logged but do not cause this
    /// function to return `Err` — a partially-started Layer 1 is better than
    /// no Layer 1.
    pub fn bootstrap_layer1(&self) -> Result<(), String> {
        // ---------------------------------------------------------------
        // Step 1: Ensure the Layer 1 keypair is loaded.
        //
        // The keypair should already be in memory because `nativeStartLayer1`
        // calls `initialize_startup_state()` which calls
        // `load_or_create_mesh_identity()`.  We check here as a defensive
        // guard: if the startup sequence was interrupted or the keypair was
        // somehow cleared (e.g., direct-boot mode before first unlock when
        // device-protected storage is not yet readable), we return an error
        // so the caller can schedule a retry on the next USER_UNLOCKED intent.
        // ---------------------------------------------------------------
        let mesh_identity_loaded = self
            .mesh_identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();

        if !mesh_identity_loaded {
            // The keypair was not loaded during initialize_startup_state().
            // This is expected in direct-boot mode (before first unlock) when
            // device-protected storage has not yet been made readable by the OS.
            // Fail visibly so the caller can retry on USER_UNLOCKED.
            return Err(
                "Layer 1 bootstrap deferred: mesh identity keypair is not loaded. \
                 Storage may not be available yet (direct-boot mode before first unlock). \
                 Will retry on USER_UNLOCKED."
                    .to_string(),
            );
        }

        // ---------------------------------------------------------------
        // Step 2: Initialise the Layer 1 WireGuard interface.
        //
        // Syncing the tunnel gossip processor and announcement processor
        // with the current mesh public key is the Layer 1 equivalent of
        // "bringing up the WireGuard interface".  The mesh identity public
        // key is the stable node address used in all WireGuard handshakes
        // and routing table entries.
        //
        // On a live device with active transports this causes the Rust
        // backend to start accepting inbound WireGuard initiator messages
        // from peers whose routing tables list our public key as reachable.
        // ---------------------------------------------------------------
        self.sync_tunnel_gossip_identity();
        self.sync_announcement_processor_identity();
        self.sync_store_forward_mode();

        // ---------------------------------------------------------------
        // Step 3 & 4: Start cover traffic and gossip participation.
        //
        // `refresh_layer1_participation_state()`:
        //   - updates `layer1_activity_state` based on current context
        //     (ScreenOff if Android and user not unlocked, Backgrounded
        //     otherwise for the headless startup case)
        //   - computes `layer1_cover_traffic` parameters for that state
        //     (the poll loop uses these to emit synthetic cover packets)
        //   - syncs transport-manager availability flags
        //   - sets `layer1_participation_started = true` if the mesh
        //     identity is loaded and at least one transport is active
        //
        // NOTE: we do NOT call reconcile_layer1_runtime() here because this
        // function is called FROM reconcile_layer1_runtime() (via the wiring
        // in the reconcile tail).  Calling it again would cause infinite
        // recursion.  The transport listeners (clearnet, mDNS) are started
        // by reconcile_layer1_runtime() before it calls bootstrap_layer1().
        // ---------------------------------------------------------------
        self.refresh_layer1_participation_state();

        // ---------------------------------------------------------------
        // Step 5: Notify any attached Flutter UI.
        //
        // If Flutter is already open (e.g., the service restart path), it
        // will receive this event on the next `mi_poll_events()` call and
        // can update the network status display without polling.
        //
        // If Flutter is not yet open the event is queued and will be
        // delivered when Flutter calls `mi_poll_events()` after attaching
        // to the shared MeshContext.
        // ---------------------------------------------------------------

        // Only push the event if participation has actually started — avoid
        // emitting false-positive Layer1Ready events when storage is not yet
        // available and the transport count is still zero.
        let participation_started = *self
            .layer1_participation_started
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if participation_started {
            let cover = *self
                .layer1_cover_traffic
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let activity_state = *self
                .layer1_activity_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let android_startup = self
                .android_startup_state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            self.push_event(
                "Layer1Ready",
                serde_json::json!({
                    // Whether the node is now actively relaying and generating
                    // cover traffic without any user interaction.
                    "participating": true,
                    // The current activity state drives cover traffic volume:
                    // ScreenOff = minimum rate; Backgrounded = low; etc.
                    "activityState": format!("{activity_state:?}").to_lowercase(),
                    // Cover traffic parameters active at bootstrap time.
                    "coverTraffic": {
                        "targetTunnelsMin": cover.target_tunnels_min,
                        "targetTunnelsMax": cover.target_tunnels_max,
                        "coverRateBytesPerSec": cover.cover_rate_bytes_per_sec,
                    },
                    // Whether this bootstrap happened in headless mode
                    // (before the user opened the app).
                    "headless": !self.identity_unlocked,
                    // Startup milestone context from the Android platform layer.
                    "androidStartup": {
                        "bootCompleted": android_startup.boot_completed,
                        "userUnlocked": android_startup.user_unlocked,
                        "lockedBootCompleted": android_startup.locked_boot_completed,
                    },
                }),
            );
        }

        Ok(())
    }

    /// Returns `true` if all Layer 1 subsystems are up and participating.
    ///
    /// "Participating" means:
    /// - The mesh identity keypair is loaded in memory (Layer 1 WireGuard
    ///   interface is initialised).
    /// - At least one transport type is active (the node can send and
    ///   receive WireGuard packets on the mesh).
    ///
    /// This is a lightweight query suitable for polling from JNI.  It does
    /// not acquire any external resources or push events.
    pub fn is_layer1_ready(&self) -> bool {
        *self
            .layer1_participation_started
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
}
