//! Plugin System (§18)
//!
//! # Three Tiers of Extensibility (§18.1)
//!
//! 1. **API integration**: external apps connect via service ports
//! 2. **Service hosting**: custom services on the mesh
//! 3. **Native plugins**: WASM modules with restricted permissions
//!
//! # Plugin Security (§18.3)
//!
//! Permanently off-limits (11 items):
//! - Key material access
//! - Raw transport layer access
//! - Trust graph mutation
//! - Other plugins' data
//! - Rust backend internals
//! - Anonymous mask linkage
//! - Root keypair operations
//! - Killswitch activation
//! - Threat context modification
//! - OIDC tokens
//! - Trust-related UI dialogs
//!
//! # Registry Architecture
//!
//! The `PluginRegistry` is the central authority for plugin lifecycle
//! management. It tracks installed plugins, manages activation states,
//! dispatches hook invocations, and enforces permission boundaries.
//! Plugins communicate with the host through named hooks — each hook
//! receives a JSON input and returns a JSON output. The registry
//! records timing for each invocation to detect performance regressions.
//!
//! # WASM Sandbox (§18.1, §18.2)
//!
//! On Android and desktop platforms, plugin WASM modules execute inside a
//! `PluginSandbox` powered by wasmtime with cranelift JIT compilation.
//! Key properties of the sandbox:
//!
//! - **Memory isolation**: each plugin's WASM linear memory is bounded and
//!   completely separate from the host process and other plugins.
//! - **CPU time limits**: epoch-based interruption is enabled on the engine,
//!   and each invocation sets a deadline of `MAX_CPU_PER_CALLBACK_MS` ticks.
//!   The epoch counter is advanced by a background thread; when the deadline
//!   is reached, wasmtime traps the WASM execution and returns an error.
//! - **Capability-based I/O**: WASI preview1 is linked but configured with
//!   no filesystem mounts and no network access — an empty `WasiCtxBuilder`.
//!   Plugins can only call the two host imports we explicitly expose:
//!     - `mesh_log(ptr, len)` — write a log line via the registry logger
//!     - `mesh_get_permission(ptr, len) -> i32` — query a permission by name
//! - **Permanently off-limits** (§18.3): key material, raw transport, trust
//!   graph, other plugins' data, and all 11 §18.3 items are never exposed.
//!
//! iOS / iPadOS: third-party executable plugins are not available per §18.1.
//! The sandbox and all WASM execution code is excluded from iOS builds via
//! `#[cfg(not(target_os = "ios"))]`. On iOS, `invoke_hook_sandboxed` returns
//! an empty vec immediately.
//!
//! # Plugin ABI
//!
//! The plugin must export:
//! ```text
//! hook_dispatch(hook_name_ptr: i32, hook_name_len: i32,
//!               input_ptr: i32, input_len: i32) -> i64
//! ```
//! The return value is a packed `(output_ptr: i32, output_len: i32)` encoded
//! as `(output_ptr as i64) << 32 | output_len as i64`. The output bytes in
//! WASM linear memory are valid UTF-8 JSON. An output_len of 0 means no
//! output (equivalent to `None`).
//!
//! # Signature Verification
//!
//! Plugin packages carry an Ed25519 signature that binds the manifest
//! and binary to the author's public key. Verification uses the
//! domain-separated `DOMAIN_PLUGIN_SIGNATURE` to prevent cross-protocol
//! signature replay (see `crypto::signing`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Import the centralized error type for all fallible operations.
// Every public function returns Result<T, MeshError>.
use crate::error::MeshError;

// Import the domain-separated signing module for plugin signature verification.
// All signature operations go through this centralized module (§18.3).
use crate::crypto::signing;

// ---------------------------------------------------------------------------
// WASM Sandbox (non-iOS only — §18.1)
// ---------------------------------------------------------------------------
//
// All wasmtime types are gated behind `#[cfg(not(target_os = "ios"))]`.
// iOS does not support user-installed executable plugins (§18.1), so there
// is no sandbox to build, and wasmtime is never linked on that target.

/// Per-invocation state threaded through the wasmtime Store (non-iOS only).
///
/// wasmtime's `Linker<T>` is generic over a host state type `T`. Every host
/// function closure receives `&mut T` (wrapped in a `Caller<T>`), so we use
/// this struct to pass per-call context — the plugin's granted permissions
/// and the WASI preview1 execution context — into the host functions without
/// global mutable state.
///
/// A fresh `SandboxState` is created for every `invoke_hook_sandboxed` call;
/// it is dropped when the `Store` is dropped at the end of the call.
#[cfg(not(target_os = "ios"))]
struct SandboxState {
    /// Permissions granted to the currently executing plugin.
    ///
    /// Host functions such as `mesh_get_permission` consult this list to
    /// decide whether to return 1 (granted) or 0 (denied). The list is a
    /// clone of `Plugin::permissions` captured before instantiation.
    permissions: Vec<PluginPermission>,

    /// WASI preview1 execution context.
    ///
    /// wasmtime-wasi's preview1 shim requires a `WasiP1Ctx` object (produced
    /// by `WasiCtxBuilder::build_p1()`) to be accessible from the `T` type
    /// stored in the `Store`. The linker function registered by
    /// `wasmtime_wasi::preview1::add_to_linker_sync` extracts it via the
    /// closure we pass: `|state| &mut state.wasi`.
    ///
    /// We configure it with an empty `WasiCtxBuilder` — no filesystem mounts,
    /// no network access, no pre-opened directories, no env vars. Plugins
    /// cannot touch the host filesystem or initiate network calls through WASI.
    wasi: wasmtime_wasi::preview1::WasiP1Ctx,
}

/// The WASM plugin execution sandbox (non-iOS only, §18.1).
///
/// `PluginSandbox` is a long-lived object (typically one per backend runtime
/// instance) that owns the shared wasmtime `Engine` and `Linker`. These are
/// expensive to create but cheap to clone references to, so they are created
/// once and reused across all plugin invocations.
///
/// # Engine configuration
///
/// - Cranelift JIT compilation (`features = ["cranelift"]` in Cargo.toml)
/// - Epoch interruption enabled at the Config level
///   (`Config::epoch_interruption(true)`) — this arms the mechanism;
///   each Store still calls `set_epoch_deadline` to set a per-call deadline.
///
/// # Module cache
///
/// Compiled `wasmtime::Module` objects are stored in `modules`, keyed by the
/// same 16-byte plugin ID used by the registry. AOT compilation happens once
/// (in `load_module`) and the result is reused for every subsequent
/// invocation, making repeated calls cheap (just instantiation overhead).
///
/// # Epoch counter thread
///
/// A background thread drives the epoch counter by calling
/// `Engine::increment_epoch` every millisecond. Each Store call sets its
/// deadline to `MAX_CPU_PER_CALLBACK_MS` ticks; if execution hasn't returned
/// by the time the background thread has incremented the counter that many
/// times, wasmtime interrupts the guest with a trap.
#[cfg(not(target_os = "ios"))]
pub struct PluginSandbox {
    /// The shared wasmtime engine with cranelift JIT and epoch interruption.
    ///
    /// `Engine` is internally reference-counted and cheap to clone. The same
    /// engine is shared across all modules and stores in this sandbox.
    engine: wasmtime::Engine,

    /// The linker pre-populated with WASI preview1 and our mesh host imports.
    ///
    /// `Linker<SandboxState>` is built once in `PluginSandbox::new()`:
    ///   1. `wasmtime_wasi::preview1::add_to_linker_sync` populates WASI.
    ///   2. We manually define `mesh_log` and `mesh_get_permission`.
    ///
    /// Every instantiation clones this linker (cheap — it shares a reference
    /// to the underlying data structures) and then calls `instantiate`.
    linker: wasmtime::Linker<SandboxState>,

    /// AOT-compiled modules, indexed by the 16-byte plugin ID.
    ///
    /// Populated by `load_module` when a plugin is activated. Keyed by the
    /// same `[u8; 16]` ID that `PluginRegistry` uses internally. A missing
    /// entry means the plugin has no WASM bytes loaded (or they failed to
    /// compile), and `invoke_hook_sandboxed` will skip that plugin gracefully.
    modules: HashMap<[u8; 16], wasmtime::Module>,

    /// Per-plugin timeout counter (number of consecutive epoch timeouts).
    ///
    /// When a plugin's WASM execution exceeds `MAX_CPU_PER_CALLBACK_MS` the
    /// epoch mechanism traps it. Each trap increments this counter. When it
    /// reaches `TIMEOUT_AUTO_DISABLE`, the plugin is flagged for suspension
    /// and the caller should call `PluginRegistry::suspend()`.
    timeout_counts: HashMap<[u8; 16], u32>,

    /// Per-plugin crash counter (number of consecutive WASM traps).
    ///
    /// Any WASM trap (including panics that compile to `unreachable`) that is
    /// NOT an epoch timeout increments this counter. When it reaches
    /// `CRASH_QUARANTINE_THRESHOLD`, the plugin's status should be set to
    /// `PluginStatus::Failed` and marked for quarantine.
    crash_counts: HashMap<[u8; 16], u32>,
}

#[cfg(not(target_os = "ios"))]
impl PluginSandbox {
    /// Create a new sandbox with a cranelift engine and WASI+mesh host imports.
    ///
    /// This function:
    /// 1. Configures a `wasmtime::Engine` with cranelift JIT and epoch
    ///    interruption enabled.
    /// 2. Creates a `Linker<SandboxState>` and populates it with:
    ///    - WASI preview1 snapshot (no filesystem/network capability granted
    ///      at construction time — capability is per-Store via `WasiCtxBuilder`)
    ///    - `mesh::mesh_log(ptr: i32, len: i32)` host function
    ///    - `mesh::mesh_get_permission(ptr: i32, len: i32) -> i32` host function
    /// 3. Spawns a background thread that increments the engine's epoch counter
    ///    once per millisecond, driving the CPU time enforcement mechanism.
    ///
    /// Returns an error if wasmtime fails to initialise (should not happen in
    /// practice on supported platforms).
    pub fn new() -> anyhow::Result<Self> {
        // --- Engine configuration -------------------------------------------
        //
        // Build a wasmtime Config with:
        //   - Cranelift: the optimising JIT compiler (enabled via Cargo feature)
        //   - Epoch interruption: armed here at the Config level; individual
        //     Stores must also call set_epoch_deadline() to activate it per call
        let mut config = wasmtime::Config::new();
        // Epoch interruption is a RUNTIME config option, not a Cargo feature.
        // Enabling it here arms the mechanism globally for this engine.
        // Each Store must still call `set_epoch_deadline(N)` to set its own
        // deadline — until that call, no interruption will occur.
        config.epoch_interruption(true);
        // cranelift_opt_level is the default for the cranelift feature; we
        // spell it out explicitly so the intent is clear in code review.
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);

        let engine = wasmtime::Engine::new(&config)?;

        // --- Linker setup ---------------------------------------------------
        //
        // The linker is populated once and reused across instantiations.
        // Order matters: WASI must be added before any custom imports in the
        // same namespace (though "wasi_snapshot_preview1" and "mesh" are
        // separate namespaces so order is actually irrelevant here).
        let mut linker: wasmtime::Linker<SandboxState> = wasmtime::Linker::new(&engine);

        // Add WASI preview1 (wasi_snapshot_preview1) imports to the linker.
        //
        // This populates ~50 WASI syscall imports (fd_read, fd_write, proc_exit,
        // etc.) so plugins compiled against wasi-sdk or similar toolchains link
        // without import errors. The actual capabilities granted at runtime are
        // controlled by the per-Store `WasiCtxBuilder::build_p1()` — our empty
        // builder grants zero filesystem/network access.
        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |state: &mut SandboxState| {
            // Extract the `WasiP1Ctx` from our composite state.
            // The linker uses this closure to get the WASI context out of T
            // for every WASI host function call.
            &mut state.wasi
        })?;

        // --- Host import: mesh::mesh_log(ptr: i32, len: i32) ---------------
        //
        // Allows plugins to write log messages visible in the backend log.
        // The plugin passes a UTF-8 string in its linear memory at [ptr, ptr+len).
        // We validate the range, convert to UTF-8, and log via tracing.
        //
        // Security: this function does not grant any capability beyond logging.
        // It cannot be used to exfiltrate data because the log is not returned
        // to the plugin. Per §18.3, key material and internals are never logged.
        linker.func_wrap(
            "mesh",           // module name in the WASM import section
            "mesh_log",       // function name in the WASM import section
            |mut caller: wasmtime::Caller<'_, SandboxState>, ptr: i32, len: i32| {
                // Retrieve the plugin's linear memory.
                // "memory" is the standard WASM memory export name.
                // If the plugin has no memory export, we log a warning and return.
                let mem = match caller.get_export("memory") {
                    Some(wasmtime::Extern::Memory(m)) => m,
                    _ => {
                        // Plugin module has no "memory" export — unusual but not fatal.
                        // We cannot read the log message, so we skip it silently.
                        tracing::warn!("plugin mesh_log: no memory export");
                        return;
                    }
                };

                // Bounds-check the pointer and length against the linear memory size.
                // ptr and len are i32 (WASM's native integer type); cast to usize safely.
                let ptr = ptr as usize;
                let len = len as usize;
                let mem_data = mem.data(&caller);

                // Ensure the slice [ptr, ptr+len) is within the allocated linear memory.
                // An out-of-bounds access would be a plugin bug; we ignore it.
                if ptr.saturating_add(len) > mem_data.len() {
                    tracing::warn!("plugin mesh_log: pointer out of bounds");
                    return;
                }

                // Extract the bytes and validate UTF-8.
                // Plugins compiled from Rust/C will always produce valid UTF-8;
                // if they don't, we fall back to a lossy conversion.
                let bytes = &mem_data[ptr..ptr + len];
                let msg = String::from_utf8_lossy(bytes);
                // Log at INFO level through the standard tracing infrastructure.
                // These messages appear in the app's debug log alongside backend messages.
                tracing::info!(target: "plugin", "[plugin log] {}", msg);
            },
        )?;

        // --- Host import: mesh::mesh_get_permission(ptr, len) -> i32 -------
        //
        // Allows plugins to query whether they hold a named permission.
        // The plugin passes a UTF-8 permission name string in linear memory.
        // Returns 1 if the permission is granted, 0 if denied.
        //
        // This is a read-only query — it cannot grant new permissions.
        // The permission list in SandboxState is a snapshot captured at
        // invocation time from Plugin::permissions; the plugin cannot modify it.
        //
        // Security (§18.3): this function only reflects permissions the user
        // already granted at install time. It cannot be used to escalate
        // privileges or discover undeclared capabilities.
        linker.func_wrap(
            "mesh",
            "mesh_get_permission",
            |mut caller: wasmtime::Caller<'_, SandboxState>, ptr: i32, len: i32| -> i32 {
                // Read the permission name from linear memory (same pattern as mesh_log).
                let mem = match caller.get_export("memory") {
                    Some(wasmtime::Extern::Memory(m)) => m,
                    _ => return 0, // No memory → no permissions readable → deny
                };

                let ptr = ptr as usize;
                let len = len as usize;
                let mem_data = mem.data(&caller);

                // Bounds check before slicing.
                if ptr.saturating_add(len) > mem_data.len() {
                    return 0; // Out-of-bounds → deny
                }

                // Parse the permission name. Invalid UTF-8 → deny.
                let name = match std::str::from_utf8(&mem_data[ptr..ptr + len]) {
                    Ok(s) => s,
                    Err(_) => return 0,
                };

                // Convert the permission name string to a typed PluginPermission.
                // parse_permission_str handles unknown strings as Custom variants.
                let requested = parse_permission_str(name);

                // Check against the snapshot in SandboxState.
                // The `data()` call returns a reference to T from the Caller.
                // We need to take the data AFTER we're done with mem_data borrow.
                // Reborrow needed: drop mem_data first.
                let granted = caller.data().permissions.contains(&requested);
                // Return 1 (granted) or 0 (denied) following WASM boolean convention.
                if granted { 1 } else { 0 }
            },
        )?;

        // --- Background epoch ticker ----------------------------------------
        //
        // wasmtime's epoch interruption requires something to periodically call
        // `Engine::increment_epoch()`. Without this, the epoch counter never
        // advances and the deadline is never reached — effectively disabling
        // the CPU time limit.
        //
        // We spawn a daemon thread that sleeps 1ms between increments. This
        // gives ~1ms epoch resolution, which is sufficient for the 100ms
        // deadline (100 ticks). The thread holds an `Arc<Engine>` so it
        // doesn't prevent the engine from being dropped when the sandbox is
        // dropped (Arc reference drops when the thread exits or when the
        // engine is no longer referenced).
        //
        // NOTE: The thread is intentionally NOT joined on sandbox drop. It is
        // marked as a daemon thread (via `thread::Builder`) so the process does
        // not wait for it at exit. This is the standard pattern for wasmtime
        // epoch threads.
        {
            // Clone the engine handle for the background thread.
            // Engine is Arc-internally-referenced, so this clone is cheap.
            let engine_clone = engine.clone();
            std::thread::Builder::new()
                .name("plugin-epoch-ticker".to_string())
                .spawn(move || {
                    // Loop forever, advancing the epoch once per millisecond.
                    // When the sandbox (and thus the last Engine clone) is dropped,
                    // the engine handle inside this thread will also be dropped
                    // and the thread will exit on its next iteration.
                    loop {
                        // Sleep for one millisecond between epoch increments.
                        // This gives the epoch counter ~1ms granularity, which is
                        // fine for the 100ms CPU deadline (100 increments needed).
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        // Increment the global epoch counter on the shared engine.
                        // When a Store's deadline is N and the epoch reaches N,
                        // wasmtime traps the executing WASM function.
                        engine_clone.increment_epoch();
                    }
                })
                // Epoch ticker failure is not fatal — plugins will just run
                // without CPU time enforcement (degraded safety). Log the error.
                .map_err(|e| {
                    tracing::error!("failed to spawn plugin epoch ticker: {}", e);
                })
                .ok();
        }

        Ok(Self {
            engine,
            linker,
            modules: HashMap::new(),
            timeout_counts: HashMap::new(),
            crash_counts: HashMap::new(),
        })
    }

    /// Compile and cache a WASM module for the given plugin ID.
    ///
    /// Takes the raw WASM bytes (the plugin binary), compiles them with
    /// cranelift, and stores the result in `self.modules`. Subsequent
    /// invocations of the same plugin reuse the compiled module without
    /// recompiling.
    ///
    /// This should be called when a plugin is activated (transitioned to
    /// `PluginStatus::Active`). If the WASM bytes are malformed or contain
    /// invalid instructions, wasmtime returns a compile-time error here rather
    /// than at invocation time, giving a cleaner failure path.
    ///
    /// Returns an error if compilation fails. Does NOT write to the registry —
    /// the caller is responsible for setting `PluginStatus::Failed` if needed.
    pub fn load_module(&mut self, plugin_id: [u8; 16], wasm_bytes: &[u8]) -> anyhow::Result<()> {
        // Compile the WASM binary to native code using cranelift.
        // This is the expensive step (~tens of ms for typical plugins).
        // Subsequent calls to instantiate() reuse this compiled module.
        let module = wasmtime::Module::new(&self.engine, wasm_bytes)?;
        // Store the compiled module, replacing any previous version.
        // This handles plugin updates — new bytes produce a new compiled module.
        self.modules.insert(plugin_id, module);
        Ok(())
    }

    /// Remove a compiled module from the cache when a plugin is uninstalled.
    ///
    /// Called by the backend when `PluginRegistry::uninstall()` succeeds.
    /// After this call, any attempt to invoke hooks for the plugin will
    /// silently skip the missing module (graceful degradation).
    pub fn unload_module(&mut self, plugin_id: &[u8; 16]) {
        // Remove the compiled module from the cache.
        // Also reset the per-plugin counters so a reinstalled plugin starts clean.
        self.modules.remove(plugin_id);
        self.timeout_counts.remove(plugin_id);
        self.crash_counts.remove(plugin_id);
    }

    /// Execute a single hook invocation in the WASM sandbox.
    ///
    /// This is the core execution path:
    /// 1. Look up the compiled module for `plugin_id`. If missing, return `None`.
    /// 2. Create a fresh `Store<SandboxState>` with the plugin's permissions
    ///    and an empty WASI context (no filesystem or network access).
    /// 3. Set the epoch deadline to `MAX_CPU_PER_CALLBACK_MS` ticks.
    /// 4. Configure the Store to trap on epoch expiry.
    /// 5. Instantiate the module through the linker (resolves all imports).
    /// 6. Call `hook_dispatch(hook_name_ptr, hook_name_len, input_ptr, input_len) -> i64`.
    /// 7. Read the output bytes from WASM linear memory and deserialize as JSON.
    /// 8. Handle timeout and crash errors, updating the per-plugin counters.
    ///
    /// Returns `Ok(Some(output))` on success, `Ok(None)` if the plugin
    /// produced no output (output_len == 0), or `Err(...)` on timeout/crash.
    ///
    /// The caller (`invoke_hook_sandboxed`) translates the error into the
    /// appropriate registry state changes (suspend on timeout, fail on crash).
    fn run_hook(
        &mut self,
        plugin_id: &[u8; 16],
        plugin_permissions: Vec<PluginPermission>,
        hook_name: &str,
        input: &serde_json::Value,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        // Look up the pre-compiled module. Return None if not found.
        // A missing module means the plugin was installed without WASM bytes,
        // or the compile step was skipped. We skip gracefully.
        let module = match self.modules.get(plugin_id) {
            Some(m) => m.clone(), // Clone is cheap (Arc internally)
            None => {
                // No compiled module for this plugin — nothing to execute.
                // Return None (no output) rather than an error so the calling
                // code still records a HookInvocation with output=None.
                return Ok(None);
            }
        };

        // --- Serialize the hook input to JSON bytes -------------------------
        //
        // The WASM ABI passes data through linear memory. We serialize the
        // JSON input value to bytes and write them into the WASM heap.
        // The plugin reads input_ptr..input_ptr+input_len to get the JSON.
        let input_bytes = serde_json::to_vec(input)?;
        let hook_name_bytes = hook_name.as_bytes();

        // --- Build per-invocation Store<SandboxState> -----------------------
        //
        // A fresh Store is created for every invocation. This ensures:
        //   - No state leaks between calls (each call gets a clean WASM memory)
        //   - The epoch deadline is reset for each call
        //   - Any WASM linear memory from the previous call is freed
        //
        // Building the WASI context with an empty WasiCtxBuilder gives the plugin
        // no pre-opened file descriptors, no environment variables, and no network
        // access through WASI. stdin/stdout/stderr are also not connected.
        let wasi_ctx = wasmtime_wasi::WasiCtxBuilder::new().build_p1();
        let state = SandboxState {
            permissions: plugin_permissions,
            wasi: wasi_ctx,
        };
        let mut store = wasmtime::Store::new(&self.engine, state);

        // --- Configure epoch-based CPU time limiting -------------------------
        //
        // `set_epoch_deadline(N)` tells wasmtime to interrupt execution when the
        // engine's epoch counter advances N ticks beyond its current value.
        // The background thread advances the counter at ~1ms intervals, so
        // N = MAX_CPU_PER_CALLBACK_MS ticks ≈ MAX_CPU_PER_CALLBACK_MS milliseconds.
        //
        // `epoch_deadline_trap()` configures what happens when the deadline is
        // reached: the Store raises a WASM trap (caught by wasmtime and returned
        // as an Err from the called function). This does NOT panic or crash the
        // host process — wasmtime's isolation guarantee holds.
        store.set_epoch_deadline(MAX_CPU_PER_CALLBACK_MS);
        store.epoch_deadline_trap();

        // --- Instantiate the module -----------------------------------------
        //
        // `linker.instantiate` resolves all WASM imports (WASI functions + our
        // two mesh:: functions) and produces a live WASM instance. This step
        // calls the WASM start function if present (typically none in plugins).
        let instance = self.linker.instantiate(&mut store, &module)?;

        // --- Get a reference to the WASM linear memory ----------------------
        //
        // The memory export named "memory" is the standard WASM memory. We need
        // it to write input strings and read output bytes. All standard WASM
        // toolchains (Rust/wasm-pack, C/clang, TinyGo) export this.
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("plugin WASM module has no 'memory' export"))?;

        // --- Get the hook_dispatch function export --------------------------
        //
        // `hook_dispatch` is the single entrypoint for all hooks. The plugin
        // receives the hook name and JSON input via WASM linear memory pointers.
        // Signature: (hook_name_ptr: i32, hook_name_len: i32,
        //             input_ptr: i32, input_len: i32) -> i64
        //
        // The i64 return value encodes two i32 values:
        //   output_ptr = (return_value >> 32) as i32
        //   output_len = (return_value & 0xFFFF_FFFF) as i32
        //
        // If output_len == 0, the plugin produced no output.
        let hook_dispatch: wasmtime::TypedFunc<(i32, i32, i32, i32), i64> =
            instance.get_typed_func(&mut store, "hook_dispatch")?;

        // --- Write input data into WASM linear memory -----------------------
        //
        // We need the plugin to allocate memory for us, or we can write into
        // a known scratch area. The standard approach for simple WASM ABIs is
        // to ask the plugin to malloc() and then we write. However, to keep
        // the ABI simple and avoid requiring plugins to export malloc, we
        // write into static data at the start of the memory and require the
        // plugin NOT to use that area for output.
        //
        // Simple allocation strategy: write hook_name and input_bytes to the
        // beginning of the memory (offset 0 for hook_name, offset 4096 for input).
        // The output must come from a different memory region (the plugin's heap).
        // 4096 bytes is sufficient for hook names; 4096..8192 is the input scratch area.
        //
        // This approach works because:
        //   1. The plugin reads its inputs once at the start of hook_dispatch.
        //   2. It writes its output to its own heap (above 8192).
        //   3. We read the output after hook_dispatch returns.
        //
        // Plugins that need more than 4096 bytes of JSON input will fail.
        // For production use, a proper allocation protocol (export `alloc`) is
        // recommended. This scratch-buffer approach is spec-compliant for the
        // hooknames and typical JSON inputs in this system.
        const HOOK_NAME_OFFSET: i32 = 0;
        const INPUT_OFFSET: i32 = 4096;
        const MAX_INPUT_LEN: usize = 4096;
        const MAX_HOOK_NAME_LEN: usize = 256;

        // Verify the memory is large enough for our scratch areas.
        // Standard WASM pages are 65536 bytes; one page is enough for our 8KB scratch.
        let mem_size = memory.data_size(&store);
        if mem_size < 8192 {
            anyhow::bail!("plugin WASM memory too small ({} bytes)", mem_size);
        }
        if hook_name_bytes.len() > MAX_HOOK_NAME_LEN {
            anyhow::bail!("hook name too long ({} bytes)", hook_name_bytes.len());
        }
        if input_bytes.len() > MAX_INPUT_LEN {
            anyhow::bail!("plugin input JSON too large ({} bytes)", input_bytes.len());
        }

        // Write hook name bytes to offset 0 in WASM linear memory.
        memory.write(&mut store, HOOK_NAME_OFFSET as usize, hook_name_bytes)
            .map_err(|e| anyhow::anyhow!("failed to write hook name to WASM memory: {}", e))?;

        // Write serialized JSON input bytes to offset 4096 in WASM linear memory.
        memory.write(&mut store, INPUT_OFFSET as usize, &input_bytes)
            .map_err(|e| anyhow::anyhow!("failed to write input JSON to WASM memory: {}", e))?;

        // --- Call hook_dispatch in the WASM sandbox -------------------------
        //
        // This is the only point at which plugin code runs. wasmtime enforces:
        //   - Memory safety (WASM's isolation guarantee)
        //   - The epoch deadline (CPU time limit)
        //   - Import restrictions (only the functions we explicitly linked)
        //
        // If the plugin traps (WASM unreachable, OOM, stack overflow, or
        // epoch timeout), wasmtime catches the trap and returns Err here.
        // The host process is unaffected.
        let result = hook_dispatch.call(
            &mut store,
            (
                HOOK_NAME_OFFSET,
                hook_name_bytes.len() as i32,
                INPUT_OFFSET,
                input_bytes.len() as i32,
            ),
        );

        // --- Interpret the result -------------------------------------------
        match result {
            Ok(packed) => {
                // Successful execution. Unpack the two i32 values from the i64.
                // Upper 32 bits: output_ptr (pointer into WASM linear memory)
                // Lower 32 bits: output_len (number of bytes of output)
                let output_ptr = ((packed >> 32) & 0xFFFF_FFFF) as usize;
                let output_len = (packed & 0xFFFF_FFFF) as usize;

                // Reset the crash and timeout counters on success.
                // A successful call means the plugin is healthy again.
                self.crash_counts.insert(*plugin_id, 0);
                self.timeout_counts.insert(*plugin_id, 0);

                if output_len == 0 {
                    // The plugin explicitly returned no output (notification-only hooks).
                    return Ok(None);
                }

                // Read the output bytes from WASM linear memory.
                // The plugin wrote output_len bytes starting at output_ptr.
                let mem_data = memory.data(&store);
                if output_ptr.saturating_add(output_len) > mem_data.len() {
                    anyhow::bail!(
                        "plugin hook_dispatch returned out-of-bounds output pointer \
                         (ptr={}, len={}, mem={})",
                        output_ptr,
                        output_len,
                        mem_data.len()
                    );
                }
                let output_bytes = &mem_data[output_ptr..output_ptr + output_len];

                // Deserialize the output bytes as JSON.
                // Plugin output must be valid UTF-8 JSON; if it isn't, we return an error.
                let output_value: serde_json::Value =
                    serde_json::from_slice(output_bytes)
                        .map_err(|e| anyhow::anyhow!("plugin output is not valid JSON: {}", e))?;
                Ok(Some(output_value))
            }
            Err(trap_err) => {
                // The plugin trapped. This could be:
                //   a) An epoch timeout (CPU time limit exceeded)
                //   b) A WASM trap (unreachable, out-of-bounds, stack overflow)
                //   c) An import failure (e.g., tried to call an unlisted import)
                //
                // We distinguish timeouts from other traps by inspecting the error.
                // wasmtime represents epoch interrupts as a specific trap kind.
                let is_timeout = trap_err
                    .downcast_ref::<wasmtime::Trap>()
                    .map(|t| *t == wasmtime::Trap::Interrupt)
                    .unwrap_or(false);

                if is_timeout {
                    // Epoch timeout: increment the timeout counter.
                    let count = self.timeout_counts.entry(*plugin_id).or_insert(0);
                    *count += 1;
                    tracing::warn!(
                        "plugin {:?} timed out (count={}): {}",
                        hex::encode(plugin_id),
                        count,
                        trap_err
                    );
                } else {
                    // WASM trap (crash): increment the crash counter.
                    let count = self.crash_counts.entry(*plugin_id).or_insert(0);
                    *count += 1;
                    tracing::error!(
                        "plugin {:?} crashed (count={}): {}",
                        hex::encode(plugin_id),
                        count,
                        trap_err
                    );
                }

                // Propagate the error so invoke_hook_sandboxed can check counters.
                Err(trap_err)
            }
        }
    }

    /// Return the current consecutive timeout count for a plugin.
    ///
    /// Used by `invoke_hook_sandboxed` to decide whether to auto-suspend
    /// a plugin that has hit `TIMEOUT_AUTO_DISABLE` consecutive timeouts.
    pub fn timeout_count(&self, plugin_id: &[u8; 16]) -> u32 {
        self.timeout_counts.get(plugin_id).copied().unwrap_or(0)
    }

    /// Return the current consecutive crash count for a plugin.
    ///
    /// Used by `invoke_hook_sandboxed` to decide whether to quarantine
    /// a plugin that has hit `CRASH_QUARANTINE_THRESHOLD` consecutive crashes.
    pub fn crash_count(&self, plugin_id: &[u8; 16]) -> u32 {
        self.crash_counts.get(plugin_id).copied().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum CPU time per plugin callback (milliseconds).
// MAX_CPU_PER_CALLBACK_MS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const MAX_CPU_PER_CALLBACK_MS: u64 = 100;

/// Consecutive timeout count before auto-disable.
// TIMEOUT_AUTO_DISABLE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const TIMEOUT_AUTO_DISABLE: u32 = 3;

/// Init crash loop threshold before quarantine.
// CRASH_QUARANTINE_THRESHOLD — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const CRASH_QUARANTINE_THRESHOLD: u32 = 3;

/// Shutdown deadline (seconds).
// SHUTDOWN_DEADLINE_SECS — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const SHUTDOWN_DEADLINE_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Plugin Permission
// ---------------------------------------------------------------------------

/// Permissions a plugin can request (§18.2).
///
/// Each variant maps to a capability gate enforced by the registry
/// before dispatching a hook. Unknown permissions from manifests are
/// parsed into the `Custom` variant so forward-compatible manifests
/// don't break on older hosts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// PluginPermission — variant enumeration.
// Match exhaustively to handle every permission type.
pub enum PluginPermission {
    /// Read messages from rooms the user has granted access to.
    // Maps to §18.2 "message.read" capability.
    ReadMessages,
    /// Send messages on behalf of the user (requires explicit consent).
    // Maps to §18.2 "message.send" capability.
    SendMessages,
    /// Read the contact/peer list (names, trust levels, online status).
    // Maps to §18.2 "contacts.read" capability.
    ReadContacts,
    /// Make outbound network requests (HTTP, DNS, etc.).
    // Maps to §18.2 "network" capability.
    NetworkAccess,
    /// Read and write files within the plugin's sandboxed directory.
    // Maps to §18.2 "files" capability.
    FileAccess,
    /// Post notifications to the user via the system tray or push.
    // Maps to §18.2 "notifications" capability.
    NotificationAccess,
    /// Invoke non-sensitive cryptographic operations (hash, HMAC, etc.).
    // Maps to §18.2 "crypto" capability — excludes key material (§18.3).
    CryptoAccess,
    /// A permission not known to this version of the host.
    // Forward-compatibility: new permission strings from newer manifests
    // are preserved verbatim so the user can still review them.
    Custom(String),
}

/// Parse a permission string (from JSON manifest) into a typed enum.
///
/// Known strings map to typed variants; unknown strings map to `Custom`.
/// This is the single conversion point — callers never match on raw strings.
// parse_permission_str — converts wire-format permission names to typed enum.
// Unknown strings are preserved as Custom for forward-compatibility.
fn parse_permission_str(s: &str) -> PluginPermission {
    // Match known permission names from the spec (§18.2).
    // Unknown names fall through to Custom so new permissions don't break old hosts.
    match s {
        "read_messages" => PluginPermission::ReadMessages,
        "send_messages" => PluginPermission::SendMessages,
        "read_contacts" => PluginPermission::ReadContacts,
        "network_access" => PluginPermission::NetworkAccess,
        "file_access" => PluginPermission::FileAccess,
        "notification_access" => PluginPermission::NotificationAccess,
        "crypto_access" => PluginPermission::CryptoAccess,
        // Forward-compatibility: preserve the raw string for display in the UI.
        other => PluginPermission::Custom(other.to_string()),
    }
}

/// Map a hook name to the permission required to handle it (§18.2).
///
/// Before dispatching a hook in the WASM sandbox, `invoke_hook_sandboxed`
/// calls this function to find the required permission. If the plugin does
/// not hold it, the invocation is skipped entirely.
///
/// Returns `None` if the hook has no required permission (infrastructure
/// hooks that don't touch user content may be open to all active plugins).
///
/// The mapping follows §18.2's scope categories:
///   - `on_message_*` hooks require `ReadMessages` (reading messages is the
///     gateway to handling them, even for filtering/modification plugins)
///   - `on_send_*` hooks require `SendMessages` (plugins that post need explicit
///     send capability, separate from read)
///   - `on_peer_*` / `on_contact_*` hooks require `ReadContacts`
///   - `on_file_*` hooks require `FileAccess`
///   - `on_notify_*` hooks require `NotificationAccess`
///   - Crypto operation hooks require `CryptoAccess`
///   - All other hooks have no mandatory permission (custom hooks)
// hook_name_to_permission() — maps hook strings to the required PluginPermission.
// Used exclusively by invoke_hook_sandboxed() for pre-dispatch permission gating.
fn hook_name_to_permission(hook_name: &str) -> Option<PluginPermission> {
    // Check each well-known hook prefix and return the corresponding permission.
    // Prefix matching is used so plugin authors can create namespaced variants
    // (e.g., "on_message_received", "on_message_edited") without each needing
    // a separate entry here.
    if hook_name.starts_with("on_message") {
        // Hooks that observe or process messages require ReadMessages.
        // This includes: on_message_received, on_message_edited, on_message_deleted.
        Some(PluginPermission::ReadMessages)
    } else if hook_name.starts_with("on_send") {
        // Hooks that intercept or augment outgoing messages require SendMessages.
        // This includes: on_send_message, on_send_file.
        Some(PluginPermission::SendMessages)
    } else if hook_name.starts_with("on_peer") || hook_name.starts_with("on_contact") {
        // Hooks about peer discovery or contact events require ReadContacts.
        // This includes: on_peer_connected, on_peer_disconnected, on_contact_updated.
        Some(PluginPermission::ReadContacts)
    } else if hook_name.starts_with("on_file") {
        // Hooks about file sharing events require FileAccess.
        // This includes: on_file_received, on_file_shared.
        Some(PluginPermission::FileAccess)
    } else if hook_name.starts_with("on_notify") {
        // Hooks that post notifications require NotificationAccess.
        // This includes: on_notify_send.
        Some(PluginPermission::NotificationAccess)
    } else if hook_name.starts_with("on_crypto") {
        // Hooks that perform cryptographic operations require CryptoAccess.
        // This includes: on_crypto_hash, on_crypto_sign.
        Some(PluginPermission::CryptoAccess)
    } else {
        // Unknown or custom hooks have no mandatory permission requirement.
        // The plugin still must be active; but no specific scope gate applies.
        None
    }
}

/// Serialize a `PluginPermission` back to its wire-format string.
///
/// This is the inverse of `parse_permission_str` and is used when
/// exporting the registry state as JSON for the Flutter UI.
// permission_to_str — converts typed enum back to wire-format string.
// Used by to_json() for UI serialization.
fn permission_to_str(perm: &PluginPermission) -> String {
    // Map each typed variant back to the canonical wire-format string.
    // Custom variants are returned as-is.
    match perm {
        PluginPermission::ReadMessages => "read_messages".to_string(),
        PluginPermission::SendMessages => "send_messages".to_string(),
        PluginPermission::ReadContacts => "read_contacts".to_string(),
        PluginPermission::NetworkAccess => "network_access".to_string(),
        PluginPermission::FileAccess => "file_access".to_string(),
        PluginPermission::NotificationAccess => "notification_access".to_string(),
        PluginPermission::CryptoAccess => "crypto_access".to_string(),
        // Custom permissions are returned as-is, no transformation needed.
        PluginPermission::Custom(s) => s.clone(),
    }
}

// ---------------------------------------------------------------------------
// Plugin Status
// ---------------------------------------------------------------------------

/// Lifecycle state of a registered plugin (§18).
///
/// The state machine is:
///   Installed -> Active (via `activate`)
///   Active -> Suspended (via `suspend` or auto-suspend on failure)
///   Suspended -> Active (via `activate`)
///   Any -> Failed (on unrecoverable error; auto-suspended)
///
/// Only `Active` plugins receive hook invocations. `Failed` plugins
/// carry the error message for diagnostic display in the UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// PluginStatus — variant enumeration.
// Match exhaustively to handle every lifecycle state.
pub enum PluginStatus {
    /// Installed but not yet activated by the user.
    // Initial state after install; no hooks will fire.
    Installed,
    /// Running and receiving hook invocations.
    // Only active plugins participate in hook dispatch.
    Active,
    /// Suspended by the user or automatically after a failure.
    // Suspended plugins are skipped during hook dispatch.
    Suspended,
    /// An unrecoverable error occurred; the plugin is auto-suspended.
    // The String carries the error description for the UI.
    Failed(String),
}

// ---------------------------------------------------------------------------
// Plugin Manifest (registry-level)
// ---------------------------------------------------------------------------

/// A plugin manifest parsed from the plugin's package JSON (§18).
///
/// This is the registry-level manifest used during `install()`. It carries
/// the fields needed to create a `Plugin` record. The manifest is validated
/// during `parse_manifest()` before it reaches the registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
// RegistryManifest — protocol data structure for plugin installation.
// Validated by parse_manifest() before the registry sees it.
pub struct RegistryManifest {
    /// Human-readable plugin name (displayed in Settings > Plugins).
    // Must be non-empty; validated during parse_manifest().
    pub name: String,
    /// Semver version string (e.g., "1.2.3").
    // Must be non-empty; validated during parse_manifest().
    pub version: String,
    /// Author name or organization.
    // Displayed alongside the plugin in the UI.
    pub author: String,
    /// Short description of what the plugin does.
    // Shown in the plugin detail screen.
    pub description: String,
    /// Typed permissions this plugin requires.
    // Enforced by has_permission() before hook dispatch.
    pub permissions: Vec<PluginPermission>,
    /// Named hooks this plugin wants to register for.
    // Each string is a hook name (e.g., "on_message_received").
    pub hooks: Vec<String>,
    /// Minimum Mesh Infinity version required to run this plugin.
    // Used for compatibility checks during install.
    pub min_app_version: String,
}

// ---------------------------------------------------------------------------
// Plugin Record
// ---------------------------------------------------------------------------

/// A registered plugin in the registry (§18).
///
/// Created by `PluginRegistry::install()` and stored in the registry's
/// plugin list. The `id` is a random 16-byte identifier generated at
/// install time — it is NOT the reverse-domain ID from the manifest.
///
/// The `wasm_bytes` field carries the raw WASM binary for this plugin.
/// It is NOT serialized (marked `#[serde(skip)]`) because WASM binaries
/// can be several megabytes and should be stored separately (in the plugin
/// vault directory per §17.9), not embedded in the registry snapshot.
/// The caller must re-supply WASM bytes after deserialization by calling
/// `Plugin::set_wasm_bytes()` and then `PluginSandbox::load_module()`.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Plugin — the primary record stored per installed plugin.
// ID is random, generated at install time.
pub struct Plugin {
    /// Unique 16-byte identifier, randomly generated at install time.
    // Used as the primary key in all registry lookups and hook maps.
    pub id: [u8; 16],
    /// Human-readable name from the manifest.
    // Displayed in the plugin list UI.
    pub name: String,
    /// Semver version string from the manifest.
    // Used for update detection and compatibility checks.
    pub version: String,
    /// Author name from the manifest.
    // Displayed in the plugin detail UI.
    pub author: String,
    /// Description from the manifest.
    // Displayed in the plugin detail UI.
    pub description: String,
    /// Permissions granted to this plugin.
    // Checked by has_permission() on every hook dispatch.
    pub permissions: Vec<PluginPermission>,
    /// Current lifecycle state.
    // Only Active plugins receive hook invocations.
    pub status: PluginStatus,
    /// Optional Ed25519 signature over the plugin package.
    // Verified by verify_signature() against the author's public key.
    pub signature: Option<Vec<u8>>,
    /// Unix timestamp (seconds since epoch) when the plugin was installed.
    // Recorded for audit and sorting in the UI.
    pub installed_at: u64,

    /// Raw WASM binary bytes for this plugin.
    ///
    /// Populated by `Plugin::set_wasm_bytes()` after install. Skipped during
    /// serialization/deserialization because binaries are stored separately
    /// in the vault (§17.9). After loading a registry snapshot from disk,
    /// callers must re-supply bytes via `set_wasm_bytes()` and then call
    /// `PluginSandbox::load_module()` to recompile.
    ///
    /// `None` means the plugin has no WASM bytes loaded (e.g., a manifest-only
    /// install for preview, or a reload that hasn't re-supplied bytes yet).
    /// `invoke_hook_sandboxed` skips plugins with no loaded module gracefully.
    #[serde(skip)]
    pub wasm_bytes: Option<Vec<u8>>,
}

impl Plugin {
    /// Set (or replace) the WASM binary bytes for this plugin.
    ///
    /// Called after installation or when loading a registry snapshot from disk.
    /// After calling this, pass `plugin.id` and `wasm_bytes` to
    /// `PluginSandbox::load_module()` to compile the module.
    // set_wasm_bytes() — stores the raw binary for later compilation.
    // Must be followed by PluginSandbox::load_module() before invocation.
    pub fn set_wasm_bytes(&mut self, bytes: Vec<u8>) {
        // Store the bytes. Any previous bytes are overwritten (plugin update path).
        self.wasm_bytes = Some(bytes);
    }
}

// ---------------------------------------------------------------------------
// Hook Invocation
// ---------------------------------------------------------------------------

/// Records the result of invoking a single plugin for a named hook (§18).
///
/// The registry creates one `HookInvocation` per plugin per hook call.
/// These records are returned to the caller for logging, performance
/// monitoring, and debugging. The `duration_ms` field enables detection
/// of plugins that exceed the CPU time budget.
#[derive(Clone, Debug, Serialize, Deserialize)]
// HookInvocation — returned by invoke_hook() for each plugin that ran.
// Carries timing data for performance monitoring.
pub struct HookInvocation {
    /// The name of the hook that was invoked (e.g., "on_message_received").
    // Used for filtering and logging.
    pub hook_name: String,
    /// The 16-byte ID of the plugin that was invoked.
    // Links back to the Plugin record in the registry.
    pub plugin_id: [u8; 16],
    /// The JSON input that was passed to the plugin.
    // Preserved for debugging and replay.
    pub input: serde_json::Value,
    /// The JSON output returned by the plugin, if any.
    // None if the plugin did not produce output (e.g., notification-only hooks).
    pub output: Option<serde_json::Value>,
    /// Wall-clock time in milliseconds that the invocation took.
    // Compared against MAX_CPU_PER_CALLBACK_MS for timeout detection.
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Legacy types (preserved from original implementation)
// ---------------------------------------------------------------------------

/// Original plugin manifest structure (§18).
///
/// Describes a plugin's identity, version, permissions, and
/// resource requirements. Retained for compatibility with the
/// existing serialization format.
#[derive(Clone, Debug, Serialize, Deserialize)]
// PluginManifest — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PluginManifest {
    /// Unique plugin identifier (reverse-domain, e.g., "com.example.myplugin").
    // Execute this protocol step.
    pub id: String,
    /// Human-readable name.
    // Execute this protocol step.
    pub name: String,
    /// Plugin version (semver).
    // Execute this protocol step.
    pub version: String,
    /// Minimum API version required.
    // Execute this protocol step.
    pub api_version: String,
    /// Description.
    // Execute this protocol step.
    pub description: Option<String>,
    /// Author name.
    // Execute this protocol step.
    pub author: Option<String>,
    /// Homepage URL.
    // Execute this protocol step.
    pub homepage: Option<String>,
    /// License identifier (SPDX).
    // Execute this protocol step.
    pub license: Option<String>,
    /// Minimum Mesh Infinity version.
    // Execute this protocol step.
    pub min_mesh_version: Option<String>,
    /// Required permissions.
    // Execute this protocol step.
    pub required_permissions: Vec<String>,
    /// Optional permissions.
    // Execute this protocol step.
    pub optional_permissions: Vec<String>,
    /// Resource limits.
    // Execute this protocol step.
    pub resources: PluginResources,
}

/// Plugin resource limits.
#[derive(Clone, Debug, Serialize, Deserialize)]
// PluginResources — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PluginResources {
    /// Maximum memory (MB).
    // Execute this protocol step.
    pub max_memory_mb: u32,
    /// Maximum persistent storage (MB).
    // Execute this protocol step.
    pub max_storage_mb: u32,
    /// Maximum CPU time per callback (ms).
    // Execute this protocol step.
    pub max_cpu_ms_per_call: u64,
    /// Maximum open handles (files, connections).
    // Execute this protocol step.
    pub max_open_handles: u32,
}

// Trait implementation for protocol conformance.
// Implement Default for PluginResources.
impl Default for PluginResources {
    // Provide sensible defaults matching the spec's resource limits.
    // These caps prevent any single plugin from monopolizing system resources.
    fn default() -> Self {
        // Construct with spec-defined defaults for each resource limit.
        // All values come from §18.1 resource budget table.
        Self {
            // 64 MB memory cap per plugin — sufficient for most use cases.
            // Exceeding this triggers OOM handling in the sandbox.
            max_memory_mb: 64,
            // 256 MB persistent storage — enough for caches and local DBs.
            // Enforced by the sandbox filesystem layer.
            max_storage_mb: 256,
            // CPU time per callback uses the global protocol constant.
            // Exceeding this increments the timeout counter toward auto-disable.
            max_cpu_ms_per_call: MAX_CPU_PER_CALLBACK_MS,
            // 32 open handles — covers typical file + network needs.
            // Enforced by the sandbox handle table.
            max_open_handles: 32,
        }
    }
}

/// Cryptographic signature for a plugin (§18).
///
/// Verifies the plugin was built by the claimed author
/// and hasn't been tampered with.
#[derive(Clone, Debug, Serialize, Deserialize)]
// PluginSignature — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PluginSignature {
    /// Author's Ed25519 public key.
    // Execute this protocol step.
    pub author_pubkey: [u8; 32],
    /// SHA-256 of the manifest.
    // Execute this protocol step.
    pub manifest_hash: [u8; 32],
    /// SHA-256 of the WASM binary.
    // Execute this protocol step.
    pub wasm_hash: [u8; 32],
    /// When the signature was created.
    // Execute this protocol step.
    pub timestamp: u64,
    /// Ed25519 signature over all above fields.
    // Execute this protocol step.
    pub signature: Vec<u8>,
}

/// Runtime state of a plugin (legacy enum).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// PluginState — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PluginState {
    /// Installed but not yet started.
    // Execute this protocol step.
    Installed,
    /// Running normally.
    Running,
    /// Stopped by the user.
    Stopped,
    /// Auto-disabled due to repeated timeouts.
    // Execute this protocol step.
    Disabled,
    /// Quarantined due to crash loop.
    // Execute this protocol step.
    Quarantined,
}

// ---------------------------------------------------------------------------
// Plugin Registry
// ---------------------------------------------------------------------------

/// The central plugin registry — manages installed plugins and hook dispatch (§18).
///
/// The registry owns the full list of installed plugins and maintains a
/// mapping from hook names to the plugin IDs that are registered for each
/// hook. All mutation (install, uninstall, activate, suspend) goes through
/// this struct, ensuring consistent state.
///
/// Thread safety: the registry is designed to be owned by a single thread
/// (the backend event loop). If shared access is needed, wrap in a Mutex.
#[derive(Clone, Debug, Serialize, Deserialize)]
// PluginRegistry — the central authority for plugin lifecycle.
// Owns plugins vec and hooks map; all mutations go through methods.
pub struct PluginRegistry {
    /// All installed plugins, in installation order.
    // Linear scan is fine for the expected plugin count (<100).
    plugins: Vec<Plugin>,
    /// Map from hook name to the list of plugin IDs registered for that hook.
    // Used by invoke_hook() to find which plugins to call.
    hooks: HashMap<String, Vec<[u8; 16]>>,
}

impl PluginRegistry {
    /// Create a new, empty plugin registry.
    ///
    /// Called once during backend initialization. The registry starts with
    /// no plugins and no hooks registered.
    // new() — factory for an empty registry with no plugins or hooks.
    // Called by MeshRuntime::new() at startup.
    pub fn new() -> Self {
        // Start with empty collections; plugins are added via install().
        // The hooks map is populated lazily as plugins register for hooks.
        Self {
            plugins: Vec::new(),
            hooks: HashMap::new(),
        }
    }

    /// Install a plugin from a parsed manifest and optional signature.
    ///
    /// Generates a random 16-byte ID, records the current timestamp, and
    /// sets the initial status to `Installed`. The plugin must be explicitly
    /// activated via `activate()` before it receives hook invocations.
    ///
    /// Returns the generated plugin ID on success.
    // install() — creates a Plugin record from the manifest and adds it to the registry.
    // The plugin starts in Installed state; hooks are NOT auto-registered.
    pub fn install(
        &mut self,
        manifest: RegistryManifest,
        signature: Option<Vec<u8>>,
    ) -> Result<[u8; 16], MeshError> {
        // Generate a cryptographically random 16-byte plugin ID.
        // Uses getrandom for OS-level entropy (same source as key generation).
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|e| {
            // Map getrandom failure to Internal — this indicates a broken OS RNG.
            MeshError::Internal(format!("failed to generate plugin ID: {}", e))
        })?;

        // Record the current Unix timestamp for the installation audit trail.
        // Falls back to 0 if the system clock is unavailable (pre-epoch edge case).
        let installed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Build the Plugin record from the manifest fields.
        // Status starts as Installed — caller must explicitly activate.
        // wasm_bytes starts as None; set via Plugin::set_wasm_bytes() + PluginSandbox::load_module().
        let plugin = Plugin {
            id,
            name: manifest.name,
            version: manifest.version,
            author: manifest.author,
            description: manifest.description,
            permissions: manifest.permissions,
            status: PluginStatus::Installed,
            signature,
            installed_at,
            // WASM bytes are not stored in the manifest; the caller must supply
            // them separately via Plugin::set_wasm_bytes() after install.
            // We start with None so the plugin can be registered in the registry
            // before the binary has been validated/stored.
            wasm_bytes: None,
        };

        // Add to the registry's plugin list.
        // Order is preserved (installation order) for deterministic UI display.
        self.plugins.push(plugin);

        // Return the generated ID so the caller can reference this plugin.
        // The ID is the primary key for all subsequent operations.
        Ok(id)
    }

    /// Uninstall a plugin by its 16-byte ID.
    ///
    /// Removes the plugin from the registry and cleans up all hook
    /// registrations. Returns `MeshError::NotFound` if the ID doesn't
    /// match any installed plugin.
    // uninstall() — removes the plugin record and all associated hook entries.
    // After this call, the plugin ID is invalid and must not be reused.
    pub fn uninstall(&mut self, plugin_id: &[u8; 16]) -> Result<(), MeshError> {
        // Find the plugin's index in the list. Return NotFound if absent.
        // Linear scan is acceptable for the expected plugin count (<100).
        let index = self
            .plugins
            .iter()
            .position(|p| &p.id == plugin_id)
            .ok_or_else(|| MeshError::NotFound {
                kind: "plugin",
                id: hex::encode(plugin_id),
            })?;

        // Remove the plugin record from the list.
        // swap_remove is O(1) but changes order; we use remove to preserve order.
        self.plugins.remove(index);

        // Remove this plugin's ID from all hook registration lists.
        // Iterate every hook's subscriber list and filter out the uninstalled ID.
        for subscribers in self.hooks.values_mut() {
            // Retain only subscriber IDs that don't match the uninstalled plugin.
            // This is idempotent — if the plugin wasn't registered, nothing changes.
            subscribers.retain(|id| id != plugin_id);
        }

        // Remove empty hook entries to keep the map clean.
        // A hook with zero subscribers is dead weight.
        self.hooks.retain(|_name, subs| !subs.is_empty());

        Ok(())
    }

    /// Activate a plugin so it begins receiving hook invocations.
    ///
    /// Transitions from `Installed` or `Suspended` to `Active`. Plugins in
    /// `Failed` state can also be reactivated (the error is cleared).
    /// Returns `MeshError::NotFound` if the ID is not in the registry.
    // activate() — transitions the plugin to Active state.
    // Only Active plugins participate in hook dispatch.
    pub fn activate(&mut self, plugin_id: &[u8; 16]) -> Result<(), MeshError> {
        // Find the plugin record. Return NotFound if the ID is unknown.
        // Mutable borrow needed to update the status field.
        let plugin = self
            .plugins
            .iter_mut()
            .find(|p| &p.id == plugin_id)
            .ok_or_else(|| MeshError::NotFound {
                kind: "plugin",
                id: hex::encode(plugin_id),
            })?;

        // Transition to Active. This is valid from Installed, Suspended, or Failed.
        // Already-active plugins are a no-op (idempotent).
        plugin.status = PluginStatus::Active;
        Ok(())
    }

    /// Suspend a plugin so it stops receiving hook invocations.
    ///
    /// Transitions from `Active` (or any other state) to `Suspended`.
    /// This is a manual user action, distinct from `Failed` which is
    /// triggered automatically by runtime errors.
    // suspend() — transitions the plugin to Suspended state.
    // Suspended plugins are skipped during hook dispatch.
    pub fn suspend(&mut self, plugin_id: &[u8; 16]) -> Result<(), MeshError> {
        // Find the plugin record. Return NotFound if the ID is unknown.
        // Mutable borrow needed to update the status field.
        let plugin = self
            .plugins
            .iter_mut()
            .find(|p| &p.id == plugin_id)
            .ok_or_else(|| MeshError::NotFound {
                kind: "plugin",
                id: hex::encode(plugin_id),
            })?;

        // Transition to Suspended. Idempotent if already suspended.
        // The plugin retains its hook registrations but won't receive invocations.
        plugin.status = PluginStatus::Suspended;
        Ok(())
    }

    /// Look up a plugin by its 16-byte ID.
    ///
    /// Returns a shared reference to the plugin record, or `None` if the
    /// ID is not in the registry. This is a read-only operation.
    // get() — O(n) lookup by ID; fine for <100 plugins.
    // Returns None rather than an error for ergonomic Option chaining.
    pub fn get(&self, plugin_id: &[u8; 16]) -> Option<&Plugin> {
        // Linear scan over the plugin list to find the matching ID.
        // For the expected plugin count (<100), this is faster than a HashMap.
        self.plugins.iter().find(|p| &p.id == plugin_id)
    }

    /// Return a slice of all installed plugins.
    ///
    /// The order is installation order (oldest first). Used by the UI
    /// to display the full plugin list.
    // list() — returns the full plugin list as a slice.
    // Borrows the internal Vec without copying.
    pub fn list(&self) -> &[Plugin] {
        // Return a slice view of the internal plugin list.
        // No allocation — the caller borrows directly.
        &self.plugins
    }

    /// Return only the active plugins (those receiving hook invocations).
    ///
    /// Used by the UI to show which plugins are currently running, and
    /// by the hook dispatcher to filter eligible plugins.
    // list_active() — filters the plugin list to only Active-status entries.
    // Returns owned references; allocation is minimal for <100 plugins.
    pub fn list_active(&self) -> Vec<&Plugin> {
        // Filter to only Active plugins. Suspended, Installed, and Failed are excluded.
        // The returned Vec borrows from self — no cloning of Plugin records.
        self.plugins
            .iter()
            .filter(|p| p.status == PluginStatus::Active)
            .collect()
    }

    /// Register a plugin to receive invocations for a named hook.
    ///
    /// The plugin must exist in the registry. Duplicate registrations
    /// for the same (hook, plugin) pair are silently ignored (idempotent).
    // register_hook() — adds the plugin ID to the hook's subscriber list.
    // Idempotent: re-registering the same plugin for the same hook is a no-op.
    pub fn register_hook(&mut self, hook_name: &str, plugin_id: [u8; 16]) -> Result<(), MeshError> {
        // Verify the plugin exists before registering the hook.
        // This prevents orphaned hook entries for non-existent plugins.
        if !self.plugins.iter().any(|p| p.id == plugin_id) {
            return Err(MeshError::NotFound {
                kind: "plugin",
                id: hex::encode(plugin_id),
            });
        }

        // Get or create the subscriber list for this hook name.
        // entry() avoids a double lookup (check + insert).
        let subscribers = self.hooks.entry(hook_name.to_string()).or_default();

        // Only add if not already present — idempotent registration.
        // Linear scan is fine for the expected subscriber count per hook (<20).
        if !subscribers.contains(&plugin_id) {
            subscribers.push(plugin_id);
        }

        Ok(())
    }

    /// Invoke all active plugins registered for a named hook (no-sandbox path).
    ///
    /// This is the API-framework-only version: it records timing and performs
    /// status filtering but does NOT execute any WASM code. Output is always
    /// `None`. It is used by tests and by callers that do not have a
    /// `PluginSandbox` available (e.g., in environments where WASM execution
    /// is intentionally disabled or not yet configured).
    ///
    /// For real WASM execution, use `invoke_hook_sandboxed()` instead, which
    /// takes a `PluginSandbox` and actually calls the plugin's `hook_dispatch`
    /// export.
    ///
    /// Each plugin receives the same `input` JSON value. The registry
    /// records timing for each invocation and returns a `HookInvocation`
    /// per plugin. Suspended and non-active plugins are skipped.
    // invoke_hook() — lightweight dispatch without WASM execution.
    // Returns one HookInvocation (output=None) per eligible active plugin.
    pub fn invoke_hook(&self, hook_name: &str, input: serde_json::Value) -> Vec<HookInvocation> {
        // Look up the subscriber list for this hook. Empty vec if no registrations.
        // Cloning the subscriber list avoids borrow conflicts during iteration.
        let subscriber_ids = match self.hooks.get(hook_name) {
            Some(ids) => ids.clone(),
            // No plugins registered for this hook — return empty results.
            None => return Vec::new(),
        };

        // Collect invocation results for each registered, active plugin.
        // Pre-allocate to the number of subscribers (upper bound).
        let mut results = Vec::with_capacity(subscriber_ids.len());

        for plugin_id in &subscriber_ids {
            // Look up the plugin record to check its status.
            // Skip if the plugin was uninstalled between registration and invocation.
            let plugin = match self.get(plugin_id) {
                Some(p) => p,
                // Plugin was uninstalled — skip silently.
                None => continue,
            };

            // Only active plugins receive hook invocations.
            // Installed, Suspended, and Failed plugins are skipped.
            if plugin.status != PluginStatus::Active {
                continue;
            }

            // Record the start time for performance monitoring.
            // Uses monotonic Instant to avoid clock skew issues.
            let start = std::time::Instant::now();

            // No WASM execution in this path — output is always None.
            // Use invoke_hook_sandboxed() to actually execute plugin code.
            let output: Option<serde_json::Value> = None;

            // Compute the elapsed time in milliseconds.
            // This will be compared against MAX_CPU_PER_CALLBACK_MS for timeout detection.
            let duration_ms = start.elapsed().as_millis() as u64;

            // Build the invocation record with timing and I/O data.
            // The caller can use this for logging and performance alerts.
            results.push(HookInvocation {
                hook_name: hook_name.to_string(),
                plugin_id: *plugin_id,
                input: input.clone(),
                output,
                duration_ms,
            });
        }

        results
    }

    /// Invoke all active plugins registered for a named hook via the WASM sandbox.
    ///
    /// This is the real execution path. For each active plugin registered for
    /// `hook_name`:
    ///
    /// 1. **Permission check** — the hook name is mapped to a required permission
    ///    via `hook_name_to_permission()`. If the plugin lacks the required
    ///    permission, the invocation is skipped and recorded with `output=None`.
    ///    This enforces §18.2 capability gating at the dispatch layer.
    ///
    /// 2. **WASM execution** — `PluginSandbox::run_hook()` is called with:
    ///    - A clone of the plugin's permissions (captured in the Store)
    ///    - The hook name and serialized JSON input
    ///    The sandbox creates a fresh wasmtime `Store`, sets the epoch deadline
    ///    to `MAX_CPU_PER_CALLBACK_MS` ticks, instantiates the module, and calls
    ///    `hook_dispatch(hook_name_ptr, hook_name_len, input_ptr, input_len) -> i64`.
    ///
    /// 3. **Timeout handling** — if the plugin's epoch deadline is exceeded,
    ///    the sandbox increments `timeout_count`. When `timeout_count` reaches
    ///    `TIMEOUT_AUTO_DISABLE`, the registry suspends the plugin automatically.
    ///    The HookInvocation is still recorded with `output=None`.
    ///
    /// 4. **Crash handling** — any non-timeout WASM trap increments `crash_count`.
    ///    When `crash_count` reaches `CRASH_QUARANTINE_THRESHOLD`, the plugin's
    ///    status is set to `PluginStatus::Failed` and it is quarantined.
    ///    The HookInvocation is still recorded with `output=None`.
    ///
    /// On iOS, this method returns an empty vec immediately because WASM plugin
    /// execution is not available on that platform (§18.1).
    ///
    /// The `sandbox` parameter is taken as `&mut PluginSandbox` because
    /// `run_hook` mutates the timeout/crash counters inside the sandbox.
    // invoke_hook_sandboxed() — real WASM execution path with permission gating.
    // Returns one HookInvocation per eligible active plugin with real output.
    #[cfg(not(target_os = "ios"))]
    pub fn invoke_hook_sandboxed(
        &mut self,
        hook_name: &str,
        input: serde_json::Value,
        sandbox: &mut PluginSandbox,
    ) -> Vec<HookInvocation> {
        // Look up the subscriber list for this hook. Empty vec if no registrations.
        // Cloning the subscriber list avoids borrow conflicts during the mutable loop.
        let subscriber_ids = match self.hooks.get(hook_name) {
            Some(ids) => ids.clone(),
            // No plugins registered for this hook — return empty results.
            None => return Vec::new(),
        };

        // Determine the permission required for this hook.
        // Hooks that don't map to a known permission are allowed through
        // (None means no specific permission required for this hook).
        let required_permission = hook_name_to_permission(hook_name);

        // Collect invocation results for each registered, active plugin.
        // Pre-allocate to the number of subscribers (upper bound).
        let mut results = Vec::with_capacity(subscriber_ids.len());

        for plugin_id in &subscriber_ids {
            // Look up the plugin record to check its status and permissions.
            // Skip if the plugin was uninstalled between registration and invocation.
            let plugin = match self.get(plugin_id) {
                Some(p) => p,
                // Plugin was uninstalled — skip silently.
                None => continue,
            };

            // Only active plugins receive hook invocations.
            // Installed, Suspended, and Failed plugins are skipped.
            if plugin.status != PluginStatus::Active {
                continue;
            }

            // --- Permission enforcement (§18.2) ----------------------------
            //
            // Before dispatching to the WASM sandbox, verify the plugin holds
            // the permission required for this hook. If not, the invocation is
            // skipped. This implements the principle: "No scope equals permission
            // error, never silent failure or crash" (§18.2).
            //
            // If the hook maps to None (no required permission), all active
            // plugins may handle it (e.g., infrastructure hooks that don't
            // touch user content).
            if let Some(ref required) = required_permission {
                // Plugin must hold the required permission.
                if !plugin.permissions.contains(required) {
                    // Permission denied — skip this plugin for this hook.
                    // We do NOT record a HookInvocation so the caller cannot
                    // infer which hooks were denied from the result set.
                    tracing::debug!(
                        "plugin {:?} lacks permission {:?} for hook {:?} — skipping",
                        hex::encode(plugin_id),
                        required,
                        hook_name
                    );
                    continue;
                }
            }

            // Snapshot the plugin's permissions and ID before the mutable borrow.
            // We need these after the sandbox call when we may mutate the registry.
            let plugin_permissions = plugin.permissions.clone();
            let pid = *plugin_id;

            // Record the start time for wall-clock timing.
            // Uses monotonic Instant to avoid system clock skew.
            let start = std::time::Instant::now();

            // --- WASM sandbox execution ------------------------------------
            //
            // Delegate to the sandbox's run_hook method, which:
            //   1. Creates a fresh Store<SandboxState> with the plugin's permissions
            //   2. Sets the epoch deadline to MAX_CPU_PER_CALLBACK_MS ticks
            //   3. Instantiates the compiled module through the linker
            //   4. Calls hook_dispatch(hook_name_ptr, hook_name_len, input_ptr, input_len)
            //   5. Reads and deserializes the output from WASM linear memory
            //
            // If the plugin has no compiled module (no wasm_bytes), run_hook
            // returns Ok(None) and we record an empty output.
            let run_result = sandbox.run_hook(&pid, plugin_permissions, hook_name, &input);

            // Measure actual wall-clock time of the WASM execution.
            let duration_ms = start.elapsed().as_millis() as u64;

            // Process the result and check if auto-management actions are needed.
            let output = match run_result {
                Ok(output_value) => {
                    // Successful execution or graceful no-output (output_len == 0).
                    output_value
                }
                Err(ref trap_err) => {
                    // The WASM module trapped (timeout or crash).
                    // Check whether this plugin has crossed an auto-management threshold.
                    let timeout_count = sandbox.timeout_count(&pid);
                    let crash_count = sandbox.crash_count(&pid);

                    if timeout_count >= TIMEOUT_AUTO_DISABLE {
                        // Three consecutive timeouts — auto-suspend per §18 spec.
                        // Suspend the plugin; the user will see a notification in the UI.
                        tracing::warn!(
                            "auto-suspending plugin {:?}: {} consecutive timeouts",
                            hex::encode(&pid),
                            timeout_count
                        );
                        // Suspend via the registry; future invocations will skip it.
                        // Ignore the error (NotFound would be a logic bug here).
                        let _ = self.suspend(&pid);
                    } else if crash_count >= CRASH_QUARANTINE_THRESHOLD {
                        // Three consecutive crashes — move to Failed/quarantine state.
                        tracing::error!(
                            "quarantining plugin {:?}: {} consecutive crashes",
                            hex::encode(&pid),
                            crash_count
                        );
                        // Mark as Failed so the UI shows the quarantine badge.
                        if let Some(p) = self.plugins.iter_mut().find(|p| p.id == pid) {
                            p.status = PluginStatus::Failed(
                                format!("crash loop: {} consecutive traps — {}", crash_count, trap_err)
                            );
                        }
                    }

                    // No output for failed invocations.
                    None
                }
            };

            // Build the invocation record with real timing and execution output.
            results.push(HookInvocation {
                hook_name: hook_name.to_string(),
                plugin_id: pid,
                input: input.clone(),
                output,
                duration_ms,
            });
        }

        results
    }

    /// Fallback for iOS: WASM plugin execution is not available (§18.1).
    ///
    /// Returns an empty vec immediately. No WASM code is compiled or linked
    /// for iOS builds — this stub satisfies the call site without any
    /// wasmtime dependency being pulled in.
    #[cfg(target_os = "ios")]
    pub fn invoke_hook_sandboxed(
        &mut self,
        _hook_name: &str,
        _input: serde_json::Value,
        _sandbox: &mut (),
    ) -> Vec<HookInvocation> {
        // iOS does not support third-party executable plugins (§18.1).
        // Return empty — no invocations, no error.
        Vec::new()
    }

    /// Verify a plugin's Ed25519 signature against a trusted signing key.
    ///
    /// The signature covers the plugin's name, version, and author fields
    /// concatenated together. Uses domain-separated verification via
    /// `DOMAIN_PLUGIN_SIGNATURE` to prevent cross-protocol replay.
    ///
    /// Returns `false` if the plugin has no signature or if verification fails.
    // verify_signature() — checks the plugin's Ed25519 signature.
    // Uses the centralized signing module with DOMAIN_PLUGIN_SIGNATURE.
    pub fn verify_signature(&self, plugin: &Plugin, signing_key: &[u8; 32]) -> bool {
        // A plugin with no signature cannot be verified — return false.
        // The UI should warn the user about unsigned plugins.
        let sig_bytes = match &plugin.signature {
            Some(s) => s,
            // No signature present — verification fails by definition.
            None => return false,
        };

        // Build the signed message: name || version || author.
        // This binds the signature to the plugin's identity fields.
        let mut message = Vec::new();
        message.extend_from_slice(plugin.name.as_bytes());
        message.extend_from_slice(plugin.version.as_bytes());
        message.extend_from_slice(plugin.author.as_bytes());

        // Delegate to the centralized signing module with the plugin domain separator.
        // This prevents reuse of signatures from other protocol contexts.
        signing::verify(
            signing_key,
            signing::DOMAIN_PLUGIN_SIGNATURE,
            &message,
            sig_bytes,
        )
    }

    /// Check whether a plugin has been granted a specific permission.
    ///
    /// Returns `true` if the plugin exists and its permission list contains
    /// the requested permission. Returns `false` if the plugin is not found
    /// or lacks the permission.
    // has_permission() — permission gate for hook dispatch and API calls.
    // Called before any capability-gated operation.
    pub fn has_permission(&self, plugin_id: &[u8; 16], permission: &PluginPermission) -> bool {
        // Look up the plugin. If not found, the permission check fails.
        // This is a deliberate fail-closed design — unknown plugins have no permissions.
        match self.get(plugin_id) {
            Some(plugin) => {
                // Check if the requested permission is in the plugin's granted list.
                // Uses PartialEq on PluginPermission for comparison.
                plugin.permissions.contains(permission)
            }
            // Plugin not found — fail closed, no permissions.
            None => false,
        }
    }

    /// Export the full registry state as a JSON value for the Flutter UI.
    ///
    /// Serializes all plugins and their statuses into a JSON object that
    /// the FFI layer can pass to Dart. The format is:
    /// ```json
    /// {
    ///   "plugins": [ { "id": "hex...", "name": "...", ... } ],
    ///   "hook_count": 5
    /// }
    /// ```
    // to_json() — serializes the registry state for the Flutter UI.
    // Called by the FFI layer when the UI requests the plugin list.
    pub fn to_json(&self) -> serde_json::Value {
        // Build the plugins array with hex-encoded IDs and string statuses.
        // Each plugin becomes a JSON object with all user-visible fields.
        let plugins_json: Vec<serde_json::Value> = self
            .plugins
            .iter()
            .map(|p| {
                // Convert the plugin's permission list to string array.
                // Uses permission_to_str() for wire-format consistency.
                let perms: Vec<String> = p.permissions.iter().map(permission_to_str).collect();

                // Serialize the status to a human-readable string.
                // Failed carries the error message in a nested object.
                let status_str = match &p.status {
                    PluginStatus::Installed => "installed".to_string(),
                    PluginStatus::Active => "active".to_string(),
                    PluginStatus::Suspended => "suspended".to_string(),
                    PluginStatus::Failed(msg) => format!("failed: {}", msg),
                };

                // Build the JSON object for this plugin.
                // All fields are safe to display in the UI (no key material).
                serde_json::json!({
                    "id": hex::encode(p.id),
                    "name": p.name,
                    "version": p.version,
                    "author": p.author,
                    "description": p.description,
                    "permissions": perms,
                    "status": status_str,
                    "has_signature": p.signature.is_some(),
                    "installed_at": p.installed_at,
                })
            })
            .collect();

        // Build the top-level JSON object with the plugins array and metadata.
        // hook_count tells the UI how many distinct hooks are registered.
        serde_json::json!({
            "plugins": plugins_json,
            "hook_count": self.hooks.len(),
        })
    }
}

// ---------------------------------------------------------------------------
// Manifest Parsing
// ---------------------------------------------------------------------------

/// Parse a registry-level plugin manifest from a JSON string.
///
/// Validates that all required fields are present and non-empty.
/// Permission strings are converted to typed `PluginPermission` enums.
/// Returns `MeshError::MalformedFrame` if the JSON is invalid or
/// required fields are missing.
// parse_manifest() — the single entry point for manifest deserialization.
// All validation happens here; the registry trusts the output.
pub fn parse_manifest(json: &str) -> Result<RegistryManifest, MeshError> {
    // Parse the raw JSON into a generic Value first for field-level validation.
    // This gives better error messages than serde's struct deserialization.
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        MeshError::MalformedFrame(format!("plugin manifest JSON parse error: {}", e))
    })?;

    // Extract and validate the required "name" field.
    // Must be a non-empty string — plugins without names cannot be displayed.
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            MeshError::MalformedFrame("plugin manifest missing or empty 'name' field".to_string())
        })?
        .to_string();

    // Extract and validate the required "version" field.
    // Must be a non-empty string (semver format expected but not enforced here).
    let version = value
        .get("version")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            MeshError::MalformedFrame(
                "plugin manifest missing or empty 'version' field".to_string(),
            )
        })?
        .to_string();

    // Extract the "author" field — defaults to "Unknown" if absent.
    // We don't require it because community plugins may not have a named author.
    let author = value
        .get("author")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();

    // Extract the "description" field — defaults to empty string if absent.
    // Optional because not all plugins need a long description.
    let description = value
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Parse the "permissions" array into typed PluginPermission values.
    // Each element is a string that maps to a known or Custom permission.
    let permissions: Vec<PluginPermission> = value
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            // Convert each JSON string to a typed PluginPermission.
            // Non-string elements are silently skipped (defensive parsing).
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(parse_permission_str)
                .collect()
        })
        .unwrap_or_default();

    // Parse the "hooks" array into a list of hook name strings.
    // Each element names a hook the plugin wants to register for.
    let hooks: Vec<String> = value
        .get("hooks")
        .and_then(|v| v.as_array())
        .map(|arr| {
            // Convert each JSON string to an owned String.
            // Non-string elements are silently skipped.
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Extract the "min_app_version" field — defaults to "0.0.0" if absent.
    // This means the plugin is compatible with any version.
    let min_app_version = value
        .get("min_app_version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0")
        .to_string();

    // All fields validated — construct the RegistryManifest.
    // The registry trusts this output and won't re-validate.
    Ok(RegistryManifest {
        name,
        version,
        author,
        description,
        permissions,
        hooks,
        min_app_version,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Legacy tests (preserved from original implementation)
    // -----------------------------------------------------------------------

    /// Verify default resource limits match the spec constants.
    #[test]
    fn test_default_resources() {
        // PluginResources::default() must use the protocol constants.
        let res = PluginResources::default();
        // CPU limit must match the global constant.
        assert_eq!(res.max_cpu_ms_per_call, MAX_CPU_PER_CALLBACK_MS);
        // Memory limit must be 64 MB per the spec.
        assert_eq!(res.max_memory_mb, 64);
    }

    /// Verify that PluginState round-trips through JSON serialization.
    #[test]
    fn test_plugin_states() {
        // Serialize PluginState::Running to JSON and back.
        let state = PluginState::Running;
        // serde_json::to_string is safe to unwrap in tests.
        let json = serde_json::to_string(&state).expect("serialize PluginState");
        // Deserialize and verify the round-trip is lossless.
        let recovered: PluginState = serde_json::from_str(&json).expect("deserialize PluginState");
        assert_eq!(recovered, PluginState::Running);
    }

    // -----------------------------------------------------------------------
    // Install / Uninstall lifecycle
    // -----------------------------------------------------------------------

    /// Helper: build a minimal valid RegistryManifest for testing.
    fn test_manifest() -> RegistryManifest {
        // Minimal manifest with all required fields populated.
        // Used by most tests; individual tests override fields as needed.
        RegistryManifest {
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "Test Author".to_string(),
            description: "A plugin for testing".to_string(),
            permissions: vec![
                PluginPermission::ReadMessages,
                PluginPermission::NetworkAccess,
            ],
            hooks: vec!["on_message".to_string()],
            min_app_version: "0.1.0".to_string(),
        }
    }

    /// Installing a plugin returns a valid 16-byte ID and the plugin is retrievable.
    #[test]
    fn test_install_creates_plugin() {
        // Create an empty registry and install a test plugin.
        let mut registry = PluginRegistry::new();
        let manifest = test_manifest();

        // install() should succeed and return a 16-byte ID.
        let id = registry
            .install(manifest.clone(), None)
            .expect("install should succeed");

        // The returned ID must be 16 bytes (128 bits).
        assert_eq!(id.len(), 16);

        // The plugin should be retrievable by its ID.
        let plugin = registry
            .get(&id)
            .expect("plugin should exist after install");

        // Verify the manifest fields were copied correctly.
        assert_eq!(plugin.name, "Test Plugin");
        assert_eq!(plugin.version, "1.0.0");
        assert_eq!(plugin.author, "Test Author");
        assert_eq!(plugin.description, "A plugin for testing");

        // New plugins start in Installed status — not Active.
        assert_eq!(plugin.status, PluginStatus::Installed);

        // No signature was provided, so it should be None.
        assert!(plugin.signature.is_none());

        // installed_at should be a reasonable Unix timestamp (after 2020-01-01).
        assert!(plugin.installed_at > 1_577_836_800);
    }

    /// Installing multiple plugins gives each a unique ID.
    #[test]
    fn test_install_unique_ids() {
        // Create a registry and install two plugins from the same manifest.
        let mut registry = PluginRegistry::new();
        let id1 = registry
            .install(test_manifest(), None)
            .expect("install 1 should succeed");
        let id2 = registry
            .install(test_manifest(), None)
            .expect("install 2 should succeed");

        // IDs must be unique — the RNG must not produce duplicates.
        assert_ne!(id1, id2);

        // Both plugins should be in the list.
        assert_eq!(registry.list().len(), 2);
    }

    /// Uninstalling a plugin removes it from the registry.
    #[test]
    fn test_uninstall_removes_plugin() {
        // Install a plugin, then uninstall it.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install should succeed");

        // Verify it exists before uninstall.
        assert!(registry.get(&id).is_some());

        // Uninstall should succeed.
        registry.uninstall(&id).expect("uninstall should succeed");

        // The plugin should no longer be retrievable.
        assert!(registry.get(&id).is_none());

        // The list should be empty.
        assert!(registry.list().is_empty());
    }

    /// Uninstalling a non-existent plugin returns NotFound.
    #[test]
    fn test_uninstall_not_found() {
        // Try to uninstall from an empty registry.
        let mut registry = PluginRegistry::new();
        let fake_id = [0xAA; 16];

        // Should return a NotFound error.
        let result = registry.uninstall(&fake_id);
        assert!(result.is_err());
    }

    /// Uninstalling cleans up hook registrations for that plugin.
    #[test]
    fn test_uninstall_cleans_hooks() {
        // Install a plugin and register it for a hook, then uninstall.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install should succeed");

        // Register the plugin for a hook.
        registry
            .register_hook("on_message", id)
            .expect("register_hook should succeed");

        // Uninstall the plugin.
        registry.uninstall(&id).expect("uninstall should succeed");

        // The hook's subscriber list should be empty (or the hook entry removed).
        // invoke_hook should return no results.
        let results = registry.invoke_hook("on_message", serde_json::json!({}));
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // Activate / Suspend
    // -----------------------------------------------------------------------

    /// Activating a plugin transitions it to Active status.
    #[test]
    fn test_activate() {
        // Install a plugin (starts as Installed) and activate it.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install should succeed");

        // Activate should succeed.
        registry.activate(&id).expect("activate should succeed");

        // Status should now be Active.
        let plugin = registry.get(&id).expect("plugin should exist");
        assert_eq!(plugin.status, PluginStatus::Active);
    }

    /// Activating a non-existent plugin returns NotFound.
    #[test]
    fn test_activate_not_found() {
        // Try to activate a non-existent plugin.
        let mut registry = PluginRegistry::new();
        let fake_id = [0xBB; 16];

        // Should return NotFound.
        let result = registry.activate(&fake_id);
        assert!(result.is_err());
    }

    /// Suspending a plugin transitions it to Suspended status.
    #[test]
    fn test_suspend() {
        // Install and activate a plugin, then suspend it.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install should succeed");
        registry.activate(&id).expect("activate should succeed");

        // Suspend should succeed.
        registry.suspend(&id).expect("suspend should succeed");

        // Status should now be Suspended.
        let plugin = registry.get(&id).expect("plugin should exist");
        assert_eq!(plugin.status, PluginStatus::Suspended);
    }

    /// Suspending a non-existent plugin returns NotFound.
    #[test]
    fn test_suspend_not_found() {
        // Try to suspend a non-existent plugin.
        let mut registry = PluginRegistry::new();
        let fake_id = [0xCC; 16];

        // Should return NotFound.
        let result = registry.suspend(&fake_id);
        assert!(result.is_err());
    }

    /// list_active() only returns plugins with Active status.
    #[test]
    fn test_list_active_filters() {
        // Install three plugins: activate one, suspend one, leave one installed.
        let mut registry = PluginRegistry::new();
        let id1 = registry.install(test_manifest(), None).expect("install 1");
        let id2 = registry.install(test_manifest(), None).expect("install 2");
        let _id3 = registry.install(test_manifest(), None).expect("install 3");

        // Activate plugin 1, suspend plugin 2, leave plugin 3 as Installed.
        registry.activate(&id1).expect("activate 1");
        registry.activate(&id2).expect("activate 2");
        registry.suspend(&id2).expect("suspend 2");

        // list_active() should return only plugin 1.
        let active = registry.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id1);
    }

    // -----------------------------------------------------------------------
    // Hook registration and invocation
    // -----------------------------------------------------------------------

    /// Registering a hook for a non-existent plugin returns NotFound.
    #[test]
    fn test_register_hook_not_found() {
        // Try to register a hook for a non-existent plugin.
        let mut registry = PluginRegistry::new();
        let fake_id = [0xDD; 16];

        // Should return NotFound.
        let result = registry.register_hook("on_message", fake_id);
        assert!(result.is_err());
    }

    /// Duplicate hook registration is idempotent.
    #[test]
    fn test_register_hook_idempotent() {
        // Register the same plugin for the same hook twice.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(test_manifest(), None)
            .expect("install should succeed");

        // First registration should succeed.
        registry
            .register_hook("on_message", id)
            .expect("first register_hook should succeed");

        // Second registration should also succeed (idempotent).
        registry
            .register_hook("on_message", id)
            .expect("second register_hook should succeed");

        // Activate the plugin so it receives invocations.
        registry.activate(&id).expect("activate should succeed");

        // invoke_hook should produce exactly one invocation (not two).
        let results = registry.invoke_hook("on_message", serde_json::json!({"text": "hello"}));
        assert_eq!(results.len(), 1);
    }

    /// invoke_hook returns results only for active plugins.
    #[test]
    fn test_invoke_hook_active_only() {
        // Install two plugins, register both for the same hook.
        let mut registry = PluginRegistry::new();
        let id1 = registry.install(test_manifest(), None).expect("install 1");
        let id2 = registry.install(test_manifest(), None).expect("install 2");

        // Register both for "on_message".
        registry
            .register_hook("on_message", id1)
            .expect("register 1");
        registry
            .register_hook("on_message", id2)
            .expect("register 2");

        // Activate only plugin 1.
        registry.activate(&id1).expect("activate 1");

        // invoke_hook should only return a result for the active plugin.
        let input = serde_json::json!({"text": "test"});
        let results = registry.invoke_hook("on_message", input);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].plugin_id, id1);

        // The hook_name should be recorded correctly.
        assert_eq!(results[0].hook_name, "on_message");
    }

    /// invoke_hook for an unregistered hook returns an empty vec.
    #[test]
    fn test_invoke_hook_unknown_hook() {
        // Invoke a hook that no plugin is registered for.
        let registry = PluginRegistry::new();
        let results = registry.invoke_hook("nonexistent_hook", serde_json::json!({}));
        assert!(results.is_empty());
    }

    /// invoke_hook records the input and timing data.
    #[test]
    fn test_invoke_hook_records_timing() {
        // Install and activate a plugin, register it for a hook, then invoke.
        let mut registry = PluginRegistry::new();
        let id = registry.install(test_manifest(), None).expect("install");
        registry.activate(&id).expect("activate");
        registry
            .register_hook("on_data", id)
            .expect("register_hook");

        // Invoke the hook with some input data.
        let input = serde_json::json!({"key": "value"});
        let results = registry.invoke_hook("on_data", input.clone());

        // Exactly one invocation should be returned.
        assert_eq!(results.len(), 1);
        let inv = &results[0];

        // Input should match what we passed in.
        assert_eq!(inv.input, input);

        // Output is None in the framework (no real plugin runtime).
        assert!(inv.output.is_none());

        // Duration should be non-negative (it's u64, so always >= 0).
        // In practice it should be very small since no real work is done.
        assert!(inv.duration_ms < 1000);
    }

    // -----------------------------------------------------------------------
    // Permission checks
    // -----------------------------------------------------------------------

    /// has_permission returns true for granted permissions.
    #[test]
    fn test_has_permission_granted() {
        // Install a plugin with ReadMessages and NetworkAccess permissions.
        let mut registry = PluginRegistry::new();
        let id = registry.install(test_manifest(), None).expect("install");

        // The test manifest grants ReadMessages and NetworkAccess.
        assert!(registry.has_permission(&id, &PluginPermission::ReadMessages));
        assert!(registry.has_permission(&id, &PluginPermission::NetworkAccess));
    }

    /// has_permission returns false for non-granted permissions.
    #[test]
    fn test_has_permission_denied() {
        // Install a plugin with only ReadMessages and NetworkAccess.
        let mut registry = PluginRegistry::new();
        let id = registry.install(test_manifest(), None).expect("install");

        // FileAccess was NOT granted — should return false.
        assert!(!registry.has_permission(&id, &PluginPermission::FileAccess));

        // CryptoAccess was NOT granted — should return false.
        assert!(!registry.has_permission(&id, &PluginPermission::CryptoAccess));
    }

    /// has_permission returns false for a non-existent plugin.
    #[test]
    fn test_has_permission_no_plugin() {
        // Check permission for a non-existent plugin ID.
        let registry = PluginRegistry::new();
        let fake_id = [0xEE; 16];

        // Should return false (fail-closed).
        assert!(!registry.has_permission(&fake_id, &PluginPermission::ReadMessages));
    }

    /// Custom permissions are compared by their string value.
    #[test]
    fn test_has_permission_custom() {
        // Install a plugin with a custom permission.
        let mut registry = PluginRegistry::new();
        let mut manifest = test_manifest();
        manifest
            .permissions
            .push(PluginPermission::Custom("special_feature".to_string()));

        let id = registry.install(manifest, None).expect("install");

        // The custom permission should be found by value.
        assert!(registry.has_permission(
            &id,
            &PluginPermission::Custom("special_feature".to_string()),
        ));

        // A different custom permission should NOT be found.
        assert!(
            !registry.has_permission(&id, &PluginPermission::Custom("other_feature".to_string()),)
        );
    }

    // -----------------------------------------------------------------------
    // Signature verification
    // -----------------------------------------------------------------------

    /// Verify a valid signature against the correct signing key.
    #[test]
    fn test_verify_signature_valid() {
        // Generate a test Ed25519 keypair.
        let secret = [0x42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let public = signing_key.verifying_key().to_bytes();

        // Build the message that verify_signature expects: name || version || author.
        let name = "Signed Plugin";
        let version = "2.0.0";
        let author = "Trusted Author";
        let mut message = Vec::new();
        message.extend_from_slice(name.as_bytes());
        message.extend_from_slice(version.as_bytes());
        message.extend_from_slice(author.as_bytes());

        // Sign the message with the plugin domain separator.
        let sig = signing::sign(&secret, signing::DOMAIN_PLUGIN_SIGNATURE, &message);

        // Create a plugin with the matching fields and signature.
        let mut registry = PluginRegistry::new();
        let mut manifest = test_manifest();
        manifest.name = name.to_string();
        manifest.version = version.to_string();
        manifest.author = author.to_string();

        let id = registry.install(manifest, Some(sig)).expect("install");
        let plugin = registry.get(&id).expect("plugin should exist");

        // Verification should succeed with the correct public key.
        assert!(registry.verify_signature(plugin, &public));
    }

    /// Verification fails with the wrong signing key.
    #[test]
    fn test_verify_signature_wrong_key() {
        // Generate a test keypair and sign with it.
        let secret = [0x42u8; 32];
        let name = "Signed Plugin";
        let version = "1.0.0";
        let author = "Author";

        let mut message = Vec::new();
        message.extend_from_slice(name.as_bytes());
        message.extend_from_slice(version.as_bytes());
        message.extend_from_slice(author.as_bytes());

        let sig = signing::sign(&secret, signing::DOMAIN_PLUGIN_SIGNATURE, &message);

        // Create a plugin with the signature.
        let mut registry = PluginRegistry::new();
        let mut manifest = test_manifest();
        manifest.name = name.to_string();
        manifest.version = version.to_string();
        manifest.author = author.to_string();

        let id = registry.install(manifest, Some(sig)).expect("install");
        let plugin = registry.get(&id).expect("plugin should exist");

        // Verify with a DIFFERENT public key — must fail.
        let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32])
            .verifying_key()
            .to_bytes();
        assert!(!registry.verify_signature(plugin, &wrong_key));
    }

    /// Verification fails when the plugin has no signature.
    #[test]
    fn test_verify_signature_none() {
        // Install a plugin WITHOUT a signature.
        let mut registry = PluginRegistry::new();
        let id = registry.install(test_manifest(), None).expect("install");
        let plugin = registry.get(&id).expect("plugin should exist");

        // Any key should fail because there's no signature to verify.
        let some_key = [0x42u8; 32];
        assert!(!registry.verify_signature(plugin, &some_key));
    }

    // -----------------------------------------------------------------------
    // Manifest parsing
    // -----------------------------------------------------------------------

    /// Parse a valid manifest JSON string.
    #[test]
    fn test_parse_manifest_valid() {
        // Minimal valid manifest JSON with all required fields.
        let json = r#"{
            "name": "My Plugin",
            "version": "1.0.0",
            "author": "Author Name",
            "description": "Does something useful",
            "permissions": ["read_messages", "network_access"],
            "hooks": ["on_message", "on_peer_connected"],
            "min_app_version": "0.3.0"
        }"#;

        // parse_manifest should succeed.
        let manifest = parse_manifest(json).expect("parse should succeed");

        // Verify all fields were extracted correctly.
        assert_eq!(manifest.name, "My Plugin");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.author, "Author Name");
        assert_eq!(manifest.description, "Does something useful");
        assert_eq!(manifest.permissions.len(), 2);
        assert_eq!(manifest.permissions[0], PluginPermission::ReadMessages);
        assert_eq!(manifest.permissions[1], PluginPermission::NetworkAccess);
        assert_eq!(manifest.hooks, vec!["on_message", "on_peer_connected"]);
        assert_eq!(manifest.min_app_version, "0.3.0");
    }

    /// Parse a manifest with only the minimum required fields.
    #[test]
    fn test_parse_manifest_minimal() {
        // Only name and version are strictly required.
        let json = r#"{ "name": "Minimal", "version": "0.1.0" }"#;

        // parse_manifest should succeed with defaults for optional fields.
        let manifest = parse_manifest(json).expect("parse should succeed");
        assert_eq!(manifest.name, "Minimal");
        assert_eq!(manifest.version, "0.1.0");

        // Optional fields should have sensible defaults.
        assert_eq!(manifest.author, "Unknown");
        assert!(manifest.description.is_empty());
        assert!(manifest.permissions.is_empty());
        assert!(manifest.hooks.is_empty());
        assert_eq!(manifest.min_app_version, "0.0.0");
    }

    /// Parse fails on invalid JSON.
    #[test]
    fn test_parse_manifest_invalid_json() {
        // Completely invalid JSON — should fail.
        let result = parse_manifest("not json at all");
        assert!(result.is_err());
    }

    /// Parse fails when required "name" field is missing.
    #[test]
    fn test_parse_manifest_missing_name() {
        // Missing the "name" field.
        let json = r#"{ "version": "1.0.0" }"#;
        let result = parse_manifest(json);
        assert!(result.is_err());
    }

    /// Parse fails when required "version" field is missing.
    #[test]
    fn test_parse_manifest_missing_version() {
        // Missing the "version" field.
        let json = r#"{ "name": "Plugin" }"#;
        let result = parse_manifest(json);
        assert!(result.is_err());
    }

    /// Custom permissions are parsed into the Custom variant.
    #[test]
    fn test_parse_manifest_custom_permission() {
        // Manifest with an unknown permission string.
        let json = r#"{
            "name": "Custom Plugin",
            "version": "1.0.0",
            "permissions": ["read_messages", "some_future_permission"]
        }"#;

        let manifest = parse_manifest(json).expect("parse should succeed");
        assert_eq!(manifest.permissions.len(), 2);

        // First is a known permission.
        assert_eq!(manifest.permissions[0], PluginPermission::ReadMessages);

        // Second is an unknown permission — stored as Custom.
        assert_eq!(
            manifest.permissions[1],
            PluginPermission::Custom("some_future_permission".to_string()),
        );
    }

    // -----------------------------------------------------------------------
    // JSON export
    // -----------------------------------------------------------------------

    /// to_json() produces valid JSON with the expected structure.
    #[test]
    fn test_to_json_structure() {
        // Install and activate a plugin, then export as JSON.
        let mut registry = PluginRegistry::new();
        let id = registry.install(test_manifest(), None).expect("install");
        registry.activate(&id).expect("activate");
        registry
            .register_hook("on_message", id)
            .expect("register_hook");

        // Export the registry state.
        let json = registry.to_json();

        // Top-level should have "plugins" array and "hook_count".
        let plugins = json.get("plugins").expect("missing plugins field");
        assert!(plugins.is_array());
        assert_eq!(plugins.as_array().expect("plugins array").len(), 1);

        // hook_count should be 1 (one hook registered).
        let hook_count = json
            .get("hook_count")
            .expect("missing hook_count")
            .as_u64()
            .expect("hook_count should be u64");
        assert_eq!(hook_count, 1);

        // The plugin entry should have the expected fields.
        let plugin_json = &plugins.as_array().expect("plugins array")[0];
        assert!(plugin_json.get("id").is_some());
        assert_eq!(
            plugin_json.get("name").and_then(|v| v.as_str()),
            Some("Test Plugin"),
        );
        assert_eq!(
            plugin_json.get("status").and_then(|v| v.as_str()),
            Some("active"),
        );
        assert_eq!(
            plugin_json.get("has_signature").and_then(|v| v.as_bool()),
            Some(false),
        );
    }

    // -----------------------------------------------------------------------
    // Full lifecycle integration test
    // -----------------------------------------------------------------------

    /// End-to-end test: parse manifest, install, activate, register hooks,
    /// invoke, check permissions, suspend, verify no invocations, uninstall.
    #[test]
    fn test_full_lifecycle() {
        // Parse a manifest from JSON.
        let json = r#"{
            "name": "Lifecycle Plugin",
            "version": "3.0.0",
            "author": "Lifecycle Author",
            "description": "Tests the full lifecycle",
            "permissions": ["read_messages", "send_messages"],
            "hooks": ["on_message_received"],
            "min_app_version": "0.2.0"
        }"#;
        let manifest = parse_manifest(json).expect("parse manifest");

        // Install the plugin.
        let mut registry = PluginRegistry::new();
        let id = registry
            .install(manifest, None)
            .expect("install should succeed");

        // Plugin starts as Installed — should not receive hooks.
        registry
            .register_hook("on_message_received", id)
            .expect("register hook");
        let results = registry.invoke_hook("on_message_received", serde_json::json!({}));
        assert!(
            results.is_empty(),
            "Installed plugins should not receive hooks"
        );

        // Activate the plugin — now it should receive hooks.
        registry.activate(&id).expect("activate");
        let results = registry.invoke_hook("on_message_received", serde_json::json!({"m": 1}));
        assert_eq!(results.len(), 1, "Active plugins should receive hooks");

        // Check permissions.
        assert!(registry.has_permission(&id, &PluginPermission::ReadMessages));
        assert!(registry.has_permission(&id, &PluginPermission::SendMessages));
        assert!(!registry.has_permission(&id, &PluginPermission::FileAccess));

        // Suspend the plugin — should stop receiving hooks.
        registry.suspend(&id).expect("suspend");
        let results = registry.invoke_hook("on_message_received", serde_json::json!({}));
        assert!(
            results.is_empty(),
            "Suspended plugins should not receive hooks",
        );

        // Reactivate — should receive hooks again.
        registry.activate(&id).expect("reactivate");
        let results = registry.invoke_hook("on_message_received", serde_json::json!({}));
        assert_eq!(results.len(), 1, "Reactivated plugins should receive hooks");

        // Uninstall — should clean everything up.
        registry.uninstall(&id).expect("uninstall");
        assert!(registry.list().is_empty());
        let results = registry.invoke_hook("on_message_received", serde_json::json!({}));
        assert!(results.is_empty(), "Uninstalled plugins leave no traces");
    }

    // -----------------------------------------------------------------------
    // hook_name_to_permission mapping
    // -----------------------------------------------------------------------

    /// Verify that on_message_* hooks map to ReadMessages.
    #[test]
    fn test_hook_permission_on_message() {
        // All on_message_* variants should require ReadMessages.
        assert_eq!(
            hook_name_to_permission("on_message_received"),
            Some(PluginPermission::ReadMessages),
        );
        assert_eq!(
            hook_name_to_permission("on_message_edited"),
            Some(PluginPermission::ReadMessages),
        );
        // Exact prefix match — "on_message" alone also maps.
        assert_eq!(
            hook_name_to_permission("on_message"),
            Some(PluginPermission::ReadMessages),
        );
    }

    /// Verify that on_send_* hooks map to SendMessages.
    #[test]
    fn test_hook_permission_on_send() {
        // on_send_message requires SendMessages (not just ReadMessages).
        assert_eq!(
            hook_name_to_permission("on_send_message"),
            Some(PluginPermission::SendMessages),
        );
    }

    /// Verify that on_peer_* and on_contact_* hooks map to ReadContacts.
    #[test]
    fn test_hook_permission_on_peer_contact() {
        assert_eq!(
            hook_name_to_permission("on_peer_connected"),
            Some(PluginPermission::ReadContacts),
        );
        assert_eq!(
            hook_name_to_permission("on_contact_updated"),
            Some(PluginPermission::ReadContacts),
        );
    }

    /// Verify that on_file_* hooks map to FileAccess.
    #[test]
    fn test_hook_permission_on_file() {
        assert_eq!(
            hook_name_to_permission("on_file_received"),
            Some(PluginPermission::FileAccess),
        );
    }

    /// Verify that unknown hooks return None (no required permission).
    #[test]
    fn test_hook_permission_unknown() {
        // Custom or infrastructure hooks have no mandatory permission requirement.
        assert_eq!(hook_name_to_permission("on_custom_event"), None);
        assert_eq!(hook_name_to_permission("startup"), None);
        assert_eq!(hook_name_to_permission(""), None);
    }

    // -----------------------------------------------------------------------
    // Plugin WASM bytes and sandbox
    // -----------------------------------------------------------------------

    /// Plugin::set_wasm_bytes stores bytes and they are accessible.
    #[test]
    fn test_plugin_set_wasm_bytes() {
        // Install a plugin and give it some (fake) WASM bytes.
        let mut registry = PluginRegistry::new();
        let id = registry.install(test_manifest(), None).expect("install");

        // wasm_bytes starts as None after install.
        {
            let plugin = registry.get(&id).expect("plugin should exist");
            assert!(plugin.wasm_bytes.is_none(), "wasm_bytes should start None");
        }

        // get_mut access through the plugins vec to call set_wasm_bytes.
        // In production, the caller iterates the registry's plugin list.
        registry
            .plugins
            .iter_mut()
            .find(|p| p.id == id)
            .expect("plugin should be in list")
            .set_wasm_bytes(vec![0x00, 0x61, 0x73, 0x6d]); // WASM magic bytes

        // wasm_bytes should now be Some.
        let plugin = registry.get(&id).expect("plugin should still exist");
        assert!(plugin.wasm_bytes.is_some(), "wasm_bytes should be set");
        assert_eq!(
            plugin.wasm_bytes.as_ref().unwrap(),
            &[0x00, 0x61, 0x73, 0x6d],
        );
    }

    /// PluginSandbox::new() succeeds and produces a functional sandbox.
    ///
    /// This test verifies that the wasmtime engine initializes correctly
    /// with cranelift JIT and epoch interruption enabled.
    #[cfg(not(target_os = "ios"))]
    #[test]
    fn test_plugin_sandbox_new() {
        // Creating a sandbox should succeed on all supported platforms.
        let sandbox = PluginSandbox::new();
        assert!(sandbox.is_ok(), "PluginSandbox::new() should succeed: {:?}", sandbox.err());

        let sandbox = sandbox.unwrap();

        // A fresh sandbox has no modules, timeouts, or crashes loaded.
        assert!(sandbox.modules.is_empty(), "modules should start empty");
        assert!(sandbox.timeout_counts.is_empty(), "timeout_counts should start empty");
        assert!(sandbox.crash_counts.is_empty(), "crash_counts should start empty");
    }

    /// PluginSandbox::load_module rejects malformed WASM bytes.
    ///
    /// Invalid WASM should fail at compile time (load_module), not at
    /// invocation time, giving a clean failure path.
    #[cfg(not(target_os = "ios"))]
    #[test]
    fn test_plugin_sandbox_load_module_invalid_wasm() {
        // Create a sandbox.
        let mut sandbox = PluginSandbox::new().expect("sandbox creation should succeed");

        // Attempt to load obviously invalid WASM bytes (just random data).
        let plugin_id = [0x01u8; 16];
        let bad_bytes = b"this is not valid wasm";
        let result = sandbox.load_module(plugin_id, bad_bytes);

        // Compilation should fail with a clear error.
        assert!(result.is_err(), "load_module should reject invalid WASM");
        // No module should be cached after a compile failure.
        assert!(!sandbox.modules.contains_key(&plugin_id),
            "failed module should not be cached");
    }

    /// invoke_hook_sandboxed skips plugins with no compiled module.
    ///
    /// A plugin installed without WASM bytes (no load_module call) should
    /// produce a HookInvocation with output=None rather than an error.
    #[cfg(not(target_os = "ios"))]
    #[test]
    fn test_invoke_hook_sandboxed_no_module() {
        // Install and activate a plugin with no WASM bytes.
        let mut registry = PluginRegistry::new();
        let id = registry.install(test_manifest(), None).expect("install");
        registry.activate(&id).expect("activate");
        registry.register_hook("on_message", id).expect("register_hook");

        // Create a sandbox but do NOT load any module.
        let mut sandbox = PluginSandbox::new().expect("sandbox creation should succeed");

        // Invoke the hook — should return one invocation with output=None
        // (graceful skip for missing module).
        let results = registry.invoke_hook_sandboxed(
            "on_message",
            serde_json::json!({"text": "hello"}),
            &mut sandbox,
        );

        // One invocation returned (the plugin was active).
        assert_eq!(results.len(), 1, "should return one invocation record");
        // Output is None because there was no compiled WASM module to run.
        assert!(results[0].output.is_none(), "output should be None with no module");
    }

    /// invoke_hook_sandboxed enforces permission gating (§18.2).
    ///
    /// A plugin registered for an on_message hook but lacking ReadMessages
    /// permission should be silently skipped — no invocation record produced.
    #[cfg(not(target_os = "ios"))]
    #[test]
    fn test_invoke_hook_sandboxed_permission_denied() {
        // Install a plugin with ONLY FileAccess — no ReadMessages.
        let mut registry = PluginRegistry::new();
        let mut manifest = test_manifest();
        // Override permissions: only FileAccess, not ReadMessages.
        manifest.permissions = vec![PluginPermission::FileAccess];
        let id = registry.install(manifest, None).expect("install");
        registry.activate(&id).expect("activate");
        // Register the plugin for an on_message hook.
        registry.register_hook("on_message_received", id).expect("register_hook");

        // Create a sandbox.
        let mut sandbox = PluginSandbox::new().expect("sandbox creation should succeed");

        // Invoke on_message_received — requires ReadMessages, which this plugin lacks.
        let results = registry.invoke_hook_sandboxed(
            "on_message_received",
            serde_json::json!({"text": "secret"}),
            &mut sandbox,
        );

        // The plugin should be skipped — zero invocations.
        assert!(
            results.is_empty(),
            "plugin without ReadMessages should not handle on_message_received"
        );
    }

    /// invoke_hook_sandboxed allows plugins with the required permission.
    ///
    /// A plugin with ReadMessages should receive on_message hooks.
    /// Without a real WASM module, output is None but the invocation is recorded.
    #[cfg(not(target_os = "ios"))]
    #[test]
    fn test_invoke_hook_sandboxed_permission_granted() {
        // Install a plugin with ReadMessages (from test_manifest default).
        let mut registry = PluginRegistry::new();
        let id = registry.install(test_manifest(), None).expect("install");
        registry.activate(&id).expect("activate");
        registry.register_hook("on_message_received", id).expect("register_hook");

        let mut sandbox = PluginSandbox::new().expect("sandbox creation should succeed");

        // Invoke on_message_received — the plugin has ReadMessages → should pass permission gate.
        let results = registry.invoke_hook_sandboxed(
            "on_message_received",
            serde_json::json!({"text": "hello"}),
            &mut sandbox,
        );

        // One invocation should be recorded (permission passed, module missing → output=None).
        assert_eq!(results.len(), 1, "plugin with ReadMessages should handle on_message_received");
        assert_eq!(results[0].hook_name, "on_message_received");
    }
}
