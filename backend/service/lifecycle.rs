//! Service lifecycle and runtime mode transitions.
//!
//! This module owns worker-thread lifecycle and mode-driven start/stop behavior.
//!
//! # What does "lifecycle" mean here?
//!
//! A "lifecycle" is the sequence of states a long-running component moves
//! through: created → started → running → stopped → (maybe restarted).
//!
//! `MeshInfinityService` is long-lived — it exists for the entire time the
//! app is open. But not all of its activity should run all the time. In
//! particular, the background *routing worker* — the loop that continuously
//! drains the outbound message queue — should only run when the node is acting
//! as a Server or Dual node. A Client node should stay quiet and save battery.
//!
//! This module contains the three methods that control that lifecycle:
//!
//! - `start()` — spin up the routing worker thread.
//! - `stop()`  — signal the worker to exit and wait for it to finish.
//! - `is_running()` — query whether the service is currently active.
//!
//! It also contains `set_node_mode()`, which changes the operating role
//! (Client / Server / Dual) and automatically calls start or stop as needed.
//!
//! # What is a "routing worker"?
//!
//! When the service wants to send a message, it doesn't transmit the bytes
//! immediately. Instead it places the message in an outbound queue (the
//! "routing queue") and returns. A background thread — the routing worker —
//! checks this queue every 50 milliseconds and tries to deliver each message
//! through the best available transport. This design means:
//!
//! 1. The UI thread (which calls `send_message`) is never blocked waiting for
//!    a network operation to finish.
//! 2. If delivery fails temporarily (e.g. the peer is momentarily unreachable),
//!    the message stays in the queue and is retried automatically.
//! 3. Server/Dual nodes can forward messages for OTHER peers too, not just their
//!    own — the worker drains everyone's queued messages.

// `Ordering` controls how an atomic operation interacts with other memory
// operations on other threads. Think of it as "how strict are the rules about
// when other threads see this change?"
//
// Rust provides five orderings (from weakest/fastest to strictest/safest):
//   Relaxed   — only guarantees the atomicity of THIS operation. No promises
//               about the order relative to any other operations.
//   Acquire   — all subsequent reads/writes in this thread see any writes that
//               happened before a matching Release in another thread.
//   Release   — all previous reads/writes in this thread become visible to
//               any thread that performs a matching Acquire.
//   AcqRel    — combines Acquire and Release.
//   SeqCst    — Sequential Consistency: the strictest ordering. ALL threads
//               agree on a single global order for ALL SeqCst operations.
//               Most expensive, but guarantees no surprises.
//
// We use `SeqCst` for start/stop (safety matters more than speed on this path)
// and `Relaxed` for the hot-loop flag check (speed matters; a tiny lag is fine).
use std::sync::atomic::Ordering;

// `thread` lets us spawn new OS threads, sleep within them, and get handles
// to join (wait for) them.
use std::thread;

// `Duration` represents a span of time (e.g. "50 milliseconds").
// Used to specify the sleep interval in the routing worker loop.
use std::time::Duration;

// Our custom Result type — like Rust's built-in `Result<T, E>` but with
// `MeshInfinityError` pre-filled as the error type, so every function in this
// crate can write `Result<()>` instead of `Result<(), MeshInfinityError>`.
use crate::core::error::Result;

// Pull in the types defined by the parent module (`service/mod.rs`).
// `super` means "the module one level up in the module tree" — here, `mod.rs`.
// We need `MeshInfinityService` (the struct we're adding methods to) and
// `NodeMode` (the enum we switch on in `set_node_mode`).
use super::{MeshInfinityService, NodeMode};

// ---------------------------------------------------------------------------
// Lifecycle implementation block
// ---------------------------------------------------------------------------
//
// In Rust, `impl SomeType { ... }` adds methods to a type. You can have
// multiple `impl` blocks for the same type scattered across different files;
// Rust merges them all together at compile time. This file adds four methods
// to `MeshInfinityService`: `start`, `stop`, `is_running`, and `set_node_mode`.

impl MeshInfinityService {
    // -----------------------------------------------------------------------
    // start()
    // -----------------------------------------------------------------------

    /// Start service runtime workers and transition to running state.
    ///
    /// This method does two things:
    /// 1. Marks the service as "running" using an atomic flag.
    /// 2. Spawns a background OS thread that continuously drains the outbound
    ///    message routing queue until `stop()` is called.
    ///
    /// # Idempotency
    ///
    /// Calling `start()` when the service is already running is **safe and
    /// harmless** — it returns immediately without starting a duplicate thread.
    ///
    /// "Idempotent" means: calling the function once has the same effect as
    /// calling it multiple times. This is intentional: FFI callers and
    /// mode-transition code can call `start()` freely without having to track
    /// whether it was already called.
    ///
    /// # What happens in the background thread?
    ///
    /// The spawned thread runs a tight loop:
    /// ```text
    /// while service is marked running:
    ///     try to drain one batch of queued messages
    ///     sleep 50 ms
    /// ```
    /// The 50 ms sleep keeps CPU usage near zero when the queue is empty,
    /// while ensuring messages are delivered within 50 ms of being enqueued —
    /// imperceptible latency for a human user.
    pub fn start(&self) -> Result<()> {
        // --- Guard: don't start twice ---
        //
        // `self.running` is an `Arc<AtomicBool>` — a boolean value that can be
        // read and written safely from multiple threads simultaneously WITHOUT
        // any locking overhead.
        //
        // Why use `AtomicBool` instead of a plain `bool`?
        // A plain `bool` in Rust is NOT safe to share across threads. If two
        // threads read and write a `bool` at the same instant, the CPU might
        // see a half-written value, leading to "undefined behaviour" (crashes,
        // wrong results, security bugs). `AtomicBool` prevents this by
        // guaranteeing that each read-modify-write happens as one indivisible
        // ("atomic") step at the hardware level.
        //
        // `.swap(true, Ordering::SeqCst)` does the following atomically:
        //   1. Read the current value of `running`.
        //   2. Write `true` into `running`.
        //   3. Return the OLD value (what it was before step 2).
        //
        // `Ordering::SeqCst` (Sequential Consistency) means this operation is
        // visible to ALL threads immediately, and all threads agree on the order
        // it happened relative to every other operation. It is the safest (and
        // slowest) ordering. On the startup path, speed doesn't matter.
        //
        // If the old value was already `true`, the service was already running.
        // We return `Ok(())` immediately — nothing to do.
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        // --- Guard: don't start a second worker thread ---
        //
        // Even if the atomic flag was `false` (so we set it to `true` above),
        // we check whether a thread handle is already stored. In theory these
        // two guards should always agree, but having both makes start() robust
        // against any unexpected race conditions.
        //
        // `self.routing_worker` is a `Mutex<Option<JoinHandle<()>>>`.
        //
        // What is a `Mutex`?
        // A Mutex ("mutual exclusion") is a lock. When one thread holds the
        // lock, ALL other threads that try to acquire it will BLOCK (pause and
        // wait) until the lock is released. This prevents two threads from
        // modifying `routing_worker` simultaneously, which would be a data race.
        //
        // `.lock().unwrap()` acquires the Mutex lock and returns a guard that
        // provides mutable access to the value inside. When the guard goes out
        // of scope (at the end of the block that contains it), the lock is
        // released automatically. `.unwrap()` panics if the lock is "poisoned"
        // — a poisoned lock means ANOTHER thread panicked while holding it,
        // leaving the protected data in an unknown state. Panicking here is
        // correct: if a lock is poisoned, something has gone seriously wrong.
        //
        // What is `Option<JoinHandle<()>>`?
        //   `None`           — no worker thread is running.
        //   `Some(handle)`   — a worker thread IS running; `handle` lets us
        //                      call `.join()` to wait for it to finish.
        //
        // If `.is_some()` returns `true`, we already have a running thread.
        // Return early without starting another.
        let mut worker_slot = self.routing_worker.lock().unwrap();
        if worker_slot.is_some() {
            return Ok(());
        }

        // --- Clone Arcs for the new thread ---
        //
        // Rust's ownership model says each piece of data has exactly ONE owner.
        // But we need BOTH the service struct AND the new background thread to
        // be able to read `self.running` and call methods on `self.message_router`.
        //
        // `Arc<T>` ("Atomically Reference Counted") solves this problem:
        //   - It wraps a value on the heap (dynamically allocated memory).
        //   - It keeps a reference count: how many `Arc` pointers exist to that value.
        //   - Calling `.clone()` on an `Arc` creates a SECOND POINTER to the
        //     same data on the heap — it does NOT copy the data itself.
        //   - The "atomic" part means the reference count is updated safely across
        //     threads (using an atomic integer, like `AtomicBool` above).
        //   - When a clone is dropped (goes out of scope), the count decreases.
        //     When the count reaches zero, the data is freed.
        //
        // Why clone them BEFORE spawning the thread?
        // Once `thread::spawn(move || { ... })` is called, the closure (the code
        // inside `|| { ... }`) takes ownership of the variables it uses. If we
        // tried to pass `&self.running` directly, the borrow checker would
        // reject it: the new thread could outlive the function that spawned it,
        // leaving a dangling reference. Cloning the `Arc`s gives the thread its
        // own owners of the data, which is safe.
        let running = std::sync::Arc::clone(&self.running);
        let router = std::sync::Arc::clone(&self.message_router);

        // --- Spawn the routing worker thread ---
        //
        // `thread::spawn(move || { ... })` creates a new native OS thread and
        // runs the closure on it concurrently with all other threads.
        //
        // `move` keyword: the closure "moves" (takes ownership of) any variables
        // it captures from the surrounding scope. Here it captures `running`
        // (the `Arc<AtomicBool>`) and `router` (the `Arc<MessageRouter>`).
        // Without `move`, the closure would try to borrow them — not allowed for
        // threads because the borrow checker cannot guarantee the borrows outlive
        // the thread.
        //
        // `thread::spawn` returns a `JoinHandle<()>`. Think of it as a "receipt"
        // for the spawned thread:
        //   - The `()` inside means the thread returns nothing when it exits.
        //   - Calling `.join()` on the handle blocks the caller until the thread
        //     finishes, and returns the thread's return value (here `()`).
        // We store the handle in `worker_slot` (the Mutex-protected `Option`).
        *worker_slot = Some(thread::spawn(move || {
            // ---------------------------------------------------------------
            // Routing worker loop
            // ---------------------------------------------------------------
            // This code runs on the NEW background thread, not on the caller's
            // thread. It loops until the `running` flag becomes `false`.

            // `while running.load(Ordering::Relaxed)` reads the atomic boolean.
            //
            // `Ordering::Relaxed` is the weakest (and cheapest) ordering. It only
            // guarantees that THIS read is atomic — there are no promises about
            // its order relative to other memory operations in other threads.
            //
            // Is it safe to use Relaxed here?
            // Yes, for this use case. We're just checking an on/off flag. A
            // very slight delay between `stop()` writing `false` and this
            // thread seeing the `false` is totally acceptable — the thread will
            // see the update within a few iterations at most and then exit.
            // Using `SeqCst` here would be overkill and would add CPU overhead
            // to a loop that runs hundreds of times per second.
            while running.load(Ordering::Relaxed) {
                // Try to drain one batch of queued outbound messages.
                //
                // `process_queue()` looks at the `MessageRouter`'s outbound
                // queue, picks up any pending messages, and attempts to deliver
                // each one through the best available transport path.
                //
                // If this call fails (e.g. because a transport is momentarily
                // down, the peer is unreachable, or a network error occurs),
                // we silently ignore the error and try again on the next tick.
                //
                // The `let _` pattern means "evaluate this expression and
                // intentionally discard the result". The underscore tells the
                // Rust compiler "I know there is a return value here, but I
                // am choosing not to use it." Without the `let _`, the compiler
                // would warn us about an unused `Result` value.
                let _ = router.process_queue();

                // Sleep for 50 milliseconds before the next queue drain.
                //
                // WHY SLEEP AT ALL?
                // Without a sleep, this loop would spin as fast as the CPU
                // allows — thousands of times per second — checking an
                // (usually empty) queue. That would consume 100% of one CPU
                // core doing essentially nothing. A 50 ms pause keeps CPU
                // usage near zero while still delivering messages with at most
                // 50 ms of extra latency, which is imperceptible to humans.
                //
                // WHY 50 ms SPECIFICALLY?
                // It is a balance between latency (how quickly messages go out)
                // and CPU efficiency. 50 ms means up to 20 delivery attempts per
                // second per peer, which is more than enough for chat traffic.
                // A message typed and sent by a user will feel instantaneous even
                // with a 50 ms queue processing delay.
                thread::sleep(Duration::from_millis(50));
            }
            // When `running.load(...)` returns `false` (because `stop()` called
            // `.store(false, ...)`), the while condition is false and the loop
            // exits here. The thread function returns `()`, the `JoinHandle`
            // stored in `worker_slot` becomes "joinable", and the thread is
            // cleaned up by the OS.
        }));

        Ok(())
    }

    // -----------------------------------------------------------------------
    // stop()
    // -----------------------------------------------------------------------

    /// Stop service runtime workers and transition to stopped state.
    ///
    /// This method:
    /// 1. Signals the routing worker thread to exit by setting `running` to `false`.
    /// 2. Waits for the routing worker thread to actually finish (`.join()`).
    ///
    /// After `stop()` returns, the background thread is GUARANTEED to be gone.
    /// No more routing work will happen until `start()` is called again.
    ///
    /// # Why wait for the thread to finish?
    ///
    /// Without `.join()`, `stop()` would return immediately but the background
    /// thread might still be in the middle of `process_queue()`. If the service
    /// were then destroyed (dropped), any shared data the worker is still using
    /// could be freed while the thread is accessing it — a "use-after-free" bug.
    /// `.join()` prevents this by blocking until the worker is completely done.
    ///
    /// # Idempotency
    ///
    /// Like `start()`, calling `stop()` when already stopped is **safe and
    /// harmless**. If `routing_worker` is `None` (no thread running), the
    /// `if let Some(...)` block is skipped entirely.
    pub fn stop(&self) -> Result<()> {
        // Signal the worker loop to stop.
        //
        // `.store(false, Ordering::SeqCst)` writes the value `false` into
        // the `AtomicBool`. `SeqCst` ensures this write is immediately visible
        // to ALL other threads — the worker will see `false` on its very next
        // iteration of `running.load(Ordering::Relaxed)` and exit the loop.
        //
        // We use `SeqCst` (not `Relaxed`) here because on the shutdown path we
        // WANT the strictest guarantee: the write must be visible to the worker
        // before `stop()` proceeds to `.join()`. Without this guarantee, in
        // theory the worker could loop for a very long time before seeing the
        // updated value.
        self.running.store(false, Ordering::SeqCst);

        // Wait for the worker thread to actually finish.
        //
        // `.lock().unwrap()` — acquire the Mutex protecting `routing_worker`.
        //
        // `.take()` — atomically replaces the `Option<JoinHandle>` with `None`
        // and returns the old value. If the old value was `Some(handle)`, we
        // get the handle back. If it was already `None` (no thread running),
        // `.take()` returns `None` and the body of `if let Some(handle)` is
        // skipped — stop() becomes a safe no-op.
        //
        // Why does `.take()` set the Option back to `None`?
        // Once we've called `.join()` on a handle, the handle is consumed
        // (moved into `.join()`). It cannot be joined again. Replacing the
        // Option with `None` accurately reflects that no thread is running.
        //
        // `handle.join()` — blocks the calling thread until the worker thread
        // has finished executing. Only returns after the worker's closure
        // has returned `()` and the thread has fully exited.
        //
        // `let _ = handle.join()` — discards the result of `.join()`. The
        // result is `Result<(), Box<dyn Any + Send>>` — the `Err` case means
        // the thread panicked. We do not propagate thread panics here because:
        // 1. The thread panicking is unusual (we'd see it in logs/crash reports).
        // 2. `stop()` should still clean up correctly even if the thread panicked.
        if let Some(handle) = self.routing_worker.lock().unwrap().take() {
            let _ = handle.join();
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // is_running()
    // -----------------------------------------------------------------------

    /// Report whether the service is currently marked as running.
    ///
    /// Returns `true` if the routing worker is (or should be) active.
    ///
    /// # Usage
    ///
    /// Primarily used by tests to verify lifecycle transitions:
    /// ```text
    /// service.start();
    /// assert!(service.is_running()); // should be true
    /// service.stop();
    /// assert!(!service.is_running()); // should be false
    /// ```
    ///
    /// Also used by the UI layer (via FFI) to show the node's running status
    /// on the Network screen.
    ///
    /// # Why `Ordering::Relaxed`?
    ///
    /// This is a read-only status check, not a synchronisation point. We are
    /// not trying to synchronise this read with any writes — we just want to
    /// know the current approximate value. A very slightly stale value (from
    /// the nanosecond before `start()` or `stop()` updated it) is perfectly
    /// fine for display or testing purposes. `Relaxed` is the cheapest option.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    // -----------------------------------------------------------------------
    // set_node_mode()
    // -----------------------------------------------------------------------

    /// Set the node's runtime mode and automatically reconcile worker lifecycle.
    ///
    /// This is the primary way for the UI (via FFI) to change the operating
    /// role of the node at runtime — for example when the user toggles between
    /// "Client" and "Server" in the Settings screen.
    ///
    /// # What "reconcile" means
    ///
    /// "Reconcile" means: inspect the new mode, compare it to the current
    /// state (is the routing worker running or not?), and make whatever
    /// calls are necessary to bring the state in line with the new mode.
    ///
    /// The logic is intentionally simple:
    ///
    /// - Switching to `Client`       → call `stop()` to shut down the worker.
    ///   A client node only sends/receives its own traffic; it does NOT relay
    ///   messages for other peers and does NOT need a background routing thread.
    ///   Stopping the worker saves battery and CPU.
    ///
    /// - Switching to `Server`/`Dual` → call `start()` to ensure the worker runs.
    ///   Both roles need to drain the routing queue continuously for other peers.
    ///
    /// Because `start()` and `stop()` are both idempotent, this method is also
    /// safe to call multiple times with the same mode — calling
    /// `set_node_mode(NodeMode::Server)` twice in a row does not start two
    /// worker threads.
    ///
    /// # Parameters
    ///
    /// `mode` — the new operating role. Passed by value (`Copy`) so no borrow
    /// or clone is needed.
    pub fn set_node_mode(&self, mode: NodeMode) {
        // Write the new mode into the shared settings state.
        //
        // `self.state` is an `Arc<RwLock<ServiceState>>`.
        //
        // What is an `RwLock` ("Read-Write Lock")?
        // It is a more flexible version of `Mutex`:
        //   - Multiple threads can hold READ access simultaneously (`.read()`).
        //     This is safe because reading doesn't change the data.
        //   - Only ONE thread at a time can hold WRITE access (`.write()`).
        //     This ensures writes don't conflict with reads or other writes.
        //
        // We need WRITE access here because we are CHANGING `node_mode`.
        //
        // `.write()` returns a "write guard" — a temporary object that:
        //   - Blocks until no other thread holds read or write access.
        //   - Provides `DerefMut` access (i.e. lets you modify the inner value).
        //   - Releases the write lock when it goes out of scope (at the `;`).
        //
        // `.unwrap()` panics if the lock is poisoned (another thread panicked
        // while holding a write lock). Acceptable here — poison means the
        // protected data is in an unknown state.
        //
        // `.settings.node_mode = mode` modifies the `node_mode` field of the
        // `Settings` struct inside `ServiceState`.
        self.state.write().unwrap().settings.node_mode = mode;

        // Reconcile the worker thread based on the new mode.
        //
        // `match` in Rust is like a supercharged `switch` statement. It
        // exhaustively covers every variant of the enum — if a new variant
        // is added to `NodeMode`, the compiler will force us to handle it here.
        //
        // The `let _ = ...` pattern discards the `Result` return values from
        // `stop()` and `start()`. In normal operation these always succeed, and
        // failure here would not change the observable behaviour (the mode is
        // already written to state above).
        match mode {
            // ---------------------------------------------------------------
            // Client mode: no routing worker needed.
            // ---------------------------------------------------------------
            //
            // A Client node only sends and receives its OWN messages. It does
            // not act as a relay for other peers. There is no need to drain a
            // routing queue continuously — messages are dispatched immediately
            // when sent (single-shot delivery) and that is sufficient.
            //
            // Calling `stop()` here is idempotent: if the worker was already
            // stopped (e.g. because we were already in Client mode), stop()
            // is a no-op.
            NodeMode::Client => {
                let _ = self.stop();
            }

            // ---------------------------------------------------------------
            // Server or Dual mode: routing worker must be running.
            // ---------------------------------------------------------------
            //
            // Both Server and Dual nodes need to forward queued messages for
            // other peers continuously. The `|` in a match arm means "OR":
            // this single arm matches EITHER `NodeMode::Server` OR `NodeMode::Dual`.
            //
            // Calling `start()` here is idempotent: if the worker is already
            // running (e.g. switching from Server to Dual), start() is a no-op.
            NodeMode::Server | NodeMode::Dual => {
                let _ = self.start();
            }
        }
    }
}
