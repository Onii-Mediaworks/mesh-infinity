//! Core transport-orchestration manager.
//!
//! # What does this module do?
//!
//! This is the engine room of the transport layer.  While `manager.rs` is the
//! control panel (which transports are enabled/disabled, in what order to try
//! them), this module does the actual work:
//!
//!   - Stores a collection of live transport objects, one per type.
//!   - Keeps a registry of the factories that were used to create them.
//!   - Tracks which connections are currently open (the *active connections* map).
//!   - Picks the *best* transport to reach a specific peer using a two-pass
//!     algorithm that respects both privacy ordering and connection quality.
//!
//! # What is "connection quality"?
//!
//! Every transport can report a [`TransportQuality`] measurement describing
//! how well it is performing right now.  Think of it like checking the bars on
//! your phone signal before making a call.  The quality has several dimensions:
//!
//!   - `reliability` (0.0 to 1.0): the fraction of packets that actually arrive.
//!     1.0 = perfect delivery; 0.0 = nothing gets through.
//!   - `congestion`  (0.0 to 1.0): how busy/saturated the path is.
//!     0.0 = not congested at all; 1.0 = completely saturated.
//!   - `latency`: how long a round-trip takes (milliseconds).
//!   - `bandwidth`: maximum bytes per second.
//!   - `cost`: a relative cost score (useful for metered connections).
//!
//! # The two-pass connection algorithm
//!
//! Connecting to a peer is not as simple as "use the first transport in the list".
//! A transport might be available in principle, but performing badly right now
//! (high packet loss, congested network).  To handle this, `get_best_connection`
//! runs two passes:
//!
//! **Pass 1 — Quality-gated (strict):**
//!   Try each transport in anti-downgrade order.  Before opening a connection,
//!   run a *quality probe* (measure latency, reliability, congestion).  Only
//!   proceed if the transport passes the minimum quality thresholds:
//!     - `reliability >= min_reliability` (at least 35% of packets arrive), AND
//!     - `congestion <= max_congestion`   (path is not more than 90% saturated).
//!   If both checks pass, try to `connect()`.  Return immediately on success.
//!
//! **Pass 2 — Fail-open (permissive):**
//!   If no transport passed the quality gate (probes timed out, returned stale
//!   data, or the network is truly rough), try again in the SAME order but
//!   *without* checking quality.  It is better to have a slightly degraded
//!   connection than no connection at all.
//!
//! # Why two passes instead of one?
//!
//! Quality probes can be wrong:
//!   - The probe might have been cached from 5 minutes ago when the network
//!     was bad, but it's fine now.
//!   - A probe timeout doesn't mean the transport is broken — maybe the probe
//!     server was temporarily unreachable while the transport itself works fine.
//!
//! By having a fail-open pass 2, we avoid refusing to connect just because
//! our measurement data is stale or imperfect.  The privacy ordering (Tor
//! before Clearnet) is still respected in pass 2, so we don't silently downgrade.
//!
//! # What is the active_connections map?
//!
//! `active_connections` is a `HashMap<String, Vec<Box<dyn Connection>>>`.
//!
//! In plain English: a dictionary (HashMap) where:
//!   - **Keys** are peer IDs — unique strings that identify each remote peer.
//!   - **Values** are lists (`Vec`) of currently-open connection objects.
//!
//! One peer can have more than one connection open at a time (e.g., a Tor
//! connection AND a Bluetooth link for redundancy).  That is why the value is
//! a `Vec` instead of a single connection.
//!
//! `Box<dyn Connection>` is a "trait object" — a heap-allocated connection
//! whose concrete type (TorConnection, ClearnetConnection, etc.) is erased.
//! The caller only needs to know it implements the `Connection` trait.  This
//! lets us store completely different connection types in the same Vec.
//!
//! # Why `Arc<Mutex<...>>` around the map?
//!
//! Multiple threads may try to read or write the `active_connections` map
//! simultaneously.  Concurrent access to a plain `HashMap` without
//! synchronization would corrupt its internal data structures.
//!
//!   - `Mutex` (Mutual Exclusion lock) ensures only ONE thread can access the
//!     map at a time.  Any other thread trying to access it will block until
//!     the lock is released.
//!   - `Arc` (Atomic Reference Count) allows the Mutex (and the map inside it)
//!     to be shared between multiple owners — e.g., the manager struct AND a
//!     background monitoring task — without any copying.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::core::error::Result;
use crate::core::{PeerInfo, TransportQuality, TransportType};

use super::traits::{Connection, Transport, TransportFactory};

/// A type alias for the active-connections data structure.
///
/// Writing `ActiveConnections` is much shorter than writing out the full type
/// every time.  Type aliases in Rust (introduced with the `type` keyword) are
/// purely a naming convenience — they don't create new types.
///
/// `HashMap<String, Vec<Box<dyn Connection>>>` means:
///   - Keys are peer ID strings (hex-encoded or similar identifiers).
///   - Values are lists of open connections to that peer.
///
/// Using a `Vec` (list) as the value allows one peer to have multiple
/// simultaneous connections open (e.g., Tor + Bluetooth in parallel for
/// redundancy or testing).
type ActiveConnections = HashMap<String, Vec<Box<dyn Connection>>>;

/// The core transport orchestration engine.
///
/// `TransportManager` stores live transport instances (one per `TransportType`),
/// applies quality gates, and selects the best connection path to a peer.
///
/// # How it fits in the architecture
///
/// `TransportManager` is created by `TransportManagerImpl::new()` in `manager.rs`,
/// which wires up all the factories and calls `initialize_transports()`.
/// After that, `TransportManagerImpl` owns an `Arc<TransportManager>` and
/// exposes it via `get_manager()`.
///
/// Code that wants to connect to a peer:
/// 1. Calls `TransportManagerImpl::enabled_transport_order_for_available()`
///    to get the ordered list of transport types to try.
/// 2. Calls `TransportManager::get_best_connection(peer, order)` with that list.
///
/// # Fields overview
///
/// - `transports`: the live transport objects, ready to open connections.
/// - `factories`:  the blueprints used to create the transports; kept so
///                 transports can be recreated if they need to restart.
/// - `active_connections`: bookkeeping of all currently-open connections.
/// - `min_reliability` / `max_congestion`: the quality gate thresholds for pass 1.
pub struct TransportManager {
    /// All live transport instances, keyed by their `TransportType`.
    ///
    /// `Arc<dyn Transport>` is used here instead of `Box<dyn Transport>`
    /// because we sometimes need to hand a reference to the same transport
    /// object to multiple callers (e.g., the connection selector and the
    /// quality monitor) at the same time.  `Arc` allows this safely; `Box`
    /// has a single owner and cannot be shared.
    transports: HashMap<TransportType, Arc<dyn Transport>>,

    /// Registered factories, keyed by `TransportType`.
    ///
    /// These are kept after initialization so the manager can recreate
    /// a transport if it needs to be restarted (e.g., after a Tor circuit
    /// failure, the factory can build a fresh `TorTransport`).
    ///
    /// `Box<dyn TransportFactory>` erases the concrete factory type; the map
    /// stores all factory types uniformly under a common trait interface.
    factories: HashMap<TransportType, Box<dyn TransportFactory>>,

    /// All currently-open connections, keyed by peer ID string.
    ///
    /// `Arc<Mutex<ActiveConnections>>` allows this map to be shared and mutated
    /// safely from multiple threads:
    ///   - `Arc` — multiple owners can hold a reference (no copying required).
    ///   - `Mutex` — only one owner can read/write at a time (prevents data races).
    active_connections: Arc<Mutex<ActiveConnections>>,

    /// Minimum reliability score (0.0–1.0) a transport must report in pass 1.
    ///
    /// A transport with `reliability < min_reliability` is skipped during the
    /// quality-gated pass and only attempted in the fail-open pass 2.
    ///
    /// Default: 0.35 (35%).  We accept transports that deliver at least 35%
    /// of packets — a deliberately low bar so we don't over-reject in pass 1.
    min_reliability: f32,

    /// Maximum congestion score (0.0–1.0) a transport may report in pass 1.
    ///
    /// A transport with `congestion > max_congestion` is skipped during pass 1.
    /// Default: 0.90 (90%).  Only truly saturated paths (more than 90%
    /// congested) are excluded in pass 1.  We set this high so that only
    /// extreme congestion causes a skip.
    max_congestion: f32,
}

impl Default for TransportManager {
    /// Implement the standard `Default` trait so callers can write
    /// `TransportManager::default()` as a synonym for `TransportManager::new()`.
    ///
    /// This is a Rust convention for types that have a sensible zero-config
    /// starting state.  Many Rust macros and framework utilities look for
    /// `Default` implementations.
    fn default() -> Self {
        Self::new()
    }
}

impl TransportManager {
    /// Create an empty manager with conservative quality thresholds.
    ///
    /// "Empty" means no transports are registered yet.  Call
    /// `register_transport_factory` and `initialize_transports` to populate it,
    /// or use `TransportManagerImpl::new()` in `manager.rs` which does all of
    /// this for you automatically.
    ///
    /// # Default thresholds
    ///
    /// `min_reliability = 0.35`: accept if at least 35% of packets arrive.
    /// `max_congestion = 0.90`:  reject only if more than 90% congested.
    ///
    /// These conservative defaults mean pass 1 rarely rejects transports, so
    /// pass 2 (fail-open) is a genuine last-resort fallback rather than a
    /// routine code path.
    pub fn new() -> Self {
        Self {
            transports: HashMap::new(),
            factories: HashMap::new(),
            // Start with an empty, thread-safe active-connections map.
            // `Arc::new(Mutex::new(HashMap::new()))` creates:
            //   1. An empty HashMap
            //   2. Wrapped in a Mutex (for thread-safe access)
            //   3. Wrapped in an Arc (so multiple owners can share it)
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            min_reliability: 0.35,
            max_congestion: 0.90,
        }
    }

    /// Register a transport factory with this manager.
    ///
    /// The factory is stored in the `factories` HashMap, keyed by the
    /// `TransportType` it produces.  If a factory for the same type was
    /// already registered, the new one replaces it.
    ///
    /// This must be called before `initialize_transports()`.  Each unique
    /// transport type you want available must have a registered factory.
    ///
    /// # Why take `Box<dyn TransportFactory>`?
    ///
    /// The `mut self` receiver in `register_transport_factory` is important —
    /// it signals that this method modifies the manager.  Taking a
    /// `Box<dyn TransportFactory>` (rather than a reference) transfers
    /// ownership of the factory into the manager.  The manager then owns the
    /// factory for the rest of its lifetime.
    pub fn register_transport_factory(&mut self, factory: Box<dyn TransportFactory>) {
        // Ask the factory what type it produces, then store it under that key.
        let transport_type = factory.transport_type();
        self.factories.insert(transport_type, factory);
    }

    /// Call every registered factory and store the resulting transport objects.
    ///
    /// This is called once during startup (by `TransportManagerImpl::new()`).
    /// After this returns `Ok(())`, the `transports` HashMap is populated and
    /// `get_best_connection()` can be called.
    ///
    /// # How it works
    ///
    /// We iterate over all registered factories.  For each one, we call
    /// `factory.create_transport()`, which returns a `Box<dyn Transport>`.
    /// We then wrap it in an `Arc` (using `Arc::from(transport)`) so it can
    /// be shared across threads, and store it in the `transports` HashMap.
    ///
    /// # `Arc::from(transport)` vs `Arc::new(transport)`
    ///
    /// `Arc::from(transport)` converts an existing `Box<dyn Transport>` into
    /// an `Arc<dyn Transport>` without any extra allocation.  This is slightly
    /// more efficient than `Arc::new(*transport)` (which would require
    /// unboxing and reboxing).
    ///
    /// # Return value
    ///
    /// Returns `Ok(())` on success.  Returns an `Err` if any factory's
    /// `create_transport()` fails.  In practice all current factories always
    /// succeed, but the `Result` return type keeps the interface honest.
    pub fn initialize_transports(&mut self) -> Result<()> {
        for (transport_type, factory) in &self.factories {
            // Call the factory to get a new transport instance.
            let transport = factory.create_transport();
            // Wrap in Arc so it can be shared across threads.
            self.transports
                .insert(*transport_type, Arc::from(transport));
        }
        Ok(())
    }

    /// Record an open connection to a peer in the active-connections map.
    ///
    /// This is used for bookkeeping.  Other parts of the code can call
    /// `active_connection_count()` to check how many connections are
    /// currently open to a given peer.
    ///
    /// # Mutex locking
    ///
    /// `lock().unwrap()` acquires the Mutex lock.  If successful, it returns a
    /// `MutexGuard` — a special wrapper that automatically releases the lock
    /// when it goes out of scope (RAII: Resource Acquisition Is Initialization).
    ///
    /// `.unwrap()` panics if the Mutex is "poisoned".  A Mutex becomes poisoned
    /// if another thread panicked while holding the lock, leaving the protected
    /// data in an unknown state.  In normal operation this never happens.
    ///
    /// # `entry(...).or_default()` pattern
    ///
    /// `active.entry(peer_id.to_string())` looks up the peer's entry.
    /// `.or_default()` inserts an empty `Vec` if the entry doesn't exist yet,
    /// then returns a mutable reference to the Vec (new or existing).
    /// `.push(connection)` appends the connection to the Vec.
    ///
    /// This "entry API" is the idiomatic Rust way to insert-or-update a HashMap
    /// value in a single lookup (more efficient than checking `.contains_key`
    /// and then calling `.insert` separately).
    pub fn track_connection(&self, peer_id: &str, connection: Box<dyn Connection>) {
        let mut active = self.active_connections.lock().unwrap();
        active
            .entry(peer_id.to_string())
            .or_default()
            .push(connection);
    }

    /// Return how many connections are currently tracked for a given peer.
    ///
    /// Returns 0 if no connections are tracked for this peer ID.
    ///
    /// # How the chain works
    ///
    /// `active.get(peer_id)` returns `Some(&Vec<...>)` if the key exists, or
    /// `None` if the peer has no tracked connections.
    ///
    /// `.map(|list| list.len())` transforms `Some(&Vec)` into `Some(usize)` by
    /// calling `.len()` on the Vec.  If the input was `None`, `.map` skips the
    /// closure and returns `None` unchanged.
    ///
    /// `.unwrap_or(0)` extracts the `usize` from `Some(n)`, or returns 0 if
    /// the Option was `None` (no connections for this peer).
    pub fn active_connection_count(&self, peer_id: &str) -> usize {
        let active = self.active_connections.lock().unwrap();
        active.get(peer_id).map(|list| list.len()).unwrap_or(0)
    }

    /// Select the best available transport and open a connection to the target peer.
    ///
    /// This is the most important method in the transport layer.  It implements
    /// the two-pass algorithm described at the top of this file.
    ///
    /// # Parameters
    ///
    /// - `target`: metadata about the peer we want to reach — their ID, their
    ///   known endpoints, their supported transports, etc.  See `PeerInfo`.
    /// - `preferred`: the ordered list of transport types to try.  This should
    ///   be produced by `TransportManagerImpl::enabled_transport_order_for_available()`
    ///   which already applies both anti-downgrade ordering AND peer-capability
    ///   filtering.  We trust the caller to pass the right list.
    ///
    /// # Return value
    ///
    /// Returns `Ok(Box<dyn Connection>)` — a heap-allocated connection object
    /// whose concrete type is erased — when any transport succeeds.
    ///
    /// Returns `Err(MeshInfinityError::NoAvailableTransport)` if every transport
    /// in `preferred` fails in both passes.
    ///
    /// # Why `async fn`?
    ///
    /// `async fn` means this function returns a `Future` — a value representing
    /// a computation that hasn't finished yet.  The caller must `.await` it to
    /// actually run it.
    ///
    /// Network operations (quality probes, circuit building) can take hundreds
    /// of milliseconds.  If they ran synchronously (blocking), the whole thread
    /// would be frozen while waiting.  Using `async` allows Tokio's scheduler to
    /// run other tasks (UI updates, other peer connections) on the same thread
    /// while waiting for network I/O.
    ///
    /// # Two-pass algorithm detail
    ///
    /// ## Pass 1 — Quality-gated
    ///
    /// For each transport in `preferred` (anti-downgrade order):
    ///
    ///   1. Look up the transport in `self.transports`.  If it is not there
    ///      (shouldn't happen in normal operation), skip.
    ///
    ///   2. Call `transport.is_available()`.  Some transports (e.g., Tor before
    ///      bootstrapping) report themselves as unavailable.  Skip those.
    ///
    ///   3. Call `transport.measure_quality(target)`.  This probes the transport
    ///      and returns a `TransportQuality` struct.  If the probe fails (network
    ///      error, timeout), treat quality as "not OK" and skip in pass 1.
    ///
    ///   4. Check `reliability >= min_reliability && congestion <= max_congestion`.
    ///      Both conditions must be true.  If either fails, skip in pass 1.
    ///
    ///   5. Call `transport.connect(target)`.  If this succeeds, return the
    ///      connection immediately.  If it fails (rare after a passing quality
    ///      probe), fall through to the next transport.
    ///
    /// ## Pass 2 — Fail-open
    ///
    /// Walk `preferred` again in the same order, but skip the quality check.
    /// Just call `is_available()` and then `connect()` directly.  Return the
    /// first success.  If all fail, return `NoAvailableTransport`.
    pub async fn get_best_connection(
        &self,
        target: &PeerInfo,
        preferred: &[TransportType],
    ) -> Result<Box<dyn Connection>> {

        // -----------------------------------------------------------------------
        // Pass 1: Quality-gated — try each transport with quality thresholds.
        // -----------------------------------------------------------------------
        //
        // `for transport_type in preferred` iterates over the slice one element
        // at a time.  The order is the anti-downgrade order provided by the caller.
        for transport_type in preferred {
            // `self.transports.get(transport_type)` looks up the transport.
            // `if let Some(transport) = ...` unpacks the Option: if the key exists,
            // `transport` is bound to the Arc<dyn Transport>.  If missing, skip.
            if let Some(transport) = self.transports.get(transport_type) {
                // Only proceed if the transport reports itself as operational.
                // For example, TorTransport returns false before bootstrapping.
                if transport.is_available() {
                    // Run a quality probe.  This is a synchronous call here
                    // (the trait is sync) but individual transports may use
                    // cached measurements internally.
                    //
                    // `.map(|q| { ... })` transforms `Ok(quality)` into `Ok(bool)`.
                    //   - `q.reliability >= self.min_reliability`: true if reliable enough.
                    //   - `q.congestion <= self.max_congestion`: true if not too congested.
                    //   - Both must be true for `quality_ok` to be `true`.
                    //
                    // `.unwrap_or(false)` converts any `Err` (probe failure) to `false`,
                    // meaning we skip this transport in pass 1 but may try it in pass 2.
                    let quality_ok = transport
                        .measure_quality(target)
                        .map(|q| {
                            q.reliability >= self.min_reliability
                                && q.congestion <= self.max_congestion
                        })
                        .unwrap_or(false); // probe error → treat as failed quality check

                    if quality_ok {
                        // Quality is acceptable.  Attempt the actual connection.
                        // `if let Ok(conn) = transport.connect(target)` unpacks the
                        // Result: if connection succeeds, bind `conn` and return it.
                        // If connect() fails (rare but possible), fall through to the
                        // next transport type in the loop.
                        if let Ok(conn) = transport.connect(target) {
                            // Found a good connection — return immediately.
                            // We don't try remaining transports; the first success wins.
                            return Ok(conn);
                        }
                        // connect() failed despite good quality — unusual, but
                        // possible (e.g., peer is offline, firewall blocks us).
                        // Fall through to the next transport in pass 1.
                    }
                    // quality_ok was false → skip this transport in pass 1.
                    // It will still be tried in pass 2 below.
                }
                // is_available() was false → completely skip this transport.
                // An unavailable transport won't succeed in pass 2 either (we
                // still check is_available() there), so it's truly skipped.
            }
            // Transport not found in the map → skip silently (shouldn't happen).
        }

        // -----------------------------------------------------------------------
        // Pass 2: Fail-open — same order, but no quality gate.
        //
        // We reach this point only if EVERY transport in pass 1 was rejected
        // (bad quality probe, probe error, or connect() failure).
        //
        // We give each transport another chance, this time ignoring quality.
        // The anti-downgrade order is still respected — Tor is still tried
        // before Clearnet, so we don't inadvertently downgrade.
        // -----------------------------------------------------------------------
        for transport_type in preferred {
            if let Some(transport) = self.transports.get(transport_type) {
                if transport.is_available() {
                    // No quality check this time.  Just try to connect directly.
                    if let Ok(conn) = transport.connect(target) {
                        // Success in pass 2 — return the connection.
                        return Ok(conn);
                    }
                    // connect() failed — try the next transport.
                }
            }
        }

        // Both passes exhausted without success.
        // Every transport in `preferred` either was unavailable or failed to
        // connect.  Signal this with a dedicated error variant so callers can
        // handle "no route to peer" specifically.
        Err(crate::core::error::MeshInfinityError::NoAvailableTransport)
    }

    /// Retrieve a specific transport implementation by type.
    ///
    /// Returns `Some(Arc<dyn Transport>)` if a transport of that type was
    /// registered and initialized, or `None` otherwise.
    ///
    /// # Why `cloned()`?
    ///
    /// `self.transports.get(transport_type)` returns `Option<&Arc<dyn Transport>>`
    /// — a reference to an `Arc`.  But callers usually want an owned `Arc`
    /// they can store or pass around.
    ///
    /// `.cloned()` on an `Option<&Arc<T>>` calls `Arc::clone()` on the inner
    /// reference (which just increments the reference count) and returns
    /// `Option<Arc<T>>`.  This is cheap and does NOT copy the transport itself.
    pub fn get_transport(&self, transport_type: &TransportType) -> Option<Arc<dyn Transport>> {
        self.transports.get(transport_type).cloned()
    }

    /// Return the list of transport types currently registered in this manager.
    ///
    /// The order of the returned Vec is unspecified — HashMaps have no ordering
    /// guarantee.  If you need a specific order (e.g., anti-downgrade), use
    /// `TransportManagerImpl::enabled_transport_order()` instead.
    ///
    /// # Iterator chain
    ///
    /// `self.transports.keys()` iterates over the `TransportType` keys of the
    /// HashMap, yielding `&TransportType` references.
    ///
    /// `.copied()` dereferences each `&TransportType` into a plain `TransportType`
    /// value.  This works because `TransportType` implements the `Copy` trait
    /// (meaning it can be duplicated cheaply, like a plain integer).
    ///
    /// `.collect()` gathers all the values into a new `Vec<TransportType>`.
    pub fn available_transports(&self) -> Vec<TransportType> {
        self.transports.keys().copied().collect()
    }

    /// Measure the quality of a specific transport to a target peer.
    ///
    /// This is a thin delegation wrapper: it looks up the transport by type
    /// and calls its `measure_quality()` method.
    ///
    /// # When to use this vs. `get_best_connection`
    ///
    /// Use `get_best_connection` when you want to actually connect.
    /// Use `measure_quality` when you want to probe a transport without
    /// opening a connection — for example, to display signal-strength-style
    /// quality indicators in the UI.
    ///
    /// # Error on missing transport
    ///
    /// Returns `Err(TransportError(...))` if no transport of `transport_type`
    /// is registered.  This is a programming error (you should only measure
    /// transports you know are available), so the error message is descriptive.
    pub fn measure_quality(
        &self,
        target: &PeerInfo,
        transport_type: TransportType,
    ) -> Result<TransportQuality> {
        if let Some(transport) = self.transports.get(&transport_type) {
            // Delegate to the transport's own measurement implementation.
            transport.measure_quality(target)
        } else {
            // Transport type not found — likely a programming error (tried to
            // measure a transport that was never registered).
            Err(crate::core::error::MeshInfinityError::TransportError(
                format!("Transport type {:?} not available", transport_type),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// These tests verify the two-pass connection algorithm without touching any
// real network.  They use "test doubles" — fake objects that mimic the real
// Transport and Connection interfaces with configurable, predictable behaviour.
//
// The test doubles live in this `mod tests` block and are only compiled when
// running `cargo test` (the `#[cfg(test)]` attribute ensures this).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::traits::Listener;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;

    // --- Test double: a fake connection that always succeeds ---

    /// A minimal `Connection` implementation used only in tests.
    ///
    /// It records which peer it belongs to and pretends to send/receive data
    /// successfully without actually touching a network.  This lets tests
    /// verify that the right connection was returned without needing sockets.
    struct TestConnection {
        /// Stores which peer this connection pretends to be connected to.
        peer: PeerInfo,
    }

    impl Connection for TestConnection {
        /// Pretend to send all bytes successfully.
        ///
        /// Returns `Ok(data.len())` — claiming all bytes were sent — without
        /// actually writing anything anywhere.
        fn send(&mut self, data: &[u8]) -> Result<usize> {
            Ok(data.len())
        }

        /// Pretend there is no incoming data.
        ///
        /// Returns `Ok(0)` — zero bytes received — simulating a quiet connection.
        fn receive(&mut self, _buffer: &mut [u8]) -> Result<usize> {
            Ok(0)
        }

        /// Nothing to close on a fake connection.
        fn close(&mut self) -> Result<()> {
            Ok(())
        }

        /// Return the peer this connection is associated with.
        fn remote_peer(&self) -> &PeerInfo {
            &self.peer
        }

        /// Test connections are always considered active (not closed).
        fn is_active(&self) -> bool {
            true
        }
    }

    // --- Test double: a configurable fake transport ---

    /// A fake `Transport` whose behaviour is fully controlled by the test.
    ///
    /// Each field controls one aspect of the transport's behaviour:
    ///
    /// - `available`:     what `is_available()` returns.  Set to `false` to
    ///                    simulate a transport that is offline or bootstrapping.
    /// - `quality`:       the quality measurement to return from `measure_quality()`.
    ///                    `None` means "no quality data available" (combined with
    ///                    `probe_error = false`).
    /// - `probe_error`:   if `true`, `measure_quality()` returns an error instead
    ///                    of a quality value, simulating a probe timeout or failure.
    /// - `connect_ok`:    if `true`, `connect()` returns a `TestConnection`.
    ///                    if `false`, `connect()` returns an error.
    /// - `connect_calls`: an `AtomicUsize` counter incremented on every `connect()`
    ///                    call (success or failure), so tests can assert exactly
    ///                    how many times `connect` was invoked.
    ///
    /// # Why `AtomicUsize` for the counter?
    ///
    /// The `Transport` trait requires `connect(&self)` — a shared (immutable)
    /// reference.  We cannot mutate a plain `usize` field through `&self`.
    /// `AtomicUsize` allows mutation through a shared reference because its
    /// operations are inherently thread-safe.  This is a common Rust pattern
    /// for counters that need to be updated in a method that takes `&self`.
    struct TestTransport {
        /// Which type of transport this fake pretends to be.
        transport_type: TransportType,
        /// Whether the transport reports itself as available.
        available: bool,
        /// Pre-configured quality to return, or `None` for no data.
        quality: Option<TransportQuality>,
        /// If `true`, `measure_quality()` returns an error.
        probe_error: bool,
        /// If `true`, `connect()` succeeds; otherwise fails.
        connect_ok: bool,
        /// Atomic counter of `connect()` invocations.
        connect_calls: Arc<AtomicUsize>,
    }

    impl Transport for TestTransport {
        /// Simulate a connection attempt.
        ///
        /// Always increments `connect_calls` so tests can verify how many times
        /// the manager tried to connect through this transport.
        ///
        /// Returns a `TestConnection` if `connect_ok` is true, or an error otherwise.
        fn connect(&self, _peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
            // Increment the call counter atomically.
            // `fetch_add(1, Relaxed)` adds 1 to the counter and returns the old value.
            // We discard the return value here (just want the side effect of counting).
            self.connect_calls.fetch_add(1, AtomicOrdering::Relaxed);
            if self.connect_ok {
                Ok(Box::new(TestConnection {
                    peer: _peer_info.clone(),
                }))
            } else {
                Err(crate::core::error::MeshInfinityError::TransportError(
                    "connect fail".to_string(),
                ))
            }
        }

        /// Listening is not exercised in these unit tests.
        fn listen(&self) -> Result<Box<dyn Listener>> {
            Err(crate::core::error::MeshInfinityError::OperationNotSupported)
        }

        /// Return a fixed priority value (irrelevant for these tests).
        fn priority(&self) -> u8 {
            1
        }

        fn transport_type(&self) -> TransportType {
            self.transport_type
        }

        fn is_available(&self) -> bool {
            self.available
        }

        /// Return the pre-configured quality, or an error if `probe_error` is set.
        ///
        /// `self.quality.clone().ok_or_else(...)` converts `Option<Quality>` to
        /// `Result<Quality, Error>`:
        ///   - `Some(q)` → `Ok(q.clone())`
        ///   - `None`    → `Err(TransportError("no quality available"))`
        fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
            if self.probe_error {
                // Simulate a probe failure (timeout, network error, etc.)
                Err(crate::core::error::MeshInfinityError::TransportError(
                    "probe failed".to_string(),
                ))
            } else {
                // Return the pre-configured quality, or error if no quality was set.
                self.quality.clone().ok_or_else(|| {
                    crate::core::error::MeshInfinityError::TransportError(
                        "no quality available".to_string(),
                    )
                })
            }
        }
    }

    /// Build a deterministic `PeerInfo` fixture for use in tests.
    ///
    /// The peer advertises support for both Tor and Clearnet.
    /// All binary fields (peer_id, public_key) are filled with simple
    /// byte patterns so tests produce the same result every time they run.
    fn test_peer() -> PeerInfo {
        PeerInfo {
            peer_id: [1u8; 32],     // 32 bytes all set to 1 (deterministic ID)
            public_key: [2u8; 32],  // 32 bytes all set to 2
            trust_level: crate::core::TrustLevel::Caution,
            available_transports: vec![TransportType::Tor, TransportType::Clearnet],
            last_seen: None,
            endpoint: None,
            transport_endpoints: std::collections::HashMap::new(),
        }
    }

    /// Build a `TransportQuality` fixture with the given reliability and congestion.
    ///
    /// The other fields (latency, bandwidth, cost) are set to plausible constants
    /// and are not the focus of these tests.
    fn quality(reliability: f32, congestion: f32) -> Result<TransportQuality> {
        Ok(TransportQuality {
            latency: Duration::from_millis(50),
            bandwidth: 1_000_000,
            reliability,
            cost: 0.2,
            congestion,
        })
    }

    #[tokio::test]
    /// Verify that a transport with quality below the threshold is skipped in pass 1
    /// and the manager falls over to the next transport in the list.
    ///
    /// # Test setup
    ///
    ///   - Tor:      available = true, reliability = 0.10
    ///               (0.10 < min_reliability of 0.35 → SKIPPED in pass 1)
    ///   - Clearnet: available = true, reliability = 0.95
    ///               (0.95 ≥ 0.35 → passes quality gate)
    ///
    /// # Expected behaviour
    ///
    ///   - Pass 1: Tor is examined but skipped (bad quality).
    ///             Clearnet passes the quality gate and `connect()` is called.
    ///   - Pass 2 is never reached because Clearnet succeeded in pass 1.
    ///
    ///   - `tor_calls` should be 0 (connect was never called on Tor).
    ///   - `clearnet_calls` should be 1 (connect was called once on Clearnet).
    async fn get_best_connection_skips_low_quality_and_fails_over() {
        let mut manager = TransportManager::new();
        // Atomic counters shared between the test transport and this test function.
        // `Arc::clone` gives both the transport struct AND the assertion below
        // a reference to the same counter.
        let tor_calls = Arc::new(AtomicUsize::new(0));
        let clearnet_calls = Arc::new(AtomicUsize::new(0));

        // Register a Tor transport that has poor reliability (0.10 < 0.35 threshold).
        manager.transports.insert(
            TransportType::Tor,
            Arc::new(TestTransport {
                transport_type: TransportType::Tor,
                available: true,
                quality: quality(0.10, 0.20).ok(), // low reliability → should fail pass 1
                probe_error: false,
                connect_ok: true,                   // would succeed if tried
                connect_calls: Arc::clone(&tor_calls),
            }),
        );
        // Register a Clearnet transport with excellent quality.
        manager.transports.insert(
            TransportType::Clearnet,
            Arc::new(TestTransport {
                transport_type: TransportType::Clearnet,
                available: true,
                quality: quality(0.95, 0.10).ok(), // high reliability → should pass
                probe_error: false,
                connect_ok: true,
                connect_calls: Arc::clone(&clearnet_calls),
            }),
        );

        let peer = test_peer();
        // Request a connection, preferring Tor first (anti-downgrade order).
        let _conn = manager
            .get_best_connection(&peer, &[TransportType::Tor, TransportType::Clearnet])
            .await
            .expect("must connect via fallback transport");

        // Tor's connect() was NEVER called — it was skipped in pass 1 due to
        // bad quality, and pass 2 was never reached because Clearnet succeeded.
        assert_eq!(tor_calls.load(AtomicOrdering::Relaxed), 0);
        // Clearnet's connect() was called exactly once (in pass 1).
        assert_eq!(clearnet_calls.load(AtomicOrdering::Relaxed), 1);
    }

    #[tokio::test]
    /// Verify the fail-open pass 2 behaviour: when the quality probe returns an
    /// error, the manager should still try `connect()` in pass 2.
    ///
    /// # Test setup
    ///
    ///   - Tor: available = true, probe_error = true (probe fails entirely)
    ///          → skipped in pass 1 because `measure_quality()` returns Err
    ///          → BUT connect_ok = true → should succeed in pass 2
    ///
    /// # Expected behaviour
    ///
    ///   - Pass 1: Tor probe fails → `quality_ok = false` → Tor skipped.
    ///   - Pass 2: Tor is tried without quality check → `connect()` called → success.
    ///   - `tor_calls` should be 1 (connect called once, in pass 2).
    async fn get_best_connection_fail_open_when_quality_probe_fails() {
        let mut manager = TransportManager::new();
        let tor_calls = Arc::new(AtomicUsize::new(0));

        manager.transports.insert(
            TransportType::Tor,
            Arc::new(TestTransport {
                transport_type: TransportType::Tor,
                available: true,
                quality: None,     // no quality data (irrelevant since probe_error=true)
                probe_error: true, // probe returns an error → skipped in pass 1
                connect_ok: true,  // but actual connect works → succeeds in pass 2
                connect_calls: Arc::clone(&tor_calls),
            }),
        );

        let peer = test_peer();
        let _conn = manager
            .get_best_connection(&peer, &[TransportType::Tor])
            .await
            .expect("should fail-open when probes unavailable");

        // connect() was called exactly once — in the fail-open pass 2.
        // It was NOT called in pass 1 (probe_error caused the skip).
        assert_eq!(tor_calls.load(AtomicOrdering::Relaxed), 1);
    }
}
