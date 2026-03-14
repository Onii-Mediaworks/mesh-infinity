//! Transport policy façade and runtime toggle ownership.
//!
//! # What does this module do?
//!
//! Think of this module as the "control panel" for all the different ways
//! Mesh Infinity can talk to other peers across a network.
//!
//! A **transport** is simply one method of sending data from one device to
//! another.  Just like you might choose to call someone on the phone, send a
//! letter, or walk over in person, Mesh Infinity can reach another peer in
//! several different ways depending on what is available:
//!
//!   - **Tor**       – routes traffic through the Tor anonymity network
//!                     (high privacy, hides your IP address)
//!   - **I2P**       – uses a custom encrypted overlay protocol inspired by
//!                     the I2P design (good privacy, lower latency than Tor)
//!   - **Bluetooth** – direct device-to-device radio link (no internet needed)
//!   - **RF**        – radio-frequency mesh link (no internet needed)
//!   - **Clearnet**  – ordinary internet TCP, the same as a regular web request
//!                     (fastest, but your IP address is visible)
//!
//! This module owns the on/off switches (enabled flags) for each transport and
//! enforces the "anti-downgrade order" (see below).  The actual work of opening
//! connections and measuring quality is delegated to [`TransportManager`]
//! (in `core_manager.rs`).
//!
//! # What is "anti-downgrade ordering"?
//!
//! Imagine a scenario where both Tor *and* clearnet are enabled.  If the code
//! were allowed to just pick whichever transport is fastest in the moment, it
//! might silently switch from Tor to clearnet — revealing your IP address
//! without any warning.  That is called a "downgrade attack" (or accidental
//! downgrade).  It is called a "downgrade" because you are downgrading from a
//! more secure transport to a less secure one.
//!
//! To prevent this, we always try the more-private transports *first*, in a
//! fixed priority order:
//!
//!   Tor → I2P → Bluetooth → RF → Clearnet
//!
//! Clearnet is always last.  No matter how congested Tor is, the code will not
//! automatically jump to clearnet unless Tor truly cannot connect *and* clearnet
//! was explicitly enabled by the user.
//!
//! # What is a "factory"?
//!
//! A factory (the `TransportFactory` trait) is a simple object whose only job is
//! to create a new transport instance on demand.
//!
//! Instead of hard-coding `TorTransport::new()` directly in the manager, we
//! register a `TorTransportFactory` with the manager.  This pattern has several
//! advantages:
//!   - The manager never needs to know the concrete transport types at
//!     construction time.  It only calls `factory.create_transport()`.
//!   - Adding a new transport only requires implementing `TransportFactory` for
//!     it — you don't have to change the manager itself.
//!   - In tests, we can swap in fake factories without touching the manager code.
//!     This is called "dependency injection" or the *Factory pattern*.
//!
//! Think of a factory like a cookie cutter: the cutter (factory) is the
//! blueprint; the cookies (transport instances) are what it produces.
//!
//! # Why `AtomicBool` instead of `Mutex<bool>`?
//!
//! Both `AtomicBool` and `Mutex<bool>` allow a boolean flag to be safely shared
//! and updated by multiple threads simultaneously.  The difference is cost:
//!
//!   - `Mutex<bool>` uses an operating-system lock.  Acquiring and releasing a
//!     Mutex involves a system call, which can take microseconds and can block
//!     the thread if another thread is already holding the lock.
//!   - `AtomicBool` uses a single CPU instruction to read or write the value.
//!     It never blocks.  It is hundreds of times faster for a simple flag.
//!
//! For a simple "is Tor enabled?" check that happens thousands of times per
//! second, `AtomicBool` is the right choice.  We only pay the heavier Mutex
//! cost when we need to protect a complex data structure like a HashMap.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::core::core::TransportType;
use crate::transport::core_manager::TransportManager;
use crate::transport::traits::{Transport, TransportFactory};

use super::{BluetoothTransport, ClearnetTransport, I2pTransport, RfTransport, TorTransport};

/// The high-level transport control panel.
///
/// `TransportManagerImpl` owns:
/// 1. A reference to the *core manager* (`inner`) that does the actual
///    connection work (see `core_manager.rs`).
/// 2. A set of atomic boolean flags, one per transport, that say whether
///    that transport is currently allowed by the user's settings.
///
/// The word "Impl" (short for "Implementation") is a Rust convention to
/// distinguish the concrete struct from an abstract interface (trait).
/// For example, you might have a `TransportManager` trait and a
/// `TransportManagerImpl` struct that implements it.
///
/// # Thread safety
///
/// Because all state is either behind an `Arc<AtomicBool>` or an `Arc<Mutex<...>>`,
/// `TransportManagerImpl` is safe to share across multiple threads.
/// The UI thread can call `set_tor_enabled()` at the same moment the networking
/// thread calls `enabled_transport_order()` — they will not interfere.
pub struct TransportManagerImpl {
    /// The underlying engine that handles connection selection and quality probes.
    ///
    /// `Arc` stands for "Atomic Reference Counting".  It is a smart pointer
    /// that wraps a value so it can be shared (not just borrowed) by multiple
    /// owners at the same time.  Internally, it keeps a count of how many
    /// `Arc` pointers currently point to the same value.  When the last `Arc`
    /// is dropped (goes out of scope), the value is freed automatically.
    ///
    /// Cloning an `Arc` is very cheap — it just increments the counter by 1.
    /// It does NOT copy the `TransportManager` itself.
    inner: Arc<TransportManager>,

    /// Whether the Tor transport is currently enabled.
    ///
    /// `AtomicBool` is a boolean (`true`/`false`) that can be safely read and
    /// written by multiple threads at the same time without a lock.
    ///
    /// A plain `bool` in Rust is NOT safe to share across threads because two
    /// threads could try to change it simultaneously, causing unpredictable
    /// results (called a "data race").  `AtomicBool` uses special CPU-level
    /// instructions (like `LOCK XCHG` on x86) that make reads and writes
    /// happen atomically — as a single indivisible operation — so there is
    /// no race condition.
    ///
    /// The value is also wrapped in `Arc` so it can be handed to background
    /// threads that need to check or update the flag.
    tor_enabled: Arc<AtomicBool>,

    /// Whether ordinary internet (clearnet) connections are currently enabled.
    ///
    /// "Clearnet" means standard TCP/IP without any anonymization layer.
    /// When this is true, the app can connect to peers using their real IP
    /// addresses over the public internet.
    clearnet_enabled: Arc<AtomicBool>,

    /// Whether the custom I2P-style encrypted overlay is currently enabled.
    ///
    /// See `i2p.rs` for a full explanation of what this transport does.
    i2p_enabled: Arc<AtomicBool>,

    /// Whether Bluetooth radio links are currently enabled.
    ///
    /// When enabled, Mesh Infinity can communicate with nearby peers directly
    /// over Bluetooth without going through the internet at all.  This is
    /// useful in offline scenarios (e.g., a local mesh network).
    bluetooth_enabled: Arc<AtomicBool>,

    /// Whether RF (radio frequency) mesh links are currently enabled.
    ///
    /// Similar to Bluetooth, but using longer-range radio hardware.  Also
    /// works without internet connectivity.
    rf_enabled: Arc<AtomicBool>,
}

impl Default for TransportManagerImpl {
    /// Rust's `Default` trait lets callers write `TransportManagerImpl::default()`
    /// as an alias for `TransportManagerImpl::new()`.
    ///
    /// This is a common Rust convention: when there is a sensible zero-config
    /// starting state, implement `Default` so libraries and test helpers can
    /// create instances without knowing the constructor name.  Many Rust macros
    /// (like `#[derive(Default)]` on containing structs) also use this trait.
    fn default() -> Self {
        Self::new()
    }
}

impl TransportManagerImpl {
    /// Build a fully wired-up transport manager.
    ///
    /// This function:
    /// 1. Creates the core [`TransportManager`] engine (the "engine room").
    /// 2. Sets up the initial enabled/disabled state for each transport.
    ///    - Tor and clearnet are **on by default** because they require no
    ///      special hardware and cover most use cases.
    ///    - I2P, Bluetooth, and RF are **off by default** because they are
    ///      either experimental or depend on specific hardware being present.
    /// 3. Registers a factory for every transport type so the core manager
    ///    knows how to create transport instances.  Think of this as handing
    ///    the engine room its set of recipe cards.
    /// 4. Calls `initialize_transports()`, which calls each factory once and
    ///    stores the resulting transport object so it is ready for use.
    ///
    /// # Panics
    ///
    /// Panics if `initialize_transports()` fails.  This is intentional:
    /// a misconfigured transport is a programming error, not something the
    /// user or calling code should try to recover from at runtime.
    pub fn new() -> Self {
        let mut manager = TransportManager::new();

        // --- Default enabled/disabled state ---
        //
        // `Arc::new(AtomicBool::new(true))` does two things:
        //   1. `AtomicBool::new(true)` creates an atomic boolean with initial value `true`.
        //   2. `Arc::new(...)` wraps it in a reference-counted smart pointer so it
        //      can be shared across threads cheaply via `Arc::clone`.
        let tor_enabled = Arc::new(AtomicBool::new(true));      // Tor on by default
        let clearnet_enabled = Arc::new(AtomicBool::new(true)); // Clearnet on by default
        let i2p_enabled = Arc::new(AtomicBool::new(false));     // I2P off by default
        let bluetooth_enabled = Arc::new(AtomicBool::new(false)); // Bluetooth off by default
        let rf_enabled = Arc::new(AtomicBool::new(false));      // RF off by default

        // --- Register one factory per transport type ---
        //
        // `Box::new(TorTransportFactory)` allocates the factory struct on the heap
        // (rather than the call stack) and returns a pointer to it.  The `Box`
        // type is Rust's simplest heap-allocation wrapper.
        //
        // `Box<dyn TransportFactory>` erases the concrete type — the manager
        // only needs to know that the thing inside the Box implements the
        // `TransportFactory` trait.  This is called "type erasure" or using a
        // "trait object".  It lets us store factories for completely different
        // transport types (Tor, I2P, Bluetooth...) in the same HashMap, because
        // they all share the same trait interface.
        manager.register_transport_factory(Box::new(TorTransportFactory));
        manager.register_transport_factory(Box::new(ClearnetTransportFactory));
        manager.register_transport_factory(Box::new(I2pTransportFactory));
        manager.register_transport_factory(Box::new(BluetoothTransportFactory));
        manager.register_transport_factory(Box::new(RfTransportFactory));

        // --- Instantiate each transport from its factory ---
        //
        // `initialize_transports()` iterates all registered factories and calls
        // `create_transport()` on each one.  The resulting transport objects are
        // stored in the manager's internal `transports` HashMap, ready to be
        // used when a connection is needed.
        //
        // `.expect("...")` is shorthand for `.unwrap_or_else(|e| panic!("{}: {}", msg, e))`.
        // If initialization fails, we panic immediately with the given message.
        // A panic in `new()` means the whole application startup fails, which is
        // correct behaviour for a fundamental setup error.
        manager
            .initialize_transports()
            .expect("Failed to initialize transports");

        Self {
            inner: Arc::new(manager),
            tor_enabled,
            clearnet_enabled,
            i2p_enabled,
            bluetooth_enabled,
            rf_enabled,
        }
    }

    /// Return a shared handle to the underlying core transport manager.
    ///
    /// `Arc::clone(&self.inner)` does NOT copy the `TransportManager`.  It
    /// increments the reference count inside the `Arc` by 1 and returns a new
    /// `Arc` pointer to the same manager.  Both the original and the clone
    /// point to the same memory.  The `TransportManager` will be freed only
    /// when every single `Arc` clone is dropped.
    ///
    /// The returned handle can be used to call `get_best_connection()`,
    /// `measure_quality()`, or any other core manager method.
    pub fn get_manager(&self) -> Arc<TransportManager> {
        Arc::clone(&self.inner)
    }

    /// Check whether a specific transport is currently enabled by local policy.
    ///
    /// # `Ordering::Relaxed` explained
    ///
    /// Rust's atomic operations require you to specify a *memory ordering*,
    /// which tells the CPU and compiler how to handle the ordering of this
    /// operation relative to surrounding memory operations.
    ///
    /// `Ordering::Relaxed` is the weakest (cheapest) guarantee:
    ///   - The load will be atomic (no partial reads).
    ///   - The load will eventually see the most recent value written by any thread.
    ///   - BUT: no constraints are placed on how other memory operations around
    ///     this load may be reordered.
    ///
    /// For a simple flag like "is Tor enabled?" this is perfectly safe.  We
    /// are just reading a boolean — we don't need the read to synchronize
    /// anything else.  Using a stronger ordering (like `SeqCst`) would be
    /// wasteful: it is correct but slower.
    ///
    /// # Match arms
    ///
    /// A `match` in Rust is like a `switch` statement in other languages, but
    /// it is exhaustive — you must handle every possible value of the type.
    /// Here each arm handles one variant of the `TransportType` enum and loads
    /// the corresponding `AtomicBool`.
    pub fn is_transport_enabled(&self, transport: TransportType) -> bool {
        match transport {
            // `.load(Ordering::Relaxed)` reads the current boolean value atomically.
            TransportType::Tor       => self.tor_enabled.load(Ordering::Relaxed),
            TransportType::I2P       => self.i2p_enabled.load(Ordering::Relaxed),
            TransportType::Bluetooth => self.bluetooth_enabled.load(Ordering::Relaxed),
            TransportType::Rf        => self.rf_enabled.load(Ordering::Relaxed),
            TransportType::Clearnet  => self.clearnet_enabled.load(Ordering::Relaxed),
        }
    }

    /// Enable or disable the Tor transport.
    ///
    /// `.store(enabled, Ordering::Relaxed)` atomically writes the new value.
    ///
    /// Because `tor_enabled` is behind an `Arc`, multiple threads can call
    /// `set_tor_enabled` safely at any time without a lock.  For example:
    ///   - The UI thread may call `set_tor_enabled(false)` when the user
    ///     flips a toggle switch in the settings screen.
    ///   - The networking thread may simultaneously be calling
    ///     `is_transport_enabled(TransportType::Tor)`.
    /// Both operations are atomic, so there is no race condition.
    ///
    /// # Effect on existing connections
    ///
    /// Disabling a transport does NOT close existing connections made through
    /// it.  It only prevents *new* connections from being made via Tor.  The
    /// service layer is responsible for tearing down existing connections if
    /// needed.
    pub fn set_tor_enabled(&self, enabled: bool) {
        self.tor_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Enable or disable clearnet (ordinary internet TCP) connections.
    ///
    /// Disabling clearnet forces all traffic through privacy-preserving
    /// transports (Tor, I2P, Bluetooth, RF).  This is useful for users who
    /// want to be certain their IP address is never revealed.
    pub fn set_clearnet_enabled(&self, enabled: bool) {
        self.clearnet_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Enable or disable the custom I2P-style encrypted overlay transport.
    pub fn set_i2p_enabled(&self, enabled: bool) {
        self.i2p_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Enable or disable Bluetooth radio transport.
    pub fn set_bluetooth_enabled(&self, enabled: bool) {
        self.bluetooth_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Enable or disable RF (radio frequency) mesh transport.
    pub fn set_rf_enabled(&self, enabled: bool) {
        self.rf_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Return the list of currently-enabled transports in anti-downgrade order.
    ///
    /// "Anti-downgrade order" means privacy-preserving transports always come
    /// before clearnet in the returned list.  Even if clearnet would be faster
    /// right now, callers that iterate this list will always try Tor first,
    /// then I2P, then Bluetooth, then RF, and only fall back to clearnet as
    /// the very last resort.
    ///
    /// Transports that are disabled are simply omitted from the list entirely —
    /// they are not placed at a lower priority; they do not appear at all.
    ///
    /// # Return type
    ///
    /// `Vec<TransportType>` is a "vector" — a growable array on the heap.
    /// The returned Vec may have 0–5 entries depending on how many transports
    /// are currently enabled.  An empty Vec means nothing is enabled (the app
    /// cannot connect to any peer).
    ///
    /// # Why not sort dynamically by speed?
    ///
    /// You might wonder: why not put the fastest transport first?  Because
    /// "fastest" changes constantly and is hard to measure accurately.  More
    /// importantly, if we allowed dynamic reordering, Tor could silently lose
    /// its priority position during a temporary slowdown, leaking the user's
    /// IP on clearnet without them realising.  A fixed privacy-first order
    /// makes the security guarantee easy to reason about.
    pub fn enabled_transport_order(&self) -> Vec<TransportType> {
        // Pre-allocate space for up to 5 entries (one per transport type).
        // `with_capacity` tells Rust how much memory to reserve upfront so
        // the Vec won't need to reallocate as we push entries.
        let mut ordered = Vec::with_capacity(5);

        // Privacy-first: Tor is the highest-priority transport.
        // We only push it if the AtomicBool is true (transport is enabled).
        if self.tor_enabled.load(Ordering::Relaxed) {
            ordered.push(TransportType::Tor);
        }
        // Second priority: our custom I2P-style encrypted overlay.
        if self.i2p_enabled.load(Ordering::Relaxed) {
            ordered.push(TransportType::I2P);
        }
        // Third: Bluetooth (local radio, no internet required).
        if self.bluetooth_enabled.load(Ordering::Relaxed) {
            ordered.push(TransportType::Bluetooth);
        }
        // Fourth: RF mesh links (also no internet required).
        if self.rf_enabled.load(Ordering::Relaxed) {
            ordered.push(TransportType::Rf);
        }
        // Last resort: clearnet — ordinary internet without any anonymization.
        // This must always be pushed last, after all privacy transports.
        if self.clearnet_enabled.load(Ordering::Relaxed) {
            ordered.push(TransportType::Clearnet);
        }

        ordered
    }

    /// Return the enabled transports filtered to only those the *peer* supports.
    ///
    /// When connecting to a specific peer, we need the intersection of:
    ///   - What WE have enabled (anti-downgrade ordered list above), AND
    ///   - What THE PEER advertises as supported (the `available` slice).
    ///
    /// There is no point in trying Tor if the peer doesn't have a Tor endpoint,
    /// so we filter out transports the peer doesn't support.
    ///
    /// Crucially, the filter preserves anti-downgrade order: our own ordering
    /// takes precedence over the order the peer listed its capabilities.
    ///
    /// # Example
    ///
    /// We have [Tor, I2P, Clearnet] enabled.
    /// The peer says it supports [Clearnet, Tor] (peer's order doesn't matter).
    /// Result: [Tor, Clearnet]
    ///   - I2P is dropped because the peer doesn't support it.
    ///   - Tor comes before Clearnet because of our anti-downgrade policy.
    ///
    /// # Iterator chain explained
    ///
    /// `.into_iter()` consumes the Vec from `enabled_transport_order()` and
    /// produces an iterator over its elements one by one.
    ///
    /// `.filter(|t| available.contains(t))` keeps only elements where the
    /// closure returns `true`.  The `|t|` syntax declares a closure parameter
    /// named `t`; `available.contains(t)` returns true if `t` is in `available`.
    ///
    /// `.collect()` gathers the surviving elements back into a new Vec.
    pub fn enabled_transport_order_for_available(
        &self,
        available: &[TransportType],
    ) -> Vec<TransportType> {
        self.enabled_transport_order()
            .into_iter()
            // Keep only transports that the peer's capability list includes.
            .filter(|t| available.contains(t))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Transport Factories
// ---------------------------------------------------------------------------
//
// Each factory below is a tiny, stateless struct that implements the
// `TransportFactory` trait.  The two methods required by the trait are:
//   - `create_transport()` — build and return a new transport instance
//   - `transport_type()`   — identify which `TransportType` this factory makes
//
// "Stateless" means the factory struct has no fields — it holds no data.
// Its only purpose is to be a named thing that implements `create_transport()`.
// In Rust, a zero-field struct like `pub struct TorTransportFactory;` is
// valid and costs zero bytes at runtime.
//
// Having one factory per transport keeps the registration code in `new()`
// simple and uniform, and makes it trivial to add new transports in the
// future (implement the trait, register the factory — done).

/// Factory that produces [`TorTransport`] instances.
///
/// This struct is purely a token — it has no data.  Its only purpose is to
/// provide a named implementation of `TransportFactory` for the Tor transport.
pub struct TorTransportFactory;

impl TransportFactory for TorTransportFactory {
    /// Construct a new Tor transport and return it as a trait object.
    ///
    /// `Box::new(TorTransport::new())` allocates the transport on the heap.
    ///
    /// The return type `Box<dyn Transport>` is a "trait object" — a pointer to
    /// heap memory where the actual data lives, paired with a vtable (a table
    /// of function pointers) that lets Rust call the right `Transport` methods
    /// at runtime even though the concrete type is erased.
    ///
    /// Callers that receive this `Box<dyn Transport>` can call `connect()`,
    /// `is_available()`, etc., without knowing they are talking to a
    /// `TorTransport` specifically.
    fn create_transport(&self) -> Box<dyn Transport> {
        Box::new(TorTransport::new())
    }

    /// Tell the manager this factory produces Tor transports.
    ///
    /// The manager uses this to store the factory under the right key in its
    /// `factories` HashMap so it can look it up by `TransportType` later.
    fn transport_type(&self) -> TransportType {
        TransportType::Tor
    }
}

/// Factory that produces [`ClearnetTransport`] instances.
///
/// "Clearnet" refers to the regular, unencrypted-at-the-transport-layer internet —
/// the same kind of TCP connection your browser makes when visiting a website.
pub struct ClearnetTransportFactory;

impl TransportFactory for ClearnetTransportFactory {
    /// Construct a new clearnet (plain TCP) transport.
    fn create_transport(&self) -> Box<dyn Transport> {
        Box::new(ClearnetTransport::new())
    }

    /// Tell the manager this factory produces clearnet transports.
    fn transport_type(&self) -> TransportType {
        TransportType::Clearnet
    }
}

/// Factory that produces [`I2pTransport`] instances.
///
/// Note: this is Mesh Infinity's *custom* I2P-style encrypted overlay, not
/// the external I2P network.  See `i2p.rs` for a full explanation.
pub struct I2pTransportFactory;

impl TransportFactory for I2pTransportFactory {
    /// Construct a new I2P-style encrypted overlay transport.
    fn create_transport(&self) -> Box<dyn Transport> {
        Box::new(I2pTransport::new())
    }

    /// Tell the manager this factory produces I2P transports.
    fn transport_type(&self) -> TransportType {
        TransportType::I2P
    }
}

/// Factory that produces [`BluetoothTransport`] instances.
pub struct BluetoothTransportFactory;

impl TransportFactory for BluetoothTransportFactory {
    /// Construct a new Bluetooth radio transport.
    fn create_transport(&self) -> Box<dyn Transport> {
        Box::new(BluetoothTransport::new())
    }

    /// Tell the manager this factory produces Bluetooth transports.
    fn transport_type(&self) -> TransportType {
        TransportType::Bluetooth
    }
}

/// Factory that produces [`RfTransport`] instances.
pub struct RfTransportFactory;

impl TransportFactory for RfTransportFactory {
    /// Construct a new RF (radio frequency) mesh transport.
    fn create_transport(&self) -> Box<dyn Transport> {
        Box::new(RfTransport::new())
    }

    /// Tell the manager this factory produces RF transports.
    fn transport_type(&self) -> TransportType {
        TransportType::Rf
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// The `#[cfg(test)]` attribute tells the Rust compiler: "only compile
// this module when running `cargo test`".  It is stripped out of release
// builds, so test code never ends up in the shipped binary.
//
// `mod tests { use super::*; }` imports everything from the parent module
// (i.e., everything in this file) into the test module's scope.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Verify that the anti-downgrade order is correct when all transports are enabled.
    ///
    /// Expected order: Tor → I2P → Bluetooth → RF → Clearnet.
    /// Clearnet must always be last, no matter what.
    ///
    /// If this test fails it means something changed the ordering logic in
    /// `enabled_transport_order()` — that is a security-relevant change and
    /// should be reviewed carefully before merging.
    fn enabled_transport_order_prefers_privacy_transports() {
        let manager = TransportManagerImpl::new();
        // Turn everything on so we can see the full ordering.
        manager.set_tor_enabled(true);
        manager.set_i2p_enabled(true);
        manager.set_bluetooth_enabled(true);
        manager.set_rf_enabled(true);
        manager.set_clearnet_enabled(true);

        let order = manager.enabled_transport_order();
        // `assert_eq!(left, right)` panics with a helpful message if they differ.
        assert_eq!(
            order,
            vec![
                TransportType::Tor,
                TransportType::I2P,
                TransportType::Bluetooth,
                TransportType::Rf,
                TransportType::Clearnet,
            ]
        );
    }

    #[test]
    /// Verify that filtering by peer availability preserves the anti-downgrade ordering.
    ///
    /// Scenario: we have Tor, I2P, and Clearnet enabled (Bluetooth off).
    /// The peer only advertises support for Clearnet and Tor.
    ///
    /// Expected result: [Tor, Clearnet]
    ///   - I2P is dropped because the peer doesn't support it.
    ///   - Tor still comes before Clearnet because our anti-downgrade policy
    ///     always puts more-private transports first.  The peer's ordering
    ///     ([Clearnet, Tor]) is irrelevant — OUR ordering wins.
    fn enabled_transport_order_for_available_filters_without_downgrade() {
        let manager = TransportManagerImpl::new();
        manager.set_tor_enabled(true);
        manager.set_i2p_enabled(true);
        manager.set_bluetooth_enabled(false);
        manager.set_clearnet_enabled(true);

        // Peer says it supports Clearnet and Tor (in any order — the peer list
        // order doesn't matter; our own ordering takes precedence).
        let available = vec![TransportType::Clearnet, TransportType::Tor];
        let order = manager.enabled_transport_order_for_available(&available);

        // I2P is dropped because the peer doesn't support it.
        // Tor comes before Clearnet because of anti-downgrade policy.
        assert_eq!(order, vec![TransportType::Tor, TransportType::Clearnet]);
    }
}
