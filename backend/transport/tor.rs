//! Tor transport via arti-client.
//!
//! # What is Tor?
//!
//! Tor (The Onion Router) is a network of thousands of volunteer-operated
//! servers ("relays") scattered around the world.  When you connect to
//! something through Tor, your traffic is encrypted in multiple layers (like
//! the layers of an onion) and bounced through a chain of three relays before
//! reaching its destination.  Each relay only knows about the previous and
//! the next hop — no single relay can tell both who you are AND where you're
//! going.  This makes it very difficult for anyone on the network (or even the
//! Tor relays themselves) to figure out your real IP address.
//!
//! To visualise: normally when you send a message over the internet, the path
//! is:  Your Device → (your IP is visible to everyone) → Destination.
//!
//! With Tor the path is:
//!   Your Device
//!     → Relay 1 (knows your IP, but not the destination or the message)
//!       → Relay 2 (knows Relay 1, but not you or the destination)
//!         → Relay 3 / Exit (knows the destination, but not your IP)
//!           → Destination
//!
//! Tor also supports **hidden services** (also called `.onion` addresses).
//! A hidden service is a server that lives entirely inside the Tor network —
//! it has a long, cryptographically-derived address like `abc123....onion`
//! instead of a normal hostname.  Both the client and the server route traffic
//! through Tor relays, so neither side ever learns the other's real IP address.
//! This is even more private than using Tor to reach a normal website.
//!
//! # Why arti-client?
//!
//! The classic Tor implementation is written in C (the `tor` daemon).  To use
//! it from a desktop app, you would have to:
//!   1. Start a separate `tor` process on the user's machine.
//!   2. Manage its lifecycle (start, stop, restart on failure).
//!   3. Communicate with it over a local "control port" (a special socket).
//!   4. Ship the `tor` binary alongside your app.
//!
//! That is complex, fragile, and platform-specific.
//!
//! `arti` is a complete, production-grade Tor implementation written in pure
//! Rust, maintained by the Tor Project itself.  `arti-client` is its high-level
//! API crate.  By depending on `arti-client`, Mesh Infinity gets an
//! **embedded Tor client** — the Tor circuits run inside the same Rust process
//! as the rest of the app, with no separate process, no daemon, and no control
//! port.
//!
//! # What is "bootstrapping"?
//!
//! Before Tor can route any traffic, it needs to do some setup work:
//! 1. **Download a consensus document** from directory servers — this is a
//!    cryptographically signed list of all known relays in the Tor network.
//!    Without it, the client doesn't know which servers to connect through.
//! 2. **Build circuits** — select three relays and establish encrypted tunnels
//!    to them (a "circuit").
//! 3. **Verify cryptographic signatures** to make sure the directory data
//!    hasn't been tampered with.
//!
//! This process is called *bootstrapping*.  On a healthy internet connection,
//! it typically takes 5–15 seconds.  Until bootstrapping is complete, you
//! cannot route any traffic through Tor — the client simply has no circuits.
//!
//! `TorTransport::bootstrap()` performs all of this and only returns once
//! the client is fully ready to use.
//!
//! During startup, `TorTransport::new()` creates the transport in an
//! *unbootstrapped* state (no Tor client yet) so it can be registered with
//! the manager immediately.  The service layer then calls `bootstrap()`
//! asynchronously when the user enables Tor, and `is_available()` flips to
//! `true` when done.
//!
//! # The synchronous/async boundary — why `block_in_place`?
//!
//! Rust has two flavours of code:
//!   - **Synchronous** (`fn`): runs step by step, may block the thread.
//!   - **Asynchronous** (`async fn`): returns a `Future` that must be `.await`-ed;
//!     never blocks the thread — Tokio runs many async tasks on a small pool of
//!     threads by interleaving them.
//!
//! The `Transport` trait defines `connect()` as a *synchronous* function.
//! But `TorClient::connect()` (from the `arti-client` crate) is an `async fn`
//! that internally does multiple network round-trips — it *must* be awaited.
//!
//! We bridge this mismatch using `tokio::task::block_in_place` combined with
//! `Handle::block_on`:
//!
//!   - `block_in_place(|| { ... })` tells Tokio: "I am about to do blocking
//!     work.  Please temporarily move other async tasks to other threads so
//!     this thread can block without starving the rest of the system."
//!   - `handle.block_on(async { ... })` runs an async block to completion on
//!     the current thread, blocking until it finishes.
//!
//! Together, they let a synchronous function run an async operation without
//! starving the Tokio task scheduler.
//!
//! # Inbound connections (hidden services)
//!
//! Receiving inbound Tor connections requires creating a **v3 onion service**
//! with a persistent private key (so the `.onion` address stays the same across
//! restarts).  Setting this up requires key management that is not yet
//! implemented.  `listen()` returns an error for now — Tor is currently
//! outbound-only.

use std::sync::{Arc, Mutex};
use std::time::Duration;

// `arti_client::DataStream` — a Tor-anonymized byte stream, similar to TcpStream.
// `arti_client::TorClient`  — the main Tor client object; manages circuits.
// `arti_client::TorClientConfig` — configuration for the Tor client.
use arti_client::{DataStream, TorClient, TorClientConfig};

// `AsyncReadExt` / `AsyncWriteExt` — extension traits that add `read()` and
// `write_all()` methods to async I/O objects like `DataStream`.
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// `Handle` — a reference to a running Tokio async runtime.  Allows synchronous
// code to submit work to the async runtime via `handle.block_on(...)`.
use tokio::runtime::Handle;

// `PreferredRuntime` — arti's way of saying "use the best async runtime
// available on this platform".  In practice this is always Tokio.
use tor_rtcompat::PreferredRuntime;

use crate::core::core::{PeerInfo, TransportQuality, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::transport::traits::{Connection, Listener, Transport};

/// A transport that routes all connections through the Tor anonymity network.
///
/// # Lifecycle
///
/// 1. **Created** via `TorTransport::new()`.
///    At this point there is no Tor client (`client` is `None`).
///    `is_available()` returns `false`.
///    The transport manager registers it anyway so it appears in the transport
///    list — it just won't be selected for connections until bootstrapping.
///
/// 2. **Bootstrapped** via `TorTransport::bootstrap()`.
///    This async method downloads the Tor relay list, builds circuits, and
///    returns a new `TorTransport` with `client = Some(...)`.
///    After this, `is_available()` returns `true`.
///
/// 3. **Connected** via `connect(peer_info)`.
///    Opens a Tor-anonymized stream to the target.  The target can be:
///      - A normal hostname + port (traffic exits via a Tor exit node).
///      - A `.onion` v3 address + port (traffic stays inside Tor, no exit node).
///
/// # Field: `client: Option<Arc<TorClient<PreferredRuntime>>>`
///
/// - `Option<...>` means the field may be present (`Some`) or absent (`None`).
///   Before bootstrapping: `None`.  After bootstrapping: `Some(client)`.
///
/// - `Arc<TorClient<...>>` wraps the client in an `Arc` (Atomic Reference
///   Count) so that both the `TorTransport` struct AND individual `TorConnection`
///   objects can hold a reference to the same client without copying it.
///   The client is only freed when all references are dropped.
///
/// - `TorClient<PreferredRuntime>` is the generic type.  `PreferredRuntime`
///   is a type parameter telling arti which async runtime to use internally.
///
/// # Field: `handle: Option<Handle>`
///
/// - `Handle` is a "receipt" or "ticket" for a running Tokio async runtime.
///   It lets synchronous code call `handle.block_on(async { ... })` to
///   run async code synchronously on the current thread.
///
/// - `Option<Handle>` because `Handle::try_current()` may return `None` if
///   no Tokio runtime is active when `new()` is called.  This is very rare
///   in practice (the app always runs inside Tokio) but we handle it safely.
pub struct TorTransport {
    /// The arti Tor client; `None` until `bootstrap()` has been called.
    client: Option<Arc<TorClient<PreferredRuntime>>>,
    /// Handle to the active Tokio async runtime, needed to bridge sync→async calls.
    handle: Option<Handle>,
}

impl Default for TorTransport {
    /// Implement `Default` so `TorTransport::default()` == `TorTransport::new()`.
    fn default() -> Self {
        Self::new()
    }
}

impl TorTransport {
    /// Create an unbootstrapped transport placeholder.
    ///
    /// This creates the struct immediately, without doing any network activity.
    /// `is_available()` will return `false` until `bootstrap()` is called.
    ///
    /// # `Handle::try_current().ok()`
    ///
    /// `Handle::try_current()` attempts to get the handle to whichever Tokio
    /// runtime is currently active on this thread.
    ///
    /// If we are inside an async function (which is always spawned by Tokio),
    /// this succeeds and returns `Ok(handle)`.
    ///
    /// If we are in a plain synchronous main thread with no Tokio runtime,
    /// it returns `Err(...)`.  `.ok()` converts `Result<Handle, E>` into
    /// `Option<Handle>`, discarding the error.  We store `None` in that case.
    ///
    /// The handle is used later in `connect()` to run async Tor I/O.
    pub fn new() -> Self {
        Self {
            client: None,                      // not yet bootstrapped
            handle: Handle::try_current().ok(), // grab runtime handle if available
        }
    }

    /// Bootstrap Tor and return a ready-to-use transport.
    ///
    /// This is an `async fn` — it must be `.await`-ed.  While waiting for
    /// bootstrapping, Tokio can run other tasks (e.g., the UI stays responsive,
    /// other peers can still be pinged).  The wait is typically 5–15 seconds
    /// on a good internet connection.
    ///
    /// # What happens inside
    ///
    /// 1. `TorClientConfig::default()` creates a sensible default configuration:
    ///    standard Tor directory authorities, system certificate store, etc.
    ///
    /// 2. `TorClient::create_bootstrapped(config).await` does the heavy lifting:
    ///    a. Downloads the Tor consensus (list of all relays).
    ///    b. Verifies cryptographic signatures.
    ///    c. Selects guard relays.
    ///    d. Builds initial circuits.
    ///    e. Resolves to a fully-ready `TorClient` — or returns an error if
    ///       the network is unreachable or consensus download fails.
    ///
    /// 3. The client is wrapped in `Arc::new(client)` so it can later be shared
    ///    between this `TorTransport` and individual `TorConnection` objects.
    ///
    /// # Error handling
    ///
    /// `.map_err(|e| MeshInfinityError::TransportError(format!(...)))` converts
    /// arti's error type into our own `MeshInfinityError`.  The `?` operator
    /// then propagates the error up to the caller if bootstrapping fails.
    pub async fn bootstrap() -> Result<Self> {
        let config = TorClientConfig::default();
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| MeshInfinityError::TransportError(format!("Tor bootstrap failed: {e}")))?;
        Ok(Self {
            client: Some(Arc::new(client)),
            // `Handle::current()` is safe here because we are inside an async
            // function, which guarantees a Tokio runtime is active.
            handle: Some(Handle::current()),
        })
    }

    /// Wrap an already-bootstrapped `TorClient` in a `TorTransport`.
    ///
    /// This constructor is useful in tests or when another part of the codebase
    /// already has a bootstrapped client and wants to hand it to this transport.
    /// It skips the bootstrapping step entirely.
    ///
    /// # Why `Arc::new(client)` and not just `client`?
    ///
    /// The field type is `Option<Arc<TorClient<...>>>`.  We need to wrap the
    /// `TorClient` in an `Arc` because `TorConnection` objects (created during
    /// `connect()`) also hold a clone of this `Arc`.  Without `Arc`, we would
    /// have to copy the entire client or limit connections to one at a time.
    pub fn from_client(client: TorClient<PreferredRuntime>) -> Self {
        Self {
            client: Some(Arc::new(client)),
            handle: Some(Handle::current()),
        }
    }

    /// Parse peer metadata into a `(hostname, port)` pair for Tor's `connect()`.
    ///
    /// Tor's connect API accepts a `(host, port)` pair where `host` can be:
    ///   - A normal hostname or IP address.  Traffic exits through a Tor exit
    ///     node and reaches the clearnet destination.  The exit node sees the
    ///     destination but NOT your real IP.
    ///   - A `.onion` v3 address.  Traffic stays inside the Tor network and
    ///     reaches a hidden service.  Neither side learns the other's real IP.
    ///
    /// We look for the endpoint in two places (in priority order):
    ///
    /// 1. `peer_info.transport_endpoints[TransportType::Tor]` — a Tor-specific
    ///    endpoint string.  This may contain a `.onion` address, so we check
    ///    here first to take advantage of hidden services.
    ///
    /// 2. `peer_info.endpoint` — the generic socket address (clearnet IP + port),
    ///    used as a fallback if no Tor-specific endpoint was advertised.
    ///
    /// # String splitting: `rsplit_once(':')`
    ///
    /// The endpoint is a string like `"192.168.1.5:7654"` or
    /// `"[::1]:7654"` (IPv6).  We split at the *last* colon because IPv6
    /// addresses contain multiple colons (e.g., `"[::1]"`), and splitting at
    /// the first colon would give the wrong result.  `rsplit_once(':')` splits
    /// at the rightmost colon, which is always the host/port separator.
    ///
    /// # Return value
    ///
    /// Returns `Ok((host_string, port_number))` on success, or an error if
    /// neither endpoint field is present, or if the port is not a valid u16.
    fn resolve_target(peer_info: &PeerInfo) -> Result<(String, u16)> {
        // Try the Tor-specific endpoint first (may contain a .onion address).
        let raw = peer_info
            .transport_endpoints
            .get(&TransportType::Tor)
            .cloned()
            // `.or_else(|| ...)` is called only if the above returned None.
            // It falls back to the generic endpoint, converting SocketAddr to String.
            .or_else(|| peer_info.endpoint.map(|a| a.to_string()))
            .ok_or_else(|| {
                // Neither field was set — we can't figure out where to connect.
                MeshInfinityError::TransportError("no Tor endpoint in peer metadata".to_string())
            })?;

        // Split "host:port" at the last colon to separate host from port.
        let (host, port_str) = raw.rsplit_once(':').ok_or_else(|| {
            MeshInfinityError::TransportError(format!("invalid Tor endpoint format: {raw}"))
        })?;

        // Parse the port string into a u16.  Ports must be in range 0–65535.
        // `.parse()` returns `Err` if the string isn't a valid number, or is
        // out of the u16 range.
        let port: u16 = port_str.parse().map_err(|_| {
            MeshInfinityError::TransportError(format!("invalid port in Tor endpoint: {raw}"))
        })?;
        Ok((host.to_string(), port))
    }
}

impl Transport for TorTransport {
    /// Open an anonymous stream to `peer_info` through the Tor network.
    ///
    /// The connection will be either:
    ///   - A route through a Tor exit node to a clearnet destination (if the
    ///     endpoint is a normal IP or hostname).
    ///   - A fully in-Tor route to a hidden service (if the endpoint ends in
    ///     `.onion`).  In this case NO exit node is involved and neither side
    ///     ever learns the other's IP address.
    ///
    /// # Why `block_in_place` + `block_on`?
    ///
    /// Recall that `connect()` is a *synchronous* function — it must block
    /// and return a completed `Box<dyn Connection>`.  But `TorClient::connect()`
    /// is *asynchronous* — it must be `.await`-ed and cannot be called in a
    /// plain synchronous context.
    ///
    /// The solution:
    ///
    /// ```text
    /// tokio::task::block_in_place(|| {
    ///     handle.block_on(async move {
    ///         client.connect((host, port)).await   // async Tor connection
    ///     })
    /// })
    /// ```
    ///
    /// Step by step:
    ///
    /// 1. `tokio::task::block_in_place(|| { ... })` tells Tokio's thread pool:
    ///    "This thread is about to do blocking work.  Please steal any pending
    ///    async tasks from this thread and schedule them elsewhere so they are
    ///    not starved."
    ///
    /// 2. Inside the closure, `handle.block_on(async { ... })` runs the
    ///    provided `async` block synchronously on the current thread.  It drives
    ///    the async future to completion (polling it) while blocking this thread.
    ///
    /// 3. Together, the two calls let a synchronous function run async code
    ///    without deadlocking or starving the rest of the Tokio scheduler.
    ///
    /// # `Arc::clone` is cheap
    ///
    /// We clone `client` and `handle` before the closure so they can be moved
    /// (captured) into the `async move { ... }` block.  Cloning an `Arc` just
    /// increments a reference count — it does NOT copy the `TorClient` itself.
    fn connect(&self, peer_info: &PeerInfo) -> Result<Box<dyn Connection>> {
        // Fail immediately if bootstrap() was never called.  Without a client,
        // we have no Tor circuits and cannot connect to anything.
        let client = self.client.as_ref().ok_or_else(|| {
            MeshInfinityError::TransportError(
                "Tor transport not bootstrapped — call bootstrap() first".to_string(),
            )
        })?;

        // Fail if we have no runtime handle.  In practice this should never
        // happen because `new()` always tries to capture the handle.
        let handle = self.handle.as_ref().ok_or_else(|| {
            MeshInfinityError::TransportError("Tor transport has no runtime handle".to_string())
        })?;

        // Parse the peer's address into (hostname_or_onion, port).
        let (host, port) = Self::resolve_target(peer_info)?;

        // Clone the Arc pointers so we can move them into the async block.
        // Moving is required because the closure takes ownership.
        let client = Arc::clone(client);
        let handle_conn = handle.clone(); // this clone is kept for TorConnection to use later
        let peer = peer_info.clone();

        // Bridge sync → async: block this thread (safely) while running the
        // async Tor circuit setup.
        let stream = tokio::task::block_in_place(|| {
            handle.block_on(async move {
                // `client.connect((host, port))` is the arti-client API call that:
                //   - Selects or reuses a Tor circuit.
                //   - Extends the circuit to a relay that can reach the destination.
                //   - Opens a data stream through the circuit.
                //   - Returns a `DataStream` — a TCP-like stream over Tor.
                //
                // If `host` ends in `.onion`, arti handles the rendezvous protocol
                // to connect to a hidden service instead of using an exit node.
                client
                    .connect((host.as_str(), port))
                    .await
                    .map_err(|e| {
                        MeshInfinityError::TransportError(format!(
                            "Tor connect to {host}:{port} failed: {e}"
                        ))
                    })
            })
        })?;
        // `?` propagates any error from `block_on` — e.g., if the circuit build
        // failed, the Tor network is unreachable, or the hidden service is down.

        // Wrap the raw DataStream in our Connection implementation and return it.
        Ok(Box::new(TorConnection::new(stream, peer, handle_conn)))
    }

    /// Receiving inbound connections requires a persistent v3 onion service.
    ///
    /// Setting up a persistent onion service requires generating and storing
    /// a private key (so the `.onion` address stays consistent across restarts).
    /// This is not yet implemented.  Returns an error for now.
    fn listen(&self) -> Result<Box<dyn Listener>> {
        Err(MeshInfinityError::TransportError(
            "Tor inbound listener requires onion service configuration (not yet implemented)"
                .to_string(),
        ))
    }

    /// Numeric priority of this transport (lower = higher priority).
    ///
    /// Tor's priority of 2 reflects its position as the second-most-preferred
    /// transport after any imagined even-higher-priority transports.  In practice
    /// the ordering is driven by `enabled_transport_order()` in `manager.rs`,
    /// and this field acts as a tiebreaker when two transports have the same
    /// position in the list.
    fn priority(&self) -> u8 {
        2
    }

    /// Returns `TransportType::Tor`.
    ///
    /// Used by the manager to store/look up this transport in its HashMap.
    fn transport_type(&self) -> TransportType {
        TransportType::Tor
    }

    /// Returns `true` only after `bootstrap()` has completed successfully.
    ///
    /// `self.client.is_some()` checks whether the `Option<Arc<TorClient>>`
    /// holds a value:
    ///   - `None`  → bootstrapping not done → returns `false`
    ///   - `Some(_)` → bootstrapped and ready → returns `true`
    ///
    /// The core manager checks `is_available()` before every connection attempt,
    /// so the transport will never be selected while still bootstrapping.
    fn is_available(&self) -> bool {
        self.client.is_some()
    }

    /// Return a static quality estimate for Tor connections.
    ///
    /// These are typical real-world Tor network characteristics:
    ///   - `latency: 520 ms` — Tor adds roughly 300–600 ms of round-trip delay
    ///     compared to clearnet, because traffic hops through three relays.
    ///   - `bandwidth: 400_000` — typical Tor throughput is ~400 KB/s because
    ///     relay bandwidth is shared among all users.
    ///   - `reliability: 0.88` — 88% packet delivery; Tor is quite reliable
    ///     but circuits do occasionally fail and need to be rebuilt.
    ///   - `cost: 0.2` — Tor is free; low cost score.
    ///   - `congestion: 0.35` — the Tor network has moderate but not severe
    ///     congestion at most times.
    ///
    /// These values inform the quality-gated pass 1 in `core_manager.rs`.
    /// In a future version, live circuit measurements could replace these
    /// static estimates.
    fn measure_quality(&self, _target: &PeerInfo) -> Result<TransportQuality> {
        Ok(TransportQuality {
            latency: Duration::from_millis(520), // ~half a second for a Tor round-trip
            bandwidth: 400_000,                  // ~400 KB/s — typical Tor throughput
            reliability: 0.88,                   // 88% packet delivery
            cost: 0.2,                           // free to use; low cost score
            congestion: 0.35,                    // moderate congestion on the Tor network
        })
    }
}

// ---------------------------------------------------------------------------
// TorConnection — a live, open Tor stream
// ---------------------------------------------------------------------------

/// An open, bidirectional Tor data stream.
///
/// This wraps an arti-client [`DataStream`] — the object you receive after
/// `TorClient::connect()` succeeds.  A `DataStream` behaves exactly like a
/// normal TCP stream: you can write bytes to it and read bytes from it.  The
/// difference is that the bytes travel through the Tor network rather than
/// directly to the destination.
///
/// # Why `Mutex<Option<DataStream>>`?  (Two wrappers, explained separately)
///
/// ## Why `Mutex<...>`?
///
/// The `Connection` trait requires `TorConnection` to be `Sync`, which in
/// Rust means: "it is safe to share a REFERENCE to this object across threads".
///
/// `DataStream` is `Send` (safe to *move* to another thread) but NOT `Sync`
/// (NOT safe to be accessed from two threads simultaneously without a lock).
///
/// Wrapping in `Mutex<...>` solves this: the Mutex enforces that only one
/// thread can access the `DataStream` at a time, and Rust's type system then
/// considers `Mutex<DataStream>` to be `Sync`.
///
/// ## Why `Option<...>` inside the Mutex?
///
/// We need a way to represent "this connection is closed".  Using
/// `Option<DataStream>` inside the Mutex gives us:
///   - `Some(stream)` → connection is open.
///   - `None`         → connection has been closed.
///
/// When `close()` is called, we call `guard.take()` which:
///   1. Removes the `DataStream` from the `Option` (takes ownership of it).
///   2. Sets the `Option` to `None`.
///   3. Returns the `DataStream` so we can call `shutdown()` on it.
///
/// After `take()`, any subsequent `send()` or `receive()` call will see
/// `None` in the Mutex and return an error — cleanly signalling "closed".
pub struct TorConnection {
    /// The underlying Tor byte stream; `None` after `close()`.
    stream: Mutex<Option<DataStream>>,
    /// Metadata about the remote peer (address, public key, etc.).
    peer: PeerInfo,
    /// Handle to the Tokio runtime, needed to run async stream I/O synchronously.
    ///
    /// Just like in `connect()`, we need `block_in_place` + `block_on` here
    /// because `DataStream::read()` and `DataStream::write_all()` are async.
    handle: Handle,
}

impl TorConnection {
    /// Create a new `TorConnection` wrapping an open `DataStream`.
    ///
    /// `Mutex::new(Some(stream))` wraps the stream in:
    ///   - `Some(stream)` to mark the connection as open.
    ///   - `Mutex` so it can be shared safely across threads.
    fn new(stream: DataStream, peer: PeerInfo, handle: Handle) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            peer,
            handle,
        }
    }
}

impl Connection for TorConnection {
    /// Send `data` over the Tor stream.
    ///
    /// # Steps
    ///
    /// 1. Acquire the Mutex lock to get exclusive access to the stream.
    ///    If the Mutex is poisoned (another thread panicked while holding it),
    ///    we return an error rather than panicking ourselves.
    ///
    /// 2. Check that `Some(stream)` is present — if it's `None`, the connection
    ///    was already closed and we return an error immediately.
    ///
    /// 3. Use `block_in_place` + `block_on` to run the async `write_all` call.
    ///    `write_all(data)` writes EVERY byte in `data` — unlike a plain `write`,
    ///    it loops internally until all bytes have been sent (or an error occurs).
    ///    This is important for Tor because the stream might only accept a few
    ///    bytes at a time before we need to wait for Tor to drain the buffer.
    ///
    /// 4. Return `Ok(data.len())` — the number of bytes the caller gave us.
    ///    (All bytes are always written or an error is returned; partial writes
    ///    don't happen because we use `write_all`.)
    fn send(&mut self, data: &[u8]) -> Result<usize> {
        // Acquire the Mutex lock.
        // `lock()` returns `Err(PoisonError)` only if another thread panicked
        // while holding this lock.  We convert that to a TransportError.
        let mut guard = self.stream.lock().map_err(|_| {
            MeshInfinityError::TransportError("Tor stream lock poisoned".to_string())
        })?;

        // Get a mutable reference to the DataStream inside the Option.
        // `.as_mut()` converts `Option<DataStream>` to `Option<&mut DataStream>`.
        // `.ok_or_else(...)` converts `None` to an Err (connection is closed).
        let stream = guard.as_mut().ok_or_else(|| {
            MeshInfinityError::NetworkError("Tor connection closed".to_string())
        })?;

        let handle = &self.handle;
        // Bridge sync → async to call the async `write_all` method on the stream.
        // `stream` is already a `&mut DataStream` so we can await I/O on it.
        tokio::task::block_in_place(|| {
            handle.block_on(async { stream.write_all(data).await })
        })
        .map_err(|e| MeshInfinityError::TransportError(format!("Tor send failed: {e}")))?;

        // Report success: we wrote all `data.len()` bytes.
        Ok(data.len())
    }

    /// Receive bytes from the Tor stream into `buffer`.
    ///
    /// Returns the number of bytes actually placed into `buffer`.  This may be
    /// less than `buffer.len()` if fewer bytes are available right now — this
    /// is entirely normal for TCP-style streaming I/O and is NOT an error.
    ///
    /// The same `block_in_place` + `block_on` pattern bridges the async
    /// `read()` call into this synchronous function.
    ///
    /// # `stream.read(buffer)` vs `stream.read_exact(buffer)`
    ///
    /// `read()` returns as soon as ANY bytes are available (up to buffer length).
    /// `read_exact()` blocks until the buffer is completely filled.
    ///
    /// We use `read()` here because the caller provides the buffer and decides
    /// how much to read.  Calling `read_exact` would risk blocking forever if
    /// the remote side sends fewer bytes than the buffer size.
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let mut guard = self.stream.lock().map_err(|_| {
            MeshInfinityError::TransportError("Tor stream lock poisoned".to_string())
        })?;
        let stream = guard.as_mut().ok_or_else(|| {
            MeshInfinityError::NetworkError("Tor connection closed".to_string())
        })?;
        let handle = &self.handle;
        // `stream.read(buffer)` asynchronously reads up to `buffer.len()` bytes
        // from the Tor stream into `buffer` and returns the byte count.
        tokio::task::block_in_place(|| handle.block_on(async { stream.read(buffer).await }))
            .map_err(|e| MeshInfinityError::TransportError(format!("Tor receive failed: {e}")))
    }

    /// Close the Tor stream gracefully.
    ///
    /// # `guard.take()` explained
    ///
    /// `guard.take()` is called on `MutexGuard<Option<DataStream>>`.  It calls
    /// `Option::take()` which:
    ///   - Replaces the `Option` with `None` (marks connection as closed).
    ///   - Returns the `DataStream` that was inside `Some(stream)`.
    ///
    /// If the Option was already `None` (already closed), `take()` returns
    /// `None` and the `if let Some(...)` block is skipped — so calling
    /// `close()` multiple times is safe (idempotent).
    ///
    /// # `stream.shutdown()`
    ///
    /// Sends a TCP FIN through the Tor circuit, signalling to the remote end
    /// that we are done sending data.  The remote end can still send data
    /// back if it hasn't closed its side, but well-behaved peers will also
    /// close their side once they receive a FIN.
    fn close(&mut self) -> Result<()> {
        let mut guard = self.stream.lock().map_err(|_| {
            MeshInfinityError::TransportError("Tor stream lock poisoned".to_string())
        })?;
        // Take the DataStream out of the Option (sets Option to None).
        // If it was already None, we do nothing (already closed).
        if let Some(mut stream) = guard.take() {
            let handle = &self.handle;
            tokio::task::block_in_place(|| {
                handle.block_on(async { stream.shutdown().await })
            })
            .map_err(|e| {
                MeshInfinityError::TransportError(format!("Tor shutdown failed: {e}"))
            })?;
        }
        Ok(())
    }

    /// Return a reference to the metadata of the peer on the other end.
    ///
    /// This does not involve any I/O — it just returns a reference to the
    /// `PeerInfo` stored when the connection was created.
    fn remote_peer(&self) -> &PeerInfo {
        &self.peer
    }

    /// Return `true` if the stream is still open (not yet closed).
    ///
    /// Acquires the Mutex lock and checks whether the Option still contains
    /// a `DataStream` (`is_some()` → `true`) or has been set to `None` by
    /// `close()` (`is_some()` → `false`).
    ///
    /// If the Mutex lock fails (poisoned), we conservatively return `false`
    /// (treat a broken lock as a closed connection — safer than panicking).
    fn is_active(&self) -> bool {
        // `.map(|g| g.is_some())` extracts `true` or `false` from the guard.
        // `.unwrap_or(false)` returns false if the lock was poisoned.
        self.stream.lock().map(|g| g.is_some()).unwrap_or(false)
    }
}
