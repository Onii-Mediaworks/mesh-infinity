//! mDNS-based local-network peer discovery.
//!
//! # What is mDNS?
//!
//! mDNS stands for **multicast DNS**. Normal DNS works by asking a central server
//! "what is the IP address of google.com?". mDNS works without any central server —
//! instead, your device *broadcasts* a question to every device on the local network
//! at once, and the device that owns the name replies directly.
//!
//! You've seen mDNS in action every time your phone automatically finds a Wi-Fi printer,
//! or when a laptop shows up in the Finder sidebar, or when you type
//! "raspberrypi.local" in a browser. All of those use mDNS.
//!
//! # How Mesh Infinity uses mDNS
//!
//! When the app starts, it:
//! 1. **Advertises** itself: tells every device on the LAN "I am a Mesh Infinity
//!    node, I have this peer-ID, and I'm listening on this port."
//! 2. **Browses**: listens for the same announcement from other nodes on the LAN.
//!
//! When another Mesh Infinity node is discovered, its address and port are wrapped
//! into a `PeerInfo` and handed up to the higher-level discovery coordinator, which
//! can then attempt to connect.
//!
//! This module advertises and listens for services with the type string
//! `_mesh-infinity._udp.local.` — the underscore-prefixed format is the standard
//! DNS-SD (DNS Service Discovery) convention for naming service types.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};

// `mdns_sd` is the Rust library that handles the low-level mDNS/DNS-SD protocol.
// - `ResolvedService` — full information about a peer once its address has been resolved
// - `ServiceDaemon`   — the background engine that sends and receives mDNS packets
// - `ServiceEvent`    — an enum of things the daemon can tell us (peer appeared, peer left, etc.)
// - `ServiceInfo`     — a description of OUR service that we want to advertise
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::core::error::{MeshInfinityError, Result};
use crate::core::{PeerId, PeerInfo, TransportType, TrustLevel};
use crate::discovery::peer_codec::{hex_to_peer_id, peer_id_to_hex};

// The service-type string used in DNS-SD announcements.
// Format: "_<application>._<transport>.local."
// Any device browsing for "_mesh-infinity._udp.local." will find our node.
const SERVICE_TYPE: &str = "_mesh-infinity._udp.local.";

// How many seconds a peer entry is kept alive after the last time it was seen.
// If a peer disappears without sending a "goodbye" packet (e.g. the app crashed or
// the Wi-Fi was cut), we still remove the entry after 5 minutes rather than keeping
// a stale, unconnectable peer in the list forever.
const PEER_TTL_SECONDS: u64 = 300; // 5 minutes

/// A discovered remote peer together with the timestamp of its most recent mDNS announcement.
///
/// The `last_seen` timestamp lets us purge peers that have gone offline without
/// explicitly sending an mDNS "goodbye" message — see `cleanup_stale_peers`.
#[derive(Clone)]
struct DiscoveredPeer {
    /// The full information needed to connect to this peer (address, port, keys, etc.)
    peer_info: PeerInfo,
    /// Wall-clock time when we last received an mDNS packet from this peer.
    /// Used to detect peers that vanish without a goodbye packet.
    last_seen: SystemTime,
}

/// The main mDNS discovery engine for Mesh Infinity.
///
/// Holds a reference to the `ServiceDaemon` (the mDNS engine), the map of
/// currently-known peers, our own identity (so we don't add ourselves to the peer
/// list), and a flag that controls the background listener thread.
pub struct MdnsDiscovery {
    /// The mDNS daemon — the library object that actually sends/receives UDP multicast
    /// packets on port 5353.  Wrapped in `Arc` so it can be shared safely between
    /// the main struct and the background listener thread.
    daemon: Arc<ServiceDaemon>,

    /// A thread-safe hash map from PeerId → DiscoveredPeer.
    ///
    /// `Arc<RwLock<…>>` means:
    /// - `Arc`    — multiple owners (main thread + listener thread both hold a reference)
    /// - `RwLock` — many readers OR one writer at a time, never both simultaneously.
    ///              This is more efficient than a plain `Mutex` when reads dominate.
    discovered_peers: Arc<RwLock<HashMap<PeerId, DiscoveredPeer>>>,

    /// Our own 32-byte node identity.  Used to filter ourselves out of discovered peers —
    /// we would otherwise see our own advertisement and add ourselves to the peer list.
    local_peer_id: PeerId,

    /// UDP port our transport layer is listening on.  Advertised so other nodes know
    /// which port to connect to.
    local_port: u16,

    /// Whether the discovery engine is currently active.
    /// `Arc<RwLock<bool>>` so the background thread can check it too.
    running: Arc<RwLock<bool>>,
}

impl MdnsDiscovery {
    /// Create a new mDNS discovery service (does NOT start advertising yet).
    ///
    /// `local_peer_id` — our unique 32-byte node identity
    /// `local_port`    — the UDP port our transport is listening on
    ///
    /// Returns `Err` if the OS refuses to create the mDNS daemon
    /// (e.g. the network interface is not available).
    pub fn new(local_peer_id: PeerId, local_port: u16) -> Result<Self> {
        // `ServiceDaemon::new()` starts the mDNS background engine.
        // It opens a UDP socket bound to 0.0.0.0:5353 and joins the multicast group
        // 224.0.0.251 (the reserved mDNS multicast address on IPv4).
        let daemon = ServiceDaemon::new().map_err(|e| {
            MeshInfinityError::NetworkError(format!("Failed to create mDNS daemon: {}", e))
        })?;

        Ok(Self {
            daemon: Arc::new(daemon),
            // Empty map — no peers known yet.
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            local_peer_id,
            local_port,
            // Start in the "not running" state; `start()` flips this to true.
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Start advertising our presence and listening for other nodes.
    ///
    /// After this returns `Ok(())`, the background listener thread is running and
    /// `discovered_peers()` will begin returning entries as nodes are found.
    ///
    /// Returns `Err` if already running, or if the OS rejects the service registration.
    pub fn start(&self) -> Result<()> {
        // --- Step 1: flip the "running" flag ------------------------------------------
        // We use a small scope `{ }` here so that the write-lock on `running` is
        // dropped before we call `register_service` below.  Holding it too long
        // would block any thread that tries to check `is_running()` while we set up.
        {
            let mut running = self.running.write().map_err(|e| {
                MeshInfinityError::LockError(format!("Running lock poisoned: {}", e))
            })?;
            if *running {
                // Calling start() twice would double-register our service and spawn
                // a second listener thread — both are bugs, so we bail early.
                return Err(MeshInfinityError::InvalidInput(
                    "mDNS discovery already running".to_string(),
                ));
            }
            *running = true;
        }

        // --- Step 2: advertise our own service on the LAN -----------------------------
        self.register_service()?;

        // --- Step 3: start listening for other nodes' advertisements ------------------
        self.browse_services()?;

        Ok(())
    }

    /// Stop advertising and shut down the listener thread.
    ///
    /// After this returns, other nodes will eventually stop seeing us in their
    /// peer lists (when their own TTLs expire).
    pub fn stop(&self) -> Result<()> {
        // Flip the running flag to false.  The background listener thread checks this
        // flag on every iteration and will exit its loop when it sees false.
        let mut running = self
            .running
            .write()
            .map_err(|e| MeshInfinityError::LockError(format!("Running lock poisoned: {}", e)))?;
        *running = false;

        // Tell the mDNS daemon to stop.  This sends an mDNS "goodbye" packet
        // (TTL=0 record) so other devices remove us from their caches immediately,
        // and then closes the underlying UDP socket.
        self.daemon.shutdown().map_err(|e| {
            MeshInfinityError::NetworkError(format!("Failed to shutdown mDNS: {}", e))
        })?;

        Ok(())
    }

    /// Returns `true` if the discovery engine is currently advertising and listening.
    pub fn is_running(&self) -> bool {
        // `unwrap_or(false)`: if the lock is poisoned (the thread that held it
        // panicked), treat it as "not running" rather than panicking ourselves.
        self.running.read().map(|r| *r).unwrap_or(false)
    }

    /// Return the list of currently-known peers, automatically removing stale entries.
    ///
    /// A peer is "stale" if we haven't seen its mDNS heartbeat for `PEER_TTL_SECONDS`.
    /// This handles the case where a device disappears without sending a goodbye packet
    /// (hard power-off, Wi-Fi dropout, app crash, etc.).
    pub fn discovered_peers(&self) -> Result<Vec<PeerInfo>> {
        // Remove peers whose last_seen timestamp is too old before returning the list.
        self.cleanup_stale_peers()?;

        let peers = self.discovered_peers.read().map_err(|e| {
            MeshInfinityError::LockError(format!("Discovered peers lock poisoned: {}", e))
        })?;

        // `.values()` gives the `DiscoveredPeer` structs; `.map` extracts the inner
        // `PeerInfo`; `.clone()` copies it so we can return owned data without holding
        // the lock.
        Ok(peers.values().map(|p| p.peer_info.clone()).collect())
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Publish our own service record onto the local network.
    ///
    /// After this call, any device on the LAN that is browsing for
    /// `_mesh-infinity._udp.local.` will see an entry for us, including our
    /// peer_id (encoded as hex) and the port we're listening on.
    fn register_service(&self) -> Result<()> {
        // The "instance name" uniquely identifies this specific node within the service
        // type.  We use the hex representation of our 32-byte peer ID, which is
        // globally unique and also gives other nodes our identity without any extra
        // lookup step.
        let instance_name = peer_id_to_hex(&self.local_peer_id);

        // DNS-SD allows arbitrary key=value pairs called "TXT records" to be attached
        // to a service announcement.  We use them to carry the peer_id in a structured
        // way (even though it's also the instance name) and the app version for future
        // compatibility checks.
        let mut properties = HashMap::new();
        properties.insert("peer_id".to_string(), peer_id_to_hex(&self.local_peer_id));
        properties.insert("version".to_string(), "0.5.0".to_string());

        // `ServiceInfo` is the full description of our service:
        // - SERVICE_TYPE        — the service type string (what kind of thing we are)
        // - instance_name       — unique name for this particular node
        // - hostname            — "<peer_id_hex>.local." — the mDNS hostname for us
        // - ()                  — no extra addresses to advertise (use OS-detected ones)
        // - local_port          — the UDP port we're listening on
        // - Some(properties)    — the TXT record key=value pairs
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &format!("{}.local.", instance_name),
            (),
            self.local_port,
            Some(properties),
        )
        .map_err(|e| {
            MeshInfinityError::NetworkError(format!("Failed to create service info: {}", e))
        })?;

        // Hand the service description to the daemon, which will start sending
        // periodic mDNS announcements on the network.
        self.daemon.register(service_info).map_err(|e| {
            MeshInfinityError::NetworkError(format!("Failed to register mDNS service: {}", e))
        })?;

        Ok(())
    }

    /// Subscribe to mDNS events for the `_mesh-infinity._udp.local.` service type
    /// and spawn a background thread to process them.
    ///
    /// The `mdns_sd` library hands us a channel `receiver` that will yield
    /// `ServiceEvent` values whenever a peer appears, resolves, or disappears.
    /// Because `receiver.recv()` blocks, we run it on a dedicated thread rather
    /// than blocking the caller.
    fn browse_services(&self) -> Result<()> {
        // `browse` returns a `Receiver<ServiceEvent>` — essentially a queue.
        // The daemon pushes events onto the queue; we pop them here.
        let receiver = self.daemon.browse(SERVICE_TYPE).map_err(|e| {
            MeshInfinityError::NetworkError(format!("Failed to browse mDNS: {}", e))
        })?;

        // Clone the Arcs so the background thread can share ownership without
        // borrowing from `self` (which would require `self` to live as long as
        // the thread — but threads can outlive the struct).
        let discovered_peers = Arc::clone(&self.discovered_peers);
        let local_peer_id = self.local_peer_id;
        let running = Arc::clone(&self.running);

        // Spawn a dedicated OS thread for the event loop.
        //
        // Why a thread and not async / tokio?  mDNS events arrive at unpredictable
        // times and the receiver is a blocking channel (not an async stream), so a
        // dedicated thread is the simplest, most robust approach.
        thread::spawn(move || {
            // `receiver.recv()` blocks until an event arrives or the daemon shuts down.
            // When the daemon shuts down it closes the channel, making `recv()` return
            // `Err`, which breaks out of the loop.
            while let Ok(event) = receiver.recv() {
                // Before processing the event, check if we've been asked to stop.
                // This is the cooperative shutdown mechanism — we don't forcefully kill
                // threads in Rust; instead the thread voluntarily exits.
                if let Ok(is_running) = running.read() {
                    if !*is_running {
                        break;
                    }
                }

                match event {
                    // A peer was fully resolved: we now have its IP address and port.
                    // mDNS resolution is a two-step process — first you see the service
                    // name, then (after a second query) you get the actual address.
                    // `ServiceResolved` fires only after both steps complete, so we
                    // always have a usable address here.
                    ServiceEvent::ServiceResolved(info) => {
                        if let Err(e) =
                            Self::handle_service_resolved(info, &discovered_peers, &local_peer_id)
                        {
                            eprintln!("mDNS error handling resolved service: {}", e);
                        }
                    }

                    // A peer explicitly announced it is leaving the network (graceful
                    // shutdown).  The full DNS-SD name uniquely identifies which peer.
                    // We remove it immediately rather than waiting for the TTL to expire.
                    ServiceEvent::ServiceRemoved(_, full_name) => {
                        if let Err(e) = Self::handle_service_removed(&full_name, &discovered_peers)
                        {
                            eprintln!("mDNS error handling removed service: {}", e);
                        }
                    }

                    // Other event variants (e.g. `SearchStarted`, `SearchStopped`,
                    // `ServiceFound` — the unresolved name before we have the address)
                    // are not actionable for us, so we ignore them with a wildcard.
                    _ => {}
                }
            }
        });

        Ok(())
    }

    /// Process a `ServiceResolved` event: validate, filter, and store the peer.
    ///
    /// This is called from the background thread (see `browse_services`).
    ///
    /// `info`             — the fully-resolved service descriptor from the mDNS library
    /// `discovered_peers` — shared map to write the new peer into
    /// `local_peer_id`    — our own identity, used to filter ourselves out
    fn handle_service_resolved(
        info: Box<ResolvedService>,
        discovered_peers: &Arc<RwLock<HashMap<PeerId, DiscoveredPeer>>>,
        local_peer_id: &PeerId,
    ) -> Result<()> {
        // --- Step 1: extract peer_id from the TXT record properties -------------------
        // Every Mesh Infinity node embeds its peer_id (hex-encoded) in the DNS-SD
        // TXT record when it registers.  We read it back here to get the canonical
        // identity of the node we just found.
        let properties = info.get_properties();
        let peer_id_str = properties
            .get("peer_id")
            .map(|v| v.val_str())
            .ok_or_else(|| {
                // If there's no peer_id, this is either not a Mesh Infinity node or
                // a node running an old/incompatible version.  Reject it.
                MeshInfinityError::InvalidInput("No peer_id in mDNS service".to_string())
            })?;

        // Convert the 64-character hex string back to a 32-byte PeerId array.
        let peer_id = hex_to_peer_id(peer_id_str)?;

        // --- Step 2: filter out ourselves -------------------------------------------
        // Because we also browse for the same service type we advertise, we would
        // otherwise see our own announcement and add ourselves to the peer list.
        // That would cause the UI to display "yourself" as a connectable peer.
        if peer_id == *local_peer_id {
            return Ok(());
        }

        // --- Step 3: validate that we have at least one IP address ------------------
        // mDNS resolution can theoretically complete without a usable address
        // (e.g. IPv6-only host on an IPv4-only network).  Guard against that.
        // ScopedIp wraps an IpAddr with an optional scope ID (e.g. link-local IPv6 scope).
        // It does not implement Copy, so we dereference each ScopedIp to get a plain IpAddr.
        // The `*` dereferences ScopedIp -> IpAddr (via Deref impl), then the outer `*` copies
        // the IpAddr value (IpAddr is Copy) so we own it rather than borrowing.
        let addresses: Vec<IpAddr> = info.get_addresses().iter().map(|sip| **sip).collect();
        if addresses.is_empty() {
            return Err(MeshInfinityError::InvalidInput(
                "No addresses in mDNS service".to_string(),
            ));
        }

        // --- Step 4: build a SocketAddr (IP + port) for the clearnet transport ------
        // Take the first available address.  In practice a device might have both
        // an IPv4 and an IPv6 address; the transport layer will handle negotiating
        // which one to actually use.
        use std::net::SocketAddr;
        let endpoint_address = SocketAddr::new(addresses[0], info.get_port());

        // --- Step 5: construct a PeerInfo -------------------------------------------
        // `PeerInfo` is the app's universal representation of a connectable peer.
        // Note that `public_key` is all zeros here — the real key will be exchanged
        // during the cryptographic handshake when we actually connect to this peer.
        // We don't trust the mDNS advertisement to carry the real key because anyone
        // on the LAN could forge an mDNS packet.
        let peer_info = PeerInfo {
            peer_id,
            public_key: [0u8; 32], // Will be exchanged during handshake
            // New peers start untrusted.  The user must explicitly verify/trust them
            // through the app UI or the web-of-trust system.
            trust_level: TrustLevel::Untrusted,
            // We found this peer via mDNS on the LAN, so clearnet (direct TCP/UDP)
            // is the available transport.  Other transports (Tor, I2P, Bluetooth)
            // may be negotiated later once a connection is established.
            available_transports: vec![TransportType::Clearnet],
            last_seen: Some(SystemTime::now()),
            endpoint: Some(endpoint_address),
            transport_endpoints: std::collections::HashMap::new(),
        };

        // --- Step 6: insert into the shared map ------------------------------------
        // Acquire a write lock briefly to update the map, then release it
        // immediately so other threads can read.
        let mut peers = discovered_peers.write().map_err(|e| {
            MeshInfinityError::LockError(format!("Discovered peers lock poisoned: {}", e))
        })?;

        // `insert` with the same key overwrites the old entry — this acts as a
        // "heartbeat refresh", updating `last_seen` every time we re-see a peer.
        peers.insert(
            peer_id,
            DiscoveredPeer {
                peer_info,
                last_seen: SystemTime::now(),
            },
        );

        Ok(())
    }

    /// Process a `ServiceRemoved` event: look up the peer by name and remove it.
    ///
    /// A `ServiceRemoved` event fires when a node sends a graceful mDNS goodbye
    /// packet (TTL=0) — usually when the app closes cleanly or the OS shuts down
    /// a network interface.
    ///
    /// `full_name`        — the full DNS-SD name, e.g. `<hex_peer_id>._mesh-infinity._udp.local.`
    /// `discovered_peers` — shared map to remove the peer from
    fn handle_service_removed(
        full_name: &str,
        discovered_peers: &Arc<RwLock<HashMap<PeerId, DiscoveredPeer>>>,
    ) -> Result<()> {
        // DNS-SD full names look like: "instance._service._protocol.local."
        // Splitting on '.' and taking the first segment gives us the instance name,
        // which is our hex-encoded peer_id.
        let instance_name = full_name
            .split('.')
            .next()
            .ok_or_else(|| MeshInfinityError::InvalidInput("Invalid service name".to_string()))?;

        let peer_id = hex_to_peer_id(instance_name)?;

        let mut peers = discovered_peers.write().map_err(|e| {
            MeshInfinityError::LockError(format!("Discovered peers lock poisoned: {}", e))
        })?;

        // If the peer_id is not in the map (e.g. we got a remove event for a peer
        // we never successfully resolved), `remove` silently does nothing — that
        // is the correct behavior here.
        peers.remove(&peer_id);

        Ok(())
    }

    /// Remove any peers whose `last_seen` timestamp is older than `PEER_TTL_SECONDS`.
    ///
    /// This handles "silent" departures where a device didn't send a goodbye packet
    /// — for example, a hard power-off, a kernel crash, or a dropped Wi-Fi connection.
    /// Without this cleanup, the discovered peer list would accumulate stale entries
    /// that are shown in the UI but can never be connected to.
    fn cleanup_stale_peers(&self) -> Result<()> {
        let now = SystemTime::now();
        let ttl = Duration::from_secs(PEER_TTL_SECONDS);

        let mut peers = self.discovered_peers.write().map_err(|e| {
            MeshInfinityError::LockError(format!("Discovered peers lock poisoned: {}", e))
        })?;

        // `retain` keeps only the entries for which the closure returns `true`.
        // We keep a peer if: (time since last seen) < TTL.
        // `duration_since` can return Err if `discovered.last_seen` is in the future
        // (clock skew); `unwrap_or(false)` treats clock anomalies as stale.
        peers.retain(|_, discovered| {
            now.duration_since(discovered.last_seen)
                .map(|elapsed| elapsed < ttl)
                .unwrap_or(false)
        });

        Ok(())
    }
}

impl Drop for MdnsDiscovery {
    /// Automatically stop the mDNS daemon when this struct goes out of scope.
    ///
    /// Rust calls `drop` when the last owner of an `MdnsDiscovery` is destroyed.
    /// This sends the mDNS goodbye packet and closes the UDP socket so we don't
    /// leave a dangling advertisement on the network.
    ///
    /// The `let _ =` syntax intentionally discards any error returned by `stop()`,
    /// because `drop` cannot return errors and we don't want to panic during cleanup.
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Peer-id hex conversion should round-trip losslessly.
    ///
    /// A `PeerId` is a `[u8; 32]` (32 raw bytes).  We encode it as a 64-character
    /// hexadecimal string for embedding in DNS TXT records (which are text-based).
    /// This test verifies that converting bytes → hex → bytes gives back the
    /// original bytes without loss.
    fn test_peer_id_hex_conversion() {
        let peer_id = [0x42u8; 32];
        let hex = peer_id_to_hex(&peer_id);
        assert_eq!(hex.len(), 64); // 32 bytes × 2 hex chars/byte = 64 chars

        let converted = hex_to_peer_id(&hex).unwrap();
        assert_eq!(peer_id, converted);
    }

    #[test]
    /// Invalid hex or length must be rejected by parser.
    ///
    /// Guards against malformed DNS TXT records (e.g. a non-Mesh-Infinity device
    /// that happens to register a service with the same type string).
    fn test_invalid_hex() {
        assert!(hex_to_peer_id("invalid").is_err());
        assert!(hex_to_peer_id("00").is_err()); // Too short
    }
}
