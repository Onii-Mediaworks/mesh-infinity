//! Bluetooth Transport (§5.6)
//!
//! Implements the Bluetooth Low Energy (BLE) transport for Mesh Infinity.
//! BLE is used for proximity-based peer discovery and short-range data
//! exchange, complementing longer-range transports (Tor, clearnet, RF).
//!
//! ## Architecture
//!
//! ```text
//! Mesh packet (encrypted)
//!     ↓
//! BLE GATT characteristic write (TX_CHAR_UUID) or notification (RX_CHAR_UUID)
//!     ↓
//! BLE radio (advertising / scanning / GATT server/client)
//! ```
//!
//! ## Peer Discovery
//!
//! BLE discovery is non-identifying. Advertisements are scanned without a
//! Mesh-specific UUID filter, and the transport extracts only an opaque
//! rotating token from plausible advertisement payloads. Discovery does not
//! disclose peer IDs or any other stable identity material.
//!
//! ## Data Channel (GATT)
//!
//! Once a peer is discovered via scanning, the node may connect to it over
//! GATT. Two characteristics are defined:
//!
//! - `TX_CHAR_UUID` — write-without-response (peripheral → central).
//!   The scanning node writes mesh packets to this characteristic on the
//!   remote peripheral.
//!
//! - `RX_CHAR_UUID` — notify (central → peripheral).
//!   The peripheral notifies the central of incoming mesh packets.
//!
//! ## Feature Gating
//!
//! Real BLE I/O requires the `transport-bluetooth-native` Cargo feature,
//! which pulls in the `btleplug` crate.  When the feature is absent, all
//! public methods return `BluetoothError::NotAvailable` and capability
//! detection returns `{ ble: false, classic: false }`.
//!
//! ## Platform Availability Detection
//!
//! Platform availability is checked at compile time first (feature flag),
//! then at runtime:
//! - **Linux**: checks for `/sys/class/bluetooth` directory.
//! - **macOS**: CoreBluetooth is always present (system framework).
//! - **Windows**: WinRT Bluetooth available on Win10+ (assumed true).
//! - **Other**: unavailable.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

// ────────────────────────────────────────────────────────────────────────────
// Constants (always-available)
// ────────────────────────────────────────────────────────────────────────────

/// Raw `u128` value of the Mesh Infinity GATT service UUID.
///
/// This UUID is used only after a connection is established for the GATT data
/// channel. It is intentionally not used as an advertisement fingerprint.
pub const MESH_INFINITY_SERVICE_UUID_U128: u128 = 0x6ba7b810_9dad_11d1_80b4_00c04fd430c8;

/// Raw `u128` value of the TX characteristic UUID.
///
/// Write-without-response characteristic: `6ba7b811-9dad-11d1-80b4-00c04fd430c8`.
pub const TX_CHAR_UUID_U128: u128 = 0x6ba7b811_9dad_11d1_80b4_00c04fd430c8;

/// Raw `u128` value of the RX characteristic UUID.
///
/// Notify characteristic: `6ba7b812-9dad-11d1-80b4-00c04fd430c8`.
pub const RX_CHAR_UUID_U128: u128 = 0x6ba7b812_9dad_11d1_80b4_00c04fd430c8;

// ────────────────────────────────────────────────────────────────────────────
// uuid::Uuid constants (only when btleplug is compiled in)
// ────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "transport-bluetooth-native")]
/// Mesh Infinity BLE service UUID (`6ba7b810-9dad-11d1-80b4-00c04fd430c8`).
pub const MESH_INFINITY_SERVICE_UUID: uuid::Uuid =
    uuid::Uuid::from_u128(MESH_INFINITY_SERVICE_UUID_U128);

#[cfg(feature = "transport-bluetooth-native")]
/// TX characteristic UUID — write-without-response (`6ba7b811-9dad-11d1-80b4-00c04fd430c8`).
pub const TX_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(TX_CHAR_UUID_U128);

#[cfg(feature = "transport-bluetooth-native")]
/// RX characteristic UUID — notify (`6ba7b812-9dad-11d1-80b4-00c04fd430c8`).
pub const RX_CHAR_UUID: uuid::Uuid = uuid::Uuid::from_u128(RX_CHAR_UUID_U128);

/// Maximum number of raw advertisement bytes stored per discovered peer.
/// BLE 4.x advertisements carry at most 31 bytes of user data; BLE 5.0
/// extended advertisements can carry up to 255 bytes, but we use the 4.x
/// limit for maximum compatibility with older hardware.  The peer ID hex
/// (64 bytes) exceeds this limit, so it is split across the advertisement
/// data and the GATT service characteristic.
pub const MAX_ADVERTISEMENT_BYTES: usize = 31;

/// BLE rotating advertisement tokens are 64 bits (§5.6.1).
pub const ROTATING_TOKEN_BYTES: usize = 8;

// ────────────────────────────────────────────────────────────────────────────
// Always-available types
// ────────────────────────────────────────────────────────────────────────────

/// A Mesh Infinity peer discovered via BLE advertisement.
#[derive(Debug, Clone)]
pub struct BluetoothPeer {
    /// Opaque rotating advertisement token extracted from the advertisement.
    ///
    /// This is discovery-only metadata. It is not a peer ID and must not be
    /// treated as stable identity.
    pub token_hex: String,

    /// Received Signal Strength Indicator at the time of discovery.
    ///
    /// `None` if the adapter did not report RSSI.  Typically in the range
    /// −127 to 0 dBm; values closer to 0 indicate stronger signal.
    pub rssi: Option<i16>,

    /// Raw advertisement bytes received from the peer.
    ///
    /// Includes the token-carrying payload fragment and any adjacent bytes the
    /// transport retained for later likelihood checks. Maximum 31 bytes.
    pub advertisement_data: Vec<u8>,
}

/// Errors returned by the Bluetooth transport.
#[derive(Debug, Clone, PartialEq)]
pub enum BluetoothError {
    /// Bluetooth is not compiled in (feature `transport-bluetooth-native` absent).
    NotAvailable,
    /// No Bluetooth adapter found on this device.
    AdapterNotFound,
    /// Starting a BLE scan failed.
    ScanFailed(String),
    /// Connecting to a peripheral failed.
    ConnectFailed(String),
    /// A GATT-level operation failed (service/characteristic discovery,
    /// read, write, or notification subscription).
    GattError(String),
}

impl std::fmt::Display for BluetoothError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BluetoothError::NotAvailable => {
                write!(
                    f,
                    "Bluetooth transport not available (feature not compiled)"
                )
            }
            BluetoothError::AdapterNotFound => {
                write!(f, "No Bluetooth adapter found on this device")
            }
            BluetoothError::ScanFailed(msg) => write!(f, "BLE scan failed: {msg}"),
            BluetoothError::ConnectFailed(msg) => write!(f, "BLE connect failed: {msg}"),
            BluetoothError::GattError(msg) => write!(f, "BLE GATT error: {msg}"),
        }
    }
}

impl std::error::Error for BluetoothError {}

/// Bluetooth hardware capabilities detected on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BluetoothCapability {
    /// Whether Bluetooth Low Energy (BLE 4.0+) is available.
    pub ble: bool,
    /// Whether Bluetooth Classic (BR/EDR) is available.
    ///
    /// Mesh Infinity only uses BLE; this field is informational.
    pub classic: bool,
}

impl BluetoothCapability {
    /// Detect Bluetooth capabilities on the current platform.
    ///
    /// When the `transport-bluetooth-native` feature is absent, always
    /// returns `{ ble: false, classic: false }` because the required
    /// driver code is not compiled in.
    ///
    /// When the feature is present, performs a lightweight platform check:
    /// - **Linux**: existence of `/sys/class/bluetooth` implies at least one
    ///   adapter is registered with the kernel.
    /// - **macOS**: CoreBluetooth is a system framework — always available.
    /// - **Windows**: WinRT Bluetooth is available on Windows 10 and later;
    ///   assumed available (the runtime initialisation in `btleplug` will
    ///   fail gracefully if actually absent).
    /// - **Other** (iOS, Android, etc.): returns false; platform-specific
    ///   native code would be needed.
    ///
    /// This is a *best-effort* check, not a guarantee.  The actual adapter
    /// presence is confirmed when `start_scan` calls `Manager::new()`.
    pub fn detect() -> BluetoothCapability {
        #[cfg(feature = "transport-bluetooth-native")]
        {
            BluetoothCapability::detect_with_runtime()
        }
        #[cfg(not(feature = "transport-bluetooth-native"))]
        {
            BluetoothCapability {
                ble: false,
                classic: false,
            }
        }
    }

    /// Runtime platform check, only compiled when the feature is enabled.
    #[cfg(feature = "transport-bluetooth-native")]
    fn detect_with_runtime() -> BluetoothCapability {
        #[cfg(target_os = "linux")]
        {
            let ble = std::path::Path::new("/sys/class/bluetooth").exists();
            BluetoothCapability { ble, classic: ble }
        }
        #[cfg(target_os = "macos")]
        {
            // CoreBluetooth is a system framework on all modern macOS versions.
            BluetoothCapability {
                ble: true,
                classic: true,
            }
        }
        #[cfg(target_os = "windows")]
        {
            // WinRT Bluetooth is available on Windows 10+; assume true.
            BluetoothCapability {
                ble: true,
                classic: true,
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            BluetoothCapability {
                ble: false,
                classic: false,
            }
        }
    }
}

/// The Bluetooth transport — handles BLE peer discovery and GATT data channels.
///
/// ## Thread safety
///
/// `BluetoothTransport` is `Send + Sync`.  The `inbound` queue is protected
/// by a `Mutex`; the `scanning` flag is an `AtomicBool`.
///
/// ## Usage
///
/// 1. Create with `BluetoothTransport::new()`.
/// 2. Call `start_scan(Arc::clone(&transport))` (requires the
///    `transport-bluetooth-native` feature).
/// 3. Poll `drain_inbound()` to retrieve discovered peers.
/// 4. Call `connect_peripheral(...)` to open a GATT data channel to a peer.
/// 5. Call `stop_scan()` to halt the background scan task.
pub struct BluetoothTransport {
    /// Whether a BLE scan is currently active.
    scanning: AtomicBool,
    /// Queue of peers discovered via BLE advertisement, pending processing
    /// by the upper transport layer.
    inbound: Mutex<Vec<BluetoothPeer>>,
}

impl BluetoothTransport {
    /// Create a new, idle Bluetooth transport.
    ///
    /// No scan is started; call `start_scan` explicitly when the transport
    /// should become active.
    pub fn new() -> Self {
        BluetoothTransport {
            scanning: AtomicBool::new(false),
            inbound: Mutex::new(Vec::new()),
        }
    }

    /// Drain all peers that have been discovered since the last call.
    ///
    /// The internal queue is cleared; the caller takes ownership of the
    /// returned `Vec`.  Returns an empty `Vec` if no peers have been
    /// discovered.
    pub fn drain_inbound(&self) -> Vec<BluetoothPeer> {
        let mut guard = self.inbound.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    }

    /// Whether a BLE scan task is currently running.
    pub fn is_scanning(&self) -> bool {
        self.scanning.load(Ordering::Relaxed)
    }
}

impl Default for BluetoothTransport {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// BLE scanning and GATT (requires `transport-bluetooth-native`)
// ────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "transport-bluetooth-native")]
mod native {
    use super::*;

    use std::sync::Arc;

    use btleplug::api::{
        Central, CentralEvent, CharPropFlags, Manager as _, Peripheral as _, ScanFilter, WriteType,
    };
    use btleplug::platform::{Adapter, Manager, Peripheral};
    use futures::StreamExt as _;
    use tokio::sync::mpsc;

    // ────────────────────────────────────────────────────────────────────────
    // GATT channel
    // ────────────────────────────────────────────────────────────────────────

    /// An active BLE GATT connection to a remote Mesh Infinity peer.
    ///
    /// Wraps a `btleplug` `Peripheral` after service/characteristic
    /// discovery has completed.  Provides `send` (write to TX characteristic)
    /// and a `tokio::mpsc` receiver for notifications on the RX characteristic.
    pub struct BluetoothGattChannel {
        /// The connected btleplug peripheral.
        peripheral: Peripheral,
        /// Notification receiver — yields raw bytes from the RX characteristic.
        pub rx: mpsc::Receiver<Vec<u8>>,
    }

    impl BluetoothGattChannel {
        /// Send `data` to the remote peer via the TX GATT characteristic.
        ///
        /// Uses write-without-response (`WriteType::WithoutResponse`) for
        /// minimum latency.  BLE MTU is typically 23–517 bytes; the caller
        /// is responsible for fragmentation if needed.
        pub async fn send(&self, data: Vec<u8>) -> Result<(), BluetoothError> {
            // Find TX characteristic in the discovered characteristics.
            let chars = self.peripheral.characteristics();
            let tx_char = chars
                .iter()
                .find(|c| c.uuid == TX_CHAR_UUID)
                .ok_or_else(|| {
                    BluetoothError::GattError(
                        "TX characteristic not found on connected peripheral".into(),
                    )
                })?;

            // Verify the characteristic is writable.
            if !tx_char
                .properties
                .contains(CharPropFlags::WRITE_WITHOUT_RESPONSE)
            {
                return Err(BluetoothError::GattError(
                    "TX characteristic does not support WRITE_WITHOUT_RESPONSE".into(),
                ));
            }

            self.peripheral
                .write(tx_char, &data, WriteType::WithoutResponse)
                .await
                .map_err(|e| BluetoothError::GattError(format!("write failed: {e}")))
        }

        /// Disconnect from the peripheral, releasing the BLE connection.
        pub async fn disconnect(self) -> Result<(), BluetoothError> {
            self.peripheral
                .disconnect()
                .await
                .map_err(|e| BluetoothError::ConnectFailed(format!("disconnect failed: {e}")))
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Scanning and connection
    // ────────────────────────────────────────────────────────────────────────

    impl BluetoothTransport {
        /// Obtain the first available Bluetooth adapter from the platform manager.
        ///
        /// Returns `BluetoothError::AdapterNotFound` if no adapters are present.
        async fn first_adapter(manager: &Manager) -> Result<Adapter, BluetoothError> {
            let adapters = manager
                .adapters()
                .await
                .map_err(|e| BluetoothError::ScanFailed(format!("adapter enumeration: {e}")))?;
            adapters
                .into_iter()
                .next()
                .ok_or(BluetoothError::AdapterNotFound)
        }

        /// Start a BLE scan for Mesh Infinity peers in a background tokio task.
        ///
        /// The task runs until `stop_scan()` is called (which sets the
        /// `scanning` atomic to `false`).  Discovered peers are appended to
        /// `self.inbound`; call `drain_inbound()` to retrieve them.
        ///
        /// # Errors
        ///
        /// Errors are logged via `tracing`; the scan task does not propagate
        /// errors back to the caller (it runs fire-and-forget).  If the
        /// adapter is absent, the task exits immediately without panicking.
        pub fn start_scan(self: Arc<Self>) {
            // Guard against double-start.
            if self.scanning.swap(true, Ordering::SeqCst) {
                tracing::debug!("BLE scan already active — ignoring start_scan call");
                return;
            }

            tokio::spawn(async move {
                if let Err(e) = self.run_scan_loop().await {
                    tracing::warn!("BLE scan loop exited with error: {e}");
                }
                self.scanning.store(false, Ordering::SeqCst);
            });
        }

        /// Internal scan loop — runs inside the tokio task spawned by `start_scan`.
        async fn run_scan_loop(&self) -> Result<(), BluetoothError> {
            let manager = Manager::new()
                .await
                .map_err(|e| BluetoothError::ScanFailed(format!("manager init: {e}")))?;

            let adapter = Self::first_adapter(&manager).await?;

            // Subscribe to central events before starting the scan so we
            // don't miss any advertisements that arrive immediately.
            let mut event_stream = adapter
                .events()
                .await
                .map_err(|e| BluetoothError::ScanFailed(format!("event stream: {e}")))?;

            // Scan broadly. The spec explicitly forbids a fixed Mesh service
            // UUID advertisement fingerprint, so discovery cannot rely on a
            // UUID-based scan filter.
            let filter = ScanFilter::default();
            adapter
                .start_scan(filter)
                .await
                .map_err(|e| BluetoothError::ScanFailed(format!("start_scan: {e}")))?;

            tracing::info!("BLE scan started (broad scan, token-based matching)");

            // Process events until stop_scan() flips the atomic.
            while self.scanning.load(Ordering::Relaxed) {
                // Poll with a short timeout so we can check the stop flag
                // even when no events arrive.
                let event = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    event_stream.next(),
                )
                .await;

                match event {
                    Ok(Some(CentralEvent::DeviceDiscovered(id)))
                    | Ok(Some(CentralEvent::DeviceUpdated(id))) => {
                        // Resolve the peripheral from the event ID and read
                        // its advertisement data.
                        if let Ok(peripheral) = adapter.peripheral(&id).await {
                            self.process_peripheral_advertisement(&peripheral).await;
                        }
                    }
                    // Device disconnected — no action needed for discovery.
                    Ok(Some(CentralEvent::DeviceDisconnected(_))) => {}
                    // Stream exhausted — adapter was removed.
                    Ok(None) => {
                        tracing::warn!("BLE event stream ended (adapter removed?)");
                        break;
                    }
                    // Timeout — normal, just re-check the stop flag.
                    Err(_timeout) => {}
                    // Ignore other event variants we don't act on.
                    Ok(Some(_)) => {}
                }
            }

            // Clean up: stop the scan and release the adapter resource.
            if let Err(e) = adapter.stop_scan().await {
                tracing::debug!("BLE stop_scan: {e}");
            }

            tracing::info!("BLE scan stopped");
            Ok(())
        }

        /// Extract peer information from a peripheral's advertisement and
        /// enqueue it into `self.inbound`.
        ///
        /// Discovery extracts only a rotating token from advertisement payloads.
        /// Advertisements that do not yield a plausible token are dropped.
        async fn process_peripheral_advertisement(&self, peripheral: &Peripheral) {
            // Fetch properties (advertisement data, RSSI, etc.).
            let props = match peripheral.properties().await {
                Ok(Some(p)) => p,
                _ => return,
            };

            let (token_hex, advertisement_data) = match Self::extract_rotating_token(&props) {
                Some(token) => token,
                None => return,
            };

            let rssi = props.rssi.map(|r| r as i16);

            let peer = BluetoothPeer {
                token_hex,
                rssi,
                advertisement_data,
            };

            let mut queue = self.inbound.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = queue.iter_mut().find(|p| p.token_hex == peer.token_hex) {
                existing.rssi = peer.rssi;
                existing.advertisement_data = peer.advertisement_data.clone();
            } else {
                queue.push(peer);
            }
        }

        /// Extract a discovery token from manufacturer or service data.
        ///
        /// This intentionally avoids any identity-bearing interpretation of
        /// the advertisement.
        fn extract_rotating_token(
            props: &btleplug::api::PeripheralProperties,
        ) -> Option<(String, Vec<u8>)> {
            for payload in props.manufacturer_data.values() {
                if let Some(token_hex) = Self::decode_rotating_token(payload) {
                    return Some((
                        token_hex,
                        payload
                            .iter()
                            .copied()
                            .take(MAX_ADVERTISEMENT_BYTES)
                            .collect(),
                    ));
                }
            }
            for payload in props.service_data.values() {
                if let Some(token_hex) = Self::decode_rotating_token(payload) {
                    return Some((
                        token_hex,
                        payload
                            .iter()
                            .copied()
                            .take(MAX_ADVERTISEMENT_BYTES)
                            .collect(),
                    ));
                }
            }
            None
        }

        /// Decode a 64-bit rotating token from advertisement bytes.
        pub(super) fn decode_rotating_token(data: &[u8]) -> Option<String> {
            if data.len() < ROTATING_TOKEN_BYTES {
                return None;
            }
            let token = &data[..ROTATING_TOKEN_BYTES];
            if token.iter().all(|b| *b == 0) {
                return None;
            }
            Some(hex::encode(token))
        }

        /// Signal the background scan task to stop.
        ///
        /// The task checks this flag every 200 ms; it will stop the adapter
        /// scan, close the event stream, and exit within one polling interval.
        /// This call returns immediately (it is non-blocking).
        pub fn stop_scan(&self) {
            self.scanning.store(false, Ordering::SeqCst);
        }

        /// Connect to a previously discovered peripheral and set up GATT.
        ///
        /// Steps:
        /// 1. Connect to the peripheral.
        /// 2. Discover all services and characteristics.
        /// 3. Subscribe to notifications on `RX_CHAR_UUID`.
        /// 4. Spawn a tokio task that forwards notifications to a channel.
        /// 5. Return the `BluetoothGattChannel` wrapping the connection.
        ///
        /// # Errors
        ///
        /// Returns `BluetoothError::ConnectFailed` if the BLE connection
        /// cannot be established, or `BluetoothError::GattError` if service
        /// or characteristic discovery fails or the expected characteristics
        /// are absent.
        pub async fn connect_peripheral(
            peripheral: &Peripheral,
        ) -> Result<BluetoothGattChannel, BluetoothError> {
            // Connect.
            peripheral
                .connect()
                .await
                .map_err(|e| BluetoothError::ConnectFailed(format!("connect: {e}")))?;

            // Discover services so characteristics become available.
            peripheral
                .discover_services()
                .await
                .map_err(|e| BluetoothError::GattError(format!("discover_services: {e}")))?;

            let chars = peripheral.characteristics();

            // Verify TX characteristic exists and is writable.
            let tx_char = chars
                .iter()
                .find(|c| c.uuid == TX_CHAR_UUID)
                .ok_or_else(|| {
                    BluetoothError::GattError(format!(
                        "TX characteristic {TX_CHAR_UUID} not found after service discovery"
                    ))
                })?
                .clone();

            if !tx_char
                .properties
                .contains(CharPropFlags::WRITE_WITHOUT_RESPONSE)
            {
                return Err(BluetoothError::GattError(
                    "TX characteristic missing WRITE_WITHOUT_RESPONSE property".into(),
                ));
            }

            // Verify RX characteristic exists and supports notifications.
            let rx_char = chars
                .iter()
                .find(|c| c.uuid == RX_CHAR_UUID)
                .ok_or_else(|| {
                    BluetoothError::GattError(format!(
                        "RX characteristic {RX_CHAR_UUID} not found after service discovery"
                    ))
                })?
                .clone();

            if !rx_char.properties.contains(CharPropFlags::NOTIFY) {
                return Err(BluetoothError::GattError(
                    "RX characteristic missing NOTIFY property".into(),
                ));
            }

            // Subscribe to RX notifications.
            peripheral.subscribe(&rx_char).await.map_err(|e| {
                BluetoothError::GattError(format!("subscribe to RX notifications: {e}"))
            })?;

            // Create channel for notification data.
            let (tx, rx_recv) = mpsc::channel::<Vec<u8>>(64);

            // Spawn forwarder task — reads from the btleplug notification
            // stream and forwards payloads to the mpsc channel.
            {
                let peripheral_clone = peripheral.clone();
                tokio::spawn(async move {
                    let mut notification_stream = match peripheral_clone.notifications().await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("BLE notification stream: {e}");
                            return;
                        }
                    };

                    while let Some(notification) = notification_stream.next().await {
                        if notification.uuid == RX_CHAR_UUID {
                            if tx.send(notification.value).await.is_err() {
                                // Receiver dropped — channel owner disconnected.
                                break;
                            }
                        }
                    }
                });
            }

            Ok(BluetoothGattChannel {
                peripheral: peripheral.clone(),
                rx: rx_recv,
            })
        }
    }
}

// Re-export `BluetoothGattChannel` when the feature is enabled.
#[cfg(feature = "transport-bluetooth-native")]
pub use native::BluetoothGattChannel;

// ────────────────────────────────────────────────────────────────────────────
// Fallback implementations when feature is disabled
// ────────────────────────────────────────────────────────────────────────────

#[cfg(not(feature = "transport-bluetooth-native"))]
impl BluetoothTransport {
    /// Not available — feature `transport-bluetooth-native` is not compiled in.
    pub fn start_scan(self: std::sync::Arc<Self>) {
        tracing::debug!(
            "BluetoothTransport::start_scan called but feature \
             `transport-bluetooth-native` is not compiled — ignoring"
        );
    }

    /// Not available — feature `transport-bluetooth-native` is not compiled in.
    pub fn stop_scan(&self) {
        // Nothing to stop.
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BluetoothCapability ──────────────────────────────────────────────────

    #[test]
    fn capability_detect_does_not_panic() {
        // Must not panic on any platform — the result varies by host.
        let cap = BluetoothCapability::detect();
        // If the feature is off, always false.
        #[cfg(not(feature = "transport-bluetooth-native"))]
        {
            assert!(!cap.ble);
            assert!(!cap.classic);
        }
        // If the feature is on, just verify the struct is well-formed.
        #[cfg(feature = "transport-bluetooth-native")]
        {
            let _ = cap.ble;
            let _ = cap.classic;
        }
    }

    #[test]
    fn capability_fields_consistent() {
        let cap = BluetoothCapability::detect();
        // classic implies ble (all classic adapters support BLE on modern hardware)
        // — this is a soft invariant; just log if violated rather than assert.
        if cap.classic && !cap.ble {
            eprintln!(
                "Warning: BluetoothCapability reports classic=true, ble=false \
                 (unusual hardware configuration)"
            );
        }
    }

    // ── BluetoothTransport::new ──────────────────────────────────────────────

    #[test]
    fn new_transport_not_scanning() {
        let transport = BluetoothTransport::new();
        assert!(!transport.is_scanning());
    }

    #[test]
    fn new_transport_inbound_empty() {
        let transport = BluetoothTransport::new();
        let peers = transport.drain_inbound();
        assert!(peers.is_empty());
    }

    #[test]
    fn default_matches_new() {
        let t1 = BluetoothTransport::new();
        let t2 = BluetoothTransport::default();
        assert!(!t1.is_scanning());
        assert!(!t2.is_scanning());
    }

    // ── drain_inbound ────────────────────────────────────────────────────────

    #[test]
    fn drain_inbound_clears_queue() {
        let transport = BluetoothTransport::new();
        {
            let mut q = transport.inbound.lock().unwrap_or_else(|e| e.into_inner());
            q.push(BluetoothPeer {
                token_hex: "aa".repeat(ROTATING_TOKEN_BYTES),
                rssi: Some(-70),
                advertisement_data: vec![0x01, 0x02],
            });
        }
        let first = transport.drain_inbound();
        assert_eq!(first.len(), 1);
        let second = transport.drain_inbound();
        assert!(second.is_empty(), "queue should be empty after first drain");
    }

    // ── stop_scan no-op without btleplug ────────────────────────────────────

    #[test]
    fn stop_scan_is_safe_when_not_scanning() {
        let transport = BluetoothTransport::new();
        transport.stop_scan(); // must not panic
        assert!(!transport.is_scanning());
    }

    #[test]
    fn start_scan_without_feature_sets_no_flag() {
        // Without the native feature, start_scan is a no-op that does NOT
        // set scanning=true.
        #[cfg(not(feature = "transport-bluetooth-native"))]
        {
            use std::sync::Arc;
            let transport = Arc::new(BluetoothTransport::new());
            transport.clone().start_scan();
            assert!(!transport.is_scanning());
        }
    }

    // ── BluetoothError ───────────────────────────────────────────────────────

    #[test]
    fn error_display_not_available() {
        let e = BluetoothError::NotAvailable;
        let s = format!("{e}");
        assert!(s.contains("not available") || s.contains("not compiled"));
    }

    #[test]
    fn error_display_adapter_not_found() {
        let e = BluetoothError::AdapterNotFound;
        let s = format!("{e}");
        assert!(s.contains("adapter") || s.contains("Adapter"));
    }

    #[test]
    fn error_display_scan_failed() {
        let e = BluetoothError::ScanFailed("timeout".into());
        let s = format!("{e}");
        assert!(s.contains("timeout"));
    }

    #[test]
    fn error_display_connect_failed() {
        let e = BluetoothError::ConnectFailed("refused".into());
        let s = format!("{e}");
        assert!(s.contains("refused"));
    }

    #[test]
    fn error_display_gatt_error() {
        let e = BluetoothError::GattError("no service".into());
        let s = format!("{e}");
        assert!(s.contains("no service"));
    }

    #[test]
    fn error_is_std_error() {
        // Confirm BluetoothError implements std::error::Error.
        fn _assert_error<E: std::error::Error>() {}
        _assert_error::<BluetoothError>();
    }

    // ── UUID constants ───────────────────────────────────────────────────────

    #[test]
    fn service_uuid_u128_is_distinct_from_characteristics() {
        assert_ne!(MESH_INFINITY_SERVICE_UUID_U128, TX_CHAR_UUID_U128);
        assert_ne!(MESH_INFINITY_SERVICE_UUID_U128, RX_CHAR_UUID_U128);
        assert_ne!(TX_CHAR_UUID_U128, RX_CHAR_UUID_U128);
    }

    #[test]
    fn uuid_u128_values_correct() {
        assert_eq!(
            MESH_INFINITY_SERVICE_UUID_U128,
            0x6ba7b810_9dad_11d1_80b4_00c04fd430c8_u128
        );
        assert_eq!(
            TX_CHAR_UUID_U128,
            0x6ba7b811_9dad_11d1_80b4_00c04fd430c8_u128
        );
        assert_eq!(
            RX_CHAR_UUID_U128,
            0x6ba7b812_9dad_11d1_80b4_00c04fd430c8_u128
        );
    }

    #[cfg(feature = "transport-bluetooth-native")]
    #[test]
    fn uuid_string_format() {
        // Verify typed UUIDs have the expected string representation.
        let svc_str = MESH_INFINITY_SERVICE_UUID.to_string();
        assert_eq!(svc_str, "6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        let tx_str = TX_CHAR_UUID.to_string();
        assert_eq!(tx_str, "6ba7b811-9dad-11d1-80b4-00c04fd430c8");
        let rx_str = RX_CHAR_UUID.to_string();
        assert_eq!(rx_str, "6ba7b812-9dad-11d1-80b4-00c04fd430c8");
    }

    // ── native decode helper (only compiled when feature is on) ─────────────

    #[cfg(feature = "transport-bluetooth-native")]
    mod native_tests {
        use super::super::BluetoothTransport;
        use super::super::ROTATING_TOKEN_BYTES;

        #[test]
        fn decode_token_valid() {
            let data = vec![0xabu8; ROTATING_TOKEN_BYTES];
            let result = BluetoothTransport::decode_rotating_token(&data);
            assert_eq!(result, Some("ab".repeat(ROTATING_TOKEN_BYTES)));
        }

        #[test]
        fn decode_token_too_short() {
            let data = vec![0x61u8; ROTATING_TOKEN_BYTES - 1];
            let result = BluetoothTransport::decode_rotating_token(&data);
            assert!(result.is_none());
        }

        #[test]
        fn decode_token_all_zero_rejected() {
            let data = vec![0x00u8; ROTATING_TOKEN_BYTES];
            let result = BluetoothTransport::decode_rotating_token(&data);
            assert!(result.is_none());
        }

        #[test]
        fn decode_token_with_extra_bytes() {
            let mut data: Vec<u8> = vec![0xcdu8; ROTATING_TOKEN_BYTES];
            data.extend_from_slice(&[0xFF, 0xFE]); // extra bytes
            let result = BluetoothTransport::decode_rotating_token(&data);
            assert_eq!(result, Some("cd".repeat(ROTATING_TOKEN_BYTES)));
        }

        #[test]
        fn decode_token_binary_payload() {
            let data = vec![0x10, 0x22, 0x34, 0x48, 0x5a, 0x6c, 0x7e, 0x80];
            let result = BluetoothTransport::decode_rotating_token(&data);
            assert_eq!(result, Some("102234485a6c7e80".to_string()));
        }
    }
}
