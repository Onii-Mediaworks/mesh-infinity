// network_state.dart
//
// This file implements NetworkState — the ChangeNotifier that owns all data
// related to transport configuration, network statistics, and local peer
// discovery for the Network section of the app.
//
// WHAT does "network state" cover?
// ----------------------------------
// Mesh Infinity can reach peers through several different transport layers:
//
//   Clearnet (TCP/IP)
//     Direct internet connections over ordinary IP.  Fast, but reveals IP
//     addresses to peers — lowest privacy, highest performance.
//     When to use: low-threat environments where speed matters most.
//
//   Tor
//     Traffic routed through the Tor anonymity network via onion services.
//     Hides the user's real IP address from peers and exit nodes.  Adds
//     latency (hundreds of ms) but is essential for high-threat users.
//
//     HOW Tor works (simplified):
//       Your message is encrypted three times and sent through three
//       randomly chosen relay nodes.  Each relay peels off one layer of
//       encryption — like peeling an onion — so no single relay knows both
//       the origin and destination.  The term "onion routing" comes from this.
//
//   I2P (Invisible Internet Project)
//     An alternative anonymity network with a different threat model to Tor.
//     Lower latency than Tor within I2P, but the overall user base is smaller.
//
//     HOW I2P differs from Tor:
//       I2P uses "garlic routing" — bundling multiple messages into a single
//       encrypted packet (like a garlic bulb with multiple cloves).  I2P is
//       designed primarily for internal network services (not accessing the
//       public internet), making it a good fit for a closed mesh chat network.
//
//   Bluetooth (planned)
//     Short-range direct connections (~10 m) for truly offline mesh scenarios.
//     No internet required.  Useful in conferences, protests, or disasters.
//
//   RF / Radio (planned)
//     Software-defined radio links for extreme off-grid use cases.
//     Range depends on hardware — can reach kilometres.
//
//   mDNS (Multicast DNS)
//     Local-area-network peer discovery — finds other Mesh Infinity nodes on
//     the same Wi-Fi without any internet connection.  Works by broadcasting
//     a DNS-SD service record on the LAN and listening for others.
//
// NetworkState tracks:
//   _settings        — which transports are enabled, node mode, pairing code, etc.
//   _stats           — live counters: bytes sent/received, connection count, etc.
//   _mdnsRunning     — whether the mDNS listener is currently active.
//   _discoveredPeers — nodes found on the local LAN via mDNS since it was started.
//
// WHY poll stats instead of receiving them as events?
// -----------------------------------------------------
// Network statistics (bytes transferred, round-trip time, peer count) change
// continuously.  Emitting a backend event for every counter increment would
// flood the event bus.  Instead, loadAll() fetches a stats snapshot on demand
// and the NetworkScreen can call loadAll() on a timer or pull-to-refresh.
//
// "On a timer" means NetworkScreen (or its State) would create a
// dart:async Timer.periodic that calls loadAll() every N seconds.  The stats
// panel then updates automatically while the user is looking at it.
//
// This is a deliberate trade-off:
//   - Stats are slightly stale (up to N seconds old).
//   - But the event bus is not flooded with noise.
//   - And loadAll() is cheap (synchronous FFI read of in-memory counters).
//
// For settings changes (e.g. toggle Tor on/off) we DO use events via
// SettingsUpdatedEvent, because settings changes are infrequent and
// correctness is critical (the UI MUST reflect the actual state).

import 'dart:async';
// dart:async provides StreamSubscription — the token returned when we
// subscribe to a stream, allowing us to cancel the subscription later.

import 'package:flutter/foundation.dart';
// ChangeNotifier lives here — the base class that powers the Provider pattern.

import '../../backend/backend_bridge.dart';
// BackendBridge — the FFI gateway to Rust.  All calls to native code go here.
import '../../backend/event_bus.dart';
// EventBus — the background isolate that polls Rust ~5 times/second and
// turns backend events into a Dart Stream.
import '../../backend/event_models.dart';
// BackendEvent and SettingsUpdatedEvent — the typed event hierarchy.
import '../../backend/models/network_models.dart';
// NetworkStatsModel   — typed stats snapshot (bytes, connections, etc.).
// DiscoveredPeerModel — info about a peer found via mDNS.
import '../../backend/models/settings_models.dart';
// SettingsModel — all app-level settings as a typed Dart object.

// ---------------------------------------------------------------------------
// Overlay Client Status
// ---------------------------------------------------------------------------

/// Connection state of a Mesh Infinity-managed overlay transport client
/// (Tailscale or ZeroTier). Mesh Infinity acts as the client itself — no
/// separate app or daemon is required.
enum OverlayClientStatus {
  /// Not set up — no credentials stored.
  notConfigured,
  /// Credentials stored; actively attempting to connect.
  connecting,
  /// Authenticated and connected to the overlay network.
  connected,
  /// Credentials stored but currently disconnected (e.g. transport disabled).
  disconnected,
  /// Authentication or connection error.
  error,
}

// ---------------------------------------------------------------------------
// NetworkState
// ---------------------------------------------------------------------------

/// NetworkState is the single source of truth for transport configuration and
/// live network data.  It is provided to the widget tree via Provider and
/// watched by NetworkScreen.
///
/// PATTERN: ChangeNotifier + Provider
/// -----------------------------------
/// 1. NetworkState extends ChangeNotifier.
/// 2. Provider registers it at the top of the widget tree (in app.dart).
/// 3. NetworkScreen (and any other network-related widget) calls
///    `context.watch<NetworkState>()` to subscribe.
/// 4. Every time NetworkState calls notifyListeners(), Flutter rebuilds
///    those subscribed widgets with the latest data.
class NetworkState extends ChangeNotifier {
  /// [bridge] is the FFI gateway passed in from the Provider setup.
  /// Dependency injection (passing it in rather than constructing it here)
  /// keeps NetworkState testable with a mock bridge.
  NetworkState(this._bridge) {
    // Subscribe to the EventBus stream immediately so we receive
    // SettingsUpdatedEvent notifications pushed from Rust.
    _sub = EventBus.instance.stream.listen(_onEvent);

    // Load an initial snapshot so the NetworkScreen is populated right away.
    loadAll();
  }

  // -------------------------------------------------------------------------
  // Private fields
  // -------------------------------------------------------------------------

  /// The FFI bridge — our only path to the Rust backend.
  final BackendBridge _bridge;

  /// Handle to the EventBus stream subscription.
  /// Kept so we can call _sub?.cancel() in dispose() and stop receiving events
  /// after this object is destroyed.
  StreamSubscription<BackendEvent>? _sub;

  /// Guard flag to prevent notifyListeners() after dispose().
  /// Stream cancellation is asynchronous — an event can arrive between
  /// cancel() and actual teardown, causing a "used after dispose" exception.
  bool _disposed = false;

  /// The full settings model fetched from the backend.
  /// Null until the first loadAll() call completes.
  /// Contains: which transports are enabled, node mode, pairing code, peer ID, etc.
  SettingsModel? _settings;

  /// A snapshot of live network counters from the backend.
  /// Null until the first successful stats fetch.
  /// Contains: bytes sent, bytes received, number of active connections, etc.
  NetworkStatsModel? _stats;

  /// Whether the mDNS (local network discovery) service is currently running.
  /// When false, _discoveredPeers is always empty because no scanning happens.
  bool _mdnsRunning = false;

  /// List of peers discovered on the local area network via mDNS since the
  /// last time mDNS was enabled.  Cleared when mDNS is disabled.
  List<DiscoveredPeerModel> _discoveredPeers = const [];

  // ---- VPN state ----

  /// Current VPN mode: "off", "mesh_only", "exit_node", "policy_based".
  String _vpnMode = 'off';

  /// The peer ID of the selected exit node, or null if none selected.
  String? _selectedExitNodeId;

  /// The selected Tailscale exit node name, or null if none selected.
  String? _selectedTailscaleExitNode;

  /// The selected exit profile ID, or null if none selected.
  String? _selectedExitProfileId;

  /// VPN connection status: "disconnected", "connecting", "connected".
  String _vpnConnectionStatus = 'disconnected';

  /// Whether the kill switch is enabled (block traffic if VPN drops).
  bool _vpnKillSwitch = false;

  /// VPN uptime in seconds since connection was established.
  int _vpnUptimeSeconds = 0;

  /// Backend-owned summary of the current routing security posture.
  String _vpnSecurityPosture = 'normal_network';

  /// Whether the current route changes the IP websites see.
  bool _vpnChangesInternetIp = false;

  /// Whether the current route can expose destinations to an exit node.
  bool _vpnExitNodeSeesDestinations = false;

  /// Backend-owned classification of the active exit route.
  String _vpnExitRouteKind = 'none';

  /// App Connector selection mode.
  String _appConnectorMode = 'allowlist';

  /// App Connector entries owned by the backend.
  List<Map<String, dynamic>> _appConnectorApps = const [];

  /// Explicit selector-based App Connector rules owned by the backend.
  List<Map<String, dynamic>> _appConnectorRules = const [];

  // ---- Overlay client state (§5.22, §5.23) ----

  /// Tailscale client connection status.
  OverlayClientStatus _tailscaleClientStatus = OverlayClientStatus.notConfigured;

  /// ZeroTier client connection status.
  OverlayClientStatus _zerotierClientStatus = OverlayClientStatus.notConfigured;

  /// Full backend-owned Tailscale status payload.
  Map<String, dynamic> _tailscaleOverlay = const {};

  /// Full backend-owned ZeroTier status payload.
  Map<String, dynamic> _zerotierOverlay = const {};

  // ---- Trusted context state (§4.8.3) ----

  /// Whether Tailscale is a trusted context for discovery.
  bool _tailscaleTrusted = true;

  /// Whether ZeroTier is a trusted context for discovery.
  bool _zerotierTrusted = true;

  /// Whether LAN is a trusted context for discovery.
  bool _lanTrusted = false;

  /// Whether mDNS is allowed on trusted context transports.
  bool _mdnsOnTrusted = true;

  // ---- Trust metrics ----

  /// Trust distribution: map from trust level (0-8) to count.
  Map<int, int> _trustCounts = {};

  /// Pairing method counts: map from method name to count.
  Map<String, int> _pairingCounts = {};

  /// Total number of known peers.
  int _totalPeers = 0;

  /// Routing table summary (§6): directPeers, totalRoutes.
  Map<String, dynamic> _routingStats = const {};


  // -------------------------------------------------------------------------
  // Public getters
  // -------------------------------------------------------------------------

  /// The current settings snapshot.  Null while the initial load is running.
  /// NetworkScreen uses this to populate transport toggle switches.
  SettingsModel? get settings => _settings;

  /// Live network statistics.  Null before the first stats fetch.
  /// NetworkScreen uses this to display byte counters and connection info.
  NetworkStatsModel? get stats => _stats;

  /// True when the mDNS listener is active on the local network interface.
  /// Used to drive the mDNS toggle switch state in NetworkScreen.
  bool get mdnsRunning => _mdnsRunning;

  /// Peers found on the LAN.  Empty when mDNS is off or when no nodes are
  /// nearby.
  List<DiscoveredPeerModel> get discoveredPeers => _discoveredPeers;

  // ---- VPN getters ----

  /// Current VPN mode: "off", "mesh_only", "exit_node", "policy_based".
  String get vpnMode => _vpnMode;

  /// The peer ID of the selected exit node, or null.
  String? get selectedExitNodeId => _selectedExitNodeId;

  /// The selected Tailscale exit node name, or null.
  String? get selectedTailscaleExitNode => _selectedTailscaleExitNode;

  /// The selected exit profile ID, or null.
  String? get selectedExitProfileId => _selectedExitProfileId;

  /// VPN connection status: "disconnected", "connecting", "connected".
  String get vpnConnectionStatus => _vpnConnectionStatus;

  /// Whether the kill switch is enabled.
  bool get vpnKillSwitch => _vpnKillSwitch;

  /// VPN uptime in seconds.
  int get vpnUptimeSeconds => _vpnUptimeSeconds;

  /// Backend-owned routing security posture code.
  String get vpnSecurityPosture => _vpnSecurityPosture;

  /// Whether the current route changes the visible internet IP.
  bool get vpnChangesInternetIp => _vpnChangesInternetIp;

  /// Whether an exit node can see traffic destinations after they leave the mesh.
  bool get vpnExitNodeSeesDestinations => _vpnExitNodeSeesDestinations;

  /// Backend-owned classification of the active exit route.
  String get vpnExitRouteKind => _vpnExitRouteKind;

  /// Current App Connector selection mode.
  String get appConnectorMode => _appConnectorMode;

  /// Current App Connector app entries.
  List<Map<String, dynamic>> get appConnectorApps => _appConnectorApps;

  /// Current App Connector explicit rules.
  List<Map<String, dynamic>> get appConnectorRules => _appConnectorRules;

  /// Whether the VPN is in any active mode (not "off").
  bool get isVpnActive => _vpnMode != 'off';

  // ---- Overlay client getters (§5.22, §5.23) ----

  /// Tailscale client connection status.
  OverlayClientStatus get tailscaleClientStatus => _tailscaleClientStatus;

  /// ZeroTier client connection status.
  OverlayClientStatus get zerotierClientStatus => _zerotierClientStatus;

  /// Full backend-owned Tailscale overlay status.
  Map<String, dynamic> get tailscaleOverlay => _tailscaleOverlay;

  /// Full backend-owned ZeroTier overlay status.
  Map<String, dynamic> get zerotierOverlay => _zerotierOverlay;

  // ---- Trusted context getters (§4.8.3) ----

  /// Whether Tailscale is marked as a trusted context for discovery.
  bool get tailscaleTrusted => _tailscaleTrusted;

  /// Whether ZeroTier is marked as a trusted context for discovery.
  bool get zerotierTrusted => _zerotierTrusted;

  /// Whether the local LAN is marked as a trusted context.
  bool get lanTrusted => _lanTrusted;

  /// Whether mDNS is allowed on trusted context transports.
  bool get mdnsOnTrusted => _mdnsOnTrusted;

  // ---- Trust metrics getters ----

  /// Trust level distribution: map from level (0-8) to peer count.
  Map<int, int> get trustCounts => _trustCounts;

  /// Pairing method distribution: map from method name to count.
  Map<String, int> get pairingCounts => _pairingCounts;

  /// Total number of known peers.
  int get totalPeers => _totalPeers;

  /// Routing table summary: directPeers, totalRoutes (§6).
  Map<String, dynamic> get routingStats => _routingStats;

  /// Count of untrusted-tier peers (levels 0-5).
  int get untrustedCount =>
      _trustCounts.entries
          .where((e) => e.key < 6)
          .fold(0, (sum, e) => sum + e.value);

  // -------------------------------------------------------------------------
  // Data loading
  // -------------------------------------------------------------------------

  /// Fetches a fresh snapshot of settings, stats, mDNS status, and discovered
  /// peers from the backend, then notifies listeners so the UI updates.
  ///
  /// Called:
  ///   - Once in the constructor (initial load).
  ///   - From NetworkScreen's pull-to-refresh handler.
  ///   - After any mutating action (toggleTransport, setNodeMode, etc.) to
  ///     confirm what the backend actually applied.
  ///
  /// All four bridge calls are synchronous — they read from Rust's in-memory
  /// state and serialise it to JSON.  There is no network I/O in this method.
  /// The `async` keyword is present only for API consistency (callers can
  /// `await loadAll()` in a pull-to-refresh callback to know when the data
  /// has been loaded and the spinner should stop).
  Future<void> loadAll() async {
    // fetchSettings() returns a SettingsModel decoded from the JSON the
    // Rust backend serialises.  Fields include: nodeMode, enableTor,
    // enableClearnet, meshDiscovery, allowRelays, enableI2p, enableBluetooth,
    // enableRf, pairingCode, localPeerId.
    //
    // fetchSettings() never returns null — if there are no settings yet the
    // backend returns its defaults.
    final raw = _bridge.fetchSettings();
    _settings = raw;

    // getNetworkStats() returns a JSON-encoded stats blob or null if the
    // backend has not accumulated any stats yet (e.g. no connections have
    // been made since the app started).
    final statsRaw = _bridge.getNetworkStats();
    if (statsRaw != null) _stats = NetworkStatsModel.fromJson(statsRaw);
    // If statsRaw is null we leave _stats as it was — the previous snapshot
    // is better than showing nothing.  Widgets should guard for null _stats
    // and show a "no data yet" placeholder when it is null.

    // Ask the backend whether its mDNS listener socket is currently open.
    // This is a simple bool — no JSON decoding needed.
    _mdnsRunning = _bridge.isMdnsRunning();

    // getDiscoveredPeers() returns a list of JSON objects, one per peer
    // that responded to mDNS queries since the listener started.
    final rawPeers = _bridge.getDiscoveredPeers();
    // `.map(DiscoveredPeerModel.fromJson)` passes the static factory method
    // as a function reference.  Each JSON Map is converted to a
    // DiscoveredPeerModel.  `.toList()` forces evaluation of the lazy Iterable.
    _discoveredPeers = rawPeers
        .map(DiscoveredPeerModel.fromJson) // Decode each JSON blob.
        .toList();

    // Fetch VPN status from the backend (may be null if not yet implemented).
    final vpnStatus = _bridge.getVpnStatus();
    if (vpnStatus != null) {
      _vpnMode = vpnStatus['mode'] as String? ?? 'off';
      _selectedExitNodeId = vpnStatus['exitNodePeerId'] as String?;
      _selectedTailscaleExitNode = vpnStatus['tailscaleExitNode'] as String?;
      _selectedExitProfileId = vpnStatus['exitProfileId'] as String?;
      _vpnConnectionStatus = vpnStatus['connectionStatus'] as String? ?? 'disconnected';
      _vpnKillSwitch = vpnStatus['killSwitch'] as bool? ?? false;
      _vpnUptimeSeconds = vpnStatus['uptimeSeconds'] as int? ?? 0;
      _vpnSecurityPosture = vpnStatus['securityPosture'] as String? ?? 'normal_network';
      _vpnChangesInternetIp = vpnStatus['changesInternetIp'] as bool? ?? false;
      _vpnExitNodeSeesDestinations =
          vpnStatus['exitNodeSeesDestinations'] as bool? ?? false;
      _vpnExitRouteKind = vpnStatus['exitRouteKind'] as String? ?? 'none';
    }

    final connectorConfig = _bridge.getAppConnectorConfig();
    if (connectorConfig != null) {
      _appConnectorMode = connectorConfig['mode'] as String? ?? 'allowlist';
      _appConnectorApps = _readAppConnectorEntries(connectorConfig['apps']);
      _appConnectorRules = _readAppConnectorEntries(connectorConfig['rules']);
    }

    final overlayStatus = _bridge.getOverlayStatus();
    if (overlayStatus != null) {
      final tailscale =
          overlayStatus['tailscale'] is Map<String, dynamic>
              ? overlayStatus['tailscale'] as Map<String, dynamic>
              : overlayStatus['tailscale'] is Map
                  ? Map<String, dynamic>.from(overlayStatus['tailscale'] as Map)
                  : const <String, dynamic>{};
      final zerotier =
          overlayStatus['zerotier'] is Map<String, dynamic>
              ? overlayStatus['zerotier'] as Map<String, dynamic>
              : overlayStatus['zerotier'] is Map
                  ? Map<String, dynamic>.from(overlayStatus['zerotier'] as Map)
                  : const <String, dynamic>{};
      _tailscaleClientStatus = _parseOverlayClientStatus(
        tailscale['status'] as String?,
        connectedFallback: tailscale['connected'] == true,
      );
      _zerotierClientStatus = _parseOverlayClientStatus(
        zerotier['status'] as String?,
        connectedFallback: zerotier['connected'] == true,
      );
      _tailscaleOverlay = Map<String, dynamic>.from(tailscale);
      _zerotierOverlay = Map<String, dynamic>.from(zerotier);
    }

    // Fetch routing table summary (§6).
    final routing = _bridge.getRoutingTableStats();
    if (routing != null) _routingStats = routing;

    // Load trust metrics from the contact store.
    _loadTrustMetrics();

    if (!_disposed) notifyListeners(); // Rebuild the NetworkScreen with fresh data.
  }

  // -------------------------------------------------------------------------
  // Transport control
  // -------------------------------------------------------------------------
  //
  // All transport-control methods follow the same pattern:
  //   1. Call the bridge to apply the change to Rust's running state.
  //   2. If the change was accepted (ok == true), re-fetch settings so _settings
  //      reflects what the backend actually did (it may differ from what we
  //      asked for, e.g. if enabling I2P automatically disables an
  //      incompatible transport).
  //   3. Call notifyListeners() so the toggle switches in NetworkScreen update.
  //   4. Return the bool so the UI can show an error message on failure.

  /// Enables or disables a named transport layer.
  ///
  /// [name] is one of: "tor", "clearnet", "i2p", "bluetooth", "rf".
  ///   The string must exactly match what the Rust backend expects.
  /// [enabled] is the new desired state (true = turn on, false = turn off).
  ///
  /// After a successful toggle we re-fetch settings so the UI reflects what
  /// the backend actually applied (the backend may reject or adjust the
  /// request based on dependencies between transports).
  ///
  /// WHY does each transport need to be toggled at runtime?
  /// -------------------------------------------------------
  /// Each transport has different privacy, performance, and resource
  /// trade-offs.  Users in different threat environments (e.g. a journalist
  /// in an authoritarian country vs a hiker using local mesh) need to
  /// enable/disable them on the fly without restarting the app.
  ///
  /// Transport dependencies (examples):
  ///   - Enabling Tor may start the embedded Tor daemon, which takes a few
  ///     seconds to build a circuit.  The UI switch should optimistically
  ///     flip, then a later SettingsUpdatedEvent confirms when Tor is ready.
  ///   - Disabling clearnet while Tor is off would leave no transport at all;
  ///     the backend may refuse this combination and return false.
  ///
  /// Returns true if the backend accepted the change, false if it rejected it.
  Future<bool> toggleTransport(String name, bool enabled) async {
    final ok = _bridge.toggleTransport(name, enabled);
    // Always re-fetch the authoritative settings from Rust, regardless of
    // whether the toggle succeeded.  If the backend rejected the change the
    // UI must revert to the actual state, not show the intended state.
    final raw = _bridge.fetchSettings();
    _settings = raw;
    if (!_disposed) notifyListeners();
    return ok; // Return false if the backend rejected the change.
  }

  /// Changes the node's operational mode.
  ///
  /// [mode] is an integer defined by the Rust backend:
  ///   0 = standard peer (sends and receives messages).
  ///   1 = relay node    (forwards messages for peers that can't reach each other).
  ///   (additional modes may be added in future).
  ///
  /// WHY have node modes?
  /// ---------------------
  /// A relay node has looser firewall/NAT requirements but also higher resource
  /// usage (CPU, bandwidth).  Not every user wants to donate bandwidth to the
  /// network, so this is opt-in.
  ///
  /// A relay node helps the mesh stay connected when two peers cannot reach
  /// each other directly (e.g. one is behind NAT and the other is on a
  /// different LAN segment).  The relay forwards encrypted packets without
  /// being able to read them.
  Future<bool> setNodeMode(int mode) async {
    final ok = _bridge.setNodeMode(mode);
    // Always re-fetch settings so the UI reflects the actual backend state,
    // even if the mode change was rejected.
    final raw = _bridge.fetchSettings();
    _settings = raw;
    if (!_disposed) notifyListeners();
    return ok;
  }

  /// Change the clearnet TCP listen port (default 7234).
  ///
  /// Takes effect on the next `mi_start_clearnet_listener` call.
  /// Port must be in range 1024–65535.
  Future<bool> setClearnetPort(int port) async {
    if (port < 1024 || port > 65535) return false;
    final ok = _bridge.setClearnetPort(port);
    final raw = _bridge.fetchSettings();
    _settings = raw;
    if (!_disposed) notifyListeners();
    return ok;
  }

  // -------------------------------------------------------------------------
  // VPN / Exit Node
  // -------------------------------------------------------------------------

  /// Set the VPN mode.
  ///
  /// [mode] is one of: "off", "mesh_only", "exit_node", "policy_based".
  /// [exitNodePeerId] is required when mode is "exit_node".
  ///
  /// Returns true if the backend accepted the change.
  Future<bool> setVpnMode(
    String mode, {
    String? exitNodePeerId,
    String? tailscaleExitNode,
    String? exitProfileId,
  }) async {
    final ok = _bridge.setVpnMode(
      mode,
      exitNodePeerId: exitNodePeerId,
      tailscaleExitNode: tailscaleExitNode,
      exitProfileId: exitProfileId,
    );
    if (ok) {
      _vpnMode = mode;
      _selectedExitNodeId = exitNodePeerId;
      _selectedTailscaleExitNode = tailscaleExitNode;
      _selectedExitProfileId = exitProfileId;
      _vpnConnectionStatus = mode == 'off' ? 'disconnected' : 'connecting';
      _vpnUptimeSeconds = 0;
    }
    // Re-fetch to get authoritative state from backend.
    final vpnStatus = _bridge.getVpnStatus();
    if (vpnStatus != null) {
      _vpnMode = vpnStatus['mode'] as String? ?? _vpnMode;
      _selectedExitNodeId = vpnStatus['exitNodePeerId'] as String? ?? _selectedExitNodeId;
      _selectedTailscaleExitNode =
          vpnStatus['tailscaleExitNode'] as String? ?? _selectedTailscaleExitNode;
      _selectedExitProfileId =
          vpnStatus['exitProfileId'] as String? ?? _selectedExitProfileId;
      _vpnConnectionStatus = vpnStatus['connectionStatus'] as String? ?? _vpnConnectionStatus;
      _vpnKillSwitch = vpnStatus['killSwitch'] as bool? ?? _vpnKillSwitch;
      _vpnUptimeSeconds = vpnStatus['uptimeSeconds'] as int? ?? _vpnUptimeSeconds;
      _vpnSecurityPosture = vpnStatus['securityPosture'] as String? ?? _vpnSecurityPosture;
      _vpnChangesInternetIp = vpnStatus['changesInternetIp'] as bool? ?? _vpnChangesInternetIp;
      _vpnExitNodeSeesDestinations =
          vpnStatus['exitNodeSeesDestinations'] as bool? ?? _vpnExitNodeSeesDestinations;
      _vpnExitRouteKind = vpnStatus['exitRouteKind'] as String? ?? _vpnExitRouteKind;
    }
    if (!_disposed) notifyListeners();
    return ok;
  }

  /// Enable or disable the VPN kill switch.
  Future<bool> setVpnKillSwitch(bool enabled) async {
    final ok = _bridge.setVpnKillSwitch(enabled);
    if (ok) {
      _vpnKillSwitch = enabled;
    }
    if (!_disposed) notifyListeners();
    return ok;
  }

  /// Replace the App Connector configuration in the backend.
  Future<bool> setAppConnectorConfig({
    required String mode,
    required List<Map<String, dynamic>> apps,
    List<Map<String, dynamic>>? rules,
  }) async {
    final ok = _bridge.setAppConnectorConfig({
      'mode': mode,
      'apps': apps,
      'rules': rules ?? _appConnectorRules,
    });
    if (ok) {
      _appConnectorMode = mode;
      _appConnectorApps = apps
          .map((entry) => Map<String, dynamic>.from(entry))
          .toList();
      _appConnectorRules = (rules ?? _appConnectorRules)
          .map((entry) => Map<String, dynamic>.from(entry))
          .toList();
    } else {
      final config = _bridge.getAppConnectorConfig();
      if (config != null) {
        _appConnectorMode = config['mode'] as String? ?? _appConnectorMode;
        _appConnectorApps = _readAppConnectorEntries(config['apps']);
        _appConnectorRules = _readAppConnectorEntries(config['rules']);
      }
    }
    if (!_disposed) notifyListeners();
    return ok;
  }

  // -------------------------------------------------------------------------
  // mDNS (local network discovery)
  // -------------------------------------------------------------------------
  //
  // mDNS is the only transport managed directly from NetworkState rather than
  // through toggleTransport().  The reason is that mDNS is a "discovery"
  // mechanism, not a "data transport" — it finds peers and populates
  // _discoveredPeers; the actual messages still travel via clearnet/Tor/I2P.
  // mDNS also returns a structured list of discovered peers, not just a bool,
  // so it has its own state fields (_mdnsRunning and _discoveredPeers).

  /// Starts the mDNS (Multicast DNS) listener on [port] (default 51820).
  ///
  /// WHAT is mDNS?
  /// -------------
  /// Multicast DNS is an IETF standard (RFC 6762) that lets devices on a
  /// local network find each other without a central DNS server.  Devices
  /// broadcast a special DNS query to a multicast IP address (224.0.0.251 on
  /// IPv4) and others on the same subnet respond with their service records.
  ///
  /// Mesh Infinity uses mDNS to discover other nodes on the same Wi-Fi network
  /// automatically — the user doesn't need to know IP addresses.  This is
  /// essential for local mesh scenarios (e.g. a community event, an emergency
  /// shelter, or a LAN party with no internet).
  ///
  /// The mDNS flow:
  ///   1. enableMdns() → Rust opens a UDP socket and binds to 224.0.0.251:5353.
  ///   2. Rust broadcasts a DNS-SD service record: "_meshinfinity._tcp.local".
  ///   3. Other Mesh Infinity nodes on the LAN see the broadcast and respond.
  ///   4. Rust adds each responding node to its discovered-peers list.
  ///   5. The UI calls loadAll() (or pull-to-refresh) to see the updated list.
  ///
  /// WHY default port 51820?
  /// -----------------------
  /// 51820 is the well-known WireGuard port.  Mesh Infinity reuses it as a
  /// convention for the service advertisement port, though the actual
  /// transport is not WireGuard.
  ///
  /// Named parameters with `{...}` and a default value:
  ///   `{int port = 51820}` means [port] is optional and defaults to 51820
  ///   if the caller doesn't specify it.  The `{` curly braces `}` make it a
  ///   named parameter (callers write `enableMdns(port: 8080)`).
  ///
  /// On success:
  ///   - Sets _mdnsRunning = true.
  ///   - Notifies listeners so the toggle in NetworkScreen flips to "on".
  Future<bool> enableMdns({int port = 51820}) async {
    final ok = _bridge.enableMdns(port: port);
    // Always re-fetch mDNS state from the backend so the UI reflects reality,
    // even if the enable call was rejected.
    _mdnsRunning = _bridge.isMdnsRunning();
    if (!_disposed) notifyListeners();
    return ok;
  }

  /// Stops the mDNS listener and clears the discovered-peers list.
  ///
  /// Clearing _discoveredPeers when mDNS stops is correct because:
  ///   - The list reflects *currently reachable* LAN peers, not historic ones.
  ///   - Once the listener is off we have no way to know if those peers are
  ///     still present (they could have left the network).
  ///   - Showing stale "discovered peers" would confuse the user (they might
  ///     try to connect to a peer that is no longer there).
  ///
  /// `const []` is a compile-time constant empty list.  It is slightly more
  /// efficient than `[]` (which creates a new object at runtime) because
  /// Dart can reuse the same empty list instance everywhere `const []` appears.
  Future<bool> disableMdns() async {
    final ok = _bridge.disableMdns();
    // Always re-fetch mDNS state and discovered peers from the backend so the
    // UI reflects reality, even if the disable call was rejected.
    _mdnsRunning = _bridge.isMdnsRunning();
    if (!_mdnsRunning) {
      _discoveredPeers = const []; // Clear stale discovery data.
    } else {
      final rawPeers = _bridge.getDiscoveredPeers();
      _discoveredPeers = rawPeers.map(DiscoveredPeerModel.fromJson).toList();
    }
    if (!_disposed) notifyListeners();
    return ok;
  }

  // -------------------------------------------------------------------------
  // Overlay client status updates (§5.22, §5.23)
  // -------------------------------------------------------------------------

  /// Update the connection status of an overlay transport client.
  ///
  /// Called by the setup screens after authentication, and by the backend
  /// event handler when overlay connection state changes.
  void setOverlayClientStatus(String overlay, OverlayClientStatus status) {
    switch (overlay) {
      case 'tailscale':
        _tailscaleClientStatus = status;
      case 'zerotier':
        _zerotierClientStatus = status;
    }
    if (!_disposed) notifyListeners();
  }

  OverlayClientStatus _parseOverlayClientStatus(
    String? raw, {
    required bool connectedFallback,
  }) {
    switch (raw) {
      case 'connected':
        return OverlayClientStatus.connected;
      case 'connecting':
        return OverlayClientStatus.connecting;
      case 'disconnected':
        return OverlayClientStatus.disconnected;
      case 'error':
        return OverlayClientStatus.error;
      case 'notconfigured':
      case 'not_configured':
        return OverlayClientStatus.notConfigured;
      default:
        return connectedFallback
            ? OverlayClientStatus.connected
            : OverlayClientStatus.notConfigured;
    }
  }

  // Trusted Context control (§4.8.3)
  // -------------------------------------------------------------------------
  //
  // Trusted contexts control which networks permit automatic peer discovery.
  // They do NOT affect routing or pathing — only mDNS/local discovery.
  // Pairing over a trusted context gives the peer a trust boost.

  /// Toggle a trusted context.
  ///
  /// [context] is one of: "tailscale", "zerotier", "lan", "mdns".
  /// [enabled] is the new state.
  void setTrustedContext(String context, bool enabled) {
    switch (context) {
      case 'tailscale':
        _tailscaleTrusted = enabled;
      case 'zerotier':
        _zerotierTrusted = enabled;
      case 'lan':
        _lanTrusted = enabled;
      case 'mdns':
        _mdnsOnTrusted = enabled;
    }
    // Persist the change to the backend.
    _bridge.setTrustedContext(context, enabled);
    if (!_disposed) notifyListeners();
  }

  /// Load trust metrics from the peer list.
  ///
  /// Computes trust distribution and pairing method counts from
  /// the contact store. Called from loadAll().
  void _loadTrustMetrics() {
    final peers = _bridge.getPeerList();
    _totalPeers = peers.length;
    _trustCounts = {};
    _pairingCounts = {};

    for (final peer in peers) {
      final level = peer['trustLevel'] as int? ?? 0;
      _trustCounts[level] = (_trustCounts[level] ?? 0) + 1;

      final method = peer['pairingMethod'] as String? ?? 'Unspecified';
      _pairingCounts[method] = (_pairingCounts[method] ?? 0) + 1;
    }
  }

  // -------------------------------------------------------------------------
  // Event handling
  // -------------------------------------------------------------------------

  /// Reacts to events emitted by the background EventBus isolate.
  ///
  /// NetworkState only cares about SettingsUpdatedEvent — fired by the Rust
  /// backend whenever a settings change is confirmed (e.g. after a transport
  /// handshake completes or a config file is written).
  ///
  /// WHY do we also listen to events after already calling toggleTransport()?
  /// -------------------------------------------------------------------------
  /// toggleTransport() is optimistic: it fires and re-fetches immediately.
  /// But some changes (e.g. Tor circuit establishment) take seconds to complete.
  /// The backend may emit a SettingsUpdatedEvent later to signal "the change
  /// is now truly active".  Listening here ensures the UI eventually shows the
  /// correct state even if the initial re-fetch was too early.
  void _onEvent(BackendEvent event) {
    switch (event) {
      case SettingsUpdatedEvent(:final settings):
        // Replace our local copy of settings with the authoritative version
        // from the backend event payload.
        _settings = settings;
        if (!_disposed) notifyListeners();
        return;
      case AppConnectorConfigChangedEvent(:final config):
        _appConnectorMode = config['mode'] as String? ?? _appConnectorMode;
        _appConnectorApps = _readAppConnectorEntries(config['apps']);
        _appConnectorRules = _readAppConnectorEntries(config['rules']);
        if (!_disposed) notifyListeners();
        return;
      case OverlayStatusChangedEvent():
        unawaited(loadAll());
        return;
      default:
        return;
    }
  }

  // -------------------------------------------------------------------------
  // Cleanup
  // -------------------------------------------------------------------------

  @override
  void dispose() {
    _disposed = true;
    // Cancel the EventBus subscription so this object can be garbage-collected.
    // Without cancellation the stream listener closure would keep a reference
    // to this NetworkState alive indefinitely, leaking memory.
    _sub?.cancel();
    // `?.cancel()` — the null-safe call: only cancel if _sub was assigned.

    super.dispose(); // Let ChangeNotifier do its own cleanup.
  }

  List<Map<String, dynamic>> _readAppConnectorEntries(Object? raw) {
    if (raw is! List) {
      return const [];
    }
    return raw.map((entry) => Map<String, dynamic>.from(entry as Map)).toList();
  }
}
