// =============================================================================
// settings_models.dart
//
// Typed Dart models for node configuration, local identity, and services.
//
// WHAT THESE MODELS REPRESENT
// The Rust backend owns the canonical settings state.  The Flutter UI reads
// these models and writes changes back via BackendBridge setter methods.  The
// backend emits a SettingsUpdatedEvent when settings change so the UI stays
// in sync without polling.
//
// HOW DATA FLOWS HERE
// BackendBridge.fetchSettings() → mi_settings_json() → SettingsModel.fromJson()
// BackendBridge.fetchLocalIdentity() → mi_local_identity_json() → LocalIdentitySummary
// BackendBridge.fetchServices() → mi_get_service_list() → List<ServiceModel>
//
// VALIDATION IN fromJson()
// Some fields are validated and clamped rather than accepted raw (M3 pattern):
//   - nodeMode is clamped to the known range [0, 2]
//   - threatContext is clamped to [0, 3]
//   - activeTier is clamped to [0, 4]
//   - bandwidthProfile is clamped to [0, 2]
// This prevents a future backend version from sending an out-of-range value
// and causing the UI to enter an undefined state.
// =============================================================================

/// Complete node configuration, as returned by mi_settings_json().
///
/// Every field has a default that matches the backend's own defaults, so a
/// partial JSON response (e.g. from a backend stub that only fills some fields)
/// produces a valid, safe model rather than null/exception.
class SettingsModel {
  const SettingsModel({
    this.nodeMode = 0,
    this.threatContext = 0,
    this.enableTor = false,
    this.enableClearnet = false,
    this.clearnetFallback = false,
    this.meshDiscovery = false,
    this.allowRelays = false,
    this.enableI2p = false,
    this.enableBluetooth = false,
    this.enableRf = false,
    this.pairingCode,
    this.localPeerId = '',
    this.clearnetPort = 7234,
    this.activeTier = 0,
    this.bandwidthProfile = 1,
  });

  /// Node operating mode:
  ///   0 = Client (leaf node — participates but does not relay for others)
  ///   1 = Server (relay node — forwards packets for the mesh)
  ///   2 = Dual (both client and server simultaneously)
  ///
  /// Out-of-range values are clamped to 0 in fromJson().
  final int nodeMode;

  /// Threat context level:
  ///   0 = Normal      — standard transport mix
  ///   1 = Elevated    — suppress cloud-push tiers, prefer Tor/I2P
  ///   2 = Critical    — all low-anonymity transports automatically disabled
  ///   3 = Emergency   — reserved (maximum suppression)
  ///
  /// Elevated and Critical automatically suppress notifications that would
  /// reveal activity to push infrastructure.
  final int threatContext;

  /// Whether the Tor transport is enabled.
  /// When active, outbound connections are routed through the Tor network for
  /// sender anonymity.
  final bool enableTor;

  /// Whether the clearnet (plain internet TCP) transport is enabled.
  /// Provides higher throughput and lower latency than privacy transports at
  /// the cost of IP address exposure.
  final bool enableClearnet;

  /// Whether this node (as message originator) may fall back to clearnet when
  /// all privacy-preserving transports have failed.  Relay hops are unaffected.
  ///
  /// Distinct from [enableClearnet]: the latter allows clearnet in general;
  /// this flag specifically permits the originating node to use it as a last
  /// resort even if the user prefers privacy transports.
  final bool clearnetFallback;

  /// Whether mDNS/local-network peer discovery is enabled.
  /// When true, the backend announces itself on the LAN and listens for other
  /// Mesh Infinity nodes.
  final bool meshDiscovery;

  /// Whether this node may serve as a relay hop for other peers' traffic.
  /// Enabling this contributes bandwidth to the mesh in exchange for stronger
  /// anonymity (your own traffic blends into relay traffic).
  final bool allowRelays;

  /// Whether the I2P transport is enabled.
  /// I2P (Invisible Internet Project) provides a garlic-routing anonymity layer
  /// similar to Tor but with different threat model trade-offs.
  final bool enableI2p;

  /// Whether the Bluetooth Low Energy transport is enabled.
  /// Allows nearby peers to communicate without internet connectivity.
  final bool enableBluetooth;

  /// Whether the software-defined radio (SDR) / RF transport is enabled.
  /// Requires compatible hardware (e.g. LoRa, HackRF — see §22.8).
  final bool enableRf;

  /// The current pairing code, or null if none has been configured.
  ///
  /// Null means the backend has not yet generated a pairing code for this
  /// session.  Empty string is semantically distinct from null — it means the
  /// code was explicitly cleared.  Do NOT use ?? '' in UI code that needs to
  /// distinguish these cases.
  final String? pairingCode;

  /// The hex-encoded peer ID of this local node.
  /// Used in the Settings and Identity screens to display "Your ID".
  final String localPeerId;

  /// The TCP port the clearnet transport listens on (default 7234).
  /// Must be in the range [1024, 65535] for user-space binding.
  final int clearnetPort;

  /// The highest unlocked feature tier (0 = social to 4 = power).
  /// Controls which advanced features are accessible in the UI.
  /// Clamped to [0, 4] in fromJson().
  final int activeTier;

  /// The mesh participation profile that controls this node's resource usage:
  ///   0 = Minimal  — minimal relay and gossip participation (battery-friendly)
  ///   1 = Standard — balanced participation (default)
  ///   2 = Generous — maximum participation, contributes most to mesh health
  /// Clamped to [0, 2] in fromJson().
  final int bandwidthProfile;

  /// Human-readable label for the current [nodeMode].
  String get nodeModeLabel => switch (nodeMode) {
    0 => 'Client',
    1 => 'Server',
    2 => 'Dual',
    _ => 'Unknown', // should never occur due to clamping in fromJson
  };

  /// Deserialise from the JSON object returned by mi_settings_json().
  factory SettingsModel.fromJson(Map<String, dynamic> json) {
    // M3: Validate nodeMode is within the known range [0, 2].
    // Out-of-range values from future backend versions are clamped to 0 rather
    // than silently stored as an invalid value that would break nodeModeLabel.
    final rawMode = json['nodeMode'] as int? ?? 0;
    final nodeMode = (rawMode >= 0 && rawMode <= 2) ? rawMode : 0;

    return SettingsModel(
      nodeMode: nodeMode,
      // .clamp() is used instead of a manual range check for conciseness.
      threatContext: ((json['threatContext'] as num?)?.toInt() ?? 0).clamp(0, 3),
      enableTor: json['enableTor'] as bool? ?? false,
      enableClearnet: json['enableClearnet'] as bool? ?? false,
      clearnetFallback: json['clearnetFallback'] as bool? ?? false,
      meshDiscovery: json['meshDiscovery'] as bool? ?? false,
      allowRelays: json['allowRelays'] as bool? ?? false,
      enableI2p: json['enableI2p'] as bool? ?? false,
      enableBluetooth: json['enableBluetooth'] as bool? ?? false,
      enableRf: json['enableRf'] as bool? ?? false,
      // M4: Preserve null vs. empty-string distinction.  Using `as String?`
      // without a fallback means a JSON null becomes Dart null — intentional.
      pairingCode: json['pairingCode'] as String?,
      localPeerId: json['localPeerId'] as String? ?? '',
      clearnetPort: (json['clearnetPort'] as num?)?.toInt() ?? 7234,
      activeTier: ((json['activeTier'] as num?)?.toInt() ?? 0).clamp(0, 4),
      bandwidthProfile: ((json['bandwidthProfile'] as num?)?.toInt() ?? 1)
          .clamp(0, 2),
    );
  }

  /// Return a copy with selected fields replaced.
  ///
  /// Used by SettingsState to apply user changes optimistically before the
  /// backend confirms them via a SettingsUpdatedEvent.
  SettingsModel copyWith({
    int? nodeMode,
    int? threatContext,
    bool? enableTor,
    bool? enableClearnet,
    bool? clearnetFallback,
    bool? meshDiscovery,
    bool? allowRelays,
    bool? enableI2p,
    bool? enableBluetooth,
    bool? enableRf,
    String? pairingCode,
    String? localPeerId,
    int? clearnetPort,
    int? activeTier,
    int? bandwidthProfile,
  }) => SettingsModel(
    nodeMode: nodeMode ?? this.nodeMode,
    threatContext: threatContext ?? this.threatContext,
    enableTor: enableTor ?? this.enableTor,
    enableClearnet: enableClearnet ?? this.enableClearnet,
    clearnetFallback: clearnetFallback ?? this.clearnetFallback,
    meshDiscovery: meshDiscovery ?? this.meshDiscovery,
    allowRelays: allowRelays ?? this.allowRelays,
    enableI2p: enableI2p ?? this.enableI2p,
    enableBluetooth: enableBluetooth ?? this.enableBluetooth,
    enableRf: enableRf ?? this.enableRf,
    pairingCode: pairingCode ?? this.pairingCode,
    localPeerId: localPeerId ?? this.localPeerId,
    clearnetPort: clearnetPort ?? this.clearnetPort,
    activeTier: activeTier ?? this.activeTier,
    bandwidthProfile: bandwidthProfile ?? this.bandwidthProfile,
  );
}

/// Lightweight summary of the local node's cryptographic identity.
///
/// Returned by [BackendBridge.fetchLocalIdentity].  Contains just enough
/// information for the You screen and the identity-related settings screens.
/// The full identity (signing keys, ratchet state) lives only in Rust memory
/// and is never exposed to Flutter.
class LocalIdentitySummary {
  const LocalIdentitySummary({
    required this.peerId,
    required this.publicKey,
    this.name,
  });

  /// This node's hex-encoded peer ID (derived from the Ed25519 public key).
  /// Displayed as "Your ID" in the You screen and QR code.
  final String peerId;

  /// The Ed25519 public key as a hex string.
  /// Used when generating pairing payloads so the remote peer can verify
  /// our signature during the pairing handshake.
  final String publicKey;

  /// The user's chosen display name for this identity.
  /// Null if the user has not set a name yet (first-run state).
  final String? name;

  /// Deserialise from the JSON returned by mi_local_identity_json().
  ///
  /// The backend JSON may use "publicKey" or "ed25519Pub" as the key name
  /// (historical inconsistency, normalised in BackendBridge.fetchLocalIdentity).
  /// Here we accept whichever key is present.
  factory LocalIdentitySummary.fromJson(Map<String, dynamic> json) =>
      LocalIdentitySummary(
        peerId: json['peerId'] as String? ?? '',
        publicKey: json['publicKey'] as String? ?? '',
        // name is genuinely optional — null means "not set yet".
        name: json['name'] as String?,
      );
}

/// A mesh service hosted by (or discoverable from) this node.
///
/// Services are optional pluggable capabilities exposed over the mesh:
/// local proxies, relay services, file-share endpoints, etc.  The user can
/// enable/disable services in the Services screen and configure per-service
/// access control.
///
/// Returned by [BackendBridge.fetchServices].
class ServiceModel {
  const ServiceModel({
    required this.id,
    required this.name,
    required this.path,
    required this.address,
    required this.enabled,
    this.minTrustLevel = 0,
    this.allowedTransports = const [],
  });

  /// Opaque backend service identifier.  Passed to
  /// [BackendBridge.configureService] to apply changes.
  final String id;

  /// Human-readable service name (e.g. "HTTP Proxy", "File Share").
  final String name;

  /// The internal service path or endpoint identifier within the Rust service
  /// registry (e.g. "/proxy", "/files").  Not directly shown to the user.
  final String path;

  /// The network address this service listens on (e.g. "127.0.0.1:8080").
  /// Shown in the service detail screen so the user can configure other apps
  /// to connect through it.
  final String address;

  /// Whether this service is currently active (accepting connections).
  final bool enabled;

  /// Minimum trust level a remote peer must have to access this service.
  /// Peers below this level have their connection attempts rejected.
  /// 0 means any peer can use the service (open access).
  final int minTrustLevel;

  /// The transports over which this service is reachable.
  /// Empty list means "all enabled transports".  Non-empty list restricts
  /// access to only the listed transports (e.g. ["clearnet", "tor"]).
  final List<String> allowedTransports;

  /// Deserialise from one element of the mi_get_service_list() JSON array.
  factory ServiceModel.fromJson(Map<String, dynamic> json) => ServiceModel(
    id: json['id'] as String? ?? '',
    name: json['name'] as String? ?? '',
    path: json['path'] as String? ?? '',
    address: json['address'] as String? ?? '',
    enabled: json['enabled'] as bool? ?? false,
    minTrustLevel: json['minTrustLevel'] as int? ?? 0,
    // The JSON value is a list of strings.  .cast<String>() reinterprets the
    // List<dynamic> from jsonDecode as List<String> — safe because we ?? []
    // for the null case, and any non-string elements would have come from Rust
    // which we trust to only emit strings here.
    allowedTransports:
        (json['allowedTransports'] as List<dynamic>?)?.cast<String>() ?? [],
  );
}
