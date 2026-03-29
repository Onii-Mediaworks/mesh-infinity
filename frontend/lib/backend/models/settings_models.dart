class SettingsModel {
  const SettingsModel({
    this.nodeMode = 0,
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
  });

  final int nodeMode;
  final bool enableTor;
  final bool enableClearnet;
  /// Whether this node (as message originator) may fall back to clearnet when
  /// all privacy-preserving transports have failed.  Relay hops are unaffected.
  final bool clearnetFallback;
  final bool meshDiscovery;
  final bool allowRelays;
  final bool enableI2p;
  final bool enableBluetooth;
  final bool enableRf;
  /// Null means the backend has not configured a pairing code yet.
  /// Empty string is distinct from null (code explicitly set to '').
  final String? pairingCode;
  final String localPeerId;
  /// TCP listen port for the clearnet transport (default 7234).
  final int clearnetPort;

  String get nodeModeLabel => switch (nodeMode) {
    0 => 'Client',
    1 => 'Server',
    2 => 'Dual',
    _ => 'Unknown',
  };

  factory SettingsModel.fromJson(Map<String, dynamic> json) {
    // M3: Validate nodeMode is within known range (0=client, 1=server, 2=dual).
    // Out-of-range values from future backend versions are clamped to 0 rather
    // than silently stored as an invalid enum value.
    final rawMode = json['nodeMode'] as int? ?? 0;
    final nodeMode = (rawMode >= 0 && rawMode <= 2) ? rawMode : 0;
    return SettingsModel(
      nodeMode: nodeMode,
      enableTor: json['enableTor'] as bool? ?? false,
      enableClearnet: json['enableClearnet'] as bool? ?? false,
      clearnetFallback: json['clearnetFallback'] as bool? ?? false,
      meshDiscovery: json['meshDiscovery'] as bool? ?? false,
      allowRelays: json['allowRelays'] as bool? ?? false,
      enableI2p: json['enableI2p'] as bool? ?? false,
      enableBluetooth: json['enableBluetooth'] as bool? ?? false,
      enableRf: json['enableRf'] as bool? ?? false,
      // M4: Preserve null vs. empty-string distinction for pairingCode.
      pairingCode: json['pairingCode'] as String?,
      localPeerId: json['localPeerId'] as String? ?? '',
      clearnetPort: (json['clearnetPort'] as num?)?.toInt() ?? 7234,
    );
  }

  SettingsModel copyWith({
    int? nodeMode,
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
  }) => SettingsModel(
    nodeMode: nodeMode ?? this.nodeMode,
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
  );
}

class LocalIdentitySummary {
  const LocalIdentitySummary({
    required this.peerId,
    required this.publicKey,
    this.name,
  });

  final String peerId;
  final String publicKey;
  final String? name;

  factory LocalIdentitySummary.fromJson(Map<String, dynamic> json) =>
      LocalIdentitySummary(
        peerId: json['peerId'] as String? ?? '',
        publicKey: json['publicKey'] as String? ?? '',
        name: json['name'] as String?,
      );
}

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

  final String id;
  final String name;
  final String path;
  final String address;
  final bool enabled;
  final int minTrustLevel;
  final List<String> allowedTransports;

  factory ServiceModel.fromJson(Map<String, dynamic> json) => ServiceModel(
    id: json['id'] as String? ?? '',
    name: json['name'] as String? ?? '',
    path: json['path'] as String? ?? '',
    address: json['address'] as String? ?? '',
    enabled: json['enabled'] as bool? ?? false,
    minTrustLevel: json['minTrustLevel'] as int? ?? 0,
    allowedTransports:
        (json['allowedTransports'] as List<dynamic>?)?.cast<String>() ?? [],
  );
}
