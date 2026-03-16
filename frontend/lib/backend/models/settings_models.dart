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
    this.pairingCode = '',
    this.localPeerId = '',
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
  final String pairingCode;
  final String localPeerId;

  String get nodeModeLabel => switch (nodeMode) {
    0 => 'Client',
    1 => 'Server',
    2 => 'Dual',
    _ => 'Unknown',
  };

  factory SettingsModel.fromJson(Map<String, dynamic> json) => SettingsModel(
    nodeMode: json['nodeMode'] as int? ?? 0,
    enableTor: json['enableTor'] as bool? ?? false,
    enableClearnet: json['enableClearnet'] as bool? ?? false,
    clearnetFallback: json['clearnetFallback'] as bool? ?? false,
    meshDiscovery: json['meshDiscovery'] as bool? ?? false,
    allowRelays: json['allowRelays'] as bool? ?? false,
    enableI2p: json['enableI2p'] as bool? ?? false,
    enableBluetooth: json['enableBluetooth'] as bool? ?? false,
    enableRf: json['enableRf'] as bool? ?? false,
    pairingCode: json['pairingCode'] as String? ?? '',
    localPeerId: json['localPeerId'] as String? ?? '',
  );

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
