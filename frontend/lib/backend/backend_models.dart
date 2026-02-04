enum BackendNodeMode {
  client,
  server,
  dual;

  static BackendNodeMode fromLabel(String label) {
    switch (label) {
      case 'server':
        return BackendNodeMode.server;
      case 'dual':
        return BackendNodeMode.dual;
      case 'client':
      default:
        return BackendNodeMode.client;
    }
  }

  String get label {
    switch (this) {
      case BackendNodeMode.client:
        return 'client';
      case BackendNodeMode.server:
        return 'server';
      case BackendNodeMode.dual:
        return 'dual';
    }
  }

  int get wireValue {
    switch (this) {
      case BackendNodeMode.client:
        return 0;
      case BackendNodeMode.server:
        return 1;
      case BackendNodeMode.dual:
        return 2;
    }
  }
}

class BackendSettings {
  const BackendSettings({
    required this.nodeMode,
    required this.enableTor,
    required this.enableClearnet,
    required this.meshDiscovery,
    required this.allowRelays,
    required this.enableI2p,
    required this.enableBluetooth,
    required this.pairingCode,
    required this.localPeerId,
  });

  final BackendNodeMode nodeMode;
  final bool enableTor;
  final bool enableClearnet;
  final bool meshDiscovery;
  final bool allowRelays;
  final bool enableI2p;
  final bool enableBluetooth;
  final String pairingCode;
  final String localPeerId;

  factory BackendSettings.fromJson(Map<String, dynamic> json) {
    final nodeModeLabel = json['nodeMode'] as String? ?? 'client';
    return BackendSettings(
      nodeMode: BackendNodeMode.fromLabel(nodeModeLabel),
      enableTor: json['enableTor'] as bool? ?? false,
      enableClearnet: json['enableClearnet'] as bool? ?? false,
      meshDiscovery: json['meshDiscovery'] as bool? ?? false,
      allowRelays: json['allowRelays'] as bool? ?? false,
      enableI2p: json['enableI2p'] as bool? ?? false,
      enableBluetooth: json['enableBluetooth'] as bool? ?? false,
      pairingCode: json['pairingCode'] as String? ?? '',
      localPeerId: json['localPeerId'] as String? ?? '',
    );
  }
}

class LocalIdentitySummary {
  const LocalIdentitySummary({
    required this.peerId,
    required this.publicKey,
    required this.dhPublicKey,
    required this.name,
  });

  final String peerId;
  final String publicKey;
  final String dhPublicKey;
  final String? name;

  factory LocalIdentitySummary.fromJson(Map<String, dynamic> json) {
    return LocalIdentitySummary(
      peerId: json['peerId'] as String? ?? '',
      publicKey: json['publicKey'] as String? ?? '',
      dhPublicKey: json['dhPublicKey'] as String? ?? '',
      name: json['name'] as String?,
    );
  }
}
