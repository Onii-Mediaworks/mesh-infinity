import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

class AndroidProximityCapabilities {
  const AndroidProximityCapabilities({
    required this.isAndroid,
    required this.nfcAvailable,
    required this.nfcEnabled,
    required this.wifiDirectAvailable,
    required this.wifiDirectEnabled,
    required this.wifiDirectPermissionGranted,
    required this.wifiDirectDiscoveryActive,
    required this.wifiDirectConnected,
    required this.wifiDirectConnectionRole,
    required this.wifiDirectGroupOwnerAddress,
    required this.wifiDirectConnectedDeviceAddress,
  });

  final bool isAndroid;
  final bool nfcAvailable;
  final bool nfcEnabled;
  final bool wifiDirectAvailable;
  final bool wifiDirectEnabled;
  final bool wifiDirectPermissionGranted;
  final bool wifiDirectDiscoveryActive;
  final bool wifiDirectConnected;
  final String? wifiDirectConnectionRole;
  final String? wifiDirectGroupOwnerAddress;
  final String? wifiDirectConnectedDeviceAddress;

  factory AndroidProximityCapabilities.fromMap(Map<Object?, Object?> map) {
    bool readBool(String key) => map[key] == true;
    return AndroidProximityCapabilities(
      isAndroid: readBool('isAndroid'),
      nfcAvailable: readBool('nfcAvailable'),
      nfcEnabled: readBool('nfcEnabled'),
      wifiDirectAvailable: readBool('wifiDirectAvailable'),
      wifiDirectEnabled: readBool('wifiDirectEnabled'),
      wifiDirectPermissionGranted: readBool('wifiDirectPermissionGranted'),
      wifiDirectDiscoveryActive: readBool('wifiDirectDiscoveryActive'),
      wifiDirectConnected: readBool('wifiDirectConnected'),
      wifiDirectConnectionRole:
          map['wifiDirectConnectionRole'] as String?,
      wifiDirectGroupOwnerAddress:
          map['wifiDirectGroupOwnerAddress'] as String?,
      wifiDirectConnectedDeviceAddress:
          map['wifiDirectConnectedDeviceAddress'] as String?,
    );
  }
}

class AndroidWifiDirectPeer {
  const AndroidWifiDirectPeer({
    required this.deviceName,
    required this.deviceAddress,
    required this.status,
    this.primaryDeviceType,
    this.secondaryDeviceType,
    this.isGroupOwner = false,
  });

  final String deviceName;
  final String deviceAddress;
  final String status;
  final String? primaryDeviceType;
  final String? secondaryDeviceType;
  final bool isGroupOwner;

  factory AndroidWifiDirectPeer.fromMap(Map<Object?, Object?> map) {
    return AndroidWifiDirectPeer(
      deviceName: map['deviceName'] as String? ?? 'Nearby device',
      deviceAddress: map['deviceAddress'] as String? ?? '',
      status: map['status'] as String? ?? 'unknown',
      primaryDeviceType: map['primaryDeviceType'] as String?,
      secondaryDeviceType: map['secondaryDeviceType'] as String?,
      isGroupOwner: map['isGroupOwner'] == true,
    );
  }
}

sealed class AndroidProximityEvent {
  const AndroidProximityEvent();

  factory AndroidProximityEvent.fromMap(Map<Object?, Object?> map) {
    final type = map['type'] as String? ?? '';
    switch (type) {
      case 'nfcPairingPayload':
        return NfcPairingPayloadEvent(
          payloadJson: map['payloadJson'] as String? ?? '',
        );
      case 'wifiDirectPairingPayload':
        return WifiDirectPairingPayloadEvent(
          payloadJson: map['payloadJson'] as String? ?? '',
        );
      case 'wifiDirectSessionFrame':
        return WifiDirectSessionFrameEvent(
          frameHex: map['frameHex'] as String? ?? '',
        );
      case 'wifiDirectPeersChanged':
        return WifiDirectPeersChangedEvent(
          peers: _readPeers(map['peers']),
        );
      case 'wifiDirectStateChanged':
        return WifiDirectStateChangedEvent(
          capabilities: _readCapabilities(map['capabilities']),
          peers: _readPeers(map['peers']),
        );
      default:
        return const AndroidProximityUnknownEvent();
    }
  }

  static AndroidProximityCapabilities? _readCapabilities(Object? raw) {
    if (raw is! Map<Object?, Object?>) {
      return null;
    }
    return AndroidProximityCapabilities.fromMap(raw);
  }

  static List<AndroidWifiDirectPeer> _readPeers(Object? raw) {
    if (raw is! List<Object?>) {
      return const [];
    }
    return raw
        .whereType<Map<Object?, Object?>>()
        .map(AndroidWifiDirectPeer.fromMap)
        .toList(growable: false);
  }
}

class NfcPairingPayloadEvent extends AndroidProximityEvent {
  const NfcPairingPayloadEvent({required this.payloadJson});
  final String payloadJson;
}

class WifiDirectPairingPayloadEvent extends AndroidProximityEvent {
  const WifiDirectPairingPayloadEvent({required this.payloadJson});
  final String payloadJson;
}

class WifiDirectSessionFrameEvent extends AndroidProximityEvent {
  const WifiDirectSessionFrameEvent({required this.frameHex});
  final String frameHex;
}

class WifiDirectPeersChangedEvent extends AndroidProximityEvent {
  const WifiDirectPeersChangedEvent({required this.peers});
  final List<AndroidWifiDirectPeer> peers;
}

class WifiDirectStateChangedEvent extends AndroidProximityEvent {
  const WifiDirectStateChangedEvent({
    required this.capabilities,
    required this.peers,
  });

  final AndroidProximityCapabilities? capabilities;
  final List<AndroidWifiDirectPeer> peers;
}

class AndroidProximityUnknownEvent extends AndroidProximityEvent {
  const AndroidProximityUnknownEvent();
}

class AndroidProximityBridge {
  AndroidProximityBridge._();

  static final AndroidProximityBridge instance = AndroidProximityBridge._();

  static const MethodChannel _methodChannel = MethodChannel(
    'mesh_infinity/android_proximity',
  );
  static const EventChannel _eventChannel = EventChannel(
    'mesh_infinity/android_proximity_events',
  );

  Stream<AndroidProximityEvent>? _events;

  bool get isSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  Future<AndroidProximityCapabilities?> getCapabilities() async {
    if (!isSupported) {
      return null;
    }
    final raw = await _methodChannel.invokeMethod<Object?>('getCapabilities');
    if (raw is! Map<Object?, Object?>) {
      return null;
    }
    return AndroidProximityCapabilities.fromMap(raw);
  }

  Future<bool> startWifiDirectDiscovery() async {
    if (!isSupported) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'startWifiDirectDiscovery',
    );
    return raw == true;
  }

  Future<bool> requestWifiDirectPermission() async {
    if (!isSupported) {
      return true;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'requestWifiDirectPermission',
    );
    return raw == true;
  }

  Future<bool> stopWifiDirectDiscovery() async {
    if (!isSupported) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'stopWifiDirectDiscovery',
    );
    return raw == true;
  }

  Future<List<AndroidWifiDirectPeer>> getWifiDirectPeers() async {
    if (!isSupported) {
      return const [];
    }
    final raw = await _methodChannel.invokeMethod<Object?>('getWifiDirectPeers');
    if (raw is! List<Object?>) {
      return const [];
    }
    return raw
        .whereType<Map<Object?, Object?>>()
        .map(AndroidWifiDirectPeer.fromMap)
        .toList(growable: false);
  }

  Future<bool> connectWifiDirectPeer(String deviceAddress) async {
    if (!isSupported || deviceAddress.isEmpty) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'connectWifiDirectPeer',
      <String, Object?>{'deviceAddress': deviceAddress},
    );
    return raw == true;
  }

  Future<bool> disconnectWifiDirectPeer() async {
    if (!isSupported) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'disconnectWifiDirectPeer',
    );
    return raw == true;
  }

  Future<bool> exchangeWifiDirectPairingPayload(String payloadJson) async {
    if (!isSupported || payloadJson.isEmpty) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'exchangeWifiDirectPairingPayload',
      <String, Object?>{'payloadJson': payloadJson},
    );
    return raw == true;
  }

  Future<bool> exchangeWifiDirectSessionFrame(List<int> frameBytes) async {
    if (!isSupported || frameBytes.isEmpty) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'exchangeWifiDirectSessionFrame',
      <String, Object?>{'frameHex': _bytesToHex(frameBytes)},
    );
    return raw == true;
  }

  List<int> decodeHexFrame(String frameHex) {
    if (frameHex.length.isOdd) {
      throw const FormatException('hex frame length must be even');
    }
    final bytes = <int>[];
    for (var index = 0; index < frameHex.length; index += 2) {
      bytes.add(int.parse(frameHex.substring(index, index + 2), radix: 16));
    }
    return bytes;
  }

  String _bytesToHex(List<int> bytes) {
    final buffer = StringBuffer();
    for (final byte in bytes) {
      buffer.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  Stream<AndroidProximityEvent> get events {
    if (!isSupported) {
      return const Stream<AndroidProximityEvent>.empty();
    }
    return _events ??= _eventChannel
        .receiveBroadcastStream()
        .where((event) => event is Map<Object?, Object?>)
        .cast<Map<Object?, Object?>>()
        .map(AndroidProximityEvent.fromMap);
  }
}
