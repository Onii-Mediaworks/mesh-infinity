// android_proximity_bridge.dart
//
// AndroidProximityBridge — Flutter-side platform channels for NFC and
// Wi-Fi Direct proximity transports on Android.
//
// WHAT THIS IS FOR:
// -----------------
// Mesh Infinity supports proximity-based contact pairing and data exchange
// using two Android-specific radios:
//
//   NFC (Near-Field Communication)
//     - Short-range (< 4 cm), requires physical proximity.
//     - Used for out-of-band pairing: one device writes the pairing payload
//       to an NFC tag; the other scans it.
//     - The Android beam / NDEF dispatch delivers the payload via Kotlin,
//       which sends it to Dart as an NfcPairingPayloadEvent.
//
//   Wi-Fi Direct (P2P)
//     - Medium-range (up to ~100 m line-of-sight), no internet required.
//     - Used as a local mesh transport between devices without a shared AP.
//     - The Android WifiP2pManager API (Kotlin side) discovers and connects
//       to peers; data frames are exchanged as hex strings over the channel.
//
// PLATFORM CHANNEL ARCHITECTURE:
// --------------------------------
// Two channels are used:
//
//   MethodChannel  'mesh_infinity/android_proximity'
//     — imperative calls: getCapabilities, startWifiDirectDiscovery, etc.
//
//   EventChannel   'mesh_infinity/android_proximity_events'
//     — push events from Kotlin: NFC payloads, peer-list changes,
//       session frames, state changes.
//
// WHY A SEALED CLASS FOR EVENTS?
// --------------------------------
// The event stream carries several distinct event types.  A sealed class
// lets Dart exhaustively pattern-match on the event type without instanceof
// chains.  The factory constructor AndroidProximityEvent.fromMap() decodes
// the raw Map from the EventChannel into the correct subclass.

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

// ---------------------------------------------------------------------------
// AndroidProximityCapabilities — state snapshot for NFC + Wi-Fi Direct
// ---------------------------------------------------------------------------

/// A snapshot of the Android device's current NFC and Wi-Fi Direct state.
///
/// Returned by [AndroidProximityBridge.getCapabilities] and also embedded in
/// [WifiDirectStateChangedEvent] when the radio state changes.
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

  /// Always true when this object was populated on Android; false on other platforms.
  final bool isAndroid;

  /// True if the device hardware includes an NFC controller.
  final bool nfcAvailable;

  /// True if the user has NFC enabled in system settings.
  final bool nfcEnabled;

  /// True if the device hardware supports Wi-Fi Direct (P2P).
  final bool wifiDirectAvailable;

  /// True if Wi-Fi is on and Wi-Fi Direct is not blocked by policy.
  final bool wifiDirectEnabled;

  /// True if ACCESS_FINE_LOCATION (required for peer discovery) has been granted.
  final bool wifiDirectPermissionGranted;

  /// True if peer discovery is currently scanning.
  final bool wifiDirectDiscoveryActive;

  /// True if a Wi-Fi Direct connection to a peer is established.
  final bool wifiDirectConnected;

  /// "GO" (group owner / AP role) or "CLIENT" when connected; null otherwise.
  final String? wifiDirectConnectionRole;

  /// IP address of the group owner when this device is a client; null otherwise.
  final String? wifiDirectGroupOwnerAddress;

  /// MAC address of the connected peer device; null when not connected.
  final String? wifiDirectConnectedDeviceAddress;

  /// Deserialise from the map returned over the platform channel.
  factory AndroidProximityCapabilities.fromMap(Map<Object?, Object?> map) {
    // Helper so we don't repeat `map[key] == true` for every boolean field.
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

// ---------------------------------------------------------------------------
// AndroidWifiDirectPeer — one discovered Wi-Fi Direct peer
// ---------------------------------------------------------------------------

/// A single peer device discovered during Wi-Fi Direct peer discovery.
///
/// Corresponds to Android's WifiP2pDevice Java class.  [deviceAddress] is
/// the MAC address used to initiate a connection.
class AndroidWifiDirectPeer {
  const AndroidWifiDirectPeer({
    required this.deviceName,
    required this.deviceAddress,
    required this.status,
    this.primaryDeviceType,
    this.secondaryDeviceType,
    this.isGroupOwner = false,
  });

  /// Human-readable device name advertised by the peer.
  final String deviceName;

  /// MAC address of the peer — used as the key for connection requests.
  final String deviceAddress;

  /// WifiP2pDevice connection status string (e.g. "AVAILABLE", "CONNECTED").
  final String status;

  /// WPS primary device type string (e.g. "1-0050F204-1" for a PC).
  /// Null if the peer did not advertise a device type.
  final String? primaryDeviceType;

  /// WPS secondary device type; null if not advertised.
  final String? secondaryDeviceType;

  /// True if this peer is currently acting as the Wi-Fi Direct group owner.
  final bool isGroupOwner;

  /// Deserialise from the map sent over the platform channel.
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

// ---------------------------------------------------------------------------
// AndroidProximityEvent — sealed event hierarchy
// ---------------------------------------------------------------------------

/// Base class for all events emitted by the Android proximity EventChannel.
///
/// Use pattern matching to handle each subtype:
/// ```dart
/// switch (event) {
///   case NfcPairingPayloadEvent(:final payloadJson): ...
///   case WifiDirectPeersChangedEvent(:final peers): ...
///   ...
/// }
/// ```
sealed class AndroidProximityEvent {
  const AndroidProximityEvent();

  /// Decode the raw map from the EventChannel into the appropriate subclass.
  ///
  /// Unknown event types produce [AndroidProximityUnknownEvent] rather than
  /// throwing, so a new event type added on the Kotlin side doesn't crash
  /// the Dart side on older app builds.
  factory AndroidProximityEvent.fromMap(Map<Object?, Object?> map) {
    final type = map['type'] as String? ?? '';
    switch (type) {
      case 'nfcPairingPayload':
        // NFC tap delivered a pairing JSON payload from the other device.
        return NfcPairingPayloadEvent(
          payloadJson: map['payloadJson'] as String? ?? '',
        );
      case 'wifiDirectPairingPayload':
        // Wi-Fi Direct channel delivered a pairing JSON payload.
        return WifiDirectPairingPayloadEvent(
          payloadJson: map['payloadJson'] as String? ?? '',
        );
      case 'wifiDirectSessionFrame':
        // A session data frame arrived over the established Wi-Fi Direct link.
        // Encoded as hex so it survives the string-based codec boundary.
        return WifiDirectSessionFrameEvent(
          frameHex: map['frameHex'] as String? ?? '',
        );
      case 'wifiDirectPeersChanged':
        // WifiP2pManager reported a change in the discovered peer list.
        return WifiDirectPeersChangedEvent(
          peers: _readPeers(map['peers']),
        );
      case 'wifiDirectStateChanged':
        // Radio state changed (enabled/disabled, connected/disconnected, etc.).
        return WifiDirectStateChangedEvent(
          capabilities: _readCapabilities(map['capabilities']),
          peers: _readPeers(map['peers']),
        );
      default:
        // Unknown type — safe to ignore; avoids crashing on future event types.
        return const AndroidProximityUnknownEvent();
    }
  }

  /// Parse the nested capabilities map, or return null if absent/malformed.
  static AndroidProximityCapabilities? _readCapabilities(Object? raw) {
    if (raw is! Map<Object?, Object?>) {
      return null;
    }
    return AndroidProximityCapabilities.fromMap(raw);
  }

  /// Parse the nested peer list, or return an empty list if absent/malformed.
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

/// An NFC tap delivered a pairing payload from a nearby device.
class NfcPairingPayloadEvent extends AndroidProximityEvent {
  const NfcPairingPayloadEvent({required this.payloadJson});
  /// JSON-encoded pairing payload from the remote device.
  final String payloadJson;
}

/// Wi-Fi Direct channel delivered a pairing payload.
class WifiDirectPairingPayloadEvent extends AndroidProximityEvent {
  const WifiDirectPairingPayloadEvent({required this.payloadJson});
  /// JSON-encoded pairing payload from the remote device.
  final String payloadJson;
}

/// A raw session data frame arrived over the established Wi-Fi Direct link.
class WifiDirectSessionFrameEvent extends AndroidProximityEvent {
  const WifiDirectSessionFrameEvent({required this.frameHex});
  /// Hex-encoded frame bytes.  Decode with [AndroidProximityBridge.decodeHexFrame].
  final String frameHex;
}

/// The Wi-Fi Direct discovered peer list changed.
class WifiDirectPeersChangedEvent extends AndroidProximityEvent {
  const WifiDirectPeersChangedEvent({required this.peers});
  /// Current snapshot of nearby discovered peers (replaces the previous list).
  final List<AndroidWifiDirectPeer> peers;
}

/// Radio state changed (capabilities or peer list updated).
class WifiDirectStateChangedEvent extends AndroidProximityEvent {
  const WifiDirectStateChangedEvent({
    required this.capabilities,
    required this.peers,
  });

  /// Updated capabilities snapshot; null if capabilities were not included.
  final AndroidProximityCapabilities? capabilities;

  /// Updated peer list at the time of the state change.
  final List<AndroidWifiDirectPeer> peers;
}

/// Catch-all for unrecognised event types from the Kotlin side.
///
/// Allows the app to safely ignore new event types added to the Kotlin side
/// in future updates without crashing.
class AndroidProximityUnknownEvent extends AndroidProximityEvent {
  const AndroidProximityUnknownEvent();
}

// ---------------------------------------------------------------------------
// AndroidProximityBridge — singleton bridge class
// ---------------------------------------------------------------------------

/// Platform channel bridge for NFC and Wi-Fi Direct proximity operations.
///
/// Access via [AndroidProximityBridge.instance].  All methods return safe
/// fallback values (false / empty list / empty stream) on non-Android platforms.
class AndroidProximityBridge {
  // Private constructor — use [instance].
  AndroidProximityBridge._();

  /// Singleton.  One instance per app lifetime.
  static final AndroidProximityBridge instance = AndroidProximityBridge._();

  /// Imperative calls (capabilities, start/stop discovery, connect, etc.).
  static const MethodChannel _methodChannel = MethodChannel(
    'mesh_infinity/android_proximity',
  );

  /// Push events from Kotlin (NFC payloads, peer-list changes, session frames).
  static const EventChannel _eventChannel = EventChannel(
    'mesh_infinity/android_proximity_events',
  );

  // Cached broadcast stream — EventChannel.receiveBroadcastStream() opens the
  // native stream; caching avoids opening it multiple times.
  Stream<AndroidProximityEvent>? _events;

  /// True only on Android (non-web).
  bool get isSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  // ---------------------------------------------------------------------------
  // Capabilities
  // ---------------------------------------------------------------------------

  /// Return a snapshot of NFC and Wi-Fi Direct state, or null on non-Android.
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

  // ---------------------------------------------------------------------------
  // Wi-Fi Direct discovery
  // ---------------------------------------------------------------------------

  /// Start peer discovery.  Returns true if Kotlin accepted the request.
  ///
  /// Discovery drains the battery; callers should stop it (via
  /// [stopWifiDirectDiscovery]) when the pairing flow completes.
  Future<bool> startWifiDirectDiscovery() async {
    if (!isSupported) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'startWifiDirectDiscovery',
    );
    return raw == true;
  }

  /// Request the ACCESS_FINE_LOCATION permission required for Wi-Fi Direct.
  ///
  /// Returns true if the permission is already granted or the user grants it.
  /// Returns false if the user denies.  On non-Android always returns true
  /// (no permission needed on other platforms).
  Future<bool> requestWifiDirectPermission() async {
    if (!isSupported) {
      // Non-Android: no permission to request; treat as granted.
      return true;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'requestWifiDirectPermission',
    );
    return raw == true;
  }

  /// Stop peer discovery.  Returns true if Kotlin accepted the request.
  Future<bool> stopWifiDirectDiscovery() async {
    if (!isSupported) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'stopWifiDirectDiscovery',
    );
    return raw == true;
  }

  /// Return the current list of discovered peers.
  ///
  /// Usually derived from [WifiDirectPeersChangedEvent] rather than polling,
  /// but this method is useful on initial load before the event arrives.
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

  // ---------------------------------------------------------------------------
  // Wi-Fi Direct connection
  // ---------------------------------------------------------------------------

  /// Connect to the peer identified by [deviceAddress] (a MAC address).
  ///
  /// Returns true when Kotlin successfully submitted the connect request to
  /// WifiP2pManager.  A successful return does NOT mean the connection is
  /// established — [WifiDirectStateChangedEvent] will deliver the outcome.
  Future<bool> connectWifiDirectPeer(String deviceAddress) async {
    // Guard against empty address: WifiP2pManager would throw IllegalArgument.
    if (!isSupported || deviceAddress.isEmpty) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'connectWifiDirectPeer',
      <String, Object?>{'deviceAddress': deviceAddress},
    );
    return raw == true;
  }

  /// Disconnect from the current Wi-Fi Direct peer.
  Future<bool> disconnectWifiDirectPeer() async {
    if (!isSupported) {
      return false;
    }
    final raw = await _methodChannel.invokeMethod<Object?>(
      'disconnectWifiDirectPeer',
    );
    return raw == true;
  }

  // ---------------------------------------------------------------------------
  // Data exchange
  // ---------------------------------------------------------------------------

  /// Send a pairing payload JSON string to the connected Wi-Fi Direct peer.
  ///
  /// Returns true if Kotlin submitted the write successfully.
  /// The payload is a JSON-encoded PairingPayload struct (§10.1).
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

  /// Send a raw session data frame as a hex string to the connected peer.
  ///
  /// [frameBytes] are converted to hex here because the platform channel
  /// codec handles strings more efficiently than arbitrary byte lists.
  /// Returns true if Kotlin submitted the write successfully.
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

  // ---------------------------------------------------------------------------
  // Hex utilities
  // ---------------------------------------------------------------------------

  /// Decode a hex string (e.g. "0a1b2c") into a list of byte values.
  ///
  /// Throws [FormatException] if [frameHex] has an odd number of characters,
  /// which would indicate truncation or corruption.
  List<int> decodeHexFrame(String frameHex) {
    if (frameHex.length.isOdd) {
      throw const FormatException('hex frame length must be even');
    }
    final bytes = <int>[];
    for (var index = 0; index < frameHex.length; index += 2) {
      // Parse two hex digits at a time into a byte value (0–255).
      bytes.add(int.parse(frameHex.substring(index, index + 2), radix: 16));
    }
    return bytes;
  }

  /// Encode a list of byte values as a lowercase hex string.
  ///
  /// Each byte is zero-padded to 2 characters (e.g. 0x0A → "0a").
  String _bytesToHex(List<int> bytes) {
    final buffer = StringBuffer();
    for (final byte in bytes) {
      buffer.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  // ---------------------------------------------------------------------------
  // Event stream
  // ---------------------------------------------------------------------------

  /// Broadcast stream of [AndroidProximityEvent]s from Kotlin.
  ///
  /// Subscribe to receive NFC payloads, peer-list changes, session frames,
  /// and state changes.  On non-Android platforms the stream never emits.
  ///
  /// The stream is lazily opened on first access and cached thereafter —
  /// calling [events] multiple times returns the same stream.
  Stream<AndroidProximityEvent> get events {
    if (!isSupported) {
      // Return a permanently empty stream on non-Android platforms.
      return const Stream<AndroidProximityEvent>.empty();
    }
    // Null-coalescing assignment: open the stream once and cache it.
    return _events ??= _eventChannel
        .receiveBroadcastStream()
        // Filter out non-map events (e.g. null sent by Kotlin error path).
        .where((event) => event is Map<Object?, Object?>)
        .cast<Map<Object?, Object?>>()
        .map(AndroidProximityEvent.fromMap);
  }
}
