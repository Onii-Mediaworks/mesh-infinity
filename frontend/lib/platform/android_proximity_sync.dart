// android_proximity_sync.dart
//
// AndroidProximitySync — helper that synchronises Android NFC / Wi-Fi Direct
// state between the platform bridge and the Rust backend.
//
// WHAT THIS FILE DOES:
// --------------------
// The Rust backend is the authoritative source for mesh networking logic, but
// it has no direct access to Android radio APIs.  AndroidProximitySync acts as
// the glue:
//
//   1. syncCurrentState()  — queries the current NFC + Wi-Fi Direct capabilities
//                            and peer list from the Android bridge, serialises
//                            them into a flat Map, and hands them to the backend
//                            via BackendBridge.updateAndroidProximityState().
//
//   2. flushWifiDirectPairingPayloads() — drains any outbound pairing payload
//                            JSONs that the Rust backend has queued (it produces
//                            them when pairing logic runs), and sends each one
//                            over Wi-Fi Direct.  If a send fails the payload is
//                            re-queued so it isn't lost.
//
//   3. flushWifiDirectSessionFrames()  — same pattern for raw session data
//                            frames produced by the Rust transport layer.
//
// CALLED FROM:
// ------------
// These methods are called from the background polling loop in event_bus.dart
// (or from a dedicated proximity handler) after the Android EventChannel
// delivers a WifiDirectStateChangedEvent or WifiDirectPeersChangedEvent.
// They may also be called proactively when the pairing UI opens.

import '../backend/backend_bridge.dart';
import 'android_proximity_bridge.dart';

/// Synchronises Android proximity state between the platform bridge and the Rust backend.
///
/// All methods are static — this class is a namespace, not an instance.
class AndroidProximitySync {
  // Private constructor prevents instantiation — all methods are static utilities.
  AndroidProximitySync._();

  // ---------------------------------------------------------------------------
  // State sync
  // ---------------------------------------------------------------------------

  /// Read current NFC + Wi-Fi Direct capabilities and peer list from Android,
  /// push them to the Rust backend, then return the backend's view of the state.
  ///
  /// Returns the Map from [BackendBridge.getAndroidProximityState] so callers
  /// can inspect the backend's latest cached state without a second call.
  ///
  /// The state map uses string keys matching the Rust ProximityState struct
  /// field names — changes here must be mirrored in the Rust FFI.
  static Future<Map<String, dynamic>> syncCurrentState(
    BackendBridge bridge,
  ) async {
    // Fetch the capabilities snapshot (NFC state, Wi-Fi Direct state, etc.).
    // Returns null on non-Android platforms; defaults to false for all fields.
    final caps = await AndroidProximityBridge.instance.getCapabilities();

    // Fetch the current discovered peer list.  May be empty if discovery
    // hasn't started or no peers are nearby.
    final peers = await AndroidProximityBridge.instance.getWifiDirectPeers();

    // Build a flat Map that matches the Rust backend's expected shape.
    // Null-safe access (?.field ?? false) handles the non-Android case where
    // caps is null — all fields default to false/null.
    final state = <String, dynamic>{
      'isAndroid': caps?.isAndroid ?? false,
      'nfcAvailable': caps?.nfcAvailable ?? false,
      'nfcEnabled': caps?.nfcEnabled ?? false,
      'wifiDirectAvailable': caps?.wifiDirectAvailable ?? false,
      'wifiDirectEnabled': caps?.wifiDirectEnabled ?? false,
      'wifiDirectPermissionGranted': caps?.wifiDirectPermissionGranted ?? false,
      'wifiDirectDiscoveryActive': caps?.wifiDirectDiscoveryActive ?? false,
      'wifiDirectConnected': caps?.wifiDirectConnected ?? false,
      'wifiDirectConnectionRole': caps?.wifiDirectConnectionRole,
      'wifiDirectGroupOwnerAddress': caps?.wifiDirectGroupOwnerAddress,
      'wifiDirectConnectedDeviceAddress': caps?.wifiDirectConnectedDeviceAddress,
      // Each peer is serialised to a map so the Rust FFI layer can deserialise it.
      'peers': peers
          .map(
            (peer) => <String, dynamic>{
              'deviceName': peer.deviceName,
              'deviceAddress': peer.deviceAddress,
              'status': peer.status,
              'primaryDeviceType': peer.primaryDeviceType,
              'secondaryDeviceType': peer.secondaryDeviceType,
              'isGroupOwner': peer.isGroupOwner,
            },
          )
          .toList(growable: false),
    };

    // Push the state to Rust so it can update its internal ProximityState.
    bridge.updateAndroidProximityState(state);

    // Return the backend's view of the state (which may differ slightly if
    // Rust applied any normalisation or validation).
    return bridge.getAndroidProximityState();
  }

  // ---------------------------------------------------------------------------
  // Outbound payload flush
  // ---------------------------------------------------------------------------

  /// Send all queued pairing payload JSONs from the Rust backend over Wi-Fi Direct.
  ///
  /// The Rust backend queues pairing payloads when the pairing logic runs (e.g.
  /// after the user taps "Pair" in the UI).  This method drains the queue by
  /// sending each payload over the Wi-Fi Direct connection.
  ///
  /// If a send fails, the payload is re-queued so it is not lost.  The method
  /// returns true if at least one payload was sent successfully.
  ///
  /// Uses a loop rather than a batch call because each payload must be
  /// acknowledged before the next is sent (the protocol is sequential).
  static Future<bool> flushWifiDirectPairingPayloads(
    BackendBridge bridge,
  ) async {
    var sentAny = false;

    while (true) {
      // Dequeue one payload from the Rust backend's outbound queue.
      // Returns null when the queue is empty.
      final payloadJson = bridge.dequeueAndroidWifiDirectPairingPayload();
      if (payloadJson == null || payloadJson.isEmpty) {
        // Queue is empty — all pending payloads have been processed.
        return sentAny;
      }

      // Attempt to send the payload over the active Wi-Fi Direct connection.
      final ok = await AndroidProximityBridge.instance
          .exchangeWifiDirectPairingPayload(payloadJson);

      if (!ok) {
        // Send failed (e.g. connection dropped).  Re-queue the payload so
        // the next sync attempt can retry it.  Stop looping to avoid an
        // infinite retry tightly bouncing on a broken connection.
        bridge.queueAndroidWifiDirectPairingPayload(payloadJson);
        return sentAny;
      }

      sentAny = true;
    }
  }

  /// Send all queued session data frames from the Rust backend over Wi-Fi Direct.
  ///
  /// Same drain-queue / re-queue-on-failure pattern as
  /// [flushWifiDirectPairingPayloads], but for raw transport frames produced
  /// by the Rust mesh session layer.
  ///
  /// Returns true if at least one frame was sent successfully.
  static Future<bool> flushWifiDirectSessionFrames(
    BackendBridge bridge,
  ) async {
    var sentAny = false;

    while (true) {
      // Dequeue one frame (as raw bytes) from the Rust outbound queue.
      final frameBytes = bridge.dequeueAndroidWifiDirectSessionFrame();
      if (frameBytes == null || frameBytes.isEmpty) {
        // Queue empty.
        return sentAny;
      }

      final ok = await AndroidProximityBridge.instance
          .exchangeWifiDirectSessionFrame(frameBytes);

      if (!ok) {
        // Re-queue on failure so the frame is not dropped.
        bridge.queueAndroidWifiDirectSessionFrame(frameBytes);
        return sentAny;
      }

      sentAny = true;
    }
  }
}
