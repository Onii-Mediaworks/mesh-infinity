import '../backend/backend_bridge.dart';
import 'android_proximity_bridge.dart';

class AndroidProximitySync {
  AndroidProximitySync._();

  static Future<Map<String, dynamic>> syncCurrentState(
    BackendBridge bridge,
  ) async {
    final caps = await AndroidProximityBridge.instance.getCapabilities();
    final peers = await AndroidProximityBridge.instance.getWifiDirectPeers();
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
    bridge.updateAndroidProximityState(state);
    return bridge.getAndroidProximityState();
  }

  static Future<bool> flushWifiDirectPairingPayloads(
    BackendBridge bridge,
  ) async {
    var sentAny = false;
    while (true) {
      final payloadJson = bridge.dequeueAndroidWifiDirectPairingPayload();
      if (payloadJson == null || payloadJson.isEmpty) {
        return sentAny;
      }
      final ok = await AndroidProximityBridge.instance
          .exchangeWifiDirectPairingPayload(payloadJson);
      if (!ok) {
        bridge.queueAndroidWifiDirectPairingPayload(payloadJson);
        return sentAny;
      }
      sentAny = true;
    }
  }

  static Future<bool> flushWifiDirectSessionFrames(
    BackendBridge bridge,
  ) async {
    var sentAny = false;
    while (true) {
      final frameBytes = bridge.dequeueAndroidWifiDirectSessionFrame();
      if (frameBytes == null || frameBytes.isEmpty) {
        return sentAny;
      }
      final ok = await AndroidProximityBridge.instance
          .exchangeWifiDirectSessionFrame(frameBytes);
      if (!ok) {
        bridge.queueAndroidWifiDirectSessionFrame(frameBytes);
        return sentAny;
      }
      sentAny = true;
    }
  }
}
