import '../backend/backend_bridge.dart';
import 'android_startup_bridge.dart';

class AndroidStartupSync {
  AndroidStartupSync._();

  static Future<Map<String, dynamic>> syncCurrentState(
    BackendBridge bridge,
  ) async {
    await AndroidStartupBridge.instance.ensureStartupService();
    final state = await AndroidStartupBridge.instance.getStartupState();
    if (state.isEmpty) {
      return bridge.getAndroidStartupState();
    }
    bridge.updateAndroidStartupState(state);
    return bridge.getAndroidStartupState();
  }
}
