// settings_state.dart
//
// SettingsState — ChangeNotifier for all user-facing settings.
//
// Also owns two stub enumerations that will be backed by real backend calls
// when the tier and bandwidth systems are implemented (§22.28.3, §22.53):
//   BandwidthProfile — how much mesh participation the user opts into.
//   MeshTier         — which feature set the user has unlocked.
//
// Both are fully self-contained here so the Settings and TierDiscovery screens
// can compile and render without any additional backend wiring.

import 'dart:async';

import 'package:flutter/material.dart';

import '../../backend/backend_bridge.dart';
import '../../backend/event_bus.dart';
import '../../backend/event_models.dart';
import '../../backend/models/settings_models.dart';

// ---------------------------------------------------------------------------
// BandwidthProfile — mesh participation level (§22.28.3, §22.55.1)
// ---------------------------------------------------------------------------

/// Controls how much of this device's network resources the mesh may use.
///
/// Higher profiles donate more bandwidth and CPU to routing for others —
/// good for always-on desktops but inappropriate for metered mobile data.
/// This is an opt-in system: the default is [standard].
enum BandwidthProfile {
  /// Metered or battery-constrained devices.  Only essential mesh functions.
  minimal,

  /// Balanced.  Helps route traffic for others.  The recommended default.
  standard,

  /// Always-on device with good connectivity.  Maximum mesh contribution.
  generous,
}

// ---------------------------------------------------------------------------
// MeshTier — feature unlock levels (§22.53, §22.28)
// ---------------------------------------------------------------------------

/// Each tier adds capabilities on top of the previous one.
///
/// Tiers are unlocked one at a time, in order.  Most users will only ever
/// need Social.  The tier system exists so the app can start simple and
/// expose more power when the user actively wants it — not by default.
enum MeshTier {
  /// Chat, communities, file sharing, secure contacts.  The default tier.
  social,

  /// Mesh VPN, per-app routing, exit node support, local service exposure.
  network,

  /// Private virtual LAN, mesh DNS, access control, shared services.
  infinet,

  /// Remote desktop, remote shell, shared file access, API gateway.
  services,

  /// Purpose devices, Qubes Air integration, split operations, plugin runtime.
  power,
}

class SettingsState extends ChangeNotifier {
  SettingsState(this._bridge) {
    _sub = EventBus.instance.stream.listen(_onEvent);
    loadAll();
  }

  final BackendBridge _bridge;
  StreamSubscription<BackendEvent>? _sub;
  bool _disposed = false;

  SettingsModel? _settings;
  LocalIdentitySummary? _identity;
  List<ServiceModel> _services = const [];
  ThemeMode _themeMode = ThemeMode.system;

  SettingsModel? get settings => _settings;
  LocalIdentitySummary? get identity => _identity;
  List<ServiceModel> get services => _services;
  ThemeMode get themeMode => _themeMode;

  // ---------------------------------------------------------------------------
  // Security feature stubs
  //
  // These fields will be backed by real backend calls once the security
  // settings FFI is implemented (§3.10, §3.9).  For now they return safe
  // defaults so the Settings screens compile and display correctly.
  // TODO(backend/security): wire to mi_get_security_config when implemented.
  // ---------------------------------------------------------------------------

  // Whether a regular app PIN has been configured (§3.10).
  bool get pinEnabled => false;

  // Whether a duress PIN has been configured (§3.10 duress unlock).
  // The duress PIN triggers emergency erase on normal-looking unlock.
  bool get duressPinConfigured => false;

  // Whether to auto-wipe after N consecutive wrong PINs.
  bool get wrongPinWipeEnabled => false;

  // Number of wrong PIN attempts before auto-wipe (3, 5, or 10).
  int get wrongPinWipeThreshold => 5;

  // Whether a Level-8 (InnerCircle) contact can trigger remote erase.
  bool get remoteWipeEnabled => false;

  // Whether emergency erase has any trigger configured (duress PIN or auto-wipe).
  bool get emergencyEraseConfigured => duressPinConfigured || wrongPinWipeEnabled;

  // Whether the dead-man's-switch / pre-committed distress message is on (§22.10.4).
  bool get distressMessageEnabled => false;

  // Whether periodic liveness signals are sent to trusted peers (§22.10.4).
  bool get livenessSignalEnabled => false;

  // Number of devices registered to this identity (§22.10.7).
  int get deviceCount => 1; // always at least 1 (this device)

  // ---------------------------------------------------------------------------
  // Tier + bandwidth stubs (§22.28.3, §22.53)
  //
  // Real implementation: mi_get_tier_state / mi_set_tier / mi_set_bandwidth.
  // Until then: Social tier is always active; bandwidth defaults to Standard.
  // TODO(backend/tiers): wire to real backend when tier unlock is implemented.
  // ---------------------------------------------------------------------------

  /// The highest tier the user has unlocked.  Starts at Social (tier 0).
  MeshTier get activeTier => MeshTier.social;

  /// Returns true if [tier] is unlocked (i.e. at or below [activeTier]).
  bool tierUnlocked(MeshTier tier) => tier.index <= activeTier.index;

  /// The user's chosen bandwidth participation profile (§22.28.3).
  BandwidthProfile _bandwidthProfile = BandwidthProfile.standard;
  BandwidthProfile get bandwidthProfile => _bandwidthProfile;

  /// Update the bandwidth profile and notify listeners.
  ///
  /// TODO(backend/tiers): persist via bridge.setBandwidthProfile(profile.name).
  void setBandwidthProfile(BandwidthProfile profile) {
    if (_bandwidthProfile == profile) return;
    _bandwidthProfile = profile;
    notifyListeners();
  }

  /// Unlock a new tier.  No-op if the tier is already unlocked.
  ///
  /// TODO(backend/tiers): call bridge.enableTier(tier.index) and await result.
  void enableTier(MeshTier tier) {
    // Stub — tier unlock will require backend confirmation.
    notifyListeners();
  }

  void setThemeMode(ThemeMode mode) {
    if (_themeMode == mode) return;
    _themeMode = mode;
    notifyListeners();
  }

  Future<void> loadAll() async {
    _settings = _bridge.fetchSettings();
    _identity = _bridge.fetchLocalIdentity();
    _services = _bridge.fetchServices();
    if (!_disposed) notifyListeners();
  }

  Future<bool> configureService(String serviceId, Map<String, dynamic> config) async {
    final ok = _bridge.configureService(serviceId, config);
    if (ok) await loadAll();
    return ok;
  }

  Future<bool> setVpnRoute(Map<String, dynamic> routeConfig) async {
    return _bridge.setVpnRoute(routeConfig);
  }

  Future<bool> setClearnetRoute(Map<String, dynamic> routeConfig) async {
    return _bridge.setClearnetRoute(routeConfig);
  }

  void _onEvent(BackendEvent event) {
    if (event is! SettingsUpdatedEvent) return;
    _settings = event.settings;
    _identity = _bridge.fetchLocalIdentity();
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _sub?.cancel();
    super.dispose();
  }
}
