import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../app/app_theme.dart';
import '../backend/event_bus.dart';
import '../backend/event_models.dart';
import '../features/network/network_state.dart';
import '../features/settings/settings_state.dart';

// ---------------------------------------------------------------------------
// SecurityState — tracks active security conditions that affect the status bar
// ---------------------------------------------------------------------------

enum SecurityCondition {
  none,
  exitExposure,
  threat,
  loSec,
}

/// Tracks the set of active security conditions and surfaces the
/// highest-priority one to [SecurityStatusBar].
///
/// Priority (highest first): exitExposure > threat > loSec.
class SecurityState extends ChangeNotifier {
  SecurityState() {
    _sub = EventBus.instance.stream.listen(_onEvent);
  }

  StreamSubscription<BackendEvent>? _sub;

  // Active LoSec session IDs (dismissible per session)
  final Set<String> _loSecSessions = {};
  final Set<String> _dismissedLoSec = {};

  bool get hasActiveLoSec =>
      _loSecSessions.any((sessionId) => !_dismissedLoSec.contains(sessionId));

  // ---------------------------------------------------------------------------
  // Dismissal
  // ---------------------------------------------------------------------------

  void dismissLoSec(String sessionId) {
    _dismissedLoSec.add(sessionId);
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // Event handling — LoSec events from EventBus
  // ---------------------------------------------------------------------------

  void _onEvent(BackendEvent event) {
    switch (event) {
      case LoSecResponseEvent(:final sessionId, :final accepted):
        if (accepted) {
          _loSecSessions.add(sessionId);
          notifyListeners();
        }
      case LoSecRequestedEvent(:final sessionId, :final accepted):
        if (accepted) {
          _loSecSessions.add(sessionId);
          notifyListeners();
        }
      default:
        break;
    }
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }
}

// ---------------------------------------------------------------------------
// SecurityStatusBar — persistent animated banner above all screen content
// ---------------------------------------------------------------------------

/// Persistent banner shown when a security condition is active (§22.4.1).
///
/// Height: 0 when no condition is active; 32–36 when active.
/// Animates in/out with 200ms easeOut.
///
/// Insert at the top of each shell body column.
class SecurityStatusBar extends StatelessWidget {
  const SecurityStatusBar({super.key});

  @override
  Widget build(BuildContext context) {
    final security = context.watch<SecurityState>();
    final settings = context.watch<SettingsState>();
    final network = context.watch<NetworkState>();
    return _SecurityBanner(
      security: security,
      settings: settings,
      network: network,
    );
  }
}

class _SecurityBanner extends StatelessWidget {
  const _SecurityBanner({
    required this.security,
    required this.settings,
    required this.network,
  });

  final SecurityState security;
  final SettingsState settings;
  final NetworkState network;

  @override
  Widget build(BuildContext context) {
    final condition = _activeCondition(security, settings, network);
    final (height, color, icon, message, dismissible) =
        _props(security, settings, network, condition);

    return AnimatedContainer(
      height: height,
      duration: const Duration(milliseconds: 200),
      curve: Curves.easeOut,
      color: color,
      child: height == 0
          ? const SizedBox.shrink()
          : SafeArea(
              bottom: false,
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Row(
                  children: [
                    Icon(icon, size: 16, color: Colors.white),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        message,
                        style: const TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w500,
                          color: Colors.white,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    if (dismissible)
                      GestureDetector(
                        onTap: () => _dismiss(security, condition),
                        child: const Icon(
                          Icons.close,
                          size: 16,
                          color: Colors.white,
                        ),
                      ),
                  ],
                ),
              ),
            ),
    );
  }

  static SecurityCondition _activeCondition(
    SecurityState security,
    SettingsState settings,
    NetworkState network,
  ) {
    if (network.vpnExitNodeSeesDestinations && network.isVpnActive) {
      return SecurityCondition.exitExposure;
    }
    if ((settings.settings?.threatContext ?? 0) > 0) {
      return SecurityCondition.threat;
    }
    if (security.hasActiveLoSec) {
      return SecurityCondition.loSec;
    }
    return SecurityCondition.none;
  }

  static (double, Color, IconData, String, bool) _props(
    SecurityState security,
    SettingsState settings,
    NetworkState network,
    SecurityCondition condition,
  ) {
    return switch (condition) {
      SecurityCondition.none => (
          0.0,
          Colors.transparent,
          Icons.info_outline,
          '',
          false,
        ),
      SecurityCondition.exitExposure => (
          36.0,
          MeshTheme.secRed,
          Icons.warning_rounded,
          network.vpnChangesInternetIp
              ? 'Traffic exits through another network. That operator can see destinations after traffic leaves the mesh.'
              : 'This route exposes destinations beyond the mesh boundary.',
          false,
        ),
      SecurityCondition.threat => (
          32.0,
          switch (settings.settings?.threatContext ?? 0) {
            1 => MeshTheme.secAmber,
            2 => MeshTheme.secRed,
            3 => MeshTheme.secPurple,
            _ => MeshTheme.brand,
          },
          Icons.shield_outlined,
          switch (settings.settings?.threatContext ?? 0) {
            1 => 'Elevated threat mode active — stricter transport and metadata controls are on.',
            2 => 'High threat mode active — privacy-preserving transports are enforced.',
            3 => 'Critical threat mode active — maximum isolation is enabled.',
            _ => '',
          },
          false,
        ),
      SecurityCondition.loSec => (
          32.0,
          MeshTheme.secAmber,
          Icons.warning_amber_rounded,
          'LoSec mode active — faster path with reduced anonymity protections.',
          true,
        ),
    };
  }

  void _dismiss(SecurityState security, SecurityCondition condition) {
    switch (condition) {
      case SecurityCondition.loSec:
        // Dismiss all active LoSec sessions at once
        for (final s in List.of(security._loSecSessions)) {
          security.dismissLoSec(s);
        }
      default:
        break;
    }
  }
}
