import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../app/app_theme.dart';
import '../backend/event_bus.dart';
import '../backend/event_models.dart';

// ---------------------------------------------------------------------------
// SecurityState — tracks active security conditions that affect the status bar
// ---------------------------------------------------------------------------

enum SecurityCondition {
  none,
  loSec,       // LoSec mode active on at least one session
  direct,      // Direct clearnet connection active (no mesh routing)
  compromised, // Message from compromised peer
  keyChange,   // Key change pending approval
}

/// Tracks the set of active security conditions and surfaces the
/// highest-priority one to [SecurityStatusBar].
///
/// Priority (highest first): direct > compromised > keyChange > loSec.
class SecurityState extends ChangeNotifier {
  SecurityState() {
    _sub = EventBus.instance.stream.listen(_onEvent);
  }

  StreamSubscription<BackendEvent>? _sub;

  // Active LoSec session IDs (dismissible per session)
  final Set<String> _loSecSessions = {};
  final Set<String> _dismissedLoSec = {};

  // Direct connection flag
  bool _directActive = false;

  // Compromised peer name (if any)
  String? _compromisedPeerName;
  bool _compromisedDismissed = false;

  // Key change peer name (if any)
  String? _keyChangePeerName;

  // ---------------------------------------------------------------------------
  // Public getters
  // ---------------------------------------------------------------------------

  SecurityCondition get activeCondition {
    if (_directActive) return SecurityCondition.direct;
    if (_compromisedPeerName != null && !_compromisedDismissed) {
      return SecurityCondition.compromised;
    }
    if (_keyChangePeerName != null) return SecurityCondition.keyChange;
    final anyLoSec = _loSecSessions.any((s) => !_dismissedLoSec.contains(s));
    if (anyLoSec) return SecurityCondition.loSec;
    return SecurityCondition.none;
  }

  String? get compromisedPeerName => _compromisedPeerName;
  String? get keyChangePeerName => _keyChangePeerName;

  // ---------------------------------------------------------------------------
  // Dismissal
  // ---------------------------------------------------------------------------

  void dismissLoSec(String sessionId) {
    _dismissedLoSec.add(sessionId);
    notifyListeners();
  }

  void dismissCompromised() {
    _compromisedDismissed = true;
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

  // ---------------------------------------------------------------------------
  // Backend-driven updates (called by network layer when implemented)
  // ---------------------------------------------------------------------------

  // TODO(backend/security): call these from the network state when the
  // corresponding backend events are implemented.
  void setDirectActive(bool active) {
    if (_directActive == active) return;
    _directActive = active;
    notifyListeners();
  }

  void setCompromisedPeer(String? name) {
    _compromisedDismissed = false;
    _compromisedPeerName = name;
    notifyListeners();
  }

  void setKeyChangePeer(String? name) {
    _keyChangePeerName = name;
    notifyListeners();
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
    final condition = security.activeCondition;
    return _SecurityBanner(security: security, condition: condition);
  }
}

class _SecurityBanner extends StatelessWidget {
  const _SecurityBanner({
    required this.security,
    required this.condition,
  });

  final SecurityState security;
  final SecurityCondition condition;

  @override
  Widget build(BuildContext context) {
    final (height, color, icon, message, dismissible) = _props(security, condition);

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

  static (double, Color, IconData, String, bool) _props(
    SecurityState security,
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
      SecurityCondition.loSec => (
          32.0,
          MeshTheme.secAmber,
          Icons.warning_amber_rounded,
          'LoSec mode active — fine for everyday use',
          true,
        ),
      SecurityCondition.direct => (
          36.0,
          MeshTheme.secRed,
          Icons.warning_rounded,
          '⚠ DIRECT CONNECTION — no mesh routing',
          false,
        ),
      SecurityCondition.compromised => (
          32.0,
          MeshTheme.secPurple,
          Icons.shield_outlined,
          'Message from compromised peer'
              '${security.compromisedPeerName != null ? ' — ${security.compromisedPeerName}' : ''}',
          true,
        ),
      SecurityCondition.keyChange => (
          32.0,
          MeshTheme.brand,
          Icons.key_outlined,
          '${security.keyChangePeerName ?? 'A contact'}\'s key changed — tap to review',
          false,
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
      case SecurityCondition.compromised:
        security.dismissCompromised();
      default:
        break;
    }
  }
}
