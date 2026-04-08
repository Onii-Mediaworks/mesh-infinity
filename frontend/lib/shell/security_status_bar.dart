// security_status_bar.dart
//
// SecurityStatusBar — persistent animated banner that appears at the top of
// every shell body column when a security-relevant condition is active.
//
// WHAT THIS FILE DOES:
// --------------------
// Some security conditions are so important that the user must be reminded
// of them at all times, regardless of which section they are viewing.
// SecurityStatusBar implements that persistent warning layer (§22.4.1).
//
// The bar is zero-height when there is nothing to report; it animates to a
// visible height when a condition becomes active, and animates back to zero
// when it clears.
//
// SECURITY CONDITIONS (priority order, highest first):
// -----------------------------------------------------
//   exitExposure — The user's VPN exit node can see traffic destinations
//                  after traffic leaves the mesh.  This is a network-
//                  architecture consequence, not a bug — but users routing
//                  sensitive traffic through a clearnet exit must know that
//                  the exit operator can observe destination metadata.
//                  Shown in red.  Not dismissible (it is an objective state).
//
//   threat       — The user has configured a non-zero threat context level
//                  (§22.10.x).  Levels 1–3 trigger progressively stricter
//                  transport and metadata controls:
//                    1 = Elevated (amber) — stricter controls on.
//                    2 = High (red)       — privacy-preserving transports enforced.
//                    3 = Critical (purple) — maximum isolation.
//                  Shown with colour matching the threat level.  Not dismissible
//                  because the user set the level explicitly.
//
//   loSec        — A "Low Security" session is active.  LoSec is an opt-in
//                  protocol mode that routes through faster but less anonymous
//                  paths.  Both sides of a session must accept LoSec for it
//                  to activate; when it is, the app shows an amber banner to
//                  remind users that normal anonymity protections are reduced.
//                  Shown in amber.  Dismissible per session — the user can
//                  acknowledge the banner and hide it while staying in LoSec.
//
// CLASSES IN THIS FILE:
// ---------------------
//   SecurityCondition   — enum of the four possible conditions.
//   SecurityState       — ChangeNotifier that tracks LoSec session state and
//                         drives the banner via EventBus events.
//   SecurityStatusBar   — StatelessWidget that reads SecurityState, SettingsState,
//                         and NetworkState, then delegates to _SecurityBanner.
//   _SecurityBanner     — internal widget that resolves the active condition and
//                         renders the animated container.
//
// PLACEMENT:
// ----------
// SecurityStatusBar is placed at the very top of every shell body column in
// AppShell._BodyWithSecurityBar.  It is always in the widget tree (zero-height
// when inactive) rather than conditionally added/removed, so the animation
// works correctly on first appearance.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../app/app_theme.dart';
import '../backend/event_bus.dart';
import '../backend/event_models.dart';
import '../features/network/network_state.dart';
import '../features/settings/settings_state.dart';

// ---------------------------------------------------------------------------
// SecurityCondition — the four possible banner states
// ---------------------------------------------------------------------------

/// The four states the security status bar can be in.
///
/// [none] means no banner is shown.  The other three are shown in priority
/// order when their respective conditions are active.
enum SecurityCondition {
  /// No security condition is active — banner is hidden (zero height).
  none,

  /// The VPN exit node can see traffic destinations after the mesh boundary.
  ///
  /// Active when [NetworkState.vpnExitNodeSeesDestinations] and
  /// [NetworkState.isVpnActive] are both true.  Shown in red; not dismissible.
  exitExposure,

  /// A non-zero threat context level is configured (1, 2, or 3).
  ///
  /// Active when [SettingsState.settings?.threatContext] > 0.  Colour and
  /// message vary by level.  Not dismissible — the user set it explicitly.
  threat,

  /// A Low Security (LoSec) session is currently active.
  ///
  /// Active when at least one LoSec session ID is in [SecurityState._loSecSessions]
  /// and has not been dismissed by the user.  Shown in amber; dismissible.
  loSec,
}

// ---------------------------------------------------------------------------
// SecurityState — ChangeNotifier for LoSec session tracking
// ---------------------------------------------------------------------------

/// Tracks the set of active LoSec session IDs and surfaces the banner flag.
///
/// LoSec (Low Security) sessions are negotiated at the transport layer when
/// both peers consent to reduced anonymity protections in exchange for a
/// faster routing path.  The backend emits [LoSecResponseEvent] and
/// [LoSecRequestedEvent] via the EventBus when these sessions start.
///
/// The banner is dismissible per session — [dismissLoSec] records the session
/// ID in a dismissed set so the dot goes away for that session even though
/// LoSec is still technically active.  This lets users acknowledge the warning
/// without being forced to end the session.
///
/// [exitExposure] and [threat] conditions are derived from NetworkState and
/// SettingsState directly (not managed here) because those are simpler
/// boolean/integer values that don't require per-session tracking.
class SecurityState extends ChangeNotifier {
  /// Creates [SecurityState] and subscribes to the EventBus for LoSec events.
  SecurityState() {
    _sub = EventBus.instance.stream.listen(_onEvent);
  }

  /// Subscription to the global EventBus stream.
  ///
  /// Cancelled in [dispose] to prevent memory leaks.  Stored as nullable so
  /// it can be set in the constructor body after the field is initialised.
  StreamSubscription<BackendEvent>? _sub;

  /// Session IDs of currently active LoSec sessions.
  ///
  /// A session is added when the backend emits an accepted LoSec event.
  /// Sessions are never explicitly removed (the backend does not emit a
  /// "LoSec ended" event yet) — dismissed sessions are tracked separately.
  final Set<String> _loSecSessions = {};

  /// Session IDs that the user has dismissed from the banner.
  ///
  /// Dismissed sessions still appear in [_loSecSessions] but are excluded
  /// from [hasActiveLoSec].  This gives the user a way to hide the banner
  /// without ending the session.
  final Set<String> _dismissedLoSec = {};

  /// True if at least one LoSec session is active and not yet dismissed.
  ///
  /// This is the value consumed by [_SecurityBanner._activeCondition] to
  /// decide whether to show the LoSec amber banner.
  bool get hasActiveLoSec =>
      _loSecSessions.any((sessionId) => !_dismissedLoSec.contains(sessionId));

  // -------------------------------------------------------------------------
  // Dismissal
  // -------------------------------------------------------------------------

  /// Mark [sessionId] as dismissed so its banner is hidden.
  ///
  /// The session remains active (LoSec is still operating) but the banner
  /// will no longer show for this session ID.  This is intentional — the
  /// user is acknowledging the condition, not ending the session.
  void dismissLoSec(String sessionId) {
    _dismissedLoSec.add(sessionId);
    notifyListeners();
  }

  // -------------------------------------------------------------------------
  // EventBus handler — LoSec events from the Rust backend
  // -------------------------------------------------------------------------

  /// Handle incoming backend events.
  ///
  /// Only [LoSecResponseEvent] and [LoSecRequestedEvent] are processed here;
  /// all other event types are ignored via the default case.
  ///
  /// Both event types carry an [accepted] flag: the event is emitted whether
  /// the peer accepted or rejected LoSec, so we must check [accepted] before
  /// adding the session to the active set.
  void _onEvent(BackendEvent event) {
    switch (event) {
      // The local node responded to a peer's LoSec invitation and the
      // peer accepted.  The session is now in LoSec mode.
      case LoSecResponseEvent(:final sessionId, :final accepted):
        if (accepted) {
          _loSecSessions.add(sessionId);
          notifyListeners();
        }
      // A peer requested LoSec and the local node accepted.  The session
      // is now in LoSec mode.
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
    // Cancel the EventBus subscription so this notifier does not receive
    // events after it has been disposed and removed from the widget tree.
    _sub?.cancel();
    super.dispose();
  }
}

// ---------------------------------------------------------------------------
// SecurityStatusBar — public widget that reads the three state providers
// ---------------------------------------------------------------------------

/// Persistent security warning banner shown at the top of every shell body (§22.4.1).
///
/// Zero-height when no condition is active; animates to 32–36 px when a
/// condition becomes active.
///
/// Reads [SecurityState], [SettingsState], and [NetworkState].  All three
/// are watched so any change in any provider causes a rebuild.  The heavy
/// logic lives in [_SecurityBanner] which receives the three states as
/// constructor arguments — this split keeps the public API clean and makes
/// the private implementation testable.
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

// ---------------------------------------------------------------------------
// _SecurityBanner — internal implementation widget
// ---------------------------------------------------------------------------

/// Internal banner widget that resolves the active condition and renders the
/// coloured animated strip.
///
/// Kept private (_Security prefix) so callers cannot instantiate it directly
/// and bypass the Provider reads in [SecurityStatusBar].
class _SecurityBanner extends StatelessWidget {
  const _SecurityBanner({
    required this.security,
    required this.settings,
    required this.network,
  });

  /// Current LoSec session state.
  final SecurityState security;

  /// Current app settings (threat context level).
  final SettingsState settings;

  /// Current network state (VPN exit exposure, active peer count).
  final NetworkState network;

  @override
  Widget build(BuildContext context) {
    // Determine the highest-priority active condition.
    final condition = _activeCondition(security, settings, network);
    // Resolve all visual properties for this condition in one call.
    final (height, color, icon, message, dismissible) =
        _props(security, settings, network, condition);

    return AnimatedContainer(
      height: height,
      // 200 ms easeOut is fast enough to feel responsive but slow enough
      // for the user to notice the banner appearing (not instant pop-in).
      duration: const Duration(milliseconds: 200),
      curve: Curves.easeOut,
      color: color,
      // When height is 0 render nothing at all.  Using a conditional child
      // rather than visibility: hidden avoids compositing overhead.
      child: height == 0
          ? const SizedBox.shrink()
          : SafeArea(
              // bottom: false because this banner is at the TOP of the screen,
              // not at the bottom — SafeArea only needs to inset for the
              // status-bar notch.
              bottom: false,
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Row(
                  children: [
                    // Leading icon — visually signals the severity category.
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
                    // Dismiss button — only shown for dismissible conditions
                    // (currently only LoSec).  exitExposure and threat are
                    // objective states that cannot be dismissed, only resolved
                    // by changing settings or ending the VPN session.
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

  /// Resolve the highest-priority active condition from the three state objects.
  ///
  /// Priority: exitExposure > threat > loSec > none.
  ///
  /// Only the first matching condition is returned — lower-priority conditions
  /// are not shown while a higher-priority one is active.
  static SecurityCondition _activeCondition(
    SecurityState security,
    SettingsState settings,
    NetworkState network,
  ) {
    // exitExposure: VPN is active AND the exit node can observe traffic
    // destinations beyond the mesh boundary.  This is a structural privacy
    // concern that always takes highest priority.
    if (network.vpnExitNodeSeesDestinations && network.isVpnActive) {
      return SecurityCondition.exitExposure;
    }
    // threat: the user has set a non-zero threat context level.
    // threatContext == 0 means Normal (no elevated threat posture).
    if ((settings.settings?.threatContext ?? 0) > 0) {
      return SecurityCondition.threat;
    }
    // loSec: at least one LoSec session is active and not dismissed.
    if (security.hasActiveLoSec) {
      return SecurityCondition.loSec;
    }
    // No condition is active — banner is hidden.
    return SecurityCondition.none;
  }

  /// Resolve visual properties for the given condition.
  ///
  /// Returns a record of (height, color, icon, message, dismissible).
  ///
  /// Using a record avoids allocating a separate data class for what is
  /// effectively five return values used in a single build method.
  static (double, Color, IconData, String, bool) _props(
    SecurityState security,
    SettingsState settings,
    NetworkState network,
    SecurityCondition condition,
  ) {
    return switch (condition) {
      // Hidden state — zero height, no content.
      SecurityCondition.none => (
          0.0,
          Colors.transparent,
          Icons.info_outline,
          '',
          false,
        ),

      // Exit exposure — red banner; message varies by whether the exit also
      // changes the device's internet-visible IP.
      SecurityCondition.exitExposure => (
          36.0,
          MeshTheme.secRed,
          Icons.warning_rounded,
          // Two message variants:
          //   vpnChangesInternetIp == true  → traffic exits through a different
          //     network (full exit node scenario, operator sees destinations).
          //   vpnChangesInternetIp == false → traffic exits but IP is unchanged
          //     (mesh boundary only, less severe but still exposes destinations).
          network.vpnChangesInternetIp
              ? 'Traffic exits through another network. That operator can see destinations after traffic leaves the mesh.'
              : 'This route exposes destinations beyond the mesh boundary.',
          false, // Cannot be dismissed — change VPN settings to resolve.
        ),

      // Threat context — colour and message depend on the level (1/2/3).
      SecurityCondition.threat => (
          32.0,
          // Colour escalation mirrors the threat level:
          //   1 (Elevated) → amber (cautious)
          //   2 (High)     → red   (serious)
          //   3 (Critical) → purple (maximum severity)
          //   other        → brand blue (should not occur; defensive fallback)
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
          false, // Not dismissible — change threat context in Settings to resolve.
        ),

      // LoSec — amber banner; dismissible per session.
      SecurityCondition.loSec => (
          32.0,
          MeshTheme.secAmber,
          Icons.warning_amber_rounded,
          'LoSec mode active — faster path with reduced anonymity protections.',
          true, // Dismissible: user can acknowledge and hide this banner.
        ),
    };
  }

  /// Dismiss the banner for the active condition.
  ///
  /// Only LoSec is dismissible.  For other conditions this is a no-op;
  /// they can only be resolved by changing app state (VPN settings, threat
  /// context level).
  void _dismiss(SecurityState security, SecurityCondition condition) {
    switch (condition) {
      case SecurityCondition.loSec:
        // Dismiss ALL active LoSec sessions at once so the banner disappears
        // cleanly.  We iterate over a copy of the set with List.of to avoid
        // concurrent modification while iterating.
        for (final s in List.of(security._loSecSessions)) {
          security.dismissLoSec(s);
        }
      default:
        // exitExposure and threat cannot be dismissed through the banner.
        break;
    }
  }
}
