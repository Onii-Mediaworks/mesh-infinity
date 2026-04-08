// badge_state.dart
//
// BadgeState — ChangeNotifier for the two-tier notification badge system.
//
// WHAT THIS FILE DOES:
// --------------------
// The nav drawer shows two columns of badge indicators to the right of each
// section label.  These columns are always the same width (reserved space)
// so the label text never jumps as badges appear and disappear.
//
// TIER DEFINITIONS:
// -----------------
//   Tier 1 (Critical): Always shown when there is something to act on.
//     - Expressed as a count pill (unread messages, active file transfers,
//       incoming contact requests) or as a coloured health dot (red/amber/green
//       for services degraded or network status).
//     - Count values are computed live from feature states inside the drawer
//       widget (NavDrawer._chatCritical etc.) rather than cached here, because
//       they already live in MessagingState, FilesState, etc.
//
//   Tier 2 (Ambient): User-controlled; off by default per spec.
//     - Expressed as a small square dot in a muted colour.
//     - Requires BOTH the global toggle AND the per-section toggle to be
//       enabled before the dot is shown (two-level opt-in).
//     - The *active* flag for each section is set by feature states when
//       ambient-relevant events occur (e.g. background Garden activity).
//
// USAGE:
// ------
// BadgeState is provided at the top of the widget tree in app.dart and
// read with context.watch<BadgeState>() inside NavDrawer.
//
// Feature states call setAmbientActive(section, true/false) when events that
// merit an ambient dot arrive.  Settings screens call setGlobalAmbient() and
// setSectionAmbient() when the user toggles the preference.

import 'package:flutter/foundation.dart';
import 'shell_state.dart';

/// ChangeNotifier that owns the ambient (Tier 2) badge toggle state.
///
/// Tier 1 counts are computed on-the-fly inside [NavDrawer] from other
/// ChangeNotifiers (MessagingState, FilesState, …) and are NOT cached here.
/// That keeps a single source of truth: the feature state itself.
///
/// Tier 2 visibility is a three-way AND:
///   1. [_ambientGlobalEnabled] — user has turned on ambient badges globally.
///   2. [_ambientSectionEnabled][section] — user has opted that section in.
///   3. [_ambientActive][section] — a feature has flagged that there is
///      something ambient to show for that section right now.
class BadgeState extends ChangeNotifier {
  // -------------------------------------------------------------------------
  // Internal state
  // -------------------------------------------------------------------------

  /// Whether the user has enabled the ambient badge system globally.
  ///
  /// When false, all Tier-2 dots are hidden regardless of per-section
  /// toggles or active flags — one switch to silence all ambient indicators.
  /// Defaults to false per spec (opt-in behaviour; ambient badges are noise
  /// until the user decides they are useful).
  bool _ambientGlobalEnabled = false;

  /// Per-section user opt-in for ambient badges.
  ///
  /// Initialised to false for every section.  A section that has
  /// _ambientSectionEnabled[section] == false will never show a Tier-2 dot
  /// even if the global toggle is on and the feature has flagged activity.
  final Map<AppSection, bool> _ambientSectionEnabled = {
    for (final s in AppSection.values) s: false,
  };

  /// Per-section flag set by feature states when ambient activity exists.
  ///
  /// This is the runtime "is there actually something to show?" signal.
  /// Feature states call [setAmbientActive] when relevant events arrive.
  /// The dot only renders when this AND the two toggle conditions are all true.
  final Map<AppSection, bool> _ambientActive = {
    for (final s in AppSection.values) s: false,
  };

  // -------------------------------------------------------------------------
  // Read API
  // -------------------------------------------------------------------------

  /// Whether the global ambient badge toggle is on.
  ///
  /// Reads the raw toggle value without combining the per-section check.
  /// Use [ambientEnabledFor] for a combined gate.
  bool get ambientGlobalEnabled => _ambientGlobalEnabled;

  /// True if ambient badges are enabled for [section] by both the global
  /// toggle AND the per-section toggle.
  ///
  /// Does NOT check whether there is active content to show — use
  /// [ambientVisibleFor] for the final render decision.
  bool ambientEnabledFor(AppSection section) =>
      _ambientGlobalEnabled && (_ambientSectionEnabled[section] ?? false);

  /// True if an ambient (Tier-2) dot should actually be rendered for [section].
  ///
  /// All three conditions must be true:
  ///   1. Global toggle on.
  ///   2. Per-section toggle on.
  ///   3. Feature state has flagged ambient activity for this section.
  bool ambientVisibleFor(AppSection section) =>
      ambientEnabledFor(section) && (_ambientActive[section] ?? false);

  /// Raw per-section toggle value (ignores the global toggle).
  ///
  /// Useful in settings screens that need to show the per-section switch
  /// state even when the global toggle is off.
  bool sectionAmbientToggle(AppSection section) =>
      _ambientSectionEnabled[section] ?? false;

  // -------------------------------------------------------------------------
  // Write API
  // -------------------------------------------------------------------------

  /// Turn the global ambient badge system on or off.
  ///
  /// No-op if the value has not changed (avoids spurious rebuilds).
  void setGlobalAmbient(bool enabled) {
    if (_ambientGlobalEnabled == enabled) return;
    _ambientGlobalEnabled = enabled;
    notifyListeners();
  }

  /// Enable or disable the ambient dot for a specific [section].
  ///
  /// No-op if the value has not changed.
  void setSectionAmbient(AppSection section, bool enabled) {
    if (_ambientSectionEnabled[section] == enabled) return;
    _ambientSectionEnabled[section] = enabled;
    notifyListeners();
  }

  /// Mark a section as having (or no longer having) ambient activity.
  ///
  /// Called by feature states when background events arrive that are worth
  /// surfacing if the user has opted in (e.g. a new Garden post in a
  /// channel the user follows).
  ///
  /// No-op if the value has not changed.
  void setAmbientActive(AppSection section, bool active) {
    if (_ambientActive[section] == active) return;
    _ambientActive[section] = active;
    notifyListeners();
  }
}
