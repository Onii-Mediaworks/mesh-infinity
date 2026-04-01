import 'package:flutter/foundation.dart';
import 'shell_state.dart';

// ---------------------------------------------------------------------------
// BadgeState — tracks the two-tier badge system
//
// Tier 1 (Critical): always shown; values computed from feature states in
// the drawer widget directly (unread counts, transfer counts, etc.)
//
// Tier 2 (Ambient): user-controlled; off by default; managed here.
// ---------------------------------------------------------------------------

class BadgeState extends ChangeNotifier {
  // Global ambient toggle — off by default per spec
  bool _ambientGlobalEnabled = false;

  // Per-section ambient enable/disable — all off by default per spec
  final Map<AppSection, bool> _ambientSectionEnabled = {
    for (final s in AppSection.values) s: false,
  };

  // Per-section ambient active indicator (set by feature states)
  final Map<AppSection, bool> _ambientActive = {
    for (final s in AppSection.values) s: false,
  };

  // ---------------------------------------------------------------------------
  // Getters
  // ---------------------------------------------------------------------------

  bool get ambientGlobalEnabled => _ambientGlobalEnabled;

  bool ambientEnabledFor(AppSection section) =>
      _ambientGlobalEnabled && (_ambientSectionEnabled[section] ?? false);

  bool ambientVisibleFor(AppSection section) =>
      ambientEnabledFor(section) && (_ambientActive[section] ?? false);

  bool sectionAmbientToggle(AppSection section) =>
      _ambientSectionEnabled[section] ?? false;

  // ---------------------------------------------------------------------------
  // Mutators
  // ---------------------------------------------------------------------------

  void setGlobalAmbient(bool enabled) {
    if (_ambientGlobalEnabled == enabled) return;
    _ambientGlobalEnabled = enabled;
    notifyListeners();
  }

  void setSectionAmbient(AppSection section, bool enabled) {
    if (_ambientSectionEnabled[section] == enabled) return;
    _ambientSectionEnabled[section] = enabled;
    notifyListeners();
  }

  // Called by feature states when ambient-relevant events occur
  void setAmbientActive(AppSection section, bool active) {
    if (_ambientActive[section] == active) return;
    _ambientActive[section] = active;
    notifyListeners();
  }
}
